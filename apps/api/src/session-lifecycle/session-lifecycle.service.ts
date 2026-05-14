/*
Sesiju dzīves cikla pārvaldība — viena kanoniska vieta visām sesiju operācijām.
Atbild par izveidi, indeksēšanu (Redis Set), atcelšanu un sesiju limita izpildi.
Audita ieraksti par login/logout/admin_force_logout/gdpr_erasure notikumiem.
OWASP ASVS v5.0 V7 — sesiju pārvaldības drošības prasības.
*/

import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { AuditService } from '../audit/audit.service';
import { parseUserAgent } from '../common/parse-user-agent';

// Audita konteksts sesiju dzīves cikla notikumiem
export interface SessionAuditContext {
  actorUserId?: string | null;
  actorRole?: string | null;
  rid?: string | null;
  clientIp?: string | null;
  userAgent?: string | null;
  reason:
    | 'login'
    | 'logout'
    | 'admin_force_logout'
    | 'admin_credentials_reset'
    | 'admin_block'
    | 'admin_role_change'
    | 'gdpr_erasure'
    | 'user_revoke_all'
    | 'passkey_revoked'
    | 'totp_rotated'
    | 'admin_bulk_revoke'
    | 'admin_session_revoke';
}

// Sesijas informācija admin pārskatam
export interface SessionInfo {
  sessionId: string;
  userId: string | null;
  firstName: string | null;
  lastName: string | null;
  userRole: string | null;
  isAdmin: boolean;
  ip: string | null;
  browser: string;
  os: string;
  createdAt: string | null;
  lastActivity: string | null;
  idleMs: number;
  ttlSec: number;
}

/**
 * Sesiju dzīves cikla pārvaldība — viena kanoniska vieta visiem sesiju operācijām.
 *
 * Atbildīga par:
 * - sesijas izveidi un indeksa uzturēšanu (Redis Set)
 * - sesiju meklēšanu (indekss-pirmā stratēģija)
 * - sesiju atcelšanu (Redis + DB + indekss)
 * - sesiju limita izpildi
 * - sesiju dzīves cikla audita ierakstiem
 *
 * OWASP ASVS v5.0 V7 — sesiju pārvaldības drošības prasības
 */
@Injectable()
export class SessionLifecycleService {
  private readonly logger = new Logger(SessionLifecycleService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly redis: RedisService,
    private readonly audit: AuditService,
  ) {}

  /*
  Redis atslēgu palīgi
  */

  /** Redis Set indeksa atslēga — satur visas lietotāja aktīvās sesiju atslēgas */
  private userSessionsKey(userId: string): string {
    return `user-sessions:${userId}`;
  }

  /** Migrācijas marķieris — norāda ka SCAN fallback jau ir izpildīts šim lietotājam */
  private userSessionsMigratedKey(userId: string): string {
    return `user-sessions:${userId}:migrated`;
  }

  /** Sesijas absolūtais TTL sekundēs no env vai noklusējuma (8h) */
  private absoluteTtl(): number {
    return Number(process.env.SESSION_ABSOLUTE_TTL ?? 8 * 60 * 60);
  }

  /*
  Sesiju meklēšana — indekss-pirmā stratēģija
  */

  /**
   * Iegūst visas aktīvās sesiju atslēgas lietotājam no Redis Set indeksa.
   *
   * L3: indekss-pirmā stratēģija — novērš O(N) SCAN katrā izsaukumā.
   * R1: migrācijas fallback izmanto atsevišķu "migrated" marķieri,
   * nevis paļaujas uz tukšu indeksu.
   */
  async findTrackedSessionKeys(userId: string): Promise<string[]> {
    const client = this.redis.getClient();
    const indexKey = this.userSessionsKey(userId);
    const migratedKey = this.userSessionsMigratedKey(userId);

    // Ja šim lietotājam vēl nav izpildīts migrācijas SCAN pēc L3 ieviešanas,
    // to veicam tagad — vienreiz — un atzīmējam ar marķieri
    const migrated = await client.exists(migratedKey);
    if (!migrated) {
      const scanned: string[] = [];
      let cursor = '0';
      do {
        const [next, batch] = await client.scan(cursor, 'MATCH', 'sess:*', 'COUNT', 200);
        cursor = next;
        for (const key of batch) {
          try {
            const raw = await client.get(key);
            if (!raw) continue;
            const data = JSON.parse(raw);
            if (data.userId === userId) scanned.push(key);
          } catch { /* ignorēt neparsējamas */ }
        }
      } while (cursor !== '0');

      if (scanned.length > 0) {
        await client.sadd(indexKey, ...scanned);
      }
      const ttl = this.absoluteTtl();
      await client.expire(indexKey, ttl + 300);
      // Marķieris ar to pašu TTL — pēc tā beigām migrācija var atkārtoties,
      // kas ir droši: idempotenta operācija
      await client.set(migratedKey, '1', 'EX', ttl + 300);
    }

    const members = await client.smembers(indexKey);
    if (members.length === 0) return [];

    // R2: pipelined EXISTS pārbaudes — izvairāmies no N sequential round-trip
    const pipeExists = client.pipeline();
    for (const key of members) pipeExists.exists(key);
    const existsResults = await pipeExists.exec();

    const stale: string[] = [];
    const alive: string[] = [];
    members.forEach((key, idx) => {
      const raw = existsResults?.[idx]?.[1];
      const existsFlag = typeof raw === 'number' ? raw : Number(raw ?? 0);
      if (existsFlag > 0) alive.push(key);
      else stale.push(key);
    });

    if (stale.length > 0) {
      await client.srem(indexKey, ...stale);
    }
    return alive;
  }

  /*
  Sesijas izveide
  */

  /**
   * H7 fix: sesijas regenerācija pēc autentifikācijas (OWASP ASVS v5.0 V7.2.x)
   * Novērš session fixation, iestata sesijas laukus, pievieno indeksam,
   * izpilda sesiju limitu.
   */
  async establishAuthenticatedSession(input: {
    req: any;
    userId: string;
    role: string;
    firstName?: string | null;
    lastName?: string | null;
    clientIp?: string | null;
    userAgent?: string | null;
  }): Promise<void> {
    const { req, userId, role, firstName, lastName, clientIp, userAgent } = input;

    // Saglabāt CSRF secret pirms regenerācijas
    const csrfSecret = req.session?.csrfSecret;

    // Sesijas regenerācija — novērš session fixation
    await new Promise<void>((resolve, reject) => {
      req.session.regenerate((err: Error | null) => {
        if (err) return reject(err);
        resolve();
      });
    });

    // Pēc regenerācijas, req.session ir JAUNS objekts
    const session = req.session;
    if (csrfSecret) session.csrfSecret = csrfSecret;

    session.userId = userId;
    session.userRole = role;
    session.isAdmin = role === 'ADMIN';
    session.firstName = firstName ?? null;
    session.lastName = lastName ?? null;
    session.clientIp = clientIp ?? null;
    session.userAgent = userAgent ?? null;
    session.createdAt = new Date().toISOString();
    session.lastActive = new Date().toISOString();
    session.userVerifiedAt = null;
    session.passkeyRegChallenge = null;
    session.passkeyAuthChallenge = null;
    session.oidcState = null;
    session.oidcNonce = null;

    // GDPR Art. 5(1)(e) — pēdējās pieteikšanās laiks neaktīvo kontu dzēšanai
    await this.prisma.user.update({
      where: { id: userId },
      data: { lastLoginAt: new Date() },
    });

    // Saglabāt sesiju pirms atgriešanas
    await new Promise<void>((resolve, reject) => {
      session.save((err: Error | null) => {
        if (err) return reject(err);
        resolve();
      });
    });

    // L3: uzturam Redis Set indeksu lietotāja sesijām — novērš O(N) SCAN
    const sessionKey = `sess:${session.id}`;
    const indexKey = this.userSessionsKey(userId);
    const client = this.redis.getClient();
    await client.sadd(indexKey, sessionKey);
    const ttl = this.absoluteTtl();
    await client.expire(indexKey, ttl + 300);

    // M5: sesiju limits — max 5 aktīvas sesijas vienam lietotājam
    await this.enforceSessionLimit(userId, 5);
  }

  /*
  Sesiju limita izpilde
  */

  /**
   * Dzēš vecākās sesijas ja pārsniegts limits — izmanto indekss-pirmā stratēģiju.
   */
  async enforceSessionLimit(userId: string, maxSessions: number): Promise<void> {
    const client = this.redis.getClient();
    const keys = await this.findTrackedSessionKeys(userId);
    if (keys.length <= maxSessions) return;

    // R2: pipelined GET — vairs neveic N atsevišķus round-trip pieprasījumus
    const pipeGet = client.pipeline();
    for (const key of keys) pipeGet.get(key);
    const getResults = await pipeGet.exec();

    const userSessions: { key: string; lastActive: number }[] = [];
    keys.forEach((key, idx) => {
      const raw = getResults?.[idx]?.[1];
      if (typeof raw !== 'string' || !raw) return;
      try {
        const data = JSON.parse(raw);
        userSessions.push({
          key,
          lastActive: data.lastActive ? new Date(data.lastActive).getTime() : 0,
        });
      } catch { /* ignorēt neparsējamas sesijas */ }
    });

    if (userSessions.length <= maxSessions) return;

    // Sakārtot pēc aktivitātes — dzēst vecākās
    userSessions.sort((a, b) => a.lastActive - b.lastActive);
    const toDelete = userSessions.slice(0, userSessions.length - maxSessions);
    const indexKey = this.userSessionsKey(userId);
    // R2: batch DEL + SREM vienā pipeline
    const pipeDel = client.pipeline();
    for (const s of toDelete) {
      pipeDel.del(s.key);
      pipeDel.srem(indexKey, s.key);
    }
    await pipeDel.exec();
  }

  /*
  Sesiju atcelšana — visas lietotāja sesijas
  */

  /**
   * Atceļ VISAS lietotāja sesijas — Redis + DB + indekss + migrācijas marķieris.
   * Kanoniskais "pilna tīrīšana" — pēc izsaukuma lietotājam nav nevienas aktīvas sesijas.
   */
  async revokeAllUserSessions(input: {
    userId: string;
    audit: SessionAuditContext;
  }): Promise<{ revokedRedis: number; deletedDb: number }> {
    const { userId, audit: ctx } = input;
    const client = this.redis.getClient();

    // 1. Atrast visas sesiju atslēgas no indeksa
    const keys = await this.findTrackedSessionKeys(userId);

    // 2. Dzēst Redis sesijas
    let revokedRedis = 0;
    if (keys.length > 0) {
      const pipe = client.pipeline();
      for (const key of keys) pipe.del(key);
      await pipe.exec();
      revokedRedis = keys.length;
    }

    // 3. Dzēst indeksu un migrācijas marķieri — tīrs stāvoklis
    const indexKey = this.userSessionsKey(userId);
    const migratedKey = this.userSessionsMigratedKey(userId);
    await client.del(indexKey, migratedKey);

    // 4. Dzēst DB sesiju ierakstus
    const dbResult = await this.prisma.session.deleteMany({ where: { userId } });

    // 5. Audita ieraksts — sesiju dzīves cikla notikums
    await this.audit.write({
      rid: ctx.rid ?? null,
      subjectId: userId,
      subjectRole: null,
      action: 'session.revoke_all',
      entityType: 'Session',
      result: 'Success',
      clientIp: ctx.clientIp ?? null,
      userAgent: ctx.userAgent ?? null,
      dataJson: {
        reason: ctx.reason,
        revokedRedis,
        deletedDb: dbResult.count,
        actorId: ctx.actorUserId ?? null,
      },
    });

    this.logger.log(
      `[SESSION] revokeAll: userId=${userId} reason=${ctx.reason} redis=${revokedRedis} db=${dbResult.count}`,
    );

    return { revokedRedis, deletedDb: dbResult.count };
  }

  /*
  Sesiju atcelšana — visas izņemot pašreizējo
  */

  /**
   * Atceļ visas lietotāja sesijas izņemot pašreizējo — pēc credential maiņas.
   *
   * DB sesiju selektīva dzēšana nav iespējama — Prisma Session.id ir UUID (auto-generated),
   * kas nav saistīts ar express-session ID (glabāts Redis kā sess:{sessionId}).
   * Tāpēc revokeOthers tīra tikai Redis, nevis DB Session ierakstus.
   * Pilna DB tīrīšana notiek caur revokeAllUserSessions (deleteMany by userId).
   */
  async revokeOtherUserSessions(input: {
    userId: string;
    currentSessionId: string;
    audit: SessionAuditContext;
  }): Promise<{ revokedRedis: number }> {
    const { userId, currentSessionId, audit: ctx } = input;
    const client = this.redis.getClient();
    const currentKey = `sess:${currentSessionId}`;

    const keys = await this.findTrackedSessionKeys(userId);
    const toRevoke = keys.filter((k) => k !== currentKey);

    let revokedRedis = 0;
    if (toRevoke.length > 0) {
      const indexKey = this.userSessionsKey(userId);
      const pipe = client.pipeline();
      for (const key of toRevoke) {
        pipe.del(key);
        pipe.srem(indexKey, key);
      }
      await pipe.exec();
      revokedRedis = toRevoke.length;
    }

    await this.audit.write({
      rid: ctx.rid ?? null,
      subjectId: userId,
      subjectRole: null,
      action: 'session.revoke_others',
      entityType: 'Session',
      result: 'Success',
      clientIp: ctx.clientIp ?? null,
      userAgent: ctx.userAgent ?? null,
      dataJson: {
        reason: ctx.reason,
        revokedRedis,
        preservedSessionId: currentSessionId,
        actorId: ctx.actorUserId ?? null,
      },
    });

    if (revokedRedis > 0) {
      this.logger.log(
        `[SESSION] revokeOthers: userId=${userId} reason=${ctx.reason} revoked=${revokedRedis}`,
      );
    }

    return { revokedRedis };
  }

  /*
  Logout — sesijas tīrīšana un indeksa atjaunināšana
  */

  /**
   * Izrakstīšanas sesijas tīrīšana — noņem no indeksa un iznīcina express-session.
   */
  async logoutSession(input: {
    session: any;
    userId: string;
    sessionId: string;
    audit: SessionAuditContext;
  }): Promise<void> {
    const { session, userId, sessionId, audit: ctx } = input;
    const client = this.redis.getClient();

    // Noņem no indeksa pirms destroy
    await client.srem(this.userSessionsKey(userId), `sess:${sessionId}`);

    // Iznīcina express-session — noņem Redis sess:{id} atslēgu
    await new Promise<void>((resolve, reject) => {
      session.destroy((err: unknown) =>
        err
          ? reject(err instanceof Error ? err : new Error('session destroy failed'))
          : resolve(),
      );
    });

    await this.audit.write({
      rid: ctx.rid ?? null,
      subjectId: userId,
      subjectRole: null,
      action: 'session.logout',
      result: 'Success',
      clientIp: ctx.clientIp ?? null,
      userAgent: ctx.userAgent ?? null,
    });
  }

  /*
  Konkrētas sesijas atcelšana (admin)
  */

  /**
   * Atceļ vienu konkrētu sesiju pēc ID — admin endpoint.
   */
  async revokeSessionById(input: {
    sessionId: string;
    audit: SessionAuditContext;
  }): Promise<{ found: boolean }> {
    const { sessionId, audit: ctx } = input;
    const client = this.redis.getClient();
    const key = `sess:${sessionId}`;

    // Nolasām sesijas datus pirms dzēšanas — audita ierakstam
    const raw = await client.get(key);
    let targetUserId: string | null = null;
    if (raw) {
      try {
        const data = JSON.parse(raw);
        targetUserId = data.userId ?? null;
      } catch { /* bojāts JSON */ }
    }

    if (!raw) {
      return { found: false };
    }

    await client.del(key);

    // Noņem no lietotāja sesiju indeksa ja zināms userId
    if (targetUserId) {
      await client.srem(this.userSessionsKey(targetUserId), key);
    }

    await this.audit.write({
      rid: ctx.rid ?? null,
      action: 'admin.session.revoke',
      subjectId: targetUserId,
      subjectRole: null,
      entityType: 'Session',
      entityId: sessionId,
      result: 'Success',
      clientIp: ctx.clientIp ?? null,
      userAgent: ctx.userAgent ?? null,
      dataJson: { actorId: ctx.actorUserId, reason: ctx.reason },
    });

    return { found: true };
  }

  /*
  Sesiju saraksti
  */

  /**
   * Lietotāja sesiju saraksts — izmanto indekss-pirmā stratēģiju.
   * Lietots UserSecurityController drošības pārskatam.
   */
  async listUserSessions(userId: string): Promise<{
    sessionId: string;
    ip: string | null;
    userAgent: string | null;
    device: string;
    lastActive: string | null;
    createdAt: string | null;
  }[]> {
    const client = this.redis.getClient();
    const keys = await this.findTrackedSessionKeys(userId);

    const sessions: {
      sessionId: string;
      ip: string | null;
      userAgent: string | null;
      device: string;
      lastActive: string | null;
      createdAt: string | null;
    }[] = [];

    if (keys.length === 0) return sessions;

    // R2: pipelined GET
    const pipe = client.pipeline();
    for (const key of keys) pipe.get(key);
    const results = await pipe.exec();

    keys.forEach((key, idx) => {
      const raw = results?.[idx]?.[1];
      if (typeof raw !== 'string' || !raw) return;
      try {
        const data = JSON.parse(raw);
        const ua = parseUserAgent(data.userAgent ?? null);
        sessions.push({
          sessionId: key.replace(/^sess:/, ''),
          ip: data.clientIp ?? null,
          userAgent: data.userAgent ?? null,
          device: ua.short,
          lastActive: data.lastActive ?? data.createdAt ?? null,
          createdAt: data.createdAt ?? null,
        });
      } catch { /* ignorēt bojātas sesijas */ }
    });

    return sessions;
  }

  /**
   * Visu aktīvo sesiju saraksts — admin pārskatam.
   * Vienīgais leģitīmais SCAN lietojums — pārskata visas sesijas neatkarīgi no lietotāja.
   */
  async listAllSessions(): Promise<{ sessions: SessionInfo[]; summary: SessionSummary }> {
    const client = this.redis.getClient();
    const sessions: SessionInfo[] = [];

    // SCAN pa sess:* atslēgām — neizmantojam KEYS lai nebloķētu Redis
    let cursor = '0';
    do {
      const [nextCursor, keys] = await client.scan(cursor, 'MATCH', 'sess:*', 'COUNT', 200);
      cursor = nextCursor;

      for (const key of keys) {
        const raw = await client.get(key);
        const ttl = await client.ttl(key);
        if (!raw) continue;

        try {
          const data = JSON.parse(raw);
          const cookie = data.cookie ?? {};
          const ua = parseUserAgent(data.userAgent ?? null);

          const lastActivity = cookie.expires
            ? new Date(new Date(cookie.expires).getTime() - (cookie.originalMaxAge ?? 0)).toISOString()
            : null;

          const now = Date.now();
          const idleMs = lastActivity ? now - new Date(lastActivity).getTime() : 0;

          sessions.push({
            sessionId: key.replace('sess:', ''),
            userId: data.userId ?? null,
            firstName: data.firstName ?? null,
            lastName: data.lastName ?? null,
            userRole: data.userRole ?? null,
            isAdmin: !!data.isAdmin,
            ip: data.clientIp ?? null,
            browser: ua.browser,
            os: ua.os,
            createdAt: data.createdAt ?? null,
            lastActivity,
            idleMs,
            ttlSec: ttl > 0 ? ttl : 0,
          });
        } catch { /* Ignorējam bojātu sesijas JSON */ }
      }
    } while (cursor !== '0');

    // Kārtojam pēc pēdējās aktivitātes — jaunākās pirmās
    sessions.sort((a, b) => {
      if (!a.lastActivity && !b.lastActivity) return 0;
      if (!a.lastActivity) return 1;
      if (!b.lastActivity) return -1;
      return new Date(b.lastActivity).getTime() - new Date(a.lastActivity).getTime();
    });

    // Kopsavilkums
    const byRole: Record<string, number> = {};
    let idle5min = 0;
    let idle30min = 0;
    const FIVE_MIN = 5 * 60 * 1000;
    const THIRTY_MIN = 30 * 60 * 1000;

    for (const s of sessions) {
      const role = s.userRole ?? 'UNKNOWN';
      byRole[role] = (byRole[role] ?? 0) + 1;
      if (s.idleMs > FIVE_MIN) idle5min++;
      if (s.idleMs > THIRTY_MIN) idle30min++;
    }

    return {
      sessions,
      summary: { total: sessions.length, byRole, idle5min, idle30min },
    };
  }

  /*
  Sesiju skaits — vieglsvara skaitītājs admin dashboard
  */

  /**
   * Saskaita kopējo aktīvo sesiju skaitu Redis — SCAN bez datu parsēšanas.
   * Lietots admin dashboard pārskatam.
   */
  async countAllSessions(): Promise<number> {
    const client = this.redis.getClient();
    let count = 0;
    let cursor = '0';
    do {
      const [nextCursor, keys] = await client.scan(cursor, 'MATCH', 'sess:*', 'COUNT', 200);
      cursor = nextCursor;
      count += keys.length;
    } while (cursor !== '0');
    return count;
  }

  /*
  Masveida sesiju atcelšana (admin)
  */

  /**
   * Masveida sesiju atcelšana — pēc lietotāju ID, lomām vai visiem.
   * Admin-only, SCAN-based (pārskata visas sesijas).
   */
  async bulkRevokeSessions(input: {
    filter: { userIds?: string[]; roles?: string[]; all?: boolean };
    adminSessionId: string;
    audit: SessionAuditContext;
  }): Promise<{ revoked: number }> {
    const { filter, adminSessionId, audit: ctx } = input;
    const client = this.redis.getClient();

    // Savācam visas sesiju atslēgas kas atbilst filtram
    const toDelete: { key: string; userId: string | null }[] = [];
    let cursor = '0';
    do {
      const [nextCursor, keys] = await client.scan(cursor, 'MATCH', 'sess:*', 'COUNT', 200);
      cursor = nextCursor;

      for (const key of keys) {
        // Neļaujam admina pašam sev pārtraukt sesiju
        const sid = key.replace('sess:', '');
        if (sid === adminSessionId) continue;

        const raw = await client.get(key);
        if (!raw) continue;

        try {
          const data = JSON.parse(raw);
          const userId = data.userId ?? null;
          const userRole = data.userRole ?? null;

          let match = false;
          if (filter.all) match = true;
          if (filter.userIds?.length && userId && filter.userIds.includes(userId)) match = true;
          if (filter.roles?.length && userRole && filter.roles.includes(userRole)) match = true;

          if (match) {
            toDelete.push({ key, userId });
          }
        } catch { /* ignorējam */ }
      }
    } while (cursor !== '0');

    // Dzēšam sesijas un noņemam no indeksa
    let revoked = 0;
    for (const item of toDelete) {
      await client.del(item.key);
      // Noņem no lietotāja sesiju indeksa
      if (item.userId) {
        await client.srem(this.userSessionsKey(item.userId), item.key);
      }
      revoked++;

      await this.audit.write({
        rid: ctx.rid ?? null,
        action: 'admin.session.revoke',
        subjectId: item.userId,
        subjectRole: null,
        entityType: 'Session',
        entityId: item.key.replace('sess:', ''),
        result: 'Success',
        clientIp: ctx.clientIp ?? null,
        userAgent: ctx.userAgent ?? null,
        dataJson: { actorId: ctx.actorUserId, bulk: true, reason: ctx.reason },
      });
    }

    return { revoked };
  }
}

/*
Kopsavilkuma tips admin pārskatam
*/

export interface SessionSummary {
  total: number;
  byRole: Record<string, number>;
  idle5min: number;
  idle30min: number;
}

