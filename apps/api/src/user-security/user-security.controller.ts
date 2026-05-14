/*
Lietotāja drošības iestatījumu endpointi — passkey saraksts, TOTP rotācija, sesijas atcelšana.
Pieslēgšanās vēsture no AuditLog; aktīvās sesijas no SessionLifecycleService.
Step-up re-auth jutīgām darbībām (passkey dzēšana, TOTP atiestate) — OWASP ASVS v4 §2.2.4.
*/

import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Param,
  Body,
  Req,
  UseGuards,
  Logger,
  BadRequestException,
  ForbiddenException,
} from '@nestjs/common';
import type { Request } from 'express';
import { AuthGuard } from '../common/auth.guard';
import { StepUpGuard } from '../common/step-up.guard';
import type { AuthSession } from '../common/session.types';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { AuditService } from '../audit/audit.service';
import { AuthService } from '../auth/auth.service';
import { SessionLifecycleService } from '../session-lifecycle/session-lifecycle.service';
import { parseUserAgent } from '../common/parse-user-agent';

@Controller()
@UseGuards(AuthGuard)
export class UserSecurityController {
  private readonly logger = new Logger(UserSecurityController.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly redis: RedisService,
    private readonly audit: AuditService,
    private readonly authService: AuthService,
    private readonly sessionLifecycle: SessionLifecycleService,
  ) {}

  /**
   * GDPR Art. 15 — lietotāja drošības pārskats: sesijas, pieslēgumu vēsture, drošības rādītājs
   */
  @Get('me/security')
  async getSecurity(@Req() req: Request) {
    const session = req.session as AuthSession;
    const userId = session.userId!;
    const currentSessionId = req.sessionID;

    // ── Aktīvās sesijas no SessionLifecycleService (indekss-pirmā stratēģija) ──
    const rawSessions = await this.sessionLifecycle.listUserSessions(userId);
    const sessions = rawSessions.map((s) => ({
      id: s.sessionId,
      ip: s.ip,
      userAgent: s.userAgent,
      device: s.device,
      lastActive: s.lastActive,
      isCurrent: s.sessionId === currentSessionId,
    }));

    // ── Pieslēgšanās vēsture no AuditLog — tikai login/logout notikumi, ne setup ──
    const loginHistory = await this.prisma.auditLog.findMany({
      where: {
        subjectId: userId,
        action: {
          in: [
            'auth.webauthn.auth',
            'auth.totp.verify',
            'auth.oidc.callback',
            'auth.logout',
          ],
        },
      },
      orderBy: { ts: 'desc' },
      take: 20,
      select: {
        ts: true,
        action: true,
        result: true,
        clientIp: true,
        userAgent: true,
      },
    });

    const historyItems = loginHistory.map((row) => {
      const parsed = parseUserAgent(row.userAgent);
      return {
        ts: row.ts.toISOString(),
        action: row.action,
        result: row.result,
        ip: row.clientIp,
        device: parsed.short,
        method: this.authMethodFromAction(row.action),
      };
    });

    // ── Passkey dati ──
    const passkeys = await this.prisma.passkeyCredential.findMany({
      where: { identity: { userId } },
      select: {
        id: true,
        name: true,
        createdAt: true,
        lastUsedAt: true,
      },
    });

    // ── TOTP statuss ──
    const totpIdentity = await this.prisma.identity.findFirst({
      where: { userId, provider: 'TOTP', secret: { not: null } },
    });

    // ── Drošības rādītājs (0-100) ──
    const securityScore = this.calculateScore(passkeys.length, !!totpIdentity);

    return {
      sessions: {
        count: sessions.length,
        list: sessions,
      },
      loginHistory: historyItems,
      hasTotp: !!totpIdentity,
      securityScore,
      passkeys: passkeys.map((p) => ({
        id: p.id,
        name: p.name,
        createdAt: p.createdAt.toISOString(),
        lastUsedAt: p.lastUsedAt?.toISOString() ?? null,
      })),
    };
  }

  /**
   * Izbeigt VISAS sesijas (ieskaitot pašreizējo) — OWASP ASVS §3.3
   * Pēc izsaukuma lietotājs tiek izrakstīts no visām ierīcēm
   */
  @UseGuards(StepUpGuard)
  @Post('me/sessions/revoke-all')
  async revokeAllSessions(@Req() req: Request) {
    const session = req.session as AuthSession;
    const userId = session.userId!;

    const { revokedRedis: revoked } = await this.sessionLifecycle.revokeAllUserSessions({
      userId,
      audit: {
        actorUserId: userId,
        actorRole: session.userRole ?? null,
        clientIp: req.ip ?? null,
        userAgent: req.headers['user-agent'] ?? null,
        reason: 'user_revoke_all',
      },
    });

    // Izrakstīties no visām ierīcēm — express-session objekts jāiznīcina atsevišķi
    // (Redis atslēgas jau dzēstas ar revokeAllUserSessions)
    await new Promise<void>((resolve, reject) => {
      req.session.destroy((err: unknown) =>
        err
          ? reject(err instanceof Error ? err : new Error('session destroy failed'))
          : resolve(),
      );
    });

    this.logger.log(
      `Lietotājs ${userId} atsauca ${revoked} sesijas (ieskaitot pašreizējo)`,
    );

    // loggedOut: true — frontend novirza uz pieslēgšanās lapu
    return { ok: true, revoked, loggedOut: true };
  }

  /**
   * Pārdēvēt passkey — lietotājs var mainīt nosaukumu savām atslēgām
   */
  @Patch('me/passkeys/:id')
  async renamePasskey(
    @Param('id') passkeyId: string,
    @Body() body: { name: string },
    @Req() req: Request,
  ) {
    const session = req.session as AuthSession;
    const userId = session.userId!;

    if (!body.name || typeof body.name !== 'string' || body.name.trim().length === 0) {
      throw new BadRequestException({ code: 'invalid_name', message: 'Nosaukums nedrīkst būt tukšs' });
    }

    // Pārbauda vai passkey pieder šim lietotājam
    const passkey = await this.prisma.passkeyCredential.findFirst({
      where: { id: passkeyId, identity: { userId } },
    });
    if (!passkey) {
      throw new BadRequestException({ code: 'not_found', message: 'Passkey nav atrasts' });
    }

    await this.prisma.passkeyCredential.update({
      where: { id: passkeyId },
      data: { name: body.name.trim().slice(0, 100) },
    });

    await this.audit.write({
      subjectId: userId,
      subjectRole: session.userRole ?? null,
      action: 'user.passkey.renamed',
      result: 'Success',
      entityType: 'PasskeyCredential',
      entityId: passkeyId,
      clientIp: req.ip ?? null,
      userAgent: req.headers['user-agent'] ?? null,
      dataJson: { newName: body.name.trim() },
    });

    return { ok: true };
  }

  /**
   * Atsaukt passkey — lietotājam vienmēr jābūt vismaz vienai autentifikācijas metodei
   */
  @UseGuards(StepUpGuard)
  @Delete('me/passkeys/:id')
  async revokePasskey(
    @Param('id') passkeyId: string,
    @Req() req: Request,
  ) {
    const session = req.session as AuthSession;
    const userId = session.userId!;

    // Pārbauda vai passkey pieder šim lietotājam
    const passkey = await this.prisma.passkeyCredential.findFirst({
      where: { id: passkeyId, identity: { userId } },
      include: { identity: true },
    });
    if (!passkey) {
      throw new BadRequestException({ code: 'not_found', message: 'Passkey nav atrasts' });
    }

    // Drošības pārbaude — nevar atsaukt pēdējo passkey ja nav TOTP
    const [passkeyCount, totpIdentity] = await Promise.all([
      this.prisma.passkeyCredential.count({
        where: { identity: { userId } },
      }),
      this.prisma.identity.findFirst({
        where: { userId, provider: 'TOTP', secret: { not: null } },
      }),
    ]);

    if (passkeyCount <= 1 && !totpIdentity) {
      throw new ForbiddenException({
        code: 'last_auth_method',
        message: 'Nevar atsaukt pēdējo passkey — vispirms iestatiet TOTP',
      });
    }

    // Dzēš passkey un tā Identity ierakstu
    await this.prisma.$transaction(async (tx) => {
      await tx.passkeyCredential.delete({ where: { id: passkeyId } });
      await tx.identity.delete({ where: { id: passkey.identityId } });
    });

    await this.audit.write({
      subjectId: userId,
      subjectRole: session.userRole ?? null,
      action: 'user.passkey.revoked',
      result: 'Success',
      entityType: 'PasskeyCredential',
      entityId: passkeyId,
      clientIp: req.ip ?? null,
      userAgent: req.headers['user-agent'] ?? null,
      dataJson: { credentialId: passkey.credentialId },
    });

    // KI-06: invalidēt citas sesijas pēc credential maiņas
    await this.sessionLifecycle.revokeOtherUserSessions({
      userId,
      currentSessionId: req.sessionID,
      audit: {
        actorUserId: userId,
        actorRole: session.userRole ?? null,
        clientIp: req.ip ?? null,
        userAgent: req.headers['user-agent'] ?? null,
        reason: 'passkey_revoked',
      },
    });

    this.logger.log(`Lietotājs ${userId} atsauca passkey ${passkeyId}`);
    return { ok: true };
  }

  /**
   * Sākt TOTP atiestatīšanu — ģenerē jaunu noslēpumu Redis pagaidu krātuvē
   * Vecais TOTP turpina darboties līdz jaunais tiek apstiprināts ar verify
   */
  @UseGuards(StepUpGuard)
  @Post('me/totp/reset')
  async totpReset(@Req() req: Request) {
    const session = req.session as AuthSession;
    const userId = session.userId!;

    // Ģenerē jaunu TOTP noslēpumu — saglabā Redis, NE datubāzē
    const { generateSecret, generateURI } = await import('otplib');
    const secret = generateSecret();
    const issuer = process.env.TOTP_ISSUER ?? 'e-Jurnieks';

    const user = await this.prisma.user.findUniqueOrThrow({
      where: { id: userId },
    });

    const otpauthUrl = generateURI({
      issuer,
      label: user.email ?? userId,
      secret,
    });

    // Pagaidu noslēpums Redis — 15 min TTL, vecais paliek DB līdz verifikācijai
    await this.redis.setJson(
      `totp-reset-pending:${userId}`,
      { secret },
      900,
    );

    await this.audit.write({
      subjectId: userId,
      subjectRole: session.userRole ?? null,
      action: 'user.totp.reset.init',
      result: 'Success',
      clientIp: req.ip ?? null,
      userAgent: req.headers['user-agent'] ?? null,
    });

    this.logger.log(`[AUTH] totpReset: jauns pending noslēpums Redis lietotājam ${userId}`);
    /*
    L2: atgriežam tikai otpauthUrl — noslēpums jau ir URL `secret` parametrā
    un frontend var to iegūt ar URLSearchParams. Tas samazina PII lauku skaitu
    atbildē uz vienu (nevis divi) un noņem atsevišķu `secret` lauku no log
    summaries, ko varētu atstāt debug middleware.
    */
    return { otpauthUrl };
  }

  /**
   * Apstiprināt jauno TOTP kodu — verificē pret Redis pending noslēpumu,
   * tikai pēc veiksmīgas verifikācijas aizstāj veco DB noslēpumu
   */
  @Post('me/totp/reset/verify')
  async totpResetVerify(
    @Body() body: { code: string },
    @Req() req: Request,
  ) {
    const session = req.session as AuthSession;
    const userId = session.userId!;

    if (!body.code || typeof body.code !== 'string' || body.code.length !== 6) {
      throw new BadRequestException({ code: 'invalid_code', message: 'Kods ir 6 cipari' });
    }

    // Nolasa pending noslēpumu no Redis — ja nav, atiestatīšana nav sākta vai beidzies TTL
    const pendingData = await this.redis.getJson<{ secret: string }>(
      `totp-reset-pending:${userId}`,
    );
    if (!pendingData) {
      throw new BadRequestException({
        code: 'reset_expired',
        message: 'TOTP atiestatīšana ir beigusies — sāciet no jauna',
      });
    }

    // Verificē kodu pret jauno (pending) noslēpumu
    const { verify } = await import('otplib');
    const result = await verify({ token: body.code, secret: pendingData.secret });
    const valid = typeof result === 'object' && result !== null ? (result as { valid: boolean }).valid : !!result;

    if (!valid) {
      this.logger.warn(`[AUTH] totpResetVerify: nepareizs kods lietotājam ${userId}`);
      throw new BadRequestException({ code: 'totp_invalid', message: 'Nepareizs verifikācijas kods' });
    }

    // TOTP atiestatīšana: šifrē jauno noslēpumu un saglabā esošajā Identity ierakstā
    const encryptedSecret = this.authService.encryptTotpSecret(pendingData.secret);

    const updateResult = await this.prisma.identity.updateMany({
      where: { userId, provider: 'TOTP' },
      data: { secret: encryptedSecret },
    });
    this.logger.log(`[AUTH] totpResetVerify: atjaunināti ${updateResult.count} Identity ieraksti lietotājam ${userId}`);

    if (updateResult.count === 0) {
      this.logger.error(`[AUTH] totpResetVerify: TOTP Identity nav atrasts lietotājam ${userId} — noslēpums NAV saglabāts!`);
      throw new BadRequestException({ code: 'totp_not_found', message: 'TOTP identitāte nav atrasta' });
    }

    // Dzēš pending noslēpumu no Redis TIKAI pēc veiksmīgas DB saglabāšanas
    await this.redis.del(`totp-reset-pending:${userId}`);

    // KI-06: invalidēt citas sesijas pēc TOTP maiņas
    await this.sessionLifecycle.revokeOtherUserSessions({
      userId,
      currentSessionId: req.sessionID,
      audit: {
        actorUserId: userId,
        actorRole: session.userRole ?? null,
        clientIp: req.ip ?? null,
        userAgent: req.headers['user-agent'] ?? null,
        reason: 'totp_rotated',
      },
    });

    await this.audit.write({
      subjectId: userId,
      subjectRole: session.userRole ?? null,
      action: 'user.totp.reset.verified',
      result: 'Success',
      clientIp: req.ip ?? null,
      userAgent: req.headers['user-agent'] ?? null,
    });

    return { ok: true };
  }

  // ── Palīgmetodes ──

  // Sesiju dzēšana/meklēšana delegēta uz SessionLifecycleService

  // Audita darbība → attēlošanas metode: webauthn=Passkey, totp=TOTP, oidc=OIDC
  private authMethodFromAction(action: string): string {
    if (action.includes('webauthn') || action.includes('passkey')) return 'PASSKEY';
    if (action.includes('totp')) return 'TOTP';
    if (action.includes('oidc') || action.includes('entra')) return 'OIDC';
    if (action.includes('latvija')) return 'LATVIJA_LV';
    if (action.includes('logout')) return 'LOGOUT';
    return action;
  }

  // Drošības punktu aprēķins: 40(passkey) + 30(totp) + 30(abas metodes) = 100
  private calculateScore(passkeyCount: number, hasTotp: boolean): number {
    let score = 0;

    // +40 par passkey esamību
    if (passkeyCount > 0) score += 40;

    // +30 par TOTP autentifikatoru
    if (hasTotp) score += 30;

    // +30 par vairākām metodēm (passkey UN totp)
    if (passkeyCount > 0 && hasTotp) score += 30;

    return score;
  }
}
