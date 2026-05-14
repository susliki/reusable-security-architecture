/*
Admin REST endpointi — lietotāju pārvaldība, sesiju iznīcināšana, GDPR eksports/dzēšana, sistēmas veselības pārbaudes.
Aizsardzība — AuthGuard + AdminGuard + StepUpGuard jutīgām darbībām.
OWASP ASVS v5 §3.7 (sesiju invalidācija), GDPR Art. 15 (subjekta datu eksports), Art. 17 (dzēšana).
*/

import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  ForbiddenException,
  Get,
  NotFoundException,
  Param,
  Patch,
  Post,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import { IsString, IsNotEmpty } from 'class-validator';
import type { Request } from 'express';
import type { AuthSession } from '../common/session.types';
import type { RectificationStatus } from '@prisma/client';

import { AdminGuard } from '../common/admin.guard';
import { AuthGuard } from '../common/auth.guard';
import { StepUpGuard } from '../common/step-up.guard';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { StorageHealthIndicator } from '../storage/storage-health.indicator';
import { ClamavHealthIndicator } from '../storage/clamav-health.indicator';
import { AuditService } from '../audit/audit.service';
import { NotificationService } from '../notification/notification.service';
import { SessionLifecycleService } from '../session-lifecycle/session-lifecycle.service';
import { EmailService } from '../email/email.service';
import { GdprExportService } from '../gdpr/gdpr-export.service';
import { credentialResetEmail } from '../notifications/templates/credential-reset.template';
import { randomBytes } from 'crypto';
import { readFileSync } from 'fs';
import { join } from 'path';

// DTO — labošanas pieprasījuma noraidīšanas pamats
class RejectRectificationDto {
  @IsString()
  @IsNotEmpty()
  reviewNote: string;
}

// Versijas informācija — ģenerēta deploy.sh laikā, vai fallback uz package.json
const VERSION_INFO = (() => {
  try {
    return JSON.parse(readFileSync(join(process.cwd(), 'version.json'), 'utf-8'));
  } catch {
    // Dev vidē version.json var neeksistēt — fallback uz package.json
    const ver = process.env.npm_package_version ?? (() => {
      try {
        return JSON.parse(readFileSync(join(process.cwd(), 'package.json'), 'utf-8')).version ?? 'unknown';
      } catch { return 'unknown'; }
    })();
    return { commit: 'dev', branch: 'local', buildTime: null, version: ver };
  }
})();
const APP_VERSION = VERSION_INFO.version;

// Palīgfunkcija — mēra izpildes laiku milisekundēs
async function timed<T>(fn: () => Promise<T>): Promise<{ result: T; ms: number }> {
  const start = performance.now();
  const result = await fn();
  return { result, ms: Math.round(performance.now() - start) };
}

// Servisa statuss pēc atbildes laika un kļūdām
function serviceStatus(ok: boolean, ms: number): 'operational' | 'degraded' | 'down' {
  if (!ok) return 'down';
  return ms < 500 ? 'operational' : 'degraded';
}

@Controller('admin')
@UseGuards(AuthGuard, AdminGuard)
export class AdminController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly redis: RedisService,
    private readonly storageHealth: StorageHealthIndicator,
    private readonly clamavHealth: ClamavHealthIndicator,
    private readonly audit: AuditService,
    private readonly notification: NotificationService,
    private readonly sessionLifecycle: SessionLifecycleService,
    private readonly email: EmailService,
    private readonly gdprExport: GdprExportService,
  ) {}

  // ── Lietotāju saraksts ar meklēšanu un filtrēšanu ──

  @Get('users')
  async listUsers(
    @Query('search') search?: string,
    @Query('role') role?: string,
    @Query('limit') limitRaw?: string,
  ) {
    const limit = Math.min(Math.max(Number(limitRaw) || 50, 1), 200);

    // Būvējam where nosacījumu dinamiski
    const where: Record<string, unknown> = {};

    if (search) {
      where.OR = [
        { firstName: { contains: search, mode: 'insensitive' } },
        { lastName: { contains: search, mode: 'insensitive' } },
        { email: { contains: search, mode: 'insensitive' } },
      ];
    }

    if (role) {
      where.role = role;
    }

    const rows = await this.prisma.user.findMany({
      where,
      select: {
        id: true,
        firstName: true,
        lastName: true,
        email: true,
        role: true,
        status: true,
        createdAt: true,
        updatedAt: true,
        identities: { select: { provider: true } },
      },
      orderBy: { createdAt: 'desc' },
      take: limit,
    });

    // Pievienojam identitāšu provaideru sarakstu katram lietotājam
    const mapped = rows.map((row) => ({
      id: row.id,
      firstName: row.firstName,
      lastName: row.lastName,
      email: row.email,
      role: row.role,
      status: row.status,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
      idProviders: row.identities.map((i) => i.provider).join(', '),
    }));

    return { ok: true, count: mapped.length, rows: mapped };
  }

  // ── Lietotāja lomas maiņa — tikai admins, nevar mainīt sev ──

  @UseGuards(StepUpGuard)
  @Patch('users/:id/role')
  async changeUserRole(
    @Param('id') userId: string,
    @Body() body: { role: string },
    @Req() req: Request,
  ) {
    const session = req.session as AuthSession;
    const VALID_ROLES = ['USER', 'OPERATOR', 'ADMIN'];

    if (!body.role || !VALID_ROLES.includes(body.role)) {
      throw new BadRequestException({ code: 'invalid_role', message: `Role must be one of: ${VALID_ROLES.join(', ')}` });
    }

    // Neļauj mainīt savu lomas — novērš pašdegradēšanu
    if (session.userId === userId) {
      throw new ForbiddenException({ code: 'self_role_change', message: 'Cannot change your own role' });
    }

    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw new BadRequestException({ code: 'user_not_found', message: 'User not found' });
    }

    const oldRole = user.role;
    const updated = await this.prisma.user.update({
      where: { id: userId },
      data: { role: body.role as any },
      select: { id: true, firstName: true, lastName: true, email: true, role: true },
    });

    // Iznīcina visas mērķa lietotāja sesijas — OWASP ASVS v5 §3.7
    // Novērš "sticky admin" — lomas maiņa stājas spēkā nekavējoties
    const { revokedRedis: destroyed } = await this.sessionLifecycle.revokeAllUserSessions({
      userId,
      audit: {
        actorUserId: session.userId,
        actorRole: session.userRole ?? null,
        clientIp: req.ip ?? null,
        userAgent: req.headers['user-agent'] ?? null,
        reason: 'admin_role_change',
      },
    });

    await this.audit.write({
      action: 'user.role.changed',
      subjectId: userId,
      subjectRole: oldRole,
      entityType: 'User',
      entityId: userId,
      result: 'Success',
      clientIp: req.ip ?? null,
      userAgent: req.headers['user-agent'] ?? null,
      dataJson: { oldRole, newRole: body.role, actorId: session.userId, sessionsDestroyed: destroyed },
    });

    return { ok: true, user: updated };
  }

  // ── Jauna lietotāja izveide ──

  @Post('users')
  async createUser(
    @Body() body: { email: string; firstName: string; lastName: string; role: string },
    @Req() req: Request,
  ) {
    const session = req.session as AuthSession;
    const VALID_ROLES = ['USER', 'OPERATOR', 'ADMIN'];

    if (!body.email || !body.firstName || !body.lastName || !body.role) {
      throw new BadRequestException({ code: 'missing_fields', message: 'email, firstName, lastName, and role are required' });
    }
    if (!VALID_ROLES.includes(body.role)) {
      throw new BadRequestException({ code: 'invalid_role', message: `Role must be one of: ${VALID_ROLES.join(', ')}` });
    }

    // Pārbauda vai e-pasts jau eksistē
    const existing = await this.prisma.user.findUnique({ where: { email: body.email } });
    if (existing) {
      throw new BadRequestException({ code: 'email_exists', message: 'User with this email already exists' });
    }

    const created = await this.prisma.user.create({
      data: {
        email: body.email,
        firstName: body.firstName,
        lastName: body.lastName,
        role: body.role as any,
        createdBy: session.userId,
      },
      select: { id: true, firstName: true, lastName: true, email: true, role: true, createdAt: true },
    });

    await this.audit.write({
      action: 'user.created',
      subjectId: created.id, // A.19: datu subjekts — kurš tika izveidots
      subjectRole: body.role,
      entityType: 'User',
      entityId: created.id,
      result: 'Success',
      clientIp: req.ip ?? null,
      userAgent: req.headers['user-agent'] ?? null,
      dataJson: { role: body.role, actorId: session.userId },
    });

    return { ok: true, user: created };
  }

  // ── Lietotāja bloķēšana — nekavējoties iznīcina sesijas ──

  @UseGuards(StepUpGuard)
  @Post('users/:id/block')
  async blockUser(
    @Param('id') userId: string,
    @Req() req: Request,
  ) {
    const session = req.session as AuthSession;

    if (session.userId === userId) {
      throw new ForbiddenException({ code: 'self_block', message: 'Nevar bloķēt savu kontu' });
    }

    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException({ code: 'user_not_found', message: 'Lietotājs nav atrasts' });
    }
    if (user.status === 'BLOCKED') {
      throw new BadRequestException({ code: 'already_blocked', message: 'Lietotājs jau ir bloķēts' });
    }
    if (user.status === 'DELETED') {
      throw new BadRequestException({ code: 'user_deleted', message: 'Lietotājs ir dzēsts' });
    }

    await this.prisma.user.update({
      where: { id: userId },
      data: { status: 'BLOCKED' },
    });

    // Iznīcina visas sesijas — bloķēšana stājas spēkā nekavējoties
    const { revokedRedis: destroyed } = await this.sessionLifecycle.revokeAllUserSessions({
      userId,
      audit: {
        actorUserId: session.userId,
        actorRole: session.userRole ?? null,
        clientIp: req.ip ?? null,
        userAgent: req.headers['user-agent'] ?? null,
        reason: 'admin_block',
      },
    });

    await this.audit.write({
      action: 'user.blocked',
      subjectId: userId,
      subjectRole: user.role,
      entityType: 'User',
      entityId: userId,
      result: 'Success',
      clientIp: req.ip ?? null,
      userAgent: req.headers['user-agent'] ?? null,
      dataJson: { actorId: session.userId, previousStatus: user.status, sessionsDestroyed: destroyed },
    });

    return { ok: true };
  }

  // ── Lietotāja atbloķēšana ──

  @Post('users/:id/unblock')
  async unblockUser(
    @Param('id') userId: string,
    @Req() req: Request,
  ) {
    const session = req.session as AuthSession;

    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException({ code: 'user_not_found', message: 'Lietotājs nav atrasts' });
    }
    if (user.status !== 'BLOCKED') {
      throw new BadRequestException({ code: 'not_blocked', message: 'Lietotājs nav bloķēts' });
    }

    await this.prisma.user.update({
      where: { id: userId },
      data: { status: 'VERIFIED' },
    });

    await this.audit.write({
      action: 'user.unblocked',
      subjectId: userId,
      subjectRole: user.role,
      entityType: 'User',
      entityId: userId,
      result: 'Success',
      clientIp: req.ip ?? null,
      userAgent: req.headers['user-agent'] ?? null,
      dataJson: { actorId: session.userId },
    });

    return { ok: true };
  }

  // ── Piekļuves atiestatīšana — dzēš visas identitātes un sesijas ──
  // Lietotājam būs jāreģistrē autentifikācijas metodes no jauna

  @UseGuards(StepUpGuard)
  @Post('users/:id/reset-credentials')
  async resetCredentials(
    @Param('id') userId: string,
    @Req() req: Request,
  ) {
    const session = req.session as AuthSession;

    if (session.userId === userId) {
      throw new ForbiddenException({ code: 'self_reset', message: 'Nevar atiestatīt savu piekļuvi' });
    }

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: { identities: { select: { id: true } } },
    });
    if (!user) {
      throw new NotFoundException({ code: 'user_not_found', message: 'Lietotājs nav atrasts' });
    }

    await this.prisma.$transaction(async (tx) => {
      // Dzēš passkey kredenciālus
      if (user.identities.length > 0) {
        await tx.passkeyCredential.deleteMany({
          where: { identityId: { in: user.identities.map((i) => i.id) } },
        });
      }
      // Dzēš identitātes
      await tx.identity.deleteMany({ where: { userId } });
    });

    // Iznīcina Redis sesijas + DB sesiju ierakstus + indeksu
    const { revokedRedis: destroyed } = await this.sessionLifecycle.revokeAllUserSessions({
      userId,
      audit: {
        actorUserId: session.userId,
        actorRole: session.userRole ?? null,
        clientIp: req.ip ?? null,
        userAgent: req.headers['user-agent'] ?? null,
        reason: 'admin_credentials_reset',
      },
    });

    // Automātiski sūta magic link ja lietotājam ir e-pasts
    let magicLinkSent = false;
    if (user.email) {
      try {
        await this.sendSetupLink(userId, user.email, [user.firstName, user.lastName].filter(Boolean).join(' ') || user.email);
        magicLinkSent = true;
      } catch {
        // E-pasta kļūda nedrīkst apturēt atiestatīšanu
      }
    }

    await this.audit.write({
      action: 'user.credentials.reset',
      subjectId: userId,
      subjectRole: user.role,
      entityType: 'User',
      entityId: userId,
      result: 'Success',
      clientIp: req.ip ?? null,
      userAgent: req.headers['user-agent'] ?? null,
      dataJson: {
        actorId: session.userId,
        identitiesRemoved: user.identities.length,
        sessionsDestroyed: destroyed,
        magicLinkSent,
      },
    });

    return { ok: true, magicLinkSent };
  }

  // ── Magic link sūtīšana — admin atkārtoti nosūta piekļuves iestatīšanas saiti ──

  @Post('users/:id/send-magic-link')
  async sendMagicLink(
    @Param('id') userId: string,
    @Req() req: Request,
  ) {
    const session = req.session as AuthSession;

    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException({ code: 'user_not_found', message: 'Lietotājs nav atrasts' });
    }
    if (!user.email) {
      throw new BadRequestException({ code: 'no_email', message: 'Lietotājam nav e-pasta adreses' });
    }
    if (user.status === 'DELETED') {
      throw new BadRequestException({ code: 'user_deleted', message: 'Lietotājs ir dzēsts' });
    }

    await this.sendSetupLink(userId, user.email, [user.firstName, user.lastName].filter(Boolean).join(' ') || user.email);

    await this.audit.write({
      action: 'user.magic_link.sent',
      subjectId: userId,
      subjectRole: user.role,
      entityType: 'User',
      entityId: userId,
      result: 'Success',
      clientIp: req.ip ?? null,
      userAgent: req.headers['user-agent'] ?? null,
      dataJson: { actorId: session.userId },
    });

    return { ok: true };
  }

  // Palīgmetode — ģenerē TOTP setup tokenu un sūta e-pastu
  private async sendSetupLink(userId: string, email: string, name: string) {
    const token = randomBytes(32).toString('hex');
    await this.redis.setJson(`totp-setup:${token}`, { userId }, 86400); // 24h

    const portalUrl = process.env.PORTAL_URL ?? 'http://localhost:5173';
    const verifyUrl = `${portalUrl}/auth/setup-totp?token=${token}`;

    const { subject, html } = credentialResetEmail({
      name,
      verifyUrl,
      expiryHours: 24,
    });

    await this.email.send({ to: email, subject, html });
  }

  // ── Piespiedu izrakstīšana — iznīcina sesijas bez bloķēšanas ──

  @UseGuards(StepUpGuard)
  @Post('users/:id/force-logout')
  async forceLogout(
    @Param('id') userId: string,
    @Req() req: Request,
  ) {
    const session = req.session as AuthSession;

    if (session.userId === userId) {
      throw new ForbiddenException({ code: 'self_logout', message: 'Nevar izrakstīt sevi ar šo endpointu' });
    }

    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException({ code: 'user_not_found', message: 'Lietotājs nav atrasts' });
    }

    // Iznīcina Redis sesijas + DB sesiju ierakstus + indeksu
    const { revokedRedis: destroyed } = await this.sessionLifecycle.revokeAllUserSessions({
      userId,
      audit: {
        actorUserId: session.userId,
        actorRole: session.userRole ?? null,
        clientIp: req.ip ?? null,
        userAgent: req.headers['user-agent'] ?? null,
        reason: 'admin_force_logout',
      },
    });

    await this.audit.write({
      action: 'user.force_logout',
      subjectId: userId,
      subjectRole: user.role,
      entityType: 'User',
      entityId: userId,
      result: 'Success',
      clientIp: req.ip ?? null,
      userAgent: req.headers['user-agent'] ?? null,
      dataJson: { actorId: session.userId, sessionsDestroyed: destroyed },
    });

    return { ok: true, sessionsDestroyed: destroyed };
  }

  // ── Lietotāja verifikācija — UNVERIFIED/PENDING_REVIEW → VERIFIED ──

  @Post('users/:id/verify')
  async verifyUser(
    @Param('id') userId: string,
    @Req() req: Request,
  ) {
    const session = req.session as AuthSession;

    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException({ code: 'user_not_found', message: 'Lietotājs nav atrasts' });
    }

    const VERIFIABLE = ['UNVERIFIED', 'PENDING_REVIEW'];
    if (!VERIFIABLE.includes(user.status)) {
      throw new BadRequestException({
        code: 'invalid_status',
        message: `Nevar verificēt lietotāju ar statusu ${user.status}`,
      });
    }

    await this.prisma.user.update({
      where: { id: userId },
      data: {
        status: 'VERIFIED',
        identityVerifiedAt: new Date(),
        identityVerifiedBy: session.userId,
        verificationMethod: 'ADMIN_MANUAL',
      },
    });

    await this.audit.write({
      action: 'user.verified',
      subjectId: userId,
      subjectRole: user.role,
      entityType: 'User',
      entityId: userId,
      result: 'Success',
      clientIp: req.ip ?? null,
      userAgent: req.headers['user-agent'] ?? null,
      dataJson: { actorId: session.userId, previousStatus: user.status },
    });

    return { ok: true };
  }

  // ── Lietotāja audita žurnāls — filtrēts pēc subjectId ──

  @Get('users/:id/audit')
  async userAuditLog(
    @Param('id') userId: string,
    @Query('limit') limitRaw?: string,
    @Query('offset') offsetRaw?: string,
  ) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException({ code: 'user_not_found', message: 'Lietotājs nav atrasts' });
    }

    const limit = Math.min(Math.max(Number(limitRaw) || 50, 1), 200);
    const offset = Math.max(Number(offsetRaw) || 0, 0);

    const [rows, total] = await Promise.all([
      this.prisma.auditLog.findMany({
        where: { subjectId: userId },
        orderBy: { ts: 'desc' },
        take: limit,
        skip: offset,
        select: {
          id: true,
          ts: true,
          action: true,
          result: true,
          clientIp: true,
          entityType: true,
          entityId: true,
          dataJson: true,
        },
      }),
      this.prisma.auditLog.count({ where: { subjectId: userId } }),
    ]);

    return { ok: true, total, rows };
  }

  // ── GDPR Art. 15 — admin puses datu eksports ──

  @Get('users/:id/data-export')
  async userDataExport(@Param('id') userId: string) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException({ code: 'user_not_found', message: 'Lietotājs nav atrasts' });
    }

    return this.gdprExport.exportUserData(userId);
  }

  // ── Detalizēta sistēmas veselības pārbaude ──

  @Get('health/detailed')
  async detailedHealth() {
   try {
    const services: {
      id: string;
      name: string;
      status: 'operational' | 'degraded' | 'down';
      responseMs: number;
    }[] = [];

    // PostgreSQL
    try {
      const pg = await timed(() => this.prisma.$queryRaw`SELECT 1`);
      services.push({
        id: 'postgresql',
        name: 'PostgreSQL',
        status: serviceStatus(true, pg.ms),
        responseMs: pg.ms,
      });
    } catch {
      services.push({
        id: 'postgresql',
        name: 'PostgreSQL',
        status: 'down',
        responseMs: 0,
      });
    }

    // Redis
    try {
      const rd = await timed(() => this.redis.ping());
      services.push({
        id: 'redis',
        name: 'Redis',
        status: serviceStatus(rd.result, rd.ms),
        responseMs: rd.ms,
      });
    } catch {
      services.push({
        id: 'redis',
        name: 'Redis',
        status: 'down',
        responseMs: 0,
      });
    }

    // MinIO
    try {
      const minio = await timed(() => this.storageHealth.isHealthy());
      services.push({
        id: 'minio',
        name: 'MinIO',
        status: serviceStatus(true, minio.ms),
        responseMs: minio.ms,
      });
    } catch {
      services.push({
        id: 'minio',
        name: 'MinIO',
        status: 'down',
        responseMs: 0,
      });
    }

    // ClamAV
    try {
      const clam = await timed(() => this.clamavHealth.isHealthy());
      services.push({
        id: 'clamav',
        name: 'ClamAV',
        status: serviceStatus(true, clam.ms),
        responseMs: clam.ms,
      });
    } catch {
      services.push({
        id: 'clamav',
        name: 'ClamAV',
        status: 'down',
        responseMs: 0,
      });
    }

    const mem = process.memoryUsage();

    return {
      ok: true,
      services,
      uptime: Math.round(process.uptime()),
      memory: {
        rss: Math.round(mem.rss / 1024 / 1024),
        heapUsed: Math.round(mem.heapUsed / 1024 / 1024),
        heapTotal: Math.round(mem.heapTotal / 1024 / 1024),
      },
      version: APP_VERSION,
      commit: VERSION_INFO.commit ?? 'dev',
      branch: VERSION_INFO.branch ?? 'local',
      buildTime: VERSION_INFO.buildTime ?? null,
      nodeVersion: process.version,
      env: process.env.NODE_ENV,
    };
   } catch (err) {
    // Drošības tīkls — nekad neatgriežam 500 veselības pārbaudē
    return {
      ok: false,
      services: [],
      error: err instanceof Error ? err.message : 'Unknown error',
      uptime: Math.round(process.uptime()),
      memory: { rss: 0, heapUsed: 0, heapTotal: 0 },
      version: 'unknown',
      commit: 'unknown',
      branch: 'unknown',
      buildTime: null,
      nodeVersion: process.version,
      env: process.env.NODE_ENV,
    };
   }
  }

  // ── Bloķēto IP un lietotāju saraksts ──

  @Get('security/blocked')
  async blockedList() {
    const client = this.redis.getClient();
    const ipBans: { ip: string; reason: string | null; bannedAt: string }[] = [];

    // SCAN pa ip-ban:* atslēgām — neizmantojam KEYS lai nebloķētu Redis
    let cursor = '0';
    do {
      const [nextCursor, keys] = await client.scan(cursor, 'MATCH', 'ip-ban:*', 'COUNT', 100);
      cursor = nextCursor;

      for (const key of keys) {
        const raw = await client.get(key);
        if (raw) {
          try {
            const data = JSON.parse(raw);
            ipBans.push({
              ip: data.ip,
              reason: data.reason ?? null,
              bannedAt: data.bannedAt,
            });
          } catch {
            // Ignorējam bojātu JSON
          }
        }
      }
    } while (cursor !== '0');

    // Bloķēto lietotāju saraksts
    const blockedUsers = await this.prisma.user.findMany({
      where: { status: 'BLOCKED' },
      select: { id: true, firstName: true, lastName: true, email: true, role: true },
    });

    return { blockedUsers, ipBans };
  }

  // ── IP bloķēšana ──

  @Post('security/block-ip')
  async blockIp(@Body() body: { ip: string; reason?: string }) {
    const data = {
      ip: body.ip,
      reason: body.reason ?? null,
      bannedAt: new Date().toISOString(),
      hits: 0,
    };

    await this.redis.setJson(`ip-ban:${body.ip}`, data);
    return { ok: true };
  }

  // ── IP atbloķēšana ──

  @Post('security/unblock-ip')
  async unblockIp(@Body() body: { ip: string }) {
    await this.redis.del(`ip-ban:${body.ip}`);
    return { ok: true };
  }

  // ── Sistēmas konfigurācija (tikai lasīšana) ──

  @Get('config')
  getConfig() {
    return {
      ok: true,
      session: {
        idleTimeoutSec: Number(process.env.SESSION_IDLE_TTL) || 1800,
        absoluteTimeoutSec: Number(process.env.SESSION_ABSOLUTE_TTL) || 28800,
      },
      rateLimit: {
        authWindow: process.env.RATE_LIMIT_AUTH_WINDOW ?? '15m',
        authMax: Number(process.env.RATE_LIMIT_AUTH_MAX) || 10,
        globalWindow: process.env.RATE_LIMIT_GLOBAL_WINDOW ?? '1m',
        globalMax: Number(process.env.RATE_LIMIT_GLOBAL_MAX) || 100,
      },
      upload: {
        maxFileSizeMb: Number(process.env.MAX_UPLOAD_SIZE_MB) || 5,
      },
      cors: {
        origins: process.env.CORS_ORIGINS ?? process.env.CORS_ORIGIN ?? 'same-origin',
      },
      security: {
        csrfEnabled: true,
        helmetEnabled: true,
        trustProxy: process.env.TRUST_PROXY !== '0',
      },
    };
  }

  // ── Operatīvā pārskata panelis — apkopo visu sistēmas stāvokli vienā atbildē ──

  @Get('ops/overview')
  async opsOverview() {
    // 10 sekunžu kešatmiņa — novērš biežu pārtēriņu
    const cacheKey = 'admin:ops:overview';
    try {
      const cached = await this.redis.get(cacheKey);
      if (cached) return JSON.parse(cached);
    } catch { /* Redis nav pieejams — turpinām bez keša */ }

    const now = new Date();
    const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const weekStart = new Date(todayStart);
    weekStart.setDate(weekStart.getDate() - weekStart.getDay() + 1); // Pirmdiena
    const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
    const h24ago = new Date(now.getTime() - 24 * 60 * 60 * 1000);

    // ── Lietotāju sekcija — katra sekcija ar savu try/catch lai neaptur pārējas ──
    let totalUsers = 0;
    let usersByRole: { role: string; _count: number }[] = [];
    let newToday = 0;
    let newWeek = 0;
    let newMonth = 0;
    try {
      [totalUsers, usersByRole, newToday, newWeek, newMonth] = await Promise.all([
        this.prisma.user.count(),
        this.prisma.user.groupBy({ by: ['role'], _count: true }),
        this.prisma.user.count({ where: { createdAt: { gte: todayStart } } }),
        this.prisma.user.count({ where: { createdAt: { gte: weekStart } } }),
        this.prisma.user.count({ where: { createdAt: { gte: monthStart } } }),
      ]);
    } catch { /* Lietotāju dati nav pieejami — rādām nulles */ }

    // ── Audita sekcija ──
    let totalAuditEntries = 0;
    let auditToday = 0;
    let auditByResult: { result: string; _count: number }[] = [];
    let auditTopActions: { action: string; _count: number }[] = [];
    try {
      [totalAuditEntries, auditToday, auditByResult, auditTopActions] = await Promise.all([
        this.prisma.auditLog.count(),
        this.prisma.auditLog.count({ where: { ts: { gte: todayStart } } }),
        this.prisma.auditLog.groupBy({ by: ['result'], _count: true }),
        this.prisma.auditLog.groupBy({ by: ['action'], _count: true, orderBy: { _count: { action: 'desc' } }, take: 10 }),
      ]);
    } catch { /* Audita dati nav pieejami */ }

    // ── Drošības signālu sekcija ──
    let failedLogins24h = 0;
    let rateLimited24h = 0;
    let lastSecurityEvent: any = null;
    let recentLogins: any[] = [];
    let topFailedIps: any[] = [];
    try {
      [failedLogins24h, rateLimited24h, lastSecurityEvent, recentLogins, topFailedIps] = await Promise.all([
        this.prisma.auditLog.count({ where: { action: { startsWith: 'auth.' }, result: 'Denied', ts: { gte: h24ago } } }).catch(() => 0),
        this.prisma.auditLog.count({ where: { action: 'http.request', result: 'Denied', ts: { gte: h24ago }, dataJson: { path: ['path'], string_starts_with: '/api/auth' } } }).catch(() => 0),
        this.prisma.auditLog.findFirst({ where: { result: { in: ['Denied', 'Error'] } }, orderBy: { ts: 'desc' }, select: { ts: true, action: true, subjectId: true, clientIp: true, result: true, dataJson: true } }).catch(() => null),
        this.prisma.auditLog.findMany({ where: { action: { startsWith: 'auth.' }, result: 'Success' }, orderBy: { ts: 'desc' }, take: 10, select: { ts: true, action: true, subjectId: true, clientIp: true, dataJson: true } }).catch(() => []),
        this.prisma.$queryRaw<any[]>`
          SELECT "clientIp", COUNT(*)::int AS count
          FROM "AuditLog"
          WHERE action LIKE 'auth.%' AND result = 'Denied' AND ts >= ${h24ago}
          AND "clientIp" IS NOT NULL
          GROUP BY "clientIp"
          ORDER BY count DESC
          LIMIT 5
        `.catch(() => []),
      ]);
    } catch { /* Drošības dati nav pieejami */ }

    // ── Sesijas no SessionLifecycleService ──
    let sessionCount = 0;
    try {
      sessionCount = await this.sessionLifecycle.countAllSessions();
    } catch { /* Redis kļūda — turpinām bez sesijām */ }

    // ── IP banu skaits ──
    let blockedIpCount = 0;
    try {
      const client = this.redis.getClient();
      let cursor = '0';
      do {
        const [nextCursor, keys] = await client.scan(cursor, 'MATCH', 'ip-ban:*', 'COUNT', 100);
        cursor = nextCursor;
        blockedIpCount += keys.length;
      } while (cursor !== '0');
    } catch { /* nav kritisks */ }

    // ── Servisu veselība ──
    const services: { id: string; name: string; status: string; responseMs: number }[] = [];

    let pgConnections = 0;
    let pgDbSize = '—';
    try {
      const start = performance.now();
      await this.prisma.$queryRaw`SELECT 1`;
      const ms = Math.round(performance.now() - start);
      services.push({ id: 'postgresql', name: 'PostgreSQL', status: ms < 500 ? 'operational' : 'degraded', responseMs: ms });
      const connResult = await this.prisma.$queryRaw`SELECT count(*)::int AS count FROM pg_stat_activity` as any[];
      pgConnections = connResult?.[0]?.count ?? 0;
      const sizeResult = await this.prisma.$queryRaw`SELECT pg_size_pretty(pg_database_size(current_database())) AS size` as any[];
      pgDbSize = sizeResult?.[0]?.size ?? '—';
    } catch {
      services.push({ id: 'postgresql', name: 'PostgreSQL', status: 'down', responseMs: 0 });
    }

    let redisMemory = '—';
    let redisKeys = 0;
    try {
      const start = performance.now();
      await this.redis.ping();
      const ms = Math.round(performance.now() - start);
      services.push({ id: 'redis', name: 'Redis', status: ms < 500 ? 'operational' : 'degraded', responseMs: ms });
      const client = this.redis.getClient();
      const info = await client.info('memory');
      const memMatch = info.match(/used_memory_human:(\S+)/);
      redisMemory = memMatch?.[1] ?? '—';
      redisKeys = await client.dbsize();
    } catch {
      services.push({ id: 'redis', name: 'Redis', status: 'down', responseMs: 0 });
    }

    try {
      const start = performance.now();
      await this.storageHealth.isHealthy();
      const ms = Math.round(performance.now() - start);
      services.push({ id: 'minio', name: 'MinIO', status: ms < 500 ? 'operational' : 'degraded', responseMs: ms });
    } catch {
      services.push({ id: 'minio', name: 'MinIO', status: 'down', responseMs: 0 });
    }

    try {
      const start = performance.now();
      await this.clamavHealth.isHealthy();
      const ms = Math.round(performance.now() - start);
      services.push({ id: 'clamav', name: 'ClamAV', status: ms < 500 ? 'operational' : 'degraded', responseMs: ms });
    } catch {
      services.push({ id: 'clamav', name: 'ClamAV', status: 'down', responseMs: 0 });
    }

    // ── Ķēdes integritāte ──
    let chainIntegrity = { ok: true, checked: 0 };
    try {
      chainIntegrity = await this.audit.verifyChain({ limit: 1000 });
    } catch { /* nav kritisks */ }

    const mem = process.memoryUsage();

    const result = {
      ts: now.toISOString(),
      users: {
        total: totalUsers,
        byRole: Object.fromEntries(usersByRole.map(r => [r.role, r._count])),
        newToday,
        newWeek,
        newMonth,
      },
      sessions: {
        active: sessionCount,
      },
      security: {
        failedLogins24h,
        rateLimited24h,
        blockedIpCount,
        topFailedIps: topFailedIps as any[],
        lastSecurityEvent,
        chainIntegrity: { ok: chainIntegrity.ok, checked: (chainIntegrity as any).checked ?? 0 },
      },
      services,
      server: {
        postgresql: { connections: pgConnections, dbSize: pgDbSize },
        redis: { memory: redisMemory, keys: redisKeys },
        uptime: Math.round(process.uptime()),
        memory: {
          rss: Math.round(mem.rss / 1024 / 1024),
          heapUsed: Math.round(mem.heapUsed / 1024 / 1024),
          heapTotal: Math.round(mem.heapTotal / 1024 / 1024),
        },
        version: APP_VERSION,
        commit: VERSION_INFO.commit ?? 'dev',
        branch: VERSION_INFO.branch ?? 'local',
        buildTime: VERSION_INFO.buildTime ?? null,
        nodeVersion: process.version,
        env: process.env.NODE_ENV,
      },
      audit: {
        totalEntries: totalAuditEntries,
        today: auditToday,
        byResult: Object.fromEntries(auditByResult.map(r => [r.result, r._count])),
        topActions: auditTopActions.map(a => ({ action: a.action, count: a._count })),
      },
      recentLogins: await (async () => {
        // Lietotāju vārdu atrisināšana — batch lookup
        const logins = recentLogins as any[];
        const ids = [...new Set(logins.map(l => l.subjectId).filter(Boolean))] as string[];
        const nameMap = new Map<string, string>();
        // Vispirms no dataJson
        for (const l of logins) {
          const dj = l.dataJson;
          if (dj?.firstName && l.subjectId) nameMap.set(l.subjectId, [dj.firstName, dj.lastName].filter(Boolean).join(' '));
        }
        // Trūkstošos no User tabulas
        const missing = ids.filter(id => !nameMap.has(id));
        if (missing.length > 0) {
          try {
            const users = await this.prisma.user.findMany({
              where: { id: { in: missing } },
              select: { id: true, firstName: true, lastName: true },
            });
            for (const u of users) {
              const name = [u.firstName, u.lastName].filter(Boolean).join(' ');
              if (name) nameMap.set(u.id, name);
            }
          } catch { /* User lookup neizdevās — turpinām ar UUID */ }
        }
        return logins.map(l => ({
          ts: l.ts,
          action: l.action,
          subjectId: l.subjectId,
          clientIp: l.clientIp,
          displayName: nameMap.get(l.subjectId) ?? (l.subjectId ? l.subjectId.slice(0, 8) : null),
        }));
      })(),
    };

    // Kešojam 10 sekundes — Redis kļūda nav kritiska
    try {
      await this.redis.set(cacheKey, JSON.stringify(result), 10);
    } catch { /* Redis kešošana neizdevās — atgriežam bez keša */ }

    return result;
  }

  // ── Aktīvo sesiju pārvaldība ──

  // User-agent parsēšana delegēta uz SessionLifecycleService

  @Get('sessions')
  async listSessions() {
    return this.sessionLifecycle.listAllSessions();
  }

  @Delete('sessions/:sessionId')
  async revokeSession(
    @Param('sessionId') sessionId: string,
    @Req() req: Request,
  ) {
    const session = req.session as AuthSession;
    const { found } = await this.sessionLifecycle.revokeSessionById({
      sessionId,
      audit: {
        actorUserId: session.userId ?? null,
        actorRole: session.userRole ?? null,
        clientIp: req.ip ?? null,
        userAgent: req.headers['user-agent'] ?? null,
        reason: 'admin_session_revoke',
      },
    });

    return { ok: true, found };
  }

  // ── Ātruma ierobežojumu statistika ──

  @Get('rate-limits')
  async rateLimitStats() {
    const h1ago = new Date(Date.now() - 60 * 60 * 1000);

    // Ātruma ierobežojumu grupu konfigurācija no env vai noklusējumiem
    const groups = [
      {
        name: 'auth',
        window: process.env.RATE_LIMIT_AUTH_WINDOW ?? '15m',
        max: Number(process.env.RATE_LIMIT_AUTH_MAX) || 10,
      },
      {
        name: 'admin',
        window: '1m',
        max: 30,
      },
      {
        name: 'global',
        window: process.env.RATE_LIMIT_GLOBAL_WINDOW ?? '1m',
        max: Number(process.env.RATE_LIMIT_GLOBAL_MAX) || 100,
      },
    ];

    // 429 atbilžu skaits pēdējā stundā pa grupām un kopā
    const [blocked429Rows, recent429, topIps] = await Promise.all([
      // Saskaitām 429 notikumus pēdējā stundā
      this.prisma.$queryRaw<{ count: number }[]>`
        SELECT COUNT(*)::int AS count
        FROM "AuditLog"
        WHERE ts >= ${h1ago}
          AND result = 'Denied'
          AND "dataJson"->>'status' = '429'
      `.catch(() => [{ count: 0 }]),

      // Pēdējie 10 bloķētie pieprasījumi
      this.prisma.$queryRaw<{ ts: Date; clientIp: string | null; path: string | null; action: string }[]>`
        SELECT ts, "clientIp", "dataJson"->>'path' AS path, action
        FROM "AuditLog"
        WHERE result = 'Denied'
          AND "dataJson"->>'status' = '429'
        ORDER BY ts DESC
        LIMIT 10
      `.catch(() => []),

      // Top 5 IP ar noraidītiem auth pieprasījumiem pēdējā stundā
      this.prisma.$queryRaw<{ ip: string; count: number }[]>`
        SELECT "clientIp" AS ip, COUNT(*)::int AS count
        FROM "AuditLog"
        WHERE action LIKE 'auth.%'
          AND result = 'Denied'
          AND ts >= ${h1ago}
          AND "clientIp" IS NOT NULL
        GROUP BY "clientIp"
        ORDER BY count DESC
        LIMIT 5
      `.catch(() => []),
    ]);

    const blocked429Count = blocked429Rows[0]?.count ?? 0;

    return {
      groups: groups.map((g) => ({
        name: g.name,
        window: g.window,
        max: g.max,
        blocked429Count,
      })),
      recent429: recent429.map((r) => ({
        ts: r.ts,
        ip: r.clientIp,
        path: r.path,
        action: r.action,
      })),
      topIps: (topIps as { ip: string; count: number }[]).map((r) => ({
        ip: r.ip,
        count: r.count,
      })),
    };
  }

  // ── Auth notikumu plūsma reāllaikā ──

  @Get('auth-feed')
  async authFeed(@Query('since') sinceRaw?: string) {
    const sinceId = sinceRaw ? Number(sinceRaw) : undefined;

    const where: Record<string, unknown> = {
      action: { startsWith: 'auth.' },
    };
    if (sinceId && !Number.isNaN(sinceId)) {
      where.id = { gt: sinceId };
    }

    const rows = await this.prisma.auditLog.findMany({
      where,
      orderBy: { ts: 'desc' },
      take: 50,
      select: {
        id: true,
        ts: true,
        action: true,
        result: true,
        subjectId: true,
        clientIp: true,
        userAgent: true,
        dataJson: true,
      },
    });

    // Nosaka auth metodi no darbības nosaukuma
    const detectMethod = (action: string): string => {
      if (action.includes('oidc') || action.includes('entra')) return 'oidc';
      if (action.includes('passkey') || action.includes('webauthn')) return 'passkey';
      if (action.includes('totp')) return 'totp';
      return 'unknown';
    };

    // Lietotāju vārdu atrisināšana — vispirms dataJson, tad User tabula
    const nameCache = new Map<string, string | null>();
    const needLookup: string[] = [];

    for (const row of rows) {
      const dj = row.dataJson as Record<string, unknown> | null;
      if (dj?.firstName) {
        nameCache.set(row.subjectId ?? '', [dj.firstName, dj.lastName].filter(Boolean).join(' ') as string);
      } else if (row.subjectId && !nameCache.has(row.subjectId)) {
        needLookup.push(row.subjectId);
      }
    }

    // Batch lookup — viena vaicājuma vietā N+1
    if (needLookup.length > 0) {
      const users = await this.prisma.user.findMany({
        where: { id: { in: [...new Set(needLookup)] } },
        select: { id: true, firstName: true, lastName: true },
      });
      for (const u of users) {
        nameCache.set(u.id, [u.firstName, u.lastName].filter(Boolean).join(' ') || null);
      }
    }

    return rows.map((row) => {
      const resolvedName = nameCache.get(row.subjectId ?? '') ?? null;
      return {
        id: row.id,
        timestamp: row.ts,
        action: row.action,
        result: row.result,
        userId: row.subjectId,
        displayName: resolvedName ?? (row.subjectId ? row.subjectId.slice(0, 8) : null),
        ip: row.clientIp,
        userAgent: row.userAgent,
        method: detectMethod(row.action),
      };
    });
  }

  @Get('auth-feed/stats')
  async authFeedStats() {
    const h24ago = new Date(Date.now() - 24 * 60 * 60 * 1000);

    const [success24h, denied24h, uniqueIpsResult] = await Promise.all([
      this.prisma.auditLog.count({
        where: { action: { startsWith: 'auth.' }, result: 'Success', ts: { gte: h24ago } },
      }),
      this.prisma.auditLog.count({
        where: { action: { startsWith: 'auth.' }, result: 'Denied', ts: { gte: h24ago } },
      }),
      this.prisma.$queryRaw`
        SELECT COUNT(DISTINCT "clientIp")::int AS count
        FROM "AuditLog"
        WHERE action LIKE 'auth.%' AND ts >= ${h24ago}
        AND "clientIp" IS NOT NULL
      ` as Promise<{ count: number }[]>,
    ]);

    return {
      success24h,
      denied24h,
      uniqueIps24h: uniqueIpsResult[0]?.count ?? 0,
    };
  }

  // ── Vides mainīgo drošības pārbaude — atgriež tikai esamību, nevis vērtības ──

  @Get('env-check')
  envCheck() {
    // Definējam pārbaudāmos mainīgos pa kategorijām
    const specs: {
      name: string;
      category: string;
      required: boolean;
      hint: string;
      validate?: (val: string) => string | null;
    }[] = [
      // Autentifikācija
      { name: 'OIDC_CLIENT_ID', category: 'Autentifikācija', required: true, hint: 'OIDC klienta identifikators' },
      { name: 'OIDC_CLIENT_SECRET', category: 'Autentifikācija', required: true, hint: 'OIDC klienta noslēpums' },
      { name: 'OIDC_ISSUER', category: 'Autentifikācija', required: true, hint: 'OIDC izdevēja URL' },
      { name: 'OIDC_ROLE_ADMIN', category: 'Autentifikācija', required: false, hint: 'Entra admin lomas ID' },
      // Sesijas
      {
        name: 'SESSION_SECRET', category: 'Sesijas', required: true,
        hint: 'Sesijas paraksta atslēga (min 32 rakstzīmes)',
        validate: (v) => v.length < 32 ? 'Garums < 32 rakstzīmes — nepietiekama drošība' : null,
      },
      { name: 'SESSION_IDLE_TTL', category: 'Sesijas', required: false, hint: 'Dīkstāves taimauts sekundēs' },
      { name: 'SESSION_ABSOLUTE_TTL', category: 'Sesijas', required: false, hint: 'Absolūtais sesijas taimauts sekundēs' },
      // Šifrēšana
      {
        name: 'TOTP_ENCRYPTION_KEY', category: 'Šifrēšana', required: true,
        hint: 'TOTP šifrēšanas atslēga (tieši 64 hex rakstzīmes)',
        validate: (v) => v.length !== 64 ? `Garums ${v.length}, bet jābūt tieši 64` : null,
      },
      {
        name: 'AUDIT_HMAC_KEY', category: 'Šifrēšana', required: true,
        hint: 'Audita HMAC ķēdes atslēga (min 32 rakstzīmes)',
        validate: (v) => v.length < 32 ? 'Garums < 32 rakstzīmes — nepietiekama drošība' : null,
      },
      // CSRF
      {
        name: 'CSRF_SECRET', category: 'CSRF', required: true,
        hint: 'CSRF token paraksta noslēpums (min 32 rakstzīmes)',
        validate: (v) => v.length < 32 ? 'Garums < 32 rakstzīmes — nepietiekama drošība' : null,
      },
      // Datu bāze
      {
        name: 'DATABASE_URL', category: 'Datu bāze', required: true,
        hint: 'PostgreSQL savienojuma URL',
        validate: (v) => !v.startsWith('postgresql://') ? 'Jāsākas ar postgresql://' : null,
      },
      // Redis
      { name: 'REDIS_URL', category: 'Redis', required: false, hint: 'Redis savienojuma URL' },
      { name: 'REDIS_HOST', category: 'Redis', required: false, hint: 'Redis servera adrese' },
      // Failu glabātuve
      { name: 'S3_ENDPOINT', category: 'Fails', required: true, hint: 'MinIO/S3 endpoint URL' },
      { name: 'S3_ACCESS_KEY', category: 'Fails', required: true, hint: 'S3 piekļuves atslēga' },
      { name: 'S3_SECRET_KEY', category: 'Fails', required: true, hint: 'S3 slepenā atslēga' },
      // Vide
      {
        name: 'NODE_ENV', category: 'Vide', required: false,
        hint: 'Vides režīms (production / development)',
        validate: (v) => v !== 'production' ? 'Nav production — ražošanā jābūt "production"' : null,
      },
    ];

    const items = specs.map((spec) => {
      const val = process.env[spec.name];
      const isSet = val !== undefined && val !== '';
      let warning: string | undefined;

      // Validācija tikai ja mainīgais ir iestatīts
      if (isSet && spec.validate) {
        warning = spec.validate(val!) ?? undefined;
      }

      return {
        name: spec.name,
        category: spec.category,
        required: spec.required,
        isSet,
        hint: spec.hint,
        ...(warning ? { warning } : {}),
      };
    });

    // Redis — pietiek ar vienu no REDIS_URL vai REDIS_HOST
    const redisUrl = items.find((i) => i.name === 'REDIS_URL');
    const redisHost = items.find((i) => i.name === 'REDIS_HOST');
    if (redisUrl && redisHost) {
      const eitherSet = redisUrl.isSet || redisHost.isSet;
      if (!eitherSet) {
        redisUrl.warning = 'Jābūt iestatītam REDIS_URL vai REDIS_HOST';
        redisHost.warning = 'Jābūt iestatītam REDIS_URL vai REDIS_HOST';
      }
    }

    const total = items.length;
    const set = items.filter((i) => i.isSet).length;
    const missing = items.filter((i) => i.required && !i.isSet).length;
    const warnings = items.filter((i) => i.warning).length;

    return { items, summary: { total, set, missing, warnings } };
  }

  @UseGuards(StepUpGuard)
  @Post('sessions/bulk-revoke')
  async bulkRevokeSessions(
    @Body() body: { userIds?: string[]; roles?: string[]; all?: boolean },
    @Req() req: Request,
  ) {
    const session = req.session as AuthSession;
    const { revoked } = await this.sessionLifecycle.bulkRevokeSessions({
      filter: { userIds: body.userIds, roles: body.roles, all: body.all },
      adminSessionId: req.sessionID,
      audit: {
        actorUserId: session.userId ?? null,
        actorRole: session.userRole ?? null,
        clientIp: req.ip ?? null,
        userAgent: req.headers['user-agent'] ?? null,
        reason: 'admin_bulk_revoke',
      },
    });

    return { ok: true, revoked };
  }

  // ── GDPR labošanas pieprasījumu pārvaldība ──

  @Get('rectification-requests')
  async listRectificationRequests(
    @Query('status') status?: string,
    @Query('search') search?: string,
    @Query('limit') limitRaw?: string,
    @Query('offset') offsetRaw?: string,
  ) {
    const limit = Math.min(Math.max(Number(limitRaw) || 50, 1), 200);
    const offset = Math.max(Number(offsetRaw) || 0, 0);

    const where: Record<string, unknown> = {};

    // Filtrē pēc statusa, ja norādīts
    if (status) {
      const VALID: RectificationStatus[] = ['PENDING', 'APPROVED', 'REJECTED'];
      if (VALID.includes(status as RectificationStatus)) {
        where.status = status;
      }
    }

    // Meklē pēc lietotāja vārda vai e-pasta
    if (search) {
      where.user = {
        OR: [
          { firstName: { contains: search, mode: 'insensitive' } },
          { lastName: { contains: search, mode: 'insensitive' } },
          { email: { contains: search, mode: 'insensitive' } },
        ],
      };
    }

    const [rawItems, total] = await Promise.all([
      this.prisma.rectificationRequest.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        take: limit,
        skip: offset,
      }),
      this.prisma.rectificationRequest.count({ where }),
    ]);

    // Ielādē lietotāju datus caur User modeli — PII extension atšifrē firstName/lastName/email
    const userIds = [...new Set(rawItems.map((r) => r.userId))];
    const users = await Promise.all(
      userIds.map((uid) => this.prisma.user.findUnique({
        where: { id: uid },
        select: { id: true, firstName: true, lastName: true, email: true },
      })),
    );
    const userMap = new Map(users.filter(Boolean).map((u) => [u!.id, u!]));

    return {
      ok: true,
      items: rawItems.map((r) => ({
        id: r.id,
        field: r.field,
        currentValue: r.currentValue,
        requestedValue: r.requestedValue,
        reason: r.reason,
        status: r.status,
        reviewNote: r.reviewNote,
        createdAt: r.createdAt,
        updatedAt: r.updatedAt,
        user: userMap.get(r.userId) ?? { id: r.userId, firstName: null, lastName: null, email: null },
      })),
      total,
    };
  }

  @Get('rectification-requests/:id')
  async getRectificationRequest(@Param('id') id: string) {
    const request = await this.prisma.rectificationRequest.findUnique({
      where: { id },
    });

    if (!request) {
      throw new NotFoundException({ code: 'rectification_not_found', message: 'Rectification request not found' });
    }

    // PII extension atšifrē tikai caur tiešu User vaicājumu
    const user = await this.prisma.user.findUnique({
      where: { id: request.userId },
      select: { id: true, firstName: true, lastName: true, email: true },
    });

    return { ok: true, item: { ...request, user: user ?? { id: request.userId, firstName: null, lastName: null, email: null } } };
  }

  @Patch('rectification-requests/:id/approve')
  async approveRectificationRequest(
    @Param('id') id: string,
    @Req() req: Request,
  ) {
    const session = req.session as AuthSession;

    const request = await this.prisma.rectificationRequest.findUnique({
      where: { id },
      select: { id: true, field: true, requestedValue: true, userId: true },
    });
    if (!request) {
      throw new NotFoundException({ code: 'rectification_not_found', message: 'Rectification request not found' });
    }

    // Atjaunina lietotāja datus ar pieprasīto vērtību
    const allowedFields = ['firstName', 'lastName', 'email'];
    if (allowedFields.includes(request.field)) {
      await this.prisma.user.update({
        where: { id: request.userId },
        data: { [request.field]: request.requestedValue },
      });
    }

    await this.prisma.rectificationRequest.update({
      where: { id },
      data: { status: 'APPROVED', reviewedBy: session.userId },
    });

    // Audita ieraksts — GDPR labošanas apstiprināšana
    await this.audit.write({
      subjectId: session.userId,
      subjectRole: session.userRole ?? null,
      action: 'gdpr.rectification_approve',
      entityType: 'RectificationRequest',
      entityId: id,
      result: 'Success',
      clientIp: req.ip ?? null,
      userAgent: req.headers['user-agent'] ?? null,
      dataJson: { field: request.field, newValue: request.requestedValue },
    });

    // Paziņojums jūrniekam par apstiprināšanu
    await this.notification.create({
      userId: request.userId,
      type: 'rectification',
      title: 'Labošanas pieprasījums apstiprināts',
      description: `Jūsu pieprasījums labot lauku "${request.field}" ir apstiprināts.`,
      actionUrl: '/security',
    });

    return { ok: true };
  }

  @Patch('rectification-requests/:id/reject')
  async rejectRectificationRequest(
    @Param('id') id: string,
    @Body() body: RejectRectificationDto,
    @Req() req: Request,
  ) {
    const session = req.session as AuthSession;

    const request = await this.prisma.rectificationRequest.findUnique({
      where: { id },
      select: { id: true, field: true, userId: true },
    });
    if (!request) {
      throw new NotFoundException({ code: 'rectification_not_found', message: 'Rectification request not found' });
    }

    await this.prisma.rectificationRequest.update({
      where: { id },
      data: {
        status: 'REJECTED',
        reviewedBy: session.userId,
        reviewNote: body.reviewNote,
      },
    });

    // Audita ieraksts — GDPR labošanas noraidīšana
    await this.audit.write({
      subjectId: session.userId,
      subjectRole: session.userRole ?? null,
      action: 'gdpr.rectification_reject',
      entityType: 'RectificationRequest',
      entityId: id,
      result: 'Success',
      clientIp: req.ip ?? null,
      userAgent: req.headers['user-agent'] ?? null,
    });

    // Paziņojums jūrniekam par noraidīšanu
    await this.notification.create({
      userId: request.userId,
      type: 'rectification',
      title: 'Labošanas pieprasījums noraidīts',
      description: `Jūsu pieprasījums labot lauku "${request.field}" ir noraidīts. Iemesls: ${body.reviewNote}`,
      actionUrl: '/security',
    });

    return { ok: true };
  }
}
