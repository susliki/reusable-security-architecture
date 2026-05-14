/*
Saknes endpointi — root, version, health, auth/status un /me.
H3 — /auth/status atgriež tikai authenticated boolean (bez lietotāja datiem), lai novērstu informācijas noplūdi neautentificētiem klientiem; /me prasa AuthGuard un atgriež pilnu profilu.
*/

import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import type { Request } from 'express';
import { readFileSync } from 'fs';
import { join } from 'path';
import { PrismaService } from './prisma/prisma.service';
import { RedisHealthIndicator } from './redis/redis-health.indicator';
import { StorageHealthIndicator } from './storage/storage-health.indicator';
import { ClamavHealthIndicator } from './storage/clamav-health.indicator';
import { AuthGuard } from './common/auth.guard';
import type { AuthSession } from './common/session.types';

// Versijas informācija — ģenerēta deploy.sh laikā
const VERSION_INFO = (() => {
  try {
    return JSON.parse(readFileSync(join(process.cwd(), 'version.json'), 'utf-8'));
  } catch {
    // Dev vidē version.json var neeksistēt
    return { commit: 'dev', commitFull: 'dev', branch: 'local', buildTime: null, version: '0.0.0-dev' };
  }
})();

@Controller()
export class AppController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly redisHealth: RedisHealthIndicator,
    private readonly storageHealth: StorageHealthIndicator,
    private readonly clamavHealth: ClamavHealthIndicator,
  ) {}

  @Get()
  getRoot() {
    return { ok: true, service: 'api' };
  }

  // Publisks versijas endpoint — nav nepieciešama autentifikācija
  @Get('version')
  getVersion() {
    return {
      commit: VERSION_INFO.commit,
      commitFull: VERSION_INFO.commitFull,
      branch: VERSION_INFO.branch,
      buildTime: VERSION_INFO.buildTime,
      version: VERSION_INFO.version,
    };
  }

  @Get('health')
  async health() {
    await this.prisma.$queryRaw`SELECT 1`;
    const redis = await this.redisHealth.isHealthy();
    const storage = await this.storageHealth.isHealthy();
    const clamav = await this.clamavHealth.isHealthy();
    return { ok: true, db: 'up', ...redis, ...storage, ...clamav };
  }

  // H3 fix: neautentificēts — tikai autentifikācijas statuss, nekādi lietotāja dati
  @Get('auth/status')
  authStatus(@Req() req: Request) {
    const session = req.session as AuthSession;
    return { authenticated: !!session?.userId };
  }

  // H3 fix: autentificēts — pilni lietotāja dati
  @UseGuards(AuthGuard)
  @Get('me')
  async me(@Req() req: Request) {
    const session = req.session as AuthSession;
    const userId = session.userId!;

    const [user, passkeyCount] = await Promise.all([
      this.prisma.user.findUnique({
        where: { id: userId },
        select: { email: true, entraRole: true, firstName: true, lastName: true, status: true },
      }),
      this.prisma.identity.count({
        where: { userId, provider: 'PASSKEY' },
      }),
    ]);

    return {
      authenticated: true,
      userId,
      email: user?.email ?? null,
      userRole: session.userRole ?? null,
      entraRole: user?.entraRole ?? null,
      isAdmin: session.isAdmin ?? false,
      firstName: user?.firstName ?? session.firstName ?? null,
      lastName: user?.lastName ?? session.lastName ?? null,
      status: user?.status ?? null,
      hasPasskey: passkeyCount > 0,
    };
  }
}
