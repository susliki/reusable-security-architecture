/*
Autentifikācijas guard — pārbauda aktīvu sesiju katram aizsargātam endpointam.
Veic DB validāciju ik 60s — noķer izdzēstus, bloķētus vai lomas mainītus lietotājus.
Pielieto absolūto sesijas TTL un noraida bloķēto/dzēsto kontu pieprasījumus.
OWASP ASVS v5.0 V7 — sesiju pārvaldība un validācija.
*/

import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import type { Request } from 'express';
import type { AuthSession } from './session.types';
import { PrismaService } from '../prisma/prisma.service';

// Kešo pārbaudi sesijā — atkārtoti pārbauda ik 60s
const USER_VERIFY_INTERVAL_MS = 60_000;

// Absolūtais sesijas TTL — neatkarīgi no aktivitātes (OWASP ASVS v5 §3.3)
const ABSOLUTE_TTL_MS =
  (parseInt(process.env.SESSION_ABSOLUTE_TTL ?? '', 10) || 8 * 60 * 60) * 1000;

// Statusi kas pilnībā bloķē piekļuvi — iznīcina sesiju
const HARD_BLOCKED_STATUSES = ['BLOCKED', 'DELETED'];

/*
── Kopīgā sesijas validācijas loģika ──
Izmanto AuthGuard (NestJS) un Bull Board middleware (Express)
Vienots avots — novērš loģikas drift starp abiem patērētājiem
*/

export type SessionCheckResult =
  | { ok: true }
  | { ok: false; status: number; code: string; message: string; destroy: boolean };

export async function validateSession(
  session: AuthSession,
  prisma: PrismaService,
): Promise<SessionCheckResult> {
  // 1. Sesijas eksistence
  if (!session?.userId) {
    return { ok: false, status: 401, code: 'session_required', message: 'Authentication is required', destroy: false };
  }

  // 2. Absolūtā TTL pārbaude — OWASP ASVS v5 §3.3
  if (session.createdAt) {
    const age = Date.now() - new Date(session.createdAt).getTime();
    if (age > ABSOLUTE_TTL_MS) {
      return { ok: false, status: 401, code: 'session_expired', message: 'Session has expired', destroy: true };
    }
  }

  // 3. DB lietotāja pārbaude (60s keš) — OWASP ASVS v5 §3.7
  const now = Date.now();
  const lastVerified = session.userVerifiedAt
    ? new Date(session.userVerifiedAt).getTime()
    : 0;

  if (now - lastVerified > USER_VERIFY_INTERVAL_MS) {
    const user = await prisma.user.findUnique({
      where: { id: session.userId },
      select: { id: true, role: true, status: true },
    });

    if (!user) {
      return { ok: false, status: 401, code: 'user_deleted', message: 'User no longer exists', destroy: true };
    }

    // Lomas sinhronizācija
    if (session.userRole !== user.role) {
      session.userRole = user.role;
      session.isAdmin = user.role === 'ADMIN';
    }

    // Statusa kešošana
    session.userStatus = user.status;

    // Bloķētu/dzēstu lietotāju noraidīšana
    if (HARD_BLOCKED_STATUSES.includes(user.status)) {
      return { ok: false, status: 403, code: 'account_blocked', message: 'Konts nav aktīvs', destroy: true };
    }

    session.userVerifiedAt = new Date().toISOString();
  }

  return { ok: true };
}

@Injectable()
export class AuthGuard implements CanActivate {
  private readonly logger = new Logger(AuthGuard.name);

  constructor(private readonly prisma: PrismaService) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const req = ctx.switchToHttp().getRequest<Request>();
    const session = req.session as AuthSession;

    const result = await validateSession(session, this.prisma);

    if (!result.ok) {
      if (result.destroy) {
        this.logger.warn(`[AUTH] ${result.code} lietotājam ${session?.userId ?? '?'}`);
        await this.destroySession(req);
      }
      if (result.status === 401) {
        throw new UnauthorizedException({ code: result.code, message: result.message });
      }
      throw new ForbiddenException({ code: result.code, message: result.message });
    }

    // Atjaunina pēdējās aktivitātes laiku — rāda drošības pārskatā
    session.lastActive = new Date().toISOString();

    return true;
  }

  private destroySession(req: Request): Promise<void> {
    return new Promise<void>((resolve) => {
      req.session.destroy(() => resolve());
    });
  }
}
