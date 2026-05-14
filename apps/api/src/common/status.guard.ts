/*
Konta statusa guard — atļauj biznesa endpointus tikai VERIFIED lietotājiem.
UNVERIFIED kontiem paliek pieejami auth, profila un verifikācijas ceļi.
Statuss tiek ņemts no sesijas keša — AuthGuard to atjaunina ik 60s no DB.
*/

import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import type { Request } from 'express';
import type { AuthSession } from './session.types';

// Atļautie statusi — tikai VERIFIED lietotāji var piekļūt biznesa endpoint
const ALLOWED_STATUSES = ['VERIFIED'];

// Izņēmuma ceļi — UNVERIFIED var piekļūt šiem (profils, auth, verifikācija, drošības iestatījumi)
const EXEMPT_PREFIXES = [
  '/api/auth',
  '/api/me',
  '/api/verification',
  '/api/csrf-token',
  '/api/health',
  '/api/public',
  '/api/dev',
  '/api/notifications',
];

@Injectable()
export class StatusGuard implements CanActivate {
  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest<Request>();
    const session = req.session as AuthSession;

    // Neautentificēti pieprasījumi — AuthGuard atbildēs pirms mums
    if (!session?.userId) return true;

    // Izņēmuma ceļi — UNVERIFIED lietotājiem pieejami
    const path = req.path;
    if (EXEMPT_PREFIXES.some((p) => path.startsWith(p))) return true;

    // Statuss no sesijas keša — AuthGuard to atjaunina ik 60s
    // Ja nav kešots (pirmais pieprasījums) — atļaujam, AuthGuard drīz kešos
    const status = session.userStatus;
    if (!status) return true;

    if (!ALLOWED_STATUSES.includes(status)) {
      throw new ForbiddenException({
        code: 'account_not_verified',
        message: 'Konts nav verificēts',
        status,
      });
    }

    return true;
  }
}
