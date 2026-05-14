/*
Step-up autentifikācijas guard — pieprasa atkārtotu pārbaudi jutīgām operācijām.
Sesijai jābūt apstiprinātai ar passkey/TOTP pēdējo 5 minūšu laikā, citādi 403.
Pielieto MFA iestatījumu maiņai, lomu izmaiņām un citām paaugstināta riska darbībām.
*/

import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import type { Request } from 'express';
import type { AuthSession } from './session.types';

const STEP_UP_WINDOW_MS = 5 * 60 * 1000; // 5 minūtes

@Injectable()
export class StepUpGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest<Request>();
    const session = req.session as AuthSession;
    const verifiedAt = session?.stepUpVerifiedAt;

    if (!verifiedAt) {
      throw new ForbiddenException({
        code: 'step_up_required',
        message: 'Nepieciešama atkārtota autentifikācija',
      });
    }

    const elapsed = Date.now() - new Date(verifiedAt).getTime();
    if (elapsed > STEP_UP_WINDOW_MS) {
      throw new ForbiddenException({
        code: 'step_up_expired',
        message: 'Atkārtotā autentifikācija ir beigusies',
      });
    }

    return true;
  }
}
