/*
Admin lomas guard — atļauj piekļuvi tikai ADMIN lomas lietotājiem.
Pielietojas pēc AuthGuard ķēdes — paredzēts, ka sesija jau ir validēta.
Belt-and-suspenders pārbaude — gan isAdmin karodziņš, gan userRole jāsakrīt.
*/

import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import type { Request } from 'express';
import type { AuthSession } from './session.types';

@Injectable()
export class AdminGuard implements CanActivate {
  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest<Request>();
    const session = req.session as AuthSession;
    if (!session?.userId) {
      throw new UnauthorizedException({
        code: 'session_required',
        message: 'Authentication is required',
      });
    }
    /*
    L1: belt-and-suspenders — pārbauda gan isAdmin karodziņu, gan userRole.
    AuthGuard sinhronizē abus no DB ik 60s, tāpēc tiem vienmēr jāsakrīt.
    Ja viens ir manipulēts, otrs pieķers nesakritību.
    */
    if (session.isAdmin && session.userRole === 'ADMIN') return true;
    throw new ForbiddenException({
      code: 'forbidden',
      message: 'Admin access is required',
    });
  }
}
