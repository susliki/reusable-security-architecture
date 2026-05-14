/*
Izstrādes endpointu guard — atļauj piekļuvi tikai no localhost un kad DEV_ENDPOINTS=1.
Aizsargā /api/dev/* maršrutus — tos nedrīkst sasniegt no produkcijas.
Pārbauda gan req.ip, gan socket remoteAddress — novērš proxy header viltošanu.
*/

import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import type { Request } from 'express';

function isLocalIp(ip?: string | null) {
  if (!ip) return false;
  return ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
}

@Injectable()
export class DevOnlyGuard implements CanActivate {
  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest<Request>();

    const enabled = process.env.DEV_ENDPOINTS === '1';
    if (!enabled) return false;

    if (isLocalIp(req.ip)) return true;

    const ra = (req.socket as any)?.remoteAddress as string | undefined;
    return isLocalIp(ra ?? null);
  }
}
