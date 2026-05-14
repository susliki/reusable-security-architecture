/*
Fona darbu marķiera guard — autorizē audita eksporta jobus ar X-Job-Token galveni.
Salīdzina marķieri konstantā laikā — novērš timing side-channel uzbrukumus.
Ja AUDIT_EXPORT_JOB_TOKEN nav konfigurēts, endpoint paliek slēgts pēc noklusējuma.
*/

import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { timingSafeEqual } from 'crypto';
import type { Request } from 'express';

@Injectable()
export class JobTokenGuard implements CanActivate {
  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest<Request>();
    const expected = (process.env.AUDIT_EXPORT_JOB_TOKEN ?? '').trim();

    // Ja nav konfigurēts, neļaut "nejaušu atvēršanu"
    if (!expected) throw new ForbiddenException('job_token_not_configured');

    const got = String(req.headers['x-job-token'] ?? '').trim();
    if (!got) throw new ForbiddenException('invalid_job_token');

    // H5: konstanta laika salīdzinājums — novērš timing side-channel uzbrukumus,
    // kas atklātu prefiksa garumu vai baitu vērtības pa daļām.
    const a = Buffer.from(got, 'utf8');
    const b = Buffer.from(expected, 'utf8');
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      throw new ForbiddenException('invalid_job_token');
    }

    return true;
  }
}
