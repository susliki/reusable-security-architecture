/*
Admin GDPR dzēšanas kontrolieris — neatgriezeniska right-to-erasure operācija /admin/users/:id/gdpr-erase maršrutā.
GDPR Art. 17 — dzēšanas tiesības, kaskāde sesijas, identitātes, faili, audits ar HMAC ķēdes saglabāšanu.
Aizsardzība pret pašdzēšanu — admin nevar dzēst savu kontu.
*/

import {
  Controller,
  Delete,
  Param,
  Req,
  UseGuards,
  ForbiddenException,
  BadRequestException,
} from '@nestjs/common';
import type { Request } from 'express';
import { AdminGuard } from '../common/admin.guard';
import { AuthGuard } from '../common/auth.guard';
import type { AuthSession } from '../common/session.types';
import { GdprService } from './gdpr.service';

// GDPR Art. 17 — admin dzēšanas endpoint
@Controller('admin/users')
@UseGuards(AuthGuard, AdminGuard)
export class GdprController {
  constructor(private readonly gdpr: GdprService) {}

  /**
   * Pilna GDPR dzēšana — neatgriezeniska operācija
   * Kaskādes secība atbilst spec §5.1
   */
  @Delete(':id/gdpr-erase')
  async eraseUser(@Param('id') userId: string, @Req() req: Request) {
    const session = req.session as AuthSession;
    const adminId = session.userId;

    if (!adminId) {
      throw new ForbiddenException({ code: 'no_session', message: 'Nav aktīvas sesijas' });
    }

    // Neļauj dzēst sevi
    if (adminId === userId) {
      throw new ForbiddenException({
        code: 'self_erasure',
        message: 'Nevar dzēst savu kontu',
      });
    }

    const result = await this.gdpr.eraseUser(userId, adminId, {
      ip: req.ip ?? undefined,
      userAgent: req.headers['user-agent'] ?? undefined,
    });

    if (!result.ok) {
      throw new BadRequestException({ code: result.code, message: 'Lietotājs nav atrasts' });
    }

    return { ok: true, erasedId: result.erasedId };
  }
}
