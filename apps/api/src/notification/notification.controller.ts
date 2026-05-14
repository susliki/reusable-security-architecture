/*
Paziņojumu kontrolieris — REST API lietotāja in-app paziņojumiem.
Atbalsta sarakstu ar filtriem, atzīmēšanu kā lasītu un masveida dzēšanu.
Aizsargāts ar AuthGuard — visi galapunkti pieprasa autentificētu sesiju.
*/

import { Controller, Delete, Get, Patch, Param, Query, Req, UseGuards } from '@nestjs/common';
import type { Request } from 'express';
import { AuthGuard } from '../common/auth.guard';
import type { AuthSession } from '../common/session.types';
import { NotificationService } from './notification.service';

// Paziņojumu API — aizstāj stub no app.controller
@Controller('notifications')
@UseGuards(AuthGuard)
export class NotificationController {
  constructor(private readonly notifications: NotificationService) {}

  @Get()
  async list(
    @Req() req: Request,
    @Query('type') type?: string,
    @Query('read') readRaw?: string,
    @Query('limit') limitRaw?: string,
    @Query('offset') offsetRaw?: string,
  ) {
    const session = req.session as AuthSession;
    const userId = session.userId!;
    const limit = Math.min(Math.max(Number(limitRaw) || 50, 1), 200);
    const offset = Math.max(Number(offsetRaw) || 0, 0);

    const filters: { type?: string; read?: boolean } = {};
    if (type) filters.type = type;
    if (readRaw === 'true') filters.read = true;
    else if (readRaw === 'false') filters.read = false;

    return this.notifications.findForUser(userId, filters, limit, offset);
  }

  @Patch(':id/read')
  async markAsRead(@Param('id') id: string, @Req() req: Request) {
    const session = req.session as AuthSession;
    await this.notifications.markAsRead(id, session.userId!);
    return { ok: true };
  }

  @Patch('read-all')
  async markAllAsRead(@Req() req: Request) {
    const session = req.session as AuthSession;
    await this.notifications.markAllAsRead(session.userId!);
    return { ok: true };
  }

  @Delete()
  async clearAll(@Req() req: Request) {
    const session = req.session as AuthSession;
    await this.notifications.deleteAll(session.userId!);
    return { ok: true };
  }
}
