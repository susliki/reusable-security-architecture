/*
Lietotāja pašapkalpošanās GDPR endpointi — datu piekļuves žurnāls, eksports un labojumu pieprasījumi.
GDPR Art. 15 (piekļuve), Art. 16 (labošana), Art. 20 (pārnesamība) — datu subjekta tiesības /me maršrutos.
Filtrēts audita skats — slēpj IP un neapstrādātus datus, rāda tikai darbību, datumu un piekļūstošo lomu.
*/

import {
  Controller,
  Get,
  Post,
  Body,
  Req,
  Query,
  UseGuards,
  BadRequestException,
} from '@nestjs/common';
import type { Request } from 'express';
import { AuthGuard } from '../common/auth.guard';
import type { AuthSession } from '../common/session.types';
import { PrismaService } from '../prisma/prisma.service';
import { AuditService } from '../audit/audit.service';
import { NotificationService } from '../notification/notification.service';
import { GdprExportService } from './gdpr-export.service';
import { RectificationRequestDto } from './dto/rectification-request.dto';

// GDPR Art. 15/16/20 — lietotāja pašapkalpošanās endpoints
@Controller('me')
@UseGuards(AuthGuard)
export class GdprMeController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    private readonly notifications: NotificationService,
    private readonly exportService: GdprExportService,
  ) {}

  /**
   * GDPR Art. 15 — datu piekļuves žurnāls
   * Rāda filtrētu audita žurnālu kur subjectId = pašreizējais lietotājs
   * Jūrniekam redzams: datums, darbība, piekļūstošā loma, datu kategorija
   * Slēpts: IP, e-pasts, neapstrādāti audita dati
   */
  @Get('data-access-log')
  async dataAccessLog(
    @Req() req: Request,
    @Query('limit') limitRaw?: string,
    @Query('offset') offsetRaw?: string,
  ) {
    const session = req.session as AuthSession;
    const userId = session.userId!;
    const limit = Math.min(Math.max(Number(limitRaw) || 50, 1), 200);
    const offset = Math.max(Number(offsetRaw) || 0, 0);

    const rows = await this.prisma.auditLog.findMany({
      where: { subjectId: userId },
      orderBy: { ts: 'desc' },
      take: limit,
      skip: offset,
      select: {
        ts: true,
        action: true,
        subjectRole: true,
        entityType: true,
        result: true,
      },
    });

    // Kartē darbību nosaukumus uz cilvēklasāmām kategorijām
    const mapped = rows.map((row) => ({
      date: row.ts.toISOString(),
      action: row.action,
      accessorRole: row.subjectRole ?? 'Sistēma',
      dataCategory: row.entityType ?? 'general',
      result: row.result === 'Success' ? 'viewed' : row.result.toLowerCase(),
    }));

    const total = await this.prisma.auditLog.count({
      where: { subjectId: userId },
    });

    return { ok: true, total, count: mapped.length, rows: mapped };
  }

  /**
   * GDPR Art. 20 — datu pārnesamība
   * Atgriež JSON ar visiem lietotāja personas datiem
   */
  @Get('data-export')
  async dataExport(@Req() req: Request) {
    const session = req.session as AuthSession;
    const userId = session.userId!;

    // Audita ieraksts — datu eksports ir nozīmīgs notikums
    await this.audit.write({
      subjectId: userId,
      subjectRole: session.userRole ?? null,
      action: 'gdpr.data_export',
      result: 'Success',
      clientIp: req.ip ?? null,
      userAgent: req.headers['user-agent'] ?? null,
    });

    return this.exportService.exportUserData(userId);
  }

  /**
   * GDPR Art. 16 — labošanas pieprasījums
   * Saglabā datubāzē, paziņo adminiem, raksta audita ierakstu
   */
  @Post('rectification-request')
  async rectificationRequest(
    @Body() body: RectificationRequestDto,
    @Req() req: Request,
  ) {
    const session = req.session as AuthSession;
    const userId = session.userId!;

    // Saglabā pieprasījumu datubāzē
    const request = await this.prisma.rectificationRequest.create({
      data: {
        userId,
        field: body.field,
        currentValue: body.currentValue,
        requestedValue: body.requestedValue,
        reason: body.reason ?? null,
      },
    });

    // Paziņo visiem adminiem caur bell
    await this.notifications.createForRole('ADMIN', {
      type: 'rectification',
      title: 'Jauns labošanas pieprasījums',
      description: `Lauks: ${body.field} → ${body.requestedValue}`,
      actionUrl: '/admin/rectification-requests',
      actionLabel: 'Skatīt',
    });

    await this.audit.write({
      subjectId: userId,
      subjectRole: session.userRole ?? null,
      action: 'gdpr.rectification_request',
      entityType: 'RectificationRequest',
      entityId: request.id,
      result: 'Success',
      clientIp: req.ip ?? null,
      userAgent: req.headers['user-agent'] ?? null,
      dataJson: {
        field: body.field,
        requestedValue: body.requestedValue,
      },
    });

    return { ok: true, id: request.id, message: 'Labošanas pieprasījums reģistrēts' };
  }

  /**
   * Lietotāja savu labošanas pieprasījumu vēsture
   */
  @Get('rectification-requests')
  async myRectificationRequests(@Req() req: Request) {
    const session = req.session as AuthSession;
    const userId = session.userId!;

    const requests = await this.prisma.rectificationRequest.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      take: 50,
      select: {
        id: true,
        field: true,
        currentValue: true,
        requestedValue: true,
        reason: true,
        status: true,
        reviewNote: true,
        createdAt: true,
      },
    });

    return { ok: true, items: requests };
  }
}
