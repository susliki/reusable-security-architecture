/*
Audita žurnāla admin endpointi — saraksts ar filtriem, ķēdes integritātes pārbaude, NDJSON un PDF eksports.
Worker job-token aizsargā automātiskos eksportus, AdminGuard pārējos lasīšanas endpointus.
*/

import {
  BadRequestException,
  Controller,
  Get,
  Post,
  Query,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import type { Request, Response } from 'express';

import { AdminGuard } from '../common/admin.guard';
import { AuthGuard } from '../common/auth.guard';
import { JobTokenGuard } from '../common/job-token.guard';

import { AuditService } from './audit.service';
import { AuditQueryDto } from './audit.query.dto';
import { AuditExportService } from './audit-export.service';
import { AuditPdfExportService } from './audit-pdf-export.service';
import {
  AuditExportQueryDto,
  AuditExportRunQueryDto,
} from './audit-export.dto';

@Controller('admin/audit')
export class AuditController {
  constructor(
    private readonly audit: AuditService,
    private readonly exporter: AuditExportService,
    private readonly pdfExporter: AuditPdfExportService,
  ) {}

  @UseGuards(AuthGuard, AdminGuard)
  @Get('integrity')
  async integrity(
    @Query('limit') limit?: string,
    @Query('from') from?: string,
  ) {
    const n = Math.min(Math.max(Number(limit ?? 5000), 1), 200_000);
    try {
      // Noklusējums: tail — pārbauda jaunākos ierakstus (visticamāk manipulētos)
      if (from === 'head') {
        return await this.audit.verifyChain({ limit: n });
      }
      return await this.audit.verifyRecentChain({ limit: n });
    } catch (err) {
      // Verifikācijas kļūda nedrīkst kļūt par 500 — atgriežam strukturētu atbildi
      return {
        ok: false,
        checked: 0,
        error: err instanceof Error ? err.message : 'Unknown verification error',
      };
    }
  }

  @UseGuards(AuthGuard, AdminGuard)
  @Get()
  async list(@Query() q: AuditQueryDto) {
    const rows = await this.audit.query(q);
    return { ok: true, count: rows.length, rows };
  }

  @UseGuards(AuthGuard, AdminGuard)
  @Post('test')
  async test(@Req() req: Request) {
    const rid = String(req.headers['x-request-id'] ?? null);

    const row = await this.audit.write({
      rid: rid && rid !== 'null' ? rid : null,
      action: 'audit.test',
      entityType: 'System',
      entityId: 'manual',
      result: 'Success',
      clientIp: req.ip ?? null,
      userAgent: req.headers['user-agent'] ?? null,
      dataJson: { note: 'manual test event' },
    });

    return { ok: true, id: row.id, rid: row.rid ?? null };
  }

  // Manuāls eksports — palaiž admins
  @UseGuards(AuthGuard, AdminGuard)
  @Get('export')
  async exportRange(@Query() q: AuditExportQueryDto) {
    const limit =
      q.limit ?? Number(process.env.AUDIT_EXPORT_DEFAULT_LIMIT ?? 200_000);

    const to = q.to ? new Date(q.to) : new Date();
    const from = q.from
      ? new Date(q.from)
      : new Date(to.getTime() - 24 * 60 * 60 * 1000);

    if (isNaN(to.getTime()) || isNaN(from.getTime())) {
      throw new BadRequestException('invalid_date_range');
    }
    if (from > to) {
      throw new BadRequestException('invalid_date_range_order');
    }

    return this.exporter.exportRange({ from, to, limit });
  }

  // Plānota eksporta palaišana (cron/job) — token auth (NEVIS admin sesija)
  @UseGuards(JobTokenGuard)
  @Post('export/run')
  async exportRun(@Query() q: AuditExportRunQueryDto) {
    const limit =
      q.limit ?? Number(process.env.AUDIT_EXPORT_DEFAULT_LIMIT ?? 200_000);
    return this.exporter.exportPeriod({ period: q.period, limit });
  }

  // HMAC-parakstīts PDF eksports — atbilstības pierādījumam
  @UseGuards(AuthGuard, AdminGuard)
  @Get('export/pdf')
  async exportPdf(
    @Query('from') fromStr?: string,
    @Query('to') toStr?: string,
    @Res() res?: Response,
  ) {
    const to = toStr ? new Date(toStr) : new Date();
    const from = fromStr
      ? new Date(fromStr)
      : new Date(to.getTime() - 30 * 24 * 60 * 60 * 1000);

    if (isNaN(to.getTime()) || isNaN(from.getTime())) {
      throw new BadRequestException('invalid_date_range');
    }
    if (from > to) {
      throw new BadRequestException('invalid_date_range_order');
    }

    await this.pdfExporter.exportPdf(res!, { from, to });
  }
}
