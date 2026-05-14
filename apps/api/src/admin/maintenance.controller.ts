/*
Uzturēšanas režīma pārvaldība — admin toggle un publisks statusa endpoint.
Karogs glabājas Redis (system:maintenance), katra pārslēgšana fiksēta audita žurnālā.
Frontend rāda banner; aktīva režīma laikā non-admin pieprasījumi tiek bloķēti.
*/

import {
  Body,
  Controller,
  Get,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import type { Request } from 'express';

import { AdminGuard } from '../common/admin.guard';
import { AuthGuard } from '../common/auth.guard';
import { RedisService } from '../redis/redis.service';
import { AuditService } from '../audit/audit.service';

const MAINTENANCE_KEY = 'system:maintenance';

interface MaintenancePayload {
  enabled: boolean;
  message: string | null;
  estimatedEnd: string | null;
  enabledBy: string | null;
  enabledAt: string;
}

// ── Admin toggle — POST /api/admin/maintenance ──

@Controller()
export class MaintenanceController {
  constructor(
    private readonly redis: RedisService,
    private readonly audit: AuditService,
  ) {}

  @Post('admin/maintenance')
  @UseGuards(AuthGuard, AdminGuard)
  async toggle(
    @Body() body: { enabled: boolean; message?: string; estimatedEnd?: string },
    @Req() req: Request,
  ) {
    if (body.enabled) {
      const payload: MaintenancePayload = {
        enabled: true,
        message: body.message ?? null,
        estimatedEnd: body.estimatedEnd ?? null,
        enabledBy: req.session?.userId ?? null,
        enabledAt: new Date().toISOString(),
      };
      await this.redis.setJson(MAINTENANCE_KEY, payload);
    } else {
      await this.redis.del(MAINTENANCE_KEY);
    }

    // Audita ieraksts — izsekojamība
    await this.audit.write({
      action: 'admin.maintenance.toggle',
      subjectId: req.session?.userId ?? null,
      subjectRole: req.session?.userRole ?? null,
      result: 'Success',
      clientIp: req.ip ?? null,
      userAgent: req.headers['user-agent'] ?? null,
      dataJson: { enabled: body.enabled },
    });

    return { ok: true };
  }

  // ── Publisks statuss — GET /api/maintenance (bez autentifikācijas) ──

  @Get('maintenance')
  async status() {
    const data = await this.redis.getJson<MaintenancePayload>(MAINTENANCE_KEY);
    if (!data || !data.enabled) {
      return { enabled: false };
    }
    return {
      enabled: true,
      message: data.message,
      estimatedEnd: data.estimatedEnd,
    };
  }
}
