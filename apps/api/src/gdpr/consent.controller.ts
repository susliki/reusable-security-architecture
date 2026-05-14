/*
Lietotāja piekrišanu kontrolieris — GET/POST endpointi /me/consent maršrutam.
GDPR Art. 7 — piekrišanas reģistrēšana ar versiju, IP un user-agent fiksāciju audita žurnālā.
*/

import { Controller, Get, Post, Body, Req, UseGuards } from '@nestjs/common';
import type { Request } from 'express';
import { AuthGuard } from '../common/auth.guard';
import type { AuthSession } from '../common/session.types';
import { AuditService } from '../audit/audit.service';
import { ConsentService } from './consent.service';
import { ConsentAcceptDto } from './dto/consent-accept.dto';

// GDPR Art. 7 — piekrišanas pārvaldības endpoints
@Controller('me/consent')
@UseGuards(AuthGuard)
export class ConsentController {
  constructor(
    private readonly consent: ConsentService,
    private readonly audit: AuditService,
  ) {}

  /** Pašreizējais piekrišanas statuss — frontend izmanto lai noteiktu vai rādīt modāli */
  @Get()
  async getStatus(@Req() req: Request) {
    const session = req.session as AuthSession;
    return this.consent.getConsentStatus(session.userId!);
  }

  /** Pieņem privātuma politiku — izveido piekrišanas ierakstu */
  @Post()
  async accept(@Body() body: ConsentAcceptDto, @Req() req: Request) {
    const session = req.session as AuthSession;
    const userId = session.userId!;

    const result = await this.consent.acceptConsent(userId, body.policyVersion, {
      ip: req.ip ?? undefined,
      userAgent: req.headers['user-agent'] ?? undefined,
    });

    if (!result.ok) {
      return { ok: false, code: result.code, currentVersion: result.currentVersion };
    }

    await this.audit.write({
      subjectId: userId,
      subjectRole: session.userRole ?? null,
      action: 'gdpr.consent.accepted',
      result: 'Success',
      clientIp: req.ip ?? null,
      userAgent: req.headers['user-agent'] ?? null,
      dataJson: { policyVersion: body.policyVersion },
    });

    return { ok: true };
  }
}
