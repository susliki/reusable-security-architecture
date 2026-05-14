/*
Profila kontrolieris — /me/profile GET/PATCH un iesniegšana operatora apstiprinājumam.
Personas kods tiek glabāts šifrētā veidā (personalCodeEnc) un meklēšanai izmanto blind-index.
*/

import {
  Controller,
  Get,
  Patch,
  Post,
  Body,
  Req,
  UseGuards,
  BadRequestException,
  ForbiddenException,
} from '@nestjs/common';
import type { Request } from 'express';
import { AuthGuard } from '../common/auth.guard';
import type { AuthSession } from '../common/session.types';
import { PrismaService } from '../prisma/prisma.service';
import { AuditService } from '../audit/audit.service';
import { NotificationService } from '../notification/notification.service';
import { blindIndex } from '../crypto/pii-crypto';

@Controller('me')
@UseGuards(AuthGuard)
export class ProfileController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    private readonly notifications: NotificationService,
  ) {}

  // ── GET /me/profile — pilns profila datu kopums ──
  @Get('profile')
  async getProfile(@Req() req: Request) {
    const session = req.session as AuthSession;
    const userId = session.userId!;

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        firstName: true,
        lastName: true,
        email: true,
        personalCodeEnc: true,
        dateOfBirth: true,
        birthPlace: true,
        sex: true,
        citizenship: true,
        phone: true,
        address: true,
        emailNotify: true,
        smsNotify: true,
        status: true,
        rejectionReason: true,
        profileSubmittedAt: true,
      },
    });

    if (!user) {
      throw new BadRequestException({ code: 'user_not_found', message: 'Lietotājs nav atrasts' });
    }

    // PK maskēšana — pilns tikai UNVERIFIED/REJECTED (rediģēšanai)
    const editable = user.status === 'UNVERIFIED' || user.status === 'REJECTED';
    let personalCode: string | null = null;
    if (user.personalCodeEnc) {
      // Prisma extension jau atšifrē — personalCodeEnc ir plaintext pēc select
      personalCode = editable ? user.personalCodeEnc : maskPersonalCode(user.personalCodeEnc);
    }

    return {
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      personalCode,
      dateOfBirth: user.dateOfBirth,
      birthPlace: user.birthPlace,
      sex: user.sex,
      citizenship: user.citizenship,
      phone: user.phone,
      address: user.address,
      emailNotify: user.emailNotify,
      smsNotify: user.smsNotify,
      status: user.status,
      rejectionReason: user.rejectionReason,
      profileSubmittedAt: user.profileSubmittedAt?.toISOString() ?? null,
    };
  }

  // ── PATCH /me/profile — saglabā melnrakstu (tikai UNVERIFIED/REJECTED) ──
  @Patch('profile')
  async updateProfile(@Req() req: Request, @Body() body: UpdateProfileDto) {
    const session = req.session as AuthSession;
    const userId = session.userId!;

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { status: true },
    });

    if (!user || (user.status !== 'UNVERIFIED' && user.status !== 'REJECTED')) {
      throw new ForbiddenException({
        code: 'profile_locked',
        message: 'Profila dati ir bloķēti — izmantojiet labošanas pieprasījumu',
      });
    }

    const errors = validateProfileFields(body);
    if (errors.length > 0) {
      throw new BadRequestException({ code: 'validation_error', message: errors.join('; ') });
    }

    // PK unikāluma pārbaude caur blind index
    if (body.personalCode) {
      const hmac = blindIndex(body.personalCode.replace(/-/g, ''));
      const existing = await this.prisma.user.findUnique({ where: { idCodeHmac: hmac } });
      if (existing && existing.id !== userId) {
        throw new BadRequestException({
          code: 'personal_code_taken',
          message: 'Lietotājs ar šo personas kodu jau ir reģistrēts',
        });
      }
    }

    const data: Record<string, unknown> = {};
    if (body.firstName !== undefined) data.firstName = body.firstName;
    if (body.lastName !== undefined) data.lastName = body.lastName;
    if (body.dateOfBirth !== undefined) data.dateOfBirth = body.dateOfBirth;
    if (body.sex !== undefined) data.sex = body.sex;
    if (body.citizenship !== undefined) data.citizenship = body.citizenship;
    if (body.phone !== undefined) data.phone = body.phone;
    if (body.emailNotify !== undefined) data.emailNotify = body.emailNotify;
    if (body.smsNotify !== undefined) data.smsNotify = body.smsNotify;

    if (body.personalCode !== undefined) {
      if (body.personalCode) {
        const normalized = body.personalCode.replace(/-/g, '');
        data.personalCodeEnc = body.personalCode;
        data.idCodeHmac = blindIndex(normalized);
      } else {
        data.personalCodeEnc = null;
        data.idCodeHmac = null;
      }
    }

    if (Object.keys(data).length === 0) {
      return { ok: true, message: 'Nav izmaiņu' };
    }

    await this.prisma.user.update({ where: { id: userId }, data });

    await this.audit.write({
      rid: (req as any).rid ?? null,
      clientIp: req.ip ?? null,
      userAgent: req.headers['user-agent'] ?? null,
      subjectId: userId,
      subjectRole: session.userRole ?? null,
      action: 'profile.updated',
      result: 'Success',
      dataJson: { fields: Object.keys(data) },
    });

    return { ok: true, message: 'Profila dati saglabāti' };
  }

  // ── POST /me/profile/submit — iesniedz profilu pārbaudei ──
  @Post('profile/submit')
  async submitProfile(@Req() req: Request) {
    const session = req.session as AuthSession;
    const userId = session.userId!;

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { status: true, firstName: true, lastName: true },
    });

    if (!user || (user.status !== 'UNVERIFIED' && user.status !== 'REJECTED')) {
      throw new ForbiddenException({
        code: 'submit_not_allowed',
        message: 'Profila iesniegšana nav pieejama šajā statusā',
      });
    }

    if (!user.firstName?.trim() || !user.lastName?.trim()) {
      throw new BadRequestException({
        code: 'missing_required_fields',
        message: 'Vārds un uzvārds ir obligāti pirms iesniegšanas',
      });
    }

    await this.prisma.user.update({
      where: { id: userId },
      data: {
        status: 'PENDING_REVIEW',
        profileSubmittedAt: new Date(),
        rejectionReason: null,
      },
    });

    // Paziņojums visiem adminiem
    const displayName = `${user.firstName} ${user.lastName}`;
    await this.notifications.createForRole('ADMIN', {
      type: 'profile_submitted',
      title: 'Jauns profila pieteikums',
      description: `Lietotājs ${displayName} ir iesniedzis profilu pārbaudei`,
      actionUrl: '/admin/users',
      actionLabel: 'Pārskatīt',
    });

    await this.audit.write({
      rid: (req as any).rid ?? null,
      clientIp: req.ip ?? null,
      userAgent: req.headers['user-agent'] ?? null,
      subjectId: userId,
      subjectRole: session.userRole ?? null,
      action: 'profile.submitted',
      result: 'Success',
      dataJson: null,
    });

    return { ok: true, message: 'Profila dati iesniegti pārbaudei' };
  }

  // ── PATCH /me/notifications — preferences (pieejams visos statusos) ──
  @Patch('notifications')
  async updateNotifications(@Req() req: Request, @Body() body: UpdateNotificationsDto) {
    const session = req.session as AuthSession;
    const userId = session.userId!;

    const data: Record<string, boolean> = {};
    if (body.emailNotify !== undefined) data.emailNotify = body.emailNotify;
    if (body.smsNotify !== undefined) data.smsNotify = body.smsNotify;

    if (Object.keys(data).length === 0) {
      return { ok: true };
    }

    await this.prisma.user.update({ where: { id: userId }, data });

    return { ok: true };
  }
}

// ── DTO tipi ──

interface UpdateProfileDto {
  firstName?: string;
  lastName?: string;
  personalCode?: string | null;
  dateOfBirth?: string | null;
  birthPlace?: string | null;
  sex?: string | null;
  citizenship?: string | null;
  phone?: string | null;
  address?: string | null;
  emailNotify?: boolean;
  smsNotify?: boolean;
}

interface UpdateNotificationsDto {
  emailNotify?: boolean;
  smsNotify?: boolean;
}

// ── Validācija ──

function validateProfileFields(body: UpdateProfileDto): string[] {
  const errors: string[] = [];

  if (body.personalCode) {
    const normalized = body.personalCode.replace(/-/g, '');
    if (!/^\d{11}$/.test(normalized)) {
      errors.push('Personas kods: 11 cipari (formāts XXXXXX-XXXXX)');
    }
  }

  if (body.sex && !['M', 'F'].includes(body.sex)) {
    errors.push('Dzimums: M vai F');
  }

  if (body.dateOfBirth) {
    const d = new Date(body.dateOfBirth);
    if (isNaN(d.getTime()) || d.getFullYear() < 1920 || d > new Date()) {
      errors.push('Dzimšanas datums: nederīgs datums');
    }
  }

  if (body.phone) {
    const cleaned = body.phone.replace(/[\s()-]/g, '');
    if (!/^\+?\d{7,15}$/.test(cleaned)) {
      errors.push('Tālrunis: nederīgs formāts');
    }
  }

  if (body.address && body.address.length > 200) {
    errors.push('Adrese: maksimums 200 simboli');
  }

  if (body.firstName && body.firstName.length > 64) {
    errors.push('Vārds: maksimums 64 simboli');
  }

  if (body.lastName && body.lastName.length > 64) {
    errors.push('Uzvārds: maksimums 64 simboli');
  }

  return errors;
}

// ── Palīgfunkcijas ──

/** Maskē personas kodu: 123456-12345 → ******-12345 */
function maskPersonalCode(code: string): string {
  const normalized = code.replace(/-/g, '');
  if (normalized.length !== 11) return '******-*****';
  return `******-${normalized.slice(6)}`;
}
