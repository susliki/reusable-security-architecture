/*
Identitātes verifikācijas endpointi — dokumentu (pase, ID karte, selfie) augšupielāde un statuss.
Lietotājs augšupielādē dokumentus, admins pārskata un apstiprina vai noraida.
Faili iet caur ClamAV skenēšanu; 10 MB limits; aizsargāts ar AuthGuard/AdminGuard.
*/

import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Req,
  UploadedFile,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import type { Request } from 'express';
import type { AuthSession } from '../common/session.types';
import type { RequestCtx } from '../auth/auth.service';
import { AuthGuard } from '../common/auth.guard';
import { AdminGuard } from '../common/admin.guard';
import { VerificationService } from './verification.service';

// 10 MB limits dokumentu augšupielādei
const MAX_FILE_SIZE = 10 * 1024 * 1024;

@Controller('verification')
export class VerificationController {
  constructor(private readonly verificationService: VerificationService) {}

  /*
  Dokumenta augšupielāde — lietotājs pats augšupielādē savu dokumentu
  */

  @Post('upload')
  @HttpCode(HttpStatus.CREATED)
  @UseGuards(AuthGuard)
  @UseInterceptors(FileInterceptor('file', { limits: { fileSize: MAX_FILE_SIZE } }))
  async upload(
    @UploadedFile() file: Express.Multer.File,
    @Body('type') type: string,
    @Req() req: Request,
  ) {
    if (!file) {
      throw new BadRequestException({
        code: 'file_required',
        message: 'Fails ir obligāts',
      });
    }

    if (!type) {
      throw new BadRequestException({
        code: 'type_required',
        message: 'Dokumenta tips ir obligāts',
      });
    }

    const session = req.session as AuthSession;
    return this.verificationService.uploadDocument(
      session.userId!,
      file,
      type,
      this.extractCtx(req),
    );
  }

  /*
  Verifikācijas statuss — lietotājs redz savu statusu
  */

  @Get('status')
  @UseGuards(AuthGuard)
  async status(@Req() req: Request) {
    const session = req.session as AuthSession;
    return this.verificationService.getStatus(session.userId!);
  }

  /*
  Verifikācijas pārskatīšana — admins apstiprina vai noraida
  */

  @Post(':userId/review')
  @HttpCode(HttpStatus.OK)
  @UseGuards(AuthGuard, AdminGuard)
  async review(
    @Param('userId') userId: string,
    @Body() body: { decision: 'APPROVED' | 'REJECTED'; reason?: string },
    @Req() req: Request,
  ) {
    if (!body.decision || !['APPROVED', 'REJECTED'].includes(body.decision)) {
      throw new BadRequestException({
        code: 'invalid_decision',
        message: 'Lēmumam jābūt APPROVED vai REJECTED',
      });
    }

    const session = req.session as AuthSession;
    return this.verificationService.reviewVerification(
      userId,
      body.decision,
      body.reason ?? null,
      session.userId!,
      this.extractCtx(req),
    );
  }

  // Palīgmetode — konteksta izgūšana no pieprasījuma
  private extractCtx(req: Request): RequestCtx {
    return {
      rid: req.headers['x-request-id'] as string ?? null,
      clientIp: req.ip ?? null,
      userAgent: req.headers['user-agent'] ?? null,
      subjectId: (req.session as AuthSession)?.userId ?? null,
      subjectRole: (req.session as AuthSession)?.userRole ?? null,
    };
  }
}
