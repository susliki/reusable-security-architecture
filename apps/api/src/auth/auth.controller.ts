/*
Autentifikācijas REST endpointi — passkey (WebAuthn), TOTP, OIDC (Microsoft Entra), reģistrācija ar magic-link.
H3 — sesijas userId tiek piešķirts tikai pēc pilnas MFA verifikācijas, lai novērstu daļēji autentificētu piekļuvi.
OWASP ASVS v5 V2 (autentifikācija), V3 (sesijas).
*/

import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Logger,
  UnauthorizedException,
  HttpCode,
  HttpStatus,
  Post,
  Query,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { AuthService, RequestCtx } from './auth.service';
import { PasskeyRegisterVerifyDto } from './dto/passkey-register-verify.dto';
import { PasskeyAuthOptionsDto } from './dto/passkey-auth-options.dto';
import { PasskeyAuthVerifyDto } from './dto/passkey-auth-verify.dto';
import { TotpVerifyDto } from './dto/totp-verify.dto';
import { RegisterDto } from './dto/register.dto';
import { CheckEmailDto } from './dto/check-email.dto';
import { TotpSetupInitDto, TotpSetupVerifyDto } from './dto/totp-setup.dto';
import { OidcCallbackDto } from './dto/oidc-callback.dto';
import { AuthGuard } from '../common/auth.guard';
import type { AuthSession } from '../common/session.types';
import type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
} from '@simplewebauthn/server';

const SESSION_COOKIE_NAME = process.env.SESSION_COOKIE_NAME ?? 'sid';

function extractCtx(req: Request): RequestCtx {
  return {
    rid: (req as Request & { requestId?: string }).requestId ?? null,
    clientIp: req.ip ?? null,
    userAgent: req.headers['user-agent'] ?? null,
    subjectId: (req.session as AuthSession)?.userId ?? null,
    subjectRole: (req.session as AuthSession)?.userRole ?? null,
  };
}

@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);
  constructor(private readonly authService: AuthService) {}

  /*
  E-pasta pārbaude — pirms autentifikācijas nosaka pieejamās metodes
  */

  @Post('check-email')
  @HttpCode(HttpStatus.OK)
  async checkEmail(@Body() dto: CheckEmailDto) {
    return this.authService.checkEmail(dto.email);
  }

  /*
  Passkeys (WebAuthn)
  */

  // C1 fix: tikai autentificēti lietotāji var reģistrēt passkey
  @UseGuards(AuthGuard)
  @Post('webauthn/register/options')
  async webauthnRegisterOptions(@Req() req: Request) {
    const userId = (req.session as AuthSession).userId!;
    return this.authService.passkeyRegisterOptions(
      userId,
      req.session as AuthSession,
    );
  }

  @Post('webauthn/register/verify')
  @HttpCode(HttpStatus.NO_CONTENT)
  @UseGuards(AuthGuard)
  async webauthnRegisterVerify(
    @Body() dto: PasskeyRegisterVerifyDto,
    @Req() req: Request,
  ) {
    const session = req.session as AuthSession;
    await this.authService.passkeyRegisterVerify(
      session.userId!,
      dto as unknown as RegistrationResponseJSON,
      session,
      extractCtx(req),
    );
  }

  @Post('webauthn/auth/options')
  async webauthnAuthOptions(
    @Body() dto: PasskeyAuthOptionsDto,
    @Req() req: Request,
  ) {
    return this.authService.passkeyAuthOptions(
      dto.email,
      req.session as AuthSession,
    );
  }

  @Post('webauthn/auth/verify')
  @HttpCode(HttpStatus.NO_CONTENT)
  async webauthnAuthVerify(
    @Body() dto: PasskeyAuthVerifyDto,
    @Req() req: Request,
  ) {
    await this.authService.passkeyAuthVerify(
      dto as unknown as AuthenticationResponseJSON,
      req,
      extractCtx(req),
    );
  }

  /*
  Fallback (TOTP)
  */

  @Post('totp/setup')
  @UseGuards(AuthGuard)
  async totpSetup(@Req() req: Request) {
    return this.authService.totpSetup(
      (req.session as AuthSession).userId!,
      extractCtx(req),
    );
  }

  @Post('totp/verify')
  @HttpCode(HttpStatus.NO_CONTENT)
  async totpVerify(@Body() dto: TotpVerifyDto, @Req() req: Request) {
    const session = req.session as AuthSession;
    /*
    H3 — nepiešķir session.userId pirms TOTP pārbaudes — pretējā gadījumā
    neveiksmīgs verify atstātu "pusautentificētu" sesiju ar userId, bet bez
    pareizas sesijas izveides. Lokāls mainīgais — session tiek atsvaidzināts
    tikai pēc veiksmīgas verifikācijas establishAuthenticatedSession() iekšienē.
    */
    let userId = session.userId;
    if (!userId) {
      if (!dto.email) {
        throw new BadRequestException({
          code: 'user_context_required',
          message: 'User context is required for TOTP verification',
        });
      }
      // C5 — neļaujam izveidot lietotāju caur TOTP verify
      const user = await this.authService.findUserByEmail(dto.email);
      if (!user) {
        throw new UnauthorizedException({
          code: 'user_not_found',
          message: 'Lietotājs nav atrasts',
        });
      }
      userId = user.id;
    }
    await this.authService.totpVerifyAndLogin(
      userId,
      dto.code,
      req,
      extractCtx(req),
    );
  }

  /*
  Reģistrācija + e-pasta verifikācija + TOTP iestatīšana
  */

  @Post('register')
  @HttpCode(HttpStatus.OK)
  async register(@Body() dto: RegisterDto, @Req() req: Request) {
    return this.authService.register(dto, extractCtx(req));
  }

  @Get('verify-email')
  async verifyEmail(
    @Query('token') token: string,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    const portalUrl = process.env.PORTAL_URL ?? 'http://localhost:5173';

    if (!token) {
      res.redirect(302, `${portalUrl}/auth/register?error=expired`);
      return;
    }

    try {
      const result = await this.authService.verifyEmail(token, extractCtx(req));
      res.redirect(
        302,
        `${result.portalUrl}/auth/setup-totp?token=${result.setupToken}`,
      );
    } catch {
      res.redirect(302, `${portalUrl}/auth/register?error=expired`);
    }
  }

  @Post('totp/setup-init')
  @HttpCode(HttpStatus.OK)
  async totpSetupInit(@Body() dto: TotpSetupInitDto, @Req() req: Request) {
    return this.authService.totpSetupInit(dto.setupToken, extractCtx(req));
  }

  @Post('totp/setup-verify')
  @HttpCode(HttpStatus.OK)
  async totpSetupVerify(@Body() dto: TotpSetupVerifyDto, @Req() req: Request) {
    return this.authService.totpSetupVerify(
      dto.setupToken,
      dto.code,
      extractCtx(req),
    );
  }

  /*
  Iekšējais OIDC (Entra)
  */

  @Get('oidc/start')
  async oidcStart(@Req() req: Request, @Res() res: Response) {
    const url = await this.authService.oidcStart(req.session as AuthSession);
    req.session.save((err) => {
      if (err) {
        res.status(500).json({ code: 'session_error', message: 'Failed to save session' });
        return;
      }
      res.redirect(302, url);
    });
  }

  @Get('oidc/callback')
  async oidcCallback(
  @Query() dto: OidcCallbackDto,
  @Req() req: Request,
  @Res() res: Response,
  ) {
  await this.authService.oidcCallback(
    { code: dto.code, state: dto.state },
    req,
    extractCtx(req),
  );

  // Sesiju jāsaglabā PIRMS redirect — citādi PostgreSQL store nav paspējis ierakstīt
  await new Promise<void>((resolve, reject) => {
    req.session.save((err) => (err ? reject(err) : resolve()));
  });

  const portalUrl = process.env.PORTAL_URL ?? 'http://localhost:5173';
  res.redirect(302, portalUrl);
  }

  /*
  Step-up re-auth — sensitīvām darbībām (KI-08)
  */

  @UseGuards(AuthGuard)
  @Post('step-up/verify')
  @HttpCode(HttpStatus.OK)
  async stepUpVerify(
    @Body() dto: { method: 'totp'; code: string },
    @Req() req: Request,
  ) {
    const session = req.session as AuthSession;
    const userId = session.userId!;

    if (dto.method !== 'totp') {
      throw new BadRequestException({ code: 'invalid_method', message: 'Neatbalstīta metode' });
    }
    if (!dto.code) {
      throw new BadRequestException({ code: 'missing_code', message: 'Kods ir obligāts' });
    }

    const verified = await this.authService.stepUpVerifyTotp(
      userId,
      dto.code,
      extractCtx(req),
    );
    if (!verified) {
      throw new UnauthorizedException({ code: 'invalid_code', message: 'Nepareizs kods' });
    }

    session.stepUpVerifiedAt = new Date().toISOString();
    await new Promise<void>((resolve, reject) => {
      req.session.save((err: unknown) => (err ? reject(err) : resolve()));
    });

    return { ok: true };
  }

  /*
  Logout
  */

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const session = req.session as AuthSession;
    if (session?.userId) {
      // Pilns logout ceļš — audit ieraksts + sesiju indeksa tīrīšana + destroy
      await this.authService.logout(session, extractCtx(req));
    } else if (req.session) {
      /*
      L4 — orphan sesija (bez userId) joprojām jāiznīcina serverī, nevis tikai
      jānotīra cookie. Iepriekš šādas sesijas palika Redis līdz TTL beigām,
      ļaujot potenciāli pārtvert sesiju identifikatoram, ja cookie jau
      nokopēts (piemēram, pirms-auth CSRF state).
      R5 — reģistrē destroy kļūdu brīdinājumā, lai infrastruktūras problēmas
      (piemēram, Redis nepieejams) būtu redzamas log agregatorā.
      */
      await new Promise<void>((resolve) => {
        req.session.destroy((err: unknown) => {
          if (err) {
            this.logger.warn(
              `[AUTH] orphan session destroy failed: ${err instanceof Error ? err.message : String(err)}`,
            );
          }
          resolve();
        });
      });
    }
    res.clearCookie(SESSION_COOKIE_NAME);
    return { ok: true };
  }
}
