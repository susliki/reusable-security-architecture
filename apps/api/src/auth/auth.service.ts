/*
Autentifikācijas serviss — passkey (WebAuthn), TOTP un OIDC (Microsoft Entra) plūsmas.
Reģistrācija caur magic-link e-pastu, PII (personas kods) šifrēts ar AES-256-GCM Redis pagaidu glabātuvē.
H2 + R3 — atšifrēšana tikai pēc verifikācijas; H3 — neatklāj pieejamās MFA metodes pirms pareizas paroles, lai novērstu konta fingerprinting.
OWASP ASVS v5 V2 (autentifikācija), V3 (sesijas), V6 (kriptogrāfija); GDPR 32. pants.
*/

import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'crypto';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture,
  WebAuthnCredential,
} from '@simplewebauthn/server';
import { generateSecret, verify as totpVerify_, generateURI } from 'otplib';
import type { Role } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { AuditService } from '../audit/audit.service';
import { RedisService } from '../redis/redis.service';
import { EmailService } from '../email/email.service';
import { emailVerificationEmail } from '../notifications/templates/email-verification.template';
import type { AuthSession } from '../common/session.types';
import type { RegisterDto } from './dto/register.dto';
import { encryptField, decryptField } from '../crypto/pii-crypto';
import { SessionLifecycleService } from '../session-lifecycle/session-lifecycle.service';

export interface RequestCtx {
  rid?: string | null;
  clientIp?: string | null;
  userAgent?: string | null;
  subjectId?: string | null;
  subjectRole?: string | null;
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    private readonly redis: RedisService,
    private readonly email: EmailService,
    private readonly sessionLifecycle: SessionLifecycleService,
  ) {}

  // Sesiju dzīves cikla loģika delegēta uz SessionLifecycleService

  private rpName(): string {
    return process.env.WEBAUTHN_RP_NAME ?? 'Jurnieks';
  }

  private badRequest(code: string, message: string): never {
    throw new BadRequestException({ code, message });
  }

  private unauthorized(code: string, message: string): never {
    throw new UnauthorizedException({ code, message });
  }

  private rpId(): string {
    return process.env.WEBAUTHN_RP_ID ?? 'localhost';
  }

  private origin(): string | string[] {
    const o = process.env.WEBAUTHN_ORIGIN;
    if (!o) return ['http://localhost:5173', 'http://localhost:3000'];
    return o.includes(',') ? o.split(',').map((s) => s.trim()) : o;
  }

  /*
  Passkey — reģistrācija
  */

  async passkeyRegisterOptions(userId: string, session: AuthSession) {
    const user = await this.prisma.user.findUniqueOrThrow({
      where: { id: userId },
      include: {
        identities: {
          where: { provider: 'PASSKEY' },
          include: { passkey: true },
        },
      },
    });

    const existingCredentials = user.identities
      .filter((i) => i.passkey)
      .map((i) => ({
        id: i.passkey!.credentialId,
        transports: i.passkey!.transports as AuthenticatorTransportFuture[],
      }));

    const opts = await generateRegistrationOptions({
      rpName: this.rpName(),
      rpID: this.rpId(),
      userName: user.email ?? user.id,
      userDisplayName: [user.firstName, user.lastName].filter(Boolean).join(' ') || user.email || user.id,
      excludeCredentials: existingCredentials,
      authenticatorSelection: {
        residentKey: 'preferred',
        // M3: prasām biometriju vai PIN autentifikatora līmenī — bez tā passkey
        // nav īsts otrais faktors, bet tikai "kaut kas, kas jums ir"
        userVerification: 'required',
      },
    });

    session.passkeyRegChallenge = opts.challenge;
    return opts;
  }

  async passkeyRegisterVerify(
    userId: string,
    body: RegistrationResponseJSON,
    session: AuthSession,
    ctx: RequestCtx,
  ): Promise<void> {
    const challenge = session.passkeyRegChallenge;
    session.passkeyRegChallenge = null; // notīrām pirms verify (replay aizsardzība)

    if (!challenge) {
      this.badRequest('no_challenge', 'No active challenge in session');
    }

    let verification: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
    try {
      verification = await verifyRegistrationResponse({
        response: body,
        expectedChallenge: challenge,
        expectedOrigin: this.origin(),
        expectedRPID: this.rpId(),
        /*
        M3 — passkey reģistrācijas laikā prasām UV: ierakstītajam kredenciālam
        jābūt biometrijas vai PIN aizsargātam, lai login plūsmā tas būtu
        īsts otrais faktors.
        */
        requireUserVerification: true,
      });
    } catch {
      await this.audit.write({
        ...ctx,
        action: 'auth.webauthn.register',
        result: 'Denied',
        subjectId: userId,
        dataJson: { reason: 'verify_error' },
      });
      this.unauthorized(
        'verification_failed',
        'Passkey verification failed',
      );
    }

    if (!verification.verified || !verification.registrationInfo) {
      await this.audit.write({
        ...ctx,
        action: 'auth.webauthn.register',
        result: 'Denied',
        subjectId: userId,
        dataJson: { reason: 'not_verified' },
      });
      this.unauthorized(
        'verification_failed',
        'Passkey verification failed',
      );
    }

    const { credential, userVerified } = verification.registrationInfo;

    await this.prisma.$transaction(async (tx) => {
      const identity = await tx.identity.create({
        data: {
          provider: 'PASSKEY',
          providerId: credential.id,
          userId,
        },
      });

      await tx.passkeyCredential.create({
        data: {
          identityId: identity.id,
          credentialId: credential.id,
          publicKey: Buffer.from(credential.publicKey).toString('base64url'),
          counter: BigInt(credential.counter),
          transports: (credential.transports ?? []) as string[],
          uvInitialized: userVerified,
        },
      });
    });

    await this.audit.write({
      ...ctx,
      action: 'auth.webauthn.register',
      result: 'Success',
      subjectId: userId,
      entityType: 'PasskeyCredential',
      entityId: credential.id,
    });
  }

  /*
  Passkey — autentifikācija
  */

  async passkeyAuthOptions(email: string | undefined, session: AuthSession) {
    let allowCredentials: {
      id: string;
      transports: AuthenticatorTransportFuture[];
    }[] = [];

    if (email) {
      const user = await this.prisma.user.findUnique({
        where: { email },
        include: {
          identities: {
            where: { provider: 'PASSKEY' },
            include: { passkey: true },
          },
        },
      });
      if (user) {
        allowCredentials = user.identities
          .filter((i) => i.passkey)
          .map((i) => ({
            id: i.passkey!.credentialId,
            transports: i.passkey!.transports as AuthenticatorTransportFuture[],
          }));
      }
    }

    const opts = await generateAuthenticationOptions({
      rpID: this.rpId(),
      allowCredentials,
      // M3: login laikā arī prasām biometriju/PIN — reģistrācijas laikā jau bija
      // iestatīts `required`, tāpēc visi kredenciāli ir UV-capable
      userVerification: 'required',
    });

    session.passkeyAuthChallenge = opts.challenge;
    return opts;
  }

  async passkeyAuthVerify(
    body: AuthenticationResponseJSON,
    req: any,
    ctx: RequestCtx,
  ): Promise<void> {
    const session = req.session as AuthSession;
    const challenge = session.passkeyAuthChallenge;
    session.passkeyAuthChallenge = null; // notīrām pirms verify (replay aizsardzība)

    if (!challenge) {
      this.badRequest('no_challenge', 'No active challenge in session');
    }

    const passkeyCredential = await this.prisma.passkeyCredential.findUnique({
      where: { credentialId: body.id },
      include: { identity: { include: { user: true } } },
    });

    if (!passkeyCredential) {
      await this.audit.write({
        ...ctx,
        action: 'auth.webauthn.auth',
        result: 'Denied',
        dataJson: { reason: 'credential_not_found' },
      });
      this.unauthorized('credential_not_found', 'Credential was not found');
    }

    const webAuthnCred: WebAuthnCredential = {
      id: passkeyCredential.credentialId,
      publicKey: Buffer.from(passkeyCredential.publicKey, 'base64url'),
      counter: Number(passkeyCredential.counter),
      transports:
        passkeyCredential.transports as AuthenticatorTransportFuture[],
    };

    let verification: Awaited<ReturnType<typeof verifyAuthenticationResponse>>;
    try {
      verification = await verifyAuthenticationResponse({
        response: body,
        expectedChallenge: challenge,
        expectedOrigin: this.origin(),
        expectedRPID: this.rpId(),
        credential: webAuthnCred,
        // M3: login pieprasa UV rezultātu assertion flagos
        requireUserVerification: true,
      });
    } catch {
      await this.audit.write({
        ...ctx,
        action: 'auth.webauthn.auth',
        result: 'Denied',
        subjectId: passkeyCredential.identity.userId,
        dataJson: { reason: 'verify_error' },
      });
      this.unauthorized(
        'verification_failed',
        'Passkey verification failed',
      );
    }

    if (!verification.verified) {
      await this.audit.write({
        ...ctx,
        action: 'auth.webauthn.auth',
        result: 'Denied',
        subjectId: passkeyCredential.identity.userId,
        dataJson: { reason: 'not_verified' },
      });
      this.unauthorized(
        'verification_failed',
        'Passkey verification failed',
      );
    }

    const { newCounter } = verification.authenticationInfo;
    const storedCounter = Number(passkeyCredential.counter);

    if (storedCounter > 0 && newCounter <= storedCounter) {
      await this.audit.write({
        ...ctx,
        action: 'auth.webauthn.auth',
        result: 'Denied',
        subjectId: passkeyCredential.identity.userId,
        dataJson: { reason: 'counter_regression', storedCounter, newCounter },
      });
      this.unauthorized(
        'counter_regression',
        'Authenticator counter regression detected',
      );
    }

    await this.prisma.passkeyCredential.update({
      where: { id: passkeyCredential.id },
      data: { counter: BigInt(newCounter), lastUsedAt: new Date() },
    });

    // Ielādē lietotāju caur User modeli — nodrošina PII atšifrēšanu
    const user = await this.prisma.user.findUniqueOrThrow({
      where: { id: passkeyCredential.identity.userId },
    });
    await this.audit.write({
      ...ctx,
      action: 'auth.webauthn.auth',
      result: 'Success',
      subjectId: user.id,
      subjectRole: user.role,
      entityType: 'PasskeyCredential',
      entityId: passkeyCredential.credentialId,
    });

    await this.sessionLifecycle.establishAuthenticatedSession({
      req, userId: user.id, role: user.role,
      firstName: user.firstName, lastName: user.lastName,
      clientIp: ctx?.clientIp, userAgent: ctx?.userAgent,
    });
  }

  /*
  TOTP
  */

  async totpSetup(
    userId: string,
    ctx: RequestCtx,
  ): Promise<{ otpauthUrl: string }> {
    const user = await this.prisma.user.findUniqueOrThrow({
      where: { id: userId },
    });

    const secret = generateSecret();
    const issuer = process.env.TOTP_ISSUER ?? 'Jurnieks';
    const otpauthUrl = generateURI({
      issuer,
      label: user.email ?? userId,
      secret,
    });
    const encryptedSecret = this.encryptTotpSecret(secret);

    await this.prisma.identity.upsert({
      where: { provider_providerId: { provider: 'TOTP', providerId: userId } },
      create: {
        provider: 'TOTP',
        providerId: userId,
        userId,
        secret: encryptedSecret,
      },
      update: { secret: encryptedSecret },
    });

    await this.audit.write({
      ...ctx,
      action: 'auth.totp.setup',
      result: 'Success',
      subjectId: userId,
    });

    return { otpauthUrl };
  }

  async totpVerifyAndLogin(
    userId: string,
    code: string,
    req: any,
    ctx: RequestCtx,
  ): Promise<void> {
    // Meklē pēc userId + provider — drošāk nekā pēc providerId, kas var būt tukšs pēc reģistrācijas
    const identity = await this.prisma.identity.findFirst({
      where: { userId, provider: 'TOTP' },
      include: { user: true },
    });

    if (!identity?.secret) {
      this.unauthorized(
        'totp_not_configured',
        'TOTP is not configured for this account',
      );
    }

    // TOTP atkārtošanas aizsardzība — Redis (darbojas multi-instance)
    const replayKey = `totp:replay:${userId}:${code}`;
    const alreadyUsed = await this.redis.get(replayKey);
    if (alreadyUsed) {
      await this.audit.write({
        ...ctx,
        action: 'auth.totp.verify',
        result: 'Denied',
        subjectId: userId,
        dataJson: { reason: 'replay' },
      });
      this.unauthorized('totp_invalid', 'Invalid verification code');
    }

    const plainSecret = this.decryptTotpSecret(identity.secret);
    // otplib v13 atgriež { valid: boolean }, nevis boolean
    const result = await totpVerify_({ token: code, secret: plainSecret });
    const valid = typeof result === 'object' && result !== null ? (result as { valid: boolean }).valid : !!result;

    if (!valid) {
      await this.audit.write({
        ...ctx,
        action: 'auth.totp.verify',
        result: 'Denied',
        subjectId: userId,
        dataJson: { reason: 'invalid_code' },
      });
      this.unauthorized('totp_invalid', 'Invalid verification code');
    }

    // R8: atzīmē kodu kā izmantotu — 90s TTL (pārklāj ±1 TOTP soli)
    await this.redis.set(replayKey, '1', 90);

    // Ielādē lietotāju caur User modeli — nodrošina PII atšifrēšanu
    const user = await this.prisma.user.findUniqueOrThrow({
      where: { id: identity.userId },
    });
    await this.audit.write({
      ...ctx,
      action: 'auth.totp.verify',
      result: 'Success',
      subjectId: user.id,
      subjectRole: user.role,
    });

    await this.sessionLifecycle.establishAuthenticatedSession({
      req, userId: user.id, role: user.role,
      firstName: user.firstName, lastName: user.lastName,
      clientIp: ctx?.clientIp, userAgent: ctx?.userAgent,
    });
  }


  // TOTP šifrēšana — publiska lai user-security kontroleris var izmantot atiestatīšanā
  encryptTotpSecret(plaintext: string): string {
    const key = this.getTotpEncryptionKey();
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, tag, encrypted]).toString('base64url');
  }

  private decryptTotpSecret(ciphertext: string): string {
    const key = this.getTotpEncryptionKey();
    const buf = Buffer.from(ciphertext, 'base64url');
    const iv = buf.subarray(0, 12);
    const tag = buf.subarray(12, 28);
    const encrypted = buf.subarray(28);
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    return decipher.update(encrypted).toString('utf8') + decipher.final('utf8');
  }

  private getTotpEncryptionKey(): Buffer {
    const hex = process.env.TOTP_ENCRYPTION_KEY ?? '';
    if (hex.length !== 64) {
      throw new Error(
        'TOTP_ENCRYPTION_KEY must be a 32-byte hex string (64 chars)',
      );
    }
    return Buffer.from(hex, 'hex');
  }

  /*
  M2 + R4 — step-up TOTP verifikācija ar audit: neveiksmīgie mēģinājumi
  reģistrēti ar Denied statusu un atšķirīgu iemeslu (replay vs invalid_code
  vs not_configured), lai operatori var atšķirt uzbrukumus no lietotāja
  kļūdām (salīdzinot ar totpVerifyAndLogin login plūsmu).
  */
  async stepUpVerifyTotp(
    userId: string,
    code: string,
    ctx: RequestCtx,
  ): Promise<boolean> {
    const result = await this.verifyTotpCode(userId, code);
    await this.audit.write({
      ...ctx,
      action: 'auth.stepup.verify',
      result: result.ok ? 'Success' : 'Denied',
      subjectId: userId,
      dataJson: result.ok ? null : { reason: result.reason },
    });
    return result.ok;
  }

  // Step-up: TOTP koda verifikācija (bez sesijas izveides).
  // R4: tagad atgriež tagged result, lai izsaucējs var reģistrēt audit iemeslu
  async verifyTotpCode(
    userId: string,
    code: string,
  ): Promise<
    | { ok: true }
    | { ok: false; reason: 'replay' | 'invalid_code' | 'not_configured' }
  > {
    /*
    M1 — replay aizsardzība: tāda pati Redis atslēgu shēma kā login plūsmā
    (totpVerifyAndLogin). Iepriekš step-up pieļāva viena koda izmantošanu
    vairākkārt 30s logā, ļaujot jebkuram novērotājam pārspēlēt sensitīvu
    darbību atļauju.
    */
    const replayKey = `totp:replay:${userId}:${code}`;
    if (await this.redis.get(replayKey)) return { ok: false, reason: 'replay' };

    const identity = await this.prisma.identity.findFirst({
      where: { userId, provider: 'TOTP' },
    });
    if (!identity?.secret) return { ok: false, reason: 'not_configured' };

    const plainSecret = this.decryptTotpSecret(identity.secret);
    const otpResult = await totpVerify_({ token: code, secret: plainSecret });
    const valid =
      typeof otpResult === 'object' && otpResult !== null
        ? (otpResult as { valid: boolean }).valid
        : !!otpResult;

    if (!valid) return { ok: false, reason: 'invalid_code' };

    // R8: TTL 90s — pārklāj ±1 TOTP soli (iepriekš 30s, īsāks par verify logu)
    await this.redis.set(replayKey, '1', 90);
    return { ok: true };
  }

  /*
  OIDC (Entra)
  */

  async oidcStart(session: AuthSession): Promise<string> {
    const { discovery, randomState, randomNonce, buildAuthorizationUrl } =
      await import('openid-client');

    const issuerUrl = process.env.OIDC_ISSUER;
    if (!issuerUrl) {
      this.badRequest('oidc_not_configured', 'OIDC is not configured');
    }

    const config = await discovery(
      new URL(issuerUrl),
      process.env.OIDC_CLIENT_ID!,
      process.env.OIDC_CLIENT_SECRET,
    );

    const state = randomState();
    const nonce = randomNonce();
    session.oidcState = state;
    session.oidcNonce = nonce;

    const redirectUrl = buildAuthorizationUrl(config, {
      redirect_uri: process.env.OIDC_REDIRECT_URI!,
      scope: 'openid profile email',
      state,
      nonce,
    });

    return redirectUrl.toString();
  }

  async oidcCallback(
    params: { code: string; state: string },
    req: any,
    ctx: RequestCtx,
  ): Promise<void> {
    const session = req.session as AuthSession;
    const expectedState = session.oidcState;
    const expectedNonce = session.oidcNonce;
    // Notīrām pirms apstrādes — replay aizsardzība
    session.oidcState = null;
    session.oidcNonce = null;

    if (!expectedState || !expectedNonce) {
      this.badRequest('no_oidc_state', 'OIDC state was not initialized');
    }

    const { discovery, authorizationCodeGrant } = await import('openid-client');

    const issuerUrl = process.env.OIDC_ISSUER;
    if (!issuerUrl) {
      this.badRequest('oidc_not_configured', 'OIDC is not configured');
    }

    const config = await discovery(
      new URL(issuerUrl),
      process.env.OIDC_CLIENT_ID!,
      process.env.OIDC_CLIENT_SECRET,
    );

    // Atjaunojam callback URL no konfigurētā redirect URI un saņemtajiem parametriem
    const callbackUrl = new URL(process.env.OIDC_REDIRECT_URI!);
    callbackUrl.searchParams.set('code', params.code);
    callbackUrl.searchParams.set('state', params.state);

    const tokens = await authorizationCodeGrant(config, callbackUrl, {
      expectedState,
      expectedNonce,
    });

    const claims = tokens.claims();
    if (!claims) {
      this.unauthorized('no_claims', 'OIDC claims were not present');
    }

    const sub = claims.sub;
    const email = (claims.email as string | undefined) ?? undefined;
    const claimName = (claims.name as string | undefined) ?? undefined;
    // OIDC claims.name ir pilns vārds — sadalām pēc pirmā atstarpes
    const firstName = claimName?.includes(' ') ? claimName.split(' ')[0] : claimName;
    const lastName = claimName?.includes(' ') ? claimName.substring(claimName.indexOf(' ') + 1) : undefined;
    const appRoles: string[] = (claims['roles'] as string[]) ?? [];
    const { role: systemRole, entraRole } = this.mapEntraRole(appRoles);

    // Audit brīdinājums ja vairākas lomas
    if (appRoles.filter((r) => this.VALID_ENTRA_ROLES.includes(r)).length > 1) {
      await this.audit.write({
        ...ctx,
        action: 'auth.oidc.multiple_roles',
        result: 'Success',
        dataJson: { assignedRoles: appRoles.filter((r) => this.VALID_ENTRA_ROLES.includes(r)), selectedRole: entraRole },
      });
    }

    let identity: { userId: string; user: { id: string; role: string; firstName: string | null; lastName: string | null } };

    try {
      identity = await this.prisma.identity.upsert({
        where: { provider_providerId: { provider: 'ENTRA', providerId: sub } },
        create: {
          provider: 'ENTRA',
          providerId: sub,
          user: {
            create: {
              email,
              firstName,
              lastName,
              role: systemRole,
              entraRole,
              status: 'VERIFIED',
              verificationMethod: 'ENTRA_OIDC',
            },
          },
        },
        update: {
          user: {
            update: {
              ...(email ? { email } : {}),
              ...(firstName ? { firstName } : {}),
              ...(lastName ? { lastName } : {}),
              role: systemRole,
              entraRole,
              status: 'VERIFIED',
              verificationMethod: 'ENTRA_OIDC',
            },
          },
        },
        include: { user: true },
      });
    } catch (err: any) {
      // Šifrēts providerId — vecais Identity ieraksts nav atrodams, upsert mēģina izveidot
      // jaunu User, bet e-pasts jau eksistē (P2002 unique constraint)
      if (err?.code === 'P2002') {
        const existingUser = await this.prisma.user.findUnique({ where: { email } });
        if (!existingUser) throw err;

        // Atjaunina esošo lietotāju un izveido jaunu Identity ar plaintext providerId
        await this.prisma.user.update({
          where: { id: existingUser.id },
          data: {
            ...(firstName ? { firstName } : {}),
            ...(lastName ? { lastName } : {}),
            role: systemRole,
            entraRole,
            status: 'VERIFIED',
            verificationMethod: 'ENTRA_OIDC',
          },
        });

        // Dzēš vecos šifrētos Identity ierakstus šim lietotājam (ENTRA)
        await this.prisma.identity.deleteMany({
          where: { userId: existingUser.id, provider: 'ENTRA' },
        });

        // Izveido jaunu Identity ar plaintext sub
        await this.prisma.identity.create({
          data: { provider: 'ENTRA', providerId: sub, userId: existingUser.id },
        });

        identity = { userId: existingUser.id, user: existingUser as any };
        this.logger.warn(`[AUTH] OIDC: migrēts šifrēts Identity ieraksts lietotājam ${existingUser.id}`);
      } else {
        throw err;
      }
    }

    await this.audit.write({
      ...ctx,
      action: 'auth.oidc.callback',
      result: 'Success',
      subjectId: identity.userId,
      subjectRole: systemRole,
    });

    await this.sessionLifecycle.establishAuthenticatedSession({
      req, userId: identity.userId, role: systemRole,
      firstName, lastName,
      clientIp: ctx?.clientIp, userAgent: ctx?.userAgent,
    });
  }

  // A.13: validētas Entra lomas ar prioritāti
  private readonly VALID_ENTRA_ROLES = ['superadmin', 'user_admin', 'sd_inspector', 'kud_inspector'];
  private readonly ENTRA_ROLE_PRIORITY = ['superadmin', 'user_admin', 'sd_inspector', 'kud_inspector'];

  private mapEntraRole(tokenRoles: string[]): { role: Role; entraRole: string } {
    const valid = tokenRoles.filter((r) => this.VALID_ENTRA_ROLES.includes(r));

    if (valid.length === 0) {
      throw new ForbiddenException({
        code: 'no_entra_role',
        message: 'Nav piešķirta lietotāja loma Entra',
      });
    }

    // Vairākas lomas — augstākā prioritāte uzvar
    const entraRole = this.ENTRA_ROLE_PRIORITY.find((r) => valid.includes(r))!;
    const dbRole = ['superadmin', 'user_admin'].includes(entraRole) ? 'ADMIN' : 'OPERATOR';

    return { role: dbRole as Role, entraRole };
  }

  /*
  Logout
  */

  async logout(session: AuthSession, ctx: RequestCtx): Promise<void> {
    // Auth-domēna audita ieraksts — pieteikšanās/izrakstīšanās notikums
    await this.audit.write({
      ...ctx,
      action: 'auth.logout',
      result: 'Success',
      subjectId: session.userId ?? null,
      subjectRole: session.userRole ?? null,
    });

    // Sesijas tīrīšana delegēta uz SessionLifecycleService
    if (session.userId && session.id) {
      await this.sessionLifecycle.logoutSession({
        session,
        userId: session.userId,
        sessionId: session.id,
        audit: {
          actorUserId: session.userId,
          actorRole: session.userRole ?? null,
          rid: ctx.rid ?? null,
          clientIp: ctx.clientIp ?? null,
          userAgent: ctx.userAgent ?? null,
          reason: 'logout',
        },
      });
    } else {
      // Fallback — sesija bez userId (neautentificēts lietotājs)
      await new Promise<void>((resolve, reject) => {
        session.destroy((err: unknown) =>
          err
            ? reject(err instanceof Error ? err : new Error('session destroy failed'))
            : resolve(),
        );
      });
    }
  }

  /*
  E-pasta pārbaude — nosaka pieejamās autentifikācijas metodes
  */

  // Pārbauda vai lietotājs ar šo e-pastu eksistē pirms autentifikācijas mēģinājuma
  // Neatgriež MFA metodes — novērš konta fingerprinting (OWASP ASVS v5 §2.2)
  async checkEmail(email: string): Promise<{ exists: boolean }> {
    const start = Date.now();

    const user = await this.prisma.user.findUnique({
      where: { email },
      select: { id: true },
    });

    // Konstanta laika aizkave — novērš timing-based enumeration
    const elapsed = Date.now() - start;
    const minMs = 200;
    if (elapsed < minMs) {
      await new Promise((r) => setTimeout(r, minMs - elapsed));
    }

    return { exists: !!user };
  }

  /*
  Lietotāju palīgmetodes
  */

  // Meklēt lietotāju pēc e-pasta — encryption extension pārraksta email → emailHmac
  async findUserByEmail(email: string) {
    return this.prisma.user.findUnique({ where: { email } });
  }

  // Pēc Phase 3 (kad @unique uz email noņemts) — tiešā emailHmac meklēšana
  private async findUserByEmailHmac(email: string) {
    const { blindIndex } = await import('../crypto/pii-crypto.js');
    const hmac = blindIndex(email);
    return this.prisma.user.findUnique({
      where: { emailHmac: hmac },
    });
  }

  // Reģistrācija: encryption extension pārraksta where { email } → { emailHmac }
  async findOrCreateUserByEmail(email: string) {
    const user = await this.prisma.user.upsert({
      where: { email },
      create: { email, role: 'USER' },
      update: {},
    });
    // M5: PII (e-pasts) izņemts no log — izmanto userId un role pietiekami
    this.logger.log(`[AUTH] findOrCreateUserByEmail: userId=${user.id}, role=${user.role}`);
    return user;
  }

  /*
  Reģistrācija — e-pasta verifikācija + TOTP iestatīšana
  */

  // Reģistrē jaunu ārējo lietotāju — pārbauda vai e-pasts nav aizņemts, sūta magic link
  async register(
    dto: RegisterDto,
    ctx: RequestCtx,
  ): Promise<{ success: true }> {
    // Meklē pēc emailHmac blind index — encryption extension pārraksta automātiski
    const existing = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });
    if (existing) {
      throw new ConflictException({
        code: 'email_exists',
        message: 'Lietotājs ar šo e-pastu jau pastāv',
      });
    }

    // Rate limit: 5 reģistrācijas mēģinājumi no viena e-pasta stundā
    const rateLimitKey = `reg-rate:${dto.email}`;
    const attempts = await this.redis.get(rateLimitKey);
    if (attempts && Number(attempts) >= 5) {
      this.badRequest(
        'rate_limited',
        'Pārāk daudz reģistrācijas mēģinājumu — mēģiniet vēlāk',
      );
    }
    await this.redis.getClient().incr(rateLimitKey);
    await this.redis.expire(rateLimitKey, 3600);

    // Ja eksistē iepriekšējais neizmantotais tokens — dzēš to
    const prevToken = await this.redis.get(`email-verify-token:${dto.email}`);
    if (prevToken) {
      await this.redis.del(`email-verify:${prevToken}`);
    }

    // H5 fix: hash personalCode pirms saglabāšanas Redis
    const blindIndexKey = process.env.PII_BLIND_INDEX_KEY;
    const personalCodeHash = dto.personalCode && blindIndexKey
      ? createHmac('sha256', blindIndexKey).update(dto.personalCode).digest('hex')
      : null;

    // H2 fix: personas kods šifrēts ar AES-256-GCM pirms Redis saglabāšanas (GDPR 32. pants).
    // Iepriekš tika glabāts plaintext — Redis kompromitēšana atklātu PII līdz 24h.
    const personalCodeEnc = dto.personalCode ? encryptField(dto.personalCode) : null;
    const phoneEnc = dto.phone ? encryptField(dto.phone) : null;

    // Ģenerē verifikācijas tokenu un saglabā Redis ar 24h TTL
    const token = randomBytes(32).toString('hex');
    await this.redis.setJson(
      `email-verify:${token}`,
      {
        email: dto.email,
        firstName: dto.firstName,
        lastName: dto.lastName,
        citizenship: dto.citizenship,
        personalCodeHash, // HMAC blind index (meklēšanai)
        personalCodeEnc, // AES-256-GCM šifrēts (lietotāja izveidei)
        phoneEnc, // AES-256-GCM šifrēts
      },
      86400, // 24h
    );
    // Reversā atsauce — ļauj atrast un dzēst veco tokenu pie atkārtotas reģistrācijas
    await this.redis.set(`email-verify-token:${dto.email}`, token, 86400);

    // Sūta verifikācijas e-pastu ar magic link — saite uz API endpointu, nevis portālu,
    // jo backend apstrādā tokenu un novirza uz portāla TOTP iestatīšanas lapu
    const apiUrl = process.env.API_URL ?? 'http://localhost:3000';
    const verifyUrl = `${apiUrl}/api/auth/verify-email?token=${token}`;
    const { subject, html } = emailVerificationEmail({
      name: `${dto.firstName} ${dto.lastName}`,
      verifyUrl,
      expiryHours: 24,
    });

    await this.email.send({ to: dto.email, subject, html });

    await this.audit.write({
      ...ctx,
      action: 'auth.register',
      result: 'Success',
      dataJson: { citizenship: dto.citizenship },
    });

    // M5: PII izņemts — konkrētā lietotāja kontekstu var iegūt no audit log
    this.logger.log('Reģistrācija: verifikācijas e-pasts nosūtīts');
    return { success: true };
  }

  // Pārbauda e-pasta verifikācijas tokenu, izveido lietotāju, atgriež TOTP setup tokenu
  async verifyEmail(
    token: string,
    ctx: RequestCtx,
  ): Promise<{ setupToken: string; portalUrl: string }> {
    const data = await this.redis.getJson<{
      email: string;
      firstName: string;
      lastName: string;
      citizenship: string;
      personalCodeHash: string | null;
      personalCodeEnc: string | null;
      phoneEnc: string | null;
    }>(`email-verify:${token}`);

    if (!data) {
      this.badRequest('token_expired', 'Verifikācijas saite ir beigusies vai nederīga');
    }

    // Dzēš tokenu un reverso atsauci — vienreizēja izmantošana
    await this.redis.del(`email-verify:${token}`, `email-verify-token:${data.email}`);

    /*
    H2 + R3: atšifrē PII no Redis (šifrēts reģistrācijas laikā).
    Atšifrēšanas kļūda (atslēgas rotācija, sabojāti dati) tiek atzīmēta
    audit žurnālā ar atšķirīgu iemeslu no parastas "expired" plūsmas,
    lai operatori var atšķirt kriptogrāfisko nepareizību no TTL beigām.
    */
    let personalCodePlain: string | null = null;
    let phonePlain: string | null = null;
    try {
      if (data.personalCodeEnc) personalCodePlain = decryptField(data.personalCodeEnc);
      if (data.phoneEnc) phonePlain = decryptField(data.phoneEnc);
    } catch {
      this.logger.warn(`[AUTH] verifyEmail: PII atšifrēšana neizdevās tokenam (key rotation vai sabojāti dati)`);
      await this.audit.write({
        ...ctx,
        action: 'auth.email.verified',
        result: 'Denied',
        dataJson: { reason: 'decrypt_failed' },
      });
      this.badRequest('token_corrupted', 'Verifikācijas dati nav atšifrējami — mēģiniet reģistrēties no jauna');
    }

    // Pārbauda vai e-pasts jau nav reģistrēts (race condition aizsardzība)
    const existing = await this.prisma.user.findUnique({
      where: { email: data.email },
    });
    if (existing) {
      throw new ConflictException({
        code: 'email_exists',
        message: 'Lietotājs ar šo e-pastu jau pastāv',
      });
    }

    // Izveido lietotāju un TOTP identitāti — role un vārds/uzvārds no reģistrācijas datiem
    // Saglabā arī citizenship, phone, idCodeHmac ja pieejami no reģistrācijas
    const user = await this.prisma.user.create({
      data: {
        email: data.email,
        firstName: data.firstName,
        lastName: data.lastName,
        role: 'USER',
        ...(data.citizenship ? { citizenship: data.citizenship } : {}),
        ...(phonePlain ? { phone: phonePlain } : {}),
        ...(data.personalCodeHash ? { idCodeHmac: data.personalCodeHash } : {}),
        ...(personalCodePlain ? { personalCodeEnc: personalCodePlain } : {}),
        identities: {
          create: {
            provider: 'TOTP',
            providerId: '', // Pagaidu — atjaunos pēc TOTP iestatīšanas
          },
        },
      },
    });
    // M5: PII (firstName/lastName) izņemts no log
    this.logger.log(`[AUTH] verifyEmail: izveidots lietotājs ${user.id}, role=${user.role}`);

    // Ģenerē TOTP setup tokenu (15 min TTL)
    const setupToken = randomBytes(32).toString('hex');
    await this.redis.setJson(
      `totp-setup:${setupToken}`,
      { userId: user.id },
      900, // 15 min
    );

    await this.audit.write({
      ...ctx,
      action: 'auth.email.verified',
      result: 'Success',
      subjectId: user.id,
      dataJson: null,
    });

    const portalUrl = process.env.PORTAL_URL ?? 'http://localhost:5173';
    return { setupToken, portalUrl };
  }

  // Inicializē TOTP iestatīšanu — ģenerē noslēpumu un QR kodu
  async totpSetupInit(
    setupToken: string,
    ctx: RequestCtx,
  ): Promise<{ otpauthUrl: string }> {
    const tokenData = await this.redis.getJson<{ userId: string }>(
      `totp-setup:${setupToken}`,
    );
    if (!tokenData) {
      this.badRequest('token_expired', 'TOTP iestatīšanas saite ir beigusies');
    }

    const user = await this.prisma.user.findUniqueOrThrow({
      where: { id: tokenData.userId },
    });

    const secret = generateSecret();
    const issuer = process.env.TOTP_ISSUER ?? 'e-Jurnieks';
    const otpauthUrl = generateURI({
      issuer,
      label: user.email ?? user.id,
      secret,
    });

    // Pagaidu TOTP noslēpums Redis — dzēš pēc veiksmīgas verifikācijas
    await this.redis.setJson(
      `totp-pending:${tokenData.userId}`,
      { secret },
      900, // 15 min
    );

    await this.audit.write({
      ...ctx,
      action: 'auth.totp.setup-init',
      result: 'Success',
      subjectId: tokenData.userId,
    });

    // L2: noslēpums netiek atgriezts atsevišķi — frontend to iegūst no otpauthUrl
    return { otpauthUrl };
  }

  // Apstiprina TOTP kodu, šifrē noslēpumu, aktivizē lietotāju
  async totpSetupVerify(
    setupToken: string,
    code: string,
    ctx: RequestCtx,
  ): Promise<{ success: true }> {
    const tokenData = await this.redis.getJson<{ userId: string }>(
      `totp-setup:${setupToken}`,
    );
    if (!tokenData) {
      this.badRequest('token_expired', 'TOTP iestatīšanas saite ir beigusies');
    }

    const userId = tokenData.userId;

    // Mēģinājumu skaitītājs — max 5 mēģinājumi
    const attemptsKey = `totp-setup-attempts:${userId}`;
    const attempts = await this.redis.get(attemptsKey);
    if (attempts && Number(attempts) >= 5) {
      // Dzēš setup datus — jāsāk no jauna
      await this.redis.del(
        `totp-setup:${setupToken}`,
        `totp-pending:${userId}`,
        attemptsKey,
      );
      this.badRequest(
        'too_many_attempts',
        'Pārāk daudz mēģinājumu — lūdzu sāciet reģistrāciju no sākuma',
      );
    }

    const pendingData = await this.redis.getJson<{ secret: string }>(
      `totp-pending:${userId}`,
    );
    if (!pendingData) {
      this.badRequest('token_expired', 'TOTP noslēpums ir beidzies — sāciet no sākuma');
    }

    // Pārbauda TOTP kodu pret pagaidu noslēpumu — otplib v13 atgriež { valid: boolean }
    const setupResult = await totpVerify_({ token: code, secret: pendingData.secret });
    const valid = typeof setupResult === 'object' && setupResult !== null ? (setupResult as { valid: boolean }).valid : !!setupResult;
    if (!valid) {
      await this.redis.getClient().incr(attemptsKey);
      await this.redis.expire(attemptsKey, 900);

      await this.audit.write({
        ...ctx,
        action: 'auth.totp.setup-verify',
        result: 'Denied',
        subjectId: userId,
        dataJson: { reason: 'invalid_code' },
      });
      this.unauthorized('totp_invalid', 'Nepareizs verifikācijas kods');
    }

    // Šifrē TOTP noslēpumu pirms saglabāšanas datubāzē
    const encryptedSecret = this.encryptTotpSecret(pendingData.secret);

    // Atjaunina vai izveido Identity ar šifrētu noslēpumu
    // Pēc admin credential reset identitāte var neeksistēt — izveido jaunu
    const existing = await this.prisma.identity.findFirst({
      where: { userId, provider: 'TOTP' },
    });
    if (existing) {
      await this.prisma.identity.update({
        where: { id: existing.id },
        data: { secret: encryptedSecret, providerId: userId },
      });
      this.logger.log(`[AUTH] totpSetupVerify: atjaunināta Identity lietotājam ${userId}`);
    } else {
      try {
        await this.prisma.identity.create({
          data: { userId, provider: 'TOTP', providerId: userId, secret: encryptedSecret },
        });
        this.logger.log(`[AUTH] totpSetupVerify: izveidota jauna TOTP Identity lietotājam ${userId}`);
      } catch (err: any) {
        // P2002 — unique constraint, iespējams race condition vai iepriekšējs šifrēts ieraksts
        if (err?.code === 'P2002') {
          await this.prisma.identity.updateMany({
            where: { userId, provider: 'TOTP' },
            data: { secret: encryptedSecret, providerId: userId },
          });
          this.logger.log(`[AUTH] totpSetupVerify: P2002 fallback — atjaunināta Identity lietotājam ${userId}`);
        } else {
          throw err;
        }
      }
    }

    // Sakopj Redis atslēgas
    await this.redis.del(
      `totp-setup:${setupToken}`,
      `totp-pending:${userId}`,
      attemptsKey,
    );

    await this.audit.write({
      ...ctx,
      action: 'auth.totp.setup-verify',
      result: 'Success',
      subjectId: userId,
    });

    this.logger.log(`TOTP iestatīts lietotājam ${userId}`);
    return { success: true };
  }
}
