/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-return, @typescript-eslint/no-unsafe-argument */
import {
  BadRequestException,
  UnauthorizedException,
  type HttpException,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import type { AuthSession } from '../common/session.types';

/*
ESM pakotņu mocki — jābūt pirms importiem, kas tās izsauc
*/

jest.mock('@simplewebauthn/server', () => ({
  generateRegistrationOptions: jest.fn(),
  verifyRegistrationResponse: jest.fn(),
  generateAuthenticationOptions: jest.fn(),
  verifyAuthenticationResponse: jest.fn(),
}));

jest.mock('otplib', () => ({
  generateSecret: jest.fn(() => 'TESTSECRETBASE32'),
  generate: jest.fn(),
  verify: jest.fn(),
  generateURI: jest.fn(
    () => 'otpauth://totp/Jurnieks:user%40test.com?secret=TESTSECRETBASE32',
  ),
}));

import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { verify as totpVerifyMock } from 'otplib';

/*
Palīgi
*/

function makeSession(overrides: Partial<AuthSession> = {}): AuthSession {
  const store: Record<string, any> = { ...overrides };
  return new Proxy(store, {
    get: (t, k) => {
      if (k === 'destroy') return t['destroy'] ?? ((cb: any) => cb(null));
      if (k === 'regenerate') return t['regenerate'] ?? ((cb: any) => cb(null));
      if (k === 'save') return t['save'] ?? ((cb: any) => cb(null));
      return t[k as string];
    },
    set: (t, k, v) => {
      t[k as string] = v;
      return true;
    },
  }) as unknown as AuthSession;
}

function makeReq(sessionOverrides: Partial<AuthSession> = {}): any {
  const session = makeSession(sessionOverrides);
  return { session };
}

function makePrisma(): any {
  return {
    user: {
      findUniqueOrThrow: jest.fn(),
      findUnique: jest.fn(),
      upsert: jest.fn(),
      update: jest.fn().mockResolvedValue({}),
    },
    identity: {
      create: jest.fn(),
      upsert: jest.fn(),
      findUnique: jest.fn(),
      findFirst: jest.fn(),
    },
    passkeyCredential: {
      create: jest.fn(),
      findUnique: jest.fn(),
      update: jest.fn(),
    },
    $transaction: jest.fn(
      (fn: (tx: ReturnType<typeof makePrisma>) => unknown) => {
        const txPrisma = makePrisma();
        return fn(txPrisma);
      },
    ),
  };
}

function makeAudit(): any {
  return { write: jest.fn().mockResolvedValue(undefined) };
}

function makeCtx() {
  return { rid: 'test-rid', clientIp: '127.0.0.1', userAgent: 'jest' };
}

function extractExceptionCode(error: HttpException): string | undefined {
  const response = error.getResponse();
  if (!response || typeof response !== 'object') return undefined;
  return (response as Record<string, unknown>).code as string | undefined;
}

/*
Testi
*/

describe('AuthService', () => {
  let service: AuthService;
  let prisma: ReturnType<typeof makePrisma>;
  let audit: ReturnType<typeof makeAudit>;
  let sessionLifecycle: any;

  beforeEach(() => {
    jest.clearAllMocks();
    prisma = makePrisma();
    audit = makeAudit();
    const redis = { get: jest.fn(), set: jest.fn(), del: jest.fn(), setJson: jest.fn(), getJson: jest.fn(), getClient: jest.fn(() => ({ incr: jest.fn(), scan: jest.fn().mockResolvedValue(['0', []]), get: jest.fn(), del: jest.fn(), sadd: jest.fn(), smembers: jest.fn().mockResolvedValue([]), srem: jest.fn(), exists: jest.fn().mockResolvedValue(1), expire: jest.fn() })), expire: jest.fn() } as any;
    const email = { send: jest.fn(), isConfigured: jest.fn(() => true) } as any;
    sessionLifecycle = {
      establishAuthenticatedSession: jest.fn(),
      logoutSession: jest.fn(),
      revokeAllUserSessions: jest.fn().mockResolvedValue({ revokedRedis: 0, deletedDb: 0 }),
      revokeOtherUserSessions: jest.fn().mockResolvedValue({ revokedRedis: 0 }),
      findTrackedSessionKeys: jest.fn().mockResolvedValue([]),
      enforceSessionLimit: jest.fn(),
    };
    service = new AuthService(prisma, audit, redis, email, sessionLifecycle);
    process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
  });

  /*
  SessionLifecycleService delegācija (pārbaudīts caur totpVerifyAndLogin)
  */

  describe('establishSession delegācija', () => {
    it('deleģē uz sessionLifecycle ar ADMIN lomu', async () => {
      const req = makeReq();
      prisma.identity.findFirst.mockResolvedValue({
        secret: encryptSecret('TESTSECRETBASE32'),
        userId: 'u1',
        user: { id: 'u1', role: 'ADMIN', email: 'admin@test.com' },
      });
      prisma.user.findUniqueOrThrow.mockResolvedValue({
        id: 'u1', role: 'ADMIN', email: 'admin@test.com', firstName: null, lastName: null,
      });
      (totpVerifyMock as jest.Mock).mockResolvedValue(true);

      await service.totpVerifyAndLogin('u1', '123456', req, makeCtx());
      expect(sessionLifecycle.establishAuthenticatedSession).toHaveBeenCalledWith(
        expect.objectContaining({ userId: 'u1', role: 'ADMIN' }),
      );
    });

    it('deleģē uz sessionLifecycle ar USER lomu', async () => {
      const req = makeReq();
      prisma.identity.findFirst.mockResolvedValue({
        secret: encryptSecret('TESTSECRETBASE32'),
        userId: 'u2',
        user: { id: 'u2', role: 'USER', email: 'user@test.com' },
      });
      prisma.user.findUniqueOrThrow.mockResolvedValue({
        id: 'u2', role: 'USER', email: 'user@test.com', firstName: null, lastName: null,
      });
      (totpVerifyMock as jest.Mock).mockResolvedValue(true);

      await service.totpVerifyAndLogin('u2', '654321', req, makeCtx());
      expect(sessionLifecycle.establishAuthenticatedSession).toHaveBeenCalledWith(
        expect.objectContaining({ userId: 'u2', role: 'USER' }),
      );
    });
  });

  /*
  passkeyRegisterOptions
  */

  describe('passkeyRegisterOptions', () => {
    it('saglabā izaicinājumu sesijā', async () => {
      prisma.user.findUniqueOrThrow.mockResolvedValue({
        id: 'u1',
        email: 'user@test.com',
        firstName: null, lastName: null,
        identities: [],
      });
      (generateRegistrationOptions as jest.Mock).mockResolvedValue({
        challenge: 'chal123',
      });

      const session = makeSession();
      await service.passkeyRegisterOptions('u1', session);

      expect(session.passkeyRegChallenge).toBe('chal123');
    });
  });

  /*
  passkeyRegisterVerify
  */

  describe('passkeyRegisterVerify', () => {
    it('met BadRequestException, ja sesijā nav izaicinājuma', async () => {
      const session = makeSession({ passkeyRegChallenge: null });
      await expect(
        service.passkeyRegisterVerify('u1', {} as any, session, makeCtx()),
      ).rejects.toThrow(BadRequestException);
    });

    it('met UnauthorizedException un raksta Denied audita ierakstu, ja verify neizdodas', async () => {
      const session = makeSession({ passkeyRegChallenge: 'stored-challenge' });
      (verifyRegistrationResponse as jest.Mock).mockRejectedValue(
        new Error('bad sig'),
      );

      let caught: unknown;
      try {
        await service.passkeyRegisterVerify('u1', {} as any, session, makeCtx());
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(UnauthorizedException);
      expect(
        extractExceptionCode(caught as UnauthorizedException),
      ).toBe('verification_failed');

      expect(audit.write).toHaveBeenCalledWith(
        expect.objectContaining({
          result: 'Denied',
          action: 'auth.webauthn.register',
        }),
      );
    });

    it('notīra izaicinājumu pirms verifikācijas — novērš replay neveiksmes gadījumā', async () => {
      const session = makeSession({ passkeyRegChallenge: 'chal' });
      (verifyRegistrationResponse as jest.Mock).mockRejectedValue(
        new Error('fail'),
      );

      await expect(
        service.passkeyRegisterVerify('u1', {} as any, session, makeCtx()),
      ).rejects.toThrow();

      expect(session.passkeyRegChallenge).toBeNull();
    });

    it('izveido Identity un PasskeyCredential un raksta Success audita ierakstu pie veiksmes', async () => {
      const session = makeSession({ passkeyRegChallenge: 'chal' });
      (verifyRegistrationResponse as jest.Mock).mockResolvedValue({
        verified: true,
        registrationInfo: {
          credential: {
            id: 'cred-id-base64url',
            publicKey: Buffer.from('pubkey'),
            counter: 0,
            transports: ['internal'],
          },
          userVerified: true,
        },
      });

      // $transaction izsauc fn ar svaigu tx prisma instanci
      let txPrismaRef: any;
      prisma.$transaction.mockImplementation(
        (fn: (tx: ReturnType<typeof makePrisma>) => unknown) => {
          txPrismaRef = makePrisma();
          txPrismaRef.identity.create.mockResolvedValue({ id: 'identity-1' });
          txPrismaRef.passkeyCredential.create.mockResolvedValue({});
          return fn(txPrismaRef);
        },
      );

      await service.passkeyRegisterVerify('u1', {} as any, session, makeCtx());

      expect(txPrismaRef.identity.create).toHaveBeenCalled();
      expect(txPrismaRef.passkeyCredential.create).toHaveBeenCalled();
      expect(audit.write).toHaveBeenCalledWith(
        expect.objectContaining({
          result: 'Success',
          action: 'auth.webauthn.register',
        }),
      );
    });
  });

  /*
  passkeyAuthVerify
  */

  describe('passkeyAuthVerify', () => {
    const baseCredential = {
      id: 'pk-row-id',
      credentialId: 'cred-1',
      publicKey: Buffer.from('pubkey').toString('base64url'),
      counter: BigInt(5),
      transports: ['internal'],
      identity: {
        userId: 'u1',
        user: { id: 'u1', role: 'USER', email: 'u@test.com' },
      },
    };

    it('met Denied audit ar counter_regression, ja skaitītājs iet atpakaļ', async () => {
      const req = makeReq({ passkeyAuthChallenge: 'chal' });
      prisma.passkeyCredential.findUnique.mockResolvedValue(baseCredential);
      (verifyAuthenticationResponse as jest.Mock).mockResolvedValue({
        verified: true,
        authenticationInfo: { newCounter: 3 }, // 3 < 5 → regresija
      });

      await expect(
        service.passkeyAuthVerify({ id: 'cred-1' } as any, req, makeCtx()),
      ).rejects.toThrow(UnauthorizedException);

      expect(audit.write).toHaveBeenCalledWith(
        expect.objectContaining({
          result: 'Denied',
          dataJson: expect.objectContaining({ reason: 'counter_regression' }),
        }),
      );
    });

    it('atjaunina skaitītāju un izveido sesiju veiksmes gadījumā', async () => {
      const req = makeReq({ passkeyAuthChallenge: 'chal' });
      prisma.passkeyCredential.findUnique.mockResolvedValue(baseCredential);
      prisma.passkeyCredential.update.mockResolvedValue({});
      // findUniqueOrThrow — ielādē lietotāju atsevišķi PII atšifrēšanai
      prisma.user.findUniqueOrThrow.mockResolvedValue({
        id: 'u1', role: 'USER', email: 'u@test.com', firstName: null, lastName: null,
      });
      (verifyAuthenticationResponse as jest.Mock).mockResolvedValue({
        verified: true,
        authenticationInfo: { newCounter: 10 },
      });

      await service.passkeyAuthVerify(
        { id: 'cred-1' } as any,
        req,
        makeCtx(),
      );

      expect(prisma.passkeyCredential.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({ counter: BigInt(10) }),
        }),
      );
      expect(sessionLifecycle.establishAuthenticatedSession).toHaveBeenCalledWith(
        expect.objectContaining({ userId: 'u1', role: 'USER' }),
      );
      expect(audit.write).toHaveBeenCalledWith(
        expect.objectContaining({
          result: 'Success',
          action: 'auth.webauthn.auth',
        }),
      );
    });
  });

  /*
  totpVerifyAndLogin
  */

  describe('totpVerifyAndLogin', () => {
    it('met UnauthorizedException un raksta Denied audita ierakstu nederīga koda gadījumā', async () => {
      const req = makeReq();
      prisma.identity.findFirst.mockResolvedValue({
        secret: encryptSecret('TESTSECRETBASE32'),
        userId: 'u1',
        user: { id: 'u1', role: 'USER', email: 'u@test.com' },
      });
      (totpVerifyMock as jest.Mock).mockResolvedValue(false);

      let caught: unknown;
      try {
        await service.totpVerifyAndLogin('u1', '000000', req, makeCtx());
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(UnauthorizedException);
      expect(
        extractExceptionCode(caught as UnauthorizedException),
      ).toBe('totp_invalid');

      expect(audit.write).toHaveBeenCalledWith(
        expect.objectContaining({
          result: 'Denied',
          action: 'auth.totp.verify',
        }),
      );
    });

    it('deleģē sesijas izveidi pie derīga koda', async () => {
      const req = makeReq();
      prisma.identity.findFirst.mockResolvedValue({
        secret: encryptSecret('TESTSECRETBASE32'),
        userId: 'u1',
        user: { id: 'u1', role: 'USER', email: 'u@test.com' },
      });
      prisma.user.findUniqueOrThrow.mockResolvedValue({
        id: 'u1', role: 'USER', email: 'u@test.com', firstName: null, lastName: null,
      });
      (totpVerifyMock as jest.Mock).mockResolvedValue(true);

      await service.totpVerifyAndLogin('u1', '123456', req, makeCtx());

      expect(sessionLifecycle.establishAuthenticatedSession).toHaveBeenCalledWith(
        expect.objectContaining({ userId: 'u1', role: 'USER' }),
      );
    });
  });

  /*
  oidcCallback
  */

  describe('oidcCallback', () => {
    it('met BadRequestException, ja sesijas state trūkst', async () => {
      const req = makeReq({ oidcState: null, oidcNonce: null });
      await expect(
        service.oidcCallback({ code: 'c', state: 's' }, req, makeCtx()),
      ).rejects.toThrow(BadRequestException);
    });
  });

  /*
  logout
  */

  describe('logout', () => {
    it('raksta audita ierakstu PIRMS session.destroy', async () => {
      const calls: string[] = [];
      audit.write = jest.fn(() => {
        calls.push('audit');
        return Promise.resolve();
      });
      const session = makeSession({ userId: 'u1', userRole: 'USER' });
      (session as any).destroy = (cb: any) => {
        calls.push('destroy');
        cb(null);
      };

      await service.logout(session, makeCtx());

      expect(calls[0]).toBe('audit');
      expect(calls[1]).toBe('destroy');
    });
  });
});

/*
Palīgs — šifrē noslēpumu tādā pat veidā kā AuthService (testu datiem)
*/

function encryptSecret(plain: string): string {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { createCipheriv, randomBytes } = require('crypto');
  const key = Buffer.from('a'.repeat(64), 'hex');
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString('base64url');
}
