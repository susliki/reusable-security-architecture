import { BadRequestException, UnauthorizedException } from '@nestjs/common';

// ESM pakotnes jābūt mockētas pirms jebkura importa, kas tās aizsauc
jest.mock('@simplewebauthn/server', () => ({
  generateRegistrationOptions: jest.fn(),
  verifyRegistrationResponse: jest.fn(),
  generateAuthenticationOptions: jest.fn(),
  verifyAuthenticationResponse: jest.fn(),
}));

jest.mock('otplib', () => ({
  generateSecret: jest.fn(),
  generate: jest.fn(),
  verify: jest.fn(),
  generateURI: jest.fn(),
}));

import { AuthController } from './auth.controller';
import type { AuthService } from './auth.service';

function makeRequest(sessionOverrides: Record<string, any> = {}): any {
  const destroy = jest.fn((cb: (err?: unknown) => void) => cb());
  return {
    ip: '127.0.0.1',
    headers: { 'user-agent': 'jest' },
    sessionID: 'sid-1',
    session: {
      id: 'sid-1',
      userId: null,
      userRole: null,
      destroy,
      save: jest.fn((cb: (err?: unknown) => void) => cb()),
      ...sessionOverrides,
    },
  };
}

function makeResponse(): any {
  return { clearCookie: jest.fn() };
}

describe('AuthController', () => {
  let authService: jest.Mocked<AuthService>;
  let controller: AuthController;

  beforeEach(() => {
    authService = {
      checkEmail: jest.fn(),
      totpVerifyAndLogin: jest.fn(),
      findUserByEmail: jest.fn(),
      stepUpVerifyTotp: jest.fn(),
      logout: jest.fn(),
    } as unknown as jest.Mocked<AuthService>;
    controller = new AuthController(authService);
  });

  describe('checkEmail', () => {
    it('deleģē uz AuthService.checkEmail', async () => {
      authService.checkEmail.mockResolvedValue({ exists: true } as any);
      const result = await controller.checkEmail({ email: 'a@b.lv' } as any);
      expect(authService.checkEmail).toHaveBeenCalledWith('a@b.lv');
      expect(result).toEqual({ exists: true });
    });
  });

  describe('totpVerify', () => {
    it('met BadRequest, ja nav sesijas userId un nav e-pasta', async () => {
      const req = makeRequest();
      await expect(
        controller.totpVerify({ code: '123456' } as any, req),
      ).rejects.toThrow(BadRequestException);
    });

    it('met Unauthorized, ja lietotājs pēc e-pasta neeksistē', async () => {
      authService.findUserByEmail.mockResolvedValue(null as any);
      const req = makeRequest();
      await expect(
        controller.totpVerify({ code: '123456', email: 'unknown@lv.lv' } as any, req),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('H3: nepiešķir session.userId priekš verifikācijas — pat ja verify izgāžas', async () => {
      authService.findUserByEmail.mockResolvedValue({ id: 'user-1' } as any);
      authService.totpVerifyAndLogin.mockRejectedValue(
        new UnauthorizedException({ code: 'totp_invalid' }),
      );
      const req = makeRequest();
      await expect(
        controller.totpVerify({ code: '000000', email: 'a@b.lv' } as any, req),
      ).rejects.toThrow(UnauthorizedException);
      // Kritiskā H3 pārbaude — sesijā nedrīkst palikt userId
      expect(req.session.userId).toBeNull();
    });

    it('izsauc totpVerifyAndLogin ar lokālo userId, nevis no sesijas', async () => {
      authService.findUserByEmail.mockResolvedValue({ id: 'user-42' } as any);
      authService.totpVerifyAndLogin.mockResolvedValue(undefined);
      const req = makeRequest();
      await controller.totpVerify(
        { code: '123456', email: 'ok@lv.lv' } as any,
        req,
      );
      expect(authService.totpVerifyAndLogin).toHaveBeenCalledWith(
        'user-42',
        '123456',
        req,
        expect.any(Object),
      );
    });

    it('ja sesijā jau ir userId, neprasa e-pastu', async () => {
      authService.totpVerifyAndLogin.mockResolvedValue(undefined);
      const req = makeRequest({ userId: 'existing-user' });
      await controller.totpVerify({ code: '123456' } as any, req);
      expect(authService.findUserByEmail).not.toHaveBeenCalled();
      expect(authService.totpVerifyAndLogin).toHaveBeenCalledWith(
        'existing-user',
        '123456',
        req,
        expect.any(Object),
      );
    });
  });

  describe('stepUpVerify', () => {
    it('met BadRequest uz neatbalstītu metodi', async () => {
      const req = makeRequest({ userId: 'u1' });
      await expect(
        controller.stepUpVerify({ method: 'passkey' as any, code: 'x' }, req),
      ).rejects.toThrow(BadRequestException);
    });

    it('met BadRequest ja kods trūkst', async () => {
      const req = makeRequest({ userId: 'u1' });
      await expect(
        controller.stepUpVerify({ method: 'totp', code: '' }, req),
      ).rejects.toThrow(BadRequestException);
    });

    it('met Unauthorized ja stepUpVerifyTotp atgriež false', async () => {
      authService.stepUpVerifyTotp.mockResolvedValue(false);
      const req = makeRequest({ userId: 'u1' });
      await expect(
        controller.stepUpVerify({ method: 'totp', code: '000000' }, req),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('iestata stepUpVerifiedAt pie veiksmīgas verifikācijas', async () => {
      authService.stepUpVerifyTotp.mockResolvedValue(true);
      const req = makeRequest({ userId: 'u1' });
      const result = await controller.stepUpVerify(
        { method: 'totp', code: '123456' },
        req,
      );
      expect(result).toEqual({ ok: true });
      expect(req.session.stepUpVerifiedAt).toBeDefined();
      expect(authService.stepUpVerifyTotp).toHaveBeenCalledWith(
        'u1',
        '123456',
        expect.any(Object),
      );
    });
  });

  describe('logout', () => {
    it('izsauc authService.logout ja sesijai ir userId', async () => {
      const req = makeRequest({ userId: 'u1' });
      const res = makeResponse();
      await controller.logout(req, res);
      expect(authService.logout).toHaveBeenCalled();
      expect(res.clearCookie).toHaveBeenCalled();
    });

    it('L4: iznīcina orphan sesiju (bez userId)', async () => {
      const req = makeRequest();
      const res = makeResponse();
      await controller.logout(req, res);
      // authService.logout netiek izsaukts (nav userId)
      expect(authService.logout).not.toHaveBeenCalled();
      // Bet session.destroy() ir izsaukts
      expect(req.session.destroy).toHaveBeenCalled();
      expect(res.clearCookie).toHaveBeenCalled();
    });
  });
});
