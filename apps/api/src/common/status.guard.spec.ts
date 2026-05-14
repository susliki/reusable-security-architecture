import { ForbiddenException } from '@nestjs/common';
import { StatusGuard } from './status.guard';

// --- Mock palīgi ---

function makeContext(
  session: Record<string, unknown>,
  path: string,
): any {
  return {
    switchToHttp: () => ({
      getRequest: () => ({ path, session }),
    }),
  };
}

describe('StatusGuard', () => {
  let guard: StatusGuard;

  beforeEach(() => {
    guard = new StatusGuard();
  });

  it('izlaiž ja nav userId sesijā (AuthGuard atbildēs)', () => {
    const ctx = makeContext({}, '/api/profile');
    expect(guard.canActivate(ctx)).toBe(true);
  });

  it('izlaiž exempt ceļus (auth, me, verification, notifications)', () => {
    for (const path of [
      '/api/auth/login',
      '/api/me',
      '/api/me/security/passkeys',
      '/api/verification/upload',
      '/api/csrf-token',
      '/api/health',
      '/api/public/verify/abc',
      '/api/notifications',
    ]) {
      const ctx = makeContext({ userId: 'user-1', userStatus: 'UNVERIFIED' }, path);
      expect(guard.canActivate(ctx)).toBe(true);
    }
  });

  it('atļauj ja userStatus nav kešots (pirmais pieprasījums)', () => {
    const ctx = makeContext({ userId: 'user-1' }, '/api/profile');
    expect(guard.canActivate(ctx)).toBe(true);
  });

  it('atļauj VERIFIED lietotāju', () => {
    const ctx = makeContext({ userId: 'user-1', userStatus: 'VERIFIED' }, '/api/profile');
    expect(guard.canActivate(ctx)).toBe(true);
  });

  it('bloķē UNVERIFIED lietotāju', () => {
    const ctx = makeContext({ userId: 'user-1', userStatus: 'UNVERIFIED' }, '/api/profile');
    expect(() => guard.canActivate(ctx)).toThrow(ForbiddenException);
  });

  it('bloķē BLOCKED lietotāju', () => {
    const ctx = makeContext({ userId: 'user-1', userStatus: 'BLOCKED' }, '/api/profile');
    expect(() => guard.canActivate(ctx)).toThrow(ForbiddenException);
  });

  it('bloķē DELETED lietotāju', () => {
    const ctx = makeContext({ userId: 'user-1', userStatus: 'DELETED' }, '/api/profile');
    expect(() => guard.canActivate(ctx)).toThrow(ForbiddenException);
  });

  it('bloķē PENDING_REVIEW lietotāju', () => {
    const ctx = makeContext({ userId: 'user-1', userStatus: 'PENDING_REVIEW' }, '/api/profile');
    expect(() => guard.canActivate(ctx)).toThrow(ForbiddenException);
  });

  it('bloķē REJECTED lietotāju', () => {
    const ctx = makeContext({ userId: 'user-1', userStatus: 'REJECTED' }, '/api/profile');
    expect(() => guard.canActivate(ctx)).toThrow(ForbiddenException);
  });

  it('kļūdas atbilde satur statusu un kodu', () => {
    const ctx = makeContext({ userId: 'user-1', userStatus: 'BLOCKED' }, '/api/profile');
    try {
      guard.canActivate(ctx);
      fail('Vajadzēja mest ForbiddenException');
    } catch (err: any) {
      const response = err.getResponse();
      expect(response.code).toBe('account_not_verified');
      expect(response.status).toBe('BLOCKED');
    }
  });
});
