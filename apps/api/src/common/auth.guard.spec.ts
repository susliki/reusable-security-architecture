import { ForbiddenException, UnauthorizedException } from '@nestjs/common';
import { AuthGuard, validateSession } from './auth.guard';
import type { AuthSession } from './session.types';

// Minimāls PrismaService mock — tikai user.findUnique tiek izmantots
function makePrismaMock(user: { id: string; role: string; status: string } | null) {
  return {
    user: {
      findUnique: jest.fn().mockResolvedValue(user),
    },
  } as any;
}

function makeSession(overrides: Partial<AuthSession> = {}): AuthSession {
  const destroy = jest.fn((cb: (err?: unknown) => void) => cb());
  return {
    id: 'sid-1',
    cookie: {} as any,
    regenerate: jest.fn(),
    destroy: destroy as any,
    reload: jest.fn(),
    save: jest.fn(),
    touch: jest.fn(),
    resetMaxAge: jest.fn(),
    userId: 'u1',
    userRole: 'USER',
    isAdmin: false,
    createdAt: new Date().toISOString(),
    userVerifiedAt: new Date().toISOString(),
    ...overrides,
  } as unknown as AuthSession;
}

function makeCtx(session: AuthSession): any {
  return {
    switchToHttp: () => ({
      getRequest: () => ({ session }),
    }),
  };
}

describe('validateSession', () => {
  it('noraida sesiju bez userId', async () => {
    const session = makeSession({ userId: null });
    const result = await validateSession(session, makePrismaMock(null));
    expect(result).toEqual(
      expect.objectContaining({ ok: false, status: 401, code: 'session_required', destroy: false }),
    );
  });

  it('noraida sesiju, kas pārsniegusi absolūto TTL', async () => {
    const nineHoursAgo = new Date(Date.now() - 9 * 60 * 60 * 1000).toISOString();
    const session = makeSession({ createdAt: nineHoursAgo });
    const result = await validateSession(session, makePrismaMock({ id: 'u1', role: 'USER', status: 'ACTIVE' }));
    expect(result).toEqual(
      expect.objectContaining({ ok: false, code: 'session_expired', destroy: true }),
    );
  });

  it('iznīcina sesiju ja lietotājs dzēsts no DB', async () => {
    // Spiest DB pārbaudi — userVerifiedAt vecāks par 60s
    const twoMinAgo = new Date(Date.now() - 2 * 60 * 1000).toISOString();
    const session = makeSession({ userVerifiedAt: twoMinAgo });
    const result = await validateSession(session, makePrismaMock(null));
    expect(result).toEqual(
      expect.objectContaining({ ok: false, code: 'user_deleted', destroy: true }),
    );
  });

  it('iznīcina sesiju ja lietotājs ir BLOCKED', async () => {
    const twoMinAgo = new Date(Date.now() - 2 * 60 * 1000).toISOString();
    const session = makeSession({ userVerifiedAt: twoMinAgo });
    const result = await validateSession(
      session,
      makePrismaMock({ id: 'u1', role: 'USER', status: 'BLOCKED' }),
    );
    expect(result).toEqual(
      expect.objectContaining({ ok: false, status: 403, code: 'account_blocked', destroy: true }),
    );
  });

  it('sinhronizē lomu no DB pie DB pārbaudes', async () => {
    const twoMinAgo = new Date(Date.now() - 2 * 60 * 1000).toISOString();
    const session = makeSession({ userRole: 'USER', isAdmin: false, userVerifiedAt: twoMinAgo });
    await validateSession(session, makePrismaMock({ id: 'u1', role: 'ADMIN', status: 'ACTIVE' }));
    expect(session.userRole).toBe('ADMIN');
    expect(session.isAdmin).toBe(true);
  });

  it('kešo DB pārbaudi 60s logā — neveicot papildu DB izsaukumu', async () => {
    const prisma = makePrismaMock({ id: 'u1', role: 'USER', status: 'ACTIVE' });
    const recent = new Date(Date.now() - 30 * 1000).toISOString(); // pirms 30s
    const session = makeSession({ userVerifiedAt: recent });
    const result = await validateSession(session, prisma);
    expect(result.ok).toBe(true);
    expect(prisma.user.findUnique).not.toHaveBeenCalled();
  });

  it('veic DB pārbaudi, ja kešs vecāks par 60s', async () => {
    const prisma = makePrismaMock({ id: 'u1', role: 'USER', status: 'ACTIVE' });
    const twoMinAgo = new Date(Date.now() - 2 * 60 * 1000).toISOString();
    const session = makeSession({ userVerifiedAt: twoMinAgo });
    const result = await validateSession(session, prisma);
    expect(result.ok).toBe(true);
    expect(prisma.user.findUnique).toHaveBeenCalledTimes(1);
    // Atjaunināts userVerifiedAt pēc veiksmīgas pārbaudes
    expect(session.userVerifiedAt).not.toBe(twoMinAgo);
  });

  it('atļauj derīgu sesiju', async () => {
    const prisma = makePrismaMock({ id: 'u1', role: 'USER', status: 'ACTIVE' });
    const session = makeSession();
    const result = await validateSession(session, prisma);
    expect(result).toEqual({ ok: true });
  });
});

describe('AuthGuard', () => {
  it('met UnauthorizedException ja sesijai trūkst userId', async () => {
    const guard = new AuthGuard(makePrismaMock(null));
    const session = makeSession({ userId: null });
    await expect(guard.canActivate(makeCtx(session))).rejects.toThrow(UnauthorizedException);
  });

  it('met ForbiddenException un iznīcina sesiju ja lietotājs BLOCKED', async () => {
    const prisma = makePrismaMock({ id: 'u1', role: 'USER', status: 'BLOCKED' });
    const guard = new AuthGuard(prisma);
    const twoMinAgo = new Date(Date.now() - 2 * 60 * 1000).toISOString();
    const session = makeSession({ userVerifiedAt: twoMinAgo });
    await expect(guard.canActivate(makeCtx(session))).rejects.toThrow(ForbiddenException);
    expect(session.destroy).toHaveBeenCalled();
  });

  it('atjaunina lastActive pie veiksmīgas pārbaudes', async () => {
    const prisma = makePrismaMock({ id: 'u1', role: 'USER', status: 'ACTIVE' });
    const guard = new AuthGuard(prisma);
    const session = makeSession({ lastActive: null });
    const ok = await guard.canActivate(makeCtx(session));
    expect(ok).toBe(true);
    expect(session.lastActive).not.toBeNull();
  });
});
