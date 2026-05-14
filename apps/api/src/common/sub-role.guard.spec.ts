import { ForbiddenException } from '@nestjs/common';
import { SubRoleGuard } from './sub-role.guard';

function makePrisma(): any {
  return { user: { findUnique: jest.fn() } };
}

function makeReflector(check: any): any {
  return { getAllAndOverride: jest.fn(() => check) };
}

function makeContext(userId: string | null): any {
  return {
    switchToHttp: () => ({
      getRequest: () => ({
        session: userId ? { userId } : {},
      }),
    }),
    getHandler: () => ({}),
    getClass: () => ({}),
  };
}

describe('SubRoleGuard', () => {
  it('izlaiž, ja nav @RequireSubRole dekoratora', async () => {
    const prisma = makePrisma();
    const guard = new SubRoleGuard(makeReflector(undefined), prisma);
    await expect(guard.canActivate(makeContext('u1'))).resolves.toBe(true);
    expect(prisma.user.findUnique).not.toHaveBeenCalled();
  });

  it('izlaiž, ja nav sesijas (AuthGuard atbildēs)', async () => {
    const prisma = makePrisma();
    const guard = new SubRoleGuard(makeReflector({ entraRole: 'superadmin' }), prisma);
    await expect(guard.canActivate(makeContext(null))).resolves.toBe(true);
  });

  it('atļauj pareizu entraRole', async () => {
    const prisma = makePrisma();
    prisma.user.findUnique.mockResolvedValue({ entraRole: 'superadmin' });
    const guard = new SubRoleGuard(makeReflector({ entraRole: ['superadmin', 'user_admin'] }), prisma);
    await expect(guard.canActivate(makeContext('u1'))).resolves.toBe(true);
  });

  it('bloķē nepareizu entraRole', async () => {
    const prisma = makePrisma();
    prisma.user.findUnique.mockResolvedValue({ entraRole: 'auditor' });
    const guard = new SubRoleGuard(makeReflector({ entraRole: 'superadmin' }), prisma);
    await expect(guard.canActivate(makeContext('u1'))).rejects.toThrow(ForbiddenException);
  });

  it('bloķē, ja entraRole ir null', async () => {
    const prisma = makePrisma();
    prisma.user.findUnique.mockResolvedValue({ entraRole: null });
    const guard = new SubRoleGuard(makeReflector({ entraRole: 'superadmin' }), prisma);
    await expect(guard.canActivate(makeContext('u1'))).rejects.toThrow(ForbiddenException);
  });

  it('bloķē, ja lietotājs nav atrasts', async () => {
    const prisma = makePrisma();
    prisma.user.findUnique.mockResolvedValue(null);
    const guard = new SubRoleGuard(makeReflector({ entraRole: 'superadmin' }), prisma);
    await expect(guard.canActivate(makeContext('u1'))).rejects.toThrow(ForbiddenException);
  });
});
