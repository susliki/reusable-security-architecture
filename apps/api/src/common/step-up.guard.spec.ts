import { ForbiddenException } from '@nestjs/common';
import { StepUpGuard } from './step-up.guard';

function makeContext(stepUpVerifiedAt: string | null): any {
  return {
    switchToHttp: () => ({
      getRequest: () => ({
        session: { userId: 'u1', stepUpVerifiedAt },
      }),
    }),
  };
}

describe('StepUpGuard', () => {
  const guard = new StepUpGuard();

  it('bloķē ja stepUpVerifiedAt nav iestatīts', () => {
    expect(() => guard.canActivate(makeContext(null))).toThrow(ForbiddenException);
  });

  it('bloķē ja step-up ir vecāks par 5 min', () => {
    const sixMinAgo = new Date(Date.now() - 6 * 60 * 1000).toISOString();
    expect(() => guard.canActivate(makeContext(sixMinAgo))).toThrow(ForbiddenException);
  });

  it('atļauj ja step-up ir jaunāks par 5 min', () => {
    const oneMinAgo = new Date(Date.now() - 60 * 1000).toISOString();
    expect(guard.canActivate(makeContext(oneMinAgo))).toBe(true);
  });

  it('atļauj tikko veiktu step-up', () => {
    const now = new Date().toISOString();
    expect(guard.canActivate(makeContext(now))).toBe(true);
  });

  it('kļūdas kods ir step_up_required ja nav veikts', () => {
    try {
      guard.canActivate(makeContext(null));
      fail('Vajadzēja mest ForbiddenException');
    } catch (err: any) {
      expect(err.getResponse().code).toBe('step_up_required');
    }
  });

  it('kļūdas kods ir step_up_expired ja beidzies', () => {
    const tenMinAgo = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    try {
      guard.canActivate(makeContext(tenMinAgo));
      fail('Vajadzēja mest ForbiddenException');
    } catch (err: any) {
      expect(err.getResponse().code).toBe('step_up_expired');
    }
  });
});
