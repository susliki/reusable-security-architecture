/* eslint-disable @typescript-eslint/no-explicit-any */
import { createRateLimitMiddleware } from './rate-limit.factory';
import * as rateLimit from './rate-limit';

jest.mock('./rate-limit', () => {
  const actual = jest.requireActual('./rate-limit');
  return {
    ...actual,
    rateLimitSlidingWindow: jest.fn(),
  };
});

const mockedSlidingWindow = rateLimit.rateLimitSlidingWindow as jest.MockedFunction<
  typeof rateLimit.rateLimitSlidingWindow
>;

function makeReq(originalUrl: string, ip = '1.2.3.4'): any {
  return {
    originalUrl,
    ip,
    socket: { remoteAddress: ip },
  };
}

function makeRes(): any {
  const res: any = {
    headers: {} as Record<string, string>,
    setHeader: jest.fn((key: string, val: string) => {
      res.headers[key] = val;
    }),
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
  };
  return res;
}

describe('createRateLimitMiddleware', () => {
  beforeEach(() => {
    mockedSlidingWindow.mockReset();
  });

  it('izlaiž pieprasījumu, kad limits nav pārsniegts', async () => {
    mockedSlidingWindow.mockResolvedValue({ ok: true, remaining: 4, resetAt: Date.now() + 300000 });
    const mw = createRateLimitMiddleware('totp');
    const req = makeReq('/api/auth/totp/verify');
    const res = makeRes();
    const next = jest.fn();

    mw(req, res, next);
    await new Promise((r) => setImmediate(r));

    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
    expect(res.headers['X-RateLimit-totp-Limit']).toBe('5'); // default TOTP max
    expect(res.headers['X-RateLimit-totp-Remaining']).toBe('4');
  });

  it('atgriež 429 kad limits pārsniegts', async () => {
    mockedSlidingWindow.mockResolvedValue({ ok: false, remaining: 0, resetAt: Date.now() + 100000 });
    const mw = createRateLimitMiddleware('totp');
    const req = makeReq('/api/auth/totp/verify');
    const res = makeRes();
    const next = jest.fn();

    mw(req, res, next);
    await new Promise((r) => setImmediate(r));

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(429);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ code: 'rate_limited' }),
    );
  });

  it('TOTP profila limits ir 5 pieprasījumi / 300s (stingrs)', async () => {
    mockedSlidingWindow.mockResolvedValue({ ok: true, remaining: 4, resetAt: 0 });
    const mw = createRateLimitMiddleware('totp');
    const req = makeReq('/api/auth/totp/verify');
    const res = makeRes();
    const next = jest.fn();

    mw(req, res, next);
    await new Promise((r) => setImmediate(r));

    expect(mockedSlidingWindow).toHaveBeenCalledWith(
      expect.objectContaining({
        limit: 5,
        windowMs: 300 * 1000,
      }),
    );
  });

  it('step-up verify arī izmanto `totp` profilu (5/300s)', async () => {
    // M2 regresijas pārbaude — step-up ceļš tiek marķēts ar to pašu stingro profilu
    mockedSlidingWindow.mockResolvedValue({ ok: true, remaining: 4, resetAt: 0 });
    const mw = createRateLimitMiddleware('totp');
    const req = makeReq('/api/auth/step-up/verify');
    const res = makeRes();
    const next = jest.fn();

    mw(req, res, next);
    await new Promise((r) => setImmediate(r));

    expect(mockedSlidingWindow).toHaveBeenCalledWith(
      expect.objectContaining({ limit: 5, windowMs: 300000 }),
    );
  });

  it('fail-closed (503) uz auth grupām, kad Redis izmet kļūdu', async () => {
    mockedSlidingWindow.mockRejectedValue(new Error('redis down'));
    const mw = createRateLimitMiddleware('totp');
    const req = makeReq('/api/auth/totp/verify');
    const res = makeRes();
    const next = jest.fn();

    mw(req, res, next);
    await new Promise((r) => setImmediate(r));

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(503);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ code: 'service_unavailable' }),
    );
  });

  it('fail-open uz `global` grupu, kad Redis izmet kļūdu', async () => {
    mockedSlidingWindow.mockRejectedValue(new Error('redis down'));
    const mw = createRateLimitMiddleware('global');
    const req = makeReq('/api/me/certificates');
    const res = makeRes();
    const next = jest.fn();

    mw(req, res, next);
    await new Promise((r) => setImmediate(r));

    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  it('izlaiž /api/csrf-token bez limita pārbaudes', () => {
    const mw = createRateLimitMiddleware('auth');
    const req = makeReq('/api/csrf-token');
    const res = makeRes();
    const next = jest.fn();

    mw(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(mockedSlidingWindow).not.toHaveBeenCalled();
  });

  it('izlaiž /api/health bez limita pārbaudes', () => {
    const mw = createRateLimitMiddleware('global');
    const req = makeReq('/api/health');
    const res = makeRes();
    const next = jest.fn();

    mw(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(mockedSlidingWindow).not.toHaveBeenCalled();
  });

  it('IP key tiek iegūts no req.ip (X-Forwarded-For header manipulācija nevar apiet)', async () => {
    /*
    createRateLimitMiddleware lasa IP no req.ip (kuru Express iestata pēc
    trust proxy konfigurācijas). Klientu piegādāts X-Forwarded-For netiek
    lasīts tieši — middleware uzticas tikai req.ip.
    */
    mockedSlidingWindow.mockResolvedValue({ ok: true, remaining: 4, resetAt: 0 });
    const mw = createRateLimitMiddleware('auth');
    const req = {
      originalUrl: '/api/auth/login',
      ip: '10.0.0.1', // Express-set IP
      headers: { 'x-forwarded-for': '99.99.99.99' }, // neleģitīms spoof
      socket: { remoteAddress: '10.0.0.1' },
    };
    const res = makeRes();
    const next = jest.fn();

    mw(req as any, res, next);
    await new Promise((r) => setImmediate(r));

    // Atslēga ir saistīta ar 10.0.0.1, nevis 99.99.99.99
    const call = mockedSlidingWindow.mock.calls[0][0];
    expect(call.key).toContain('auth:');
    // Hashētā vērtība no 99.99.99.99 atšķiras no 10.0.0.1
    const { ipKey } = jest.requireActual('./rate-limit');
    expect(call.key).toBe(`auth:${ipKey('10.0.0.1')}`);
    expect(call.key).not.toBe(`auth:${ipKey('99.99.99.99')}`);
  });
});
