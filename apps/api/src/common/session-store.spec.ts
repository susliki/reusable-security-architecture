/* eslint-disable @typescript-eslint/no-explicit-any */
// Mock connect-redis lai izvairītos no reāla Redis kliena inicializācijas
jest.mock('connect-redis', () => ({
  RedisStore: jest.fn().mockImplementation((opts: any) => ({ opts })),
}));

import { buildSessionOptions } from './session-store';

const fakeRedisClient = {} as any;

const originalEnv = process.env;

function resetEnv() {
  process.env = { ...originalEnv };
  delete process.env.NODE_ENV;
  delete process.env.COOKIE_SECURE;
  delete process.env.SESSION_SECRET;
  delete process.env.SESSION_IDLE_TTL;
  delete process.env.SESSION_ABSOLUTE_TTL;
  delete process.env.SESSION_COOKIE_NAME;
  delete process.env.TRUST_PROXY;
}

describe('buildSessionOptions', () => {
  let warnSpy: jest.SpyInstance;

  beforeEach(() => {
    resetEnv();
    warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    warnSpy.mockRestore();
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  describe('SESSION_SECRET validācija', () => {
    it('met kļūdu ražošanā ja SESSION_SECRET nav iestatīts', () => {
      process.env.NODE_ENV = 'production';
      expect(() => buildSessionOptions(fakeRedisClient)).toThrow(
        /SESSION_SECRET must be set/,
      );
    });

    it('met kļūdu ražošanā ja SESSION_SECRET ir par īsu (<32 simboli)', () => {
      process.env.NODE_ENV = 'production';
      process.env.SESSION_SECRET = 'short';
      expect(() => buildSessionOptions(fakeRedisClient)).toThrow(
        /SESSION_SECRET must be set/,
      );
    });

    it('izstrādes vidē turpina darboties ar vāju noslēpumu (brīdinājums)', () => {
      // Nav ražošana, SESSION_SECRET nav iestatīts — izmanto dev fallback
      const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
      const opts = buildSessionOptions(fakeRedisClient);
      expect(opts.secret).toBe('dev-secret');
      warnSpy.mockRestore();
    });

    it('pieņem derīgu 32+ simbolu noslēpumu', () => {
      process.env.NODE_ENV = 'production';
      process.env.SESSION_SECRET = 'a'.repeat(64);
      const opts = buildSessionOptions(fakeRedisClient);
      expect(opts.secret).toBe('a'.repeat(64));
    });
  });

  describe('H4: cookie secure karodziņš', () => {
    it('ražošanā pēc noklusējuma secure=true bez COOKIE_SECURE iestatījuma', () => {
      process.env.NODE_ENV = 'production';
      process.env.SESSION_SECRET = 'a'.repeat(64);
      const opts = buildSessionOptions(fakeRedisClient);
      expect(opts.cookie?.secure).toBe(true);
    });

    it('ražošanā secure var tikt izslēgts tikai ar explicit COOKIE_SECURE=false', () => {
      process.env.NODE_ENV = 'production';
      process.env.SESSION_SECRET = 'a'.repeat(64);
      process.env.COOKIE_SECURE = 'false';
      const opts = buildSessionOptions(fakeRedisClient);
      expect(opts.cookie?.secure).toBe(false);
    });

    it('dev vidē pēc noklusējuma secure=false (lokāls HTTP)', () => {
      const opts = buildSessionOptions(fakeRedisClient);
      expect(opts.cookie?.secure).toBe(false);
    });

    it('dev vidē secure var tikt ieslēgts ar COOKIE_SECURE=true', () => {
      process.env.COOKIE_SECURE = 'true';
      const opts = buildSessionOptions(fakeRedisClient);
      expect(opts.cookie?.secure).toBe(true);
    });
  });

  describe('TTL aprēķini', () => {
    it('noklusētais idle TTL ir 30 minūtes', () => {
      const opts = buildSessionOptions(fakeRedisClient);
      expect((opts.store as any).opts.ttl).toBe(30 * 60);
    });

    it('noklusētais absolūtais TTL (maxAge) ir 8 stundas', () => {
      const opts = buildSessionOptions(fakeRedisClient);
      expect(opts.cookie?.maxAge).toBe(8 * 60 * 60 * 1000);
    });

    it('SESSION_IDLE_TTL pārraksta idle TTL', () => {
      process.env.SESSION_IDLE_TTL = '1800';
      const opts = buildSessionOptions(fakeRedisClient);
      expect((opts.store as any).opts.ttl).toBe(1800);
    });

    it('SESSION_ABSOLUTE_TTL pārraksta maxAge', () => {
      process.env.SESSION_ABSOLUTE_TTL = '3600';
      const opts = buildSessionOptions(fakeRedisClient);
      expect(opts.cookie?.maxAge).toBe(3600 * 1000);
    });

    it('ignorē nederīgas TTL vērtības un atgriežas pie noklusējuma', () => {
      process.env.SESSION_IDLE_TTL = 'garbage';
      process.env.SESSION_ABSOLUTE_TTL = '-1';
      const opts = buildSessionOptions(fakeRedisClient);
      expect((opts.store as any).opts.ttl).toBe(30 * 60);
      expect(opts.cookie?.maxAge).toBe(8 * 60 * 60 * 1000);
    });
  });

  describe('Cookie vārds un parametri', () => {
    it('noklusētais cookie vārds ir "sid"', () => {
      const opts = buildSessionOptions(fakeRedisClient);
      expect(opts.name).toBe('sid');
    });

    it('SESSION_COOKIE_NAME pārraksta cookie vārdu', () => {
      process.env.SESSION_COOKIE_NAME = 'app-sid';
      const opts = buildSessionOptions(fakeRedisClient);
      expect(opts.name).toBe('app-sid');
    });

    it('cookie ir httpOnly un sameSite=lax', () => {
      const opts = buildSessionOptions(fakeRedisClient);
      expect(opts.cookie?.httpOnly).toBe(true);
      expect(opts.cookie?.sameSite).toBe('lax');
    });

    it('rolling sesija ir ieslēgta (idle TTL atjaunina katrs pieprasījums)', () => {
      const opts = buildSessionOptions(fakeRedisClient);
      expect(opts.rolling).toBe(true);
    });

    it('saveUninitialized ir false (neveido sesijas līdz nepieciešamībai)', () => {
      const opts = buildSessionOptions(fakeRedisClient);
      expect(opts.saveUninitialized).toBe(false);
    });

    it('trust proxy pēc noklusējuma ir true', () => {
      const opts = buildSessionOptions(fakeRedisClient);
      expect(opts.proxy).toBe(true);
    });

    it('TRUST_PROXY=0 izslēdz proxy uzticēšanos', () => {
      process.env.TRUST_PROXY = '0';
      const opts = buildSessionOptions(fakeRedisClient);
      expect(opts.proxy).toBe(false);
    });
  });
});
