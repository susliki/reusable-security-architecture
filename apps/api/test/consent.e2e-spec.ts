/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import session from 'express-session';

jest.mock('@simplewebauthn/server', () => ({
  generateRegistrationOptions: jest.fn().mockResolvedValue({ challenge: 'c' }),
  verifyRegistrationResponse: jest.fn(),
  generateAuthenticationOptions: jest.fn().mockResolvedValue({ challenge: 'c' }),
  verifyAuthenticationResponse: jest.fn(),
}));
jest.mock('otplib', () => ({
  generateSecret: jest.fn(() => 'S'),
  generate: jest.fn().mockResolvedValue('123456'),
  verify: jest.fn().mockResolvedValue(false),
  generateURI: jest.fn(() => 'otpauth://totp/test'),
}));

async function createApp(): Promise<INestApplication> {
  process.env.SESSION_SECRET = 'test-session-secret-min-32-chars!!';
  process.env.AUDIT_HMAC_KEY = 'test-audit-hmac-key-for-e2e-tests';
  process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
  process.env.PRIVACY_POLICY_VERSION = '1.0';

  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { AppModule } = require('./../src/app.module');

  const moduleFixture: TestingModule = await Test.createTestingModule({
    imports: [AppModule],
  }).compile();

  const app = moduleFixture.createNestApplication();
  app.useGlobalPipes(new ValidationPipe({ transform: true, whitelist: true }));
  app.setGlobalPrefix('api');
  app.use(
    session({
      secret: process.env.SESSION_SECRET,
      resave: false,
      saveUninitialized: false,
      cookie: { httpOnly: true, secure: false, sameSite: 'lax' },
    }),
  );
  await app.init();
  return app;
}

/**
 * GDPR Art. 7 — piekrišanas izsekošanas testi
 */
describe('GDPR Consent (e2e)', () => {
  let app: INestApplication | undefined;

  beforeAll(async () => {
    app = await createApp();
  });

  afterAll(async () => {
    if (app) {
      await app.close();
      app = undefined;
    }
  });

  // --- Consent status ---

  it('GET /api/me/consent without session → 401', async () => {
    const res = await request(app!.getHttpServer())
      .get('/api/me/consent');

    expect(res.status).toBe(401);
  });

  // --- Consent acceptance ---

  it('POST /api/me/consent without session → 401', async () => {
    const res = await request(app!.getHttpServer())
      .post('/api/me/consent')
      .send({ policyVersion: '1.0' });

    expect(res.status).toBe(401);
  });

  // --- ConsentMiddleware ---

  it('ConsentMiddleware allows /api/auth/* through without consent', async () => {
    // Auth endpoints ir izņēmums — vienmēr pieejami
    const res = await request(app!.getHttpServer())
      .get('/api/auth/status');

    // Neprasa piekrišanu — atgriež normālu atbildi
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('authenticated');
  });

  it('ConsentMiddleware allows /api/me/consent through without consent', async () => {
    // Consent endpoint pats ir izņēmums — citādi nevarētu pieņemt piekrišanu
    const res = await request(app!.getHttpServer())
      .get('/api/me/consent');

    // 401 (nav sesijas), nevis 403 consent_required
    expect(res.status).toBe(401);
    expect(res.body.code).not.toBe('consent_required');
  });

  it('Auth routes are accessible without consent check', async () => {
    // /api/auth/* ir ConsentMiddleware izņēmums
    const res = await request(app!.getHttpServer())
      .post('/api/auth/logout');

    // Logout vienmēr pieejams — atgriež 200 (idempotent)
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ ok: true });
  });
});
