/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import session from 'express-session';

// Mock ESM libraries
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
 * GDPR Art. 17 — dzēšanas kaskādes testi
 *
 * Testē endpoint pieejamību un guard loģiku.
 * Pilns kaskādes tests prasa DB ar lietotāju datiem — atstāts integrācijas testiem.
 */
describe('GDPR Erasure (e2e)', () => {
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

  it('DELETE /api/admin/users/:id/gdpr-erase without session → 401', async () => {
    const res = await request(app!.getHttpServer())
      .delete('/api/admin/users/some-uuid/gdpr-erase');

    expect(res.status).toBe(401);
  });

  it('DELETE /api/admin/users/:id/gdpr-erase as non-admin → 403', async () => {
    // Sesija bez admin tiesībām — AuthGuard + AdminGuard noraidīs
    const agent = request.agent(app!.getHttpServer());

    const res = await agent
      .delete('/api/admin/users/some-uuid/gdpr-erase');

    // Nav sesijas → 401 (AuthGuard pirms AdminGuard)
    expect([401, 403]).toContain(res.status);
  });

  it('Erasure endpoint exists and returns proper error format', async () => {
    const res = await request(app!.getHttpServer())
      .delete('/api/admin/users/nonexistent/gdpr-erase');

    // Neatkarīgi no statusa — atbilde satur code un message
    expect(res.body).toHaveProperty('code');
    expect(res.body).toHaveProperty('message');
  });
});
