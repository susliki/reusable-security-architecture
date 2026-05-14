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
 * GDPR Art. 15/16/20 — datu piekļuves, eksporta, labošanas testi
 */
describe('GDPR Data Access & Export (e2e)', () => {
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

  // --- Art. 15: Data access log ---

  it('GET /api/me/data-access-log without session → 401', async () => {
    const res = await request(app!.getHttpServer())
      .get('/api/me/data-access-log');

    expect(res.status).toBe(401);
  });

  // --- Art. 20: Data export ---

  it('GET /api/me/data-export without session → 401', async () => {
    const res = await request(app!.getHttpServer())
      .get('/api/me/data-export');

    expect(res.status).toBe(401);
  });

  // --- Art. 16: Rectification request ---

  it('POST /api/me/rectification-request without session → 401', async () => {
    const res = await request(app!.getHttpServer())
      .post('/api/me/rectification-request')
      .send({
        field: 'displayName',
        currentValue: 'Old Name',
        requestedValue: 'New Name',
      });

    expect(res.status).toBe(401);
  });

  it('Rectification endpoint exists and rejects unauthenticated', async () => {
    const res = await request(app!.getHttpServer())
      .post('/api/me/rectification-request')
      .send({});

    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty('code');
  });
});
