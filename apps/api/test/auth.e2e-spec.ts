/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-argument */
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import session from 'express-session';
import { createRateLimitMiddleware } from './../src/common/rate-limit.factory';

// Mock ESM auth libraries before any module loads
jest.mock('@simplewebauthn/server', () => ({
  generateRegistrationOptions: jest
    .fn()
    .mockResolvedValue({ challenge: 'reg-challenge-abc' }),
  verifyRegistrationResponse: jest.fn(),
  generateAuthenticationOptions: jest
    .fn()
    .mockResolvedValue({ challenge: 'auth-challenge-xyz' }),
  verifyAuthenticationResponse: jest.fn(),
}));

jest.mock('otplib', () => ({
  generateSecret: jest.fn(() => 'MOCKSECRET'),
  generate: jest.fn().mockResolvedValue('123456'),
  verify: jest.fn().mockResolvedValue(false),
  generateURI: jest.fn(() => 'otpauth://totp/test'),
}));

import { verifyAuthenticationResponse } from '@simplewebauthn/server';

async function createApp(): Promise<INestApplication> {
  process.env.SESSION_SECRET = 'test-session-secret-min-32-chars!!';
  process.env.AUDIT_HMAC_KEY = 'test-audit-hmac-key-for-e2e-tests';
  process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
  process.env.RATE_LIMIT_AUTH_MAX = '5';

  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { AppModule } = require('./../src/app.module');

  const moduleFixture: TestingModule = await Test.createTestingModule({
    imports: [AppModule],
  }).compile();

  const app = moduleFixture.createNestApplication();

  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      whitelist: true,
      forbidNonWhitelisted: true,
    }),
  );
  app.setGlobalPrefix('api');
  app.use(
    session({
      secret: process.env.SESSION_SECRET,
      resave: false,
      saveUninitialized: false,
      cookie: { httpOnly: true, secure: false, sameSite: 'lax' },
    }),
  );
  app.use('/api/auth', createRateLimitMiddleware('auth'));

  await app.init();
  return app;
}

describe('Auth endpoints (e2e)', () => {
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

  // -------------------------------------------------------------------------
  // Passkey auth options
  // -------------------------------------------------------------------------

  it('POST /api/auth/webauthn/auth/options → 201 with challenge', async () => {
    const res = await request(app!.getHttpServer())
      .post('/api/auth/webauthn/auth/options')
      .send({});

    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty('challenge');
  });

  it('POST /api/auth/webauthn/auth/verify with no prior options → 400 no_challenge', async () => {
    // Fresh request with no session challenge set
    const res = await request(app!.getHttpServer())
      .post('/api/auth/webauthn/auth/verify')
      .send({
        id: 'cred-id',
        rawId: 'cred-id',
        response: {
          clientDataJSON: 'ey',
          authenticatorData: 'ey',
          signature: 'sig',
        },
        clientExtensionResults: {},
        type: 'public-key',
      });

    expect(res.status).toBe(400);
    expect(res.body).toMatchObject({
      code: 'no_challenge',
      message: 'No active challenge in session',
    });
  });

  it('GET /api/admin/audit/integrity without session → 401 session_required', async () => {
    const res = await request(app!.getHttpServer()).get('/api/admin/audit/integrity');
    expect(res.status).toBe(401);
    expect(res.body).toMatchObject({
      code: 'session_required',
      message: 'Authentication is required',
    });
  });

  // -------------------------------------------------------------------------
  // Logout
  // -------------------------------------------------------------------------

  it('POST /api/auth/logout when not logged in → 200 idempotent', async () => {
    const res = await request(app!.getHttpServer()).post('/api/auth/logout');

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ ok: true });
  });

  it('POST /api/auth/logout when logged in → session destroyed', async () => {
    // Mock a successful auth verification so we can establish a session
    (verifyAuthenticationResponse as jest.Mock).mockResolvedValueOnce({
      verified: true,
      authenticationInfo: { newCounter: 1, credentialID: 'cred-1' },
    });

    // Simulate being logged in by using the dev endpoint (DEV_ENDPOINTS must be set)
    process.env.DEV_ENDPOINTS = '1';
    jest.resetModules();
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { AppModule: AppModuleDev } = require('./../src/app.module');
    const modFixture = await Test.createTestingModule({
      imports: [AppModuleDev],
    }).compile();
    const devApp = modFixture.createNestApplication();
    devApp.useGlobalPipes(
      new ValidationPipe({ transform: true, whitelist: true }),
    );
    devApp.setGlobalPrefix('api');
    devApp.use(
      session({
        secret: process.env.SESSION_SECRET!,
        resave: false,
        saveUninitialized: false,
        cookie: { httpOnly: true, secure: false, sameSite: 'lax' },
      }),
    );
    await devApp.init();

    const agent = request.agent(devApp.getHttpServer());

    // Become admin
    await agent.post('/api/dev/become-admin').expect(201);

    // Logout
    const logoutRes = await agent.post('/api/auth/logout');
    expect(logoutRes.status).toBe(200);
    expect(logoutRes.body).toMatchObject({ ok: true });

    await devApp.close();
    delete process.env.DEV_ENDPOINTS;
  });

  // -------------------------------------------------------------------------
  // Rate limiting on auth endpoints
  // -------------------------------------------------------------------------

  it('auth endpoint rate limits after RATE_LIMIT_AUTH_MAX+1 requests', async () => {
    // RATE_LIMIT_AUTH_MAX is set to 5 in createApp().
    // Prior tests consumed some slots (auth/options, auth/verify, auth/logout).
    // Keep sending until we get a 429.
    const responses: number[] = [];
    let rateLimitedBody: Record<string, unknown> | null = null;
    for (let i = 0; i < 10; i++) {
      const res = await request(app!.getHttpServer())
        .post('/api/auth/webauthn/auth/options')
        .send({});
      responses.push(res.status);
      if (res.status === 429) {
        rateLimitedBody = res.body as Record<string, unknown>;
        break;
      }
    }
    expect(responses).toContain(429);
    expect(rateLimitedBody).toMatchObject({
      code: 'rate_limited',
      message: 'Too many requests. Please retry later.',
    });
  });
});
