/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-argument */
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import session from 'express-session';

// Prevent ESM-only packages (loaded transitively by AuthService) from breaking Jest
jest.mock('@simplewebauthn/server', () => ({
  generateRegistrationOptions: jest.fn(),
  verifyRegistrationResponse: jest.fn(),
  generateAuthenticationOptions: jest.fn(),
  verifyAuthenticationResponse: jest.fn(),
}));

jest.mock('otplib', () => ({
  generateSecret: jest.fn(),
  generate: jest.fn(),
  verify: jest.fn(),
  generateURI: jest.fn(),
}));

async function createApp(
  devEndpoints: '0' | '1' | undefined,
): Promise<INestApplication> {
  if (devEndpoints === undefined) {
    delete process.env.DEV_ENDPOINTS;
  } else {
    process.env.DEV_ENDPOINTS = devEndpoints;
  }

  process.env.SESSION_SECRET =
    process.env.SESSION_SECRET ?? 'test-session-secret';

  jest.resetModules();
  // reload AppModule so devEnabled reflects current process.env for each test case
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { AppModule } = require('./../src/app.module');

  const moduleFixture: TestingModule = await Test.createTestingModule({
    imports: [AppModule],
  }).compile();

  const app = moduleFixture.createNestApplication();
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

describe('DEV endpoints (e2e)', () => {
  let app: INestApplication | undefined;

  afterEach(async () => {
    if (app) {
      await app.close();
      app = undefined;
    }
  });

  it('returns 404 for /api/dev/become-admin when DEV_ENDPOINTS is 0', async () => {
    app = await createApp('0');

    await request(app.getHttpServer())
      .post('/api/dev/become-admin')
      .expect(404);
  });

  it('exposes /api/dev/become-admin when DEV_ENDPOINTS is 1', async () => {
    app = await createApp('1');
    const agent = request.agent(app.getHttpServer());

    const becomeAdmin = await agent.post('/api/dev/become-admin').expect(201);

    expect(becomeAdmin.body).toMatchObject({ ok: true, isAdmin: true });
  });
});
