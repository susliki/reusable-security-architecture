import { config as loadEnv } from 'dotenv';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
// Lokālais apps/api/.env, tad fallback uz monorepo saknes .env
{
  const localEnv = resolve(process.cwd(), '.env');
  const rootEnv = resolve(process.cwd(), '../../.env');
  loadEnv({ path: existsSync(localEnv) ? localEnv : rootEnv });
}

import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { validateCryptoKeys } from './crypto/crypto-config';
import helmet from 'helmet';

import { requestIdMiddleware } from './common/request-id.middleware';
import { requestLoggerMiddleware } from './common/request-logger.middleware';

import session from 'express-session';
import { buildSessionOptions } from './common/session-store';

import { createRateLimitMiddleware } from './common/rate-limit.factory';
import { initRateLimitRedis } from './common/rate-limit';

import { AuditService } from './audit/audit.service';
import { auditMiddleware } from './audit/audit.middleware';
import { PrismaService } from './prisma/prisma.service';
import { validateSession } from './common/auth.guard';

import cookieParser from 'cookie-parser';

import {
  doubleCsrfProtection,
  csrfTokenHandler,
} from './common/csrf.middleware';

import { RedisService } from './redis/redis.service';
import { createMaintenanceMiddleware } from './common/maintenance.middleware';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  /*
  Drošības galvenes — OWASP ASVS v14.4.
  nginx (infra/nginx/default.conf) jau iestata X-Frame-Options, X-Content-Type-Options,
  Referrer-Policy, Permissions-Policy. Helmet papildina ar CSP un HSTS.
  */
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", 'data:', 'blob:'],
          connectSrc: ["'self'"],
          fontSrc: ["'self'"],
          frameSrc: ["'none'"],
          objectSrc: ["'none'"],
          baseUri: ["'self'"],
        },
      },
      // CORP atspējots — SPA un API vienā origin, nav nepieciešams
      crossOriginEmbedderPolicy: false,
      // HSTS — 1 gads ar subdomain iekļaušanu (DMZ nginx arī iestata, dubultošana droša)
      hsts: { maxAge: 31536000, includeSubDomains: true },
    }),
  );

  // CORS lokālajam dev portālam (CORS_ORIGIN nav iestatīts prod — neaktīvs)
  if (process.env.CORS_ORIGIN) {
    app.enableCors({
      origin: process.env.CORS_ORIGIN,
      credentials: true,
    });
  }

  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      whitelist: true,
      forbidNonWhitelisted: true,
    }),
  );

  // X-Forwarded-For uzticēšanās — 2 proxy ķēde: DMZ NPM (ja-npm-01) → Docker nginx → API
  // Ar 2 hopiem Express pareizi nolasa klienta IP no X-Forwarded-For galvenes
  const trustProxy = process.env.TRUST_PROXY !== '0';
  if (trustProxy) {
    app.getHttpAdapter().getInstance().set('trust proxy', 2);
  }

  app.setGlobalPrefix('api');

  // Pieprasījumu korelācija un žurnāli — agri ķēdē
  app.use(requestIdMiddleware);
  app.use(requestLoggerMiddleware);

  // Redis klients — sesijām un rate-limit
  const redis = app.get(RedisService);
  const redisClient = redis.getClient();

  // Sesijas (Redis krātuve — dīkstāve 30min, absolūtais 8h)
  const sessionOpts = buildSessionOptions(redisClient);
  app.use(session(sessionOpts));

  console.log(
    JSON.stringify({
      ts: new Date().toISOString(),
      event: 'startup.session',
      store: 'redis',
      cookieName: sessionOpts.name ?? null,
      secure: sessionOpts.cookie?.secure ?? null,
      sameSite: sessionOpts.cookie?.sameSite ?? null,
      ttlSec: Math.round(((sessionOpts.cookie?.maxAge as number) ?? 0) / 1000),
      trustProxy,
    }),
  );

  // Uzturēšanas režīma middleware — pēc sesijas, pirms CSRF
  // Admin lietotāji apiet, pārējiem 503 ja ieslēgts
  app.use(createMaintenanceMiddleware(redis));

  // Cookie parsēšana — csrf-csrf bibliotēkai nepieciešams req.cookies
  app.use(cookieParser());

  // CSRF double-submit cookie — OWASP ASVS v4 §4.2.2
  // Pēc sesijas (lai piekļūtu session.id), pirms rate-limit
  app.use('/api/csrf-token', csrfTokenHandler);
  app.use(doubleCsrfProtection);

  // Audits — jāreģistrē PIRMS rate-limit, lai 429 atbildes tiktu auditētas
  const audit = app.get(AuditService);
  app.use(auditMiddleware(audit));

  // rate-limit Redis inicializācija (sliding window)
  initRateLimitRedis(redisClient);

  // C3: per-endpoint rate limits — stingrāki limiti auth endpoints
  app.use('/api/auth/totp/verify', createRateLimitMiddleware('totp'));
  app.use('/api/auth/totp/setup', createRateLimitMiddleware('totp-setup'));
  // M2: step-up TOTP re-auth ar to pašu stingro 5/300s limitu kā login TOTP —
  // aizsargā pret brute-force pēc sesijas iegūšanas (1M iespējas / 5 per 5 min)
  app.use('/api/auth/step-up/verify', createRateLimitMiddleware('totp'));
  app.use('/api/auth/webauthn/auth', createRateLimitMiddleware('passkey-login'));
  app.use('/api/auth', createRateLimitMiddleware('auth'));
  app.use('/api/admin', createRateLimitMiddleware('admin'));
  app.use('/api', createRateLimitMiddleware('global'));

  // Bull Board aizsardzība — izmanto kopīgo validateSession() no auth.guard.ts
  // Vienots avots ar AuthGuard — novērš loģikas drift
  const prismaForBullBoard = app.get(PrismaService);
  app.use('/api/admin/queues', async (req: any, res: any, next: any) => {
    const result = await validateSession(req.session, prismaForBullBoard);
    if (!result.ok) {
      if (result.destroy) req.session.destroy(() => {});
      return res.status(result.status).json({ code: result.code, message: result.message });
    }
    // Admin lomas pārbaude (pēc validateSession DB atsvaidzināšanas)
    if (!req.session.isAdmin) {
      return res.status(403).json({ code: 'forbidden', message: 'Admin access is required' });
    }
    next();
  });

  // audit reģistrēts augstāk — pirms rate-limit middleware

  console.log(
    JSON.stringify({
      ts: new Date().toISOString(),
      event: 'startup.dev_endpoints',
      value: process.env.DEV_ENDPOINTS ?? null,
      enabled: process.env.DEV_ENDPOINTS === '1',
    }),
  );

  // Pārbaude pirms servera starta — nestrādāt bez šifrēšanas atslēgām
  validateCryptoKeys();

  await app.listen(3000);
}
bootstrap();
