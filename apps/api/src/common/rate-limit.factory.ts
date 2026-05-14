import type { Request, Response, NextFunction } from 'express';
import { ipKey, rateLimitSlidingWindow } from './rate-limit';

// Ceļi kurus izlaist no rate-limit — nav drošības risks, bet bloķē UX
const RATE_LIMIT_SKIP = new Set(['/api/csrf-token', '/api/health', '/api/auth/status']);

function getClientIp(req: Request) {
  return req.ip || req.socket.remoteAddress || 'unknown';
}

function toInt(value: string | undefined, fallback: number): number {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

// Noklusētie limiti pa grupām — admin lietotāji veic daudz API izsaukumu
const GROUP_DEFAULTS: Record<string, { max: number; windowSec: number }> = {
  auth: { max: 20, windowSec: 60 },
  admin: { max: 300, windowSec: 60 },
  global: { max: 200, windowSec: 60 },
  totp: { max: 5, windowSec: 300 },
  'totp-setup': { max: 3, windowSec: 3600 },
  'passkey-login': { max: 10, windowSec: 300 },
};

/**
 * Izveido rate-limit middleware grupai (auth, admin, global).
 * Konfigurē ar env mainīgajiem: RATE_LIMIT_{GROUP}_MAX, RATE_LIMIT_{GROUP}_WINDOW
 */
export function createRateLimitMiddleware(group: string) {
  const maxEnv = `RATE_LIMIT_${group.toUpperCase()}_MAX`;
  const windowEnv = `RATE_LIMIT_${group.toUpperCase()}_WINDOW`;
  const defaults = GROUP_DEFAULTS[group] ?? { max: 100, windowSec: 60 };

  return (req: Request, res: Response, next: NextFunction) => {
    // Izlaist ceļus kas nav drošības risks
    const path = req.originalUrl?.split('?')[0] ?? '';
    if (RATE_LIMIT_SKIP.has(path)) return next();

    const limit = toInt(process.env[maxEnv], defaults.max);
    const windowMs = toInt(process.env[windowEnv], defaults.windowSec) * 1000;

    const ip = getClientIp(req);
    const key = `${group}:${ipKey(ip)}`;

    // Async sliding window — Redis pipeline
    rateLimitSlidingWindow({ key, limit, windowMs })
      .then((out) => {
        res.setHeader(`X-RateLimit-${group}-Limit`, String(limit));
        res.setHeader(`X-RateLimit-${group}-Remaining`, String(out.remaining));
        res.setHeader(
          `X-RateLimit-${group}-Reset`,
          String(Math.ceil(out.resetAt / 1000)),
        );

        if (!out.ok) {
          const retryAfter = Math.max(
            1,
            Math.ceil((out.resetAt - Date.now()) / 1000),
          );
          res.setHeader(`Retry-After-${group}`, String(retryAfter));

          return res.status(429).json({
            ok: false,
            code: 'rate_limited',
            message: 'Too many requests. Please retry later.',
            error: 'rate_limited',
            retryAfterSec: retryAfter,
          });
        }

        next();
      })
      .catch(() => {
        // Redis kļūda — fail-closed uz auth endpoints (drošībai)
        const authGroups = ['auth', 'totp', 'totp-setup', 'passkey-login'];
        if (authGroups.includes(group)) {
          res.status(503).json({ code: 'service_unavailable', message: 'Serviss īslaicīgi nepieejams' });
        } else {
          next(); // Pārējie — fail-open (pieejamība)
        }
      });
  };
}
