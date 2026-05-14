import type { SessionOptions, CookieOptions } from 'express-session';
import session from 'express-session';
import { RedisStore } from 'connect-redis';
import type Redis from 'ioredis';

// Mēs vienmēr atgriežam plain CookieOptions objektu (ne funkciju), tāpēc
// sašaurinām SessionOptions['cookie'] tipu, lai patērētāji var droši lasīt
// cookie.secure / cookie.maxAge bez papildu type-guard.
export type SessionOptionsWithCookie = Omit<SessionOptions, 'cookie'> & {
  cookie: CookieOptions;
};

function toInt(v: string | undefined, fallback: number) {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

/**
 * Redis sesiju veikals ar diviem TTL līmeņiem:
 * - idle TTL (30 min) — sesija beidzas pēc neaktivitātes
 * - absolute TTL (8h) — maksimālais sesijas laiks neatkarīgi no aktivitātes
 * OWASP ASVS v4 §3.3 — sesijas taimautam jābūt gan idle, gan absolute
 */
export function buildSessionOptions(redisClient: Redis): SessionOptionsWithCookie {
  const isProd = process.env.NODE_ENV === 'production';
  // Pēc noklusējuma uzticamies vienam proxy (nginx); izslēgt ar TRUST_PROXY=0
  const trustProxy = process.env.TRUST_PROXY !== '0';

  const secret = (process.env.SESSION_SECRET ?? '').trim();
  if (!secret || secret.length < 32) {
    if (isProd) {
      throw new Error('SESSION_SECRET must be set (>=32 chars) in production');
    }
    console.warn(
      JSON.stringify({
        ts: new Date().toISOString(),
        event: 'startup.session_secret',
        warning: 'missing_or_weak',
        usingFallback: true,
      }),
    );
  }

  // Idle TTL — sesija beidzas pēc 30 min neaktivitātes (rolling: true)
  const idleTtlSeconds = toInt(process.env.SESSION_IDLE_TTL, 30 * 60);
  // Absolute TTL — maksimālais sesijas laiks 8h
  const absoluteTtlSeconds = toInt(process.env.SESSION_ABSOLUTE_TTL, 8 * 60 * 60);
  const cookieName =
    (process.env.SESSION_COOKIE_NAME ?? 'sid').trim() || 'sid';

  const store = new RedisStore({
    client: redisClient,
    prefix: 'sess:',
    ttl: idleTtlSeconds,
    // Neizmantot touch — rolling sesija atjaunina TTL caur resave
    disableTouch: false,
  });

  return {
    name: cookieName,
    secret: secret.length >= 32 ? secret : 'dev-secret',
    resave: false,
    saveUninitialized: false,
    proxy: trustProxy,
    store,

    // Rolling: true — katrs pieprasījums atiestata idle TTL
    rolling: true,

    cookie: {
      httpOnly: true,
      /*
      H4 fix: ražošanā secure ir true pēc noklusējuma. Atļauts izslēgt tikai
      explicit COOKIE_SECURE=false (piemēram, lokāls HTTP debug uz prod imeidža).
      Iepriekš secure prasīja explicit COOKIE_SECURE=true — trūkstošs env mainīgais
      klusi noveda pie sesijas cookies sūtīšanas pa HTTP.
      */
      secure: isProd
        ? process.env.COOKIE_SECURE !== 'false'
        : process.env.COOKIE_SECURE === 'true',
      sameSite: 'lax',
      // Cookie maxAge = absolute TTL (pārlūks izdzēš pēc 8h)
      maxAge: absoluteTtlSeconds * 1000,
    },
  };
}
