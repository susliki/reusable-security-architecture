/*
CSRF double-submit cookie aizsardzība — OWASP ASVS v4 §4.2.2
Tokens tiek ģenerēts un saglabāts sīkfailā; frontend nolasa un nosūta
caur X-CSRF-Token galveni. Serveris salīdzina abus.
*/
import { doubleCsrf } from 'csrf-csrf';
import type { Request, Response, NextFunction } from 'express';

const isProd = process.env.NODE_ENV === 'production';

// Atsevišķi maršruti kurus izlaist no CSRF pārbaudes
const SKIP_PATHS = [
  '/api/admin/audit/export/run', // Fona darbs ar X-Job-Token autentifikāciju
];

// Auth maršruti izslēgti no CSRF — nav sesijas ko aizsargāt pirms autentifikācijas
// Aizsardzību nodrošina rate limiting uz auth galapunktiem
const SKIP_PREFIXES = [
  '/api/auth/',   // Visi auth galapunkti — pre-auth, CSRF nav piemērojams
  '/api/public/', // Publiskā verifikācija, nav sesijas
  '/api/dev/',    // Dev galapunkti — aizsargāti ar DEV_ENDPOINTS env mainīgo
];

// Eksportēts testēšanas vajadzībām (T4)
export function shouldSkipCsrf(req: Request): boolean {
  const path = req.originalUrl.split('?')[0];
  if (SKIP_PATHS.includes(path)) return true;
  return SKIP_PREFIXES.some((prefix) => path.startsWith(prefix));
}

const csrfSecret = (process.env.CSRF_SECRET ?? '').trim();
if (!csrfSecret && isProd) {
  throw new Error('CSRF_SECRET must be set in production');
}

const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => csrfSecret || 'dev-csrf-secret-at-least-32-chars-long',
  // Sesijas ID kā papildu saistība — tokens derīgs tikai šai sesijai
  getSessionIdentifier: (req) => (req as any).session?.id ?? 'anonymous',
  cookieName: isProd ? '__Host-csrf' : 'csrf',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax' as const,
    secure: isProd,
    path: '/',
  },
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'] as string,
  skipCsrfProtection: shouldSkipCsrf,
  errorConfig: {
    statusCode: 403,
    message: 'CSRF token validation failed',
    code: 'csrf_invalid',
  },
});

export { generateCsrfToken, doubleCsrfProtection };

/*
GET /api/csrf-token — frontend izsauc lai saņemtu tokenu
Problēma: saveUninitialized=false nozīmē ka jauna sesija (bez sīkfaila) nav saglabāta Redis.
CSRF tokens tiek piesaistīts session.id — ja sesija nav persisted, nākamajā pieprasījumā
tiks piešķirts jauns session.id un vecais CSRF tokens kļūs nederīgs (403).
Risinājums: force-save sesiju pirms tokena ģenerēšanas, lai session.id tiek fiksēts Redis.
*/
export function csrfTokenHandler(req: Request, res: Response, _next: NextFunction) {
  const sess = (req as any).session;
  if (!sess) {
    res.status(500).json({ code: 'csrf_init_failed', message: 'No session available' });
    return;
  }

  // Atzīmē sesiju kā "modified" lai express-session to saglabā Redis pat ar saveUninitialized=false
  if (!sess._csrfInit) {
    sess._csrfInit = true;
  }

  sess.save((err: Error | null) => {
    if (err) {
      console.error('Sesijas saglabāšana neizdevās pirms CSRF tokena:', err);
      res.status(500).json({ code: 'csrf_init_failed', message: 'Session save failed' });
      return;
    }
    try {
      const token = generateCsrfToken(req, res);
      res.json({ csrfToken: token });
    } catch (genErr) {
      console.error('CSRF tokena ģenerēšana neizdevās:', genErr);
      res.status(500).json({ code: 'csrf_init_failed', message: 'CSRF token generation failed' });
    }
  });
}
