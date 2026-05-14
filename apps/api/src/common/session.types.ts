import type { Session, SessionData } from 'express-session';

declare module 'express-session' {
  interface SessionData {
    userId?: string | null;
    userRole?: string | null;
    isAdmin?: boolean | null;
    firstName?: string | null; // Lietotāja vārds
    lastName?: string | null; // Lietotāja uzvārds
    clientIp?: string | null; // IP adrese sesijas izveidē — rāda drošības pārskatā
    userAgent?: string | null; // Pārlūka user-agent — ierīces identifikācijai
    createdAt?: string | null; // Sesijas izveides laiks (ISO)
    lastActive?: string | null; // Pēdējā aktivitāte (ISO) — atjaunina ar katru pieprasījumu
    userVerifiedAt?: string | null; // Kešo pārbaudi sesijā — atkārtoti pārbauda ik 60s
    userStatus?: string | null; // Lietotāja statuss — kešots no AuthGuard 60s pārbaudes
    passkeyRegChallenge?: string | null;
    passkeyAuthChallenge?: string | null;
    oidcState?: string | null;
    oidcNonce?: string | null;
    stepUpVerifiedAt?: string | null; // Step-up re-auth laiks (ISO) — 5 min logs
    consentedPolicyVersion?: string | null; // GDPR Art. 7 — kešota piekrišanas versija
    _csrfInit?: boolean; // Atzīme lai force-save sesiju pirms CSRF tokena ģenerēšanas
  }
}

/**
 * Tipizēta sesija — atbilst faktiskajam req.session tipam (Session & Partial<SessionData>)
 * ar mūsu pielāgotajiem laukiem. Izmanto šo servisu metožu parakstos.
 */
export type AuthSession = Session & Partial<SessionData>;
