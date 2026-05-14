/* eslint-disable @typescript-eslint/no-explicit-any */
/*
CSRF modulis importē `csrf-csrf` pakotni, kas ir vienkārša CommonJS — nav
nepieciešams mock. Tāpat arī `doubleCsrf()` tiek inicializēts modulē kā
side-effect pie importa, tāpēc nav nepieciešams ieviest testu videi
CSRF_SECRET env mainīgo (NODE_ENV nav production testos).
*/

import { shouldSkipCsrf } from './csrf.middleware';

function makeReq(url: string): any {
  return { originalUrl: url };
}

describe('shouldSkipCsrf', () => {
  it('izlaiž visus /api/auth/* maršrutus', () => {
    expect(shouldSkipCsrf(makeReq('/api/auth/login'))).toBe(true);
    expect(shouldSkipCsrf(makeReq('/api/auth/totp/verify'))).toBe(true);
    expect(shouldSkipCsrf(makeReq('/api/auth/webauthn/auth/verify'))).toBe(true);
    expect(shouldSkipCsrf(makeReq('/api/auth/logout'))).toBe(true);
    expect(shouldSkipCsrf(makeReq('/api/auth/step-up/verify'))).toBe(true);
  });

  it('izlaiž visus /api/public/* maršrutus', () => {
    expect(shouldSkipCsrf(makeReq('/api/public/verify/ABC123'))).toBe(true);
    expect(shouldSkipCsrf(makeReq('/api/public/certificate'))).toBe(true);
  });

  it('izlaiž visus /api/dev/* maršrutus', () => {
    expect(shouldSkipCsrf(makeReq('/api/dev/seed'))).toBe(true);
    expect(shouldSkipCsrf(makeReq('/api/dev/login-as/u1'))).toBe(true);
  });

  it('izlaiž fona darba audit export maršrutu', () => {
    expect(shouldSkipCsrf(makeReq('/api/admin/audit/export/run'))).toBe(true);
  });

  it('NEIZLAIŽ vispārīgos autentificētos maršrutus', () => {
    expect(shouldSkipCsrf(makeReq('/api/me/profile'))).toBe(false);
    expect(shouldSkipCsrf(makeReq('/api/admin/users'))).toBe(false);
    expect(shouldSkipCsrf(makeReq('/api/profile/data'))).toBe(false);
    expect(shouldSkipCsrf(makeReq('/api/me/totp/reset'))).toBe(false);
  });

  it('NEIZLAIŽ citus /api/admin/* maršrutus (tikai konkrēts audit export)', () => {
    expect(shouldSkipCsrf(makeReq('/api/admin/audit/logs'))).toBe(false);
    expect(shouldSkipCsrf(makeReq('/api/admin/audit'))).toBe(false);
  });

  it('ignorē query string', () => {
    expect(shouldSkipCsrf(makeReq('/api/auth/login?next=/dashboard'))).toBe(true);
    expect(shouldSkipCsrf(makeReq('/api/me/profile?edit=1'))).toBe(false);
  });

  it('NEIZLAIŽ maršrutus, kas tikai sākas ar līdzīgu prefiksu, bet nav zem /api/auth/', () => {
    // /api/authentication nav /api/auth/ — tas ir svarīga prefiksa korekta salīdzināšana
    expect(shouldSkipCsrf(makeReq('/api/authentication/foo'))).toBe(false);
  });
});
