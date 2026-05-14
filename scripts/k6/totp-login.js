// k6 slodzes tests — TOTP pieslēgšanās caurlaidspēja
// Lietošana: k6 run --out json=docs/security-testing/reports/k6-totp-login.json scripts/k6/totp-login.js
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';

export const options = {
  stages: [
    { duration: '15s', target: 10 },   // Pakāpenisks kāpums
    { duration: '30s', target: 50 },    // Pilna slodze
    { duration: '15s', target: 0 },     // Atslābums
  ],
  thresholds: {
    http_req_duration: ['p(95)<2000'],   // p95 < 2s
    http_req_failed: ['rate<0.1'],       // < 10% kļūdu
  },
};

const loginDuration = new Trend('totp_login_duration');
const loginSuccess = new Rate('totp_login_success');

export default function () {
  // 1. CSRF tokena iegūšana
  const csrfRes = http.get(`${BASE_URL}/api/csrf-token`, {
    tags: { name: 'csrf' },
  });

  const csrfToken = csrfRes.json('token') || '';

  // 2. TOTP register — izveido lietotāju ar unikālu e-pastu
  const registerRes = http.post(
    `${BASE_URL}/api/auth/totp/register`,
    JSON.stringify({
      email: `k6-totp-${__VU}-${__ITER}@loadtest.lv`,
    }),
    {
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
      },
      tags: { name: 'totp-register' },
    },
  );

  loginDuration.add(registerRes.timings.duration);
  loginSuccess.add(registerRes.status === 201 || registerRes.status === 200);

  check(registerRes, {
    'register status 2xx vai 429': (r) => (r.status >= 200 && r.status < 300) || r.status === 429,
  });

  // 3. TOTP verify — prasa reālu OTP kodu
  // TODO: dev vidē izmantot fiksētu kodu vai dev bypass
  // Pagaidām mērām tikai register throughput

  sleep(0.5);
}
