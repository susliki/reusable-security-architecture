import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Counter } from 'k6/metrics';

/**
 * PII šifrēšanas veiktspējas testi — tēzes 3.4. nodaļai.
 * Mēra AES-256-GCM overhead uz CRUD operācijām.
 *
 * Priekšnosacījums: API darbojas ar TEST datubāzi un admin sesiju.
 * Palaist: k6 run k6/pii-encryption-bench.js --env BASE_URL=http://localhost:3000
 */

const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';
const ADMIN_COOKIE = __ENV.ADMIN_COOKIE || '';

const createUserTrend = new Trend('user_create_ms', true);
const findUserTrend = new Trend('user_find_by_email_ms', true);
const updateUserTrend = new Trend('user_update_ms', true);
const listUsersTrend = new Trend('user_list_100_ms', true);
const encryptionErrors = new Counter('encryption_errors');

// CSRF token un cookie — iegūst setup() fāzē
let csrfToken = '';
let csrfCookie = '';

function allCookies() {
  return csrfCookie ? `${ADMIN_COOKIE}; ${csrfCookie}` : ADMIN_COOKIE;
}

function readHeaders() {
  return {
    'Content-Type': 'application/json',
    Cookie: allCookies(),
  };
}

function writeHeaders() {
  return {
    'Content-Type': 'application/json',
    Cookie: allCookies(),
    'x-csrf-token': csrfToken,
  };
}

export const options = {
  scenarios: {
    // Viena operācija — mēra latenci
    single_ops: {
      executor: 'per-vu-iterations',
      vus: 1,
      iterations: 100,
      exec: 'singleOps',
    },
    // Slodzes tests — mēra caurlaidspēju
    load_test: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '30s', target: 10 },
        { duration: '1m', target: 10 },
        { duration: '30s', target: 0 },
      ],
      exec: 'loadTest',
      startTime: '2m',
    },
  },
  thresholds: {
    // Šifrēšanas overhead nedrīkst pārsniegt šos limitus
    user_create_ms: ['p(95)<50'],
    user_find_by_email_ms: ['p(95)<20'],
    user_update_ms: ['p(95)<50'],
    user_list_100_ms: ['p(95)<200'],
  },
};

// ── Setup — CSRF token iegūšana ──

export function setup() {
  const csrfRes = http.get(`${BASE_URL}/api/csrf-token`, {
    headers: { Cookie: ADMIN_COOKIE },
    redirects: 0,
  });
  if (csrfRes.status === 200) {
    const body = JSON.parse(csrfRes.body);
    // Iegūt csrf cookie no Set-Cookie header
    const setCookies = csrfRes.headers['Set-Cookie'] || '';
    const csrfCookieMatch = (Array.isArray(setCookies) ? setCookies.join('; ') : setCookies)
      .split(',')
      .map(c => c.trim())
      .find(c => c.startsWith('__Host-csrf=') || c.startsWith('csrf='));
    const csrfCookie = csrfCookieMatch ? csrfCookieMatch.split(';')[0] : '';
    console.log(`CSRF token iegūts: ${body.csrfToken.substring(0, 10)}...`);
    console.log(`CSRF cookie: ${csrfCookie.substring(0, 20)}...`);
    return { csrfToken: body.csrfToken, csrfCookie };
  }
  console.error(`CSRF token iegūšana neizdevās: ${csrfRes.status} ${csrfRes.body}`);
  return { csrfToken: '', csrfCookie: '' };
}

// ── Scenāriji ──

export function singleOps(data) {
  csrfToken = data.csrfToken;
  csrfCookie = data.csrfCookie;
  const uniqueEmail = `bench-${__VU}-${__ITER}-${Date.now()}@test.lv`;

  // CREATE — lietotāja izveide ar šifrēšanu
  const createRes = http.post(
    `${BASE_URL}/api/admin/users`,
    JSON.stringify({ email: uniqueEmail, displayName: 'Bench Lietotājs', role: 'USER' }),
    { headers: writeHeaders(), tags: { op: 'create' } },
  );
  createUserTrend.add(createRes.timings.duration);
  if (
    !check(createRes, {
      'create 2xx': (r) => r.status >= 200 && r.status < 300,
    })
  ) {
    encryptionErrors.add(1);
    if (__ITER < 3) console.error(`CREATE failed: ${createRes.status} ${createRes.body}`);
  }

  // FIND — meklēšana pēc e-pasta (blind index)
  const findRes = http.get(
    `${BASE_URL}/api/admin/users?email=${encodeURIComponent(uniqueEmail)}`,
    { headers: readHeaders(), tags: { op: 'find' } },
  );
  findUserTrend.add(findRes.timings.duration);
  if (
    !check(findRes, {
      'find 2xx': (r) => r.status >= 200 && r.status < 300,
    })
  ) {
    encryptionErrors.add(1);
  }

  // UPDATE — atjaunināšana ar pāršifrēšanu
  if (createRes.status === 201 || createRes.status === 200) {
    try {
      const userId = JSON.parse(createRes.body).id;
      if (userId) {
        const updateRes = http.patch(
          `${BASE_URL}/api/admin/users/${userId}`,
          JSON.stringify({ displayName: 'Atjaunināts Vārds' }),
          { headers: writeHeaders(), tags: { op: 'update' } },
        );
        updateUserTrend.add(updateRes.timings.duration);
      }
    } catch {
      // Body parsēšanas kļūda — ignorēt
    }
  }

  sleep(0.1);
}

export function loadTest(data) {
  csrfToken = data.csrfToken;
  csrfCookie = data.csrfCookie;
  // LIST — 100 lietotāju saraksts ar atšifrēšanu
  const listRes = http.get(
    `${BASE_URL}/api/admin/users?limit=100`,
    { headers: readHeaders(), tags: { op: 'list' } },
  );
  listUsersTrend.add(listRes.timings.duration);

  check(listRes, {
    'list 2xx': (r) => r.status >= 200 && r.status < 300,
  });

  sleep(1);
}

/*
 * Sagaidāmie rezultāti (~8000 lietotāji):
 *
 * | Operācija              | p50    | p95    | Slieksnis  |
 * |------------------------|--------|--------|------------|
 * | User create            | <10ms  | <50ms  | p95 < 50ms |
 * | Find by email (HMAC)   | <5ms   | <20ms  | p95 < 20ms |
 * | User update            | <10ms  | <50ms  | p95 < 50ms |
 * | List 100 (decrypt all) | <50ms  | <200ms | p95 <200ms |
 */
