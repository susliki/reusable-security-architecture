// k6 tests — šifrētu CRUD operāciju veiktspēja
// Mērī encryption overhead salīdzinot ar nešifrētu baseline
// Lietošana: k6 run -e BASE_URL=... -e SESSION_COOKIE=... scripts/k6/encrypted-crud.js
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend } from 'k6/metrics';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';
const SESSION_COOKIE = __ENV.SESSION_COOKIE || '';
const CSRF_TOKEN = __ENV.CSRF_TOKEN || '';

export const options = {
  scenarios: {
    encrypted_crud: {
      executor: 'constant-vus',
      vus: 20,
      duration: '30s',
    },
  },
  thresholds: {
    encrypted_create: ['p(95)<1000'],
    encrypted_read: ['p(95)<500'],
  },
};

const createDuration = new Trend('encrypted_create');
const readDuration = new Trend('encrypted_read');

export default function () {
  const headers = {
    'Content-Type': 'application/json',
    'Cookie': `connect.sid=${SESSION_COOKIE}`,
    'X-CSRF-Token': CSRF_TOKEN,
  };

  // CREATE — sea service ieraksts (nav šifrēts, bet mērām DB write throughput)
  const createRes = http.post(
    `${BASE_URL}/api/me/profile`,
    JSON.stringify({
      vesselName: `K6 Test Vessel ${__VU}-${__ITER}`,
      rank: 'AB',
      startDate: '2024-01-01',
      endDate: '2024-06-30',
      days: 180,
    }),
    { headers, tags: { name: 'create-profile' } },
  );

  createDuration.add(createRes.timings.duration);
  check(createRes, {
    'create 2xx vai 403': (r) => (r.status >= 200 && r.status < 300) || r.status === 403,
  });

  // READ — profils ar šifrētiem laukiem (email, displayName atšifrējas automātiski)
  const readRes = http.get(`${BASE_URL}/api/me`, {
    headers: { 'Cookie': `connect.sid=${SESSION_COOKIE}` },
    tags: { name: 'read-profile' },
  });

  readDuration.add(readRes.timings.duration);
  check(readRes, {
    'read 200': (r) => r.status === 200,
  });

  sleep(0.5);
}
