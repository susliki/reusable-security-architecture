// k6 tests — audit log rakstīšanas caurlaidspēja
// Katrs API pieprasījums automātiski ģenerē audit ierakstu (HMAC chain)
// Mērī writes/s un latency zem slodzes
// Lietošana: k6 run -e BASE_URL=... -e SESSION_COOKIE=... scripts/k6/audit-write.js
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Counter } from 'k6/metrics';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';
const SESSION_COOKIE = __ENV.SESSION_COOKIE || '';

export const options = {
  stages: [
    { duration: '15s', target: 25 },
    { duration: '30s', target: 100 },
    { duration: '15s', target: 0 },
  ],
  thresholds: {
    audit_write_duration: ['p(95)<500'],
  },
};

const writeDuration = new Trend('audit_write_duration');
const writeCount = new Counter('audit_writes_total');

export default function () {
  // /api/auth/status — ātrs endpoint, ģenerē audit ierakstu
  const res = http.get(`${BASE_URL}/api/auth/status`, {
    headers: { 'Cookie': `connect.sid=${SESSION_COOKIE}` },
    tags: { name: 'audit-trigger' },
  });

  writeDuration.add(res.timings.duration);
  writeCount.add(1);

  check(res, {
    'status 200': (r) => r.status === 200,
  });

  sleep(0.1);
}

// Pēc testa — manuāli pārbaudīt HMAC chain integritāti
export function teardown() {
  console.log('=== Pēc testa ===');
  console.log('Pārbaudīt audit integritāti:');
  console.log(`  curl -s "${BASE_URL}/api/admin/audit/integrity" -H "Cookie: connect.sid=<admin>" | jq .`);
}
