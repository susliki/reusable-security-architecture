// k6 tests — rate limiter uzvedība zem ilgstošas slodzes
// 100 VU, 120s — mērī block rate, 429 response latency, Redis atmiņu
// Lietošana: k6 run scripts/k6/rate-limiter.js
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Counter } from 'k6/metrics';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';

export const options = {
  scenarios: {
    sustained_load: {
      executor: 'constant-vus',
      vus: 100,
      duration: '120s',
    },
  },
};

const blockedRate = new Rate('rate_limited_pct');
const totalRequests = new Counter('total_requests');
const blockedRequests = new Counter('blocked_requests');

export default function () {
  // Auth endpoint — stingrākais limits (20 req/60s per IP)
  const res = http.post(
    `${BASE_URL}/api/auth/webauthn/auth/options`,
    '{}',
    {
      headers: { 'Content-Type': 'application/json' },
      tags: { name: 'rate-limit-test' },
    },
  );

  const isBlocked = res.status === 429;
  blockedRate.add(isBlocked);
  totalRequests.add(1);
  if (isBlocked) blockedRequests.add(1);

  check(res, {
    'atbilde ir 201 vai 429': (r) => r.status === 201 || r.status === 429,
  });

  sleep(0.1);
}

export function teardown(data) {
  console.log('=== Rate Limiter Rezultāti ===');
  console.log('Pārbaudīt Redis atmiņu:');
  console.log('  ssh <REDIS_HOST> "docker exec redis redis-cli INFO memory | grep used_memory_human"');
}
