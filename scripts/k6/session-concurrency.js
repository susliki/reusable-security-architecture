// k6 tests — sesiju vienlaicīguma tests
// 200 VU, 60s — mērī sesiju izveides/iznīcināšanas ātrumu un Redis atmiņu
// Lietošana: k6 run scripts/k6/session-concurrency.js
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Counter } from 'k6/metrics';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';

export const options = {
  scenarios: {
    session_flood: {
      executor: 'constant-vus',
      vus: 200,
      duration: '60s',
    },
  },
};

const sessionCreateDuration = new Trend('session_create_duration');
const sessionDestroyDuration = new Trend('session_destroy_duration');
const sessionsCreated = new Counter('sessions_created');

export default function () {
  // Izveidot sesiju — /api/auth/status izveido jaunu sesiju ja nav
  const createRes = http.get(`${BASE_URL}/api/auth/status`, {
    tags: { name: 'session-create' },
  });

  sessionCreateDuration.add(createRes.timings.duration);
  sessionsCreated.add(1);

  check(createRes, {
    'status 200': (r) => r.status === 200,
  });

  // Iznīcināt sesiju
  const destroyRes = http.post(`${BASE_URL}/api/auth/logout`, null, {
    headers: { 'Content-Type': 'application/json' },
    tags: { name: 'session-destroy' },
  });

  sessionDestroyDuration.add(destroyRes.timings.duration);

  check(destroyRes, {
    'logout 200': (r) => r.status === 200,
  });

  sleep(0.1);
}

export function teardown() {
  console.log('=== Session Concurrency Rezultāti ===');
  console.log('Pārbaudīt Redis sesiju skaitu un atmiņu:');
  console.log('  ssh <REDIS_HOST> "docker exec redis redis-cli DBSIZE"');
  console.log('  ssh <REDIS_HOST> "docker exec redis redis-cli INFO memory | grep used_memory_human"');
}
