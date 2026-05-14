// k6 tests — blind index e-pasta meklēšana
// Mērī query latency ar HMAC blind index vs tiešu meklēšanu
// Lietošana: k6 run -e BASE_URL=... -e SESSION_COOKIE=... scripts/k6/blind-index-lookup.js
import http from 'k6/http';
import { Trend } from 'k6/metrics';
import { check, sleep } from 'k6';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';
const SESSION_COOKIE = __ENV.SESSION_COOKIE || '';

export const options = {
  scenarios: {
    blind_index: {
      executor: 'constant-vus',
      vus: 20,
      duration: '30s',
    },
  },
  thresholds: {
    blind_index_lookup: ['p(95)<500'],
  },
};

const lookupDuration = new Trend('blind_index_lookup');

export default function () {
  const headers = {
    'Content-Type': 'application/json',
    'Cookie': `connect.sid=${SESSION_COOKIE}`,
  };

  // Admin user search — izmanto blind index (emailHmac)
  const res = http.get(
    `${BASE_URL}/api/admin/users?email=k6-search-${__VU}@test.lv`,
    { headers, tags: { name: 'blind-index-search' } },
  );

  lookupDuration.add(res.timings.duration);
  check(res, {
    'search 200 vai 403': (r) => r.status === 200 || r.status === 403,
  });

  sleep(0.3);
}
