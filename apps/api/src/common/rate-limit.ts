import { createHash } from 'crypto';
import type Redis from 'ioredis';

/**
 * Redis bīdāmā loga (sliding window) rate limiter.
 * Izmanto sorted set ar pieprasījumu timestamp kā score.
 * Daudzinstanču drošs — visi API serveri dala vienu Redis.
 */

let redisClient: Redis | null = null;

/** Inicializē Redis klientu — izsauc no main.ts pēc NestFactory.create */
export function initRateLimitRedis(client: Redis) {
  redisClient = client;
}

export async function rateLimitSlidingWindow(opts: {
  key: string;
  limit: number;
  windowMs: number;
}): Promise<{ ok: boolean; remaining: number; resetAt: number }> {
  if (!redisClient) {
    // Fail-closed ja Redis nav pieejams — bloķēt pieprasījumu
    return { ok: false, remaining: 0, resetAt: Date.now() + opts.windowMs };
  }

  const now = Date.now();
  const windowStart = now - opts.windowMs;
  const redisKey = `rl:${opts.key}`;

  /*
  Atomāra operācija ar pipeline:
  1. Noņemt novecojušos ierakstus (score < windowStart)
  2. Pievienot jauno pieprasījumu
  3. Saskaitīt logā esošos pieprasījumus
  4. Iestatīt TTL (automātiska tīrīšana)
  */
  const pipeline = redisClient.pipeline();
  pipeline.zremrangebyscore(redisKey, 0, windowStart);
  pipeline.zadd(redisKey, now, `${now}:${Math.random().toString(36).slice(2, 8)}`);
  pipeline.zcard(redisKey);
  pipeline.pexpire(redisKey, opts.windowMs);

  const results = await pipeline.exec();

  // zcard rezultāts ir 3. komanda (index 2)
  const count = (results?.[2]?.[1] as number) ?? 0;
  const remaining = Math.max(0, opts.limit - count);
  const resetAt = now + opts.windowMs;

  if (count > opts.limit) {
    return { ok: false, remaining: 0, resetAt };
  }

  return { ok: true, remaining, resetAt };
}

/** Hash IP lai izvairītos no neapstrādātu IP ierakstīšanas žurnālos */
export function ipKey(ip: string) {
  return createHash('sha256').update(ip, 'utf8').digest('hex').slice(0, 16);
}
