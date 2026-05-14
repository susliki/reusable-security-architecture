/*
Redis savienojuma serviss — viena ioredis instance visam API.
Izmantots sesijām, kešatmiņai, BullMQ rindām un sesiju indeksu uzturēšanai.
Eksponenciāla atkāpšanās atkārtotai savienošanai (200ms - 10s, maks 20 mēģinājumi).
*/

import { Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import Redis from 'ioredis';

@Injectable()
export class RedisService implements OnModuleDestroy {
  private readonly logger = new Logger(RedisService.name);
  private readonly client: Redis;

  constructor() {
    const host = process.env.REDIS_HOST || 'localhost';
    const port = Number(process.env.REDIS_PORT) || 6379;
    const password = process.env.REDIS_PASSWORD || undefined;
    const db = Number(process.env.REDIS_DB) || 0;

    this.logger.log(`Redis inicializācija: ${host}:${port}/${db}`);

    this.client = new Redis({
      host,
      port,
      password,
      db,
      // Eksponenciāla atkāpšanās — sāk ar 200ms, maks 10s
      retryStrategy: (times: number) => {
        if (times > 20) {
          this.logger.error('Redis savienojums neizdevās pēc 20 mēģinājumiem');
          return null; // Pārtraukt atkārtotu savienošanos
        }
        const delay = Math.min(200 * 2 ** (times - 1), 10_000);
        this.logger.warn(`Redis atkārtots savienojums pēc ${delay}ms (mēģinājums ${times})`);
        return delay;
      },
      maxRetriesPerRequest: 3,
      enableReadyCheck: true,
      lazyConnect: false,
    });

    this.client.on('connect', () =>
      this.logger.log(`Redis savienots: ${host}:${port}/${db}`),
    );
    this.client.on('error', (err: Error) =>
      this.logger.error(`Redis kļūda: ${err.message}`),
    );
    this.client.on('close', () => this.logger.warn('Redis savienojums aizvērts'));
  }

  async onModuleDestroy() {
    await this.client?.quit();
  }

  /** Iegūt ioredis klientu (session store, BullMQ u.c.) */
  getClient(): Redis {
    return this.client;
  }

  // ── Pamata operācijas ──

  async get(key: string): Promise<string | null> {
    return this.client.get(key);
  }

  async set(key: string, value: string, ttlSeconds?: number): Promise<void> {
    if (ttlSeconds) {
      await this.client.set(key, value, 'EX', ttlSeconds);
    } else {
      await this.client.set(key, value);
    }
  }

  async del(...keys: string[]): Promise<number> {
    if (keys.length === 0) return 0;
    return this.client.del(...keys);
  }

  // ── JSON serializācija ──

  async getJson<T = unknown>(key: string): Promise<T | null> {
    const raw = await this.client.get(key);
    if (raw === null) return null;
    return JSON.parse(raw) as T;
  }

  async setJson<T>(key: string, value: T, ttlSeconds?: number): Promise<void> {
    await this.set(key, JSON.stringify(value), ttlSeconds);
  }

  // ── TTL pārvaldība ──

  async ttl(key: string): Promise<number> {
    return this.client.ttl(key);
  }

  async expire(key: string, seconds: number): Promise<boolean> {
    return (await this.client.expire(key, seconds)) === 1;
  }

  async exists(key: string): Promise<boolean> {
    return (await this.client.exists(key)) === 1;
  }

  // ── Pub/Sub ──

  async publish(channel: string, message: string): Promise<number> {
    return this.client.publish(channel, message);
  }

  /** Atgriež jaunu Redis klientu priekš subscribe (ioredis prasība) */
  createSubscriber(): Redis {
    return this.client.duplicate();
  }

  // ── Veselības pārbaude ──

  async ping(): Promise<boolean> {
    try {
      const result = await this.client.ping();
      return result === 'PONG';
    } catch {
      return false;
    }
  }
}
