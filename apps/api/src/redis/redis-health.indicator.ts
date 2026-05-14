import { Injectable } from '@nestjs/common';
import { RedisService } from './redis.service';

/** Redis veselības pārbaude — izmanto /api/health endpoint */
@Injectable()
export class RedisHealthIndicator {
  constructor(private readonly redis: RedisService) {}

  async isHealthy(): Promise<{ redis: 'up' | 'down' }> {
    const ok = await this.redis.ping();
    if (!ok) {
      throw new Error('Redis is not responding to PING');
    }
    return { redis: 'up' };
  }
}
