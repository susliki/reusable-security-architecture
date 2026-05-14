import { Global, Module } from '@nestjs/common';
import { RedisService } from './redis.service';
import { RedisHealthIndicator } from './redis-health.indicator';

// Globāls Redis modulis — sesijas, kešatmiņa, rate-limit, rindas
@Global()
@Module({
  providers: [RedisService, RedisHealthIndicator],
  exports: [RedisService, RedisHealthIndicator],
})
export class RedisModule {}
