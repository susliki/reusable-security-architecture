import { Injectable } from '@nestjs/common';
import { ClamavService } from './clamav.service';

/** ClamAV veselības pārbaude — izmanto /api/health endpoint */
@Injectable()
export class ClamavHealthIndicator {
  constructor(private readonly clamav: ClamavService) {}

  async isHealthy(): Promise<{ clamav: 'up' | 'down' }> {
    const ok = await this.clamav.ping();
    if (!ok) {
      throw new Error('ClamAV nav pieejams (PING/PONG neveiksmīgs)');
    }
    return { clamav: 'up' };
  }
}
