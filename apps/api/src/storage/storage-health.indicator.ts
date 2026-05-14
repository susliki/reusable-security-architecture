import { Injectable } from '@nestjs/common';
import { StorageService } from './storage.service';
import { BUCKETS } from './storage.constants';

/** MinIO veselības pārbaude — izmanto /api/health endpoint */
@Injectable()
export class StorageHealthIndicator {
  constructor(private readonly storage: StorageService) {}

  async isHealthy(): Promise<{ storage: 'up' | 'down' }> {
    // Pārbauda primāro bucket pieejamību
    const ok = await this.storage.ping(BUCKETS.DOCUMENTS);
    if (!ok) {
      throw new Error('MinIO is not responding (documents bucket)');
    }
    return { storage: 'up' };
  }
}
