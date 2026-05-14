/*
Backup verifikācijas statusa endpoint — admin dashboard veselības indikators.
Lasa Redis metadatus no nakts pg_dump cron darba un aprēķina veselības līmeni (zaļš/dzeltens/sarkans) pēc vecuma un izmēra.
*/

import { Controller, Get, UseGuards } from '@nestjs/common';
import { AdminGuard } from '../common/admin.guard';
import { AuthGuard } from '../common/auth.guard';
import { RedisService } from '../redis/redis.service';

// Backup metadatu tips no Redis
interface BackupMeta {
  timestamp: string;
  sizeBytes: number;
  durationSeconds: number;
  dbName: string;
  location: string;
  status: 'success' | 'failed';
}

// Veselības līmenis — aprēķināts no vecuma un izmēra
type BackupHealth = 'green' | 'amber' | 'red';

// Minimālais pieņemamais backup izmērs (1 MB)
const MIN_BACKUP_SIZE = 1_048_576;
const H24 = 24 * 60 * 60 * 1000;
const H48 = 48 * 60 * 60 * 1000;

@Controller('admin')
@UseGuards(AuthGuard, AdminGuard)
export class BackupStatusController {
  constructor(private readonly redis: RedisService) {}

  // ── Backup verifikācijas statuss ──

  @Get('backup-status')
  async backupStatus() {
    const meta = await this.redis.getJson<BackupMeta>('backup:last');

    if (!meta) {
      // Redis atslēga neeksistē — cron vēl nav konfigurēts vai nav izpildīts
      return {
        status: 'unknown' as const,
        health: 'amber' as BackupHealth,
        message:
          'Rezerves kopijas metadati nav pieejami Redis. Pārbaudiet cron darbu rezervju serverī.',
        nextScheduled: '02:00 UTC daily',
        retentionDays: 30,
        walArchiving: true,
      };
    }

    const ageMs = Date.now() - new Date(meta.timestamp).getTime();

    // Veselības aprēķins: zaļš ja <24h UN >1MB, dzeltens ja <48h, sarkans citādi
    let health: BackupHealth;
    if (ageMs < H24 && meta.sizeBytes >= MIN_BACKUP_SIZE) {
      health = 'green';
    } else if (ageMs < H48) {
      health = 'amber';
    } else {
      health = 'red';
    }

    // Ja izmērs pārāk mazs — vienmēr sarkans
    if (meta.sizeBytes < MIN_BACKUP_SIZE) {
      health = 'red';
    }

    return {
      status: meta.status,
      health,
      lastBackup: meta.timestamp,
      sizeBytes: meta.sizeBytes,
      durationSeconds: meta.durationSeconds,
      dbName: meta.dbName,
      location: meta.location,
      nextScheduled: '02:00 UTC daily',
      retentionDays: 30,
      walArchiving: true,
    };
  }
}
