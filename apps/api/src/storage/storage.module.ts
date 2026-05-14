import { Module } from '@nestjs/common';
import { StorageService } from './storage.service';
import { StorageHealthIndicator } from './storage-health.indicator';
import { ClamavHealthIndicator } from './clamav-health.indicator';
import { ClamavService } from './clamav.service';
import { AuditModule } from '../audit/audit.module';

// Failu glabātuve — MinIO/S3 + ClamAV vīrusu pārbaude
@Module({
  imports: [AuditModule],
  providers: [StorageService, StorageHealthIndicator, ClamavService, ClamavHealthIndicator],
  exports: [StorageService, StorageHealthIndicator, ClamavService, ClamavHealthIndicator],
})
export class StorageModule {}
