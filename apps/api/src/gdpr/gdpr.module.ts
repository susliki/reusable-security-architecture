import { Module } from '@nestjs/common';
import { PrismaModule } from '../prisma/prisma.module';
import { AuditModule } from '../audit/audit.module';
import { RedisModule } from '../redis/redis.module';
import { StorageModule } from '../storage/storage.module';
import { SessionLifecycleModule } from '../session-lifecycle/session-lifecycle.module';
import { NotificationModule } from '../notification/notification.module';
import { GdprController } from './gdpr.controller';
import { GdprService } from './gdpr.service';
import { GdprMeController } from './gdpr-me.controller';
import { GdprExportService } from './gdpr-export.service';
import { ConsentController } from './consent.controller';
import { ConsentService } from './consent.service';

// GDPR Art. 15–20 — datu subjekta tiesību realizācija
@Module({
  imports: [PrismaModule, AuditModule, RedisModule, StorageModule, SessionLifecycleModule, NotificationModule],
  controllers: [GdprController, GdprMeController, ConsentController],
  providers: [GdprService, GdprExportService, ConsentService],
  exports: [GdprService, ConsentService, GdprExportService],
})
export class GdprModule {}
