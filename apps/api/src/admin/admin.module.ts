import { Module } from '@nestjs/common';
import { AdminController } from './admin.controller';
import { SecurityEventsController } from './security-events.controller';
import { BackupStatusController } from './backup-status.controller';
import { MaintenanceController } from './maintenance.controller';
import { PrismaModule } from '../prisma/prisma.module';
import { RedisModule } from '../redis/redis.module';
import { StorageModule } from '../storage/storage.module';
import { AuditModule } from '../audit/audit.module';
import { NotificationModule } from '../notification/notification.module';
import { SessionLifecycleModule } from '../session-lifecycle/session-lifecycle.module';
import { EmailModule } from '../email/email.module';
import { GdprModule } from '../gdpr/gdpr.module';

@Module({
  imports: [
    PrismaModule,
    RedisModule,
    StorageModule,
    AuditModule,
    NotificationModule,
    SessionLifecycleModule,
    EmailModule,
    GdprModule,
  ],
  controllers: [AdminController, SecurityEventsController, BackupStatusController, MaintenanceController],
})
export class AdminModule {}
