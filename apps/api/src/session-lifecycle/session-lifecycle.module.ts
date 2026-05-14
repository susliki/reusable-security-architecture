import { Module } from '@nestjs/common';
import { AuditModule } from '../audit/audit.module';
import { SessionLifecycleService } from './session-lifecycle.service';

// PrismaModule un RedisModule ir @Global — nav jāimportē
@Module({
  imports: [AuditModule],
  providers: [SessionLifecycleService],
  exports: [SessionLifecycleService],
})
export class SessionLifecycleModule {}
