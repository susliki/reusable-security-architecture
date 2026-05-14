import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { AuditModule } from '../audit/audit.module';
import { EmailModule } from '../email/email.module';
import { SessionLifecycleModule } from '../session-lifecycle/session-lifecycle.module';

// RedisModule ir globāls — RedisService pieejams automātiski
@Module({
  imports: [AuditModule, EmailModule, SessionLifecycleModule],
  controllers: [AuthController],
  providers: [AuthService],
  exports: [AuthService],
})
export class AuthModule {}
