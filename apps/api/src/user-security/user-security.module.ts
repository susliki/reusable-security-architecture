import { Module } from '@nestjs/common';
import { PrismaModule } from '../prisma/prisma.module';
import { AuditModule } from '../audit/audit.module';
import { AuthModule } from '../auth/auth.module';
import { SessionLifecycleModule } from '../session-lifecycle/session-lifecycle.module';
import { UserSecurityController } from './user-security.controller';

// Redis ir globāls modulis — nav jāimportē atsevišķi
@Module({
  imports: [PrismaModule, AuditModule, AuthModule, SessionLifecycleModule],
  controllers: [UserSecurityController],
})
export class UserSecurityModule {}
