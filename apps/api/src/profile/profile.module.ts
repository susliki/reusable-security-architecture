import { Module } from '@nestjs/common';
import { ProfileController } from './profile.controller';
import { PrismaModule } from '../prisma/prisma.module';
import { AuditModule } from '../audit/audit.module';
import { NotificationModule } from '../notification/notification.module';

@Module({
  imports: [PrismaModule, AuditModule, NotificationModule],
  controllers: [ProfileController],
})
export class ProfileModule {}
