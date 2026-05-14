import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { BullModule } from '@nestjs/bullmq';
import { PrismaModule } from '../../api/src/prisma/prisma.module';
import { AuditModule } from '../../api/src/audit/audit.module';
import { QUEUES, DEFAULT_JOB_OPTS } from '../../api/src/queue/queue.constants';
import { EmailProcessor } from '../../api/src/queue/processors/email.processor';
import { SmsProcessor } from '../../api/src/queue/processors/sms.processor';

// Worker modulis — importē tikai rindu apstrādi, bez HTTP/auth/session
@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, envFilePath: '.env' }),

    BullModule.forRoot({
      connection: {
        host: process.env.REDIS_HOST || 'localhost',
        port: Number(process.env.REDIS_PORT) || 6379,
        password: process.env.REDIS_PASSWORD || undefined,
        db: Number(process.env.REDIS_DB) || 0,
      },
      defaultJobOptions: DEFAULT_JOB_OPTS,
    }),

    BullModule.registerQueue(
      { name: QUEUES.EMAIL },
      { name: QUEUES.SMS },
    ),

    PrismaModule,
    AuditModule,
  ],
  providers: [
    EmailProcessor,
    SmsProcessor,
  ],
})
export class WorkerModule {}
