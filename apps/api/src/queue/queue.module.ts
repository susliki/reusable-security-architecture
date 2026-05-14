import { Module, OnModuleInit } from '@nestjs/common';
import { BullModule, InjectQueue } from '@nestjs/bullmq';
import { Queue } from 'bullmq';
import { QUEUES, DEFAULT_JOB_OPTS } from './queue.constants';
import { EmailProcessor } from './processors/email.processor';
import { SmsProcessor } from './processors/sms.processor';
import { RetentionProcessor } from '../gdpr/retention.processor';
import { PrismaModule } from '../prisma/prisma.module';
import { AuditModule } from '../audit/audit.module';
import { EmailModule } from '../email/email.module';

// BullMQ rindu modulis — izmanto to pašu Redis, kas sesijām
// Darbi: e-pasts, SMS, GDPR datu glabāšanas tīrīšana
@Module({
  imports: [
    // BullMQ savienojums — izmanto REDIS_* env mainīgos
    BullModule.forRoot({
      connection: {
        host: process.env.REDIS_HOST || 'localhost',
        port: Number(process.env.REDIS_PORT) || 6379,
        password: process.env.REDIS_PASSWORD || undefined,
        db: Number(process.env.REDIS_DB) || 0,
      },
      defaultJobOptions: DEFAULT_JOB_OPTS,
    }),

    // Rindu reģistrācija
    BullModule.registerQueue(
      { name: QUEUES.EMAIL },
      { name: QUEUES.SMS },
      { name: QUEUES.DATA_RETENTION },
    ),

    PrismaModule,
    AuditModule,
    EmailModule,
  ],
  providers: [
    EmailProcessor,
    SmsProcessor,
    RetentionProcessor,
  ],
  exports: [BullModule],
})
export class QueueModule implements OnModuleInit {
  constructor(
    @InjectQueue(QUEUES.DATA_RETENTION) private readonly retentionQueue: Queue,
  ) {}

  // GDPR datu glabāšanas tīrīšana — katru nakti 03:00
  async onModuleInit() {
    await this.retentionQueue.upsertJobScheduler(
      'daily-retention-cleanup',
      { pattern: '0 3 * * *' },
      { name: 'retention-cleanup' },
    );
  }
}
