import { Module } from '@nestjs/common';
import { BullBoardModule } from '@bull-board/nestjs';
import { ExpressAdapter } from '@bull-board/express';
import { BullMQAdapter } from '@bull-board/api/bullMQAdapter';
import { BullModule } from '@nestjs/bullmq';
import { QUEUES } from './queue.constants';

// Bull Board UI — /api/admin/queues
// Aizsargāts ar AdminGuard caur middleware (skatīt main.ts)
@Module({
  imports: [
    BullBoardModule.forRoot({
      route: '/admin/queues',
      adapter: ExpressAdapter,
    }),

    // Reģistrēt katru rindu Bull Board
    BullBoardModule.forFeature({
      name: QUEUES.EMAIL,
      adapter: BullMQAdapter,
    }),
    BullBoardModule.forFeature({
      name: QUEUES.SMS,
      adapter: BullMQAdapter,
    }),
    BullBoardModule.forFeature({
      name: QUEUES.DATA_RETENTION,
      adapter: BullMQAdapter,
    }),
  ],
})
export class BullBoardAdminModule {}
