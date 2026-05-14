/*
SMS sūtīšanas BullMQ procesors — pagaidām vietturas (placeholder).
Reālā integrācija ar SMS vārteju (Tele2 Business API vai Baltcom) tiks pievienota
pēc līguma noslēgšanas; pašlaik tikai pieraksta brīdinājumu logos.
*/

import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { Job } from 'bullmq';
import { QUEUES } from '../queue.constants';
import type { SmsJobData } from '../queue.types';

/**
 * SMS sūtīšanas procesors — pagaidām vietturas (placeholder).
 * Integrācija ar SMS vārteju tiks pievienota, kad būs noslēgts līgums.
 */
@Processor(QUEUES.SMS)
export class SmsProcessor extends WorkerHost {
  private readonly logger = new Logger(SmsProcessor.name);

  async process(job: Job<SmsJobData>): Promise<void> {
    const { phone, message } = job.data;

    // TODO: integrēt ar SMS vārteju (piem., Tele2 Business API vai Baltcom)
    this.logger.warn(
      `SMS nav konfigurēts — ziņojums netika nosūtīts | Tel: ${phone} | Garums: ${message.length}`,
    );
  }
}
