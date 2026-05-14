/*
E-pasta sūtīšanas BullMQ procesors — Microsoft Graph API caur EmailService.
Atbalsta veidņu renderēšanu vai tiešu HTML; retry 3x ar eksponenciālu atkāpšanos.
Pēc 3 neveiksmēm darbs nonāk failed statusā un tiek pierakstīts logos.
*/

import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { Job } from 'bullmq';
import { QUEUES } from '../queue.constants';
import type { EmailJobData } from '../queue.types';
import { EmailService } from '../../email/email.service';
import { renderTemplate } from '../../notifications/template-renderer';

/*
E-pasta sūtīšanas procesors — Microsoft Graph API
Retry: 3x ar eksponenciālu atkāpšanos (3s → 6s → 12s)
Pēc 3 neveiksmēm darbs nonāk "failed" statusā
*/
@Processor(QUEUES.EMAIL)
export class EmailProcessor extends WorkerHost {
  private readonly logger = new Logger(EmailProcessor.name);

  constructor(private readonly emailService: EmailService) {
    super();
  }

  async process(job: Job<EmailJobData>): Promise<void> {
    const { to, subject, template, data, cc } = job.data;

    this.logger.log(
      `E-pasts: ${Array.isArray(to) ? to.join(',') : to} | Veidne: "${template ?? 'tiešs'}" | Mēģinājums: ${job.attemptsMade + 1}/${job.opts.attempts}`,
    );

    // Renderē HTML no veidnes vai izmanto tiešo subject/html
    let mailSubject: string;
    let mailHtml: string;

    if (template && data) {
      const rendered = renderTemplate(template, data);
      mailSubject = subject || rendered.subject;
      mailHtml = rendered.html;
    } else {
      // Tiešais režīms — subject un html jau norādīti darba datos
      mailSubject = subject;
      mailHtml = job.data.html ?? '';
    }

    await this.emailService.send({
      to,
      subject: mailSubject,
      html: mailHtml,
      cc,
    });

    this.logger.log(
      `E-pasts nosūtīts: job=${job.id} | to=${Array.isArray(to) ? to.join(',') : to}`,
    );
  }
}
