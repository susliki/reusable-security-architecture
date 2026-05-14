/*
GDPR datu glabāšanas BullMQ procesors — ikdienas cron darbs ar divu līmeņu tīrīšanu.
GDPR Art. 5(1)(e) — glabāšanas ierobežojums; Art. 30 — audita žurnāli >10 gadi tiek dzēsti.
Tier 1 — automātiska dzēšana (audits, piekrišanas); Tier 2 — atzīmē admin pārskatīšanai.
*/

import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { Job } from 'bullmq';
import { PrismaService } from '../prisma/prisma.service';
import { AuditService } from '../audit/audit.service';
import { QUEUES } from '../queue/queue.constants';

/**
 * GDPR Art. 5(1)(e) — datu glabāšanas ierobežojums
 * Ikdienas cron darbs ar diviem līmeņiem:
 *
 * Tier 1 — automātiska dzēšana (droši, nav juridiska konflikta):
 *   - Audita žurnāls: >10 gadi (GDPR Art. 30)
 *   - Piekrišanas ieraksti dzēstiem lietotājiem: >5 gadi pēc dzēšanas
 *
 * Tier 2 — atzīmē admin pārskatīšanai (juridiska nenoteiktība):
 *   - Neaktīvi konti: >5 gadi pēc pēdējās pieteikšanās
 *   - Verifikācijas dokumenti: >1 gads pēc lēmuma
 */
@Processor(QUEUES.DATA_RETENTION)
export class RetentionProcessor extends WorkerHost {
  private readonly logger = new Logger(RetentionProcessor.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {
    super();
  }

  async process(_job: Job) {
    this.logger.log('[RETENTION] Sāk datu glabāšanas tīrīšanu');

    const results: Record<string, unknown> = {};

    /*
    ═══════════════════════════════════════════════
    TIER 1 — Automātiska dzēšana (nav juridiska konflikta)
    ═══════════════════════════════════════════════
    */

    // 1. Novecojuši audita ieraksti (>10 gadi) — GDPR Art. 30
    const auditCutoff = new Date();
    auditCutoff.setFullYear(auditCutoff.getFullYear() - 10);
    try {
      const { count } = await this.prisma.auditLog.deleteMany({
        where: { ts: { lt: auditCutoff } },
      });
      results.auditLogsDeleted = count;
      if (count > 0) {
        this.logger.log(`[RETENTION] Dzēsti ${count} audita ieraksti (>10 gadi)`);
      }
    } catch (err) {
      this.logger.error(`[RETENTION] Audita tīrīšanas kļūda: ${err}`);
      results.auditLogsError = String(err);
    }

    // 2. Piekrišanas ieraksti dzēstiem lietotājiem (>5 gadi pēc deletedAt)
    const consentCutoff = new Date();
    consentCutoff.setFullYear(consentCutoff.getFullYear() - 5);
    try {
      const deletedUsers = await this.prisma.user.findMany({
        where: { deletedAt: { lt: consentCutoff } },
        select: { id: true },
      });
      if (deletedUsers.length > 0) {
        const { count } = await this.prisma.userConsent.deleteMany({
          where: { userId: { in: deletedUsers.map((u) => u.id) } },
        });
        results.consentsDeleted = count;
        if (count > 0) {
          this.logger.log(`[RETENTION] Dzēsti ${count} piekrišanas ieraksti (dzēsti lietotāji >5g)`);
        }
      }
    } catch (err) {
      this.logger.error(`[RETENTION] Piekrišanu tīrīšanas kļūda: ${err}`);
      results.consentsError = String(err);
    }

    /*
    ═══════════════════════════════════════════════
    TIER 2 — Atzīmē admin pārskatīšanai
    STCW / MK 895 var prasīt ilgāku glabāšanu — admins lemj
    ═══════════════════════════════════════════════
    */

    // 3. Neaktīvi konti (>5 gadi pēc pēdējās pieteikšanās)
    const inactiveCutoff = new Date();
    inactiveCutoff.setFullYear(inactiveCutoff.getFullYear() - 5);
    try {
      const inactiveAccounts = await this.prisma.user.findMany({
        where: {
          lastLoginAt: { lt: inactiveCutoff },
          status: { not: 'DELETED' },
        },
        select: {
          id: true,
          firstName: true,
          lastName: true,
          role: true,
          lastLoginAt: true,
        },
      });

      results.inactiveAccountsFlagged = inactiveAccounts.length;
      if (inactiveAccounts.length > 0) {
        // Logojam katru atzīmēto kontu — admins var redzēt žurnālā
        const flagged = inactiveAccounts.map((u) => ({
          userId: u.id,
          firstName: u.firstName,
          lastName: u.lastName,
          role: u.role,
          lastLoginAt: u.lastLoginAt?.toISOString(),
        }));

        results.inactiveAccountsDetails = flagged;
        this.logger.warn(
          `[RETENTION] ⚠ ${inactiveAccounts.length} neaktīvi konti (>5g) prasa admin pārskatīšanu`,
        );
      }
    } catch (err) {
      this.logger.error(`[RETENTION] Neaktīvo kontu pārbaudes kļūda: ${err}`);
      results.inactiveAccountsError = String(err);
    }

    // 4. Verifikācijas dokumenti (>1 gads pēc lēmuma)
    const verificationCutoff = new Date();
    verificationCutoff.setFullYear(verificationCutoff.getFullYear() - 1);
    try {
      // Meklē lietotājus kuru verifikācija notika >1g atpakaļ
      const staleVerificationDocs = await this.prisma.verificationDocument.findMany({
        where: {
          user: {
            identityVerifiedAt: { lt: verificationCutoff },
            status: { not: 'DELETED' },
          },
        },
        select: {
          id: true,
          userId: true,
          type: true,
          uploadedAt: true,
        },
      });

      results.staleVerificationDocsFlagged = staleVerificationDocs.length;
      if (staleVerificationDocs.length > 0) {
        results.staleVerificationDocsDetails = staleVerificationDocs.map((d) => ({
          docId: d.id,
          userId: d.userId,
          type: d.type,
          uploadedAt: d.uploadedAt.toISOString(),
        }));

        this.logger.warn(
          `[RETENTION] ⚠ ${staleVerificationDocs.length} verifikācijas dokumenti (>1g pēc lēmuma) prasa admin pārskatīšanu`,
        );
      }
    } catch (err) {
      this.logger.error(`[RETENTION] Verifikācijas dokumentu pārbaudes kļūda: ${err}`);
      results.staleVerificationDocsError = String(err);
    }

    /*
    ═══════════════════════════════════════════════
    Audita ieraksts ar pilnu pārskatu
    ═══════════════════════════════════════════════
    */

    await this.audit.write({
      action: 'gdpr.retention.cleanup',
      result: 'Success',
      dataJson: results,
    });

    this.logger.log(`[RETENTION] Tīrīšana pabeigta: ${JSON.stringify(results)}`);
    return results;
  }
}
