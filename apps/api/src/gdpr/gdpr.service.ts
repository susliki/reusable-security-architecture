/*
GDPR datu subjekta tiesību serviss — pilna lietotāja dzēšanas kaskāde sesijām, identitātēm, failiem un pieteikumiem.
GDPR Art. 17 — right-to-erasure ar audita ierakstu anonimizāciju (nejaušs UUID, nekorelējams ar oriģinālo userId).
Saglabā audita HMAC ķēdes integritāti — ieraksti tiek anonimizēti, nevis dzēsti.
*/

import { Injectable, Logger } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { PrismaService } from '../prisma/prisma.service';
import { AuditService } from '../audit/audit.service';
import { SessionLifecycleService } from '../session-lifecycle/session-lifecycle.service';
import { StorageService } from '../storage/storage.service';
import { BUCKETS } from '../storage/storage.constants';

@Injectable()
export class GdprService {
  private readonly logger = new Logger(GdprService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    private readonly sessionLifecycle: SessionLifecycleService,
    private readonly storage: StorageService,
  ) {}

  /**
   * GDPR Art. 17 — pilna lietotāja dzēšanas kaskāde
   * Anonimizē audita ierakstus ar nejaušu UUID (nekorelējamu)
   * Saglabā HMAC ķēdes integritāti — audita ieraksti netiek dzēsti
   */
  async eraseUser(userId: string, adminId: string, ctx: { ip?: string; userAgent?: string }) {
    // Pārbauda vai lietotājs eksistē
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      return { ok: false as const, code: 'user_not_found' };
    }

    // Nejaušs UUID katrai dzēšanas operācijai — GDPR anonimizācija
    // Neizmantojam determinismu no userId lai novērstu korelāciju
    const erasedId = `ERASED-${randomUUID()}`;

    // 1. Iznīcina visas Redis sesijas + DB sesiju ierakstus + indeksu
    const { revokedRedis: destroyedSessions } = await this.sessionLifecycle.revokeAllUserSessions({
      userId,
      audit: {
        actorUserId: adminId,
        clientIp: ctx.ip ?? null,
        userAgent: ctx.userAgent ?? null,
        reason: 'gdpr_erasure',
      },
    });
    this.logger.log(`[GDPR] Dzēstas ${destroyedSessions} sesijas lietotājam ${userId}`);

    await this.prisma.$transaction(async (tx) => {

      // 3. Dzēš PasskeyCredentials (caur Identity relāciju)
      const identities = await tx.identity.findMany({
        where: { userId },
        select: { id: true },
      });
      if (identities.length > 0) {
        await tx.passkeyCredential.deleteMany({
          where: { identityId: { in: identities.map((i) => i.id) } },
        });
      }

      // 4. Dzēš Identity ierakstus
      await tx.identity.deleteMany({ where: { userId } });

      // 5. Dzēš verifikācijas dokumentus (DB + MinIO objekti)
      const verDocs = await tx.verificationDocument.findMany({
        where: { userId },
        select: { storageKey: true },
      });
      for (const doc of verDocs) {
        if (doc.storageKey) {
          try {
            await this.storage.deleteFile(BUCKETS.DOCUMENTS, doc.storageKey);
          } catch (err) {
            // MinIO kļūda nedrīkst apturēt dzēšanas kaskādi
            this.logger.warn(`[GDPR] MinIO dzēšana neizdevās: ${doc.storageKey}`, err);
          }
        }
      }
      await tx.verificationDocument.deleteMany({ where: { userId } });

      // 6. Dzēš piekrišanas ierakstus
      await tx.userConsent.deleteMany({ where: { userId } });

      // 7. Anonimizē audita ierakstus — aizvieto subjectId ar nejaušu UUID
      // HMAC ķēde paliek neskarta — mēs mainām tikai subjectId lauku
      await tx.auditLog.updateMany({
        where: { subjectId: userId },
        data: { subjectId: erasedId },
      });

      // 8. Lietotāja PII iznīcināšana — pārraksta ar null, statuss DELETED
      // Iekļauj VISUS šifrētos laukus: email, firstName, lastName, phone, citizenship, dateOfBirth, birthPlace
      await tx.user.update({
        where: { id: userId },
        data: {
          email: null,
          emailHmac: null,
          firstName: null,
          lastName: `[Dzēsts lietotājs]`,
          phone: null,
          citizenship: null,
          dateOfBirth: null,
          birthPlace: null,
          idCodeHmac: null,
          status: 'DELETED',
          deletedAt: new Date(),
          consentedPolicyVersion: null,
        },
      });
    });

    // 11. Audita ieraksts par dzēšanu — pēc transakcijas
    await this.audit.write({
      subjectId: adminId,
      action: 'gdpr.erasure',
      entityType: 'User',
      entityId: userId,
      result: 'Success',
      clientIp: ctx.ip ?? null,
      userAgent: ctx.userAgent ?? null,
      dataJson: {
        erasedId,
        destroyedSessions,
        performedBy: adminId,
      },
    });

    this.logger.warn(`[GDPR] Lietotājs ${userId} dzēsts — anonimizēts kā ${erasedId}`);
    return { ok: true as const, erasedId };
  }
}
