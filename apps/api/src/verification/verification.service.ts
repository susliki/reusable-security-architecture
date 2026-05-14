/*
Identitātes verifikācijas serviss — dokumentu glabāšana MinIO un statusa pārvaldība.
Pieņem augšupielādes tikai UNVERIFIED vai REJECTED statusā; admins apstiprina vai noraida.
Faili iziet ClamAV skenēšanu StorageService līmenī; visas darbības tiek auditētas.
*/

import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { StorageService } from '../storage/storage.service';
import { AuditService } from '../audit/audit.service';
import { BUCKETS } from '../storage/storage.constants';
import type { RequestCtx } from '../auth/auth.service';

// Atļautie dokumentu tipi identitātes verifikācijai
const VALID_DOC_TYPES = ['PASSPORT', 'SELFIE', 'ID_CARD'] as const;
type DocType = (typeof VALID_DOC_TYPES)[number];

@Injectable()
export class VerificationService {
  private readonly logger = new Logger(VerificationService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly storage: StorageService,
    private readonly audit: AuditService,
  ) {}

  /**
   * Augšupielādēt verifikācijas dokumentu.
   * Pieņem tikai UNVERIFIED vai REJECTED statusā esošus lietotājus.
   */
  async uploadDocument(
    userId: string,
    file: Express.Multer.File,
    type: string,
    ctx: RequestCtx,
  ) {
    // Pārbaude vai dokumenta tips ir derīgs
    if (!VALID_DOC_TYPES.includes(type as DocType)) {
      throw new BadRequestException({
        code: 'invalid_document_type',
        message: `Neatbalstīts dokumenta tips: ${type}. Atļautie: ${VALID_DOC_TYPES.join(', ')}`,
      });
    }

    // Pārbaude vai lietotājs drīkst augšupielādēt dokumentus
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { status: true },
    });

    if (!user) {
      throw new NotFoundException({
        code: 'user_not_found',
        message: 'Lietotājs nav atrasts',
      });
    }

    if (user.status !== 'UNVERIFIED' && user.status !== 'REJECTED') {
      throw new BadRequestException({
        code: 'invalid_status',
        message: 'Dokumentu augšupielāde pieejama tikai UNVERIFIED vai REJECTED statusā',
      });
    }

    // Augšupielāde uz MinIO — unikāla atslēga ar timestamp
    const storageKey = `verification/${userId}/${type}-${Date.now()}`;

    await this.storage.uploadFile(BUCKETS.DOCUMENTS, storageKey, file.buffer, {
      contentType: file.mimetype,
    });

    // Saglabāt ierakstu datubāzē
    const doc = await this.prisma.verificationDocument.create({
      data: {
        userId,
        type,
        storageKey,
        mimeType: file.mimetype,
        fileSize: file.size,
        scanStatus: 'CLEAN', // StorageService jau pārbaudīja ar ClamAV
      },
    });

    this.logger.log(`Verifikācijas dokuments augšupielādēts: ${doc.id} (${type})`);

    // Audita ieraksts — subjectId ir datu subjekts (lietotājs, kura dokuments)
    await this.audit.write({
      ...ctx,
      action: 'verification.document_uploaded',
      entityType: 'verification_document',
      entityId: doc.id,
      result: 'Success',
      subjectId: userId,
      dataJson: { type, fileSize: file.size },
    });

    return doc;
  }

  /**
   * Pārskatīt lietotāja verifikāciju — apstiprināt vai noraidīt.
   * Tikai inspektori/administratori.
   */
  async reviewVerification(
    userId: string,
    decision: 'APPROVED' | 'REJECTED',
    reason: string | null,
    inspectorId: string,
    ctx: RequestCtx,
  ) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, status: true },
    });

    if (!user) {
      throw new NotFoundException({
        code: 'user_not_found',
        message: 'Lietotājs nav atrasts',
      });
    }

    const newStatus = decision === 'APPROVED' ? 'VERIFIED' : 'REJECTED';

    // Atjaunot lietotāja statusu un verifikācijas datus
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        status: newStatus,
        ...(decision === 'APPROVED'
          ? {
              identityVerifiedAt: new Date(),
              identityVerifiedBy: inspectorId,
              verificationMethod: 'DOCUMENT_REVIEW',
            }
          : {}),
      },
    });

    this.logger.log(
      `Verifikācija ${decision} lietotājam ${userId} (inspektors: ${inspectorId})`,
    );

    // Audita ieraksts — subjectId ir datu subjekts (pārskatāmais lietotājs)
    await this.audit.write({
      ...ctx,
      action: `verification.${decision.toLowerCase()}`,
      entityType: 'user',
      entityId: userId,
      result: 'Success',
      subjectId: userId,
      dataJson: { decision, reason, inspectorId },
    });

    return { status: newStatus };
  }

  /**
   * Atgriezt lietotāja verifikācijas statusu un dokumentu sarakstu.
   */
  async getStatus(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        status: true,
        identityVerifiedAt: true,
        identityVerifiedBy: true,
        verificationMethod: true,
      },
    });

    if (!user) {
      throw new NotFoundException({
        code: 'user_not_found',
        message: 'Lietotājs nav atrasts',
      });
    }

    const documents = await this.prisma.verificationDocument.findMany({
      where: { userId },
      orderBy: { uploadedAt: 'desc' },
    });

    return {
      status: user.status,
      identityVerifiedAt: user.identityVerifiedAt,
      identityVerifiedBy: user.identityVerifiedBy,
      verificationMethod: user.verificationMethod,
      documents,
    };
  }
}
