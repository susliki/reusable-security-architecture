/*
GDPR datu pārnesamības serviss — eksportē visus lietotāja personas datus mašīnlasāmā JSON formātā.
GDPR Art. 20 — datu subjekta tiesības saņemt savus datus strukturētā veidā.
Drošs wrapper ap vaicājumiem — daļēji eksporti, ja kāda tabula vēl nav migrēta.
*/

import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

// GDPR Art. 20 — datu pārnesamības serviss
// Eksportē visus lietotāja personas datus mašīnlasāmā JSON formātā
@Injectable()
export class GdprExportService {
  private readonly logger = new Logger(GdprExportService.name);

  constructor(private readonly prisma: PrismaService) {}

  async exportUserData(userId: string) {
    // Drošs wrapper — dažas tabulas var neeksistēt ja migrācijas nav pilnas
    const safe = <T>(promise: Promise<T>, fallback: T): Promise<T> =>
      promise.catch((err) => {
        this.logger.warn(`[EXPORT] Vaicājuma kļūda (turpina): ${err.message ?? err}`);
        return fallback;
      });

    const [user, consents, passkeys] =
      await Promise.all([
        // Profila informācija
        this.prisma.user.findUnique({
          where: { id: userId },
          select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
            role: true,
            createdAt: true,
            updatedAt: true,
          },
        }),

        // Piekrišanas ieraksti
        safe(this.prisma.userConsent.findMany({
          where: { userId },
          select: {
            id: true,
            type: true,
            version: true,
            accepted: true,
            givenAt: true,
          },
          orderBy: { givenAt: 'desc' },
        }), []),

        // Drošības iestatījumi — identities ar passkey metadatiem
        safe(this.prisma.identity.findMany({
          where: { userId, provider: 'PASSKEY' },
          select: {
            passkey: {
              select: {
                id: true,
                name: true,
                createdAt: true,
                lastUsedAt: true,
              },
            },
          },
        }), []),
      ]);

    // Izvelk passkey datus no identity rezultāta
    const passkeyData = (passkeys as { passkey: { id: string; name: string | null; createdAt: Date; lastUsedAt: Date | null } | null }[])
      .map((i) => i.passkey)
      .filter((p): p is NonNullable<typeof p> => p !== null);

    // TOTP statuss — tikai esamība, ne noslēpums
    const totpIdentity = await safe(this.prisma.identity.findFirst({
      where: { userId, provider: 'TOTP', secret: { not: null } },
      select: { createdAt: true },
    }), null);

    return {
      exportedAt: new Date().toISOString(),
      format: 'application/json',
      // GDPR Art. 20 — strukturēts, mašīnlasāms, plaši lietots formāts
      profile: user,
      security: {
        passkeys: passkeyData.map((p) => ({
          id: p.id,
          name: p.name,
          createdAt: p.createdAt.toISOString(),
          lastUsedAt: p.lastUsedAt?.toISOString() ?? null,
        })),
        hasTotpConfigured: !!totpIdentity,
        totpConfiguredAt: totpIdentity?.createdAt.toISOString() ?? null,
      },
      consents,
    };
  }
}
