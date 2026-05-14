/*
Lietotāja piekrišanu pārvaldība — privātuma politikas versiju izsekošana un atsaukšanas iespēja.
GDPR Art. 6, 7 — tiesiskais pamats, piekrišanas vēsture (UserConsent tabula), versijas pārbaude.
*/

import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

// GDPR Art. 7 — piekrišanas pārvaldība ar versiju izsekošanu
@Injectable()
export class ConsentService {
  /** Pašreizējā politikas versija — no env vai noklusējuma */
  getCurrentPolicyVersion(): string {
    return process.env.PRIVACY_POLICY_VERSION ?? '1.0';
  }

  constructor(private readonly prisma: PrismaService) {}

  /**
   * Pārbauda vai lietotājs ir piekritis pašreizējai politikas versijai
   * Atgriež true ja piekrišana ir aktuāla
   */
  async hasCurrentConsent(userId: string): Promise<boolean> {
    const currentVersion = this.getCurrentPolicyVersion();

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { consentedPolicyVersion: true },
    });

    return user?.consentedPolicyVersion === currentVersion;
  }

  /**
   * Reģistrē piekrišanu — izveido UserConsent ierakstu un atjaunina User
   */
  async acceptConsent(
    userId: string,
    policyVersion: string,
    ctx: { ip?: string; userAgent?: string },
  ) {
    const currentVersion = this.getCurrentPolicyVersion();

    // Drošības pārbaude — neļauj pieņemt novecojušu versiju
    if (policyVersion !== currentVersion) {
      return { ok: false as const, code: 'version_mismatch', currentVersion };
    }

    await this.prisma.$transaction(async (tx) => {
      // Izveido piekrišanas ierakstu
      await tx.userConsent.create({
        data: {
          userId,
          version: policyVersion,
          type: 'privacy_policy',
          accepted: true,
          ipAddress: ctx.ip ?? null,
          userAgent: ctx.userAgent ?? null,
        },
      });

      // Atjaunina lietotāja piekrišanas versiju
      await tx.user.update({
        where: { id: userId },
        data: {
          consentedPolicyVersion: policyVersion,
          consentedAt: new Date(),
        },
      });
    });

    return { ok: true as const };
  }

  /**
   * Piekrišanas statuss — frontend rāda bloķēšanas modāli ja neatbilst
   */
  async getConsentStatus(userId: string) {
    const currentVersion = this.getCurrentPolicyVersion();

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { consentedPolicyVersion: true },
    });

    return {
      currentPolicyVersion: currentVersion,
      userConsentedVersion: user?.consentedPolicyVersion ?? null,
      consentRequired: user?.consentedPolicyVersion !== currentVersion,
    };
  }
}
