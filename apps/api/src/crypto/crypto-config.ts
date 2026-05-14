import { Logger } from '@nestjs/common';

const logger = new Logger('CryptoConfig');

/**
 * Validē PII šifrēšanas atslēgas startējot.
 * Ja PII_ENCRYPTION_ACTIVE=true — fail-fast bez derīgām atslēgām.
 * Ja nav aktīva — brīdina bet ļauj startēt (pirms datu migrācijas).
 * OWASP ASVS v5.0 §11.3 — atslēgu pārvaldības validācija.
 */
export function validateCryptoKeys(): void {
  const active = process.env.PII_ENCRYPTION_ACTIVE === 'true';
  const errors: string[] = [];

  const encKey = process.env.PII_ENCRYPTION_KEY ?? '';
  if (encKey.length !== 64) {
    errors.push('PII_ENCRYPTION_KEY jābūt 32-baitu hex virknei (64 simboli)');
  } else if (!/^[0-9a-fA-F]{64}$/.test(encKey)) {
    errors.push('PII_ENCRYPTION_KEY satur nederīgus hex simbolus');
  }

  const idxKey = process.env.PII_BLIND_INDEX_KEY ?? '';
  if (idxKey.length !== 64) {
    errors.push('PII_BLIND_INDEX_KEY jābūt 32-baitu hex virknei (64 simboli)');
  } else if (!/^[0-9a-fA-F]{64}$/.test(idxKey)) {
    errors.push('PII_BLIND_INDEX_KEY satur nederīgus hex simbolus');
  }

  // Atslēgas nedrīkst sakrist — šifrēšana un indeksēšana jābūt neatkarīgām
  if (encKey && idxKey && encKey === idxKey) {
    errors.push(
      'PII_ENCRYPTION_KEY un PII_BLIND_INDEX_KEY nedrīkst būt vienādas',
    );
  }

  if (errors.length > 0) {
    if (active) {
      // Šifrēšana aktīva — nedrīkst startēt bez atslēgām
      errors.forEach((e) => logger.error(e));
      throw new Error(
        `PII šifrēšanas konfigurācija nav derīga:\n${errors.join('\n')}`,
      );
    } else {
      // Šifrēšana vēl nav aktīva — brīdinājums, bet startē
      errors.forEach((e) => logger.warn(`[INACTIVE] ${e}`));
      logger.warn(
        'PII šifrēšana nav aktīva — ieslēgt PII_ENCRYPTION_ACTIVE=true pēc datu migrācijas',
      );
    }
    return;
  }

  logger.log(
    active
      ? 'PII šifrēšanas atslēgas validētas — šifrēšana AKTĪVA'
      : 'PII šifrēšanas atslēgas validētas — šifrēšana NEAKTĪVA (ieslēgt ar PII_ENCRYPTION_ACTIVE=true)',
  );
}
