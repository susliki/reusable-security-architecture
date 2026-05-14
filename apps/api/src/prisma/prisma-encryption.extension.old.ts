import { Prisma } from '@prisma/client';
import { encryptField, decryptField, blindIndex } from '../crypto/pii-crypto';

// Šifrēšana aktīva tikai pēc datu migrācijas — pirms tam DB satur plaintext
// Ieslēgt: PII_ENCRYPTION_ACTIVE=true pēc pii-encrypt-existing.ts palaišanas
function isEncryptionActive(): boolean {
  return process.env.PII_ENCRYPTION_ACTIVE === 'true';
}

// ── Šifrējamo lauku konfigurācija ──
// Tikai RESTRICTED/CONFIDENTIAL lauki pēc data-classification.ts

const ENCRYPTED_FIELDS: Record<string, string[]> = {
  User: ['email', 'firstName', 'lastName', 'phone', 'citizenship', 'dateOfBirth', 'birthPlace'],
  Identity: ['providerId'],
  // PasskeyCredential: credentialId un publicKey NAV PII — kriptogrāfiskas vērtības, ne personas dati
  VerificationDocument: ['storageKey'],
};

/** E-pasts → emailHmac; idCodeHmac jau eksistē un nav šifrēts */
const BLIND_INDEX_MAP: Record<string, Record<string, string>> = {
  User: { email: 'emailHmac' },
};

// ── Palīgfunkcijas ──

/** Šifrē norādītos laukus objektā (mutē in-place) */
function encryptFields(data: Record<string, any>, fields: string[]): void {
  if (!isEncryptionActive()) return;
  for (const field of fields) {
    if (data[field] != null && typeof data[field] === 'string') {
      data[field] = encryptField(data[field]);
    }
  }
}

/** Atšifrē norādītos laukus objektā (mutē in-place) */
function decryptFields(data: Record<string, any>, fields: string[]): void {
  if (!isEncryptionActive()) return;
  for (const field of fields) {
    if (data[field] != null && typeof data[field] === 'string') {
      try {
        data[field] = decryptField(data[field]);
      } catch {
        // Plaintext fallback — migrācijas laikā vecās rindas nav šifrētas
      }
    }
  }
}

/** Aprēķina blind index vērtības un pievieno datu objektam */
function computeBlindIndexes(
  data: Record<string, any>,
  indexMap: Record<string, string>,
): void {
  if (!isEncryptionActive()) return;
  for (const [sourceField, targetField] of Object.entries(indexMap)) {
    if (data[sourceField] != null && typeof data[sourceField] === 'string') {
      // Aprēķina HMAC pirms šifrēšanas — vajag plaintext vērtību
      data[targetField] = blindIndex(data[sourceField]);
    }
  }
}

/**
 * Pārraksta where nosacījumu lai izmantotu blind index.
 * Piemēram: { email: 'test@test.lv' } → { emailHmac: hmac('test@test.lv') }
 */
function rewriteWhereToBlindIndex(
  where: Record<string, any>,
  indexMap: Record<string, string>,
): void {
  if (!isEncryptionActive()) return;
  for (const [sourceField, targetField] of Object.entries(indexMap)) {
    if (where[sourceField] != null && typeof where[sourceField] === 'string') {
      where[targetField] = blindIndex(where[sourceField]);
      delete where[sourceField];
    }
  }
}

/** Atšifrē vienu rezultātu vai null */
function decryptResult<T>(result: T | null, fields: string[]): T | null {
  if (!result) return null;
  decryptFields(result as Record<string, any>, fields);
  return result;
}

/** Atšifrē rezultātu masīvu */
function decryptResults<T>(results: T[], fields: string[]): T[] {
  for (const r of results) {
    decryptFields(r as Record<string, any>, fields);
  }
  return results;
}

// ── Prisma $extends() definīcija ──

/**
 * Izveido Prisma klienta paplašinājumu ar caurspīdīgu PII šifrēšanu.
 * Katram modelim ar šifrētiem laukiem definētas query pārklājumi.
 */
export const piiEncryptionExtension = Prisma.defineExtension({
  query: {
    user: {
      async create({ args, query }) {
        if (args.data) {
          computeBlindIndexes(
            args.data as Record<string, any>,
            BLIND_INDEX_MAP.User,
          );
          encryptFields(
            args.data as Record<string, any>,
            ENCRYPTED_FIELDS.User,
          );
        }
        const result = await query(args);
        return decryptResult(result, ENCRYPTED_FIELDS.User)!;
      },

      async createMany({ args, query }) {
        const dataArr = Array.isArray(args.data) ? args.data : [args.data];
        for (const item of dataArr) {
          computeBlindIndexes(
            item as Record<string, any>,
            BLIND_INDEX_MAP.User,
          );
          encryptFields(item as Record<string, any>, ENCRYPTED_FIELDS.User);
        }
        return query(args);
      },

      async update({ args, query }) {
        if (args.data) {
          computeBlindIndexes(
            args.data as Record<string, any>,
            BLIND_INDEX_MAP.User,
          );
          encryptFields(
            args.data as Record<string, any>,
            ENCRYPTED_FIELDS.User,
          );
        }
        if (args.where) {
          rewriteWhereToBlindIndex(
            args.where as Record<string, any>,
            BLIND_INDEX_MAP.User,
          );
        }
        const result = await query(args);
        return decryptResult(result, ENCRYPTED_FIELDS.User)!;
      },

      async updateMany({ args, query }) {
        if (args.data) {
          computeBlindIndexes(
            args.data as Record<string, any>,
            BLIND_INDEX_MAP.User,
          );
          encryptFields(
            args.data as Record<string, any>,
            ENCRYPTED_FIELDS.User,
          );
        }
        if (args.where) {
          rewriteWhereToBlindIndex(
            args.where as Record<string, any>,
            BLIND_INDEX_MAP.User,
          );
        }
        return query(args);
      },

      async upsert({ args, query }) {
        if (args.create) {
          computeBlindIndexes(
            args.create as Record<string, any>,
            BLIND_INDEX_MAP.User,
          );
          encryptFields(
            args.create as Record<string, any>,
            ENCRYPTED_FIELDS.User,
          );
        }
        if (args.update) {
          computeBlindIndexes(
            args.update as Record<string, any>,
            BLIND_INDEX_MAP.User,
          );
          encryptFields(
            args.update as Record<string, any>,
            ENCRYPTED_FIELDS.User,
          );
        }
        if (args.where) {
          rewriteWhereToBlindIndex(
            args.where as Record<string, any>,
            BLIND_INDEX_MAP.User,
          );
        }
        const result = await query(args);
        return decryptResult(result, ENCRYPTED_FIELDS.User)!;
      },

      async findUnique({ args, query }) {
        if (args.where) {
          rewriteWhereToBlindIndex(
            args.where as Record<string, any>,
            BLIND_INDEX_MAP.User,
          );
        }
        const result = await query(args);
        return decryptResult(result, ENCRYPTED_FIELDS.User);
      },

      async findUniqueOrThrow({ args, query }) {
        if (args.where) {
          rewriteWhereToBlindIndex(
            args.where as Record<string, any>,
            BLIND_INDEX_MAP.User,
          );
        }
        const result = await query(args);
        return decryptResult(result, ENCRYPTED_FIELDS.User)!;
      },

      async findFirst({ args, query }) {
        if (args?.where) {
          rewriteWhereToBlindIndex(
            args.where as Record<string, any>,
            BLIND_INDEX_MAP.User,
          );
        }
        const result = await query(args);
        return decryptResult(result, ENCRYPTED_FIELDS.User);
      },

      async findMany({ args, query }) {
        if (args?.where) {
          rewriteWhereToBlindIndex(
            args.where as Record<string, any>,
            BLIND_INDEX_MAP.User,
          );
        }
        const results = await query(args);
        return decryptResults(results, ENCRYPTED_FIELDS.User);
      },

      async delete({ args, query }) {
        if (args.where) {
          rewriteWhereToBlindIndex(
            args.where as Record<string, any>,
            BLIND_INDEX_MAP.User,
          );
        }
        const result = await query(args);
        return decryptResult(result, ENCRYPTED_FIELDS.User)!;
      },
    },

    identity: {
      async create({ args, query }) {
        if (args.data) {
          encryptFields(
            args.data as Record<string, any>,
            ENCRYPTED_FIELDS.Identity,
          );
        }
        const result = await query(args);
        return decryptResult(result, ENCRYPTED_FIELDS.Identity)!;
      },

      async update({ args, query }) {
        if (args.data) {
          encryptFields(
            args.data as Record<string, any>,
            ENCRYPTED_FIELDS.Identity,
          );
        }
        const result = await query(args);
        return decryptResult(result, ENCRYPTED_FIELDS.Identity)!;
      },

      async findUnique({ args, query }) {
        const result = await query(args);
        return decryptResult(result, ENCRYPTED_FIELDS.Identity);
      },

      async findUniqueOrThrow({ args, query }) {
        const result = await query(args);
        return decryptResult(result, ENCRYPTED_FIELDS.Identity)!;
      },

      async findFirst({ args, query }) {
        const result = await query(args);
        return decryptResult(result, ENCRYPTED_FIELDS.Identity);
      },

      async findMany({ args, query }) {
        const results = await query(args);
        return decryptResults(results, ENCRYPTED_FIELDS.Identity);
      },
    },

    // PasskeyCredential — nav šifrēts, credentialId/publicKey nav PII

    verificationDocument: {
      async create({ args, query }) {
        if (args.data) {
          encryptFields(
            args.data as Record<string, any>,
            ENCRYPTED_FIELDS.VerificationDocument,
          );
        }
        const result = await query(args);
        return decryptResult(result, ENCRYPTED_FIELDS.VerificationDocument)!;
      },

      async update({ args, query }) {
        if (args.data) {
          encryptFields(
            args.data as Record<string, any>,
            ENCRYPTED_FIELDS.VerificationDocument,
          );
        }
        const result = await query(args);
        return decryptResult(result, ENCRYPTED_FIELDS.VerificationDocument)!;
      },

      async findUnique({ args, query }) {
        const result = await query(args);
        return decryptResult(result, ENCRYPTED_FIELDS.VerificationDocument);
      },

      async findUniqueOrThrow({ args, query }) {
        const result = await query(args);
        return decryptResult(result, ENCRYPTED_FIELDS.VerificationDocument)!;
      },

      async findFirst({ args, query }) {
        const result = await query(args);
        return decryptResult(result, ENCRYPTED_FIELDS.VerificationDocument);
      },

      async findMany({ args, query }) {
        const results = await query(args);
        return decryptResults(results, ENCRYPTED_FIELDS.VerificationDocument);
      },
    },
  },
});
