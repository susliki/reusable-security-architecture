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
  User: ['email', 'firstName', 'lastName', 'phone', 'citizenship', 'dateOfBirth', 'birthPlace', 'personalCodeEnc', 'address'],
  UserNameHistory: ['previousFirst', 'previousLast', 'newFirst', 'newLast'],
  /*
  Identity: providerId nav PII — tas ir userId vai providera identifikators
  Šifrēšana lauž @@unique([provider, providerId]) ar nedeterministisku šifrētekstu
  PasskeyCredential: credentialId un publicKey NAV PII — kriptogrāfiskas vērtības, ne personas dati
  */
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

// ── Query ģenerators ──

/**
 * Ģenerē Prisma query pārklājumus vienam modelim.
 * Novērš koda dublēšanos — katra modeļa šifrēšanas loģika ir identiska,
 * atšķiras tikai lauku saraksts un blind index konfigurācija.
 */
function buildModelQueries(
  fields: string[],
  indexMap?: Record<string, string>,
) {
  /** Šifrē datus pirms rakstīšanas DB (blind index + lauku šifrēšana) */
  function processWrite(data: Record<string, any> | undefined): void {
    if (!data) return;
    if (indexMap) computeBlindIndexes(data, indexMap);
    encryptFields(data, fields);
  }

  /** Pārraksta where nosacījumu uz blind index meklēšanu */
  function processWhere(where: Record<string, any> | undefined): void {
    if (!where || !indexMap) return;
    rewriteWhereToBlindIndex(where, indexMap);
  }

  return {
    async create({ args, query }) {
      processWrite(args.data as any);
      return decryptResult(await query(args), fields)!;
    },

    async createMany({ args, query }) {
      const dataArr = Array.isArray(args.data) ? args.data : [args.data];
      for (const item of dataArr) {
        processWrite(item as any);
      }
      // createMany neatgriež ierakstus — nav ko atšifrēt
      return query(args);
    },

    async update({ args, query }) {
      processWrite(args.data as any);
      processWhere(args.where as any);
      return decryptResult(await query(args), fields)!;
    },

    async updateMany({ args, query }) {
      processWrite(args.data as any);
      processWhere(args.where as any);
      // updateMany atgriež tikai count — nav ko atšifrēt
      return query(args);
    },

    async upsert({ args, query }) {
      processWrite(args.create as any);
      processWrite(args.update as any);
      processWhere(args.where as any);
      return decryptResult(await query(args), fields)!;
    },

    async findUnique({ args, query }) {
      processWhere(args.where as any);
      return decryptResult(await query(args), fields);
    },

    async findUniqueOrThrow({ args, query }) {
      processWhere(args.where as any);
      return decryptResult(await query(args), fields)!;
    },

    async findFirst({ args, query }) {
      processWhere(args?.where as any);
      return decryptResult(await query(args), fields);
    },

    async findMany({ args, query }) {
      processWhere(args?.where as any);
      return decryptResults(await query(args), fields);
    },

    async delete({ args, query }) {
      processWhere(args.where as any);
      return decryptResult(await query(args), fields)!;
    },
  };
}

// ── Prisma $extends() definīcija ──

/**
 * Prisma klienta paplašinājums ar caurspīdīgu PII šifrēšanu.
 * Izmanto buildModelQueries() lai novērstu identisku loģiku katrā modelī.
 */
export const piiEncryptionExtension = Prisma.defineExtension({
  query: {
    user: buildModelQueries(ENCRYPTED_FIELDS.User, BLIND_INDEX_MAP.User),
    userNameHistory: buildModelQueries(ENCRYPTED_FIELDS.UserNameHistory),
    // Identity — providerId nav šifrēts, skatīt komentāru pie ENCRYPTED_FIELDS
    // PasskeyCredential — nav šifrēts, credentialId/publicKey nav PII
    verificationDocument: buildModelQueries(ENCRYPTED_FIELDS.VerificationDocument),
  },
});
