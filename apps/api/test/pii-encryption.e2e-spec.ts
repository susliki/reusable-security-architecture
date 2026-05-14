import { config } from 'dotenv';
import { resolve } from 'path';
config({ path: resolve(__dirname, '../.env') });

import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import { Pool } from 'pg';
import { piiEncryptionExtension } from '../src/prisma/prisma-encryption.extension';
import {
  blindIndex,
  isEncryptedValue,
  _resetKeyCache,
} from '../src/crypto/pii-crypto';
import { validateCryptoKeys } from '../src/crypto/crypto-config';

/**
 * E2E testi — pārbauda šifrēšanu caur pilnu Prisma extension plūsmu.
 * Verificē, ka extension atgriež plaintext bet DB satur šifrētu.
 */

const TEST_ENC_KEY = 'a'.repeat(64);
const TEST_IDX_KEY = 'b'.repeat(64);

let prisma: PrismaClient;
let rawPrisma: PrismaClient;
let pool: Pool;

beforeAll(() => {
  _resetKeyCache();
  process.env.PII_ENCRYPTION_KEY = TEST_ENC_KEY;
  process.env.PII_BLIND_INDEX_KEY = TEST_IDX_KEY;
  process.env.PII_ENCRYPTION_ACTIVE = 'true';

  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) throw new Error('DATABASE_URL nav iestatīts');

  pool = new Pool({ connectionString });
  const adapter = new PrismaPg(pool);
  rawPrisma = new PrismaClient({ adapter });
  prisma = rawPrisma.$extends(piiEncryptionExtension) as unknown as PrismaClient;
});

afterAll(async () => {
  await rawPrisma.$disconnect();
  await pool.end();
  _resetKeyCache();
});

describe('PII Encryption E2E', () => {
  it('lietotāja izveide šifrē PII laukus datubāzē', async () => {
    const testEmail = `e2e-${Date.now()}@test.lv`;

    // Izveido caur extension — atgriež plaintext
    const user = await prisma.user.create({
      data: { email: testEmail, firstName: 'E2E', lastName: 'Tests' },
    });
    expect(user.email).toBe(testEmail);

    // DB satur šifrētu
    const raw = await rawPrisma.user.findUnique({ where: { id: user.id } });
    expect(raw!.email).not.toBe(testEmail);
    expect(isEncryptedValue(raw!.email!)).toBe(true);
    expect(raw!.emailHmac).toBe(blindIndex(testEmail));

    // Meklēšana pēc email strādā (caur blind index)
    const found = await prisma.user.findUnique({
      where: { email: testEmail },
    });
    expect(found).not.toBeNull();
    expect(found!.id).toBe(user.id);

    // Notīram
    await rawPrisma.user.delete({ where: { id: user.id } });
  });

  it('startup validācija noraida nederīgu atslēgu', () => {
    const original = process.env.PII_ENCRYPTION_KEY;
    process.env.PII_ENCRYPTION_KEY = 'tooshort';
    _resetKeyCache();

    expect(() => validateCryptoKeys()).toThrow();

    process.env.PII_ENCRYPTION_KEY = original;
    _resetKeyCache();
  });

  it('startup validācija noraida vienādas atslēgas', () => {
    const original = process.env.PII_BLIND_INDEX_KEY;
    process.env.PII_BLIND_INDEX_KEY = TEST_ENC_KEY; // Tāda pati kā encryption
    _resetKeyCache();

    expect(() => validateCryptoKeys()).toThrow('nedrīkst būt vienādas');

    process.env.PII_BLIND_INDEX_KEY = original;
    _resetKeyCache();
  });
});
