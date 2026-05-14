import { config } from 'dotenv';
import { existsSync } from 'fs';
import { resolve } from 'path';

// Pirms apps/api/.env, tad fallback uz monorepo saknes .env
const localEnv = resolve(__dirname, '../../.env');
const rootEnv = resolve(__dirname, '../../../../.env');
config({ path: existsSync(localEnv) ? localEnv : rootEnv });

import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import { Pool } from 'pg';
import { piiEncryptionExtension } from './prisma-encryption.extension';
import {
  decryptField,
  blindIndex,
  _resetKeyCache,
} from '../crypto/pii-crypto';

/**
 * Integrācijas testi — pārbauda vai Prisma extension šifrē/atšifrē caurspīdīgi.
 * Vajadzīga testa datubāze (DATABASE_URL jānorāda uz test DB).
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

describe('User encryption extension', () => {
  const testEmail = `test-${Date.now()}@example.com`;
  let userId: string;

  afterAll(async () => {
    if (userId) {
      await rawPrisma.user.delete({ where: { id: userId } }).catch(() => {});
    }
  });

  it('create šifrē laukus un aprēķina emailHmac', async () => {
    const user = await prisma.user.create({
      data: {
        email: testEmail,
        firstName: 'Testa',
        lastName: 'Lietotājs',
        role: 'USER',
      },
    });
    userId = user.id;

    // Extension atgriež atšifrētu — application kods redz plaintext
    expect(user.email).toBe(testEmail);
    expect(user.firstName).toBe('Testa');
    expect(user.lastName).toBe('Lietotājs');

    // DB satur šifrētu vērtību — pārbaudam ar raw query
    const raw = await rawPrisma.user.findUnique({ where: { id: userId } });
    expect(raw!.email).not.toBe(testEmail);

    // emailHmac ir korekts
    expect(raw!.emailHmac).toBe(blindIndex(testEmail));
  });

  it('findUnique pēc email pārraksta uz emailHmac', async () => {
    const user = await prisma.user.findUnique({
      where: { email: testEmail },
    });
    expect(user).not.toBeNull();
    expect(user!.id).toBe(userId);
    expect(user!.email).toBe(testEmail);
  });

  it('findMany atšifrē visus rezultātus', async () => {
    const users = await prisma.user.findMany({
      where: { id: userId },
    });
    expect(users.length).toBe(1);
    expect(users[0].email).toBe(testEmail);
    expect(users[0].firstName).toBe('Testa');
    expect(users[0].lastName).toBe('Lietotājs');
  });

  it('update pāršifrē mainītos laukus', async () => {
    const updated = await prisma.user.update({
      where: { id: userId },
      data: { firstName: 'Jauns', lastName: 'Vārds' },
    });
    expect(updated.firstName).toBe('Jauns');
    expect(updated.lastName).toBe('Vārds');

    // DB satur šifrētu firstName/lastName
    const raw = await rawPrisma.user.findUnique({ where: { id: userId } });
    expect(raw!.firstName).not.toBe('Jauns');
    expect(raw!.lastName).not.toBe('Vārds');
  });

  it('upsert strādā ar šifrēšanu', async () => {
    const newEmail = `upsert-${Date.now()}@example.com`;
    const user = await prisma.user.upsert({
      where: { email: newEmail },
      create: { email: newEmail, role: 'USER' },
      update: {},
    });
    expect(user.email).toBe(newEmail);

    // Notīram
    await rawPrisma.user.delete({ where: { id: user.id } });
  });
});
