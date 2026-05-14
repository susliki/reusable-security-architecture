/*
Prisma klients ar PII šifrēšanas un audita lauku paplašinājumiem.
Izmanto pg savienojumu pūlu caur PrismaPg adapteri; reģistrē graceful shutdown,
lai onModuleDestroy aizver gan klientu, gan pg pūlu pareizi.
GDPR Art. 32 — šifrēšana miera stāvoklī personu datiem.
*/

import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import { Pool } from 'pg';
import { piiEncryptionExtension } from './prisma-encryption.extension';
import { auditFieldsExtension } from './prisma-audit-fields.extension';

// Paplašinātā klienta tips — $extends() atgriež jaunu instanci, nevar extends PrismaClient
const extendedPrismaClient = () => {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) throw new Error('DATABASE_URL is not set');

  const pool = new Pool({ connectionString });
  const adapter = new PrismaPg(pool);
  const client = new PrismaClient({ adapter })
    .$extends(piiEncryptionExtension)
    .$extends(auditFieldsExtension);

  return { client, pool };
};

export type ExtendedPrismaClient = ReturnType<
  typeof extendedPrismaClient
>['client'];

@Injectable()
export class PrismaService implements OnModuleInit, OnModuleDestroy {
  private readonly pool: Pool;
  public readonly client: ExtendedPrismaClient;

  constructor() {
    const { client, pool } = extendedPrismaClient();
    this.client = client;
    this.pool = pool;
  }

  async onModuleInit() {
    await (this.client as any).$connect();
  }

  async onModuleDestroy() {
    await (this.client as any).$disconnect();
    await this.pool.end();
  }

  // Proxy getteri — esošais kods turpina izmantot this.prisma.user utt.
  get user() {
    return this.client.user;
  }
  get identity() {
    return this.client.identity;
  }
  get passkeyCredential() {
    return this.client.passkeyCredential;
  }
  get session() {
    return this.client.session;
  }
  get auditLog() {
    return this.client.auditLog;
  }
  get verificationDocument() {
    return this.client.verificationDocument;
  }
  get userConsent() {
    return this.client.userConsent;
  }
  get rectificationRequest() {
    return this.client.rectificationRequest;
  }
  get notification() {
    return this.client.notification;
  }
  get userNameHistory() {
    return this.client.userNameHistory;
  }
  get $transaction() {
    return this.client.$transaction.bind(this.client);
  }
  get $queryRaw() {
    return this.client.$queryRaw.bind(this.client);
  }
  get $executeRaw() {
    return this.client.$executeRaw.bind(this.client);
  }
}
