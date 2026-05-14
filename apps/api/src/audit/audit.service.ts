/*
Imutāls audita žurnāls ar HMAC-SHA256 ķēdes integritātes nodrošinājumu.
Katra ieraksta hash atkarīgs no iepriekšējā prevHash — manipulācijas nosakāmas verifikācijā gan no head, gan tail.
Serializācija aizsargāta ar pg_advisory_xact_lock, lai paralēlas rakstīšanas nesabojātu ķēdi.
OWASP ASVS v5 V10 (logging) — tamper-evident audit trail.
*/

import { Injectable } from '@nestjs/common';
import { createHmac } from 'crypto';
import { PrismaService } from '../prisma/prisma.service';

export type AuditResult = 'Success' | 'Denied' | 'Error';

export interface AuditEventInput {
  rid?: string | null;
  subjectId?: string | null;
  subjectRole?: string | null;

  action: string;
  entityType?: string | null;
  entityId?: string | null;

  result: AuditResult;

  clientIp?: string | null;
  userAgent?: string | null;

  // Papildu strukturēti dati (bez noslēpumiem / bez PII)
  dataJson?: unknown | null;
}

function canonicalize(value: any): any {
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.map(canonicalize);
  if (typeof value === 'object') {
    const out: Record<string, any> = {};
    for (const k of Object.keys(value).sort()) out[k] = canonicalize(value[k]);
    return out;
  }
  return value;
}

function canonicalJson(value: any): string {
  return JSON.stringify(canonicalize(value));
}

@Injectable()
export class AuditService {
  private readonly key: string;
  private static readonly LOCK_ID = 726175726175726175n;

  constructor(private readonly prisma: PrismaService) {
    const k = process.env.AUDIT_HMAC_KEY;
    if (!k || !k.trim()) throw new Error('AUDIT_HMAC_KEY is not set');
    this.key = k;
  }

  private hmacBase64(input: string): string {
    return createHmac('sha256', this.key)
      .update(input, 'utf8')
      .digest('base64');
  }

  // Ķēdes verifikācija no sākuma (klasiskā) — saderīga ar esošajiem izsaukumiem
  async verifyChain(opts?: { limit?: number }) {
    return this.verifyChainWindow({ limit: opts?.limit ?? 5000, from: 'head' });
  }

  // Jaunāko ierakstu verifikācija — pārbauda pēdējās N rindas
  // Novērš situāciju kur tiek pārbaudītas tikai vecākās rindas un jaunākas manipulācijas paliek nepamanītas
  async verifyRecentChain(opts?: { limit?: number }) {
    return this.verifyChainWindow({ limit: opts?.limit ?? 5000, from: 'tail' });
  }

  private async verifyChainWindow(opts: { limit: number; from: 'head' | 'tail' }) {
    const { limit, from } = opts;
    const chainSelect = {
      id: true, seq: true, ts: true, rid: true,
      subjectId: true, subjectRole: true, action: true,
      entityType: true, entityId: true, result: true,
      clientIp: true, userAgent: true, dataJson: true,
      prevHash: true, hash: true,
    } as const;

    let rows: Awaited<ReturnType<typeof this.prisma.auditLog.findMany>>;
    let anchorHash = ''; // Hash no iepriekšējā ieraksta pirms loga

    if (from === 'head') {
      rows = await this.prisma.auditLog.findMany({
        orderBy: { seq: 'asc' },
        take: limit,
        select: chainSelect,
      });
    } else {
      // Tail: ielasām limit+1 rindas no beigām, lai pirmā rinda kalpo kā enkurs
      const descRows = await this.prisma.auditLog.findMany({
        orderBy: { seq: 'desc' },
        take: limit + 1,
        select: chainSelect,
      });
      // Apgriežam atpakaļ ASC secībā
      descRows.reverse();

      if (descRows.length > limit) {
        // Pirmā rinda ir enkurs — tās hash ir prevHash atskaites punkts
        anchorHash = descRows[0].hash;
        rows = descRows.slice(1);
      } else {
        // Mazāk rindu nekā limit — pārbaudām visu ķēdi no sākuma
        rows = descRows;
      }
    }

    let prev = anchorHash;
    for (let i = 0; i < rows.length; i++) {
      const r = rows[i];

      const safeEvent = {
        ts: new Date(r.ts).toISOString(),
        rid: r.rid ?? null,
        subjectId: r.subjectId ?? null,
        subjectRole: r.subjectRole ?? null,
        action: r.action,
        entityType: r.entityType ?? null,
        entityId: r.entityId ?? null,
        result: r.result as any,
        clientIp: r.clientIp ?? null,
        userAgent: r.userAgent ?? null,
        dataJson: r.dataJson ?? null,
      };

      const payload = canonicalJson(safeEvent);
      const expected = this.hmacBase64((prev ?? '') + payload);

      const expectedPrevHash = prev === '' ? null : prev;
      const prevMatches = (r.prevHash ?? null) === expectedPrevHash;
      const hashMatches = r.hash === expected;

      if (!prevMatches || !hashMatches) {
        return {
          ok: false,
          checked: i + 1,
          brokenAt: {
            index: i + 1,
            id: r.id,
            seq: Number(r.seq),
            rid: r.rid ?? null,
            reason: !prevMatches ? 'prevHash_mismatch' : 'hash_mismatch',
            expectedPrevHash,
            storedPrevHash: r.prevHash ?? null,
            expectedHash: expected,
            storedHash: r.hash,
          },
        };
      }

      prev = r.hash;
    }

    return { ok: true, checked: rows.length, brokenAt: null };
  }
  async query(q: {
    rid?: string;
    action?: string;
    subjectId?: string;
    entityType?: string;
    entityId?: string;
    order?: 'asc' | 'desc';
    limit?: number;
  }) {
    const take = Math.min(Math.max(q.limit ?? 50, 1), 200);
    const order = q.order === 'asc' ? 'asc' : 'desc';

    return this.prisma.auditLog.findMany({
      where: {
        rid: q.rid ? { equals: q.rid } : undefined,
        action: q.action
          ? { contains: q.action, mode: 'insensitive' }
          : undefined,
        subjectId: q.subjectId ? { equals: q.subjectId } : undefined,
        entityType: q.entityType ? { equals: q.entityType } : undefined,
        entityId: q.entityId ? { equals: q.entityId } : undefined,
      },
      orderBy: { seq: order },
      take,
      select: {
        ts: true,
        rid: true,
        subjectId: true,
        subjectRole: true,
        action: true,
        entityType: true,
        entityId: true,
        result: true,
        clientIp: true,
        userAgent: true,
        prevHash: true,
        hash: true,
        dataJson: true,
      },
    });
  }

  async write(event: AuditEventInput) {
    const tsIso = new Date().toISOString();

    return this.prisma.$transaction(async (tx) => {
      /*
      Serializē visus audita ierakstus ŠAJĀ datubāzē
      — transakcijas līmeņa slēdzene atbrīvojas automātiski, kad tx beidzas.
      */
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(${AuditService.LOCK_ID});`;

      const last = await tx.auditLog.findFirst({
        orderBy: { seq: 'desc' },
        select: { hash: true },
      });

      const prevHash = last?.hash ?? null;

      const safeEvent = {
        ts: tsIso,
        rid: event.rid ?? null,
        subjectId: event.subjectId ?? null,
        subjectRole: event.subjectRole ?? null,
        action: event.action,
        entityType: event.entityType ?? null,
        entityId: event.entityId ?? null,
        result: event.result,
        clientIp: event.clientIp ?? null,
        userAgent: event.userAgent ?? null,
        dataJson: event.dataJson ?? null,
      };

      const payload = canonicalJson(safeEvent);
      const hash = this.hmacBase64((prevHash ?? '') + payload);

      return tx.auditLog.create({
        data: {
          ts: new Date(tsIso),
          rid: event.rid ?? null,
          subjectId: event.subjectId ?? null,
          subjectRole: event.subjectRole ?? null,
          action: event.action,
          entityType: event.entityType ?? null,
          entityId: event.entityId ?? null,
          result: event.result,
          clientIp: event.clientIp ?? null,
          userAgent: event.userAgent ?? null,
          prevHash,
          hash,
          dataJson:
            event.dataJson == null ? undefined : (event.dataJson as any),
        },
      });
    });
  }
}
