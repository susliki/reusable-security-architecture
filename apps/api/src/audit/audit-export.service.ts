/*
Audita žurnāla periodisks NDJSON eksports — ikdienas/iknedēļas/ikmēneša ārējais arhīvs.
Katrs fails parakstīts ar HMAC-SHA256 un satur SHA-256 checksum metadatos — atbilstības verifikācija ārpus DB.
OWASP ASVS v5 V10 (logging) — eksportu fails liecina par neatkarīgu žurnāla kopiju ārpus aplikācijas.
*/

import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { createHash, createHmac } from 'crypto';
import * as fs from 'fs/promises';
import * as path from 'path';

type ExportMeta = {
  version: 1;
  exportedAt: string; // ISO
  range: { from: string; to: string };
  limit: number;
  count: number;
};

function sha256Hex(buf: Buffer | string) {
  return createHash('sha256').update(buf).digest('hex');
}

function hmacBase64(key: string, input: string) {
  return createHmac('sha256', key).update(input, 'utf8').digest('base64');
}

function startOfDay(d: Date) {
  return new Date(
    Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate(), 0, 0, 0, 0),
  );
}

function addDays(d: Date, days: number) {
  const x = new Date(d.getTime());
  x.setUTCDate(x.getUTCDate() + days);
  return x;
}

function periodRange(period: 'daily' | 'weekly' | 'monthly', now = new Date()) {
  // Pēc noklusējuma eksportē *iepriekšējo* pilno periodu
  const today0 = startOfDay(now);

  if (period === 'daily') {
    const to = today0;
    const from = addDays(to, -1);
    return { from, to };
  }

  if (period === 'weekly') {
    // ISO stila nedēļa — sākas pirmdien 00:00 UTC
    const day = today0.getUTCDay(); // 0 = svētdiena .. 6 = sestdiena
    const mondayOffset = (day + 6) % 7; // Pirm=0, Otrd=1, ... Svētd=6
    const thisMon = addDays(today0, -mondayOffset);
    const to = thisMon;
    const from = addDays(to, -7);
    return { from, to };
  }

  // mēneša periods
  const y = today0.getUTCFullYear();
  const m = today0.getUTCMonth();
  const firstThis = new Date(Date.UTC(y, m, 1, 0, 0, 0, 0));
  const to = firstThis;
  const firstPrev = new Date(Date.UTC(y, m - 1, 1, 0, 0, 0, 0));
  const from = firstPrev;
  return { from, to };
}

@Injectable()
export class AuditExportService {
  constructor(private readonly prisma: PrismaService) {}

  private getExportDir() {
    const dir = (process.env.AUDIT_EXPORT_DIR ?? '').trim();
    if (!dir) throw new Error('AUDIT_EXPORT_DIR is not set');
    return dir;
  }

  private getExportKey() {
    const k = (process.env.AUDIT_EXPORT_HMAC_KEY ?? '').trim();
    if (!k) throw new Error('AUDIT_EXPORT_HMAC_KEY is not set');
    if (k.length < 32)
      throw new Error('AUDIT_EXPORT_HMAC_KEY must be >= 32 chars');
    return k;
  }

  async exportRange(input: { from: Date; to: Date; limit: number }) {
    const exportDir = this.getExportDir();
    const exportKey = this.getExportKey();

    await fs.mkdir(exportDir, { recursive: true });

    const exportedAt = new Date().toISOString();
    const runId = exportedAt.replace(/[:.]/g, '-'); // drošs failu nosaukumiem
    const base = `audit_${runId}`;

    const rowsFile = path.join(exportDir, `${base}.rows.jsonl`);
    const metaFile = path.join(exportDir, `${base}.meta.json`);
    const sumsFile = path.join(exportDir, `${base}.sha256sums.txt`);
    const sigFile = path.join(exportDir, `${base}.signature.txt`);

    // Deterministiska secība — ts asc, tad id asc
    const rows = await this.prisma.auditLog.findMany({
      where: {
        ts: { gte: input.from, lt: input.to },
      },
      orderBy: [{ ts: 'asc' }, { id: 'asc' }],
      take: input.limit,
      select: {
        id: true,
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

    // Rakstām rindas JSONL formātā
    const lines: string[] = [];
    for (const r of rows) {
      lines.push(
        JSON.stringify({
          id: r.id,
          ts: new Date(r.ts).toISOString(),
          rid: r.rid ?? null,
          subjectId: r.subjectId ?? null,
          subjectRole: r.subjectRole ?? null,
          action: r.action,
          entityType: r.entityType ?? null,
          entityId: r.entityId ?? null,
          result: r.result,
          clientIp: r.clientIp ?? null,
          userAgent: r.userAgent ?? null,
          prevHash: r.prevHash ?? null,
          hash: r.hash,
          dataJson: r.dataJson ?? null,
        }),
      );
    }
    const rowsContent = lines.join('\n') + (lines.length ? '\n' : '');
    await fs.writeFile(rowsFile, rowsContent, 'utf8');

    const meta: ExportMeta = {
      version: 1,
      exportedAt,
      range: { from: input.from.toISOString(), to: input.to.toISOString() },
      limit: input.limit,
      count: rows.length,
    };
    const metaContent = JSON.stringify(meta, null, 2) + '\n';
    await fs.writeFile(metaFile, metaContent, 'utf8');

    const rowsSha = sha256Hex(rowsContent);
    const metaSha = sha256Hex(metaContent);

    const sumsContent = `${metaSha}  ${path.basename(metaFile)}\n${rowsSha}  ${path.basename(rowsFile)}\n`;
    await fs.writeFile(sumsFile, sumsContent, 'utf8');

    // Parakstām meta+hashus (mazs + stabils saturs)
    const sigPayload = `metaSha256=${metaSha}\nrowsSha256=${rowsSha}\nexportedAt=${exportedAt}\n`;
    const signature = hmacBase64(exportKey, sigPayload);
    await fs.writeFile(sigFile, signature + '\n', 'utf8');

    return {
      ok: true,
      meta,
      files: {
        meta: path.basename(metaFile),
        rows: path.basename(rowsFile),
        sha256sums: path.basename(sumsFile),
        signature: path.basename(sigFile),
      },
      signature,
      signaturePayload: sigPayload, // noder verifikācijas rīkiem
    };
  }

  async exportPeriod(input: {
    period: 'daily' | 'weekly' | 'monthly';
    limit: number;
  }) {
    const { from, to } = periodRange(input.period, new Date());
    return this.exportRange({ from, to, limit: input.limit });
  }
}
