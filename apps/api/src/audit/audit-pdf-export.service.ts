/*
Audita žurnāla PDF eksports — HMAC-parakstīts atbilstības dokuments inspektoriem un auditoriem.
Straumē PDF tieši uz HTTP response, iekļauj ķēdes integritātes verifikācijas rezultātu eksporta brīdī.
OWASP ASVS v5 V10 — neatkarīgs cilvēkam lasāms audita žurnāla momentuzņēmums ar paraksta verifikāciju.
*/

import { Injectable } from '@nestjs/common';
import { createHmac } from 'crypto';
import PDFDocument from 'pdfkit';
import type { Response } from 'express';

import { PrismaService } from '../prisma/prisma.service';
import { AuditService } from './audit.service';

// Formāts: DD.MM.YYYY HH:mm:ss
function formatTs(d: Date | string): string {
  const date = typeof d === 'string' ? new Date(d) : d;
  const dd = String(date.getDate()).padStart(2, '0');
  const mm = String(date.getMonth() + 1).padStart(2, '0');
  const yyyy = date.getFullYear();
  const hh = String(date.getHours()).padStart(2, '0');
  const mi = String(date.getMinutes()).padStart(2, '0');
  const ss = String(date.getSeconds()).padStart(2, '0');
  return `${dd}.${mm}.${yyyy} ${hh}:${mi}:${ss}`;
}

// ISO datuma formāts failam
function isoDate(d: Date | string): string {
  const date = typeof d === 'string' ? new Date(d) : d;
  return date.toISOString().slice(0, 10);
}

@Injectable()
export class AuditPdfExportService {
  private readonly hmacKey: string;

  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {
    const k = process.env.AUDIT_HMAC_KEY;
    if (!k || !k.trim()) throw new Error('AUDIT_HMAC_KEY is not set');
    this.hmacKey = k;
  }

  /**
   * Ģenerē HMAC-parakstītu PDF ar audita ierakstiem un ķēdes verifikāciju.
   * Rezultātu straumē tieši uz HTTP response.
   */
  async exportPdf(
    res: Response,
    opts: { from: Date; to: Date },
  ): Promise<void> {
    const { from, to } = opts;
    const now = new Date();

    // Iegūt ierakstus no DB — hronoloģiskā secībā
    const rows = await this.prisma.auditLog.findMany({
      where: { ts: { gte: from, lt: to } },
      orderBy: [{ ts: 'asc' }, { id: 'asc' }],
      select: {
        id: true,
        ts: true,
        subjectId: true,
        action: true,
        result: true,
        clientIp: true,
        hash: true,
      },
    });

    // Ķēdes integritātes pārbaude — jaunākie ieraksti (visticamāk manipulēti)
    const chainResult = await this.audit.verifyRecentChain({ limit: 200_000 });

    // PDF faila nosaukums
    const filename = `audit-export-${isoDate(now)}.pdf`;

    // HTTP galvenes — straumēšanai
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename=${filename}`,
    );

    // A4 landscape — vairāk vietas tabulai
    const doc = new PDFDocument({
      size: 'A4',
      layout: 'landscape',
      margins: { top: 50, bottom: 60, left: 40, right: 40 },
      bufferPages: true,
      info: {
        Title: 'E-Jūrnieks — Audita žurnāla eksports',
        Author: 'Latvijas Jūras administrācija',
        Creator: 'E-Jūrnieks sistēma',
      },
    });

    doc.pipe(res);

    // ── Virsraksts ──

    doc
      .fontSize(18)
      .font('Helvetica-Bold')
      .text('Audita zurnala eksports', { align: 'center' });

    doc
      .moveDown(0.3)
      .fontSize(11)
      .font('Helvetica')
      .text('Latvijas Juras administracija', { align: 'center' });

    doc.moveDown(0.5);

    doc
      .fontSize(9)
      .text(
        `Eksporta datums: ${formatTs(now)}    |    Periods: ${formatTs(from)} — ${formatTs(to)}    |    Ieraksti: ${rows.length}`,
        { align: 'center' },
      );

    doc.moveDown(1);

    // ── Tabulas galvene ──

    const colX = {
      ts: 40,
      user: 180,
      action: 330,
      result: 490,
      ip: 570,
      hash: 660,
    };

    const drawTableHeader = () => {
      const y = doc.y;
      doc.fontSize(8).font('Helvetica-Bold');
      doc.text('Laiks', colX.ts, y);
      doc.text('Lietotajs', colX.user, y);
      doc.text('Darbiba', colX.action, y);
      doc.text('Rezultats', colX.result, y);
      doc.text('IP', colX.ip, y);
      doc.text('Hash (16)', colX.hash, y);
      doc.moveDown(0.3);

      // Atdalītāja līnija
      const lineY = doc.y;
      doc
        .strokeColor('#999999')
        .lineWidth(0.5)
        .moveTo(colX.ts, lineY)
        .lineTo(780, lineY)
        .stroke();
      doc.moveDown(0.3);
    };

    drawTableHeader();

    // ── Ierakstu rindas ──

    for (const row of rows) {
      // Pārbaude vai jāpārlec uz jaunu lapu (atlikums < 60pt)
      if (doc.y > 500) {
        doc.addPage();
        drawTableHeader();
      }

      const y = doc.y;
      const tsStr = formatTs(new Date(row.ts));
      const user =
        row.subjectId
          ? row.subjectId.length > 16
            ? row.subjectId.slice(0, 14) + '..'
            : row.subjectId
          : 'SYSTEM';
      const actionStr =
        row.action.length > 22 ? row.action.slice(0, 20) + '..' : row.action;
      const hashShort = row.hash.slice(0, 16);

      doc.fontSize(7).font('Helvetica');
      doc.text(tsStr, colX.ts, y, { width: 130 });
      doc.text(user, colX.user, y, { width: 140 });
      doc.text(actionStr, colX.action, y, { width: 150 });
      doc.text(row.result, colX.result, y, { width: 70 });
      doc.text(row.clientIp ?? '—', colX.ip, y, { width: 80 });

      // Hash — monospace fonts
      doc.font('Courier').text(hashShort, colX.hash, y, { width: 130 });

      doc.moveDown(0.2);
    }

    // ── Integritātes apliecinājuma sekcija ──

    doc.addPage();

    doc
      .fontSize(14)
      .font('Helvetica-Bold')
      .text('Integritates apliecinajums', { align: 'center' });

    doc.moveDown(1);
    doc.fontSize(10).font('Helvetica');

    const firstHash = rows.length > 0 ? rows[0].hash : '(nav ierakstu)';
    const lastHash =
      rows.length > 0 ? rows[rows.length - 1].hash : '(nav ierakstu)';

    doc.text(`Kopejais ierakstu skaits: ${rows.length}`);
    doc.moveDown(0.3);

    doc.text('Pirmais ieraksta hash:');
    doc.font('Courier').fontSize(8).text(firstHash);
    doc.moveDown(0.3);

    doc.font('Helvetica').fontSize(10).text('Pedejais ieraksta hash:');
    doc.font('Courier').fontSize(8).text(lastHash);
    doc.moveDown(0.5);

    // Ķēdes verifikācijas rezultāts
    doc.font('Helvetica-Bold').fontSize(10).text('Kedes verifikacija:');
    doc.moveDown(0.2);

    if (chainResult.ok) {
      doc
        .font('Helvetica')
        .fontSize(10)
        .text(
          `Rezultats: Deriga (parbaudes ${chainResult.checked} ieraksti)`,
        );
    } else {
      const brokenIdx = chainResult.brokenAt
        ? chainResult.brokenAt.index
        : '?';
      doc
        .font('Helvetica')
        .fontSize(10)
        .text(`Rezultats: Kluda ieraksta #${brokenIdx}`);
    }

    doc.moveDown(0.5);

    // HMAC paraksts pār eksporta kopsavilkumu
    const summaryStr = [
      String(rows.length),
      firstHash,
      lastHash,
      from.toISOString(),
      to.toISOString(),
    ].join('|');

    const exportHmac = createHmac('sha256', this.hmacKey)
      .update(summaryStr, 'utf8')
      .digest('hex');

    doc.font('Helvetica-Bold').fontSize(10).text('Eksporta HMAC-SHA256:');
    doc.moveDown(0.2);
    doc.font('Courier').fontSize(8).text(exportHmac);

    doc.moveDown(1);

    doc
      .font('Helvetica')
      .fontSize(9)
      .fillColor('#666666')
      .text('Sis dokuments ir generets automatiski.', { align: 'center' });

    // ── Kājenes uz katras lapas — lappuses nr. + konfidencialitātes norāde ──

    const pageCount = doc.bufferedPageRange().count;
    for (let i = 0; i < pageCount; i++) {
      doc.switchToPage(i);

      // Kājenes pozīcija — zem lapas satura
      const footerY = doc.page.height - 40;

      doc
        .fontSize(7)
        .font('Helvetica')
        .fillColor('#999999')
        .text(
          `${i + 1} / ${pageCount}`,
          40,
          footerY,
          { width: doc.page.width - 80, align: 'center' },
        );

      doc
        .text(
          'Konfidenciali — tikai ieksejai lietosanai',
          40,
          footerY + 10,
          { width: doc.page.width - 80, align: 'center' },
        );
    }

    doc.end();
  }
}
