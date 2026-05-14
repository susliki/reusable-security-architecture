/*
Drošības notikumu skatījums — filtrē audita žurnālu uz auth.*, admin.*, noraidījumiem un likmes ierobežošanas trāpījumiem.
Klasificē smagumu (critical/warning/info) pēc darbības un rezultāta — patērē admin SOC dashboard.
*/

import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { AdminGuard } from '../common/admin.guard';
import { AuthGuard } from '../common/auth.guard';
import { PrismaService } from '../prisma/prisma.service';

// Drošības notikumu smaguma klasifikācija
type Severity = 'critical' | 'warning' | 'info';

// Darbības, kas uzskatāmas par kritiskām
const CRITICAL_ACTIONS = [
  'admin.session.revoke',
  'admin.lockdown',
  'admin.user.block',
];

// Laika diapazonu mapping uz milisekundēm
const TIME_RANGE_MS: Record<string, number> = {
  '1h': 60 * 60 * 1000,
  '6h': 6 * 60 * 60 * 1000,
  '24h': 24 * 60 * 60 * 1000,
  '7d': 7 * 24 * 60 * 60 * 1000,
};

// Klasificē notikuma smagumu pēc darbības un rezultāta
function classifySeverity(action: string, result: string, dataJson: any): Severity {
  if (CRITICAL_ACTIONS.some((a) => action.startsWith(a))) return 'critical';

  // Rate limit — status 429 dataJson
  if (dataJson && typeof dataJson === 'object' && (dataJson as any).status === 429) {
    return 'warning';
  }

  if (action.startsWith('auth.') && result === 'Denied') return 'warning';
  if (result === 'Denied' || result === 'Error') return 'warning';
  if (action.startsWith('auth.') && result === 'Success') return 'info';

  return 'info';
}

@Controller('admin')
@UseGuards(AuthGuard, AdminGuard)
export class SecurityEventsController {
  constructor(private readonly prisma: PrismaService) {}

  // ── Drošības notikumu saraksts ar filtrēšanu ──

  @Get('security-events')
  async listSecurityEvents(
    @Query('severity') severity?: string,
    @Query('timeRange') timeRange?: string,
    @Query('search') search?: string,
  ) {
    const rangeMs = TIME_RANGE_MS[timeRange ?? '24h'] ?? TIME_RANGE_MS['24h'];
    const since = new Date(Date.now() - rangeMs);

    // Drošības notikumu filtrs — auth.*, admin.*, noraidītie, kļūdas, rate limit
    const rows = await this.prisma.$queryRaw<
      {
        id: number;
        ts: Date;
        subjectId: string | null;
        subjectRole: string | null;
        action: string;
        result: string;
        clientIp: string | null;
        userAgent: string | null;
        dataJson: any;
        entityType: string | null;
        entityId: string | null;
      }[]
    >`
      SELECT id, ts, "subjectId", "subjectRole", action, result,
             "clientIp", "userAgent", "dataJson", "entityType", "entityId"
      FROM "AuditLog"
      WHERE ts >= ${since}
        AND (
          action LIKE 'auth.%'
          OR action LIKE 'admin.%'
          OR result IN ('Denied', 'Error')
          OR ("dataJson"->>'status')::int = 429
        )
      ORDER BY ts DESC
      LIMIT 200
    `;

    // Klasificējam un filtrējam
    let events = rows.map((row) => {
      const sev = classifySeverity(row.action, row.result, row.dataJson);
      const dj = row.dataJson && typeof row.dataJson === 'object' ? row.dataJson as any : null;
      const displayName = dj?.firstName
        ? [dj.firstName, dj.lastName].filter(Boolean).join(' ')
        : null;

      return {
        id: row.id,
        timestamp: row.ts,
        severity: sev,
        action: row.action,
        result: row.result,
        displayName,
        ip: row.clientIp,
        userAgent: row.userAgent,
        details: row.dataJson,
      };
    });

    // Filtrs pēc smaguma
    if (severity && ['critical', 'warning', 'info'].includes(severity)) {
      events = events.filter((e) => e.severity === severity);
    }

    // Meklēšana pēc darbības, IP vai lietotāja ID
    if (search) {
      const q = search.toLowerCase();
      events = events.filter(
        (e) =>
          e.action.toLowerCase().includes(q) ||
          (e.ip && e.ip.toLowerCase().includes(q)) ||
          (e.displayName && e.displayName.toLowerCase().includes(q)),
      );
    }

    return events;
  }

  // ── Drošības notikumu statistika pa smaguma līmeņiem ──

  @Get('security-events/stats')
  async securityEventStats(@Query('timeRange') timeRange?: string) {
    const rangeMs = TIME_RANGE_MS[timeRange ?? '24h'] ?? TIME_RANGE_MS['24h'];
    const since = new Date(Date.now() - rangeMs);

    const rows = await this.prisma.$queryRaw<
      { action: string; result: string; dataJson: any }[]
    >`
      SELECT action, result, "dataJson"
      FROM "AuditLog"
      WHERE ts >= ${since}
        AND (
          action LIKE 'auth.%'
          OR action LIKE 'admin.%'
          OR result IN ('Denied', 'Error')
          OR ("dataJson"->>'status')::int = 429
        )
    `;

    let critical = 0;
    let warning = 0;
    let info = 0;

    for (const row of rows) {
      const sev = classifySeverity(row.action, row.result, row.dataJson);
      if (sev === 'critical') critical++;
      else if (sev === 'warning') warning++;
      else info++;
    }

    return { critical, warning, info };
  }
}
