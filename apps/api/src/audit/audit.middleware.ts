/*
Automātiskais HTTP pieprasījumu audita middleware — fiksē katru /api/* atbildi pēc res.finish.
Izlaiž paša audita lasīšanas ceļus (rekursijas novēršana) un /api/auth/status status pollus (lieka trokšņa filtrs).
Audita rakstīšanas kļūdas nekad nepārrauj pieprasījumu plūsmu.
*/

import type { Request, Response, NextFunction } from 'express';
import { AuditService } from './audit.service';

function pickResult(status: number): 'Success' | 'Denied' | 'Error' {
  if (status >= 200 && status < 400) return 'Success';
  if (status === 401 || status === 403) return 'Denied';
  return 'Error';
}

function parseSkipPaths(): Set<string> {
  const raw = process.env.AUDIT_AUTO_SKIP_PATHS ?? '';
  return new Set(
    raw
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
  );
}

export function auditMiddleware(audit: AuditService) {
  const apiPrefix = '/api';
  const skipPaths = parseSkipPaths();

  return (req: Request, res: Response, next: NextFunction) => {
    res.on('finish', () => {
      try {
        const path = req.path || ''; // no query string
        if (!path.startsWith(apiPrefix)) return;

        if (skipPaths.has(path)) return;

        // Audita lasīšanas ceļus izlaižam — izvairāmies no rekursijas
        if (path.startsWith('/api/admin/audit')) return;

        // Auth status poll — frontend izsauc katrā lapā, rada lieku troksni
        if (path === '/api/auth/status') return;

        const rid = (req as any).requestId as string | undefined;

        // Sesijas dati — identificē lietotāju, kas veica darbību
        const session = (req as any).session;
        const subjectId = session?.userId ?? null;
        const subjectRole = session?.userRole ?? null;

        void audit
          .write({
            rid: rid ?? null,
            subjectId,
            subjectRole,
            action: 'http.request',
            result: pickResult(res.statusCode),
            // req.ip respektē Express trust proxy — drošāk nekā raw X-Forwarded-For
            clientIp: req.ip || null,
            userAgent: req.header('user-agent') ?? null,
            dataJson: {
              method: req.method,
              path,
              status: res.statusCode,
            },
          })
          .catch(() => {
            // Nekad nepārraut pieprasījumu plūsmu audita kļūdas dēļ
          });
      } catch {
        // Nekad nepārraut pieprasījumu plūsmu audita kļūdas dēļ
      }
    });

    next();
  };
}
