/*
Uzturēšanas režīma middleware — bloķē ne-admin pieprasījumus kad sistēma uzturēšanā.
Statusu kešo Redis 5 sekundes, lai nenoslogotu cache pie liela pieprasījumu apjoma.
Admin lietotāji un auth/csrf/maintenance ceļi paliek pieejami arī uzturēšanas laikā.
*/

import type { Request, Response, NextFunction } from 'express';
import type { RedisService } from '../redis/redis.service';

const MAINTENANCE_KEY = 'system:maintenance';
// Kešatmiņa — nenoslogo Redis ar katru pieprasījumu
const CACHE_TTL_MS = 5_000;

interface MaintenancePayload {
  enabled: boolean;
  message: string | null;
  estimatedEnd: string | null;
}

let cachedData: MaintenancePayload | null = null;
let cachedAt = 0;

export function createMaintenanceMiddleware(redis: RedisService) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const now = Date.now();

      // Kešatmiņas atjaunināšana — ne biežāk kā reizi 5 sekundēs
      if (!cachedData || now - cachedAt > CACHE_TTL_MS) {
        const raw = await redis.getJson<MaintenancePayload>(MAINTENANCE_KEY);
        cachedData = raw ?? { enabled: false, message: null, estimatedEnd: null };
        cachedAt = now;
      }

      if (!cachedData.enabled) return next();

      // Admin lietotāji apiet uzturēšanas režīmu
      const session = (req as any).session;
      if (session?.isAdmin) return next();

      // Atļautie ceļi — maintenance statuss, auth un admin endpoints
      const path = req.originalUrl || req.url;
      if (
        path === '/api/maintenance' ||
        path.startsWith('/api/auth') ||
        path.startsWith('/api/admin') ||
        path.startsWith('/api/csrf-token')
      ) {
        return next();
      }

      // 503 — sistēma uzturēšanā
      res.status(503).json({
        maintenance: true,
        message: cachedData.message,
        estimatedEnd: cachedData.estimatedEnd,
      });
    } catch {
      // Kļūdas gadījumā nepārtaucam pieprasījumu — drošāk laist cauri
      next();
    }
  };
}
