/*
Piekrišanas middleware — bloķē API piekļuvi kamēr lietotājs nav pieņēmis pašreizējo politikas versiju.
GDPR Art. 7 — piekrišanai jābūt aktuālai pirms personas datu apstrādes.
Izņēmumi: /api/auth, /api/public, /api/me/consent, /api/dev — lai nesalauztu pieteikšanos un pašu piekrišanas plūsmu.
*/

import { Injectable, NestMiddleware } from '@nestjs/common';
import type { Request, Response, NextFunction } from 'express';
import type { AuthSession } from '../common/session.types';
import { ConsentService } from './consent.service';

// GDPR Art. 7 — bloķē API piekļuvi ja piekrišana nav aktuāla
// Izņēmumi: auth/*, public/*, me/consent, dev/*
@Injectable()
export class ConsentMiddleware implements NestMiddleware {
  // Ceļi kur piekrišana NAV nepieciešama
  private readonly skipPaths = [
    '/api/auth/',
    '/api/public/',
    '/api/me/consent',
    '/api/dev/',
    '/api/csrf-token',
    '/api/health',
  ];

  constructor(private readonly consent: ConsentService) {}

  async use(req: Request, res: Response, next: NextFunction) {
    const path = req.originalUrl ?? req.url;

    // Izlaist neaizsargātos ceļus
    if (this.skipPaths.some((p) => path.startsWith(p))) {
      return next();
    }

    const session = req.session as AuthSession;
    const userId = session?.userId;

    // Nav autentificēts — middleware neattiecas
    if (!userId) {
      return next();
    }

    const hasConsent = await this.consent.hasCurrentConsent(userId);
    if (!hasConsent) {
      return res.status(403).json({
        code: 'consent_required',
        message: 'Nepieciešams pieņemt atjaunināto privātuma politiku',
        currentPolicyVersion: this.consent.getCurrentPolicyVersion(),
      });
    }

    next();
  }
}
