/*
Pieprasījuma konteksta middleware — saglabā userId AsyncLocalStorage glabātavā.
Ļauj Prisma extension automātiski aizpildīt createdBy/updatedBy laukus auditam.
Konteksts dzīvo tikai pieprasījuma cikla laikā — drošs no izsaukumu krustošanās.
*/

import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { requestContextStore } from './request-context';
import type { AuthSession } from './session.types';

@Injectable()
export class RequestContextMiddleware implements NestMiddleware {
  use(req: Request, _res: Response, next: NextFunction): void {
    const session = req.session as AuthSession;
    const userId = session?.userId ?? undefined;
    requestContextStore.run({ userId }, () => next());
  }
}
