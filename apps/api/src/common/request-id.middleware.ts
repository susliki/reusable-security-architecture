/*
Pieprasījuma korelācijas ID — ģenerē rid katram pieprasījumam vai pārņem ienākošo.
Kalpo audita žurnāla, kļūdu izsekošanas un loga sasaistīšanai starp servisiem.
Atgriež X-Request-Id galvenē, lai klients var to ietvert kļūdu ziņojumos.
*/

import type { Request, Response, NextFunction } from 'express';
import { randomUUID } from 'crypto';

export function requestIdMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const incoming = req.header('x-request-id');
  const id =
    incoming && incoming.trim().length > 0 ? incoming.trim() : randomUUID();

  // Pievieno pieprasījumam vēlākai izmantošanai
  (req as any).requestId = id;

  // Atgriež klientam
  res.setHeader('X-Request-Id', id);

  next();
}
