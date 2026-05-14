/*
Pieprasījumu žurnāla middleware — strukturēts JSON ieraksts katra atbildei.
Reģistrē rid, metodi, ceļu, statusu un ilgumu ms — pamats novērošanai un debugošanai.
*/

import type { Request, Response, NextFunction } from 'express';

export function requestLoggerMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const start = Date.now();

  res.on('finish', () => {
    const ms = Date.now() - start;
    const rid = (req as any).requestId;

    // Vienkāršs JSON rindas žurnāls
    console.log(
      JSON.stringify({
        ts: new Date().toISOString(),
        rid,
        method: req.method,
        path: req.originalUrl,
        status: res.statusCode,
        ms,
      }),
    );
  });

  next();
}
