/*
Dev-only kontrolieris — testēšanas palīgi, pieejami tikai NODE_ENV=development režīmā.
DevOnlyGuard bloķē šos maršrutus produkcijā — ļauj ātri iegūt admin sesiju lokālai izstrādei.
*/

import { Controller, Post, Req, UseGuards } from '@nestjs/common';
import type { Request } from 'express';
import { DevOnlyGuard } from '../common/dev-only.guard';
import type { AuthSession } from '../common/session.types';

@UseGuards(DevOnlyGuard)
@Controller('dev')
export class DevController {
  @Post('become-admin')
  becomeAdmin(@Req() req: Request) {
    if (!req.session) {
      return { ok: false, error: 'no_session' };
    }

    const session = req.session as AuthSession;
    session.isAdmin = true;
    session.userId = session.userId ?? '00000000-0000-0000-0000-000000000001';
    session.userRole = 'ADMIN';
    return { ok: true, isAdmin: true };
  }
}
