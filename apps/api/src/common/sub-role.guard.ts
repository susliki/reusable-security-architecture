/*
Apakšlomu guard — pārbauda entraRole vērtības papildus DB lomai.
Ļauj precīzāk ierobežot piekļuvi pēc Entra grupas — RequireSubRole dekorators.
Lieto kopā ar AuthGuard ķēdi — paredzēts, ka sesija jau ir validēta.
*/

import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  SetMetadata,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';
import type { AuthSession } from './session.types';
import { PrismaService } from '../prisma/prisma.service';

// Guard konfigurācija — entraRole pārbaude
export interface SubRoleCheck {
  entraRole?: string | string[];
}

export const SUB_ROLE_KEY = 'subRole';

// Dekorators SubRoleGuard lietošanai
export const RequireSubRole = (check: SubRoleCheck) =>
  SetMetadata(SUB_ROLE_KEY, check);

@Injectable()
export class SubRoleGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly prisma: PrismaService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const check = this.reflector.getAllAndOverride<SubRoleCheck>(SUB_ROLE_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!check) return true; // Nav definēta apakšlomu pārbaude

    const req = context.switchToHttp().getRequest<Request>();
    const session = req.session as AuthSession;
    if (!session?.userId) return true; // AuthGuard atbildēs

    const user = await this.prisma.user.findUnique({
      where: { id: session.userId },
      select: { entraRole: true },
    });

    if (!user) {
      throw new ForbiddenException({ code: 'user_not_found' });
    }

    // Pārbaudīt entraRole
    if (check.entraRole) {
      const allowed = Array.isArray(check.entraRole)
        ? check.entraRole
        : [check.entraRole];
      if (!user.entraRole || !allowed.includes(user.entraRole)) {
        throw new ForbiddenException({
          code: 'insufficient_sub_role',
          message: 'Nav pietiekamas tiesības šai darbībai',
        });
      }
    }

    return true;
  }
}
