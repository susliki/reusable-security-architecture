/*
Lietotāja paziņojumu serviss — sertifikāti, atgādinājumi, sistēmas brīdinājumi.
CRUD operācijas un masveida izveide pēc lomas (BLOCKED/DELETED tiek izslēgti).
Paziņojumi tiek glabāti Prisma datubāzē; piegāde caur in-app saraksta API.
*/

import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import type { Role } from '@prisma/client';

// Paziņojumu serviss — CRUD + masveida izveide pēc lomas
@Injectable()
export class NotificationService {
  constructor(private readonly prisma: PrismaService) {}

  async create(data: {
    userId: string;
    type: string;
    title: string;
    description: string;
    actionUrl?: string;
    actionLabel?: string;
  }) {
    return this.prisma.notification.create({ data });
  }

  // Izveido paziņojumu visiem lietotājiem ar norādīto lomu
  async createForRole(
    role: Role,
    data: {
      type: string;
      title: string;
      description: string;
      actionUrl?: string;
      actionLabel?: string;
    },
  ) {
    const users = await this.prisma.user.findMany({
      where: { role, status: { notIn: ['BLOCKED', 'DELETED'] } },
      select: { id: true },
    });

    if (users.length === 0) return;

    await this.prisma.notification.createMany({
      data: users.map((u) => ({ userId: u.id, ...data })),
    });
  }

  // Lietotāja paziņojumu saraksts ar filtriem
  async findForUser(
    userId: string,
    filters: { type?: string; read?: boolean },
    limit: number,
    offset: number,
  ) {
    const where: Record<string, unknown> = { userId };
    if (filters.type) where.type = filters.type;
    if (filters.read !== undefined) where.read = filters.read;

    const [items, total, unreadCount] = await Promise.all([
      this.prisma.notification.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        take: limit,
        skip: offset,
      }),
      this.prisma.notification.count({ where }),
      this.prisma.notification.count({ where: { userId, read: false } }),
    ]);

    return {
      items: items.map((n) => ({
        id: n.id,
        type: n.type,
        title: n.title,
        description: n.description,
        read: n.read,
        createdAt: n.createdAt.toISOString(),
        actionUrl: n.actionUrl,
        actionLabel: n.actionLabel,
      })),
      total,
      unreadCount,
    };
  }

  async markAsRead(id: string, userId: string) {
    await this.prisma.notification.updateMany({
      where: { id, userId },
      data: { read: true },
    });
  }

  async markAllAsRead(userId: string) {
    await this.prisma.notification.updateMany({
      where: { userId, read: false },
      data: { read: true },
    });
  }

  async deleteAll(userId: string) {
    await this.prisma.notification.deleteMany({ where: { userId } });
  }
}
