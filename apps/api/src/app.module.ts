import { MiddlewareConsumer, Module, NestModule, type Provider } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { ConfigModule } from '@nestjs/config';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { PrismaModule } from './prisma/prisma.module';
import { RedisModule } from './redis/redis.module';
import { StorageModule } from './storage/storage.module';
import { AuditModule } from './audit/audit.module';
import { AuthModule } from './auth/auth.module';
import { QueueModule } from './queue/queue.module';
import { BullBoardAdminModule } from './queue/bull-board.module';
import { DevModule } from './dev/dev.module';
import { AdminModule } from './admin/admin.module';
import { UserSecurityModule } from './user-security/user-security.module';
import { EmailModule } from './email/email.module';
import { VerificationModule } from './verification/verification.module';
import { GdprModule } from './gdpr/gdpr.module';
import { NotificationModule } from './notification/notification.module';
import { ProfileModule } from './profile/profile.module';
import { ConsentMiddleware } from './gdpr/consent.middleware';
import { RequestContextMiddleware } from './common/request-context.middleware';
import { StatusGuard } from './common/status.guard';

// Shell env pārraksta .env; restartē procesu pēc DEV_ENDPOINTS maiņas.
const devEnabled = process.env.DEV_ENDPOINTS === '1';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, envFilePath: '.env' }), // ielādē .env
    PrismaModule,
    RedisModule,
    StorageModule,
    AuthModule,
    AuditModule,
    QueueModule,
    BullBoardAdminModule,
    EmailModule,
    AdminModule,
    UserSecurityModule,
    VerificationModule,
    GdprModule,
    NotificationModule,
    ProfileModule,
    ...(devEnabled ? [DevModule] : []),
  ],
  controllers: [AppController],
  providers: [
    AppService,
    // OWASP ASVS v5 §8.1.1 — UNVERIFIED lietotāji nevar piekļūt biznesa endpoint
    { provide: APP_GUARD, useClass: StatusGuard } satisfies Provider,
  ],
})
export class AppModule implements NestModule {
  // GDPR Art. 7 — piekrišanas pārbaude uz visiem API ceļiem
  configure(consumer: MiddlewareConsumer) {
    // RequestContext pirms visa — saglabā userId AsyncLocalStorage, lai Prisma var aizpildīt createdBy/updatedBy
    consumer.apply(RequestContextMiddleware).forRoutes('*');
    consumer.apply(ConsentMiddleware).forRoutes('*');
  }
}
