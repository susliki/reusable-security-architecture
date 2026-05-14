import { Module } from '@nestjs/common';
import { PrismaModule } from '../prisma/prisma.module';
import { AuditService } from './audit.service';
import { AuditController } from './audit.controller';
import { AuditExportService } from './audit-export.service';
import { AuditPdfExportService } from './audit-pdf-export.service';
import { JobTokenGuard } from '../common/job-token.guard';

@Module({
  imports: [PrismaModule],
  controllers: [AuditController],
  providers: [AuditService, AuditExportService, AuditPdfExportService, JobTokenGuard],
  exports: [AuditService],
})
export class AuditModule {}
