import {
  IsIn,
  IsInt,
  IsISO8601,
  IsOptional,
  IsString,
  Max,
  Min,
} from 'class-validator';
import { Type } from 'class-transformer';

export class AuditExportQueryDto {
  @IsOptional()
  @IsISO8601()
  from?: string; // ieskaitot

  @IsOptional()
  @IsISO8601()
  to?: string; // neieskaitot

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(1_000_000)
  limit?: number;
}

export class AuditExportRunQueryDto {
  @IsIn(['daily', 'weekly', 'monthly'])
  period!: 'daily' | 'weekly' | 'monthly';

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(1_000_000)
  limit?: number;
}
