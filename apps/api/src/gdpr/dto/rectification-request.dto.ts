import { IsString, IsNotEmpty, IsOptional, MaxLength } from 'class-validator';

// GDPR Art. 16 — datu labošanas pieprasījuma DTO
export class RectificationRequestDto {
  /** Lauks kuru vēlas labot (piem. "firstName", "lastName", "email") */
  @IsString()
  @IsNotEmpty()
  field!: string;

  /** Pašreizējā vērtība — lai admins saprot kontekstu */
  @IsString()
  @IsNotEmpty()
  currentValue!: string;

  /** Pieprasītā jaunā vērtība */
  @IsString()
  @IsNotEmpty()
  requestedValue!: string;

  /** Papildu pamatojums (nav obligāts) */
  @IsOptional()
  @IsString()
  @MaxLength(500)
  reason?: string;
}
