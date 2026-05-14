import { IsString, IsNotEmpty } from 'class-validator';

// GDPR Art. 7 — piekrišanas pieņemšanas DTO
export class ConsentAcceptDto {
  /** Privātuma politikas versija kurai piekrīt */
  @IsString()
  @IsNotEmpty()
  policyVersion!: string;
}
