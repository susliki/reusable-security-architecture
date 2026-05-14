import { IsString, Length, Matches } from 'class-validator';

// TOTP iestatīšanas inicializācija — saņem setup tokenu no e-pasta verifikācijas
export class TotpSetupInitDto {
  @IsString()
  setupToken: string;
}

// TOTP iestatīšanas apstiprinājums — 6 ciparu kods + setup tokens
export class TotpSetupVerifyDto {
  @IsString()
  setupToken: string;

  @IsString()
  @Length(6, 6)
  @Matches(/^\d{6}$/)
  code: string;
}
