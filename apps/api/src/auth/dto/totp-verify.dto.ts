import { IsEmail, IsOptional, IsString, Length, Matches } from 'class-validator';

export class TotpVerifyDto {
  @IsString()
  @Length(6, 6)
  @Matches(/^\d{6}$/)
  code: string;

  @IsEmail()
  @IsOptional()
  email?: string;
}
