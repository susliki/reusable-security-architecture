import { IsEmail, IsOptional, IsString } from 'class-validator';

export class PasskeyAuthOptionsDto {
  @IsEmail()
  @IsString()
  @IsOptional()
  email?: string;
}
