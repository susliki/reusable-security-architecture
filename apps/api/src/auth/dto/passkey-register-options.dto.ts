import { IsEmail, IsString } from 'class-validator';

export class PasskeyRegisterOptionsDto {
  @IsEmail()
  @IsString()
  email: string;
}
