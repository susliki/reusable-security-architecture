import { IsEmail } from 'class-validator';

// E-pasta pārbaude pirms autentifikācijas — nosaka pieejamās metodes
export class CheckEmailDto {
  @IsEmail()
  email: string;
}
