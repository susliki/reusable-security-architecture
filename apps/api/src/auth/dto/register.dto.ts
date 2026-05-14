import {
  IsEmail,
  IsOptional,
  IsString,
  Length,
  Matches,
  MinLength,
} from 'class-validator';

// Reģistrācijas DTO — ārējie lietotāji (jūrnieki, partneri, uzņēmumi)
export class RegisterDto {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(2)
  firstName: string;

  @IsString()
  @MinLength(2)
  lastName: string;

  @IsString()
  @Length(2, 3)
  citizenship: string;

  // Latvijas personas kods — tikai LV pilsoņiem
  @IsOptional()
  @IsString()
  @Matches(/^\d{6}-\d{5}$/, {
    message: 'Personas kods jābūt formātā 123456-12345',
  })
  personalCode?: string;

  @IsOptional()
  @IsString()
  phone?: string;
}
