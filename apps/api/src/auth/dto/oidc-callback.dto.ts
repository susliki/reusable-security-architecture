import { IsOptional, IsString } from 'class-validator';

export class OidcCallbackDto {
  @IsString()
  code: string;

  @IsString()
  state: string;

  @IsOptional()
  @IsString()
  session_state?: string;
}
