import { IsObject, IsString, IsOptional } from 'class-validator';

export class PasskeyAuthVerifyDto {
  @IsString()
  id: string;

  @IsString()
  rawId: string;

  @IsObject()
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle?: string;
  };

  @IsString()
  @IsOptional()
  authenticatorAttachment?: string;

  @IsObject()
  clientExtensionResults: Record<string, unknown>;

  @IsString()
  type: string;
}
