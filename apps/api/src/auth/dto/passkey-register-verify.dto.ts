import { IsObject, IsString, IsOptional } from 'class-validator';

export class PasskeyRegisterVerifyDto {
  @IsString()
  id: string;

  @IsString()
  rawId: string;

  @IsObject()
  response: {
    clientDataJSON: string;
    attestationObject: string;
    transports?: string[];
    publicKeyAlgorithm?: number;
    publicKey?: string;
    authenticatorData?: string;
  };

  @IsString()
  @IsOptional()
  authenticatorAttachment?: string;

  @IsObject()
  clientExtensionResults: Record<string, unknown>;

  @IsString()
  type: string;
}
