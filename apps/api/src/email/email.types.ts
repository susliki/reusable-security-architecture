/** Microsoft Graph e-pasta sūtīšanas opcijas */
export interface SendMailOptions {
  to: string | string[];
  subject: string;
  html: string;
  cc?: string[];
  bcc?: string[];
}

/** Graph API tokena atbilde */
export interface GraphTokenResponse {
  access_token: string;
  expires_in: number;
  token_type: string;
}

/** Graph API kļūdas atbilde */
export interface GraphErrorResponse {
  error: {
    code: string;
    message: string;
  };
}
