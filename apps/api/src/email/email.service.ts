/*
E-pasta sūtīšana caur Microsoft Graph API (NEVIS Nodemailer/SMTP) — koplietota pastkaste.
OAuth2 client credentials plūsma, marķiera kešošana ar atjaunošanu pirms termiņa beigām.
Izmanto reģistrācijas magic-link, paziņojumu un audita ziņojumu sūtīšanai.
NB: Azure AD app reģistrācijai nepieciešama Mail.Send application atļauja.
*/

import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type {
  SendMailOptions,
  GraphTokenResponse,
  GraphErrorResponse,
} from './email.types';

@Injectable()
export class EmailService implements OnModuleInit {
  private readonly logger = new Logger(EmailService.name);

  private readonly tenantId: string;
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly fromAddress: string;
  private readonly saveToSent: boolean;

  // Kešots piekļuves tokens — atjaunojas pirms derīguma termiņa beigām
  private accessToken: string | null = null;
  private tokenExpiresAt = 0;

  constructor(private readonly config: ConfigService) {
    this.tenantId = this.config.get<string>('GRAPH_TENANT_ID', '');
    this.clientId = this.config.get<string>('GRAPH_CLIENT_ID', '');
    this.clientSecret = this.config.get<string>('GRAPH_CLIENT_SECRET', '');
    this.fromAddress = this.config.get<string>(
      'GRAPH_MAIL_FROM',
      'noreply@lja.lv',
    );
    this.saveToSent = this.config.get<string>('GRAPH_MAIL_SAVE_TO_SENT', 'false') === 'true';
  }

  onModuleInit() {
    if (!this.tenantId || !this.clientId || !this.clientSecret) {
      this.logger.warn(
        'GRAPH_TENANT_ID, GRAPH_CLIENT_ID vai GRAPH_CLIENT_SECRET nav iestatīts — e-pastu sūtīšana nebūs pieejama',
      );
    } else {
      this.logger.log(
        `Graph Mail konfigurēts: ${this.fromAddress} (tenant: ${this.tenantId.slice(0, 8)}…)`,
      );
    }
  }

  /** Vai serviss ir konfigurēts un gatavs sūtīt */
  isConfigured(): boolean {
    return !!(this.tenantId && this.clientId && this.clientSecret);
  }

  /** Sūta e-pastu caur Microsoft Graph API */
  async send(opts: SendMailOptions): Promise<void> {
    if (!this.isConfigured()) {
      throw new Error('Graph Mail nav konfigurēts — trūkst GRAPH_* env mainīgo');
    }

    const token = await this.getAccessToken();
    const toArr = Array.isArray(opts.to) ? opts.to : [opts.to];

    // Graph API sendMail pieprasījuma struktūra
    const body = {
      message: {
        subject: opts.subject,
        body: { contentType: 'HTML', content: opts.html },
        toRecipients: toArr.map((addr) => ({
          emailAddress: { address: addr },
        })),
        ...(opts.cc?.length && {
          ccRecipients: opts.cc.map((addr) => ({
            emailAddress: { address: addr },
          })),
        }),
        ...(opts.bcc?.length && {
          bccRecipients: opts.bcc.map((addr) => ({
            emailAddress: { address: addr },
          })),
        }),
      },
      saveToSentItems: this.saveToSent,
    };

    const url = `https://graph.microsoft.com/v1.0/users/${encodeURIComponent(this.fromAddress)}/sendMail`;
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });

    // Graph sendMail atgriež 202 Accepted bez ķermeņa
    if (!res.ok) {
      const err = (await res.json().catch(() => null)) as GraphErrorResponse | null;
      const code = err?.error?.code ?? 'unknown';
      const msg = err?.error?.message ?? res.statusText;
      this.logger.error(
        `Graph sendMail neizdevās: ${res.status} ${code} — ${msg} | to=${toArr.join(',')}`,
      );
      throw new Error(`Graph sendMail: ${res.status} ${code} — ${msg}`);
    }

    this.logger.log(`E-pasts nosūtīts: ${toArr.join(', ')} | Tēma: "${opts.subject}"`);
  }

  // Autentificē ar Azure AD client credentials flow un kešo tokenu
  private async getAccessToken(): Promise<string> {
    // Atjaunojam 60s pirms derīguma termiņa beigām
    if (this.accessToken && Date.now() < this.tokenExpiresAt - 60_000) {
      return this.accessToken;
    }

    const url = `https://login.microsoftonline.com/${this.tenantId}/oauth2/v2.0/token`;
    const params = new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: this.clientId,
      client_secret: this.clientSecret,
      scope: 'https://graph.microsoft.com/.default',
    });

    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    });

    if (!res.ok) {
      const text = await res.text().catch(() => '');
      this.logger.error(`Graph token pieprasījums neizdevās: ${res.status} — ${text}`);
      throw new Error(`Graph token: ${res.status} ${res.statusText}`);
    }

    const data = (await res.json()) as GraphTokenResponse;
    this.accessToken = data.access_token;
    this.tokenExpiresAt = Date.now() + data.expires_in * 1000;

    this.logger.debug(
      `Graph token iegūts, derīgs ${data.expires_in}s`,
    );

    return this.accessToken;
  }
}
