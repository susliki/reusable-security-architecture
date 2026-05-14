/** E-pasta darba dati */
export interface EmailJobData {
  to: string | string[];
  subject: string;
  /** Veidnes nosaukums (no notifications/templates/) */
  template?: string;
  /** Veidnes mainīgie */
  data?: Record<string, unknown>;
  /** Tiešais HTML — ja template nav norādīts */
  html?: string;
  /** Kopijas adresāti */
  cc?: string[];
}

/** SMS darba dati */
export interface SmsJobData {
  phone: string;
  message: string;
}
