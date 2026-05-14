import { Logger } from '@nestjs/common';
import { emailLayout } from './templates/base.layout';
import {
  emailVerificationEmail,
  credentialResetEmail,
  accountApprovedEmail,
  accountRejectedEmail,
  broadcastEmail,
} from './templates';

const logger = new Logger('TemplateRenderer');

// Veidņu reģistrs — saista nosaukumu ar render funkciju
// Katra funkcija saņem data objektu un atgriež { subject, html }
const TEMPLATES: Record<
  string,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (data: any) => { subject: string; html: string }
> = {
  'email-verification': emailVerificationEmail,
  'credential-reset': credentialResetEmail,
  'account-approved': accountApprovedEmail,
  'account-rejected': accountRejectedEmail,
  broadcast: broadcastEmail,
};

/**
 * Renderē e-pasta veidni pēc nosaukuma.
 * Ja veidne nav atrasta — ģenerē vienkāršu teksta e-pastu ar brīdinājumu.
 */
export function renderTemplate(
  templateName: string,
  data: Record<string, unknown>,
): { subject: string; html: string } {
  const fn = TEMPLATES[templateName];

  if (!fn) {
    logger.warn(
      `Veidne "${templateName}" nav atrasta — izmanto fallback teksta veidni`,
    );
    return {
      subject: `Paziņojums`,
      html: emailLayout(`
        <h2 style="color: #1A365D;">Paziņojums</h2>
        <p>${typeof data.message === 'string' ? data.message : 'Jums ir jauns paziņojums no portāla.'}</p>
      `),
    };
  }

  return fn(data);
}
