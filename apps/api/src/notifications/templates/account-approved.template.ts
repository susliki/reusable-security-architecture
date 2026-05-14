import { emailLayout } from './base.layout';

// Konta apstiprinājuma veidne — pēc profila pārbaudes

type AccountApprovedData = {
  name: string;
  portalUrl: string;
};

export function accountApprovedEmail(
  data: AccountApprovedData,
): { subject: string; html: string } {
  const subject = 'Konts apstiprināts';
  const html = emailLayout(`
    <h2 style="color: #1A365D;">Konts apstiprināts</h2>
    <p>Labdien, ${data.name}!</p>
    <p>Jūsu profils ir veiksmīgi pārbaudīts un apstiprināts. Tagad jūs varat pilnībā izmantot portālu.</p>
    <div style="text-align: center; margin: 24px 0;">
      <a href="${data.portalUrl}" class="btn btn-primary" style="padding: 14px 32px; font-size: 14px; color: #ffffff !important; text-decoration: none;">
        Atvērt portālu →
      </a>
    </div>
  `);
  return { subject, html };
}
