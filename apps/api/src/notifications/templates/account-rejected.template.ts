import { emailLayout } from './base.layout';

// Konta noraidījuma veidne — pēc profila pārbaudes

type AccountRejectedData = {
  name: string;
  reason: string;
  portalUrl: string;
};

export function accountRejectedEmail(
  data: AccountRejectedData,
): { subject: string; html: string } {
  const subject = 'Profils noraidīts';
  const html = emailLayout(`
    <h2 style="color: #1A365D;">Profils noraidīts</h2>
    <p>Labdien, ${data.name}!</p>
    <p>Diemžēl jūsu profila pieteikums tika noraidīts.</p>
    <div class="info-box">
      <strong>Iemesls:</strong> ${data.reason}
    </div>
    <p>Lūdzu, labojiet datus un iesniedziet profilu atkārtoti.</p>
    <div style="text-align: center; margin: 24px 0;">
      <a href="${data.portalUrl}/profile" class="btn btn-primary" style="padding: 14px 32px; font-size: 14px; color: #ffffff !important; text-decoration: none;">
        Labot profilu →
      </a>
    </div>
  `);
  return { subject, html };
}
