import { emailLayout } from './base.layout';

// Piekļuves atiestatīšanas e-pasta veidne — admin izsūta magic link
// Lietotājs saņem saiti TOTP pārkonfigurēšanai

type ResetData = {
  name: string;
  verifyUrl: string;
  expiryHours: number;
};

export function credentialResetEmail(
  data: ResetData,
): { subject: string; html: string } {
  const subject = 'Piekļuves atiestatīšana';
  const html = emailLayout(`
    <h2 style="color: #003D61;">Piekļuves atiestatīšana</h2>
    <p>Labdien, ${data.name}!</p>
    <p>Sistēmas administrators ir atiestatījis jūsu piekļuves datus portālā.
    Lai turpinātu sistēmas lietošanu, jums ir jāiestata jauna autentifikācijas metode.</p>
    <p>Noklikšķiniet uz zemāk esošās pogas, lai iestatītu jaunu piekļuvi:</p>
    <div style="text-align: center; margin: 24px 0;">
      <a href="${data.verifyUrl}" class="btn btn-primary" style="padding: 14px 32px; font-size: 14px; color: #ffffff !important; text-decoration: none;">
        Iestatīt piekļuvi →
      </a>
    </div>
    <div class="info-box">
      <strong>Saite ir derīga ${data.expiryHours} stundas.</strong><br/>
      Ja jums nav zināms par šo darbību, sazinieties ar administrāciju.
    </div>
  `);
  return { subject, html };
}
