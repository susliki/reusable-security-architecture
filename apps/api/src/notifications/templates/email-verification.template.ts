import { emailLayout } from './base.layout';

// E-pasta verifikācijas veidne — reģistrācijas magic link

type VerificationData = {
  name: string;
  verifyUrl: string;
  expiryHours: number;
};

export function emailVerificationEmail(
  data: VerificationData,
): { subject: string; html: string } {
  const subject = 'Apstipriniet savu e-pastu';
  const html = emailLayout(`
    <h2 style="color: #003D61;">Apstipriniet savu e-pastu</h2>
    <p>Labdien, ${data.name}!</p>
    <p>Paldies par reģistrēšanos portālā — drošās piekļuves portālā.</p>
    <p>Lūdzu apstipriniet savu e-pasta adresi, noklikšķinot uz zemāk esošās pogas:</p>
    <div style="text-align: center; margin: 24px 0;">
      <a href="${data.verifyUrl}" class="btn btn-primary" style="padding: 14px 32px; font-size: 14px; color: #ffffff !important; text-decoration: none;">
        Apstiprināt e-pastu →
      </a>
    </div>
    <div class="info-box">
      <strong>Saite ir derīga ${data.expiryHours} stundas.</strong><br/>
      Ja neesat pieprasījis šo reģistrāciju, droši ignorējiet šo e-pastu.
    </div>
  `);
  return { subject, html };
}
