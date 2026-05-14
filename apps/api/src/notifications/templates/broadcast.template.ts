import { emailLayout } from './base.layout';

// Informatīvas ziņas veidne — admin masveida sūtījumiem

type BroadcastData = {
  title: string;
  body: string;
  portalUrl?: string;
};

export function broadcastEmail(
  data: BroadcastData,
): { subject: string; html: string } {
  const subject = data.title;
  const portalLink = data.portalUrl
    ? `<div style="text-align: center; margin: 24px 0;">
         <a href="${data.portalUrl}" class="btn btn-primary" style="padding: 14px 32px; font-size: 14px; color: #ffffff !important; text-decoration: none;">
           Atvērt portālu →
         </a>
       </div>`
    : '';
  const html = emailLayout(`
    <h2 style="color: #1A365D;">${data.title}</h2>
    <div>${data.body}</div>
    ${portalLink}
  `);
  return { subject, html };
}
