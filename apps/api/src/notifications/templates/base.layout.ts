// E-pasta veidņu bāzes izkārtojums — neitrāls HTML šablons
// Aizvieto ar savu zīmolu (krāsas, logo, organizācijas nosaukums) pirms produkcijas

export function emailLayout(content: string): string {
  return `<!DOCTYPE html>
<html lang="lv">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <style>
    body { margin: 0; padding: 0; background: #F5F5F5; font-family: -apple-system, 'Segoe UI', 'Helvetica Neue', sans-serif; }
    .email-wrap { max-width: 560px; margin: 24px auto; }
    .email-header { padding: 16px 24px; background: linear-gradient(135deg, #1A365D 0%, #2C5282 100%); border-radius: 8px 8px 0 0; }
    .email-logo { width: 32px; height: 32px; border-radius: 7px; background: rgba(255,255,255,0.2); display: inline-block; text-align: center; line-height: 32px; font-size: 12px; font-weight: 800; color: #fff; margin-right: 10px; vertical-align: middle; }
    .email-org { display: inline-block; vertical-align: middle; }
    .email-org-name { font-size: 13px; font-weight: 600; color: #fff; }
    .email-org-sub { font-size: 10px; color: rgba(255,255,255,0.6); }
    .email-body { padding: 24px 28px; background: #fff; }
    .email-footer { padding: 14px 28px; background: #F5F5F5; border-top: 1px solid rgba(0,0,0,0.05); font-size: 10px; color: #6B6B69; line-height: 1.6; border-radius: 0 0 8px 8px; }
    .email-footer a { color: #2C5282; }
    h2 { margin: 0 0 8px; font-size: 17px; font-family: Georgia, 'Times New Roman', serif; }
    p { margin: 0 0 16px; font-size: 13px; color: #0F1418; line-height: 1.6; }
    .info-box { padding: 14px 18px; border-radius: 8px; background: #F5F5F5; margin-bottom: 16px; }
    .btn { display: inline-block; padding: 10px 20px; border-radius: 7px; font-size: 13px; font-weight: 600; text-decoration: none; }
    .btn-primary { background: #1A365D; color: #fff; }
  </style>
</head>
<body>
  <div class="email-wrap">
    <div class="email-header">
      <span class="email-logo">APP</span>
      <span class="email-org">
        <span class="email-org-name">Drošās piekļuves portāls</span><br/>
        <span class="email-org-sub">Automātisks paziņojums</span>
      </span>
    </div>
    <div class="email-body">
      ${content}
    </div>
    <div class="email-footer">
      Šis ir automātiski ģenerēts e-pasts. Lūdzu, neatbildiet uz šo ziņu.<br/>
      Ja nevēlaties saņemt šādus paziņojumus, mainiet iestatījumus <a href="{{profileUrl}}">savā profilā</a>.
    </div>
  </div>
</body>
</html>`;
}
