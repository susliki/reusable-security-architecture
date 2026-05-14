/*
Admin e-pasta testa kontrolieris — pārbauda Microsoft Graph savienojumu un autentifikāciju.
Pieejams tikai admin lomai — nosūta testa ziņojumu uz norādīto adresi caur EmailService.
*/

import {
  Body,
  Controller,
  Post,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { AdminGuard } from '../common/admin.guard';
import { AuthGuard } from '../common/auth.guard';
import { EmailService } from './email.service';
import { emailLayout } from '../notifications/templates/base.layout';

// Admin e-pasta testa endpoint — pārbauda Graph savienojumu
@Controller('admin/email')
@UseGuards(AuthGuard, AdminGuard)
export class EmailController {
  constructor(private readonly emailService: EmailService) {}

  @Post('test')
  @HttpCode(HttpStatus.OK)
  async sendTest(@Body() body: { to: string }) {
    if (!body.to) {
      return { success: false, error: 'Trūkst "to" lauks' };
    }

    const html = emailLayout(`
      <h2 style="color: #003D61;">Testa e-pasts</h2>
      <p>Šis ir testa e-pasts no portāla.</p>
      <p>Ja saņēmāt šo e-pastu, Microsoft Graph e-pasta integrācija darbojas pareizi.</p>
      <div class="info-box">
        <table class="data-table">
          <tr><td>Sistēma</td><td>Drošās piekļuves portāls</td></tr>
          <tr><td>Nosūtīts</td><td>${new Date().toLocaleString('lv-LV', { timeZone: 'Europe/Riga' })}</td></tr>
          <tr><td>Metode</td><td>Microsoft Graph API</td></tr>
        </table>
      </div>
    `);

    await this.emailService.send({
      to: body.to,
      subject: 'Testa e-pasts',
      html,
    });

    return { success: true };
  }
}
