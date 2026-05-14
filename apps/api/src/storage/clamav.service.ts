/*
ClamAV antivīrusa skenēšana augšupielādētiem failiem.
INSTREAM protokols caur TCP socketu — vairāku megabaitu failiem efektīvāks par CLAMSCAN procesu.
Kļūdu gadījumā fail-closed politika: ja skenēšana neizdodas, augšupielāde tiek noraidīta.
*/

import { Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import { Socket } from 'net';

/*
ClamAV INSTREAM protokols:
1. Sūtīt "zINSTREAM\0"
2. Katru chunk sūtīt kā [4-byte length BE][data]
3. Beigu signāls: [0x00 0x00 0x00 0x00]
4. Atbilde: "stream: OK\0" vai "stream: <vīruss> FOUND\0"
*/

const CLAMAV_TIMEOUT = 30_000; // 30s — maksimālais skenēšanas laiks
const CONNECT_TIMEOUT = 5_000; // 5s — TCP savienojuma taimauts

export type ScanResult = {
  clean: boolean;
  virus?: string;
};

@Injectable()
export class ClamavService implements OnModuleDestroy {
  private readonly logger = new Logger(ClamavService.name);
  private readonly host: string;
  private readonly port: number;

  constructor() {
    this.host = process.env.CLAMAV_HOST || 'localhost';
    this.port = parseInt(process.env.CLAMAV_PORT || '3310', 10);
    this.logger.log(`ClamAV konfigurēts: ${this.host}:${this.port}`);
  }

  onModuleDestroy() {
    // Nav pastāvīgu savienojumu — katrs skenējums ir atsevišķs TCP savienojums
  }

  /**
   * Skenēt buferi ar ClamAV INSTREAM protokolu.
   * Atgriež { clean: true } vai { clean: false, virus: 'vīrusa nosaukums' }.
   * Izmet kļūdu, ja ClamAV nav pieejams vai taimauts.
   */
  async scanBuffer(buffer: Buffer): Promise<ScanResult> {
    return new Promise((resolve, reject) => {
      const socket = new Socket();
      let response = '';
      let settled = false;

      const finish = (err?: Error) => {
        if (settled) return;
        settled = true;
        socket.destroy();
        if (err) return reject(err);
      };

      // Taimauts — 30s visam skenēšanas procesam
      socket.setTimeout(CLAMAV_TIMEOUT);

      socket.on('timeout', () => {
        finish(new Error(`ClamAV taimauts (${CLAMAV_TIMEOUT / 1000}s)`));
      });

      socket.on('error', (err) => {
        finish(new Error(`ClamAV savienojuma kļūda: ${err.message}`));
      });

      socket.on('data', (chunk) => {
        response += chunk.toString();
      });

      socket.on('end', () => {
        if (settled) return;
        settled = true;
        socket.destroy();

        const trimmed = response.replace(/\0/g, '').trim();

        // "stream: OK" — fails tīrs
        if (trimmed.endsWith('OK')) {
          return resolve({ clean: true });
        }

        // "stream: Eicar-Signature FOUND" — atrasts vīruss
        const match = trimmed.match(/stream:\s*(.+)\s+FOUND$/);
        if (match) {
          return resolve({ clean: false, virus: match[1].trim() });
        }

        // Neparedzēta atbilde
        reject(new Error(`ClamAV neparedzēta atbilde: ${trimmed}`));
      });

      // TCP savienojums ar atsevišķu taimautu
      socket.connect({ host: this.host, port: this.port }, () => {
        // INSTREAM komanda
        socket.write('zINSTREAM\0');

        // Sūtīt datus pa gabaliem (max 2MB chunks — clamd ierobežojums)
        const CHUNK_SIZE = 2 * 1024 * 1024;
        for (let offset = 0; offset < buffer.length; offset += CHUNK_SIZE) {
          const chunk = buffer.subarray(offset, offset + CHUNK_SIZE);
          const header = Buffer.alloc(4);
          header.writeUInt32BE(chunk.length, 0);
          socket.write(header);
          socket.write(chunk);
        }

        // Beigu signāls — 4 nulles baiti
        const end = Buffer.alloc(4);
        end.writeUInt32BE(0, 0);
        socket.write(end);
      });
    });
  }

  /**
   * Veselības pārbaude — PING/PONG komanda.
   * Atgriež true, ja ClamAV atbild ar "PONG".
   */
  async ping(): Promise<boolean> {
    return new Promise((resolve) => {
      const socket = new Socket();
      let response = '';

      socket.setTimeout(CONNECT_TIMEOUT);
      socket.on('timeout', () => { socket.destroy(); resolve(false); });
      socket.on('error', () => { socket.destroy(); resolve(false); });

      socket.on('data', (chunk) => {
        response += chunk.toString();
      });

      socket.on('end', () => {
        socket.destroy();
        resolve(response.replace(/\0/g, '').trim() === 'PONG');
      });

      socket.connect({ host: this.host, port: this.port }, () => {
        socket.write('zPING\0');
      });
    });
  }
}
