/*
NestJS skeleta noklusējuma serviss — paliek no scaffolding, faktiski netiek lietots produkcijā.
*/

import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  getHello(): string {
    return 'Hello World!';
  }
}
