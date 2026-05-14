import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { WorkerModule } from './worker.module';

/*
Worker process — atsevišķs NestJS konteiners tikai rindu apstrādei.
Nav HTTP servera — tikai BullMQ procesori.
Docker — tas pats attēls, cits entrypoint (node dist/main.js).
*/
async function bootstrap() {
  const app = await NestFactory.createApplicationContext(WorkerModule);

  console.log(
    JSON.stringify({
      ts: new Date().toISOString(),
      event: 'worker.started',
      queues: ['email', 'sms'],
    }),
  );

  process.on('SIGTERM', async () => {
    console.log(JSON.stringify({ ts: new Date().toISOString(), event: 'worker.stopping' }));
    await app.close();
    process.exit(0);
  });

  process.on('SIGINT', async () => {
    console.log(JSON.stringify({ ts: new Date().toISOString(), event: 'worker.stopping' }));
    await app.close();
    process.exit(0);
  });
}

bootstrap();
