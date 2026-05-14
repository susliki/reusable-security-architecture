# Uzstādīšanas rokasgrāmata – lokāla izstrādes vide

Šī rokasgrāmata apraksta, kā palaist projektu no nulles lokālā datorā. Sagaidāmais rezultāts – uz `http://localhost:3000` darbojas API serveris, `/api/health` atbild ar visu pakalpojumu statusu `up`, un visi 124 vienībtesti ir zaļi.

> Šajā rokasgrāmatā komandas paredzētas izpildei no projekta saknes (`/Users/.../refproject/`), ja nav norādīts citādi.

## 1. Priekšnosacījumi

| Rīks | Versija | Pārbaude |
|---|---|---|
| Node.js | ≥ 22 | `node --version` |
| pnpm | 9.15.0 (caur Corepack) | `pnpm --version` |
| Docker | ≥ 20 | `docker --version` |
| Docker Compose | v2+ | `docker compose version` |
| k6 (opcionāli) | ≥ 0.50 | `k6 version` |

Ja `pnpm` nav uzstādīts:

```bash
corepack enable
corepack prepare pnpm@9.15.0 --activate
```

**Apple Silicon (arm64) piezīme.** ClamAV oficiālajiem Docker attēliem nav arm64 manifesta – `docker-compose.yml` jau norāda `platform: linux/amd64` ClamAV pakalpojumam, kas darbojas caur Rosetta 2 emulāciju. Pārliecinieties, ka Rosetta 2 ir instalēta (`softwareupdate --install-rosetta` vai caur Docker Desktop iestatījumiem).

## 2. Atkarību instalācija

```bash
pnpm install
```

`postinstall` skripts automātiski izpilda `prisma generate` un izveido Prisma klientu `node_modules/@prisma/client/`.

## 3. Vides mainīgo iestatīšana

Nokopējiet paraugu:

```bash
cp .env.example .env
```

Ģenerējiet drošas atslēgas obligātajiem kriptogrāfiskajiem mainīgajiem:

```bash
node -e "
const c = require('crypto');
const fs = require('fs');
let env = fs.readFileSync('.env', 'utf8');
const gen = () => c.randomBytes(32).toString('hex');
env = env.replace(/SESSION_SECRET=.*/, 'SESSION_SECRET=' + c.randomBytes(48).toString('hex'));
env = env.replace(/AUDIT_HMAC_KEY=.*/, 'AUDIT_HMAC_KEY=' + gen());
env = env.replace(/AUDIT_EXPORT_HMAC_KEY=.*/, 'AUDIT_EXPORT_HMAC_KEY=' + gen());
env = env.replace(/PII_ENCRYPTION_KEY=.*/, 'PII_ENCRYPTION_KEY=' + gen());
env = env.replace(/PII_BLIND_INDEX_KEY=.*/, 'PII_BLIND_INDEX_KEY=' + gen());
env = env.replace(/TOTP_ENCRYPTION_KEY=.*/, 'TOTP_ENCRYPTION_KEY=' + gen());
fs.writeFileSync('.env', env);
console.log('.env aizpildīts ar ģenerētām atslēgām');
"
```

**Obligātie mainīgie produkcijas videi:**

| Mainīgais | Apraksts |
|---|---|
| `DATABASE_URL` | PostgreSQL savienojuma virkne |
| `SESSION_SECRET` | ≥ 32 rakstzīmes; sesijas paraksts |
| `AUDIT_HMAC_KEY` | HMAC-SHA256 atslēga audita ķēdei |
| `AUDIT_EXPORT_HMAC_KEY` | Atslēga audita eksporta parakstam |
| `PII_ENCRYPTION_KEY` | 32 baiti (64 hex) AES-256-GCM šifrēšanai |
| `PII_BLIND_INDEX_KEY` | 32 baiti HMAC blind indeksiem |
| `TOTP_ENCRYPTION_KEY` | TOTP noslēpumu glabāšanai |

`PII_ENCRYPTION_ACTIVE` jāatstāj `false` līdz datu migrācijas pabeigšanai (skat. 8. sadaļu).

## 4. Docker pakalpojumi

```bash
docker compose up -d postgres redis minio clamav
docker compose ps    # pārbaude – visiem statuss "Up"
```

Sagaidāmais izvads:

```
refproject-clamav-1     clamav/clamav:stable    Up   3310, 3310
refproject-minio-1      minio:latest            Up   9000-9001
refproject-postgres-1   postgres:16-alpine      Up   5432
refproject-redis-1      redis:7-alpine          Up   6379
```

ClamAV pirmajā palaišanas reizē patērē ~2 minūtes signatūru lejupielādei (`freshclam`) – `/api/health` atgriezīs `clamav: down`, līdz tas ir pabeigts.

## 5. MinIO `bucket` tipa krātuvju izveide

API paredz piecas `bucket` tipa krātuves. Izveidojiet tās vienreiz:

```bash
docker exec refproject-minio-1 sh -c '
  mc alias set local http://localhost:9000 minioadmin minioadmin > /dev/null
  for b in documents photos exports temp certificates; do
    mc mb -p local/$b
  done
  mc ls local
'
```

MinIO konsole pieejama: <http://localhost:9001> (lietotājs `minioadmin` / parole `minioadmin`).

## 6. Prisma migrācija

```bash
cd apps/api
pnpm exec prisma migrate dev --name init
cd ../..
```

Sagaidāmais izvads – `Your database is now in sync with your schema.` un jauna mape `apps/api/prisma/migrations/<timestamp>_init/migration.sql`.

## 7. Verifikācija

### 7.1. TypeScript kompilācija

```bash
cd apps/api && pnpm exec tsc --noEmit && cd ../..
cd apps/worker && pnpm exec tsc --noEmit && cd ../..
```

Abas komandas izpildās bez kļūdām.

### 7.2. Vienībtesti

```bash
cd apps/api && pnpm exec jest && cd ../..
```

Sagaidāmais: `Test Suites: 12 passed, 12 total | Tests: 124 passed, 124 total`.

### 7.3. Runtime smoke

Citā logā:

```bash
cd apps/api && pnpm run start:dev
```

Pēc palaišanas ziņojuma `Nest application successfully started` palaidiet:

```bash
curl -s http://localhost:3000/api/health | jq
# {"ok":true, "db":"up", "redis":"up", "storage":"up", "clamav":"up"}

curl -s http://localhost:3000/api | jq
# {"ok":true, "service":"api"}

curl -s http://localhost:3000/api/csrf-token | jq
# {"csrfToken":"..."}
```

### 7.4. Slodzes testi (opcionāli)

```bash
k6 run scripts/k6/rate-limiter.js
k6 run scripts/k6/audit-write.js
k6 run scripts/k6/encrypted-crud.js
k6 run scripts/k6/blind-index-lookup.js
k6 run scripts/k6/session-concurrency.js
k6 run scripts/k6/totp-login.js
```

## 8. Pārejas uz produkcijas vidi kontrolsaraksts

1. **Ģenerēt jaunas drošās atslēgas**. Atkārtot 3. sadaļas skriptu produkcijas vidē; neizmantot atkārtoti lokālās atslēgas.
2. **Iestatīt `PII_ENCRYPTION_ACTIVE=true`**. Tikai pēc esošu PII datu migrācijas caur `crypto/` moduli.
3. **TLS termināciju** veikt apgrieztajā starpniekserverī (nginx, Traefik, Caddy vai mākoņa slodzes balansētājs ar Let's Encrypt vai komerciālu sertifikātu).
4. **Iestatīt `COOKIE_SECURE=true`** un `NODE_ENV=production` produkcijas vidē.
5. **Aizvietot `DEV_ENDPOINTS=1`** ar `DEV_ENDPOINTS=0`. Pēc tam `apps/api/src/dev/` kontrolieri tiek izslēgti.
6. **Konteinerizācija**. Produkcijas videi izmantot Kubernetes / Docker Swarm / Nomad ar centralizētu noslēpumu pārvaldību (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault), nevis šajā repozitorijā iekļauto `docker-compose.yml`.

## 9. Zīmola un adaptācijas vietas

Pirms publicēšanas pielāgot:

- `apps/api/src/notifications/templates/base.layout.ts` – krāsas (`#1A365D`, `#2C5282`), logo (`APP`), organizācijas nosaukums.
- `.env.example` – `WEBAUTHN_RP_NAME`, `TOTP_ISSUER`, `OIDC_ROLE_ADMIN`, `OIDC_ROLE_OPERATOR`.
- `README.md` – pirmā teikuma jomas apraksts, saites uz konkrēto organizāciju.
- `package.json` (saknē un `apps/api/`) – `name` un `version` lauki.

## 10. Tipiskas problēmas

**`Error: DATABASE_URL is not set`** – pārbaudiet, ka `.env` atrodas projekta saknē. `apps/api/prisma.config.ts` un `apps/api/src/main.ts` meklē abās vietās: `apps/api/.env`, tad rezerves variants `./.env`.

**`/api/health` atgriež 500 ar `MinIO is not responding (documents bucket)`** – `bucket` tipa krātuves nav izveidotas. Atgriezieties pie 5. sadaļas.

**`clamav: down`** – `freshclam` vēl lejupielādē signatūras. Pārbaude: `docker compose logs clamav | tail`. Pirmajā palaišanas reizē – ~2 minūtes.

**`Error: no matching manifest for linux/arm64/v8`** ClamAV pakalpojumam – pārbaudiet, ka `docker-compose.yml` saglabā `platform: linux/amd64` rindu zem `clamav` un ka Rosetta 2 ir aktivizēta.

**Aizņemti porti** (5432, 6379, 9000, 9001, 3000, 3310) – apturiet konfliktējošos pakalpojumus vai pārkonfigurējiet portus `.env` un `docker-compose.yml`.

## Norādes

- Akadēmiskā izcelsme un citēšana: [README.md](README.md)
- Licence: [LICENSE](LICENSE), [LICENSE.lv.md](LICENSE.lv.md), [NOTICE](NOTICE)
- Drošības testu saraksts: `README.md` sadaļa "Drošības specifikāciju faili"
