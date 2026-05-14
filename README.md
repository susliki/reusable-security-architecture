# Arhitektūras references modelis

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.20186229.svg)](https://doi.org/10.5281/zenodo.20186229)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

Drošas valsts sektora tīmekļa lietojumprogrammu arhitektūras references modelis — atvasināts no maģistra darba *Atkārtoti lietojama drošības arhitektūras modeļa izstrāde un validācija Latvijas valsts sektora tīmekļa lietojumprogrammām* (Edgars Naglis, Vidzemes Augstskola, 2026). Mērķis — piedāvāt atkārtoti lietojamu kodola arhitektūru, kas īsteno modernas drošības kontroles ar minimālu pielāgošanas darbu jaunās jomās.

## Tehnoloģiju kopa

- **Backend** — NestJS 11 + Prisma 7 + PostgreSQL 16
- **Auth** — OIDC (Microsoft Entra), WebAuthn (passkeys), TOTP
- **Sesijas** — server-side cookies caur express-session + connect-redis
- **Rindas** — BullMQ uz Redis
- **Failu glabātuve** — S3 vai MinIO ar ClamAV starpposmu
- **E-pasts** — pievienojama saskarne, iekļauti divi varianti (SMTP, Microsoft Graph)
- **Konteinerizācija** — Docker (CIS Docker Benchmark atbilstošs)
- **Monorepo** — pnpm + Turborepo

## Drošības iezīmes

- 12 līmeņu starpnieka ķēde `main.ts` (Helmet, CORS, CSRF dubultās sīkdatnes, trust proxy)
- HMAC-SHA256 audita ķēde ar PostgreSQL advisory lock un `verifyChain` metodi
- AES-256-GCM kolonnu šifrēšana ar blind index lauka meklēšanai
- GDPR pilna sēkla — dzēšanas kaskāde, piekrišanas versionēšana, rektifikācijas plūsma, datu eksports
- Redis balstīts algotā loga likmes ierobežotājs
- Sesijas verifikācija ik pēc 60 s, MFA step-up, atkopšanas kodi
- Strukturēts audita žurnāls ar pieprasījuma kontekstu

## Mapju struktūra

```
apps/
  api/           — NestJS backend (visi moduļi vienā procesā)
  worker/        — BullMQ darbinieks (tas pats kods, cita ieejas vieta)
packages/
  shared/        — Datu klasifikācijas matrice (referenču artefakts, sk. piezīmi zem)
infra/
  nginx/         — Apgrieztā starpniekservera paraugs
scripts/
  deploy.sh      — Parametrizēts izvietošanas skripts
  k6/            — Slodzes testi (audit write, encrypted CRUD, rate limit, sesijas, TOTP)
benchmarks/      — PII šifrēšanas etalons
```

> **Piezīme par `packages/shared/`.** Mape satur `data-classification.ts` — GDPR/OWASP ASVS datu klasifikācijas matrici (PUBLIC / INTERNAL / CONFIDENTIAL / RESTRICTED) ar pamatojumu katram Prisma laukam. Tas ir **referenču artefakts no maģistra darba 4. nodaļas**, kas demonstrē, kā modeļa septītajā drošības domēnā tiek dokumentēts datu aizsardzības līmenis. Šablonā tas pašlaik **netiek tieši importēts** — to var izmantot kā paraugu, integrējot savā kodā (piem., `prisma-encryption.extension.ts` un `gdpr-export.service.ts` lēmumiem) vai kā dokumentāciju datu inventarizācijai.

## Instalācija

Ātrs starts:

```bash
pnpm install
cp .env.example .env                     # ģenerējiet drošas atslēgas — sk. SETUP.md §3
docker compose up -d                     # postgres, redis, minio, clamav
cd apps/api && pnpm exec prisma migrate dev --name init && cd ../..
# Izveidot MinIO bucketus (vienreiz) — sk. SETUP.md §5
cd apps/api && pnpm run start:dev
```

Pilns soli-pa-solim gids ar priekšnosacījumiem, drošo atslēgu ģenerēšanu, MinIO bucketu izveidi, verifikāciju, pārejas uz produkciju kontrolsarakstu un tipisko problēmu risinājumiem — sk. **[SETUP.md](SETUP.md)**.

## Adaptācija uz citu domēnu

1. **Pievienot biznesa moduļus** — izveidot jaunu direktoriju `apps/api/src/<jomas-nosaukums>/` ar saviem kontrolieriem, servisiem un DTO.
2. **Paplašināt Prisma shēmu** — pievienot jaunus modeļus blakus eksistējošajiem `User`, `Profile`, `AuditLog` u.c.
3. **Pievienot vai aizvietot e-pasta veidnes** — `apps/api/src/notifications/templates/` ir veidņu mape; veidņu renderēšanas mehānisms paliek nemainīgs.
4. **Pielāgot lomas** — `Role` enum `apps/api/prisma/schema.prisma` un loģisko lomu kartējums servisos.
5. **Konfigurēt e-pasta piegādātāju** — `.env` izvēlēties SMTP vai Microsoft Graph (vai pievienot citu adapteri).

## Drošības spec faili

Kritiskie testi `apps/api/src/`:

- `common/auth.guard.spec.ts`, `csrf.middleware.spec.ts`, `rate-limit.factory.spec.ts`, `session-store.spec.ts`
- `common/status.guard.spec.ts`, `step-up.guard.spec.ts`, `sub-role.guard.spec.ts`
- `crypto/pii-crypto.spec.ts`, `prisma/prisma-encryption.extension.spec.ts`
- `auth/auth.service.spec.ts`, `auth.controller.spec.ts`
- `session-lifecycle/session-lifecycle.service.spec.ts`

Palaist visus: `cd apps/api && pnpm exec jest`.

## Slodzes testi

`scripts/k6/` direktorijā 6 funkcionējoši k6 skripti — palaist katru atsevišķi:

```bash
k6 run scripts/k6/rate-limiter.js
k6 run scripts/k6/audit-write.js
k6 run scripts/k6/encrypted-crud.js
k6 run scripts/k6/blind-index-lookup.js
k6 run scripts/k6/session-concurrency.js
k6 run scripts/k6/totp-login.js
```

Etalons `benchmarks/pii-encryption-bench.js` mēra šifrēšanas/atšifrēšanas caurplūdi.

## Akadēmiskā izcelsme un citēšana

Šis projekts ir atvasināts no maģistra darba:

**Naglis, E. (2026).** *Atkārtoti lietojama drošības arhitektūras modeļa izstrāde un validācija Latvijas valsts sektora tīmekļa lietojumprogrammām* [Maģistra darbs, Vidzemes Augstskola, Inženierzinātņu fakultāte]. Valmiera.

- **Autors:** Edgars Naglis (stud. apl. Nr. KI24016)
- **Darba vadītājs:** Mg. sc. comp. ing. Andis Maksimovs
- **Augstskola:** Vidzemes Augstskola, Inženierzinātņu fakultāte
- **Gads:** 2026, Valmiera
- **Apjoms:** 135 lpp., 4 attēli, 36 tabulas, 7 pielikumi
- **Metode:** Design Science Research (DSR) ar jauktu metožu validāciju
- **Validācija:** OWASP ASVS v5.0 L2 → 97,1 % (99/102 prasības)

### BibTeX

**Maģistra darbs** (primārā atsauce uz modeli):
```bibtex
@mastersthesis{naglis2026,
  author       = {Edgars Naglis},
  title        = {Atk\={a}rtoti lietojama dro\v{s}\={\i}bas arhitekt\={u}ras
                  mode\c{l}a izstr\={a}de un valid\={a}cija Latvijas valsts
                  sektora t\={\i}mek\c{l}a lietojumprogramm\={a}m},
  school       = {Vidzemes Augstskola, In\v{z}enierzin\={a}t\c{n}u fakult\={a}te},
  year         = {2026},
  address      = {Valmiera, Latvija},
  type         = {Ma\v{g}istra darbs}
}
```

**Programmatūra** (atsauce uz konkrētu kodu versiju, arhivēta Zenodo):
```bibtex
@software{naglis2026_code,
  author    = {Edgars Naglis},
  title     = {Reusable Security Architecture Reference Model
               for Latvian Public Sector Web Applications},
  year      = {2026},
  publisher = {Zenodo},
  version   = {v1.0.0},
  doi       = {10.5281/zenodo.20186229},
  url       = {https://doi.org/10.5281/zenodo.20186229}
}
```

Ja izmantojat šo kodu vai modeli savā pētniecībā vai produktā, lūdzu atsaucieties uz augstāk minēto darbu.

## Licence

Apache License 2.0 — sk. [LICENSE](LICENSE).

Saskaņā ar Apache 2.0 4(d) punktu, visās atvasinātajās programmās jāsaglabā [NOTICE](NOTICE) fails ar atsauci uz oriģinālo maģistra darbu.

Latviešu informatīvs licences kopsavilkums — sk. [LICENSE.lv.md](LICENSE.lv.md) (juridiski saistošā ir angļu versija `LICENSE` failā).
