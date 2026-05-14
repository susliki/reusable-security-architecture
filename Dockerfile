# ── 1. Pilna atkarību instalācija (build + dev) ──
FROM node:22-alpine AS deps
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@9.15.0 --activate
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml* ./
COPY apps/api/package.json apps/api/
COPY apps/worker/package.json apps/worker/
COPY packages/shared/package.json packages/shared/
RUN --mount=type=cache,target=/root/.local/share/pnpm/store \
    pnpm install --shamefully-hoist --frozen-lockfile --ignore-scripts || pnpm install --shamefully-hoist --ignore-scripts

# ── 2. API kompilācija ──
FROM deps AS build-api
COPY apps/api/ apps/api/
COPY packages/shared/ packages/shared/
# Versijas fails — ģenerēts deploy.sh pirms docker build (opcijas)
COPY version.json* ./
RUN cd /app/apps/api && npx prisma generate && pnpm run build

# ── 3. Produkcijas atkarības (no deps + prisma generate + prune) ──
FROM deps AS prod-deps
COPY apps/api/prisma/ apps/api/prisma/
COPY apps/api/prisma.config.ts apps/api/prisma.config.ts
RUN cd apps/api && npx prisma generate
# Pēc generate — noņem devDependencies, lai samazinātu image
RUN --mount=type=cache,target=/root/.local/share/pnpm/store \
    pnpm install --shamefully-hoist --prod --ignore-scripts

# ── 4. Produkcijas API image ──
FROM node:22-alpine AS api
WORKDIR /app

# Sistēmas lietotājs — nesakņu (CIS Docker Benchmark)
RUN addgroup -g 1001 appuser 2>/dev/null || true && \
    adduser -u 1001 -G appuser -s /bin/sh -D appuser 2>/dev/null || true && \
    mkdir -p /exports && chown appuser:appuser /exports

COPY --from=build-api /app/apps/api/dist ./dist
COPY --from=prod-deps /app/node_modules ./node_modules
COPY --from=build-api /app/apps/api/prisma ./prisma
COPY --from=build-api /app/apps/api/prisma.config.ts ./prisma.config.ts
COPY --from=build-api /app/apps/api/package.json ./package.json
COPY --from=build-api /app/packages/shared ./node_modules/@app/shared
COPY --from=build-api /app/version.json* ./

USER appuser
EXPOSE 3000

HEALTHCHECK --interval=15s --timeout=5s --retries=3 --start-period=20s \
  CMD wget --spider -q http://localhost:3000/api/health || exit 1

CMD ["node", "dist/src/main.js"]
