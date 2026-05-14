#!/bin/bash
# Parametrizēts izvietošanas skripts — pielāgojiet pirms lietošanas
# Vajadzīgie env mainīgie: APP_HOST, REGISTRY, SSH_KEY
set -euo pipefail

: "${APP_HOST:?APP_HOST not set — piemēram: APP_HOST=root@app.example.org}"
: "${REGISTRY:?REGISTRY not set — piemēram: REGISTRY=registry.example.org:5000}"
: "${SSH_KEY:=$HOME/.ssh/id_rsa}"
: "${REMOTE_PATH:=/opt/app}"
: "${IMAGE_NAME:=app-api}"

SSH="ssh -i ${SSH_KEY}"

# ── Izvēlne ──
echo ""
echo "  Šablona deploy skripts          "
echo "  1) API build + push + restart   "
echo "  2) Tikai restart (serverī)      "
echo "  3) Migrācija (serverī)          "
echo ""
read -p "Izvēle [1]: " CHOICE
CHOICE=${CHOICE:-1}

step_start() { STEP_START=$(date +%s); echo ""; echo "▸ $1"; }
step_done() {
  local elapsed=$(( $(date +%s) - STEP_START ))
  echo "  ✓ done in ${elapsed}s"
}

generate_version() {
  step_start "Generating version.json..."
  cat > version.json <<VEOF
{
  "commit": "$(git rev-parse --short HEAD 2>/dev/null || echo dev)",
  "commitFull": "$(git rev-parse HEAD 2>/dev/null || echo dev)",
  "branch": "$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo local)",
  "buildTime": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "version": "$(node -p "require('./apps/api/package.json').version" 2>/dev/null || echo 0.0.0)"
}
VEOF
  step_done
}

deploy_api() {
  step_start "API: Docker build"
  docker build --platform linux/amd64 \
    -t ${REGISTRY}/${IMAGE_NAME}:latest \
    -f Dockerfile --target api .
  step_done
  step_start "API: Docker push"
  docker push ${REGISTRY}/${IMAGE_NAME}:latest
  step_done
}

restart_server() {
  step_start "Server: pull + restart"
  ${SSH} ${APP_HOST} "cd ${REMOTE_PATH} \
    && docker compose pull api worker \
    && docker compose up -d"
  step_done
}

run_migration() {
  step_start "Migration: prisma migrate deploy"
  ${SSH} ${APP_HOST} "docker exec ${IMAGE_NAME} npx prisma migrate deploy"
  step_done
}

DEPLOY_START=$(date +%s)

case $CHOICE in
  1) generate_version; deploy_api; restart_server ;;
  2) restart_server ;;
  3) run_migration ;;
  *) echo "Nezināma izvēle: $CHOICE"; exit 1 ;;
esac

TOTAL=$(( $(date +%s) - DEPLOY_START ))
echo ""
echo "══════════════════════════════════"
echo "✓ Deploy pabeigts: ${TOTAL}s"
echo "══════════════════════════════════"
