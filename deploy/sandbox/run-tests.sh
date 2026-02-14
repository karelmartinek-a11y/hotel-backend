#!/usr/bin/env bash
set -euo pipefail
trap '' PIPE

SANDBOX_DIR="/opt/hotelapp/deploy/sandbox"
COMPOSE_FILE="$SANDBOX_DIR/docker-compose.yml"
ENV_FILE="$SANDBOX_DIR/hotel.env"
CENTRAL_COMPOSE="/opt/sandbox/docker-compose.yml"
CENTRAL_PG_SERVICE="hotel-postgres-sandbox"
CENTRAL_PG_HOST="127.0.0.1"
CENTRAL_PG_PORT=15433
PROD_ENV="/opt/hotelapp/deploy/.env"
LOG_FILE="/var/log/hotelapp/sandbox-tests.log"
if ! touch "$LOG_FILE" 2>/dev/null; then
  LOG_FILE="/tmp/hotelapp-sandbox-tests.log"
fi
LOCK_FILE="/tmp/hotelapp-sandbox.lock"
COOKIE_FILE="$(mktemp /tmp/hotel_sandbox_cookies.XXXXXX)"

log() {
  # tee může občas dostat SIGPIPE (např. při uzavření výstupu); neukončujeme kvůli pipefail.
  printf '%s %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG_FILE" >/dev/null || true
}

die() {
  log "CHYBA: $*"
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Chybi prikaz: $1"
}

require_cmd docker
require_cmd curl

log "Start sandbox testu HOTEL"

cleanup() {
  log "Vypinam sandbox compose"
  docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" down >/dev/null 2>&1 || true
  log "Vypinam centralni DB"
  docker compose -f "$CENTRAL_COMPOSE" down >/dev/null 2>&1 || true
  rm -f "$COOKIE_FILE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Zabran soubeznym sandbox testum (kolize na portech/cookies)
exec 9>"$LOCK_FILE"
if ! flock -w 600 9; then
  die "Sandbox je zamceny jinym behom testu"
fi

# načti produkční .env (obsahuje tajemství pro testy)
if [ -f "$PROD_ENV" ]; then
  # shellcheck disable=SC2046
  export $(grep -v '^#' "$PROD_ENV" | xargs -d '\n') || true
else
  die "Chybi $PROD_ENV"
fi

ADMIN_USERNAME="${ADMIN_USERNAME:-provoz@hotelchodovasc.cz}"
ADMIN_HASH_ESCAPED='$$argon2id$$v=19$$m=65536,t=3,p=4$$t9+7cfDBMNoQTVysEYitDw$$dAOWeqYXSp5yI6zI4o7CFDAjIkr509rfrH+BmyoIJnk'

# vygeneruj sandbox .env (použije centralni sandbox DB)
cat > "$ENV_FILE" <<EOF
POSTGRES_USER=hotelapp_sandbox
POSTGRES_PASSWORD=hotelapp_sandbox_pw
POSTGRES_DB=hotelapp_sandbox
DATABASE_URL=postgresql+psycopg://hotelapp_sandbox:hotelapp_sandbox_pw@${CENTRAL_PG_HOST}:${CENTRAL_PG_PORT}/hotelapp_sandbox
HOTEL_DATABASE_URL=postgresql+psycopg://hotelapp_sandbox:hotelapp_sandbox_pw@${CENTRAL_PG_HOST}:${CENTRAL_PG_PORT}/hotelapp_sandbox
DB_HOST=${CENTRAL_PG_HOST}
DB_PORT=${CENTRAL_PG_PORT}
RUN_MIGRATIONS=0
PUBLIC_BASE_URL=https://hotel.hcasc.cz
HOTEL_PUBLIC_BASE_URL=https://hotel.hcasc.cz
HOTEL_CANONICAL_HOST=hotel.hcasc.cz
TRUST_PROXY_HEADERS=1
SESSION_COOKIE_NAME=hotel_session
HOTEL_SESSION_COOKIE_NAME=hotel_session
SESSION_COOKIE_SAMESITE=lax
HOTEL_SESSION_COOKIE_SAMESITE=lax
SESSION_COOKIE_SECURE=false
HOTEL_SESSION_COOKIE_SECURE=false
SESSION_COOKIE_MAX_AGE_SECONDS=43200
SESSION_SECRET=${SESSION_SECRET:-sandbox-session-secret-0123456789abcdef}
HOTEL_SESSION_SECRET=${HOTEL_SESSION_SECRET:-sandbox-session-secret-0123456789abcdef}
CSRF_SECRET=${CSRF_SECRET:-sandbox-csrf-secret-0123456789abcdef}
HOTEL_CSRF_SECRET=${HOTEL_CSRF_SECRET:-sandbox-csrf-secret-0123456789abcdef}
CRYPTO_SECRET=${CRYPTO_SECRET:-sandbox-crypto-secret}
HOTEL_CRYPTO_SECRET=${HOTEL_CRYPTO_SECRET:-sandbox-crypto-secret}
ADMIN_PASSWORD_HASH=${ADMIN_HASH_ESCAPED}
HOTEL_ADMIN_PASSWORD_HASH=${ADMIN_HASH_ESCAPED}
ADMIN_PASSWORD_SEED=
LOG_LEVEL=INFO
HOTEL_LOG_LEVEL=INFO
LOG_JSON=0
HOTEL_ENVIRONMENT=dev
MAX_PHOTO_BYTES=3500000
HOTEL_MAX_PHOTO_BYTES=3500000
MAX_PHOTOS_PER_REPORT=5
HOTEL_MAX_PHOTOS_PER_REPORT=5
MAX_REPORT_TOTAL_BYTES=16000000
HOTEL_MAX_REQUEST_BYTES=16000000
THUMB_MAX_SIZE=512
HOTEL_THUMBNAIL_MAX_SIZE=512
THUMB_JPEG_QUALITY=82
HOTEL_JPEG_QUALITY=82
HOTEL_ENABLE_HSTS=0
RATE_LIMIT_ADMIN_LOGIN=10/minute
HOTEL_RATE_LIMIT_ADMIN_LOGIN_PER_MINUTE=10
MEDIA_ROOT=/var/lib/hotelapp/media-sandbox
HOTEL_MEDIA_ROOT=/var/lib/hotelapp/media-sandbox
MEDIA_ORIGINALS_DIR=original
MEDIA_THUMBNAILS_DIR=thumb
ACCEPTED_IMAGE_MIME=image/jpeg,image/png
TZ=Europe/Prague
GUNICORN_BIND=0.0.0.0:18201
EOF

# vygeneruj compose, pokud chybí
cat > "$COMPOSE_FILE" <<EOF
services:
  backend:
    image: deploy-backend:latest
    env_file: hotel.env
    network_mode: host
    restart: unless-stopped
    volumes:
      - /var/lib/hotelapp/media-sandbox:/var/lib/hotelapp/media
      - /var/log/hotelapp:/var/log/hotelapp
    healthcheck:
      test: ["CMD", "curl", "-f", "http://127.0.0.1:18201/api/health"]
      interval: 10s
      timeout: 5s
      retries: 10
EOF

log "Spoustim centralni Postgres"
docker compose -f "$CENTRAL_COMPOSE" up -d "$CENTRAL_PG_SERVICE" >/dev/null 2>&1

log "Cekam na centralni Postgres health"
PG_CID=$(docker compose -f "$CENTRAL_COMPOSE" ps -q "$CENTRAL_PG_SERVICE")
for i in {1..40}; do
  if [ -n "$PG_CID" ] && docker inspect --format '{{json .State.Health.Status}}' "$PG_CID" 2>/dev/null | grep -q healthy; then
    break
  fi
  sleep 1
  [ "$i" -eq 40 ] && die "Centralni Postgres neni healthy"
done

log "Spoustim sandbox compose"
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d --force-recreate >/dev/null 2>&1

log "Inicializace DB schema"
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" exec -T backend python - <<'PY'
import sys
sys.path.append('/app/backend')
from app.db.models import Base
from app.db.session import get_engine

engine = get_engine()
Base.metadata.create_all(engine)
PY

log "Cekam na backend health"
for i in {1..40}; do
  if curl -fsS "http://127.0.0.1:18201/api/health" >/dev/null 2>&1; then
    break
  fi
  sleep 1
  if [ "$i" -eq 40 ]; then
    die "Backend neni ready"
  fi
done

log "Admin login (CSRF)"
CSRF=$(curl -fsS -c "$COOKIE_FILE" "http://127.0.0.1:18201/admin/login" | perl -ne '$t //= $1 if /name="csrf_token" value="([^"]*)"/; END { print $t if defined $t }')
if [ -z "$CSRF" ]; then
  die "Chybi CSRF token"
fi

curl -fsS -b "$COOKIE_FILE" -c "$COOKIE_FILE" \
  -X POST \
  --data-urlencode "csrf_token=$CSRF" \
  --data-urlencode "username=$ADMIN_USERNAME" \
  --data-urlencode "password=+Sin8glov8" \
  http://127.0.0.1:18201/admin/login -o /dev/null

log "Sandbox testy HOTEL OK"
