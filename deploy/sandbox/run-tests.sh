#!/usr/bin/env bash
set -euo pipefail
trap '' PIPE

SANDBOX_DIR="/opt/hotelapp/deploy/sandbox"
COMPOSE_FILE="$SANDBOX_DIR/docker-compose.yml"
ENV_FILE="$SANDBOX_DIR/hotel.env"
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
  rm -f "$COOKIE_FILE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Zabran soubeznym sandbox testum (kolize na portech/cookies)
exec 9>"$LOCK_FILE"
if ! flock -w 600 9; then
  die "Sandbox je zamceny jinym behom testu"
fi

log "Spoustim sandbox compose"
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d --force-recreate >/dev/null 2>&1

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

log "Inicializace DB schema"
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" exec -T backend python - <<'PY'
import sys
sys.path.append('/app/backend')
from app.db.models import Base
from app.db.session import get_engine

engine = get_engine()
Base.metadata.create_all(engine)
PY

log "Admin login (CSRF)"
CSRF=$(curl -fsS -c "$COOKIE_FILE" "http://127.0.0.1:18201/admin/login" | perl -ne '$t //= $1 if /name="csrf_token" value="([^"]*)"/; END { print $t if defined $t }')
if [ -z "$CSRF" ]; then
  die "Chybi CSRF token"
fi

curl -fsS -b "$COOKIE_FILE" -c "$COOKIE_FILE" \
  -X POST --data-urlencode "csrf_token=$CSRF" --data-urlencode "password=+Sin8glov8" \
  http://127.0.0.1:18201/admin/login -o /dev/null

log "Registrace zarizeni (PENDING)"
DEVICE_ID="sandbox-device-$(date '+%s')"
FP="sandbox-fp-$(date '+%s')"

curl -fsS -X POST -H 'Content-Type: application/json' \
  -d '{"device_id":"'"$DEVICE_ID"'","display_name":"Sandbox Uzivatel","device_info":{"ua":"sandbox","platform":"cli","fp":"'"$FP"'"}}' \
  http://127.0.0.1:18201/api/v1/device/register >/dev/null

log "Aktivace zarizeni v adminu"
# Zjisti interní numeric ID zarizeni z HTML adminu
ADMIN_HTML=$(curl -fsS -b "$COOKIE_FILE" http://127.0.0.1:18201/admin/devices)
NUM_ID=$(perl -ne '$id //= $1 if /\/admin\/devices\/([0-9]+)\/activate/; END { print $id if defined $id }' <<<"$ADMIN_HTML")
if [ -z "$NUM_ID" ]; then
  die "Chybi admin device id"
fi

CSRF2=$(perl -ne '$t //= $1 if /name="csrf_token" value="([^"]*)"/; END { print $t if defined $t }' <<<"$ADMIN_HTML")
if [ -z "$CSRF2" ]; then
  die "Chybi CSRF token pro admin akce"
fi

curl -fsS -b "$COOKIE_FILE" -X POST \
  -d "csrf_token=$CSRF2" \
  http://127.0.0.1:18201/admin/devices/$NUM_ID/activate -o /dev/null

log "Device status ACTIVE"
STATUS_RESP=$(curl -fsS -H "X-Device-Id: $DEVICE_ID" http://127.0.0.1:18201/api/v1/device/status)
log "STATUS_RESP=${STATUS_RESP}"
if ! printf '%s' "$STATUS_RESP" | grep -q '"status":"ACTIVE"'; then
  die "Necekany status zarizeni: ${STATUS_RESP:-neznamy}"
fi

log "Sandbox testy HOTEL OK"
