#!/usr/bin/env bash
set -euo pipefail

# HOTEL backend container entrypoint
# - waits for postgres
# - optionally runs migrations
# - starts gunicorn

log() {
  echo "[$(date -Is)] entrypoint: $*" >&2
}

: "${DATABASE_URL:?DATABASE_URL is required}"

HOST="${DB_HOST:-postgres}"
PORT="${DB_PORT:-5432}"

WAIT_SECONDS="${DB_WAIT_SECONDS:-60}"

RUN_MIGRATIONS="${RUN_MIGRATIONS:-0}"

# Gunicorn settings (can be overridden)
GUNICORN_BIND="${GUNICORN_BIND:-0.0.0.0:8000}"
GUNICORN_WORKERS="${GUNICORN_WORKERS:-2}"
GUNICORN_TIMEOUT="${GUNICORN_TIMEOUT:-60}"

log "Starting; will wait for DB at ${HOST}:${PORT} (timeout ${WAIT_SECONDS}s)"

python - <<'PY'
import os, socket, time, sys
host = os.environ.get("DB_HOST", "postgres")
port = int(os.environ.get("DB_PORT", "5432"))
wait = int(os.environ.get("DB_WAIT_SECONDS", "60"))

deadline = time.time() + wait
last_err = None
while time.time() < deadline:
    s = socket.socket()
    s.settimeout(2.0)
    try:
        s.connect((host, port))
        s.close()
        print("DB socket reachable", file=sys.stderr)
        sys.exit(0)
    except Exception as e:
        last_err = e
        time.sleep(1)

print(f"DB not reachable within {wait}s: {last_err}", file=sys.stderr)
sys.exit(1)
PY

if [ "$RUN_MIGRATIONS" = "1" ]; then
  log "RUN_MIGRATIONS=1 -> running alembic upgrade head"
  # Alembic config is inside backend/app/db/migrations
  (cd /app/backend && python -m alembic -c app/db/migrations/alembic.ini upgrade head)
fi

log "Starting gunicorn on ${GUNICORN_BIND} (workers=${GUNICORN_WORKERS}, timeout=${GUNICORN_TIMEOUT})"

export PYTHONPATH="/app/backend:${PYTHONPATH:-}"
cd /app/backend

exec gunicorn \
  --config /app/backend/gunicorn.conf.py \
  --bind "${GUNICORN_BIND}" \
  --workers "${GUNICORN_WORKERS}" \
  --timeout "${GUNICORN_TIMEOUT}" \
  -k uvicorn.workers.UvicornWorker \
  app.main:app
