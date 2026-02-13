#!/usr/bin/env bash
set -euo pipefail

FRONTEND_DIR="${1:-../hotel-frontend}"
if [ ! -x "$FRONTEND_DIR/sync-to-backend.sh" ]; then
  echo "ERROR: Expected frontend script at: $FRONTEND_DIR/sync-to-backend.sh" >&2
  exit 1
fi

"$FRONTEND_DIR/sync-to-backend.sh" "$(pwd)"
