#!/usr/bin/env bash
# Run trigger P0–P6 against xvwa stored_xss (executed inside the container).
# Dependencies: MariaDB is running, the xvwa database exists, and scripts/setup-db.sh has been executed (this script will run it again, idempotently).
set -euo pipefail
cd "$(dirname "$0")/.."

DB="${TIA_DB_NAME:-xvwa}"
export TIA_APP_ROOT="${TIA_APP_ROOT:-/app/xvwa}"
export TIA_DB_NAME="$DB"
export TIA_DB_USER="${TIA_DB_USER:-tia_${DB}}"
export TIA_DB_PASSWORD="${TIA_DB_PASSWORD:-tia-dev-pass}"
BASE_URL="${TIA_BASE_URL:-http://127.0.0.1/xvwa/vulnerabilities/stored_xss/}"

./scripts/setup-db.sh "$DB" >/dev/null
exec uv run tia-agent trigger \
  --slice examples/xvwa-stored-xss.json \
  --base-url "$BASE_URL" "$@"
