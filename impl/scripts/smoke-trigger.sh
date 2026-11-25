#!/usr/bin/env bash
# 对 xvwa stored_xss 跑一遍 trigger P0–P6（容器内执行）。
# 依赖：MariaDB 已启动、xvwa 库存在、scripts/setup-db.sh 已跑过（本脚本会再跑一次，幂等）。
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
