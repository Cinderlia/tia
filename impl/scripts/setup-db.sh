#!/usr/bin/env bash
# Create a read-only/write single-database account for the target DB using root (default empty password in container).
# Usage: ./scripts/setup-db.sh xvwa
# Output: Account tia_<db>, granted SELECT/INSERT/UPDATE/DELETE on that DB only.
set -euo pipefail

DB="${1:?Usage: setup-db.sh <database_name>}"
APP_USER="tia_${DB}"
APP_PASS="${TIA_DB_PASSWORD:-tia-dev-pass}"
ROOT_PASS="${TIA_ROOT_PASSWORD:-}"
MYSQL_ROOT=(mysql -uroot ${ROOT_PASS:+-p"${ROOT_PASS}"})

"${MYSQL_ROOT[@]}" <<SQL
CREATE DATABASE IF NOT EXISTS \`${DB}\` DEFAULT CHARACTER SET utf8mb4;
CREATE USER IF NOT EXISTS '${APP_USER}'@'localhost' IDENTIFIED BY '${APP_PASS}';
CREATE USER IF NOT EXISTS '${APP_USER}'@'127.0.0.1' IDENTIFIED BY '${APP_PASS}';
ALTER USER '${APP_USER}'@'localhost' IDENTIFIED BY '${APP_PASS}';
ALTER USER '${APP_USER}'@'127.0.0.1' IDENTIFIED BY '${APP_PASS}';
GRANT SELECT, INSERT, UPDATE, DELETE ON \`${DB}\`.* TO '${APP_USER}'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON \`${DB}\`.* TO '${APP_USER}'@'127.0.0.1';
FLUSH PRIVILEGES;
SQL

echo "Created ${APP_USER} (granted SELECT/INSERT/UPDATE/DELETE on ${DB}.* only)"
echo "Usage: export TIA_DB_NAME=${DB} TIA_DB_USER=${APP_USER} TIA_DB_PASSWORD=${APP_PASS}"
