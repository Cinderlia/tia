#!/usr/bin/env bash
# 用 root（容器内默认空密码）为目标库建一个只读/写单库的账号。
# 用法：./scripts/setup-db.sh xvwa
# 产物：账号 tia_<db>，只授予该库 SELECT/INSERT/UPDATE/DELETE。
set -euo pipefail

DB="${1:?用法: setup-db.sh <数据库名>}"
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

echo "已创建 ${APP_USER}（只授权 ${DB}.* 的 SELECT/INSERT/UPDATE/DELETE）"
echo "使用：export TIA_DB_NAME=${DB} TIA_DB_USER=${APP_USER} TIA_DB_PASSWORD=${APP_PASS}"
