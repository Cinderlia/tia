#!/usr/bin/env bash
# Build the directed opcode tracer and install it into the test PHP runtime.
#
# Usage: scripts/build-opcode-tracer.sh [build_container] [test_container]
# Defaults: php84-build / php84-dev.
set -euo pipefail

BUILD="${1:-php84-build}"
TEST="${2:-php84-dev}"
SRC="$(cd "$(dirname "$0")/.." && pwd)/probe-php/opcode-tracer"

docker cp "$SRC" "$BUILD:/php-build/ext/opcode_tracer"
docker exec "$BUILD" bash -lc '
  cd /php-build/ext/opcode_tracer
  phpize >/dev/null
  ./configure --with-php-config=/usr/local/bin/php-config >/dev/null
  make -j4 >/dev/null
'
docker cp "$BUILD:/php-build/ext/opcode_tracer/modules/opcode_tracer.so" /tmp/opcode_tracer.so
docker cp /tmp/opcode_tracer.so "$TEST:/tmp/opcode_tracer.so"
docker exec --user root "$TEST" bash -lc '
  cp /tmp/opcode_tracer.so "$(php -r "echo ini_get(\"extension_dir\");")"/
  echo "extension=opcode_tracer.so" > /usr/local/etc/php/conf.d/zz-opcode-tracer.ini
  mkdir -p /tmp/trace && chmod 777 /tmp/trace
  apache2ctl graceful >/dev/null 2>&1 || true
'
echo "opcode_tracer installed into $TEST"
