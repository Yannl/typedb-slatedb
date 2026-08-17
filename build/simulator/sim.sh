#!/usr/bin/env bash
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Bring up the local R2 simulator.
#
# Three processes, each earning its place:
#
#   minio       :9000   A faithful S3 implementation. Real SigV4, real headers, real error
#                       shapes — this is what proves the AmazonS3Builder configuration is right.
#   workerd     :9200   The r2-s3-shim Worker over a real R2 binding, via Miniflare. This is
#                       what proves SlateDB's manifest compare-and-swap works against R2's own
#                       conditional-put implementation rather than an approximation of it.
#   op-counter  :9100   A transparent proxy in front of MinIO that counts operations the way R2
#                       bills them, so a test can assert on the bill rather than on behaviour
#                       alone. Nothing else in the suite can tell one request from forty.
#
# Usage: ./sim.sh up | down | status | ops | reset

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

MINIO_PORT=9000
COUNTER_PORT=9100
WORKERD_PORT=9200
export MINIO_ROOT_USER=typedbtest
export MINIO_ROOT_PASSWORD=typedbtest123

# Every request below is to a loopback address. The sandbox exports HTTPS_PROXY, and curl would
# otherwise try to reach 127.0.0.1 through it.
CURL=(curl -sS --noproxy '*')

pids_file="$HERE/.sim.pids"

wait_for() {
  local url="$1" name="$2" attempts=60
  for _ in $(seq $attempts); do
    if "${CURL[@]}" -o /dev/null "$url" 2>/dev/null; then return 0; fi
    sleep 0.5
  done
  echo "$name did not come up at $url" >&2
  return 1
}

up() {
  mkdir -p data/minio data/workerd
  : > "$pids_file"

  if ! "${CURL[@]}" -o /dev/null "http://127.0.0.1:$MINIO_PORT/minio/health/live" 2>/dev/null; then
    ./bin/minio server ./data/minio \
      --address "127.0.0.1:$MINIO_PORT" \
      --console-address "127.0.0.1:9001" > minio.log 2>&1 &
    echo $! >> "$pids_file"
    wait_for "http://127.0.0.1:$MINIO_PORT/minio/health/live" minio
  fi

  # Idempotent: `mb` on an existing bucket is not an error worth failing the script over.
  ./bin/mc alias set sim "http://127.0.0.1:$MINIO_PORT" \
    "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" --api S3v4 >/dev/null 2>&1 || true
  ./bin/mc mb --ignore-existing sim/typedb >/dev/null 2>&1 || true

  if ! "${CURL[@]}" -o /dev/null "http://127.0.0.1:$COUNTER_PORT/__ops" 2>/dev/null; then
    OP_COUNTER_PORT=$COUNTER_PORT OP_COUNTER_BACKEND_PORT=$MINIO_PORT \
      node op-counter.mjs > op-counter.log 2>&1 &
    echo $! >> "$pids_file"
    wait_for "http://127.0.0.1:$COUNTER_PORT/__ops" op-counter
  fi

  if ! "${CURL[@]}" -o /dev/null "http://127.0.0.1:$WORKERD_PORT/typedb" 2>/dev/null; then
    WORKERD_PORT=$WORKERD_PORT node worker/serve.mjs > workerd.log 2>&1 &
    echo $! >> "$pids_file"
    wait_for "http://127.0.0.1:$WORKERD_PORT/typedb" workerd
  fi

  status
}

down() {
  if [[ -f "$pids_file" ]]; then
    while read -r pid; do
      [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
    done < "$pids_file"
    rm -f "$pids_file"
  fi
  pkill -f 'bin/minio server' 2>/dev/null || true
  pkill -f 'op-counter.mjs' 2>/dev/null || true
  pkill -f 'worker/serve.mjs' 2>/dev/null || true
  echo "simulator stopped"
}

status() {
  printf '%-12s %-28s %s\n' COMPONENT ENDPOINT STATE
  for entry in \
    "minio|http://127.0.0.1:$MINIO_PORT/minio/health/live|http://127.0.0.1:$MINIO_PORT" \
    "op-counter|http://127.0.0.1:$COUNTER_PORT/__ops|http://127.0.0.1:$COUNTER_PORT" \
    "workerd|http://127.0.0.1:$WORKERD_PORT/typedb|http://127.0.0.1:$WORKERD_PORT"; do
    IFS='|' read -r name probe endpoint <<< "$entry"
    if "${CURL[@]}" -o /dev/null "$probe" 2>/dev/null; then
      printf '%-12s %-28s %s\n' "$name" "$endpoint" up
    else
      printf '%-12s %-28s %s\n' "$name" "$endpoint" down
    fi
  done
}

case "${1:-up}" in
  up) up ;;
  down) down ;;
  status) status ;;
  ops) "${CURL[@]}" "http://127.0.0.1:$COUNTER_PORT/__ops" ;;
  reset) "${CURL[@]}" "http://127.0.0.1:$COUNTER_PORT/__ops/reset" ;;
  *) echo "usage: $0 {up|down|status|ops|reset}" >&2; exit 2 ;;
esac
