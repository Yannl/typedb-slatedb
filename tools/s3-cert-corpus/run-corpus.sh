#!/usr/bin/env bash
#
# Provider-neutral S3 certification corpus runner (round-4 §6.4, OD-009).
#
# Orchestrates the full corpus against ONE candidate native S3 server:
#
#   phase 1 "semantics":   start the server fresh, create the bucket, run
#                          every semantic test (conditional create race,
#                          conditional update, list pagination, multipart,
#                          byte-exact readback) and write the persistence
#                          witnesses;
#   crash barrier:         kill -9 the server process group (a real crash,
#                          not a graceful stop), then restart it over the
#                          SAME data directory;
#   phase 2 "post-restart":re-read the witnesses byte-exact.
#
# Provider selection (provider-neutral by construction):
#   S3_CERT_PROVIDER=minio   (default) — the locked transition-baseline
#                            binary via the stack supervisor's lock node
#   S3_CERT_PROVIDER=rustfs  — promotion candidate; requires
#                            S3_CERT_SERVER_BIN pointing at the EXACT
#                            pinned RustFS binary (OD-009: the artifact
#                            digest must be source-locked before a
#                            promotion verdict may cite this run)
#
# The corpus refuses non-loopback endpoints. Exit 0 ONLY when both phases
# pass AND the executed-test count matches the expected corpus size (a
# skipped corpus can never read as green).

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

PROVIDER="${S3_CERT_PROVIDER:-minio}"
PORT="${S3_CERT_PORT:-39301}"
BUCKET="s3-cert-corpus"
ACCESS="cert-$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
SECRET="cert-$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
WORK="$(mktemp -d)"
DATA="$WORK/data"
mkdir -p "$DATA"
chmod 700 "$WORK"

SERVER_PID=""
cleanup() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -9 -- -"$SERVER_PID" 2>/dev/null || kill -9 "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

server_bin() {
  case "$PROVIDER" in
    minio)
      # the locked transition-baseline binary (loopback-confined, random
      # per-run credentials, synthetic data — OD-009 containment)
      local bin="$REPO/sources/minio/minio-RELEASE.2025-09-07T16-13-09Z"
      if [ ! -x "$bin" ]; then
        echo "corpus: locked MinIO binary absent at $bin — run the stack once (node stack/cli.mjs dev) to fetch+verify it" >&2
        exit 2
      fi
      echo "$bin"
      ;;
    rustfs)
      # the OD-009 promotion candidate: the source-locked RUSTFS artifact.
      # The digest check against the lock is MANDATORY — a corpus verdict
      # may only ever cite the exact pinned binary. S3_CERT_SERVER_BIN can
      # point at an alternate materialization of the SAME artifact, but it
      # still has to match the locked sha256.
      local bin="${S3_CERT_SERVER_BIN:-$REPO/sources/rustfs/rustfs-1.0.0-rc.2}"
      if [ ! -x "$bin" ]; then
        echo "corpus: pinned RustFS binary absent at $bin — fetch the source-locked release zip (RUSTFS node in source-lock/source-lock.json) and extract it there" >&2
        exit 2
      fi
      local want got
      want="$(python3 -c "
import json,sys
nodes=json.load(open('$REPO/source-lock/source-lock.json'))['nodes']
print(next(n['sha256'] for n in nodes if n.get('id')=='RUSTFS'))
")"
      got="$(sha256sum "$bin" | cut -d' ' -f1)"
      if [ "$got" != "$want" ]; then
        echo "corpus: RustFS binary digest mismatch — want $want (source-lock RUSTFS) got $got; refusing (OD-009: verdicts cite only the pinned artifact)" >&2
        exit 2
      fi
      echo "$bin"
      ;;
    *)
      echo "corpus: unknown provider '$PROVIDER'" >&2; exit 2 ;;
  esac
}

start_server() {
  local bin; bin="$(server_bin)"
  case "$PROVIDER" in
    minio)
      MINIO_ROOT_USER="$ACCESS" MINIO_ROOT_PASSWORD="$SECRET" \
        setsid "$bin" server "$DATA" --address "127.0.0.1:$PORT" --console-address "127.0.0.1:0" \
        > "$WORK/server.log" 2>&1 &
      SERVER_PID=$!
      ;;
    rustfs)
      RUSTFS_ACCESS_KEY="$ACCESS" RUSTFS_SECRET_KEY="$SECRET" \
        setsid "$bin" --address "127.0.0.1:$PORT" "$DATA" > "$WORK/server.log" 2>&1 &
      SERVER_PID=$!
      ;;
  esac
  # readiness = an AUTHENTICATED S3 operation, never a health endpoint
  # (round-4 R4-LOCAL-01: RustFS /health can claim ready before quorum)
  for i in $(seq 1 60); do
    if AWS_ACCESS_KEY_ID="$ACCESS" AWS_SECRET_ACCESS_KEY="$SECRET" \
       python3 "$HERE/s3op.py" "http://127.0.0.1:$PORT" list-buckets >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "corpus: server never became S3-ready" >&2
  tail -30 "$WORK/server.log" >&2
  exit 1
}

echo "corpus: provider=$PROVIDER port=$PORT work=$WORK"
start_server
AWS_ACCESS_KEY_ID="$ACCESS" AWS_SECRET_ACCESS_KEY="$SECRET" \
  python3 "$HERE/s3op.py" "http://127.0.0.1:$PORT" create-bucket "$BUCKET"

export S3_CERT_ENDPOINT="http://127.0.0.1:$PORT"
export S3_CERT_BUCKET="$BUCKET"
export S3_CERT_ACCESS_KEY="$ACCESS"
export S3_CERT_SECRET_KEY="$SECRET"

echo "corpus: phase 1 (semantics)"
S3_CERT_PHASE=semantics cargo +1.93.0 test --manifest-path "$HERE/Cargo.toml" --locked -- --test-threads=4 \
  2>&1 | tee "$WORK/phase1.log" | tail -3
grep -q "test result: ok. 9 passed" "$WORK/phase1.log" || {
  echo "corpus: phase 1 did not execute the full 9-test corpus green" >&2; exit 1; }

echo "corpus: CRASH BARRIER (kill -9 the server process group)"
kill -9 -- -"$SERVER_PID" 2>/dev/null || kill -9 "$SERVER_PID"
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""
sleep 1

echo "corpus: restart over the same data directory"
start_server

echo "corpus: phase 2 (post-restart persistence)"
S3_CERT_PHASE=post-restart cargo +1.93.0 test --manifest-path "$HERE/Cargo.toml" --locked \
  persisted_objects_survive_server_crash_restart -- --test-threads=1 \
  2>&1 | tee "$WORK/phase2.log" | tail -3
grep -q "test result: ok. 1 passed" "$WORK/phase2.log" || {
  echo "corpus: post-restart persistence phase failed" >&2; exit 1; }

echo "CORPUS: PASS (provider=$PROVIDER — 9 semantic tests + crash/restart persistence)"
