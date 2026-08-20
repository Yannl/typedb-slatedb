#!/usr/bin/env bash
#
# Provider-neutral S3 certification corpus runner (round-4 §6.4, OD-009;
# hardened round-5 R5-LOCAL-01/03; evidence hardened round-6 R6-EVID-01).
#
# Orchestrates the full corpus against ONE candidate native S3 server:
#
#   phase 1 "semantics":   start the server fresh, create the bucket, run
#                          every semantic test — including the HARDENED
#                          barrier-synchronized CAS races (many rounds,
#                          independent clients, 1 MiB distinct bodies) —
#                          and write the persistence witnesses;
#   phase 1b "mp-cas":     MULTI-PROCESS conditional-create races: N
#                          independent OS processes per round, released by
#                          a start-file barrier; exactly one winner whose
#                          stored bytes are byte-exact its own (exit 4 =
#                          changed-byte overwrite = decisive failure);
#   crash barrier:         kill -9 the server process group (a real crash,
#                          not a graceful stop), then restart it over the
#                          SAME data directory;
#   phase 2 "post-restart":re-read the witnesses byte-exact.
#
# R5-LOCAL-03: the run emits a STRUCTURED, SEALED evidence bundle —
# provider binary digest + version, config, source identity, toolchain,
# per-phase raw logs with digests, restart receipt, and a root seal —
# verifiable independently by verify-bundle.py.
#
# R6-EVID-01 hardening:
#   * CLEAN-TREE GATE runs BEFORE execution (not only before sealing).
#     Any tracked or untracked dirt refuses the run. S3_CERT_ALLOW_DIRTY=1
#     is an explicit opt-out that STAMPS the bundle qualification=false.
#   * The cas_racer path is resolved from `cargo build --message-format=json`
#     (falling back to `cargo metadata`'s target_directory), NEVER from a
#     hardcoded tools/s3-cert-corpus/target/debug path. A custom
#     CARGO_TARGET_DIR therefore works, and an unresolvable/absent racer
#     refuses the run instead of degrading to "0 winners, N process errors".
#   * Every multi-process CAS round is recorded STRUCTURALLY in
#     phase1b.json (per-round winners/losers/overwrites/errors), and a
#     nonzero process-error count is a hard failure of its own.
#   * Every significant command is logged to commands.jsonl (argv + cwd).
#
# Provider selection (provider-neutral by construction):
#   S3_CERT_PROVIDER=minio   (default) — the locked transition-baseline
#   S3_CERT_PROVIDER=rustfs  — promotion candidate (source-lock RUSTFS;
#                              digest verified below, mismatch refused)
#
# Tunables: S3_CERT_CAS_ROUNDS (100) S3_CERT_CAS_WRITERS (16)
#           S3_CERT_UPDATE_ROUNDS (50) S3_CERT_MP_ROUNDS (20)
#           S3_CERT_MP_PROCS (8) S3_CERT_EVIDENCE_DIR
#           S3_CERT_ALLOW_DIRTY (unset) — non-qualification escape hatch
#
# Exit 0 ONLY when every phase passes AND the executed-test count matches
# the expected corpus size (a skipped corpus can never read as green).

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

# expected executed-test counts (fail-closed: a filtered/skipped corpus
# can never read green)
SEMANTICS_EXPECTED=11
MP_ROUNDS="${S3_CERT_MP_ROUNDS:-20}"
MP_PROCS="${S3_CERT_MP_PROCS:-8}"

ALLOW_DIRTY_ARG=()
if [ -n "${S3_CERT_ALLOW_DIRTY:-}" ]; then
  ALLOW_DIRTY_ARG=(--allow-dirty)
fi

# --- R6-EVID-01: clean-tree gate BEFORE any execution ---------------------
# Evidence must be produced from a checkout whose executable inputs are
# committed. The same gate runs again inside seal-bundle.py.
python3 "$HERE/seal-bundle.py" --preflight --repo "$REPO" "${ALLOW_DIRTY_ARG[@]}"

EVIDENCE_DIR="${S3_CERT_EVIDENCE_DIR:-$HERE/evidence/run-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
mkdir -p "$EVIDENCE_DIR"
EVIDENCE_DIR="$(cd "$EVIDENCE_DIR" && pwd)"
PHASES_TSV="$EVIDENCE_DIR/phases.tsv"
: > "$PHASES_TSV"
COMMANDS="$EVIDENCE_DIR/commands.jsonl"
: > "$COMMANDS"

SERVER_PID=""
cleanup() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -9 -- -"$SERVER_PID" 2>/dev/null || kill -9 "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

record_phase() { # name exit_code log_file detail
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$PHASES_TSV"
}

# record_cmd LABEL argv... — the argv log the bundle binds (R6-EVID-01)
record_cmd() {
  local label="$1"; shift
  python3 - "$COMMANDS" "$label" "$PWD" "$@" <<'PY'
import json, sys
out, label, cwd, *argv = sys.argv[1:]
with open(out, "a") as fh:
    fh.write(json.dumps({"label": label, "cwd": cwd, "argv": argv}) + "\n")
PY
}

server_bin() {
  case "$PROVIDER" in
    minio)
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
      # may only ever cite the exact pinned binary.
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
      record_cmd start-server "$bin" server "$DATA" --address "127.0.0.1:$PORT" --console-address "127.0.0.1:0"
      MINIO_ROOT_USER="$ACCESS" MINIO_ROOT_PASSWORD="$SECRET" \
        setsid "$bin" server "$DATA" --address "127.0.0.1:$PORT" --console-address "127.0.0.1:0" \
        > "$WORK/server.log" 2>&1 &
      SERVER_PID=$!
      ;;
    rustfs)
      record_cmd start-server "$bin" --address "127.0.0.1:$PORT" "$DATA"
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

SERVER_BIN_PATH="$(server_bin)"
SERVER_BIN_SHA256="$(sha256sum "$SERVER_BIN_PATH" | cut -d' ' -f1)"

echo "corpus: provider=$PROVIDER port=$PORT work=$WORK evidence=$EVIDENCE_DIR"
start_server
record_cmd create-bucket python3 "$HERE/s3op.py" "http://127.0.0.1:$PORT" create-bucket "$BUCKET"
AWS_ACCESS_KEY_ID="$ACCESS" AWS_SECRET_ACCESS_KEY="$SECRET" \
  python3 "$HERE/s3op.py" "http://127.0.0.1:$PORT" create-bucket "$BUCKET"

export S3_CERT_ENDPOINT="http://127.0.0.1:$PORT"
export S3_CERT_BUCKET="$BUCKET"
export S3_CERT_ACCESS_KEY="$ACCESS"
export S3_CERT_SECRET_KEY="$SECRET"

echo "corpus: building test + racer binaries"
record_cmd build-tests cargo +1.93.0 test --manifest-path "$HERE/Cargo.toml" --locked --no-run
cargo +1.93.0 test --manifest-path "$HERE/Cargo.toml" --locked --no-run >/dev/null 2>&1

# --- R6-EVID-01: resolve cargo output paths from cargo, never hardcoded ---
CARGO_TARGET_DIR_EFFECTIVE="$(cargo +1.93.0 metadata --format-version 1 --no-deps \
  --manifest-path "$HERE/Cargo.toml" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
record_cmd build-racer cargo +1.93.0 build --manifest-path "$HERE/Cargo.toml" --bin cas_racer --locked --message-format=json
RACER="$(cargo +1.93.0 build --manifest-path "$HERE/Cargo.toml" --bin cas_racer --locked \
  --message-format=json 2>/dev/null \
  | python3 -c '
import json, sys
exe = ""
for line in sys.stdin:
    line = line.strip()
    if not line.startswith("{"):
        continue
    try:
        msg = json.loads(line)
    except ValueError:
        continue
    if (msg.get("reason") == "compiler-artifact" and msg.get("executable")
            and msg.get("target", {}).get("name") == "cas_racer"):
        exe = msg["executable"]
print(exe)
')"
if [ -z "$RACER" ]; then
  # cargo emitted no artifact message (e.g. an older cargo): fall back to the
  # metadata-reported target directory — still never a hardcoded path.
  RACER="$CARGO_TARGET_DIR_EFFECTIVE/debug/cas_racer"
fi
if [ ! -x "$RACER" ]; then
  echo "corpus: cas_racer not executable at '$RACER' (effective CARGO_TARGET_DIR=$CARGO_TARGET_DIR_EFFECTIVE)" >&2
  echo "corpus: refusing to run the multi-process CAS phase without the racer — a missing racer would report 0 winners / N process errors and read as a provider failure" >&2
  exit 2
fi
RACER_SHA256="$(sha256sum "$RACER" | cut -d' ' -f1)"
echo "corpus: cas_racer $RACER ($RACER_SHA256, target_dir=$CARGO_TARGET_DIR_EFFECTIVE)"

echo "corpus: phase 1 (semantics incl. hardened barrier races)"
record_cmd phase1-semantics cargo +1.93.0 test --manifest-path "$HERE/Cargo.toml" --locked -- --test-threads=4
set +e
S3_CERT_PHASE=semantics cargo +1.93.0 test --manifest-path "$HERE/Cargo.toml" --locked -- --test-threads=4 \
  > "$EVIDENCE_DIR/phase1.log" 2>&1
PH1=$?
set -e
tail -3 "$EVIDENCE_DIR/phase1.log"
grep -q "test result: ok. $SEMANTICS_EXPECTED passed" "$EVIDENCE_DIR/phase1.log" || {
  echo "corpus: phase 1 did not execute the full $SEMANTICS_EXPECTED-test corpus green" >&2
  record_phase semantics 1 phase1.log "expected $SEMANTICS_EXPECTED passed"
  exit 1; }
record_phase semantics "$PH1" phase1.log "$SEMANTICS_EXPECTED tests"

echo "corpus: phase 1b (multi-process CAS: $MP_ROUNDS rounds x $MP_PROCS processes)"
MP_LOG="$EVIDENCE_DIR/phase1b.log"
MP_ROUNDS_TSV="$WORK/mp-rounds.tsv"
: > "$MP_LOG"
: > "$MP_ROUNDS_TSV"
record_cmd phase1b-racer "$RACER" '<key>' '<worker>' '<barrier-file>'
for r in $(seq 1 "$MP_ROUNDS"); do
  KEY="cert/mp-cas/round-$r-$RANDOM"
  START="$WORK/start-$r"
  pids=()
  for w in $(seq 1 "$MP_PROCS"); do
    "$RACER" "$KEY" "$w" "$START" >> "$MP_LOG" 2>&1 &
    pids+=($!)
  done
  # every racer is now polling for the barrier; release them together
  sleep 0.3
  touch "$START"
  winners=0; losers=0; overwrites=0; errors=0
  for pid in "${pids[@]}"; do
    set +e; wait "$pid"; rc=$?; set -e
    case $rc in
      0) winners=$((winners+1)) ;;
      3) losers=$((losers+1)) ;;
      4) overwrites=$((overwrites+1)) ;;
      *) errors=$((errors+1)) ;;
    esac
  done
  echo "round $r: winners=$winners losers=$losers overwrites=$overwrites errors=$errors" >> "$MP_LOG"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$r" "$KEY" "$winners" "$losers" "$overwrites" "$errors" \
    >> "$MP_ROUNDS_TSV"
  if [ "$overwrites" -ne 0 ]; then
    echo "corpus: CHANGED-BYTE OVERWRITE in multi-process CAS round $r — provider fails conditional create" >&2
    record_phase mp-cas 1 phase1b.log "overwrite at round $r"
    exit 1
  fi
  if [ "$errors" -ne 0 ]; then
    echo "corpus: $errors racer PROCESS ERRORS in round $r — the CAS evidence is degraded, not a provider verdict (racer=$RACER)" >&2
    record_phase mp-cas 1 phase1b.log "round $r process errors=$errors"
    exit 1
  fi
  if [ "$winners" -ne 1 ] || [ "$losers" -ne $((MP_PROCS-1)) ]; then
    echo "corpus: multi-process CAS round $r: winners=$winners losers=$losers (want 1/$((MP_PROCS-1)))" >&2
    record_phase mp-cas 1 phase1b.log "round $r winners=$winners losers=$losers errors=$errors"
    exit 1
  fi
done

# structured mp-cas result (R6-EVID-01: not a grep over prose)
python3 - "$MP_ROUNDS_TSV" "$EVIDENCE_DIR/phase1b.json" "$MP_PROCS" "$RACER" "$RACER_SHA256" <<'PY'
import json, sys
tsv, out, procs, racer, racer_sha = sys.argv[1:6]
rounds = []
with open(tsv) as fh:
    for line in fh:
        if not line.strip():
            continue
        r, key, w, l, o, e = line.rstrip("\n").split("\t")
        rounds.append({"round": int(r), "key": key, "winners": int(w), "losers": int(l),
                       "overwrites": int(o), "errors": int(e)})
with open(out, "w") as fh:
    json.dump({"kind": "mp-cas", "procs": int(procs), "racer_path": racer,
               "racer_sha256": racer_sha, "rounds": rounds}, fh, indent=1)
    fh.write("\n")
PY
record_phase mp-cas 0 phase1b.log "$MP_ROUNDS rounds x $MP_PROCS procs, one winner each, zero overwrites, zero process errors"

echo "corpus: CRASH BARRIER (kill -9 the server process group)"
CRASH_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
OLD_PID="$SERVER_PID"
kill -9 -- -"$SERVER_PID" 2>/dev/null || kill -9 "$SERVER_PID"
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""
sleep 1

echo "corpus: restart over the same data directory"
start_server
record_phase crash-restart 0 server.log "kill -9 pid=$OLD_PID at $CRASH_AT; restarted pid=$SERVER_PID"
cp "$WORK/server.log" "$EVIDENCE_DIR/server.log" 2>/dev/null || true

echo "corpus: phase 2 (post-restart persistence)"
record_cmd phase2-post-restart cargo +1.93.0 test --manifest-path "$HERE/Cargo.toml" --locked persisted_objects_survive_server_crash_restart -- --test-threads=1
set +e
S3_CERT_PHASE=post-restart cargo +1.93.0 test --manifest-path "$HERE/Cargo.toml" --locked \
  persisted_objects_survive_server_crash_restart -- --test-threads=1 \
  > "$EVIDENCE_DIR/phase2.log" 2>&1
PH2=$?
set -e
tail -3 "$EVIDENCE_DIR/phase2.log"
grep -q "test result: ok. 1 passed" "$EVIDENCE_DIR/phase2.log" || {
  echo "corpus: post-restart persistence phase failed" >&2
  record_phase post-restart 1 phase2.log "witness re-read failed"
  exit 1; }
record_phase post-restart "$PH2" phase2.log "witnesses byte-exact after kill -9"

# --- R5-LOCAL-03 + R6-EVID-01: sealed, source-bound evidence bundle -------
record_cmd seal python3 "$HERE/seal-bundle.py" "$EVIDENCE_DIR" --provider "$PROVIDER"
python3 "$HERE/seal-bundle.py" "$EVIDENCE_DIR" \
  --provider "$PROVIDER" \
  --server-bin "$SERVER_BIN_PATH" --server-sha256 "$SERVER_BIN_SHA256" \
  --endpoint "http://127.0.0.1:$PORT" \
  --repo "$REPO" \
  --racer "$RACER" \
  --cargo-target-dir "$CARGO_TARGET_DIR_EFFECTIVE" \
  --semantics-expected "$SEMANTICS_EXPECTED" \
  --mp-rounds "$MP_ROUNDS" --mp-procs "$MP_PROCS" \
  "${ALLOW_DIRTY_ARG[@]}"

VERIFY_ARGS=()
if [ -n "${S3_CERT_ALLOW_DIRTY:-}" ]; then
  VERIFY_ARGS=(--allow-non-qualification)
fi
python3 "$HERE/verify-bundle.py" "$EVIDENCE_DIR" "${VERIFY_ARGS[@]}"

echo "CORPUS: PASS (provider=$PROVIDER — $SEMANTICS_EXPECTED semantic tests incl. hardened races, $MP_ROUNDS multi-process CAS rounds, crash/restart persistence; sealed bundle: $EVIDENCE_DIR)"
