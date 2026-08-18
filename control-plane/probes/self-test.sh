#!/usr/bin/env bash
#
# Self-test controls for the platform probe harness (audit C-P0-10).
#
# Runs entirely without credentials and proves the harness can turn red:
#
#   control 1: --mock                          => exit 0, all 14 probes PASS
#   control 2: --mock --fault <id>:<fault>     => exit 1 for EVERY probe's
#              canonical fault, with that probe reported FAIL
#   control 3: --mock-500 (the audit's exact counterexample: every
#              response HTTP 500)              => exit 1
#   control 4: --mock --only P-R2-01 (a probe omitted from the run)
#              => exit 1 via the manifest completeness / NOT_RUN gate
#   control 5: real mode with all credentials scrubbed
#              => exit 3 (PREREQUISITE_MISSING), never 0
#
# Exits nonzero if ANY control fails. Evidence bundles for these control
# runs are written to a throwaway directory, not the repo evidence tree.

set -u

cd "$(dirname "$0")"

RUNNER="run-platform-probes.ts"
NODE=(node --experimental-strip-types --no-warnings)
EVIDENCE_ROOT="$(mktemp -d)"
trap 'rm -rf "$EVIDENCE_ROOT"' EXIT

failures=0
controls=0

# run <expected-exit> <output-file> <args...>
run_control() {
  local expected="$1" out="$2"
  shift 2
  controls=$((controls + 1))
  "${NODE[@]}" "$RUNNER" --evidence-root "$EVIDENCE_ROOT" "$@" >"$out" 2>&1
  local actual=$?
  if [ "$actual" -ne "$expected" ]; then
    echo "CONTROL FAILED: '$*' exited $actual, expected $expected"
    sed 's/^/    | /' "$out"
    failures=$((failures + 1))
    return 1
  fi
  return 0
}

# --- control 1: mock all-pass run -----------------------------------------
out="$EVIDENCE_ROOT/control1.log"
if run_control 0 "$out" --mock; then
  pass_count=$(grep -c '^P-[A-Z0-9-]*: PASS' "$out")
  if [ "$pass_count" -ne 14 ]; then
    echo "CONTROL FAILED: --mock printed $pass_count PASS lines, expected 14"
    failures=$((failures + 1))
  elif grep -q 'FAIL\|NOT_RUN\|PREREQUISITE_MISSING' "$out"; then
    echo "CONTROL FAILED: --mock printed a non-PASS verdict"
    failures=$((failures + 1))
  else
    # The evidence bundle must be sealed (COMPLETE written last).
    complete_count=$(find "$EVIDENCE_ROOT" -name COMPLETE | wc -l)
    if [ "$complete_count" -lt 1 ]; then
      echo "CONTROL FAILED: --mock run left no sealed COMPLETE evidence file"
      failures=$((failures + 1))
    else
      echo "control 1 ok: --mock => exit 0, 14/14 PASS, sealed evidence bundle"
    fi
  fi
fi

# --- control 2: every probe's canonical fault must turn the run red -------
fault_controls=$("${NODE[@]}" "$RUNNER" --list-fault-controls)
if [ "$(printf '%s\n' "$fault_controls" | wc -l)" -ne 14 ]; then
  echo "CONTROL FAILED: --list-fault-controls did not list 14 faults"
  failures=$((failures + 1))
fi
for spec in $fault_controls; do
  probe_id="${spec%%:*}"
  out="$EVIDENCE_ROOT/fault-$probe_id.log"
  if run_control 1 "$out" --mock --fault "$spec"; then
    if ! grep -q "^$probe_id: FAIL" "$out"; then
      echo "CONTROL FAILED: fault $spec exited 1 but $probe_id was not reported FAIL"
      failures=$((failures + 1))
    else
      echo "control 2 ok: fault $spec => exit 1, $probe_id FAIL"
    fi
  fi
done

# --- control 3: the audit's all-HTTP-500 counterexample -------------------
out="$EVIDENCE_ROOT/control3.log"
if run_control 1 "$out" --mock-500; then
  echo "control 3 ok: --mock-500 (every response HTTP 500) => exit 1"
fi

# --- control 4: omitting probes from the run must fail completeness -------
out="$EVIDENCE_ROOT/control4.log"
if run_control 1 "$out" --mock --only P-R2-01; then
  if ! grep -q 'NOT_RUN' "$out"; then
    echo "CONTROL FAILED: --only run exited 1 but reported no NOT_RUN verdict"
    failures=$((failures + 1))
  else
    echo "control 4 ok: --mock --only P-R2-01 => exit 1 (13 probes NOT_RUN)"
  fi
fi

# --- control 5: real mode without credentials => PREREQUISITE_MISSING ------
out="$EVIDENCE_ROOT/control5.log"
controls=$((controls + 1))
env -u R2_ACCOUNT_ID -u R2_ACCESS_KEY_ID -u R2_SECRET_ACCESS_KEY -u R2_PROBE_BUCKET \
    -u CF_ACCOUNT_ID -u CF_API_TOKEN -u CF_PROBE_HARNESS_URL \
    "${NODE[@]}" "$RUNNER" --evidence-root "$EVIDENCE_ROOT" >"$out" 2>&1
actual=$?
if [ "$actual" -ne 3 ]; then
  echo "CONTROL FAILED: credential-less real mode exited $actual, expected 3"
  sed 's/^/    | /' "$out"
  failures=$((failures + 1))
else
  echo "control 5 ok: real mode without credentials => exit 3 (PREREQUISITE_MISSING)"
fi

echo
if [ "$failures" -ne 0 ]; then
  echo "self-test: $failures control(s) FAILED out of $controls"
  exit 1
fi
echo "self-test: all $controls controls passed"
exit 0
