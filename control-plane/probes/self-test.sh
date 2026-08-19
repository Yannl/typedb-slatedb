#!/usr/bin/env bash
#
# Self-test controls for the platform probe harness (audit C-P0-10,
# round-3 P-01/P-04/P-05/P-06).
#
# Runs entirely without credentials and proves the harness can turn red:
#
#   control 1: --mock                          => exit 0, all 14 probes PASS,
#              sealed PlatformRunBundle v2 (plan.json, probes/<id>.json,
#              run.json, cleanup.json, artifacts.json, VERDICT.json, COMPLETE)
#   control 2: --mock --fault <id>:<fault>     => exit 1 for EVERY probe's
#              canonical fault, with that probe reported FAIL
#   control 3: --mock-500 (the audit's exact counterexample: every
#              response HTTP 500)              => exit 1
#   control 4: --mock --only P-R2-01 (a probe omitted from the run)
#              => exit 1 via the manifest completeness / NOT_RUN gate
#   control 5: real mode with all credentials scrubbed
#              => exit 3 (PREREQUISITE_MISSING via P-06 preflight), never 0
#   control 6: P-01 executed mutant — the mock's temp credentials are
#              canary-valued (AKIACANARY…/MOCKSECRETCANARY…); a recursive
#              grep over EVERY evidence bundle produced above must find
#              ZERO canaries (redaction is applied before serialization)
#   control 7: the P-04 recording/deadline suite (intent-before-dispatch,
#              typed outcome in finally for throw/reject/never-resolving)
#   control 8: P-06 preflight CLI — mock preflight exits 0; real preflight
#              without prerequisites exits 3
#   control 9: R4-CF-04 obligation manifest — obligations.ts exact-set
#              reconciles against the probe registry, the mock bundle
#              carries obligations.json with every obligation resolved,
#              and VERDICT.json states the HONEST product_conformance
#              sub-verdict: status OPEN with exactly the three open
#              product obligations (runtime-cannot-delete,
#              ambiguity-resolution-real,
#              attempt-identity-changed-bytes-real) — a 14/14 probe PASS
#              must never read as contract proof
#   control 10: R4-CF-02 probe-harness Worker suite — the in-repo
#              deployable harness (harness-worker.ts) refuses missing/
#              wrong bearer tokens, serves build identity on
#              /harness/health, answers the P-DO-01/P-CTR-01 path
#              contracts, persists its durable slices, and labels
#              simulated behavior
#
# Exits nonzero if ANY control fails. Evidence bundles for these control
# runs are written to a throwaway directory (or, when
# PROBE_SELFTEST_EVIDENCE_DIR is set — as CI does for the secret canary
# scanner — to that directory, which is then left in place for scanning).
#
# npm-script entry points (package.json):
#   probes:selftest         -> this script
#   probes:platform         -> probes/run-platform-probes.ts
#   probes:preflight        -> probes/preflight.ts (P-06)
#   probes:recording-tests  -> probes/recording.test.ts (P-04/P-01)

set -u

cd "$(dirname "$0")"

RUNNER="run-platform-probes.ts"
NODE=(node --experimental-strip-types --no-warnings)
if [ -n "${PROBE_SELFTEST_EVIDENCE_DIR:-}" ]; then
  EVIDENCE_ROOT="$PROBE_SELFTEST_EVIDENCE_DIR"
  mkdir -p "$EVIDENCE_ROOT"
else
  EVIDENCE_ROOT="$(mktemp -d)"
  trap 'rm -rf "$EVIDENCE_ROOT"' EXIT
fi

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

# --- control 1: mock all-pass run + sealed v2 bundle ----------------------
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
    # The v2 bundle must be complete: every schema file present, 14 probe
    # records under probes/, and the COMPLETE seal written last.
    run_dir=$(sed -n 's/^platform-probes: evidence bundle //p' "$out" | head -1)
    CONTROL1_RUN_DIR="$run_dir"
    bundle_ok=1
    for f in run.json plan.json cleanup.json obligations.json artifacts.json VERDICT.json COMPLETE; do
      if [ ! -f "$run_dir/$f" ]; then
        echo "CONTROL FAILED: --mock bundle is missing $f"
        bundle_ok=0
      fi
    done
    probe_files=$(find "$run_dir/probes" -name 'P-*.json' 2>/dev/null | wc -l)
    if [ "$probe_files" -ne 14 ]; then
      echo "CONTROL FAILED: --mock bundle has $probe_files probes/<id>.json files, expected 14"
      bundle_ok=0
    fi
    if ! grep -q '"required_in"' "$run_dir/plan.json"; then
      echo "CONTROL FAILED: plan.json carries no required_in assertion modes"
      bundle_ok=0
    fi
    if [ "$bundle_ok" -eq 1 ]; then
      echo "control 1 ok: --mock => exit 0, 14/14 PASS, sealed v2 bundle (plan/probes/run/cleanup/artifacts/VERDICT/COMPLETE)"
    else
      failures=$((failures + 1))
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
    -u CF_ACCOUNT_ID -u CF_API_TOKEN -u CF_RUNTIME_API_TOKEN \
    -u CF_PROBE_HARNESS_URL -u CF_PROBE_HARNESS_TOKEN -u CF_PROBE_HARNESS_ALLOWED_HOSTS \
    -u R2_PROBE_OWNERSHIP_NONCE \
    "${NODE[@]}" "$RUNNER" --evidence-root "$EVIDENCE_ROOT" >"$out" 2>&1
actual=$?
if [ "$actual" -ne 3 ]; then
  echo "CONTROL FAILED: credential-less real mode exited $actual, expected 3"
  sed 's/^/    | /' "$out"
  failures=$((failures + 1))
else
  echo "control 5 ok: real mode without credentials => exit 3 (PREREQUISITE_MISSING)"
fi

# --- control 6: P-01 executed mutant — zero canaries in ANY evidence ------
# The mock's minted credentials are deliberately canary-shaped
# (AKIACANARYMOCK…, MOCKSECRETCANARY…, eyJCANARY…). Every bundle written
# above embedded those responses; a single canary in any evidence file
# means the redaction pipeline regressed.
controls=$((controls + 1))
canary_hits=$(grep -RIl -e 'CANARY' -e 'AKIA[0-9A-Z]\{16\}' \
  --include='*.json' --include='COMPLETE' "$EVIDENCE_ROOT" 2>/dev/null | wc -l)
if [ "$canary_hits" -ne 0 ]; then
  echo "CONTROL FAILED: $canary_hits evidence file(s) contain credential canaries:"
  grep -RIl -e 'CANARY' -e 'AKIA[0-9A-Z]\{16\}' --include='*.json' --include='COMPLETE' "$EVIDENCE_ROOT" | sed 's/^/    | /'
  failures=$((failures + 1))
else
  echo "control 6 ok: zero credential canaries across every evidence bundle (recursive grep)"
fi

# --- control 7: P-04 recording/deadline suite -----------------------------
out="$EVIDENCE_ROOT/control7.log"
controls=$((controls + 1))
if "${NODE[@]}" --test recording.test.ts >"$out" 2>&1; then
  echo "control 7 ok: recording/deadline suite (intent-before-dispatch, typed outcomes, redaction mutants)"
else
  echo "CONTROL FAILED: recording.test.ts failed"
  sed 's/^/    | /' "$out"
  failures=$((failures + 1))
fi

# --- control 7b: R4-CF-00/01/03 destructive-stop mutants ------------------
# The round-4 audit's exact reproduced counterexample (RED preflight run
# with dummy credentials against a forbidden bucket name issued one real
# PUT .../lock rules:[]) plus the envelope-budget, lock-baseline-conflict,
# post-deadline-refusal and seal-scanner mutants. All must be inert/typed.
out="$EVIDENCE_ROOT/control7b.log"
controls=$((controls + 1))
if "${NODE[@]}" --test runner-safety.test.ts >"$out" 2>&1; then
  echo "control 7b ok: destructive-stop mutants (RED=>zero calls, lock baseline restore, envelope budget, seal scanner)"
else
  echo "CONTROL FAILED: runner-safety.test.ts failed"
  sed 's/^/    | /' "$out"
  failures=$((failures + 1))
fi

# --- control 8: P-06 preflight CLI ----------------------------------------
out="$EVIDENCE_ROOT/control8.log"
controls=$((controls + 1))
"${NODE[@]}" preflight.ts --mock >"$out" 2>&1
mock_pf=$?
env -u R2_ACCOUNT_ID -u R2_ACCESS_KEY_ID -u R2_SECRET_ACCESS_KEY -u R2_PROBE_BUCKET \
    -u CF_ACCOUNT_ID -u CF_API_TOKEN -u CF_RUNTIME_API_TOKEN \
    -u CF_PROBE_HARNESS_URL -u CF_PROBE_HARNESS_TOKEN -u CF_PROBE_HARNESS_ALLOWED_HOSTS \
    -u R2_PROBE_OWNERSHIP_NONCE \
    "${NODE[@]}" preflight.ts >>"$out" 2>&1
real_pf=$?
if [ "$mock_pf" -ne 0 ] || [ "$real_pf" -ne 3 ]; then
  echo "CONTROL FAILED: preflight exits (mock=$mock_pf, real=$real_pf), expected (0, 3)"
  sed 's/^/    | /' "$out"
  failures=$((failures + 1))
else
  echo "control 8 ok: preflight => mock GREEN (0), real without prerequisites RED (3)"
fi

# --- control 9: R4-CF-04 obligation manifest + honest OPEN sub-verdict ----
# The obligation manifest must exact-set reconcile against the registry,
# the mock bundle must carry obligations.json with every obligation
# resolved, and VERDICT.json must state product_conformance OPEN with
# exactly today's three open product obligations — the honest state.
out="$EVIDENCE_ROOT/control9.log"
controls=$((controls + 1))
if [ -z "${CONTROL1_RUN_DIR:-}" ] || [ ! -f "$CONTROL1_RUN_DIR/obligations.json" ]; then
  echo "CONTROL FAILED: the --mock bundle carries no obligations.json"
  failures=$((failures + 1))
elif RUN_DIR="$CONTROL1_RUN_DIR" "${NODE[@]}" --input-type=module -e '
  import { readFileSync } from "node:fs";
  import { join } from "node:path";
  import { OBLIGATION_MANIFEST, obligationViolations } from "./obligations.ts";
  import { R2_PROBES } from "./probes-r2.ts";
  import { DO_PROBES } from "./probes-do.ts";
  import { CTR_PROBES, WORKER_PROBES } from "./probes-ctr.ts";
  const registry = [...R2_PROBES, ...DO_PROBES, ...CTR_PROBES, ...WORKER_PROBES];
  const violations = obligationViolations(OBLIGATION_MANIFEST, registry);
  if (violations.length > 0) {
    console.error("obligation manifest violations:", violations);
    process.exit(1);
  }
  const dir = process.env.RUN_DIR;
  const obligations = JSON.parse(readFileSync(join(dir, "obligations.json"), "utf8"));
  const verdict = JSON.parse(readFileSync(join(dir, "VERDICT.json"), "utf8"));
  if (obligations.obligations.length !== OBLIGATION_MANIFEST.obligations.length) {
    console.error("obligations.json does not cover the whole manifest");
    process.exit(1);
  }
  const unresolved = obligations.obligations.filter(
    (o) => !["SATISFIED", "OPEN", "NOT-EXERCISED-THIS-MODE"].includes(o.status),
  );
  if (unresolved.length > 0) {
    console.error("unresolved obligation statuses in a green mock run:", unresolved.map((o) => `${o.id}:${o.status}`));
    process.exit(1);
  }
  const pc = verdict.product_conformance;
  if (!pc || pc.status !== "OPEN") {
    console.error("VERDICT.json product_conformance.status must be OPEN today, got:", JSON.stringify(pc));
    process.exit(1);
  }
  const open = [...pc.open_obligations].sort();
  const expected = ["ambiguity-resolution-real", "attempt-identity-changed-bytes-real", "runtime-cannot-delete"];
  if (JSON.stringify(open) !== JSON.stringify(expected)) {
    console.error("open product obligations mismatch:", open, "expected:", expected);
    process.exit(1);
  }
  if (!verdict.provider_facts || verdict.provider_facts.status !== "PASS") {
    console.error("provider_facts should be PASS in a green mock run, got:", JSON.stringify(verdict.provider_facts));
    process.exit(1);
  }
  console.log("obligations reconcile; product_conformance is honestly OPEN:", expected.join(", "));
' >"$out" 2>&1; then
  echo "control 9 ok: obligation manifest reconciles; VERDICT product_conformance=OPEN (runtime-cannot-delete, ambiguity-resolution-real, attempt-identity-changed-bytes-real)"
else
  echo "CONTROL FAILED: obligation manifest / product_conformance honesty check"
  sed 's/^/    | /' "$out"
  failures=$((failures + 1))
fi

# --- control 10: R4-CF-02 probe-harness Worker suite ----------------------
out="$EVIDENCE_ROOT/control10.log"
controls=$((controls + 1))
if "${NODE[@]}" --test harness-worker.test.ts >"$out" 2>&1; then
  echo "control 10 ok: probe-harness Worker (auth refusals, health identity, P-DO-01/P-CTR-01 contracts, durable slices, simulated labels)"
else
  echo "CONTROL FAILED: harness-worker.test.ts failed"
  sed 's/^/    | /' "$out"
  failures=$((failures + 1))
fi

echo
if [ "$failures" -ne 0 ]; then
  echo "self-test: $failures control(s) FAILED out of $controls"
  exit 1
fi
echo "self-test: all $controls controls passed"
exit 0
