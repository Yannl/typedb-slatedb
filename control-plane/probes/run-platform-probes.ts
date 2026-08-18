/*
 * Platform probe runner — the release-gate entrypoint for the 14
 * normative probes in contract/typedb-r2-v16-platform-probes.md.
 *
 * This runner replaces the pre-audit run-r2-probes.ts, which the external
 * audit (finding C-P0-10) proved false-green. The fix is structural:
 *
 *   - a manifest completeness gate: a run that cannot account for every
 *     one of the 14 normative probe IDs is itself a FAIL (exit 1);
 *   - an ASSERTION PLAN (round-3 P-05): every probe declares its
 *     assertion ids with required_in modes; plan.json is written before
 *     results; a declared assertion required in the current mode with no
 *     recorded result fails the probe, and a free-form note can never
 *     satisfy one;
 *   - fail-closed verdict aggregation: exit 0 ONLY when every manifest
 *     probe is PASS; missing credentials => PREREQUISITE_MISSING (exit 3);
 *     any FAIL or NOT_RUN => exit 1;
 *   - deadlines at every level (round-3 P-04): per-request (recording
 *     provider + AbortSignal), per-probe, and per-run — a wedged probe
 *     becomes a recorded FAIL, never a hung process;
 *   - cleanup executes in a finally and writes its own evidence records
 *     (cleanup.json), whatever happened before it;
 *   - real mode runs the P-06 preflight first: non-disposable targets are
 *     refused and a missing owner-approved numeric envelope is RED
 *     (PREREQUISITE_MISSING, exit 3) — limits are never guessed;
 *   - a sealed, content-addressed PlatformRunBundle v2 per run
 *     (COMPLETE written last, over the sha256 of every artifact).
 *
 * Usage:
 *   node --experimental-strip-types run-platform-probes.ts            real mode
 *   ... --mock                                deterministic fake, no creds
 *   ... --mock --fault P-R2-01:precondition-ignored   force one probe red
 *   ... --mock-500                            audit counterexample: every
 *                                             response HTTP 500 (must exit 1)
 *   ... --mock --only P-R2-01                 subset run (completeness gate
 *                                             makes this exit 1 by design)
 *   ... --list-fault-controls                 print "<id>:<fault>" per probe
 *   ... --evidence-root <dir>                 override the evidence root
 *   ... --probe-deadline-ms N / --run-deadline-ms N   tighten deadlines
 */

import { realpathSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { NORMATIVE_PROBE_COUNT, PROBE_MANIFEST } from "./manifest.ts";
import type { ManifestEntry, ProbeVerdict } from "./manifest.ts";
import { EvidenceBundle, fileSha256, gitDirtyCount, gitHead, RecordingProvider } from "./evidence.ts";
import type { CheckRecord, ProbeEvidence } from "./evidence.ts";
import { MockPlatformProvider } from "./mock-provider.ts";
import type { PlatformProvider } from "./provider.ts";
import { randomHex, realConfigFromEnv, RealPlatformProvider, utf8 } from "./provider.ts";
import type { ProbeContext, ProbeImpl } from "./probe.ts";
import { R2_PROBES } from "./probes-r2.ts";
import { DO_PROBES } from "./probes-do.ts";
import { CTR_PROBES, WORKER_PROBES } from "./probes-ctr.ts";
import { runPreflight } from "./preflight.ts";
import type { PreflightResult } from "./preflight.ts";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const DEFAULT_EVIDENCE_ROOT = join(REPO_ROOT, "docs/evidence/G1-platform/runs");

/** Implementation registry; cross-checked against the manifest below. */
const REGISTRY: ReadonlyArray<ProbeImpl> = [...R2_PROBES, ...DO_PROBES, ...CTR_PROBES, ...WORKER_PROBES];

/** Runner-injected failure id (deadlines, thrown errors, out-of-plan). */
const RUNNER_ASSERTION = "__runner__";

// ---------------------------------------------------------------------------
// CLI parsing (fail-closed: unknown flags and malformed values are usage
// errors, exit 2 — never silently ignored).
// ---------------------------------------------------------------------------

interface CliOptions {
  mock: boolean;
  mock500: boolean;
  faults: Map<string, string>;
  only: Set<string> | null;
  evidenceRoot: string;
  listFaultControls: boolean;
  probeDeadlineMs: number;
  runDeadlineMs: number;
}

function usageError(msg: string): never {
  console.error(`usage error: ${msg}`);
  process.exit(2);
}

function parsePositiveInt(value: string | undefined, flag: string): number {
  if (value === undefined) usageError(`${flag} requires a positive integer`);
  const n = Number(value);
  if (!Number.isInteger(n) || n <= 0) usageError(`${flag} requires a positive integer, got '${value}'`);
  return n;
}

function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = {
    mock: false,
    mock500: false,
    faults: new Map(),
    only: null,
    evidenceRoot: DEFAULT_EVIDENCE_ROOT,
    listFaultControls: false,
    probeDeadlineMs: 120_000,
    runDeadlineMs: 900_000,
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    switch (arg) {
      case "--mock":
        opts.mock = true;
        break;
      case "--mock-500":
        opts.mock = true;
        opts.mock500 = true;
        break;
      case "--fault": {
        const spec = argv[++i] ?? usageError("--fault requires <probe-id>:<fault>");
        const sep = spec.indexOf(":");
        if (sep <= 0) usageError(`malformed --fault '${spec}', expected <probe-id>:<fault>`);
        const id = spec.slice(0, sep);
        const fault = spec.slice(sep + 1);
        const entry = PROBE_MANIFEST.find((e) => e.id === id);
        if (!entry) usageError(`--fault names unknown probe '${id}'`);
        if (entry.mockFault !== fault) {
          usageError(`unknown fault '${fault}' for ${id} (known: ${entry.mockFault})`);
        }
        opts.faults.set(id, fault);
        break;
      }
      case "--only": {
        const spec = argv[++i] ?? usageError("--only requires a comma-separated probe-id list");
        opts.only = new Set(spec.split(",").map((s) => s.trim()).filter((s) => s.length > 0));
        for (const id of opts.only) {
          if (!PROBE_MANIFEST.some((e) => e.id === id)) usageError(`--only names unknown probe '${id}'`);
        }
        break;
      }
      case "--evidence-root":
        opts.evidenceRoot = argv[++i] ?? usageError("--evidence-root requires a directory");
        break;
      case "--probe-deadline-ms":
        opts.probeDeadlineMs = parsePositiveInt(argv[++i], "--probe-deadline-ms");
        break;
      case "--run-deadline-ms":
        opts.runDeadlineMs = parsePositiveInt(argv[++i], "--run-deadline-ms");
        break;
      case "--list-fault-controls":
        opts.listFaultControls = true;
        break;
      default:
        usageError(`unknown argument '${arg}'`);
    }
  }
  if (opts.faults.size > 0 && !opts.mock) usageError("--fault requires --mock");
  return opts;
}

// ---------------------------------------------------------------------------
// Manifest completeness gate.
// ---------------------------------------------------------------------------

/**
 * Validate manifest/registry integrity BEFORE running anything. Returns
 * the list of violations; any violation makes the whole run invalid
 * (exit 1) — a shrunken manifest or an unimplemented probe must never
 * produce a green gate.
 */
export function manifestViolations(
  manifest: ReadonlyArray<ManifestEntry>,
  registry: ReadonlyArray<ProbeImpl>,
): string[] {
  const violations: string[] = [];
  if (manifest.length !== NORMATIVE_PROBE_COUNT) {
    violations.push(
      `manifest lists ${manifest.length} probes but the contract requires exactly ${NORMATIVE_PROBE_COUNT}`,
    );
  }
  const manifestIds = new Set(manifest.map((e) => e.id));
  if (manifestIds.size !== manifest.length) violations.push("manifest contains duplicate probe IDs");
  const registryIds = new Set(registry.map((p) => p.id));
  if (registryIds.size !== registry.length) violations.push("registry contains duplicate probe IDs");
  for (const e of manifest) {
    if (!registryIds.has(e.id)) violations.push(`manifest probe ${e.id} has no implementation`);
  }
  for (const p of registry) {
    if (!manifestIds.has(p.id)) violations.push(`implemented probe ${p.id} is not in the manifest`);
    const ids = new Set(p.assertions.map((a) => a.id));
    if (ids.size !== p.assertions.length) violations.push(`probe ${p.id} declares duplicate assertion ids`);
    if (p.assertions.length === 0) violations.push(`probe ${p.id} declares no assertions (an empty plan proves nothing)`);
  }
  return violations;
}

// ---------------------------------------------------------------------------
// Verdict aggregation.
// ---------------------------------------------------------------------------

/**
 * Fail-closed exit-code computation over the full manifest:
 *   1  if any probe is FAIL or NOT_RUN, or any manifest ID lacks a verdict;
 *   3  else if any probe is PREREQUISITE_MISSING;
 *   0  ONLY when every one of the NORMATIVE_PROBE_COUNT probes is PASS.
 */
export function aggregateExitCode(verdicts: ReadonlyMap<string, ProbeVerdict>): number {
  let prerequisiteMissing = false;
  let passCount = 0;
  for (const entry of PROBE_MANIFEST) {
    const v = verdicts.get(entry.id) ?? "NOT_RUN";
    if (v === "FAIL" || v === "NOT_RUN") return 1;
    if (v === "PREREQUISITE_MISSING") prerequisiteMissing = true;
    if (v === "PASS") passCount += 1;
  }
  if (prerequisiteMissing) return 3;
  // Belt and braces: even if every seen verdict is PASS, the count must
  // equal the normative total; anything else is a failed run.
  return passCount === NORMATIVE_PROBE_COUNT ? 0 : 1;
}

// ---------------------------------------------------------------------------
// Probe execution.
// ---------------------------------------------------------------------------

async function runOneProbe(
  entry: ManifestEntry,
  impl: ProbeImpl,
  provider: PlatformProvider,
  bucket: string,
  runNonce: string,
  parentAccessKeyId: string,
  injectedFault: string | null,
  probeDeadlineMs: number,
): Promise<ProbeEvidence> {
  const startedAt = new Date().toISOString();
  const recording = new RecordingProvider(provider);
  const declared = new Map(impl.assertions.map((a) => [a.id, a]));
  const checks: CheckRecord[] = [];
  const notes: string[] = [];
  const ctx: ProbeContext = {
    fetch: (req) => recording.fetch(req),
    mode: provider.mode,
    bucket,
    runNonce,
    parentAccessKeyId,
    check: (assertionId, ok, detail) => {
      if (!declared.has(assertionId)) {
        // Out-of-plan assertion: recorded as a FAILURE whatever `ok` was —
        // results must be traceable to the published plan.
        checks.push({
          assertion_id: RUNNER_ASSERTION,
          ok: false,
          detail: `probe recorded a check against undeclared assertion id '${assertionId}' (out of plan)`,
        });
        return;
      }
      checks.push({ assertion_id: assertionId, ok, detail });
    },
    note: (msg) => {
      notes.push(msg);
    },
  };
  let deadlineTimer: ReturnType<typeof setTimeout> | undefined;
  try {
    // Per-probe deadline (P-04): a wedged probe becomes a recorded FAIL.
    const deadline = new Promise<never>((_, reject) => {
      deadlineTimer = setTimeout(
        () => reject(new Error(`probe deadline ${probeDeadlineMs}ms exceeded`)),
        probeDeadlineMs,
      );
    });
    await Promise.race([impl.run(ctx), deadline]);
  } catch (err) {
    // A thrown error is never a pass: record it as a failed check.
    checks.push({
      assertion_id: RUNNER_ASSERTION,
      ok: false,
      detail: `unhandled probe error: ${err instanceof Error ? err.message : String(err)}`,
    });
  } finally {
    if (deadlineTimer !== undefined) clearTimeout(deadlineTimer);
  }

  // Coverage (P-05): every assertion required in this mode must have at
  // least one recorded result. A note can never stand in for one.
  const satisfied = new Set(checks.map((c) => c.assertion_id));
  const unsatisfied = impl.assertions
    .filter((a) => a.required_in.includes(provider.mode) && !satisfied.has(a.id))
    .map((a) => a.id);

  const failed = checks.filter((c) => !c.ok);
  // Fail-closed verdict: zero checks proves nothing; unsatisfied required
  // assertions prove the probe silently dropped part of its plan.
  const verdict: ProbeVerdict =
    checks.length > 0 && failed.length === 0 && unsatisfied.length === 0 ? "PASS" : "FAIL";
  const actual =
    checks.length === 0
      ? "probe recorded no assertions (fail-closed)"
      : failed.length > 0
        ? `${failed.length}/${checks.length} checks failed: ${failed.map((c) => `${c.assertion_id}: ${c.detail}`).join(" | ")}`
        : unsatisfied.length > 0
          ? `required assertions not exercised: ${unsatisfied.join(", ")} (a note cannot satisfy them)`
          : `all ${checks.length} checks passed, all required assertions covered`;
  return {
    probe_id: entry.id,
    title: entry.title,
    spec_section: entry.specSection,
    mode: provider.mode,
    injected_fault: injectedFault,
    started_at: startedAt,
    finished_at: new Date().toISOString(),
    verdict,
    expected_outcome: impl.expected,
    actual_outcome: actual,
    checks,
    unsatisfied_required_assertions: unsatisfied,
    exchanges: recording.exchanges,
    notes,
  };
}

function skippedEvidence(
  entry: ManifestEntry,
  impl: ProbeImpl | undefined,
  mode: "real" | "mock",
  verdict: ProbeVerdict,
  reason: string,
): ProbeEvidence {
  const now = new Date().toISOString();
  return {
    probe_id: entry.id,
    title: entry.title,
    spec_section: entry.specSection,
    mode,
    injected_fault: null,
    started_at: now,
    finished_at: now,
    verdict,
    expected_outcome: impl?.expected ?? "(no implementation)",
    actual_outcome: reason,
    checks: [],
    unsatisfied_required_assertions: [],
    exchanges: [],
    notes: [],
  };
}

// ---------------------------------------------------------------------------
// Cleanup (P-04/P-06): executes in the runner's finally, with evidence.
// ---------------------------------------------------------------------------

interface CleanupActionRecord {
  obligation_id: string;
  action: string;
  status: "executed" | "virtual" | "planned-not-executed" | "failed";
  detail: string;
}

async function executeCleanup(
  provider: PlatformProvider,
  bucket: string,
  createdKeys: ReadonlySet<string>,
  preflight: PreflightResult,
): Promise<{ actions: CleanupActionRecord[]; exchanges: unknown[] }> {
  const recording = new RecordingProvider(provider);
  const actions: CleanupActionRecord[] = [];
  // 1. remove probe lock rules (before object deletion, or the lock
  //    itself blocks the deletes).
  try {
    if (provider.capabilities.cfapi) {
      const res = await recording.fetch({
        service: "cfapi",
        method: "PUT",
        path: `/r2/buckets/${bucket}/lock`,
        principal: "admin",
        body: utf8(JSON.stringify({ rules: [] })),
      });
      actions.push({
        obligation_id: "remove-probe-lock-rules",
        action: `PUT /r2/buckets/${bucket}/lock rules:[]`,
        status: res.status === 200 ? "executed" : "failed",
        detail: `status ${res.status}`,
      });
    } else {
      actions.push({
        obligation_id: "remove-probe-lock-rules",
        action: "none",
        status: "planned-not-executed",
        detail: "cfapi not capable in this run",
      });
    }
  } catch (err) {
    actions.push({
      obligation_id: "remove-probe-lock-rules",
      action: "lock reset",
      status: "failed",
      detail: err instanceof Error ? err.message : String(err),
    });
  }
  // 2. delete every object this run created.
  let deleted = 0;
  let failures = 0;
  for (const key of [...createdKeys].sort()) {
    try {
      const res = await recording.fetch({ service: "r2", method: "DELETE", path: key });
      if (res.status === 204 || res.status === 404) deleted += 1;
      else failures += 1;
    } catch {
      failures += 1;
    }
  }
  actions.push({
    obligation_id: "delete-run-objects",
    action: `DELETE ${createdKeys.size} run-created objects`,
    status: failures === 0 ? (provider.mode === "mock" ? "virtual" : "executed") : "failed",
    detail: `deleted ${deleted}, failed ${failures}`,
  });
  // 3./4. obligations that only apply to a live run are recorded, not
  //       silently dropped.
  actions.push({
    obligation_id: "verify-bucket-empty",
    action: "LIST before first write",
    status: provider.mode === "mock" ? "virtual" : "planned-not-executed",
    detail:
      provider.mode === "mock"
        ? "in-process fake starts empty by construction"
        : "no live run occurred (preflight verdict: " + preflight.verdict + ")",
  });
  actions.push({
    obligation_id: "credential-expiry",
    action: "record ttlSeconds of minted temporary credentials",
    status: provider.mode === "mock" ? "virtual" : "planned-not-executed",
    detail: "mints use ttlSeconds=900; there is no revocation API — expiry is the bound",
  });
  return { actions, exchanges: recording.exchanges };
}

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------

export async function main(argv: string[]): Promise<number> {
  const opts = parseArgs(argv);

  if (opts.listFaultControls) {
    // Self-test support: one canonical injectable fault per probe.
    for (const entry of PROBE_MANIFEST) console.log(`${entry.id}:${entry.mockFault}`);
    return 0;
  }

  // --- completeness gate: refuse to run from a broken manifest ---
  const violations = manifestViolations(PROBE_MANIFEST, REGISTRY);
  if (violations.length > 0) {
    for (const v of violations) console.error(`RUN-INVALID: ${v}`);
    console.error("platform-probes: manifest completeness check failed; exit 1");
    return 1;
  }
  const implById = new Map(REGISTRY.map((p) => [p.id, p]));

  // --- preflight (P-06): real mode must prove a disposable, approved run ---
  const preflight = runPreflight({ mode: opts.mock ? "mock" : "real", env: process.env });

  // --- provider construction ---
  let provider: PlatformProvider;
  let bucket: string;
  let parentAccessKeyId: string;
  if (opts.mock) {
    provider = new MockPlatformProvider({ faults: opts.faults, force500: opts.mock500 });
    bucket = "mock-bucket";
    parentAccessKeyId = "mock-parent-access-key";
  } else {
    // A dangerous configuration (token reuse, unapproved harness host) was
    // already recorded by preflight as RED/REFUSED; construct a
    // zero-capability provider so the run records PREREQUISITE_MISSING
    // evidence instead of crashing without a bundle.
    let cfg;
    try {
      cfg = realConfigFromEnv(process.env);
    } catch {
      cfg = {};
    }
    const real = new RealPlatformProvider(cfg);
    provider = real;
    bucket = real.bucket ?? "";
    parentAccessKeyId = real.parentAccessKeyId ?? "";
  }
  const runNonce = `${Date.now().toString(36)}-${randomHex(4)}`;

  // --- evidence bundle: unique per run, sealed at the end ---
  const bundle = new EvidenceBundle(opts.evidenceRoot);
  const startedAt = new Date().toISOString();
  const startedMs = Date.now();
  console.log(`platform-probes: run ${bundle.runId} (${provider.mode} mode)`);

  // plan.json is written BEFORE any probe runs: the plan is what results
  // are judged against, not a summary written after the fact.
  bundle.writePlan({
    schema: "platform-probe-plan/v2",
    normative_probe_count: NORMATIVE_PROBE_COUNT,
    note:
      "every assertion id below must have a recorded result in every mode listed in its " +
      "required_in, or its probe FAILs; a free-form probe note can never satisfy a required assertion",
    probes: PROBE_MANIFEST.map((entry) => {
      const impl = implById.get(entry.id);
      return {
        probe_id: entry.id,
        title: entry.title,
        spec_section: entry.specSection,
        requires: entry.requires,
        mock_fault: entry.mockFault,
        assertions: (impl?.assertions ?? []).map((a) => ({
          id: a.id,
          title: a.title,
          required_in: a.required_in,
        })),
      };
    }),
  });

  const verdicts = new Map<string, ProbeVerdict>();
  const probeEvidence: ProbeEvidence[] = [];
  const createdKeys = new Set<string>();
  let cleanupRecord: { actions: CleanupActionRecord[]; exchanges: unknown[] } = { actions: [], exchanges: [] };
  let exitCode = 1; // fail-closed default; only aggregateExitCode may change it
  try {
    if (!opts.mock && preflight.verdict === "RED") {
      // P-06: no live probe executes without every prerequisite. Every
      // probe records PREREQUISITE_MISSING and the run exits 3.
      for (const r of preflight.reasons) console.error(`PREFLIGHT ${r.code}: ${r.detail}`);
      for (const entry of PROBE_MANIFEST) {
        const evidence = skippedEvidence(
          entry,
          implById.get(entry.id),
          provider.mode,
          "PREREQUISITE_MISSING",
          "preflight RED: " + preflight.reasons.map((r) => `${r.code}: ${r.detail}`).join(" | "),
        );
        verdicts.set(entry.id, evidence.verdict);
        probeEvidence.push(evidence);
        bundle.writeProbeEvidence(evidence);
        console.log(`${entry.id}: ${evidence.verdict} — preflight RED`);
      }
    } else {
      for (const entry of PROBE_MANIFEST) {
        const impl = implById.get(entry.id);
        let evidence: ProbeEvidence;
        if (impl === undefined) {
          // Unreachable after the completeness gate, but kept fail-closed.
          evidence = skippedEvidence(entry, impl, provider.mode, "NOT_RUN", "no implementation registered");
        } else if (opts.only !== null && !opts.only.has(entry.id)) {
          evidence = skippedEvidence(entry, impl, provider.mode, "NOT_RUN", "excluded by --only (subset runs never pass the gate)");
        } else if (Date.now() - startedMs > opts.runDeadlineMs) {
          // Per-run deadline (P-04): remaining probes are recorded, not run.
          evidence = skippedEvidence(entry, impl, provider.mode, "NOT_RUN", `run deadline ${opts.runDeadlineMs}ms exceeded before this probe`);
        } else {
          const missing = entry.requires.filter((r) => !provider.capabilities[r]);
          if (missing.length > 0) {
            // No credentials => no execution, never a fabricated one.
            evidence = skippedEvidence(
              entry,
              impl,
              provider.mode,
              "PREREQUISITE_MISSING",
              `missing credentials/capabilities: ${missing.join(", ")} — probe NOT executed (recorded non-execution, not a pass)`,
            );
          } else {
            evidence = await runOneProbe(
              entry,
              impl,
              provider,
              bucket,
              runNonce,
              parentAccessKeyId,
              opts.faults.get(entry.id) ?? null,
              opts.probeDeadlineMs,
            );
            // Track run-created objects for the cleanup pass.
            for (const ex of evidence.exchanges) {
              if (
                ex.request.service === "r2" &&
                (ex.request.method === "PUT" || ex.request.method === "POST") &&
                ex.outcome.type === "success" &&
                ex.outcome.status === 200 &&
                ex.request.path.includes(`/probes/${runNonce}/`)
              ) {
                createdKeys.add(ex.request.path.split("?", 1)[0]);
              }
            }
          }
        }
        verdicts.set(entry.id, evidence.verdict);
        probeEvidence.push(evidence);
        bundle.writeProbeEvidence(evidence);
        console.log(`${entry.id}: ${evidence.verdict} — ${evidence.actual_outcome}`);
      }
    }
    exitCode = aggregateExitCode(verdicts);
  } finally {
    // -----------------------------------------------------------------------
    // Cleanup ALWAYS runs and ALWAYS leaves evidence (P-04): even a crashed
    // run records what it created and what was disposed.
    // -----------------------------------------------------------------------
    try {
      cleanupRecord = await executeCleanup(provider, bucket, createdKeys, preflight);
    } catch (err) {
      cleanupRecord = {
        actions: [
          {
            obligation_id: "cleanup",
            action: "executeCleanup",
            status: "failed",
            detail: err instanceof Error ? err.message : String(err),
          },
        ],
        exchanges: [],
      };
    }
    bundle.writeCleanupRecord({
      schema: "platform-probe-cleanup/v2",
      obligations: preflight.cleanup_obligations,
      actions: cleanupRecord.actions,
      exchanges: cleanupRecord.exchanges,
    });
  }

  // --- run record, verdict, sealed bundle root ---
  const observedVerdicts = Object.fromEntries(verdicts);
  bundle.writeRunRecord({
    schema: "platform-probe-run/v2",
    run_id: bundle.runId,
    started_at: startedAt,
    finished_at: new Date().toISOString(),
    mode: provider.mode,
    source: {
      git_head: gitHead(REPO_ROOT),
      dirty_paths: gitDirtyCount(REPO_ROOT),
    },
    locks: {
      source_lock_sha256: fileSha256(join(REPO_ROOT, "source-lock", "source-lock.json")),
      workspace_lock_sha256: fileSha256(join(REPO_ROOT, "source-lock", "workspace-lock.json")),
    },
    toolchain: { node_version: process.version },
    argv,
    // The deterministic "seed" of a mock run is its fault schedule.
    fault_schedule: { injected_faults: Object.fromEntries(opts.faults), mock_500: opts.mock500 },
    deadlines_ms: { request: 30_000, probe: opts.probeDeadlineMs, run: opts.runDeadlineMs },
    normative_probe_count: NORMATIVE_PROBE_COUNT,
    capabilities: provider.capabilities,
    preflight: {
      verdict: preflight.verdict,
      reasons: preflight.reasons,
      bucket: preflight.bucket,
      envelope_present: preflight.envelope !== null,
    },
    observed_verdicts: observedVerdicts,
    policy_verdict: exitCode === 0 ? "PASS" : exitCode === 3 ? "PREREQUISITE_MISSING" : "FAIL",
  });
  bundle.writeVerdict({
    schema: "platform-probe-verdict/v2",
    policy: `exit 0 only when every one of the ${NORMATIVE_PROBE_COUNT} manifest probes is PASS with full required-assertion coverage; PREREQUISITE_MISSING => 3; anything else => 1`,
    observed_verdicts: observedVerdicts,
    required_assertion_coverage: Object.fromEntries(
      probeEvidence.map((ev) => [
        ev.probe_id,
        {
          checks_recorded: ev.checks.length,
          checks_failed: ev.checks.filter((c) => !c.ok).length,
          unsatisfied_required_assertions: ev.unsatisfied_required_assertions,
        },
      ]),
    ),
    exit_code: exitCode,
    verdict: exitCode === 0 ? "PASS" : exitCode === 3 ? "PREREQUISITE_MISSING" : "FAIL",
  });
  const root = bundle.seal();
  console.log(`platform-probes: evidence bundle ${bundle.runDir}`);
  console.log(`platform-probes: bundle root sha256 ${root}`);

  // -------------------------------------------------------------------------
  // Verdict aggregation (the C-P0-10 fix). This block is the ONLY path to
  // exit code 0: every one of the 14 manifest probes must be PASS.
  // PREREQUISITE_MISSING => 3; any FAIL or NOT_RUN => 1. Removing or
  // bypassing this block is caught by self-test.sh mutant controls.
  // -------------------------------------------------------------------------
  console.log(`platform-probes: aggregated exit code ${exitCode}`);
  return exitCode;
}

// Entry point when executed directly (the wrapper run-r2-probes.ts imports
// main() instead, so this guard keeps a single execution path).
const invokedDirectly = (() => {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return import.meta.url === pathToFileURL(realpathSync(entry)).href;
  } catch {
    return false;
  }
})();

if (invokedDirectly) {
  main(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (err) => {
      // A crashed runner is a failed run, never a silent success.
      console.error("platform-probes: runner crashed:", err);
      process.exitCode = 1;
    },
  );
}
