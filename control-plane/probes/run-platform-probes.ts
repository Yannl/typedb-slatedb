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
import { budgetFromEnvelope, MeteredProvider, RefusedProvider } from "./envelope.ts";
import { captureLockBaseline, restoreLockBaseline } from "./lock-baseline.ts";
import type { LockBaseline } from "./lock-baseline.ts";
import { SealViolationError } from "./evidence.ts";

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
  /** Envelope path override (mutant tests only; default is the owner file). */
  envelopePath: string | undefined;
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
    envelopePath: undefined,
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
      case "--envelope":
        opts.envelopePath = argv[++i] ?? usageError("--envelope requires a path");
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
    if (err instanceof Error && err.message.startsWith("probe deadline")) {
      // R4-CF-01: Promise.race does not cancel the losing task — closing
      // the recorder does. The raced-out probe's leftover async work gets
      // typed refusals instead of continuing to reach the provider.
      recording.close(`probe ${entry.id} deadline exceeded`);
    }
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
// Cleanup (P-04/P-06/R4-CF-00/R4-CF-01): executes in the runner's finally,
// with evidence. Never `rules:[]`; never a call on a refused run.
// ---------------------------------------------------------------------------

interface CleanupActionRecord {
  obligation_id: string;
  action: string;
  status: "executed" | "virtual" | "planned-not-executed" | "failed" | "conflict" | "refused-zero-authority";
  detail: string;
}

/** Cleanup record for a refused run: zero authority, zero calls, by design. */
function refusedCleanup(preflight: PreflightResult, attempts: number): { actions: CleanupActionRecord[]; exchanges: unknown[] } {
  const detail =
    `preflight ${preflight.verdict}: a refusal path holds zero authority and makes zero external ` +
    `calls, cleanup included (provider attempt count: ${attempts}; anything nonzero fails the run)`;
  return {
    actions: preflight.cleanup_obligations.map((o) => ({
      obligation_id: o.id,
      action: "none",
      status: "refused-zero-authority" as const,
      detail,
    })),
    exchanges: [],
  };
}

async function executeCleanup(
  provider: PlatformProvider,
  bucket: string,
  createdKeys: ReadonlySet<string>,
  attemptedWrites: ReadonlySet<string>,
  preflight: PreflightResult,
  runNonce: string,
  lockBaseline: LockBaseline | null,
  emptyListRecord: CleanupActionRecord,
  mintedCredentialCount: number,
): Promise<{ actions: CleanupActionRecord[]; exchanges: unknown[] }> {
  const recording = new RecordingProvider(provider);
  const actions: CleanupActionRecord[] = [];
  // 1. restore the captured lock baseline (before object deletion, or a
  //    still-active run-owned lock rule blocks the deletes). NEVER
  //    `rules:[]` — the exact pre-run policy is restored, and a
  //    concurrent operator change is a CONFLICT that refuses to write.
  try {
    if (provider.capabilities.cfapi && lockBaseline !== null) {
      const restore = await restoreLockBaseline((req) => recording.fetch(req), lockBaseline, runNonce);
      actions.push({
        obligation_id: "remove-probe-lock-rules",
        action: `restore captured lock baseline on ${bucket} (conservative, run-owned rules only)`,
        status:
          restore.status === "noop"
            ? provider.mode === "mock"
              ? "virtual"
              : "executed"
            : restore.status === "executed" && provider.mode === "mock"
              ? "virtual"
              : restore.status,
        detail: restore.detail,
      });
    } else if (provider.capabilities.cfapi && lockBaseline === null) {
      // Capability existed but no baseline was captured: the run must
      // not guess. This is a failed obligation, never a blind reset.
      actions.push({
        obligation_id: "remove-probe-lock-rules",
        action: "none",
        status: "failed",
        detail: "no lock baseline was captured before the run; refusing to write any lock policy blind",
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
      action: "lock baseline restore",
      status: "failed",
      detail: err instanceof Error ? err.message : String(err),
    });
  }
  // 2. delete every object this run may have created: the union of
  //    observed committed keys, journaled write INTENTS (R4-CF-01:
  //    a timeout-after-commit object is in the journal even though its
  //    200 was never observed), and — real mode — a LIST reconciliation
  //    of the run prefix so provider-side state is the authority.
  const runPrefix = `/${bucket}/probes/${runNonce}/`;
  const toDelete = new Set<string>([...createdKeys, ...[...attemptedWrites].filter((k) => k.startsWith(runPrefix))]);
  if (provider.mode === "real" && provider.capabilities.r2) {
    try {
      const listed = await recording.fetch({
        service: "r2",
        method: "GET",
        path: `/${bucket}?list-type=2&prefix=${encodeURIComponent(`probes/${runNonce}/`)}&max-keys=1000`,
      });
      if (listed.status === 200) {
        const xml = new TextDecoder().decode(listed.body);
        for (const m of xml.matchAll(/<Key>([^<]+)<\/Key>/g)) toDelete.add(`/${bucket}/${m[1]}`);
      } else {
        actions.push({
          obligation_id: "delete-run-objects",
          action: "LIST run prefix for reconciliation",
          status: "failed",
          detail: `prefix LIST returned ${listed.status}; deletion proceeds over journaled keys only`,
        });
      }
    } catch (err) {
      actions.push({
        obligation_id: "delete-run-objects",
        action: "LIST run prefix for reconciliation",
        status: "failed",
        detail: err instanceof Error ? err.message : String(err),
      });
    }
  }
  let deleted = 0;
  let failures = 0;
  for (const key of [...toDelete].sort()) {
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
    action: `DELETE ${toDelete.size} run-owned objects (observed ∪ journaled intents ∪ prefix list)`,
    status: failures === 0 ? (provider.mode === "mock" ? "virtual" : "executed") : "failed",
    detail: `deleted ${deleted}, failed ${failures}`,
  });
  // 3. the empty-bucket LIST record (executed BEFORE the first write in
  //    real mode; virtual in mock) is recorded here so cleanup.json
  //    carries the actual result, never a planned-not-executed stub.
  actions.push(emptyListRecord);
  // 4. credential expiry: the actual mint count from this run's recorded
  //    exchanges, with expiry bounded by ttl.
  actions.push({
    obligation_id: "credential-expiry",
    action: "record minted temporary credentials and their ttl bound",
    status: provider.mode === "mock" ? "virtual" : mintedCredentialCount === 0 ? "executed" : "executed",
    detail:
      `${mintedCredentialCount} temporary credential(s) minted this run; each used ttlSeconds=900 — ` +
      "there is no revocation API, expiry is the bound and it is clamped by preflight to the approved envelope",
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
  const preflight = runPreflight({
    mode: opts.mock ? "mock" : "real",
    env: process.env,
    envelopePath: opts.envelopePath,
  });

  // --- provider construction (R4-CF-00: RED preflight => ZERO authority) ---
  let provider: PlatformProvider;
  let refused: RefusedProvider | null = null;
  let metered: MeteredProvider | null = null;
  let cleanupProvider: PlatformProvider | null = null;
  let bucket: string;
  let parentAccessKeyId: string;
  const knownSecrets: string[] = [];
  let probeDeadlineMs = opts.probeDeadlineMs;
  let runDeadlineMs = opts.runDeadlineMs;
  if (opts.mock) {
    provider = new MockPlatformProvider({ faults: opts.faults, force500: opts.mock500 });
    cleanupProvider = provider;
    bucket = "mock-bucket";
    parentAccessKeyId = "mock-parent-access-key";
  } else if (preflight.verdict === "RED") {
    // R4-CF-00 (dynamically reproduced by the round-4 audit): a refusal
    // path holds ZERO authority. No real provider is ever constructed on
    // a RED preflight; probes AND cleanup see only this refusing stub,
    // which counts (and rejects) every attempted call. The count must be
    // zero at the end of the run or the run itself fails.
    refused = new RefusedProvider(
      "preflight RED: " + preflight.reasons.map((r) => r.code).join(","),
    );
    provider = refused;
    cleanupProvider = refused;
    bucket = preflight.bucket ?? "";
    parentAccessKeyId = "";
  } else {
    // GREEN: the real provider runs ONLY under the enforcing envelope
    // meter (R4-CF-01). A fixed slice of the approved request budget is
    // reserved for cleanup so an exhausted probe budget can still
    // restore state; both meters share the same absolute run deadline.
    const cfg = realConfigFromEnv(process.env);
    for (const s of [cfg.r2?.secret, cfg.cfapi?.adminApiToken, cfg.cfapi?.runtimeApiToken, cfg.harness?.apiToken]) {
      if (s !== undefined) knownSecrets.push(s);
    }
    const real = new RealPlatformProvider(cfg);
    const limits = (preflight.envelope?.limits ?? {}) as Record<string, unknown>;
    const budget = budgetFromEnvelope(limits, Date.now());
    const cleanupRequestReserve = Math.min(64, Math.max(1, Math.ceil(budget.maxTotalRequests / 5)));
    metered = new MeteredProvider(real, {
      ...budget,
      maxTotalRequests: Math.max(0, budget.maxTotalRequests - cleanupRequestReserve),
    });
    cleanupProvider = new MeteredProvider(real, {
      ...budget,
      maxTotalRequests: cleanupRequestReserve,
      maxTotalBytesWritten: Math.min(65_536, budget.maxTotalBytesWritten),
    });
    provider = metered;
    bucket = real.bucket ?? "";
    parentAccessKeyId = real.parentAccessKeyId ?? "";
    // CLI deadlines may only NARROW the approved envelope, never widen it.
    const maxProbeSeconds = limits.max_probe_seconds;
    const maxRunSeconds = limits.max_run_seconds;
    if (typeof maxProbeSeconds === "number") probeDeadlineMs = Math.min(probeDeadlineMs, maxProbeSeconds * 1000);
    if (typeof maxRunSeconds === "number") runDeadlineMs = Math.min(runDeadlineMs, maxRunSeconds * 1000);
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

  // --- real-mode GREEN pre-run gates: empty-bucket LIST before any write,
  //     then the lock-policy baseline snapshot (R4-CF-00) ---
  let lockBaseline: LockBaseline | null = null;
  let runRefusalReason: string | null = null;
  let emptyListRecord: CleanupActionRecord = {
    obligation_id: "verify-bucket-empty",
    action: "LIST before first write",
    status: opts.mock ? "virtual" : "planned-not-executed",
    detail: opts.mock ? "in-process fake starts empty by construction" : "no live run occurred",
  };
  if (!opts.mock && preflight.verdict === "GREEN" && provider.capabilities.r2) {
    try {
      const listed = await provider.fetch({ service: "r2", method: "GET", path: `/${bucket}?list-type=2&max-keys=2` });
      if (listed.status !== 200) {
        runRefusalReason = `pre-run empty-bucket LIST returned ${listed.status}; refusing to write to an unverified bucket`;
        emptyListRecord = { ...emptyListRecord, status: "failed", detail: runRefusalReason };
      } else {
        const keyCount = [...new TextDecoder().decode(listed.body).matchAll(/<Key>/g)].length;
        if (keyCount > 0) {
          runRefusalReason = `target bucket '${bucket}' is NOT empty (${keyCount}+ objects listed); a probe run only ever writes to a fresh disposable bucket`;
          emptyListRecord = { ...emptyListRecord, status: "executed", detail: runRefusalReason };
        } else {
          emptyListRecord = { ...emptyListRecord, status: "executed", detail: "bucket listed empty before the first write" };
        }
      }
    } catch (err) {
      runRefusalReason = `pre-run empty-bucket LIST failed: ${err instanceof Error ? err.message : String(err)}`;
      emptyListRecord = { ...emptyListRecord, status: "failed", detail: runRefusalReason };
    }
    if (runRefusalReason === null && provider.capabilities.cfapi) {
      try {
        lockBaseline = await captureLockBaseline((req) => provider.fetch(req), bucket);
      } catch (err) {
        runRefusalReason = `lock baseline capture failed: ${err instanceof Error ? err.message : String(err)}; a run that cannot prove the pre-run lock policy must not mutate it`;
      }
    }
  } else if (opts.mock) {
    // Mock lane exercises the same baseline machinery (empty by default).
    try {
      lockBaseline = await captureLockBaseline((req) => provider.fetch(req), bucket);
    } catch {
      lockBaseline = null;
    }
  }

  const verdicts = new Map<string, ProbeVerdict>();
  const probeEvidence: ProbeEvidence[] = [];
  const createdKeys = new Set<string>();
  let cleanupRecord: { actions: CleanupActionRecord[]; exchanges: unknown[] } = { actions: [], exchanges: [] };
  let cleanupMutationsRan = false;
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
    } else if (runRefusalReason !== null) {
      // Pre-run gate refused (non-empty bucket / unprovable baseline):
      // zero probes execute, zero mutations happen.
      console.error(`PRE-RUN REFUSAL: ${runRefusalReason}`);
      for (const entry of PROBE_MANIFEST) {
        const evidence = skippedEvidence(
          entry,
          implById.get(entry.id),
          provider.mode,
          "PREREQUISITE_MISSING",
          `pre-run gate refused: ${runRefusalReason}`,
        );
        verdicts.set(entry.id, evidence.verdict);
        probeEvidence.push(evidence);
        bundle.writeProbeEvidence(evidence);
        console.log(`${entry.id}: ${evidence.verdict} — pre-run refusal`);
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
        } else if (Date.now() - startedMs > runDeadlineMs) {
          // Per-run deadline (P-04): remaining probes are recorded, not run.
          evidence = skippedEvidence(entry, impl, provider.mode, "NOT_RUN", `run deadline ${runDeadlineMs}ms exceeded before this probe`);
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
              probeDeadlineMs,
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
    // Cleanup ALWAYS leaves evidence (P-04) — but on a refused run it makes
    // ZERO calls (R4-CF-00): refusal means no authority, cleanup included.
    // -----------------------------------------------------------------------
    metered?.close("run moved to cleanup"); // probe stragglers lose their provider
    try {
      if (!opts.mock && preflight.verdict === "RED") {
        cleanupRecord = refusedCleanup(preflight, refused?.attempts ?? 0);
      } else if (runRefusalReason !== null) {
        cleanupRecord = refusedCleanup(preflight, 0);
        // the pre-run LIST result is still factual evidence
        cleanupRecord.actions = cleanupRecord.actions.map((a) =>
          a.obligation_id === "verify-bucket-empty" ? emptyListRecord : a,
        );
      } else {
        cleanupMutationsRan = true;
        const mintedCredentialCount = probeEvidence
          .flatMap((ev) => ev.exchanges)
          .filter(
            (ex) =>
              ex.request.method === "POST" &&
              ex.request.path.includes("temp-access-credentials") &&
              ex.outcome.type === "success",
          ).length;
        cleanupRecord = await executeCleanup(
          cleanupProvider ?? provider,
          bucket,
          createdKeys,
          metered?.attemptedWrites ?? new Set(),
          preflight,
          runNonce,
          lockBaseline,
          emptyListRecord,
          mintedCredentialCount,
        );
      }
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
      // Non-secret recovery scope: everything a failed cleanup could have
      // left behind is addressable under these run-owned identifiers.
      recovery_scope: {
        bucket,
        run_prefix: `probes/${runNonce}/`,
        lock_baseline_rule_count: lockBaseline?.rules.length ?? null,
        run_owned_lock_rule_id_prefix: `probe-lock-${runNonce}`,
      },
    });
  }

  // --- R4-CF-01: the verdict is computed AFTER cleanup. A failed or
  //     conflicted cleanup action makes the run red — an exit 0 with
  //     unrestored state is exactly the false-green the audit named. A
  //     zero-authority violation (any attempted call on a refused run)
  //     is likewise fatal to the run, not merely logged.
  const cleanupFailed = cleanupRecord.actions.some((a) => a.status === "failed" || a.status === "conflict");
  const zeroAuthorityViolated = refused !== null && refused.attempts > 0;
  if (cleanupMutationsRan && cleanupFailed) exitCode = 1;
  if (zeroAuthorityViolated) {
    console.error(
      `ZERO-AUTHORITY VIOLATION: ${refused?.attempts} provider call(s) attempted on a refused run — runner bug, run fails`,
    );
    exitCode = 1;
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
    deadlines_ms: { request: 30_000, probe: probeDeadlineMs, run: runDeadlineMs },
    normative_probe_count: NORMATIVE_PROBE_COUNT,
    capabilities: provider.capabilities,
    preflight: {
      verdict: preflight.verdict,
      reasons: preflight.reasons,
      bucket: preflight.bucket,
      envelope_present: preflight.envelope !== null,
    },
    // R4-CF-01: the enforced budget actually consumed, and the R4-CF-00
    // zero-authority accounting (attempted calls on a refused run: MUST
    // be zero; nonzero already forced exit 1 above).
    envelope_enforcement:
      metered !== null
        ? {
            requests_used: metered.requestsUsed,
            bytes_written: metered.bytesWritten,
            journaled_write_intents: metered.attemptedWrites.size,
            meter_closed: metered.closed,
          }
        : null,
    zero_authority: refused !== null ? { attempted_calls: refused.attempts } : null,
    pre_run_refusal: runRefusalReason,
    cleanup_failed: cleanupRecord.actions.some((a) => a.status === "failed" || a.status === "conflict"),
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
  // R4-CF-03: seal scans every artifact byte for secret leaks (the run's
  // actual configured secrets included); a hit refuses COMPLETE and the
  // run fails — a leaking bundle is never sealed evidence.
  let root: string;
  try {
    root = bundle.seal(knownSecrets);
  } catch (err) {
    if (err instanceof SealViolationError) {
      console.error(`platform-probes: ${err.message}`);
      console.error("platform-probes: bundle left UN-SEALED (no COMPLETE); run fails");
      return 1;
    }
    throw err;
  }
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
