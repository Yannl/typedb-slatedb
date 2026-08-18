/*
 * Platform probe runner — the release-gate entrypoint for the 14
 * normative probes in contract/typedb-r2-v16-platform-probes.md.
 *
 * This runner replaces the pre-audit run-r2-probes.ts, which the external
 * audit (finding C-P0-10) proved false-green: probes printed FAIL while
 * main() never aggregated verdicts, so the process exited 0. The fix is
 * structural, not cosmetic:
 *
 *   - a manifest completeness gate: a run that cannot account for every
 *     one of the 14 normative probe IDs is itself a FAIL (exit 1);
 *   - fail-closed verdict aggregation: exit 0 ONLY when every manifest
 *     probe is PASS; missing credentials => PREREQUISITE_MISSING (exit 3);
 *     any FAIL or NOT_RUN => exit 1; there is NO path to exit 0 with a
 *     non-PASS verdict anywhere;
 *   - a sealed, content-addressed evidence bundle per run (COMPLETE
 *     written last, over the sha256 of every artifact);
 *   - a provider seam so the identical probe code runs against the real
 *     platform or a deterministic in-process fake, with per-probe fault
 *     injection proving the harness can actually turn red.
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
 */

import { realpathSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { NORMATIVE_PROBE_COUNT, PROBE_MANIFEST } from "./manifest.ts";
import type { ManifestEntry, ProbeVerdict } from "./manifest.ts";
import { EvidenceBundle, gitHead, RecordingProvider } from "./evidence.ts";
import type { CheckRecord, ProbeEvidence } from "./evidence.ts";
import { MockPlatformProvider } from "./mock-provider.ts";
import type { PlatformProvider } from "./provider.ts";
import { randomHex, realConfigFromEnv, RealPlatformProvider } from "./provider.ts";
import type { ProbeContext, ProbeImpl } from "./probe.ts";
import { R2_PROBES } from "./probes-r2.ts";
import { DO_PROBES } from "./probes-do.ts";
import { CTR_PROBES, WORKER_PROBES } from "./probes-ctr.ts";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const DEFAULT_EVIDENCE_ROOT = join(REPO_ROOT, "docs/evidence/G1-platform/runs");

/** Implementation registry; cross-checked against the manifest below. */
const REGISTRY: ReadonlyArray<ProbeImpl> = [...R2_PROBES, ...DO_PROBES, ...CTR_PROBES, ...WORKER_PROBES];

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
}

function usageError(msg: string): never {
  console.error(`usage error: ${msg}`);
  process.exit(2);
}

function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = {
    mock: false,
    mock500: false,
    faults: new Map(),
    only: null,
    evidenceRoot: DEFAULT_EVIDENCE_ROOT,
    listFaultControls: false,
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
  injectedFault: string | null,
): Promise<ProbeEvidence> {
  const startedAt = new Date().toISOString();
  const recording = new RecordingProvider(provider);
  const checks: CheckRecord[] = [];
  const notes: string[] = [];
  const ctx: ProbeContext = {
    fetch: (req) => recording.fetch(req),
    mode: provider.mode,
    bucket,
    runNonce,
    check: (ok, label) => {
      checks.push({ label, ok });
    },
    note: (msg) => {
      notes.push(msg);
    },
  };
  try {
    await impl.run(ctx);
  } catch (err) {
    // A thrown error is never a pass: record it as a failed check.
    checks.push({ label: `unhandled probe error: ${err instanceof Error ? err.message : String(err)}`, ok: false });
  }
  const failed = checks.filter((c) => !c.ok);
  // Fail-closed verdict: zero checks proves nothing and is a FAIL.
  const verdict: ProbeVerdict = checks.length > 0 && failed.length === 0 ? "PASS" : "FAIL";
  const actual =
    checks.length === 0
      ? "probe recorded no assertions (fail-closed)"
      : failed.length === 0
        ? `all ${checks.length} checks passed`
        : `${failed.length}/${checks.length} checks failed: ${failed.map((c) => c.label).join(" | ")}`;
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
    exchanges: [],
    notes: [],
  };
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

  // --- provider construction ---
  let provider: PlatformProvider;
  let bucket: string;
  if (opts.mock) {
    provider = new MockPlatformProvider({ faults: opts.faults, force500: opts.mock500 });
    bucket = "mock-bucket";
  } else {
    const real = new RealPlatformProvider(realConfigFromEnv(process.env));
    provider = real;
    bucket = real.bucket ?? "";
  }
  const runNonce = `${Date.now().toString(36)}-${randomHex(4)}`;

  // --- evidence bundle: unique per run, sealed at the end ---
  const bundle = new EvidenceBundle(opts.evidenceRoot);
  const startedAt = new Date().toISOString();
  console.log(`platform-probes: run ${bundle.runId} (${provider.mode} mode)`);

  const verdicts = new Map<string, ProbeVerdict>();
  for (const entry of PROBE_MANIFEST) {
    const impl = implById.get(entry.id);
    let evidence: ProbeEvidence;
    if (impl === undefined) {
      // Unreachable after the completeness gate, but kept fail-closed.
      evidence = skippedEvidence(entry, impl, provider.mode, "NOT_RUN", "no implementation registered");
    } else if (opts.only !== null && !opts.only.has(entry.id)) {
      evidence = skippedEvidence(entry, impl, provider.mode, "NOT_RUN", "excluded by --only (subset runs never pass the gate)");
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
        evidence = await runOneProbe(entry, impl, provider, bucket, runNonce, opts.faults.get(entry.id) ?? null);
      }
    }
    verdicts.set(entry.id, evidence.verdict);
    bundle.writeProbeEvidence(evidence);
    console.log(`${entry.id}: ${evidence.verdict} — ${evidence.actual_outcome}`);
  }

  // --- run record + sealed bundle root ---
  bundle.writeRunRecord({
    run_id: bundle.runId,
    started_at: startedAt,
    finished_at: new Date().toISOString(),
    git_head: gitHead(REPO_ROOT),
    node_version: process.version,
    mode: provider.mode,
    argv,
    injected_faults: Object.fromEntries(opts.faults),
    mock_500: opts.mock500,
    normative_probe_count: NORMATIVE_PROBE_COUNT,
    capabilities: provider.capabilities,
    verdicts: Object.fromEntries(verdicts),
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
  const exitCode = aggregateExitCode(verdicts);
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
