// Agent-local provider selection and the EXECUTABLE promotion gate
// (round-6 R6-LOCAL-01).
//
// THE HONESTY PROBLEM. The audit recommends promoting source-locked RustFS
// to the canonical agent-local S3 default, but conditions that promotion on
// an additional lane being green: full TypeDB U2S3 against RustFS, the
// deterministic fault-proxy matrix, checkpoint/restore with post-cut WAL
// replay, multipart copy + fallback under RSS bounds, the one-command
// supervisor start/readiness/teardown path, and exact locked-binary
// evidence binding.
//
// The tempting implementation is to flip a constant and write "the lane is
// green" in a comment. That is exactly the failure mode this program keeps
// hitting. So the flip is implemented as a MEASUREMENT, not a claim:
//
//   * RustFS is the configured default for agent/native-local work
//     (DEFAULT_PROVIDER below) — that part of the recommendation is real
//     and takes effect;
//   * whether that default is QUALIFIED is computed at call time from a
//     ledger of lane runs that actually executed in this session. Nothing
//     in this file can report a lane as passed unless recordLaneResult()
//     was called with a real result;
//   * a lane nobody ran is reported as NOT_EXECUTED — structured, in the
//     manifest and on stdout, never as prose in a document;
//   * `requireQualified` turns the gate into a hard refusal for callers
//     (CI, release) that must not proceed on a provisional default.
//
// The ledger is SESSION-SCOPED on purpose: it lives in the per-uid run root
// (or $STACK_LANE_LEDGER), not in git. A committed ledger would become a
// standing claim that outlives the evidence, which is the thing the audit
// says has repeatedly gone wrong. "Has this lane run on this host, in this
// session, against this exact binary digest?" is the only question this
// gate is allowed to answer.

import { existsSync, mkdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { LOCAL_S3_PROVIDER_COMPARATOR, LOCAL_S3_PROVIDER_DEFAULT } from "./graph.data.mjs";
import { ensureRunRoot, runRoot, writeFileAtomic } from "./minio.mjs";
import { providerIds } from "./s3-provider.mjs";

export const LANE_LEDGER_SCHEMA = "typedb-r2-stack/lane-ledger@1";
export const GATE_SCHEMA = "typedb-r2-stack/provider-gate@1";

/**
 * The lanes R6-LOCAL-01 requires before RustFS may be called the QUALIFIED
 * agent-local default. Ids are stable; descriptions cite the audit clause.
 */
export const REQUIRED_LANES = Object.freeze([
  Object.freeze({ id: "u2s3", description: "full TypeDB U2S3 suite against the provider (not only the generic object_store corpus)" }),
  Object.freeze({ id: "fault", description: "deterministic fault proxy: timeout before/after commit, truncated body, reset, stale/contradictory responses, restart" }),
  Object.freeze({ id: "recovery", description: "checkpoint create/restore with post-cut WAL replay and an explicit flush barrier" }),
  Object.freeze({ id: "multipart", description: "multipart copy-supported and fallback paths under RSS bounds" }),
  Object.freeze({ id: "supervision", description: "one-command supervisor start / readiness / verified teardown" }),
  Object.freeze({ id: "evidence-binding", description: "exact locked binary + evidence binding per R6-EVID-01" }),
]);

/**
 * The provider agent/native-local development uses when nothing is asked
 * for, and the comparator kept per R6-LOCAL-01. Both names come from the
 * canonical graph so the CLI, the graph and native-fidelity cannot drift.
 */
export const DEFAULT_PROVIDER = LOCAL_S3_PROVIDER_DEFAULT;
export const COMPARATOR_PROVIDER = LOCAL_S3_PROVIDER_COMPARATOR;

export function ledgerPath() {
  if (process.env.STACK_LANE_LEDGER) return process.env.STACK_LANE_LEDGER;
  return path.join(runRoot(), "lane-ledger.json");
}

function emptyLedger() {
  return { schema: LANE_LEDGER_SCHEMA, entries: [] };
}

export function readLedger(file = ledgerPath()) {
  if (!existsSync(file)) return emptyLedger();
  try {
    const doc = JSON.parse(readFileSync(file, "utf8"));
    if (doc?.schema !== LANE_LEDGER_SCHEMA || !Array.isArray(doc.entries)) return emptyLedger();
    return doc;
  } catch {
    // an unreadable ledger is NOT a green lane; it is no evidence at all
    return emptyLedger();
  }
}

/**
 * Record that a lane actually executed. `status` must be "pass" or "fail";
 * anything else is rejected, because "probably fine" is not a lane result.
 * `binarySha256` binds the result to the exact artifact that produced it
 * (R6-EVID-01) — a result whose digest does not match the provider binary
 * in use is treated as evidence for a DIFFERENT artifact and ignored.
 */
export function recordLaneResult({ lane, provider, status, binarySha256 = null, command = null, detail = null, file = ledgerPath() }) {
  if (!REQUIRED_LANES.some((l) => l.id === lane)) {
    throw new Error(`unknown lane ${JSON.stringify(lane)} — known: ${REQUIRED_LANES.map((l) => l.id).join(", ")}`);
  }
  if (!providerIds().includes(provider)) {
    throw new Error(`unknown provider ${JSON.stringify(provider)}`);
  }
  if (status !== "pass" && status !== "fail") {
    throw new Error(`lane status must be "pass" or "fail", got ${JSON.stringify(status)}`);
  }
  const ledger = readLedger(file);
  ledger.entries.push({
    lane,
    provider,
    status,
    binarySha256,
    command,
    detail,
    host: process.env.HOSTNAME ?? null,
    pid: process.pid,
    at: new Date().toISOString(),
  });
  const dir = path.dirname(file);
  if (dir === runRoot()) ensureRunRoot();
  else mkdirSync(dir, { recursive: true, mode: 0o700 });
  writeFileAtomic(file, `${JSON.stringify(ledger, null, 2)}\n`, { mode: 0o600 });
  return ledger.entries[ledger.entries.length - 1];
}

/**
 * Evaluate the promotion gate for a provider. Pure function of the ledger:
 * there is no code path that returns GREEN without a matching pass entry
 * for every required lane.
 */
export function evaluateGate({ provider = DEFAULT_PROVIDER, binarySha256 = null, file = ledgerPath() } = {}) {
  const ledger = readLedger(file);
  const lanes = {};
  for (const lane of REQUIRED_LANES) {
    const runs = ledger.entries.filter(
      (e) => e.lane === lane.id && e.provider === provider && (binarySha256 == null || e.binarySha256 === binarySha256),
    );
    const last = runs[runs.length - 1] ?? null;
    lanes[lane.id] = {
      description: lane.description,
      executed: runs.length > 0,
      runs: runs.length,
      status: last ? last.status : "NOT_EXECUTED",
      lastRunAt: last?.at ?? null,
      binarySha256: last?.binarySha256 ?? null,
      reason: last
        ? last.status === "pass"
          ? null
          : `last run FAILED: ${last.detail ?? "no detail recorded"}`
        : "not executed in this session (session-scoped ledger; a lane that did not run is not green)",
    };
  }
  const missing = Object.entries(lanes)
    .filter(([, v]) => v.status !== "pass")
    .map(([k]) => k);
  return {
    schema: GATE_SCHEMA,
    provider,
    binarySha256,
    ledgerPath: file,
    ledgerEntries: ledger.entries.length,
    requiredLanes: REQUIRED_LANES.map((l) => l.id),
    lanes,
    missing,
    state: missing.length === 0 ? "GREEN" : "OPEN",
    evaluatedAt: new Date().toISOString(),
  };
}

export class ProviderNotQualifiedError extends Error {
  constructor(message, gate) {
    super(message);
    this.name = "ProviderNotQualifiedError";
    this.code = "PROVIDER_NOT_QUALIFIED";
    this.gate = gate;
  }
}

/**
 * Resolve which provider a command should use, and say honestly what that
 * choice is worth.
 *
 *   selection = "EXPLICIT"             caller named it (flag or env)
 *               "DEFAULT_QUALIFIED"    default AND every required lane green
 *               "DEFAULT_PROVISIONAL"  default, gate still OPEN
 *
 * The default takes effect either way — DEFAULT_PROVISIONAL is the honest
 * label for "we run RustFS by default, and we are not claiming the audit's
 * qualification lane has been executed here". `requireQualified` (CLI
 * --require-qualified-provider / STACK_REQUIRE_QUALIFIED_PROVIDER=1) turns
 * a provisional default into a typed refusal instead.
 */
export function resolveProvider({
  requested = null,
  env = process.env,
  binarySha256 = null,
  requireQualified = env.STACK_REQUIRE_QUALIFIED_PROVIDER === "1",
  file = ledgerPath(),
} = {}) {
  const asked = requested ?? env.S3_PROVIDER ?? null;
  if (asked) {
    if (!providerIds().includes(asked)) {
      throw new Error(`unknown S3 provider ${JSON.stringify(asked)} — known: ${providerIds().join(", ")}`);
    }
    return {
      provider: asked,
      selection: "EXPLICIT",
      requestedBy: requested ? "flag" : "S3_PROVIDER env",
      gate: evaluateGate({ provider: asked, binarySha256, file }),
      comparator: asked === COMPARATOR_PROVIDER ? null : COMPARATOR_PROVIDER,
    };
  }
  const gate = evaluateGate({ provider: DEFAULT_PROVIDER, binarySha256, file });
  const selection = gate.state === "GREEN" ? "DEFAULT_QUALIFIED" : "DEFAULT_PROVISIONAL";
  if (requireQualified && selection !== "DEFAULT_QUALIFIED") {
    throw new ProviderNotQualifiedError(
      `PROVIDER_NOT_QUALIFIED: ${DEFAULT_PROVIDER} is the configured agent-local default but its promotion gate is ${gate.state}; ` +
        `lanes not passed in this session: ${gate.missing.join(", ")}. ` +
        `Run those lanes (they record into ${gate.ledgerPath}) or select a provider explicitly.`,
      gate,
    );
  }
  return {
    provider: DEFAULT_PROVIDER,
    selection,
    requestedBy: "default",
    gate,
    comparator: COMPARATOR_PROVIDER,
  };
}

/** Human-readable rendering of the structured gate (stdout convenience). */
export function formatGate(gate) {
  const lines = [`provider gate: ${gate.provider} — ${gate.state} (ledger ${gate.ledgerPath}, ${gate.ledgerEntries} entries)`];
  for (const id of gate.requiredLanes) {
    const l = gate.lanes[id];
    lines.push(`  ${l.status === "pass" ? "PASS" : l.status === "fail" ? "FAIL" : "NOT_EXECUTED"}  ${id}${l.reason ? ` — ${l.reason}` : ""}`);
  }
  return lines.join("\n");
}
