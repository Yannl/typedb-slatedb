/*
 * Real-mode preflight (round-3 audit finding P-06).
 *
 * Before any live-spend probe run, this module verifies — fail-closed —
 * that the run is pointed at a DISPOSABLE, owner-approved target:
 *
 *   1. the target bucket is disposable by NAME: it must match the probe
 *      naming pattern AND carry the run's ownership nonce
 *      (R2_PROBE_OWNERSHIP_NONCE); arbitrary/pre-existing/prod-like
 *      names are refused outright;
 *   2. an owner-approved NUMERIC envelope exists on disk
 *      (docs/probe-run-envelope.json, in the docs/owner-decisions.json
 *      style): machine-readable limits with an explicit approver. If the
 *      file is absent or any limit is missing/non-numeric, preflight is
 *      RED with PREREQUISITE_MISSING — limits are NEVER guessed by the
 *      implementation (they are a product/cost decision, not a default);
 *   3. every credential the probes need is present (else
 *      PREREQUISITE_MISSING, same as the runner's per-probe gate);
 *   4. the bucket-empty intent is planned: the first act of a real run
 *      MUST be a LIST proving the bucket is empty, and that obligation is
 *      emitted here so the runner records its execution in cleanup.json;
 *   5. cleanup obligations are planned up front (delete run-prefixed
 *      objects, remove probe lock rules, record credential expiry) so
 *      the runner's finally has a checklist to record against.
 *
 * Real mode without EVERY prerequisite exits 3 (the runner's
 * PREREQUISITE_MISSING code). Mock mode is green with a virtual target.
 *
 * CLI (also reachable as `npm run probes:preflight` equivalent):
 *   node --experimental-strip-types probes/preflight.ts            real mode
 *   node --experimental-strip-types probes/preflight.ts --mock     mock mode
 *   ... --envelope <path>    override the envelope file (tests only)
 */

import { readFileSync, realpathSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { ProviderConfigError, realConfigFromEnv } from "./provider.ts";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
export const DEFAULT_ENVELOPE_PATH = join(REPO_ROOT, "docs", "probe-run-envelope.json");

/**
 * The numeric limits the OWNER must approve before live spend. Every one
 * must be present and a finite positive number; none has a default.
 */
export const REQUIRED_ENVELOPE_LIMITS = [
  "max_total_requests",
  "max_total_bytes_written",
  "max_run_seconds",
  "max_probe_seconds",
  "max_request_seconds",
  "max_cost_usd_cents",
] as const;

export interface PreflightReason {
  code: "PREREQUISITE_MISSING" | "REFUSED";
  detail: string;
}

export interface CleanupObligation {
  id: string;
  description: string;
}

export interface PreflightResult {
  verdict: "GREEN" | "RED";
  mode: "real" | "mock";
  reasons: PreflightReason[];
  /** Obligations the runner must record execution of in cleanup.json. */
  cleanup_obligations: CleanupObligation[];
  /** The parsed, validated envelope (real mode, green only). */
  envelope: Record<string, unknown> | null;
  bucket: string | null;
}

/** Bucket names that must never be probe targets, whatever else matches. */
const FORBIDDEN_NAME_FRAGMENTS = ["prod", "live", "main", "backup", "primary", "customer", "data"];

/** Disposable-name pattern: typedb-probe-<ownership nonce>[-suffix]. */
export function disposableBucketPattern(nonce: string): RegExp {
  return new RegExp(`^typedb-probe-${nonce}(?:-[a-z0-9-]+)?$`);
}

function checkEnvelope(path: string, reasons: PreflightReason[]): Record<string, unknown> | null {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    reasons.push({
      code: "PREREQUISITE_MISSING",
      detail:
        `owner-approved numeric envelope ${path} is ABSENT — live limits are an owner ` +
        "decision (docs/owner-decisions.json style) and are never guessed by the implementation",
    });
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    reasons.push({ code: "PREREQUISITE_MISSING", detail: `envelope ${path} is not valid JSON: ${String(err)}` });
    return null;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    reasons.push({ code: "PREREQUISITE_MISSING", detail: `envelope ${path} is not a JSON object` });
    return null;
  }
  const doc = parsed as Record<string, unknown>;
  if (typeof doc.approved_by !== "string" || doc.approved_by.trim().length === 0) {
    reasons.push({ code: "PREREQUISITE_MISSING", detail: "envelope missing 'approved_by' (an explicit human approver)" });
  }
  if (typeof doc.approved_at !== "string" || Number.isNaN(Date.parse(doc.approved_at))) {
    reasons.push({ code: "PREREQUISITE_MISSING", detail: "envelope missing ISO 'approved_at'" });
  }
  const limits = doc.limits;
  if (typeof limits !== "object" || limits === null || Array.isArray(limits)) {
    reasons.push({ code: "PREREQUISITE_MISSING", detail: "envelope missing 'limits' object" });
    return null;
  }
  const l = limits as Record<string, unknown>;
  for (const key of REQUIRED_ENVELOPE_LIMITS) {
    const v = l[key];
    if (typeof v !== "number" || !Number.isFinite(v) || v <= 0) {
      reasons.push({
        code: "PREREQUISITE_MISSING",
        detail: `envelope limit '${key}' is missing or not a positive finite number — it is not guessed`,
      });
    }
  }
  return doc;
}

export function runPreflight(opts: {
  mode: "real" | "mock";
  env: NodeJS.ProcessEnv;
  envelopePath?: string;
}): PreflightResult {
  const reasons: PreflightReason[] = [];
  const obligations: CleanupObligation[] = [
    { id: "verify-bucket-empty", description: "LIST the target bucket BEFORE the first write; a non-empty bucket aborts the run" },
    { id: "delete-run-objects", description: "delete every object under probes/<runNonce>/ in finally, and record the post-run inventory" },
    { id: "remove-probe-lock-rules", description: "remove every bucket-lock rule whose id carries the run nonce; restore the prior policy" },
    { id: "credential-expiry", description: "record minted temporary-credential ttlSeconds and their expiry instants; no credential outlives the envelope" },
  ];

  if (opts.mode === "mock") {
    // Mock mode spends nothing and targets an in-process fake; the plan
    // still exists so the mock lane exercises the same obligations.
    return {
      verdict: "GREEN",
      mode: "mock",
      reasons: [],
      cleanup_obligations: obligations,
      envelope: null,
      bucket: "mock-bucket",
    };
  }

  // --- 1. owner-approved numeric envelope (never guessed) ---
  const envelope = checkEnvelope(opts.envelopePath ?? DEFAULT_ENVELOPE_PATH, reasons);

  // --- 2. credentials (fail-closed, same currency as the runner) ---
  let bucket: string | null = null;
  try {
    const cfg = realConfigFromEnv(opts.env);
    if (!cfg.r2) reasons.push({ code: "PREREQUISITE_MISSING", detail: "R2_* credentials absent" });
    if (!cfg.cfapi) reasons.push({ code: "PREREQUISITE_MISSING", detail: "CF_ACCOUNT_ID / CF_API_TOKEN absent" });
    if (cfg.cfapi && !cfg.cfapi.runtimeApiToken) {
      reasons.push({ code: "PREREQUISITE_MISSING", detail: "CF_RUNTIME_API_TOKEN absent (separate runtime principal)" });
    }
    if (!cfg.harness) reasons.push({ code: "PREREQUISITE_MISSING", detail: "CF_PROBE_HARNESS_URL / _TOKEN / _ALLOWED_HOSTS absent" });
    bucket = cfg.r2?.bucket ?? null;
  } catch (err) {
    // A dangerous configuration (token reuse, unapproved harness host) is
    // REFUSED, not merely missing.
    reasons.push({
      code: err instanceof ProviderConfigError ? "REFUSED" : "PREREQUISITE_MISSING",
      detail: err instanceof Error ? err.message : String(err),
    });
  }

  // --- 3. disposable-target refusal ---
  const nonce = opts.env.R2_PROBE_OWNERSHIP_NONCE ?? "";
  if (!/^[a-z0-9]{8,}$/.test(nonce)) {
    reasons.push({
      code: "PREREQUISITE_MISSING",
      detail: "R2_PROBE_OWNERSHIP_NONCE absent or not >=8 chars of [a-z0-9] — the run must own its target by name",
    });
  } else if (bucket !== null) {
    if (!disposableBucketPattern(nonce).test(bucket)) {
      reasons.push({
        code: "REFUSED",
        detail:
          `target bucket '${bucket}' does not match the disposable pattern ` +
          `typedb-probe-${nonce}[-suffix] — arbitrary or pre-existing targets are refused`,
      });
    }
    const lower = bucket.toLowerCase();
    for (const frag of FORBIDDEN_NAME_FRAGMENTS) {
      if (lower.includes(frag)) {
        reasons.push({ code: "REFUSED", detail: `target bucket '${bucket}' contains forbidden fragment '${frag}'` });
      }
    }
  }

  return {
    verdict: reasons.length === 0 ? "GREEN" : "RED",
    mode: "real",
    reasons,
    cleanup_obligations: obligations,
    envelope: reasons.length === 0 ? envelope : null,
    bucket,
  };
}

// ---------------------------------------------------------------------------
// CLI.
// ---------------------------------------------------------------------------

export function preflightCli(argv: string[]): number {
  let mode: "real" | "mock" = "real";
  let envelopePath: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    switch (argv[i]) {
      case "--mock":
        mode = "mock";
        break;
      case "--envelope":
        envelopePath = argv[++i];
        if (envelopePath === undefined) {
          console.error("usage error: --envelope requires a path");
          return 2;
        }
        break;
      default:
        console.error(`usage error: unknown argument '${argv[i]}'`);
        return 2;
    }
  }
  const result = runPreflight({ mode, env: process.env, envelopePath });
  console.log(`preflight: ${result.verdict} (${result.mode} mode)`);
  for (const r of result.reasons) console.log(`  ${r.code}: ${r.detail}`);
  for (const o of result.cleanup_obligations) console.log(`  obligation ${o.id}: ${o.description}`);
  return result.verdict === "GREEN" ? 0 : 3;
}

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
  process.exitCode = preflightCli(process.argv.slice(2));
}
