/*
 * Bucket-lock baseline capture and conservative restore (round-4
 * finding R4-CF-00, second half).
 *
 * The previous cleanup issued `PUT .../lock {"rules":[]}`, replacing the
 * bucket's ENTIRE lock policy — including rules this run never created.
 * On any bucket that is not perfectly fresh that is destructive: it can
 * erase an operator's pre-existing retention rules.
 *
 * The contract here is snapshot / add-only / conservative-restore:
 *
 *   1. BEFORE any probe runs, captureLockBaseline() records the exact
 *      current rule list (DTO-validated);
 *   2. probes may only ADD rules whose id starts with the run-owned
 *      prefix `probe-lock-<runNonce>` (P-R2-03 does read-modify-write,
 *      preserving whatever else is present);
 *   3. restoreLockBaseline() re-reads the policy and classifies every
 *      rule: run-owned rules are expected and will be removed; every
 *      OTHER rule must be exactly a baseline rule and every baseline
 *      rule must still be present. Any unexpected difference — an
 *      operator added/changed/removed a rule mid-run — is a CONFLICT:
 *      the restore refuses to write anything (never overwrite an
 *      operator's concurrent change) and cleanup reports failed;
 *   4. on a clean classification the exact baseline snapshot is PUT
 *      back and re-read for byte-equivalent verification.
 *
 * `rules: []` never appears here as a cleanup payload.
 */

import type { SeamRequest, SeamResponse } from "./provider.ts";
import { utf8 } from "./provider.ts";
import type { BucketLockRule } from "./cfapi-dto.ts";
import { canonicalRules, validateBucketLockGetResponse } from "./cfapi-dto.ts";

type FetchFn = (req: SeamRequest) => Promise<SeamResponse>;

export interface LockBaseline {
  bucket: string;
  rules: BucketLockRule[];
  canonical: string;
}

/** Run-owned rule-id prefix: only these may be added and removed by a run. */
export function runOwnedRuleIdPrefix(runNonce: string): string {
  return `probe-lock-${runNonce}`;
}

function parseLockPolicy(res: SeamResponse): BucketLockRule[] {
  const body = JSON.parse(new TextDecoder().decode(res.body));
  return validateBucketLockGetResponse(body).result.rules;
}

/**
 * Snapshot the current lock policy. A non-200 or malformed policy is a
 * hard error — a run that cannot prove the baseline must not mutate it.
 */
export async function captureLockBaseline(fetchFn: FetchFn, bucket: string): Promise<LockBaseline> {
  const res = await fetchFn({ service: "cfapi", method: "GET", path: `/r2/buckets/${bucket}/lock`, principal: "admin" });
  if (res.status !== 200) {
    throw new Error(`lock baseline capture failed: GET /r2/buckets/${bucket}/lock returned ${res.status}`);
  }
  const rules = parseLockPolicy(res);
  return { bucket, rules, canonical: canonicalRules(rules) };
}

export interface LockRestoreResult {
  status: "executed" | "conflict" | "failed" | "noop";
  detail: string;
}

/**
 * Conservative restore. Classifies the current rules against the
 * baseline; refuses (conflict) on any non-run-owned difference; writes
 * the EXACT baseline back otherwise and verifies the readback.
 */
export async function restoreLockBaseline(
  fetchFn: FetchFn,
  baseline: LockBaseline,
  runNonce: string,
): Promise<LockRestoreResult> {
  const ownedPrefix = runOwnedRuleIdPrefix(runNonce);
  let current: BucketLockRule[];
  try {
    const res = await fetchFn({
      service: "cfapi",
      method: "GET",
      path: `/r2/buckets/${baseline.bucket}/lock`,
      principal: "admin",
    });
    if (res.status !== 200) return { status: "failed", detail: `pre-restore GET returned ${res.status}` };
    current = parseLockPolicy(res);
  } catch (err) {
    return { status: "failed", detail: `pre-restore GET failed: ${err instanceof Error ? err.message : String(err)}` };
  }

  const runOwned = current.filter((r) => r.id.startsWith(ownedPrefix));
  const foreign = current.filter((r) => !r.id.startsWith(ownedPrefix));
  // Every non-owned rule must be exactly a baseline rule, and every
  // baseline rule must still be present: set equality on canonical form.
  const foreignCanonical = canonicalRules([...foreign].sort((a, b) => a.id.localeCompare(b.id)));
  const baselineCanonical = canonicalRules([...baseline.rules].sort((a, b) => a.id.localeCompare(b.id)));
  if (foreignCanonical !== baselineCanonical) {
    return {
      status: "conflict",
      detail:
        "current non-run-owned rules differ from the captured baseline (an operator " +
        "changed the policy mid-run); refusing to overwrite — manual reconciliation required. " +
        `baseline_rule_count=${baseline.rules.length} current_foreign_rule_count=${foreign.length}`,
    };
  }
  if (runOwned.length === 0 && foreignCanonical === baselineCanonical) {
    return { status: "noop", detail: "policy already equals the baseline; nothing to restore" };
  }

  try {
    const put = await fetchFn({
      service: "cfapi",
      method: "PUT",
      path: `/r2/buckets/${baseline.bucket}/lock`,
      principal: "admin",
      body: utf8(JSON.stringify({ rules: baseline.rules })),
    });
    if (put.status !== 200) return { status: "failed", detail: `baseline restore PUT returned ${put.status}` };
    const verify = await fetchFn({
      service: "cfapi",
      method: "GET",
      path: `/r2/buckets/${baseline.bucket}/lock`,
      principal: "admin",
    });
    if (verify.status !== 200) return { status: "failed", detail: `post-restore GET returned ${verify.status}` };
    const after = parseLockPolicy(verify);
    if (canonicalRules(after) !== baseline.canonical) {
      return { status: "failed", detail: "post-restore policy readback does not equal the captured baseline" };
    }
    return {
      status: "executed",
      detail: `removed ${runOwned.length} run-owned rule(s); baseline of ${baseline.rules.length} rule(s) verified restored`,
    };
  } catch (err) {
    return { status: "failed", detail: `restore failed: ${err instanceof Error ? err.message : String(err)}` };
  }
}
