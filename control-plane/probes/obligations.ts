/*
 * Versioned contract obligation manifest (R4-CF-04).
 *
 * The round-4 audit proved the probe gate mixed two different questions —
 * "what does raw R2 do?" (provider facts) and "does the product enforce
 * its contract?" (product conformance) — inside one green verdict, so a
 * 14/14 PASS could be read as contract proof while the normative product
 * obligations (pre-G13 no-delete through the product path, real-mode
 * ambiguity resolution, real-mode changed-bytes attempt identity) had no
 * real-mode assertion at all.
 *
 * This manifest is the fix's source of truth:
 *
 *   - every probe assertion is JOINED to a contract obligation here, and
 *     the runner exact-set reconciles the two before anything runs: a
 *     dangling reference, an unclaimed assertion, a product-conformance
 *     obligation whose evidence is not required in real mode — each is a
 *     RUN-INVALID violation (exit 1), never a silent drift;
 *   - obligations are CLASSED: "provider-fact" (what the raw platform /
 *     labeled harness demonstrably does) vs "product-conformance" (proof
 *     the PRODUCT contract holds on the actual enforcement path);
 *   - a normative product obligation with NO real-mode assertion today is
 *     recorded with satisfied_by: [] and status "OPEN" plus a blocker
 *     string — the gap is stated, not hidden. mock_evidence may name the
 *     mock-only assertions that model the obligation; they are evidence,
 *     NEVER satisfaction (a mock check cannot close a real obligation);
 *   - every run emits obligations.json (per-obligation status) and the
 *     VERDICT carries provider_facts / product_conformance sub-verdicts:
 *     product_conformance CANNOT be PASS while any product obligation is
 *     OPEN or failed, so "14 probe IDs exist" can never again read as
 *     obligation coverage.
 */

import type { ProbeImpl, ProbeMode } from "./probe.ts";
import type { AssertionClass } from "./probe.ts";

/** Reference to one declared probe assertion. */
export interface ObligationRef {
  probe: string;
  assertion: string;
}

export interface ContractObligation {
  /** Stable obligation id, unique in the manifest. */
  id: string;
  /** What the contract requires. */
  title: string;
  class: AssertionClass;
  /**
   * The assertions whose recorded PASS results satisfy this obligation.
   * Empty REQUIRES status "OPEN" + blocker: the obligation is stated as
   * unmet instead of quietly unmapped.
   */
  satisfied_by: ReadonlyArray<ObligationRef>;
  /**
   * Modes in which the obligation must be exercised. A product-conformance
   * obligation with satisfied_by non-empty MUST include "real" (the audit's
   * core rule: normative product assertions execute in cloudflare-real).
   */
  required_in: ReadonlyArray<ProbeMode>;
  /** Present (as "OPEN") exactly when satisfied_by is empty. */
  status?: "OPEN";
  /** For OPEN obligations: what blocks satisfaction today. */
  blocker?: string;
  /**
   * Mock-only assertions that MODEL this obligation without satisfying it
   * (e.g. the adapter-contract enforcement only the mock implements).
   */
  mock_evidence?: ReadonlyArray<ObligationRef>;
}

export interface ObligationManifest {
  schema: "probe-obligations/v1";
  contract: string;
  obligations: ReadonlyArray<ContractObligation>;
}

const BOTH: ReadonlyArray<ProbeMode> = ["mock", "real"];
const MOCK: ReadonlyArray<ProbeMode> = ["mock"];
const REAL: ReadonlyArray<ProbeMode> = ["real"];

function refs(probe: string, ...assertions: string[]): ObligationRef[] {
  return assertions.map((assertion) => ({ probe, assertion }));
}

export const OBLIGATION_MANIFEST: ObligationManifest = {
  schema: "probe-obligations/v1",
  contract: "contract/typedb-r2-v16-platform-probes.md",
  obligations: [
    // ----- R2 conditions and ambiguity (P-R2-01) --------------------------
    {
      id: "r2-conditional-semantics",
      title:
        "R2 conditional PUT semantics: exact success/412 classification, single " +
        "concurrent winner, byte/hash-exact readback",
      class: "provider-fact",
      satisfied_by: refs(
        "P-R2-01",
        "create-if-absent-succeeds",
        "duplicate-create-412",
        "if-match-current-succeeds",
        "if-match-wrong-412",
        "readback-200",
        "readback-byte-exact",
        "race-single-winner",
        "race-winner-bytes",
      ),
      required_in: BOTH,
    },
    {
      id: "ambiguity-resolution-real",
      title:
        "timeout-before/after-commit ambiguity is resolved with a typed " +
        "classification through the product adapter path, in cloudflare-real",
      class: "product-conformance",
      satisfied_by: [],
      required_in: REAL,
      status: "OPEN",
      blocker:
        "only mock-only assertions exercise ambiguity typing (P-R2-01 " +
        "ambiguous-observed/-retry-classified/-committed-once, which depend on the " +
        "mock's commit-then-timeout control); no real-mode probe drives the actual " +
        "adapter's ambiguity classifier — real fault injection at the adapter " +
        "boundary is required before this obligation can be satisfied",
      mock_evidence: refs(
        "P-R2-01",
        "ambiguous-observed",
        "ambiguous-retry-classified",
        "ambiguous-committed-once",
      ),
    },
    // ----- Temporary credentials (P-R2-02) --------------------------------
    {
      id: "r2-temp-credential-minting",
      title: "temp credentials mint via the official DTO; malformed mints are refused",
      class: "provider-fact",
      satisfied_by: refs("P-R2-02", "mint-malformed-refused", "mint-envelope-valid", "ro-envelope-valid"),
      required_in: BOTH,
    },
    {
      id: "r2-credential-scope-grants",
      title: "scoped credentials can perform their granted actions inside their prefix",
      class: "provider-fact",
      satisfied_by: refs("P-R2-02", "rw-put-in-scope", "rw-get-in-scope", "seed-outside-with-parent", "ro-get-allowed"),
      required_in: BOTH,
    },
    {
      id: "forbidden-credential-actions-denied",
      title:
        "all forbidden credential actions are denied at the credential layer the " +
        "product relies on: read-only cannot write, out-of-prefix reads and writes fail",
      class: "product-conformance",
      satisfied_by: refs("P-R2-02", "ro-put-denied", "rw-put-outside-denied", "rw-get-outside-denied"),
      required_in: BOTH,
    },
    {
      id: "preset-cannot-express-no-delete",
      title:
        "PROVIDER FACT: Cloudflare's permission preset enum cannot express " +
        "put+get-without-delete — an object-read-write credential CAN delete in " +
        "scope, so no-delete must be enforced above the credential layer",
      class: "provider-fact",
      satisfied_by: refs("P-R2-02", "rw-delete-in-scope-allowed"),
      required_in: BOTH,
    },
    {
      id: "runtime-cannot-delete",
      title:
        "pre-G13 no-delete: the RUNTIME principal cannot delete through the " +
        "product path — the joined product verdict over the provider fact that " +
        "the preset allows DELETE must prove a tested gateway/lock/authority " +
        "boundary denies the runtime action",
      class: "product-conformance",
      satisfied_by: [],
      required_in: REAL,
      status: "OPEN",
      blocker:
        "P-R2-02 rw-delete-in-scope-allowed proves the OPPOSITE as a provider " +
        "fact (HTTP 204 on DELETE with an object-read-write credential); no probe " +
        "exercises the product's runtime delete path through its gateway/lock " +
        "boundary, and P-R2-03's lock denials cover only lock-ruled prefixes, not " +
        "the runtime principal's whole pre-G13 surface — a probe through the " +
        "product adapter/gateway with the runtime principal is required",
    },
    // ----- Bucket Locks (P-R2-03) -----------------------------------------
    {
      id: "r2-lock-configuration",
      title:
        "lock rules use the official shape, legacy shapes are refused, policy is " +
        "machine-verifiable via the result envelope, unlock-ruled paths behave normally",
      class: "provider-fact",
      satisfied_by: refs(
        "P-R2-03",
        "seed-created",
        "legacy-rule-shape-refused",
        "admin-lock-accepted",
        "new-under-lock-creatable",
        "outside-rules-normal",
        "policy-readback-exact",
      ),
      required_in: BOTH,
    },
    {
      id: "immutability-above-credential-layer",
      title:
        "locked objects are immutable ABOVE the credential layer: overwrite and " +
        "delete denied, bytes survive, new objects are covered immediately",
      class: "product-conformance",
      satisfied_by: refs(
        "P-R2-03",
        "locked-overwrite-denied",
        "locked-delete-denied",
        "locked-bytes-survive",
        "new-under-lock-covered",
      ),
      required_in: BOTH,
    },
    {
      id: "lock-policy-immutable-to-runtime",
      title:
        "the runtime principal (a genuinely separate credential in real mode) " +
        "cannot alter lock policy, and a denied attempt changes nothing",
      class: "product-conformance",
      satisfied_by: refs("P-R2-03", "runtime-mutation-denied", "policy-unchanged-after-denial"),
      required_in: BOTH,
    },
    // ----- Checksums and multipart (P-R2-04) ------------------------------
    {
      id: "r2-checksum-verification",
      title:
        "checksummed writes are verified and echoed; the application SHA-256 " +
        "remains authoritative over the provider echo",
      class: "provider-fact",
      satisfied_by: refs("P-R2-04", "checksummed-put-accepted", "checksum-echoed", "app-sha256-authoritative"),
      required_in: BOTH,
    },
    {
      id: "r2-multipart-mechanics",
      title:
        "multipart create/part/complete/abort mechanics: identical-byte retry " +
        "idempotent, new-attempt replacement legal, final bytes match the part " +
        "manifest, aborted uploads are dead",
      class: "provider-fact",
      satisfied_by: refs(
        "P-R2-04",
        "mp-create-accepted",
        "mp-upload-id",
        "mp-part1-accepted",
        "mp-identical-retry-idempotent",
        "mp-new-attempt-accepted",
        "mp-part2-accepted",
        "mp-complete-accepted",
        "mp-final-bytes-match-manifest",
        "mp-abort-accepted",
        "mp-after-abort-refused",
      ),
      required_in: BOTH,
    },
    {
      id: "attempt-identity-changed-bytes-real",
      title:
        "application-level multipart attempt identity: changed bytes under the " +
        "same UploadAttemptId are refused by the product adapter, in cloudflare-real",
      class: "product-conformance",
      satisfied_by: [],
      required_in: REAL,
      status: "OPEN",
      blocker:
        "raw R2 accepts changed bytes under the same attempt id (P-R2-04 real " +
        "mode merely notes the raw behavior); only the mock enforces the adapter " +
        "contract (mp-changed-bytes-refused, mock-only) — a real-mode probe " +
        "through the actual adapter's UploadAttemptId gate is required",
      mock_evidence: refs("P-R2-04", "mp-changed-bytes-refused"),
    },
    // ----- Consistency and pressure (P-R2-05) -----------------------------
    {
      id: "r2-read-after-write",
      title: "read-after-write consistency on the S3 endpoint",
      class: "provider-fact",
      satisfied_by: refs("P-R2-05", "write-accepted", "read-after-write"),
      required_in: BOTH,
    },
    {
      id: "r2-pressure-bounded-typed",
      title:
        "same-key pressure is a bounded schedule with a typed outcome in every " +
        "mode: burst statuses exact, shed writers complete within the backoff " +
        "bound, overload never yields an incorrect success, and a no-429 real run " +
        "is a recorded classification, not a structural hole",
      class: "provider-fact",
      satisfied_by: refs(
        "P-R2-05",
        "burst-statuses-exact",
        "burst-some-accepted",
        "visible-bytes-acknowledged",
        "shed-writers-complete",
        "backoff-bounded",
        "final-winner-complete",
        "pressure-outcome-typed",
      ),
      required_in: BOTH,
    },
    {
      id: "mock-pressure-model",
      title:
        "the deterministic mock pressure model behaves exactly as declared " +
        "(exact shed count, last-committed winner, single bounded retry round, " +
        "exact retry statuses)",
      class: "provider-fact",
      satisfied_by: refs(
        "P-R2-05",
        "burst-shed-exact",
        "winner-last-committed",
        "retry-statuses-exact",
        "mock-single-retry-round",
      ),
      required_in: MOCK,
    },
    // ----- DO / container / gateway harness models ------------------------
    // All provider-fact: the harness is a labeled reference implementation
    // (probes/harness-worker.ts / the in-process fake), not the product
    // adapter — see the classification note in probes-do.ts / probes-ctr.ts.
    {
      id: "do-interleaving-model",
      title: "DO request-interleaving reference: stale post-await validation never commits",
      class: "provider-fact",
      satisfied_by: refs(
        "P-DO-01",
        "reset-ok",
        "conflict-lands",
        "gate-released",
        "stale-commit-rejected",
        "single-commit",
        "winner-value",
        "legal-trace",
      ),
      required_in: BOTH,
    },
    {
      id: "do-alarm-durability-model",
      title:
        "DO alarm reference: duplicate delivery idempotent, throw retries, work " +
        "reconstructed from durable intent after reset",
      class: "provider-fact",
      satisfied_by: refs(
        "P-DO-02",
        "reset-ok",
        "not-delivered-early",
        "throw-retries",
        "duplicate-idempotent",
        "work-once",
        "do-reset-accepted",
        "rescheduled-from-intent",
        "reschedule-respects-time",
        "rescheduled-completes",
        "all-work-done",
      ),
      required_in: BOTH,
    },
    {
      id: "do-overload-shedding-model",
      title: "DO overload reference: explicit shedding at the soft budget with metrics and alert",
      class: "provider-fact",
      satisfied_by: refs(
        "P-DO-03",
        "reset-ok",
        "accepted-or-shed",
        "soft-budget-exact",
        "shed-reason-explicit",
        "rows-held-at-soft",
        "shed-count-metrics",
        "alert-fired",
      ),
      required_in: BOTH,
    },
    {
      id: "do-incarnation-authority-model",
      title: "incarnation reference: every superseded-authority action rejected without effect",
      class: "provider-fact",
      satisfied_by: refs(
        "P-DO-04",
        "reset-ok",
        "current-authority-works",
        "rotation-applied",
        "old-authority-rejected",
        "new-authority-unaffected",
        "no-old-authority-effect",
      ),
      required_in: BOTH,
    },
    {
      id: "ctr-lifecycle-model",
      title: "container lifecycle reference: idempotent start, converging stop, stale callbacks rejected",
      class: "provider-fact",
      satisfied_by: refs(
        "P-CTR-01",
        "reset-ok",
        "cold-start",
        "concurrent-start-idempotent",
        "stop-while-starting-converges",
        "duplicate-stop-noop",
        "restart-advances-generation",
        "current-callback-completes",
        "stale-callback-rejected",
        "truth-intact",
      ),
      required_in: BOTH,
    },
    {
      id: "ctr-rollout-model",
      title: "rollout reference: only declared tuples admitted; ready requires observed convergence",
      class: "provider-fact",
      satisfied_by: refs(
        "P-CTR-02",
        "reset-ok",
        "declared-tuple-admitted",
        "not-ready-before-convergence",
        "convergence-observed",
        "ready-after-convergence",
        "undeclared-tuple-refused",
        "unsupported-never-ready",
      ),
      required_in: BOTH,
    },
    {
      id: "ctr-sleep-shutdown-model",
      title: "sleep/shutdown reference: no stop with open work; acknowledged state survives kill",
      class: "provider-fact",
      satisfied_by: refs(
        "P-CTR-03",
        "reset-ok",
        "w1-acked",
        "no-stop-with-open-txn",
        "hibernation-denied",
        "safe-stop-when-idle",
        "w2-acked",
        "kill-applied",
        "acked-survives-kill",
      ),
      required_in: BOTH,
    },
    {
      id: "ctr-network-placement-model",
      title:
        "networking reference: no colocation assumption, egress allowlist enforced, " +
        "possibly-committed operations stay queryable after disconnect",
      class: "provider-fact",
      satisfied_by: refs(
        "P-CTR-04",
        "reset-ok",
        "not-colocated",
        "internal-http-ok",
        "allowlisted-egress-ok",
        "unauthorized-egress-denied",
        "internet-off-denies-all",
        "disconnect-observed",
        "committed-still-queryable",
      ),
      required_in: BOTH,
    },
    {
      id: "worker-gateway-bounds-model",
      title:
        "gateway reference: bounded streaming buffer, no premature success receipt, " +
        "six-connection saturation queues correctly",
      class: "provider-fact",
      satisfied_by: refs(
        "P-WORKER-01",
        "reset-ok",
        "stream-complete",
        "stream-pattern-exact",
        "buffer-bounded",
        "upstream-5xx-surfaces",
        "no-premature-receipt",
        "permits-capped-at-six",
        "excess-queued",
        "no-incorrect-success",
      ),
      required_in: BOTH,
    },
  ],
};

// ---------------------------------------------------------------------------
// Exact-set reconciliation (runs inside the runner's completeness gate).
// ---------------------------------------------------------------------------

/**
 * Reconcile the obligation manifest against the probe registry EXACT-SET.
 * Any violation invalidates the run (exit 1):
 *
 *   - a satisfied_by / mock_evidence reference that names no declared
 *     probe+assertion (dangling refs prove nothing);
 *   - a declared assertion claimed by NO obligation (unclaimed assertions
 *     are exactly the "14 probe IDs exist" non-coverage the audit named);
 *   - a product-conformance obligation with recorded evidence that is not
 *     required in cloudflare-real;
 *   - an obligation whose required_in modes exceed what its satisfying
 *     assertions are required to record;
 *   - an empty satisfied_by without an explicit OPEN status + blocker
 *     (a silent gap), or an OPEN status on a satisfied obligation.
 */
export function obligationViolations(
  manifest: ObligationManifest,
  registry: ReadonlyArray<ProbeImpl>,
): string[] {
  const violations: string[] = [];
  if (manifest.schema !== "probe-obligations/v1") {
    violations.push(`obligation manifest schema is '${manifest.schema}', expected 'probe-obligations/v1'`);
  }
  if (manifest.obligations.length === 0) {
    violations.push("obligation manifest is empty (an empty manifest proves nothing)");
  }
  const ids = new Set<string>();
  for (const o of manifest.obligations) {
    if (ids.has(o.id)) violations.push(`duplicate obligation id '${o.id}'`);
    ids.add(o.id);
  }

  // Assertion index: probe -> assertion -> required_in.
  const byProbe = new Map<string, Map<string, ReadonlyArray<ProbeMode>>>();
  for (const p of registry) {
    byProbe.set(p.id, new Map(p.assertions.map((a) => [a.id, a.required_in])));
  }

  const claimed = new Set<string>();
  for (const o of manifest.obligations) {
    const allRefs = [...o.satisfied_by, ...(o.mock_evidence ?? [])];
    for (const ref of allRefs) {
      const assertions = byProbe.get(ref.probe);
      if (!assertions || !assertions.has(ref.assertion)) {
        violations.push(`obligation ${o.id} references unknown assertion ${ref.probe}/${ref.assertion}`);
        continue;
      }
      claimed.add(`${ref.probe}/${ref.assertion}`);
    }
    for (const ref of o.satisfied_by) {
      const required = byProbe.get(ref.probe)?.get(ref.assertion);
      if (!required) continue; // already reported above
      for (const mode of o.required_in) {
        if (!required.includes(mode)) {
          violations.push(
            `obligation ${o.id} is required in '${mode}' but ${ref.probe}/${ref.assertion} ` +
              `is not required to record a result in that mode`,
          );
        }
      }
    }
    if (o.class === "product-conformance" && o.satisfied_by.length > 0 && !o.required_in.includes("real")) {
      violations.push(
        `product-conformance obligation ${o.id} has recorded evidence but is not required in real ` +
          `mode — every normative product assertion must execute in cloudflare-real (R4-CF-04)`,
      );
    }
    if (o.satisfied_by.length === 0) {
      if (o.status !== "OPEN" || !o.blocker || o.blocker.trim().length === 0) {
        violations.push(
          `obligation ${o.id} has empty satisfied_by but no explicit OPEN status + blocker — ` +
            `a gap must be stated, never silent`,
        );
      }
    } else if (o.status === "OPEN") {
      violations.push(`obligation ${o.id} is marked OPEN but names satisfying assertions`);
    }
  }

  for (const p of registry) {
    for (const a of p.assertions) {
      if (!claimed.has(`${p.id}/${a.id}`)) {
        violations.push(
          `assertion ${p.id}/${a.id} is claimed by no obligation — probe-count coverage is not ` +
            `obligation coverage (R4-CF-04)`,
        );
      }
    }
  }
  return violations;
}

// ---------------------------------------------------------------------------
// Per-run obligation status (emitted as obligations.json).
// ---------------------------------------------------------------------------

export type ObligationRunStatus =
  | "SATISFIED"
  | "OPEN"
  | "NOT-EXERCISED-THIS-MODE"
  | "NOT-EXERCISED-THIS-RUN"
  | "FAILED";

export interface ObligationRunRecord {
  id: string;
  title: string;
  class: AssertionClass;
  status: ObligationRunStatus;
  required_in: ReadonlyArray<ProbeMode>;
  satisfied_by: ReadonlyArray<ObligationRef>;
  mock_evidence?: ReadonlyArray<ObligationRef>;
  blocker?: string;
  detail: string;
}

/** Minimal view of a recorded check the status computation needs. */
export interface RecordedCheck {
  assertion_id: string;
  ok: boolean;
}

/**
 * Compute each obligation's status for ONE run, strictly from the checks
 * the probes actually recorded. Fail-closed: an obligation required in
 * this mode whose evidence has no recorded result is NOT-EXERCISED-THIS-RUN
 * (a refused/skipped run), and any failed check is FAILED — neither can
 * ever be read as SATISFIED.
 */
export function computeObligationStatuses(
  manifest: ObligationManifest,
  mode: ProbeMode,
  checksByProbe: ReadonlyMap<string, ReadonlyArray<RecordedCheck>>,
): ObligationRunRecord[] {
  return manifest.obligations.map((o) => {
    const base = {
      id: o.id,
      title: o.title,
      class: o.class,
      required_in: o.required_in,
      satisfied_by: o.satisfied_by,
      ...(o.mock_evidence !== undefined ? { mock_evidence: o.mock_evidence } : {}),
      ...(o.blocker !== undefined ? { blocker: o.blocker } : {}),
    };
    if (o.status === "OPEN") {
      return { ...base, status: "OPEN" as const, detail: `open obligation: ${o.blocker ?? "(no blocker recorded)"}` };
    }
    if (!o.required_in.includes(mode)) {
      return {
        ...base,
        status: "NOT-EXERCISED-THIS-MODE" as const,
        detail: `obligation applies to [${o.required_in.join(", ")}]; this run is '${mode}'`,
      };
    }
    let failed = 0;
    let missing = 0;
    let passed = 0;
    for (const ref of o.satisfied_by) {
      const recorded = (checksByProbe.get(ref.probe) ?? []).filter((c) => c.assertion_id === ref.assertion);
      if (recorded.length === 0) missing += 1;
      else if (recorded.some((c) => !c.ok)) failed += 1;
      else passed += 1;
    }
    if (failed > 0) {
      return { ...base, status: "FAILED" as const, detail: `${failed} of ${o.satisfied_by.length} evidence assertions failed` };
    }
    if (missing > 0) {
      return {
        ...base,
        status: "NOT-EXERCISED-THIS-RUN" as const,
        detail: `${missing} of ${o.satisfied_by.length} evidence assertions recorded no result this run`,
      };
    }
    return { ...base, status: "SATISFIED" as const, detail: `all ${passed} evidence assertions recorded PASS` };
  });
}
