/*
 * Normative probe manifest (contract/typedb-r2-v16-platform-probes.md).
 *
 * This is the SINGLE list of probe IDs the release gate is allowed to
 * reason about. The runner enforces, before and after execution:
 *
 *   - the manifest carries EXACTLY the normative probe count (14, fixed by
 *     the v16 contract) with no duplicates;
 *   - the implementation registry covers exactly this set (both
 *     directions: no unimplemented manifest ID, no unmanifested probe);
 *   - every manifest ID ends the run with a recorded verdict.
 *
 * A run that cannot account for every manifest ID is ITSELF a failure
 * (exit 1) — a probe that silently disappears from a run must never look
 * like a green gate (audit finding C-P0-10).
 */

/** Verdict for one probe. Anything other than PASS blocks exit 0. */
export type ProbeVerdict = "PASS" | "FAIL" | "NOT_RUN" | "PREREQUISITE_MISSING";

/** Provider capabilities a probe needs before it can genuinely execute. */
export type ProbeRequirement = "r2" | "cfapi" | "cfapi_runtime" | "harness";

export interface ManifestEntry {
  /** Normative probe ID, exactly as written in the contract. */
  id: string;
  /** Human title, mirroring the contract's section heading. */
  title: string;
  /** Section heading in contract/typedb-r2-v16-platform-probes.md. */
  specSection: string;
  /**
   * Provider capabilities the probe needs in real mode. Missing
   * credentials for any of these => PREREQUISITE_MISSING (exit 3),
   * never a fabricated execution.
   */
  requires: ReadonlyArray<ProbeRequirement>;
  /**
   * Canonical injectable fault for this probe (mock mode,
   * `--fault <id>:<fault>`). Each fault makes the mock provider violate
   * the semantics the probe asserts, and the probe MUST then FAIL —
   * proving the harness detects real failures (anti-false-green control).
   */
  mockFault: string;
}

/**
 * The normative probe count. This constant is derived from the contract
 * document, NOT from the manifest below — the runner cross-checks the two
 * so that deleting a manifest entry can never shrink the gate.
 */
export const NORMATIVE_PROBE_COUNT = 14;

export const PROBE_MANIFEST: ReadonlyArray<ManifestEntry> = [
  {
    id: "P-R2-01",
    title: "Conditions and ambiguity",
    specSection: "## P-R2-01 — Conditions and ambiguity",
    requires: ["r2"],
    mockFault: "precondition-ignored",
  },
  {
    id: "P-R2-02",
    title: "Temporary credential action and path scope",
    specSection: "## P-R2-02 — Temporary credential action and path scope",
    requires: ["r2", "cfapi"],
    mockFault: "scope-not-enforced",
  },
  {
    id: "P-R2-03",
    title: "Bucket Locks",
    specSection: "## P-R2-03 — Bucket Locks",
    // cfapi_runtime: the "runtime principal cannot alter policy" check
    // needs a genuinely separate, less-privileged token in real mode.
    requires: ["r2", "cfapi", "cfapi_runtime"],
    mockFault: "lock-not-enforced",
  },
  {
    id: "P-R2-04",
    title: "Checksums and multipart identity",
    specSection: "## P-R2-04 — Checksums and multipart identity",
    requires: ["r2"],
    mockFault: "changed-bytes-accepted",
  },
  {
    id: "P-R2-05",
    title: "Consistency and same-key pressure",
    specSection: "## P-R2-05 — Consistency and same-key pressure",
    requires: ["r2"],
    mockFault: "429-commits-write",
  },
  {
    id: "P-DO-01",
    title: "Request interleaving",
    specSection: "## P-DO-01 — Request interleaving",
    requires: ["harness"],
    mockFault: "stale-commit",
  },
  {
    id: "P-DO-02",
    title: "Alarm durability",
    specSection: "## P-DO-02 — Alarm durability",
    requires: ["harness"],
    mockFault: "alarm-lost-on-reset",
  },
  {
    id: "P-DO-03",
    title: "Overload and storage budgets",
    specSection: "## P-DO-03 — Overload and storage budgets",
    requires: ["harness"],
    mockFault: "no-shedding",
  },
  {
    id: "P-DO-04",
    title: "Incarnation and old-authority rejection",
    specSection: "## P-DO-04 — Incarnation and old-authority rejection",
    requires: ["harness"],
    mockFault: "old-authority-accepted",
  },
  {
    id: "P-CTR-01",
    title: "Lifecycle state machine",
    specSection: "## P-CTR-01 — Lifecycle state machine",
    requires: ["harness"],
    mockFault: "stale-callback-applied",
  },
  {
    id: "P-CTR-02",
    title: "Mixed rollout",
    specSection: "## P-CTR-02 — Mixed rollout",
    requires: ["harness"],
    mockFault: "unsupported-image-ready",
  },
  {
    id: "P-CTR-03",
    title: "Sleep and shutdown",
    specSection: "## P-CTR-03 — Sleep and shutdown",
    requires: ["harness"],
    mockFault: "sleep-with-open-txn",
  },
  {
    id: "P-CTR-04",
    title: "Networking and placement",
    specSection: "## P-CTR-04 — Networking and placement",
    requires: ["harness"],
    mockFault: "egress-not-denied",
  },
  {
    id: "P-WORKER-01",
    title: "Gateway bounds",
    specSection: "## P-WORKER-01 — Gateway bounds",
    requires: ["harness"],
    mockFault: "full-buffering",
  },
];
