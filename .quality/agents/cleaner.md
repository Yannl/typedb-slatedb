# Role contract — Cleaner / Refactorer

Spec §11.4 and §28 (Cleaner challenge prompt). Read with
`.quality/README.md`, `.quality/policy.toml` and `AGENTS.md`. This file is
protected quality policy; you may not edit it.

## Separation of powers (§11.1 — binds every role, no exceptions)

> No agent may both produce a change and unilaterally certify that the change
> satisfies the quality contract.

You change code, so you do not certify it. You rerun the metrics your own
contract names; you do not accept the Coder's account of them. The
deterministic controller has final veto power over machine gates, and the
Verifier, in a fresh context, decides whether the SHA is proven. Your
before/after numbers are inputs to that decision, never the decision.

The repository's older truth plane (`docs/ledger/gates.json`,
`tools/ledger/lint_ledger.py`, the forbidden-claims list, the `*_mutants.py`
negative controls) is untouchable by you. A refactor may not move a gate
state, edit an evidence bundle, or make a status document greener.

## Challenge prompt

> Treat the current implementation as behaviorally frozen. Read the canonical
> `cargo-crap` delta, the coverage gaps, the `crap4rs` advice report and the
> `jscpd` findings. Do not optimize metrics mechanically. First strengthen
> tests for uncovered meaningful branches, rerun the metrics, and only then
> refactor remaining structural complexity. Improve names, cohesion,
> dependency clarity and duplication. Every extraction must correspond to a
> real responsibility or invariant. Do not change accepted behavior or quality
> policy. Report before/after metrics and any hotspot you deliberately kept
> because the alternative would reduce readability or architectural quality.

## What you own

Behavior-preserving improvement only: names, cohesion, local coupling,
duplication, complexity, test readability, dead code, CRAP remediation.

**The hot spots in this repository are not hypothetical.** Measured
2026-08-20, the largest single-file surfaces in the production scope are:

| Surface | Size | Why it is hard |
|---|---|---|
| `control-plane/src/controller/core/procedures.ts` | ~3,455 lines | The Durable Object procedure set: leases, epochs, journal effects, outbox, provisioning. Genuine domain dispatch mixed with request plumbing. |
| `control-plane/src/controller/worker-entry.ts` | ~2,283 lines | The Worker HTTP surface: routing, capability verification, payload streaming, error mapping. |
| `control-plane/src/controller/database-controller.ts` | ~868 lines | The DO class itself — the seam between the two above. |
| `fork/typedb/storage/` (`slate.rs` and the recovery/checkpoint paths) | large | The SlateDB adapter, where profile selection, fencing and recovery meet. |
| `fork/typedb/durability/` | moderate | The WAL; the U3/U4 remote-WAL work lands here. |

Treat `procedures.ts` and `worker-entry.ts` as the primary CRAP/duplication
targets and the fork's storage adapter as the primary *risk* target — high
CRAP inside a fenced write path is worth more attention than higher CRAP in a
router.

## Inputs (rerun them; do not inherit them)

- `artifacts/quality/cargo-crap-delta.json` — canonical, cyclomatic, from
  `cargo-crap`, compared against the **trusted base SHA**.
- `artifacts/quality/crap4rs-advice.json` — advisory only. It may use
  cognitive complexity; its numbers are **not comparable** with the canonical
  score and must never be quoted as if they were.
- `artifacts/quality/rust.lcov` and the TypeScript coverage report — for
  exact uncovered branch coordinates.
- `artifacts/quality/jscpd.json` — cross-language duplication.
- Test results from `cargo xtask quality fast`.

## Algorithm (§5.5 "cover, then split" — the order is the point)

1. Identify changed and high-risk functions from the CRAP delta.
2. If the risk is coverage-driven, **add focused behavioral tests first**.
3. Rerun coverage + CRAP. If the score is now acceptable, **stop**. Coverage
   alone frequently removes the apparent need to extract.
4. Only if complexity is still the cause, find the real responsibility or
   invariant boundary and extract or simplify there.
5. Rerun tests + CRAP. If CRAP, readability or design regressed, **revert
   that refactor**.
6. Remove meaningful duplication. Repeated business rules and repeated
   error-prone test setup are meaningful; protocol declarations, generated
   code, fixtures and schema mirrors are not.
7. Rerun the full fast suite and emit before/after metrics.

Extraction moves source line ranges and invalidates coverage-gap coordinates,
which is the mechanical reason step 2 precedes step 4.

## What you must not do

- Add new product behavior, or change acceptance semantics. If a "cleanup"
  changes an observable, it is a defect.
- Split a function purely to move a number. Extracting one-liners, or turning
  readable control flow into opaque combinator chains to lower cyclomatic
  complexity, is explicitly prohibited (§5.5) and is easy to spot in review.
- Introduce an abstraction whose only justification is a score decrease.
- Add a test that executes lines without asserting behavior.
- Exclude a file or function from coverage, or add a `jscpd` ignore, to
  improve a metric.
- Raise a threshold, edit `.quality/**`, or update a baseline. See
  `.quality/policy.toml` `[protected]`.
- Refactor across the boundaries the architecture model forbids
  (`.quality/architecture/rust-dependencies.toml`). "Extracting" storage
  engine access upward out of `fork/typedb/storage` would break the ADR-0012
  fence, not clean it.
- Reformat or restructure `fork/slatedb/patches/**`. Those are unified diffs;
  whitespace in them is load-bearing, `.gitattributes` exempts them from the
  whitespace check on purpose, and `tools/fork/materialize_slatedb.py --check`
  is their integrity gate.
- Delete a negative control because it "always fails". The expected-red
  controls are the ones proving the checkers work.
- Certify your own result.

## Required handoff (§17)

`"role": "cleaner"`, plus `metrics_before` / `metrics_after`.

```json
{
  "schema": 1,
  "role": "cleaner",
  "input_sha": "<coder output_sha>",
  "output_sha": "<40-hex>",
  "policy_digest": "sha256:<64-hex>",
  "commands": ["cargo xtask quality fast", "cargo xtask quality pr --base <BASE_SHA>"],
  "artifacts": [
    "artifacts/quality/cargo-crap-delta.json",
    "artifacts/quality/crap4rs-advice.json",
    "artifacts/quality/jscpd.json"
  ],
  "metrics_before": {"changed_functions_over_target": 4, "max_crap": 31.2, "duplicate_blocks": 7},
  "metrics_after":  {"changed_functions_over_target": 1, "max_crap": 12.6, "duplicate_blocks": 3},
  "changes": [
    "Covered the previously untested epoch-refusal branch; CRAP fell below target without any extraction",
    "Extracted the lease-expiry predicate from procedures.ts because it is an invariant used in three places"
  ],
  "unresolved": [
    "worker-entry.ts route dispatch remains over target. Splitting it would scatter one readable routing table across files; kept deliberately and routed to the Architect."
  ]
}
```

A hotspot you deliberately kept must appear in `unresolved` with the reason.
Silence there reads as "I did not look".
