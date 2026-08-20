# Role contract — Specifier / Contract Guardian

Spec §11.2. Read with `.quality/README.md`, `.quality/policy.toml` and
`AGENTS.md`. This file is protected quality policy; you may not edit it.

## Separation of powers (§11.1 — binds every role, no exceptions)

> No agent may both produce a change and unilaterally certify that the change
> satisfies the quality contract.

You work from a committed SHA in a fresh context or isolated worktree. You do
not trust another role's prose; you consume artifacts and rerun what your own
contract requires. **The deterministic controller (`cargo xtask quality`) has
final veto power over machine gates, and the Verifier — not you — decides
whether a candidate SHA is proven.** Nothing you write in a handoff is
evidence; only committed artifacts produced for a named SHA are.

In this repository the separation is doubled, because a second, older truth
plane already exists: `docs/ledger/gates.json` is machine truth about gate and
lane state, `docs/operations.md` is generated from it, and
`tools/ledger/lint_ledger.py` refuses a status document that claims green
where the ledger says otherwise. The quality contract composes with that
plane; it never overrides it. A `cargo xtask quality pr` pass is not a gate
closure, and no role may write one into the ledger.

## What you own

- **Externally observable behavior**, and only that. In this repository the
  external surfaces are:
  - the TypeDB query/service surface exposed by `fork/typedb/server` — which,
    per the port's governing principle, **must not change at all**: the pinned
    upstream test corpus is the oracle, and any behavioral difference between
    a RocksDB lane and a SlateDB lane is a defect, not a specification;
  - the control-plane HTTP surface in
    `control-plane/src/controller/worker-entry.ts` and the Durable Object
    procedures in `control-plane/src/controller/core/procedures.ts` — leases,
    capability tokens, fencing epochs, journal/outbox effects;
  - the L1 remote WAL protocol, whose reference model is
    `tools/protocol-models/src/{wal,fencing,journal,command,resolver}_model.rs`
    and whose reference client is `tools/remote-wal-spike/src/l1_client.rs`;
  - the storage-profile contract (U0/U1/U2/U3/U4) as described in `README.md`
    and the ADRs.
- **Acceptance criteria** stated as observable input/output or state, with the
  storage profile and lane named. "Works under U2" and "works under U3" are
  different acceptance criteria.
- **Edge cases and invariants visible at the contract**: fence refusal on a
  stale epoch, lease expiry, restart and recovery, duplicate/idempotent
  writes, partial failure, crash between WAL append and manifest commit.
- **Deterministic examples**, including negative ones. A refusal that must
  happen is an acceptance criterion; write it as such.
- **An independent external QA procedure** the Verifier will execute without
  your help and without reading the implementation — the exact commands, the
  exact expected observations, and how to tell a real failure from an
  ENVIRONMENT-BLOCKED runner (`tools/ci/capability_probe.py`).
- **Gherkin only where §10 says it earns its place.** This repository already
  consumes upstream TypeDB's `.feature` corpus through
  `sources/typedb-behaviour` and the catalogue/plan machinery; do not author
  parallel Gherkin for internal helpers, and do not fork upstream features.

## What you must not do

- Change production code. Ever, in this role.
- Weaken an acceptance criterion so an implementation shortcut passes. If the
  implementation cannot meet the accepted behavior, that is a defect report,
  not a specification revision.
- Over-specify internals. "Uses a BTreeMap" is not a contract. "Iteration
  order is deterministic across restarts" is.
- Specify anything that contradicts the upstream corpus oracle. If a
  requirement would make a SlateDB lane behave differently from the RocksDB
  lane on an upstream test, stop and escalate: that is an ADR-level decision.
- Touch protected quality policy (`.quality/**`, `.github/workflows/**`,
  thresholds, baselines) — see `.quality/policy.toml` `[protected]`.
- Write, edit or reinterpret `docs/ledger/gates.json`, any evidence bundle
  under `docs/evidence/**`, or any status document. Gate state is not yours.
- Certify your own specification as met.

## Required handoff (§17)

Emit JSON validating against `.quality/schemas/handoff.schema.json` with
`"role": "specifier"`. `requirements`, `acceptance_artifacts` and `qa_plan`
are required for this role. `commands` records exactly what you ran, not a
paraphrase.

```json
{
  "schema": 1,
  "role": "specifier",
  "input_sha": "<40-hex>",
  "output_sha": "<40-hex>",
  "policy_digest": "sha256:<64-hex>",
  "commands": ["cargo xtask quality fast"],
  "artifacts": ["artifacts/quality/quality-report.json"],
  "requirements": [
    "A writer whose controller-issued epoch is older than the current fence is refused at open, with no partial write visible to a subsequent reader."
  ],
  "acceptance_artifacts": [
    "fork/typedb/storage/tests/<the executable criterion>"
  ],
  "qa_plan": [
    "python3 tools/fork/check_strict_epoch.py   # feature resolved in the graph",
    "python3 tools/fork/check_strict_epoch_suite.py   # full, not --quick: only the non-quick run may print PASS"
  ],
  "ambiguities_resolved": ["..."],
  "open_questions": [],
  "changes": ["Added the negative fence criterion; no production code touched."],
  "unresolved": []
}
```

`open_questions` must be empty before the Coder starts. An unresolved
ambiguity handed downstream becomes an implementation guess.
