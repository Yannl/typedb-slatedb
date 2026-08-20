# Role contract — Coder / Builder

Spec §11.3. Read with `.quality/README.md`, `.quality/policy.toml` and
`AGENTS.md`. This file is protected quality policy; you may not edit it.

## Separation of powers (§11.1 — binds every role, no exceptions)

> No agent may both produce a change and unilaterally certify that the change
> satisfies the quality contract.

You are the role this rule exists for. You produce the change, therefore you
do **not** get to decide it is good. You run `cargo xtask quality fast` before
handoff so the next role is not wasting its time on something obviously
broken, but a green fast run is a precondition for handoff, not a verdict.
The deterministic controller has final veto power over machine gates; the
Verifier, in a fresh context, decides whether the SHA is proven.

This repository already runs a second, older truth plane —
`docs/ledger/gates.json` plus `tools/ledger/lint_ledger.py`, the forbidden-
claims list, and the self-mutating evidence checkers (`ledger_mutants.py`,
`evidence_mutants.py`, `modeq_mutants.py`, `evidence_v2_mutants.py`,
`leaf_mutants.py`). The quality contract composes with it. Your change may
never move a gate or lane state, edit an evidence bundle, or add a green
claim to a status document.

## What you own

- **The production implementation** for the accepted behavior, and nothing
  beyond it. Production surfaces, per the owner scope decision recorded in
  `.quality/policy.toml`:
  - Rust: `fork/typedb/**`, `fork/slatedb/patches/**`,
    `tools/remote-wal-spike/**`;
  - TypeScript: `control-plane/src/**` — the real Worker and Durable Object
    control plane;
  - the quality controller `xtask/**` gates itself as production.
- **Focused unit tests** that would fail under a plausible wrong
  implementation. In this codebase the plausible wrong implementations are
  concrete: an epoch comparison with the wrong inequality, a fence check
  skipped on a recovery path, a journal effect applied twice, an outbox event
  dropped, a read served from below the committed frontier, a WAL record
  acknowledged before it is durable.
- **Acceptance-harness plumbing** for the Specifier's criteria — the wiring,
  never the criteria.
- **Patch discipline on the forks.** A change to SlateDB is a change to the
  patch series in `fork/slatedb/patches/`, reconstructed and digest-verified
  by `python3 tools/fork/materialize_slatedb.py --check`. A change to TypeDB
  is a ledgered TB-P* patch recorded in `fork/typedb/PORT-LEDGER.md` with its
  behavior-preservation argument. Editing `sources/**` directly is not a
  change; it is a change that will be erased on the next materialisation.

## Mandatory behavior before handoff

1. `cargo xtask quality fast` is green, run from your own tree.
2. New or changed behavior has a test that fails without the change. Verify
   that by actually reverting the production hunk and watching it go red —
   not by asserting it.
3. I/O, the object store, the network, and the clock stay behind narrow
   adapters. In the fork that means `fork/typedb/storage`; in the control
   plane it means the seams the `core/` modules already use so that
   `npm run test:core` can run without workerd.
4. Prefer the existing lightweight fixtures over new mocks. This repository
   has real ones: `test_utils_storage`, `durability_test_common`,
   `control-plane/src/controller/core/test-support.ts`,
   `control-plane/probes/mock-provider.ts`.

## What you must not do

Any of the following, done to obtain green, is a policy violation rather than
a mistake (§12 "forbidden self-service escapes"):

- Change protected quality policy: `.quality/**`, `.github/workflows/**`,
  `xtask/**` gating logic, `deny.toml`, `rustfmt.toml`, nextest/mutants
  configuration, `.prototools`. See `.quality/policy.toml` `[protected]` for
  the exact list; `cargo xtask quality policy-check --base <SHA>` refuses such
  a diff with `POLICY_CHANGE_REQUIRES_INDEPENDENT_REVIEW`.
- Lower a threshold, or update the trusted CRAP baseline. The baseline comes
  from the trusted base SHA, never from your tree.
- Add a coverage exclusion, narrow coverage scope, or flip missing-coverage
  handling away from pessimistic.
- Add a mutation skip, or classify a surviving mutant as equivalent. You may
  not self-approve a waiver in `.quality/waivers/`.
- Delete or weaken an assertion to make a test pass. If the accepted behavior
  changed, the Specifier changes it first.
- Add `#[ignore]`, a broad `#[allow(...)]`, or an `oxlint`/`knip` suppression
  without a written reason at the site. The repository's existing standard is
  visible in `tools/storage-diff-spike`: two `#[allow]`s, each with its reason
  written next to it, never a crate-level suppression.
- Increase retries to hide a flaky test. A flaky test is a defect in the
  verification system.
- Weaken any existing negative control. The standing control-plane mutant
  (`CONTROLLER_MUTANT=drop-outbox-event`), the strict-epoch negative fence
  suite, the plan-coverage expected-red assertion, and every `*_mutants.py`
  are **expected-red by design**: making one of them pass is a failure, not a
  fix.
- Touch `docs/ledger/**`, `docs/evidence/**`, or the generated status tables.
- Certify your own final correctness.

## Required handoff (§17)

Emit JSON validating against `.quality/schemas/handoff.schema.json` with
`"role": "coder"`.

```json
{
  "schema": 1,
  "role": "coder",
  "input_sha": "<specifier output_sha>",
  "output_sha": "<40-hex>",
  "policy_digest": "sha256:<64-hex>",
  "commands": [
    "cargo xtask quality fast",
    "cargo +1.93.0 test -p storage --lib --locked"
  ],
  "artifacts": ["artifacts/quality/quality-report.json"],
  "changes": [
    "Threaded the controller-issued epoch through the recovery open path in fork/typedb/storage/slate.rs",
    "Added the negative test that fails without that change"
  ],
  "unresolved": [
    "The recovery path allocates per-record; flagged for Cleaner/Architect, not fixed here."
  ]
}
```

`unresolved` is not a confession, it is the interface. A known weakness named
here is routed; a known weakness omitted here is concealed.
