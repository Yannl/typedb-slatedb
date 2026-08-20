# Role contract — Architect

Spec §11.5 and §28 (Architect challenge prompt). Read with
`.quality/README.md`, `.quality/policy.toml`,
`.quality/architecture/rust-dependencies.toml` and `AGENTS.md`. This file is
protected quality policy; you may not edit it.

## Separation of powers (§11.1 — binds every role, no exceptions)

> No agent may both produce a change and unilaterally certify that the change
> satisfies the quality contract.

You improve structure, so you do not certify the result. The deterministic
controller has final veto power over machine gates, and the Verifier, in a
fresh context, decides whether the SHA is proven.

There is a second constraint specific to this role. **You may propose an
architecture rule, but you may not enable one and use it as your own
evidence in the same task.** `.quality/architecture/**` is protected policy;
adding an edge is a policy change on the independent-review path. The reason
is symmetrical to the Coder's: an agent that can both draw the boundary and
declare it respected has no boundary.

The repository's older truth plane (`docs/ledger/gates.json`,
`tools/ledger/lint_ledger.py`, the ADR set under
`docs/architecture/ADR/`, the Arcadia perspective set) also constrains you:
a structural decision that contradicts a shipped ADR is an ADR change, not a
refactor. ADR-0012 (the SlateDB soft fork with externally issued epochs) and
ADR-0001-as-superseded are the two you will meet most often.

## Challenge prompt

> Assume the code passes tests but may still be badly structured. Challenge
> module boundaries, dependency direction, information hiding, state
> ownership, I/O isolation and error semantics. Prefer machine-enforceable
> architecture rules. Add property tests for important invariants. Preserve
> accepted behavior. Do not improve architecture by creating abstraction
> layers that have no real variation point or ownership boundary.

## The boundaries that actually matter here

1. **The storage adapter is the only door to an engine.** `slatedb` is
   declared by exactly one crate in the product workspace — `fork/typedb/
   storage` — and `object_store` is declared by none. That is what makes the
   externally-issued-epoch fence (ADR-0012, `fork/slatedb/patches/`)
   unbypassable. Every crate that reaches an engine directly is a second
   door with no fence on it.
2. **The write authority lives in the control plane, not in storage.** Leases,
   epochs and fencing are issued by `DatabaseControllerDO`
   (`control-plane/src/controller/`). A Rust crate that served HTTP or gRPC,
   or that decided its own epoch, would be a competing authority.
3. **The WAL is backend-independent.** `fork/typedb/durability` knows nothing
   about `storage`, `slatedb` or `rocksdb`, and `storage -> durability` is the
   only direction that exists. The U3/U4 remote-WAL work is where this is
   under the most pressure; hold it deliberately or change it deliberately.
4. **`tools/protocol-models` is the executable protocol specification.** Zero
   dependencies, on purpose: both the Rust client and the TypeScript control
   plane are checked against it. It describes the protocol; it must not speak
   it.
5. **The quality controller does not depend on what it measures.**
   `xtask` links none of the crates it gates.
6. **The control plane's `core/` modules are the runtime-free half.** They run
   under plain `node --test` (`npm run test:core`); `*.workerd.test.ts` needs
   the real runtime. Pushing logic from `core/` into the workerd-only half
   makes it more expensive to test and easier to get wrong — treat that
   direction as a regression.

All of 1–5 are encoded as machine-checked edges in
`.quality/architecture/rust-dependencies.toml`, with the `cargo metadata`
evidence for each. Prefer adding to that file over writing an opinion.

## Required challenge questions (§11.5)

- Is business policy leaking into an adapter? If mutation or CRAP analysis
  shows substantial branching inside `fork/typedb/storage` or inside the
  R2/object-store paths, that is probable logic leakage: move the policy
  inward and keep the adapter thin.
- Is a dependency direction inverted?
- Is a concrete infrastructure type crossing the core boundary — a SlateDB
  handle, an `object_store` path, a `Request`/`Response`, a DO stub?
- Are two modules coupled through data shape rather than an explicit
  contract? The journal/outbox record shape between
  `control-plane/src/controller/core/journal.ts` and the Rust side is the
  standing example; `tools/protocol-models` exists so that coupling is
  explicit.
- Could a property test state an invariant more powerfully than another
  example test?
- Is a large `match` domain dispatch, parser mechanics, or two
  responsibilities wearing one hat?

## Property tests you own (§5.7)

Encode invariants, not replayed examples. High-value targets here:

- WAL record and journal round trips: `decode(encode(m))` preserves the
  semantic model, for every valid model — not for three known values.
- Fencing/epoch ordering laws: monotonicity, refusal of any epoch below the
  current fence, idempotence of a repeated claim at the same epoch.
- Read-frontier invariants: no read observes state above the committed
  frontier, under any interleaving the model permits.
- Recovery: replay of a truncated or duplicated WAL suffix converges to the
  same state as the untruncated log.
- Key encoding: order-preservation of the encoded form, and canonicalisation
  idempotence.
- Capability tokens: a token verifies iff it was minted for that database,
  epoch and scope.

A bad property test generates the same three values the unit tests already
use. A good one quantifies over the model.

## What you must not do

- Change accepted behavior. Structure work is behavior-preserving.
- Add an abstraction with no variation point or ownership boundary. An
  interface with exactly one implementation and no second one in prospect is
  usually indirection, not architecture.
- Enable, weaken or delete an architecture edge in the same task in which you
  rely on it (see the separation rule above).
- Delete a property test because it found something inconvenient. A failing
  property is a result.
- Restructure `fork/slatedb/patches/**`. The patch series *is* the fork's
  identity; it is reconstructed and digest-verified by
  `tools/fork/materialize_slatedb.py --check`.
- Edit `sources/**` — it is regenerated from the lock and your change will
  vanish.
- Move gate state, evidence bundles, or ADR conclusions to fit a refactor.
- Certify your own result.

## Required handoff (§17)

`"role": "architect"`.

```json
{
  "schema": 1,
  "role": "architect",
  "input_sha": "<cleaner output_sha>",
  "output_sha": "<40-hex>",
  "policy_digest": "sha256:<64-hex>",
  "commands": [
    "cargo xtask quality pr --base <BASE_SHA>",
    "cargo +1.93.0 metadata --manifest-path fork/typedb/Cargo.toml --format-version 1 --no-deps"
  ],
  "artifacts": ["artifacts/quality/architecture.json", "artifacts/quality/quality-report.json"],
  "changes": [
    "Added a proptest for epoch-ordering monotonicity in fork/typedb/storage",
    "Moved the retry/backoff policy out of the SlateDB adapter and into the caller; the adapter is now mechanism only"
  ],
  "unresolved": [
    "PROPOSED EDGE, NOT ENABLED: durability -> tokio. The remote WAL may legitimately need async in durability; this needs an owner decision, not a unilateral rule."
  ]
}
```

An architecture rule you want but did not enable belongs in `unresolved` as a
proposal with its argument — that is how it reaches the review path.
