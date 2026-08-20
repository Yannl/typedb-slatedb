# AGENTS.md — the operating contract for any agent working in this repository

Short and enforceable on purpose. The detailed role prompts live in
`.quality/agents/`; the machine-readable policy lives in `.quality/policy.toml`;
the deterministic controller is `cargo xtask quality`.

Not to be confused with `contract/AGENTS.md`, which is the **archived**
operating note from the received inception package (see
`docs/inception/ARCHIVE-NOTE.md`). This file governs work done now.

---

## 1. Two truth planes, and neither one is your prose

This repository already ran a truth plane before it had a quality contract,
and the quality contract **composes with it rather than replacing it**.

**Plane 1 — evidence and gate state.** `docs/ledger/gates.json` is machine
truth about gates, lanes and actions. `docs/operations.md` is generated from
it. `tools/ledger/lint_ledger.py` fails CI when a status document contains a
forbidden claim, when a gate the ledger holds open is described as green, when
a closed action cites a commit that does not exist or is not an ancestor of
`HEAD`, or when a rendered table drifts. Evidence bundles under
`docs/evidence/**` re-verify from their own raw bytes, and every checker
executes its own forgery mutants (`tools/ledger/ledger_mutants.py`,
`tools/catalog/evidence_mutants.py`, `tools/modeq/modeq_mutants.py`,
`tools/evidence/evidence_v2_mutants.py`, `tools/qualification/leaf_mutants.py`,
`tools/source-lock/lock_mutants.py`, `tools/drivers/driver_mutants.py`).

**Plane 2 — code quality.** `cargo xtask quality` decides whether a change
meets the quality contract, from machine-readable evidence.

They do not overlap and they do not override each other. **A passing
`cargo xtask quality pr` is not a gate closure**, must not be written into
`docs/ledger/gates.json`, and must not be summarised as "green" in any status
document. Gate state changes are their own reviewed act with their own
evidence.

## 2. Toolchain

Pins live in `.prototools` and are the declared source of truth (`proto
install`; in environments without proto, honour the same versions and record
them in `docs/evidence/G0/toolchains.json`). Removing proto/moon must never
change a build or test outcome.

| Tool | Pin |
|---|---|
| rust | 1.93.0 (`rustfmt` is pinned separately at `nightly-2026-04-15`, because rustfmt output changes between nightlies) |
| node | 22.22.2 |
| pnpm | 10.33.0 |
| python | 3.11.15 (**note:** the CI workflows currently request 3.11.9 via `actions/setup-python`; the divergence is real and unreconciled — do not "fix" it in an implementation diff, it is a protected-policy decision) |
| protoc | 3.21.12 |
| cmake | 3.28.3 |

Quality-tool versions are pinned in `.quality/tools.lock.toml`. A missing or
mismatched tool is an `InfrastructureFailure`, never a pass.

## 3. The quality contract

1. **Do not modify `.quality/**`, the CI quality workflows, quality
   thresholds, coverage exclusions, mutation skips, lint allowlists,
   architecture rule files, or trusted baselines during a normal
   implementation task.** The exact protected list is
   `.quality/policy.toml` `[protected]`; `cargo xtask quality policy-check
   --base <SHA>` refuses such a diff with
   `POLICY_CHANGE_REQUIRES_INDEPENDENT_REVIEW`. Removing a path from the
   protected list is itself a protected change.
2. **Run `cargo xtask quality fast` before handing off implementation work.**
3. **A green test run is necessary but not sufficient.** Rust production
   changes are additionally subject to coverage instrumentation checks, a CRAP
   delta against the trusted base SHA, differential mutation testing,
   architecture checks and independent verification.
4. **Never weaken or delete a test to make a change pass** unless the accepted
   behavior itself changed and the Specifier updated it first.
5. **Do not add a lint, coverage, mutation or duplication exclusion** without
   an explicit quality-policy change on the review path. A local `#[allow]` or
   `oxlint-disable` carries its reason at the site.
6. **Cleaner refactors preserve behavior.** When CRAP is driven by both low
   coverage and high complexity, **cover first, then split** — and revert any
   refactor that makes the function worse.
7. **The deterministic quality controller, not an agent's judgement, decides
   whether machine gates pass.** `InfrastructureFailure` and
   ENVIRONMENT-BLOCKED are not passes, and a skipped or `continue-on-error`
   job is not a pass. There is no `continue-on-error:` on any job or step in
   `.github/workflows/**`; keep it that way.
8. **All handoffs reference committed SHAs and machine-generated artifacts**,
   and validate against `.quality/schemas/handoff.schema.json`. A report
   produced for SHA `A` does not certify SHA `B`.
9. **No agent both produces a change and certifies it** (§11.1). See
   `.quality/agents/` for the seven role contracts.

## 4. Repository-specific rules that override generic instincts

- **The upstream test corpus is the oracle.** A SlateDB lane that behaves
  differently from the RocksDB lane on an upstream test is a defect, not a new
  specification. Do not change an upstream expectation to make a port pass.
- **`sources/**` is generated.** It is materialised from `source-lock/` and is
  gitignored. Editing it is not a change; it will be erased. Author in
  `fork/typedb/**`, and stage with `tools/fork/stage.py`.
- **The SlateDB fork is a patch series.** `fork/slatedb/patches/` is the
  fork's identity, reconstructed byte-for-byte and digest-verified by
  `python3 tools/fork/materialize_slatedb.py --check`. Whitespace inside those
  `.patch` files is load-bearing and `.gitattributes` exempts them from the
  whitespace check; never reformat them.
- **`storage` is the only door to a storage engine.** `slatedb` is declared by
  exactly one crate; `object_store` by none. The externally-issued-epoch fence
  (ADR-0012) depends on that. The machine-checked edges are in
  `.quality/architecture/rust-dependencies.toml`.
- **Expected-red controls are load-bearing.** The standing control-plane
  mutant (`CONTROLLER_MUTANT=drop-outbox-event`), the strict-epoch negative
  fence suite, the plan-coverage exit-1 assertion, and every `*_mutants.py`
  are supposed to fail. Making one of them pass is a regression.
- **`--quick` is not `PASS`.** `tools/fork/check_strict_epoch_suite.py
  --quick` prints `PARTIAL` by design; only the non-quick run may be cited as
  evidence.
- **Do not add an unpinned GitHub Action.** Every action in
  `.github/workflows/**` is pinned to a commit SHA that was resolved and
  recorded; `zizmor` audits the workflows on every push and PR.

## 5. Where to look

| You need | Read |
|---|---|
| Your role's contract | `.quality/agents/<role>.md` |
| The machine policy | `.quality/policy.toml`, `.quality/tools.lock.toml` |
| Architecture invariants | `.quality/architecture/rust-dependencies.toml` |
| Handoff / report shape | `.quality/schemas/` |
| Repo layout, build, test lanes | `docs/development.md` |
| Gates, evidence, runbooks | `docs/operations.md` (generated — edit the ledger, not the table) |
| Architecture and ADRs | `docs/architecture.md`, `docs/architecture/ADR/` |
