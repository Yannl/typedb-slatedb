# `.quality/` — deterministic quality policy

Everything in this directory is **protected quality policy** (spec §12). An
implementation agent may not modify it as part of a normal implementation task.
`cargo xtask quality policy-check --base <SHA>` refuses such a diff with
`POLICY_CHANGE_REQUIRES_INDEPENDENT_REVIEW`.

## Contents

| Path | Purpose |
|---|---|
| `policy.toml` | Thresholds (§26), protected-path list (§12), scope manifest, diff-trigger patterns (§15) |
| `tools.lock.toml` | Pinned tool versions and exact remediation commands (§19) |
| `waivers/quality-waivers.toml` | Exception register (§13) |
| `schemas/quality-report.schema.json` | JSON Schema for the unified evidence report (§4) |
| `schemas/handoff.schema.json` | JSON Schema for inter-agent handoffs (§17) |
| `architecture/` | Machine-checkable architecture invariants (§6) |
| `agents/` | Role prompts (§11) |

## Interface

```bash
cargo xtask quality fast                    # Tier A, inner loop
cargo xtask quality pr --base <BASE_SHA>    # Tier B, merge gate
cargo xtask quality full                    # Tier C, scheduled / release
cargo xtask quality policy-check --base <BASE_SHA>
cargo xtask quality verify-report --path artifacts/quality/quality-report.json
```

Exit codes are differentiated (spec §2.1, §18):

| Code | Meaning |
|---|---|
| 0 | `Pass` |
| 1 | `QualityFailure` — a gate ran and the code did not meet the contract |
| 2 | `PolicyViolation` — the diff changes protected quality policy |
| 3 | `InfrastructureFailure` — a gate could not run (missing/mismatched tool, insufficient disk, tool crash) |

All non-zero states block merge. `InfrastructureFailure` is never interpreted
as a quality pass.

## Anti-gaming properties

1. The protected-path list is loaded from the **trusted base SHA** and unioned
   with the head tree. Deleting `.quality/policy.toml` in the PR does not
   disable the check; shrinking the protected list is itself a protected change.
2. Scope is decided in exactly one machine-readable place (`[[scope.rule]]`).
   A changed file with a source extension that matches no rule is a failure,
   not an implicit pass, so a new top-level directory cannot escape the gates.
3. Renames are resolved with `git diff -M` and classified on **both** the old
   and the new path, so a rename cannot make a risky change look docs-only.
4. Tool absence and version drift are `InfrastructureFailure`, so an
   uninstalled mutation tester can never produce a green report.
5. The report records `head_sha`; `verify-report` refuses a report whose
   `head_sha` does not match the working `HEAD`. A green report for SHA `A`
   does not certify SHA `B`.

## Role contracts (`agents/`)

Seven role contracts, spec §11, each stating what the role owns, what it must
not do, and its required structured handoff (§17, validated against
`schemas/handoff.schema.json`). **The separation-of-powers rule of §11.1 —
no agent may both produce a change and unilaterally certify it — is restated
in every one of them**, because it is the property the whole pipeline is for.

| File | Role | Owns | Fresh context required |
|---|---|---|---|
| `agents/specifier.md` | Specifier / Contract Guardian | observable behavior, acceptance criteria, the independent QA plan | recommended |
| `agents/coder.md` | Coder / Builder | production implementation and focused unit tests | recommended |
| `agents/cleaner.md` | Cleaner / Refactorer | behavior-preserving improvement; cover-then-split CRAP remediation | recommended |
| `agents/architect.md` | Architect | boundaries, dependency direction, property tests | recommended |
| `agents/hardener.md` | Hardener / Breaker | mutation, fuzzing, adversarial cases | **yes** (`[agents] fresh_hardener_context`) |
| `agents/verifier.md` | QA / Independent Verifier | independent re-verification from a clean checkout | **yes** (`[agents] fresh_verifier_context`) |
| `agents/integrator.md` | Integrator (optional) | landing, never implementation | — |

## Architecture invariants (`architecture/`)

`architecture/rust-dependencies.toml` — the §6 forbidden-edge model, 33 edges
across the repository's two cargo workspaces (`fork/typedb/Cargo.toml` and
`tools/Cargo.toml`). Every edge was derived from real `cargo metadata` output
rather than from what sounds plausible, every one is currently satisfied, and
the edges deliberately **not** added are named in the file's header with the
reason. The load-bearing facts it encodes:

- `slatedb` is declared by exactly one crate in the product workspace,
  `fork/typedb/storage`; `object_store` by none. That is what makes the
  externally-issued-epoch fence (ADR-0012) unbypassable.
- `fork/typedb/durability` knows nothing about `storage` or any engine;
  `storage -> durability` is the only direction that exists.
- `tools/protocol-models` has zero dependencies of any kind — it is the
  executable protocol specification, and it describes the protocol rather
  than speaking it.
- `xtask` depends on none of the code it measures.

The model is evaluated over **declared** dependencies (`cargo metadata
--no-deps`), normal and build kinds only. Resolve-graph questions — such as
whether the product actually links the SlateDB soft fork rather than the
registry crate — have a different and stronger owner in
`tools/ci/check_dependency_sources.py`, and are deliberately not restated
here.
