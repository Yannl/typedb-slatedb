# ADR-0001 — Federated workspaces, and no task runner at G0

**Status:** accepted, Phase A (G0)
**Contract:** brief §21.1, Appendix H; addendum A17.2

## Context

The programme forbids a single root Cargo workspace spanning TypeDB and SlateDB, because
that would change feature unification, profile selection and lock resolution relative to
upstream — and U0/U1 equality is meaningless if the fork resolves its dependency graph
differently from the pin. Addendum A17.2 additionally retains moonrepo as a
repository-level task orchestrator, with the constraint that removing it must never change
a build or test outcome.

## Decision

Three independent Cargo workspaces, upstream paths preserved:

| Path | Workspace | Origin |
|---|---|---|
| `fork/typedb/` | 42 members + root package, upstream layout untouched | TB `2256711a` |
| `fork/slatedb/` | upstream layout untouched | SL `f88be86d` |
| `tools/` | fork-owned: `xtask`, `corpus-catalog`, `conformance-runner`, `source-lock` | new |

`sources/` holds the pinned checkouts with their git history and is the ground truth for
every source-anchored claim. `fork/` holds the working copies that patches apply to. U0
runs against `sources/typedb` precisely because it must be pristine; U1 will run against
`fork/typedb`.

The normative command boundary is `cargo xtask <command>`, wired through the repository
`.cargo/config.toml` alias. Each command is runnable directly as
`cargo run --manifest-path tools/Cargo.toml -p xtask -- <command>`, so the alias is
convenience, not authority.

**No task runner is introduced at G0.** Addendum A17.2 permits moonrepo, and Appendix H.2
permits `just`/Make/moon by ADR — but permission is not obligation. At G0 there is exactly
one build system per workspace and a handful of xtask entry points; a runner would add a
pinned binary, a cache layer, and a negative control ("prove removing it changes nothing")
in exchange for no capability the programme currently needs. The decision is revisited when
the control-plane pnpm workspace lands in Phase G and there is genuinely cross-language
ordering to express. Until then, the release evidence records bare commands, which is what
A17.2 requires of it anyway.

## Consequences

* Cargo feature unification, profiles and lock resolution behave exactly as upstream per
  workspace, so a U0/U1 difference cannot be blamed on repository layout.
* `tools/` builds on stable Rust independently of the 1.93.0 parity lane, so tooling
  bugs cannot be confused with corpus behaviour.
* Adding a runner later is cheap; removing one that gate evidence had come to depend on
  would not be.

## Alternatives rejected

* **Single root workspace.** Rejected by the contract, and rightly: it silently changes the
  dependency resolution the oracle is defined against.
* **Adopt moonrepo now.** Deferred, not refused. It buys CI caching the programme cannot
  use yet — brief §21.9 and Appendix H.2 both forbid cache reuse for real-account,
  credential and fault tests, which is most of what G2 onward runs.
