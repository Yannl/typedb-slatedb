# ADR-0010 — Cargo-only builds, federated workspaces, and a machine-verified source lock

**Status:** accepted (brief §0.2.1/§5.10 restated as implementation decisions; operative since G0)

## Context

Upstream TypeDB builds with Bazel. The release discipline demands
reconstructible, offline, content-verified builds; the port must remain
rebaseable against upstream; and three very different toolchains coexist
(fork Rust, tools Rust, control-plane TypeScript). Flattening everything
into one build system or one workspace couples their lockfiles and
destroys upstream-shaped rebasing.

## Decision

- **Cargo (plus rustc/libtest and fork-owned xtask-style Python runners)
  is the only executed build/test orchestrator** for the Rust side; Bazel
  files are read-only discovery evidence, never executed for a release.
  Bazel semantics that tests depend on (runfiles layouts, serial groups,
  assembly archive mode, env) are reproduced explicitly by the corpus
  runner and staged symlink arrangements — each recorded in the port
  ledger with the exact upstream path defect it reproduces.
- **Federated workspaces**: `fork/typedb`, `tools/`, and `control-plane/`
  keep independent workspaces and lockfiles; nothing is flattened without
  an ADR proving behavior preservation.
- **One normative source lock** (`source-lock/source-lock.json`) pins
  every proof-critical input — git checkouts by commit+tree, artifacts by
  sha256, registry crates by version+checksum (the consume-only SlateDB
  node is verified against *every* consumer lockfile). The lock linter
  enforces it mechanically and carries a demonstrated-effective negative
  control (a corrupted checksum must fail the lint).
- **Staging model**: upstream test execution happens in the pinned
  `sources/typedb` checkout with fork files staged over it (warm cache,
  Bazel-equivalent layout); the tree is restored pristine afterwards and
  the lint requires it clean at rest.

## Consequences

- A release is reconstructible from content-verified inputs with no
  network and no Bazel; the offline `--frozen` build of the server binary
  is archived G0 evidence.
- Rebasing to a new TypeDB pin is an atomic lock-graph bump plus patch
  replay (`tools/fork/materialize.sh` reads the revision from the lock —
  never hardcoded).
- The cost is the staging dance and the discipline that every manifest
  and lockfile is fork-owned and reviewed; the lint turns violations into
  mechanical failures instead of code-review vigilance.
