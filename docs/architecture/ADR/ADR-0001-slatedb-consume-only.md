# ADR-0001 — SlateDB is consume-only: pinned crates.io dependency, no fork

**Status:** accepted (owner decision, 2026-08-16)
**Amends:** brief v16 §0.2.1 (federated workspaces), §8.3–8.4 / §12.7 (SL-P1–SL-P4 as source patches), §21.1 (fork/slatedb materialization)

## Decision

SlateDB is consumed as an ordinary Cargo dependency from crates.io, pinned by
exact version and registry checksum. There is no `fork/slatedb` workspace, no
vendored SlateDB source tree, and no fork-owned SlateDB patch series.

- Dependency: `slatedb = { version = "=0.15.0", default-features = false }`
- Checksums (recorded in `tools/Cargo.lock` and source-lock node `SL`):
  - `slatedb 0.15.0` — `35ca56b01922b15aa69fe3abb62cadc985d86032c9647e4606e211c4da751a76`
  - `slatedb-common 0.15.0` — `0aa8de522ff46a0f9b5a66f45e650d125421d4d91990933591092f9d010c40d1`
  - `slatedb-txn-obj 0.15.0` — `d85fd9c0c86dd4954524fa8238d0548bd80f4a9a66983cbde3728402d339993e`
- The source-lock node `SL` changed `kind: git → registry`;
  `tools/source-lock/lint_source_lock.py` now verifies the node against the
  consumer `Cargo.lock` (version + checksum), with a demonstrated-effective
  negative control (corrupted checksum ⇒ lint FAIL).

## Identity change and re-validation

The prior pin was git commit `f88be86d` — **32 commits ahead** of the last
published release (`git describe`: `v0.15.0-32-gf88be86`). Moving to the
registry artifact therefore changed the tested identity to the released
`v0.15.0`. The semantics differential (`tools/storage-diff-spike`) was re-run
against the registry artifact and passed 2/2 with an effective negative
control (byte-order equivalence, read-your-writes, WriteBatch atomicity,
prefix-range scans, reopen durability — see
`docs/evidence/G3/slatedb-differential-registry.json`). The pre-switch run at
the git pin remains archived (`slatedb-differential.json`).

Nothing consumed today requires any of the 32 unreleased commits. If a future
need lands upstream (e.g. RFC-30 custom WAL hooks), the response is a version
bump to the release that contains it — never a fork of an unreleased commit.

## What replaces the SL-P1–SL-P4 source patches

The brief's four planned SlateDB patches existed because the design moves
write authority out of the engine into the `DatabaseControllerDO`. Each
obligation is retained but relocated to layers we own:

| Was | Obligation | Now lives at |
|---|---|---|
| SL-P1 | stale writer/compactor cannot publish reachable metadata | TypeDB-owned fencing `ObjectStore` wrapper: every SlateDB object I/O passes a controller-leased gate; on lease loss/revocation the wrapper fails closed (rejects writes), so a zombie engine cannot publish. Controller-issued epochs live in the lease protocol (see `tools/protocol-models/src/fencing_model.rs`), not inside SlateDB manifests. |
| SL-P2 | no unfenced active-manifest mutation; no protective checkpoints guarding deletion that is disabled | config: GC/checkpoints disabled via public `Settings`; production import ban on `slatedb::admin` enforced by fork-side static checks (same regime as the existing 141 statics). |
| SL-P3 | explicit compactor lifecycle | run with in-process compactor disabled via public config; any future standalone compactor runs as its own controller-leased process behind the same fencing wrapper. |
| SL-P4 | fail-closed retry/conditional/iterator behavior | the wrapper converts ambiguous object-store outcomes to hard errors before SlateDB sees them; residual engine-internal fail-open paths, if any are proven at TB-P7 failpoint testing, are handled by upstream PR + version bump. |

**Escape hatch:** if post-G2 evidence proves an obligation genuinely cannot be
met at the `ObjectStore` boundary or via public config, the order of remedies
is (1) upstream PR and pin the release that ships it, (2) only then a fork —
and that requires a new ADR reversing this one.

## Consequences

- `fork/` contains only `fork/typedb`. `tools/fork/materialize.sh` no longer
  materializes SlateDB. `.gitignore` no longer references `sources/vendor-slatedb`.
- Offline/reproducible release builds vendor SlateDB the same way as every
  other crates.io dependency (`cargo vendor` over `tools/Cargo.lock`,
  checksums recorded); no special-case source tree.
- The feature allowlist from the brief is unchanged and needs no patch:
  `wal_disable`, `aws`, `foyer` are stock upstream features
  (`default-features = false` everywhere).
- Historical G0/G3 evidence referencing the git pin and vendored tree remains
  archived unmodified; new evidence records the registry identity.
