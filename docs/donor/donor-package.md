# Donor package for the lead integration agent

**From:** the independent verification / donor-package owner
(branch `claude/typedb-donor-verification-sfxfbz`).
**To:** the lead agent integrating `claude/review-continue-previous-zv4wmi` (branch A) against
the V16 brief.
**Audited A-branch commit:** `e20cff50081b9ae4b3c5f88e6d4ef89a88b06585`.
**Donor branch tip at packaging:** `5514ce21a6e7` (engine hardening).

This branch is **not** proposed as a whole-branch merge, and this package does not recommend
one. It hands over four independently reviewable bundles. Each builds on its own and documents
its dependencies. Take what survives your own review; leave the rest.

The donor engine's object-store profile was **not** exportable in its original state — it
shipped WAL-on, GC-on, an implicit compactor, dirty-capable reads and no delete control. Those
were corrected fail-closed before anything here was offered as a donor (commit `ffbd504`), and
the correctness of that correction is proved by negative controls, not by a passing happy path.
Do not export any pre-`ffbd504` engine state.

---

## The four bundles

### 1. `donor/test-corpus-and-runner`

The machine-counted upstream test denominator and the runner that refuses to report green on an
incomplete run. This is the strongest asset in the package: a generated (not asserted) test
denominator, with fail-closed handling of anything unclassifiable.

**Crates:** `tools/corpus-catalog`, `tools/conformance-runner`, `tools/xtask` (the CLI front
end).

**What it retains, all machine-checked:** Cargo target discovery + static Bazel/Starlark
declaration reconciliation with fail-closed unknown-macro handling; typedb-behaviour scenario
and `Examples:`-row expansion (one leaf per row); failpoint-registry × loop-context expansion;
libtest leaf discovery read off the built harnesses (so a `#[cfg]`-gated or macro-generated case
cannot vanish); fixture / runfile / environment / cwd / timeout / serialization metadata;
stable target and leaf IDs; explicit exclusions and owners; zero-test and dynamic-skip
detection; negative controls; and coherent signed evidence output. The runner refuses to start
if `SCENARIO_FILTER`, `FAILPOINTS` or `RUST_TEST_ARGS` is set, because any of them silently
shrinks the corpus.

**Reusability status (item 1).** The subject tree is *already* parameterized — the catalog and
runner accept `--typedb-root` / `--behaviour-root` and every fork-relative read follows them, so
the tooling can be pointed at another checkout (e.g. `A/fork/typedb`) for the purely static
stages today. Four couplings still anchor a full run to this repo's layout and are the exact,
minimal work to make it fully checkout-independent; they are enumerated in
`docs/donor/tooling-reusability.md` with file:line and a change set. **What genuinely cannot run
against a bare fork** is the `source-lock` stage (it requires the 14 pinned `.git` checkouts)
and any executing stage (needs built harnesses + a staged fixture tree). See the reusability
note for how to run the static denominator against A without those.

**Dependencies:** `tools/Cargo.toml` workspace; a `Cargo.lock` in the subject fork (for
`cargo metadata --locked --no-deps`); no network.

### 2. `donor/source-lock-and-fixtures`

**Crate:** `tools/source-lock`. **Data:** `fixtures/typedb-behaviour`, `source-lock/source-lock.json`.

Resolves 14 upstream nodes to full commits and hashes their contents independently of git, then
refuses to lock a graph containing a dirty checkout, a pin that does not match its tag, or a
shallow clone of anything that ships. This is what makes the denominator's provenance checkable
rather than asserted. Keep it paired with bundle 1: the catalog stage reads `source-lock.json`
and aborts without it.

**Dependencies:** a materialized `sources/` tree of the 14 nodes (reproduced by
`contract/fetch-pinned-sources-v16.sh`). Standalone from the engine.

### 3. `donor/safe-performance-primitives`

The reusable engine ideas, each independently reviewable. **Crate:** `engine/slatedb-keyspace`.
Do **not** bundle these with the test harness — they share no code with it.

Four primitives the mission calls out, mapped to where they live:

1. **Manifest-based approximate-size / key-count estimation** — `size_bytes` and
   `estimated_key_count` in `src/lib.rs`. Size is summed from the manifest (no scan); key count
   is summed from each SST's stats block (O(SSTs), not O(keys)). Replaces the O(stored-bytes)
   scan that RocksDB hides behind an O(1) property. Introduced in `f8032e5`/`86f3209`; the
   key-count path is now bounded + single-flight (see below).
2. **Bounded retry/backoff and cache configuration** — `Tuning` in `src/config.rs`:
   `object_store_max_retries` (bounded, vs SlateDB's retry-forever, which under a sync facade is
   a hang), the read-through block cache, read-ahead/fetch-task scan tuning, and the R2
   operation-cost reasoning on every field.
3. **Shared-store / keyspace-prefix implementation** — `physical_key` / `logical_key` /
   `keyspace_end` in `src/lib.rs`, plus `StoreIdentity` in `src/identity.rs`. **ADR:**
   `docs/architecture/ADR/0006-shared-store-and-coalesced-writes.md`.
4. **Coalesced cross-keyspace write implementation** — `KeyspaceSet::write` + `Batch` in
   `src/lib.rs`: one logical commit = one physical `WriteBatch` = one object-store write,
   regardless of keyspaces touched. **ADR:** same as (3).

Also in this bundle, and directly relevant to A-branch defects: **exact identities**
(`identity.rs`, fixes A8), the **process-wide bounded runtime** (`runtime.rs`, fixes the
per-database-runtime defect A shares), the **bounded single-flight estimate** (`lib.rs`, fixes
A6), the **structured `RetryClass` error channel** (`error.rs`, fixes A10), and the **honest
production-qualification statement** (`qualification.rs`, the alternative to A9's green-test
hiding). Safe defaults and their negative controls: `src/safety.rs`,
`tests/posture_negative_controls.rs`.

**ADR / benchmark status:** the shared-store-vs-per-keyspace and coalesced-write ADR (item 7) is
written with the full analytical comparison the brief enumerates — per-keyspace vs shared
physical atomicity, VisibilityWatermark, checkpoint root shape, compaction/cache interference,
failure blast radius, external epoch handling, and amplification. The **differential/crash
benchmark** is recorded there as an owned, outstanding artifact, not asserted with unproduced
numbers; the one-write-per-commit and second-writer-fences-first properties are already proved
by `tests/object_store_simulator.rs`.

**Dependencies:** pinned SlateDB at `f88be86d17ac53260d3684edbc8f82811d945b5c` under
`sources/slatedb`, features `wal_disable` + `zstd`. Builds and tests green standalone
(65 tests / 7 binaries).

### 4. `donor/a-branch-adversarial-report`

`docs/donor/a-branch-adversarial-report.md` — 14 findings against A-branch commit `e20cff5`,
each with file/symbol, minimal reproducer, violated invariant and the negative test that would
have caught it. Four are P0. Two headline claims are **refuted** (A used no dirty reads at the
tip; A has no forked SlateDB / external epochs) and one is **partial** (evidence provenance).
This bundle depends on nothing.

---

## Exact SHAs

| bundle | primary commit(s) on this branch |
|---|---|
| test-corpus-and-runner | tooling history through `055cfdf`; entry point `tools/xtask` |
| source-lock-and-fixtures | `tools/source-lock`, `fixtures/`, `source-lock/source-lock.json` |
| safe-performance-primitives | `ffbd504` (safe defaults) + `f8032e5`/`86f3209` (estimates) + **`5514ce2`** (identities, qualification, runtime, single-flight, structured errors) |
| test-corpus reusability (item 1) | **`0193746`** (catalogue `--fork-root` / `--source-lock` / `--evidence-dir`) |
| a-branch-adversarial-report + denominator run + ADR-0006 + this manifest | this commit (the one adding `docs/donor/`) — its parent is `0193746` |

Audited A-branch commit for every finding: `e20cff50081b9ae4b3c5f88e6d4ef89a88b06585`.

---

## File-level import map

Files to lift, grouped by what they give you. Paths are relative to the repo root.

**Structured error channel (fixes A10; prerequisite for the rest):**
- `engine/slatedb-keyspace/src/error.rs` — `KeyspaceError { operation, retry, context }`,
  `Operation`, `RetryClass::from_slatedb`.

**Exact identities (fixes A8):**
- `engine/slatedb-keyspace/src/identity.rs` — `StoreIdentity`.
- `engine/slatedb-keyspace/tests/identity_collisions.rs` — the four non-collision proofs.
- Wire-in point: `KeyspaceSet::open_for_identity` in `src/lib.rs`.

**Process-wide bounded runtime (fixes the per-database runtime; prerequisite for single-flight):**
- `engine/slatedb-keyspace/src/runtime.rs` — `StorageRuntime`, `SCAN_ADMISSION_LIMIT`.
- Wire-in point: `KeyspaceSet::open_with_runtime` in `src/lib.rs`.

**Bounded single-flight estimate (fixes A6):**
- `engine/slatedb-keyspace/src/lib.rs` — `EstimateLimits`, `EstimateState`, `EstimateHealth`,
  `Keyspace::estimated_stats`, `scan_stats`, `serve_stale`.
- `engine/slatedb-keyspace/tests/estimate_bounds.rs`.

**Safe posture + honest qualification (fixes A7's ceiling; the alternative to A9's hidden gap):**
- `engine/slatedb-keyspace/src/config.rs` — `Tuning::validate`, `SAFE_L0_CEILING`, `read_options`.
- `engine/slatedb-keyspace/src/safety.rs` — `DeleteGuard`, `PostureAttestation`.
- `engine/slatedb-keyspace/src/qualification.rs` — `production_qualification`, `FeatureStatus`.
- `engine/slatedb-keyspace/tests/posture_negative_controls.rs`.

**Shared store + coalesced writes (donor primitives 3, 4):**
- `engine/slatedb-keyspace/src/lib.rs` — `physical_key`/`logical_key`/`keyspace_end`,
  `KeyspaceSet::write`, `Batch`.
- `docs/architecture/ADR/0006-shared-store-and-coalesced-writes.md`.

**Test denominator (bundle 1) + provenance (bundle 2):**
- `tools/corpus-catalog/`, `tools/conformance-runner/`, `tools/xtask/`, `tools/source-lock/`.
- `docs/donor/tooling-reusability.md` — the four couplings and the minimal `--fork-root` change.

---

## What NOT to export

The mission is explicit, and so is this package. Do not export from the donor engine any of:
WAL-on, GC-on, an expiring or listing-based checkpoint as if it were a release checkpoint, a
weak path-derived prefix, a per-database runtime, or a stringly-typed storage error. Every one
of those was a defect here before it was fixed, and A-branch still carries several of them
(A1, A6, A7, A8, A9) — the adversarial report is where they are named.

After this package and the A-branch run, the donor owner stops broad implementation and remains
available only as a verification oracle.
