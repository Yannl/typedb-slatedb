# V16 convergence audit

**Normative contract:** `contract/typedb-r2-implementation-brief-v16.md` (+
`typedb-r2-v17-final-addendum.md`), imported from donor branch
`claude/typedb-r2-implementation-q1vb0j` @ `8dc0398` in commit `65da032` —
this branch previously referenced the brief without carrying it.
**Convergence base:** this branch (`claude/review-continue-previous-zv4wmi`).
**Method:** every directive finding was verified against the actual code
before any status was assigned. Statuses: **CLOSED** (code + negative
control + evidence, SHA cited), **PARTIAL** (some of the finding closed,
remainder itemised), **OPEN-P0** (accepted, staged design recorded, no
completion claim), **CONTESTED** (directive conflicts with a pinned ADR or
with the brief itself; decision record required before code moves).

An item is only CLOSED here if a test exists that FAILS when the defect is
deliberately reintroduced, and the mutant run was actually executed.

**Status update (closure session, merged to main in PR #1 @ `5f9fbd5`):**
the statuses in the section bodies below are the audit-time assessments;
the closure session then moved several of them. The heading of each
section carries the CURRENT status; where it differs from the body, the
heading (and this table) wins. Closures this session, each with executed
negative controls and mutant runs:

| Finding | Now | Closure commit |
|---|---|---|
| F3 storage side (purge at open) | CLOSED | `3c00b9e` — immutable materialisation namespaces; open never deletes; `NoDeleteStore` |
| F7r exact u64 sequences | CLOSED | `997da46` — BE-blob SQL, bigint core, decimal-string wire; 2^53 mutant |
| F7r/F6r controller surface | PARTIAL→ journaled authority commands (NOT the inv. 85–98 command ledger — Q-28), CheckpointCut, anchored verification | `d47378e` (F6r remainder: TypeDB-integrated global cut, U3.2) |
| F8 authenticated journal | CLOSED (R2 RecoveryAnchor publication remains) | `ed13a9a` |
| F9 data-path hardening | CLOSED (streaming payloads remain) | `fe853aa` — capability tokens, content-addressed keys |
| F10 verification infra | CLOSED (Mode-Q Bazel oracle remains) | `b76ad35` — fail-closed declaration parsing, leaf recounts, flake ledger |
| Donor A3 (session-bound finalize) | CLOSED | `c71b8e1` |
| Donor A6 (metrics lock + dead memo) | CLOSED | `f8c1bae` |

Still OPEN-P0 by design (staged, no completion claim): F4/F5 external-epoch
fork (interim posture guard landed in `3c00b9e`), F6r global-cut
integration, F8r RecoveryAnchor publication. Donor P1 dispositions:
`docs/reviews/donor-a-branch-response.md`.

---

## F2 — SlateDB read contract (`dirty=true`) — **CLOSED** @ `65da032`

- **File/symbol:** `fork/typedb/storage/keyspace/slate.rs`
  `read_options()` / `scan_options()`.
- **Was:** both resolved `with_dirty(true)`. SlateDB defines `dirty` as
  rows whose sequence exceeds the last **committed** sequence — a
  concurrent batch mid-commit was observable, violating inv. 74 (resolved
  committed/non-dirty memory-visible options, no caller override).
- **Failure scenario:** reader thread scans while another thread's
  `write_with_options` batch is inside the write pipeline (between
  memtable insertion and commit): the reader observes a torn prefix of an
  atomic TypeDB commit batch.
- **Patch:** options resolve to the defaults — exactly
  `{DurabilityLevel::Memory, dirty:false}`; no other option constructor
  exists in the module, so no caller can override (inv. 74's second
  clause). Read-your-writes (inv. 75) needs no dirty flag: SlateDB
  advances the committed sequence inside the write path before
  `write_with_options` resolves (`batch_write.rs` — the ordering the brief
  itself cites at anchor 25).
- **Negative control (the exact control anchor 25 names):** dev-only
  `fail-parallel/failpoints` feature unification arms SlateDB's built-in
  `write-batch-pre-commit` hook.
  `read_contract_tests::paused_precommit_write_is_invisible_to_committed_frontier_reads`
  pauses a write between memtable insertion and commit; asserts a
  `dirty:true` probe SEES the row (mutant detector) while the production
  options see nothing (get AND scan); resumes; asserts the same options
  then see the committed row.
- **Mutant run executed:** `with_dirty(true)` reintroduced → test fails
  with `a pre-commit write leaked through read_options()`; restored →
  passes.
- **Evidence:** storage crate suite baseline-equal on U2 and U2S3 after
  the flip (6/10/4/14 green + the two upstream recovery stubs); database
  `test_transaction` 31/31; durability 12+5. Full-corpus re-proof ON THE
  NEW CONTRACT: `docs/evidence/G3/u2s3-full-2/` — built and run from ONE
  commit (`c75a1af`, which contains every convergence change): 106
  executables, 105 green, 1 baseline-identical red (upstream recovery
  stubs), 0 timeouts, 0 unexplained divergences vs the U1 oracle
  (`u2s3-full-2-vs-oracle-comparison.json`; the single +1-case delta is
  this audit's own read-contract control, classified in the artifact).
- **Fail-closed/observability:** contract violation is impossible to
  reach by configuration — the options are hard-resolved in one place.

## F3 — destructive purge of the remote prefix at open — **CLOSED (storage side) @ `3c00b9e`**

- **File/symbol:** `fork/typedb/storage/keyspace/slate.rs` `open_s3()`
  (`purge_remote_prefix` + `upload_dir_to_remote`), `purge_remote()` used
  by `KeyspaceSet::delete`.
- **Current behavior:** open purges the keyspace's own derived prefix and
  re-seeds it from the local lifecycle marker. This is the deliberate
  U2S3 *local-lane* transcription of the disposable-store model
  (ADR-0003: TypeDB WAL is sole authority; RocksDB lane deletes the local
  dir the same way) — and it is proven by the corpus. It is **not** a
  production posture: inv. 81–84 and inv. 11/21 (no delete-capable
  runtime credential before G13) forbid exactly this on shared R2, where
  a duplicate container or stale actor purging the active materialisation
  is catastrophic.
- **Violated invariants (production):** 81 (one active materialisation
  per generation), 82 (scratch/active never collide), 83 (stale actor =
  orphan bytes only), 84 (no reachable delete authority before G13).
- **Staged design (v16-aligned):** immutable namespaces
  `<environment>/<DatabaseId>/<DatabaseGeneration>/<MaterializationId>/<KeyspaceId>/<format-version>/…`;
  open NEVER deletes — a new materialisation gets a fresh
  `MaterializationId` and the controller activates it (checkpoint state
  machine); stale materialisations are report-only-GC candidates
  (inv. 105). Delete authority exists only in a separated maintenance
  principal after G13. Lands with U3.2 (generation rollover), where
  MaterializationId naturally enters the protocol.
- **What already narrows the risk:** the prefix encoding is injective per
  keyspace path, so no purge can cross keyspaces; checkpoint/restore
  paths use the raw store but never delete outside the derived prefix;
  the U2S3 lane is single-actor by contract of the conformance runner.
- **Required tests when closed:** resumed-stale-container cannot delete
  or alter the active materialisation; duplicate-open allocates a new
  MaterializationId and cannot publish over the active one; credential
  matrix proves no delete scope (inv. 84's "mere symbol absence is not
  proof" — probe-based).

## F4 — SlateDB soft fork with exact external epochs — **CONTESTED → decision record ADR-0012 (accepted-as-plan)**

- **Conflict:** ADR-0001 pins consume-only crates.io SlateDB; the brief
  (inv. 78–80, SL-P1/SL-P2 matrix, §fencing) requires externally issued
  `SlateWriterEpoch`/`SlateCompactorEpoch` on every publication path,
  which upstream 0.15.0 does not expose (epochs are internally allocated
  in `FenceableManifest`). The donor branch carries a full
  `fork/slatedb` + path-dep (`sources/slatedb`) proving the fork route
  is workable.
- **Position:** production (post-G2) cannot ship on unmodified 0.15.0 —
  ADR-0012 frames the supersession of ADR-0001's consume-only rule for
  the production lane while keeping crates.io SlateDB for the local
  conformance lanes (U2/U2S3 semantics are epoch-independent:
  single-actor by construction). Pause-before-publication matrices land
  with the fork. **No observe-and-bind fallback will ship** — recorded
  as a release-gate stop condition.
- **Status:** OPEN-P0 behind ADR-0012 acceptance; not implementable
  under the current pinned ADR without the decision record this audit
  adds.

## F5 — no-compactor/L0 workaround — **OPEN-P0 (accepted; interim risk quantified)**

- **File/symbol:** `slate.rs` `settings()` — `l0_max_ssts = 1_000_000`.
- **Assessment:** the giant L0 threshold is liveness-only tech debt, and
  the audit confirms the directive: it is not a production substitute
  for compaction. Inv. 77/78 prescribe the exact target design (implicit
  compactor disabled + controller-authorised compactor under
  CompactorEpoch with budgets and drain/revoke) — which depends on F4's
  external epochs. Interim mitigation on local lanes: stores are
  disposable and short-lived (corpus-scale), so L0 growth is bounded by
  run length; checkpoint quiescence depends on no background rewrites,
  which the current posture guarantees trivially.
- **Required when closed:** bounded read/write amplification under a
  long-running workload, compactor start/drain/revoke/status hooks, no
  object-delete capability in the compactor principal.

## F6 — listing-based checkpoints — **PARTIAL** @ `8679cb1` (ordering) / remainder OPEN-P0

- **Closed part:** the manifest-pin ordering race found by this branch's
  own review (pin from a manifest-prefix-only listing STRICTLY BEFORE
  data listing; SSTs immutable and durable before the manifest that
  references them) — `checkpoint_remote`, commit `8679cb1`.
- **Open part (accepted):** the full V16 global checkpoint protocol
  (inv. 99–103): controller-owned quiescence, CheckpointCut across every
  keyspace + WAL head + control head, root pin journal-durable before
  enumeration, scratch restore + exact replay + independent logical
  digest before activation, controller-only activation. Listings demoted
  to diagnostics. Depends on the U3 controller integration
  (checkpoint/pin/materialisation state machine, F7c).
- **Interim honesty:** the current per-keyspace checkpoint is correct
  under the quiescent-store posture it requires (flush-then-pin with no
  background rewrites) and is proven baseline-equal by the storage
  suite; it does not claim to be the global-cut protocol.

## F7 — remote durability/controller completeness — **PARTIAL** @ `997da46`+`d47378e` (exact u64 CLOSED; journaled authority commands + CheckpointCut landed; U3.2 integration remains)

Q-28 label correction: `appendCommand` journals authority mutations into
the authenticated journal (F8). It is **not** the contract command ledger —
inv. 85–98's `CommandRecord` reservation/no-intent/outcome protocol remains
OPEN below — and no prose in this audit may call it one.

- **Closed now:**
  - **F7a** — finalized operations queryable by operation id after their
    session is fenced: `queryOperation` on core/DO/worker
    (`GET /wal/{db}/{gen}/operation/{opId}`), pinned in core tests + E2E.
    Inv. 38 unchanged: the finalize-RETRY path still answers
    `SESSION_FENCED` (ADR-0006); the READ surface never hides immutable
    history.
  - **F7b** — exact-u64 fail-closed guards (`exactU64`) on every
    authoritative sequence value read from SQL: outside
    `Number.isSafeInteger` → `INTEGER_RANGE_VIOLATION` throw, never a
    silent rounding.
- **Open (accepted):** fixed-width big-endian blob storage for u64 (the
  guard fails closed at 2^53; the blob representation removes the bound);
  command ledgers (inv. 85–98); checkpoint/pin/materialisation state;
  controller incarnation; catastrophic reconstruction (inv. 109–111);
  durable barriers beyond the current outbox frontier. These are the U3
  controller build-out — the current controller is the L1 protocol core
  (finalisation, fencing, replay, read surface, outbox) proven across
  three lanes, not the complete V16 controller, and this audit does not
  claim otherwise.

## F8 — authenticated control journal — **CLOSED @ `ed13a9a`** (R2 RecoveryAnchor publication remains OPEN)

- **Present today:** transactional outbox with contiguous ControlSeq,
  exactly-once drain, at-least-once peek/ack, and SQL-vs-pure-reducer
  replay equivalence over generated schedules (already a required lane —
  the directive's final bullet exists and runs today, incl. the
  drop-outbox-event mutant).
- **Missing (accepted):** canonical deterministic encoding, hash
  chaining, commit-time signing, conditional immutable R2 publication,
  digest-based ambiguity resolution, signed snapshots, RecoveryAnchor,
  incarnation rotation. Outbox peek/ack exposure: flagged into F9's
  capability work — admin surfaces must not be public.

## F9 — Worker/data-path hardening — **CLOSED @ `fe853aa`+`c71b8e1`** (streaming payloads remain)

- **Closed now:** bounded scan responses (byte budget from catalogued
  lengths BEFORE fetch, 8 MiB cap, one-record progress, exact resume —
  E2E-pinned); bounded per-fetch concurrency (8) from the earlier review
  pass; strict numeric param validation; payload immutability by
  conditional create; digest verification on both receipt and read
  paths.
- **Open (accepted):** controller-issued audience-bound expiring
  capabilities binding incarnation/principal/method/key/digest/budgets/
  nonce (production boundary — the local Worker is L1 scaffolding, per
  the parity plan, and is not represented as a security boundary);
  caller-selected R2 keys must die with the capability model; streaming
  bodies (today bounded, not streamed); auth/replay/cross-tenant/
  oversized/stale-incarnation negative matrix.

## F10 — donor verification infrastructure — **CLOSED @ `b76ad35`** (Mode-Q Bazel oracle remains)

- **Imported now:** the entire `contract/` set (normative brief v16, v17
  addendum, playbook, contract lock, source matrix, probe plan) @ donor
  `8dc0398`.
- **Evaluated, superseded by equivalents already on this branch:** the
  corpus runner here already does Cargo target + libtest discovery,
  fixture/runfile catalogue (four-spelling behaviour fixture), timeout
  ledger, per-target manifests with binary sha256, mutant negative
  controls, and single-commit evidence bundles
  (`u2s3-vs-oracle-comparison.json` refuses unexplained divergence).
- **Open (accepted):** fail-closed Starlark/Bazel declaration parsing
  (this branch's catalogue derives from cargo metadata, not from Bazel
  declarations — a real denominator-completeness gap vs the donor's
  parser); Gherkin scenario/Examples expansion to LEAF level (this
  branch counts executables/cases, not expanded scenario leaves);
  failpoint-registry × execution-context expansion; flake/exclusion
  ledger as a first-class artifact. These port next; the donor's Rust
  crates (`tools/corpus-catalog`, `tools/conformance-runner`) are the
  reference implementations to port against this branch's layout.
- **Single-source-commit rule:** accepted as a release-gate condition —
  today's evidence bundles each cite one commit, but the aggregate gate
  table spans commits; a release run re-executes on one commit.

## F11 — donor performance ideas — **ADR-0012 (this audit) + selective ports staged**

- Manifest-based size estimates / bounded retry-backoff / explicit cache
  settings: approved for port after semantic review (estimates are
  observational per inv. 72 — safe; cache settings already partially
  landed via the HydraDB review's `TYPEDB_S3_CACHE_BYTES`).
- Shared-store/coalesced-writes: **not copied**; evaluated in
  `docs/architecture/ADR/ADR-0013-shared-store-vs-per-keyspace.md`
  against TypeDB semantics, failure isolation, checkpointing, external
  epochs, compaction interference, amplification, and migration cost.
  Adoption requires differential + crash + capacity evidence.

## F12 — donor defects excluded — **CLOSED (by exclusion list)**

None of the following are imported, and each is now a named review
tripwire: SlateDB WAL enabled; destructive SlateDB GC; expiring
authoritative checkpoints (donor HEAD commit `8dc0398` title is exactly
this defect); weak path-derived namespaces (NOTE: this branch's U2S3
prefix is also path-derived — injective and single-actor-safe, but it is
named here as shared debt, resolved by F3's immutable namespaces); one
Tokio runtime per database (this branch: one process-wide runtime);
mutex across remote scans; stringly typed storage errors;
checkpoint-unsupported as final design.

## F13 — evidence bundle — **see the convergence map below + gate table**

Current honest state: U0/U1/U2/U2S3 full-corpus results exist and are
oracle-compared (`docs/evidence/G3/…`); U3 exists as the L1 protocol
lanes (not TypeDB-integrated); U4 does not exist yet; G2/L3 blocked on
credentials (SI-G0-3); tested-digest==shipped-digest proof and platform
probes are L3 items. **No completion is claimed: F3, F4/F5 (behind
ADR-0012), F6-remainder, F7-remainder, F8, F9-remainder, F10-remainder
are OPEN-P0.** The release-gate stop conditions from the directive are
adopted verbatim in the gate table.

---

## Commit-by-commit convergence map (this audit's session)

| Commit | Content |
|---|---|
| `65da032` | F2 closed (dirty=false + paused-pre-commit control, mutant-verified); `contract/` imported @ donor `8dc0398` |
| `ce3d64c` | F7a (operation read surface post-fence), F7b (exact-u64 guards), F9a (bounded scan pages) |
| `d5cd3ca` | This audit; ADR-0012/0013 |
| `c75a1af` | F11 approved ports (manifest size estimate; bounded-staleness remote key count, no lock across scan) |
| *(evidence commit)* | `u2s3-full-2` + oracle comparison: the single-commit corpus run of the converged tree |

Donor artifacts used: `contract/**` (verbatim import @ `8dc0398`);
`engine/slatedb-keyspace` + `fork/slatedb` (read as evidence for
ADR-0012/F4, no code imported); donor commit titles audited for the F12
exclusion list.
