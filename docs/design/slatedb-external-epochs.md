# SlateDB external epochs: the ADR-0012 fork, at file/symbol level

**Status:** **IMPLEMENTED as ADR-0012 Candidate A** — see
`fork/slatedb/PATCH-LEDGER.md` and
`docs/evidence/G3/slatedb-external-epoch-spike.json`. The patch series
builds against the pinned crate, its qualifying matrix passes (34/34 in
`manifest::store`, five of them new), and the observe-and-bind mutant is
killed. F4/F5 are **no longer unbuilt**, but they are also **not decided**:
ADR-0012 requires this candidate to be compared against a
provider-enforced publication firewall over stock SlateDB before either is
normative, and the production lane stays on crates.io until that decision
and a real G2 pass.

**Correction to §"What upstream already has" below.** This document
originally described external issuance as something upstream lacks. That is
wrong at this pin: `slatedb-txn-obj 0.15.0` already exports
`FenceableTransactionalObject::init_with_epoch` publicly, with exactly the
fail-closed semantics required (`epoch <= stored` → `Fenced` before any
write), and SlateDB already uses it for its compactions object. What is
missing is only the wiring to the *manifest's* writer/compactor epochs and
a builder knob — which is why the realised patch is five files and roughly
90 non-test lines rather than an open-ended vendoring. The paragraphs below
are retained as the design record; where they conflict with the patch
ledger, the ledger is what was built.

## What upstream already has

The manifest schema already carries both epochs (`Manifest.writer_epoch`,
`Manifest.compactor_epoch` — `schemas/manifest.fbs`, surfaced in
`manifest/mod.rs:824-855` with public read accessors). Fencing exists and
works: `FenceableManifest::init_writer` / `init_compactor`
(`manifest/store.rs:34-67`) wrap `FenceableTransactionalObject::init`,
which **internally allocates** the next epoch (stored + 1) and CAS-writes
it; a stale handle observing a newer epoch fails everything with
`SlateDBError::Fenced`.

What V16 (inv. 78–80) requires and upstream lacks is **external issuance**:
the epoch must be a controller-allocated exact u64 presented at open, so
that fencing composes with the controller's own fencing story
(startup-session/incarnation) instead of racing it. Internal allocation is
observe-and-bind — prohibited as a release-gate stop condition (ADR-0012).

## The fork diff (production lane only; local lanes stay on crates.io)

1. `manifest/store.rs` — add
   `FenceableManifest::init_writer_with_epoch(stored, timeout, clock, external_epoch: u64)`
   (and the compactor twin). Same body as `init_writer` except the epoch
   closure pair is replaced by an exact-set path:
   - **fail closed**: `external_epoch <= stored.writer_epoch` →
     `SlateDBError::Fenced` *before any write* (a controller replaying an
     old epoch must be refused, never bumped over);
   - CAS-write `writer_epoch = external_epoch` with the same
     `FenceableTransactionalObject` conditional-put machinery (no new
     concurrency surface);
   - the local handle's fencing detection is unchanged — any later
     manifest with a greater epoch still fences this handle.

2. `config.rs` + `db.rs` (builder) — `DbBuilder::with_external_writer_epoch(u64)`.
   When set, every open path that would call `init_writer` calls
   `init_writer_with_epoch`; when unset on the production lane feature, open
   REFUSES (`external epoch required; internal allocation is
   observe-and-bind`) — the flag that makes the fork's posture fail-closed
   rather than optional.

3. Compactor (`compactor/*.rs`) — the orchestrator accepts
   `with_external_compactor_epoch(u64)` the same way. The controller starts
   the compactor as a *separately scheduled* job (inv. 77/78: budgets,
   drain/revoke via epoch supersession — revocation IS issuing a newer
   compactor epoch to a successor, the old job fences out on its next
   manifest CAS). No object-delete capability in the compactor principal:
   it publishes new SSTs + manifest; GC of superseded objects stays
   report-only until G13.

4. Vendoring mechanics — `fork/slatedb` as a git-subtree of the pinned
   upstream tag + this diff as a patch series (same model as
   `tools/fork/materialize.sh` uses for `fork/typedb`);
   `sources/typedb/Cargo.toml` gains a `[patch.crates-io] slatedb = { path
   = ... }` activated only by the production-lane profile. Local conformance
   lanes (U2/U2S3) keep crates.io — single-actor by construction, epoch
   semantics not exercised (ADR-0012).

## The qualifying matrix (lands with the fork, SL-P1/SL-P2)

Pause-before-publication controls, mirroring the F2 pattern (failpoint
between epoch claim and first manifest publication):

- stale writer paused pre-publication while a successor with a higher
  external epoch opens → resumed writer's CAS fails `Fenced`; no torn
  manifest;
- controller replay of an already-used epoch → refused before any write;
- compactor revocation: successor compactor epoch issued mid-run → the
  draining job's next manifest CAS fences; published SSTs from the fenced
  run stay orphan bytes (inv. 83), never referenced;
- exactness: epoch `2^53 + 1` round-trips through issue → manifest →
  refresh exactly (the F7 blob/bigint rule, Rust side is native u64).

## What is enforced TODAY without the fork (F5 interim)

`assert_pre_g13_posture` (`fork/typedb/storage/keyspace/slate.rs`) refuses
any open whose settings enable the SlateDB WAL, the in-process compactor,
or the garbage collector — typed refusal naming every violated clause,
with violation controls in `posture_tests` and a wiring mutant run. The
other posture clauses are structural: committed-only reads
(`read_contract_tests`), no delete authority (`NoDeleteStore`,
`materialization_tests`). The giant `l0_max_ssts` liveness posture and its
bounded-run-length rationale are unchanged (audit F5); bounded read/write
amplification under long-running load is fork-gated.
