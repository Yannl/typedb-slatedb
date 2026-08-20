# ADR-0012 — Production lane: SlateDB soft fork carrying exact external epochs

**Status:** accepted (shipped, ratified 2026-08-20 in response to round-6
finding R6-TRUTH-01). Fully supersedes ADR-0001's consume-only rule for the
**whole product workspace**, not only the production R2 lane. Originally
recorded as accepted-as-plan (V16 convergence audit F4/F5).

> **What actually shipped, and why the scope widened.** The plan above
> scoped the fork to the production lane and left the conformance lanes on
> the registry crate. The implementation used
> `[patch.crates-io]`, which is **workspace-global by construction** — Cargo
> offers no per-lane patch table. So the moment the redirect landed, every
> lane in `sources/typedb` began resolving the fork. That is the right
> outcome (one SlateDB, one fenced open path, no lane silently linking a
> different engine than the one under test), but it is a *wider* decision
> than this ADR originally ratified, and it was in force before the
> documents said so. This status block ratifies it explicitly.
>
> **Scope, as shipped:**
>
> | Workspace | Resolved `slatedb` | Why |
> |---|---|---|
> | `sources/typedb` (product: U0–U4, all profiles) | `path` → `sources/slatedb-fork` @ 0.15.0, `external_epoch_required` + `aws` + `wal_disable` | workspace-global `[patch.crates-io]`; the fenced open path must be the only one |
> | `tools/` (spikes, protocol models) | `registry` → crates.io 0.15.0 | no patch table, on purpose: `tools/storage-diff-spike` measures the **unmodified** crate as the fork's differential oracle |
>
> **The oracle property is preserved, differently than planned.** Decision 3
> below kept the conformance lanes on crates.io so the unmodified dependency
> would preserve the oracle. That is no longer how it is preserved. It is
> preserved by (a) the upstream TypeDB corpus remaining the conformance
> oracle across profiles, and (b) `tools/storage-diff-spike` linking the
> registry crate from a workspace with no patch table, so a semantics
> differential against unmodified 0.15.0 is still executable at will.
> Decision 3 is superseded by this block.
>
> **The fence is default-on.** `fork/typedb/storage/Cargo.toml` enables
> `slatedb/external_epoch_required` unconditionally; feature unification
> carries it to every crate that links `storage`. Attested by
> `tools/fork/check_strict_epoch.py` and executed by
> `check_strict_epoch_suite.py`. Removing it is release-blocking.
>
> **Fork identity, upgrade and rebase.** The fork is a five-patch series over
> the digest-pinned crate (`fork/slatedb/patches/`, `UPSTREAM-PROVENANCE`,
> `PATCH-LEDGER.md`), reconstructed by `tools/fork/materialize_slatedb.py`
> and digest-verified by `--check`. The rebase procedure and the standing
> maintenance liability are recorded in
> [development.md](../../development.md#upgrading--rebasing-the-fork-onto-a-new-slatedb-release).
>
> **Risk ownership.** Carrying a storage-engine fork is owned by the storage
> lane owner jointly with this ADR: rebase cost per upstream release, a
> divergence surface no upstream CI covers, and the obligation to propose
> every carryable patch upstream first. Bounded by the minimal-patch rule.
>
> **Enforcement.** `tools/ci/check_dependency_sources.py` re-derives the
> resolved source from `cargo metadata` on every PR and fails when any
> registered document contradicts it. Prose alone cannot restore the old
> story.

## Context

ADR-0001 pinned SlateDB as an unmodified crates.io dependency, relocating
all patch obligations into owned layers. That has held through U2/U2S3:
every semantic the local lanes need (WAL off, quiescent store, manifest
CAS) is reachable through the public API, and single-actor operation makes
internal epoch allocation invisible.

The V16 brief makes it insufficient for production (inv. 78–80, the
SL-P1/SL-P2 pause-fence-resume matrix): every SlateDB publication path —
writer manifest updates, compactor publications, checkpoint create/
refresh/delete, clone, retry, recovery — must carry an **externally
issued** epoch (`SlateWriterEpoch`, `SlateCompactorEpoch`) minted by the
DatabaseControllerDO, so that platform-level fencing composes with
controller fencing instead of running as a parallel, internally-numbered
scheme. Upstream 0.15.0 allocates epochs internally in
`FenceableManifest`; `Admin` checkpoint paths bypass fencing entirely
(`StoredManifest` over `SimpleTransactionalObject` — the brief calls this
out explicitly). The brief also prohibits an observe-and-bind fallback
(watch what epoch the store happened to pick and adopt it), and this ADR
adopts that prohibition as a release stop condition.

The donor branch (`claude/typedb-r2-implementation-q1vb0j`) demonstrates
the fork route end-to-end: a vendored `fork/slatedb` consumed by path
dependency. Its existence is evidence of feasibility, not a patch set to
copy — its fork also enables SlateDB WAL and destructive GC (excluded
defects, audit F12).

## Decision

1. The production R2 lane will consume a **soft fork** of SlateDB at the
   pinned version, carrying the minimal patch set:
   - external epoch injection for writer and compactor manifest
     publication (`FenceableManifest` constructors take the epoch instead
     of allocating);
   - fenced checkpoint create/refresh/delete (no unfenced `Admin`
     mutation path reachable in active namespaces);
   - epoch-carrying clone/scratch/build publication;
   - typed fenced outcomes on every rejected publication.
2. Each patch is source-mapped in the source lock (fork base commit +
   patch series), mirroring how `fork/typedb` is managed today.
3. *(SUPERSEDED by the round-6 ratification in the status block above —
   `[patch.crates-io]` is workspace-global, so this is not what shipped.)*
   The conformance lanes keep crates.io SlateDB: semantics under test
   there (storage contract, checkpoint shape, read contract) are
   epoch-independent, and keeping the unmodified dependency preserves the
   oracle property of those lanes.
4. Every reachable publication path gets a pause-before-publication test:
   pause stale actor → advance epoch → replacement publishes → resume
   stale actor → typed fenced outcome, orphan bytes only.
5. No observe-and-bind fallback ships. This is a named release-gate stop
   condition.

## The two-candidate spike (J.3/D4), both sides measured

The directive forbids deciding the fork question by shortcut: both
candidates had to be built and measured. They now are.

**Candidate A — soft fork carrying exact external epochs.** Measured in
`docs/evidence/G3/slatedb-external-epoch-spike.json`: a five-file patch
series over the digest-pinned crate (~90 non-test lines — `slatedb-txn-obj`
0.15.0 already exports `FenceableTransactionalObject::init_with_epoch`
publicly, so the fork is wiring, not mechanism), qualifying matrix 34/34,
observe-and-bind mutant killed by three of five new cases. Satisfies
inv. 78–80 exactly; publications carry controller-minted epochs; rejected
publications get typed `Fenced` outcomes.

**Candidate B — publication firewall over stock SlateDB.** Measured in
`docs/evidence/G3/slatedb-publication-firewall-spike.json` (crate:
`spikes/publication-firewall`, workspace-external, non-production): an
`ObjectStore` wrapper bound to a controller-rotated credential domain gates
every mutation path. The round-3 deep audit found three defects in the
spike as first measured — F-01, a nested read-guard deadlock on the rename
path (an outer publication guard plus an inner source guard deadlocks
against tokio's write-preferring `RwLock` when a rotation writer queues
between them); F-02, a fencing gate that applied to publication paths only,
so a revoked actor could overwrite or delete manifest-referenced data keys;
and F-03, authorization by key path alone rather than by typed manifest
transition. All three are **fixed in the spike**:

- **F-01 fixed (single-guard gate):** every operation classifies all paths
  it touches, acquires exactly one authority read guard, validates the
  whole transition under it, and performs the single provider mutation
  while it is held; no code path acquires the authority lock while a guard
  is held. The audit's deterministic barrier probe (admission held →
  rotation writer queued → source validation, bounded by
  `tokio::time::timeout`) passes on the fixed gate and was executed once
  against the pre-fix nested-guard shape, where it deadlocks (times out)
  on every run.
- **F-02 fixed (full-surface authority):** revoked domains are denied
  overwrite, multipart create/complete, copy/rename, and delete on every
  authoritative key class; data keys are create-only or same-bytes
  idempotent, with different bytes at an existing key refused *and*
  quarantined; delete of completed authoritative data is denied globally
  (pre-G13); multipart uploads carry a journaled `UploadAttemptId`, with
  completion gated on the exact recorded uncommitted attempt and abort
  admitted only for that attempt. The audit's probe shape (revoked actor
  attempts overwrite and delete on a manifest-referenced key → both
  typed-denied, bytes unchanged) is a test; the executed
  publication-only-fencing mutant is killed by five cases.
- **F-03 fixed (typed transitions):** under the gateway policy the spike
  decodes mutation class, role, base/target manifest ids, and old/new
  writer/compactor epochs from a versioned envelope and validates the
  whole transition against attested state: PROMOTING writer-open may only
  increase the writer epoch, ACTIVE publication preserves the attested
  epochs, compactor-open changes only the compactor epoch, and unknown or
  malformed versions fail closed. The executed verdict-ignoring mutant is
  killed by the decoder/semantic suites.
- **Coverage advantage:** the firewall sits on the only channel to storage,
  so it gates *every* mutation path — including the `Admin`/
  `StoredManifest` checkpoint paths that bypass upstream fencing types,
  which Candidate A must patch one by one.
- **Structural gap for a stock client:** the typed-transition gate can only
  be exercised by a client that authors the transition envelope; stock
  SlateDB cannot, so with an unpatched client the epoch *numbers* remain
  internally allocated, inv. 78–80 is not satisfied, and adopting the
  store's numbering is the prohibited observe-and-bind.
- **Failure surface:** a fenced writer observes an opaque store error that
  upstream cannot distinguish from an outage (the typed refusal is
  recoverable from the error source, but stock retry logic does not look);
  under the stock unbounded retry default the first spike run HUNG on the
  refusal (the Q-13 hazard, observed live) — Candidate B fails closed only
  under a bounded-retry posture, where Candidate A's typed `Fenced` is
  terminal by construction.

**Status of the comparison: open — no winner is declared here.** Both
candidates are measured; the deadlock and bypass defects that disqualified
the Candidate-B spike's earlier measurement are repaired. Before
Candidate B could be *selected*, at minimum the following remain
unmeasured or undone: (1) provider-credential enforcement — the in-process
wrapper is defense in depth only, and R2 scoped tokens / IAM session
credentials must enforce the same policy matrix server-side; (2) the
latency envelope of the gate's preflight reads and typed validation under
production object-store latencies; (3) a cooperating client for the typed
transition envelope (stock SlateDB cannot author it). Independent of
selection, Candidate B's provider-enforced credential rotation remains a
sound storage-side backstop underneath whichever mechanism is chosen.
Production integration of either candidate stays behind the existing
gates.

## Consequences

- ADR-0001's consume-only rule survives where it earns its keep (local
  oracle lanes) and is superseded exactly where the brief proves it
  cannot hold (production fencing).
- The compactor plan (audit F5: controller-authorised compactor under
  `CompactorEpoch` with budgets and drain/revoke) becomes implementable;
  the giant-L0 workaround retires with it.
- Fork maintenance cost is accepted and bounded by the minimal-patch
  rule; any patch that could be an upstream contribution is proposed
  upstream first.
