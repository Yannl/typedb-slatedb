# ADR-0012 — Production lane: SlateDB soft fork carrying exact external epochs

**Status:** accepted-as-plan (V16 convergence audit F4/F5); supersedes
ADR-0001's consume-only rule **for the production R2 lane only** once the
fork lands. Local conformance lanes (U2/U2S3) stay on crates.io SlateDB.

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
3. The conformance lanes keep crates.io SlateDB: semantics under test
   there (storage contract, checkpoint shape, read contract) are
   epoch-independent, and keeping the unmodified dependency preserves the
   oracle property of those lanes.
4. Every reachable publication path gets a pause-before-publication test:
   pause stale actor → advance epoch → replacement publishes → resume
   stale actor → typed fenced outcome, orphan bytes only.
5. No observe-and-bind fallback ships. This is a named release-gate stop
   condition.

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
