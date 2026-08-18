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
every manifest-path mutation; 4/4 qualifying cases (full-cycle coverage,
pause-fence-resume, stale reopen, the vocabulary limit) and the gate-removal
mutant killed by both fencing cases. Measured findings:

- **Coverage advantage:** the firewall sits on the only channel to storage,
  so it gates *every* publication path — including the `Admin`/
  `StoredManifest` checkpoint paths that bypass upstream fencing types,
  which Candidate A must patch one by one.
- **Structural gap, permanent:** the firewall decides *who* may publish;
  the epoch *numbers* remain internally allocated. No wrapper of this shape
  can satisfy inv. 78–80, and adopting the store's numbering is the
  prohibited observe-and-bind.
- **Failure surface:** a fenced writer observes an opaque store error that
  upstream cannot distinguish from an outage; and under the stock unbounded
  retry default the first spike run HUNG on the refusal (the Q-13 hazard,
  observed live) — Candidate B fails closed only under a bounded-retry
  posture, where Candidate A's typed `Fenced` is terminal by construction.

**Resolution of the comparison:** the candidates compose rather than
compete. Candidate A remains the fencing mechanism of record (it is the
only one that can satisfy inv. 78–80); Candidate B's provider-enforced
credential rotation is adopted as the storage-side backstop underneath it
(defense in depth: server-side revocation holds even if the process is
compromised). This section records the measured comparison; production
integration of either half stays behind the existing gates.

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
