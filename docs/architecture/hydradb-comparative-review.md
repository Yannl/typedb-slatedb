# Comparative review: HydraDB (property graph on SlateDB) vs this port

**Reviewed:** [hydra-db/hydradb](https://github.com/hydra-db/hydradb) at its
single squashed public commit (Aug 2026) — an object-store-native graph
database on a forked SlateDB 0.14.1, S3 as the durable source of truth,
CAS leases + SlateDB writer epochs for fencing, no controller in the data
path. Reviewed because it is the closest published system to our stack
(TypeDB storage on SlateDB over R2 + a Durable-Object remote WAL) and makes
several opposite bets worth testing our decisions against.

## The two architectures in one table

| Axis | HydraDB | This port |
|---|---|---|
| Durability authority | SlateDB's own WAL (S3 objects), `await_durable` mandatory for writers | TypeDB's WAL — file today, DO-remote in U3 (ADR-0003); SlateDB WAL disabled |
| Coordination | None in the data path: object-store CAS leases + SlateDB writer epoch as final fence | `DatabaseControllerDO` — one serialization point per database, typed protocol |
| Fencing detection | `refresh_manifest()` — one object-store GET **per write attempt** | Free: every finalize revalidates the session inside the same DO round trip |
| Exact-once | Idempotency records as KV data inside the same transaction | Operation-identity replay in the controller (inv. 34–35) |
| Compaction/GC | Upstream defaults ON, in-process per open cell | Disabled by design (ADR-0005): quiescent store, manifest-pinned checkpoints |
| Checkpoints | None explicitly — readers use `ManagedCheckpoint` mode, 10-min lifetime | Explicit manifest-pinned checkpoint + restore (RocksDB-equivalent semantics) |
| Snapshot pinning | Task-local (`ACTIVE_STORAGE_SNAPSHOT`) makes per-query pinning structural | TypeDB MVCC open-sequence pinning; remote WAL iterators pin server-side (mandatory `throughLsn`) |
| Change feed | "xlog": per-edge final-state records written in the mutation's own transaction, keyed by commit sequence, with a low-water floor key | Transactional outbox (control events), record_type-indexed catalogue scans |

Their fencing bet costs a manifest GET on every write attempt to buy eager
fence detection; our DO gives fencing + commit ack in a single round trip.
That confirms the DO architecture rather than challenging it — but several
of their operational mechanisms are better than ours were.

## Transfers applied (this repo, now)

1. **Fence attribution, separate from authority.** Their `_cell_writers/v1`
   record exists because epochs carry no identity: the first question in a
   fence incident is *"who is the writer now?"*, and their design doc is
   emphatic that the attribution record must never be *consulted* for
   decisions (read-then-act has no CAS). Our control plane can serve
   attribution safely from the authority row itself: `SESSION_FENCED` now
   carries `fencedBy` — the live actor that superseded the caller — pinned
   across the TS core, workerd, E2E, and the Rust client
   (`FinalizeHttpOutcome.fenced_by`). Read-only information in a typed
   error; it can never change an outcome.
2. **Local disk cache for remote SSTs** (`TYPEDB_S3_CACHE_BYTES`, default
   off). SlateDB 0.15's `object_store_cache_options` — no fork needed,
   unlike their 0.14.1 fork — with `cache_on_flush` so a writer's own
   flushed SSTs are served locally. One correctness constraint they don't
   have: our open **purges and re-seeds the remote prefix** (disposable
   stores, ADR-0003), so a cache surviving open would serve stale bytes for
   reused object paths. The cache therefore lives *inside* the keyspace dir
   (the lifecycle marker — recovery wipes it with the store), is wiped
   again at open as defense in depth, and is excluded from the
   checkpoint-restore upload walk.

## Transfers adopted into staged plans (not yet code)

3. **Fence backoff ≠ failure backoff** (U3.1 client). Their
   `WriterReopenGate`: a fence waits exactly one heartbeat interval (sized
   for the *rival* to stand down) and resets the exponential ladder; only
   plain open failures climb 2→4→…→60 s; and the fence handler never
   re-promotes — re-acquisition goes back through the full open path. Our
   U3.1 retry taxonomy adopts this: `SESSION_FENCED` is not a retryable
   error and never enters the ambiguity-resolution loop; it surfaces to
   `Database` lifecycle, which may only re-enter via a fresh
   register (new startup session id — ADR-0011 keeps superseded actors
   superseded).
4. **Per-operation fault injection** (U3.4 matrix). Their `FaultStore`
   fails LIST while PUTs still land — reproducing a node that sheds
   ownership yet keeps heartbeating, permanently unwritable and invisible
   to any all-or-nothing fault double. Our U3.4 failpoint matrix must
   fault per operation type (upload / finalize / read / register), not per
   call sequence only.
5. **Content-addressed artifacts + byte-identity oracles.** Their index
   generations are `sha256(payload)`-named, and incremental-vs-full
   correctness is proven by byte-identical store objects. When incremental
   checkpoints land (post-U3), the same oracle applies: an incremental
   checkpoint must byte-equal a full checkpoint of the same watermark.

## Contrasts examined and kept as-is (with reasons)

- **SlateDB WAL as durability authority.** Their model needs
  `flush_interval = 1 ms` and a second-order knob
  (`max_wal_flushes_before_l0_flush` 4096→128) to keep readers from
  drowning in WAL replay — a WAL object per active millisecond on R2 class
  storage, plus a manifest GET per write for fencing. Our DO WAL
  amortizes both into one round trip and keeps group-commit batching open
  (U3.0's `finalize-batch`). ADR-0003 stands.
- **In-process compactor/GC.** Correct for their long-lived cells; wrong
  for our disposable keyspace stores whose quiescence the checkpoint
  algorithm depends on (ADR-0005). Their implicit-budget lesson still
  matters: with default features every open `Db` handle carries its own
  ~64 MiB in-memory block cache — N TypeDB keyspaces multiply that, which
  is now documented in operations.md.
- **Leases with server-time expiry.** Their `server-clock` PUT+HEAD probe
  and monotone remainder tracking are a careful answer to a problem the DO
  design does not have: our authority is a linearized session row, not a
  TTL object, and the client never extrapolates authority from local time
  (every write revalidates). The invariant they encode — *local authority
  must never outlive the durable record* — is already structural here.
- **Bookmarks (causal reads).** Their `sgk:1:…:<seq>` bookmark maps to
  TypeDB's transaction-level consistency; the remote WAL's `head` +
  pinned iterators already expose the equivalent frontier. Nothing to do
  until multi-node readers exist (post-G2).
- **Key encoding.** Flat string keyspace with zero-padded decimal integers
  is fine for a graph cell; TypeDB's binary keyspace encoding is
  load-bearing for its type system and stays.

## Verdict

The strongest signal is convergent: both systems independently arrived at
typed-error taxonomies, advisory-vs-authority separation, snapshot pinning
made structural, quiescent-store checkpointing... and both treat "cache
budgets are per-handle" as an operational trap. The DO-controller bet is
reinforced by seeing its absence: HydraDB pays one object-store GET per
write attempt for fencing and still needs three coordination layers
(placement hash, CAS lease, writer epoch) where the DO needs one. What
they do better — fence attribution, fence-vs-failure backoff, per-op fault
injection, byte-identity oracles, disk caching — is now either applied or
staged above.
