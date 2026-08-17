# Adversarial audit of the selected integration base

**Target:** branch `claude/review-continue-previous-zv4wmi`, commit **`e20cff5`**
(`e20cff50081b9ae4b3c5f88e6d4ef89a88b06585`), repo `Yannl/typedb-slatedb`.
**Method:** static, source-backed inspection of a clean worktree of that one commit, plus a
byte-diff of its SlateDB dependency against the pinned upstream checkout
(`f88be86d17ac53260d3684edbc8f82811d945b5c`). No claim below depends on running the branch.
**Auditor's posture:** this branch was *selected* as the final integration base. The point of
this report is not to unseat it — it is to hand the lead agent the exact defects that a
passing corpus does not surface, each with a file/symbol anchor, a minimal reproducer, the
invariant it violates, and the shape of the negative test that would have caught it.

Every finding is pinned to `e20cff5`. Where a claim is *refuted* (the branch is correct, or
was fixed before the tip), that is stated as plainly as the confirmations — an audit that only
reports hits is not an audit.

---

## Severity summary

| # | Finding | Verdict | Severity |
|---|---|---|---|
| A1 | Object-store purge runs *before* `Db::build()`, bypassing SlateDB's writer-epoch fence | CONFIRMED | **P0 — silent data destruction** |
| A2 | No authentication on any control-plane endpoint; arbitrary R2 keys writable | CONFIRMED | **P0 — unauthenticated takeover** |
| A3 | `SESSION_FENCED` response leaks `fencedBy` — the impersonation identity | CONFIRMED | **P0 — fence is self-defeating** |
| A4 | `outboxAck` / `setBudgets` / `queryOperation` take no session; unfenced | CONFIRMED | P1 |
| A5 | Authoritative counters are JS `number`; `generation` unguarded end-to-end | CONFIRMED | P1 |
| A6 | Database schema read-lock held across a full remote scan; the "memo" is never written | CONFIRMED | **P0 — server-wide stall** |
| A7 | L0 ceiling raised 8 → 1,000,000 on a misread precedent; unbounded read amplification | CONFIRMED | P1 |
| A8 | Path-derived prefixes: cross-process collision, generation reuse, permanent import leak | CONFIRMED | P1 |
| A9 | Checkpoints are listing-and-copy with no durable root; native API unused | CONFIRMED | P1 |
| A10 | `get_prev` panics the whole process on any transient object-store error | CONFIRMED | P1 |
| A11 | Container DO is unreachable dead code; no controller↔container epoch token exists | CONFIRMED | P1 |
| A12 | `dirty: true` reads on the correctness path | REFUTED at tip (fixed in `65da032`) | — |
| A13 | Forked SlateDB / externally supplied epochs | REFUTED (no fork; stock crate) | — |
| A14 | Evidence assembled from multiple commits | PARTIAL (headline single-commit; prior run 4-commit; the 1 red is honest) | note |

The single most consequential defect is **A1**: it makes SlateDB's only exclusive-writer
protection structurally unreachable, so one process can erase another's live database with no
error on either side. A6 and A8 compound it.

---

## A1 — Purge-on-open precedes the fence (P0)

**File/symbol:** `fork/typedb/storage/keyspace/slate.rs`, `open_s3` (≈ lines 366–409);
`purge_remote_prefix` (≈ 249–254).

**What it does.** On every open of an S3-backed keyspace, the code lists every object under
the derived prefix and deletes it, *then* builds the SlateDB handle:

```
purge_remote_prefix(store.as_ref(), &prefix).await?;   // ~line 376
if let Some(root) = restored_root { upload_dir_to_remote(...).await?; }
...
let db = bridge(async move { Db::builder(DB_SUBDIR, prefixed) ... }).await;  // ~line 401
```

**Violated invariant.** Exclusive-writer safety. Pinned SlateDB *has* writer-epoch fencing —
`sources/slatedb/slatedb/src/manifest/store.rs:30–46` ("fences other conflicting writers by
incrementing … fails all operations with `SlateDBError::Fenced`"). But that fence is claimed
inside `Db::builder(...).build()`. Because the unconditional purge runs *before* `build()`, a
second process destroys the first's objects before any CAS/epoch handshake can reject it. The
library's protection is unreachable by construction.

**Minimal reproducer.** Point two processes at the same keyspace path and bucket prefix.
Process A opens and writes. Process B opens: `purge_remote_prefix` deletes A's manifest and
SSTs; A's next flush writes into a partially-deleted store. No `Fenced` error is ever raised
because the collision happened below the manifest layer.

**Negative test that would have caught it.** Open store A, write and flush; without closing A,
open store B at the same prefix; assert that either B is refused (`Fenced`) *or* A's committed
keys are still readable. The branch has no such test — its corpus uses fresh, short-lived
prefixes, so two live writers on one prefix never occur.

**Note:** the same unfenced destructive path is reachable from delete
(`purge_remote`, ≈ 578–587, which additionally discards the `db.close()` result at ≈ 583) and
from `reset()` (≈ 589–612, an O(store) tombstone-write of every key).

---

## A2 — No authentication; arbitrary R2 keys (P0)

**File/symbol:** `control-plane/src/controller/worker-entry.ts`, `fetch` dispatch
(≈ 141–408); payload PUT (≈ 149–177).

**What it does.** `grep -rn "Authorization|Bearer|token|API_KEY" control-plane/src` returns
nothing. `wrangler.toml` binds only `CONTROLLER` and `PAYLOADS` — no secret, no service-binding
gate. Every route dispatches on method+path alone. Unauthenticated *mutating* routes include
`POST /session/register` (fence the live writer of any database in one request),
`POST /session/fence`, `POST /budgets` (`maxTailRecords: 0` → permanent write wedge),
`POST /wal/finalize` (forge WAL records; the only "identity" is a `startupSessionId` string in
the body), and `POST /outbox/{db}/ack` (silently discard a database's control events).

The payload key is fully caller-controlled with no tenant namespacing:

```
const key = decodeURIComponent(path.slice("/payload/".length));   // ~line 150
const created = await env.PAYLOADS.put(key, bytes, { onlyIf: ... }); // ~line 162
```

`decodeURIComponent` re-introduces `/` and `..` *after* the URL parser has normalized
dot-segments, and `finalizeStep` never checks that `payloadKey` belongs to the caller's
database prefix. A caller can pre-squat a key the legitimate writer will later need; ADR-0007
immutability then turns against the system — the real `PUT` gets `409` and is permanently
poisoned, with no delete path to recover.

**Violated invariant.** Tenancy isolation, and "exactly one live writer per database" — both
unenforceable without caller authentication. The entire fencing design is decorative against
anyone who can reach the Worker.

**Negative test.** From an unauthenticated client, `POST /session/register` for a database an
existing session owns; assert the existing writer is *not* fenced (or that the request is
rejected `401/403`). And: `PUT /payload/db-A/../db-B/x`; assert it cannot land under `db-B`'s
prefix.

---

## A3 — The fence hands out the impersonation token (P0)

**File/symbol:** `control-plane/src/controller/core/procedures.ts`, fenced-response branch
(≈ 256–264); pinned by `core/controller-core.test.ts:216` (`fencedBy: "sess-2"`).

**What it does.** When a fenced session is rejected, the controller replies:

```
return { ok:false, error:"SESSION_FENCED",
         fencedBy: live.length ? String(live[0].startup_session_id) : null };
```

`startupSessionId` is the *only* credential the finalize path checks (see A2). So the
controller responds to a fenced actor by telling it the exact identity it needs to resume
writing.

**Violated invariant.** ADR-0006 in this same tree states: "every controller response to a
fenced session is the typed `SESSION_FENCED`, **with no informational side channel**." `fencedBy`
is exactly that side channel, and it is the highest-value one possible.

**Negative test.** Fence session S1 in favour of S2; call any endpoint as S1; assert the
response body contains *no* other session's id. Related: `SESSION_UNKNOWN` (≈ 249) vs
`SESSION_FENCED` (≈ 260) are distinguishable, giving an unauthenticated caller a
session-existence oracle — the pure model (`tools/protocol-models/.../wal_model.rs`) collapses
both to `Fenced`, so this is a real cross-lane divergence.

---

## A4 — Fencing is enforced on exactly one procedure (P1)

**File/symbol:** `control-plane/src/controller/core/procedures.ts`. `finalizeStep`
(≈ 245–265) is the only code that reads the `sessions` table. `outboxAck` (≈ 404–411),
`setBudgets` (≈ 202–208) and `queryOperation` (≈ 497–512) take no session argument.

**Consequence.** A stale actor can ack the *live* actor's undelivered
`WAL_RECORD_FINALIZED` events (`outboxAck(upToControlSeq = huge)`), permanently hiding them
from the real consumer; can wedge the live writer via `setBudgets`; and can read its own
committed LSNs via `queryOperation` — which ADR-0006 explicitly names as a capability a fenced
holder must lose. `registerSession` and `fence` both return `void`, and `worker-entry.ts`
turns them into unconditional `200 {ok:true}`, so a fenced caller believes it holds authority
and a never-registered fence "succeeds."

**Negative test.** After fencing S1, assert `outboxAck`/`setBudgets`/`queryOperation` as S1 are
all rejected; assert `register` as a fenced session returns a typed failure, not `ok:true`.

---

## A5 — JS `number` for authoritative counters; `generation` unguarded (P1)

**File/symbol:** `control-plane/src/controller/core/procedures.ts`. `exactU64` guard
(≈ 92–98) is applied to `appendLsn`/`typeSequence`/`controlSeq` on *some* paths, but **not**
to `head()`, `openIterator()`, `exactLookup()`, `auditContiguity()` or the outbox surface
(≈ 385, 401, 406, 426, 437, 451, 534). `generation` is `Number(...)` everywhere and never
range-checked (`worker-entry.ts:280` parses an unbounded `(\d+)` capture; the finalize path
takes `req.generation` from client JSON with no check).

**Violated invariant.** Authoritative counters must be exact 64-bit. `grep -rn "bigint"
control-plane/` returns nothing, so every counter is an IEEE-754 double: a u64 above 2^53 is
already corrupted at the JSON boundary, before any SQL-read guard can see it. A float
generation (`1.5`) silently creates a distinct WAL partition; generation monotonicity is
unenforced (the `databases` table that would carry `current_generation` is created but never
read or written — dead DDL).

**Negative test.** Finalize with `generation = 9007199254740993` (2^53+1); assert it is
rejected, not silently rounded to 2^53. Finalize with `generation = 1.5`; assert rejection.

---

## A6 — Schema lock held across a full remote scan; the memo is a no-op (P0)

**File/symbol:** `fork/typedb/database/database.rs`, `get_metrics` (≈ 552–564);
`fork/typedb/storage/keyspace/slate.rs`, `estimate_key_count` (≈ 652–671) and the
`key_count_memo` field (declared ≈ 343, read ≈ 655).

**What it does.** `get_metrics` takes the database schema *read-lock* at ≈ 553 and holds it
across ≈ 563, `estimate_key_count`, which on the S3 lane is a full scan of every key in every
keyspace over the network. The diagnostics loop calls this roughly every 15 seconds.

The claimed mitigation does not exist. `key_count_memo` is initialized to `None` and **never
written** — `grep -rn "key_count_memo"` shows a declaration, two `Default::default()` inits,
and one read, and no store. So line 655 always misses and every poll performs the full remote
scan, while the caller holds the schema lock across it. The docstring at ≈ 644–651 describes
bounded-staleness behaviour the code does not implement, and commit `c75a1af` ("bounded-staleness
remote key count") advertises it.

**Violated invariant.** No unbounded remote I/O under a lock that serializes schema access.
Against RocksDB the same caller was harmless — `rocksdb.estimate-num-keys` is an O(1) property;
replacing it with an unbounded remote scan is what turns it into a defect.

**Negative test.** With a store large enough that a scan takes seconds, spawn a schema read and
a `get_metrics` concurrently and assert the schema read is not blocked for the scan's duration;
assert two successive `estimate_key_count` calls within the staleness window issue only one
scan. (This is precisely the property the donor engine's single-flight estimate path enforces —
see the import map.)

---

## A7 — L0 ceiling raised to 1,000,000 on a misread precedent (P1)

**File/symbol:** `fork/typedb/storage/keyspace/slate.rs` (≈ 104–119).

```
settings.compactor_options = None;
settings.garbage_collector_options = None;
settings.l0_max_ssts = 1_000_000;
settings.l0_max_ssts_per_key = 1_000_000;
```

Upstream default is 8 (`sources/slatedb/slatedb/src/config.rs:1078`). This is a 125,000×
raise, justified in-comment as "the same posture SlateDB's own compactor-less tests take
(l0_max_ssts = 10_000)" — but the cited test (`db.rs:9347`) is **not** compactor-less: it sets
`compactor_options: Some(...)` and drives compaction manually. With no compactor and no
backpressure, L0 grows without bound for the life of the database; every point read consults an
ever-growing L0 fan, so read latency degrades linearly and never recovers. GC being off means
nothing is reclaimed.

**Contrast with the donor posture.** The donor engine refuses an L0 ceiling above a bounded
`SAFE_L0_CEILING` (64) unless the operator explicitly attests external compaction is arranged —
i.e. it treats "raise the ceiling until backpressure stops" as the liveness-for-amplification
trade it is, and makes it un-reachable by accident. See `engine/slatedb-keyspace/src/config.rs`
and `tests/posture_negative_controls.rs::an_unbounded_l0_ceiling_is_refused_without_external_compaction`.

**Negative test.** Assert that a configuration with `l0_max_ssts` above a safe bound is either
refused or accompanied by an explicit external-compaction declaration.

---

## A8 — Path-derived prefixes collide (P1)

**File/symbol:** `fork/typedb/storage/keyspace/slate.rs`, `object_prefix` (≈ 211–227).

The prefix is an injective encoding of the *absolute local filesystem path*
`<data_dir>/<db>/storage/<keyspace>`. A path string is not an identity, so:

1. **Two processes, same path, one bucket → mutual destruction** (compounds A1): two replicas,
   or a restart overlapping a not-yet-dead process, compute an identical prefix and purge each
   other. `s3_config()` memoization guards only the *intra-process* half of the race (its own
   comment acknowledges the race).
2. **Generation reuse:** drop and recreate a database → same path → same prefix; a failed or
   partial purge leaves the new generation reading the old one's objects.
3. **Permanent import leak:** `database_manager.rs:228–247` `finalise_imported_database` drops
   the database (close only, no purge) then moves the directory. The remote objects under the
   *import-directory* prefix are never deleted by anything — every import leaks its full object
   set into the bucket.

**Contrast with the donor posture.** The donor `StoreIdentity`
(`engine/slatedb-keyspace/src/identity.rs`) makes the prefix a function of environment,
`DatabaseId`, `DatabaseGeneration`, `MaterializationId`, keyspace-schema version and a format
digest, with fixed-width segments so no identity's prefix is a string prefix of another's;
`tests/identity_collisions.rs` proves the four scenarios above cannot collide.

**Negative test.** Recreate a database at the same path; assert the new store cannot read the
old generation's keys. Import a database; assert no orphaned objects remain under the import
prefix.

---

## A9 — Listing-and-copy checkpoints, no durable root (P1)

**File/symbol:** `fork/typedb/storage/keyspace/slate.rs`, `checkpoint_local` (≈ 506–532),
`checkpoint_remote` (≈ 540–572). The control plane has *no* checkpoint code at all
(`grep -rn "checkpoint" control-plane/src` → a test fixture string and one comment).

Pinned SlateDB ships a native checkpoint API (`sources/slatedb/slatedb/src/checkpoint.rs:30`),
unused here. Instead the "pin" is a lexicographic-max over a directory/prefix listing — not a
CAS, not a manifest read, not a durable reference — followed by a full copy/download. Nothing
records that the checkpoint exists; the root is transient in-process state. Correctness rests
entirely on GC and the compactor staying off (their own step-2 comment says so); enable either
and every checkpoint silently tears. A single missing SST yields a checkpoint that opens and
returns wrong answers rather than failing.

**Violated invariant.** A release checkpoint must be rooted in a durable, non-expiring record
independent of the mutable store it describes, and verifiable globally.

**Note on the donor side.** The donor engine does *not* claim to have solved this either — it
classifies checkpoint/restore as explicitly `Unimplemented` in
`engine/slatedb-keyspace/src/qualification.rs` and excludes itself from production
qualification, rather than presenting a green engine test as a solved checkpoint. That is the
honest posture the mission requires; A9 is the same gap left implicit.

**Negative test.** Take a checkpoint while a writer is live and a compaction/GC is enabled;
assert the restored store equals the point-in-time state or fails loudly — never opens with a
missing SST.

---

## A10 — `get_prev` panics the process on any transient error (P1)

**File/symbol:** `fork/typedb/storage/keyspace/slate.rs`, `get_prev` (≈ 437–460).

```
Err(error) => panic!("SlateDB floor scan (get_prev) failed; refusing to report absence: {error}")
```

The fail-closed *intent* is sound (a silent `None` would make the vertex-ID allocator re-issue
existing IDs). But on a remote object store, transient 5xx/throttling is routine, and this
converts a single retryable hiccup into a whole-server abort — a liveness cliff that does not
exist on the RocksDB lane. The right shape is a structured, retry-classified error the layer
above can handle (the donor `KeyspaceError` carries exactly a `RetryClass`), not a panic.
Related unwraps on remote results: `database.rs:562–563` (two `.expect` on remote ops in the
diagnostics thread), `slate.rs:311/276/525/528`.

**Negative test.** Inject a transient object-store error into a `get_prev` and assert the call
returns a retryable error, not a panic.

---

## A11 — No controller↔container epoch token; container is dead code (P1)

**File/symbol:** `control-plane/src/controller/container/database-container.ts` (≈ 40–44);
`worker-entry.ts` exports (≈ 31); `wrangler.toml`.

`grep -rn "epoch"` outside `docs/` hits only `tools/protocol-models/src/fencing_model.rs` (a
pure model with no production caller) and unrelated `UNIX_EPOCH` uses. `DatabaseContainerDO`
is not exported and has no binding or migration in `wrangler.toml` — it is unreachable. Its
`reportObservation` discards every observation ("implemented with CF-P3"). So there is no
message carrying a generation from controller to container, and the storage layer runs stock
SlateDB whose epochs are allocated *internally* — controller fencing (`sessions.fenced` in the
DO, which gates only the WAL catalogue) and platform fencing never meet. A container that lost
the controller race keeps flushing SSTs under SlateDB's internal epoch, unobserved and
unstoppable.

**Negative test.** Rotate the controller incarnation; assert a container from the prior
incarnation cannot commit a manifest (requires an epoch token the storage layer verifies — the
mechanism ADR-0012 defers to a SlateDB soft fork that does not exist here).

---

## Refuted / partial claims (stated for completeness)

**A12 — dirty reads (REFUTED at tip).** `slate.rs:85–102` resolves both `read_options()` and
`scan_options()` to bare upstream defaults (`dirty: false`), and no caller can override them.
The only `with_dirty(true)` is in a `#[cfg(test)]` mutant-detector. **Provenance matters:** this
was a *repair* — commit `65da032` ("committed-memory-visible read contract (dirty=false)") is
four commits before the tip, so the claim would have been CONFIRMED before it. The integration
base is correct here; a re-audit is warranted if history is squashed in a way that reorders it.

**A13 — forked SlateDB / external epochs (REFUTED).** `fork/` contains only `typedb`. SlateDB
is a stock `=0.15.0` crate dependency (`fork/typedb/Cargo.toml`), and the main repo's
`fork/slatedb` is byte-identical to the pin (`diff -rq --exclude=.git` → empty). No epoch or
fencing code exists in the Rust storage path. They rely entirely on the unmodified library
allocator — which A1 then makes unable to protect anything.

**A14 — multi-commit evidence (PARTIAL).** The headline run
(`docs/evidence/G3/u2s3-full-2/u0-results.json`) is genuinely single-commit — all 106 rows
carry `repo_commit = c75a1af`, the *parent* of the tip; the tip adds only evidence docs and a
scoring script (0 `.rs` changes), so no Rust code is untested, *but the scoring script itself
was edited in the commit that publishes the score*. A **previously published** run still in the
tree (`docs/evidence/G3/u2s3-full/`), and still cited by `PORT-LEDGER.md`, is assembled from
**four** commits via a merge-by-target_id harness (`tools/catalog/run_u0.py:356–359`). The one
red target is `storage:test_recovery` — two upstream `todo!()` WAL-recovery stubs — and the U1
RocksDB oracle records the identical 5-pass/2-fail, so that red is honest. Weaknesses in the
comparison: `EXPLAINED` is a hardcoded allowlist; `test_fail_points` uses U2's own measurement
as its "oracle" because the U1 baseline timed out (candidate defining its own baseline,
disclosed); targets are joined by log-filename suffix, so two `bench_*` executables are
`ABSENT` from the U1 denominator.

---

## What the lead agent should do with this

1. **Treat A1, A2, A3, A6 as merge blockers.** None is surfaced by the corpus; all are
   reachable in a real multi-process, authenticated deployment.
2. **Graft the donor primitives** that already fix four of these: `StoreIdentity` (A8),
   the single-flight bounded estimate (A6), the structured `RetryClass` error channel (A10),
   and the L0-ceiling refusal (A7). See `docs/donor/donor-package.md` for the file-level import
   map.
3. **Do not treat the passing corpus as coverage** for exclusive-writer safety, tenancy, or
   sustained-write operation — the denominator does not contain those scenarios. The negative
   tests named above are the missing coverage.
