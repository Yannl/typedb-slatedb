# Physical Architecture (PA)

*Arcadia perspective 4 — how the system is built: concrete components,
technology, deployment topologies, and the allocation of logical
components onto them.*

## Physical components

### Database node (Rust, parity toolchain 1.93.0)

| Physical | Realises (logical) | Notes |
|---|---|---|
| `fork/typedb` server crates (`typedb_server_bin`) | Query Engine, MVCC Storage, Recovery Manager | soft-fork of upstream at pin `2256711ab`; every patch ledgered (`fork/typedb/PORT-LEDGER.md`) |
| `storage/factory.rs` | Storage Factory | `TYPEDB_STORAGE_PROFILE`, cached per process |
| RocksDB (vendored via upstream deps) | Keyspace Engine — oracle arm | upstream tuning verbatim; WAL disabled |
| **SlateDB `=0.15.0` from crates.io** | Keyspace Engine — object-store arm | consume-only (ADR-0001); adapter is `storage/keyspace/slate.rs` |
| Tokio storage runtime (4 threads) + std-channel bridge | sync/async boundary | ADR-0004; one per process, all SlateDB futures |
| File WAL (`durability/`) | Durability Client realisation (U0–U2) | upstream implementation behind the factory |

SlateDB physical configuration (ADR-0005): engine WAL off, compactor off,
GC off, compression off, L0 caps 1M, dirty+Memory reads,
`await_durable: false` writes; object store = `LocalFileSystem` rooted at
the keyspace directory (store layout `<dir>/keyspace/{manifest,…}`).
Checkpoints = flush + manifest-pinned directory copy.

### Control plane (TypeScript, workerd)

| Physical | Realises | Notes |
|---|---|---|
| `worker-entry.ts` (Worker) | Payload Data Path, HTTP facade | conditional-create payload puts against the R2 binding |
| `DatabaseControllerDO` (Durable Object, SqlStorage/SQLite) | Session Registry, Finalisation, Outbox | one DO per database; finalisation is one synchronous SQLite transaction |
| `controller/core/` (runtime-neutral TS) | the same procedures on plain SQLite | executed by both the DO and the node test lane — one implementation, two hosts |
| wrangler / workerd (pinned via lockfile) | production Workers/DO engine | the actual engine, not an emulator (ADR-0009) |

### Proof machinery

| Physical | Realises |
|---|---|
| `tools/catalog/` (generate_catalog, run_u0, run_static, package_assembly) | Corpus Catalogue & Runner; statics; assembly archive |
| `tools/protocol-models/` (pure Rust) | reference models with mutant controls |
| `tools/remote-wal-spike/` | deterministic spike controller + real-HTTP L1 client |
| `tools/storage-diff-spike/` | SlateDB-vs-ordered-oracle semantics differential |
| `tools/source-lock/lint_source_lock.py` | lock verification (git nodes, artifacts, registry pins in every consumer lockfile) |

## Deployment topologies (the parity ladder, ADR-0009)

| Rung | Topology | Storage physicals |
|---|---|---|
| **L0** | one native process | RocksDB or SlateDB-on-LocalFS + file WAL |
| **L1** | native process/client ⇄ workerd (`wrangler dev --local`): Worker + DO + local R2 binding | protocol over real HTTP; payloads in simulated R2 |
| **L2** | production container image beside workerd via `wrangler dev` containers | adds container lifecycle (needs Docker) |
| **L3 / production target** | Cloudflare: gateway Worker + `DatabaseControllerDO` + TypeDB container (4 vCPU / 12 GiB / 20 GB envelope) + R2 buckets | R2 conditional writes; controller-issued epochs fence every publication |

Production object layout (from the brief): per-database prefixes with
`keyspaces/{keyspace_id}/slatedb/...` for materialisation and
exact-identity WAL/command objects (`EXACT_AUTHORITATIVE` class) vs
orphanable bulk SST uploads (`PREFIX_BULK_ORPHANABLE`) fenced at manifest
publication.

## Physical constraints and their consequences

- **Object stores read by path** — no POSIX unlink-while-open grace; one
  upstream benchmark depends on it and is carried as a corrected
  expectation (ADR-0008).
- **No background rewrites** (compactor/GC off) — read amplification
  grows with L0 within a store's lifetime; bounded by disposable-store
  recovery. Production revisits compaction only as a fenced external
  process.
- **Bridge overhead** — µs per storage call; measured 2–5× oracle
  wall-clock on storage-heavy suites, zero timeouts in the full corpus.
- **Single writer per store** — SlateDB manifest epochs fence concurrent
  opens of one directory; the distributed design layers controller-issued
  epochs on top (modelled in `fencing_model.rs`, enforced end-to-end in
  U3/U4).
- **DO synchronous transaction window** — the finalisation procedure
  performs no I/O await between validation and its SQLite commit (brief
  inv. 151), which is why it can be one `transactionSync`.

## Verification status of this architecture

Corpus: 106/106 executables executed on U2, structurally equal to the
oracle (2 documented upstream defects; 0 timeouts). Protocol: 20-check
L1 E2E green over real HTTP; DO suites green on workerd; node/SQLite lane
green with an effective mutant control; models exhaustive with negative
controls. Statics 141/141; source-lock lint green. Evidence:
`docs/evidence/`.
