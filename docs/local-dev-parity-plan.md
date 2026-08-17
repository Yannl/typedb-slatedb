# Local development & simulation plan (dev/production parity ladder)

Decision: **everything is developed and proven locally first; Cloudflare
deployment is the last step, not a development environment.** This is
possible with high fidelity because Cloudflare's runtime is open source:
`workerd` — pinned in our source lock via workers-sdk — **is the production
Workers/DO engine itself**, not an emulator. Only R2's *service internals*
and platform operational behavior cannot be reproduced locally.

## The ladder

| Lane | What runs | Backend | Fidelity | Status |
|---|---|---|---|---|
| **L0** | TypeDB server, native process | `StorageFactory` profile **U1** (RocksDB + file WAL), **U2** (SlateDB LocalFS), or **U2S3** (SlateDB over a local MinIO speaking the S3 API R2 serves — TB-P8) | Storage semantics exact; U2S3 additionally exercises the real S3 data-path protocol (conditional puts included); no distribution | U1/U2/U2S3 all live (TB-P7/TB-P8; storage crate baseline-equal on all three, corpus evidence under `docs/evidence/G3/u2-full/` and `u2s3-full/`) |
| **L1** | Gateway Worker + `DatabaseControllerDO` under **workerd** (`wrangler dev --local`), payloads through the **local R2 binding**; TypeDB (or the Rust spike client) as native process | Remote WAL protocol against the real DO runtime | DO/Worker semantics = production engine; R2 = API-faithful simulator | **RUNNING — 35/35 E2E green** (`control-plane/scripts/local-stack-e2e.mjs`), incl. the complete U3.0 replay/head/scan/fence surface |
| **L2** | Full topology: TypeDB in the production container image next to workerd, orchestrated by `wrangler dev` container support | Same as production wiring | Adds container lifecycle | Needs a Docker daemon — available on dev machines; absent in this CI sandbox |
| **L3** | Real Cloudflare staging account | Real R2/DO/Containers/Bucket Lock | Platform facts, cost/latency envelopes | Blocked on credentials (SI-G0-3); the only lane that can close gate G2 |

Rules:
- L0→L1→L2 must be green before anything is deployed; L3 is for platform
  facts and the G2 measurements, never for debugging logic.
- Local R2 (miniflare's simulator) is **API-faithful but not
  evidence-grade**: throttling, 5xx patterns, conditional-write races,
  multipart edge semantics and cost are re-implementations. Anything the
  conformance plan calls a "platform fact" still requires L3. Local lanes
  prove *our* logic; L3 proves *their* platform.

## Should local dev use a "local dev TypeDB stack" (plain TypeDB), or the production backend?

Both — they serve two different users, and the whole conformance programme
exists precisely so this choice has no consequences:

- **Application developers** (people building on TypeDB's query API): use
  the cheapest lane, L0/U1 — plain TypeDB semantics with local RocksDB +
  file WAL. The backend is invisible at the TypeQL/driver surface, and that
  invisibility is not an assumption: it is the measured gate criterion.
  U0–U4 structural equality (result sets, errors, transaction outcomes,
  visibility, recovery frontiers) is what G3/G5/G6 certify. When those
  gates are green, "swap the backend" is a proven no-op for applications —
  so app dev on the light stack and production on R2 are in parity **by
  construction, continuously re-verified**, not by hope.
- **System developers** (us, building the backend itself): must run the
  real topology locally — L1/L2 — because the things we are building
  (fencing, finalisation, ambiguity resolution, outbox, budgets) only
  exist in the distributed lanes.

The one honest caveat to "swap with no consequence": *operational*
characteristics (latency profile, cost, hibernation behavior) differ
between backends by design. Functional parity is gated; operational
envelopes are measured at L3 and stated, not hidden.

## What was proven locally today (this sandbox, no Cloudflare account)

- `DatabaseControllerDO` executing on real workerd: SqlStorage +
  `transactionSync` finalisation, replay idempotency, digest conflict,
  status singleton, register-fences-predecessor + the U3.0 read surface
  (vitest-pool-workers, 7 tests across 2 files).
- Full L1 topology over real HTTP (`wrangler dev` + local R2): payload
  upload → data-path SHA-256 receipt verification → DO finalisation →
  exact read-back; lost-response retry replays the identical allocation;
  tampered digests and ghost payloads rejected in the data path (422)
  before the controller; conflicting status 409; fenced session 409; exact
  read miss typed 404; tail contiguity audit green; outbox
  peek/redeliver/ack/idempotent-ack; takeover fencing, head, pinned scans
  with type filters, last-by-type, all-or-nothing batches, typed
  400s/param validation — **35/35**.
- The controller logic itself: 21/21 on real SQLite with an EFFECTIVE
  mutant negative control (the mutant run fails exactly one test), and
  SQL-vs-pure-reducer trace equivalence (recordType included).

## U3: remote WAL for TypeDB itself (staged; U3.0 done)

The full scoping report (trait surface, protocol mapping, risks) lives in
the session record; the staged plan:

- **U3.0 — protocol completion (DONE)**: `record_type` catalogued on every
  WAL record; `/head` (LSN + TypeSequence); `POST /iterator` (pinned
  snapshot); `/scan` (physical-order replay pages, mandatory pinned bound,
  optional type filter, digest-verified inline payloads); `/last?recordType`
  (`find_last_type`); `/wal/finalize-batch`; **register fences the
  predecessor** (takeover-at-open, pinned in the TS core, the Rust spike
  client lane, and the pure model — a cross-lane divergence of exactly the
  class ADR-0006 exists to prevent); AppendLsn base 0 aligned across all
  lanes; the read path's base64 built chunked.
- **U3.1** — productionise `l1_client` into fork-owned
  `durability/remote/`: paged scan iterator yielding `RawRecord` with
  exact-start enforcement, StatusKey derivation from the 9-byte
  StatusRecord prefix, deterministic operation ids
  (generation ⊕ session ⊕ counter), typed error mapping, bounded retry with
  identical-request ambiguity resolution.
- **U3.2** — `enum DurabilityBackend { File(WAL), Remote(RemoteWal) }`
  behind `StorageFactory` (keeps `Database<WALClient>` and its ~106 call
  sites untouched); `truncate_from`/`delete_durability`/`reset` are typed
  `Unsupported` until generation rollover lands.
- **U3.3** — run `durability`/`storage`/`database` suites under
  `TYPEDB_STORAGE_PROFILE=U3` against a self-booted `wrangler dev`;
  classify file-WAL-specific tests, never skip silently.
- **U3.4** — fencing at `Database::create/load` before any read
  (fence-precedes-replay, ADR-0006), failpoint crash matrix.

## Remaining local work items (added to the plan)

1. **TB-P4 client spike → L1 wiring** — DONE: `tools/remote-wal-spike`
   `l1_client.rs` + self-booting integration test (1/1 green, leak-free
   process-group reaping).
2. **U2 lane (SlateDB LocalFS)** behind `StorageFactory` — DONE. Semantic
   ground proven by `tools/storage-diff-spike` (2/2 green vs an ordered
   oracle, negative control effective) and the TB-P7 adapter landed
   (owner-authorized ahead of the playbook's G2 gating): full `storage`
   crate suite baseline-equal on U2, upstream corpus run archived under
   `docs/evidence/G3/u2-full/`.
3. **L2 bring-up on a Docker-equipped machine**: production container image
   + wrangler dev containers; add a one-command `npm run stack:local`.
4. **Outbox → consumer path in L1** — DONE: at-least-once peek/ack contract
   through core/DO/worker; node E2E green including redelivery-without-ack
   and idempotent duplicate ack.
