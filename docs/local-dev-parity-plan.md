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
| **L0** | TypeDB server, native process | `StorageFactory` profile **U1** (RocksDB + file WAL), **U2** (SlateDB LocalFS), or **U2S3** (SlateDB over a local MinIO speaking the S3 API R2 serves — TB-P8) | Storage semantics exact; U2S3 additionally exercises the real S3 data-path protocol (conditional puts included); no distribution | U1/U2 adapter lanes run locally (TB-P7/TB-P8). Honesty (R4-EVID-02): the archived U2S3 run is a HISTORICAL dirty-tree target-aggregate smoke (`docs/evidence/G3/u2s3-full-3/CLASSIFICATION.json`), not qualification; leaf-level plan coverage is 0/23,138 (`docs/evidence/G1/plan-coverage-v2.json`) |
| **L1** | Gateway Worker + `DatabaseControllerDO` under **workerd** (`wrangler dev --local -c wrangler.local-dev.toml`), payloads through the **local R2 binding**; TypeDB (or the Rust spike client) as native process | Remote WAL protocol against the real DO runtime | DO/Worker semantics = production engine; R2 = API-faithful simulator; **security posture = developer-convenience (dev issuer/admin routes), explicitly NON-PARITY (R4-STACK-01/R4-SEC-01)** | E2E green on the dev-issuer surface (`control-plane/scripts/local-stack-e2e.mjs`); it proves refusal mechanics and protocol shape, NOT the production authorization topology — the managed-posture parity lane lands with the private issuer/registry (R4-PR1) |
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

## The canonical stack: `stack/` (Alchemy as IaC/orchestrator — R3 audit A-01)

Round-3 direction: **Alchemy (pinned `2.0.0-beta.72`, upstream commit
`6b73819a…`) is the canonical Cloudflare IaC/orchestrator**; the retained
`control-plane/wrangler.toml` is a *validated view*, never an independent
source of truth. Everything lives in the top-level `stack/` package:

- **`stack/graph.data.mjs`** — the single source of truth for the logical
  graph: worker name/entry, compatibility date, `CONTROLLER` →
  `DatabaseControllerDO` (SQLite DO), the **declared-ahead** `CONTAINER` →
  `DatabaseContainerDO` namespace (activates automatically once the class
  is exported from the worker entry), `PAYLOADS` R2 binding, `[vars]`
  posture, `CONTROLLER_*` secret schema, and the production-env invariants
  (`CONTROLLER_KEY_PROFILE=managed`; `CONTROLLER_SURFACE` **must be
  absent** — fail-closed). R4-STACK-01: the DEFAULT `wrangler.toml` is
  now the managed posture; the developer-convenience posture lives in the
  explicit `wrangler.local-dev.toml`, and every graph carries a declared
  `securityPosture` that `graph-diff` validates per graph.
- **`stack/alchemy.run.ts`** — the canonical Alchemy program (local file
  state only). `alchemy dev` runs the real worker-entry bundle on the
  Alchemy-pinned workerd and emulates the R2 binding locally.
- **`stack/cli.mjs`** — the one command:
  - `node cli.mjs dev` (mode `native`): no-cloud guard → wrangler
    consistency check → source-locked native **MinIO** (S3 half; loopback,
    random per-run credentials, per-run data dir, readiness = SigV4
    ListBuckets round-trip) → `alchemy dev` (Worker/DO/local-R2 half) →
    `dev:` identity assertion → run-identity manifest (digests of graph,
    wrangler.toml, lockfile, MinIO binary).
  - `node cli.mjs down --verify-clean`: kills recorded process groups,
    verifies ports released and no survivors from ANY recorded run;
    nonzero otherwise.
  - `node cli.mjs graph` / `check-wrangler`: canonical-JSON graph and the
    toml drift check (CI-runnable, offline).
- **`stack/graph-diff.mjs`** — mode differential with an explicit
  allowlist (endpoints, secret values, provider identity,
  native-vs-container execution); binding names, DO classes, compat date,
  budgets, and backend identity differing is a hard failure.
- **Zero-cloud-risk rule** (`stack/no-cloud-guard.mjs`): the local command
  hard-fails if `CLOUDFLARE_API_TOKEN`/`CLOUDFLARE_ACCOUNT_ID` are set,
  statically refuses `remote()`/live/bridge imports and any resource kind
  outside the local-provider allowlist, and asserts every persisted
  resource is `providerMode=local` with a `dev:` physical id. Upstream
  wart, handled: alchemy `2.0.0-beta.72` resolves the credential *chain*
  even for purely-local providers, so the CLI injects self-evidently fake
  placeholder values (all-zero account id, non-token string) into the
  child env after stripping the real ones — they cannot authenticate, so
  an accidental live call fails closed.
- **Source lock**: `ALCHEMY` (npm, exact pin + integrity, cross-checked
  against `stack/package-lock.json` and the rangeless spec in
  `stack/package.json`), `WORKERD_ALCHEMY` (the EFFECTIVE workerd
  `1.20260704.1` that `alchemy dev` executes — deliberately locked as a
  SEPARATE line from the wrangler-resolved `WORKERD 1.20260811.1`; any
  runtime-sensitive result must name its line; converging them is tracked
  follow-up), and `MINIO` (exact release binary, sha256-verified on every
  use, cached uncommitted under `sources/minio/`).
- **What Alchemy local R2 is NOT**: it has **no S3 endpoint** (no SigV4,
  no XML API, no S3 conditional/multipart surface) — it exists only as a
  Worker binding inside the workerd proxy. The TypeDB/SlateDB
  `object_store` path therefore keeps the pinned native MinIO; an S3
  facade over local R2 is explicitly rejected.
- **Known limits here**: `alchemy dev` serves on its default port 1337
  (one stack instance at a time); the ContainerDO execution lane (L2)
  still needs a Docker daemon and stays blocked in this sandbox; wiring
  the exact TypeDB release binary + fault proxy into `stack dev` is the
  next PR on this path.

## Should local dev use a "local dev TypeDB stack" (plain TypeDB), or the production backend?

Both — they serve two different users, and the whole conformance programme
exists precisely so this choice has no consequences:

- **Application developers** (people building on TypeDB's query API): use
  the cheapest lane, L0/U1 — plain TypeDB semantics with local RocksDB +
  file WAL. Backend invisibility at the TypeQL/driver surface is the
  INTENDED gate criterion, and today it is NOT yet measured: leaf-level
  plan coverage is 0/23,138 and the official-driver lanes are
  NOT_IMPLEMENTED (R4-EVID-02). U0–U4 structural equality (result sets,
  errors, transaction outcomes, visibility, recovery frontiers) is what
  G3/G5/G6 will certify. Only when those gates are green does
  "swap the backend" become a proven no-op for applications —
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
  identical-request ambiguity resolution. Retry taxonomy per the hydradb
  comparative review: `SESSION_FENCED` is never retryable and never enters
  the ambiguity loop — it surfaces to `Database` lifecycle, which re-enters
  only via a fresh register with a NEW startup session id (ADR-0011);
  fence handling and failure backoff are separate mechanisms.
- **U3.2** — `enum DurabilityBackend { File(WAL), Remote(RemoteWal) }`
  behind `StorageFactory` (keeps `Database<WALClient>` and its ~106 call
  sites untouched); `truncate_from`/`delete_durability`/`reset` are typed
  `Unsupported` until generation rollover lands.
- **U3.3** — run `durability`/`storage`/`database` suites under
  `TYPEDB_STORAGE_PROFILE=U3` against a self-booted `wrangler dev`;
  classify file-WAL-specific tests, never skip silently.
- **U3.4** — fencing at `Database::create/load` before any read
  (fence-precedes-replay, ADR-0006), failpoint crash matrix. Faults are
  injected **per operation type** (upload / finalize / read / register),
  not only per call sequence — the partial-failure mode where one verb
  fails while others land is invisible to all-or-nothing fault doubles
  (hydradb comparative review, transfer 4).

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
   + the ContainerDO lane under Alchemy (`Cloudflare.Container` attaches
   the OCI image to the declared `CONTAINER` namespace). The one-command
   entry point exists now — `stack/cli.mjs dev` (see the canonical-stack
   section above); the container lane extends it, it does not replace it.
4. **Outbox → consumer path in L1** — DONE: at-least-once peek/ack contract
   through core/DO/worker; node E2E green including redelivery-without-ack
   and idempotent duplicate ack.
