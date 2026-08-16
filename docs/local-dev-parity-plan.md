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
| **L0** | TypeDB server, native process | `StorageFactory` profile **U1** (RocksDB + file WAL) or **U2** (SlateDB LocalFS) | Storage semantics exact; no distribution | U1 live today; U2 lands with TB-P7 |
| **L1** | Gateway Worker + `DatabaseControllerDO` under **workerd** (`wrangler dev --local`), payloads through the **local R2 binding**; TypeDB (or the Rust spike client) as native process | Remote WAL protocol against the real DO runtime | DO/Worker semantics = production engine; R2 = API-faithful simulator | **RUNNING — 12/12 E2E green** (`control-plane/scripts/local-stack-e2e.mjs`) |
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
  status singleton (vitest-pool-workers, 2/2).
- Full L1 topology over real HTTP (`wrangler dev` + local R2): payload
  upload → data-path SHA-256 receipt verification → DO finalisation →
  exact read-back; lost-response retry replays the identical allocation;
  tampered digests and ghost payloads rejected in the data path (422)
  before the controller; conflicting status 409; fenced session 409; exact
  read miss typed 404; tail contiguity audit green — **12/12**.
- The controller logic itself: 12/12 on real SQLite with an EFFECTIVE
  mutant negative control, and SQL-vs-pure-reducer trace equivalence.

## Remaining local work items (added to the plan)

1. **TB-P4 client spike → L1 wiring**: point the Rust remote-WAL client at
   the L1 HTTP facade so the same protocol tests run Rust-native against
   workerd (today the E2E driver is a node script).
2. **U2 lane (SlateDB LocalFS)** behind `StorageFactory` — then L0
   differential U1↔U2 becomes the storage-swap proof at the TypeDB test
   corpus level (G5 pre-work).
3. **L2 bring-up on a Docker-equipped machine**: production container image
   + wrangler dev containers; add a one-command `npm run stack:local`.
4. **Outbox → consumer path in L1**: drain the control outbox to a local
   queue consumer, closing the event loop locally.
