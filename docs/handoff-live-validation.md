# Live-validation handoff — Cloudflare setup and pickup guide

> **Status correction (2026-08-18, deep audit).** The claim this document
> used to open with — that everything local is complete and credentials are
> the only blocker — is FALSE. The authoritative state lives in
> `docs/ledger/gates.json` (rendered into docs/operations.md): G0 is
> OPEN_RED (Mode-Q evidence absent), G1 is OPEN (catalogue is a census,
> not a qualification denominator), and G2 is NOT_READY_TO_EXECUTE (owner
> envelope and authority-boundary prerequisites outstanding). Credentials
> (SI-G0-3) are ONE blocker among several. The setup instructions below
> remain useful for the eventual disposable `G2_PLATFORM_PROBE` run — which
> is a platform-fact probe, never product qualification.
>
> **Round-3 update (2026-08-18).** The old "copy `wrangler.toml`, change only
> the bucket, `wrangler deploy`" flow is superseded: the canonical staging
> path is the Alchemy graph in `stack/` (one `alchemy.run.ts` owning Worker /
> ControllerDO / ContainerDO / R2, generated from — or checked against — the
> committed `wrangler.toml`), and no live run may start until
> `probes:preflight` is machine-green (disposable target + owner numeric
> envelope `docs/probe-run-envelope.json`). The probe adapter now separates
> admin/runtime principals and redacts secrets; see the round-3 response for
> the full P-01..P-06 changes.

Written so that a **fresh session with empty context** can take the
program from its current state toward a disposable platform-probe run on
Cloudflare, once the ledger's prerequisites are met.

## 0. Orientation (60 seconds)

- **What this repo is**: TypeDB with its keyspace storage ported to
  SlateDB-on-object-store, plus a Durable-Object control plane for the
  remote WAL protocol. Read [README.md](../README.md) then
  [architecture.md](architecture.md).
- **Branch**: `claude/review-continue-previous-zv4wmi` (continues and
  contains `claude/typedb-r2-implementation-5o64sh`; push to the branch
  you are on — the session assignment names it).
- **State**: U2 (SlateDB local) passes the full upstream corpus
  structurally equal to the RocksDB oracle (106 executables, 0 timeouts;
  2 documented upstream defects —
  [u2-vs-oracle-comparison.json](evidence/G3/u2-vs-oracle-comparison.json)).
  Control plane green on real workerd (L1: 20/20 E2E). Locks +
  workspace binding lint-verified. Spec reconciliation:
  [spec-delivery-comparison.md](spec-delivery-comparison.md).
- **What's left**: platform facts + G2 measurements on a real account —
  this document; then the G2-gated phases (U3/U4).

Sanity check before starting (all must pass, no credentials needed).
On a fresh machine `sources/` does not exist yet — materialise it from
the lock first (docs/development.md §"Bootstrapping a fresh machine"):

```sh
python3 tools/dev/doctor.py                            # env preflight + fixes
python3 tools/source-lock/materialize_sources.py       # sources/ from the lock
python3 tools/source-lock/lint_source_lock.py          # LINT: PASS
cd control-plane && npm ci && npm run typecheck && npm run test:controller && npm run test:workerd
```

(The Rust corpus needs the fork staged plus a one-time cold build,
~40 min: `python3 tools/fork/stage.py &&
cd sources/typedb && cargo +1.93.0 test --workspace --no-run`.)

## 1. Cloudflare account prerequisites

| Requirement | Why | Where |
|---|---|---|
| **Workers Paid plan** (~$5/mo) | SQLite-backed Durable Objects require it; Containers (later, L2/L3 topology) require it too | Dashboard → Workers & Pages → Plans |
| **R2 enabled** (billing card on file) | payload bucket + probe bucket; free tier covers the probe volumes | Dashboard → R2 |
| **Account ID** | every API call / env var below | Dashboard, right sidebar ("Account ID") |

Use a **dedicated staging account/sub-account** if possible — nothing in
this plan touches production data, but blast-radius isolation is cheap.

## 2. Credentials — two tokens, minimal scopes

### 2.1 R2 S3 credentials (for the platform probes)

The probe runner (`control-plane/probes/run-r2-probes.ts`) speaks the S3
API directly (SigV4) and reads **exactly these env vars** (it exits with
code 3 and the SI-G0-3 marker if any is missing):

```
R2_ACCOUNT_ID            # the account id
R2_ACCESS_KEY_ID         # minted by the R2 API token below
R2_SECRET_ACCESS_KEY     # minted by the R2 API token below
R2_PROBE_BUCKET          # a dedicated empty bucket, e.g. typedb-probe-staging
```

Setup:
1. Dashboard → **R2 → Create bucket** → `typedb-probe-staging`
   (automatic location, no public access).
2. Dashboard → **R2 → Manage R2 API Tokens → Create API Token**:
   - Permissions: **Object Read & Write** (NOT admin — the probes never
     create or delete buckets);
   - Scope: **Apply to specific buckets only** → `typedb-probe-staging`;
   - TTL: cover the session only (e.g. 7 days);
   - copy the minted Access Key ID / Secret Access Key.

Probe P-R2-02 (credential scoping/revocation) additionally needs a
*second*, deliberately narrower prefix-scoped token minted the same way —
create it when running that probe and revoke it as part of the probe.

### 2.2 API token for wrangler (deploying the control plane)

Dashboard → **My Profile → API Tokens → Create Token → Custom token**
with exactly:

| Scope | Permission | Needed for |
|---|---|---|
| Account → **Workers Scripts** | **Edit** | deploy Worker + `DatabaseControllerDO` (SQLite class migration `v1` is in `wrangler.toml`) |
| Account → **Workers R2 Storage** | **Edit** | `wrangler r2 bucket create` + the `PAYLOADS` binding |
| Account → **Account Settings** | **Read** | wrangler account resolution (`whoami`) |

- Account Resources: **only** the staging account.
- Optional: Workers Observability/Logs **Read** (live tail);
  **Containers Edit** only when the container topology is exercised —
  not needed for the Worker+DO+R2 validation below.
- No zone scopes, no user scopes, no DNS. Client-IP filter and short TTL
  recommended.

```
export CLOUDFLARE_API_TOKEN=...     # the custom token
export CLOUDFLARE_ACCOUNT_ID=...
```

**Custody rules**: env vars only — never committed, never echoed into
logs or evidence (the probe runner writes raw request logs; credentials
must stay redacted). Rotate/revoke both tokens when the session ends.

## 3. Execution plan

### Step 1 — Platform probes (closes the "platform fact" caveats)

```sh
cd control-plane && npm ci
npm run probes:r2         # needs the four R2_* env vars
```

Evidence lands in `docs/evidence/G1-platform/<probe_id>/` (structured
JSON + raw logs). What they establish: real R2 conditional-write
semantics (`If-None-Match:*` → 412 for the loser, exactly one winner
under concurrency), checksum echo, same-key-pressure behavior,
credential scoping/revocation latency. These replace every
"simulator, not evidence-grade" caveat in
[local-dev-parity-plan.md](local-dev-parity-plan.md) — especially the
payload-immutability contract (ADR-0007), whose local test ran against
miniflare's re-implementation.

### Step 2 — Staging deploy of the control plane

```sh
cd control-plane
npx wrangler r2 bucket create typedb-payloads-staging
# staging config: copy wrangler.toml -> wrangler.staging.toml, change ONLY
#   bucket_name = "typedb-payloads-staging"
npx wrangler deploy --config wrangler.staging.toml
```

Then run the full protocol E2E **against the real platform**:

```sh
node scripts/local-stack-e2e.mjs https://typedb-r2-control-plane.<subdomain>.workers.dev
```

Expected: **ALL PASS (20 checks)** — payload digest path,
finalize/replay/digest-conflict, status singleton + conflict, fenced
session, exact reads, tail contiguity, outbox
peek/redeliver/ack/idempotent-ack. Any deviation from the local L1 run
is by definition a platform fact: record it under `docs/evidence/G2/`
**before** touching any code (ADR-0009: L3 is never for debugging
logic — reproduce locally instead).

### Step 3 — The G2 measurement matrix (the kill gate)

Measure (brief §9.10 in [inception/](inception/ARCHIVE-NOTE.md); the
probes sidecar has detailed protocols):

1. **Append + sync latency** p50/p95/p99 — loop the
   upload→finalize→receipt path at 1 KiB / 64 KiB / 1 MiB payloads; the
   Rust client (`tools/remote-wal-spike/src/l1_client.rs`) drives the
   identical protocol against the staging URL for tight timing.
2. **DO transaction throughput** — sustained finalize/s on one
   `DatabaseControllerDO` (the single-writer ceiling) and
   batch-finalize scaling (`finalizeBatch`).
3. **Outbox lag** — finalize→peek latency under load; redelivery under a
   deliberately slow consumer.
4. **Amplification** — objects, requests, and $ per logical commit
   (R2 class-A/B ops + DO duration billing) vs. the per-record and batch
   shapes the brief models.

Record to `docs/evidence/G2/` (JSON-per-measurement, like the rest of
the evidence tree). **Gate semantics**: G2 red triggers protocol
redesign (batch shape, sync cadence) *before* any U3/U4 build-out — a
kill gate, not a soft target.

### Step 4 — After G2 green

In order (details:
[spec-delivery-comparison.md](spec-delivery-comparison.md) WP8):
productionise the remote-WAL client behind `StorageFactory` (U3; the
TB-P4 spike is the reference implementation), add the fencing
`ObjectStore` wrapper (ADR-0001's SL-P1 obligation) plus `aws`/`foyer`
features for R2 (the allowlist ceiling), then run the corpus on U3 and
finally U4 against real R2. The L2 container rung
(`npm run stack:local`) needs any Docker-equipped machine and can
proceed in parallel.

## 4. Hard rules for the live session

- **No logic debugging on L3** (ADR-0009); capture evidence, reproduce
  locally.
- **No real data**; staging buckets only; delete them after if cost
  matters.
- **Never edit** upstream tests, `docs/inception/`, or historical
  evidence — new facts get new files.
- Push to the session's designated branch (currently
  `claude/review-continue-previous-zv4wmi`); keep
  `python3 tools/source-lock/lint_source_lock.py` green before each
  commit.

## 5. Empty-context pickup checklist

1. Read [README.md](../README.md) → [architecture.md](architecture.md) →
   [operations.md](operations.md) → this file.
2. Run the §0 sanity block.
3. Export the seven env vars per §2.
4. Execute §3 step by step, committing evidence as you go.
5. Ground-truth chain when anything surprises you:
   `git log --oneline` → the evidence tree → the ADR index
   ([architecture/ADR/](architecture/ADR/README.md)) → the
   reconciliation
   ([spec-delivery-comparison.md](spec-delivery-comparison.md)).
