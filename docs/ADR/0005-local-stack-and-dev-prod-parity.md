# ADR-0005 — Local stack: what parity is free, and what is not

**Status:** accepted, planning (pre-Phase C)
**Contract:** brief §21.9 (no cache reuse for fault/credential tests), §22.3 (U0/U1 equality)

## The question

If the programme only swaps TypeDB's storage backend, dev/production parity should come for
free — the same binary runs in both places. So is a local stack worth building at all?

## The short answer

Mostly yes, it is free — but not for the reason it sounds like, and there is a second seam
that is not free and is easy to miss.

**There is not one swap here. There are two.**

| | Before | After | Parity cost |
|---|---|---|---|
| Swap 1 — TypeDB's storage layer | RocksDB | SlateDB | free: one binary, same everywhere |
| Swap 2 — where that storage lives | local disk (POSIX) | object storage | **not free** |

RocksDB was a local-disk engine: `fsync`, microsecond latency, POSIX rename semantics.
SlateDB is object-store-backed: PUTs over a network, millisecond latency, no rename, different
durability points. That is a genuine behavioural change, not a drop-in — and it is the change
the two upstream `todo!()` WAL-recovery tests sit directly on top of (Phase B summary).

So the thing to get right locally is not "TypeDB" — it is **the object store seam**.

## What Cloudflare's OSS actually gives us

Verified against the pinned checkouts rather than recalled:

* **`workerd`** (`CF-WORKERD @ 562ac20f`) is the production Workers runtime, and `wrangler dev`
  runs *that binary* locally. This is not an emulator with its own semantics; it is the same
  runtime.
* **Containers run locally.** `containers/local-dev.mdx` in `CF-DOCS @ dec26351`: "You can run
  both your container and your Worker locally by simply running `npx wrangler dev`", requiring
  a Docker-compatible engine; instances launch on demand and "requests will then automatically
  be routed to the correct locally-running container". Two documented divergences: local
  concurrency is bounded by the machine, and `max_instances` does not apply locally.
* **R2 is emulated with persistence.** `packages/miniflare/README.md` in `CF-SDK @ c5762872`
  documents R2 bindings and states that resource state (KV, R2, D1, Durable Objects,
  Workflows) is persisted between sessions.
* **SlateDB already targets S3-compatible endpoints as a first-class path.** `slatedb/Cargo.toml`
  L92-93 makes `aws = ["object_store/aws"]` a default feature, and the repo's own
  `examples/src/s3_compatible.rs` builds an `AmazonS3Builder` with
  `.with_endpoint("http://localhost:4566").with_allow_http(true)` — i.e. pointing SlateDB at a
  local S3 is a supported configuration, not a hack.

R2 is S3-compatible. So SlateDB reaches R2 in production and MinIO/LocalStack locally through
**the same `object_store::aws` client**, differing only in endpoint and credentials. That is
where the parity actually comes from, and it is why swap 2's parity is cheap even though swap 2
itself is not.

## Decision

Build the local stack in three layers, and do not conflate them. Each is independently useful
and each fails differently.

**L1 — TypeDB + SlateDB against a local S3.** No containers, no Workers. One binary, one MinIO
(or LocalStack) endpoint.

This is not a developer convenience. **It is the U1 lane.** U1 is defined as the fork running
the same 4 757 catalogued leaf cases that U0 just measured, and the fork's storage backend
needs somewhere to put bytes. Without L1 there is no U1, and without U1 there is no
U0/U1 equality claim — which is the core of the contract. It is a prerequisite, not an extra.

**L2 — Worker + container via `wrangler dev`.** The TypeDB container fronted by a Worker,
against local R2. This exercises what L1 cannot: container lifecycle, sleep/wake, request
routing, Durable Object coordination. None of that is the storage swap, and all of it is new
code that has to work before anything is deployed.

**L3 — Cloudflare.** Only after L1 and L2 are green.

## Why this is not over-engineering

The instinct behind the question — "we swap a backend, parity should be free" — is right about
TypeDB and wrong about the deployment shape. Concretely, L2 exists because these are true only
on Cloudflare and cannot be observed at L1:

* a container can be stopped between requests and must resume correctly;
* the Worker↔container hop has its own failure and timeout behaviour;
* R2 consistency and rate limits differ from a local MinIO under load.

Equally, L1 exists because debugging a SlateDB WAL problem through a Worker, a Durable Object
and a container is far harder than debugging it against a bare binary. Keeping them separate
means a failure at L1 is a storage bug and a failure at L2 is a platform bug, which is most of
the diagnostic value.

## What stays honest

* L1 parity is **near**-free, not free: same client, same code path, different endpoint. Local
  MinIO will not reproduce R2's rate limiting or tail latency, so performance and
  backpressure claims may not be made from L1 evidence.
* §21.9 forbids cache reuse for fault and credential tests, so L1/L2 runs feed iteration, not
  release evidence. `CF-ACCOUNT` remains class-U and real-account probes remain required.
* The container image needs a base; `TB-BASE` is still unresolved.

## Plan additions

1. `cargo xtask local-stack up` — MinIO + a SlateDB-configured TypeDB, deterministic ports and
   a fixed bucket.
2. Point the U1 profile at it, so `cargo xtask test-upstream --profile U1` needs no manual setup.
3. Add L2 (`wrangler dev` + container + local R2) once U1 is measurable.
4. Record the divergences above in the release evidence, so no L1 result is cited for a claim
   it cannot support.
