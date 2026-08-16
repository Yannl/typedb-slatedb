# 4 — Physical Architecture

**Arcadia level:** PA. **Maturity: PROVISIONAL.** Technology-bound realisation of the logical
components. The conformance rows are built and measured; the deployment rows are an intent
with named unknowns.

Every platform claim below is anchored to a pinned checkout. Anything not anchored is labelled
an assumption.

## Realisation map

| Logical | Physical | Technology | Status |
|---|---|---|---|
| LC-1 Query & Type Engine | TypeDB server crates | Rust, `TB @ 2256711a`, unmodified | built |
| LC-2 Storage Abstraction | `storage`, `durability`, `encoding` | Rust | built |
| LC-3a Local-Disk Engine | `rocksdb` / `librocksdb-sys` | RocksDB (C++) | built |
| LC-3b Object-Store Engine | `slatedb` | Rust, `SL @ f88be86d` | **not integrated** |
| LC-4 Object Store | R2 (prod) / MinIO or LocalStack (local) | S3 API | not provisioned |
| LC-5 Lifecycle Manager | Worker + Durable Object + Container | workerd, `@cloudflare/containers` | not built |
| LC-6/7/8 Conformance | `tools/` workspace | Rust: `corpus-catalog`, `conformance-runner`, `xtask` | **built, 73 unit tests** |

## Deployment topology (intended)

```
   client
     │ HTTPS
┌────▼──────────────────────────────────────────┐
│  Worker (workerd isolate)                     │  routing, auth
│    └─ Durable Object                          │  per-domain coordination
│         └─ Container                          │  ← TypeDB server runs here
└────┬──────────────────────────────────────────┘
     │ S3 API
┌────▼──────────┐
│  R2 bucket    │  ← SlateDB objects
└───────────────┘
```

TypeDB is a native binary linking RocksDB's C++ tree; it cannot run inside a V8 isolate. It
therefore runs in a **Container**, not in the Worker. This is the single most consequential
physical constraint and it follows from LC-1 being unmodified.

## Anchored platform facts

| Fact | Source |
|---|---|
| `wrangler dev` runs the container and Worker locally, with requests routed to the local container; Docker required | `CF-DOCS @ dec26351`, `containers/local-dev.mdx` |
| `max_instances` does **not** apply locally, and local concurrency is machine-bound | same |
| Miniflare emulates R2 with persistence across sessions | `CF-SDK @ c5762872`, `packages/miniflare/README.md` |
| SlateDB targets S3-compatible endpoints as a default feature (`aws = ["object_store/aws"]`) | `SL @ f88be86d`, `slatedb/Cargo.toml` L92-93 |
| SlateDB's own example points at `http://localhost:4566` with `allow_http` | `SL`, `examples/src/s3_compatible.rs` |
| The distribution bundle is server + Console + Loader | `TB`, root `BUILD` L182-188 |
| Console and Loader are one Cargo workspace at `console-3.12.0` | `TCONSOLE @ 0292fddf`, `Cargo.toml` |

R2 speaks the S3 API, so LC-3b reaches R2 in production and MinIO locally through the *same*
`object_store::aws` client, differing only in endpoint. That is the mechanism behind
[ADR-0005](../ADR/0005-local-stack-and-dev-prod-parity.md)'s claim that dev/prod parity for the
storage seam is cheap — while the seam itself is not.

## Build and toolchain

Pinned and digested; see [`native-toolchain.json`](../../evidence/phase-a/native-toolchain.json).

| Input | Value |
|---|---|
| Rust (parity lane) | 1.93.0, from `MODULE.bazel` L34/L49 |
| rustfmt | nightly-2026-04-15, from `MODULE.bazel` L37 |
| C/C++ | 13.3.0 — compiles RocksDB's tree |
| protoc | 32.1 |
| Toolchain digest | `465f338b916e18c039bfc5b5cbc7da8d1ddd405958e821b3ba4db0343f548be7` |

The C++ compiler is pinned for a reason: `librocksdb-sys` builds a large C++ tree, so a
different `c++` or libstdc++ can change behaviour with no Rust change. A U0/U1 equality claim
pinning only Rust would attest to half the build.

## Conformance realisation — what is actually built

```
cargo xtask source-lock            → source-lock/source-lock.json
cargo xtask native-toolchain       → native-toolchain.json
cargo xtask verify-cargo-parity    → 0 unknown BUILD rules over 76 files
cargo xtask catalog-upstream-tests → 258 targets, 4 757 leaf cases
cargo xtask assemble               → typedb-all-linux-x86_64.tar.gz
cargo xtask test-upstream          → coverage report + verdict
```

`assemble` reproduces Bazel's `//:assemble-typedb-all` from source, layout read from root
`BUILD` L85-93/L155-165/L211-219. It is a **semantic** reproduction: tar ordering, timestamps
and permission bits differ, so its digest is not upstream's and must not be compared against
one.

## Physical constraints and open questions

| # | Question | Why it matters |
|---|---|---|
| PA-1 | Container memory/CPU limits vs RocksDB and SlateDB working sets | may bound domain size before any code is written |
| PA-2 | Container cold-start time with SlateDB recovery from R2 | directly realises SF-6; unmeasured |
| PA-3 | Is the container's local disk usable at all, and is it durable across restarts? | decides whether a local WAL tier is even available |
| PA-4 | R2 rate limits and tail latency under commit load | local MinIO will not reproduce these — no L1 evidence may be cited for them |
| PA-5 | Base image for the container | `TB-BASE` is an unresolved class-U node |

PA-3 is the one that most likely feeds back into
[Logical Architecture](03-logical-architecture.md) question 2 (where the WAL lives).

## Honest gaps

* No SlateDB integration exists. LC-3b is a crate in `sources/`, not a wired component.
* No deployment has been attempted; the topology above is intent.
* Cold start, throughput and cost are **unmeasured**. No number in this file should be quoted
  as a performance characteristic, because none has been measured.
