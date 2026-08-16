# Phase A summary — source lock, topology, contract lint

Every claim here points at a generated artifact in this directory or at
`source-lock/source-lock.json`. Nothing is restated from prose.

## What was produced

| Artifact | What it is |
|---|---|
| `source-lock/source-lock.json` | 13 resolved upstream nodes + 7 unresolved, with per-node content digests |
| `docs/evidence/phase-a/doc-lint.json` | digest of all 16 contract documents; patch/gate id audit; schema compilability |
| `docs/evidence/phase-a/contradiction-records.md` | 10 contract/source disagreements with anchors and corrections |
| `docs/evidence/phase-a/native-toolchain.json` | every native build input, digested (the `NATIVE` node) |
| `docs/ADR/0001..0004` | topology, Bazel evidence mode, composite-harness attribution, static-check porting |

## Source graph

`cargo xtask source-lock` resolves each node to a full commit, counts its tracked files, and
computes a content digest independent of git — then folds them into one
`source_graph_digest` that the catalogue is bound to. The command **fails** the lock if any
node is dirty, does not match its declared pin, or is a shallow clone of something that
ships or compiles.

Resolved nodes (alias, role, revision prefix):

| Alias | Role | Revision | Origin |
|---|---|---|---|
| `TB` | ships | `2256711abd53` | typedb/typedb |
| `SL` | ships | `f88be86d17ac` | slatedb/slatedb |
| `TQL` | ships | `7f4cac93fa8e` | typedb/typeql |
| `TPROTO` | ships | `0373c1ae106b` | typedb/typedb-protocol |
| `CF-CTR-SRC` | ships | `78913f0e66b5` | cloudflare/containers |
| `CF-SDK` | compiles | `c576a8271503` | cloudflare/workers-sdk |
| `BH` | proof | `ac5d5733a484` | typedb/typedb-behaviour |
| `TDRIVER` | proof | `f487d9618840` | typedb/typedb-driver |
| `TBD` | proof | `a5c51254088f` | typedb/dependencies |
| `TBDIST` | proof | `ab5bfc90274e` | typedb/bazel-distribution |
| `CF-WORKERD` | proof | `562ac20f7950` | cloudflare/workerd |
| `CF-DOCS` | proof | `dec26351feea` | cloudflare/cloudflare-docs |
| `CF-APISCHEMA` | proof | `2ac8369e9b63` | cloudflare/api-schemas |

Cloudflare's open-source implementations are held locally on purpose. Every platform limit
the design leans on — Durable Object storage semantics, container lifecycle, WebSocket
hibernation — is a claim that must be read out of workerd or the SDK at a known revision,
not recalled.

`TDRIVER` is pinned to `3.12.3`, matching the server pin's own `VERSION` file, per addendum
A17.5. The protocol pin stays at `3.12.0`; these are independently versioned and the
mismatch is intentional.

## Unresolved (class U)

Seven nodes are unresolved and each is recorded against the gate it blocks, in
`sources/UNRESOLVED.md` and in the lock's `unresolved` array. They are not assumed away and
they are not silently deferred:

| Alias | Blocks | Missing |
|---|---|---|
| `TCONSOLE` | G1 | TypeDB Console 3.12.0 linux-x86_64 URL, SHA-256, licence |
| `TLOADER` | G1 | TypeDB Loader 3.12.0 applicability to the selected corpus |
| `TB-BASE` | G0 | OCI digest for `typedb/ubuntu:3.1.0-amd64` and the production base |
| `CF-CTR-PKG` | G0 | npm tarball integrity for `@cloudflare/containers` 0.3.7 |
| `CF-VITEST` | G0 | npm tarball integrity for `@cloudflare/vitest-pool-workers` |
| `CF-WORKERD-PKG` | G0 | workerd runtime version selected by the locked Wrangler stack |
| `CF-ACCOUNT` | G1 | real-account probe context and probe evidence |

`NATIVE` is **closed**. `cargo xtask native-toolchain` resolves and digests every native
input the build invokes — the parity-lane rustc/cargo (1.93.0), the pinned rustfmt
(nightly-2026-04-15), cc/c++ 13.3.0, ld/ar 2.42, CMake 3.28.3, protoc 32.1, pkg-config 1.8.1
— plus the four shared objects the built server links and the 152-certificate TLS root
bundle, under one digest `465f338b916e18c039bfc5b5cbc7da8d1ddd405958e821b3ba4db0343f548be7`
now carried in the catalogue's `rust_toolchain.native_toolchain_digest`.

The C++ toolchain is the reason this matters: `librocksdb-sys` compiles a large C++ tree, so
a different `c++` or libstdc++ can change behaviour without a line of Rust changing. A U0/U1
equality claim that pinned only Rust would be attesting to half the build.

Seven class-U nodes remain, none of them resolvable from inside this environment.

## Contract lint

`cargo xtask doc-lint` digests all 16 contract documents and cross-audits their symbol
usage. Result: **0 findings**.

* 44 patch ids defined in the brief; 30 scheduled by the playbook; every scheduled id is
  defined. The 14 brief-only ids belong to phases beyond the authorised set.
* 15 gate ids in the brief; every gate the playbook references is defined.
* The catalogue schema compiles as a JSON Schema validator and is used to validate the
  generated catalogue on every run, so the two cannot drift apart.

## Contradictions

Ten recorded, in full in `contradiction-records.md`. Four are upstream defects rather than
contract errors — CR-A-06 through CR-A-08 and CR-A-10 — and all four live in the seam between
Bazel's conventions and Cargo's, which is exactly the ground the migration has to cross.

The two that most change work:

* **CR-A-01** — the workspace has **42** members, not the 41 asserted in Appendix G.1 and
  restated in A17.1 and `AGENTS.md`. `cargo metadata` reports 43 packages (42 members plus
  the root `typedb_server_bin`). The other census figures reproduce exactly: 59 `[[test]]`
  and 8 `[[bench]]` targets across 13 manifests.

* **CR-A-02** — `release_validate_deps` is a **test-producing macro**, expanding to two
  Kotlin/JVM Bazel test targets that no Cargo-only reading can see. It is now registered as
  test-producing, catalogued as `BAZEL_MACRO`, and given a semantic port.

## Gate G0 status

Met: source graph locked and digested; topology established with ADRs; contract lint clean;
Bazel/Cargo parity audit reports zero unknown rules over 76 BUILD files.

`NATIVE` is closed (above). Not met: the Mode Q Bazel snapshot that ADR-0002 defers, which
needs a Bazel-capable sacrificial environment this one is not. Tracked as a residual, not
closed and not quietly dropped.
