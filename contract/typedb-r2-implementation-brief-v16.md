# TypeDB on Cloudflare Containers with SlateDB/R2

## Implementation brief v16 — pre-implementation convergence contract, complete source graph, Cloudflare-qualified architecture

**Status:** candidate implementation contract for the **G0–G2 proof programme only**. The TypeDB/SlateDB protocol core from v15 is retained where restated below, but v16 is standalone: no normative rule is inherited merely by reference to an earlier revision. Broad semantic implementation remains prohibited until G0, G1, and G2 are green for one exact source/toolchain/platform lock.

**What v16 changes:** this revision adversarially reconciles v15 against (a) its own appendices and patch map, (b) the exact TypeDB `MODULE.bazel` dependency graph at the selected commit, and (c) current Cloudflare contracts for R2 Bucket Locks, temporary credentials, R2 checksums/consistency, Durable Object concurrency/alarms/limits, and Container lifecycle/rollouts. It closes the remaining design ambiguity around repository authority, Cloudflare component ownership, delete capability, multipart identity, rollout compatibility, and production feature selection.

**V15 defects corrected here:**

1. The mandatory `typedb-behaviour` repository is present in the normative source graph rather than being announced only in an appendix.
2. The two duplicate `Appendix F` sections are assigned distinct identities and scopes.
3. The claimed `11/11` re-verification count is removed; only machine-generated evidence may establish a count.
4. The “moonrepo is the source of truth” rule is removed. Cargo remains Rust authority; pnpm/Wrangler remains control-plane authority; any cross-language task runner is replaceable orchestration.
5. TypeDB and SlateDB remain independent upstream-shaped Cargo workspaces rather than being flattened into one root workspace.
6. The source lock includes proof-critical TypeDB repositories, artifacts, base images, toolchains, and Cloudflare runtime packages—not only the two main Rust repositories.
7. The implementation playbook is remapped to the actual `TB-P*`, `SL-P*`, `BT-P*`, `CT-P*`, and `DP-P*` series.
8. A dedicated `DatabaseContainerDO` owns Cloudflare Container lifecycle; `DatabaseControllerDO` remains the database authority. Their state, deployment, and failure domains are distinct.
9. V1 is HTTP-only. Non-HTTP native TypeDB ingress is outside the release profile because current end-user Container ingress is HTTP-mediated.
10. R2 Bucket Locks are used as defence in depth for immutable namespaces, while explicitly not being treated as an unremovable malicious-administrator WORM guarantee.
11. Runtime principals receive no delete-capable R2 credential before G13. Broad `object-read-write` temporary credentials are prohibited because that scope includes delete operations.
12. Multipart part identity is immutable: changing bytes for a part number requires a new upload identity.
13. Durable Object authoritative procedures contain no uncontrolled network await between final validation and SQLite commit; alarms are merely at-least-once wakeups.
14. Container rollouts are assumed mixed-version and non-transactional. Readiness is bound to an explicit deployment compatibility envelope.
15. The production SlateDB feature set is explicit and minimal; `compaction_filters`, provider features not used in production, and `--all-features` release builds are prohibited.
16. The Rust toolchain has an upstream-parity lane and a separately approved security/toolchain-qualification lane.

**Primary objective:** preserve the selected TypeDB/TypeQL semantics while making compute disposable and durable state remote, with a machine-auditable proof chain from pinned source, through Cargo-native upstream conformance, through distributed protocol models, to real-account Cloudflare probes.

**Normative language:** `MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` use RFC 2119 meanings.

### Evidence classes

- **I — inspected source fact:** exact repository/artifact, immutable revision, path/symbol/range, resolved configuration, and callers.
- **R — reconciled design resolution:** a locked conclusion based on inspected facts, still requiring composed executable proof.
- **D — design decision:** behavior introduced by this architecture.
- **P — platform contract/probe:** exact documentation revision plus real-account reproduction.
- **E — executable evidence:** model trace, test, failpoint, chaos run, restore drill, build attestation, or release artifact.
- **U — unresolved source/platform item:** explicitly blocks the dependent gate. `U` is never silently converted to `D`.

A local source fact does not prove a distributed composition. A current documentation statement does not replace a real-account probe where ambiguity can affect correctness. A green test command does not prove that the intended denominator was discovered.

## 0. Executive decision

The architecture remains viable **in principle**, but implementation authority is now divided into explicit planes:

1. **TypeDB transaction plane.** The external durability log is authoritative transaction-intent history. The outcome is the pinned deterministic resolver result over an immutable basis. A `CommitRecord`, `StatusRecord`, controller event, or SlateDB manifest alone is never commit authority.
2. **Materialisation plane.** SlateDB/R2 is replayable physical state. TypeDB's `VisibilityWatermark` hides partial cross-keyspace application.
3. **Database control plane.** One `DatabaseControllerDO` per `DatabaseId` serialises generation, controller incarnation, sessions, logical/physical epochs, WAL finalisation, command state, checkpoint state, pins, indexes, and lifecycle authority.
4. **Container lifecycle plane.** One separate `DatabaseContainerDO` per provisioned container identity subclasses or wraps the Cloudflare Container helper and owns start/stop/status/port proxying only. It cannot allocate TypeSequence, AppendLsn, ControlSeq, epochs, command outcome, checkpoint activation, pin release, or delete authority.
5. **Object data plane.** R2 objects are immutable by protocol. Fine-grained capabilities, exact object identities, application hashes, bucket separation, and Bucket Locks compose defence in depth.
6. **Recovery plane.** Total controller-namespace loss remains an offline administrative recovery under an independent lock and anti-rollback anchor; R2 is not leader election.
7. **Build/proof plane.** TypeDB and SlateDB retain upstream-shaped Cargo workspaces. Cargo is Rust build authority, pnpm/Wrangler is Workers authority, and a thin repository-level coordinator may invoke them without becoming semantic authority.

### 0.1 Binding protocol decisions retained

The following are unchanged and remain non-negotiable:

- one active TypeDB writer per logical generation;
- RocksDB as the semantic oracle behind a TypeDB-owned safe backend boundary;
- `AppendLsn` as unique physical WAL order, distinct from `TypeSequence`;
- late atomic allocation of sequenced `TypeSequence`, `AppendLsn`, and `ControlSeq`;
- one durability sequencer for sequenced, unsequenced, and sync operations;
- physical sync barriers and finite iterator snapshots;
- fallible durability, no environmental panic or indefinite wait;
- singleton transaction status keys with conflict-as-corruption;
- one shared pure transaction resolver for live, recovery, and scratch modes;
- explicit intent, resolution, physical apply, visibility, and returnable outcome states;
- exact command result binding before intent where application bytes are required;
- permanent database-scoped `CommandId` non-reuse;
- exact archived indexes for absence proofs;
- externally supplied SlateDB publication epochs at every reachability mutation;
- no unfenced active `Admin` mutation;
- fully quiesced V1 checkpoints with fresh-process verification;
- new materialisation for rebuild and new generation for historical restore;
- no physical WAL deletion in V1;
- report-only GC before G13;
- independently anchored controller history;
- Cargo-native accounting for the complete applicable upstream test corpus.

### 0.2 New v16 implementation decisions

1. **Federated workspaces.** `fork/typedb`, `fork/slatedb`, and `tools` each retain their own Cargo workspace and lockfile. A generated `workspace-lock.json` binds their commits, lockfile digests, feature sets, toolchains, fixtures, and package digests.
2. **Replaceable orchestration.** Normative commands are `cargo xtask ...`, `pnpm ...`, and pinned `wrangler ...`. A task runner may call those commands but is not required to interpret correctness, discover tests, generate manifests, or define the release.
3. **Complete source graph.** Proof-critical TypeDB external repositories and artifacts referenced by the selected snapshot are first-class lock nodes. A source bump is atomic across this graph.
4. **Two Rust lanes.**
   - **Parity lane:** Rust `1.93.0`, the version declared by the selected TypeDB source graph.
   - **Qualification lane:** the approved current patched stable toolchain, initially `1.97.1`, after compiler-delta and full-corpus qualification.
   Production cannot silently move between lanes.
5. **Minimal SlateDB features.** Candidate production features are `aws`, `wal_disable`, and `foyer`, with `default-features = false`; any compression feature is individually justified. `compaction_filters`, `all`, test-only features, and unused providers are prohibited.
6. **Separate DO classes.** Database authority never subclasses the Container helper. Container lifecycle resets, alarms, or rollouts cannot mutate transaction authority except through authenticated idempotent reports accepted by the controller.
7. **HTTP-only V1 ingress.** The mandatory production API is the BioAxiom/TypeDB HTTP facade. Native TypeDB gRPC/TCP is a future architecture profile, not a V1 gate.
8. **Mixed-version rollouts.** Every Worker↔container exchange carries a `DeploymentCompatibilityEnvelope`; the controller admits readiness only for an explicitly supported tuple.
9. **Authoritative DO transaction discipline.** External object/network work happens before an idempotent finalisation transaction or after it through a durable outbox. No authoritative procedure validates state, awaits arbitrary network I/O, then commits on the assumption that no request interleaved.
10. **Alarm discipline.** Alarms only wake an idempotent reducer/outbox worker. `next_due_at` and attempt state are durable; the handler catches, classifies, and reschedules rather than relying on the platform's finite automatic retry sequence.
11. **Delete-free runtime credentials.** Pre-G13 runtime principals receive exact `PutObject`, multipart, read, or copy actions only. Presets that include `DeleteObject`/`DeleteObjects` are prohibited.
12. **Bucket topology and locks.** Authority, active materialisation, scratch/orphanable, administrative backup, and test data use separate buckets or administrative domains. Immutable authority prefixes receive coarse Bucket Locks verified continuously.
13. **Canonical object identity.** Application SHA-256 over exact bytes remains identity. Provider ETags and composite multipart SHA-256 are observations, not interchangeable identities.
14. **Multipart attempt identity.** `(upload_id, part_number)` binds one digest and length. Different bytes allocate a new `UploadAttemptId`; they never overwrite the same part.
15. **No broad implementation before G2.** Prior to G2, permitted code is source/bootstrap evidence, Cargo corpus tooling, pure models, real-platform probes, and narrow oracle-preserving refactors.

### 0.3 Architecture stop conditions

The dependent milestone stops when any of the following cannot be proved:

- exact TypeDB WAL and resolver semantics can be preserved through fallible remote interfaces;
- every validation input belongs to one finite immutable basis;
- status deduplication preserves all oracle outcomes;
- every ordinary read is visibility-capped and every raw read is lifecycle-gated;
- every SlateDB reachability mutation is externally epoch-fenced;
- scratch replay performs no authoritative write;
- R2 conditional, checksum, multipart, consistency, credential, Bucket Lock, and ambiguous-result behavior satisfies the selected object-class protocol;
- runtime credentials can exclude delete independently of application convention;
- controller SQL state and exact lookup remain bounded far below platform limits;
- controller procedures remain correct under Durable Object request interleaving;
- alarm loss/retry/restart cannot strand required work indefinitely;
- Container lifecycle DO resets or mixed rollouts cannot grant or preserve stale database authority;
- the HTTP facade carries the required application semantics without unbounded buffering;
- checkpoint quiescence/digest duration meets the accepted availability envelope;
- full restore and WAL replay meet the declared RTO while V1 retains history indefinitely;
- aggregate TypeDB plus all SlateDB keyspaces fit the 4-vCPU/12-GiB/20-GB container envelope with approved headroom;
- the complete applicable upstream corpus is machine-enumerated with zero unknown macro, fixture, case, feature, or platform predicate;
- the Cargo-built server tested by assembly/behaviour/crash suites is byte-identical to the image payload;
- the fork, source graph, test porting, and licence obligations are maintainable;
- the production release can be reconstructed from offline, content-verified dependencies and exact Cloudflare package/runtime locks.

## 1. Source lock, evidence, and reproducibility

### 1.1 Normative source graph

The release lock is a graph, not a three-row list. Every node records immutable identity, retrieval method, licence, purpose, transitive inputs used by that purpose, and whether it ships, compiles, or serves only as proof evidence.

#### Core code and semantic oracle

| Alias | Source | Selected identity | Role |
|---|---|---|---|
| `TB` | `typedb/typedb` | commit `2256711abd532742dae8e822a9ad5cce63e69b1a` | soft-fork source and RocksDB/file-WAL oracle |
| `SL` | `slatedb/slatedb` | commit `f88be86d17ac53260d3684edbc8f82811d945b5c` | candidate object-store engine, version `0.15.0` |
| `BH` | `typedb/typedb-behaviour` | commit `ac5d5733a484cea1d8809a2968029a818fdae24f` | authoritative Cucumber feature corpus |

The TypeDB source commit is the implementation identity even when it is adjacent to a numbered release. Release tags, image tags, and package versions are provenance metadata; they never replace the full commit.

#### Proof-critical TypeDB graph imported from the selected `MODULE.bazel`

| Alias | Source | Selected identity | Required use |
|---|---|---|---|
| `TBD` | `typedb/dependencies` | `a5c51254088f343fb8b6a9668eaf99b35503dad4` | reconstruct generated Cargo/build metadata and artifact rules |
| `TBDIST` | `typedb/bazel-distribution` | `ab5bfc90274e2d34569d5bc22558314b551cdecd` | static target/macro/query audit oracle |
| `TQL` | `typedb/typeql` | tag `3.12.2`, resolved to a full commit and tree digest at G0 | TypeQL source/dependency identity |
| `TPROTO` | `typedb/typedb-protocol` | tag `3.12.0`, resolved to a full commit and tree digest at G0 | protocol source identity |
| `TCONSOLE` | TypeDB Console Linux x86-64 artifact | version `3.12.0`, exact URL/SHA-256/licence unresolved until G0 | assembly/behaviour fixture |
| `TLOADER` | TypeDB Loader Linux x86-64 artifact | version `3.12.0`, exact URL/SHA-256/licence unresolved until G0 | only if an applicable upstream target requires it |
| `TB-BASE` | `typedb/ubuntu:3.1.0-amd64` | registry digest resolved and mirrored at G0 | upstream package provenance, not necessarily the production base |
| `RUST-PARITY` | Rust toolchain | `1.93.0`, edition 2024; rustfmt `nightly/2026-04-15` | exact upstream-parity lane |

The private macOS signing artifact referenced by upstream is catalogued as platform-inapplicable for Linux and never retrieved into ordinary CI. Its declaration remains visible so the denominator does not silently forget it.

#### Cloudflare shipping and test graph

| Alias | Source/package | Candidate identity | Rule |
|---|---|---|---|
| `CF-CTR-SRC` | `cloudflare/containers` | source revision corresponding exactly to `@cloudflare/containers` package lock | required when the helper is used |
| `CF-CTR-PKG` | `@cloudflare/containers` | candidate `0.3.7`, package tarball integrity locked | container-lifecycle DO only |
| `CF-SDK` | `cloudflare/workers-sdk` | candidate release commit `c576a82…` / Wrangler `4.123.0` | resolve to full commit and pnpm integrity |
| `CF-VITEST` | `@cloudflare/vitest-pool-workers` | candidate `0.21.3` | local controller/gateway tests |
| `CF-MINIFLARE` | `miniflare` | candidate `5.20260811.1-alpha` only if the selected test pool requires it | never substitutes for real-account proof |
| `CF-WORKERD` | `workerd` | exact runtime version transitively selected by the locked Wrangler/test stack | local runtime compatibility evidence |
| `CF-DOCS` | official Cloudflare contract pages | URL, retrieved bytes/digest, retrieval time, product status, account profile | platform contract lock |
| `CF-ACCOUNT` | production/staging account configuration | account ID alias, plan, enabled products/betas, region/jurisdiction settings, bucket IDs, class migrations, compatibility date | real-account probe context |

The exact package set is generated from `pnpm-lock.yaml`; prose versions are candidates, not the release lock.

#### Native build and production-image inputs

The lock also contains the production base image by digest, C/C++ compiler, linker, CMake, `protoc`, `pkg-config`, libc, OpenSSL/TLS roots, Node, pnpm, Python only where a proof task needs it, and every downloaded fixture. No `latest` tag, floating channel, implicit host tool, or remote build script is allowed.

### 1.2 Platform contract record

```text
PlatformContractRecord {
  contract_id,
  product,
  exact_url,
  retrieved_at_utc,
  content_sha256,
  last_updated_as_reported,
  compatibility_date?,
  account_profile_digest,
  sdk_package_lock_digest,
  source_revision?,
  exact_claims,
  known_non_guarantees,
  required_real_account_probes,
  dependent_invariants,
  dependent_gates
}
```

A documentation update does not silently change the release. The contract lock is reviewed and probes are rerun before a platform-contract bump.

### 1.3 Source evidence record

```text
EvidenceRecord {
  evidence_id,
  class,                         // I | R | D | P | E | U
  source_node,
  immutable_identity,
  path_or_artifact,
  symbol_or_member?,
  line_or_byte_range?,
  resolved_features,
  resolved_configuration,
  caller_graph_summary,
  applicable_tests,
  exact_claim,
  counterexamples_checked,
  architectural_consequence,
  gate,
  artifact_digest
}
```

Line anchors alone are insufficient where behavior depends on feature flags, callers, package build scripts, generated files, or account configuration.

### 1.4 G0 reproduction

G0 begins from clean immutable copies and produces:

- full source-graph lock and tree hashes;
- `git fsck`/archive integrity evidence;
- licences and notices;
- each independent Cargo workspace metadata and lockfile digest;
- pnpm lock and package tarball integrity;
- native toolchain and base-image digests;
- TypeDB Cargo/BUILD/Starlark inventories;
- all direct RocksDB types/calls and unsafe storage lifetimes;
- all durability callers, record types, panic/error assumptions, and background appenders;
- every raw-storage caller;
- every SlateDB publication, Admin, checkpoint, clone, compaction, retry, and delete path;
- exact resolved SlateDB feature sets for production and tests;
- every upstream test target, unit case, Cucumber scenario, failpoint context, script phase, static check, fixture, environment, platform predicate, feature/cfg set, timeout, and process-isolation requirement;
- Cloudflare source/package/docs contract matrix;
- reproducible offline builds and package identity evidence.

The reported `59` explicit test targets and `8` benches in v15 are a reconnaissance floor only. They are not a release denominator until emitted by the versioned catalogue generator from the complete source graph.

### 1.5 Cargo/Bazel audit boundary

Bazel is absent from ordinary development, CI, packaging, and release. One of two mutually exclusive G0 evidence modes is recorded:

- **Mode Q — isolated query oracle:** a disposable, non-release environment executes exact-source-lock `bazel query/cquery` only to produce signed target/configuration snapshots. It builds no shipping artifact and its outputs are treated as audit evidence.
- **Mode S — strict static proof:** every relevant macro and external repository declaration is parsed/expanded by fork-owned tooling with zero unknown target.

The release cannot claim both “Bazel is never executed anywhere” and rely on a one-time Bazel query. The chosen mode is explicit.

### 1.6 Toolchain policy

- **Parity lane:** exact TypeDB-declared Rust `1.93.0`; establishes source and test parity.
- **Qualification lane:** current approved stable toolchain, initially `1.97.1`, used only after all U0/U1 corpus, ABI/package, sanitiser, and differential gates pass.
- A compiler upgrade is a release input change with its own evidence. Security fixes are not ignored merely to preserve historical parity; instead the two lanes expose the delta.
- Release provenance records which lane produced the image. Mixing objects from two toolchains is prohibited.

### 1.7 Durable source bytes

TypeDB WAL payloads remain the exact opaque bytes produced by the selected serializer. Identity never depends on reserialising an old record under a newer binary. Every payload is bound to source lock, record registry, serializer format, and original byte digest.

## 2. Scope and service profile

### 2.1 V1 goals

1. Preserve supported pinned TypeDB/TypeQL semantics through differential tests.
2. Remove correctness dependence on container-local persistence.
3. Maintain one externally fenced writer per generation.
4. Recover after arbitrary process death at every persistence boundary.
5. Reconstruct controller state from authenticated immutable history under an external recovery lock and anti-rollback anchor.
6. Produce global checkpoints representing one exact TypeDB visibility cut.
7. Provide effectively-once observable outcomes for a bounded command API.
8. Keep native TypeDB retry ambiguity explicit.
9. Restore without overwriting active history.
10. Bound every queue, cursor, object, result, retry, table tail, background job, and recovery scan.
11. Keep patches narrow, bisectable, source-mapped, and oracle-tested.
12. Produce reproducible builds, SBOMs, schemas, vectors, model traces, and gate evidence.
13. Build, test, and package the fork without executing Bazel.
14. Execute and account for 100% of the applicable pinned upstream TypeDB test corpus on the required backend profiles.
15. Preserve a machine-auditable mapping from upstream test declarations and source cases to Cargo executions and archived results.

### 2.2 V1 deployment profile

V1 is **P-SINGLE**:

- one logical database generation is actively written by one container;
- one process contains all TypeDB keyspaces;
- no pooled placement reducer;
- no independent read-replica protocol;
- no transparent keyspace sharding;
- HTTP/BioAxiom facade is the mandatory deployable transport; native TypeDB transport is outside V1 and requires a future ADR/profile.

### 2.3 Non-goals

V1 does not provide multi-writer operation, cross-database transactions, native-driver exactly-once retries, online checkpointing, in-place rollback, WAL branching, transparent per-keyspace sharding, automatic controller failover after namespace loss, arbitrary post-crash result reconstruction, or physical object deletion before G13.

---

## 3. Failure, threat, and promise model

### 3.1 Safety-preserving failures

The protocol assumes process death, OOM, disk loss, duplicate containers, delayed zombie execution, DO restart, network timeout before or after commit, duplicated/reordered responses, R2 throttling or ambiguous conditional results, partial multipart work, stale publication attempts, verifier/checkpoint/backup crashes, mixed supported binaries, malformed objects, active-materialisation corruption, and old-generation traffic.

Safety means:

- no acknowledged commit or command outcome is lost;
- no unresolved/aborted intent is reported committed;
- no command executes again after a durable intent binding;
- no stale actor publishes authoritative metadata;
- no reader sees a partial cross-keyspace apply;
- no read turns a storage failure into successful truncation/EOF;
- no pinned or otherwise reachable object is deleted;
- no unverifiable or rollbacked history is selected automatically.

### 3.2 Fail-closed conditions

The database may become unavailable on an unresolved append, unresolved intent, status conflict, validation-version mismatch, controller/R2 outage past deadline, outbox lag, epoch uncertainty, raw-read lifecycle violation, checkpoint verification failure, unknown mandatory format, authentication failure, counter/storage exhaustion, or inability to prove the exact iterator/no-intent snapshot.

### 3.3 Security boundary

Trusted computing base: approved source/build, edge/controller/gateway code, key service, deployment configuration, recovery coordinator, and approved operators. Untrusted: clients, network responses, object listings/timestamps/ETags as sole proof, local container state, advisory routing/readiness state, and stale actors.

A compromised currently authoritative controller remains capable of violating online safety. V16 reduces that blast radius with least privilege, signed capabilities, independent recovery anchors, and controller-incarnation rotation; it does not claim Byzantine tolerance.

### 3.4 Acknowledged promises

A promise is classified explicitly:

```text
PromiseClass {
  WAL_PREFIX_DURABLE,
  TRANSACTION_RESOLVED,
  TRANSACTION_VISIBLE,
  COMMAND_OUTCOME_DURABLE,
  CHECKPOINT_ACTIVE,
  BACKUP_VERIFIED,
  MATERIALIZATION_ACTIVE
}
```

Each class names the exact barrier it waits for. “Committed”, “durable”, “applied”, “materialised”, and “returnable” are never used interchangeably.

---

## 4. Architecture, authority, identities, and frontiers

### 4.1 Components and failure domains

1. **Edge/API Worker**
   - authenticates user/agent principals;
   - validates request, generation, limits, and deployment compatibility;
   - calls the database controller through a service binding/RPC;
   - never treats a container HTTP response as commit authority.

2. **`DatabaseControllerDO` — one per `DatabaseId`**
   - database online linearisation point;
   - owns generation, controller incarnation, authoritative lifecycle, startup reservations, logical and physical epochs, WAL finalisation, command state, checkpoints, materialisations, pins, exact indexes, and admission budgets;
   - uses SQLite and an authenticated R2 outbox;
   - does **not** extend the Cloudflare `Container` class;
   - never starts/stops a container directly except by idempotent RPC to the lifecycle DO;
   - never receives bulk object bodies.

3. **`DatabaseContainerDO` — one per `ContainerIdentity`**
   - the only component that extends/wraps `@cloudflare/containers`;
   - owns platform start/stop/destroy/status hooks, `sleepAfter`, port readiness, HTTP proxying, labels, and rollout-image observations;
   - persists only lifecycle observations and idempotency needed to manage that container instance;
   - reports platform facts to the database controller under a signed request;
   - cannot allocate or validate transaction authority.

4. **TypeDB container process**
   - selected TypeDB/SlateDB fork;
   - one active database generation and all TypeDB keyspaces;
   - process-local bounded storage runtime;
   - disposable RAM and disk;
   - serves the internal HTTP facade;
   - acts only under an activated startup session and exact epochs.

5. **Object data path**
   - exact presigned operation, narrowly scoped temporary credential, or streaming gateway selected per object class;
   - emits application-verifiable evidence;
   - has no sequence, epoch, command, activation, pin-release, or delete authority.

6. **R2 buckets**
   - authority/journal/WAL;
   - active materialisations;
   - scratch/orphanable builds;
   - account-isolated backup;
   - test/chaos.
   These are distinct administrative and credential domains where feasible.

7. **Verifier and maintenance workers**
   - use attempt-scoped capabilities and scratch materialisations;
   - cannot append authoritative WAL, activate themselves, mutate routing, release pins, or delete.

8. **Offline recovery coordinator**
   - independent administrative identity, lock, anchor store, key rotation, and approval workflow;
   - not part of online leader election.

### 4.2 Authority hierarchy

```text
DatabaseControllerDO SQLite transaction
  > contiguous authenticated control journal + independent RecoveryAnchor
  > immutable WAL/result/checkpoint/index/ledger roots
  > active SlateDB manifests/SSTs as replayable materialisation
  > DatabaseContainerDO lifecycle observations
  > TypeDB container RAM/disk and route/readiness caches
```

The `DatabaseContainerDO` is deliberately below immutable database history. Its reset, code update, alarm retry, or stale platform status cannot create transaction authority.

### 4.3 Deployment compatibility envelope

```text
DeploymentCompatibilityEnvelopeV1 {
  deployment_id,
  controller_worker_version,
  controller_schema_version,
  container_helper_package_version,
  container_image_digest,
  server_binary_digest,
  source_lock_digest,
  config_digest,
  protocol_min,
  protocol_max,
  durable_format_reader_set,
  durable_format_writer_set,
  cloudflare_compatibility_date,
  required_account_features,
  expiry_or_release_id
}
```

A startup reservation names one exact envelope. During a rollout, the Worker may communicate with both old and new images; each side negotiates and refuses unsupported tuples. A deployment is not considered complete merely because `wrangler deploy` returned success.

### 4.4 Typed identities

Every identifier is a distinct newtype and durable schema field:

| Type | Meaning |
|---|---|
| `DatabaseId` | stable logical database identity; never reused |
| `DatabaseGeneration` | logical history generation; restore creates a new value |
| `MaterializationId` | physical SlateDB incarnation in one generation |
| `ControllerIncarnationId` | database-controller authority incarnation |
| `DeploymentId` | one release/deployment compatibility identity |
| `ContainerIdentity` | stable address of one container lifecycle DO |
| `ContainerProcessNonce` | one concrete process start inside a container identity |
| `StartupSessionId` | one database-authorized writer session |
| `AppendLsn` | unique physical WAL order within a generation |
| `TypeSequence` | TypeDB durability/MVCC sequence; guarded `u64` |
| `ControlSeq` | database-global control-event order |
| `VisibilityWatermark` | highest contiguous resolved-and-visible TypeSequence |
| `WriterEpoch` | logical active-writer authority |
| `CompactorEpoch` | logical active-compactor authority |
| `BuildEpoch` | scratch attempt authority, never WAL authority |
| `SlateWriterEpoch` | physical SlateDB writer epoch for one materialisation |
| `SlateCompactorEpoch` | physical SlateDB compactor epoch |
| `SegmentCatalogVersion` | immutable index-catalogue identity |
| `IteratorSnapshotId` | fixed finite durability-iteration identity |
| `CommandId` | permanent database-scoped idempotency identity |
| `CommandExecutionEpoch` | monotonic execution generation for one command |
| `AttemptId`, `UploadAttemptId` | execution/maintenance and multipart attempts |
| `CheckpointId`, `BackupId`, `PinId` | workflow identities |

Authoritative 64-bit values never cross JavaScript as `number`. Counters never wrap and fail closed before sentinel/exhaustion boundaries.

### 4.5 Physical WAL barrier

```text
DurabilityBarrier {
  database_id,
  generation,
  through_append_lsn,
  through_control_seq,
  wal_head_digest,
  controller_incarnation_id,
  format_version
}
```

A barrier proves an exact physical WAL/control prefix, not a `TypeSequence` alone.

### 4.6 Fixed iterator snapshot

```text
DurabilityIteratorSnapshot {
  iterator_snapshot_id,
  database_id,
  generation,
  start_type_sequence,
  through_append_lsn,
  through_control_seq,
  head_record_digest,
  segment_catalog_version,
  active_tail_start_lsn,
  source_lock_digest,
  retention_lease_id,
  explicit_operation_deadline?,
  format_version
}
```

It is captured atomically against the activated catalogue and tail. Later appends are invisible. Missing data, catalogue mismatch, invalid pin, or deadline is an error, never EOF.

### 4.7 Public bookmark

```text
CommitBookmark {
  database_id,
  generation,
  commit_append_lsn,
  type_sequence,
  commit_record_digest,
  format_version
}
```

Bookmarks compare only within one generation.

### 4.8 Checkpoint cut

```text
CheckpointCut {
  database_id,
  generation,
  materialization_id,
  visibility_watermark,
  last_applied_commit_lsn?,
  wal_cut_lsn,
  control_cut_seq,
  writer_epoch,
  compactor_epoch,
  source_lock_digest,
  config_digest,
  format_version
}
```

### 4.9 Historical restore sequence rule

```text
new_generation.next_type_sequence = restored_visibility_watermark + 1
new_generation.next_append_lsn     = GENESIS_APPEND_LSN
new_generation.control lineage     = GenerationRestored(...)
```

A non-empty restored database never resets TypeSequence to one unless a separately proved logical export/rewrite re-encodes all MVCC keys.

## 5. Non-negotiable invariants

Every invariant has one model owner, one implementation owner, one gate, one test/failpoint set, one zero-budget metric where observable, and one documented failure state.

### 5.1 Evidence, identity, and immutable history

1. No normative requirement is inherited from an earlier revision.
2. No source-dependent claim lacks an evidence class and evidence record.
3. A `RecordId = (DatabaseId, DatabaseGeneration, AppendLsn)` maps to exactly one descriptor digest.
4. A payload digest maps to exactly one byte string and length within its namespace.
5. AppendLsn values are contiguous from generation genesis.
6. Every non-genesis descriptor names the previous descriptor digest.
7. A sequenced record has one unique TypeSequence within its generation.
8. Unsequenced records may repeat the current previous TypeSequence and are distinguished by AppendLsn.
9. TypeSequence is never used alone as physical identity, sync barrier, iterator head, or public cross-generation identity.
10. One generation has one WAL lineage in V1.
11. A materialisation belongs to one generation and one namespace.
12. Self hashes/signatures are excluded from their own canonical input; every other authoritative field is included.
13. Duplicate control positions or descriptor positions with competing valid bodies quarantine the database.
14. Exact original WAL payload bytes are retained; old bytes are never reconstructed by a newer serializer.
15. A historical restore preserves TypeSequence continuity unless a full logical rewrite protocol is separately proven.

### 5.2 Controller, sessions, and publication fencing

16. Every authoritative request carries database, generation, controller incarnation, actor/session or attempt, operation ID, request digest, deadline, and exact authority fields.
17. Every WAL finalisation revalidates current generation, controller incarnation, session, holder, lease, writer epoch, and lifecycle inside the committing SQLite transaction.
18. Every active SlateDB writer publication uses the exact controller-issued WriterEpoch through SL-P1.
19. Every active compactor publication uses a distinct controller-issued CompactorEpoch.
20. `BuildEpoch` is a role/attempt authority, not a third SlateDB epoch field: every scratch publication also carries exact `SlateWriterEpoch` and, when compaction runs, `SlateCompactorEpoch` values allocated from the same per-materialisation physical domains later used by active roles.
21. Before a scratch materialisation can become active, the builder is frozen, strictly higher physical writer/compactor epochs are claimed and attested by a prepared active holder, a resumed stale builder is proven fenced, and only then may controller activation grant WAL/routing authority; epoch advancement/revocation always precedes replacement authority.
22. Lease expiry is not the final publication fence; epochs and controller transaction checks are.
23. After fencing, stale data bytes may become orphans but no stale metadata may become reachable.
24. No active-namespace manifest/checkpoint mutation may use unfenced `StoredManifest`/`SimpleTransactionalObject` paths.
25. SlateDB `Admin` mutators are absent from the production active-namespace build unless wrapped by a proven fenced protocol.
26. An ambiguous exact-epoch open is not retried under the same session; the session is abandoned and a strictly newer epoch is issued.
27. Controller-incarnation rotation revokes old authoritative data-path and journal-signing capabilities before new routing is enabled.
28. Routing, readiness, placement, and metrics never grant authority.

### 5.3 Append, status, sync, and iteration

29. Sequenced writes, unsequenced writes, and sync markers pass through one bounded durability sequencer per active session.
30. No later append or sync overtakes an unresolved finalisation.
31. Failed pre-finalisation upload consumes neither TypeSequence nor AppendLsn.
32. Sequenced finalisation allocates TypeSequence, AppendLsn, and its ControlSeq atomically.
33. Unsequenced finalisation copies the current previous TypeSequence and allocates only AppendLsn/ControlSeq.
34. A finalisation operation ID is immutable to one canonical request/descriptor digest.
35. Lost finalisation responses are resolved by operation ID; no fresh identity is allocated.
36. `request_sync` captures the physical head after every earlier sequencer operation has resolved.
37. A sync success proves all payloads, descriptors, and required control events through its barrier.
38. Fencing after finalisation cannot revoke the durability truth of the record; it can prevent the old holder from applying or reporting it.
39. Sync never panics, blocks without a deadline, or reports a partial prefix as success.
40. `current()` and `previous()` are local session state initialized by a fallible open handshake and updated only after resolved finalisation.
41. Every remote durability iterator is bound to a fixed finite `DurabilityIteratorSnapshot`.
42. New appends are invisible to an existing iterator.
43. Missing data, catalogue drift, invalid retention lease, or explicit deadline expiry is an error, never EOF; authoritative recovery iterators do not expire merely because a controller TTL elapsed.
44. Activated index segments plus the active SQLite tail form one exact contiguous descriptor history with no gap or overlap.
45. Exact lookup catalogues exist for finalisation operation ID, command attempt binding, target status key, source snapshot ID, permanent CommandId, TypeSequence, and record type; lookup cost is bounded independently of the number of archived physical segments.
46. Probabilistic indexes may accelerate positive lookup or shard routing but never prove absence; a full canonical key comparison is required.
47. V1 archives controller rows but does not physically delete WAL descriptor/payload history.

### 5.4 Status cache and deterministic resolution

48. A durable CommitRecord is replayable transaction intent, not a commit verdict.
49. For each target commit sequence, at most one logical status verdict exists.
50. Retrying the same status key and verdict returns the original physical record; it does not append another record.
51. The same status key with the opposite verdict is fatal corruption.
52. Status records are memoised resolver certificates; absence is recoverable by deterministic resolution.
53. Status records never override a different result produced by the pinned resolver; a mismatch fails closed.
54. Live validation, authoritative recovery, and scratch replay call the same resolver library.
55. The resolver reads one fixed WAL iterator snapshot and an exact checkpoint/isolation base.
56. The resolver never depends on wall clock, random IDs, thread schedule, mutable statistics, object listing order, or current unrelated configuration.
57. A resolver-version change cannot overlap transaction resolution in V1; upgrades drain unresolved intents and replace the validator.
58. Controller `TransactionResolved` events are immutable memoised certificates. If missing, resolution can be recomputed; if conflicting, recovery quarantines.
59. A validation or transport error is not an abort verdict; the intent remains unresolved and is retried or fails closed.

### 5.5 Apply, visibility, and reads

60. A positive resolution is not returnable success until every keyspace batch is applied and VisibilityWatermark covers the sequence.
61. Per-keyspace physical writes may occur one at a time; logical visibility belongs to TypeDB's watermark.
62. VisibilityWatermark advances only across a contiguous sequence of applied commits or aborts.
63. Recovery idempotently completes every partially applied positive resolution before readiness.
64. A keyspace failure after positive resolution is an unavailable committed transaction, never an abort or permission to re-execute.
65. Ordinary correctness reads are capped by a TypeDB logical snapshot no greater than VisibilityWatermark.
66. No ordinary read path bypasses that cap, including schema, metadata, optimization, and extension reads.
67. Raw backend reads require `RawMaintenanceRead` capability, an inventoried caller, and a lifecycle state proving no unresolved partial apply can affect the result.
68. Raw reads are forbidden during ordinary query serving.
69. Backend read/scan errors fail the entire logical read; they never produce partial success or ordinary EOF.
70. A cursor is bound to database, generation, materialisation, logical snapshot, backend snapshot, range, and finite lifetime.
71. Cursor expiry or materialisation cutover returns an explicit error.
72. Backend estimates/statistics are observational unless separately proven correctness-critical.

### 5.6 SlateDB materialisation

73. SlateDB WAL is disabled; TypeDB's external WAL is the only transaction-intent durability authority.
74. Correctness reads explicitly use the resolved committed/non-dirty memory-visible options; no caller can override them.
75. Immediate same-handle visibility after a successful write is proved before flush.
76. Built-in destructive GC and provider lifecycle deletion are disabled.
77. Automatic TypeDB checkpointing and implicit SlateDB compactor startup are disabled in the remote profile.
78. A compactor starts only under an explicit controller attempt, CompactorEpoch, resource budget, and drain/revoke API.
79. Protective checkpoint creation/pruning is either disabled safely when no internal deletion exists, or handled by a fenced active-writer path; unfenced Admin pruning is forbidden.
80. All manifest, compactions, checkpoint, clone, active-admin, retry, and recovery publication paths are included in the SL-P1/SL-P2 pause-fence-resume matrix.
81. One active materialisation exists per generation.
82. Scratch and active prefixes can never collide.
83. A stale actor may upload orphans but cannot publish reachability metadata.
84. Before G13, no reachable production call path, linked release feature, credential, gateway route, worker binding, or provider lifecycle rule can delete authoritative objects. Mere presence of a generic SDK method or symbol is not used as the proof.

### 5.7 Command outcomes

85. CommandId is database-global and permanently non-reusable for the lifetime of DatabaseId.
86. Same CommandId/same request digest returns stored state or outcome; different digest is permanent conflict.
87. Reservation is journal-durable before approval or assignment.
88. Assignment is journal-durable before execution.
89. A command executes one bounded deterministic TypeDB transaction and contains no external/human/tool wait.
90. `PREPARED_BYTES` are generated during pre-intent transaction execution, uploaded, verified, and bound before CommitRecord finalisation.
91. A canonical receipt contains only immutable identities and resolver/apply outcome.
92. Once a command-bound intent is finalised, no execution epoch for that CommandId may run again.
93. A new execution epoch is permitted only after an exact two-store `NoIntentProof` under a fenced old context.
94. A no-intent proof uses exact archived indexes and atomically rechecks unchanged catalogue/head plus active-tail absence.
95. Arbitrary current-state re-query may not reconstruct historical result bytes.
96. Successful outcome requires positive resolution, complete visibility, exact final envelope, and journal barrier.
97. Result availability expiry does not mutate the terminal outcome and never permits re-execution.
98. External effects use a post-commit idempotent outbox and do not inherit exactly-once guarantees from the database command.

### 5.8 Checkpoint, backup, retention, and recovery

99. V1 checkpoint capture fully quiesces mutation admission, sequencer work, validation/resolution, apply, status/statistics append, automatic checkpointer, compactor publication, and active-manifest maintenance.
100. Every keyspace, extension, visibility frontier, WAL head, control head, and expected digest belongs to one CheckpointCut.
101. No checkpoint activates before isolated scratch restore, exact replay, and independent logical digest verification.
102. A root pin is journal-durable before closure enumeration begins.
103. A releasing pin remains protective until `PinReleased` is journal-durable.
104. Unknown object/format/parser state is retained, never treated as garbage.
105. V1 report-only GC performs no delete and exposes no delete capability.
106. A backup manifest is a closure over pinned immutable roots, not a list inferred from timestamps.
107. A same-provider/account copy is not advertised as independent disaster protection.
108. R2 alone is not WORM; any immutable/offline claim names a separately qualified destination.
109. Catastrophic controller recovery requires an external lock, trusted RecoveryAnchor, controller-incarnation rotation, epoch advancement, fresh materialisation, two-person approval, and stale-old-authority test.
110. Recovery rejects a head below the trusted anchor, any gap, competing position, bad digest/authentication, missing required object, or unknown mandatory format.
111. Live leases, sessions, TTLs, connections, alarms, and routing caches are never restored from control snapshots.
112. Every acknowledged promise can be answered from machine state without reading informal logs.

### 5.9 Formats, boundedness, and software quality

113. Every durable format has a version, deterministic encoder, parser limits, compatibility matrix, golden/negative/fuzz vectors, and root-closure parser where applicable.
114. Unknown mandatory semantics fail closed.
115. Writers do not emit a new mandatory format before every supported reader/verifier/recovery tool can parse it.
116. Every queue, transaction, upload, iterator, cursor, result, retry, table tail, background task, and maintenance attempt has enforced row/byte/time/concurrency bounds.
117. No authoritative success depends only on local state, unjournaled SQLite, an ETag, a listing, or a timestamp.
118. Correctness-affecting configuration is typed, explicit, hashed, attested, and free of silent library defaults.
119. Environmental failures do not panic; they produce typed errors or explicit database fail-closed state.
120. Any invariant violation increments a zero-budget metric and transitions the affected database according to the generated reducer.

### 5.10 Cargo-only build and upstream-test conformance

121. Cargo/rustc/libtest/rustdoc plus fork-owned Rust `xtask` binaries are the only executed build, test, and package orchestrator for the TypeDB/SlateDB fork and container image; Cargo-invoked native tools are pinned, while the Cloudflare control plane retains a separate locked TypeScript toolchain.
122. Every committed Cargo manifest and `Cargo.lock` entry is fork-owned, reviewed, and source-locked; no release step regenerates them by invoking Bazel.
123. Upstream Bazel files are read-only discovery/rebase evidence, never an executable release dependency.
124. Every applicable upstream test target and every leaf case—libtest case, Cucumber scenario, failpoint-registry member, script scenario, or static validation—has one stable catalogue identity and source hash.
125. No upstream test target, test-producing macro, fixture, platform predicate, feature set, or test case may remain `UNKNOWN` or `UNCLASSIFIED` at a passing gate.
126. The coverage denominator and all exclusions are machine-generated, versioned, and archived before test execution.
127. Upstream test source remains byte-identical where possible; any port has a reviewed semantic-equivalence ledger and retains the original source/hash.
128. Bazel `data`, `env`, runfiles, timeout, serialisation, platform, and package-layout semantics required by a test are reproduced explicitly by the Cargo runner.
129. Every storage-independent upstream test executes against both the oracle and candidate backend profiles; backend-specific exclusions require a named replacement contract test.
130. Backend selection for generic tests is centralized and runtime/config driven where practical; test-local `if rocksdb` branches are prohibited.
131. `#[ignore]`, environment-based early returns, missing credentials, absent fixtures, dynamic skips, and unsupported-profile exits are counted as non-executions unless explicitly approved in the catalogue.
132. Automatic retry may diagnose a flaky failure but cannot convert a failed qualifying run into PASS.
133. The server binary digest exercised by assembly, behavior, failpoint, crash, and E2E tests equals the server binary digest shipped in the release image.
134. Tests that mutate global state, ports, failpoints, process data directories, R2 namespaces, controller state, or clocks run in declared isolated sandboxes/serial groups.
135. Random/property tests record deterministic seeds; every found failure seed becomes a permanent regression fixture.
136. Critical tests include negative controls or mutation evidence proving that they fail when the protected invariant is deliberately broken.
137. Drift between upstream BUILD declarations, committed upstream Cargo manifests, fork Cargo metadata, and executed test lists fails the build.
138. Release builds/tests run `--frozen --offline` from vendored or otherwise content-verified sources with pinned Rust and native toolchains.
139. The full applicable corpus runs against the real R2/DO release profile at least pre-release; a smaller PR lane does not satisfy release conformance.
140. Passing the upstream corpus never waives the model, differential, failpoint, stale-actor, checkpoint, command, or platform-chaos obligations.


### 5.11 Cloudflare integration and release-authority invariants

141. The release source graph contains every proof-critical external repository, artifact, base image, package, compatibility date, and native tool; a missing node fails G0.
142. `typedb-behaviour` is a first-class source-lock node, not an implicit Bazel runfile.
143. Reported target/case counts are informational until emitted from the locked machine-readable catalogue.
144. TypeDB, SlateDB, and fork tooling keep independent Cargo workspaces and lockfiles unless a later ADR proves that flattening preserves upstream Cargo behavior and rebaseability.
145. A task runner is replaceable orchestration; deleting it must not change source discovery, build semantics, test denominator, package bytes, or gate meaning.
146. The upstream-parity and qualification Rust toolchains never contribute object files to one binary.
147. Production SlateDB uses an explicit minimal feature allowlist; `compaction_filters`, unused cloud providers, and test-only/all-feature bundles cannot enter the release.
148. `DatabaseControllerDO` and `DatabaseContainerDO` are different Durable Object classes, namespaces, schemas, and capabilities.
149. Container helper state, hooks, alarms, and status observations never grant database authority.
150. Every controller-to-container and container-to-controller message binds `DeploymentId`, `ContainerIdentity`, `ContainerProcessNonce`, `StartupSessionId`, generation, source/config/protocol, and request digest where applicable.
151. A controller procedure performs no uncontrolled network await between final authority validation and its SQLite commit.
152. Any operation requiring object I/O uses prepare–I/O–finalise or commit–outbox structure with an immutable operation identity.
153. Durable Object input/output gates are treated as runtime assistance, not as a substitute for explicit transactional state-machine design.
154. Alarm execution is idempotent and progress is reconstructible without assuming more than at-least-once delivery and finite automatic retries.
155. Durable Object overload is admission-controlled; blind client retry storms are prohibited.
156. The controller admission-stop thresholds remain conservatively below the platform's hard per-object storage and row limits.
157. Pre-G13 runtime R2 credentials contain no `DeleteObject`, `DeleteObjects`, bucket administration, lifecycle administration, or Bucket Lock administration action.
158. Broad `object-read-write` temporary credentials are prohibited for runtime writers unless the platform definition is proven delete-free for the exact release; the current candidate definition is not.
159. Authority, active materialisation, scratch, backup, and test buckets have separate parent credentials and independently reviewable policies.
160. Bucket Locks cover immutable authority namespaces with coarse rules; rule-count pressure cannot cause per-object lock creation.
161. Bucket Locks are defence in depth, not the sole proof of immutability or protection from a privileged administrator able to change lock configuration.
162. Application SHA-256 over exact bytes is canonical object identity even when provider checksum headers are used.
163. An ETag is never a content digest authority, including multipart uploads.
164. `(UploadAttemptId, part_number)` binds one exact digest and length. A changed part starts a new upload attempt.
165. Container rollout success means only that rollout began; readiness and release completion require per-instance compatibility evidence and observed convergence.
166. V1 exposes only the HTTP facade to end users; no native non-HTTP Container ingress claim appears in a V1 release manifest.
167. `sleepAfter`, shutdown handling, egress allowlists, image digest, instance shape, rollout plan, and compatibility date are explicit release configuration.
168. `enableInternet` is false unless an allowlisted, reviewed requirement proves otherwise; container-to-platform control uses the qualified HTTP/service path.
169. No component assumes the lifecycle DO and container process are colocated.
170. A release cannot be green while any Cloudflare contract record, real-account probe, source/package mapping, or rollout compatibility tuple required by its profile remains unresolved.

---

## 6. Canonical formats and R2 namespace

### 6.1 Namespace

```text
typedb-r2/p1/{environment}/{database_id}/
  database-indexes/exact/permanent-command-id/roots/{catalog_version}/{root_digest}
  database-indexes/exact/permanent-command-id/shards/{partition}/{level}/{shard_digest}
  generations/{generation}/
    wal/payloads/{payload_sha256}
    wal/index-segments/{start_lsn_be}-{end_lsn_be}/{segment_digest}
    commands/results/{result_sha256}
    commands/ledger-segments/{segment_id}/{segment_digest}
    indexes/exact/{index_kind}/roots/{catalog_version}/{root_digest}
    indexes/exact/{index_kind}/shards/{partition}/{level}/{shard_digest}
    materializations/{materialization_id}/
      keyspaces/{keyspace_id}/slatedb/...
    checkpoints/{checkpoint_id}/
      candidate/{candidate_digest}
      logical-digest/{algorithm_version}/{manifest_digest}
      verification/{attempt_id}/{report_digest}
    backups/{backup_id}/manifest/{manifest_digest}
    pins/{pin_id}/descriptor/{pin_digest}
    gc/inventories/{attempt_id}/{shard_no}/{digest}
    gc/marks/{attempt_id}/{shard_no}/{digest}
    gc/candidates/{attempt_id}/{shard_no}/{digest}
  control/events/{control_seq_be}/{event_digest}
  control/snapshots/{through_control_seq_be}/{projection_digest}/{snapshot_digest}
  control/manifests/{through_control_seq_be}/{manifest_digest}
  control/recovery-anchors/{anchor_id}/{anchor_digest}
  admin/recovery/{attempt_id}/...
```

The `p1` prefix is a protocol namespace and never changes merely because this document is revised. There is no per-record `wal/descriptors/` object in the baseline. `WalRecordFinalized` is the durable descriptor event until the descriptor is archived into an activated index segment. No mutable `latest`, `current`, or `active` object grants authority.

### 6.2 Canonical encoding

Structured durable objects use deterministic CBOR with numeric schema keys, definite lengths, shortest encodings, duplicate-key rejection, no authoritative floats, explicit text normalization rules, bounded nesting/allocation, and cross-language golden vectors. JSON is observability/API representation only.

```text
canonical_body = deterministic_cbor(authoritative_fields_without_self_auth)
body_digest    = SHA256(domain_separator || format_version || canonical_body)
auth_tag       = Sign(key_id, rotation_epoch, domain_separator || body_digest)
```

Ed25519 or another qualified asymmetric signature is preferred for gateway/control objects. HMAC may be used only when the shared-secret TCB and rotation/recovery consequences are accepted explicitly.

### 6.3 `ObjectWriteCapability`

```text
ObjectWriteCapabilityV1 {
  capability_id,
  controller_incarnation_id,
  issued_control_seq,
  principal_kind,
  environment,
  database_id,
  generation,
  materialization_id?,
  attempt_id?,
  authority_class,             // EXACT_AUTHORITATIVE | PREFIX_BULK_ORPHANABLE
  permitted_methods,
  exact_object_key?,
  permitted_prefix?,
  expected_digest?,
  expected_length?,
  write_condition,
  max_object_bytes,
  max_total_bytes,
  max_requests,
  not_before,
  expires_at,
  nonce,
  audience,
  controller_signature
}
```

`EXACT_AUTHORITATIVE` is used for WAL payloads, command results, candidate manifests, and other objects whose exact key/digest/length are known before the write. `PREFIX_BULK_ORPHANABLE` may be used for SlateDB SSTs and scratch build objects because stale uploads are harmless until separately fenced manifest publication.

### 6.4 `ObjectReceipt`

```text
ObjectReceiptV1 {
  capability_id,
  capability_digest,
  controller_incarnation_id,
  operation_id,
  exact_object_key,
  method,
  condition_requested,
  condition_outcome,
  observed_digest,
  observed_length,
  backend_request_id?,
  backend_version_or_etag_observation?,
  gateway_observed_at,
  gateway_instance,
  auth_key_id,
  auth_rotation_epoch,
  gateway_signature
}
```

The controller verifies its original capability, audience, incarnation, key/prefix, operation, digest/length where exact, condition result, expiry, nonce, and signature. Gateway time is diagnostic. An ETag is not a content proof. An exact authoritative receipt is not signed until the remote outcome is resolved.

### 6.5 WAL descriptor

```text
WalDescriptorV1 {
  environment,
  database_id,
  generation,
  append_lsn,
  type_sequence,
  sequencing_kind,             // SEQUENCED | UNSEQUENCED
  record_type,
  payload_key,
  payload_digest,
  payload_length,
  previous_record_digest?,
  writer_epoch,
  startup_session_id,
  controller_incarnation_id,
  finalization_operation_id,
  request_digest,
  unsequenced_logical_key?,
  command_binding?,
  source_lock_digest,
  record_registry_digest,
  format_version,
  descriptor_digest
}
```

`unsequenced_logical_key` is mandatory for singleton/cache records such as transaction status. For a status it is `(StatusRecordType, target_commit_type_sequence)`. The controller stores a unique mapping from logical key to verdict/payload digest and physical record.

### 6.6 WAL index segment

An activated `WalIndexSegmentV1` archives one exact contiguous descriptor range and contains:

- start/end AppendLsn and predecessor/final descriptor digests;
- exact canonical descriptor entries or authenticated offsets;
- exact sorted index `finalization_operation_id -> descriptor`;
- exact sorted index `(CommandId, CommandExecutionEpoch, AttemptId) -> descriptor`;
- exact sorted index `unsequenced_logical_key -> descriptor`;
- TypeSequence and record-type indexes for iteration/latest lookup;
- payload references, count, lengths, source/format version, digest, signature.

No Bloom filter or sparse table is accepted as an absence proof. Segment activation is journal-durable before row pruning. Old activated segments remain roots while any iterator/no-intent proof/catalogue version references them.

### 6.7 Validation basis and resolution certificate

```text
ValidationBasisV1 {
  database_id,
  generation,
  commit_record_id,
  commit_type_sequence,
  commit_append_lsn,
  iterator_snapshot,
  checkpoint_base_id?,
  checkpoint_visibility_watermark,
  isolation_context_start_sequence,
  resolver_version,
  source_lock_digest,
  config_digest,
  record_registry_digest,
  predecessor_resolution_root,
  format_version
}

TransactionResolutionV1 {
  commit_record_id,
  validation_basis_digest,
  verdict,                      // COMMIT | ABORT_CONFLICT
  conflict_class?,
  apply_plan_digest?,
  resolver_version,
  resolution_digest,
  signature
}
```

`ControlSeq` is not semantic validation input merely because the result is later journaled. The certificate's control event binds publication/audit; the resolver's semantic input is the fixed WAL/checkpoint basis.

### 6.8 Command result and tombstone

```text
CommandTerminalRecordV1 {
  command_id,
  request_digest,
  expected_generation,
  outcome,                      // SUCCEEDED | FAILED_FINAL
  result_availability,          // AVAILABLE | EXPIRED
  final_envelope_key?,
  final_envelope_digest,
  commit_bookmark?,
  transaction_resolution_digest?,
  policy_approval_digest?,
  terminal_control_seq,
  format_version
}
```

Expiry updates only `result_availability`; terminal outcome never changes.

### 6.9 Recovery anchor

```text
RecoveryAnchorV1 {
  database_id,
  controller_incarnation_id,
  minimum_control_head_seq,
  minimum_control_head_digest,
  snapshot_manifest_digest?,
  source_lock_digest,
  protocol_version,
  created_reason,              // CHECKPOINT | BACKUP | RELEASE | MIGRATION | MANUAL
  created_at,
  anchor_store,
  signer,
  signature
}
```

A recovery anchor is copied to an independently controlled administrative store/log or release package. Recovery may select a later valid contiguous head, but never a head below the newest trusted applicable anchor. The anchor cadence defines the residual malicious-suffix-deletion window; zero such RPO requires synchronous independent anchoring.

### 6.10 Checkpoint and backup formats

A checkpoint candidate names the exact cut, expected keyspace inventory, each immutable keyspace contribution, extensions, WAL/index/control roots, source/config/record formats, expected logical digest manifest, and root-closure parser version. A backup manifest is a verified copy closure over already pinned roots and states its failure domain and immutability properties without overclaiming Object Lock.


### 6.11 Bounded exact lookup catalogues

Physical WAL segments are ordered by `AppendLsn`; they are not a bounded lookup structure for random operation, command, status, or snapshot identities. V1 therefore maintains immutable copy-on-write exact lookup catalogues for at least:

```text
FINALIZATION_OPERATION_ID
COMMAND_ATTEMPT_BINDING
STATUS_KEY
SOURCE_SNAPSHOT_ID
PERMANENT_COMMAND_ID
TYPE_SEQUENCE
LATEST_UNSEQUENCED_RECORD_TYPE
```

```text
ExactLookupRootV1 {
  database_id,
  scope,                         // DATABASE | GENERATION
  generation?,
  index_kind,
  catalog_version,
  covered_through_append_lsn?,
  covered_through_control_seq,
  active_delta_start?,
  routing_hash_algorithm,
  partition_bits,
  maximum_levels,
  partitions_and_level_roots,
  source_lock_digest,
  format_version,
  root_digest,
  signature
}
```

`PERMANENT_COMMAND_ID` is database-scoped and its root lives outside generation namespaces. Online lookup is the union of the reconstructed active-command SQLite/control-journal delta and this immutable root, which maps archived CommandIds to ledger locations across historical generations. All WAL-derived indexes are generation-scoped.

Each shard contains sorted full canonical keys and exact values, not only hashes. Hash prefixes may select a partition; full-key equality proves membership. Each partition has a configured maximum level count and bounded shard size, so a lookup touches a bounded number of immutable objects plus the active SQLite delta regardless of database age. Index compaction is prepare/verify/activate/prune, copy-on-write, journaled, crash-tested, and root-pinned exactly like WAL archival. If level or delta bounds cannot be maintained, mutation admission stops before controller exhaustion.

An absence certificate names the exact lookup-root version, covered frontier, active-delta frontier, queried canonical key, and all shard proofs. It is valid only after the final controller transaction rechecks unchanged root/head and active-delta absence. Bloom filters, hash prefixes, MPHFs without stored-key verification, or “searched every current segment” are not absence authority.

The physical `WalIndexSegmentV1` may retain local secondary indexes as accelerators, but random-key correctness and boundedness belong to these catalogues. `WalIndexCatalogueActivated` binds both the physical segment set and the WAL exact-lookup roots; command-ledger activation atomically binds its generation-local segment and the database-global permanent CommandId root.

---

## 7. Controller state, reducer, journal, and bounded archival

### 7.1 SQLite authority model

SQLite is the online linearisation point. Every state-changing procedure:

1. validates controller incarnation, database/generation/materialisation, lifecycle, actor/session/attempt, epochs, operation ID, request digest, deadline, and storage budgets;
2. resolves idempotent replay or rejects conflict;
3. mutates projection state and inserts the unsigned canonical outbox body in the same SQLite transaction;
4. commits atomically;
5. waits for the appropriate journal barrier only when the caller needs a promise surviving total controller loss.

Bulk bytes never enter SQLite or the DO. Tail tables have hard byte/row limits, archival high/low watermarks, oldest-age limits, and admission-stop thresholds.

### 7.2 Core logical tables

Generated DDL/procedures are normative. The minimum projection contains:

```text
databases(
  database_id PK,
  current_generation,
  lifecycle_state,
  controller_incarnation_id,
  control_head_seq,
  control_head_digest,
  journal_durable_seq,
  trusted_anchor_seq,
  trusted_anchor_digest,
  source_lock_digest,
  config_digest,
  protocol_version,
  storage_budget_state
)

generations(
  database_id,
  generation,
  parent_generation?,
  restore_provenance?,
  active_materialization_id,
  visibility_watermark_blob,
  last_applied_commit_lsn?,
  wal_head_lsn,
  wal_head_digest,
  next_type_sequence_blob,
  next_append_lsn,
  writer_epoch,
  compactor_epoch,
  build_epoch_counter,
  active_checkpoint_id?,
  state,
  PRIMARY KEY(database_id, generation)
)

materializations(
  database_id,
  generation,
  materialization_id,
  kind, state,
  writer_epoch?, compactor_epoch?, build_epoch?,
  slate_writer_epoch, slate_compactor_epoch,
  attempt_id?,
  created_control_seq,
  activated_control_seq?,
  retired_control_seq?,
  PRIMARY KEY(database_id, generation, materialization_id)
)

startup_sessions(
  startup_session_id PK,
  database_id, generation, materialization_id,
  controller_incarnation_id,
  holder_id, process_nonce, image_digest,
  source_lock_digest, config_digest,
  writer_epoch,
  slate_writer_epoch, slate_compactor_epoch?,
  state,
  granted_at, expires_at_controller_time,
  revoked_control_seq?
)

wal_tail(
  database_id, generation, append_lsn,
  type_sequence_blob,
  sequencing_kind, record_type,
  descriptor_digest, previous_record_digest,
  payload_key, payload_digest, payload_length,
  finalization_operation_id,
  request_digest,
  unsequenced_logical_key?,
  writer_epoch, startup_session_id,
  command_id?, command_execution_epoch?, attempt_id?,
  control_seq,
  PRIMARY KEY(database_id, generation, append_lsn),
  UNIQUE(database_id, generation, finalization_operation_id),
  UNIQUE(database_id, generation, type_sequence_blob)
    WHERE sequencing_kind='SEQUENCED',
  UNIQUE(database_id, generation, unsequenced_logical_key)
    WHERE unsequenced_logical_key IS NOT NULL
)

wal_index_segments(... exact physical catalogue/version/range/digests/state ...)
exact_lookup_catalogs(... kind/version/partition/levels/covered_frontier/root_digest/state ...)
status_cache(... target_type_sequence PK, verdict, descriptor_ref ...)
transaction_resolutions(... command-bound or bounded operational cache only ...)
commands_active(...)
command_attempts_active(...)
command_ledger_segments(...)
checkpoints(...)
checkpoint_attempts(...)
pins(...)
backups(...)
maintenance_attempts(...)
control_outbox(... canonical body, chosen key id/epoch, publish state ...)
control_snapshots(...)
recovery_anchors(...)
format_migrations(...)
recovery_attempts(...)
```

### 7.3 Mandatory transactional constraints

Generated procedures enforce at least:

- monotonic generation/control/epoch/counter values and exhaustion guards;
- exact 8-byte big-endian TypeSequence storage;
- contiguous AppendLsn and predecessor digest;
- atomic sequenced allocation of TypeSequence/AppendLsn/ControlSeq;
- unsequenced stamping with current previous TypeSequence;
- immutable operation ID/request digest;
- singleton unsequenced logical key, including status verdict conflict detection;
- current controller incarnation/session/epoch/lifecycle on finalisation;
- one command intent, one immutable resolution, one terminal outcome;
- no outcome success before visibility proof;
- no `NoIntentProven` while an exact command-attempt binding exists in active tail or activated segments;
- checkpoint cut only while every declared drain counter is zero and compactor/active-manifest publication is paused;
- one active materialisation per generation;
- new-generation TypeSequence initialized from restore watermark + 1;
- segment activation before row pruning;
- iterator/no-intent catalogue pins before physical-segment or exact-lookup-root replacement/retirement;
- scratch-to-active transition only after higher physical SlateDB writer/compactor epochs are claimed and stale build publication is fenced;
- no terminal-outcome mutation when result availability expires;
- budget breach stopping new mutations before platform exhaustion.

### 7.4 Transactional outbox and signing

The state transaction commits an unsigned canonical event body, body digest, exact ControlSeq, previous-event digest, and selected signing key/rotation epoch. The flusher:

1. loads the oldest unpublished event;
2. recomputes canonical bytes/digest;
3. signs with the key selected in the transaction;
4. conditionally creates the exact event object through the authoritative data path bound to the current controller incarnation;
5. resolves ambiguity by exact GET/digest or trusted receipt;
6. marks it published and advances the contiguous journal frontier;
7. wakes barrier waiters.

Key rotation cannot strand old outbox rows: selected old keys remain usable for signing pending rows until drained, or rows are explicitly migrated under a journaled protocol.

### 7.5 Pure reducer

One generated/pure library defines legal transitions and projection semantics for controller procedures, catastrophic recovery, model tests, schema generation, compatibility readers, and documentation tables. It rejects gaps, duplicate positions, stale incarnation/session/epoch, second intents/resolutions/outcomes, activation without proof, result-expiry outcome mutation, unsafe pin release, unknown mandatory formats, and source/config/protocol mismatch.

The production controller may use optimized SQL procedures, but every committed trace is replay-equivalent to the pure reducer. CI diff-checks SQL projection against reducer projection.

### 7.6 Authoritative versus observational events

Only transitions needed to reconstruct authority are durable reducer events. Waiter satisfaction, worker start, fenced observation, queue state, retries, and progress telemetry remain logs/metrics unless a specific recovery proof requires them.

The V1 authoritative event set is frozen in Appendix A. Adding an event requires schema ID, transition, model, compatibility rule, and evidence that it is not duplicate authority.

### 7.7 Control snapshots and anti-rollback

A snapshot contains reducer projection only—never live leases, local TTLs, sockets, alarms, cursors, or process queues. It is bound to exact event head, activated index/ledger catalogues, source/protocol, controller incarnation, and projection digest.

Snapshot publication is replay-verified before preferred recovery use. Periodically, and at every checkpoint activation, verified backup, release, key migration, and controller recovery, an independent RecoveryAnchor is emitted. Recovery rejects a valid-looking history below the anchor.

### 7.8 WAL-tail archival

A bounded archival attempt:

1. captures an exact immutable descriptor range and current segment catalogue version;
2. builds `WalIndexSegmentV1` for the contiguous physical range and immutable exact-lookup delta shards for every required random-key index;
3. uploads/verifies the physical segment, shards, and candidate lookup roots;
4. records `WalIndexSegmentPrepared`;
5. verifies chain, entries, full-key indexes, payload references, bounded partition/level invariants, and parser semantics using two implementations where practical;
6. atomically activates one catalogue version binding the physical segment set and exact-lookup roots, then journals it;
7. waits for journal durability;
8. prunes covered SQLite rows in bounded batches;
9. retains old physical and exact-lookup roots while any iterator/no-intent/status/operation proof references them.

This reduces controller storage only. It does not delete WAL objects.

### 7.9 Command-ledger archival

Terminal command records are sealed into immutable generation-local ledger segments and a database-global copy-on-write `PERMANENT_COMMAND_ID` exact lookup root. A partitioned sorted index or authenticated perfect/hash table is accepted only when it stores/verifies the full canonical CommandId and has bounded levels. Bloom filters can reduce I/O but cannot authorize execution. Root activation precedes row pruning. Permanent CommandId non-reuse evidence is never dropped, and reservation cost is independent of the number of historical ledger segments.

### 7.10 Catastrophic controller recovery

1. Disable routing, startup grants, and authoritative data-path minting.
2. Acquire the separately controlled recovery lock.
3. Load the newest trusted applicable RecoveryAnchor from the independent anchor store.
4. Validate key roots, snapshots, contiguous events, activated index/ledger catalogues, payload references, and formats at or above the anchor.
5. Quarantine competing valid heads or any suffix below the anchor.
6. Reconstruct the pure reducer projection.
7. Rotate `ControllerIncarnationId`, journal/data-path signing authority, and relevant parent credentials through the external administrative control.
8. Clear live sessions/leases and advance writer/compactor/build epoch counters.
9. Create a fresh controller namespace and SQLite projection.
10. Build and verify a fresh scratch materialisation from immutable roots.
11. Record two-person recovery approval and new anchor.
12. Activate the new materialisation/controller incarnation and issue fresh sessions.
13. Re-enable routing.
14. Run a negative drill proving the old controller, old sessions, and stale temporary credentials cannot produce accepted authoritative events, receipts, WAL finalisations, or publications.

Without independent incarnation revocation, old-controller fencing is not proven and G7 fails.

---

## 8. Startup, leases, and SlateDB publication epochs

### 8.1 Startup protocol

1. Controller reserves startup for exact database, generation, active materialisation, controller incarnation, image/source/config/protocol, holder, and process nonce.
2. `StartupReserved` reaches its journal barrier.
3. Container proves attestation and one-time reservation possession.
4. Controller allocates a fresh logical WriterEpoch, one exact `SlateWriterEpoch` greater than the known/stored writer epoch of every keyspace in the active materialisation, and a startup session in one transition.
5. Grant reaches its journal barrier before any authoritative WAL/manifest publication.
6. Container opens every active keyspace with the session's exact physical `SlateWriterEpoch` through SL-P1, while WAL finalisation continues to validate the logical WriterEpoch/session; SlateDB WAL/GC/implicit compactor are disabled.
7. Container performs fallible durability-session open and fixed-head authoritative recovery.
8. It proves keyspace inventory, resolved options, epoch readback, visibility/durable/materialised frontiers, raw-read initialization order, background-task configuration, and zero fatal unresolved state.
9. Controller records readiness and activates routing only after the readiness barrier.

Restart always creates a new session, a strictly newer logical WriterEpoch, and a physical SlateWriterEpoch greater than every value possibly claimed during the prior attempt. An ambiguous `init_with_epoch(E)` abandons the session and never causes blind reuse of E.

### 8.2 Lease timing

Controller time is authoritative. The holder computes only a conservative local stop deadline from the controller-reported remaining TTL, measured request uncertainty, scheduling stalls, and a configured floor. It stops new admission before that deadline. Every finalisation/publication still validates current authority transactionally.

A timed-out lease does not erase already-finalised WAL intent. It prevents the old process from acting as current materialisation authority.

### 8.3 SL-P1 — exact external publication epoch

SL-P1 injects exact epochs into every publication-capable open/path:

- active writer manifest publication;
- explicit compactor publication and compactions object;
- active writer checkpoint creation;
- clone/scratch creation under BuildEpoch;
- refresh/retry/recovery paths that can make metadata reachable.

Every pause-before-publication test advances the relevant epoch and proves the resumed stale actor cannot publish. Observe-and-bind is diagnostic only.

### 8.4 SL-P2 — fenced active-manifest maintenance

V11's assumption that `Admin::delete_checkpoint` runs “under the writer epoch” is false at the pinned source: `Admin` loads `StoredManifest`, which wraps `SimpleTransactionalObject`, whereas active writer publication uses `FenceableManifest`/`FenceableTransactionalObject`.

SL-P2 therefore provides one of two source-proven V1 configurations:

- **Preferred:** when internal destructive GC is disabled, suppress creation of compactor-protective checkpoints if source proof shows they exist solely to protect against deletion; or
- **Fallback:** expose a writer-owned, exact-WriterEpoch fenced checkpoint-metadata maintenance API. It may prune only declared temporary protective entries, never catalog-pinned checkpoints.

Unfenced `Admin::{create,refresh,delete}_checkpoint`, parent checkpoint stripping, active clone mutation, and destructive Admin helpers are prohibited in active namespaces. G0 must enumerate every such path.

### 8.5 Explicit compactor lifecycle

The active database opens with automatic compactor disabled. The controller starts a separate explicitly authorized compactor task/process only after:

- creating a maintenance attempt and budget;
- issuing a CompactorEpoch and scoped prefix capability;
- verifying SL-P1 exact epoch injection;
- registering drain/revoke/status hooks.

Compactor revocation is independent of writer revocation. It cannot delete objects. If the pinned API cannot start/stop/drain an explicit compactor without implicit open-time behavior, SL-P3 supplies the minimal lifecycle hook.

### 8.6 Scratch builder

A builder receives scratch MaterializationId, immutable inputs, exact BuildEpoch, exact per-materialisation `SlateWriterEpoch` and optional `SlateCompactorEpoch`, prefix-scoped orphanable bulk capability, and read-only authoritative WAL access. BuildEpoch is controller authority; the physical SlateDB values are the actual publication fences. It cannot append WAL/status/statistics, mutate active prefixes, activate itself, alter routing, release pins, or delete objects.

---

## 9. Fallible TypeDB durability interface and remote WAL

### 9.1 Conceptual interface

Exact source-compatible signatures are fixed at G0, but the semantics include explicit operation identity, status singleton keys, and fixed iterator snapshots:

```rust
pub trait DurabilityClient: Send + Sync {
    type Iterator: Iterator<Item = Result<DurabilityRecord, DurabilityError>> + Send;

    fn open_session(&self, ctx: OpenContext)
        -> Result<DurabilitySession, DurabilityError>;

    fn sequenced_write(
        &self,
        session: &DurabilitySession,
        operation_id: OperationId,
        record_type: RecordType,
        payload: &[u8],
        binding: Option<CommandBinding>,
        deadline: Deadline,
    ) -> Result<FinalizedRecord, DurabilityError>;

    fn unsequenced_write(
        &self,
        session: &DurabilitySession,
        operation_id: OperationId,
        logical_key: Option<UnsequencedLogicalKey>,
        record_type: RecordType,
        payload: &[u8],
        deadline: Deadline,
    ) -> Result<FinalizedRecord, DurabilityError>;

    fn request_sync(
        &self,
        session: &DurabilitySession,
        deadline: Deadline,
    ) -> Result<SyncWaiter, DurabilityError>;

    fn iter_from(
        &self,
        session: &DurabilitySession,
        sequence: TypeSequence,
        bounds: IteratorBounds,
    ) -> Result<(DurabilityIteratorSnapshot, Self::Iterator), DurabilityError>;

    fn find_last_unsequenced_type(
        &self,
        session: &DurabilitySession,
        record_type: RecordType,
        snapshot: Option<&DurabilityIteratorSnapshot>,
    ) -> Result<Option<DurabilityRecord>, DurabilityError>;

    fn reset_or_delete(
        &self,
        session: &DurabilitySession,
        request: ResetDeleteRequest,
    ) -> Result<(), DurabilityError>;
}
```

Unsupported remote semantics fail explicitly and block dependent features.

### 9.2 Error discipline

Errors classify transport, deadline, cancellation, ambiguity, fenced/session/generation/incarnation mismatch, conflict, integrity, missing record, iterator expiry, unsupported operation, capacity, corruption, and internal invariant. Each carries operation identity and retry class: retry same operation, query status, do not retry, or fatal database.

No remote/environmental error panics. Dropping a waiter does not cancel or alter a possibly finalised operation.

### 9.3 Sequencer actor

One bounded actor orders sequenced append, unsequenced append, and sync markers. Channel-full is a typed overload before caller side effects that require logging. An ambiguous append blocks the lane until exact status resolution. The actor maintains local `current/previous` only after resolved controller results.

### 9.4 Payload upload and exact finalisation

1. TypeDB serialises exact opaque bytes without consuming TypeSequence.
2. Client computes payload digest, length, and canonical request digest.
3. It obtains an exact authoritative object capability or qualified presigned equivalent for the content-addressed key.
4. Bytes stream with bounded memory/backpressure and are independently hashed by the qualified path.
5. Ambiguous object outcome is resolved at the exact key with exact bytes/metadata semantics.
6. Controller finalisation verifies capability/receipt, incarnation, session, epoch, operation, request, current head, and budgets.
7. In one SQLite transaction it allocates TypeSequence when sequenced, AppendLsn, ControlSeq, descriptor, head/counters, singleton keys, command binding, and outbox event.
8. A lost response is queried by operation ID.

No counter is consumed on failed transaction.

### 9.5 Status singleton protocol

Pinned TypeDB recovery treats a second terminal status as an unreachable state, while a separate live disk path inserts statuses into a map with last-wins behavior. V16 does not preserve this inconsistency.

For a transaction status:

```text
StatusKey = (StatusRecordType, target_commit_type_sequence)
StatusValue = COMMITTED | ABORTED
```

- first finalisation appends one unsequenced physical record;
- same key/same verdict/payload returns that record;
- same key/different verdict is `STATUS_CONFLICT`, quarantines the database, and never appends;
- authoritative recovery, live resolver repair, and retries use deterministic operation identity from StatusKey/verdict;
- status repair is optional cache maintenance and cannot change transaction truth.

Singleton lookup remains exact and bounded after tail archival. Before appending a status whose key is not in the active SQLite cache, the controller captures the exact-lookup root version/head, queries the `STATUS_KEY` partition/levels plus active delta, and then—in the finalisation SQLite transaction—rechecks unchanged lookup root/head plus active-tail absence. Found-same returns the archived record; found-conflict fails closed; exact absence permits append. Status-key rows may be pruned only after the activated segment carries the exact index.

Statistics or other non-singleton unsequenced records use explicit operation identities and type-specific dedupe/retention rules. No blind retry is allowed after ambiguity.

### 9.6 Sync

When the sequencer reaches a sync marker, every earlier operation is resolved. The barrier captures the current physical head and corresponding finalisation control event. The waiter succeeds when:

- descriptor history through the head is contiguous in activated segments + tail;
- every referenced payload is verified exact;
- control journal is durable through the barrier;
- no integrity/format conflict exists.

Session revocation after finalisation does not invalidate WAL durability. The commit handler must separately revalidate authority before applying/reporting current-materialisation progress.

### 9.7 Fixed iterator semantics

The pinned file WAL holds a `RwLockReadGuard<Files>` for `RecordIterator` lifetime, so iteration observes a stable finite file set. Remote iteration reproduces this externally visible behavior:

1. atomically capture `DurabilityIteratorSnapshot` and pin its segment catalogue roots;
2. locate the exact first sequenced record required by source `iter_from(s)` semantics;
3. merge activated segments and active tail strictly through captured `through_append_lsn`;
4. verify descriptor chain, payload digest/length, TypeSequence rules, and exact head;
5. return physically interleaved unsequenced records;
6. return EOF only after the captured head;
7. release/persist expiry of iterator root pin.

A missing requested sequenced head is a typed missing-record error, not empty iteration.

### 9.8 Index lookup and no physical WAL deletion

`find_last_unsequenced_type`, commit-idempotency scans by snapshot ID, validation context, command no-intent proof, recovery, and future tooling can depend on retained history. V1 therefore:

- archives descriptor rows into exact immutable index segments;
- retains every WAL payload, descriptor event/index entry, and required control history;
- excludes physical WAL deletion from all pre-G13 code and credentials.

A future deletion protocol must inventory and prove all source and application readers, including `commit_record_exists`, before changing this rule.

### 9.9 Finalisation batching

The baseline emits one `WalRecordFinalized` event per record. G2 may introduce `WalRecordsFinalizedBatchV1` only if it specifies bounded K/bytes, all-or-nothing SQLite semantics, ordered per-record results, singleton-key conflicts, command bindings, one previous/final digest chain, sync coverage, idempotent batch operation identity, compatibility reader, and crash/model tests. “One covering event” without this format is forbidden.

### 9.10 Segmentation kill gate

G2 measures p50/p95/p99 append and sync, DO transaction throughput, outbox lag, object/event/request/cost amplification, and per-record versus explicitly modelled batch shape. Failure triggers protocol redesign before broad TypeDB/SlateDB forking.


---

## 10. Transaction resolution, apply, and read visibility

### 10.1 Normative progression

```text
NO_INTENT
  -> INTENT_FINALIZED
  -> INTENT_DURABLE
  -> RESOLUTION_PENDING
       -> RESOLVED_ABORT
       -> RESOLVED_COMMIT
            -> APPLY_PENDING
            -> VISIBILITY_COMPLETE
```

`INTENT_DURABLE` means the CommitRecord's physical barrier is satisfied. It is not a verdict. `VISIBILITY_COMPLETE` means every keyspace batch for the committed transaction is applied and VisibilityWatermark has advanced through its sequence.

### 10.2 Shared prefix resolver

V1 extracts one pure `TransactionResolver` library used by:

- live commit validation;
- authoritative startup recovery;
- status-cache repair;
- scratch checkpoint/materialisation replay;
- differential verification.

Conceptual interface:

```rust
fn resolve(
    commit: CommitIntent,
    basis: &ValidationBasis,
    history: &mut dyn FixedPrefixHistory,
) -> Result<ResolutionAndApplyPlan, ResolutionError>;
```

The resolver:

- sees only sequenced commit intents at or before the fixed head;
- recursively resolves missing predecessor statuses from earlier intents;
- treats a present status as a cache certificate, verifies singleton rules, and can compare it against recomputation in verification modes;
- produces deterministic verdict, conflict class, normalized apply plan, and digests;
- never writes status, keyspaces, controller state, or metrics as semantic input.

The current live-source `unreachable!` for an evicted predecessor with missing status is replaced by this resolver path. The current recovery/live duplicate-status inconsistency is removed at the durability boundary and parser.

### 10.3 Validation basis

For commit S:

1. sync S's CommitRecord barrier;
2. capture a fixed iterator snapshot whose head contains S and the required predecessor prefix;
3. bind checkpoint base, visibility floor, isolation-context start, resolver/source/config/record versions;
4. run the shared resolver;
5. compute predecessor-resolution Merkle/root summary and apply-plan digest;
6. persist an immutable resolution certificate in controller state/event where needed;
7. optionally append the singleton source StatusRecord cache through the normal WAL.

No later status record is required as semantic input. If source analysis finds a dependency outside the finite basis, the architecture stops.

### 10.4 Resolution authority

Transaction truth is the deterministic resolver result over its immutable basis. A controller resolution event and source StatusRecord are independent memoised certificates of that truth:

- missing certificate: recompute;
- duplicate identical certificate: idempotent at its own identity;
- conflicting certificate or recomputation mismatch: corruption/fail closed.

This avoids two competing commit authorities while retaining efficient recovery and command audit.

### 10.5 Cross-keyspace apply

A committed resolution contains a complete deterministic apply-plan digest. TypeDB applies one atomic batch per keyspace in the source-defined order. Recovery may persist per-keyspace progress as optimization, but correctness comes from idempotent replay of the recorded operations.

After each crash point—zero keyspaces, every individual keyspace, all keyspaces before watermark, watermark before status—recovery must reach the same oracle state. VisibilityWatermark advances only after all batches for that sequence complete; aborted sequences also permit contiguous advancement.

### 10.6 Authority checks around apply

A holder may be fenced after intent finalisation or sync. The intent remains durable and must be recovered by the replacement writer. Before active-materialisation mutation/reporting, the apply path checks current session/WriterEpoch. A stale process may modify only its local/discarded memtable or leave unreachable objects; it cannot advance controller visibility or publish an active manifest.

### 10.7 Status persistence degradation

After positive resolution and complete apply, failure to append the source status cache cannot turn the transaction into abort. Behavior is profile-specific:

- native TypeDB call surfaces the pinned-compatible ambiguous/degraded error class unless a separately reviewed protocol mapping improves it;
- command API may finalize the proven outcome independently of the status cache;
- a controller-owned repair task retries the same deterministic StatusKey and never creates duplicates;
- persistent failure moves the database to a declared degraded state and blocks checkpoints that require a drained status lane.

### 10.8 Visibility watermark and raw reads

The TypeDB watermark includes applied commits and aborts. All ordinary snapshots/read paths use it. V11's statement that no source read bypasses MVCC is too broad: pinned `MVCCStorage` exposes raw production reads such as `get_raw_mapped`, `get_prev_raw`, and raw keyspace ranges; generator initialization uses raw predecessor lookup.

V16 requires:

```text
RawMaintenanceReadCapability {
  caller_id,
  database_id,
  generation,
  materialization_id,
  required_lifecycle_state,
  minimum_visibility_watermark,
  reason,
  expires_at
}
```

G0 inventories every raw caller. Each is classified as initialization, migration/import, consistency check, or forbidden query path. Raw reads run only after authoritative recovery has resolved/applied every sequence through the declared watermark, never during ordinary request serving or partial apply.

### 10.9 Validator upgrades

V1 does not support two resolver algorithms concurrently deciding intents in one generation. Upgrade protocol:

1. stop new mutation admission;
2. resolve/apply every old-version intent;
3. checkpoint/anchor exact old head;
4. deploy readers/tools that understand both durable formats where needed;
5. replace validator/source/config as one controlled startup generation state;
6. resume writes under the new resolver version.

Rollback cannot reintroduce an older resolver after new-version intents exist unless its compatibility is exhaustively proved.

---

## 11. Controller-mediated mutation commands

### 11.1 Guarantee boundary

The command API guarantees effectively-once observable database outcome for a finite, declared command catalogue. It does not guarantee exactly-once external effects, native TypeDB requests, arbitrary user code, or transactions containing external waits.

Every command class declares:

- canonical request schema/digest;
- guards and bounded transaction footprint;
- result mode and maximum bytes;
- approval policy;
- timeout/retention;
- deterministic error/result schema;
- whether source/database versions affect execution eligibility.

Command inventories and limits are design artifacts, not “source-confirmed” facts.

### 11.2 Orthogonal state dimensions

```text
ExecutionState:
  ABSENT -> RESERVED -> APPROVAL_PENDING? -> APPROVED -> ASSIGNED
  -> EXECUTING_PRE_INTENT -> RESULT_BOUND -> INTENT_FINALIZED
  -> INTENT_DURABLE -> RESOLUTION_PENDING
  -> RESOLVED_ABORT | RESOLVED_COMMIT
  -> APPLY_PENDING? -> VISIBILITY_COMPLETE?
  -> FINALIZING -> TERMINAL

TerminalOutcome:
  SUCCEEDED | FAILED_FINAL

ResultAvailability:
  AVAILABLE | EXPIRED
```

Pre-intent attempts can close as retryable only after exact `NoIntentProven`. `EXPIRED` is not a terminal outcome and never reopens execution.

### 11.3 Reservation and approval

Reservation checks active rows and exact archived ledger segments. Same ID/same digest returns existing state; different digest is permanent conflict; old-generation command returns its stored historical outcome/expiry or stale-generation response, never execution in current generation.

Approval binds command/request/generation, policy digest/version, approval class/slot, eligible role/principal, decision, issue/expiry, and signature. Dual approval requires distinct eligible principals. Assignment revalidates current policy and approvals. Rejection/cancellation/expiry before assignment is terminal under the same CommandId unless policy explicitly requires a new business command.

### 11.4 Assignment and execution

Assignment allocates CommandExecutionEpoch and AttemptId, binds one current startup session/WriterEpoch, journals the assignment, and waits for the barrier.

The worker opens one bounded TypeDB transaction and evaluates guards/writes. No LLM, tool, human, network service, or timer wait occurs inside it. The transaction can remain open only within a configured pre-intent deadline and resource footprint.

### 11.5 Result modes and corrected preparation order

1. **`CANONICAL_RECEIPT`:** the eventual envelope is defined solely from immutable command identity, resolution, visibility proof, and commit bookmark. No application bytes are uploaded before intent.
2. **`PREPARED_BYTES`:** during `EXECUTING_PRE_INTENT`, transaction-local deterministic values generate exact canonical result bytes. Those bytes are encrypted if required, uploaded, verified, and bound as `RESULT_BOUND` **before** invoking CommitRecord finalisation.

This order fixes V11's impossible `PREPARED -> EXECUTING` sequence for results that depend on transaction-local generated values.

If result upload fails, no intent is submitted; the transaction rolls back. The old attempt can be retried only under the normal no-intent rules. Result limits must make upload while a transaction is open operationally safe; otherwise that command class must use a canonical receipt or leave V1.

### 11.6 Intent binding and resolution

The CommitRecord descriptor binds CommandId, execution epoch, attempt, request digest, result mode, and prepared-result digest/key/length where applicable. That finalisation permanently forbids re-execution.

After intent durability, the shared resolver decides. Positive resolution is applied through VisibilityWatermark. The final envelope binds exact terminal outcome, bookmark, result reference/availability, resolution/apply proof, source/config/protocol, and retention. Success is returned only after `CommandTerminalized` journal durability.

### 11.7 Exact no-intent proof

A no-intent proof is not “search current SQLite”. It is an atomic proof across archived and active history:

1. revoke/fence the old execution context as necessary;
2. capture immutable exact-lookup root version, exact WAL head, and active-delta frontier;
3. exact-lookup `(CommandId, ExecutionEpoch, AttemptId)` in the bounded `COMMAND_ATTEMPT_BINDING` partition/levels; probabilistic indexes cannot return absence;
4. in one controller SQLite transaction recheck unchanged lookup-root version/head and exact absence in active tail/finalisation table;
5. close the attempt and append `NoIntentProven` with proof digest;
6. wait for its journal barrier before new assignment.

If catalogue/head changes, repeat. Any unavailable segment or ambiguous lookup fails closed.

### 11.8 Terminal result expiry

Result retention may delete encrypted result/final-envelope bytes only under the future explicit retention/delete protocol. The command ledger permanently retains terminal outcome, request digest, generation, result digest, bookmark, and expiry marker. Polling after expiry returns deterministic `RESULT_EXPIRED` metadata permitted by policy; execution never resumes.

### 11.9 Native operations and external effects

Native TypeDB operations share remote WAL and resolver machinery but not command reservation/result storage; response loss remains ambiguous. External effects run after terminal committed outcome through an idempotent outbox keyed by `(CommandId, CommitBookmark, effect_type)`. Third-party exactly-once is not claimed.

---

## 12. Safe TypeDB storage boundary and bounded runtime

### 12.1 Boundary objective

Replace concrete RocksDB ownership and unsafe iterator lifetime coupling with TypeDB-owned semantic interfaces. Do not impersonate the `rocksdb` crate. First land the refactor with only the RocksDB oracle; every upstream build/test remains green before SlateDB code is introduced.

### 12.2 Conceptual interfaces

```rust
pub trait KvEngine: Send + Sync {
    type Snapshot: KvSnapshot;

    fn snapshot(&self, logical: LogicalSnapshot)
        -> Result<Self::Snapshot, StorageError>;
    fn get(&self, snapshot: &Self::Snapshot, key: &[u8])
        -> Result<Option<Bytes>, StorageError>;
    fn scan(&self, snapshot: &Self::Snapshot, range: KeyRange)
        -> Result<Box<dyn KvCursor + '_>, StorageError>;
    fn write_batch(&self, batch: KeyspaceBatch, ctx: WriteContext)
        -> Result<(), StorageError>;
    fn flush(&self, target: FlushTarget)
        -> Result<FlushReceipt, StorageError>;
    fn checkpoint(&self, request: KeyspaceCheckpointRequest)
        -> Result<KeyspaceCheckpointContribution, StorageError>;
    fn approximate_size(&self, range: KeyRange)
        -> Result<SizeEstimate, StorageError>;
    fn metrics(&self) -> EngineMetricsSnapshot;
    fn close(&self, deadline: Deadline) -> Result<(), StorageError>;
}

pub trait KvSnapshot: Send + Sync {
    fn generation(&self) -> DatabaseGeneration;
    fn materialization_id(&self) -> MaterializationId;
    fn visibility_cap(&self) -> VisibilityWatermark;
}

pub trait KvCursor {
    fn next(&mut self) -> Result<Option<KvEntry>, StorageError>;
    fn cancel(&mut self);
}
```

No physical cross-keyspace atomicity is claimed. Raw maintenance access is a separate privileged interface, not a method exposed to ordinary snapshots.

### 12.3 RocksDB oracle

The RocksDB adapter preserves source semantics with owned safe snapshots/cursors; no forged `'static` lifetime escapes. The approved ephemeral spillover cache remains separate and is explicitly non-authoritative.

### 12.4 SlateDB adapter

One logical SlateDB instance exists per TypeDB keyspace/materialisation. Resolved correctness options are internal constants/config types; TypeDB callers cannot supply arbitrary SlateDB options. WAL and GC are disabled. Active writer/compactor/build epochs are exact and attested.

### 12.5 Runtime and concurrency

One process-wide Tokio storage runtime owns network/object clients and actor handles. The mutation/publication lane for each SlateDB handle is serialized. Reads may use bounded concurrent snapshot readers only after source/thread-safety and semantic tests prove it; otherwise the single-actor baseline remains. V11's unconditional serialization of all reads is not made a permanent performance design without evidence.

Rules:

- bounded high/normal/background queues and memory permits;
- no runtime per request/keyspace;
- no recursive `block_on`;
- no mutex held across network/await;
- owned bytes across actor boundaries;
- bounded prefetch/cursor lifetime;
- cancellation resolves ambiguous remote effects by operation ID;
- explicit quota separation for WAL/recovery, foreground operations, compaction, checkpoint/backup, and report-only GC;
- bounded count of TypeDB blocking threads waiting on storage replies.

### 12.6 Semantic differential matrix

RocksDB versus SlateDB tests cover point operations, binary ordering, every bound/prefix, floor behavior, snapshot stability, read-your-write overlay, per-keyspace batch atomicity, cross-keyspace partial apply hiding, tombstones, immediate pre-flush visibility, cursor error/expiry, large values, checkpoints, replay, all keyspaces/extensions, raw-maintenance callers, and failure mapping.

### 12.7 TypeDB background tasks

The pinned database constructs an interval Statistics updater and automatic checkpointer. The remote profile must not silently inherit them:

- automatic checkpointer is disabled; controller checkpoint workflow is the only checkpoint authority;
- Statistics updater uses a fallible, bounded, drainable task under explicit lifecycle control;
- its current `.expect`/panic/error assumptions enter the TB panic inventory;
- startup, checkpoint, hibernation, shutdown, and recovery can prove it stopped/drained;
- any remaining background durability/storage task is generated into startup attestation and the quiescence inventory.

---

## 13. SlateDB soft-fork contract

### 13.1 Production dependency and feature lock

The TypeDB adapter depends on the pinned SlateDB workspace revision, never a floating crates.io range. The candidate production dependency is equivalent to:

```toml
slatedb = {
  path = "../slatedb/slatedb",
  default-features = false,
  features = ["aws", "wal_disable", "foyer"]
}
```

This is a candidate allowlist, not permission to rely on defaults. G0 records `cargo tree -e features`, enabled `cfg`s, build-script outputs, and final linked symbols. Compression features are enabled individually only when the resolved storage format and compatibility matrix require them.

Forbidden in the production image:

- `all`;
- `test-util`, `bencher`, `bench-internal`;
- `azure`, `gcp`, or another unused provider;
- `moka` unless selected by a measured cache ADR;
- `compaction_filters`;
- blanket `--all-features`.

`compaction_filters` is specifically prohibited because the pinned source warns that configured filters may affect snapshot consistency.

### 13.2 Fixed runtime settings

Release attestation includes exact values for:

- SlateDB WAL disabled;
- correctness reads using memory-visible committed, non-dirty semantics;
- built-in garbage collector disabled;
- automatic compactor disabled at ordinary database open;
- explicit writer/compactor epoch injection;
- object-store retry policy;
- cache/memtable/L0/compaction limits;
- compression and block format;
- checkpoint behavior;
- object namespace and materialisation identity;
- delete/lifecycle capability absence.

Defaults are never correctness authority.

### 13.3 Publication inventory and fencing patches

`SL-P1` covers every writer, compactor, builder, checkpoint, clone, refresh, retry, and recovery path that can publish reachable metadata. `SL-P2` suppresses protective checkpoint creation when its only purpose is guarding internal deletion and deletion is disabled, or supplies a writer-owned fenced maintenance path. `SL-P3` provides explicit compactor start/drain/revoke hooks where the pinned public API is insufficient. `SL-P4` removes fail-open retry or iterator behavior where a real source gap remains.

The source inventory is generated from the resolved feature set. A publication path compiled out in one profile but compiled into another is still catalogued.

### 13.4 Read and write semantics

- same-handle write visibility before flush is mandatory;
- every production point/range read uses explicit adapter-owned options;
- scans preserve bytewise order, bounds, prefix behavior, snapshot pinning, and error propagation;
- per-keyspace batch visibility is atomic;
- cross-keyspace visibility is governed only by TypeDB's global watermark;
- object errors cannot become ordinary `None` or EOF;
- all cursors are bounded and invalidate on materialisation cutover.

### 13.5 Compactor lifecycle

The controller creates a compaction attempt, allocates exact logical and physical compactor epochs, grants a scratch-safe object capability, and starts the standalone compactor through the lifecycle API. Drain/revoke is explicit. Compaction can upload orphan data after revocation but cannot publish reachability. It has no delete credential.

### 13.6 Deletion reachability

Before G13:

- no production feature or runtime principal can call an authoritative delete;
- provider lifecycle rules are absent;
- Bucket Locks cover immutable authority prefixes;
- generic SDK delete methods may exist in dependencies, but static call graph, capabilities, bindings, routes, and account policies prove they are unreachable;
- tests use separate buckets and cleanup principals that cannot access production.

### 13.7 Aggregate resource model

One process hosts all TypeDB keyspaces. A global resource governor caps:

- total SlateDB memtables;
- block/object cache;
- reader prefetch;
- compaction buffers and concurrent jobs;
- checkpoint/digest buffers;
- RocksDB oracle resources in test profiles;
- TypeDB query/result memory;
- Tokio blocking and async task counts;
- local ephemeral disk use.

Per-keyspace allocations are children of the global budget, never independent maxima.

## 14. R2 object topology, data path, and real-service qualification

### 14.1 Bucket and administrative topology

Candidate production topology:

| Bucket/domain | Contents | Runtime mutation rights | Delete rights before G13 | Lock posture |
|---|---|---|---|---|
| authority | WAL payloads, control events, exact indexes, command ledgers, checkpoint/pin manifests | exact create/read only | none | indefinite or policy-duration Bucket Lock by coarse immutable prefix |
| materialisation | active SlateDB manifests/SSTs/checkpoints | writer/compactor scoped put/read | none | retention chosen to preserve active/recovery roots; no lifecycle deletion |
| scratch | verifier/rebuild/compaction orphanable outputs | attempt prefix put/read/abort-multipart | none | shorter policy where operationally appropriate |
| backup | copied verified closures | backup writer only | separate administrative policy | account-isolated Bucket Locks; not advertised as malicious-admin WORM |
| tests | conformance/chaos namespaces | test principals | isolated cleanup principal | never shares production parent credentials |

A separate bucket is preferred where one principal, lifecycle rule, or lock policy would otherwise span incompatible retention classes.

### 14.2 R2 Bucket Locks

R2 Bucket Locks can prevent overwrite and deletion for a duration, until a date, or indefinitely, and can apply by prefix. V16 uses them as an independent platform guard against accidental and runtime deletion.

They do **not** replace protocol reachability, pins, signatures, exact capabilities, backups, or an independent recovery anchor. An administrator able to change policy remains in the wider trust boundary; the system does not claim AWS S3 Object Lock API compatibility or immutable legal hold semantics.

Rules:

- use a small number of coarse, stable prefixes, not one rule per object;
- record the full lock policy and API response in every release;
- continuously verify that the expected rule set exists and is the strictest matching policy;
- Bucket Lock administration belongs only to the offline security/backup principal;
- no release depends on an unlocked interval between object creation and later policy application unless the real-account probe proves the intended semantics;
- lock-policy change is an authenticated administrative event and security incident when outside an approved change.

### 14.3 Object-class path selection

#### Class A — exact authoritative objects

WAL payloads, command results, control events, checkpoint/backup/pin manifests, exact index roots, and recovery metadata have exact key, digest, and length before upload. Use either:

- exact-operation presigned request;
- streaming gateway that validates a controller capability and returns a signed receipt;
- temporary credentials with explicit exact-object path plus only the required S3 actions.

A broad preset is not acceptable.

#### Class B — bulk orphanable objects

SlateDB SSTs and scratch outputs may use short-lived prefix-scoped temporary credentials with explicit actions. Stale uploads are inert until an epoch-fenced manifest publication. The credentials still contain no delete action.

#### Class C — maintenance reads/copies

Verifier/backup/recovery reads and copies use independent read/copy capabilities. They cannot publish active manifests or mutate the controller.

#### Class D — future deletion

A separately built and deployed delete worker appears only after G13. Its parent credential, Worker binding, routes, source feature, package and approval policy do not exist in the pre-G13 production release.

### 14.4 Temporary credentials and presigned operations

Current R2 temporary-credential presets named `object-read-write` include write actions that encompass `DeleteObject`/`DeleteObjects`. Therefore V1 runtime writers use:

- locally signed credentials with explicit action allowlists, when that path is qualified;
- or exact presigned operations;
- or the gateway.

Each credential is bound to one bucket, exact objects or prefixes, minimum action set, short TTL, audience/attempt where applicable, and a separately revocable parent. Parent revocation latency is probed and included in the stale-incarnation drill.

### 14.5 Application identity, checksums, and ETags

- canonical identity is `SHA256(exact_object_bytes)`;
- expected byte length is part of identity;
- R2 provider checksum headers are transport evidence only;
- CRC64/NVME full-object support may detect transport corruption but does not replace application SHA-256;
- provider SHA-256 for multipart is composite, not necessarily SHA-256 of the completed object bytes;
- ETag is an opaque version/conditional token, not a content digest;
- ambiguity is resolved by exact GET/range reconstruction and application hash, or a trusted streaming gateway receipt.

### 14.6 Multipart protocol

```text
MultipartAttempt {
  upload_attempt_id,
  exact_object_key,
  expected_object_sha256,
  expected_total_length,
  part_size,
  parts: [(part_number, offset, length, sha256)],
  credential_id,
  expiry,
  state
}
```

Rules:

1. `(upload_attempt_id, part_number)` is immutable to one offset, length, and digest.
2. A retry sends identical bytes for the same part.
3. Changed bytes, changed partitioning, or uncertain failed replacement allocate a new upload attempt.
4. Completion verifies ordered part manifests and then the completed object through application SHA-256.
5. Abandoned uploads are inventory-only before the future retention/delete profile.
6. No correctness path assumes a previous part remains after a failed overwrite attempt.

### 14.7 Ambiguous immutable write algorithm

1. write under exact operation identity and condition;
2. on transport ambiguity, read the exact key directly through the S3/Workers binding, not a cached public domain;
3. verify complete bytes or the qualified receipt;
4. exact match means resolved success;
5. absence means retry the same idempotent operation within deadline;
6. different bytes mean corruption/permanent conflict;
7. unverifiable outcome remains ambiguous and blocks dependent authority.

Strong consistency is useful evidence, not permission to weaken the exact-read verification protocol.

### 14.8 Gateway constraints

A gateway:

- streams request and response bodies without buffering full objects;
- hashes incrementally;
- respects Workers' isolate memory and simultaneous-connection limits;
- applies backpressure and bounded subrequests;
- cancels unused response bodies;
- rejects capability/key/action/length/digest mismatch before or during streaming;
- never signs success before remote outcome resolution;
- exposes no delete route pre-G13.

Large bulk SST traffic should bypass the gateway when a narrower direct credential is safer and materially cheaper.

### 14.9 Real-account conformance matrix

The exact selected SDK/package/account path must test:

- conditional create/update/read and conflict classification;
- strong read/list behavior without CDN caching;
- same-key concurrency and 429 overload;
- custom metadata round-trip;
- checksum headers for single and multipart objects;
- multipart create/upload/retry/complete/abort;
- failed same-part replacement behavior;
- exact credential action/path enforcement;
- expiration and parent revocation;
- presigned URL method/key/header binding;
- Bucket Lock create/overwrite/delete rejection, overlapping rules, existing/new objects, lock-policy audit;
- range and complete reads under faults;
- 5xx/reset/timeout/ambiguous success;
- streaming memory/CPU/connection bounds;
- absence of any production lifecycle-delete configuration.

All platform evidence names account, bucket, SDK, package lock, compatibility date, operation, raw response classification, and cleanup boundary.

## 15. Recovery and materialisation lifecycle

### 15.1 Replay modes

```text
AUTHORITATIVE_RECOVERY
  - current startup session + WriterEpoch;
  - may apply active keyspaces and advance controller visibility;
  - may append singleton status repairs through normal WAL;
  - may report readiness.

READ_ONLY_BUILD
  - immutable checkpoint/WAL/control inputs;
  - scratch MaterializationId + BuildEpoch;
  - runs the same resolver in memory;
  - writes only scratch keyspaces/manifests;
  - never appends authoritative WAL/status/statistics;
  - never advances controller visibility or activates itself.
```

The source-owner must inventory every normal recovery write and prove the mode split. A “one flag” estimate is not evidence.

### 15.2 Startup authoritative recovery

1. Verify controller incarnation, session, generation, materialisation, WriterEpoch, source/config/protocol.
2. Open all expected keyspaces with exact settings/epoch and no implicit compactor/checkpointer/GC.
3. Load active checkpoint, VisibilityWatermark, WAL/index/control heads, and memoised resolutions.
4. Verify checkpoint roots and keyspace identity.
5. Open a fixed-head durability iterator from the exact recovery floor.
6. Resolve every pending intent with the shared resolver.
7. Idempotently apply every positive resolution.
8. Advance VisibilityWatermark contiguously across commits/aborts.
9. Repair singleton status caches only after transaction truth is known.
10. Initialize raw-read consumers/generators only after partial apply is absent.
11. Report durable/resolved/visibility/materialised frontiers, raw-read initialization, task config, and fatal state.
12. Route only after controller verifies the report and readiness barrier.

### 15.3 Active materialisation corruption

On suspected corruption:

- stop routing/admission;
- revoke active writer/compactor authority;
- pin the corrupt materialisation for forensics;
- create a fresh scratch MaterializationId/BuildEpoch;
- restore/replay in READ_ONLY_BUILD;
- compute logical digest and semantic checks;
- perform quiesced final catch-up/cutover;
- never repair active state in place without a separately proven source operation.

### 15.4 Same-generation rebuild cutover

1. Scratch build starts from an immutable checkpoint/root and may replay to a captured fixed WAL head while the old active writer continues.
2. Enter `MATERIALIZATION_CUTOVER_QUIESCING`; stop new mutations and old active compactor/manifest publication.
3. Drain transactions, sequencer, resolver, apply, status/statistics, command finalisation, and automatic tasks.
4. Final-sync and capture the exact WAL/control/visibility head.
5. Replay scratch through that head and compare full digest/frontiers/inventory.
6. Freeze the scratch builder and scratch compactor; record their final physical SlateDB writer/compactor epochs and prove no publication-capable task remains.
7. Controller allocates a prepared-active startup session for the new materialisation with `SlateWriterEpoch` and `SlateCompactorEpoch` values strictly greater than every value stored/issued for that materialisation. The session has no WAL authority while the materialisation is not active.
8. A fresh active-holder process opens every keyspace with those exact physical epochs, attests readback, and passes a pause-resume negative test proving the old builder/compactor is fenced.
9. Revoke/advance the old active materialisation's writer/compactor authority.
10. In one controller transition, activate the new MaterializationId and prepared startup session; journal the cutover before routing.
11. Route only after readiness under the activated session. Retain the old materialisation under pin/rollback/forensic policy.

No mutation is admitted between final head capture and switch. A BuildEpoch value is never compared directly with a generation-global WriterEpoch; the physical per-materialisation SlateDB epoch domains provide the ordering proof.

### 15.5 Historical restore

Historical restore never overwrites the active generation:

1. select exact pinned checkpoint/backup roots and source provenance;
2. build/verify scratch materialisation;
3. stop old-generation admission and resolve/apply every durable intent that policy requires before cutover;
4. create a new monotonic DatabaseGeneration;
5. initialize `next_type_sequence = restored_visibility_watermark + 1`;
6. initialize a new AppendLsn lineage and fresh epochs/namespaces;
7. journal/anchor approval and generation cutover;
8. reject old-generation bookmarks/commands on the new generation;
9. retain the prior generation under policy.

Old TypeSequences may numerically equal or precede new-generation internal sequences only according to this continuation. Public generation identity prevents cross-generation bookmark confusion.

### 15.6 Reads during remote outage

A read proceeds only when the complete pinned snapshot closure required by its query is locally present and verified. A cache miss or uncertain closure fails the whole read. V1 may use the simpler fail-all-reads policy during R2 outage. Scans never map missing remote blocks to EOF.

---

## 16. Global checkpoint protocol

### 16.1 Controller ownership and quiescence

The remote profile disables TypeDB's interval checkpointer. Checkpoint creation is controller-owned.

V1 capture:

1. reserve checkpoint attempt/capability;
2. stop native and command mutation admission;
3. stop new command assignment and pre-intent execution;
4. drain open mutation transactions, durability sequencer, resolver, apply, status repair, Statistics updater, schema/import/migration writes, command finalisation, and automatic TypeDB tasks;
5. pause SlateDB compactor publication and all active-manifest checkpoint/protective maintenance;
6. require no unresolved intent whose outcome/apply crosses the cut;
7. sync the exact physical WAL/control prefix;
8. capture CheckpointCut and expected keyspace/extension inventory in one controller transition;
9. wait for `CheckpointCutCaptured` journal barrier;
10. hold quiescence while immutable keyspace contributions and expected source digest are captured;
11. pin candidate roots before releasing their source retention protection;
12. resume only after every source contribution is immutable and bound.

An online protocol is a future ADR/model/gate, not an optimization flag.

### 16.2 Keyspace contributions

Every expected TypeDB keyspace produces one authenticated contribution bound to database, generation, source materialisation, keyspace ID/role, exact cut, SlateDB checkpoint/manifest root and format, observed writer/compactor epochs, root closure seed, and digest. Missing, duplicate, extra, or mismatched contributions fail the candidate.

Catalog-pinned checkpoints are non-expiring. Temporary/protective checkpoint policy follows SL-P2 and is not pruned by unfenced Admin APIs.

### 16.3 Independent expected digest

While the source is stable at the cut, compute a full versioned logical digest independent of the scratch implementation:

- deterministic keyspace/range partitioning;
- visible logical key/value pairs at VisibilityWatermark;
- canonical framing of keyspace/key/value lengths and bytes;
- per-partition counts, byte totals, min/max, digest and Merkle root;
- schema/metadata/extension semantic summaries;
- algorithm/source/config versions.

The digest path uses ordinary MVCC-capped reads, not raw backend scans, unless a separately proved raw snapshot reader is used. It is bounded/streamed. Sampling is diagnostics only.

### 16.4 Candidate, verification, and activation

Build/upload/verify the immutable candidate manifest and root pin. A fresh process restores every keyspace under a scratch prefix, replays exact WAL tail in READ_ONLY_BUILD, validates resolutions/frontiers, computes the same digest, opens TypeDB, and runs semantic checks. It uploads a signed report but cannot activate.

Controller activation verifies exact candidate, pin, report, expected digest, generation/source/protocol, and policy, then journals `CheckpointActivated`. A checkpoint is a recovery root; it does not automatically replace the active materialisation.

### 16.5 Failure and pause budget

Failure never changes the active checkpoint. The source is resumed only after barrier teardown is safe; failed candidate roots remain attempt-pinned until classified. No single-process/operator flag can activate a failed candidate.

G10/G12 measure checkpoint pause and digest duration. If full quiescence violates the accepted availability objective, the architecture stops for a separately modelled online checkpoint protocol; it does not relax the cut.

---

## 17. Pins, backup, retention, and future GC

### 17.1 Root-first pins

`PinCreated` binds immutable root descriptors before closure enumeration. Protection begins after its journal barrier. `RELEASE_REQUESTED` remains protective; only journal-durable `PinReleased` ends protection. Unknown/failed release retains.

### 17.2 Backup classes

- **Operational copy:** same provider/account or nearby failure domain; fast but correlated.
- **Administrative-isolated copy:** separate R2 account/credentials/jurisdiction as policy requires; reduces account compromise and operator blast radius but is not WORM.
- **Immutable/offline disaster copy:** a separately qualified destination with immutability controls and independent keys/administration.

R2's S3 compatibility does not implement the AWS S3 Object Lock API. Native R2 Bucket Locks are configured and audited as defence in depth, but a same-provider copy is not described as malicious-administrator-proof WORM without an independently administered profile.

### 17.3 Backup creation

1. pin an activated checkpoint and exact WAL/control/command/source/config roots;
2. wait for pin barrier;
3. parse/enumerate the transitive closure with versioned parsers;
4. copy/verify deterministic objects to the declared destination;
5. create authenticated manifest with counts/bytes/Merkle root, encryption/key data, unknown/missing classification, and failure-domain statement;
6. restore into an isolated environment/materialisation;
7. replay to target and compare logical digest/semantics;
8. journal `BackupVerified` and create/update RecoveryAnchor;
9. release source pin only under policy and barrier.

A backup not restored within its policy window is unhealthy.

### 17.4 V1 retention posture

Pre-G13 production contains no object delete capability. It retains:

- all WAL payloads/descriptors/index segments;
- required control events/snapshots/anchors;
- active and retained generations/materialisations;
- activated/retained checkpoints;
- command ledgers and result objects under retention;
- active/release-pending pins;
- backup/restore/verifier/build/compaction attempts;
- unknown formats and safety grace windows.

Report-only inventory estimates growth and safe horizon.

### 17.5 Future destructive GC

Only after G13:

1. capture journal-durable root-set version and fencing state;
2. independently inventory and mark in bounded immutable shards;
3. unknown parser/format means live/failure;
4. two independent implementations/runs agree on exact candidate set;
5. grace period elapses;
6. controller revalidates root version, generations, materialisations, pins, attempts, formats, and age;
7. two-person approval binds exact candidate Merkle root and expiry;
8. issue one short-lived GC-only delete capability for exact shards/objects;
9. worker rechecks every object against current holds and deletes bounded batches with receipts;
10. restore/read canaries and zero-budget metrics stop work on any anomaly.

Before any WAL deletion, G13 additionally proves every source/application reader, `commit_record_exists` semantics, status/isolation context, Statistics latest lookup, checkpoint floors, command/no-intent lookup, legal/audit retention, and migration tooling. No wildcard prefix delete exists.

### 17.6 Safe horizon

Production measures daily byte/object growth under deletion off, compaction amplification, checkpoints, results, backups, and orphans. The safe horizon must exceed detection, approval, investigation, restore validation, and operator response policy. Otherwise production is blocked or G13 must pass first.


---

## 18. Cloudflare lifecycle, routing, rollout, transport, and shutdown

### 18.1 Database lifecycle versus container lifecycle

The database and container have separate state machines.

```text
DatabaseLifecycle:
ABSENT -> CREATING -> RECOVERING -> READY
READY -> CHECKPOINT_QUIESCING -> READY | DEGRADED
READY -> CUTOVER_QUIESCING -> RECOVERING | DEGRADED
READY -> HIBERNATING -> HIBERNATED -> RECOVERING
* -> FAILED_CLOSED
```

```text
ContainerLifecycle:
UNPROVISIONED -> START_REQUESTED -> STARTING -> PORT_READY
PORT_READY -> RUNNING -> STOP_REQUESTED -> STOPPED
* -> PLATFORM_ERROR | DESTROYED
```

A container becoming `RUNNING` is not database readiness. Database readiness requires controller-owned recovery and attestation barriers.

### 18.2 Controller/lifecycle DO protocol

`DatabaseControllerDO` sends idempotent lifecycle intentions to `DatabaseContainerDO`:

```text
EnsureContainerRunning {
  operation_id,
  database_id,
  generation,
  container_identity,
  deployment_envelope_digest,
  requested_image_digest,
  instance_shape,
  startup_reservation_digest,
  deadline
}
```

The lifecycle DO returns platform observations only. The controller then performs startup-session and epoch grants through its own SQLite/journal path. A lifecycle response lost or duplicated cannot allocate a second database session.

The two DOs may run in different locations. Latency and failure handling assume ordinary network RPC.

### 18.3 Container identity and startup attestation

The process proves:

- `ContainerIdentity` and fresh `ContainerProcessNonce`;
- actual image digest and server binary digest;
- source/config/protocol/format reader/writer sets;
- expected database/generation/materialisation;
- internal HTTP port and readiness challenge;
- effective SlateDB feature/config digest;
- delete-free credential/capability set;
- activated startup reservation possession.

Only then may the controller grant epochs and authorize recovery. Startup after process death always creates a new nonce, session, and higher physical epoch.

### 18.4 `sleepAfter`, hibernation, and shutdown

The Container helper's default inactivity shutdown is not accepted implicitly. Release configuration states one of:

- `sleepAfter` disabled/extended while a database is READY;
- custom `onActivityExpired()` that first asks the controller for a signed hibernation decision;
- explicit always-on policy.

A lifecycle DO cannot infer safe hibernation from request inactivity alone. It must not stop a container with open transactions, unresolved intent, checkpoint quiescence, active cutover, or required recovery work.

Shutdown:

1. controller stops new admission and routes;
2. session enters drain/revoke;
3. process stops accepting new work;
4. bounded transaction/storage queues drain;
5. optional flush/checkpoint optimization occurs without becoming correctness-critical;
6. process reports final observable frontiers;
7. controller advances epochs/revokes authority;
8. lifecycle DO requests stop;
9. SIGTERM handler exits within a bounded internal deadline substantially below the platform's forced-kill ceiling.

Arbitrary SIGKILL at every earlier point remains recoverable.

### 18.5 Rollout compatibility

Cloudflare deploys Worker code before all container instances have necessarily replaced their image, and rollout steps are not transactional. Therefore:

- Worker N must speak to image N−1 and N where explicitly declared;
- image N must reject unsupported controller schema/protocol tuples;
- durable formats use reader-before-writer rollout;
- controller migrations are expand/contract and never assume the rollout is complete;
- each request carries the deployment envelope digest;
- readiness is withdrawn when the observed image differs from the session grant;
- release completion requires observed convergence or deliberate retained mixed-version support;
- rollback retains every referenced image until rollback evidence expires.

Breaking Worker/image changes use an immediate rollout only to reduce—not eliminate—the mixed window.

### 18.6 Routing

The Edge asks `DatabaseControllerDO` for the current activated route/session. Routing caches are advisory and carry explicit freshness. A stale route yields typed retry/refresh, never authority.

`DatabaseContainerDO` proxies only HTTP to the container. End-user public access to the lifecycle DO is absent.

### 18.7 V1 transport

V1 exposes:

- external HTTPS BioAxiom/TypeDB HTTP facade;
- Worker/service-binding/RPC control calls;
- lifecycle DO to container HTTP proxy;
- container outbound HTTP/HTTPS only through explicit handlers/allowlists.

V1 does not claim native TypeDB TCP/gRPC ingress. That profile requires a new architecture document and platform capability, because current Container requests are Worker-mediated HTTP for end users.

### 18.8 Egress

`enableInternet = false` by default. Allowlisted outbound handlers cover only the controller/data-path hosts required by the release. Plain in-platform HTTP may be used only on the documented internal handler path; public Internet fallback is prohibited. HTTPS interception, when selected, installs the runtime CA at startup and fails readiness when unavailable.

Non-HTTP egress cannot be assumed to pass through HTTP interception.

### 18.9 Request limits and timeout semantics

Every edge/controller/lifecycle/container hop has independent connect, header, body-idle, operation, and total deadlines. Request and response bodies are bounded or streamed. Client disconnect never cancels a possibly finalised mutation; the operation remains queryable by identity.

### 18.10 Container platform qualification

G6/G12 test:

- cold starts and fresh ephemeral disk;
- lifecycle DO reset during start/stop;
- duplicate start/stop/status callbacks;
- rollout while active instances exist;
- Worker/image mixed versions;
- platform start-rate limiting and overload;
- `sleepAfter` and custom inactivity handling;
- SIGTERM and forced SIGKILL;
- lifecycle observation loss;
- controller/lifecycle DO geographic separation;
- HTTP streaming/backpressure;
- image registry pin/rollback;
- resource envelope and ephemeral-disk pressure.

## 19. Security, tenancy, credentials, and supply chain

### 19.1 Principal separation

Distinct principals exist for:

- end user/agent;
- Edge Worker;
- `DatabaseControllerDO`;
- `DatabaseContainerDO`;
- container writer session;
- compactor;
- scratch builder/verifier;
- object gateway;
- backup copy;
- report-only inventory;
- future delete worker;
- offline recovery coordinator;
- Bucket Lock administrator;
- CI/test cleanup.

No parent credential is shared across production runtime, backup administration, test cleanup, and future deletion.

### 19.2 Capability construction

Every capability binds:

- environment, bucket, database/generation/materialisation/attempt;
- controller incarnation and deployment identity;
- exact S3/HTTP methods or actions;
- exact object or prefix;
- expected digest/length when known;
- byte/request/concurrency ceiling;
- issue/not-before/expiry;
- audience, nonce, signer, and parent identity.

A path prefix without an action restriction is insufficient. A write scope that includes delete is treated as delete-capable even when application code promises not to call delete.

### 19.3 Parent revocation and incarnation rotation

Catastrophic controller recovery or security incident:

1. disables routing and capability minting;
2. acquires external recovery lock;
3. rotates controller incarnation;
4. revokes old parent credentials and signing keys;
5. advances logical/physical epochs;
6. updates gateway accepted incarnation/key roots;
7. proves old credentials, lifecycle DO, controller DO, and containers cannot create accepted authority;
8. only then activates fresh routing.

IAM revocation is measured as an eventually propagating control and is not the sole immediate fence.

### 19.4 Bucket policy and lock administration

- no public buckets or cached public domains for correctness reads;
- no production lifecycle-delete rules;
- Bucket Lock policy is exported and verified;
- Bucket Lock administration is unavailable to runtime Workers/containers;
- rule changes require two-person approval and an authenticated administrative event;
- unlocked scratch/test data is never a recovery root;
- bucket deletion is outside runtime authority.

### 19.5 Authentication and anti-replay

Every authoritative message carries signed or mutually authenticated caller identity, operation ID, request digest, deadline, generation, controller incarnation, deployment envelope, and exact authority fields. Nonces/operation IDs are persisted where replay changes state. Timestamp alone is not replay protection.

### 19.6 Data confidentiality

Keys contain opaque identifiers, not queries, user labels, prompts, or biomedical payloads. WAL/result/checkpoint contents use the approved encryption profile. Logs and traces never record TypeQL values, WAL bodies, credentials, prepared result bytes, or patient/biomedical data. Backup keys and administration are independent from production runtime.

### 19.7 Tenant isolation

V1 P-SINGLE still treats every namespace and capability as tenant/database-scoped. Tests prove:

- no cross-database prefix access;
- no command-ID collision across databases;
- no lifecycle DO can proxy another database without controller authorization;
- no shared cache broadens visibility;
- no test/backup credential reaches production authority.

### 19.8 Durable Object and Worker hardening

- SQLite procedures use parameterised SQL and generated constraints;
- control requests have body/row/statement/CPU/subrequest bounds;
- large CBOR/JSON parsers are length/depth/allocation bounded;
- overloaded errors are classified and shed/backed off rather than blindly retried;
- gateway streams and cancels bodies;
- source maps and diagnostics do not embed secrets;
- compatibility flags/dates are explicit and generated types are locked.

### 19.9 Supply chain

Release evidence contains:

- full source graph and licences;
- independent Cargo/pnpm lockfiles and vendored/content-verified dependencies;
- exact npm tarball integrity and source-package mapping;
- exact base image and native toolchain digests;
- SBOM and provenance;
- signed server/image/package attestations;
- compiler lane;
- test catalogue/results;
- Cloudflare contract/probe lock;
- patch provenance and upstream/removal plan;
- secret scan, dependency audit, and vulnerability disposition.

The TypeDB and SlateDB forks are reviewed as source modifications under their respective licences. External AGPL design references remain clean-room provenance only and are not build/source-lock dependencies.

## 20. Observability, SLOs, and cost

### 20.1 Structured dimensions

Every applicable trace/log/metric includes environment, database, generation, materialisation, controller incarnation, startup session, holder, writer/compactor/build epoch, command/attempt, AppendLsn, TypeSequence, VisibilityWatermark, ControlSeq, segment catalogue version, checkpoint/backup/pin/GC IDs, operation ID, digest prefix, source/config/protocol, error kind/retry class, and deadline remaining.

Payloads, raw TypeQL, prompts, secrets, and full results are excluded/redacted.

### 20.2 Required frontiers

Per database:

- WAL head, journal-durable head, sync-verified head;
- ControlSeq head/outbox lag;
- sequenced intent, resolved, VisibilityWatermark, and materialised frontiers;
- unresolved intent count/age;
- singleton status repair state/conflicts;
- partial apply state;
- command execution/outcome/result availability;
- segment catalogue versions and active tail rows/bytes;
- live iterator/no-intent catalogue pins;
- lifecycle/controller incarnation/session/epochs;
- checkpoint/backup/pin/recovery state;
- storage growth/safe horizon;
- queues, blocked TypeDB workers, memory permits, cursors;
- object operations/bytes/retries/ambiguity/latency;
- cache/compaction/read/write amplification.

### 20.3 Zero-budget metrics

- lost acknowledged WAL/transaction/command outcome;
- competing descriptor/control body;
- stale publication accepted;
- unfenced active Admin manifest mutation;
- duplicate/conflicting status accepted;
- ordinary read above VisibilityWatermark;
- raw read outside capability/lifecycle;
- command re-executed after intent;
- probabilistic absence authorizing retry;
- checkpoint activated without full verification;
- rooted object deleted;
- scratch touching active prefix/WAL;
- recovery selecting below trusted anchor;
- old controller incarnation producing accepted authority after recovery;
- unknown mandatory format accepted;
- current legitimate holder unexpectedly fenced.

### 20.4 SLO framework

Gates set numeric SLOs after measurement for read/native-write/command availability, append/sync latency, command phases, cold/warm recovery, RTO, checkpoint pause, verification duration, backup age/drill, storage horizon, controller/outbox lag, and capacity. RPO is zero only for acknowledged promises under the stated failure model; malicious-suffix-deletion RPO is bounded by independent anchor cadence unless synchronously anchored.

### 20.5 Internal cost ledger

Internal counters track controller operations/CPU estimates, journal objects/bytes, R2 operation classes/bytes/storage/egress, WAL/result/index/ledger/checkpoint/backup objects, container resources, compaction amplification, and verification/restore work. Provider billing reconciles/calibrates asynchronously; it never decides whether a correctness operation already in progress may finish.

---

## 21. Software-engineering and repository quality standard

### 21.1 Repository topology: federated upstream-shaped workspaces

```text
bioaxiom-typedb-r2/
  source-lock/
    source-lock.json
    platform-contract-lock.json
    workspace-lock.json
    evidence/
  fork/
    typedb/                 # upstream tree and Cargo workspace preserved
      Cargo.toml
      Cargo.lock
      xtask/ or tool/ hooks
    slatedb/                # upstream tree and Cargo workspace preserved
      Cargo.toml
      Cargo.lock
  tools/                    # fork-owned Rust workspace
    Cargo.toml
    Cargo.lock
    xtask/
    corpus-catalog/
    conformance-runner/
    protocol-models/
    format-vectors/
    evidence/
  control-plane/            # pnpm workspace
    pnpm-lock.yaml
    controller/
    container-lifecycle/
    gateway/
    edge/
    generated/
  infra/
    wrangler/
    images/
    policies/
    probes/
  fixtures/
    typedb-behaviour/
    console/
    bazel-evidence/
  docs/
    implementation-brief-v16.md
    ADR/
    runbooks/
```

TypeDB and SlateDB retain their own roots, workspace members, profiles, patches, and lockfiles. The fork does not create a giant Cargo workspace that changes feature unification, profile selection, target layout, or upstream paths.

`workspace-lock.json` binds all workspaces and products:

```text
WorkspaceLock {
  source_graph_digest,
  typedb_cargo_lock_digest,
  slatedb_cargo_lock_digest,
  tools_cargo_lock_digest,
  pnpm_lock_digest,
  native_toolchain_digest,
  rust_parity_toolchain,
  rust_qualification_toolchain,
  resolved_feature_sets,
  fixture_manifest_digest,
  platform_contract_lock_digest,
  server_binary_digest,
  image_digest
}
```

### 21.2 Normative command boundary

Normative entry points are:

```text
cargo xtask source-lock
cargo xtask catalog-upstream-tests
cargo xtask verify-cargo-parity
cargo xtask test-upstream --profile U0|U1|U2|U3|U4
cargo xtask package-server
cargo xtask package-upstream-test-dist
cargo xtask crash-suite
cargo xtask model-check
cargo xtask evidence

pnpm --frozen-lockfile ...
pnpm test
pnpm typecheck
pnpm wrangler ...             # exact locked version
```

A repository-level shell/Make/task-runner wrapper may order these commands. It may not own manifests, infer test cases, rewrite feature sets, alter gate pass/fail, or become required to reproduce a product. Any optional orchestrator is pinned and attested but can be removed without semantic change.

### 21.3 Module boundaries

Owned Rust crates/modules include:

```text
typedb-storage-api
typedb-rocksdb-adapter
typedb-slatedb-adapter
typedb-durability-api
typedb-remote-wal
typedb-transaction-resolver
controller-protocol
controller-reducer-model
object-capability-model
checkpoint-model
retention-model
recovery-model
corpus-catalog
conformance-runner
test-sandbox
release-evidence
```

Control-plane packages include independent database controller, container lifecycle, gateway, edge, schemas, and generated vectors. No concrete engine type crosses its adapter.

### 21.4 Error discipline

- no panic/abort for network, object, controller, fencing, format, overload, or capacity conditions;
- exhaustive typed mapping and retry class;
- ambiguity means exact status query, not blind retry;
- terminal database state is explicit and queryable;
- no ignored result or detached durability mutation;
- close/drop errors are observable but cannot rewrite prior truth;
- platform overload and lifecycle errors are distinct from fencing.

### 21.5 Concurrency discipline

Every actor/queue/permit pool has bounded count and bytes. Locks are ordered and never held across uncontrolled network awaits. Cancellation has a written effect boundary. The controller uses one SQLite transaction as the online linearisation point and never assumes that JavaScript single-threading prevents interleaving across arbitrary `await`.

### 21.6 Durable-format discipline

Every durable object/event/schema has numeric ID, version, deterministic encoder, parser budget, compatibility matrix, golden/negative/fuzz vectors, root-closure parser, key/signature policy, and migration/rollback rule. Rust and TypeScript vectors must match byte-for-byte.

### 21.7 Configuration discipline

Correctness options are typed, explicit, sanitized, hashed, and attested. Library defaults, environment names, Worker compatibility-date defaults, npm semver ranges, and Cargo default features cannot silently change behavior.

### 21.8 Patch review template

Every patch states:

- invariant/gate ownership;
- source evidence and caller graph;
- exact behavior delta;
- failure/ambiguity semantics;
- model/unit/upstream/differential/failpoint tests;
- negative control;
- observability;
- durable-format/config/package/corpus impact;
- performance/cost;
- unsafe audit;
- upgrade/rollback;
- upstream/removal criterion.

Refactor, semantic protocol, generated output, and formatting churn are separate commits.

### 21.9 Static and dynamic gates

For each exact declared feature/profile set:

- `cargo fmt --all --check`;
- `cargo clippy --workspace --all-targets --locked -- -D warnings`;
- build/test/doc/bench compilation through the catalogue runner;
- dependency, licence, SBOM, provenance and vulnerability policy;
- Miri and sanitizers where supported;
- parser/reducer/index/iterator fuzzing;
- mutation/property/failpoint tests;
- no engine leakage above adapters;
- no active SlateDB Admin mutation;
- no production delete capability;
- no JS `number` for authoritative 64-bit values;
- no unresolved correctness TODO/FIXME without a stop item;
- TypeScript strictness, runtime schema validation, no unawaited authority mutation;
- package/image/tested-binary identity.

`--all-features` is not a release gate unless the catalogue explicitly defines that feature combination as meaningful. It may be a compile-smoke lane only.

### 21.10 Cargo manifest ownership and rebase

TypeDB's committed generated Cargo manifests are the migration seed. The fork:

1. archives pristine Cargo/BUILD/Starlark hashes;
2. makes TypeDB Cargo manifests fork-owned;
3. keeps SlateDB's workspace independently fork-owned;
4. adds fork crates with upstream-shaped paths;
5. replaces Bazel sync in fork workflows with a Cargo/source-graph auditor;
6. compares upstream Cargo and BUILD changes separately on rebase;
7. fails on unexplained dependency, target, feature, fixture, or package drift.

The auditor does not claim to evaluate arbitrary Starlark unless Mode Q provides a locked query result. Unknown macros fail G0.

### 21.11 Test runner and sandbox

The runner uses Cargo JSON build messages, locked libtest listing, and explicit composite-harness enumeration. It stages exact fixture, cwd, environment, ports, credentials, data directory, R2 bucket/prefix, DO namespace, compatibility date, and timeout. It kills complete process trees and records raw/normalized results, deterministic seeds, source/toolchain/config/package digests, and remote namespace.

Timeout, zero tests, skip, missing fixture, early success, filtered-out case, or incomplete report is failure unless the checked catalogue explicitly classifies it.

### 21.12 Package identity

Two packages share one server binary:

- production Cloudflare server image;
- upstream-compatible test distribution with additional locked fixtures.

Two clean path-remapped offline builds must produce the same server binary digest. The image references the binary by digest and the conformance evidence proves that the tested binary is the image payload.

### 21.13 Cloudflare package/source mapping

For each shipping npm package:

- exact version and tarball integrity;
- source repository and full commit;
- generated/bundled files mapping;
- licence;
- transitive runtime package lock;
- compatibility date/flags;
- local-runtime version;
- real-platform probes.

A package version without a source mapping is an unresolved source node, not a completed G0 record.

## 22. Verification strategy

### 22.1 Executable models before production reducer/client

Build deterministic models for:

1. WAL allocation/finalisation/status singleton/sync/fixed iteration/archival;
2. controller incarnation/session/epoch fencing;
3. prefix resolver/resolution/apply/VisibilityWatermark;
4. command reservation/no-intent/result/outcome/ledger;
5. checkpoint quiescence/candidate/verification/activation/cutover;
6. pins/backup/report-only GC/future deletion;
7. control journal/snapshot/anchor/reconstruction/format migration.

Models enumerate crash, retry, reorder, timeout, stale actor, and mixed-version points. Production traces replay against them.

### 22.2 Complete upstream TypeDB test corpus

The locked denominator is the union of:

- Cargo package unit tests, integration tests, doctests, examples/benches used as tests, and explicit root `[[test]]` targets;
- direct Bazel `rust_test`, crate-unit-test wrappers, shell/crash tests, assembly tests, formatting/checkstyle tests, release/dependency validations, and test-producing macros;
- source-level `#[test]`, `#[tokio::test]`, generated behavior scenarios, failpoint registry iterations, and declared ignored tests;
- required fixture/data/runfile/env/platform/timeout metadata.

The pinned source already demonstrates that Cargo exposes major suites: root behavior/HTTP/query/assembly/failpoint targets and per-crate storage/durability tests. It also demonstrates the risk: Cargo manifests are generated by a Bazel-invoking sync script, while assembly tests rely on Bazel-provided archive/data/env. V16 therefore locks the following catalogue rather than relying on accidental Cargo discovery:

```text
UpstreamTestTarget {
  target_id,
  origin,                       // CARGO | BAZEL_DIRECT | BAZEL_MACRO | SHELL | STATIC_CHECK
  upstream_label?,
  cargo_package?, cargo_target?,
  source_files_and_sha256,
  case_discovery,               // LIBTEST_LIST | CUCUMBER_SCENARIOS | FAILPOINT_REGISTRY | SCRIPT | STATIC_CHECK
  platform_predicate,
  feature_and_cfg_set,
  env,
  data_and_external_fixtures,
  working_directory,
  timeout,
  serial_and_resource_group,
  profile_applicability,
  port_status,                  // BYTE_IDENTICAL | LAUNCHER_ADAPTED | SEMANTIC_PORT
  exclusion?, owner?, expiry?,
}
```

A passing catalogue has zero unknown origin, target, macro, case, fixture, or applicability. Counts are filled from the real checkout and stored in the release evidence; this document does not invent them. A composite Rust test that loops over many scenarios counts each scenario/failpoint as a leaf case, not as one opaque green case.

### 22.3 Coverage definition

Report separately:

1. **target coverage** = executed applicable targets / applicable targets;
2. **leaf-case coverage** = executed libtest/scenario/failpoint/script/static cases / applicable discovered leaf cases;
3. **profile coverage** = required `(case, profile)` pairs executed / required pairs;
4. **fixture coverage** = verified/staged fixture sets / required fixture sets;
5. **port fidelity** = byte-identical, launcher-adapted, semantic-port, excluded;
6. **negative-control coverage** for correctness-critical invariants.

Release requires 100% target, leaf-case, fixture, and required-profile coverage. “Not run because Cargo did not discover it”, `#[ignore]`, missing credentials, platform mismatch, timeout, or dynamic skip is not a pass. Platform-inapplicable and manual signing/deployment actions may be excluded only by a checked predicate and rationale; they remain visible in the denominator report.

### 22.4 Test execution profiles

```text
U0  pristine pin: RocksDB + file WAL
U1  fork after safe boundaries: RocksDB adapter + file WAL
U2  candidate KV: SlateDB LocalFS + file WAL
U3  candidate storage: SlateDB LocalFS + remote-WAL/controller model
U4  production parity: SlateDB R2 + real DO/data path + Cargo-built release server
```

Rules:

- U0 establishes upstream failures, flakiness, case list, and behavior before modifications.
- U1 must run the identical applicable corpus after each oracle-preserving refactor; any difference is a fork regression.
- Every storage-independent test required by U1 is also required under U2.
- Storage/durability/recovery/checkpoint/failpoint suites are required under U3.
- The complete applicable behavior, HTTP, assembly, failpoint, storage, recovery, and query corpus is required under U4 pre-release; nightly cadence may shard it, but release evidence is one coherent source/config/toolchain set.
- A physically RocksDB-specific assertion is classified explicitly and receives a backend-neutral semantic replacement under U2–U4; it is not counted as a candidate pass merely because it ran only on U1.

### 22.5 Preservation and backend parameterisation

Upstream test files are hashed at the pin. Backend/profile selection is injected through central test/application configuration, factories, CLI/config files, and the package launcher—not by editing each test. G0 inventories every direct test construction of RocksDB, `Keyspace`, `MVCCStorage`, file WAL, checkpoint directory, `DatabaseManager`, and server process.

A source edit to an upstream test requires:

```text
TestPortRecord {
  upstream_test_id,
  original_sha256,
  ported_sha256,
  exact_diff,
  reason,
  semantic_equivalence_argument,
  negative_control,
  reviewer,
  removal/upstream_plan
}
```

Where possible, assembly/failpoint tests remain byte-identical by reproducing their archive name, environment, package layout, console fixture, script, working directory, and process behavior externally.

### 22.6 Cargo test runner semantics

The normative runner uses Cargo and libtest directly. It must:

- compile with exact profile-specific features/cfg/env, never blanket `--all-features` unless that exact combination is declared valid;
- discover binaries from Cargo JSON messages, reproduce Cargo's runtime target environment, and discover libtest plus composite-harness leaf cases;
- run normal and upstream-declared ignored cases according to catalogue policy;
- enforce per-target/leaf-case timeout and serial/resource groups;
- allocate collision-free ports and isolated data/R2/DO namespaces;
- record property-test seeds and failpoint directives;
- kill and reap complete process trees;
- detect zero-test binaries, unreported composite-harness scenarios, filtered-out cases, missing runfiles, and early successful exit;
- prohibit automatic retry from changing the gate result;
- preserve raw logs and normalized structured results.

### 22.7 Assembly, failpoint, and crash tests without Bazel

The root Cargo package already names assembly and failpoint integration tests, but Bazel currently supplies `TYPEDB_ASSEMBLY_ARCHIVE`, the package archive, and fixture runfiles. `cargo xtask package-upstream-test-dist` reproduces those inputs from the Cargo-built server:

- same archive naming/platform convention expected by the test;
- same wrapper/server/config layout needed by `typedb ...` commands;
- pinned TypeDB Console fixture, exact digest/licence/provenance;
- `tests/assembly/script.tql` staged at the expected path;
- isolated working directory and data directory;
- explicit timeout/serial execution;
- server binary digest equality with the release image.

Durability crash streamer/recoverer binaries and shell loops become Rust `xtask` scenarios supervising Cargo-built processes. The original commands, timing/failpoint semantics, and expected recovery assertions remain in the catalogue and regression ledger.

### 22.8 Differential suites

- pinned RocksDB before/after safe boundary;
- file WAL versus remote-WAL model, including fixed iterator head and status singleton;
- RocksDB versus SlateDB LocalFS over all TypeDB keyspaces;
- live validation versus recovery versus READ_ONLY_BUILD resolver output;
- SQLite projection versus pure reducer replay;
- source checkpoint digest versus scratch restore/replay;
- command result/outcome before/after crash/expiry;
- active-tail versus archived exact lookup/no-intent proof.

Upstream test outcomes are compared structurally across U0–U4: result sets, errors, transaction outcomes, visibility, persisted state digests, and recovery frontiers—not merely process exit codes.

### 22.9 Test efficacy and negative controls

Critical protections must demonstrate that the tests can fail. Required mutants/negative controls include at least:

- wrong range bound/prefix/floor behavior;
- `dirty=true` or remote-only SlateDB read visibility;
- non-atomic per-keyspace batch;
- watermark advancement before complete apply;
- dropped WAL payload/control event before sync;
- moving-head iterator;
- duplicate/conflicting status acceptance;
- stale epoch/Admin publication acceptance;
- response loss followed by duplicate command execution;
- checkpoint contribution from a different cut;
- missing object mapped to EOF;
- condition downgrade or ETag-as-digest;
- package test accidentally running a different server binary.

Mutation tools may assist, but committed hand-written fault switches are preferred for load-bearing protocol invariants.

### 22.10 Deterministic failpoints

Kill/fail before/after payload capability/upload/receipt, WAL finalisation/event/outbox publication, sync capture/wake, iterator snapshot/catalogue pin, status dedupe/conflict, every resolver predecessor read/certificate, resolution event, each keyspace apply/watermark, status repair, command result binding/intent/final envelope, segment prepare/activate/prune, every SlateDB publication/Admin path, checkpoint quiesce/contribution/digest/pin/candidate/verify/activate, materialisation catch-up/cutover, pin/backup, anchor publication, controller-incarnation recovery, key/format rotation, and G13 deletion phases.

### 22.11 Stale actor matrix

Pause writer/compactor/builder/Admin/old-controller at every publication/finalisation site; advance epoch/incarnation, progress replacement, resume stale actor. Allowed result: typed fenced/revoked and orphan bytes. Forbidden: reachable metadata, accepted finalisation/event/receipt, visibility advancement, or routing authority.

### 22.12 Cross-keyspace visibility

For N keyspaces, crash after every physical subset/order. Concurrent readers restart repeatedly. No reader observes a subset above VisibilityWatermark; final oracle state matches; positive resolution never changes; transaction never re-executes.

### 22.13 Command matrix

Crash at reservation, approval, assignment, transaction execution, prepared-result upload, result binding, intent finalisation/sync, resolution, every apply, visibility, final envelope, terminal event, response, result expiry, and ledger archival. Test same/different digest, old generation, segment lookup outage, catalogue race, and no-intent proof. Prove one intent, immutable outcome, exact result or expiry, and permanent nonreuse.

### 22.14 Real-platform chaos

Inject R2 throttling, 5xx, resets, ambiguous success, concurrent conditions, multipart interruption, partial/corrupt reads, credential expiry/revocation, gateway memory/CPU pressure, Worker rollout/disconnect, DO restart/outbox lag, container kill, and stale controller route. Verify no condition downgrade, no partial read, and all bounds.

### 22.15 Long soak and upgrades

Representative BioAxiom schema/data/query/command workloads across all keyspaces, compaction, repeated checkpoint/backup, hibernation, archival, controller restarts, report-only GC, format/key rotation, and rolling deployment. Measure memory/object/request/cost amplification, safe horizon, RTO, digest drift, status repair, iterator/catalogue retention, test-corpus drift, and zero-budget metrics.

V1 validator upgrades drain unresolved intents; the broader compatibility matrix still covers readers, formats, controller, gateway, verifier, recovery tools, Cargo manifests, test fixtures, and package layout.

## 23. Patch series and ownership

Patch identifiers are stable. The implementation playbook references only these identifiers.

### 23.1 TypeDB patches

- **TB-P0 — source evidence and inventories:** no behavior change.
- **TB-P1 — safe RocksDB cursor ownership:** remove forged lifetimes while RocksDB remains the only backend.
- **TB-P2 — TypeDB-owned `KvEngine`, resources, and raw-maintenance boundary:** no semantic change.
- **TB-P3 — fully fallible durability/session/iterator interface:** file WAL remains oracle.
- **TB-P4 — remote allocation/finalisation, physical sync, operation identity, and fixed iterator snapshots.**
- **TB-P5 — singleton status protocol and shared pure transaction resolver.**
- **TB-P6 — explicit `AUTHORITATIVE_RECOVERY` and `READ_ONLY_BUILD`; append prohibition and status repair.**
- **TB-P7 — SlateDB adapter/runtime/read options/all keyspaces/raw-read lifecycle.**
- **TB-P8 — visibility/apply instrumentation and source background-task control:** disable interval checkpointer; fallible Statistics updater.
- **TB-P9 — global checkpoint, rebuild/cutover, historical restore, and sequence continuity.**
- **TB-P10 — Cargo-only build/test/package ownership and upstream-drift enforcement.**

### 23.2 SlateDB patches

- **SL-P0 — source/feature/config/publication/Admin/delete inventory:** no behavior change.
- **SL-P1 — exact externally supplied `SlateWriterEpoch` and `SlateCompactorEpoch` at every publication path; `BuildEpoch` remains controller attempt authority.**
- **SL-P2 — suppress unnecessary protective checkpoints when internal deletion is disabled, or provide fenced writer-owned maintenance; ban unfenced active Admin mutation.**
- **SL-P3 — explicit standalone compactor start/drain/revoke and epoch injection where required.**
- **SL-P4 — fail-closed object-store retry, conditional, metadata, and iterator error behavior where the pinned source is insufficient.**

### 23.3 Build and conformance patches

- **BT-P0 — source graph and federated workspace bootstrap:** toolchains, lockfiles, vendoring, offline proof.
- **BT-P1 — upstream corpus catalogue:** Cargo metadata/libtest, Bazel AST/query oracle, Cucumber/failpoint/script/static cases, applicability and exclusions.
- **BT-P2 — conformance runner/sandbox:** fixture/env/cwd/timeout/resource/process/evidence semantics.
- **BT-P3 — backend/profile injection:** central factories and U0–U4 profile matrix; direct-constructor inventory.
- **BT-P4 — Cargo packaging:** one binary for test distribution and production image; fixture/source/package identity.
- **BT-P5 — rebase/corpus/package drift:** zero unknowns, baseline flake evidence, release evidence bundle.
- **BT-P6 — dual Rust qualification:** parity lane, patched-stable lane, compiler/package differential and selection evidence.

### 23.4 Database controller and object path

- **CT-P0 — canonical schemas, reducer, models, event catalogue.**
- **CT-P1 — SQLite procedures, transactional outbox, budgets, overload admission.**
- **CT-P2 — controller incarnation, startup reservations, sessions, logical/physical epochs.**
- **CT-P3 — WAL finalisation, status singleton, sync, fixed iterator and exact lookup.**
- **CT-P4 — journal, snapshots, independent anchor, catastrophic reconstruction.**
- **CT-P5 — bounded WAL/command exact indexes and catalogue pins.**
- **CT-P6 — command reservation, approval, result, no-intent, resolution and terminal outcome.**
- **CT-P7 — checkpoint, materialisation, pins, backup and cutover.**
- **CT-P8 — report-only retention; no delete profile.**

- **DP-P0 — object class, bucket topology, capability and credential selection.**
- **DP-P1 — gateway streaming and signed receipts.**
- **DP-P2 — exact presigned and action/path-scoped temporary-credential paths.**
- **DP-P3 — multipart attempt protocol and checksum/ambiguity handling.**
- **DP-P4 — maintenance read/copy and backup profile.**
- **DP-P5 — separately built future delete worker after G13 only.**

### 23.5 Cloudflare lifecycle and deployment patches

- **CF-P0 — official docs/source/package contract lock and real-account probe harness.**
- **CF-P1 — `DatabaseContainerDO` lifecycle class separated from `DatabaseControllerDO`.**
- **CF-P2 — deployment compatibility envelope, mixed-version rollout, readiness and rollback.**
- **CF-P3 — alarm/outbox worker discipline, persistent schedules, overload/backoff.**
- **CF-P4 — HTTP-only internal/external routing, egress allowlist and shutdown.**
- **CF-P5 — Bucket Lock policy generation/audit and delete-free credential policy.**

Every patch names owner, reviewer, upstream/removal criterion, rebase test, and affected gates. No “temporary” patch exists without a removal condition.

## 24. Release gates G0–G14

Every gate is machine-verifiable, versioned, source/config/account-specific, and archives immutable evidence. Waivers may remove a feature or stop a release; they cannot weaken safety invariants.

### G0 — Complete source, toolchain, corpus, and document truth

**Requires**

- complete source graph, package/source mapping, licences, base images and native tools;
- selected Bazel evidence mode;
- federated Cargo/pnpm lockfiles and offline sources;
- resolved production/test feature sets;
- complete source inventories;
- complete target/leaf-case/fixture/profile catalogue;
- Cloudflare contract lock;
- document/schema/event/patch/gate consistency.

**Pass**

- clean immutable source retrieval and integrity;
- Rust parity lane builds offline;
- candidate target/case counts generated, not manually asserted;
- zero unknown macro, fixture, package source, feature, or platform predicate;
- duplicate Appendix/source-lock/count contradictions eliminated;
- exact `typedb-behaviour`, TypeQL, protocol, Console/Loader, dependencies, distribution and base-image nodes resolved;
- no source fact lacks evidence.

**Failure:** only research, catalogue tooling, models and platform probes continue.

### G1 — Models, platform contracts, budgets, and toolchain qualification

**Requires**

- pure models for WAL/status/iterator, resolver/apply, commands, epochs/incarnation, checkpoint/retention, journal/anchor;
- dual Rust lane comparison;
- current Workers/DO/R2/Containers limits and package/source contracts;
- bounded configuration;
- controller/container lifecycle separation model.

**Pass**

- model/property traces satisfy invariants;
- SQL/reducer trace equivalence;
- toolchain selection approved;
- DO interleaving, alarm and overload models green;
- source/package/docs contract lock green;
- every bound has admission and fail-closed behavior.

### G2 — Remote append, R2 data path, and amplification kill gate

**Requires**

- standalone Rust client;
- model controller and real `DatabaseControllerDO`;
- real R2 staging account;
- exact object-class paths, credentials, Bucket Locks and multipart attempts;
- sequenced/unsequenced/status/sync/fixed iterator prototype;
- per-record and candidate batching measurements.

**Pass**

- no sequence/LSN holes;
- exact lost-response resolution;
- singleton status behavior;
- finite iterator;
- delete-free credentials proven;
- Bucket Lock behavior proven;
- checksum/multipart/conditional/ambiguity tests green;
- p99/throughput/cost/storage/outbox within approved envelope or a fully modelled segment format replaces the baseline.

**Failure:** stop broad TypeDB/SlateDB semantic work.

### G3 — Safe TypeDB boundaries and U0/U1 parity

**Requires:** `TB-P1`–`TB-P3`, `BT-P0`–`BT-P3`, RocksDB/file-WAL oracle, source inventories.

**Pass**

- 100% applicable upstream corpus green under U0 and U1 with structured equality;
- no forged cursor lifetime on new path;
- all durability errors typed;
- raw calls classified;
- upstream background tasks controlled;
- no upstream test edit outside the port ledger;
- server package identity established.

### G4 — Shared resolver, status, and recovery modes

**Requires:** `TB-P5`, `TB-P6`, fixed-prefix resolver, singleton status, authoritative/scratch modes.

**Pass**

- identical verdict/apply plan across live/recovery/scratch;
- duplicate/conflicting/missing status matrix;
- no missing-status panic;
- finite deterministic input basis;
- READ_ONLY_BUILD cannot append;
- drain-and-replace validator upgrade proof.

### G5 — SlateDB LocalFS semantics and publication fencing

**Requires:** `TB-P7`, `SL-P1`–`SL-P3`, production feature allowlist, full publication/Admin/delete inventory, U2.

**Pass**

- all applicable storage-independent upstream cases under U2;
- RocksDB/SlateDB differential;
- immediate visibility and snapshot/range/error semantics;
- every publication path pause–fence–resume;
- exact writer/compactor physical epoch readback;
- no active Admin mutation;
- explicit compactor lifecycle;
- production binary excludes prohibited features/delete paths.

### G6 — Production Cloudflare object and container path

**Requires:** `DP-P0`–`DP-P4`, `CF-P0`–`CF-P5`, real R2/DO/Containers, exact packages/account/config.

**Pass**

- real-R2 conformance and chaos;
- controller/lifecycle DO separation;
- mixed-version rollout and lifecycle reset tests;
- HTTP streaming/backpressure;
- egress allowlist;
- no non-HTTP V1 dependency;
- credential expiry/revocation;
- Bucket Lock audit;
- no condition downgrade or error-to-EOF;
- container kill/restart with no acknowledged loss;
- resource and cold-start evidence.

### G7 — Controller journal, exact indexes, anchor, and reconstruction

**Requires:** controller SQLite/outbox/events/snapshots, exact WAL/command catalogues, independent anchor, incarnation rotation, offline recovery tool.

**Pass**

- reconstruction from immutable history;
- exact absence proofs;
- bounded controller state;
- alarm/outbox catch-up after resets;
- old controller/lifecycle DO/credentials rejected after recovery;
- anti-rollback drill;
- competing valid heads quarantine.

### G8 — End-to-end remote WAL and transaction recovery

**Requires:** `TB-P4`–`TB-P8`, U3, crash/failpoint matrix.

**Pass**

- every successful native commit recoverable with local state removed;
- intent/resolution/apply/visibility distinctions preserved;
- partial cross-keyspace apply hidden and completed;
- sync/iterator/status behavior matches oracle;
- arbitrary process death at every boundary produces one allowed state.

### G9 — Command outcomes

**Requires:** `CT-P6`, exact result modes, permanent ledger, no-intent proofs, approval rules.

**Pass**

- one intent per command;
- no re-execution after intent;
- exact stored result or deterministic expiry metadata;
- old-generation behavior;
- exact no-intent race proof;
- external effects remain idempotent outbox only.

### G10 — Global checkpoint, rebuild, and cutover

**Requires:** `TB-P9`, controller checkpoint/materialisation protocol, all keyspaces/extensions, quiescence inventory.

**Pass**

- one exact cut;
- fresh-process restore/replay and independent logical digest;
- stale builder fenced during active transition;
- old materialisation retained;
- measured pause and verification duration within objective or architecture stops.

### G11 — Pins, backup, security, supply chain, and restore

**Requires:** root-first pins, backup profiles, security threat model, key/credential rotation, SBOM/provenance/licence, isolated restore.

**Pass**

- no root released early;
- account-isolated backup restored and verified;
- Bucket Locks and backup claims stated precisely;
- independent keys/administration;
- no high/critical unaccepted issue;
- offline reproducible release;
- complete source/package/platform evidence.

### G12 — Capacity, SLO, cost, rollout, and soak

**Requires:** representative BioAxiom workloads, standard-4 envelope, controller/load tests, rolling deployments, repeated recovery/checkpoint/backup.

**Pass**

- approved headroom for memory/CPU/disk/queues/DO storage;
- latency/availability/RTO/pause/object/cost budgets;
- no overload retry storm;
- mixed rollout converges;
- 72-hour release-candidate soak with zero zero-budget breach;
- V1 indefinite WAL retention has an approved safe horizon.

### G13 — Optional destructive GC and physical retention reduction

Not required for initial production. Until green, the release contains no delete worker, credential, route, feature or lifecycle rule.

**Pass requires**

- complete reader/root/format inventory;
- Bucket Lock interaction and retention windows;
- candidate-set capability bound to exact digest;
- quiesced/fenced two-phase deletion;
- parser-version safety;
- two-person approval;
- restored backup;
- negative tests for every protected root;
- separate source/build/deployment profile.

### G14 — Final production release

**Requires:** G0–G12 green; G13 only if deletion is shipped.

**Pass**

- one exact release manifest binds source graph, patches, toolchains, features, packages, compatibility date, account profile, tests, models, probes, server/image, configuration, runbooks and residual risks;
- tested binary equals shipped binary;
- release owner, operations owner, stop authority and rollback are named;
- no unresolved architecture-stop item;
- deployment convergence and stale-version rejection observed;
- prior image/source/reader retained for the declared rollback window.

## 25. Performance and capacity qualification

The maximum current Container shape used as the design ceiling is 4 vCPU, 12 GiB RAM, and 20 GB ephemeral disk. The actual release may choose a smaller shape but cannot assume a larger one without a new contract lock. One SQLite-backed Durable Object has a 10 GB hard storage ceiling, 2 MB row/value ceiling, a soft approximately 1,000 requests/s limit, default 30-second configurable CPU ceiling, and six simultaneous outgoing connections per invocation. Workers isolates have 128 MB memory and six simultaneous initial outgoing connections.

These are platform maxima, not configuration targets. V16 initially caps controller SQLite well below the hard limit and stops admission before archival lag can threaten it.

Measure the exact production build/account/profile with:

- all TypeDB keyspaces and representative schema/data/query distributions;
- native and command transactions;
- WAL/status/Statistics frequency;
- controller request/transaction/outbox/index amplification;
- R2 object and request amplification;
- gateway and direct-path streaming;
- compaction and checkpoint/digest/restore;
- hibernation/cold start/rollout;
- repeated controller/lifecycle DO resets;
- active-tail archival and exact lookup;
- concurrent readers/cursors and failpoints.

Report separately:

- queue wait;
- TypeDB computation;
- payload upload;
- controller finalisation;
- outbox/journal barrier;
- resolution;
- per-keyspace apply;
- visibility advancement;
- result finalisation;
- SlateDB flush/compaction;
- container cold start and recovery;
- lifecycle/controller RPC;
- Worker/gateway CPU, memory, subrequests and connection waits.

For each, record p50/p95/p99/max, cold/warm, steady/burst, failure tails, confidence interval, object/byte/request cost, and 24-hour plus 72-hour soak.

Release configuration bounds transaction duration/bytes/keys/keyspaces, result size, WAL object size, multipart shape, concurrent transactions/reads/cursors, controller QPS, SQLite rows/bytes, outbox lag, blocked storage threads, gateway concurrency, R2 requests, compactor I/O, memory/cache/disk, checkpoint pause, active pins, and recovery tail.

Overload rules:

- bounded queues shed before memory exhaustion;
- DO `.overloaded` is propagated with bounded jitter/backoff and admission reduction;
- retries never multiply an already overloaded controller;
- correctness repair/recovery traffic has reserved capacity;
- archival starts at a high-water mark and mutation admission stops at an emergency threshold;
- no runtime path waits for provider billing data to decide whether an already begun correctness operation may finish.

If the process exceeds the Container envelope, partition at supported database/application boundaries or choose a different compute platform. Transparent TypeDB keyspace sharding remains prohibited.

## 26. Risk register

Risk severity changes only through attached executable evidence, never through prose confidence.

| ID | Risk | Severity | Required control / stop condition |
|---|---|---:|---|
| R1 | Incomplete source graph or wrong TypeDB external pin | Critical | G0 full graph, immutable tags→commits, artifact hashes, negative missing-node test |
| R2 | Reported test counts differ from executable catalogue | Critical | Generated target/leaf/fixture/profile denominator; manual counts non-authoritative |
| R3 | Cargo-only port misses a Starlark macro/configuration | Critical | Mode Q query oracle or Mode S full static expansion; UNKNOWN fails G0 |
| R4 | Federating workspaces changes dependency resolution unexpectedly | High | Independent upstream-shaped workspaces, lock digests, U0/U1 parity |
| R5 | Flattened/root orchestration becomes hidden build authority | High | Replaceable wrappers; direct Cargo/pnpm commands and reproducibility tests |
| R6 | Rust 1.93 parity lane carries known compiler/toolchain defects | High | Qualification lane on patched stable; compiler differential and explicit release choice |
| R7 | New Rust toolchain changes behavior/ABI/package output | High | Full corpus, differential, two-build reproducibility, package/ABI evidence |
| R8 | SlateDB default/all features enable unsafe or unused code | Critical | default-features=false; allowlist; feature-tree attestation; prohibited-feature link test |
| R9 | Compaction filter weakens snapshot consistency | Critical | Feature absent and symbol/config checks |
| R10 | Duplicate/conflicting StatusRecord diverges live and recovery | Critical | Singleton StatusKey, shared resolver, corruption on conflict |
| R11 | Validation basis omits a consulted durability record | Critical | Fixed prefix model, read tracing, resolver differential and stop condition |
| R12 | Remote append consumes logical/physical counters before certainty | Critical | Late atomic finalisation; same-operation query; no-hole model |
| R13 | Sync orders by TypeSequence instead of physical log | Critical | One sequencer, AppendLsn/ControlSeq barrier, mixed record tests |
| R14 | Remote iterator accidentally tails new records | Critical | Captured head/catalogue pin, moving-head negative control |
| R15 | Iterator error becomes EOF/partial read | Critical | Result-valued cursor and fault injection |
| R16 | Cross-keyspace partial apply becomes visible | Critical | VisibilityWatermark, crash each subset/order, raw-read lifecycle controls |
| R17 | Raw backend read observes partial/unresolved state | Critical | Capability inventory, startup phase gate, CI import/caller checks |
| R18 | Stale writer publishes SlateDB metadata | Critical | Exact external physical epoch, publication inventory, pause/fence/resume |
| R19 | Stale compactor/builder publishes after revocation | Critical | Independent epochs, scratch namespaces, publication tests |
| R20 | Unfenced Admin path mutates active manifest | Critical | Production import/call-graph ban, SL-P2 |
| R21 | Protective checkpoint suppression is invalid for a hidden deleter | Critical | Complete feature-resolved deletion inventory and negative mutation tests |
| R22 | Database controller is coupled to Container helper state | Critical | Separate DO classes/namespaces/capabilities and failure-injection tests |
| R23 | Container lifecycle DO accidentally gains database authority | Critical | Protocol allowlist, reducer ownership, no authority tables/keys in lifecycle DO |
| R24 | DO request interleaves across external await | Critical | Prepare–I/O–finalise/outbox discipline, interleaving model and stress tests |
| R25 | Input/output gates are overinterpreted as full transaction isolation | High | Explicit SQL state machines, no network await in authority transaction |
| R26 | Alarm finite retry strands outbox/lease/checkpoint work | Critical | Durable next_due, idempotent handler, catch/reschedule, external watchdog |
| R27 | DO overload triggers retry amplification | High | Backpressure, Retry-After/jitter, admission reduction, no blind retries |
| R28 | Controller SQLite reaches hard storage or row limit | Critical | Conservative budgets, archival watermarks, emergency stop, capacity soak |
| R29 | R2 temporary credential preset includes delete | Critical | Explicit action allowlist or exact presigned/gateway; policy tests |
| R30 | Runtime parent credential can mint delete-capable children | Critical | Separate parent tokens and signing policy; IAM audit |
| R31 | Provider lifecycle rule deletes authoritative objects | Critical | Absence attestation, Bucket Locks, periodic audit |
| R32 | Bucket Lock is mistaken for immutable administrator-proof WORM | High | Precise threat model, independent backup/anchor, separate admin |
| R33 | Bucket Lock rules exhaust 1,000-rule limit or mismatch prefixes | High | Coarse bucket/prefix topology, rule budget, strictest-rule audit |
| R34 | Object created before effective lock policy is vulnerable | Critical | Preconfigured locked namespace/probe or gateway-held acknowledgement rule |
| R35 | ETag treated as content digest | Critical | Application SHA-256 identity and re-read verification |
| R36 | Multipart composite SHA-256 confused with full-object SHA-256 | Critical | Separate checksum types and completed-object application hash |
| R37 | Failed UploadPart replacement destroys a previously valid part | High | Immutable part binding; changed bytes use new UploadAttemptId |
| R38 | R2 ambiguity cannot be resolved before deadline | High | Exact GET/receipt; fail closed, never fabricate success |
| R39 | Same-key write rate causes 429 or hot-key outage | High | Immutable keys, measured CAS cadence, bounded retry/backpressure |
| R40 | Gateway buffers large object and exceeds 128 MB | Critical | Streaming architecture, memory negative tests, direct bulk path |
| R41 | Gateway exhausts six outgoing connections/subrequest budget | High | Connection permits, body cancellation, batching measurements |
| R42 | Worker/image rollout is assumed transactional | Critical | DeploymentCompatibilityEnvelope and mixed-version tests |
| R43 | Deploy returns while old images remain active | High | Observed convergence gate and retained compatibility window |
| R44 | Old image/protocol accepts new mandatory format | Critical | Reader-before-writer, envelope negotiation, fail closed |
| R45 | Container helper reset/start-stop race loses lifecycle state | High | Pinned package/source, idempotent lifecycle reconciliation, rollout tests |
| R46 | Lifecycle DO and container location separation causes timeout assumptions | High | Ordinary network deadlines/retry; no colocation dependency |
| R47 | Default sleepAfter stops an authoritative database unexpectedly | Critical | Explicit policy and controller-approved hibernation |
| R48 | SIGTERM cleanup becomes correctness dependency | Critical | Arbitrary-kill recovery; shutdown only optimization |
| R49 | Container egress is broader than intended | Critical | enableInternet=false, allowlists, startup probes |
| R50 | V1 accidentally depends on native TCP/gRPC ingress | Critical | HTTP-only manifest and integration tests |
| R51 | Checkpoint cut misses background writer/compactor/Admin activity | Critical | Generated quiescence inventory, drain counters, failpoints |
| R52 | Independent logical digest reads wrong snapshot or partial data | Critical | MVCC-capped fixed snapshot, partition manifests, fault-to-failure |
| R53 | Scratch verifier appends authority or touches active prefix | Critical | READ_ONLY_BUILD and capability/prefix negative tests |
| R54 | Historical restore reuses low TypeSequence | Critical | Restore watermark+1 rule and MVCC visibility tests |
| R55 | Command re-executes after durable intent | Critical | Permanent binding/ledger, exact no-intent proof, crash matrix |
| R56 | Prepared command result cannot be generated within transaction budget | High | Per-command mode/size/deadline; canonical receipt fallback or exclude class |
| R57 | Control history valid suffix is deleted/rolled back | Critical | Independent RecoveryAnchor and cadence/RPO, Bucket Locks |
| R58 | Old controller credentials remain accepted after recovery | Critical | Incarnation/key/parent rotation and negative drill |
| R59 | Indefinite V1 WAL retention exceeds cost/RTO horizon | High | Growth forecast, archival indexes, capacity gate; no unsafe deletion shortcut |
| R60 | Implementation agent marks gates green from prose or retries | Critical | Signed evidence only, clean final run, stop authority and CI policy |

## 27. Production definition of done

Production is complete only when all applicable items below are evidenced for one exact release:

1. One machine-readable source graph resolves every shipping and proof-critical repository, artifact, image, package, fixture, toolchain and platform contract.
2. `typedb-behaviour`, TypeQL, typedb-protocol, TypeDB build dependencies/distribution, Console/Loader fixtures and base images are locked and licensed.
3. TypeDB, SlateDB and tools retain independently reproducible Cargo workspaces and lockfiles.
4. Cargo is the sole Rust build/test/package authority; pnpm/Wrangler is the sole Workers authority; any task runner is replaceable.
5. The selected Bazel evidence mode is recorded and no shipping artifact is Bazel-built.
6. The complete applicable upstream target/leaf-case/fixture/profile denominator is generated with zero UNKNOWN entries.
7. U0 establishes the pristine source baseline including declared pre-existing failures/flakes.
8. Every oracle-preserving TypeDB refactor is structured-equal under U0/U1.
9. The RocksDB backend uses safe cursor ownership and no new forged lifetime.
10. The TypeDB-owned storage and durability boundaries expose no concrete SlateDB/RocksDB type above adapters.
11. Every durability operation, waiter and iterator is fallible, deadline-bound and panic-free for environmental failures.
12. Remote WAL sequencing, physical sync, singleton status and fixed iteration match the file-WAL oracle.
13. The shared resolver gives identical verdict/apply-plan in live, recovery and scratch modes.
14. Every transaction outcome is separated from intent durability, apply, visibility and client returnability.
15. Every ordinary read is capped by VisibilityWatermark and every raw read is capability/lifecycle classified.
16. SlateDB production features are the approved minimal allowlist and prohibited features/symbols are absent.
17. Every SlateDB reachability mutation is externally epoch-fenced and stale publication tests pass.
18. Built-in SlateDB deletion and unfenced Admin mutation are unreachable in the production profile.
19. `DatabaseControllerDO` and `DatabaseContainerDO` are separate classes, schemas, namespaces, packages and capability sets.
20. Authoritative controller transitions remain correct under request interleaving and contain no uncontrolled network await before commit.
21. Alarm/outbox work is idempotent, durably scheduled and recoverable beyond platform automatic retries.
22. Controller overload/storage budgets shed before platform limits and preserve recovery/repair capacity.
23. R2 bucket topology, credentials, Bucket Locks, lifecycle policies and parent-token separation pass real-account conformance.
24. No pre-G13 runtime credential, binding, route, feature or principal can delete authoritative objects.
25. Application SHA-256, length and exact key—not ETag or provider composite checksum—define object identity.
26. Multipart attempts enforce immutable part identities and completed-object verification.
27. Gateway/direct data paths meet streaming memory, connection, conditional, ambiguity and revocation requirements.
28. V1 has no native TCP/gRPC ingress dependency; the HTTP facade passes the application and upstream applicable suites.
29. Mixed Worker/container rollout, lifecycle DO reset, sleep/stop, SIGTERM/SIGKILL and stale-image tests pass.
30. Every acknowledged promise survives local disk loss, process kill and ordinary DO restart.
31. Controller catastrophic recovery reconstructs from authenticated history above the independent anchor and rejects old authority.
32. Command reservation, no-intent, result binding, terminal outcome and permanent ID non-reuse pass the full crash matrix.
33. Global checkpoint captures one exact cut and fresh-process scratch verification matches the independent logical digest.
34. Same-generation rebuild and historical restore preserve epochs, materialisation identity, TypeSequence continuity and bookmark rules.
35. Pins and backup closures are root-first, account-isolated and restore-drilled with precise immutability claims.
36. V1 retains all WAL history and the measured storage/RTO horizon is accepted; no delete shortcut ships.
37. The 4-vCPU/12-GiB/20-GB container and DO/Worker budgets hold under representative load with approved headroom.
38. Dual Rust parity/qualification evidence selects one release compiler and the tested binary equals the image payload.
39. SBOM, licences, provenance, security review, compatibility dates, account features, probes, runbooks and residual-risk approvals are archived.
40. G0–G12 are green for one exact release manifest, G13 is green only when deletion ships, and no stop condition or retry-created green remains.

A signed release manifest binds the evidence digests. Informal logs, agent summaries, dashboard screenshots without raw context, and partially retried runs are not release proof.

# Appendix A — Authoritative control-event catalogue

Event IDs are numeric, versioned, never reused, and generated with reducer/schema/tests. Audit-only observations are not listed.

## A.1 Database, generation, routing, and controller incarnation

1. `DatabaseCreated`
2. `GenerationCreated`
3. `GenerationRestored`
4. `LifecycleTransitioned`
5. `RoutingActivated`
6. `RoutingDeactivated`
7. `ControllerIncarnationPrepared`
8. `ControllerIncarnationActivated`
9. `DatabaseFailedClosed`
10. `DeletionRequested`

## A.2 Startup and epochs

11. `StartupReserved`
12. `StartupSessionGranted`
13. `StartupSessionReady`
14. `StartupSessionRevoked`
15. `WriterEpochAdvanced`
16. `CompactorEpochAdvanced`
17. `BuildEpochAdvanced`

A grant/advance event carries both the controller authority epoch and the exact physical SlateDB epoch(s); a separate duplicate “bound” event is unnecessary when readiness attests every keyspace readback.

## A.3 WAL, status, resolution, apply, and archival

18. `WalRecordFinalized`
19. `WalRecordsFinalizedBatch` — schema absent/forbidden unless G2 explicitly enables it
20. `WalIndexSegmentPrepared`
21. `WalIndexCatalogueActivated`
22. `WalTailRowsPruned`
23. `TransactionResolved`
24. `TransactionVisibilityCompleted`
25. `StatusRepairDegraded`
26. `RecoveryCompleted`

`WalRecordFinalized` with a command binding is the durable intent binding. There is no duplicate `TransactionIntentBound` or `CommandIntentBound` authority event. `TransactionResolved` contains the ValidationBasis/ResolutionCertificate digests. Status record physical finalisation remains a normal WAL event, not a second transaction-resolution event.

`TransactionResolved` and `TransactionVisibilityCompleted` are emitted per transaction only for command-bound or explicitly declared externally recoverable outcomes. Native transaction verdicts/visibility are reconstructed from WAL/checkpoint state; their controller rows may be bounded operational caches. Checkpoint, hibernation, recovery, and readiness events publish aggregate frontiers, avoiding two mandatory control events for every native commit.

## A.4 Commands

27. `CommandReserved`
28. `ApprovalRecorded`
29. `CommandPreIntentTerminalized` — rejected/cancelled/expired variants
30. `CommandAssigned`
31. `CommandResultBound`
32. `NoIntentProven`
33. `CommandTerminalized`
34. `CommandResultAvailabilityChanged`
35. `CommandLedgerSegmentPrepared`
36. `CommandLedgerCatalogueActivated`
37. `CommandRowsPruned`

Worker-start and result-finalisation-start are telemetry, not authority.

## A.5 Checkpoint and materialisation

38. `CheckpointQuiesceStarted`
39. `CheckpointCutCaptured`
40. `CheckpointCandidatePublished`
41. `CheckpointVerificationRecorded`
42. `CheckpointActivated`
43. `MaterializationBuildRegistered`
44. `MaterializationBuildVerified`
45. `MaterializationActivated`
46. `MaterializationRetired`

Per-keyspace contributions and expected digest may be embedded as exact digested sets in candidate publication rather than one event per keyspace. The chosen representation is fixed by schema and boundedness evidence.

## A.6 Retention, backup, security, and recovery

47. `RetentionPinTransitioned`
48. `BackupTransitioned`
49. `RecoveryAnchorPublished`
50. `SigningKeyRotationTransitioned`
51. `ControllerRecoveryTransitioned`
52. `GcAttemptTransitioned` — delete-capable variants absent from pre-G13 schemas/builds

### A.7 Event rules

- A semantic change requires a new event version/type and migration matrix.
- Optional additions use reserved fields and reader-first deployment.
- High-volume progress is telemetry unless reconstruction mathematically requires it.
- Every event maps to exactly one reducer transition or certified no-op/idempotent replay.
- Pre-G13 readers reject delete-capable variants even if syntactically valid.

---

# Appendix B — Key state transitions and response rules

## B.1 Command transition table

| Current | Input/proof | Next | Client implication |
|---|---|---|---|
| `ABSENT` | exact active+ledger absence | `RESERVED` | pending |
| `RESERVED` | approval needed | `APPROVAL_PENDING` | pending approval |
| `RESERVED/APPROVED` | assignment barrier | `ASSIGNED` | in progress |
| `ASSIGNED` | worker begins bounded TypeDB txn | `EXECUTING_PRE_INTENT` | in progress |
| `EXECUTING_PRE_INTENT` | canonical receipt mode selected | `RESULT_BOUND` | in progress |
| `EXECUTING_PRE_INTENT` | exact prepared bytes uploaded/bound | `RESULT_BOUND` | in progress |
| `EXECUTING_PRE_INTENT` | retryable failure + exact no-intent proof | attempt closed, assignable | controller retrying |
| `RESULT_BOUND` | CommitRecord finalised with command binding | `INTENT_FINALIZED` | outcome unknown, never re-execute |
| `INTENT_FINALIZED` | physical barrier | `INTENT_DURABLE` | outcome unknown |
| `INTENT_DURABLE` | resolver starts | `RESOLUTION_PENDING` | recovering |
| `RESOLUTION_PENDING` | abort certificate | `RESOLVED_ABORT` | finalizable failure |
| `RESOLUTION_PENDING` | commit certificate | `RESOLVED_COMMIT` | not success yet |
| `RESOLVED_COMMIT` | per-keyspace apply | `APPLY_PENDING` | in progress |
| `APPLY_PENDING` | all batches + watermark | `VISIBILITY_COMPLETE` | finalizable success |
| resolved abort / visibility complete | exact final envelope + barrier | terminal outcome | exact result/failure |
| terminal outcome | result retention expires | same outcome, availability expired | `RESULT_EXPIRED`, never retry |

Illegal: prepare result before the transaction when transaction-local values are required; second assignment after intent; success before visibility; cancellation after intent; result expiry changing outcome; execution in a different generation.

## B.2 Durability responses

| Condition | Response | Retry rule |
|---|---|---|
| exact finalisation complete | `FinalizedRecord` | no new operation |
| same operation/same digest | exact prior result | safe |
| same operation/different digest | permanent conflict | never |
| timeout/status unknown | `AMBIGUOUS` + operation ID | query same operation |
| stale session/epoch/incarnation | `FENCED`/`STALE_*` | reopen/recover, no blind append |
| exact status key/same verdict | original record | no duplicate append |
| exact status key/different verdict | `STATUS_CONFLICT` + fail closed | never |
| iterator reaches captured head | EOF | complete |
| iterator gap/expiry/catalogue change | explicit error | reopen exact snapshot if safe |
| sync deadline | ambiguous/timeout | query barrier, never claim durable |

## B.3 Reads

A read succeeds only if its complete result at the pinned logical snapshot is known. Mid-read R2/backend error fails the whole read. Bookmark above VisibilityWatermark yields bounded wait or `BOOKMARK_NOT_REACHED`. Raw maintenance reads are not public query behavior.

---

# Appendix C — Source-owner reconciliation packet

For each item return repository/commit, path/symbol/line range, feature/config assumptions, immediate caller graph, tests, exact behavior, current verdict, minimum patch/design change, proof/gate, and residual uncertainty.

## C.1 P0 source contradictions and missing inventories

1. Enumerate every possible duplicate `StatusRecord` path. Confirm recovery's second-status panic and live last-wins map behavior. Propose the minimal shared singleton/parser patch.
2. Prove a deterministic StatusKey/operation ID can be supplied by every live/recovery status writer.
3. Enumerate all other unsequenced types and define their ambiguity/dedupe semantics.
4. Prove the complete live/recovery/scratch resolver input set and finite prefix. Identify every nondeterministic input.
5. Show how dependent-put/reinsert mutations are reproduced from exact CommitRecord bytes.
6. Prove a shared resolver can replace the live missing-status `unreachable!` without changing oracle outcomes.
7. Enumerate every raw-storage production caller and classify lifecycle/visibility requirements.
8. Enumerate every TypeDB background `IntervalRunner`/thread/task touching WAL, Statistics, checkpoint, keyspaces, schema, import, or generators; include panic/error behavior.
9. Prove the automatic checkpointer can be disabled/replaced cleanly in the remote profile.
10. Prove the Statistics updater can be stopped, drained, made fallible, and repaired idempotently.
11. Confirm file-WAL iterator holds a stable read guard and define exact behavior with concurrent writes/files/EOF.
12. Define the minimal remote iterator snapshot needed to reproduce that behavior.
13. Inventory every WAL-history reader, including commit/snapshot idempotency checks, Statistics, isolation, import/migration, admin, tests, and tooling.
14. Challenge any WAL deletion floor; state why V1 physical retention can or cannot remain indefinite.
15. Prove historical restore from physical MVCC keys requires TypeSequence continuation; identify all counters/generators affected.
16. Prove VisibilityWatermark semantics across committed and aborted sequences and rename misleading fields.

## C.2 SlateDB P0 questions

17. Enumerate every `Admin` method that mutates a manifest/checkpoint/clone/parent and identify whether it uses `StoredManifest` or `FenceableManifest`.
18. Confirm `Admin::delete_checkpoint` is not WriterEpoch-fenced at the pinned commit.
19. Design the minimum SL-P2 patch or source-proven configuration that prevents protective-checkpoint growth without unfenced active mutation.
20. Prove whether protective compactor checkpoints are unnecessary when all internal destructive GC is disabled.
21. Enumerate every active writer/compactor/checkpoint/clone/retry/recovery reachability publication and prove SL-P1/SL-P2 coverage.
22. Specify ambiguous exact-epoch open/retry behavior for `init_with_epoch` when the stored epoch equals the requested epoch.
23. Prove automatic compactor can be disabled at open and explicitly started/drained/revoked later; otherwise provide SL-P3.
24. Inventory every delete helper, lifecycle hook, admin method, test feature, object-store retry, and provider rule that can delete.
25. Prove same-handle immediate visibility, snapshot stability, and object-error propagation under the exact no-WAL configuration.
26. Measure/share cache and resource ownership across all per-keyspace Db instances.

## C.3 Controller/WAL/command questions

27. Prove the controller can enforce unique unsequenced logical keys and exact replay without changing file-WAL oracle behavior.
28. Specify all exact indexes in WalIndexSegment and their parser/lookup complexity.
29. Prove `NoIntentProven` remains race-free across catalogue replacement and active finalisation.
30. Decide whether per-record finalisation meets G2. If batching is needed, deliver the complete batch schema/model—not prose.
31. Prove controller outbox signing key selection is deterministic across key rotation and delayed flush.
32. Define RecoveryAnchor storage, trust root, cadence, retention, and malicious suffix-deletion RPO.
33. Define the independent mechanism that revokes old ControllerIncarnation authority after catastrophic recovery.
34. Prove stale old DO/controller cannot write accepted control events or mint accepted object capabilities after cutover.
35. Reorder every PREPARED_BYTES command implementation so transaction-local result generation precedes binding and intent finalisation.
36. Inventory command classes/results/limits as design data, not source facts; remove or justify arbitrary 1 MiB/retention values.
37. Prove terminal outcome and result availability are stored/indexed independently.

## C.4 R2/Cloudflare questions

38. Re-evaluate gateway versus path/action-scoped temporary credentials and presigned URLs per object class using current R2 capabilities.
39. Prove exact checksum type/semantics for single-part and multipart operations; do not treat ETag as digest.
40. Measure gateway streaming memory/CPU/subrequests/connections and `DigestStream` behavior at maximum object size.
41. Prove credential parent revocation behavior and maximum stale-credential window during controller recovery.
42. Qualify every conditional/retry/metadata/range/multipart operation on exact account/SDK/profile.
43. Reconcile S3 Object Lock absence with native R2 Bucket Locks; prove lock administration, threat boundary, and the actual disaster-backup profile.
44. Reconcile gate numbering for all platform/capacity claims; capacity is G12, optional delete is G13.

## C.5 Checkpoint, recovery, and compatibility questions

45. Enumerate the complete quiescence inventory, including compactor publication and active-manifest maintenance.
46. Prove expected digest reads a stable MVCC-capped snapshot and does not rely on unsafe raw reads.
47. Prove READ_ONLY_BUILD performs no authoritative WAL/status/statistics/controller write, including generator/schema initialization.
48. Prove same-generation cutover and historical restore preserve every identity/frontier rule.
49. Define validator drain-and-replace upgrade steps and recovery tooling compatibility.
50. Produce the complete root-closure parser inventory and no-delete storage-horizon evidence.

## C.6 V16 composed-design closure questions

51. Show exactly how `BuildEpoch` binds one scratch attempt while the actual SlateDB publication fields receive exact `SlateWriterEpoch`/`SlateCompactorEpoch` values.
52. Prove a prepared-active holder can open and attest a materialisation without WAL authority, claims higher physical epochs, and fences a resumed builder before cutover.
53. Inventory every random historical lookup key required by TypeDB/controller semantics.
54. Supply bounded exact-lookup root/shard/compaction design and prove lookup/absence cost is independent of total archived segment count.
55. Prove physical WAL catalogues and random exact-lookup catalogues activate consistently enough that archival/pruning cannot create false absence or missing iteration.
56. Prove permanent `CommandId` lookup is database-global across restores/generations and root activation precedes row pruning.
57. Produce the complete source graph from the selected TypeDB `MODULE.bazel`, including all tag-to-commit and artifact/hash resolutions.
58. Prove TypeDB and SlateDB retain identical Cargo feature/profile/lock behavior in the federated repository compared with their upstream-shaped workspaces.
59. Produce package-to-source mappings for `@cloudflare/containers`, Wrangler, Vitest pool, Miniflare and workerd.
60. Prove `DatabaseControllerDO` and `DatabaseContainerDO` cannot mutate each other's authority domains.
61. Model and test authoritative controller procedures under arbitrary interleaving at every non-storage `await`.
62. Demonstrate durable alarm progress after handler duplication, reset and exhaustion of automatic retries.
63. Demonstrate overload shedding without retry amplification and with reserved recovery/archival capacity.
64. Prove every pre-G13 runtime R2 credential has an explicit action list excluding delete and bucket-policy administration.
65. Prove Bucket Locks cover every acknowledged immutable authority object from the time its promise can be returned, and document the privileged-admin residual risk.
66. Prove multipart retries never replace a part with different bytes under the same upload attempt and verify the final object by application SHA-256.
67. Prove Worker/image mixed rollouts preserve protocol/format compatibility and stale images cannot regain readiness.
68. Prove the release has no native TCP/gRPC ingress dependency and the HTTP facade covers all required application semantics.
69. Compare Rust parity and qualification lanes across the complete U0/U1 corpus and release package; justify the selected compiler.
70. Return raw G0/G1/G2 evidence, exact commands, tool/package/account versions, seeds, failures, exclusions and every design contradiction.

Any contradiction updates the design, model, schema, tests, source lock, package lock and gate together. An informal comment does not close an item.

# Appendix D — Implementation-start checklist

- [ ] Exact source lock, submodules, builds, licences, and inventories reproduced.
- [ ] Cargo manifests are fork-owned; Rust/native toolchain and `Cargo.lock` are pinned; offline build passes.
- [ ] Upstream target/leaf-case/runfile catalogue is complete, reconciled, and has zero unclassified entry.
- [ ] Pristine U0 and refactored U1 corpus results are identical.
- [ ] Backend profile matrix U2–U4 and direct test constructor inventory are complete.
- [ ] Cargo runner stages Bazel-equivalent data/env/timeouts/serial groups without executing Bazel.
- [ ] Cargo-built test distribution and Cloudflare image share the exact server binary digest.
- [ ] V11 contradictory source claims removed or corrected with evidence.
- [ ] Status singleton and shared resolver model pass.
- [ ] Fixed iterator snapshot, bounded exact lookup roots, database-global CommandId index, and no-intent model pass.
- [ ] Scratch-to-active materialisation takeover claims higher physical SlateDB writer/compactor epochs and fences stale build tasks before activation.
- [ ] Historical restore sequence-continuity model pass.
- [ ] Raw-read and background-task inventories are complete.
- [ ] Active SlateDB Admin mutation is absent or fenced through SL-P2.
- [ ] Explicit compactor lifecycle is proven.
- [ ] Object-class data paths and recovery credential revocation are qualified.
- [ ] RecoveryAnchor and ControllerIncarnation model pass.
- [ ] Command result lifecycle and outcome/availability separation pass.
- [ ] Global checkpoint quiescence/digest model pass.
- [ ] No reachable authoritative delete call path, shipping cleanup feature, lifecycle rule, route, capability, credential, or production binary exists before G13.
- [ ] G2 remote append/data-path spike passes or the protocol is redesigned.
- [ ] Patch owners/rebase/upstream strategy and accepted residual risks are explicit.

Until these conditions are met, durable production formats and broad forks remain prohibited.

---

# Appendix E — Cargo-only TypeDB test-conformance packet for the source-owning agent

For every answer, return exact source commit/path/symbol/line or generated artifact digest. Do not answer “covered by cargo test” without target and case evidence.

## E.1 Corpus discovery

1. Produce `cargo metadata --locked --format-version 1` for the pristine pin and enumerate every package, lib/bin/test/bench/example target.
2. Produce the complete libtest case list for every test-capable Cargo target, including normal and `#[ignore]` cases.
3. Enumerate every direct `rust_test`, crate-unit wrapper, `sh_test`, checkstyle/rustfmt, release/dependency validation, and test-producing macro in all TypeDB BUILD files.
4. Supply a Bazel query/cquery target snapshot for the exact source lock if possible. Otherwise expand every custom macro by source and prove that no test target is hidden.
5. Reconcile direct BUILD test targets with committed generated Cargo manifests. Explain every difference.
6. Enumerate all test source files not reachable from Cargo today.
7. Enumerate generated behavior scenarios/features and prove case discovery is complete.
8. Enumerate every `#[ignore]`, runtime skip, environment guard, platform guard, and zero-test target.

## E.2 Build and feature equivalence

9. Record rustc/cargo versions, target triple, linker, C/C++ toolchain, protoc, cmake, clang, pkg-config, native libraries, and relevant environment.
10. Enumerate Bazel rustc flags, cfgs, features, compile data, generated sources, proc macros, and environment that are not represented in Cargo.
11. Define explicit Cargo feature/profile sets for U0–U4; do not use blanket `--all-features` unless proven valid.
12. Prove a clean `cargo build --workspace --all-targets --locked` and catalogue-driven test compile from the pristine pin.
13. Prove vendored/offline resolution of git dependencies and record the exact commit behind each tag/revision.
14. Identify every Cargo manifest limitation caused by the current Bazel sync tool and the manual fork change needed.

## E.3 Runfiles, assembly, failpoints, and crash tests

15. Enumerate Bazel `data`, `env`, `timeout`, `tags`, `select`, runfiles, and working-directory assumptions for each test.
16. Define the Cargo-only package layout required by `tests/assembly/assembly.rs` and `fail_points.rs`.
17. Lock the TypeDB Console test fixture by repository/version/download URL/SHA-256/licence, or provide a reviewed semantic port that preserves every test command.
18. Prove the assembly/failpoint package contains the same Cargo-built server binary as the release image.
19. Port the durability crash streamer/recoverer/shell orchestration to a Rust xtask while preserving kill points and expected outcomes.
20. Enumerate fixed ports, global failpoint variables, filesystem paths, clocks, and singleton resources requiring serial groups.

## E.4 Candidate backend applicability

21. Enumerate every test-time direct RocksDB, Keyspace, MVCCStorage, file-WAL, checkpoint-dir, DatabaseManager, and server construction.
22. Define the single central backend/profile injection mechanism and show which test files remain byte-identical.
23. Classify every physical RocksDB test as generic, oracle-only, or requiring a candidate semantic replacement.
24. Produce the exact required `(test case, U0..U4)` matrix and justify every non-required pair.
25. Prove every storage-independent upstream behavior/query/HTTP test runs against SlateDB rather than silently defaulting to RocksDB.
26. Prove real-R2 tests use unique namespaces and that test cleanup code/credentials are absent from the production artifact.

## E.5 Runner fidelity and quality

27. Provide the Cargo/libtest executable discovery and `--list` parser with golden tests against the pin.
28. Prove the runner detects filtered-out, ignored, dynamically skipped, zero-test, timed-out, missing-fixture, and early-success cases.
29. Define flake policy: diagnostic retry, final clean run, baseline flake evidence, quarantine prohibition for storage correctness.
30. Produce stable test IDs, source hashes, result records, seeds, profile/config/server digests, and JUnit/JSON evidence.
31. Add negative controls for each load-bearing storage/durability/fencing/checkpoint invariant and demonstrate the intended test fails.
32. Produce exact target/leaf-case/profile coverage numbers. No “approximately all tests”.

## E.6 Cargo-only release workflow

33. Implement `cargo xtask catalog-upstream-tests`, `verify-cargo-manifest-parity`, `test-upstream`, `package-upstream-test-dist`, `package-cloudflare`, and `evidence`.
34. Demonstrate that normal CI and release environments have no Bazel executable and make no Bazel subprocess call.
35. Demonstrate rebase drift handling when upstream changes a BUILD target, Cargo manifest, test case, fixture, macro, feature, or package layout.
36. Return the minimum patch set and ownership/upstream strategy for keeping Cargo authoritative.

A contradiction updates the test denominator, Cargo manifests, profile matrix, package, gates, and this specification together. It may not be hidden as an exclusion.

---

# Appendix F — TypeDB/SlateDB source reconciliation packet (historical evidence, design reconciled into v16)

Anchors are commit-pinned: TB `2256711a`, SL `f88be86d`. Verdict classes per the v12 taxonomy (I/R/D/P/E).

## F.1 Status records, resolver, determinism (1–6)

**1 — I, reviewer CONFIRMED.** Duplicate-status paths: live validation collects statuses into a HashMap (last-wins, TB `storage/isolation_manager.rs` L205-210); recovery removes-and-reinserts and hits `unreachable!("found second commit status for a record")` on a second *committed* status (TB `storage/recovery/commit_recovery.rs` L95-105) and silently overwrites to Rejected on a later *false* (L108) — so true-then-false duplicates diverge between live and recovery. Physical duplicate creation vector: an ambiguous remote retry of `persist_commit_status` (TB `storage/storage.rs` L401-410). v12's StatusKey dedupe is the correct fix and is enforceable at one place: the controller finalisation transaction (unique `(record_type, target_sequence)` for unsequenced records) — the file-WAL oracle never produces duplicates because status writes are single-shot in-process, so dedupe changes no oracle behaviour.
**2 — I.** Both unsequenced writers carry a deterministic StatusKey today: `StatusRecord.commit_record_sequence_number` (TB `storage/record.rs` L226-233) and Statistics' own type identity; the controller derives `StatusKey` without source changes. Same-key/same-verdict retries return the existing physical record (v12 rule), satisfied by controller-side exact lookup.
**3 — I, exhaustive.** Unsequenced impls at the pin: `StatusRecord` (TB `storage/record.rs` L263) and `Statistics` (TB `concept/thing/statistics.rs` L784). Nothing else. Statistics ambiguity semantics: duplicates are harmless (latest-wins by physical position via `find_last_unsequenced_type`); dedupe key = record type + producing checkpoint frontier, uniqueness not required.
**4 — I/E.** Resolver input set (live and recovery converge on): the CommitRecord's `{operations, open_sequence_number, snapshot_id}`; every sequenced CommitRecord in `(open_seq, S)`; their verdicts (recursively, same rule); nothing else — anchors: `validate_all_concurrent` (isolation_manager L114-171), `iterate_commit_status_from_disk` (L197-224), recovery re-validation (commit_recovery L175-199). Nondeterministic inputs found: **none** in verdict computation (no clock/randomness; `reinsert` flags and `snapshot_id` are embedded pre-serialization, TB storage.rs L270-276). The remaining risk is *structural divergence* (two code paths), which is exactly why the shared pure resolver (v12 §10) is an E-obligation, not because a nondeterministic input exists.
**5 — I.** Dependent puts are reproduced bit-exactly: `Write::Put{reinsert}` is resolved by `set_initial_put_status` **before** `into_commit_record` serialises (storage.rs L270-276), so recovery's `WriteBatches::from_operations` (commit_recovery L147-203) consumes the embedded flags; apply keys embed the sequence (`MVCCKey::build(key, seq, op)`, TB `storage/write_batches.rs` L27-49) — byte-idempotent re-apply, deletes included (tombstone-puts).
**6 — I/E.** The live missing-status `unreachable!` (isolation_manager L158-161) fires only for evicted predecessors with no durable status; the shared resolver replaces it with the recovery rule (recompute the predecessor's verdict from its own prefix). Oracle outcomes are unchanged because recovery already computes exactly that verdict for the same inputs — the panic is the only behavioural delta, and it is a crash, not an answer.

## F.2 Raw reads, background tasks, iterator, retention (7–14)

**7 — I, reviewer CONFIRMED.** Production raw callers at the pin: `get_prev_raw` from vertex/IID generator initialisation (TB `encoding/graph/thing/vertex_generator.rs` L123, L141); the raw surface is `get_raw_mapped`/`get_prev_raw`/`iterate_keyspace_range` (TB `storage/storage.rs` L530/L547/L556). Classification: generator init needs *max-key-below-prefix over all versions* — legal only after recovery resolves partial apply and within the active materialisation; gate it behind `RawMaintenanceReadCapability` (v12 rule) with lifecycle = post-RECOVERED, never in ordinary query paths.
**8 — I, inventory.** Background tasks constructed by `Database`: `_statistics_updater` and `_checkpointer` `IntervalRunner`s (TB `database/database.rs` L93-94, constructed L341-342 and L457+). No other durability-touching interval tasks at the pin (WAL fsync thread is the durability client's own, replaced by the remote adapter).
**9 — I/PATCH.** The automatic checkpointer calls the same checkpoint creation the controller protocol owns; remote profile disables the IntervalRunner behind a config flag (patch TB-P9 scope) — construction sites are exactly the two anchors above, so the change is mechanical and the controller becomes the only checkpoint authority (v12 §16).
**10 — I/PATCH.** Statistics updater: producer of the second unsequenced type; made drainable/fallible in TB-P4/TB-P9 scope; repair = regenerate and append a fresh record after activation (v11 H-Q25 rule carried: fresh Statistics after every activated checkpoint).
**11 — I, reviewer CONFIRMED + one stronger fact.** `RecordIterator<'a>` holds `RwLockReadGuard<'a, Files>` for its whole life (TB `durability/wal.rs` L566-573) — the view is frozen **and** concurrent `sequenced_write` (which takes the write lock, L135-149) is *blocked* while a file iterator lives. The remote adapter must reproduce the frozen view (v12 `DurabilityIteratorSnapshot`) but must NOT reproduce the write-blocking — and that is safe: no source caller depends on iterator-blocks-writers for correctness (recovery runs pre-writes; validation reads bounded closed prefixes), so the snapshot restores equivalence strictly more permissively.
**12 — R.** Minimal snapshot = v12 §9's `DurabilityIteratorSnapshot{head_lsn, head_digest, catalogue_version, tail_boundary, expiry}` — sufficient because the file oracle's frozen view is exactly "head fixed at creation".
**13 — I, inventory.** WAL-history readers at the pin: recovery replay (commit_recovery), isolation disk validation (isolation_manager L197-224), **transaction/snapshot idempotency** `commit_record_exists(open_seq, snapshot_id)` scanning from a live snapshot's open sequence (TB `storage/storage.rs` L383-399 — reviewer CONFIRMED, with the in-code warning about removed records), `find_last_unsequenced_type::<Statistics>` (TB `database/database.rs` L394), import/migration reads, and admin/reset paths.
**14 — I→R, reviewer CONFIRMED.** Because `commit_record_exists` anchors at *live snapshot open sequences* (unbounded below any checkpoint floor while snapshots live), v1 physical retention is **indefinite**: SQLite descriptor rows may archive into exact segments, but no WAL descriptor or payload object is ever deleted in v1 (v12 §7.8/§17 stands). Any future floor requires the full reader inventory above plus live-snapshot lower bounds.

## F.3 Restore identity, watermark (15–16)

**15 — I.** MVCC keys physically encode the sequence (E.1-5 anchor); checkpoint recovery replays from watermark+1 and panics if the checkpoint is ahead of durability (TB `storage/recovery/checkpoint.rs` L75-113). Counters affected by restore: `next_type_sequence` (must continue: `restored_visibility_watermark + 1`, v12 §15 rule CONFIRMED), the isolation timeline base (reset to the same watermark, `IsolationManager::reset`/`new(initial)`), and IID generators (self-heal via raw max-key lookup — E.2-7 — which is precisely why generator init needs the raw capability after restore). TypeSequence reset-to-1 on non-empty state is impossible without full logical rewrite: I-confirmed.
**16 — I.** The watermark advances through aborted heads (`may_increment_watermark` on abort, isolation_manager L100) — it is a visibility watermark, not an applied-commit frontier. v12's `VisibilityWatermark` rename + optional `last_applied_commit_lsn` is the correct model (D, now I-motivated).

## F.4 SlateDB maintenance, epochs, compactor, deletes (17–26)

**17 — I, inventory.** `Admin` production methods loading **unfenced** `StoredManifest` at the pin: four sites (SL `slatedb/src/admin.rs` L497, L525, L549 [delete_checkpoint], L619 [clone-parent path]); test-only uses at L1566+. None uses `FenceableManifest`. All active-namespace Admin mutations are banned in v1 (v12 rule I-grounded).
**18 — I.** Confirmed: `delete_checkpoint` = `StoredManifest::load` + `maybe_apply_update` (admin.rs L546-560); no epoch check on that path (`check_epoch` lives only in `FenceableTransactionalObject`, SL `slatedb-txn-obj/src/lib.rs` L403-417).
**19/20 — I→SL-P2 option A proven.** Protective checkpoints exist solely to shield in-flight readers from **GC deletion** — the in-tree comment says so verbatim, including the TODO acknowledging the leak (SL `slatedb/src/compactor_state_protocols.rs` L243-263: "prevent GC from deleting SSTs… for now, just write a checkpoint with 15-minute expiry"). With every internal deleter disabled (GC `None`; deletion inventory E.4-24), the protected hazard cannot occur; SL-P2 option A = a compactor flag skipping protective-checkpoint creation when internal deletion is disabled (~10 lines at the single `write_manifest` site). No unfenced maintenance API is ever needed. Option B (fenced maintenance) remains the fallback if upstream prefers it.
**21 — I.** Publication inventory (all through `FenceableTransactionalObject`, hence SL-P1-covered): writer L0 manifest updates (memtable flusher, durable-seq advance SL `memtable_flusher/manifest_writer.rs` L731), compactor manifest + compactions updates (`compactor_state_protocols.rs`), checkpoint writes via `maybe_apply_update` on the *fenced* wrapper for the active writer, clone/init (fresh namespace). The unfenced exceptions are exactly the Admin sites of E.4-17 — banned. Retry/refresh re-enter `check_epoch`; version CAS closes races (create-only consecutive IDs, SL `slatedb-txn-obj/src/object_store.rs` L371-397). Pause-fence-resume matrix per publication site = E-obligation at G4/G5.
**22 — I→R.** `init_with_epoch` returns `Fenced` when `stored >= requested` (txn-obj L355-397) — so a retried open with the *same* issued epoch self-fences after an ambiguous first attempt. Rule: every open attempt gets a **fresh controller-issued epoch** (attempt-scoped, monotonic per generation); an ambiguous open is resolved by issuing E+1 and retrying, never by re-presenting E. This also collapses the ambiguous-equal case: stored==E means *some* attempt with E won; whether it was ours is irrelevant once E+1 is claimed.
**23 — I.** `Settings::default()` enables the in-process compactor (SL `config.rs` L1081-1084); `compactor_options: None` at open prevents its spawn (builder path), and a standalone `Compactor` component exists (SL `slatedb/src/compactor.rs` L307) using the epoch handshake already anchored (`compactor_state_protocols.rs` L177-205, `init_with_epoch` by value). v12's open-quiet-then-start-explicit compactor model is I-feasible; SL-P3 is needed only if the standalone API cannot accept the externally issued epoch — same ~small family as SL-P1.
**24 — I, delete inventory.** In-tree deleters at the pin: the six GC task classes (SL `slatedb/src/garbage_collector.rs` L60-110: Wal, WalFence, Compacted, Compactions, Manifest, Detach; fan-out 8), `ManifestStore::delete_manifest[_unchecked]` (SL `manifest/store.rs` L466-495), boundary-checked protocol `delete` (txn-obj L666-681), `Admin::delete_checkpoint` (metadata), plus the object-store retry layer's attribute-dropping fallback (SL `retrying_object_store.rs` L347-364, L405-411 — SL-P4/fail-closed) and provider lifecycle rules (external; attested absent per v12 §17). v1 config disables GC (`garbage_collector_options: None`, no spawn per `db/builder.rs` L775-800); the rest are unreachable or banned.
**25 — I (carried v11 H-Q31, anchors re-verified).** Same-handle read-your-writes before any flush: committed-seq advances inside the write path pre-return (SL `transaction_manager.rs` L221-259; `batch_write.rs` L200-313); default reads `{Memory, dirty:false}` capped by `prepare_max_seq` (SL `reader.rs` L103-131); snapshot stability via pinned max-seq; object errors propagate as `Result` through the reader stack; negative control = failpoint `write-batch-pre-commit` (batch_write.rs L274-281).
**26 — P (G1/G12) with API basis:** per-Db settings; builder-level `with_block_cache_policy` (SL `db/builder.rs` L302); cross-Db cache sharing = one-line check at G1; aggregate budgets measured at G12 per v12's gate registry.

## F.5 Controller indexes, batching, anchors, incarnation (27–34)

**27 — I→R.** Controller-enforced unique unsequenced StatusKeys change no oracle behaviour (E.1-1) and exact replay is preserved because `iter_from` returns stored bytes in physical order — the file oracle's own pairing tolerates out-of-order statuses (isolation_manager L205-210).
**28 — R/E.** `WalIndexSegment` exact indexes (v12 §7.7): sorted exact keys for `(finalisation_operation_id)`, `(command_id, execution_epoch, attempt)`, `(StatusKey)`, plus the sparse TypeSequence/type indexes; lookup O(log n) per segment over the pinned catalogue version. Schema = E-obligation at G2 with vectors.
**29 — R.** `NoIntentProven` race rule (v12 §11): pin catalogue version + head, query segments, then one controller transaction re-checks catalogue unchanged + head unchanged + active-tail absence before journaling — CAS-equivalent; any interleaved finalisation bumps the head and forces re-run.
**30 — P (G2 kill gate).** Per-record baseline first; `WalRecordsFinalizedBatchV1` (bounded K/bytes, all-or-nothing, per-record responses, digest-chain rule: batch event carries the ordered record digests and one covering chain link) is specified as schema + model + failpoints before activation — E-obligation; measured against R2/DO amplification per v12 §25.
**31 — R.** Outbox signing: key id embedded per event; selection = key active at SQLite-commit time of the event row (recorded in the row), not flush time — deterministic under delayed flush; rotation = new key id forward-only, verifiers hold the keyring window.
**32 — R/D.** `RecoveryAnchor`: minimum trusted `(ControlSeq, head_digest)` written at every checkpoint activation + daily, to an independently controlled store (separate account + release package copy); residual suffix-deletion RPO = one anchor cadence; drill at G7.
**33/34 — R.** `ControllerIncarnationId` in every event/capability; catastrophic recovery mints incarnation N+1 under the external lock, rotates journal-signing and capability-parent keys, gateway and data-path reject incarnation < N+1, routing disables the old namespace; negative drill (old DO still alive, attempts event write + capability mint, both rejected) is the G7 exit criterion.

## F.6 Commands, data path, platform (35–44)

**35 — R (v12 order adopted).** `ASSIGNED → EXECUTING_PRE_INTENT → RESULT_BOUND → INTENT_FINALIZED`: transaction-local result bytes are generated inside the open transaction, uploaded (bounded size/duration), digest bound into the CommitRecord's command binding, then intent finalises. v11's PREPARING-before-EXECUTING withdrawn.
**36 — D, reclassified.** Command classes (insert_facts, upsert_entity, retract_facts, define_schema_step, import_batch) and the result ceiling are design data; ceiling and retention become G1-approved configuration with derivation (DO response and SQLite budgets), not asserted constants.
**37 — R.** `TerminalOutcome ⟂ ResultAvailability` stored as two columns/indexes; `RESULT_EXPIRED` is availability, never outcome; ledger compaction keys on outcome only.
**38 — P (G2/G6), premise corrected.** Per-object-class path selection: exact authoritative objects (WAL payloads, control events, results) via gateway or exact presigned PUT; SlateDB bulk via short-lived path/action-scoped temporary credentials (stale uploads orphanable). R2 temporary credentials and presigned URLs are the documented basis; exact scoping semantics are the G2 probe.
**39 — P (G2).** Checksums qualified per operation: single-part vs multipart (composite) explicitly distinguished; ETag never treated as digest; trusted streaming hash (gateway `DigestStream`) or re-read where the backend cannot prove full-object SHA-256.
**40 — P (G2/G6).** Gateway streaming limits measured (128 MB isolate ceiling as the documented bound; no buffering permitted by construction).
**41 — P (G6/G7).** Credential-parent revocation window measured in the incarnation drill (E.5-33).
**42 — P (G2/G6).** Full conditional/retry/metadata/range/multipart qualification per v12 §14 on the exact account/SDK — evidence archived.
**43 — I(doc)/D, superseded by current platform contract.** The R2 S3 API does not implement S3 Object Lock, but R2 now supplies native Bucket Locks that prevent overwrite/delete for a configured duration/date/indefinitely. V16 uses them as defence in depth while preserving separate operational, account-isolated, and independently administered backup classes; Bucket Locks are not marketed as malicious-administrator-proof legal-hold WORM.
**44 — R.** Gate registry normalised (capacity = G12; optional destructive GC = G13); v11's stray G13-capacity references corrected by this packet.

## F.7 Checkpoint, recovery, compatibility (45–50)

**45 — I→R.** Quiescence inventory (complete): client transactions, command executor, importer/migration, Statistics updater (unsequenced producer), the **source automatic checkpointer** (disabled entirely in the remote profile — E.2-9), **compactor publication** (paused: its manifest writes and protective-checkpoint metadata are physical roots under capture — v11's "compactor may continue" withdrawn per P1-11), and active-manifest maintenance. Resume after immutable contributions bind.
**46 — I.** The expected digest reads ordered per-keyspace scans under the pinned VisibilityWatermark through the normal MVCC-capped read path — raw reads are not needed and are forbidden here (raw surface reserved to generator init, E.2-7).
**47 — I/PATCH.** Recovery's only authoritative writes are re-derived StatusRecords (commit_recovery L175-199) — `READ_ONLY_BUILD` suppresses them and opens the durability client append-disabled (TB-P7 flag); generator initialisation performs raw *reads* only (vertex_generator anchors), no writes; schema init reads the schema keyspace. Negative test: any append attempt in READ_ONLY_BUILD is a typed fatal.
**48 — R.** Same-generation cutover and historical restore preserve: TypeSequence continuation (E.3-15), AppendLsn/lineage reset per v12 §15, VisibilityWatermark base, IID generator self-heal, permanent command-ID nonreuse across generations (ledger consulted at reservation), bookmark comparability rules (branch-qualified).
**49 — R/E.** Validator upgrades: drain-and-replace under a version fence — no mixed-version verdict window; `ValidationBasis` records the resolver version; recovery tooling ships N and N−1 resolvers; switch requires a quiesced boundary event.
**50 — E (G11/G13).** Root-closure parser inventory enumerated from the object-kind registry (versioned, unknown-kind-retained); v1 storage horizon = no deletion of anything (E.2-14 makes this trivial); evidence artifact at G11; destructive-GC preconditions unchanged (G13).

## F.8 Verdict summary

50/50 answered: 24 **I** (inspected-source, anchored — including 6/6 reviewer contradictions of v11 CONFIRMED against this agent's own prior answers), 14 **R** locked resolutions, 3 **D** design data reclassified, 9 **P** platform/gate-bound with documented basis, and every **E** executable obligation mapped to its gate. Two v11 statements are formally withdrawn (H-Q12 duplicate-status idempotency; R9 Admin pruning). No v12 binding invariant is contradicted by source; SL-P2 option A is upgraded from hypothesis to source-proven (the protective checkpoint's only purpose is GC protection, per the in-tree comment).

---

# Appendix G — Cargo/test source-owner return packet (pinned checkout evidence)

Anchors: TB `2256711a` unless noted. Verdicts per the v12/v13 taxonomy (I/R/D/P/E).

## G.1 Reviewer anchor re-verification — listed anchors; machine count remains G0 evidence

1. Root `Cargo.toml` header: "Generated by TypeDB Cargo sync tool. Do not modify this file." (L1-2); declares 16 `[[test]]` targets incl. `test_assembly` (tests/assembly/assembly.rs), `test_fail_points`, behaviour/HTTP suites (L89-131) and 2 root benches. **I.**
2. `tool/rust/sync.sh` L9: `bazel run @typedb_dependencies//tool/ide:rust_sync -- @typedb_workspace_refs//:refs.json` — Cargo metadata is Bazel-downstream at the pin. **I** → the fork-owned-manifest rule (v14 P0-1) stands.
3. `tests/assembly/BUILD` L8-16: per-platform `TYPEDB_ASSEMBLY_ARCHIVE` env `select` (5 platforms); `test_assembly` has `data = ["//:assemble-typedb-all", ":script.tql"]` (L17-24) — archive + script are runfiles, exactly the fixture semantics v14 P0-5 requires the Cargo runner to stage. **I.**
4. `tool/test/simulate-crash.sh` L14-22: docker-runs `bazel:assemble-linux-x86_64`, kills and restarts — the xtask port (v14 P0-8) is confirmed necessary. **I.**
5. Failpoint registry: `common/fail_point` generates `pub const ALL: [&str; COUNT]` via macro (fail_point crate L26-29); the composite harness iterates `fail_point::ALL` at `tests/assembly/fail_points.rs` L95 and L126 — two loops, so leaf-case accounting per registry member × loop context (v14 P0-4) is confirmed real. **I.**
6. Workspace: 41 members enumerated at root `Cargo.toml` L157-159 (exact list frozen into the G0 catalogue). **I.**

## G.2 The real target-level denominator (counted from the checkout)

`[[test]]` / `[[bench]]` census across every non-generated-excluded manifest:

| Manifest | tests | benches |
|---|---:|---:|
| root `Cargo.toml` | 16 | 2* |
| `executor` | 11 | 1 |
| `query` | 6 | 2 |
| `storage` | 5 | 2 |
| `database` | 5 | 0 |
| `ir` | 4 | 0 |
| `encoding` | 3 | 1 |
| `concept` | 3 | 1 |
| `durability` | 2 | 1 |
| `server`, `admin`, `function`, `compiler` | 1 each | 0 |
| **Total** | **59** | **8** (root benches are `[[test]]`-declared bench harnesses `bench_concurrency`/`bench_iam`, counted in the 16) |

This is the **target-level** denominator only. Leaf-case expansion (libtest cases, Cucumber scenarios, `fail_point::ALL` members × contexts, scripts, STATIC_CHECKs) is the executable G0-CARGO artifact per the v14 catalogue schema — with one correction now possible: `fail_point::ALL` gives the failpoint member count mechanically at build time, and the scenario count comes from the newly pinned behaviour repo (G.3). Unit tests inside `crate-unit` wrappers (`storage/BUILD` L39-50 pattern) map to ordinary `cargo test --lib/--bins` per member crate.

## G.3 New mandatory source pin — the behaviour corpus

`MODULE.bazel` L189-194: `git_override(module_name = "typedb_behaviour", remote = "https://github.com/typedb/typedb-behaviour", commit = "ac5d5733a484cea1d8809a2968029a818fdae24f")`. The `.feature` files defining every Cucumber scenario are **not in the TypeDB repository**. Consequences (normative): (a) the source lock gains `BH = typedb/typedb-behaviour @ ac5d5733…`; (b) the monorepo vendors it read-only under `third_party/typedb-behaviour/` with hash attestation; (c) the leaf-case catalogue's scenario denominator is computed from BH, and a BH bump is a catalogue drift event (v14 P1-9) exactly like a BUILD change; (d) the Cargo runner stages feature files as runfiles with hashes, replacing Bazel's data wiring.

## G.4 Return-packet items → disposition

Cargo metadata + executable/case lists: **E at G0-CARGO** (the harness emits them; format = v14 catalogue schema). Bazel query snapshot: **R** — one locked `bazel cquery` snapshot is produced once on a sacrificial machine as the audit oracle, archived as evidence and never used by ordinary CI or release builds (Mode Q); Mode S executes no Bazel at all. Runfile/env/data/timeout matrix: **I-seeded** (F.1-3 gives the assembly rows; remainder at G0). Constructor inventory (P0-9): **E at G0**, with the known seeds: keyspace/file-WAL constructors in `storage/tests/*`, `durability/tests/*`, server boot in behaviour steps. U0–U4 applicability, Console fixture (pin by URL+SHA-256+licence of the released Console matching the pinned server version), crash-script port, feature/cfg comparison, exact counts/exclusions, min patch set, tested-equals-shipped digest: all **E** with owners in §P phases; none requires further design.

---

# Appendix H — Federated repository blueprint

## H.1 Tree

```text
bioaxiom-typedb-r2/
  source-lock/
  fork/typedb/
  fork/slatedb/
  tools/
  control-plane/
  infra/
  fixtures/
  docs/
```

The authoritative details are §21.1. No root Cargo workspace lists the upstream TypeDB and SlateDB members together.

## H.2 Optional orchestration

A thin root script may run named Cargo/pnpm tasks. Moonrepo, `just`, Make, or another runner is permitted only by ADR and must satisfy:

- pinned binary and source;
- no manifest generation;
- no test discovery or denominator ownership;
- no correctness-affecting hidden environment;
- no cache reuse for real-account/credential/fault tests;
- clean direct-command reproduction without the runner.

The release manifest records whether an optional runner was used, but its absence cannot prevent reproduction.

## H.3 Source import/rebase

- TypeDB is imported with upstream paths preserved.
- SlateDB is imported with upstream paths preserved.
- Fork patches are rebased in stable series order.
- `typedb-behaviour` is a read-only fixture source.
- proof-critical TypeDB external repos/artifacts are mirrored or materialized by digest.
- upstream Cargo and BUILD/Starlark changes are audited independently.
- no generated source is accepted without generator identity and deterministic reproduction.

---

# Appendix I — Cloudflare source and contract matrix

All URLs are official unless explicitly marked source repository.

| ID | Area | Source/contract | V16 use | Required probe |
|---|---|---|---|---|
| CF-R2-LOCK | R2 Bucket Locks | `https://developers.cloudflare.com/r2/buckets/bucket-locks/` | overwrite/delete defence in depth | create locked prefixes; existing/new object; overwrite/delete; overlapping rules; audit/removal permissions |
| CF-R2-CRED | temporary credentials | `https://developers.cloudflare.com/r2/api/s3/temporary-credentials/` | bucket/path/action/TTL-scoped access | exact action denial, path denial, expiration, parent revocation |
| CF-R2-S3 | S3 compatibility/checksums | `https://developers.cloudflare.com/r2/api/s3/api/` | condition/checksum/multipart contract | full/composite checksum, same-part failure, headers, conditional errors |
| CF-R2-CONS | consistency | `https://developers.cloudflare.com/r2/reference/consistency/` | exact-key ambiguity resolution basis | write/read/list/concurrency without CDN cache |
| CF-R2-LIMIT | limits | `https://developers.cloudflare.com/r2/platform/limits/` | object/part/request/key limits | maximum sizes, 429, multipart limits |
| CF-DO-RULES | DO concurrency | `https://developers.cloudflare.com/durable-objects/best-practices/rules-of-durable-objects/` | input/output gate semantics | forced interleaving around non-storage awaits |
| CF-DO-LIMIT | DO limits | `https://developers.cloudflare.com/durable-objects/platform/limits/` | storage/row/CPU/QPS/connection budgets | overload, SQLITE_FULL guard, statement/parameter bounds |
| CF-DO-ALARM | alarms | `https://developers.cloudflare.com/durable-objects/api/alarms/` | wake-up/retry semantics | duplicate, throw, reset, exhausted automatic retries, manual reschedule |
| CF-CTR-ARCH | Container lifecycle | `https://developers.cloudflare.com/containers/platform-details/architecture/` | ephemeral disk, DO separation, sleep, shutdown, HTTP ingress | location separation, cold start, sleep, SIGTERM/SIGKILL |
| CF-CTR-ROLL | rollouts | `https://developers.cloudflare.com/containers/platform-details/rollouts/` | mixed Worker/image deployment | old/new image traffic, failed rollout step, rollback |
| CF-CTR-LIMIT | Container limits | `https://developers.cloudflare.com/containers/platform-details/limits/` | 4 vCPU/12 GiB/20 GB ceiling | sustained resource pressure and image size |
| CF-CTR-EGRESS | outbound traffic | `https://developers.cloudflare.com/containers/platform-details/outbound-networking/` or current canonical page | allowlisted HTTP/HTTPS and runtime CA | `enableInternet=false`, handler routing, TLS failure |
| CF-W-LIMIT | Worker limits | `https://developers.cloudflare.com/workers/platform/limits/` | 128 MB and connection/subrequest budgets | gateway streaming/memory/connection exhaustion |
| CF-CTR-SRC | helper source | `https://github.com/cloudflare/containers` + locked npm tarball | `DatabaseContainerDO` only | package/source mapping, unit tests, rollout/reset/lifecycle races |
| CF-SDK-SRC | Workers tooling/runtime | `https://github.com/cloudflare/workers-sdk` + locked packages | Wrangler, local test runtime, generated types | local/remote behavior delta, package/runtime identity |

The contract lock stores retrieved bytes and hashes, not just URLs.

---

# Appendix J — Implementation-agent playbook

The agent executes phases in order. Every phase produces immutable evidence and may stop the programme. Parallel work is allowed only when dependencies below are satisfied.

## J.0 Phase A — Source graph and document integrity

**Patches:** `TB-P0`, `SL-P0`, `BT-P0`, `CF-P0`.

**Work**

- materialize every §1 source node;
- resolve tags/artifacts/images/packages to immutable identities;
- choose Bazel evidence Mode Q or S;
- create federated workspaces and offline dependency stores;
- generate platform contract lock;
- run document/schema/patch/gate linter.

**Done**

- G0 source graph has no unresolved shipping/proof node;
- clean offline parity-lane build starts;
- missing-node negative control fails.

## J.1 Phase B — Corpus catalogue and pristine U0

**Patches:** `BT-P1`, `BT-P2`.

**Work**

- enumerate Cargo/BUILD/Starlark targets;
- enumerate libtest, doctest, Cucumber, failpoint, script and static cases;
- stage fixtures and environment;
- execute U0 under Rust parity lane;
- record pre-existing failures/flakes without retry-created green.

**Done**

- zero unknown target/case/fixture/profile;
- removed-scenario/failpoint/runfile negative controls fail infrastructure;
- catalogue and raw results archived.

## J.2 Phase C — Safe TypeDB oracle boundaries

**Patches:** `TB-P1`, `TB-P2`, `TB-P3`, `BT-P3`.

**Work**

- safe cursor ownership;
- storage/durability interfaces and typed errors;
- RocksDB adapter;
- backend/profile injection;
- U0/U1 after each small patch.

**Done**

- structured equality;
- no engine leakage;
- no environmental panic in modified paths.

## J.3 Phase D — Pure distributed models and Cloudflare probes

**Patches:** `CT-P0`, `CF-P3`, `DP-P0`–`DP-P3`.

**Work**

- model WAL/status/iterator, resolver/apply, commands, checkpoint, journal/anchor, controller/lifecycle separation;
- implement R2 credentials/checksum/multipart/Bucket Lock probes;
- implement DO interleaving/alarm/overload probes;
- implement Container lifecycle/rollout probes.

**Done**

- G1 green;
- every platform fact has raw evidence or remains a stop item.

## J.4 Phase E — Remote append/data-path spike

**Patches:** `CT-P1`–`CT-P5`, `DP-P1`–`DP-P3`, minimal `TB-P4` client spike.

**Work**

- real controller SQLite/outbox;
- payload upload/finalisation/sync/iterator/status;
- exact indexes;
- per-record and explicit batch candidates;
- kill/ambiguous/overload tests.

**Done**

- G2 green or architecture revised before broad fork changes.

## J.5 Phase F — Shared resolver and SlateDB LocalFS

**Patches:** `TB-P4`–`TB-P8`, `SL-P1`–`SL-P4`, `BT-P3`.

**Work**

- remote durability integration;
- shared resolver and recovery modes;
- SlateDB adapter with minimal feature set;
- explicit compactor;
- U2/U3;
- all publication and visibility fault tests.

**Done**

- G3–G5 green.

## J.6 Phase G — Cloudflare lifecycle and production object path

**Patches:** `CF-P1`–`CF-P5`, `DP-P4`, control-plane packages.

**Work**

- split controller/lifecycle DOs;
- compatibility envelope;
- HTTP proxy/facade;
- egress and credentials;
- real R2/Containers;
- mixed rollout and arbitrary-kill tests.

**Done**

- G6 green and U4 release package can start/recover.

## J.7 Phase H — End-to-end recovery, commands, checkpoint, backup

**Patches:** `TB-P9`, `CT-P6`–`CT-P8`.

**Work**

- transaction recovery;
- command outcomes;
- checkpoint/digest/verifier;
- rebuild/cutover/restore;
- pins/backup/anchor/incarnation recovery.

**Done**

- G7–G11 green.

## J.8 Phase I — Qualification and release

**Patches:** `TB-P10`, `BT-P4`–`BT-P6`, operational/security artifacts.

**Work**

- qualification Rust lane;
- tested-equals-shipped package;
- capacity, SLO, cost, rollout, soak;
- security/licence/SBOM;
- runbooks/game days;
- final source/platform contract refresh.

**Done**

- G12 and G14 green; G13 only when deletion is intentionally shipped.

### J.9 Standing agent rules

- never infer a green gate from prose;
- never weaken an invariant to make a test pass;
- never hide a contradiction as an exclusion;
- update spec, model, schema, catalogue and tests in one change when an assumption changes;
- retain raw commands, stdout/stderr, seeds, account/profile, toolchain and digests;
- stop the affected phase on source/platform disagreement;
- use a new ADR for every new authority, durable format, feature, background task, credential class, or delete path.

---

# Appendix K — V15 adversarial closure

V15's transaction/storage core survived this review. The following changes are design-significant and must be confirmed by the source-owning implementation agent:

1. verify the selected TypeDB snapshot and all `MODULE.bazel` external nodes as one lock;
2. generate—not narrate—the final test denominator;
3. prove the Console/Loader fixture identity and required package layout;
4. preserve TypeDB/SlateDB Cargo workspace semantics in the repository layout;
5. map every Cloudflare npm package to exact source;
6. validate `@cloudflare/containers` lifecycle behavior under code update and rollout;
7. keep the lifecycle DO separate from the database controller;
8. demonstrate controller correctness across non-storage awaits and request interleaving;
9. demonstrate alarm recovery after automatic retries are exhausted;
10. prove exact delete denial in every runtime R2 credential;
11. install/audit Bucket Locks before authority traffic;
12. prove multipart identity and failed-part behavior;
13. qualify the minimal SlateDB feature set;
14. remove native TCP/gRPC from V1 claims;
15. prove mixed Worker/image compatibility and rollback;
16. select one release Rust toolchain through dual-lane evidence;
17. reconcile every existing V15 patch/playbook reference with §23/J;
18. return raw G0/G1/G2 evidence and every contradiction discovered.
