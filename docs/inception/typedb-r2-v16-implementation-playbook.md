# V16 implementation-agent playbook

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

