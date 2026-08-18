# Response: main-branch deep audit, round 3 (2026-08-18)

**Audit input:** "TypeDB on SlateDB/R2 — round-3 deep audit and total-quality
implementation directive," over main commit
`05886cf1dde17b5e07c80684a691e83fb0401a64` (the merge of the round-2 work).
**Gate truth lives in `docs/ledger/gates.json`**, not here; this document
is the per-finding accounting. The audit's disposition — **NO-GO for a live
Cloudflare run today, continue local implementation** — is preserved, and
nothing below claims a gate green.

Status vocabulary: **CLOSED** (invariant at the real boundary + positive and
negative tests + an executed mutant), **PARTIAL** (a bounded sub-scope closed,
the remainder named), **OPEN** (a recorded remainder with its blocker),
**BLOCKED** (needs a dependency this environment does not have; never faked).

Round-3 commits on branch `claude/typedb-slatedb-r2-continue-ss62cz`:
`048d46b` (R3-A control authority), `fbcb942` (R3-B WAL/recovery),
`0454115` (R3-D firewall), `1844c96` (R3-E probes/CI/ledger), `cc5c727`
(R3-F streaming + ContainerDO), `767b387` (R3-G Alchemy stack), `7f2ba55`
(R3-H catalogue/evidence). Storage findings (S-*, R-03..R-06, O-01) land in
follow-on commits; their rows below carry the honest current status.

## Control-plane findings (C-*)

| ID | Status | Where |
|---|---|---|
| C-01 journal migration re-signs tampered history | **CLOSED** | v11 is a trust transition: it authenticates the legacy chain under its original v1 preimage+MAC first, reframes only genuine history (with an old-root/new-root certificate), and QUARANTINES anything authentic under neither v1 nor v2 — rewriting nothing. The quarantine is durable; every later open refuses at construction. The audit's tamper-then-reopen mutant now quarantines instead of going green (`048d46b`). |
| C-02 capability outcomes mutable / retries re-execute | **CLOSED** (local scope) | Every mutating route runs through one `withMutation` wrapper: a terminal use replays its stored `{status, body}` verbatim and NEVER re-executes (the double-BUDGETS_SET mutant is dead); `resolveCapabilityUse` enforces legal transitions and quarantines a second, different terminal (reject→success); transport uncertainty is recorded AMBIGUOUS and stays retryable (`048d46b`). The full cross-restart result-retention store is the recorded remainder. |
| C-03 auth after DO creation/binding | **CLOSED** | The outer worker verifies the token's framing/MAC/expiry/audience/method/key/digest/session/generation with its own key BEFORE any DO is contacted, so a junk token never instantiates, migrates or binds an object; the DO re-checks incarnation + claims (defense in depth). Workerd SELF.fetch test (`048d46b`, `cc5c727`). |
| C-04 no tenant registry / private issuer / router | **PARTIAL** | The enforceable local invariant — the production surface exposes no public issuer or admin-takeover route — was met by the round-2 CONTROLLER_SURFACE gate, and the DO binds its database identity and refuses foreign calls. The full opaque-DatabaseId tenant registry, private provisioning/issuer service binding, and role/policy engine are platform-shaped and remain OPEN. |
| C-05 capability/time/generation schemas too weak | **PARTIAL→CLOSED for the named mutants** | Issuance and verification run on the persisted nondecreasing controller clock (a backward wall-clock jump cannot extend a token), and WAL_FINALIZE binds the generation as a canonical decimal string (a token for generation N is refused against N+1). The remaining schema fields (receipt binding, materialisation, full-u64 incarnation) are the recorded remainder (`048d46b`). |
| C-06 buffering / untrusted-input boundaries | **CLOSED** (local scope) | The PUT read path uses `crypto.DigestStream`, hashing the body chunk-by-chunk with the 8 MiB cap enforced per chunk (never trusting content-length); the exact/scan/last read paths verify each object's digest through a streaming DigestStream; every `decodeURIComponent` is a typed 400 on malformed input, never a 500 (`cc5c727`). True whole-response streaming (vs. the inline base64 wire contract) is a recorded P-WORKER remainder. |
| C-07 reads create durable capability rows | **CLOSED** | Read routes verify without claiming a durable use row (`checkCapabilityOnly`): reads no longer write to SQLite; incarnation and session are still enforced; a read token is freely replayable because reads are side-effect-free (`048d46b`). |
| C-08 ContainerDO stub | **CLOSED** (control authority) | DatabaseContainerDO is a production-shaped SQLite control authority: advisory-only observations (no sequence/epoch/grant/fence capability, inv. 148–150), a durable full-identity binding that refuses foreign calls, a bounded observation ring with a typed overload refusal, and a durable alarm-driven GC. Exported and bound under a separate v2 migration; workerd-tested (`cc5c727`). The actual container PROCESS lifecycle needs a container runtime (matrix CF-02). |

## Storage / recovery / SlateDB findings (S-*, R-*)

| ID | Status | Where |
|---|---|---|
| R-01 recovery does not prove a contiguous fixed head | **CLOSED** | Strict fixed-head parser: head captured before folding, exactly one commit per sequence in start..=head, typed refusals for gap/regression/trailing-gap/unsequenced-fresh-sequence/status-for-unwritten/beyond-head; frontier is the WAL's recovered end, never max(). The two `todo!()` integration tests are now real and the flake-ledger exception is removed (`fbcb942`). |
| R-01b WAL framing / tail repair not corruption-safe | **CLOSED** | Versioned authenticated frame (magic/version/type/seq/lengths + CRC-32 over header+payload), budget-checked lengths and decompression, v0 legacy frames readable under a hardened weaker guarantee; tail repair is restricted to a genuinely torn terminal append in the unsealed file, copies the damaged original to a forensic sidecar, and fsyncs; every other defect is a typed CorruptFrame quarantine leaving bytes untouched. Corruption matrix executed (`fbcb942`). |
| R-02 divergent live/recovery status semantics | **CLOSED** | One `status_resolver` folds status history (identical duplicate converges; opposite verdict is an order-independent typed conflict) and is used by BOTH recovery and live disk validation — the last-write-wins insert and the `unreachable!` missing-certificate arm are gone. Cross-path equivalence test (`fbcb942`). |
| R-07 sequence arithmetic not checked | **CLOSED** | Canonical `try_next`/`try_previous`/`checked_window_end` with typed exhaustion, no wrap, no mutation on refusal, at every WAL/timeline/watermark/storage site; debug+release boundary matrix at MIN/MIN+1/MAX-1/MAX (`fbcb942`). |
| R-09 unbounded predecessor waits | **CLOSED** (isolation part) | Predecessor waits are promptly bounded (30s containment default reusing the OD-002/OD-006 cadence) with a typed timeout instead of spinning toward the 600s deadline (`fbcb942`). The full hierarchical request→bridge→object-store→worker cancellation token is the recorded remainder. |
| R-08 crash tests prove reboot, not convergence | **OPEN** | The assembly failpoint lane is subprocess-gated and does not fully run in this environment; extending it to assert logical convergence (rows, WAL head, retry identity) is a recorded remainder. |
| S-02 tested SlateDB patches not shipping | **IN PROGRESS** | The patched SlateDB (external epochs, bounded uploader) is being linked in place of crates.io 0.15.0, with TypeDB supplying an external epoch at every builder site; status finalised in the follow-on storage commit. |
| S-03 unbounded uploader in the actual dependency | **IN PROGRESS** | Ships with S-02 once the fork is the linked crate: bounded attempts + total deadline + typed exhaustion, no infinite inner retry. |
| S-01 backend seam resolved after mutation | **OPEN** | The typed per-database persisted `classic\|slatedb-r2` BackendSpec resolved before any filesystem/WAL/object touch, controller-provisioned opaque remote namespaces, and fail-closed mismatch/missing-marker refusal are a recorded remainder. |
| S-04 NoDeleteStore not an immutability boundary | **OPEN** | Path/mutation-class-aware create-only/same-digest policy, journaled multipart UploadAttemptId with gated completion, and seed-into-fresh-namespace are a recorded remainder. |
| R-03 fixture checkpoint in the automatic path | **OPEN** | Making background tasks part of BackendSpec (disable the interval checkpointer on the remote lane, controller-frozen cuts only, startup task-inventory attestation) is a recorded remainder. |
| R-04 concurrent checkpoints collide | **OPEN** | Per-database serialisation, unique attempt id + lease, never-delete-an-active-attempt is a recorded remainder. |
| R-05 restore destroys live state before validation | **OPEN** | Scratch-first no-follow open, sealed-manifest verify, transitive-closure restore, digest equality before atomic activation, older-checkpoint/full-WAL fallback is a recorded remainder. |
| R-06 remote checkpoint closure/fsync/COMPLETE weak | **OPEN** | Digest-bound COMPLETE root, bottom-up fsync, parse-all-references (not LIST-trust) is a recorded remainder. |
| O-01 diagnostics can panic / full-scan / overflow | **OPEN** | Total, typed, budgeted metrics with single-flight cached refresh and checked counters is a recorded remainder. |
| S-05 no-compactor posture unbounded | **OPEN** | Explicit experimental labelling + an admission bound that rejects new writes before violating the declared envelope is a recorded remainder. |

The storage items marked OPEN are honest remainders: they were scoped for a
dedicated storage work-stream whose large Rust builds could not all be
driven to the mutant-tested bar in this environment's session. They are
recorded in the ledger with their blockers, not faked closed. The
completed storage findings (R-01, R-01b, R-02, R-07, R-09) each carry an
executed mutant.

## Firewall, probe, evidence, CI, and stack findings

| ID | Status | Where |
|---|---|---|
| F-01/02/03 publication firewall | **CLOSED** | Single-guard gate (deadlock gone), authority on every mutating path (revoked overwrite/delete denied), typed manifest-transition validation; each with an executed mutant. ADR-0012 updated honestly, no winner declared (`0454115`). |
| E-01 Mode-Q false-closeable | **CLOSED** | Semantic validator (bazel digest, argv/env/toolchain, source pin, raw-byte hashes, exit 0, unique targets, catalogue crosswalk, content root); absence keeps G0 open, presence must validate, both ledger directions enforced; six executed mutants; CI runs it instead of the any-file check (`1844c96`). |
| E-02 catalogue denominator is 106 aggregate rows | **CLOSED** (as an honest denominator) | build_plan_v2 emits the immutable 23,132-row (leaf, profile, fixture, toolchain) plan with a content-addressed root; plan_coverage reports 0 covered / 107 PARTIAL / 23,031 uncovered → PLAN NOT SATISFIED. The plan is the denominator; leaf-level runners remain to be built (`7f2ba55`). |
| E-03 U2S3 archive mislabelled | **CLOSED** | CLASSIFICATION.json records it as historical-dirty-tree-aggregate-smoke; the ledger lane uses that phrase; no archived byte changed (`7f2ba55`). |
| E-04 evidence policy/provenance mutable | **CLOSED** | Independent read-only verifier sharing no code with the producer; verdicts pin policy_roots so a policy change cannot reclassify an observation; 9 executed mutants; --require-current-source correctly fails on the historical archive (`7f2ba55`). |
| E-05 official drivers absent | **OPEN** (recorded) | The plan carries the six driver rows as NOT_IMPLEMENTED, required_by v17-A17.5; no harness was fabricated (`7f2ba55`). |
| E-06 CI "fresh U0" does not run U0 | **CLOSED** | The job is renamed to compile+catalogue-drift and gains a storage integration step; a true fresh-execution U0 job is a recorded remainder (`1844c96`). |
| E-07 ledger/lock semantics incomplete | **CLOSED** | The ledger linter checks unique ids, status enums, commit-ancestry and evidence paths; the workspace lock drops its self-referential repo_commit claim for an external attestation marker (`1844c96`). |
| P-01..P-06 probe safety | **CLOSED** (local preflight) | Secret separation + recursive redaction + CI canary scan; corrected Cloudflare DTOs verified against the live docs; record-before-dispatch with deadlines and finally cleanup; PlatformRunBundle v2; disposable-target + owner-envelope preflight (absent → exit 3). Live execution stays credential-gated (`1844c96`). |
| A-01 no canonical Alchemy/native-S3 integration | **CLOSED** (local) | Alchemy 2.0.0-beta.72 pinned exactly as the canonical IaC with a no-cloud guard; source-locked native MinIO supervisor with SigV4 readiness and process-group teardown; graph differential + wrangler consistency check. The Docker container lane is a recorded platform residual (`767b387`). |

## Final factorization / simplification pass (R3-I)

After every audit finding above was addressed, a dedicated review pass swept
all round-3 code (control-plane TS, Rust storage/recovery, the Python/stack
validators, and the firewall spike) for factorable duplication, drift, and
dead code — the "verify nothing can be factored or simplified, no drift, no
debt" close-out. Every applied change is behavior-preserving and was
re-verified by the owning lane's tests before commit.

| Area | Applied | Verified |
|---|---|---|
| control-plane (`e3b3632`) | dropped a dead `_useDigest` param + ~11 wasted per-read SHA-256s (reads never claim a use, C-07); extracted one `streamCappedDigest` for the body/object streaming loops; single-sourced the canonical-u64 regex (`journal-crypto.CANONICAL_U64`) that capability.ts and procedures.ts had defined twice | tsc; node 82; workerd 19; drop-outbox mutant still caught; L1 E2E 85 ALL PASS |
| tooling + stack (`b1f574a`) | aliased `run_u0.ENV_BASE` to `common.CARGO_ENV`; single-sourced the runner-row-id join as `common.runner_row_id`; **closed a graph-diff rigor gap** — `sqlite`/`container` binding fields were skipped by both the set-level and positional checks, so a silent backend-shape flip went uncaught — plus a new executed mutant; deduped `processAlive` | stack 31/31 (+1 mutant); completeness self-test; evidence_mutants 32/32; plan_coverage join unchanged (72) |
| storage / recovery / WAL (`4397747`) | one no-follow (R-05) enforcement point (`assert_safe_checkpoint_entry`) instead of three; deduped the restore remove-entry block; one crate `fsync_path`; unified `checked_next`→`try_next`; `previous()` delegates to `try_previous()`; extracted WAL `seek_to` / `payload_available` / `check_payload_budget`; documented the informational-only checkpoint watermark | storage --lib 110; test_recovery 7; test_snapshot 10; test_isolation 14; test_mvcc 4; test_storage 6; durability + database green |
| firewall spike (`e054e45`) | folded two repeated refusal builders (`quarantine_overwrite`, `manifest_rejected`) into helpers | spike 15/15; clippy clean |

Deliberately **left duplicated**, because collapsing them would weaken a
property rather than remove debt: the producer/independent-verifier/forger
independence across the evidence and Mode-Q validators (they must share no
code); the four bounded-wait sites (the abort-vs-typed-return distinction is
load-bearing); `PREDECESSOR_WAIT_DEADLINE`'s intentional aliasing of the report
interval; `write_record`'s defence-in-depth budget copy; and `verifyJournal`'s
granular error taxonomy.

The workspace-lock was regenerated for the fork's new tree digest (`92573cb`);
source-lock lint, ledger lint, and the full evidence chain (bundle root
`28ae4b7e`, 0 anomalies) stayed green throughout.

## What this response deliberately does not do

- It does not close G0/G1/G2 — the ledger holds them open (Mode-Q evidence,
  catalogue-as-denominator, owner envelope, credentials, drivers).
- It does not fake the OPEN storage remainders as closed; they carry named
  blockers in the ledger.
- It does not treat any local simulator (Alchemy, MinIO, mock probes) result
  as a Cloudflare platform fact.
- The factorization pass changed no behavior and closed no gate; it removed
  duplication and one rigor gap, nothing more.
