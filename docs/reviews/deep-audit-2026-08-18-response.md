# Response: main-branch deep audit, 2026-08-18

**Audit input:** "typedb-r2 main-branch deep audit and total-quality
implementation directive" over main commit `640c7d46` (adopted in
`docs/ledger/gates.json` → `adopted_audit`). **Gate truth lives in the
ledger**, not here: this document is the per-finding accounting - what was
implemented, in which commit, and what remains open with its named blocker.
The audit's NO-GO stance is preserved; nothing below claims a gate green.

Status vocabulary: **CLOSED** (invariant enforced at the real boundary +
negative tests + executed mutant), **PARTIAL** (a bounded sub-scope closed;
remainder named), **BLOCKED** (not implementable in this environment; the
external dependency named; never faked).

Commits referenced: `db1a103` (PR0/PR1), `5d072c6` (PR2/PR3), `36f3f9f`
(PR8), `20f542b` + `864e727` (PR4), `60da7d8` (PR5 part 1), `0b407ff`
(PR7), plus the follow-up commits noted inline.

## Evidence/G0 findings (E-P0)

| Finding | Status | Where |
|---|---|---|
| E-P0-01 Mode-Q evidence absent → G0 false-green | **BLOCKED** (evidence), truth CLOSED | No Bazel toolchain here. G0 is OPEN_RED in the ledger; the static avoidance proof is banner-superseded as authority; CI's Mode-Q consistency check fails any ledger that closes G0 without evidence (`0b407ff`). |
| E-P0-02 source-lock forgeable | **CLOSED** | Per-kind fail-closed validators reconciling every consumer lock; OBJECT_STORE 0.14.1 mismatch repaired; 7 executed forgery mutants held (`db1a103`). |
| E-P0-03 catalogue identity collapse | **CLOSED** (identity), catalogue v2 OPEN | The catalogue→runner join refuses on row-id collision (`5d072c6`). The full leaf/profile qualification plan (PR2) remains OPEN; its Mode-Q crosswalk is Bazel-blocked. |
| E-P0-04 leaf/profile reconciliation absent | **PARTIAL** | Execution reconciliation now states its denominator scope machine-readably (`denominator_scope: cargo-targets-only`) and prints the non-reconciled leaf families every run (`5d072c6`). Per-leaf reconciliation for composite suites remains OPEN (PR3 remainder). |
| E-P0-05 evidence forgeable via JSON-aggregate trust | **CLOSED** | Verdicts re-derive from raw logs: reparse, per-log sha256 binding, duplicate/shared-log refusal, bundle root sealed COMPLETE-last; 32 behavioral mutants over the real CLI held (`5d072c6`). CI re-verifies the archived bundle on every commit (`0b407ff`). |
| E-P0-06 flake policy unbound | **CLOSED** | The flake ledger binds exact case-name fingerprints and the observed execution profile, both checked against the logs on every verdict (`5d072c6`). |
| E-P0-07/08 official drivers absent | **BLOCKED** | External repositories + harness build-out; ledger lane OFFICIAL_DRIVERS = NOT_IMPLEMENTED; CI header records the exclusion. Nothing pretends otherwise. |
| E-P0-09 CI non-enforcing | **CLOSED** (core), release lanes OPEN | All actions SHA-pinned, exact runner/tool versions, ledger linter, lock mutants, archived-bundle re-verification, probe self-test, workerd E2E in CI; dispatch-only fresh-qualification job (`0b407ff`). SBOM/provenance/tested-equals-shipped await a release pipeline (recorded in the workflow header + ledger). |
| E-P0-10 decorative grep-mutants | **CLOSED** | Every remaining mutant lane is behavioral (subprocess over the real tool, named defect, killed-then-restored): locks 7, evidence 32, probes 2+18 controls, storage 4+, control-plane standing mutant in CI. |

## Control-plane findings (C-P0 / C-P1)

| Finding | Status | Where |
|---|---|---|
| C-P0-01 Rust client / Worker protocol drift | see PR4b section below | |
| C-P0-02 no tenant authorization boundary | **PARTIAL** | Locally closed: production surface gate (dev routes physically absent), credentialed issuance, and the immutable DO database binding - every database-scoped DO method refuses a foreign identity before any SQL/R2 (`864e727`, workerd-tested). Full tenant/environment registry, authenticated ingress and external recovery root are platform work (ledger PR4 remainder). |
| C-P0-03 legacy register takeover | **CLOSED** (production) | `/session/register` and `/session/fence` do not exist on the production surface (CONTROLLER_SURFACE gate, fail-closed on unset; `20f542b`). On the dev surface register remains the lifecycle macro (activation is still the only fencing mechanism). |
| C-P0-04 authority not incarnation/generation-bound | **CLOSED** (local scope) | `requireLeasedAuthority` binds state+lease+incarnation+current-generation; rollover moves commit authority (old generation → SESSION_GENERATION_MISMATCH); `bumpIncarnation` transactionally revokes all live sessions and fences all actors with a checked increment; both audit counterexamples now refuse and are pinned by tests (`20f542b`). External recovery root for incarnation recovery is platform work. |
| C-P0-05 legacy sessions fail open | **CLOSED** | No-lifecycle-row → SESSION_UNMIGRATED (never a pass); migration v10 maps every historical session to terminal REVOKED/EXPIRED, journaled; fixture test proves a live historical session cannot finalize (`20f542b`). |
| C-P0-06 historical migration broken | **CLOSED** | Byte-exact era-A fixture (verbatim schema from commit `732ffb5`); v9 copy/verify/swap rebuilds (INTEGER→u64 blob via CAST-to-TEXT, lossless at 2^53+1 and high-i64; hash-less outbox → v2-framed chain); crash-after-every-statement convergence matrix; idempotent re-open; future-schema refusal (`20f542b`). |
| C-P0-07 arbitrary global R2 references | **CLOSED** | Finalize and every batch member must present exactly `p/<db>/<digest>`; cross-database or digest-disagreeing references refuse with zero R2 I/O; E2E covers both refusals (`20f542b`). Signed provider receipts (ObjectReceiptV1) remain platform work. |
| C-P0-08 capability burn without outcome machine | **CLOSED** (local scope) | `claimCapability`: nonce durably bound to the canonical digest of the ONE authorized request; identical retry admits (procedures are idempotent by operation identity), different request → CAPABILITY_REPLAYED; worker records RESOLVED_SUCCESS/REJECTED/AMBIGUOUS; transport uncertainty stays retryable (`20f542b`; E2E single-request-capability check). |
| C-P0-09 batch ahead of contract | **CLOSED** (containment) | Batch is physically absent from the production surface; on the dev surface K/aggregate-byte bounds run before capability and before any receipt GET (`20f542b`). The v16-authorized batch contract itself stays post-G2. |
| C-P0-10 probe runner false-green | **CLOSED** | All 14 normative IDs, manifest-count contract, PASS/FAIL/NOT_RUN/PREREQUISITE_MISSING with fail-closed aggregation (the audit's mocked-500 case now exits 1), sealed evidence bundles, 18-control self-test in CI, two executed harness mutants (`36f3f9f`). Live execution stays credential-gated (SI-G0-3). |
| C-P0-11 ContainerDO stub | **BLOCKED** (platform), recorded | Real attestation, private ingress and container lifecycle need the live platform; the ledger G1 blocker list carries it. No local pretend-implementation was added. |
| C-P1-01 unbounded pre-auth JSON | **CLOSED** | Every structural body is length-gated (256 KiB) and parsed fail-closed (typed MALFORMED_JSON); data-path bodies keep the 8 MiB pre-read gate (`20f542b`). |
| C-P1-02 u64 closure incomplete | **CLOSED** (control plane) | One canonical decimal encoding (aliases like "00" refused, golden vectors at 2^53±1 and u64 max/max+1); checked incarnation increment with no mutation on exhaustion (`20f542b`). Rust counter closure: PR5 part 2. |
| C-P1-03 checkpoint activation trust | **PARTIAL/BLOCKED** | Local protocol (cut anchor, restore-evidence-required activation, single ACTIVE cut) was already enforced; global quiesce, pinned immutable roots and independent scratch-restore verification need the real storage/platform integration (post-G2; ledger records it). |
| C-P1-04 journal framing ambiguous | **CLOSED** (local anchor remainder noted) | v2 framing: domain-separated, 8-byte length-framed, binds database identity; verifier recomputes it; migration v11 rechains v1 chains; repartition and database-substitution mutants detected in the tamper matrix (`20f542b`). The independent external RecoveryAnchor remains the recorded F8 remainder. |
| C-P1-07 status/alias identity incomplete | **CLOSED** | Status-singleton identity covers digest+key+length+sequencing-kind+record-type (any divergence conflicts); alias-resolved queries return the alias's own request binding with the original physical outcome (`20f542b`). |
| C-P1-05/06/08/09 (bounded journal work, read fencing, lease/restore drills, confidentiality profile) | **OPEN**, recorded | Named in the ledger as PR4/post-G2 remainders with their blockers; partial local coverage exists (indexed outbox access, controller-time floor, session-bound operation reads) but none is claimed closed. |

## Storage findings (S-P0 / S-P1) - part 1 (`60da7d8`)

CLOSED with executed mutants: S-P0-03 (recovery status fold total:
idempotent duplicates, typed conflict quarantine, exactly-once size
accounting), S-P0-04 (checkpoint enumeration error propagation + fsync
discipline + typed metadata corruption), S-P0-05 (supervised interval
tasks: FATAL abort instead of detached unwrap; non-panicking drop),
S-P1-01 (get_prev terminal fail-stop; cursor seek fallback only for the
documented contract error kinds, everything else poisons), S-P1-04
(injective non-UTF-8 object prefix encoding).

## Storage findings - part 2 (PR5 remainder) and PR4b

| Finding | Status | Where |
|---|---|---|
| C-P0-01 Rust client protocol drift | **CLOSED** | `l1_client.rs` rewritten to the deployed protocol (credentialed issuance, single-request capabilities, canonical content-addressed keys, server-derived request digest, canonical-decimal u64, snapshot-bound scans, typed errors); shared 22-check suite executed 22/22 against real workerd; 3 mutants killed (`99038fc`). Wire types stay hand-mirrored (no codegen) - kept honest by contract tests, recorded. |
| S-P0-01 unbounded SST upload retry | **CLOSED** | slatedb patch `0002-bounded-l0-sst-upload-retry.patch`: shutdown escape decoupled from wal_enabled; non-transient errors terminal on first sight; transient errors bounded (8 attempts) then typed L0SstUploadRetriesExhausted fails the flush loudly. Bound proven against a permanently failing store with WAL off; upstream-loop mutant killed; provenance restamped and `--check` byte-identical. |
| S-P0-02 post-WAL raw recv()/spins | **CLOSED** | All four sites bounded under the EXISTING OD-002/OD-006 policy constants (no new policy invented): typed SyncAcknowledgementTimeout / PredecessorWaitTimeout, threaded so a validation infrastructure error is never an abort verdict; 6 tests, 2 mutants killed. |
| S-P0-06 product seam | **CLOSED** (local), registry OPEN | Typed `StorageBackend` chosen at the constructor (no global); one profile→backend decision point; U3/U4 are typed BackendNotYetAvailable refusals before any engine touch; silent-fallback mutant killed. The controller-owned per-database backend registry is post-G2. |
| S-P0-07 Candidate A helper-only proof | **CLOSED** | Test-only patch `0003`: the ENFORCED public `Db::builder` path proves exact epoch storage, stale-replay Fenced refusal with no write, MAX-boundary fencing (no wrap-over), and the executed `external_epoch_required` refusal. The audit's named surviving mutant (builder field ignored) now kills 3 tests. |
| S-P0-08 Candidate B TOCTOU | **CLOSED** (spike scope) | The gate is one atomic conditional operation: admitted publications hold the authority read guard across the provider mutation; rotation takes the write guard; multipart complete() re-gated. Concurrent park-inside-provider test + 2 mutants killed. The spike still models the provider in-process (recorded). |
| S-P0-09 / S-P1-02 (Rust) sequence wrap | **CLOSED** | Checked arithmetic end to end: WAL increment CAS with typed SequenceExhausted and no mutation on exhaustion; checkpoint replay successors typed; spike rotation typed; 10 boundary tests at u64::MAX, 3 mutants killed. |

Totals for part 2: storage lib 55 (11 new), durability 20 (8 new), slatedb
fork uploader 13 / builder 11 / manifest 34 (full fork lib 2003 passed with
8 pre-existing baseline-equal failures in `db_cache_manager`, verified
identical on the unpatched tree), spike 7; ten executed mutants, all
killed and restored.

## What this response deliberately does not do

- It does not close G0/G1/G2 - the ledger holds them open with named
  blockers (Mode-Q evidence, catalogue-as-denominator, owner envelope,
  credentials, drivers).
- It does not treat the U2/U2S3 archive as current-tree conformance: the
  archive is a historical observation whose integrity is now re-verified
  from raw logs on every commit, nothing more.
- It does not substitute prose for machine truth: every gate/lane/action
  statement here is derivable from `docs/ledger/gates.json`, and the
  linter rejects this document's own class of failure (a lower-authority
  green claim) across the live status surfaces.
