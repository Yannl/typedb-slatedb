# Response to the consolidated convergence and total-quality directive

**Directive audited baseline:** `0a697870` (with the follow-up round `7fd118f`
merged to `main` before this session started).
**Responding branch:** `claude/typedb-slatedb-r2-continue-ss62cz`.
**Method:** every finding was re-verified against the actual code or re-run
before a status was assigned. Nothing here is CLOSED on the strength of the
directive's description alone, and nothing is CLOSED without a control that
fails when the defect is deliberately reintroduced **and was executed**.

Statuses used below:

- **CLOSED** — code changed, negative control written, mutant executed, SHA cited.
- **PARTIAL** — the named part is closed; the remainder is itemised, not implied.
- **OPEN** — accepted, unbuilt. No completion claim.
- **CONTRADICTION** — the directive conflicts with a pinned contract; recorded in
  `docs/contradictions.json` and the safe side taken.

> **Corpus result (follow-up 1).** `docs/evidence/G3/u2s3-full-3/`: 106
> executables, 105 green, 1 ledgered red (the two upstream `todo!()` stubs),
> 0 timeouts, 462 cases passed / 2 failed / 1 ignored. Verdict GREEN with the
> denominator checked; oracle comparison 0 unexplained. Each row names the
> tree that produced it (checkout `2256711a` + staged-fork digest
> `cc0d283a`), not the outer repo commit.
>
> **Scope honesty.** This directive is a multi-phase programme. The sessions
> on this branch closed the truth-plane defects, the executable security and
> correctness defects the audit itself demonstrated, the P1 donor remainder,
> both ADR-0012 candidates, the §12.4 lifecycle, the key/issuance posture,
> the storage containment batch, the Q-17 remainder, and the J.3 pure
> resolver model. What remains open is either post-G2 by design or blocked
> on this environment — see "Blocked here, and why" below — and is recorded
> as such, not softened.

---

## 1. Independent re-verification of the directive's own findings

Before changing anything, the directive's executed observations were
reproduced. All of them held:

| Directive claim | Reproduced? | How |
|---|---|---|
| `lint_source_lock.py` exits nonzero | yes | fresh materialisation, then lint |
| `generate_workspace_lock.py --check` nonzero; SlateDB features omit `aws` | yes | the committed lock listed `["wal_disable"]`, the manifest carries `["wal_disable","aws"]` |
| catalogue: 4,740 leaf rows but 4,711 unique ids; 27 duplicated ids / 29 extra rows | yes, exactly | independent census |
| 44 failpoint leaves reference a target absent from the catalogue's own table | yes | `cargo:typedb:test:test_fail_points` is in no target row (the package is `typedb_server_bin`) |
| 42 cargo targets have zero leaves | yes | 8 `[[bench]]` + 34 crates with no `#[test]` |
| every required pair is U0 | yes | 4,740/4,740 |
| **none** of the 106 result target ids exists in the catalogue | yes | different id spaces; a `package:target` join matches all 106 |
| `run_static.py` writes FAIL rows and exits 0 | yes | source-evident, now fixed |
| `run_u0.py` has no terminal verdict | yes | source-evident, now fixed |
| a `PUT_PAYLOAD` capability omitting key/digest/maxBytes is accepted | yes | reproduced as an executed test before the fix |
| an old controller database cannot migrate | yes | reproduced as a test: the schema script creates an index over `record_type` before the `ALTER TABLE` that adds it |

One correction to the directive, in its favour: the audit noted the bootstrap
does not declare all native prerequisites. `tools/dev/doctor.py` **does**
already check `protoc`, `cmake`, `pkg-config` and the toolchains — and it
would have caught this session's only environment failure (a cold build died
on a missing `protoc`) had it been run first. The gap is not the check; it is
that nothing forces the check before a build. That is the Q-21 remainder.

---

## 2. Blocker-by-blocker disposition

### Truth plane and evidence producers

| ID | Status | What was done |
|---|---|---|
| **Q-29** evidence: `run_static.py` false-green | **CLOSED** `52707a7` | Terminal verdict; any FAIL/ERROR row, and an empty selection, exit nonzero. |
| **Q-30** evidence: `run_u0.py` no terminal verdict | **CLOSED** `52707a7` | One shared policy (`tools/catalog/verdict.py`) decides GREEN/RED. The flake ledger is the only tolerance, matched on exact target **and** counts **and** exit code. Timeouts, unknown crash rcs, unledgered ignores, stale ledger entries, missing required targets and case-bearing targets that ran zero cases are all red. A filtered run can never be a corpus verdict. `verdict.json` + a `COMPLETE` marker per run; a re-run that goes red removes a stale marker. |
| **Q-06** catalogue + comparator + completeness | **CLOSED** `52707a7`, `255e0d8` (Mode-Q Bazel oracle remains OPEN) | **Regenerated and measured:** the catalogue now comes from a pristine worktree (`2256711a`, clean), validates with 0 errors (was 116), has 4,740/4,740 unique leaf ids, and emits 23,132 required pairs across U0..U4. The U2S3 corpus denominator closes: 106 required executable targets == 106 rows, `run_u0.py --verdict-only` GREEN, `completeness.py` exit 0, comparator 4 divergent / 0 unexplained. Three mutants over the same archived rows each turn that green red. | Duplicate leaf ids disambiguated by occurrence; failpoint parent resolved from the cargo target table; all 42 zero-case targets declared with a reason; the U0..U4 required matrix the conformance plan asks for; generation fails closed on duplicate or dangling ids. The comparator now walks the **union** of both sides, folds `ok`/`rc=N`/`TIMEOUT` into the profile, and requires each classification to declare the exact expected profiles on both sides. Completeness joins results to the catalogue through the cargo package/target pair — the join that did not exist. A new validator checks the catalogue against the normative v14 contract schema, which nothing had ever done. |
| **Q-05** source/workspace lock red | **CLOSED** `52707a7` | Workspace lock regenerated. The lint no longer fails with a bare "dirty tree" in the only state the test lane can run in: it accepts exactly one dirty state — fully staged, with the fork patch set matching a digest now bound in `workspace-lock.json`. Before this the fork's own content was unpinned: any edit to a staged file produced a differently-behaving tree under an unchanged lock. |
| **Q-21** no root CI | **CLOSED (CI-budget scope)** | `.github/workflows/gates.yml`: source-lock lint, catalogue validation, the seven controller suites (70 tests, incl. key-config, lifecycle and query-plans) with the standing drop-outbox mutant as an expected-red step, the workerd lane, protocol models, and the storage library lane. The full corpus is deliberately NOT in CI (the header says so and why); `doctor.py` gates the build steps. |

Executed controls: `docs/evidence/G1/controls/evidence-producer-controls.txt`
(24/24 producer mutants killed, 10 completeness negative-control groups plus a
clean-run control, 7 catalogue-schema mutants) and
`.../source-lock-staged-fork-controls.txt` (two staged-fork mutants).

### Storage correctness

| ID | Status | What was done |
|---|---|---|
| **Q-01** post-WAL commit boundary | **PARTIAL (containment CLOSED; J.3 model CLOSED)** `98fecad`, `2f81f4a` | `PostWalCommitGuard` is armed immediately *before* `sequenced_write` — an error from the append itself already carries an unknown outcome, and transport failure is not proof of non-append. Every exit resolves as known-not-appended, deterministic abort, or visibility-complete; anything else names its reason and fail-stops. Two further defects found and fixed while wiring it: the committed frontier was advanced **unconditionally, including on error returns**, and `wait_for_watermark` spins forever — together these meant an unresolved obligation did not present as an error at all, but as every later snapshot open hanging with no diagnostic. The J.3 pure resolver model is now built (`tools/protocol-models/src/resolver_model.rs`): `ValidationBasisV1` with every contract field digest-bound, deterministic `resolve()`, infra-fault schedules that can never fabricate a verdict, and the certificate-memo quarantine rules — two executed mutants killed. Remainder: the J.5 **production** shared-resolver integration, idempotent per-keyspace apply markers, and the full failpoint schedule matrix stay OPEN (post-G2 by the playbook split). |
| **Q-04** production namespace/no-delete not proven | **PARTIAL** (prior `3c00b9e`) | Unchanged this session beyond Q-25. Fresh materialisation ids and `NoDeleteStore` stand; IAM/credential-ancestry/provider-lifecycle proof is OPEN. |
| **Q-25** `s3_gc.py --delete` pre-G13 | **CLOSED** `7d70306` | The delete *implementation* is removed, not flag-guarded — no DELETE request remains in the file — and the flag now names the missing G13 preconditions (reachability closure, restore pin, retention clearance, recorded approval, IAM ancestry, proven restore). Executed refusal recorded. |
| **Q-13 / Q-23** unbounded retry/deadline | **CLOSED (containment)** `af12fb5` | The watermark wait was already bounded (Q-01 work). Now also: `object_store_max_retries = Some(8)` replaces SlateDB's retry-forever default, and the async→sync bridge reports every 30 s (ERROR naming the pending operation) and fail-stops at 600 s instead of hanging forever holding storage locks; a dead runtime panics immediately. Both bounds recorded as **OD-006**. The Candidate B spike then re-observed the unbounded-retry hazard live (a firewall refusal hung `flush()` under the stock default) — independent confirmation this bound is load-bearing. Remainder: caller-side cancellation needs fallible signatures up the read stack (named in OD-006). |
| **Q-14** cache removal errors ignored | **CLOSED** `f648ad0` | The object-cache wipe is correctness-critical — entries are keyed by store-relative paths that repeat across materialisations, so a survivor serves the previous materialisation's bytes for this one's paths — and its error was discarded. Only `NotFound` is benign now; anything else refuses the open. Control injects the failure the way it happens (a non-directory occupying the cache path). |
| **Q-16** checkpoint closure by LIST/copy | **CLOSED (as accepted)** `af12fb5` | The directive's disposition — "call it a test fixture exporter, never a production checkpoint" — is now IN the code: `checkpoint()`'s doc declares it the conformance-lane fixture exporter, and no prose anywhere claims a durable production checkpoint exists. No behavioural change; none was asked. |
| **Q-19** whole-object/serial remote helpers | **OPEN** | Not addressed (streaming/backpressure framing; also the Q-12 base64 remainder). |
| **Q-22** Rocks cursor `transmute` | **CLOSED** `af12fb5` | The audited fragility — drop order hanging on field declaration order — is now structural: the iterator lives in `ManuallyDrop` and an explicit `Drop` impl is the only place it dies, always before the co-owned `Arc<DB>`; reordering fields changes nothing. New ownership control (cursor keeps the DB alive after every other handle is gone) plus an executed mutant that reintroduces the defect: it dies SIGABRT (`pthread lock: Invalid argument`). Caveat recorded honestly in the evidence: the mutant fails via UB, so the crash is observed, not guaranteed — the structural ordering is the durable closure. |
| **Q-27** `NoDeleteStore` composite mutators | **CLOSED (rename + copy)** `f648ad0`, `af12fb5` | `rename` closed earlier (refusal precedes the copy half). Now `copy_opts` refuses every non-`Create` mode with a typed error — an overwrite-mode copy is a delete of the destination's bytes wearing a copy's name — with an executed mutant. Remainder OPEN: multipart overwrite-sensitivity, which needs a provider conditional-write posture, not another wrapper method (tracked with Q-04's provider proof). |

### SlateDB fork decision

| ID | Status | What was done |
|---|---|---|
| **F4/F5** external epochs | **BOTH CANDIDATES MEASURED, comparison recorded** `8e750bf`, `2f81f4a` | ADR-0012 Candidate A is implemented as a five-file patch series over the digest-pinned crate, deterministically reconstructible, with a qualifying matrix (34/34 in `manifest::store`, five new) and an executed observe-and-bind mutant that kills three of the five. **Correction to the staged design**, in the project's favour: `slatedb-txn-obj 0.15.0` already exports `FenceableTransactionalObject::init_with_epoch` publicly with exactly the required fail-closed semantics — so the fork is wiring, not mechanism, at roughly 90 non-test lines. Candidate B (a credential-domain publication firewall over STOCK slatedb 0.15.0, `spikes/publication-firewall`) is now also built and measured: 4/4 qualifying cases, gate-removal mutant killed, and three findings recorded — total-path coverage including the unfenced `Admin` checkpoint paths, a live-observed Q-13 hang under stock retries, and the permanent inv. 78–80 gap (a wrapper can decide WHO publishes, never which epoch VALUES the manifests carry). ADR-0012 records the comparison: A is the fencing mechanism of record; B's provider-enforced credential rotation composes underneath as defense in depth. Production still consumes crates.io — integration of either half stays behind the gates. |

### Control plane

| ID | Status | What was done |
|---|---|---|
| **Q-26** capability restrictions optional | **CLOSED** `7d70306` | Omission is now refusal: restrictions are mandatory by method, a restriction the request needs must be present in the token, issuance fails closed on the same table, and a byte budget above the 8 MiB ceiling is refused at verification rather than trusted from the issuer. Two mutants executed, including one that reproduces the audit's exact accepted token. |
| **Q-09** migration cannot run | **CLOSED** `7d70306` | Ordered, versioned, transactional migrations stamped in `schema_migrations`; additive columns driven by `PRAGMA table_info` so one step is correct on fresh and old databases; dependent indexes last. Mutant executed. |
| **Q-11** dedupe returns A for B | **CLOSED** `7d70306` | Durable idempotency aliases; `queryOperation` resolves through them; a different request under the same id is a typed conflict. Mutant executed. |
| **Q-18** caller-supplied replay digest | **CLOSED** `7d70306` | Both finalize paths recompute the digest over the canonical authority-bearing fields and refuse a disagreeing caller-supplied value. |
| **Q-20** eight R2 subrequests vs a ceiling of six | **CLOSED** `7d70306` | Named constant sourced from the Cloudflare contract lock. |
| **Q-12** admission bounds | **CLOSED (streaming remainder moves to Q-19)** `7d70306`, `fa4fb37`, `88fbe20`, `156192b` | Body admission is a declared-length check before the body is read, with a post-read backstop; scan pages no longer exempt "record zero"; usage counters are transactional (Q-17); the pinned iterator hands back an **opaque server-owned `SnapshotId`** MACed over (database, generation, head, incarnation), with a caller-supplied `throughLsn` refused outright and a continuation outside its own snapshot typed rather than answered with an empty page. And budgets are now MANDATORY: a database with no budget row is denied (`ADMISSION_REJECTED_NO_BUDGET`) — "no budget means unlimited" inverted the fail direction — with every budget field validated as an exact integer in [1, platform ceiling] (`INVALID_BUDGET`, never a coercion). E2E checks 4–6 exercise deny → install → fractional-refusal. Streaming/backpressure framing instead of accumulated base64 stays OPEN under Q-19. |
| **donor A4** per-procedure session revalidation | **CLOSED** `7d70306` | `setBudgets`, `outboxAck` and `queryOperation` revalidate the actor at the core, beneath the capability layer — closing the window in which a fenced actor's still-unexpired token keeps working. Mutant executed. |
| **§12.5** `fencedBy` disclosure | **CLOSED** `98fecad` | A stale actor now receives exactly `SESSION_FENCED`. The attribution was read from "any unfenced session of this database" without the generation/materialisation authority scope, so it could name a session that is not the holder of the scope asked about; attribution stays in the command-ledger entries. |
| **Q-02** unauthenticated Worker facade | **CLOSED (attestation-root remainder blocked)** `156192b` | Every route except `/health` requires a capability, and issuance itself is now credentialed: `/capability` demands `x-issuer-authorization` compared constant-time against the configured issuer secret, in every posture — the L1 E2E proves anonymous and wrong-credential issuance are refused. What remains is not a facade hole but the external attestation root for §12.4 (see "Blocked here"). |
| **Q-03** any fresh session takes over | **CLOSED (external attestation root blocked)** `85c3e1e` | The full lifecycle is built at core, DO and worker: `RESERVED → ATTESTED → ACTIVE → DRAINING → REVOKED/EXPIRED` with single-use session ids, process nonces, controller-time leases (persisted nondecreasing floor — a backward clock jump cannot extend a lease, a forward one fails closed), and **activation as the only operation that fences**. A fresh random id can no longer fence anyone (`SESSION_NOT_RESERVED`); a hijacked nonce is `PROCESS_NONCE_MISMATCH`; a spent id is permanently refused. Legacy `registerSession` is now a macro over the lifecycle. 13 core tests + E2E section; two executed mutants. Remainder: the ATTESTED step trusts nonce possession — binding it to an external attestation root (platform identity) needs infrastructure this environment does not have. |
| **Q-10** remaining authority-sized values | **CLOSED** `156192b` | `generation` was already guarded at every wire entry (prior `0953ec0`); incarnation, budgets and payload lengths now refuse inexact or out-of-range values with typed errors (`INVALID_BUDGET{field}`, `INVALID_PAYLOAD_LENGTH{observed}`) instead of traversing ordinary number paths. |
| **Q-17** SQL cost grows with history | **CLOSED** `88fbe20`, `36bf14d` | Both admission `COUNT(*)`s replaced by transactionally maintained singleton counters (migration v5), plus the partial unpublished-drain index. Now also the §12.7 remainder: a plan suite (`query-plans.test.ts`, in CI) EXPLAINs every statement the hot paths execute (bare `SCAN` fails), and a 500k-row synthetic fixture bounds per-append latency to 8× a 1k-row baseline. Building it surfaced two real O(history) defects the plan text could NOT see: the double-`MAX` head lookup (walked the whole generation per append behind an innocent SEARCH plan — mutant measured at 118.7×) and the unindexed nonce-expiry sweep (migration v8). Two executed mutants, each killed by exactly one layer — proof the suite needed both. |
| **Q-24** confidentiality/key management | **CLOSED (deployment provisioning remains)** `156192b` | `resolveKeyConfig`: profile unset ⇒ `managed` ⇒ refuses to boot without real hex keys ≥ 32 bytes, refuses the dev constants even when explicitly configured, refuses journal==capability key reuse, requires an issuer secret; `local-dev` must be opted into by name. 7 tests; wrangler production env carries the managed profile. Actually provisioning production secrets is a deployment act, not code. |
| **Q-28** journal/command-ledger mislabelling | **CLOSED (prose)** | This document, the commit messages, and now the status prose in `docs/reviews/v16-convergence-audit.md` all label `appendCommand` as journaled authority commands, explicitly NOT the inv. 85–98 command ledger — which remains OPEN as a feature (F7 build-out), no longer as a mislabel. |
| **§12.6** `/wal/finalize-batch` without the v16 batch schema | **CLOSED** `71c7a94` | The directive's minimum was to make the route physically test-only; giving it the envelope is stronger and keeps the lane. A batch now carries a `batchOperationId`; the digest is computed server-side over the ordered members' own canonical request digests and a supplied one is only checked (Q-18's rule one level up); K and byte ceilings are enforced before any allocation; and one batch id names one member set forever — the same id with different members, or the same members reordered, is a permanent conflict. An unnamed batch is refused, so one-record finalisation is always the open path. Remainder OPEN: the intermediate descriptor chain and mixed-version compatibility rules. |

### Product, platform, gates

| ID | Status |
|---|---|
| **Q-07** v17 per-database backend + driver gates | **OPEN** — unbuilt. Seam note so the build starts in the right place: the per-database backend selection belongs at the **keyspace-engine seam** (`KeyspaceEngine::Rocks | Slate`, ADR-0002; per-keyspace vs shared store already decided by ADR-0013) — the engine choice is per `Keyspace` today and a per-database policy is a constructor-level dispatch, not a new abstraction. The driver gates additionally need the TDRIVER catalogue/launchers (J.3/D3), which are unbuilt and partly blocked (classic-matrix drivers are external repos). |
| **Q-08** G1 models, probes, ContainerDO fail-closed | **PARTIAL** — the models half is built (protocol-models: WAL, fencing, journal, command, and now the J.3 resolver — 37 tests, all in CI); the ContainerDO stub is unbound, which is the required posture. The disposable probe applications (P-R2/P-DO/P-CTR/P-WORKER) are unbuilt, and their execution needs the same staging credentials as G2. |
| **G2** | **OPEN/BLOCKED** — SI-G0-3 credentials. Nothing here changes that, and no G2 claim is made. |

### Blocked here, and why (recorded, not softened)

Items no amount of work in THIS environment can close, each with the
missing external dependency named:

1. **Mode-Q Bazel oracle** (Q-06/F10 remainder) — needs a working Bazel
   toolchain for the upstream tree (SI-G0-1); the environment has none and
   the directive forbids substituting the cargo lane as its own oracle.
2. **G2 and everything gated behind it** — needs Cloudflare staging
   credentials (SI-G0-3). The probe harness (Q-08) should be finished
   first, per the directive, but its *execution* is equally
   credential-blocked.
3. **Real IAM / provider no-delete proof** (Q-04, Q-27 multipart
   remainder) — needs provider credentials and account-level policy
   control to prove bucket-side immutability and credential ancestry;
   `NoDeleteStore` is the in-process half only.
4. **Driver gates / classic matrix** (Q-07, J.3/D3) — needs the external
   driver repositories and their runtimes.
5. **External attestation root for §12.4** (Q-02/Q-03 remainder) — the
   lifecycle's ATTESTED step verifies nonce possession; binding it to a
   platform identity (Workers attestation, mTLS, or provider IAM) needs
   the platform. The protocol was built so the root slots into
   `attestSession` without reshaping the state machine.

---

## 3. Contradictions recorded rather than resolved

`docs/contradictions.json` — four entries, each with the safe side taken:

1. **CD-001** the U2S3 lane has no profile id in the normative catalogue
   schema, so its completeness is not derivable from the catalogue. Required
   pairs are emitted for U0..U4 only.
2. **CD-002** zero-case declarations are carried in the exclusion record,
   which the schema shapes for temporary debt and gives an expiry a
   structural fact does not deserve.
3. **CD-003** the U1 oracle predates the package-id fix, so the strongest
   comparison in the project is joined on target *name*, not identity.
4. **CD-004** the catalogue (upstream denominator) and the corpus (fork tree)
   need opposite states of the same checkout, so they cannot come from one
   build.

`docs/owner-decisions.json` — six values this work needed and refused to
invent: soak thresholds, the watermark-wait deadline, the data-path size
ceiling, the subrequest budget, the flake-ledger expiry policy, and the
storage bridge deadline / object-store retry bound (OD-006).

---

## 4. On the directive's release verdict

The directive's conclusion — **NO-GO**, repair truth and post-WAL safety
first — is accepted, and this branch followed that order: producers before
evidence, containment before breadth. **It remains NO-GO after this work.**
G0 and G1 are closer to honest than they were (the locks pass, the catalogue
is joinable and schema-checked, both producers fail closed, the corpus
denominator closes at 106/106 with a clean oracle comparison), but G1 is not
green while U3/U4 required pairs have zero coverage and the Mode-Q Bazel
oracle is absent, and G2 has not been attempted — it cannot be, without
SI-G0-3. Every remaining OPEN item above is either post-G2 by the playbook
split or names its external blocker in "Blocked here, and why".

Two findings the directive did not predict, both in the project's favour:
the SlateDB correction (the primitive the fork was staged to build already
exists upstream, public — Candidate A is ~90 lines of wiring), and the
Q-17 double-`MAX` head lookup (an O(history)-per-append cost hiding behind
an index-shaped `SEARCH` plan, which is why the closure carries a measured
latency-ratio control and not only plan assertions). The ADR-0012
comparison is now recorded with both candidates measured; the composition
verdict (A as mechanism, B's credential rotation as backstop) is in the ADR.
