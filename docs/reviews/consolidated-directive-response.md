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
> **Scope honesty.** This directive is a multi-phase programme. One session
> closed the truth-plane defects, the executable security and correctness
> defects the audit itself demonstrated, the P1 donor remainder, and the F4/F5
> fork. It did not close the post-G2 phases, the G2 gate itself, the driver
> gates, or the production control-plane lifecycle protocol — those are marked
> OPEN with what is actually missing, not softened.

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
| **Q-21** no root CI | **OPEN** | No CI workflow exists. The commands are all runnable and now all fail closed, which is the precondition; wiring them into a root workflow is unbuilt. |

Executed controls: `docs/evidence/G1/controls/evidence-producer-controls.txt`
(24/24 producer mutants killed, 10 completeness negative-control groups plus a
clean-run control, 7 catalogue-schema mutants) and
`.../source-lock-staged-fork-controls.txt` (two staged-fork mutants).

### Storage correctness

| ID | Status | What was done |
|---|---|---|
| **Q-01** post-WAL commit boundary | **PARTIAL (containment CLOSED)** `98fecad` | `PostWalCommitGuard` is armed immediately *before* `sequenced_write` — an error from the append itself already carries an unknown outcome, and transport failure is not proof of non-append. Every exit resolves as known-not-appended, deterministic abort, or visibility-complete; anything else names its reason and fail-stops. Two further defects found and fixed while wiring it: the committed frontier was advanced **unconditionally, including on error returns**, and `wait_for_watermark` spins forever — together these meant an unresolved obligation did not present as an error at all, but as every later snapshot open hanging with no diagnostic. Remainder: the J.5 shared resolver, `ValidationBasisV1`/`TransactionResolutionV1`, idempotent per-keyspace apply markers, and the full failpoint schedule matrix are OPEN. |
| **Q-04** production namespace/no-delete not proven | **PARTIAL** (prior `3c00b9e`) | Unchanged this session beyond Q-25. Fresh materialisation ids and `NoDeleteStore` stand; IAM/credential-ancestry/provider-lifecycle proof is OPEN. |
| **Q-25** `s3_gc.py --delete` pre-G13 | **CLOSED** `7d70306` | The delete *implementation* is removed, not flag-guarded — no DELETE request remains in the file — and the flag now names the missing G13 preconditions (reachability closure, restore pin, retention clearance, recorded approval, IAM ancestry, proven restore). Executed refusal recorded. |
| **Q-13 / Q-23** unbounded retry/deadline | **PARTIAL** | The watermark wait is now bounded (Q-01 work). SlateDB lower-layer retry bounds and a caller deadline on the blocking bridge are OPEN. |
| **Q-14** cache removal errors ignored | **CLOSED** `f648ad0` | The object-cache wipe is correctness-critical — entries are keyed by store-relative paths that repeat across materialisations, so a survivor serves the previous materialisation's bytes for this one's paths — and its error was discarded. Only `NotFound` is benign now; anything else refuses the open. Control injects the failure the way it happens (a non-directory occupying the cache path). |
| **Q-16** checkpoint closure by LIST/copy | **OPEN** | Unchanged; the directive's "call it a test fixture exporter, never a production checkpoint" is accepted. |
| **Q-19** whole-object/serial remote helpers | **OPEN** | Not addressed. |
| **Q-22** Rocks cursor `transmute` | **OPEN** | Not addressed. |
| **Q-27** `NoDeleteStore` composite mutators | **PARTIAL** `f648ad0` | `rename` closed: `ObjectStore`'s default `rename_opts` is copy-then-delete, so blocking only `delete_stream` left a full duplicate at the destination while telling the caller the rename failed. The refusal now precedes the copy and the control asserts the destination stays `NotFound`. Remainder OPEN: `copy_opts` and multipart remain overwrite-sensitive — that is an immutability question rather than a delete-authority one, and closing it needs a conditional-write posture, not another wrapper method. |

### SlateDB fork decision

| ID | Status | What was done |
|---|---|---|
| **F4/F5** external epochs | **BUILT, NOT DECIDED** `8e750bf` | ADR-0012 Candidate A is implemented as a five-file patch series over the digest-pinned crate, deterministically reconstructible, with a qualifying matrix (34/34 in `manifest::store`, five new) and an executed observe-and-bind mutant that kills three of the five. **Correction to the staged design**, in the project's favour: `slatedb-txn-obj 0.15.0` already exports `FenceableTransactionalObject::init_with_epoch` publicly with exactly the required fail-closed semantics, and SlateDB already uses it internally — so the fork is wiring, not mechanism, at roughly 90 non-test lines. Candidate B (a provider-enforced publication firewall over stock SlateDB) is **not** built, so the directive's two-candidate spike has one candidate measured and no verdict. Production still consumes crates.io. |

### Control plane

| ID | Status | What was done |
|---|---|---|
| **Q-26** capability restrictions optional | **CLOSED** `7d70306` | Omission is now refusal: restrictions are mandatory by method, a restriction the request needs must be present in the token, issuance fails closed on the same table, and a byte budget above the 8 MiB ceiling is refused at verification rather than trusted from the issuer. Two mutants executed, including one that reproduces the audit's exact accepted token. |
| **Q-09** migration cannot run | **CLOSED** `7d70306` | Ordered, versioned, transactional migrations stamped in `schema_migrations`; additive columns driven by `PRAGMA table_info` so one step is correct on fresh and old databases; dependent indexes last. Mutant executed. |
| **Q-11** dedupe returns A for B | **CLOSED** `7d70306` | Durable idempotency aliases; `queryOperation` resolves through them; a different request under the same id is a typed conflict. Mutant executed. |
| **Q-18** caller-supplied replay digest | **CLOSED** `7d70306` | Both finalize paths recompute the digest over the canonical authority-bearing fields and refuse a disagreeing caller-supplied value. |
| **Q-20** eight R2 subrequests vs a ceiling of six | **CLOSED** `7d70306` | Named constant sourced from the Cloudflare contract lock. |
| **Q-12** admission bounds | **PARTIAL** `7d70306`, `fa4fb37`, `88fbe20` | Body admission is a declared-length check before the body is read, with a post-read backstop; scan pages no longer exempt "record zero"; usage counters are transactional (Q-17); and the pinned iterator now hands back an **opaque server-owned `SnapshotId`** MACed over (database, generation, head, incarnation), with a caller-supplied `throughLsn` refused outright and a continuation outside its own snapshot typed rather than answered with an empty page. Remainder OPEN: a mandatory budget row before generation activation (no budget row still means unlimited), and streaming/backpressure framing instead of accumulated base64. |
| **donor A4** per-procedure session revalidation | **CLOSED** `7d70306` | `setBudgets`, `outboxAck` and `queryOperation` revalidate the actor at the core, beneath the capability layer — closing the window in which a fenced actor's still-unexpired token keeps working. Mutant executed. |
| **§12.5** `fencedBy` disclosure | **CLOSED** `98fecad` | A stale actor now receives exactly `SESSION_FENCED`. The attribution was read from "any unfenced session of this database" without the generation/materialisation authority scope, so it could name a session that is not the holder of the scope asked about; attribution stays in the command-ledger entries. |
| **Q-02** unauthenticated Worker facade | **PARTIAL** | Every route except `/health` and issuance requires a capability, and the capability is now genuinely restrictive (Q-26). Issuance itself is still open on the L1 facade — that is a real hole for anything deployable, and closing it needs the §12.4 lifecycle protocol, which is OPEN. |
| **Q-03** any fresh session takes over | **OPEN** | The `reserveSession`/`attest`/`activateSession` lifecycle with leases, holder nonces and an external recovery root is unbuilt. Registration is still takeover-at-open. |
| **Q-10** remaining authority-sized values | **PARTIAL** | `generation` is guarded at every wire entry point (prior `0953ec0`); incarnation, budgets and lengths still traverse ordinary number paths. |
| **Q-17** SQL cost grows with history | **CLOSED** `88fbe20` | Both admission `COUNT(*)`s replaced by transactionally maintained singleton counters (migration v5 backfills them), plus a partial index over unpublished rows for the ordered drain. The consistency control checks counter == `COUNT(*)` after every path that moves a row, across two databases in one core; its mutant reds two tests. It also surfaced an unrelated real bug: `outboxAck`'s UPDATE was not scoped by `database_id`. Remaining from §12.7: `EXPLAIN QUERY PLAN` assertions and a million-row fixture. |
| **Q-24** confidentiality/key management | **OPEN** | Development keys remain; no approved profile exists. |
| **Q-28** journal/command-ledger mislabelling | **PARTIAL** | This document and the commit messages avoid the mislabel; the status prose in `docs/reviews/v16-convergence-audit.md` still says "command ledger" for `appendCommand`. The primitive is unchanged. |
| **§12.6** `/wal/finalize-batch` without the v16 batch schema | **CLOSED** `71c7a94` | The directive's minimum was to make the route physically test-only; giving it the envelope is stronger and keeps the lane. A batch now carries a `batchOperationId`; the digest is computed server-side over the ordered members' own canonical request digests and a supplied one is only checked (Q-18's rule one level up); K and byte ceilings are enforced before any allocation; and one batch id names one member set forever — the same id with different members, or the same members reordered, is a permanent conflict. An unnamed batch is refused, so one-record finalisation is always the open path. Remainder OPEN: the intermediate descriptor chain and mixed-version compatibility rules. |

### Product, platform, gates

| ID | Status |
|---|---|
| **Q-07** v17 per-database backend + driver gates | **OPEN** — unbuilt. |
| **Q-08** G1 models, probes, ContainerDO fail-closed | **OPEN** — the stub is unbound, which is the required posture, but the probe applications are unbuilt. |
| **G2** | **OPEN/BLOCKED** — SI-G0-3 credentials. Nothing here changes that, and no G2 claim is made. |

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

`docs/owner-decisions.json` — five values this work needed and refused to
invent: soak thresholds, the watermark-wait deadline, the data-path size
ceiling, the subrequest budget, and the flake-ledger expiry policy.

---

## 4. On the directive's release verdict

The directive's conclusion — **NO-GO**, repair truth and post-WAL safety
first — is accepted, and this session followed that order: producers before
evidence, containment before breadth. It remains NO-GO after this work.
G0 and G1 are closer to honest than they were (the locks pass, the catalogue
is joinable and schema-checked, both producers fail closed), but G1 is not
green while U3/U4 required pairs have zero coverage and the Mode-Q Bazel
oracle is absent, and G2 has not been attempted.

The single most useful thing this session found that the directive did not
predict is the SlateDB correction: the primitive the fork was staged to build
already exists upstream and is public. That materially lowers the cost of
Candidate A and belongs in the ADR-0012 decision, which is still owed.
