# Response to the donor adversarial audit (branch `claude/typedb-donor-verification-sfxfbz`)

The independent donor audited this branch at `e20cff5` and filed 14
findings (4 P0, the rest P1/refuted). Each is verified here against the
actual code and given a disposition with a commit SHA. Findings are not
taken on trust — the donor's file/symbol pointers were checked, and two of
the four P0s were already closed by this session's convergence work before
the report arrived.

## P0 — all four closed

| ID | Finding | Disposition |
|----|---------|-------------|
| **A1** | Object-store purge runs before `Db::build()`, bypassing the writer-epoch fence — one process can erase another's live database | **CLOSED, `3c00b9e` (F3)**. The purge is *gone*, not merely re-ordered: open never deletes. Each open mints a fresh immutable materialisation namespace (`<base>/fv1/<id>/keyspace/…`), so two opens never share a prefix — there is nothing to erase and no fence to bypass. This is strictly stronger than adding the epoch fence the donor asked for. Runtime delete authority is additionally removed structurally (`NoDeleteStore`). Controls + 2 mutants executed. |
| **A2** | No authentication on any endpoint; arbitrary caller-controlled R2 keys (cross-DB path traversal) | **CLOSED, `fe853aa` (F9r)**. Every endpoint except `/health` and local issuance requires a controller-issued capability (audience/method/expiry/nonce/incarnation-bound). Payload keys are issuer-derived and content-addressed (`p/<db>/<sha256hex>`); the worker rejects any non-content-addressed key and the capability binds the exact key + digest + budget. Cross-DB traversal is impossible: the key names the database and must match the capability's audience. 9-case refusal matrix over real HTTP. |
| **A3** | `SESSION_FENCED` leaks `fencedBy` — the impersonation identity a fenced actor needs to resume writing | **CLOSED, `c71b8e1`**. Root cause was that `startupSessionId` was a caller-asserted bearer identity. `WAL_FINALIZE` capabilities are now **session-bound**: the token carries the actor identity and the finalize guard enforces it (`CAPABILITY_SESSION_MISMATCH`). A leaked id without a session-bound capability finalizes nothing; the controller issues such a capability only to the actor it admitted. `fencedBy` is now attribution, not a credential. Negative control: a token bound to `sess-OTHER` cannot finalize as `sess-3` (a live unfenced actor). |
| **A6** | Schema read-lock held across a full remote scan; the `key_count_memo` is never written | **CLOSED, `<A6 commit>`**. Two real defects, one of them mine: (1) `estimate_key_count` read the memo but never wrote it, so the TTL was dead code and every ~15s metrics poll re-scanned — now the memo is populated after each scan (lock held only for the O(1) store, never across the scan). (2) `get_metrics` held the schema read-lock across the storage estimate calls — now the storage reads (which depend only on `self.storage`) are hoisted out before the schema lock is taken. Memo-population control added (a second call within the TTL serves the stale count; removing the write fails it). |

## P1 — dispositions

| ID | Finding | Disposition |
|----|---------|-------------|
| **A4** | `outboxAck`/`setBudgets`/`queryOperation` take no session; unfenced | **Substantially addressed** by the capability layer (`fe853aa`+`c71b8e1`): `setBudgets` is `SESSION_ADMIN`-gated, `outboxAck` is `OUTBOX`-gated, `queryOperation` is `WAL_READ`-gated. `queryOperation` intentionally stays a read surface (inv. 38: immutable history is queryable by the current actor after a fence). Core-level per-procedure session revalidation beyond the capability layer is a follow-up, not a hole. |
| **A5** | Authoritative counters are JS `number`; `generation` unguarded | **Sequence counters closed** (`997da46`, F7r): AppendLsn/TypeSequence/ControlSeq are exact u64 (BE-blob SQL, bigint core, decimal-string wire) with a 2⁵³ mutant control. `generation` remains a JS number — a monotonic rollover counter, small in practice; guarding it to the exact range at the boundary is an open follow-up (tracked). |
| **A7** | L0 ceiling raised 8 → 1,000,000; unbounded read amplification | **Documented interim** (audit F5). The giant ceiling is a liveness workaround for the compactor-less posture; `assert_pre_g13_posture` (`3c00b9e`) now refuses any open that enables the compactor, and bounded amplification under long-running load is gated on the external-epoch compactor fork (`docs/design/slatedb-external-epochs.md`, F4/F5 OPEN-P0). |
| **A8** | Path-derived prefixes collide (cross-process, generation reuse, import leak) | **Substantially addressed** by F3 (`3c00b9e`): every open mints a fresh unique materialisation id, so cross-process collision and generation reuse cannot occur — two actors never write the same prefix. The donor's `StoreIdentity` is an alternative approach to the same end; the fresh-id namespace is the one adopted. |
| **A9** | Listing-and-copy checkpoints, no durable root; native API unused | **Partially closed / staged**. The manifest-pin ordering race is fixed (`8679cb1`); the CheckpointCut state machine with a journal anchor and controller-only activation from restore evidence is in (`d47378e`, F6r). The native by-reference clone (donor O3) and controller-owned global quiescence remain the U3.2 integration (audit F6 remainder). |
| **A10** | `get_prev` panics the whole process on any transient object-store error | **Accepted, follow-up**. The panic is deliberate fail-closed (a silent `None` would let the vertex-ID allocator re-issue existing IDs — corruption). The donor's valid refinement is that a *transient* blip should retry rather than abort; a `RetryClass` error channel that distinguishes transient from fatal is the tracked fix. Until then, fail-closed-loud is the correct conservative posture (a crash is recoverable; ID reuse is not). |
| **A11** | Container DO is dead code; no controller↔container epoch token | **Staged** (U3/U4 integration). The container lifecycle and the controller↔container epoch token are part of the not-yet-built real-DO lane; the audit does not claim U4 exists. |

## Refuted claims the donor confirmed honestly

- No dirty reads at this tip (fixed in `65da032`, F2) — the donor verified this against the current code.
- No forked SlateDB / external epochs — correct; that is exactly the OPEN-P0 F4/F5 the design doc stages.

## On grafting the donor's engine primitives

The donor's `engine/slatedb-keyspace` primitives (StoreIdentity, bounded
single-flight estimate, `RetryClass`, L0-ceiling refusal, `qualification.rs`)
are **design references, not code imports** — consistent with ADR-0013 (the
donor's shared-store engine is not adopted wholesale) and the donor's own
instruction to graft reviewed pieces rather than merge. Where a primitive's
intent was sound it was reimplemented against this branch's layout: the
bounded single-flight estimate as the A6 memo fix, the L0-ceiling refusal as
`assert_pre_g13_posture`, StoreIdentity's collision-safety as F3's fresh-id
namespaces. The donor's explicit exclusions (WAL-on, GC-on, expiring/listing
checkpoints, weak path-derived prefixes, per-database runtimes, stringly-typed
errors) match this branch's own F12 tripwire list and none are imported.

## Denominator cross-check

The donor's corpus tooling run against this fork (`docs/donor/a-branch-catalog/`)
reports 296 targets / 4353 leaves / 0 unknown macros / zero set-level delta
vs its baseline — the denominator was not shrunk. Caveat (donor's own): that
is the *static* denominator; it does not validate the 105/106 executing-pass
claim, which is what `docs/evidence/G3/u2s3-full-2/` and the oracle comparison
cover. This branch's `tools/catalog/completeness.py` (F10r) independently
re-derives the leaf count and already caught 4 phantom catalogue leaves the
donor's static count did not flag (dead Scenario Outlines).
