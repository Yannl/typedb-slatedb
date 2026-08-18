# Post-merge quality audit: findings and dispositions

**Scope:** every line of owned code after PR #3 merged to `main` —
control-plane TypeScript (core, entry, tests, E2E), Python tooling
(catalog, source-lock, fork, dev), owned Rust (protocol models, the
publication-firewall spike, the fork-authored storage code). Four parallel
audit passes plus mechanical sweeps (clippy, `tsc --noUnusedLocals
--noUnusedParameters`, unused-export/never-called scans). ~85 findings;
every one verified against the code before acting. The bar (owner's words):
no compromise on safe/robust/maintainable — the target is bloat and
unnecessary complexity, never the guards.

## Bugs found and fixed (each was a real failure window)

1. **Lease expiry could run outside any transaction** — `setBudgets` and
   `outboxAck` called `requireLeasedAuthority` before opening their
   transaction; on an expired lease that guard executes a multi-statement
   mutation (state UPDATE + journaled command + counter bump) auto-committed
   statement by statement. A crash mid-sequence left `outbox_unpublished`
   permanently under-counted or an EXPIRED session with no journal entry.
   Both guards now run inside the procedure's one transaction.
2. **`drainOutbox` marked and counted in separate auto-commits** — a crash
   between them permanently inflated the unpublished counter (admission
   then rejects at a lower effective depth forever). Mark+count are now one
   transaction per row; the method is also labelled what it is: the STAGED
   push path (peek/ack is the shipped contract).
3. **Outbox peek `limit` unvalidated** — `?limit=-1` reached SQL, and a
   negative LIMIT is documented by SQLite as "no upper bound": the one
   route where a caller could request an unbounded page. Now validated and
   clamped like scan's.
4. **Exact-read LSN segment unbounded** — a 21+-digit LSN passed the regex,
   overflowed u64 inside the core, and surfaced as an unhandled 500 *after*
   the caller's single-use capability was burned. Now a typed 400 before
   the capability check.
5. **`package_assembly.py` enforced fixture integrity with `assert`** —
   stripped under `python3 -O`, so a tampered fixture tarball would be
   silently packaged into the archive the corpus runs. Now `sys.exit`
   checks against digests read from `source-lock.json` (the hand-copied
   constants are gone).
6. **`generate_workspace_lock.py` sniffed `"--check" in sys.argv`** — a
   mistyped `--chek` fell through to GENERATE mode and overwrote the
   committed lock: a verify that becomes a write on a typo. Now argparse;
   unknown arguments refuse.

## Duplication collapsed (the drift-risk class)

- **The release-denominator join existed twice** (`run_u0` and
  `completeness`, line-for-line) — a repair to one silently diverged the
  other. Now once, in `tools/catalog/common.py`, along with
  `package_name_from_id`, the harness-detection predicate (also previously
  duplicated between generator and runner), `sha256_file`, and the shared
  cargo env/toolchain constants.
- **The fork-file iterator existed twice** — `generate_workspace_lock`
  re-implemented `stage.py`'s walk with private copies of its skip/only
  sets; a fork-only file added in one place silently changed what the other
  digested. The lock generator now imports `stage.fork_files()` (the
  regenerated digest proved byte-identical).
- **The rustfmt nightly pin existed three ways** (constant, regex-scrape of
  the constant's source, second hardcopy). `doctor.py` and the lock
  generator now import `run_static.RUSTFMT_TOOLCHAIN`; the scrape (which
  silently skipped the check on a rename) is gone.
- **The controller test fixtures existed five times** (`makeSql`/`req`/
  `boot` per suite) — five harnesses that could diverge while appearing to
  test one. Now `core/test-support.ts` (with an observe hook the
  query-plans recorder builds on). The CI suite list is now owned by
  `package.json`'s `test:core` glob instead of a second hand-maintained
  list in gates.yml (which had already drifted).
- **Worker entry:** the 30-line hand-maintained DO stub type (plus eleven
  per-route re-casts that had already drifted to `object`) replaced by
  `DurableObjectNamespace<DatabaseControllerDO>` — one method surface, the
  class itself. The 15 copy-pasted generation guards became `generationOr`;
  the two capability middlewares now share one verification core;
  `nonNegativeU64` wraps the core's `u64FromWire` (one exact parser).
- **Core:** ControlSeq allocation was spelled three times (and
  `bumpIncarnation` was byte-for-byte `appendCommand`) → `nextControlSeq()`
  + `appendCommand`. The seven startup-session point reads → one
  `startupSession()` helper. The lease-window guard, the WAL-descriptor
  column list (4 sites), key-config's private `hex` → single definitions.
- **E2E:** six hand-paired payload-field triples → `payloadFields(receipt)`.

## Dead code removed (or honestly labelled)

- `exactU64` (zero callers), the unused `SCHEMA`/`U64_MAX`/`BatchAbort`
  exports, the superseded stacked doc comments, the unreachable
  batch-insert fallbacks, `Env.CONTAINER_LIFECYCLE` (no binding, no
  reference), the unreachable `WAL_FINALIZE_BATCH` restriction row, the
  `database-controller` no-op `core()` accessor.
- Python: the unreachable `or` clauses in `run_u0`, `run_static`'s compiled-
  but-unused regex / dead inner `glob` / identical branches / always-false
  disjunct, `validate_catalog`'s subsumed bool branch, the vacuous
  docstring conjunct in `evidence_mutants` (plus its leaked temp dir), the
  dead `mkdir`, scattered function-local imports.
- Rust: `PublishError::StaleIncarnation` (never constructed),
  `wal_model`'s redundant nested condition and duplicate match arms, the
  `command_model` double-destructure, the spike's leftover debug example.
  `resolved_known_not_appended` was NOT deleted: it is the J.5 resolver's
  landing slot (directive §9.2 step 1) and now says so.
- The `ABANDONED` states stay in both CHECK constraints, now annotated as
  reserved — removing them would make adding the transition a migration.

## Correctness-adjacent hardening

- `finalizeBatch` now refuses a mixed database/generation member set
  (`BATCH_MIXED_SCOPE`) — the envelope is recorded under `reqs[0]`'s scope,
  so a stray member was replayable nowhere; the HTTP route couldn't produce
  one, but the core is directly callable and must not trust that. Test
  added.
- The post-WAL guard's illegal-transition arm was unobservable in test mode
  (message built, nothing recorded): now a terminal `IllegalTransition`
  state with the previously missing double-resolve test.
- `command_model`'s negative control asserted a hardcoded `true` instead of
  executing its mutant; the mutant is now a real function whose false
  absence is observed.
- `openCheckpointCut` no longer walks the whole journal twice per cut: the
  post-cut anchor is derived from the appended entry's hash (returned by
  `appendJournalEntry`), keeping the pre-cut full verify. `journalHashAt`
  fetches one row (`LIMIT 1 OFFSET n-1`) instead of materialising the
  anchored prefix.
- `materialize_slatedb` fetches with curl for the same proxy/CA rationale
  its sibling documents; checkpoint_local pins the newest manifest with
  `.max()` like its remote twin; `lint_source_lock` runs the whole-tree
  workspace-lock rehash once per lint instead of twice.
- Worker consistency: checkpoint routes now parse the generation before the
  capability check (an invalid request no longer burns the single-use
  token on two route families and not the others); `/payload` answers a
  token-less request before buffering 8 MiB; the audit route wears the
  same `{ok:true}` envelope as its siblings; a non-string `batchDigest` is
  `BATCH_DIGEST_MALFORMED` (a shape error), no longer a fake comparison
  verdict; the catalogue stamps its rust toolchain by executing it, never
  from an asserted string.

## Considered and declined, with reasons (bloat-avoidance cuts both ways)

- **Folding ControlSeq allocation and prev-hash read into one query** —
  both are single index seeks now; merging couples two APIs for no
  measurable win.
- **A shared bounded-wait helper for the two storage fail-stop loops** —
  the messages are load-bearing and differ; worth it only if a third loop
  appears.
- **Unifying the two toy digest schemes in protocol-models** — both are
  deliberately toy and self-contained.
- **`resolver_model`'s `Vec::contains`** — evaluated: at model scale
  (≤4-key sets) a `BTreeSet` adds allocation and obscures the
  canonical-order logic. Left, on purpose.
- **Routing `run_static` through the shared verdict policy** — changes the
  evidence-dir format (adds verdict.json/COMPLETE); its exit codes already
  fail closed. Recorded as an owner-visible format decision, not smuggled
  in.
- **De-globalifying `completeness.py`'s error accumulators** — a CLI-run
  tool whose self-test pins current behavior; threading an errors list
  through every checker is churn without a defect. The `del errors[:]`
  resets stay, noted here as the accepted smell.
- **The two independent cucumber parsers / BUILD scanners** — stated
  design: agreement between two implementations IS the check.

## Verification (all executed after the last edit)

- `tsc --noEmit` clean (also under `--noUnusedLocals --noUnusedParameters`);
  seven controller suites 70/70; vitest workerd 8/8; standing
  drop-outbox-event mutant still killed; **L1 E2E: ALL PASS (84 checks)**.
- protocol-models 37/37 (clippy clean); publication-firewall spike 4/4;
  storage lane 28/28 (includes the new illegal-transition test).
- Evidence producers re-verified over the ARCHIVED corpus: `run_u0
  --verdict-only` GREEN over the same 106 rows, `completeness` exit 0 with
  identical counts, `compare_u2s3 u2s3-full-3` byte-identical comparison
  output, `evidence_mutants` 24/24, both validators' self-tests PASS,
  `doctor` green, source-lock lint PASS with the regenerated workspace
  lock, `materialize_slatedb --check` OK.
