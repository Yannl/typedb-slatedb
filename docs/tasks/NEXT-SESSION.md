# Handoff: state at merge to main, and what a fresh session does next

**Written at:** end of the V16-convergence + donor-response session; updated
after the follow-up round (PR #2). Start a new session FROM `main`.

## One-paragraph state

Every P0 the V16 convergence audit accepted is closed with code, executed
negative controls, and executed mutant runs; the independent donor's
adversarial audit (branch `claude/typedb-donor-verification-sfxfbz`) filed
4 P0s — all four are closed, and of its 7 P1s, A5 and A10 are now also
closed (A4/A8 substantially addressed, A7 documented interim, A9/A11
staged for U3.2). All lanes are green: storage lib 18/18 on U2S3 (memo,
posture, materialisation and retry-channel controls, mutant-verified),
control-plane core 23/23 / journal 7/7 / state 5/5 / workerd 8/8 / L1 E2E
61/61, catalogue completeness green (exit 0). The full single-commit
corpus evidence exists at `docs/evidence/G3/u2s3-full-2/` (105/106,
0 unexplained) but predates this session's storage changes — a re-run is
the top follow-up.

## Read these first (10 minutes)

1. `docs/reviews/v16-convergence-audit.md` — the finding-by-finding truth
   table (headings + status table are current).
2. `docs/reviews/donor-a-branch-response.md` — all 14 donor findings with
   dispositions and SHAs.
3. `docs/design/slatedb-external-epochs.md` — the staged F4/F5 fork design
   (file/symbol level).
4. `docs/operations.md` — gate table + how to run everything.

## Commit map (this session, oldest first)

| SHA | What |
|---|---|
| `e20cff5` | u2s3-full-2 corpus evidence (single-commit, 105/106, 0 unexplained) |
| `997da46` | F7r: exact u64 (BE-blob SQL, bigint core, decimal-string wire) + 2^53 mutant |
| `ed13a9a` | F8: authenticated journal (canonical encoding, chain, MAC) + tamper matrix |
| `fe853aa` | F9r: capability tokens on every route; content-addressed keys; refusal matrix |
| `d47378e` | F7r/F6r: command ledger, CheckpointCut, anchored journal verification |
| `3c00b9e` | F3: immutable materialisation namespaces, NoDeleteStore; F4/F5 posture guard + fork design |
| `b76ad35` | F10r: completeness tooling (fail-closed BUILD parse, leaf recounts, flake ledger) |
| `c71b8e1` | Donor A3: session-bound WAL_FINALIZE capabilities |
| `f8c1bae` | Donor A6: key-count memo actually written; schema lock off the remote scan |

## Follow-ups already done (second round, PR #2)

- Catalogue regenerated from the pristine tree (4740 leaves; dead outlines
  correctly excluded) and `completeness.py` runs GREEN against
  `u2s3-full-2` (`3fde3be`) — the one fail-closed catch (Bazel
  `test_crate_client`) resolved by directory identity, no allowlist entry.
- V16 audit statuses folded into the headings + a status table (`d16a912`).
- Donor A5 CLOSED (`0953ec0`): `generation` exact at every wire entry
  point, E2E 61/61 with two new refusal controls.
- Donor A10 CLOSED (`5d05d5c`): `get_prev` retries `ErrorKind::Unavailable`
  (bounded, backoff) before the fail-closed panic; retry-everything mutant
  executed; storage lib 18/18 on U2S3.

## Top follow-ups, in order

1. **Re-run the single-commit corpus on the merged tree.** The
   `u2s3-full-2` evidence is from `c75a1af`; F3/A6/A10 changed `open_s3`,
   the estimate path and `get_prev` since. Run:
   `python3 tools/fork/stage.py && cd sources/typedb && cargo +1.93.0 test --workspace --no-run`
   then `python3 tools/catalog/package_assembly.py` and
   `python3 tools/catalog/run_u0.py --reap --timeout 7200 --out docs/evidence/G3/u2s3-full-3`
   (U2S3 env vars in `docs/operations.md`; MinIO must be up), then
   `python3 tools/catalog/compare_u2s3.py u2s3-full-3` and
   `python3 tools/catalog/completeness.py --results docs/evidence/G3/u2s3-full-3`.
   Expect the same 105/106 with the storage:storage delta growing by the
   new controls (+8 lib tests vs u2s3-full-2: memo, posture,
   materialisation, retry-channel).
2. **Donor P1 remainders**: A4 core-level per-procedure session
   revalidation beneath the capability layer; A9/A11 are U3.2 integration
   items (native checkpoint clone, container epoch token).
3. **The remaining OPEN-P0s are the big builds**: F4/F5 external-epoch
   SlateDB fork (design staged at file/symbol level), F6r controller-owned
   global CheckpointCut integration with TypeDB (U3.2), F8r immutable R2
   RecoveryAnchor publication. G2/L3 remain blocked on credentials
   (SI-G0-3).

## Environment notes (save yourself an hour)

- Build/test in `sources/typedb` (materialize via
  `python3 tools/source-lock/materialize_sources.py`, then
  `python3 tools/fork/stage.py`). `stage.py` now bumps mtimes — do NOT
  revert that; cargo fingerprints by mtime and stale mutant binaries
  survive restores otherwise.
- Never `pkill rustc` mid-build: cargo orphans into `do_wait` holding
  `target/debug/.cargo-lock`, and every later build deadlocks silently at
  0% CPU. If it happens: kill the cargos, `rm target/debug/.cargo-lock`.
- MinIO: binary + data in the session scratchpad previously; a fresh
  session should install its own (`docs/operations.md`) and export the
  TYPEDB_S3_* env vars before any U2S3 test. Two lib tests hang (not
  fail) if MinIO is down.
- Disk: the session allowance dies at ~38G used; `sources/typedb/target`
  is ~15G after a full corpus build. Delete target/ before a fresh corpus
  run if a previous build generation exists.
- Control-plane: `cd control-plane && npx tsc --noEmit`, node suites via
  `node --test --experimental-strip-types src/controller/core/*.test.ts`,
  `npx vitest run`, E2E via `npx wrangler dev --port 8787` +
  `node scripts/local-stack-e2e.mjs` (wipe `.wrangler/state` first — old
  DO SQLite rows predate the blob-sequence schema and fail closed).

## Suggested opening message for the new session

> Continue the TypeDB-on-SlateDB/R2 work from main (see
> docs/tasks/NEXT-SESSION.md). Start with follow-up 1: re-run the
> single-commit corpus on the merged tree into u2s3-full-3, with the
> oracle comparison and a completeness run against the new results. Then
> the donor P1 remainders (A4 core-level session revalidation) and the
> staged OPEN-P0 builds per the audit (F4/F5 external-epoch fork first).
