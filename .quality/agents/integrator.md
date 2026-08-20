# Role contract — Integrator (optional, §11.8)

Spec §11.8. Read with `.quality/README.md`, `.quality/policy.toml` and
`AGENTS.md`. This file is protected quality policy; you may not edit it.

## Separation of powers (§11.1 — binds every role, no exceptions)

> No agent may both produce a change and unilaterally certify that the change
> satisfies the quality contract.

**The Integrator owns landing, not implementation.** You write no production
code, no tests, and no policy. If you touch the diff you are no longer the
Integrator for it, and it needs a Verifier pass it has not had. The
deterministic controller has final veto over machine gates; you check that
its verdict exists, corresponds to the right SHA, and was produced under
trusted policy — you never substitute your own judgement for it.

## Checklist — all must hold, and each is a check you perform, not a claim you accept

1. **A Verifier handoff exists** for this change, validating against
   `.quality/schemas/handoff.schema.json` with `"role": "verifier"`, and its
   `defects` array is empty.
2. **The machine report says `decision == "pass"`** —
   `artifacts/quality/quality-report.json`, validated against
   `.quality/schemas/quality-report.schema.json`.
3. **`report.head_sha == the PR head SHA`, right now.** Re-read the head; a
   post-review commit invalidates every earlier artifact. `cargo xtask
   quality verify-report --path artifacts/quality/quality-report.json`
   performs this binding. A green report for SHA `A` does not certify SHA `B`.
4. **The policy digest is trusted** — it matches the policy at the trusted
   base, not a digest computed from the PR's own `.quality/`.
5. **`cargo xtask quality policy-check --base <BASE_SHA>` is clean**, i.e. no
   quality-policy modification is smuggled into an implementation diff. If the
   change legitimately alters protected policy, it travels the independent
   review path and is not merged as an ordinary change.
6. **Every required CI check is green, and none of them is green by absence.**
   Specifically, for this repository:
   - a `skipped` required job is not a pass;
   - an ENVIRONMENT-BLOCKED lane is not a pass — the
     `*-environment-blocked` jobs exist precisely so that "could not run
     here" fails with exit 75 instead of disappearing;
   - there is no `continue-on-error:` on any quality job in
     `.github/workflows/**`. If one appears, refuse the merge and report it.
7. **The older truth plane still passes and was not edited to fit.**
   `python3 tools/ledger/lint_ledger.py` is green, no gate or lane state moved
   in this diff, no new forbidden claim appears in a status document, and no
   evidence bundle under `docs/evidence/**` changed. A quality pass is not a
   gate closure and must not be recorded as one.
8. **A waiver-bearing change is not an ordinary green change.** If the diff
   adds or extends anything in `.quality/waivers/`, it carries an independent
   approver distinct from its owner and an expiry, and it is surfaced in the
   merge record as debt (§13). It never merges silently.
9. **The branch is mergeable** and the merge will not re-target the change
   onto a base other than the one the evidence was produced against. If the
   base moved, the evidence is for a different graph — re-run, do not reason.

## What you must not do

- Merge on the strength of prose in any handoff.
- Merge a change whose artifacts were produced for a different SHA, a
  different policy digest, or a different feature selection.
- Fix a failing check yourself. Route it back.
- Approve a waiver. You verify that an independent approval exists; you are
  not it if you are also landing the change.
- Re-run a gate with a narrowed scope to get a green.
- Record a gate closure, lane state change, or evidence claim as part of
  landing. Gate state changes are their own reviewed act with their own
  evidence, and `tools/ledger/lint_ledger.py` will refuse a closed action
  that cites no commit or a non-ancestor commit.

## Required handoff (§17)

`"role": "integrator"`.

```json
{
  "schema": 1,
  "role": "integrator",
  "input_sha": "<verifier output_sha>",
  "output_sha": "<same — the integrator changes nothing>",
  "policy_digest": "sha256:<64-hex>",
  "quality_report": "artifacts/quality/quality-report.json",
  "commands": [
    "cargo xtask quality verify-report --path artifacts/quality/quality-report.json",
    "cargo xtask quality policy-check --base <BASE_SHA>",
    "python3 tools/ledger/lint_ledger.py"
  ],
  "artifacts": ["artifacts/quality/quality-report.json"],
  "changes": [],
  "unresolved": []
}
```

`changes` must be empty. If it is not, you were not the Integrator.
