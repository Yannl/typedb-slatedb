# Evidence handling

## What is produced

| Artifact | Command | Authoritative for |
|---|---|---|
| `source-lock/source-lock.json` | `source-lock` | which sources were used |
| `docs/evidence/phase-a/native-toolchain.json` | `native-toolchain` | which compilers were used |
| `docs/evidence/phase-b/upstream-test-catalog-U0.json` | `catalog-upstream-tests` | the denominator |
| `docs/evidence/phase-b/run-U0/coverage-report.json` | `test-upstream` | the verdict |
| `docs/evidence/phase-b/run-U0/target-runs.json` | `test-upstream` | exact argv, env, per-case outcomes |
| `docs/evidence/<phase>/manifest.json` | `evidence --phase` | one digest over the whole phase |

## What is authoritative

The **JSON artifacts**. The markdown summaries are navigation, and they have drifted from the
artifacts more than once in this project's short history — always by restating a number that
later changed.

If a summary and an artifact disagree, the artifact is right and the summary is a bug.

## Staging, and why runs do not delete first

A run writes to `.run-<profile>.staging/` and swaps it in on completion. Two failure modes this
avoids:

* merging into the previous run, leaving logs from targets the catalogue no longer contains;
* deleting the published directory up front, so a crash mid-run leaves the repository with its
  baseline missing for hours.

The last good evidence stays in place until there is new evidence to replace it.

## Retention

Keep, and commit:

* every JSON artifact and manifest;
* the summaries.

Do not commit per-target `.stdout.txt`/`.stderr.txt` — they are large and git-ignored. They are
the first thing to read when diagnosing, and the first thing to discard afterwards.

## Reproducing a result

`target-runs.json` records the exact argv, working directory and environment of every target.
A result that cannot be reproduced from it is a bug in the recording, not an acceptable
outcome — the point of recording commands rather than narrative is that anyone can re-run them.

## When evidence and reality diverge

Regenerate; do not edit. Every artifact has a command. Hand-editing one produces something that
looks like evidence and is not, which is worse than having none.
