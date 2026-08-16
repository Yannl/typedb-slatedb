# Source pin changes

A pin change invalidates the baseline. The baseline is a statement about *one* revision.

## Procedure

1. **Update the declaration** in `tools/source-lock/src/`.
2. **Re-fetch** and run `cargo xtask source-lock`. It refuses dirty, mismatched, or shallow
   shipping/compiling nodes. Note whether `source_graph_digest` changed — it should, and only
   because the sources did.
3. **`cargo xtask verify-cargo-parity`.** Expect failure if upstream added a Bazel macro. Read
   the new rule's `.bzl` definition before classifying it; `release_validate_deps` looks like an
   ordinary rule and expands to two Kotlin/JVM test targets.
4. **Regenerate the catalogue.** Compare target and leaf-case counts against the previous
   catalogue. An unexplained *drop* is the dangerous direction — it means coverage vanished
   silently.
5. **Re-run U0.** Compare against the previous baseline case by case, not in aggregate.
6. **Record contradictions.** If the new revision disagrees with the contract, write a record
   with anchors rather than adapting quietly.

## What a changed digest means

`source_graph_digest` covers node revisions and content only. It must **not** move because a
run left artifacts behind — that happened once, when the tree hash included staged fixtures and
logs, and made every post-run regeneration look like a source change. Run residue is excluded
by name; if the digest moves without a pin change, that exclusion has a gap.

## Reviewing a count change

| Change | Likely meaning |
|---|---|
| leaf cases up | upstream added tests, or a previously-missed case is now enumerated |
| leaf cases down | upstream removed tests, **or the enumerator regressed** |
| targets up/down | a BUILD rule was added or removed |
| exclusions up | more skips are owned — check they are upstream's decision, not ours |

The second row deserves suspicion every time. Confirm a drop against upstream's diff before
accepting it.
