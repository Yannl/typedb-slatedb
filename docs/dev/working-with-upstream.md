# Working with upstream

## The prime directive

**Upstream test sources are not edited to make them pass.** If a test cannot find a fixture,
the launcher supplies the fixture; the test file stays byte-identical. This is what keeps the
conformance claim meaningful — a corpus you edited is a corpus you can always make green.

Four times upstream turned out to be wrong rather than us. In none of those cases was the
source patched; the runner adapted around it and the disagreement was recorded in
[contradiction records](../evidence/phase-a/contradiction-records.md).

## Fixture staging

Upstream behaviour tests resolve `.feature` files through paths Bazel used to provide. The
runner stages the pinned corpus at **every path the sources reference**, derived by reading
the string literals rather than hardcoding a convention. That matters because upstream's paths
are not uniform:

| Source | Path | Correct? |
|---|---|---|
| 92 files | `bazel-typedb/external/typedb_behaviour+/…` | yes |
| `query/language/variables.rs` L20 | `typedb_behaviour**++**` | no — one `+` too many |
| `query/language/given.rs` L20 | `typedb_behaviour` | no — missing `+` |
| `concept/migration/*.rs` | `../typedb_behaviour+/…`, no non-Bazel branch at all | n/a |

All three deviations live in the `#[cfg(not(feature = "bazel"))]` branch, which Bazel CI never
compiles — which is exactly how two typos survived into a released tag. Deriving the list means
a fourth spelling stages itself instead of failing a run.

**Never pass `--features bazel`.** No Cargo manifest declares it, and it is the flag that
selects the path the Cargo lane must *not* take.

## Bumping a pin

1. Update the revision in `tools/source-lock/src/`.
2. Re-fetch, then `cargo xtask source-lock` — it refuses dirty, mismatched or shallow nodes.
3. `cargo xtask verify-cargo-parity` — **expect this to fail** if upstream added a macro. That
   is the point: an unknown rule stops the catalogue rather than silently shrinking it.
4. Read any new macro's `.bzl` definition before classifying it. `release_validate_deps` looks
   like an ordinary rule at the call site and expands to two Kotlin test targets.
5. Regenerate the catalogue and re-run U0. The baseline is per-pin; an old baseline is not
   evidence about a new pin.

## Adding a patch to the fork

Patches apply to `fork/`, never to `sources/`. Each needs:

* a patch id defined in the brief (`cargo xtask doc-lint` cross-audits this);
* a `TestPortRecord` if it changes how any upstream test executes;
* a re-run of U1 against the U0 baseline.

`server/service/admin/proto/Cargo.toml` is hand-maintained upstream and excluded from their
sync gate — do not "fix" it by regenerating, or its `[build-dependencies]` disappear and the
Cargo build breaks.

## When upstream is wrong

Record it, do not route around it silently. A contradiction record needs the anchor
(file and line at the pinned revision), what the contract or convention claimed, what the
source actually says, the minimal correction, and the impact. Ten exist; four are upstream
defects, including two tests that fail in a released tag because their bodies are `todo!()`.
