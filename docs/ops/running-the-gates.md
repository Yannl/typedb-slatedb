# Running the gates

## Fast checks (seconds to minutes)

```bash
cargo xtask source-lock          # source graph resolvable and clean
cargo xtask doc-lint             # contract internally consistent
cargo xtask verify-cargo-parity  # no unknown Bazel macro
cargo xtask native-toolchain     # native inputs pinned and digested
```

Any failure here stops everything downstream. They are cheap; run them first and often.

| Failure | Meaning | Action |
|---|---|---|
| dirty checkout | a pinned source was edited | revert it; the baseline is void otherwise |
| pin mismatch | declared tag ≠ resolved commit | fix the declaration or the checkout, not the check |
| unknown BUILD rule | upstream added a macro | read its `.bzl` definition and classify it |
| doc-lint finding | contract references an undefined id | correct the contract, record why |

## The corpus gates (hours)

```bash
cargo xtask catalog-upstream-tests --with-libtest-listing   # ~35 min
cargo xtask assemble                                        # needs Console built
cargo xtask test-upstream --profile U0                      # ~90 min
```

## Reading the verdict

```
targets    : 114/114
leaf cases : 4757/4757
passed=…  failed=…  ignored=…  unknown=…
verdict    : NOT GREEN
```

Check reconciliation **first**: passed + failed + ignored + unknown must equal the leaf-case
total. If it does not, the numbers mean nothing regardless of how good they look.

| Line | What it means | Is it acceptable? |
|---|---|---|
| `failed` | a real failure | only if traced to an owned exclusion |
| `unknown` | the runner could not classify | never — investigate |
| `never executed` | catalogued but not run | never — a hole in coverage |
| `absent from the catalogue` | ran something not catalogued | never — the denominator is wrong |
| `declared-ignored with no exclusion` | an unowned skip | must be owned before a gate passes |

`NOT GREEN` at this stage is **correct**: nothing has been ported, and the baseline records
what upstream actually does — including two of its own tests that fail.

## What must never be done

* Re-running until green. Duplicate results merge to the *worst* verdict specifically to make
  this useless.
* Setting `SCENARIO_FILTER`, `FAILPOINTS` or `RUST_TEST_ARGS`. The runner refuses to start.
* Citing a `--only` run as coverage. It self-labels as unable to support a claim.
* Converting a failure to a skip to clear a gate. If a target cannot run here but runs
  upstream, it stays red; only something nothing runs anywhere is excludable.
