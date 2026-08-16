# ADR-0003 — How a composite harness reports leaf cases

**Status:** accepted, Phase B (G1)
**Contract:** brief §22.2, §22.3, §21.11; conformance plan steps 8–10 and hard stops

## Context

Three of the upstream corpus's largest suites hide many leaf cases behind very few libtest
cases:

| Suite | libtest cases | Catalogued leaf cases |
|---|---:|---:|
| behaviour (Cucumber) | 2–4 per target | thousands of scenarios |
| `test_fail_points` | 2 | 44 (22 registry members × 2 loops) |
| criterion benches | 0 (`harness = false`) | 1 per bench binary |

Brief §22.2 forbids counting these as opaque greens. The conformance plan makes
"composite harness cannot expose leaf cases" a hard stop, and step 9 forbids treating
skips, zero-case runs, early success or retry-created passes as passes.

The difficulty is that "expose leaf cases" is not free: each harness reports differently,
and a wrong parser is worse than no parser, because it produces confident nonsense.

## Decision

Each composite kind gets its own attributor, and each is allowed to say "I don't know".

**Cucumber** (`conformance-runner/src/cucumber.rs`). Scenario results are parsed from the
`Basic` writer's own output — `Scenario:` / `Scenario Outline:` lines followed by step
glyphs (`✔` pass, `✘` fail, `?` skip; `writer/basic.rs` L566/L669/L609 at cucumber 0.19.1).
A skipped step counts as a failure because upstream sets `.fail_on_skipped()`
(`tests/behaviour/steps/lib.rs` L180). Two independent checks guard the parse:

1. the `[Summary]` block's own `N scenarios (…)` total is summed across libtest cases and
   compared against the number of scenarios parsed — a mismatch downgrades every result
   from that target to `Unknown`, never to a pass;
2. a scenario reported by the harness but absent from the catalogue is emitted under an
   `<uncatalogued>` id, which `summarise` counts as an unknown case and which turns the
   gate red — because it means the denominator is wrong.

**Failpoints** (`conformance-runner/src/failpoint.rs`). The harness prints nothing per
registry member, so attribution is deliberately conservative and asymmetric:

* loop case passed → all 22 of its members pass. The loop body is unconditional and any
  failure panics (`fail_points.rs` L108, L118), so reaching the end proves all 22 ran.
* loop case failed → all 22 of its members fail, including those that had already
  succeeded before the panic. This under-credits and never over-credits.
* loop case absent from the output → no result emitted, so the members appear as
  not-executed and the gate stays red.

**Benches.** One leaf case per binary, verdict from the process exit status. A criterion
binary has no libtest CLI, so nothing finer is available without editing upstream sources —
which §22.5 would require a `TestPortRecord` for, and which buys nothing here.

Two rules apply across all of them, in `summarise`:

* a duplicate result never upgrades an earlier verdict, so a retry cannot manufacture a
  pass;
* an outcome the runner cannot classify is `Unknown`, which is never green.

The runner also refuses to start when `SCENARIO_FILTER`, `FAILPOINTS` or `RUST_TEST_ARGS`
are set in the ambient environment. `SCENARIO_FILTER` in particular is read by upstream's
own `filter_run` closure (`lib.rs` L193): inheriting it from a developer's shell would
produce a green over a silently reduced corpus, which is the precise failure mode brief
§22.3 exists to prevent.

## Consequences

* Behaviour targets contribute per-scenario results, so a single regressed scenario is
  visible instead of being averaged into a target-level pass.
* Failpoint failures are over-reported by design. The raw log names the failing member, so
  triage is not harmed.
* The bench leaf cases are coarse, and the catalogue says so via `case_discovery = SCRIPT`
  rather than pretending finer granularity exists.

## Alternatives rejected

* **Exit status for everything.** One green for 4 000+ scenarios. Exactly what the contract
  forbids.
* **A JSON writer for cucumber.** Would require editing upstream test sources or the steps
  crate, converting byte-identical targets into semantic ports for a reporting convenience.
  Reconsider only if the text parse proves fragile against a cucumber bump — the summary
  cross-check exists to detect that rather than to hide it.
