# ADR-0002 — Bazel evidence: Mode S now, Mode Q deferred

**Status:** accepted, Phase A (G0)
**Contract:** brief §1.5, §21.10; addendum A17.3

## Context

Brief §1.5 offers two mutually exclusive ways to prove the test denominator is complete
despite Bazel being absent from CI:

* **Mode Q** — one isolated, sacrificial environment runs `bazel cquery` once per source
  pin and archives the target snapshot as inert audit evidence.
* **Mode S** — fork-owned tooling parses and expands every relevant macro and external
  repository declaration, with zero unknown target.

Addendum A17.3 selects Mode Q. §21.10 adds the binding constraint either way: "The auditor
does not claim to evaluate arbitrary Starlark unless Mode Q provides a locked query result.
Unknown macros fail G0."

## Decision

Mode S is implemented and passing now; Mode Q remains the selected mode and is deferred
until a Bazel-capable sacrificial environment exists.

The Mode S auditor is `tools/corpus-catalog/src/starlark.rs` plus the rule classification in
`corpus-catalog/src/lib.rs`. Its load-bearing property is that it **fails on anything it
does not recognise** rather than returning an empty result:

* every top-level construct it cannot parse is an error naming the file and line;
* every rule name not on an explicit list is reported as unknown and fails the audit;
* `glob()` and `select()` are preserved as structured values, so a `select` cannot collapse
  to the host platform's branch and hide the other four;
* file-scope assignments are resolved, because `tests/assembly/BUILD` passes its archive
  environment through a variable and reading it as empty would have silently dropped the
  assembly fixture contract.

Current result over TB `2256711a`: **76 BUILD files, 0 unparsed, 0 unknown rules**, 227
test-producing targets (85 `rust_test`, 63 `rustfmt_test`, 78 `checkstyle_test`, and
1 `release_validate_deps` call site expanding to 2 Bazel test targets).

Mode Q is still required before a release claim, for one specific reason: Mode S proves
that no *unrecognised* rule exists in the checked-in BUILD files, but it does not evaluate
macro expansion in general. `release_validate_deps` is the proof that this matters — it
looks like an ordinary rule at the call site and only reveals two test targets when its
`.bzl` definition is read (see CR-A-02). That one was caught by reading the definition;
Mode Q catches the class mechanically.

## Consequences

* G0 can complete without a Bazel installation, and CI stays Bazel-free as §1.5 requires.
* The "zero unknown macro" claim is currently backed by an auditor that errors on
  surprises, plus hand-verification of each rule against its `.bzl` definition. Every such
  verification is anchored in `KNOWN_NON_TEST_RULES` and `TEST_PRODUCING_RULES`.
* A source rebase that introduces a new macro stops the catalogue, which is the intended
  behaviour.
* Until the Mode Q snapshot exists, `bazel_query_oracle` in the emitted catalogue is
  `null` — an honest absence rather than an unbacked claim.

## Follow-up

Produce the Mode Q snapshot on a disposable machine at the exact source pin, archive it
under `third_party/bazel-evidence/` with the Bazel version and full invocation, and set
`bazel_query_oracle` in the catalogue. Tracked as a G0 residual, not a silent gap.
