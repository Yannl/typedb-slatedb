# ADR-0004 — Port the static checks rather than exclude them

**Status:** accepted, Phase B (G1)
**Contract:** brief §22.2, §22.5; conformance plan steps 8–10

## Context

154 of the 271 catalogued targets are static checks declared only in Bazel:

| Rule | Targets | What it does upstream |
|---|---:|---|
| `checkstyle_test` | 91 | Java Checkstyle over a glob-selected file set |
| `rustfmt_test` | 63 | rustfmt `--check` over a crate's sources |
| `release_validate_deps` | 2 | Kotlin/JVM validation of tagged deps vs `VERSION` |

Every one of the 154 `static::` targets pairs with a BUILD rule; none is unresolved. The
240 test-producing BUILD targets account for exactly 91 + 63 + 85 `rust_test` + 1
`release_validate_deps` call site.

None has a Cargo entry point. Left alone they sit in `not_executed` permanently and the
gate can never be green for an honest reason. The contract does provide an escape hatch —
a catalogue `exclusions` entry with an owner and an expiry — and using it here would be
formally compliant.

It would also be 154 recorded admissions that the majority of the corpus was not
reproduced, on targets that are individually trivial. The exclusion mechanism exists for
things that genuinely cannot run in this environment (real-account probes, platform-specific
paths), not for things that are merely inconvenient.

## Decision

Port the checks. Each is reproduced from its upstream definition, not approximated.

**`checkstyle_test`.** Upstream runs Java Checkstyle (TBD `tool/checkstyle/rules.bzl`
L6-60) with the config at `tool/checkstyle/templates/checkstyle.xml`. That config's
`TreeWalker` modules — `AvoidStarImport`, `JavadocType`, `NeedBraces`,
`OneTopLevelClass`, `OuterTypeFilename` and the rest — parse Java and contribute nothing
over this repository's Rust, Starlark and TOML files. The modules that actually apply are
the file-level ones, and two are reproduced exactly:

* `RegexpHeader` against `config/checkstyle-file-mpl-header.txt`, whose five regexes are
  used verbatim. The first is an alternation over `#!`, `@` and `<?`, which is why a
  shebang-prefixed script still satisfies the header; that optionality is preserved rather
  than paraphrased away.
* `FileTabCharacter` — no literal tab anywhere in the file.

The file set is resolved from the same `include`/`exclude` globs the BUILD rule declares,
so a file upstream excludes is excluded here for the same reason.

**`rustfmt_test`.** Run with `nightly-2026-04-15`, the toolchain `MODULE.bazel` L37 pins as
`rustfmt_version = "nightly/2026-04-15"`. This matters more than it looks: rustfmt's output
changes between releases, so running the stable formatter would be a different check wearing
the same name, and it could fail on code upstream considers correctly formatted. The rule
names Bazel *targets* rather than files, so the BUILD scan records `srcs` for every rule —
not only test producers — and resolves them.

**`release_validate_deps`.** A semantic port (see CR-A-02): the same three inputs the Kotlin
harness reads — workspace refs, `VERSION`, the tagged dependency list — checked in Rust.

**Anything else.** A static rule with no port produces `Unknown`, never a pass. Nothing is
in that state today, but the branch exists so that a rule added upstream keeps the gate red
until it is ported, rather than vanishing from the run.

## The regex subset

`RegexpHeader` needs a regex engine, and this repository has no regex dependency. Rather
than add one or hand-wave the match, the implementation supports exactly the syntax the five
checked-in patterns use — `^`/`$` anchors, `.*`, top-level alternation, backslash escapes —
and **hard-errors on anything else**.

This is the same principle as the BUILD reader failing on unknown macros. A permissive
matcher that silently accepted an unrecognised pattern would report 91 passing checkstyle
targets while checking nothing, and that failure would be invisible. A matcher that stops is
noisy and correct.

## Consequences

* 154 targets and 156 leaf cases move from "never executed" to executed, with real verdicts.
* The checks are now fork-owned code, so they can drift from upstream's. The mitigation is
  that they are derived from pinned source with anchors in the module docs, and the source
  graph digest changes if those definitions change.
* `nightly-2026-04-15` becomes a required toolchain for the lane, recorded alongside 1.93.0.
* These are ports, not byte-identical reproductions: the catalogue marks them
  `SEMANTIC_PORT`, which is the honest classification.

## Alternatives rejected

* **154 exclusions.** Formally allowed, substantively an admission of non-reproduction on
  the majority of the corpus.
* **Run real Checkstyle under a JVM.** Faithful to the letter, but it would add a JVM and a
  Checkstyle jar to the toolchain to execute Java-shaped rules that do nothing on Rust
  files. The two file-level modules are the entire effective content.
* **Skip rustfmt because the nightly is awkward to obtain.** It installed in under a minute.
  "Hard to get" was an assumption worth checking before it became an exclusion.
