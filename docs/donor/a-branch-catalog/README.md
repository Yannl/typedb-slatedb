# A-branch denominator run — evidence

The donor test-corpus tooling, run against the selected integration base
(`claude/review-continue-previous-zv4wmi` @ `e20cff5`, subject `A/fork/typedb`).

- `DENOMINATOR-SUMMARY.json` — the headline result: 296 targets, 4353 leaf cases, 0 unknown
  macros, 0 unparsed BUILD files, and **zero set-level delta** against the donor's own fork
  baseline (identical target and leaf sets).
- `a-fork-sealed-catalog-U0.json` — the full catalogue, sealed under a fork-tree digest of
  `A/fork/typedb` (`3e360b23…`).
- `catalogue-provenance-U0.json` — marks that seal fork-derived, not pinned-graph-derived.
- `cargo-build-reconciliation.json`, `build-test-targets.json` — Cargo↔BUILD reconciliation
  (85 matched, 0 unknown rules, 0 unparsed).

See `../tooling-reusability.md` for how these were produced and the provenance caveat, and
`../a-branch-adversarial-report.md` §A14 for why an identical denominator does **not** by
itself validate A's 105/106 pass claim.
