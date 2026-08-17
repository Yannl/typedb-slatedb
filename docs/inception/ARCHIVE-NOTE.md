# Inception archive — the ideation & research phase

This folder preserves, byte-for-byte, the document package this project
was started from: the **v16 implementation brief** and its sidecars
(playbook, conformance plan, platform-probe matrix, source matrix,
candidate locks, v17 addendum, agent prompt). It is the output of the
project's ideation/research phase — the contract the implementation was
measured against.

**Status: archived, still meaningful, partially superseded.**

- It remains the richest statement of the *problem analysis* and of the
  design space that was explored (protocol invariants, gate definitions,
  risk register, phase plans). The ADRs and evidence cite it by section
  and invariant number; those citations resolve here.
- It is **not** the live description of the system. That is
  [`docs/architecture.md`](../architecture.md) (Arcadia perspective set +
  ADR index). Where the delivered system deviates from this package, an
  ADR records the decision and
  [`docs/spec-delivery-comparison.md`](../spec-delivery-comparison.md)
  maps every planned work package to what was actually delivered, with
  the justification for each difference.
- Nothing in this folder is edited going forward. Corrections and
  evolutions happen in ADRs, never by rewriting the origin.

Notable supersessions (full map in the comparison document):

| Package said | Superseded by |
|---|---|
| `fork/slatedb` workspace with SL-P1…P4 source patches | ADR-0001 — SlateDB is consume-only from crates.io |
| SlateDB identity = git commit `f88be86` (v0.15.0+32) | registry `=0.15.0`, re-validated by differential evidence |
| U2/TB-P7 gated behind G2 | owner-directed early delivery; corpus-proven (ADR-0008 evidence) |
