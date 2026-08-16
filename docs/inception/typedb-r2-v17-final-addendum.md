# TypeDB/R2 — v17 final addendum (release authorization for the implementation programme)

**Role of this document.** `typedb-r2-implementation-brief-v16.md` is the sole normative architecture contract. This addendum (a) records the source-owner's acceptance of the v16 review, (b) closes the three decisions v16 left open or under-specified, and (c) adds three product requirements stated by the project owner that the implementing agent MUST treat as first-class release criteria. Where this addendum and v16 conflict, this addendum wins; everywhere else v16 is authoritative verbatim.

## A17.1 Acceptance of the v16 review

All 24 P0, 10 P1, and 2 P2 findings from `typedb-r2-v15-adversarial-review-v16.md` are ACCEPTED as resolved by v16's design text, with two scoped amendments below (A17.2, A17.3). The prior source-verification history stands: every source-anchored fact cited in v13/v15 appendices was verified by direct read of the pinned checkouts (TypeDB `2256711a`, SlateDB `f88be86d`), including the target-level census (59 `[[test]]` + 8 bench targets over 13 manifests, 41 workspace members), the generated-manifest/Bazel-sync coupling, the assembly/crash fixture semantics, the `fail_point::ALL` registry, and the external behaviour-corpus pin `typedb/typedb-behaviour @ ac5d5733a484cea1d8809a2968029a818fdae24f`. Prose counts remain non-authoritative until the generated catalogue exists (v16 P0-24) — they are reconnaissance floors, not denominators.

## A17.2 Amendment — repository orchestration (v16 P0-04 / P2-02)

The federated-workspace correction is ACCEPTED in full: the TypeDB fork keeps its own upstream-shaped Cargo workspace (`fork/`, 41 members, paths unchanged), SlateDB keeps its own (`slatedb/`), and tooling/conformance crates form a third small workspace. No unified root Cargo workspace exists; Cargo feature unification, profiles, and lock resolution therefore behave exactly as upstream per workspace.

Amendment: **moonrepo is retained as the repository-level task orchestrator** — a standing product decision by the project owner — with v16's constraint honored by construction: moon never becomes a semantic build system. It only invokes per-workspace Cargo/npm commands with content-hashed inputs for CI caching; every task remains runnable by its bare underlying command; the release evidence records the underlying commands, not moon invocations; and moon's own binary is proto-pinned like every other tool. Removing moon must never change any build or test outcome (this is a stated negative control in Phase A). Per v16 P1-06, bare `cargo test` remains allowed for local iteration; only *release coverage claims* must come from the catalogue runner.

## A17.3 Amendment — Bazel evidence mode (v16 P0-05)

**Mode Q is selected**: one isolated, documented, sacrificial environment produces the `bazel cquery` snapshot once per source pin, archived under `third_party/bazel-evidence/` with the exact Bazel version and invocation recorded. CI and developer environments are Bazel-free; the snapshot is inert audit input to the catalogue parity auditor. A source rebase regenerates the snapshot in the same isolated mode.

## A17.4 Product requirement — pluggable backend, identical server API (NEW, release-blocking)

The fork MUST support two fully supported storage/durability backends behind the same server binary, selected by configuration only:

1. **`classic`** — RocksDB keyspaces + file WAL, byte-for-byte upstream behaviour. This is profile U1's runtime shape and is a shipping mode, not just a test oracle: the project's local development runs classic TypeDB in an ordinary container.
2. **`slatedb-r2`** — the remote profile of the v16 contract (SlateDB keyspaces, external WAL, controller).

Requirements: (a) selection via server config/flag (`--storage.backend=classic|slatedb-r2` or config-file equivalent) resolved at database open; no compile-time-only switch may remove `classic` from the release binary; (b) **zero difference above the storage boundary** — query semantics, wire protocols, error surfaces, and observable behaviour are identical across backends, proven continuously by U0/U1 structured equality and by running the storage-independent corpus on both; (c) a database created under one backend is not silently openable under the other — cross-backend movement is an explicit export/import or backup/restore operation with typed errors otherwise; (d) mixed-backend deployments (some databases classic, some remote) are permitted only if per-database isolation is proven, else the server rejects mixed config with a typed error — decided at G1 and recorded as an ADR.

## A17.5 Product requirement — driver compatibility is a release gate (NEW, release-blocking)

The server's public APIs (gRPC on the pinned `typedb/typedb-protocol`, and the HTTP service) MUST remain rigorously identical: **no protocol, message, endpoint, status-code, or semantic change of any kind** is permitted by any patch in the series. Compatibility is proven, not assumed:

1. Add `typedb/typedb-driver` (the official polyglot driver monorepo) to the source graph at G0, pinned to the release matching the server pin, alongside the already-locked `typedb-protocol`.
2. The conformance programme runs the official driver integration/behaviour suites for **Rust, Python, and TypeScript/Node** — TypeScript is the project's primary client and is mandatory; Rust and Python are mandatory-minimal — against both backends (`classic` and `slatedb-r2`, profiles U1 and U3/U4), unmodified except launcher-level server pointing. The in-repo `test_http_driver_*` and behaviour targets (already in the census) are necessary but not sufficient; the external driver suites are the compatibility denominator.
3. Any driver-suite divergence between backends, or between fork and pristine upstream (U0), is a release-blocking defect regardless of which layer "caused" it.
4. Driver suites' fixture/toolchain requirements (Node, Python versions) join the pinned toolchain set; their test counts join the catalogue with the same no-false-green rules.

## A17.6 Product requirement — upstream test conformance restated as the floor

"Capable of conforming to the entire TypeDB test suite" is the minimum bar, exactly as v14–v16 specify: everything transposable runs natively under the Cargo catalogue runner; everything not directly transposable (Bazel-wired assembly archives, Console-driven scripts, docker crash orchestration) is reproduced with equivalent-or-stricter semantics via the xtask ports and pinned fixtures, each with a TestPortRecord and negative controls. The quality bar is the upstream developers' own bar; exclusions exist only as counted, owned, justified catalogue entries.

## A17.7 Final document map (what the implementing agent reads, in order)

1. `AGENTS.md` — operating instructions and environment bootstrap (start here).
2. `typedb-r2-implementation-brief-v16.md` — the architecture contract (normative).
3. This addendum — final decisions and the three product requirements above (normative, wins on conflict).
4. `typedb-r2-v16-implementation-playbook.md` — phase order J.0→ with stable patch IDs.
5. `typedb-r2-v16-source-lock-candidate.json` + `fetch-pinned-sources-v16.sh` — the source graph and its fetcher (extend per A17.5 with `typedb-driver`).
6. `typedb-r2-v14-upstream-test-catalog.schema.json` + `typedb-r2-v14-cargo-test-conformance-plan.md` — the test-denominator contract.
7. `typedb-r2-v16-cloudflare-contract-lock.json`, `typedb-r2-v16-platform-probes.md`, `typedb-r2-v16-cloudflare-source-matrix.md` — platform contract and real-account probe plan.
8. `typedb-r2-v16-review-actions.json` — 50 tracked actions with gates/owners.

Authorized programme at handoff: G0–G2 (source graph, catalogue + U0 baseline, models + probes + remote-append spike). Broader implementation unlocks phase by phase per the playbook's Done criteria, never by narrative claims.
