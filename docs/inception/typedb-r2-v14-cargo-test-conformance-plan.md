# Cargo-only TypeDB test-conformance implementation plan

## Contract

The implementation claims complete TypeDB test conformance only when the locked catalogue has zero unknown target or leaf case, every required `(leaf case, profile)` pair executed, all required fixtures were verified, and the tested server digest equals the released server digest.

## Profiles

| Profile | KV | Durability | Controller/object path | Purpose |
|---|---|---|---|---|
| U0 | pristine RocksDB | file WAL | upstream local | baseline corpus, failures, flakes, case IDs |
| U1 | RocksDB adapter | file WAL | fork local | oracle-preserving patch parity |
| U2 | SlateDB LocalFS | file WAL | local | KV semantic parity |
| U3 | SlateDB LocalFS | remote WAL | deterministic controller model | protocol/recovery/failpoint parity |
| U4 | SlateDB R2 | remote WAL | real DO/data path | production qualification |

## Required Rust commands

```text
cargo xtask catalog-upstream-tests
cargo xtask verify-cargo-manifest-parity
cargo xtask test-upstream --profile U0
cargo xtask test-upstream --profile U1
cargo xtask test-upstream --profile U2
cargo xtask test-upstream --profile U3
cargo xtask test-upstream --profile U4
cargo xtask package-upstream-test-dist
cargo xtask package-cloudflare
cargo xtask evidence
```

The root `.cargo/config.toml` defines `xtask = "run --locked --package xtask --"`. Release reproduction adds `--frozen --offline` internally.

## Runner algorithm

1. Load and schema-validate the source lock, Cargo metadata, upstream test catalogue, profile matrix, fixture lock, and exclusion ledger.
2. Invoke Cargo with the exact profile features/cfg/toolchain and JSON messages; identify every test executable.
3. Reconstruct Cargo's target runner and dynamic-library environment.
4. Discover libtest cases and composite leaf cases.
5. Reconcile discovered targets/cases with the locked denominator before running anything.
6. Create isolated sandboxes, ports, data dirs, R2 prefixes, controller namespaces, credentials, fixtures, cwd, and timeouts.
7. Run batch-safe targets or exact leaf cases; kill and reap process trees on timeout/cancellation.
8. Record raw and normalized outcome, source/config/toolchain/server/image digests, seed, duration, profile, fixture hashes, and remote namespace.
9. Reject skips, missing fixtures, zero cases, early success, retry-created PASS, or incomplete composite case reports.
10. Sign the evidence summary and verify 100% target, leaf-case, fixture, and required-pair coverage.

## Initial implementation sequence

1. U0 catalogue and baseline with no source changes.
2. Cargo authority patch and offline toolchain lock.
3. Runner/sandbox/package fixture implementation.
4. U1 parity after every safe-boundary patch.
5. Central profile injection and U2.
6. U3 deterministic remote-WAL/controller model.
7. U4 real Cloudflare qualification.

## Hard stop conditions

- unknown BUILD macro or target;
- Cargo target missing from catalogue or vice versa;
- composite harness cannot expose leaf cases;
- test requires an unpinned/unlicensed fixture;
- generic test cannot select candidate backend without semantic modification;
- release/test server digests differ;
- final run needs retry or quarantine;
- release cannot build and test offline;
- real R2/DO corpus cannot isolate parallel tests safely.
