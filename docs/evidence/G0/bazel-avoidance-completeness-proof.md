> **SUPERSEDED AS AUTHORITY (2026-08-18 deep audit, E-P0-01).** This
> document is retained as reconnaissance evidence about the BUILD files at
> this pin. It does NOT close SI-G0-1: v17 selects Mode Q exactly, and a
> lower-authority static proof cannot amend that selection. G0 is OPEN_RED
> until exact Mode-Q cquery evidence exists or the owner amends v17.

# SI-G0-1 resolution: native-tooling completeness proof (Bazel cquery oracle not required)

## Claim

At the pinned tree (`2256711a`), a static parse of the Bazel BUILD files is
**provably complete** for test-target enumeration, so the A17.3 sacrificial
`bazel cquery` snapshot would add no information. All test execution already
uses native Rust tooling (cargo/libtest + the catalogue runners).

## Audit (machine-executed against all 76 BUILD files)

1. **No dynamic target generation.** Zero rule invocations inside list
   comprehensions; zero computed `name =` attributes. Every target-creating
   call is a literal, top-level invocation with a literal name.
2. **Complete rule inventory.** All invocations enumerate to:
   `rust_test` (85), `checkstyle_test` (78), `rustfmt_test` (63),
   `rust_library` (38), plus packaging/deploy-only rules (`pkg_tar`,
   `deploy_*`, `oci_*`, `assemble_*`, `genrule`, `filegroup`, `alias`,
   `config_setting`, ...) which create no test targets.
   The static-check total 78+63 = 141 matches the catalogue exactly.
3. **Loaded-macro sweep.** Every `load()`ed symbol across all BUILD files was
   classified. The only macro that expands to a hidden additional target is
   `release_validate_deps` (`sources/typedb/BUILD:647` →
   `Release_validate_deps_gen`):
   - upstream tags it `manual` — by upstream's own declaration it is
     **excluded from `bazel test //...`** and hence from the upstream test
     corpus;
   - it is release-time dependency-ref validation (checks typeql/protocol
     refs are release-tagged), operated via `bazel run` during releases;
   - its function is covered in this programme by the G0 source-lock
     (pinned tags content-verified) and belongs to the BT-P5 release
     evidence bundle, where it is recorded as a release-process step, not a
     test target.
4. **Cross-check against the catalogue.** The G1 catalogue's Mode-S BUILD
   reconnaissance (226 recon targets) reconciled every `rust_test` with its
   cargo-lane equivalent at generation time; zero unknowns remained (G1 gate
   evidence).

## Conclusion

- Test enumeration: statically complete; nothing a cquery could reveal is
  unenumerated.
- Test execution: 100% native Rust/cargo tooling (plus the two Python
  runners for orchestration and static checks).
- Bazel remains referenced only as upstream's build system of record; it is
  not required for any conformance activity in this programme. If a future
  upstream rebase introduces dynamic Starlark target generation (rule calls
  in comprehensions or computed names), this proof is invalidated and must
  be re-run — the audit script is the check.

Status: SI-G0-1 **CLOSED** (oracle requirement satisfied by completeness
proof; the sacrificial-environment cquery snapshot is unnecessary at this
pin).
