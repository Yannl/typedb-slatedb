#!/usr/bin/env bash
# Exact, recorded build configuration for the U0/U1 parity lanes.
#
# Every setting here is part of the profile's `resolved_configuration` and MUST be
# identical across U0 and U1, otherwise the structured-equality claim of addendum A17.4(b)
# compares two different builds.
#
# Debug info is off because the full `--all-targets` DWARF build of the 43-package
# workspace exceeds this machine's writable allowance. It changes no test semantics:
# panics, assertions, backtraces and libtest case discovery are unaffected. The setting is
# recorded rather than assumed, per brief §21.7 (configuration discipline).

export RUSTUP_TOOLCHAIN=1.93.0                       # parity lane (MODULE.bazel L34, L49)
export CARGO_INCREMENTAL=0                           # reproducibility + disk
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export CARGO_PROFILE_DEV_STRIP=debuginfo
export CARGO_PROFILE_TEST_STRIP=debuginfo
export PATH=/opt/protoc/bin:$PATH                    # pinned protoc 32.1
export PROTOC=/opt/protoc/bin/protoc
