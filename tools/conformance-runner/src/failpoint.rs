//! Attribution for the failpoint harness.
//!
//! `tests/assembly/fail_points.rs` at TB `2256711a` exposes two libtest cases,
//! `test_fail_point_always` (L91) and `test_fail_point_chance` (L120), each of which loops
//! over the whole `fail_point::ALL` registry (L95, L126). The registry has 22 members, so
//! the denominator is 44 leaf cases — but the harness prints nothing per member on success.
//!
//! The attribution rule is therefore deliberately conservative, because the one thing that
//! must never happen is a member being recorded as passed when it did not run:
//!
//! * the libtest case passed  -> every member in that loop ran and passed. The loop body is
//!   unconditional and any failure panics (`panic!("Fail point {fail_point} is never
//!   triggered")` L108, `assert_boots(fail_point)` L118), so reaching the end means all 22
//!   completed.
//! * the libtest case failed  -> every member in that loop is recorded as failed, including
//!   the ones that had already passed before the panic. This under-reports success and
//!   never over-reports it.
//! * the libtest case did not run -> no result at all, so the members show as
//!   not-executed and the gate stays red.
//!
//! When the panic message names a member, it is attached as detail so the failing one is
//! identifiable without re-reading the raw log.

use corpus_catalog::model::{Catalog, Target};

use crate::{CaseResult, Outcome};

/// Extract the `<loop_context>` -> pass/fail map from libtest's own result lines.
fn loop_outcomes(stdout: &str) -> Vec<(String, Outcome)> {
    crate::parse_libtest_results("", stdout)
        .unwrap_or_default()
        .into_iter()
        .map(|c| (c.leaf_case_id.trim_start_matches("::").to_string(), c.outcome))
        .collect()
}

/// The failpoint named in a panic message, if the harness identified one.
fn failing_member(stdout: &str) -> Option<String> {
    stdout.lines().find_map(|line| {
        let line = line.trim();
        let rest = line.strip_prefix("Fail point ")?;
        let name = rest.split_whitespace().next()?;
        name.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
            .then(|| name.to_string())
    })
}

pub fn attribute(
    target: &Target,
    catalog: &Catalog,
    stdout: &str,
    exit_code: Option<i32>,
    timed_out: bool,
) -> Vec<CaseResult> {
    let outcomes = loop_outcomes(stdout);
    let named = failing_member(stdout);

    catalog
        .leaf_cases
        .iter()
        .filter(|c| c.target_id == target.target_id)
        .filter_map(|case| {
            // Leaf ids are `<target>::<loop_context>::<FAIL_POINT>`.
            let tail = case.leaf_case_id.strip_prefix(&format!("{}::", target.target_id))?;
            let (loop_context, member) = tail.split_once("::")?;

            let outcome = outcomes
                .iter()
                .find(|(name, _)| name == loop_context)
                .map(|(_, o)| o.clone())?;

            let outcome = match outcome {
                Outcome::Passed if timed_out || exit_code != Some(0) => {
                    Outcome::Unknown("harness reported ok but the process did not exit cleanly".into())
                }
                other => other,
            };

            Some(CaseResult {
                leaf_case_id: case.leaf_case_id.clone(),
                outcome,
                duration_ms: None,
                detail: named
                    .as_deref()
                    .filter(|n| *n == member)
                    .map(|n| format!("harness named {n} in its failure message")),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use corpus_catalog::model::*;

    fn catalog_with(target_id: &str, ids: &[&str]) -> Catalog {
        Catalog {
            schema_version: 1,
            source_lock_digest: "0".repeat(64),
            rust_toolchain: RustToolchain {
                rustc: "x".into(),
                cargo: "x".into(),
                native_toolchain_digest: None,
            },
            target_triple: "x86_64-unknown-linux-gnu".into(),
            bazel_query_oracle: None,
            profiles: default_profiles(),
            targets: vec![],
            leaf_cases: ids
                .iter()
                .map(|id| LeafCase {
                    leaf_case_id: format!("{target_id}::{id}"),
                    target_id: target_id.into(),
                    kind: LeafKind::Failpoint,
                    display_name: None,
                    source_hash: "0".repeat(64),
                    declared_ignored: false,
                    resource_group: None,
                })
                .collect(),
            required_pairs: vec![],
            fixtures: vec![],
            exclusions: vec![],
        }
    }

    fn target(id: &str) -> Target {
        Target {
            target_id: id.into(),
            origin: Origin::Cargo,
            upstream_label: None,
            cargo_package: Some("p".into()),
            cargo_target: Some("test_fail_points".into()),
            source_files: vec![],
            case_discovery: CaseDiscovery::FailpointRegistry,
            platform_predicate: "linux-x86_64".into(),
            features: vec![],
            cfg: vec![],
            env: Default::default(),
            fixture_ids: vec![],
            working_directory: None,
            timeout_seconds: 60,
            serial_group: None,
            port_status: PortStatus::LauncherAdapted,
        }
    }

    #[test]
    fn a_passing_loop_credits_every_member() {
        let c = catalog_with("t", &["test_fail_point_always::A", "test_fail_point_always::B"]);
        let r = attribute(&target("t"), &c, "test test_fail_point_always ... ok\n", Some(0), false);
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|x| x.outcome == Outcome::Passed));
    }

    #[test]
    fn a_failing_loop_credits_no_member() {
        let c = catalog_with("t", &["test_fail_point_always::A", "test_fail_point_always::B"]);
        let r = attribute(
            &target("t"),
            &c,
            "Fail point WAL_RECORD_UNFLUSHED is never triggered\ntest test_fail_point_always ... FAILED\n",
            Some(101),
            false,
        );
        assert_eq!(r.len(), 2);
        assert!(
            r.iter().all(|x| x.outcome == Outcome::Failed),
            "members before the panic must not be credited"
        );
    }

    #[test]
    fn a_loop_that_never_ran_produces_no_result() {
        let c = catalog_with("t", &["test_fail_point_chance::A"]);
        let r = attribute(&target("t"), &c, "test test_fail_point_always ... ok\n", Some(0), false);
        assert!(r.is_empty(), "an unrun loop must show as not-executed, not as a pass");
    }

    #[test]
    fn an_ok_line_with_a_dirty_exit_is_not_a_pass() {
        let c = catalog_with("t", &["test_fail_point_always::A"]);
        let r = attribute(&target("t"), &c, "test test_fail_point_always ... ok\n", Some(101), false);
        assert!(matches!(r[0].outcome, Outcome::Unknown(_)));
    }

    #[test]
    fn names_the_failing_member_when_the_harness_does() {
        assert_eq!(
            failing_member("Fail point WAL_RECORD_UNFLUSHED is never triggered"),
            Some("WAL_RECORD_UNFLUSHED".into())
        );
        assert_eq!(failing_member("nothing here"), None);
    }
}
