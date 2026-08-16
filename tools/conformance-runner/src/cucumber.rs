//! Per-scenario attribution for Cucumber targets.
//!
//! Brief §22.2 is explicit that "a composite Rust test that loops over many scenarios
//! counts each scenario/failpoint as a leaf case, not as one opaque green case", and the
//! conformance plan makes "composite harness cannot expose leaf cases" a hard stop. A
//! behaviour target is one libtest case covering hundreds of scenarios, so taking its exit
//! status as the verdict for all of them is exactly the false green the contract forbids.
//!
//! Output shape, observed from a real `test_connection` run at TB `2256711a` against
//! cucumber `0.19.1` (workspace dependency, root `Cargo.toml` L419-422):
//!
//! ```text
//! Feature: Connection Database :: create one database with name ALICE
//!   Scenario Outline: create one database with name ALICE
//!    ✔> Given typedb starts
//!    ✔  Given connection create database: typedb
//! [Summary]
//! 43 features
//! 43 scenarios (43 passed)
//! 443 steps (443 passed)
//! ```
//!
//! Step glyphs come from `writer/basic.rs`: `✔`/`✔>` passed, `✘`/`✘>` failed (L566, L669,
//! L844, L947), `?`/`?>` skipped (L609, L887). Upstream sets `.fail_on_skipped()`
//! (`tests/behaviour/steps/lib.rs` L180), so a skipped step is a failure, not a pass.

use std::collections::BTreeMap;

use corpus_catalog::model::{Catalog, Target};

use crate::{CaseResult, Outcome};

/// One scenario as the harness reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedScenario {
    pub name: String,
    pub outcome: Outcome,
}

const SCENARIO_KEYWORDS: [&str; 4] =
    ["Scenario Outline:", "Scenario Template:", "Scenario:", "Example:"];

/// Read the ordered scenario results out of a cucumber run's stdout.
pub fn parse(stdout: &str) -> Vec<ObservedScenario> {
    let mut out: Vec<ObservedScenario> = Vec::new();
    for raw in stdout.lines() {
        let line = raw.trim();
        if line.starts_with("[Summary]") {
            continue;
        }
        if let Some(kw) = SCENARIO_KEYWORDS.iter().find(|kw| line.starts_with(**kw)) {
            out.push(ObservedScenario {
                name: line[kw.len()..].trim().to_string(),
                // A scenario is a pass only if nothing below it says otherwise.
                outcome: Outcome::Passed,
            });
            continue;
        }
        // Step results belong to the most recent scenario.
        let Some(current) = out.last_mut() else { continue };
        let failed = line.starts_with('✘');
        let skipped = line.starts_with('?') && !line.starts_with("??");
        if failed {
            current.outcome = Outcome::Failed;
        } else if skipped && current.outcome == Outcome::Passed {
            // `.fail_on_skipped()` turns a skip into a failure upstream.
            current.outcome = Outcome::Failed;
        }
    }
    out
}

/// Scenario totals declared by the `[Summary]` block(s), summed across libtest cases.
///
/// Used as an independent check on the line parser: if the two disagree, the attribution
/// is wrong and must not be trusted.
pub fn summary_scenario_total(stdout: &str) -> Option<usize> {
    let mut total = 0usize;
    let mut seen = false;
    for line in stdout.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_suffix(')') else { continue };
        let Some((counts, _)) = rest.split_once(" (") else { continue };
        let Some(n) = counts.strip_suffix(" scenarios").or_else(|| counts.strip_suffix(" scenario"))
        else {
            continue;
        };
        let Ok(n) = n.trim().parse::<usize>() else { continue };
        total += n;
        seen = true;
    }
    seen.then_some(total)
}

/// Map observed scenarios onto the catalogued leaf cases for this target.
///
/// Names can repeat (an outline whose placeholders do not appear in its name expands to
/// several identically named scenarios), so matching is by name with an occurrence
/// counter, in catalogue order. Anything that cannot be matched is surfaced as an unknown
/// case rather than dropped, which fails the denominator check downstream.
pub fn attribute(
    target: &Target,
    catalog: &Catalog,
    stdout: &str,
    exit_code: Option<i32>,
    timed_out: bool,
) -> Vec<CaseResult> {
    let observed = parse(stdout);

    // Catalogued cases for this target, grouped by display name, in stable id order.
    let mut by_name: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for case in catalog.leaf_cases.iter().filter(|c| c.target_id == target.target_id) {
        let name = case.display_name.as_deref().unwrap_or(&case.leaf_case_id);
        by_name.entry(name).or_default().push(&case.leaf_case_id);
    }
    let mut used: BTreeMap<&str, usize> = BTreeMap::new();

    let mut results = Vec::with_capacity(observed.len());
    for scenario in &observed {
        let idx = used.entry(scenario.name.as_str()).or_insert(0);
        let matched = by_name
            .get(scenario.name.as_str())
            .and_then(|ids| ids.get(*idx))
            .copied();
        *idx += 1;

        match matched {
            Some(id) => results.push(CaseResult {
                leaf_case_id: id.to_string(),
                outcome: scenario.outcome.clone(),
                duration_ms: None,
                detail: None,
            }),
            // Reported but not catalogued: keep it, under an id the catalogue does not
            // contain, so `summarise` counts it as an unknown case and the gate goes red.
            None => results.push(CaseResult {
                leaf_case_id: format!("{}::<uncatalogued>::{}", target.target_id, scenario.name),
                outcome: scenario.outcome.clone(),
                duration_ms: None,
                detail: Some("scenario reported by the harness but absent from the catalogue".into()),
            }),
        }
    }

    // Scenarios the harness filtered out never appear in its output at all — cucumber's
    // `.filter_run` predicate drops them before reporting. A catalogued case that is
    // declared-ignored and went unreported is therefore accounted for: it is `Ignored`,
    // which §22.3 counts and never treats as a pass. Leaving it unreported would put it in
    // `not_executed` alongside genuine holes, which is where 29 of the 34 remaining entries
    // came from — and it would make a declared skip indistinguishable from a scenario that
    // silently failed to run.
    let reported: BTreeMap<&str, ()> =
        results.iter().map(|r| (r.leaf_case_id.as_str(), ())).collect();
    let mut skipped: Vec<CaseResult> = catalog
        .leaf_cases
        .iter()
        .filter(|c| c.target_id == target.target_id)
        .filter(|c| c.declared_ignored && !reported.contains_key(c.leaf_case_id.as_str()))
        .map(|c| CaseResult {
            leaf_case_id: c.leaf_case_id.clone(),
            outcome: Outcome::Ignored,
            duration_ms: None,
            detail: Some("filtered out by the harness's ignore-tag predicate".into()),
        })
        .collect();
    results.append(&mut skipped);

    // Independent cross-check. A mismatch means the parser missed scenarios, so no result
    // from this target may stand as a pass.
    let declared = summary_scenario_total(stdout);
    let parser_disagrees = declared.is_some_and(|d| d != observed.len());
    let process_failed = timed_out || exit_code != Some(0);

    if parser_disagrees || (process_failed && results.iter().all(|r| r.outcome == Outcome::Passed)) {
        let reason = if parser_disagrees {
            format!(
                "cucumber summary declares {} scenario(s) but {} were parsed",
                declared.unwrap_or_default(),
                observed.len()
            )
        } else {
            format!("harness exited {exit_code:?} (timed_out={timed_out}) with no failing scenario")
        };
        for r in &mut results {
            // A declared skip is already fully explained; downgrading it to Unknown would
            // turn a known, catalogued exclusion into an unexplained one.
            if r.outcome == Outcome::Ignored {
                continue;
            }
            r.outcome = Outcome::Unknown(reason.clone());
            r.detail = Some(reason.clone());
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUN: &str = "\
Feature: Connection Database :: create one database
  Scenario Outline: create one database
   ✔> Given typedb starts
   ✔  Given connection create database: typedb
Feature: Connection Database :: delete a database
  Scenario: delete a database
   ✔> Given typedb starts
   ✘  Then connection has 0 databases
[Summary]
2 features
2 scenarios (1 passed, 1 failed)
4 steps (3 passed, 1 failed)
";

    #[test]
    fn attributes_each_scenario_separately() {
        let s = parse(RUN);
        assert_eq!(s.len(), 2, "two scenarios, not one opaque case");
        assert_eq!(s[0].outcome, Outcome::Passed);
        assert_eq!(s[1].outcome, Outcome::Failed);
    }

    #[test]
    fn a_skipped_step_fails_the_scenario() {
        // Upstream sets `.fail_on_skipped()`, so a skip is not a pass.
        let s = parse("  Scenario: x\n   ?  Given nothing\n");
        assert_eq!(s[0].outcome, Outcome::Failed);
    }

    #[test]
    fn reads_the_summary_total_independently() {
        assert_eq!(summary_scenario_total(RUN), Some(2));
        assert_eq!(summary_scenario_total("43 scenarios (43 passed)"), Some(43));
        assert_eq!(summary_scenario_total("no summary here"), None);
    }

    #[test]
    fn sums_summaries_across_libtest_cases() {
        // A behaviour target runs several `#[tokio::test]` cases, each with its own block.
        let two = "16 scenarios (16 passed)\n43 scenarios (43 passed)\n";
        assert_eq!(summary_scenario_total(two), Some(59));
    }

    #[test]
    fn ignores_step_text_that_looks_like_a_keyword() {
        // A step body mentioning "Scenario:" must not open a new scenario.
        let s = parse("  Scenario: real\n   ✔  Given a step about Scenario: fake\n");
        assert_eq!(s.len(), 1);
    }
}
