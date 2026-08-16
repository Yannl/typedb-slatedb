//! Coverage arithmetic and the gate decision.
//!
//! Brief §22.3 defines release coverage as 100% of targets, leaf cases, fixtures and
//! required profile pairs, and states plainly what does not count as a pass: "Not run
//! because Cargo did not discover it", `#[ignore]`, missing credentials, platform
//! mismatch, timeout, or dynamic skip.

use corpus_catalog::model::ProfileId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Outcome {
    Passed,
    Failed,
    /// Declared `#[ignore]` or tag-skipped. Counted, never a pass.
    Ignored,
    /// The harness reported something this runner does not understand. Never a pass.
    Unknown(String),
}

impl Outcome {
    /// How bad this outcome is, for merging duplicate reports of one leaf case.
    ///
    /// Merging must keep the worst verdict, not merely refuse to overwrite a pass. A
    /// same-run duplicate happens whenever a case is reported by more than one path — a
    /// retried target, a scenario name appearing under two harnesses — and if `Ignored`
    /// won over a later `Failed`, a real failure would be reported as a declared skip and
    /// the gate would call it a hole to be owned rather than a regression.
    pub fn severity(&self) -> u8 {
        match self {
            Outcome::Passed => 0,
            Outcome::Ignored => 1,
            Outcome::Unknown(_) => 2,
            Outcome::Failed => 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageReport {
    pub profile: ProfileId,
    pub targets_total: usize,
    pub targets_executed: usize,
    pub leaf_cases_total: usize,
    pub leaf_cases_executed: usize,
    pub passed: usize,
    pub failed: usize,
    pub ignored: usize,
    pub unknown: usize,
    /// Catalogued cases that never ran.
    pub not_executed: Vec<String>,
    /// Cases the harness reported that the catalogue does not know about — the
    /// denominator is wrong, which is a stop condition in its own right.
    pub unknown_cases: Vec<String>,
    pub timed_out_targets: Vec<String>,
    /// A target that produced no case at all is a false green in waiting.
    pub zero_case_targets: Vec<String>,
}

/// Why a profile did or did not reach the release bar.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub green: bool,
    pub reasons: Vec<String>,
    pub target_coverage: f64,
    pub leaf_case_coverage: f64,
}

impl CoverageReport {
    pub fn target_coverage(&self) -> f64 {
        if self.targets_total == 0 {
            return 0.0;
        }
        self.targets_executed as f64 / self.targets_total as f64
    }

    pub fn leaf_case_coverage(&self) -> f64 {
        if self.leaf_cases_total == 0 {
            return 0.0;
        }
        self.leaf_cases_executed as f64 / self.leaf_cases_total as f64
    }

    /// Decide the gate. Everything that is not an executed pass is named explicitly.
    pub fn verdict(&self) -> Verdict {
        let mut reasons = Vec::new();

        if self.leaf_cases_total == 0 {
            reasons.push("catalogue has zero leaf cases: an empty denominator is not a pass".into());
        }
        if self.failed > 0 {
            reasons.push(format!("{} leaf case(s) failed", self.failed));
        }
        if self.unknown > 0 {
            reasons.push(format!(
                "{} leaf case(s) reported an outcome the runner does not classify",
                self.unknown
            ));
        }
        if !self.not_executed.is_empty() {
            reasons.push(format!(
                "{} catalogued leaf case(s) never executed (first: {})",
                self.not_executed.len(),
                self.not_executed.first().map(String::as_str).unwrap_or("-")
            ));
        }
        if !self.unknown_cases.is_empty() {
            reasons.push(format!(
                "{} executed case(s) are absent from the catalogue: the denominator is wrong \
                 (first: {})",
                self.unknown_cases.len(),
                self.unknown_cases.first().map(String::as_str).unwrap_or("-")
            ));
        }
        if !self.timed_out_targets.is_empty() {
            reasons.push(format!("{} target(s) timed out", self.timed_out_targets.len()));
        }
        if !self.zero_case_targets.is_empty() {
            reasons.push(format!(
                "{} target(s) executed zero cases",
                self.zero_case_targets.len()
            ));
        }
        if self.ignored > 0 {
            // Not a failure by itself — it is a visible hole that must be owned.
            reasons.push(format!(
                "{} leaf case(s) are declared-ignored and need a catalogue exclusion entry",
                self.ignored
            ));
        }

        Verdict {
            green: reasons.is_empty(),
            reasons,
            target_coverage: self.target_coverage(),
            leaf_case_coverage: self.leaf_case_coverage(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> CoverageReport {
        CoverageReport {
            profile: ProfileId::U0,
            targets_total: 1,
            targets_executed: 1,
            leaf_cases_total: 1,
            leaf_cases_executed: 1,
            passed: 1,
            failed: 0,
            ignored: 0,
            unknown: 0,
            not_executed: vec![],
            unknown_cases: vec![],
            timed_out_targets: vec![],
            zero_case_targets: vec![],
        }
    }

    #[test]
    fn a_full_clean_run_is_green() {
        assert!(base().verdict().green);
    }

    #[test]
    fn an_empty_denominator_is_never_green() {
        let mut r = base();
        r.leaf_cases_total = 0;
        r.leaf_cases_executed = 0;
        r.passed = 0;
        assert!(!r.verdict().green);
    }

    #[test]
    fn an_unexecuted_case_is_never_green() {
        let mut r = base();
        r.not_executed = vec!["t::a".into()];
        assert!(!r.verdict().green);
    }

    #[test]
    fn a_case_outside_the_catalogue_fails_the_denominator() {
        let mut r = base();
        r.unknown_cases = vec!["t::surprise".into()];
        assert!(!r.verdict().green);
    }

    #[test]
    fn a_zero_case_target_is_never_green() {
        let mut r = base();
        r.zero_case_targets = vec!["t".into()];
        assert!(!r.verdict().green);
    }

    #[test]
    fn a_timeout_is_never_green() {
        let mut r = base();
        r.timed_out_targets = vec!["t".into()];
        assert!(!r.verdict().green);
    }

    #[test]
    fn an_unclassified_outcome_is_never_green() {
        let mut r = base();
        r.unknown = 1;
        assert!(!r.verdict().green);
    }
}
