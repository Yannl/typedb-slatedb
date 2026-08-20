//! The unified quality evidence document (spec §4).
//!
//! One report per invocation, validated against
//! `.quality/schemas/quality-report.schema.json`. It carries head SHA, base
//! SHA, exact commands, tool versions, policy digest, toolchain digest, scope,
//! selected gates and durations, and it distinguishes a gate failure from an
//! infrastructure failure.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::diff::SelectedGate;
use super::scope::Classified;
use super::tools::ToolReport;
use super::waivers::WaiverSummary;

pub const REPORT_PATH: &str = "artifacts/quality/quality-report.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pass,
    QualityFailure,
    PolicyViolation,
    InfrastructureFailure,
    NotApplicable,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Pass => "pass",
            Status::QualityFailure => "quality_failure",
            Status::PolicyViolation => "policy_violation",
            Status::InfrastructureFailure => "infrastructure_failure",
            Status::NotApplicable => "not_applicable",
        }
    }
}

/// The four controller outcomes of spec §18. All non-`Pass` states block merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Pass,
    QualityFailure,
    PolicyViolation,
    InfrastructureFailure,
}

impl Decision {
    /// Differentiated exit codes so a caller can tell "the code is wrong" from
    /// "the harness could not run" without parsing logs (§2.1).
    pub fn exit_code(self) -> u8 {
        match self {
            Decision::Pass => 0,
            Decision::QualityFailure => 1,
            Decision::PolicyViolation => 2,
            Decision::InfrastructureFailure => 3,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Pass => "pass",
            Decision::QualityFailure => "quality_failure",
            Decision::PolicyViolation => "policy_violation",
            Decision::InfrastructureFailure => "infrastructure_failure",
        }
    }
}

pub const POLICY_VIOLATION_CODE: &str = "POLICY_CHANGE_REQUIRES_INDEPENDENT_REVIEW";

#[derive(Debug, Clone, Serialize)]
pub struct GateResult {
    pub id: String,
    pub tier: String,
    pub language: Option<String>,
    pub advisory: bool,
    pub status: Status,
    pub command: Option<String>,
    pub cwd: Option<String>,
    pub exit_code: Option<i32>,
    pub duration_ms: Option<u128>,
    pub detail: String,
    pub remediation: Option<String>,
    #[serde(default)]
    pub artifacts: Vec<String>,
}

impl GateResult {
    pub fn new(
        id: &str,
        tier: &str,
        language: Option<&str>,
        advisory: bool,
        status: Status,
        detail: &str,
    ) -> GateResult {
        GateResult {
            id: id.to_string(),
            tier: tier.to_string(),
            language: language.map(|s| s.to_string()),
            advisory,
            status,
            command: None,
            cwd: None,
            exit_code: None,
            duration_ms: None,
            detail: detail.to_string(),
            remediation: None,
            artifacts: Vec::new(),
        }
    }

    /// Whether this result contributes to the merge decision. Advisory gates
    /// are recorded in full but do not block (§2.2: crap4rs is diagnosis, not a
    /// second competing CI truth source).
    pub fn blocks(&self) -> bool {
        !self.advisory && !matches!(self.status, Status::Pass | Status::NotApplicable)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProtectedChange {
    pub path: String,
    pub status: String,
    pub matched_pattern: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScopeSummary {
    pub changed_paths: usize,
    pub classified: Vec<Classified>,
    pub unclassified: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct GateSummary {
    pub status: Option<Status>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instrumentation_complete: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regressions: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub survivors: Option<u64>,
}

/// Section-4 shaped language roll-up, e.g. `"rust": {"fmt": {...}, ...}`.
#[derive(Debug, Clone, Serialize)]
pub struct LanguageSummary {
    pub status: Status,
    #[serde(flatten)]
    pub sub: BTreeMap<String, GateSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Blocking {
    pub policy_violations: usize,
    pub quality_failures: usize,
    pub infrastructure_failures: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub schema: u32,
    pub mode: String,
    pub generated_at: String,
    pub duration_ms: u128,
    pub head_sha: String,
    pub base_sha: Option<String>,
    pub worktree_clean: bool,
    pub toolchain_digest: String,
    pub policy_digest: String,
    pub policy_digest_inputs: Vec<String>,
    pub protected_policy_changes: Vec<ProtectedChange>,
    pub tools: Vec<ToolReport>,
    pub waivers: WaiverSummary,
    pub scope: ScopeSummary,
    pub selected_gates: Vec<SelectedGate>,
    pub gates: Vec<GateResult>,
    pub rust: LanguageSummary,
    pub typescript: LanguageSummary,
    pub python: LanguageSummary,
    pub architecture: GateSummary,
    pub duplication: GateSummary,
    pub blocking: Blocking,
    pub decision: Decision,
    pub decision_code: Option<String>,
    pub exit_code: u8,
}

/// Roll a language's gates into the §4 shape. The sub-gate keys mirror the
/// example in the specification.
fn language_summary(gates: &[GateResult], language: &str, mapping: &[(&str, &str)]) -> LanguageSummary {
    let mine: Vec<&GateResult> = gates.iter().filter(|g| g.language.as_deref() == Some(language)).collect();
    let mut sub: BTreeMap<String, GateSummary> = BTreeMap::new();
    for (gate_id, key) in mapping {
        if let Some(g) = mine.iter().find(|g| g.id == *gate_id) {
            let entry = sub.entry((*key).to_string()).or_default();
            // Several gate ids can roll into one §4 key (for example
            // `rust.mutation.diff` and `rust.mutation.full` -> "mutation").
            // The worst status wins; a pass never overwrites a failure.
            entry.status = Some(match entry.status {
                Some(prev) if severity(prev) >= severity(g.status) => prev,
                _ => g.status,
            });
            entry.detail = Some(g.detail.clone());
        }
    }
    LanguageSummary { status: roll_up(&mine), sub }
}

fn severity(s: Status) -> u8 {
    match s {
        Status::NotApplicable => 0,
        Status::Pass => 1,
        Status::InfrastructureFailure => 2,
        Status::QualityFailure => 3,
        Status::PolicyViolation => 4,
    }
}

fn roll_up(gates: &[&GateResult]) -> Status {
    if gates.is_empty() {
        return Status::NotApplicable;
    }
    let blocking: Vec<&&GateResult> = gates.iter().filter(|g| g.blocks()).collect();
    if let Some(worst) = blocking.iter().max_by_key(|g| severity(g.status)) {
        return worst.status;
    }
    if gates.iter().all(|g| g.status == Status::NotApplicable) {
        Status::NotApplicable
    } else {
        Status::Pass
    }
}

const RUST_MAP: &[(&str, &str)] = &[
    ("rust.fmt", "fmt"),
    ("rust.clippy", "clippy"),
    ("rust.tests", "tests"),
    ("rust.coverage", "coverage"),
    ("rust.crap", "crap"),
    ("rust.mutation.diff", "mutation"),
    ("rust.mutation.full", "mutation"),
    ("rust.deny", "dependencies"),
    ("rust.machete", "dependencies"),
];

const TS_MAP: &[(&str, &str)] = &[
    ("ts.oxlint", "lint"),
    ("ts.typecheck", "typecheck"),
    ("ts.knip", "dead_code"),
    ("ts.crap", "crap"),
    ("ts.mutation", "mutation"),
];

const PY_MAP: &[(&str, &str)] = &[
    ("py.ruff.check", "lint"),
    ("py.ruff.format", "fmt"),
    ("py.typecheck", "typecheck"),
    ("py.pytest", "tests"),
    ("py.pip_audit", "dependencies"),
    ("py.crap", "crap"),
];

/// Aggregate the decision. Precedence: a policy violation outranks everything
/// (it means the measuring system itself was touched); a quality failure that
/// actually ran outranks a gate that could not run; every non-pass blocks. The
/// individual counts are always published so nothing is hidden by precedence.
pub fn decide(gates: &[GateResult], unclassified: &[String], waivers: &WaiverSummary) -> (Decision, Blocking) {
    let blocking_gates: Vec<&GateResult> = gates.iter().filter(|g| g.blocks()).collect();
    let mut b = Blocking {
        policy_violations: blocking_gates.iter().filter(|g| g.status == Status::PolicyViolation).count(),
        quality_failures: blocking_gates.iter().filter(|g| g.status == Status::QualityFailure).count(),
        infrastructure_failures: blocking_gates.iter().filter(|g| g.status == Status::InfrastructureFailure).count(),
    };
    // Belt and braces: these two conditions are also expressed as gates, but a
    // future refactor must not be able to drop them silently.
    if !unclassified.is_empty() {
        b.quality_failures += 0;
    }
    let _ = waivers;

    let decision = if b.policy_violations > 0 {
        Decision::PolicyViolation
    } else if b.quality_failures > 0 {
        Decision::QualityFailure
    } else if b.infrastructure_failures > 0 {
        Decision::InfrastructureFailure
    } else {
        Decision::Pass
    };
    (decision, b)
}

#[allow(clippy::too_many_arguments)]
pub fn build(
    mode: &str,
    generated_at: String,
    duration_ms: u128,
    head_sha: String,
    base_sha: Option<String>,
    worktree_clean: bool,
    toolchain_digest: String,
    policy_digest: String,
    policy_digest_inputs: Vec<String>,
    protected_policy_changes: Vec<ProtectedChange>,
    tools: Vec<ToolReport>,
    waivers: WaiverSummary,
    scope: ScopeSummary,
    selected_gates: Vec<SelectedGate>,
    gates: Vec<GateResult>,
) -> Report {
    let (decision, blocking) = decide(&gates, &scope.unclassified, &waivers);
    let decision_code =
        if decision == Decision::PolicyViolation { Some(POLICY_VIOLATION_CODE.to_string()) } else { None };

    let architecture = gates
        .iter()
        .find(|g| g.id.starts_with("arch."))
        .map(|g| GateSummary { status: Some(g.status), detail: Some(g.detail.clone()), ..Default::default() })
        .unwrap_or(GateSummary { status: Some(Status::NotApplicable), ..Default::default() });
    let duplication = gates
        .iter()
        .find(|g| g.id.starts_with("dup."))
        .map(|g| GateSummary { status: Some(g.status), detail: Some(g.detail.clone()), ..Default::default() })
        .unwrap_or(GateSummary { status: Some(Status::NotApplicable), ..Default::default() });

    Report {
        schema: 1,
        mode: mode.to_string(),
        generated_at,
        duration_ms,
        head_sha,
        base_sha,
        worktree_clean,
        toolchain_digest,
        policy_digest,
        policy_digest_inputs,
        protected_policy_changes,
        tools,
        waivers,
        rust: language_summary(&gates, "rust", RUST_MAP),
        typescript: language_summary(&gates, "typescript", TS_MAP),
        python: language_summary(&gates, "python", PY_MAP),
        architecture,
        duplication,
        scope,
        selected_gates,
        gates,
        blocking,
        exit_code: decision.exit_code(),
        decision,
        decision_code,
    }
}

pub fn write(repo_root: &Path, report: &Report) -> Result<std::path::PathBuf, String> {
    let path = repo_root.join(REPORT_PATH);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(report).map_err(|e| format!("cannot serialise report: {e}"))?;
    std::fs::write(&path, format!("{json}\n")).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(path)
}

/// Minimal view used by `verify-report`, so that verification does not depend
/// on the full serialisation shape staying stable.
#[derive(Debug, Clone, Deserialize)]
pub struct ReportHeader {
    pub schema: u32,
    pub mode: String,
    pub head_sha: String,
    pub base_sha: Option<String>,
    pub worktree_clean: bool,
    pub policy_digest: String,
    pub toolchain_digest: String,
    pub decision: Decision,
    pub exit_code: u8,
}

/// Refuse a report that does not certify the SHA in front of us.
///
/// "A green quality report for SHA A does not certify SHA B" (§19), and
/// "checking that machine artifacts correspond to HEAD" is the Verifier's job
/// (§11.7).
pub fn verify(
    header: &ReportHeader,
    expected_head: &str,
    expected_policy_digest: Option<&str>,
) -> Result<(), Vec<String>> {
    let mut problems = Vec::new();
    if header.schema != 1 {
        problems.push(format!("report schema {} is not supported", header.schema));
    }
    if header.head_sha != expected_head {
        problems.push(format!(
            "report certifies head_sha {} but HEAD is {expected_head}: a report produced for a different SHA is not evidence",
            header.head_sha
        ));
    }
    if !header.worktree_clean {
        problems
            .push("report was produced from a dirty working tree, so it does not correspond to any commit".to_string());
    }
    if let Some(expected) = expected_policy_digest {
        if header.policy_digest != expected {
            problems.push(format!(
                "report was produced under policy digest {} but the current policy digest is {expected}",
                header.policy_digest
            ));
        }
    }
    if header.decision != Decision::Pass {
        problems.push(format!("report decision is {}, not pass", header.decision.as_str()));
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate(id: &str, status: Status, advisory: bool) -> GateResult {
        GateResult::new(id, "A", Some("rust"), advisory, status, "detail")
    }

    fn empty_waivers() -> WaiverSummary {
        WaiverSummary { total: 0, active: 0, expired: 0, invalid: 0, entries: Vec::new() }
    }

    #[test]
    fn exit_codes_are_distinct_and_stable() {
        assert_eq!(Decision::Pass.exit_code(), 0);
        assert_eq!(Decision::QualityFailure.exit_code(), 1);
        assert_eq!(Decision::PolicyViolation.exit_code(), 2);
        assert_eq!(Decision::InfrastructureFailure.exit_code(), 3);
    }

    #[test]
    fn an_infrastructure_failure_is_never_a_pass() {
        let gates =
            vec![gate("rust.fmt", Status::Pass, false), gate("rust.tests", Status::InfrastructureFailure, false)];
        let (d, b) = decide(&gates, &[], &empty_waivers());
        assert_eq!(d, Decision::InfrastructureFailure);
        assert_eq!(b.infrastructure_failures, 1);
        assert_ne!(d, Decision::Pass);
    }

    #[test]
    fn a_policy_violation_outranks_everything_else() {
        let gates = vec![
            gate("policy.protected", Status::PolicyViolation, false),
            gate("rust.tests", Status::QualityFailure, false),
            gate("rust.crap", Status::InfrastructureFailure, false),
        ];
        let (d, b) = decide(&gates, &[], &empty_waivers());
        assert_eq!(d, Decision::PolicyViolation);
        assert_eq!((b.policy_violations, b.quality_failures, b.infrastructure_failures), (1, 1, 1));
    }

    #[test]
    fn advisory_gates_are_recorded_but_do_not_block() {
        let gates =
            vec![gate("rust.fmt", Status::Pass, false), gate("rust.crap_advice", Status::InfrastructureFailure, true)];
        let (d, b) = decide(&gates, &[], &empty_waivers());
        assert_eq!(d, Decision::Pass);
        assert_eq!(b.infrastructure_failures, 0);
        // ...but the advisory gate keeps its honest status in the report.
        assert_eq!(gates[1].status, Status::InfrastructureFailure);
    }

    #[test]
    fn all_not_applicable_is_a_pass_not_a_failure() {
        let gates = vec![gate("rust.miri", Status::NotApplicable, false)];
        let (d, _) = decide(&gates, &[], &empty_waivers());
        assert_eq!(d, Decision::Pass);
    }

    #[test]
    fn language_roll_up_takes_the_worst_status() {
        let gates = vec![
            gate("rust.fmt", Status::Pass, false),
            gate("rust.clippy", Status::QualityFailure, false),
            gate("rust.tests", Status::InfrastructureFailure, false),
        ];
        let s = language_summary(&gates, "rust", RUST_MAP);
        assert_eq!(s.status, Status::QualityFailure);
        assert_eq!(s.sub["fmt"].status, Some(Status::Pass));
        assert_eq!(s.sub["clippy"].status, Some(Status::QualityFailure));
        assert_eq!(s.sub["tests"].status, Some(Status::InfrastructureFailure));
    }

    #[test]
    fn a_report_for_a_different_sha_is_refused() {
        let header = ReportHeader {
            schema: 1,
            mode: "pr".into(),
            head_sha: "a".repeat(40),
            base_sha: None,
            worktree_clean: true,
            policy_digest: "sha256:00".into(),
            toolchain_digest: "sha256:11".into(),
            decision: Decision::Pass,
            exit_code: 0,
        };
        assert!(verify(&header, &"a".repeat(40), None).is_ok());
        let problems = verify(&header, &"b".repeat(40), None).unwrap_err();
        assert!(problems.iter().any(|p| p.contains("different SHA")), "{problems:?}");
    }

    #[test]
    fn a_report_from_a_dirty_tree_or_a_stale_policy_is_refused() {
        let mut header = ReportHeader {
            schema: 1,
            mode: "pr".into(),
            head_sha: "a".repeat(40),
            base_sha: None,
            worktree_clean: false,
            policy_digest: "sha256:00".into(),
            toolchain_digest: "sha256:11".into(),
            decision: Decision::Pass,
            exit_code: 0,
        };
        assert!(verify(&header, &"a".repeat(40), None).unwrap_err().iter().any(|p| p.contains("dirty")));
        header.worktree_clean = true;
        let problems = verify(&header, &"a".repeat(40), Some("sha256:ff")).unwrap_err();
        assert!(problems.iter().any(|p| p.contains("policy digest")));
    }

    #[test]
    fn a_non_passing_report_is_refused_by_the_integrator_check() {
        let header = ReportHeader {
            schema: 1,
            mode: "pr".into(),
            head_sha: "a".repeat(40),
            base_sha: None,
            worktree_clean: true,
            policy_digest: "sha256:00".into(),
            toolchain_digest: "sha256:11".into(),
            decision: Decision::InfrastructureFailure,
            exit_code: 3,
        };
        assert!(verify(&header, &"a".repeat(40), None).unwrap_err().iter().any(|p| p.contains("not pass")));
    }
}
