//! Pinned tool presence and version detection (`.quality/tools.lock.toml`).
//!
//! The rule this module exists to enforce: a missing tool or a version
//! mismatch yields `InfrastructureFailure` carrying the exact remediation
//! command. It is never a silent skip and it is never a pass. An uninstalled
//! mutation tester must not be able to produce a green report.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::exec::{self, Cmd};

#[derive(Debug, Clone, Deserialize)]
pub struct ToolsLock {
    pub schema: u32,
    #[serde(default)]
    pub resolved_on: String,
    #[serde(default)]
    pub toolchain: BTreeMap<String, ToolSpec>,
    #[serde(default)]
    pub tool: BTreeMap<String, ToolSpec>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ToolSpec {
    pub version: String,
    pub mode: MatchMode,
    pub detect: Vec<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    pub remediation: String,
    #[serde(default)]
    pub advisory: bool,
    #[serde(default)]
    pub conditional: bool,
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchMode {
    Exact,
    Minimum,
    Presence,
}

impl MatchMode {
    pub fn as_str(self) -> &'static str {
        match self {
            MatchMode::Exact => "exact",
            MatchMode::Minimum => "minimum",
            MatchMode::Presence => "presence",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolStatus {
    Ok,
    Absent,
    VersionMismatch,
    DetectionFailed,
}

impl ToolStatus {
    pub fn is_ok(self) -> bool {
        self == ToolStatus::Ok
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolReport {
    pub name: String,
    pub expected_version: String,
    pub detected_version: Option<String>,
    pub mode: MatchMode,
    pub status: ToolStatus,
    pub advisory: bool,
    pub conditional: bool,
    pub remediation: String,
    pub detect_command: String,
}

impl ToolReport {
    /// One-line explanation suitable for a gate `detail` field.
    pub fn problem(&self) -> String {
        match self.status {
            ToolStatus::Ok => format!("{} {} present", self.name, self.detected_version.clone().unwrap_or_default()),
            ToolStatus::Absent => format!("tool `{}` is not installed", self.name),
            ToolStatus::VersionMismatch => format!(
                "tool `{}` is pinned to {} but {} is installed",
                self.name,
                self.expected_version,
                self.detected_version.clone().unwrap_or_else(|| "?".into())
            ),
            ToolStatus::DetectionFailed => {
                format!("tool `{}` is present but its version could not be parsed", self.name)
            }
        }
    }
}

impl ToolsLock {
    pub fn parse(text: &str) -> Result<ToolsLock, String> {
        let lock: ToolsLock = toml::from_str(text).map_err(|e| format!("tools.lock.toml: {e}"))?;
        if lock.schema != 1 {
            return Err(format!("tools.lock.toml: unsupported schema {}", lock.schema));
        }
        Ok(lock)
    }

    pub fn load(repo_root: &Path) -> Result<ToolsLock, String> {
        let path = repo_root.join(super::policy::TOOLS_LOCK_PATH);
        let text = std::fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        ToolsLock::parse(&text)
    }

    /// Every entry, toolchain first, as (name, spec).
    pub fn all(&self) -> Vec<(&String, &ToolSpec)> {
        self.toolchain.iter().chain(self.tool.iter()).collect()
    }

    pub fn get(&self, name: &str) -> Option<&ToolSpec> {
        self.toolchain.get(name).or_else(|| self.tool.get(name))
    }
}

/// Extract the first version-looking token from a `--version` banner.
///
/// Handles `rustc 1.94.1 (e408947bf 2026-03-25)`, `v22.22.2`,
/// `cargo-nextest-cargo-nextest 0.9.143`, `ruff 0.15.8` and
/// `Python 3.11.15`. Returns `None` when nothing version-shaped is present,
/// which is reported as `DetectionFailed` rather than assumed to be fine.
pub fn extract_version(text: &str) -> Option<String> {
    for token in text.split(|c: char| c.is_whitespace() || c == '(' || c == ')' || c == ',') {
        let t = token.trim().trim_start_matches('v');
        let core: String = t.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
        if core.is_empty() || !core.contains('.') {
            continue;
        }
        let parts: Vec<&str> = core.trim_end_matches('.').split('.').collect();
        if parts.len() >= 2 && parts.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())) {
            return Some(parts.join("."));
        }
    }
    None
}

fn semver_parts(v: &str) -> Vec<u64> {
    v.split('.').map(|p| p.parse::<u64>().unwrap_or(0)).collect()
}

/// `a >= b` under numeric component ordering.
pub fn version_at_least(a: &str, b: &str) -> bool {
    let (av, bv) = (semver_parts(a), semver_parts(b));
    let n = av.len().max(bv.len());
    for i in 0..n {
        let x = av.get(i).copied().unwrap_or(0);
        let y = bv.get(i).copied().unwrap_or(0);
        if x != y {
            return x > y;
        }
    }
    true
}

pub fn evaluate(name: &str, spec: &ToolSpec, detected: Option<&str>) -> ToolStatus {
    let Some(detected) = detected else {
        return ToolStatus::Absent;
    };
    let _ = name;
    match spec.mode {
        MatchMode::Presence => ToolStatus::Ok,
        MatchMode::Exact => {
            if detected == spec.version {
                ToolStatus::Ok
            } else {
                ToolStatus::VersionMismatch
            }
        }
        MatchMode::Minimum => {
            if version_at_least(detected, &spec.version) {
                ToolStatus::Ok
            } else {
                ToolStatus::VersionMismatch
            }
        }
    }
}

/// Detect one tool by running its pinned `detect` command.
pub fn detect(repo_root: &Path, name: &str, spec: &ToolSpec) -> ToolReport {
    let program = spec.detect.first().cloned().unwrap_or_default();
    let args: Vec<&str> = spec.detect.iter().skip(1).map(|s| s.as_str()).collect();
    let mut cmd = Cmd::new(&program, &args);
    if let Some(cwd) = &spec.cwd {
        cmd = cmd.in_dir(cwd);
    }
    let detect_command = cmd.display();
    let result = exec::run(repo_root, &cmd, Duration::from_secs(120));

    let (detected, status) = if result.spawn_error.is_some() || !result.success() {
        (None, ToolStatus::Absent)
    } else {
        let banner = format!("{}\n{}", result.stdout, result.stderr);
        match extract_version(&banner) {
            Some(v) => {
                let st = evaluate(name, spec, Some(&v));
                (Some(v), st)
            }
            None => (None, ToolStatus::DetectionFailed),
        }
    };

    ToolReport {
        name: name.to_string(),
        expected_version: spec.version.clone(),
        detected_version: detected,
        mode: spec.mode,
        status,
        advisory: spec.advisory,
        conditional: spec.conditional,
        remediation: spec.remediation.clone(),
        detect_command,
    }
}

/// Detect everything in the lock file once; gates then look results up.
#[derive(Debug, Clone)]
pub struct Registry {
    pub reports: Vec<ToolReport>,
}

impl Registry {
    pub fn detect_all(repo_root: &Path, lock: &ToolsLock) -> Registry {
        let reports = lock.all().into_iter().map(|(name, spec)| detect(repo_root, name, spec)).collect();
        Registry { reports }
    }

    pub fn get(&self, name: &str) -> Option<&ToolReport> {
        self.reports.iter().find(|r| r.name == name)
    }

    /// The first unusable tool among `required`, if any.
    pub fn first_problem(&self, required: &[&str]) -> Option<&ToolReport> {
        required.iter().find_map(|name| match self.get(name) {
            Some(r) if !r.status.is_ok() => Some(r),
            Some(_) => None,
            // A gate naming a tool that the lock file does not pin is itself a
            // configuration defect, surfaced through the same channel.
            None => None,
        })
    }

    /// Gate requirement naming a tool absent from the lock file at all.
    pub fn unpinned(&self, required: &[&str]) -> Option<String> {
        required.iter().find(|n| self.get(n).is_none()).map(|n| (*n).to_string())
    }

    /// Input to the toolchain digest: every pinned tool and what was actually
    /// found, so that a report cannot be reused across differing toolchains.
    pub fn digest_pairs(&self) -> Vec<(String, Vec<u8>)> {
        self.reports
            .iter()
            .map(|r| {
                let value = format!(
                    "expected={} mode={} detected={} status={:?}",
                    r.expected_version,
                    r.mode.as_str(),
                    r.detected_version.clone().unwrap_or_else(|| "<absent>".into()),
                    r.status
                );
                (r.name.clone(), value.into_bytes())
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(version: &str, mode: MatchMode) -> ToolSpec {
        ToolSpec {
            version: version.to_string(),
            mode,
            detect: vec!["true".into()],
            cwd: None,
            remediation: "install it".into(),
            advisory: false,
            conditional: false,
            source: None,
        }
    }

    #[test]
    fn version_extraction_handles_real_banners() {
        assert_eq!(extract_version("rustc 1.94.1 (e408947bf 2026-03-25)").as_deref(), Some("1.94.1"));
        assert_eq!(extract_version("cargo 1.94.1 (29ea6fb6a 2026-03-24)").as_deref(), Some("1.94.1"));
        assert_eq!(extract_version("v22.22.2").as_deref(), Some("22.22.2"));
        assert_eq!(extract_version("Python 3.11.15").as_deref(), Some("3.11.15"));
        assert_eq!(extract_version("ruff 0.15.8").as_deref(), Some("0.15.8"));
        assert_eq!(extract_version("cargo-nextest-cargo-nextest 0.9.143").as_deref(), Some("0.9.143"));
        assert_eq!(extract_version("clippy 0.1.94 (e408947bfd 2026-03-25)").as_deref(), Some("0.1.94"));
        assert_eq!(extract_version("5.9.2").as_deref(), Some("5.9.2"));
    }

    #[test]
    fn version_extraction_refuses_to_invent_a_version() {
        assert_eq!(extract_version(""), None);
        assert_eq!(extract_version("command not found"), None);
        assert_eq!(extract_version("no numbers here"), None);
    }

    #[test]
    fn an_absent_tool_is_never_ok() {
        assert_eq!(evaluate("cargo-mutants", &spec("27.1.0", MatchMode::Exact), None), ToolStatus::Absent);
        assert_eq!(evaluate("rustfmt", &spec("0.0.0", MatchMode::Presence), None), ToolStatus::Absent);
        assert_eq!(evaluate("cargo-hack", &spec("0.6.45", MatchMode::Minimum), None), ToolStatus::Absent);
    }

    #[test]
    fn exact_mode_rejects_any_drift() {
        let s = spec("0.9.143", MatchMode::Exact);
        assert_eq!(evaluate("cargo-nextest", &s, Some("0.9.143")), ToolStatus::Ok);
        assert_eq!(evaluate("cargo-nextest", &s, Some("0.9.144")), ToolStatus::VersionMismatch);
        assert_eq!(evaluate("cargo-nextest", &s, Some("0.9.142")), ToolStatus::VersionMismatch);
    }

    #[test]
    fn minimum_mode_orders_numerically_not_lexically() {
        assert!(version_at_least("0.9.143", "0.9.99"), "143 > 99 numerically");
        assert!(version_at_least("1.10.0", "1.9.0"));
        assert!(version_at_least("1.2.3", "1.2.3"));
        assert!(!version_at_least("1.2.2", "1.2.3"));
        assert!(version_at_least("2.0", "1.999.999"));
    }

    #[test]
    fn detection_of_a_real_absent_tool_reports_the_remediation() {
        let mut s = spec("1.0.0", MatchMode::Exact);
        s.detect = vec!["definitely-not-a-real-tool-xyzzy".into(), "--version".into()];
        s.remediation = "cargo install --locked definitely-not-a-real-tool-xyzzy@1.0.0".into();
        let r = detect(Path::new("."), "definitely-not-a-real-tool-xyzzy", &s);
        assert_eq!(r.status, ToolStatus::Absent);
        assert!(r.problem().contains("not installed"));
        assert_eq!(r.remediation, "cargo install --locked definitely-not-a-real-tool-xyzzy@1.0.0");
    }

    #[test]
    fn repository_tools_lock_parses_and_pins_the_whole_stack() {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../.quality/tools.lock.toml")).unwrap();
        let lock = ToolsLock::parse(&text).unwrap();
        for required in [
            "cargo-nextest",
            "cargo-llvm-cov",
            "cargo-crap",
            "crap4rs",
            "cargo-mutants",
            "cargo-deny",
            "cargo-machete",
            "cargo-hack",
            "jscpd",
            "ruff",
        ] {
            let spec = lock.get(required).unwrap_or_else(|| panic!("{required} must be pinned"));
            assert!(!spec.remediation.is_empty(), "{required} must carry a remediation command");
            assert!(!spec.detect.is_empty(), "{required} must carry a detect command");
        }
        assert!(lock.get("rustc").is_some(), "the base toolchain must be pinned");
    }

    #[test]
    fn registry_reports_the_first_unusable_required_tool() {
        let reports = vec![
            ToolReport {
                name: "a".into(),
                expected_version: "1.0.0".into(),
                detected_version: Some("1.0.0".into()),
                mode: MatchMode::Exact,
                status: ToolStatus::Ok,
                advisory: false,
                conditional: false,
                remediation: "x".into(),
                detect_command: "a --version".into(),
            },
            ToolReport {
                name: "b".into(),
                expected_version: "2.0.0".into(),
                detected_version: None,
                mode: MatchMode::Exact,
                status: ToolStatus::Absent,
                advisory: false,
                conditional: false,
                remediation: "cargo install b".into(),
                detect_command: "b --version".into(),
            },
        ];
        let reg = Registry { reports };
        assert!(reg.first_problem(&["a"]).is_none());
        assert_eq!(reg.first_problem(&["a", "b"]).map(|r| r.name.clone()), Some("b".to_string()));
        assert_eq!(reg.unpinned(&["a", "c"]), Some("c".to_string()));
    }
}
