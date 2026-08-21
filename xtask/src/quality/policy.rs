//! `.quality/policy.toml` — the protected quality policy (spec §12, §26).
//!
//! Two properties matter more than anything else in this file:
//!
//! 1. The protected-path list used to judge a diff is loaded from the **trusted
//!    base SHA**, unioned with the head tree. An implementation agent that
//!    shrinks or deletes the list in its own branch does not thereby escape the
//!    check; it merely trips it.
//! 2. Scope classification lives in exactly one place, the `[[scope.rule]]`
//!    manifest, so the diff-to-gate matrix has a single source of truth.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use super::glob;

pub const POLICY_PATH: &str = ".quality/policy.toml";
pub const TOOLS_LOCK_PATH: &str = ".quality/tools.lock.toml";
pub const WAIVERS_PATH: &str = ".quality/waivers/quality-waivers.toml";

/// Extra protected policy files that live outside `.quality/` and therefore
/// must be folded into the policy digest explicitly.
pub const EXTRA_DIGEST_INPUTS: &[&str] =
    &[".prototools", "deny.toml", ".config/nextest.toml", ".cargo-crap.toml", "crap.toml", "tools/rustfmt.toml"];

#[derive(Debug, Clone, Deserialize)]
pub struct Policy {
    pub schema: u32,
    #[serde(default)]
    pub policy_version: String,
    pub crap: Crap,
    pub mutation: Mutation,
    pub coverage: Coverage,
    pub duplication: Duplication,
    pub agents: Agents,
    pub exceptions: Exceptions,
    pub execution: Execution,
    pub protected: Protected,
    pub languages: Languages,
    pub scope: Scope,
    pub triggers: Triggers,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Crap {
    pub rust: CrapRust,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CrapRust {
    pub canonical: String,
    pub missing_coverage: String,
    pub fail_regression: bool,
    pub new_function_max: f64,
    pub cleaner_target_changed_domain: f64,
    pub adapter_review_threshold: f64,
    pub legacy_hotspot_threshold: f64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Mutation {
    pub rust: MutationRust,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MutationRust {
    pub changed_production: String,
    pub full_run: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Coverage {
    pub rust: CoverageRust,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CoverageRust {
    pub require_instrumentation_complete: bool,
    pub global_percent_hard_gate: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Duplication {
    pub strategy: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Agents {
    pub implementation_can_change_policy: bool,
    pub fresh_verifier_context: bool,
    pub fresh_hardener_context: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Exceptions {
    pub require_reason: bool,
    pub require_issue_for_persistent: bool,
    pub require_independent_approval: bool,
    #[serde(default = "yes")]
    pub require_owner_field: bool,
    #[serde(default = "yes")]
    pub require_expiry_field: bool,
    #[serde(default = "default_lifetime")]
    pub max_waiver_lifetime_days: i64,
}

fn yes() -> bool {
    true
}
fn default_lifetime() -> i64 {
    180
}

#[derive(Debug, Clone, Deserialize)]
pub struct Execution {
    pub min_free_disk_gb_light: f64,
    pub min_free_disk_gb_heavy: f64,
    pub min_free_disk_gb_campaign: f64,
    pub fail_on_unclassified_source: bool,
    #[serde(default = "default_timeout")]
    pub gate_timeout_secs: u64,
    /// Per-workspace floors, keyed by manifest path, for workspaces whose
    /// build dwarfs the cost-class default. A single global number cannot be
    /// right for both the tiny `tools` workspace and the whole TypeDB fork.
    #[serde(default)]
    pub workspace_free_disk_gb: BTreeMap<String, f64>,
}

fn default_timeout() -> u64 {
    3600
}

#[derive(Debug, Clone, Deserialize)]
pub struct Protected {
    pub paths: Vec<String>,
    #[serde(default)]
    pub rationale: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Languages {
    pub rust: Vec<String>,
    pub typescript: Vec<String>,
    pub javascript: Vec<String>,
    pub python: Vec<String>,
    pub fail_closed: Vec<String>,
}

impl Languages {
    /// Language name for a path, by extension. `None` for data/docs.
    pub fn of_path(&self, path: &str) -> Option<&'static str> {
        let ext = Path::new(path).extension()?.to_str()?.to_ascii_lowercase();
        let table: [(&'static str, &Vec<String>); 4] = [
            ("rust", &self.rust),
            ("typescript", &self.typescript),
            ("javascript", &self.javascript),
            ("python", &self.python),
        ];
        table.iter().find(|(_, exts)| exts.iter().any(|e| e == &ext)).map(|(name, _)| *name)
    }

    pub fn is_fail_closed(&self, language: &str) -> bool {
        self.fail_closed.iter().any(|l| l == language)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Scope {
    pub rule: Vec<ScopeRule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScopeRule {
    pub id: String,
    pub globs: Vec<String>,
    pub class: ScopeClass,
    pub tier: ScopeTier,
    #[serde(default)]
    pub rust_manifest: Option<String>,
    #[serde(default)]
    pub rust_package: Option<String>,
    #[serde(default)]
    pub ts_project: Option<String>,
    #[serde(default)]
    pub python_project: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ScopeClass {
    Production,
    Tooling,
    Excluded,
}

impl ScopeClass {
    pub fn as_str(self) -> &'static str {
        match self {
            ScopeClass::Production => "production",
            ScopeClass::Tooling => "tooling",
            ScopeClass::Excluded => "excluded",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ScopeTier {
    Fast,
    Full,
}

impl ScopeTier {
    pub fn as_str(self) -> &'static str {
        match self {
            ScopeTier::Fast => "fast",
            ScopeTier::Full => "full",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Triggers {
    pub unsafe_ffi: PatternTrigger,
    pub public_api: PublicApiTrigger,
    pub features: FeaturesTrigger,
    pub dependencies: GlobTrigger,
    pub fuzz_critical: GlobTrigger,
    pub architecture: GlobTrigger,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PatternTrigger {
    pub patterns: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PublicApiTrigger {
    pub patterns: Vec<String>,
    pub compatibility_contract: bool,
    #[serde(default)]
    pub compatibility_contract_reason: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FeaturesTrigger {
    pub manifest_globs: Vec<String>,
    pub section: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GlobTrigger {
    pub globs: Vec<String>,
}

impl Policy {
    pub fn parse(text: &str) -> Result<Policy, String> {
        let policy: Policy = toml::from_str(text).map_err(|e| format!("{POLICY_PATH}: {e}"))?;
        if policy.schema != 1 {
            return Err(format!("{POLICY_PATH}: unsupported schema {}", policy.schema));
        }
        if policy.protected.paths.is_empty() {
            // An empty protected list is indistinguishable from "protection
            // disabled". Refuse it outright rather than reporting zero
            // protected-path hits for every diff.
            return Err(format!("{POLICY_PATH}: [protected].paths is empty; protection would be vacuous"));
        }
        Ok(policy)
    }

    pub fn load(repo_root: &Path) -> Result<Policy, String> {
        let path = repo_root.join(POLICY_PATH);
        let text = std::fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        Policy::parse(&text)
    }
}

/// The protected-path matcher, built from the union of the base-SHA policy and
/// the head-tree policy.
#[derive(Debug, Clone)]
pub struct ProtectedMatcher {
    /// pattern -> where it came from ("base", "head", "base+head")
    patterns: Vec<(String, &'static str)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedHit {
    pub path: String,
    pub matched_pattern: String,
    pub source: &'static str,
}

impl ProtectedMatcher {
    /// Union of two lists. `base` may be `None` when the base SHA predates the
    /// existence of the policy file (bootstrap); in that case the head list is
    /// used alone and the caller is told so via the `source` field.
    pub fn union(base: Option<&[String]>, head: &[String]) -> ProtectedMatcher {
        let mut map: BTreeMap<String, &'static str> = BTreeMap::new();
        if let Some(base) = base {
            for p in base {
                map.insert(glob::normalize(p), "base");
            }
        }
        for p in head {
            let key = glob::normalize(p);
            let entry = map.entry(key).or_insert("head");
            if *entry == "base" {
                *entry = "base+head";
            }
        }
        ProtectedMatcher { patterns: map.into_iter().collect() }
    }

    pub fn patterns(&self) -> impl Iterator<Item = &str> {
        self.patterns.iter().map(|(p, _)| p.as_str())
    }

    /// First protected pattern matching `path`, if any.
    pub fn hit(&self, path: &str) -> Option<ProtectedHit> {
        self.patterns.iter().find(|(pat, _)| glob::matches(pat, path)).map(|(pat, src)| ProtectedHit {
            path: glob::normalize(path),
            matched_pattern: pat.clone(),
            source: src,
        })
    }

    /// Every protected hit across a set of paths, de-duplicated and ordered.
    pub fn hits<'a, I: IntoIterator<Item = &'a str>>(&self, paths: I) -> Vec<ProtectedHit> {
        let mut out: Vec<ProtectedHit> = paths.into_iter().filter_map(|p| self.hit(p)).collect();
        out.sort_by(|a, b| a.path.cmp(&b.path));
        out.dedup_by(|a, b| a.path == b.path);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_policy() -> Policy {
        let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../.quality/policy.toml"))
            .expect("repository policy must be readable from the crate directory");
        Policy::parse(&text).expect("repository policy must parse")
    }

    #[test]
    fn repository_policy_parses_and_carries_the_spec_26_values() {
        let p = sample_policy();
        assert_eq!(p.crap.rust.canonical, "cargo-crap");
        assert_eq!(p.crap.rust.missing_coverage, "pessimistic");
        assert!(p.crap.rust.fail_regression);
        assert_eq!(p.crap.rust.new_function_max, 8.0);
        assert_eq!(p.crap.rust.cleaner_target_changed_domain, 6.0);
        assert_eq!(p.crap.rust.adapter_review_threshold, 15.0);
        assert_eq!(p.crap.rust.legacy_hotspot_threshold, 30.0);
        assert_eq!(p.mutation.rust.changed_production, "no-unexplained-survivors");
        assert_eq!(p.mutation.rust.full_run, "scheduled");
        assert!(p.coverage.rust.require_instrumentation_complete);
        assert!(!p.coverage.rust.global_percent_hard_gate);
        assert_eq!(p.duplication.strategy, "no-new-unjustified-duplication");
        assert!(!p.agents.implementation_can_change_policy);
        assert!(p.agents.fresh_verifier_context);
        assert!(p.agents.fresh_hardener_context);
        assert!(p.exceptions.require_reason);
        assert!(p.exceptions.require_issue_for_persistent);
        assert!(p.exceptions.require_independent_approval);
    }

    #[test]
    fn empty_protected_list_is_refused() {
        let text = r#"
schema = 1
[crap.rust]
canonical = "cargo-crap"
missing_coverage = "pessimistic"
fail_regression = true
new_function_max = 8.0
cleaner_target_changed_domain = 6.0
adapter_review_threshold = 15.0
legacy_hotspot_threshold = 30.0
[mutation.rust]
changed_production = "no-unexplained-survivors"
full_run = "scheduled"
[coverage.rust]
require_instrumentation_complete = true
global_percent_hard_gate = false
[duplication]
strategy = "x"
[agents]
implementation_can_change_policy = false
fresh_verifier_context = true
fresh_hardener_context = true
[exceptions]
require_reason = true
require_issue_for_persistent = true
require_independent_approval = true
[execution]
min_free_disk_gb_light = 0.5
min_free_disk_gb_heavy = 12.0
min_free_disk_gb_campaign = 40.0
fail_on_unclassified_source = true
[protected]
paths = []
[languages]
rust = ["rs"]
typescript = ["ts"]
javascript = ["js"]
python = ["py"]
fail_closed = ["rust"]
[[scope.rule]]
id = "x"
globs = ["**"]
class = "tooling"
tier = "fast"
reason = "x"
[triggers.unsafe_ffi]
patterns = []
[triggers.public_api]
patterns = []
compatibility_contract = false
[triggers.features]
manifest_globs = []
section = "[features]"
[triggers.dependencies]
globs = []
[triggers.fuzz_critical]
globs = []
[triggers.architecture]
globs = []
"#;
        let err = Policy::parse(text).unwrap_err();
        assert!(err.contains("vacuous"), "unexpected error: {err}");
    }

    #[test]
    fn language_detection_by_extension() {
        let p = sample_policy();
        assert_eq!(p.languages.of_path("tools/remote-wal-spike/src/lib.rs"), Some("rust"));
        assert_eq!(p.languages.of_path("control-plane/src/controller/core.ts"), Some("typescript"));
        assert_eq!(p.languages.of_path("stack/cli.mjs"), Some("javascript"));
        assert_eq!(p.languages.of_path("tools/catalog/common.py"), Some("python"));
        assert_eq!(p.languages.of_path("docs/ledger/x.md"), None);
        assert_eq!(p.languages.of_path("Makefile"), None);
    }

    #[test]
    fn protected_union_prefers_base_and_records_provenance() {
        let base = vec![".quality/**".to_string(), "deny.toml".to_string()];
        let head = vec![".quality/**".to_string(), "xtask/**".to_string()];
        let m = ProtectedMatcher::union(Some(&base), &head);
        assert_eq!(m.hit(".quality/policy.toml").unwrap().source, "base+head");
        assert_eq!(m.hit("deny.toml").unwrap().source, "base");
        assert_eq!(m.hit("xtask/src/main.rs").unwrap().source, "head");
        assert!(m.hit("tools/catalog/common.py").is_none());
    }

    #[test]
    fn deleting_a_protected_entry_in_the_pr_does_not_disable_it() {
        // The adversarial case: the head tree drops `deny.toml` from the list
        // in the same PR that edits `deny.toml`.
        let base = vec!["deny.toml".to_string(), ".quality/**".to_string()];
        let head = vec![".quality/**".to_string()];
        let m = ProtectedMatcher::union(Some(&base), &head);
        let hit = m.hit("deny.toml").expect("base list still governs");
        assert_eq!(hit.matched_pattern, "deny.toml");
        assert_eq!(hit.source, "base");
    }

    #[test]
    fn repository_protected_list_covers_the_spec_12_classes() {
        let p = sample_policy();
        let m = ProtectedMatcher::union(None, &p.protected.paths);
        for path in [
            ".github/workflows/quality.yml",
            ".quality/policy.toml",
            ".quality/waivers/quality-waivers.toml",
            "xtask/src/quality/policy.rs",
            ".cargo-crap.toml",
            "crap.toml",
            "deny.toml",
            ".config/nextest.toml",
            "rust-toolchain.toml",
            "CODEOWNERS",
            ".jscpd.json",
            "tools/rustfmt.toml",
            "tools/Cargo.toml",
            "control-plane/vitest.config.ts",
        ] {
            assert!(m.hit(path).is_some(), "{path} must be protected");
        }
        for path in ["tools/remote-wal-spike/src/lib.rs", "control-plane/src/controller/core.ts", "docs/ledger/a.md"] {
            assert!(m.hit(path).is_none(), "{path} must not be protected");
        }
    }
}
