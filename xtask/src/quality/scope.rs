//! Scope classification: the single machine-readable answer to "is this path
//! production or tooling?".
//!
//! The diff-to-gate matrix consults this and nothing else. Owner scope
//! decisions live in `[[scope.rule]]` in `.quality/policy.toml`, never inline
//! in Rust.

use serde::Serialize;

use super::glob;
use super::policy::{Policy, ScopeClass, ScopeRule, ScopeTier};

#[derive(Debug, Clone, Serialize)]
pub struct Classified {
    pub path: String,
    pub previous_path: Option<String>,
    pub git_status: String,
    pub rule: String,
    pub class: ScopeClass,
    pub tier: ScopeTier,
    pub language: Option<String>,
}

/// Result of classifying one path.
#[derive(Debug, Clone)]
pub enum Classification<'a> {
    Matched(&'a ScopeRule),
    Unclassified,
}

/// First matching rule wins. Rule order in `policy.toml` is significant and is
/// part of the reviewed policy.
pub fn classify<'a>(policy: &'a Policy, path: &str) -> Classification<'a> {
    for rule in &policy.scope.rule {
        if rule.globs.iter().any(|g| glob::matches(g, path)) {
            return Classification::Matched(rule);
        }
    }
    Classification::Unclassified
}

/// Rust manifests that contain in-scope code, in policy order, de-duplicated.
///
/// `classes` restricts the result, e.g. `[Production]` for Tier-B Rust gates.
pub fn rust_manifests(policy: &Policy, classes: &[ScopeClass]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for rule in &policy.scope.rule {
        if !classes.contains(&rule.class) {
            continue;
        }
        if let Some(m) = &rule.rust_manifest {
            if !out.contains(m) {
                out.push(m.clone());
            }
        }
    }
    out
}

/// TypeScript project roots (directories holding a `package.json`) in scope.
pub fn ts_projects(policy: &Policy, classes: &[ScopeClass]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for rule in &policy.scope.rule {
        if !classes.contains(&rule.class) {
            continue;
        }
        if let Some(p) = &rule.ts_project {
            if !out.contains(p) {
                out.push(p.clone());
            }
        }
    }
    out
}

/// Python project roots in scope.
pub fn python_projects(policy: &Policy, classes: &[ScopeClass]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for rule in &policy.scope.rule {
        if !classes.contains(&rule.class) {
            continue;
        }
        if let Some(p) = &rule.python_project {
            if !out.contains(p) {
                out.push(p.clone());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../.quality/policy.toml")).unwrap();
        Policy::parse(&text).unwrap()
    }

    fn expect_rule(p: &Policy, path: &str) -> (String, ScopeClass, ScopeTier) {
        match classify(p, path) {
            Classification::Matched(r) => (r.id.clone(), r.class, r.tier),
            Classification::Unclassified => panic!("{path} is unclassified"),
        }
    }

    #[test]
    fn owner_scope_decision_is_encoded_exactly() {
        let p = policy();

        // Production, full gates.
        for path in [
            "fork/typedb/storage/src/lib.rs",
            "fork/slatedb/patches/0001-foo.patch",
            "tools/remote-wal-spike/src/bin/l1_e2e.rs",
            "control-plane/src/controller/core.ts",
        ] {
            let (_, class, tier) = expect_rule(&p, path);
            assert_eq!(class, ScopeClass::Production, "{path} must be production");
            assert_eq!(tier, ScopeTier::Full, "{path} must be full-gated");
        }

        // Tooling, fast gates only.
        for path in [
            "control-plane/probes/probe.ts",
            "stack/supervisor.mjs",
            "tools/catalog/common.py",
            "tools/qualification/cucumber_common.py",
            "tools/source-lock/lock_mutants.py",
        ] {
            let (_, class, tier) = expect_rule(&p, path);
            assert_eq!(class, ScopeClass::Tooling, "{path} must be tooling");
            assert_eq!(tier, ScopeTier::Fast, "{path} must be fast-gated only");
        }
    }

    #[test]
    fn remote_wal_spike_wins_over_the_generic_tools_rule() {
        let p = policy();
        assert_eq!(expect_rule(&p, "tools/remote-wal-spike/src/lib.rs").0, "remote-wal-spike");
        assert_eq!(expect_rule(&p, "tools/catalog/run_u0.py").0, "tools-generic");
    }

    #[test]
    fn control_plane_src_is_production_but_probes_are_not() {
        let p = policy();
        assert_eq!(expect_rule(&p, "control-plane/src/container/index.ts").1, ScopeClass::Production);
        assert_eq!(expect_rule(&p, "control-plane/probes/approval.ts").1, ScopeClass::Tooling);
        // A file directly in control-plane/ is configuration, not the worker.
        assert_eq!(expect_rule(&p, "control-plane/package.json").1, ScopeClass::Tooling);
    }

    #[test]
    fn the_controller_gates_itself() {
        let p = policy();
        let (id, class, tier) = expect_rule(&p, "xtask/src/quality/policy.rs");
        assert_eq!(id, "quality-controller");
        assert_eq!(class, ScopeClass::Production);
        assert_eq!(tier, ScopeTier::Full);
    }

    #[test]
    fn a_brand_new_top_level_source_directory_is_unclassified_not_free() {
        let p = policy();
        assert!(matches!(classify(&p, "newservice/src/main.rs"), Classification::Unclassified));
        assert!(matches!(classify(&p, "escape-hatch/index.ts"), Classification::Unclassified));
    }

    #[test]
    fn production_rust_manifests_are_derived_from_the_manifest_not_hardcoded() {
        let p = policy();
        let manifests = rust_manifests(&p, &[ScopeClass::Production]);
        assert!(manifests.contains(&"fork/typedb/Cargo.toml".to_string()));
        assert!(manifests.contains(&"tools/Cargo.toml".to_string()));
        // De-duplicated: xtask and remote-wal-spike share the tools workspace.
        assert_eq!(manifests.iter().filter(|m| *m == "tools/Cargo.toml").count(), 1);
    }
}
