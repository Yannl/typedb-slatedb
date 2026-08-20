//! Change set parsing and the §15 diff-to-gate matrix.
//!
//! Gates are chosen from `git diff --name-status` plus the scope manifest.
//! They are never chosen by asking a model what seems necessary, and never by
//! a hardcoded path list outside `.quality/policy.toml`.

use serde::Serialize;

use super::glob;
use super::policy::{Policy, ScopeClass, ScopeTier};
use super::scope::{self, Classification, Classified};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeEntry {
    /// Raw git status letter(s): `A`, `M`, `D`, `R100`, `C75`, `T`, …
    pub status: String,
    pub path: String,
    pub previous_path: Option<String>,
}

impl ChangeEntry {
    /// Both sides of a rename. A rename cannot be used to make a risky change
    /// look docs-only, so classification considers the old path too (§15).
    pub fn paths(&self) -> Vec<&str> {
        match &self.previous_path {
            Some(p) => vec![self.path.as_str(), p.as_str()],
            None => vec![self.path.as_str()],
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangeSet {
    pub entries: Vec<ChangeEntry>,
}

impl ChangeSet {
    /// Parse NUL-delimited `git diff --name-status -M -z` output.
    ///
    /// Rename and copy records carry two path fields; everything else carries
    /// one. A malformed stream is an error, never a silently empty change set:
    /// an empty change set would select no gates at all.
    pub fn parse_z(bytes: &[u8]) -> Result<ChangeSet, String> {
        let mut fields = bytes.split(|b| *b == 0).filter(|f| !f.is_empty());
        let mut entries = Vec::new();
        while let Some(status_raw) = fields.next() {
            let status = String::from_utf8_lossy(status_raw).to_string();
            let first = status.chars().next().ok_or("empty status field in diff stream")?;
            let path_raw = fields.next().ok_or_else(|| format!("status {status:?} without a path"))?;
            let path = glob::normalize(&String::from_utf8_lossy(path_raw));
            if first == 'R' || first == 'C' {
                let new_raw =
                    fields.next().ok_or_else(|| format!("status {status:?} without a destination path"))?;
                let new_path = glob::normalize(&String::from_utf8_lossy(new_raw));
                entries.push(ChangeEntry { status, path: new_path, previous_path: Some(path) });
            } else {
                entries.push(ChangeEntry { status, path, previous_path: None });
            }
        }
        Ok(ChangeSet { entries })
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn all_paths(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.entries.iter().flat_map(|e| e.paths()).collect();
        v.sort_unstable();
        v.dedup();
        v
    }
}

/// Everything the matrix needs to know about a diff, derived deterministically.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Facts {
    pub classified: Vec<Classified>,
    pub unclassified: Vec<String>,
    pub rust_production: bool,
    pub rust_any: bool,
    pub typescript_production: bool,
    pub typescript_any: bool,
    pub python_any: bool,
    pub unsafe_or_ffi: bool,
    pub public_api: bool,
    pub features: bool,
    pub dependencies: bool,
    pub fuzz_critical: bool,
    pub architecture: bool,
    pub tests_only: bool,
    pub empty: bool,
}

fn is_test_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.contains("/tests/")
        || p.starts_with("tests/")
        || p.ends_with(".test.ts")
        || p.ends_with(".test.mts")
        || p.ends_with(".spec.ts")
        || p.ends_with("_test.rs")
        || p.ends_with("_test.py")
        || p.contains("/test_")
        || p.starts_with("test_")
        || p.contains("/behaviour/")
}

/// Derive the matrix facts. `added` is the concatenation of added diff lines,
/// used for content triggers that a path alone cannot express.
pub fn derive_facts(policy: &Policy, changes: &ChangeSet, added: &str) -> Facts {
    let mut facts = Facts { empty: changes.is_empty(), ..Default::default() };
    let mut source_paths: Vec<&str> = Vec::new();

    for entry in &changes.entries {
        let mut best: Option<Classified> = None;
        for path in entry.paths() {
            let language = policy.languages.of_path(path).map(|s| s.to_string());
            match scope::classify(policy, path) {
                Classification::Matched(rule) => {
                    let candidate = Classified {
                        path: entry.path.clone(),
                        previous_path: entry.previous_path.clone(),
                        git_status: entry.status.clone(),
                        rule: rule.id.clone(),
                        class: rule.class,
                        tier: rule.tier,
                        language: language.clone(),
                    };
                    // Renames: take the stricter of the two classifications so
                    // that moving a production file into a docs directory does
                    // not downgrade the gates.
                    best = Some(match best {
                        None => candidate,
                        Some(prev) => {
                            if strictness(candidate.class) > strictness(prev.class) {
                                candidate
                            } else {
                                prev
                            }
                        }
                    });
                }
                Classification::Unclassified => {
                    if let Some(lang) = &language {
                        if policy.languages.is_fail_closed(lang) && !facts.unclassified.contains(&path.to_string()) {
                            facts.unclassified.push(path.to_string());
                        }
                    }
                }
            }
        }

        if let Some(c) = best {
            if c.class != ScopeClass::Excluded {
                if let Some(lang) = c.language.as_deref() {
                    source_paths.push(entry.path.as_str());
                    let production = c.class == ScopeClass::Production && c.tier == ScopeTier::Full;
                    match lang {
                        "rust" => {
                            facts.rust_any = true;
                            facts.rust_production |= production;
                        }
                        "typescript" | "javascript" => {
                            facts.typescript_any = true;
                            facts.typescript_production |= production;
                        }
                        "python" => facts.python_any = true,
                        _ => {}
                    }
                } else if c.class == ScopeClass::Production {
                    // Production non-source artefacts, e.g. slatedb patches.
                    source_paths.push(entry.path.as_str());
                }
            }
            facts.classified.push(c);
        }
    }

    let all: Vec<&str> = changes.all_paths();
    let matches_any = |globs: &[String]| all.iter().any(|p| globs.iter().any(|g| glob::matches(g, p)));

    facts.dependencies = matches_any(&policy.triggers.dependencies.globs);
    facts.fuzz_critical = matches_any(&policy.triggers.fuzz_critical.globs);
    facts.architecture = matches_any(&policy.triggers.architecture.globs);

    facts.unsafe_or_ffi = policy.triggers.unsafe_ffi.patterns.iter().any(|p| added.contains(p.as_str()));
    facts.public_api = facts.rust_any && policy.triggers.public_api.patterns.iter().any(|p| added.contains(p.as_str()));
    facts.features = matches_any(&policy.triggers.features.manifest_globs)
        && added.contains(policy.triggers.features.section.as_str());

    facts.tests_only = !source_paths.is_empty() && source_paths.iter().all(|p| is_test_path(p));

    facts
}

fn strictness(class: ScopeClass) -> u8 {
    match class {
        ScopeClass::Production => 2,
        ScopeClass::Tooling => 1,
        ScopeClass::Excluded => 0,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SelectedGate {
    pub id: String,
    pub reason: String,
    pub matrix_row: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Fast,
    Pr,
    Full,
    PolicyCheck,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Fast => "fast",
            Mode::Pr => "pr",
            Mode::Full => "full",
            Mode::PolicyCheck => "policy-check",
        }
    }
}

fn push(out: &mut Vec<SelectedGate>, id: &str, row: &str, reason: &str) {
    if !out.iter().any(|g| g.id == id) {
        out.push(SelectedGate { id: id.to_string(), reason: reason.to_string(), matrix_row: row.to_string() });
    }
}

/// The §15 matrix. Every selected gate records the row that selected it, so a
/// reviewer can audit the decision without rerunning anything.
pub fn select_gates(mode: Mode, policy: &Policy, facts: &Facts) -> Vec<SelectedGate> {
    let mut out: Vec<SelectedGate> = Vec::new();

    // ---- Controller self-checks: always on, in every mode. ----
    push(&mut out, "policy.waivers", "always", "waiver register is schema-validated on every run (§13)");
    push(&mut out, "policy.toolchain_pin", "always", "pinned toolchain identity is verified on every run (§19)");
    push(&mut out, "policy.scope_classification", "always", "every changed source path must be classified (§15)");

    if matches!(mode, Mode::Pr | Mode::PolicyCheck) {
        push(
            &mut out,
            "policy.protected",
            ".quality/** or other protected policy",
            "protected-policy check is mandatory for the merge gate (§14.2)",
        );
    }
    if mode == Mode::PolicyCheck {
        return out;
    }

    // ---- Tier A, §14.1: Rust fast gates run unconditionally. ----
    push(&mut out, "rust.fmt", "tier A", "formatting is a hard gate (§5.1)");
    push(&mut out, "rust.clippy", "tier A", "clippy -D warnings is a hard gate (§5.2)");
    push(&mut out, "rust.tests", "tier A", "nextest is the canonical runner (§5.3)");

    // ---- §15 row: Cargo.lock / dependencies ----
    if facts.dependencies || mode == Mode::Full {
        push(&mut out, "rust.deny", "Cargo.lock / dependencies", "advisories, licences, bans, sources (§5.11)");
        push(&mut out, "rust.machete", "Cargo.lock / dependencies", "unused dependency detection (§5.11)");
    }

    // ---- §15 row: Cargo.toml features ----
    if facts.features {
        push(&mut out, "rust.hack.each_feature", "Cargo.toml features", "feature declarations changed (§5.10)");
    }
    if mode == Mode::Full {
        push(&mut out, "rust.hack.powerset", "tier C", "deeper feature matrix on scheduled runs (§5.10)");
    }

    // ---- §15 row: crates/**/src/**/*.rs (Rust production) ----
    // Tier B and C only: coverage, CRAP and mutation are too expensive for the
    // inner loop (§14.1 "no expensive full mutation campaign").
    if (facts.rust_production && mode == Mode::Pr) || mode == Mode::Full {
        let row = "rust production source";
        push(&mut out, "rust.coverage", row, "LCOV for the canonical CRAP input (§5.4)");
        push(&mut out, "rust.crap", row, "canonical cargo-crap against the trusted base (§5.5)");
        push(&mut out, "rust.crap_advice", row, "crap4rs advisory artefact for the Cleaner (§2.2)");
        if mode != Mode::Full {
            push(&mut out, "rust.mutation.diff", row, "differential mutation on changed production code (§5.6)");
        }
    }
    if mode == Mode::Full {
        push(&mut out, "rust.mutation.full", "tier C", "full mutation campaign on scheduled runs (§5.6)");
        push(&mut out, "rust.crap.trend", "tier C", "CRAP trend report (§14.3)");
    }

    // ---- §15 row: unsafe / FFI / allocator / raw pointer ----
    if facts.unsafe_or_ffi {
        let row = "unsafe / FFI / allocator / raw pointer";
        push(&mut out, "rust.miri", row, "Miri becomes a PR requirement (§5.9)");
        push(&mut out, "rust.fuzz.smoke", row, "targeted fuzz smoke becomes a PR requirement (§5.8)");
    }
    if mode == Mode::Full {
        push(&mut out, "rust.miri.full", "tier C", "Miri across supported critical packages (§14.3)");
        push(&mut out, "rust.fuzz.long", "tier C", "longer fuzz budgets (§14.3)");
    }

    // ---- §15 row: parser / codec / protocol / storage format ----
    if facts.fuzz_critical {
        let row = "parser / codec / protocol / storage format";
        push(&mut out, "rust.fuzz.smoke", row, "fuzz target strongly expected on this surface (§5.8)");
        push(&mut out, "rust.property_tests", row, "property tests strongly expected on this surface (§5.7)");
    }

    // ---- §15 row: public exported API ----
    if facts.public_api {
        if policy.triggers.public_api.compatibility_contract {
            push(&mut out, "rust.semver", "public exported API", "API compatibility is a repository contract (§5.11)");
        } else {
            push(
                &mut out,
                "rust.semver.not_contracted",
                "public exported API",
                "public API changed but no crate here publishes a compatibility contract; recorded, not gated (§5.11)",
            );
        }
    }

    // ---- §15 row: TypeScript tooling ----
    if facts.typescript_any || mode == Mode::Full {
        let row = "TypeScript";
        push(&mut out, "ts.typecheck", row, "one canonical type-checking truth (§8)");
        push(&mut out, "ts.oxlint", row, "lint gate (§8)");
        push(&mut out, "ts.knip", row, "unused files/exports/dependencies (§8)");
        push(&mut out, "ts.depcruise", row, "TypeScript architecture rules (§8)");
        if (facts.typescript_production && mode == Mode::Pr) || mode == Mode::Full {
            push(&mut out, "ts.crap", row, "CRAP for production TypeScript (§8)");
            push(&mut out, "ts.mutation", row, "StrykerJS on material production logic (§8)");
        }
    }

    // ---- §15 row: Python tooling ----
    if facts.python_any || mode == Mode::Full {
        let row = "Python";
        push(&mut out, "py.ruff.check", row, "lint gate (§9)");
        push(&mut out, "py.ruff.format", row, "format gate (§9)");
        push(&mut out, "py.typecheck", row, "one canonical type checker (§9)");
        push(&mut out, "py.pytest", row, "branch-coverage test run (§9)");
        if matches!(mode, Mode::Pr | Mode::Full) {
            push(&mut out, "py.pip_audit", row, "dependency security (§9)");
            push(&mut out, "py.crap", row, "advisory CRAP with an instrumentation-completeness assertion (§9)");
        }
    }

    // ---- §15 row: architecture boundary files ----
    if matches!(mode, Mode::Pr | Mode::Full) && (facts.architecture || mode == Mode::Full) {
        push(&mut out, "arch.rust_deps", "architecture boundary files", "crate dependency direction (§6)");
    }

    // ---- Duplication (§7): delta on PR, full scan on schedule. ----
    match mode {
        Mode::Pr => push(&mut out, "dup.jscpd_delta", "always (tier B)", "no new unjustified duplication (§7)"),
        Mode::Full => push(&mut out, "dup.jscpd_full", "tier C", "full duplication scan (§14.3)"),
        _ => {}
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

    fn zstream(items: &[&str]) -> Vec<u8> {
        let mut v = Vec::new();
        for i in items {
            v.extend_from_slice(i.as_bytes());
            v.push(0);
        }
        v
    }

    fn ids(gates: &[SelectedGate]) -> Vec<&str> {
        gates.iter().map(|g| g.id.as_str()).collect()
    }

    fn select_for(paths: &[&str], added: &str, mode: Mode) -> Vec<SelectedGate> {
        let p = policy();
        let mut items: Vec<&str> = Vec::new();
        for path in paths {
            items.push("M");
            items.push(path);
        }
        let cs = ChangeSet::parse_z(&zstream(&items)).unwrap();
        let facts = derive_facts(&p, &cs, added);
        select_gates(mode, &p, &facts)
    }

    #[test]
    fn parses_plain_and_rename_records() {
        let cs = ChangeSet::parse_z(&zstream(&["M", "a.rs", "A", "b/c.ts", "R100", "old/x.rs", "new/x.rs", "D", "d.py"]))
            .unwrap();
        assert_eq!(cs.entries.len(), 4);
        assert_eq!(cs.entries[2], ChangeEntry {
            status: "R100".into(),
            path: "new/x.rs".into(),
            previous_path: Some("old/x.rs".into())
        });
        assert_eq!(cs.all_paths(), vec!["a.rs", "b/c.ts", "d.py", "new/x.rs", "old/x.rs"]);
    }

    #[test]
    fn a_truncated_diff_stream_is_an_error_not_an_empty_change_set() {
        assert!(ChangeSet::parse_z(&zstream(&["M"])).is_err());
        assert!(ChangeSet::parse_z(&zstream(&["R100", "old/x.rs"])).is_err());
    }

    #[test]
    fn paths_with_spaces_survive_nul_parsing() {
        let cs = ChangeSet::parse_z(&zstream(&["M", "docs/a file with spaces.md"])).unwrap();
        assert_eq!(cs.entries[0].path, "docs/a file with spaces.md");
    }

    // ---- §15 matrix, one test per row ----

    #[test]
    fn row_rust_production_source() {
        let g = select_for(&["tools/remote-wal-spike/src/lib.rs"], "", Mode::Pr);
        for want in ["rust.coverage", "rust.crap", "rust.crap_advice", "rust.mutation.diff"] {
            assert!(ids(&g).contains(&want), "expected {want} in {:?}", ids(&g));
        }
    }

    #[test]
    fn row_rust_tooling_source_does_not_trigger_the_expensive_rust_gates() {
        let g = select_for(&["tools/protocol-models/src/lib.rs"], "", Mode::Pr);
        for unwanted in ["rust.coverage", "rust.crap", "rust.mutation.diff"] {
            assert!(!ids(&g).contains(&unwanted), "{unwanted} must not fire for tooling-class Rust");
        }
        // But the Tier-A gates still run.
        assert!(ids(&g).contains(&"rust.fmt"));
        assert!(ids(&g).contains(&"rust.clippy"));
        assert!(ids(&g).contains(&"rust.tests"));
    }

    #[test]
    fn row_unsafe_ffi() {
        let g = select_for(&["fork/typedb/storage/src/lib.rs"], "let p: *mut u8 = ptr;", Mode::Pr);
        assert!(ids(&g).contains(&"rust.miri"));
        assert!(ids(&g).contains(&"rust.fuzz.smoke"));

        let g = select_for(&["fork/typedb/storage/src/lib.rs"], "let x = 1;", Mode::Pr);
        assert!(!ids(&g).contains(&"rust.miri"));
    }

    #[test]
    fn row_public_api_without_a_compatibility_contract_is_recorded_not_gated() {
        let g = select_for(&["tools/remote-wal-spike/src/lib.rs"], "pub fn frobnicate() {}", Mode::Pr);
        assert!(ids(&g).contains(&"rust.semver.not_contracted"));
        assert!(!ids(&g).contains(&"rust.semver"));
    }

    #[test]
    fn row_cargo_toml_features() {
        let g = select_for(&["tools/remote-wal-spike/Cargo.toml"], "[features]\nfoo = []", Mode::Pr);
        assert!(ids(&g).contains(&"rust.hack.each_feature"));

        let g = select_for(&["tools/remote-wal-spike/Cargo.toml"], "serde = \"1\"", Mode::Pr);
        assert!(!ids(&g).contains(&"rust.hack.each_feature"));
    }

    #[test]
    fn row_dependencies() {
        let g = select_for(&["tools/Cargo.lock"], "", Mode::Pr);
        assert!(ids(&g).contains(&"rust.deny"));
        assert!(ids(&g).contains(&"rust.machete"));

        let g = select_for(&["docs/ledger/a.md"], "", Mode::Pr);
        assert!(!ids(&g).contains(&"rust.deny"));
    }

    #[test]
    fn row_typescript_production_and_tooling_differ() {
        let prod = select_for(&["control-plane/src/controller/core.ts"], "", Mode::Pr);
        for want in ["ts.typecheck", "ts.oxlint", "ts.knip", "ts.depcruise", "ts.crap", "ts.mutation"] {
            assert!(ids(&prod).contains(&want), "expected {want}");
        }
        let tooling = select_for(&["control-plane/probes/probe.ts"], "", Mode::Pr);
        assert!(ids(&tooling).contains(&"ts.typecheck"));
        assert!(!ids(&tooling).contains(&"ts.mutation"), "tooling TS gets fast gates only");
        assert!(!ids(&tooling).contains(&"ts.crap"));
    }

    #[test]
    fn row_python_tooling() {
        let g = select_for(&["tools/catalog/common.py"], "", Mode::Pr);
        for want in ["py.ruff.check", "py.ruff.format", "py.typecheck", "py.pytest", "py.pip_audit", "py.crap"] {
            assert!(ids(&g).contains(&want), "expected {want}");
        }
        // Python is tooling everywhere here, so no Python mutation gate fires.
        assert!(!ids(&g).contains(&"py.mutation"));
    }

    #[test]
    fn row_parser_codec_protocol_storage_format() {
        let g = select_for(&["fork/typedb/encoding/src/graph.rs"], "", Mode::Pr);
        assert!(ids(&g).contains(&"rust.fuzz.smoke"));
        assert!(ids(&g).contains(&"rust.property_tests"));
    }

    #[test]
    fn row_architecture_boundary_files() {
        let g = select_for(&["tools/Cargo.toml"], "", Mode::Pr);
        assert!(ids(&g).contains(&"arch.rust_deps"));
    }

    #[test]
    fn row_protected_policy() {
        let g = select_for(&[".quality/policy.toml"], "", Mode::Pr);
        assert!(ids(&g).contains(&"policy.protected"));
        let g = select_for(&[".quality/policy.toml"], "", Mode::PolicyCheck);
        assert_eq!(ids(&g).last(), Some(&"policy.protected"));
    }

    #[test]
    fn row_tests_only_recomputes_but_claims_nothing_about_mutation() {
        let p = policy();
        let cs = ChangeSet::parse_z(&zstream(&["M", "fork/typedb/storage/tests/mod.rs"])).unwrap();
        let facts = derive_facts(&p, &cs, "");
        assert!(facts.tests_only, "a tests-only diff must be recognised as such");
    }

    #[test]
    fn row_docs_only_selects_no_language_gates_beyond_tier_a() {
        let p = policy();
        let cs = ChangeSet::parse_z(&zstream(&["M", "docs/ledger/a.md", "M", "README.md"])).unwrap();
        let facts = derive_facts(&p, &cs, "");
        assert!(!facts.rust_production);
        assert!(!facts.typescript_any);
        assert!(!facts.python_any);
        assert!(facts.unclassified.is_empty());
    }

    #[test]
    fn a_rename_cannot_launder_production_code_into_docs() {
        let p = policy();
        let cs = ChangeSet::parse_z(&zstream(&["R090", "tools/remote-wal-spike/src/lib.rs", "docs/lib.rs"])).unwrap();
        let facts = derive_facts(&p, &cs, "");
        assert!(facts.rust_production, "the production side of a rename still governs");
        assert_eq!(facts.classified[0].rule, "remote-wal-spike");
    }

    #[test]
    fn an_unclassified_source_path_is_reported_fail_closed() {
        let p = policy();
        let cs = ChangeSet::parse_z(&zstream(&["A", "newservice/src/main.rs"])).unwrap();
        let facts = derive_facts(&p, &cs, "");
        assert_eq!(facts.unclassified, vec!["newservice/src/main.rs".to_string()]);
    }

    #[test]
    fn an_unclassified_non_source_path_is_not_fail_closed() {
        let p = policy();
        let cs = ChangeSet::parse_z(&zstream(&["A", "newthing/data.bin"])).unwrap();
        let facts = derive_facts(&p, &cs, "");
        assert!(facts.unclassified.is_empty());
    }

    #[test]
    fn full_mode_runs_the_expensive_campaigns_without_a_diff() {
        let p = policy();
        let facts = derive_facts(&p, &ChangeSet::default(), "");
        let g = select_gates(Mode::Full, &p, &facts);
        for want in ["rust.mutation.full", "rust.hack.powerset", "rust.miri.full", "dup.jscpd_full", "rust.crap.trend"]
        {
            assert!(ids(&g).contains(&want), "expected {want} in full mode");
        }
        assert!(!ids(&g).contains(&"policy.protected"), "full mode has no base SHA to diff against");
    }

    #[test]
    fn fast_mode_never_selects_a_campaign_or_tier_b_gate() {
        let g = select_for(&["tools/remote-wal-spike/src/lib.rs", "control-plane/src/a.ts"], "", Mode::Fast);
        for forbidden in [
            "rust.mutation.full",
            "rust.mutation.diff",
            "rust.hack.powerset",
            "rust.coverage",
            "rust.crap",
            "dup.jscpd_full",
            "dup.jscpd_delta",
            "rust.miri.full",
            "ts.crap",
            "ts.mutation",
            "arch.rust_deps",
            "policy.protected",
        ] {
            assert!(!ids(&g).contains(&forbidden), "{forbidden} must not run in the inner loop");
        }
        // Tier A still runs in full.
        for want in ["rust.fmt", "rust.clippy", "rust.tests", "ts.typecheck", "ts.oxlint", "ts.knip"] {
            assert!(ids(&g).contains(&want), "expected {want} in fast mode");
        }
    }
}
