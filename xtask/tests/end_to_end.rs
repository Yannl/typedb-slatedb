//! End-to-end tests of the deterministic quality controller against real Git
//! repositories.
//!
//! Every fixture is created inside the operating system temporary directory and
//! removed afterwards. Nothing here touches the repository under development:
//! each `git` invocation is anchored with `-C <fixture>` and the fixture path is
//! asserted to live under `std::env::temp_dir()` before anything runs.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

const XTASK: &str = env!("CARGO_BIN_EXE_xtask");
static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn repo_under_test() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/..")).canonicalize().unwrap()
}

struct Fixture {
    dir: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Fixture {
    fn new(name: &str) -> Fixture {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("xtask-quality-{}-{}-{}", std::process::id(), n, name));
        assert!(
            dir.starts_with(std::env::temp_dir()),
            "fixtures must never be created outside the temporary directory"
        );
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let f = Fixture { dir };
        f.git(&["init", "--quiet", "--initial-branch=main"]);
        f.git(&["config", "user.email", "controller-test@invalid"]);
        f.git(&["config", "user.name", "controller test"]);
        f.git(&["config", "commit.gpgsign", "false"]);
        f.install_quality_policy();
        f.write(".gitignore", "artifacts/\n");
        f
    }

    fn git(&self, args: &[&str]) -> String {
        let out = Command::new("git").arg("-C").arg(&self.dir).args(args).output().unwrap();
        assert!(out.status.success(), "git {args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn write(&self, rel: &str, content: &str) {
        let path = self.dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.dir.join(rel)).unwrap()
    }

    /// The real `.quality/policy.toml` from the repository under test, so that
    /// these tests exercise the shipped protected list and scope manifest, plus
    /// a hermetic tool lock so the fixture does not depend on what happens to
    /// be installed on the machine running the tests.
    fn install_quality_policy(&self) {
        let src = repo_under_test();
        std::fs::create_dir_all(self.dir.join(".quality/waivers")).unwrap();
        std::fs::create_dir_all(self.dir.join(".quality/architecture")).unwrap();
        std::fs::copy(src.join(".quality/policy.toml"), self.dir.join(".quality/policy.toml")).unwrap();
        std::fs::copy(
            src.join(".quality/architecture/rust-dependencies.toml"),
            self.dir.join(".quality/architecture/rust-dependencies.toml"),
        )
        .unwrap();
        self.write(".quality/waivers/quality-waivers.toml", "schema = 1\n");
        self.write(
            ".quality/tools.lock.toml",
            r#"
schema = 1
resolved_on = "2026-08-20"

[toolchain.rustc]
version = "0.0.0"
mode = "presence"
detect = ["rustc", "--version"]
remediation = "rustup toolchain install stable"

[tool.cargo-nextest]
version = "0.9.143"
mode = "exact"
detect = ["definitely-not-installed-nextest", "--version"]
remediation = "cargo install --locked cargo-nextest@0.9.143"
"#,
        );
    }

    fn commit(&self, message: &str) -> String {
        self.git(&["add", "-A"]);
        self.git(&["commit", "--quiet", "--no-gpg-sign", "-m", message]);
        self.git(&["rev-parse", "HEAD"])
    }

    fn xtask(&self, args: &[&str]) -> (i32, String) {
        let out = Command::new(XTASK).args(args).current_dir(&self.dir).output().unwrap();
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        (out.status.code().unwrap_or(-1), text)
    }

    fn report(&self) -> serde_json::Value {
        serde_json::from_str(&self.read("artifacts/quality/quality-report.json")).unwrap()
    }
}

fn seed(f: &Fixture) -> String {
    f.write("docs/readme.md", "base\n");
    f.write("deny.toml", "[bans]\nmultiple-versions = \"deny\"\n");
    f.write("tools/remote-wal-spike/src/lib.rs", "pub fn ok() -> u8 { 1 }\n");
    f.commit("base")
}

// ---------------------------------------------------------------------------
// The anti-gaming core.
// ---------------------------------------------------------------------------

#[test]
fn a_normal_implementation_diff_that_touches_protected_policy_is_refused() {
    let f = Fixture::new("protected");
    let base = seed(&f);

    f.write("tools/remote-wal-spike/src/lib.rs", "pub fn ok() -> u8 { 2 }\n");
    f.write("deny.toml", "[bans]\nmultiple-versions = \"allow\"\n");
    f.commit("implementation change that also relaxes deny.toml");

    let (code, output) = f.xtask(&["quality", "policy-check", "--base", &base]);
    assert_eq!(code, 2, "protected-policy changes must exit 2 (PolicyViolation)\n{output}");
    assert!(output.contains("POLICY_CHANGE_REQUIRES_INDEPENDENT_REVIEW"), "{output}");

    let report = f.report();
    assert_eq!(report["decision"], "policy_violation");
    assert_eq!(report["decision_code"], "POLICY_CHANGE_REQUIRES_INDEPENDENT_REVIEW");
    assert_eq!(report["exit_code"], 2);
    let changes = report["protected_policy_changes"].as_array().unwrap();
    assert_eq!(changes.len(), 1, "{changes:?}");
    assert_eq!(changes[0]["path"], "deny.toml");
    assert_eq!(changes[0]["matched_pattern"], "deny.toml");
    assert_eq!(changes[0]["source"], "base+head");
}

#[test]
fn removing_a_path_from_the_protected_list_does_not_unprotect_it() {
    let f = Fixture::new("delist");
    let base = seed(&f);

    // The adversarial move: delete `deny.toml` from [protected].paths in the
    // same change that edits `deny.toml`.
    let policy = f.read(".quality/policy.toml").replace("\n  \"deny.toml\",", "");
    assert!(!policy.contains("\n  \"deny.toml\","));
    f.write(".quality/policy.toml", &policy);
    f.write("deny.toml", "[bans]\nmultiple-versions = \"allow\"\n");
    f.commit("de-list deny.toml and then edit it");

    let (code, output) = f.xtask(&["quality", "policy-check", "--base", &base]);
    assert_eq!(code, 2, "the base-SHA protected list must still govern\n{output}");

    let report = f.report();
    let paths: Vec<String> = report["protected_policy_changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["path"].as_str().unwrap().to_string())
        .collect();
    assert!(paths.contains(&"deny.toml".to_string()), "{paths:?}");
    assert!(paths.contains(&".quality/policy.toml".to_string()), "editing the policy is itself protected: {paths:?}");

    let deny =
        report["protected_policy_changes"].as_array().unwrap().iter().find(|c| c["path"] == "deny.toml").unwrap();
    assert_eq!(deny["source"], "base", "the pattern survives only because the base list is trusted");
}

#[test]
fn deleting_the_policy_file_entirely_does_not_disable_the_check() {
    let f = Fixture::new("delete-policy");
    let base = seed(&f);

    std::fs::remove_file(f.dir.join(".quality/policy.toml")).unwrap();
    f.write("deny.toml", "[bans]\nmultiple-versions = \"allow\"\n");
    f.commit("delete the policy");

    let (code, output) = f.xtask(&["quality", "policy-check", "--base", &base]);
    // The controller cannot load its own policy, so it refuses to run at all
    // rather than reporting a pass.
    assert_eq!(code, 3, "a controller that cannot load its policy is an infrastructure failure\n{output}");
    assert!(output.contains("cannot read"), "{output}");
}

#[test]
fn an_ordinary_implementation_diff_passes_policy_check() {
    let f = Fixture::new("clean");
    let base = seed(&f);

    f.write("tools/remote-wal-spike/src/lib.rs", "pub fn ok() -> u8 { 2 }\n");
    f.write("docs/readme.md", "changed\n");
    f.commit("ordinary implementation change");

    let (code, output) = f.xtask(&["quality", "policy-check", "--base", &base]);
    assert_eq!(code, 0, "an ordinary diff must pass policy-check\n{output}");

    let report = f.report();
    assert_eq!(report["decision"], "pass");
    assert!(report["protected_policy_changes"].as_array().unwrap().is_empty());
    assert_eq!(report["base_sha"], base);
    assert_eq!(report["schema"], 1);
    assert!(report["policy_digest"].as_str().unwrap().starts_with("sha256:"));
    assert!(report["toolchain_digest"].as_str().unwrap().starts_with("sha256:"));
}

#[test]
fn a_rename_into_a_documentation_directory_cannot_launder_a_protected_change() {
    let f = Fixture::new("rename");
    let base = seed(&f);

    std::fs::rename(f.dir.join("deny.toml"), f.dir.join("docs/deny.toml")).unwrap();
    f.commit("move deny.toml under docs/");

    let (code, output) = f.xtask(&["quality", "policy-check", "--base", &base]);
    assert_eq!(code, 2, "the old path of a rename is still judged\n{output}");
    let report = f.report();
    let paths: Vec<String> = report["protected_policy_changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["path"].as_str().unwrap().to_string())
        .collect();
    assert!(paths.contains(&"deny.toml".to_string()), "{paths:?}");
}

// ---------------------------------------------------------------------------
// Scope, waivers, tools and report integrity.
// ---------------------------------------------------------------------------

#[test]
fn a_new_unclassified_source_directory_is_a_quality_failure() {
    let f = Fixture::new("unclassified");
    let base = seed(&f);
    f.write("newservice/src/main.rs", "fn main() {}\n");
    f.commit("add an unmapped source tree");

    let (code, output) = f.xtask(&["quality", "policy-check", "--base", &base]);
    assert_eq!(code, 1, "an unclassified source path is a quality failure\n{output}");
    let report = f.report();
    assert_eq!(report["scope"]["unclassified"][0], "newservice/src/main.rs");
    assert_eq!(report["decision"], "quality_failure");
}

#[test]
fn an_expired_waiver_fails_the_run() {
    let f = Fixture::new("expired-waiver");
    let base = seed(&f);
    f.write(
        ".quality/waivers/quality-waivers.toml",
        r##"
schema = 1
[[waiver]]
id = "QW-0001"
kind = "mutation-equivalent"
path = "tools/remote-wal-spike/src/lib.rs"
reason = "Mutant changes an internal representation with no observable semantic difference."
owner = "architecture"
approved_by = "human-technical-owner"
issue = "#1234"
created = "2020-01-01"
review_after = "2020-06-01"
"##,
    );
    f.commit("add an expired waiver");

    let (code, output) = f.xtask(&["quality", "policy-check", "--base", &base]);
    // The waiver register is protected policy, so the policy violation is
    // reported first; the expired waiver is nonetheless recorded.
    assert_eq!(code, 2, "{output}");
    let report = f.report();
    assert_eq!(report["waivers"]["expired"], 1);
    assert_eq!(report["waivers"]["active"], 0);
    let waiver_gate = report["gates"].as_array().unwrap().iter().find(|g| g["id"] == "policy.waivers").unwrap().clone();
    assert_eq!(waiver_gate["status"], "quality_failure", "{waiver_gate}");
}

#[test]
fn a_waiver_missing_a_reason_fails_the_run() {
    let f = Fixture::new("waiver-no-reason");
    let base = seed(&f);
    f.write(
        ".quality/waivers/quality-waivers.toml",
        r##"
schema = 1
[[waiver]]
id = "QW-0002"
kind = "mutation-equivalent"
path = "tools/remote-wal-spike/src/lib.rs"
owner = "architecture"
approved_by = "human-technical-owner"
issue = "#1234"
created = "2026-08-01"
review_after = "2026-12-01"
"##,
    );
    f.commit("add a waiver with no reason");

    let (_, _) = f.xtask(&["quality", "policy-check", "--base", &base]);
    let report = f.report();
    assert_eq!(report["waivers"]["invalid"], 1);
    let problems = report["waivers"]["entries"][0]["problems"].as_array().unwrap();
    assert!(problems.iter().any(|p| p.as_str().unwrap().contains("missing mandatory field `reason`")), "{problems:?}");
}

#[test]
fn the_report_records_absent_tools_as_infrastructure_failures_with_remediation() {
    let f = Fixture::new("absent-tools");
    let base = seed(&f);
    f.write("tools/remote-wal-spike/src/lib.rs", "pub fn ok() -> u8 { 3 }\n");
    f.commit("touch production rust");

    let (_, _) = f.xtask(&["quality", "policy-check", "--base", &base]);
    let report = f.report();
    let nextest = report["tools"].as_array().unwrap().iter().find(|t| t["name"] == "cargo-nextest").unwrap().clone();
    assert_eq!(nextest["status"], "absent");
    assert_eq!(nextest["detected_version"], serde_json::Value::Null);
    assert_eq!(nextest["remediation"], "cargo install --locked cargo-nextest@0.9.143");
}

#[test]
fn verify_report_refuses_a_report_produced_for_a_different_sha() {
    let f = Fixture::new("verify");
    let base = seed(&f);
    f.write("docs/readme.md", "second\n");
    f.commit("second");

    let (code, _) = f.xtask(&["quality", "policy-check", "--base", &base]);
    assert_eq!(code, 0);

    // The report certifies the current HEAD.
    let (code, output) = f.xtask(&["quality", "verify-report"]);
    assert_eq!(code, 0, "{output}");
    assert!(output.contains("verify-report       pass"), "{output}");

    // Move HEAD on. The same report must now be refused.
    f.write("docs/readme.md", "third\n");
    f.commit("third");
    let (code, output) = f.xtask(&["quality", "verify-report"]);
    assert_eq!(code, 1, "a report for another SHA is not evidence\n{output}");
    assert!(output.contains("different SHA"), "{output}");
}

#[test]
fn verify_report_refuses_a_report_whose_policy_digest_no_longer_matches() {
    let f = Fixture::new("verify-digest");
    let base = seed(&f);
    f.write("docs/readme.md", "second\n");
    f.commit("second");
    assert_eq!(f.xtask(&["quality", "policy-check", "--base", &base]).0, 0);

    // Tamper with the report rather than the tree, the way a forged handoff
    // would.
    let mut report: serde_json::Value = f.report();
    report["policy_digest"] = serde_json::Value::String("sha256:".to_string() + &"0".repeat(64));
    f.write("artifacts/quality/quality-report.json", &serde_json::to_string_pretty(&report).unwrap());

    let (code, output) = f.xtask(&["quality", "verify-report"]);
    assert_eq!(code, 1, "{output}");
    assert!(output.contains("policy digest"), "{output}");
}

#[test]
fn the_report_conforms_to_the_published_schema_key_set() {
    let f = Fixture::new("schema");
    let base = seed(&f);
    f.write("docs/readme.md", "second\n");
    f.commit("second");
    assert_eq!(f.xtask(&["quality", "policy-check", "--base", &base]).0, 0);

    let report = f.report();
    let schema: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(repo_under_test().join(".quality/schemas/quality-report.schema.json")).unwrap(),
    )
    .unwrap();

    let required = schema["required"].as_array().unwrap();
    for key in required {
        let key = key.as_str().unwrap();
        assert!(report.get(key).is_some(), "report is missing required key `{key}`");
    }
    let allowed: Vec<&str> = schema["properties"].as_object().unwrap().keys().map(|k| k.as_str()).collect();
    for key in report.as_object().unwrap().keys() {
        assert!(allowed.contains(&key.as_str()), "report has key `{key}` that the schema does not allow");
    }
}

#[test]
fn the_diff_to_gate_matrix_selects_gates_from_the_diff_not_from_a_guess() {
    let f = Fixture::new("matrix");
    let base = seed(&f);
    f.write("tools/remote-wal-spike/src/lib.rs", "pub unsafe fn danger(p: *mut u8) -> u8 { *p }\n");
    f.commit("unsafe production change");

    let (_, _) = f.xtask(&["quality", "pr", "--base", &base]);
    let report = f.report();
    let selected: Vec<String> =
        report["selected_gates"].as_array().unwrap().iter().map(|g| g["id"].as_str().unwrap().to_string()).collect();
    for want in ["rust.coverage", "rust.crap", "rust.mutation.diff", "rust.miri", "rust.fuzz.smoke", "policy.protected"]
    {
        assert!(selected.contains(&want.to_string()), "expected `{want}` in {selected:?}");
    }
    // Every selection records the matrix row responsible for it.
    for g in report["selected_gates"].as_array().unwrap() {
        assert!(!g["matrix_row"].as_str().unwrap().is_empty());
        assert!(!g["reason"].as_str().unwrap().is_empty());
    }
}

#[test]
fn a_documentation_only_diff_selects_no_language_gate_beyond_tier_a() {
    let f = Fixture::new("docs-only");
    let base = seed(&f);
    f.write("docs/readme.md", "docs only\n");
    f.commit("docs");

    let (_, _) = f.xtask(&["quality", "pr", "--base", &base]);
    let report = f.report();
    let selected: Vec<String> =
        report["selected_gates"].as_array().unwrap().iter().map(|g| g["id"].as_str().unwrap().to_string()).collect();
    for unwanted in ["rust.coverage", "rust.crap", "rust.mutation.diff", "ts.typecheck", "py.ruff.check"] {
        assert!(!selected.contains(&unwanted.to_string()), "`{unwanted}` must not fire for a docs-only diff");
    }
}

#[test]
fn an_unknown_base_revision_is_an_infrastructure_failure_not_an_empty_diff() {
    let f = Fixture::new("bad-base");
    seed(&f);
    let (code, output) = f.xtask(&["quality", "policy-check", "--base", "0000000000000000000000000000000000000000"]);
    assert_eq!(code, 3, "{output}");
    assert!(output.contains("cannot resolve base revision"), "{output}");
}

#[test]
fn pr_and_policy_check_require_a_base_sha() {
    let f = Fixture::new("no-base");
    seed(&f);
    for mode in ["pr", "policy-check"] {
        let (code, output) = f.xtask(&["quality", mode]);
        assert_eq!(code, 3, "{output}");
        assert!(output.contains("requires --base"), "{output}");
    }
}
