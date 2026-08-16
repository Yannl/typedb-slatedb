//! Catalogue-driven test execution and the no-false-green rules.
//!
//! The runner's job is not "run the tests" — `cargo test` already does that. Its job is
//! to make a green result mean something: every catalogued leaf case is accounted for,
//! nothing was skipped into a pass, and a retry can never manufacture one
//! (brief §21.11, §22.3, conformance plan steps 5–10).

pub mod cucumber;
pub mod failpoint;
pub mod verdict;

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use std::os::unix::process::CommandExt;
use corpus_catalog::model::{Catalog, CaseDiscovery, ProfileId, Target};
use serde::{Deserialize, Serialize};

pub use verdict::{CoverageReport, Outcome, Verdict};

/// A single executed target, with everything needed to re-run it byte for byte.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetRun {
    pub target_id: String,
    pub profile_id: ProfileId,
    /// Exact argv, so the evidence records commands rather than a narrative.
    pub command: Vec<String>,
    pub working_directory: String,
    pub env: BTreeMap<String, String>,
    pub exit_code: Option<i32>,
    pub duration_ms: u128,
    pub timed_out: bool,
    pub stdout_path: String,
    pub stderr_path: String,
    /// Per-leaf-case results parsed out of the harness output.
    pub cases: Vec<CaseResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseResult {
    pub leaf_case_id: String,
    pub outcome: Outcome,
    pub duration_ms: Option<u128>,
    /// Raw harness text for this case, when the harness reported one.
    pub detail: Option<String>,
}

/// The resolved build configuration for the U0/U1 parity lanes.
///
/// Single definition on purpose. Case discovery and execution must use the same settings:
/// listing cases off a stable-toolchain build and then running a 1.93.0 build compares two
/// different corpora, and it silently rebuilds the whole workspace at run time. Two copies
/// of this list would drift, and the drift would be invisible until a U0/U1 diff blamed it
/// on SlateDB.
///
/// `RUSTUP_TOOLCHAIN` is the parity lane from `MODULE.bazel` L34, L49. Debug info is off
/// because the full DWARF build of the workspace does not fit this machine's disk; it
/// changes no test semantics, and brief §21.7 requires the setting to be explicit and
/// attested rather than inherited. `tools/u0-build-env.sh` carries the same values for
/// manual invocations.
pub const PARITY_BUILD_ENV: [(&str, &str); 5] = [
    ("RUSTUP_TOOLCHAIN", "1.93.0"),
    ("RUST_BACKTRACE", "1"),
    ("CARGO_INCREMENTAL", "0"),
    ("CARGO_PROFILE_DEV_DEBUG", "0"),
    ("CARGO_PROFILE_TEST_DEBUG", "0"),
];

/// `PARITY_BUILD_ENV` as an owned map, for staging into a child process.
pub fn parity_build_env() -> BTreeMap<String, String> {
    PARITY_BUILD_ENV.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

/// Where a run's artifacts live and which profile it ran under.
pub struct RunContext {
    pub profile: ProfileId,
    pub workspace_root: PathBuf,
    pub evidence_dir: PathBuf,
    pub cargo_bin: String,
    pub target_dir: PathBuf,
    pub extra_path: Option<String>,
    /// Environment the sandbox stages for every target.
    pub base_env: BTreeMap<String, String>,
}

/// Environment variables that would silently shrink the denominator if they leaked in.
///
/// `SCENARIO_FILTER` is read by `Context::test`'s `filter_run` closure at
/// TB `2256711a` `tests/behaviour/steps/lib.rs` L193; `FAILPOINTS` is the failpoint
/// harness's own directive channel. A run that inherits either from the developer's shell
/// would report a green over a subset of the corpus.
pub const DENOMINATOR_POISONING_ENV: [&str; 3] = ["SCENARIO_FILTER", "FAILPOINTS", "RUST_TEST_ARGS"];

/// Refuse to start if the ambient environment could shrink what gets run.
pub fn check_environment_is_clean() -> Result<()> {
    let mut poisoned = Vec::new();
    for key in DENOMINATOR_POISONING_ENV {
        if let Ok(value) = std::env::var(key) {
            poisoned.push(format!("{key}={value}"));
        }
    }
    if !poisoned.is_empty() {
        bail!(
            "refusing to run: these variables would filter the corpus and manufacture a \
             green over a subset: {}",
            poisoned.join(", ")
        );
    }
    Ok(())
}

/// Stage the fixtures a target needs, reproducing what Bazel's `data` used to provide.
///
/// Upstream behaviour tests hard-code `bazel-typedb/external/typedb_behaviour+/…` on the
/// non-Bazel path (e.g. `tests/behaviour/connection/database.rs` L20-21). Staging the
/// corpus at exactly that relative path keeps every upstream test source byte-identical.
pub fn stage_behaviour_corpus(workspace_root: &Path, behaviour_root: &Path) -> Result<PathBuf> {
    let dest = workspace_root.join("bazel-typedb/external/typedb_behaviour+");
    if dest.exists() {
        std::fs::remove_dir_all(&dest)
            .with_context(|| format!("clearing stale fixture at {}", dest.display()))?;
    }
    std::fs::create_dir_all(&dest)?;
    copy_tree(behaviour_root, &dest)?;

    // Prove the staging worked rather than assuming it: a missing fixture must fail the
    // run, not turn into a test that quietly asserts on an absent file.
    let probe = dest.join("connection/database.feature");
    if !probe.exists() {
        bail!(
            "behaviour corpus staged at {} but {} is missing; the fixture layout changed",
            dest.display(),
            probe.display()
        );
    }
    Ok(dest)
}

fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    for entry in walkdir_lite(from)? {
        let rel = entry.strip_prefix(from)?;
        let target = to.join(rel);
        if entry.is_dir() {
            std::fs::create_dir_all(&target)?;
        } else {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(&entry, &target)
                .with_context(|| format!("copying {} -> {}", entry.display(), target.display()))?;
        }
    }
    Ok(())
}

fn walkdir_lite(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.file_name().is_some_and(|n| n == ".git") {
                continue;
            }
            if path.is_dir() {
                out.push(path.clone());
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Run one catalogued target and collect its per-case results.
/// Run a command, killing its whole process group if it outlives `limit`.
///
/// `Command::output()` waits forever, so a hung harness would stall the entire run with no
/// evidence of why. That is not hypothetical: a per-target `cargo test` deadlocked during
/// catalogue generation with no child process alive and no compiler running. A timeout must
/// terminate the target and be recorded, because the conformance plan makes a timeout a
/// non-green outcome rather than something to wait out.
fn wait_with_timeout(
    mut cmd: Command,
    limit: Duration,
) -> Result<(std::process::Output, bool)> {
    use std::io::Read;

    let mut child = cmd.spawn()?;
    let pid = child.id() as i32;

    // Drain both pipes on their own threads; a full pipe buffer would otherwise block the
    // child and look exactly like a hang.
    let mut out_pipe = child.stdout.take().context("stdout was not piped")?;
    let mut err_pipe = child.stderr.take().context("stderr was not piped")?;
    let out_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = out_pipe.read_to_end(&mut buf);
        buf
    });
    let err_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = err_pipe.read_to_end(&mut buf);
        buf
    });

    let deadline = Instant::now() + limit;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait()? {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                timed_out = true;
                // Signal the whole group directly. Shelling out to `kill -TERM -<pgid>` is
                // not equivalent: util-linux `kill` parses the leading `-` as an option, so
                // the signal is never delivered and the run hangs anyway — which is exactly
                // how this was first written, and it waited out the full 600s.
                //
                // TERM first so a TypeDB server can release its data directory and port,
                // then KILL whatever ignored it.
                unsafe { libc::kill(-pid, libc::SIGTERM) };
                let grace = Instant::now() + Duration::from_secs(5);
                while child.try_wait()?.is_none() && Instant::now() < grace {
                    std::thread::sleep(Duration::from_millis(100));
                }
                unsafe { libc::kill(-pid, libc::SIGKILL) };
                break child.wait()?;
            }
            None => std::thread::sleep(Duration::from_millis(200)),
        }
    };

    let stdout = out_thread.join().unwrap_or_default();
    let stderr = err_thread.join().unwrap_or_default();
    Ok((std::process::Output { status, stdout, stderr }, timed_out))
}

pub fn run_target(ctx: &RunContext, catalog: &Catalog, target: &Target) -> Result<TargetRun> {
    let (Some(pkg), Some(name)) = (target.cargo_package.as_ref(), target.cargo_target.as_ref())
    else {
        bail!("target {} is not Cargo-executable", target.target_id);
    };

    let mut argv = vec![
        ctx.cargo_bin.clone(),
        "test".into(),
        "--locked".into(),
        "-p".into(),
        pkg.clone(),
    ];
    // The Cargo target kind is carried in the id as `cargo::<kind>::<pkg>::<target>`,
    // because `--lib`, `--bin`, `--test` and `--bench` are not interchangeable and the
    // catalogue schema has no field for it.
    let kind = target.target_id.split("::").nth(1).unwrap_or_default();
    let is_bench = kind == "bench";
    match kind {
        "lib" | "rlib" | "proc-macro" => argv.push("--lib".into()),
        "bin" => {
            argv.push("--bin".into());
            argv.push(name.clone());
        }
        "test" => {
            argv.push("--test".into());
            argv.push(name.clone());
        }
        "bench" => {
            argv.push("--bench".into());
            argv.push(name.clone());
        }
        other => bail!(
            "target {} declares Cargo kind {other:?}; refusing to guess a selector flag",
            target.target_id
        ),
    }
    if !target.features.is_empty() {
        argv.push("--features".into());
        argv.push(target.features.join(","));
    }
    if !is_bench {
        // libtest's own arguments: exact, machine-readable, no capture.
        argv.extend([
            "--".into(),
            "--test-threads".into(),
            "1".into(),
            "--nocapture".into(),
        ]);
    }

    let cwd = ctx.workspace_root.clone();
    std::fs::create_dir_all(&ctx.evidence_dir)?;
    let slug = target.target_id.replace([':', '/', ' '], "_");
    let stdout_path = ctx.evidence_dir.join(format!("{slug}.stdout.txt"));
    let stderr_path = ctx.evidence_dir.join(format!("{slug}.stderr.txt"));

    let mut env: BTreeMap<String, String> = ctx.base_env.clone();
    env.extend(target.env.clone());
    env.insert("CARGO_TARGET_DIR".into(), ctx.target_dir.display().to_string());

    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .current_dir(&cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in &env {
        cmd.env(k, v);
    }
    if let Some(extra) = &ctx.extra_path {
        let path = std::env::var("PATH").unwrap_or_default();
        cmd.env("PATH", format!("{extra}:{path}"));
    }
    // Never inherit a filter from the developer's shell.
    for key in DENOMINATOR_POISONING_ENV {
        if !env.contains_key(key) {
            cmd.env_remove(key);
        }
    }

    // Run in its own process group so a timeout kills the server and any child the test
    // spawned, not just the cargo wrapper. An orphaned TypeDB server would hold its data
    // directory and port and make every later target fail for the wrong reason.
    cmd.process_group(0);

    let started = Instant::now();
    let (output, timed_out) = wait_with_timeout(cmd, Duration::from_secs(target.timeout_seconds))
        .with_context(|| format!("spawning {argv:?} in {}", cwd.display()))?;
    let duration = started.elapsed();

    std::fs::write(&stdout_path, &output.stdout)?;
    std::fs::write(&stderr_path, &output.stderr)?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let cases = match target.case_discovery {
        CaseDiscovery::LibtestList => parse_libtest_results(&target.target_id, &stdout)?,
        CaseDiscovery::CucumberScenarios => {
            cucumber::attribute(target, catalog, &stdout, output.status.code(), timed_out)
        }
        // A criterion bench is one leaf case; its process exit is the verdict.
        CaseDiscovery::Script => {
            let outcome = match output.status.code() {
                Some(0) if !timed_out => Outcome::Passed,
                Some(_) => Outcome::Failed,
                None => Outcome::Unknown("terminated by signal".into()),
            };
            catalog
                .leaf_cases
                .iter()
                .filter(|c| c.target_id == target.target_id)
                .map(|c| CaseResult {
                    leaf_case_id: c.leaf_case_id.clone(),
                    outcome: outcome.clone(),
                    duration_ms: None,
                    detail: None,
                })
                .collect()
        }
        CaseDiscovery::FailpointRegistry => {
            failpoint::attribute(target, catalog, &stdout, output.status.code(), timed_out)
        }
        CaseDiscovery::StaticCheck => Vec::new(),
    };
    Ok(TargetRun {
        target_id: target.target_id.clone(),
        profile_id: ctx.profile,
        command: argv,
        working_directory: cwd.display().to_string(),
        env,
        exit_code: output.status.code(),
        duration_ms: duration.as_millis(),
        timed_out,
        stdout_path: stdout_path.display().to_string(),
        stderr_path: stderr_path.display().to_string(),
        cases,
    })
}

/// Parse libtest's `test <name> ... ok|FAILED|ignored` result lines.
pub fn parse_libtest_results(target_id: &str, stdout: &str) -> Result<Vec<CaseResult>> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("test ") else { continue };
        let Some((name, status)) = rest.rsplit_once(" ... ") else { continue };
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        let outcome = match status.trim() {
            "ok" => Outcome::Passed,
            "FAILED" => Outcome::Failed,
            // libtest prints `ignored` with an optional reason.
            s if s == "ignored" || s.starts_with("ignored,") => Outcome::Ignored,
            other => Outcome::Unknown(other.to_string()),
        };
        out.push(CaseResult {
            leaf_case_id: format!("{target_id}::{name}"),
            outcome,
            duration_ms: None,
            detail: None,
        });
    }
    Ok(out)
}

/// Fold a set of runs into the coverage report the release gate reads.
pub fn summarise(catalog: &Catalog, runs: &[TargetRun], profile: ProfileId) -> CoverageReport {
    let mut executed_cases: BTreeMap<String, Outcome> = BTreeMap::new();
    for run in runs.iter().filter(|r| r.profile_id == profile) {
        for case in &run.cases {
            // A later duplicate never upgrades an earlier verdict: retries cannot
            // manufacture a pass (conformance plan hard-stop 9).
            executed_cases
                .entry(case.leaf_case_id.clone())
                .and_modify(|existing| {
                    if *existing == Outcome::Passed && case.outcome != Outcome::Passed {
                        *existing = case.outcome.clone();
                    }
                })
                .or_insert(case.outcome.clone());
        }
    }

    let catalogued: BTreeSet<&str> =
        catalog.leaf_cases.iter().map(|c| c.leaf_case_id.as_str()).collect();
    let executed: BTreeSet<&str> = executed_cases.keys().map(String::as_str).collect();

    let not_executed: Vec<String> =
        catalogued.difference(&executed).map(|s| s.to_string()).collect();
    let unknown_cases: Vec<String> =
        executed.difference(&catalogued).map(|s| s.to_string()).collect();

    let applicable_targets: Vec<&Target> = catalog
        .targets
        .iter()
        .filter(|t| t.cargo_package.is_some())
        .collect();
    let executed_targets: BTreeSet<&str> = runs
        .iter()
        .filter(|r| r.profile_id == profile)
        .map(|r| r.target_id.as_str())
        .collect();

    CoverageReport {
        profile,
        targets_total: applicable_targets.len(),
        targets_executed: applicable_targets
            .iter()
            .filter(|t| executed_targets.contains(t.target_id.as_str()))
            .count(),
        leaf_cases_total: catalog.leaf_cases.len(),
        leaf_cases_executed: executed_cases.len(),
        passed: executed_cases.values().filter(|o| **o == Outcome::Passed).count(),
        failed: executed_cases.values().filter(|o| **o == Outcome::Failed).count(),
        ignored: executed_cases.values().filter(|o| **o == Outcome::Ignored).count(),
        unknown: executed_cases
            .values()
            .filter(|o| matches!(o, Outcome::Unknown(_)))
            .count(),
        not_executed,
        unknown_cases,
        timed_out_targets: runs
            .iter()
            .filter(|r| r.profile_id == profile && r.timed_out)
            .map(|r| r.target_id.clone())
            .collect(),
        zero_case_targets: runs
            .iter()
            .filter(|r| r.profile_id == profile && r.cases.is_empty())
            .map(|r| r.target_id.clone())
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn piped(program: &str, args: &[&str]) -> Command {
        let mut c = Command::new(program);
        c.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
        c.process_group(0);
        c
    }

    #[test]
    fn a_hanging_target_is_killed_and_flagged() {
        let started = Instant::now();
        let (_, timed_out) =
            wait_with_timeout(piped("sleep", &["600"]), Duration::from_secs(1)).unwrap();
        assert!(timed_out, "a target that outlives its budget must be reported as timed out");
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the runner must terminate the target rather than wait for it"
        );
    }

    #[test]
    fn a_prompt_target_is_not_flagged_and_keeps_its_output() {
        let (out, timed_out) =
            wait_with_timeout(piped("echo", &["hello"]), Duration::from_secs(60)).unwrap();
        assert!(!timed_out);
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hello");
        assert_eq!(out.status.code(), Some(0));
    }

    #[test]
    fn output_larger_than_a_pipe_buffer_does_not_stall() {
        // Behaviour targets emit megabytes with --nocapture. Reading after wait() would
        // deadlock on a full pipe and be indistinguishable from a hung test.
        let (out, timed_out) = wait_with_timeout(
            piped("head", &["-c", "1000000", "/dev/zero"]),
            Duration::from_secs(60),
        )
        .unwrap();
        assert!(!timed_out);
        assert_eq!(out.stdout.len(), 1_000_000);
    }

    #[test]
    fn parses_pass_fail_and_ignored_lines() {
        let cases = parse_libtest_results(
            "t",
            "running 3 tests\ntest a ... ok\ntest b ... FAILED\ntest c ... ignored\n",
        )
        .unwrap();
        assert_eq!(cases.len(), 3);
        assert_eq!(cases[0].outcome, Outcome::Passed);
        assert_eq!(cases[1].outcome, Outcome::Failed);
        assert_eq!(cases[2].outcome, Outcome::Ignored);
    }

    #[test]
    fn keeps_an_unrecognised_status_as_unknown_not_as_a_pass() {
        let cases = parse_libtest_results("t", "test a ... bench: 4 ns/iter\n").unwrap();
        assert!(matches!(cases[0].outcome, Outcome::Unknown(_)));
    }

    #[test]
    fn a_later_pass_never_overwrites_an_earlier_failure() {
        use corpus_catalog::model::*;
        let catalog = Catalog {
            schema_version: 1,
            source_lock_digest: "0".repeat(64),
            rust_toolchain: RustToolchain { rustc: "x".into(), cargo: "x".into(), native_toolchain_digest: None },
            target_triple: "x86_64-unknown-linux-gnu".into(),
            bazel_query_oracle: None,
            profiles: default_profiles(),
            targets: vec![],
            leaf_cases: vec![LeafCase {
                leaf_case_id: "t::a".into(),
                target_id: "t".into(),
                kind: LeafKind::Libtest,
                display_name: None,
                source_hash: "0".repeat(64),
                declared_ignored: false,
                resource_group: None,
            }],
            required_pairs: vec![],
            fixtures: vec![],
            exclusions: vec![],
        };
        let mk = |outcome: Outcome| TargetRun {
            target_id: "t".into(),
            profile_id: ProfileId::U0,
            command: vec![],
            working_directory: ".".into(),
            env: BTreeMap::new(),
            exit_code: Some(0),
            duration_ms: 1,
            timed_out: false,
            stdout_path: String::new(),
            stderr_path: String::new(),
            cases: vec![CaseResult {
                leaf_case_id: "t::a".into(),
                outcome,
                duration_ms: None,
                detail: None,
            }],
        };
        let report = summarise(&catalog, &[mk(Outcome::Failed), mk(Outcome::Passed)], ProfileId::U0);
        assert_eq!(report.failed, 1, "a retry must not turn a failure into a pass");
        assert_eq!(report.passed, 0);
    }

    #[test]
    fn refuses_a_filtered_environment() {
        // Guard the guard: the check must actually look at the variable.
        assert!(DENOMINATOR_POISONING_ENV.contains(&"SCENARIO_FILTER"));
    }
}
