//! Gate catalogue and execution.
//!
//! Every gate declares its tier, language, cost class, the pinned tools it
//! needs and whether it is advisory. Preconditions are checked before the gate
//! is attempted, and an unmet precondition is an `InfrastructureFailure`
//! carrying the exact remediation command — never a skip and never a pass.

use std::path::Path;
use std::time::Duration;

use super::diff::{ChangeSet, Facts, Mode};
use super::exec::{self, Cmd, Weight};
use super::policy::{Policy, ProtectedMatcher, ScopeClass};
use super::report::{GateResult, ProtectedChange, Status};
use super::scope;
use super::tools::Registry;
use super::waivers::WaiverSummary;

#[derive(Debug, Clone, Copy)]
pub struct GateDef {
    pub id: &'static str,
    pub tier: &'static str,
    pub language: Option<&'static str>,
    pub weight: Weight,
    pub tools: &'static [&'static str],
    pub advisory: bool,
}

const DEFS: &[GateDef] = &[
    // Controller self-checks.
    def("policy.protected", "B", None, Weight::Light, &[], false),
    def("policy.waivers", "A", None, Weight::Light, &[], false),
    def("policy.toolchain_pin", "A", None, Weight::Light, &[], false),
    def("policy.scope_classification", "A", None, Weight::Light, &[], false),
    // Rust, tier A.
    def("rust.fmt", "A", Some("rust"), Weight::Light, &["rustfmt"], false),
    def("rust.clippy", "A", Some("rust"), Weight::Heavy, &["clippy"], false),
    def("rust.tests", "A", Some("rust"), Weight::Heavy, &["cargo-nextest"], false),
    def("rust.deny", "A", Some("rust"), Weight::Light, &["cargo-deny"], false),
    def("rust.machete", "A", Some("rust"), Weight::Light, &["cargo-machete"], false),
    def("rust.hack.each_feature", "A", Some("rust"), Weight::Heavy, &["cargo-hack"], false),
    // Rust, tier B.
    def("rust.coverage", "B", Some("rust"), Weight::Heavy, &["cargo-llvm-cov", "cargo-nextest"], false),
    def("rust.crap", "B", Some("rust"), Weight::Heavy, &["cargo-crap"], false),
    def(
        "rust.crap.baseline",
        "B",
        Some("rust"),
        Weight::Heavy,
        &["cargo-llvm-cov", "cargo-nextest", "cargo-crap"],
        false,
    ),
    def("rust.crap_advice", "B", Some("rust"), Weight::Heavy, &["crap4rs"], true),
    def("rust.mutation.diff", "B", Some("rust"), Weight::Campaign, &["cargo-mutants", "cargo-nextest"], false),
    def("rust.miri", "B", Some("rust"), Weight::Heavy, &["miri"], false),
    def("rust.fuzz.smoke", "B", Some("rust"), Weight::Light, &[], false),
    def("rust.property_tests", "B", Some("rust"), Weight::Light, &[], true),
    def("rust.semver", "B", Some("rust"), Weight::Heavy, &["cargo-semver-checks"], false),
    def("rust.semver.not_contracted", "B", Some("rust"), Weight::Light, &[], true),
    // Rust, tier C.
    def("rust.mutation.full", "C", Some("rust"), Weight::Campaign, &["cargo-mutants", "cargo-nextest"], false),
    def("rust.hack.powerset", "C", Some("rust"), Weight::Campaign, &["cargo-hack"], false),
    def("rust.miri.full", "C", Some("rust"), Weight::Campaign, &["miri"], false),
    def("rust.fuzz.long", "C", Some("rust"), Weight::Campaign, &[], false),
    def("rust.crap.trend", "C", Some("rust"), Weight::Heavy, &["cargo-crap"], true),
    // TypeScript.
    def("ts.typecheck", "A", Some("typescript"), Weight::Light, &["tsc"], false),
    def("ts.oxlint", "A", Some("typescript"), Weight::Light, &["oxlint"], false),
    def("ts.knip", "A", Some("typescript"), Weight::Light, &["knip"], false),
    def("ts.depcruise", "A", Some("typescript"), Weight::Light, &["dependency-cruiser"], false),
    def("ts.crap", "B", Some("typescript"), Weight::Light, &["crap4ts"], true),
    def("ts.mutation", "B", Some("typescript"), Weight::Heavy, &["stryker"], false),
    // Python.
    def("py.ruff.check", "A", Some("python"), Weight::Light, &["ruff"], false),
    def("py.ruff.format", "A", Some("python"), Weight::Light, &["ruff"], false),
    def("py.typecheck", "A", Some("python"), Weight::Light, &["basedpyright"], false),
    def("py.pytest", "A", Some("python"), Weight::Light, &["pytest"], false),
    def("py.pip_audit", "B", Some("python"), Weight::Light, &["pip-audit"], false),
    def("py.crap", "B", Some("python"), Weight::Light, &["crap4py"], true),
    // Architecture and duplication.
    def("arch.rust_deps", "B", None, Weight::Light, &[], false),
    def("dup.jscpd_delta", "B", None, Weight::Light, &["jscpd"], false),
    def("dup.jscpd_full", "C", None, Weight::Light, &["jscpd"], false),
];

const fn def(
    id: &'static str,
    tier: &'static str,
    language: Option<&'static str>,
    weight: Weight,
    tools: &'static [&'static str],
    advisory: bool,
) -> GateDef {
    GateDef { id, tier, language, weight, tools, advisory }
}

pub fn definition(id: &str) -> Option<&'static GateDef> {
    DEFS.iter().find(|d| d.id == id)
}

pub fn all_definitions() -> &'static [GateDef] {
    DEFS
}

/// Everything a gate needs, assembled once per run.
pub struct Ctx<'a> {
    pub repo_root: &'a Path,
    pub policy: &'a Policy,
    pub tools: &'a Registry,
    pub mode: Mode,
    pub base_sha: Option<String>,
    pub facts: &'a Facts,
    pub changes: &'a ChangeSet,
    pub protected: &'a ProtectedMatcher,
    pub waivers: &'a WaiverSummary,
    /// Rust workspace manifests in scope for tier-A gates.
    pub rust_manifests_all: Vec<String>,
    /// Rust workspace manifests holding production code, for tier-B gates.
    pub rust_manifests_production: Vec<String>,
    pub ts_projects: Vec<String>,
    pub python_projects: Vec<String>,
    pub policy_digest: String,
    pub toolchain_digest: String,
}

impl Ctx<'_> {
    /// TypeScript project roots that carry every one of `required` (a file or
    /// directory name), so a gate is never pointed at a project that cannot
    /// meaningfully answer it.
    pub fn ts_projects_with(&self, required: &[&str]) -> Vec<String> {
        self.ts_projects
            .iter()
            .filter(|p| required.iter().all(|r| self.repo_root.join(p).join(r).exists()))
            .cloned()
            .collect()
    }
}

const ARTIFACTS: &str = "artifacts/quality";

fn slug(manifest: &str) -> String {
    manifest.trim_end_matches("/Cargo.toml").replace('/', "-")
}

/// The exact commands a gate runs. Agents never handcraft these (spec §5.6).
pub fn commands(id: &str, ctx: &Ctx) -> Vec<Cmd> {
    let mut out = Vec::new();
    match id {
        "rust.fmt" => {
            for m in &ctx.rust_manifests_all {
                out.push(Cmd::new("cargo", &["fmt", "--manifest-path", m, "--all", "--", "--check"]));
            }
        }
        "rust.clippy" => {
            for m in &ctx.rust_manifests_all {
                if overlay_of(ctx, m).is_some() {
                    // An overlay workspace is mostly upstream's code, which we
                    // may not edit (see forkowned). `-D warnings` would abort
                    // the build on the first upstream lint and gate us on code
                    // nobody here wrote, so findings are collected as JSON and
                    // judged per file after the run.
                    out.push(Cmd::new(
                        "cargo",
                        &[
                            "clippy",
                            "--manifest-path",
                            m,
                            "--workspace",
                            "--all-targets",
                            "--all-features",
                            "--message-format",
                            "json",
                        ],
                    ));
                } else {
                    out.push(Cmd::new(
                        "cargo",
                        &[
                            "clippy",
                            "--manifest-path",
                            m,
                            "--workspace",
                            "--all-targets",
                            "--all-features",
                            "--",
                            "-D",
                            "warnings",
                        ],
                    ));
                }
            }
        }
        "rust.tests" => {
            for m in &ctx.rust_manifests_all {
                out.push(Cmd::new("cargo", &["nextest", "run", "--manifest-path", m, "--workspace", "--all-features"]));
            }
        }
        "rust.deny" => {
            for m in &ctx.rust_manifests_all {
                out.push(Cmd::new("cargo", &["deny", "--manifest-path", m, "check"]));
            }
        }
        "rust.machete" => {
            // Plain binary, not the `cargo machete` subcommand form; see the
            // note on [tool.cargo-machete] in .quality/tools.lock.toml.
            for m in &ctx.rust_manifests_all {
                out.push(Cmd::new("cargo-machete", &["--with-metadata", m.trim_end_matches("/Cargo.toml")]));
            }
        }
        "rust.hack.each_feature" => {
            for m in &ctx.rust_manifests_all {
                out.push(Cmd::new("cargo", &["hack", "check", "--manifest-path", m, "--workspace", "--each-feature"]));
            }
        }
        "rust.hack.powerset" => {
            for m in &ctx.rust_manifests_all {
                out.push(Cmd::new(
                    "cargo",
                    &["hack", "check", "--manifest-path", m, "--workspace", "--feature-powerset", "--depth", "2"],
                ));
            }
        }
        "rust.coverage" => {
            for m in &ctx.rust_manifests_production {
                let lcov = format!("{ARTIFACTS}/{}.lcov", slug(m));
                out.push(Cmd::new("cargo", &["llvm-cov", "clean", "--manifest-path", m, "--workspace"]));
                out.push(Cmd::new(
                    "cargo",
                    &[
                        "llvm-cov",
                        "nextest",
                        "--manifest-path",
                        m,
                        "--workspace",
                        "--all-features",
                        "--lcov",
                        "--output-path",
                        &lcov,
                    ],
                ));
            }
        }
        "rust.crap" => {
            for m in &ctx.rust_manifests_production {
                let s = slug(m);
                let lcov = format!("{ARTIFACTS}/{s}.lcov");
                let json = format!("{ARTIFACTS}/cargo-crap-{s}.json");
                let mut args: Vec<String> = vec![
                    "crap".into(),
                    "--workspace".into(),
                    "--lcov".into(),
                    lcov.clone(),
                    "--missing".into(),
                    ctx.policy.crap.rust.missing_coverage.clone(),
                    "--format".into(),
                    "json".into(),
                    "--output".into(),
                    json,
                ];
                let dir = m.trim_end_matches("/Cargo.toml");
                out.push(Cmd::new("cargo", &args.iter().map(|s| s.as_str()).collect::<Vec<_>>()).in_dir(dir));

                // Regression comparison against the immutable trusted baseline
                // generated from the base SHA, never from the PR tree (§2.1).
                if ctx.base_sha.is_some() && ctx.policy.crap.rust.fail_regression {
                    let baseline = format!("{ARTIFACTS}/base/cargo-crap-{s}.json");
                    let delta = format!("{ARTIFACTS}/cargo-crap-delta-{s}.json");
                    args = vec![
                        "crap".into(),
                        "--workspace".into(),
                        "--lcov".into(),
                        lcov,
                        "--missing".into(),
                        ctx.policy.crap.rust.missing_coverage.clone(),
                        "--baseline".into(),
                        baseline,
                        "--fail-regression".into(),
                        "--format".into(),
                        "json".into(),
                        "--output".into(),
                        delta,
                    ];
                    out.push(Cmd::new("cargo", &args.iter().map(|s| s.as_str()).collect::<Vec<_>>()).in_dir(dir));
                }
            }
        }
        "rust.crap.trend" => {
            for m in &ctx.rust_manifests_production {
                let s = slug(m);
                out.push(
                    Cmd::new(
                        "cargo",
                        &[
                            "crap",
                            "--workspace",
                            "--lcov",
                            &format!("{ARTIFACTS}/{s}.lcov"),
                            "--missing",
                            &ctx.policy.crap.rust.missing_coverage,
                            "--format",
                            "json",
                            "--output",
                            &format!("{ARTIFACTS}/cargo-crap-trend-{s}.json"),
                        ],
                    )
                    .in_dir(m.trim_end_matches("/Cargo.toml")),
                );
            }
        }
        "rust.crap_advice" => {
            for m in &ctx.rust_manifests_production {
                out.push(
                    Cmd::new("crap4rs", &["--strict", "--format", "advice"]).in_dir(m.trim_end_matches("/Cargo.toml")),
                );
            }
        }
        "rust.mutation.diff" => {
            let diff = format!("{ARTIFACTS}/pr.diff");
            for m in &ctx.rust_manifests_production {
                out.push(Cmd::new(
                    "cargo",
                    &["mutants", "--manifest-path", m, "--workspace", "--in-diff", &diff, "--test-tool=nextest"],
                ));
            }
        }
        "rust.mutation.full" => {
            for m in &ctx.rust_manifests_production {
                out.push(Cmd::new("cargo", &["mutants", "--manifest-path", m, "--workspace", "--test-tool=nextest"]));
            }
        }
        "rust.miri" | "rust.miri.full" => {
            for m in &ctx.rust_manifests_production {
                out.push(Cmd::new("cargo", &["+nightly", "miri", "test", "--manifest-path", m, "--workspace"]));
            }
        }
        "rust.semver" => {
            for m in &ctx.rust_manifests_production {
                out.push(Cmd::new("cargo", &["semver-checks", "check-release", "--manifest-path", m, "--workspace"]));
            }
        }
        // TypeScript gates only target projects that actually carry the
        // configuration the gate needs. Pointing `tsc --noEmit` at a plain
        // ESM tooling directory with no tsconfig.json produces a usage error
        // that would be recorded as a quality failure of the code, which it is
        // not.
        "ts.typecheck" => {
            for p in ctx.ts_projects_with(&["tsconfig.json"]) {
                out.push(Cmd::new("npx", &["--no-install", "tsc", "--noEmit"]).in_dir(&p));
            }
        }
        "ts.oxlint" => {
            for p in ctx.ts_projects_with(&["package.json"]) {
                out.push(Cmd::new("npx", &["--no-install", "oxlint", "."]).in_dir(&p));
            }
        }
        "ts.knip" => {
            for p in ctx.ts_projects_with(&["package.json"]) {
                out.push(Cmd::new("npx", &["--no-install", "knip"]).in_dir(&p));
            }
        }
        "ts.depcruise" => {
            for p in ctx.ts_projects_with(&["tsconfig.json", "src"]) {
                out.push(
                    Cmd::new(
                        "npx",
                        &[
                            "--no-install",
                            "depcruise",
                            "--config",
                            "../.quality/architecture/dependency-cruiser.cjs",
                            "src",
                        ],
                    )
                    .in_dir(&p),
                );
            }
        }
        "ts.crap" => {
            for p in ctx.ts_projects_with(&["tsconfig.json"]) {
                out.push(Cmd::new("npx", &["--no-install", "crap4ts", "--format", "json"]).in_dir(&p));
            }
        }
        "ts.mutation" => {
            for p in ctx.ts_projects_with(&["package.json"]) {
                out.push(Cmd::new("npx", &["--no-install", "stryker", "run"]).in_dir(&p));
            }
        }
        "py.ruff.check" => {
            for p in &ctx.python_projects {
                out.push(Cmd::new("ruff", &["check", p]));
            }
        }
        "py.ruff.format" => {
            for p in &ctx.python_projects {
                out.push(Cmd::new("ruff", &["format", "--check", p]));
            }
        }
        "py.typecheck" => {
            for p in &ctx.python_projects {
                out.push(Cmd::new("basedpyright", &[p]));
            }
        }
        "py.pytest" => {
            for p in &ctx.python_projects {
                out.push(Cmd::new(
                    "python3",
                    &[
                        "-m",
                        "pytest",
                        p,
                        "--cov",
                        p,
                        "--cov-branch",
                        "--cov-report",
                        &format!("lcov:{ARTIFACTS}/python-{}.lcov", p.replace('/', "-")),
                    ],
                ));
            }
        }
        "py.pip_audit" => out.push(Cmd::new("pip-audit", &["--strict"])),
        "py.crap" => {
            for p in &ctx.python_projects {
                out.push(Cmd::new(
                    "crap4py",
                    &[
                        p,
                        "--lcov",
                        &format!("{ARTIFACTS}/python-{}.lcov", p.replace('/', "-")),
                        "--max-crap",
                        &ctx.policy.crap.rust.legacy_hotspot_threshold.to_string(),
                    ],
                ));
            }
        }
        "dup.jscpd_delta" | "dup.jscpd_full" => {
            out.push(Cmd::new(
                "jscpd",
                &[
                    "--reporters",
                    "json",
                    "--output",
                    &format!("{ARTIFACTS}/jscpd"),
                    "--silent",
                    "--ignore",
                    "**/node_modules/**,sources/**,target/**,artifacts/**",
                    ".",
                ],
            ));
        }
        _ => {}
    }
    out
}

/// Gates decided inside the controller rather than by an external tool.
fn is_internal(id: &str) -> bool {
    matches!(
        id,
        "policy.protected"
            | "policy.waivers"
            | "policy.toolchain_pin"
            | "policy.scope_classification"
            | "rust.fuzz.smoke"
            | "rust.fuzz.long"
            | "rust.property_tests"
            | "rust.semver.not_contracted"
            | "rust.crap.baseline"
            | "arch.rust_deps"
    )
}

/// Run one gate, preconditions first.
pub fn run(id: &str, ctx: &Ctx) -> GateResult {
    let Some(d) = definition(id) else {
        return GateResult::new(
            id,
            "?",
            None,
            false,
            Status::InfrastructureFailure,
            &format!(
            "gate `{id}` was selected by the diff-to-gate matrix but has no definition; this is a controller defect"
        ),
        );
    };

    // Does this gate have anything to act on? A gate with no in-scope target
    // is `not_applicable`; reporting a missing tool for a gate that would have
    // had nothing to check would be noise, not evidence.
    let cmds = if is_internal(id) { Vec::new() } else { commands(id, ctx) };
    if !is_internal(id) && cmds.is_empty() {
        return GateResult::new(
            id,
            d.tier,
            d.language,
            d.advisory,
            Status::NotApplicable,
            &format!("no in-scope target for `{id}`: the scope manifest selects no workspace or project for this gate"),
        );
    }

    // A gate naming a tool the lock file does not pin is a configuration
    // defect, and must not be allowed to run unpinned.
    if let Some(missing) = ctx.tools.unpinned(d.tools) {
        let mut r = GateResult::new(
            id,
            d.tier,
            d.language,
            d.advisory,
            Status::InfrastructureFailure,
            &format!("gate `{id}` requires tool `{missing}`, which is not pinned in .quality/tools.lock.toml"),
        );
        r.remediation = Some(format!(
            "add a [tool.{missing}] entry to .quality/tools.lock.toml through an independent policy review"
        ));
        return r;
    }

    // Tool presence and version. Never a silent skip, never a pass.
    if let Some(problem) = ctx.tools.first_problem(d.tools) {
        let mut r = GateResult::new(
            id,
            d.tier,
            d.language,
            d.advisory,
            Status::InfrastructureFailure,
            &format!("{} — gate `{id}` could not run", problem.problem()),
        );
        r.remediation = Some(problem.remediation.clone());
        return r;
    }

    // Build space. An ENOSPC part-way through a compile is indistinguishable
    // from a tool bug, so refuse up front and say exactly why. This applies to
    // internal gates too: the trusted-baseline gate compiles a whole worktree.
    let required = d.weight.required_free_gb(&ctx.policy.execution);
    if let Some(free) = exec::free_disk_gb(ctx.repo_root) {
        if free < required {
            let mut r = GateResult::new(
                id,
                d.tier,
                d.language,
                d.advisory,
                Status::InfrastructureFailure,
                &format!("insufficient build space: gate `{id}` needs {required:.1} GB free, {free:.1} GB available"),
            );
            r.command = cmds.first().map(|c| c.display());
            r.remediation = Some(format!(
                "free at least {:.1} GB, or run this gate on a machine with more disk; the gate was not attempted \
                 and no quality conclusion may be drawn from this run",
                required - free
            ));
            return r;
        }
    }

    if is_internal(id) {
        return internal(id, d, ctx);
    }

    let timeout = Duration::from_secs(ctx.policy.execution.gate_timeout_secs);
    let mut total_ms = 0u128;
    let mut last_command = None;
    for cmd in &cmds {
        // Per-workspace floor, checked immediately before the command that
        // builds that workspace. The single pre-gate check above uses the cost
        // class alone, and a class number cannot be right for both the tiny
        // `tools` workspace and the whole TypeDB fork: 14 GB free passed the
        // 12 GB heavy floor and then ran out at 23 GB mid-compile.
        let manifest = exec::manifest_of(cmd);
        let need = d.weight.required_free_gb_for(&ctx.policy.execution, id, manifest.as_deref());
        if let Some(free) = exec::free_disk_gb(ctx.repo_root) {
            if free < need {
                let where_ = manifest.as_deref().unwrap_or("this workspace");
                let mut r = GateResult::new(
                    id,
                    d.tier,
                    d.language,
                    d.advisory,
                    Status::InfrastructureFailure,
                    &format!(
                        "insufficient build space: gate `{id}` needs {need:.1} GB free to build \
                         {where_}, {free:.1} GB available"
                    ),
                );
                r.command = Some(cmd.display());
                r.cwd = cmd.cwd.clone();
                r.remediation = Some(format!(
                    "free at least {:.1} GB (`cargo clean` in any other build tree), or run this \
                     gate on a machine with more disk; the command was not attempted and no \
                     quality conclusion may be drawn from this run",
                    need - free
                ));
                return r;
            }
        }
        let res = exec::run(ctx.repo_root, cmd, timeout);
        total_ms += res.duration_ms;
        last_command = Some(res.command.clone());
        if res.success() {
            // A zero exit is not automatically a pass: a gate that reports in
            // its output rather than its status code is judged below.
            if let Some(fail) = judge_output(id, ctx, cmd, &res) {
                let mut r = GateResult::new(id, d.tier, d.language, d.advisory, Status::QualityFailure, &fail);
                r.command = Some(res.command);
                r.cwd = cmd.cwd.clone();
                r.exit_code = res.exit_code;
                r.duration_ms = Some(total_ms);
                return r;
            }
            continue;
        }
        let (status, detail) = if let Some(err) = &res.spawn_error {
            (Status::InfrastructureFailure, format!("could not start `{}`: {err}", res.command))
        } else if res.timed_out {
            (
                Status::InfrastructureFailure,
                format!(
                    "`{}` exceeded the {}s gate timeout and was killed",
                    res.command, ctx.policy.execution.gate_timeout_secs
                ),
            )
        } else if exec::looks_like_enospc(&res.tail(200)) {
            // The disk ran out mid-command. That is infrastructure, not a
            // statement about the code, and calling it a QualityFailure sends
            // the next reader hunting for a defect that is not there.
            (
                Status::InfrastructureFailure,
                format!(
                    "`{}` ran out of disk space (exit {}); the gate did not complete and no \
                     quality conclusion may be drawn from it\n{}",
                    res.command,
                    res.exit_code.unwrap_or(-1),
                    res.tail(25)
                ),
            )
        } else {
            (
                Status::QualityFailure,
                format!("`{}` exited {}\n{}", res.command, res.exit_code.unwrap_or(-1), res.tail(25)),
            )
        };
        let mut r = GateResult::new(id, d.tier, d.language, d.advisory, status, &detail);
        if status == Status::InfrastructureFailure && r.remediation.is_none() {
            r.remediation =
                Some("free disk space (`cargo clean` in any other build tree) and re-run the gate".to_string());
        }
        r.command = Some(res.command);
        r.cwd = cmd.cwd.clone();
        r.exit_code = res.exit_code;
        r.duration_ms = Some(total_ms);
        return r;
    }

    let mut r = GateResult::new(
        id,
        d.tier,
        d.language,
        d.advisory,
        Status::Pass,
        &format!("{} command(s) succeeded", cmds.len()),
    );
    r.command = last_command;
    r.duration_ms = Some(total_ms);
    r
}

/// Overlay workspaces: a manifest whose sources are a file overlay on a pinned
/// upstream checkout, and the checkout + lock node that pins it.
///
/// Only these workspaces get per-file lint attribution. Everything else in the
/// repository is ours end to end and is gated whole.
const OVERLAYS: &[(&str, &str, &str, &str)] = &[("fork/typedb/Cargo.toml", "fork/typedb", "sources/typedb", "TB")];

fn overlay_of<'a>(_ctx: &Ctx, manifest: &str) -> Option<&'a (&'a str, &'a str, &'a str, &'a str)> {
    OVERLAYS.iter().find(|(m, _, _, _)| *m == manifest)
}

/// One compiler diagnostic, reduced to what deciding needs.
fn diagnostic_file(msg: &serde_json::Value) -> Option<(String, String, u32)> {
    let d = msg.get("message")?;
    let level = d.get("level")?.as_str()?;
    if level != "warning" && level != "error" {
        return None;
    }
    let code = d.get("code").and_then(|c| c.get("code")).and_then(|c| c.as_str()).unwrap_or("").to_string();
    let span =
        d.get("spans")?.as_array()?.iter().find(|s| s.get("is_primary").and_then(|b| b.as_bool()).unwrap_or(false))?;
    let file = span.get("file_name")?.as_str()?.to_string();
    let line = span.get("line_start").and_then(|l| l.as_u64()).unwrap_or(0) as u32;
    Some((file, format!("{code}{}{line}", if code.is_empty() { "" } else { ":" }), line))
}

/// Judge a gate that reports in its OUTPUT rather than its exit code.
///
/// Returns `Some(detail)` when the gate should fail. `None` means it passed.
fn judge_output(id: &str, ctx: &Ctx, cmd: &Cmd, res: &exec::CmdResult) -> Option<String> {
    if id != "rust.clippy" {
        return None;
    }
    let manifest = exec::manifest_of(cmd)?;
    let (_, fork_root, upstream, node) = overlay_of(ctx, &manifest)?;
    let owned = match super::forkowned::detect(ctx.repo_root, fork_root, upstream, node) {
        Ok(o) => o,
        // Ownership cannot be derived, so nothing can be attributed. Refusing
        // is the only honest answer: silently gating everything would fail on
        // upstream's code, and silently gating nothing would be a false pass.
        Err(e) => return Some(format!("cannot determine which {fork_root} files are ours: {e}")),
    };
    let (ours, upstream_hits) = attribute_clippy(&res.stdout, &owned);
    if ours.is_empty() {
        return None;
    }
    let shown: Vec<String> = ours.iter().take(20).cloned().collect();
    Some(format!(
        "{} clippy finding(s) in files this fork owns ({} owned, {} identical to the pinned \
         upstream revision and therefore not gated; {} finding(s) fell in those upstream files \
         and were not counted):\n{}{}",
        ours.len(),
        owned.len(),
        owned.upstream_identical,
        upstream_hits,
        shown.join("\n"),
        if ours.len() > shown.len() { format!("\n  … and {} more", ours.len() - shown.len()) } else { String::new() }
    ))
}

/// Split clippy's JSON stream into findings we own and findings we do not.
///
/// Pure, so the attribution rule can be tested directly rather than only
/// through a whole gate run: getting this wrong in either direction is severe.
/// Too broad and we gate on upstream's code; too narrow and our own defects
/// pass silently.
fn attribute_clippy(stdout: &str, owned: &super::forkowned::ForkOwnership) -> (Vec<String>, usize) {
    let mut ours: Vec<String> = Vec::new();
    let mut upstream_hits = 0usize;
    let mut seen = std::collections::BTreeSet::new();
    for line in stdout.lines() {
        let Ok(msg) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        if msg.get("reason").and_then(|r| r.as_str()) != Some("compiler-message") {
            continue;
        }
        let Some((file, tag, line)) = diagnostic_file(&msg) else { continue };
        if !seen.insert(format!("{file}|{tag}")) {
            continue;
        }
        // Absolute paths are generated build output (OUT_DIR), never ours.
        // Attribution is per LINE, not per file: a finding on a line the fork
        // did not write is upstream's, however heavily the fork edited the
        // rest of that file.
        if file.starts_with('/') || !owned.owns_line(&file, line) {
            upstream_hits += 1;
            continue;
        }
        let rendered = msg
            .get("message")
            .and_then(|m| m.get("rendered"))
            .and_then(|r| r.as_str())
            .unwrap_or("")
            .lines()
            .next()
            .unwrap_or("")
            .to_string();
        ours.push(format!("  {file} — {rendered}"));
    }
    (ours, upstream_hits)
}

/// Protected-path hits for the current change set, with provenance.
pub fn protected_changes(ctx: &Ctx) -> Vec<ProtectedChange> {
    let mut out = Vec::new();
    for entry in &ctx.changes.entries {
        for path in entry.paths() {
            if let Some(hit) = ctx.protected.hit(path) {
                if !out.iter().any(|c: &ProtectedChange| c.path == hit.path) {
                    out.push(ProtectedChange {
                        path: hit.path,
                        status: entry.status.clone(),
                        matched_pattern: hit.matched_pattern,
                        source: hit.source.to_string(),
                    });
                }
            }
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

fn internal(id: &str, d: &GateDef, ctx: &Ctx) -> GateResult {
    match id {
        "policy.protected" => {
            let hits = protected_changes(ctx);
            if hits.is_empty() {
                return GateResult::new(
                    id,
                    d.tier,
                    d.language,
                    d.advisory,
                    Status::Pass,
                    &format!(
                        "no protected quality-policy path is touched by {}..HEAD",
                        ctx.base_sha.clone().unwrap_or_else(|| "<worktree>".into())
                    ),
                );
            }
            let listing = hits
                .iter()
                .map(|h| format!("  {} {}  (matched `{}`, from {})", h.status, h.path, h.matched_pattern, h.source))
                .collect::<Vec<_>>()
                .join("\n");
            let mut r = GateResult::new(
                id,
                d.tier,
                d.language,
                d.advisory,
                Status::PolicyViolation,
                &format!(
                    "{}\n{} protected quality-policy path(s) changed by this diff:\n{listing}",
                    super::report::POLICY_VIOLATION_CODE,
                    hits.len()
                ),
            );
            r.remediation = Some(
                "A normal implementation task may not modify quality policy. Split the policy change into its own \
                 change set and route it through independent review. Removing the path from the protected list is \
                 not a remedy: the list is read from the trusted base SHA."
                    .to_string(),
            );
            r
        }
        "policy.waivers" => {
            if ctx.waivers.is_clean() {
                GateResult::new(
                    id,
                    d.tier,
                    d.language,
                    d.advisory,
                    Status::Pass,
                    &format!(
                        "{} waiver(s) registered, {} active, none expired or malformed",
                        ctx.waivers.total, ctx.waivers.active
                    ),
                )
            } else {
                GateResult::new(
                    id,
                    d.tier,
                    d.language,
                    d.advisory,
                    Status::QualityFailure,
                    &format!(
                        "{} expired and {} malformed waiver(s):\n{}",
                        ctx.waivers.expired,
                        ctx.waivers.invalid,
                        ctx.waivers.problem_summary()
                    ),
                )
            }
        }
        "policy.toolchain_pin" => {
            let names = ["rustc", "cargo", "node", "python"];
            let bad: Vec<&super::tools::ToolReport> =
                names.iter().filter_map(|n| ctx.tools.get(n)).filter(|r| !r.status.is_ok()).collect();
            if bad.is_empty() {
                let listing = names
                    .iter()
                    .filter_map(|n| ctx.tools.get(n))
                    .map(|r| format!("{}={}", r.name, r.detected_version.clone().unwrap_or_default()))
                    .collect::<Vec<_>>()
                    .join(" ");
                GateResult::new(
                    id,
                    d.tier,
                    d.language,
                    d.advisory,
                    Status::Pass,
                    &format!("toolchain matches the pins: {listing}"),
                )
            } else {
                let mut r = GateResult::new(
                    id,
                    d.tier,
                    d.language,
                    d.advisory,
                    Status::InfrastructureFailure,
                    &format!(
                        "pinned toolchain mismatch:\n{}",
                        bad.iter().map(|r| format!("  {}", r.problem())).collect::<Vec<_>>().join("\n")
                    ),
                );
                r.remediation = Some(bad.iter().map(|r| r.remediation.clone()).collect::<Vec<_>>().join(" ; "));
                r
            }
        }
        "policy.scope_classification" => {
            if ctx.facts.unclassified.is_empty() {
                GateResult::new(
                    id,
                    d.tier,
                    d.language,
                    d.advisory,
                    Status::Pass,
                    &format!(
                        "all {} changed path(s) are classified by the scope manifest",
                        ctx.changes.all_paths().len()
                    ),
                )
            } else if !ctx.policy.execution.fail_on_unclassified_source {
                GateResult::new(id, d.tier, d.language, d.advisory, Status::QualityFailure, &format!(
                    "{} unclassified source path(s); [execution].fail_on_unclassified_source is false, which is itself reported",
                    ctx.facts.unclassified.len()
                ))
            } else {
                let mut r = GateResult::new(id, d.tier, d.language, d.advisory, Status::QualityFailure, &format!(
                    "{} changed source path(s) match no [[scope.rule]], so no gate tier can be selected for them:\n  {}",
                    ctx.facts.unclassified.len(),
                    ctx.facts.unclassified.join("\n  ")
                ));
                r.remediation = Some(
                    "Add a [[scope.rule]] covering these paths to .quality/policy.toml through an independent policy \
                     review, declaring whether they are production or tooling."
                        .to_string(),
                );
                r
            }
        }
        "rust.semver.not_contracted" => GateResult::new(
            id,
            d.tier,
            d.language,
            d.advisory,
            Status::NotApplicable,
            &format!(
                "the diff changes a public Rust API, but no crate here declares a compatibility contract: {}",
                ctx.policy.triggers.public_api.compatibility_contract_reason
            ),
        ),
        "rust.fuzz.smoke" | "rust.fuzz.long" => {
            let targets: Vec<String> = ctx
                .rust_manifests_production
                .iter()
                .filter(|m| ctx.repo_root.join(m.trim_end_matches("/Cargo.toml")).join("fuzz").is_dir())
                .cloned()
                .collect();
            if targets.is_empty() {
                let mut r = GateResult::new(id, d.tier, d.language, d.advisory, Status::QualityFailure, &format!(
                    "the diff touches a fuzz-critical or unsafe/FFI surface, but no cargo-fuzz target is declared in any \
                     in-scope workspace ({})",
                    ctx.rust_manifests_production.join(", ")
                ));
                r.remediation = Some(
                    "add a durable cargo-fuzz target for the changed parser/codec/protocol/storage surface (§5.8), or \
                     record an independently approved waiver of kind `coverage-exclusion`"
                        .to_string(),
                );
                r
            } else {
                GateResult::new(
                    id,
                    d.tier,
                    d.language,
                    d.advisory,
                    Status::NotApplicable,
                    &format!("fuzz targets exist in {}; running them is Phase 2 work", targets.join(", ")),
                )
            }
        }
        "rust.property_tests" => {
            let has_proptest = ctx.rust_manifests_production.iter().any(|m| {
                std::fs::read_to_string(ctx.repo_root.join(m)).map(|t| t.contains("proptest")).unwrap_or(false)
            });
            let status = if has_proptest { Status::Pass } else { Status::QualityFailure };
            GateResult::new(
                id,
                d.tier,
                d.language,
                d.advisory,
                status,
                &format!(
                "property tests are strongly expected on this surface (§5.7); proptest {} declared in the in-scope \
                 workspaces. This gate is advisory until Phase 2.",
                if has_proptest { "is" } else { "is not" }
            ),
            )
        }
        "rust.crap.baseline" => crap_baseline(id, d, ctx),
        "arch.rust_deps" => arch_rust_deps(id, d, ctx),
        _ => GateResult::new(
            id,
            d.tier,
            d.language,
            d.advisory,
            Status::InfrastructureFailure,
            &format!("internal gate `{id}` has no implementation; this is a controller defect"),
        ),
    }
}

/// Generate the trusted CRAP baseline from the exact base SHA (spec §2.1).
///
/// The baseline is produced in an isolated detached worktree, with the same
/// tool versions, feature set, coverage command, exclusions and policy as the
/// head run, and cached under a key of `(base_sha, policy_digest,
/// toolchain_digest)`. The Builder never generates or modifies the baseline
/// from its own checkout.
fn crap_baseline(id: &str, d: &GateDef, ctx: &Ctx) -> GateResult {
    let Some(base) = ctx.base_sha.clone() else {
        return GateResult::new(
            id,
            d.tier,
            d.language,
            d.advisory,
            Status::NotApplicable,
            &format!("no base SHA: `{id}` only applies to a merge-gate run"),
        );
    };
    let short = |s: &str| s.trim_start_matches("sha256:").chars().take(12).collect::<String>();
    let key = format!("{}-{}-{}", &base[..12], short(&ctx.policy_digest), short(&ctx.toolchain_digest));
    let cache_rel = format!("{ARTIFACTS}/base/{key}");
    let cache_dir = ctx.repo_root.join(&cache_rel);
    let out_dir = ctx.repo_root.join(ARTIFACTS).join("base");

    let expected: Vec<String> =
        ctx.rust_manifests_production.iter().map(|m| format!("cargo-crap-{}.json", slug(m))).collect();
    let cached = !expected.is_empty() && expected.iter().all(|f| cache_dir.join(f).is_file());

    if !cached {
        if let Err(e) = build_baseline(ctx, &base, &cache_dir, &expected) {
            let mut r = GateResult::new(id, d.tier, d.language, d.advisory, Status::InfrastructureFailure, &e);
            r.remediation = Some(format!(
                "the trusted baseline could not be generated from {base}; the CRAP regression gate cannot run and no \
                 quality conclusion may be drawn"
            ));
            return r;
        }
    }

    // Publish the cached baseline where the head-side `cargo crap --baseline`
    // invocation expects to find it.
    if let Err(e) = std::fs::create_dir_all(&out_dir) {
        return GateResult::new(
            id,
            d.tier,
            d.language,
            d.advisory,
            Status::InfrastructureFailure,
            &format!("cannot create {}: {e}", out_dir.display()),
        );
    }
    for f in &expected {
        if let Err(e) = std::fs::copy(cache_dir.join(f), out_dir.join(f)) {
            return GateResult::new(
                id,
                d.tier,
                d.language,
                d.advisory,
                Status::InfrastructureFailure,
                &format!("cannot publish baseline {f}: {e}"),
            );
        }
    }

    let mut r = GateResult::new(
        id,
        d.tier,
        d.language,
        d.advisory,
        Status::Pass,
        &format!(
            "trusted CRAP baseline for {base} {} under key {key}",
            if cached { "reused from cache" } else { "generated in an isolated worktree" }
        ),
    );
    r.artifacts = expected.iter().map(|f| format!("{ARTIFACTS}/base/{f}")).collect();
    r
}

fn build_baseline(ctx: &Ctx, base: &str, cache_dir: &Path, expected: &[String]) -> Result<(), String> {
    let worktree_rel = format!("{ARTIFACTS}/base/.worktree-{}", &base[..12]);
    let worktree = ctx.repo_root.join(&worktree_rel);
    let timeout = Duration::from_secs(ctx.policy.execution.gate_timeout_secs);

    let _ = std::fs::remove_dir_all(&worktree);
    super::git::run(ctx.repo_root, &["worktree", "prune"]).ok();
    super::git::run(ctx.repo_root, &["worktree", "add", "--detach", "--force", &worktree_rel, base])
        .map_err(|e| format!("cannot create an isolated worktree at {base}: {e}"))?;

    let result = (|| -> Result<(), String> {
        std::fs::create_dir_all(cache_dir).map_err(|e| format!("cannot create {}: {e}", cache_dir.display()))?;
        for m in &ctx.rust_manifests_production {
            let s = slug(m);
            let lcov = format!("{ARTIFACTS}/{s}.lcov");
            let json = format!("{ARTIFACTS}/cargo-crap-{s}.json");
            let steps = vec![
                Cmd::new("cargo", &["llvm-cov", "clean", "--manifest-path", m, "--workspace"]),
                Cmd::new(
                    "cargo",
                    &[
                        "llvm-cov",
                        "nextest",
                        "--manifest-path",
                        m,
                        "--workspace",
                        "--all-features",
                        "--lcov",
                        "--output-path",
                        &lcov,
                    ],
                ),
                Cmd::new(
                    "cargo",
                    &[
                        "crap",
                        "--workspace",
                        "--lcov",
                        &format!("../../../{lcov}"),
                        "--missing",
                        &ctx.policy.crap.rust.missing_coverage,
                        "--format",
                        "json",
                        "--output",
                        &format!("../../../{json}"),
                    ],
                )
                .in_dir(m.trim_end_matches("/Cargo.toml")),
            ];
            for cmd in &steps {
                let res = exec::run(&worktree, cmd, timeout);
                if !res.success() {
                    return Err(format!("baseline step `{}` failed:\n{}", res.command, res.tail(20)));
                }
            }
            std::fs::copy(worktree.join(&json), cache_dir.join(format!("cargo-crap-{s}.json")))
                .map_err(|e| format!("cannot cache baseline for {m}: {e}"))?;
        }
        for f in expected {
            if !cache_dir.join(f).is_file() {
                return Err(format!("baseline generation produced no {f}"));
            }
        }
        Ok(())
    })();

    super::git::run(ctx.repo_root, &["worktree", "remove", "--force", &worktree_rel]).ok();
    let _ = std::fs::remove_dir_all(&worktree);
    result
}

#[derive(Debug, serde::Deserialize, Default)]
struct ArchFile {
    #[serde(default)]
    architecture: ArchSection,
}

#[derive(Debug, serde::Deserialize, Default)]
struct ArchSection {
    #[serde(default)]
    forbidden_edge: Vec<ForbiddenEdge>,
}

#[derive(Debug, serde::Deserialize)]
struct ForbiddenEdge {
    /// Optional workspace scope: the directory of the workspace manifest the
    /// rule applies to, e.g. `tools` or `fork/typedb`. Absent means every
    /// in-scope workspace.
    #[serde(default)]
    workspace: Option<String>,
    from: String,
    to: String,
    reason: String,
}

impl ForbiddenEdge {
    fn applies_to(&self, manifest: &str) -> bool {
        let Some(scope) = &self.workspace else { return true };
        let dir = manifest.trim_end_matches("/Cargo.toml");
        scope == dir || dir.rsplit('/').next() == Some(scope.as_str())
    }
}

/// Crate-level dependency direction from `cargo metadata` (spec §6).
fn arch_rust_deps(id: &str, d: &GateDef, ctx: &Ctx) -> GateResult {
    let rules_path = ctx.repo_root.join(".quality/architecture/rust-dependencies.toml");
    let text = match std::fs::read_to_string(&rules_path) {
        Ok(t) => t,
        Err(e) => {
            let mut r = GateResult::new(
                id,
                d.tier,
                d.language,
                d.advisory,
                Status::InfrastructureFailure,
                &format!("cannot read {}: {e}", rules_path.display()),
            );
            r.remediation = Some("restore .quality/architecture/rust-dependencies.toml".to_string());
            return r;
        }
    };
    let rules: ArchFile = match toml::from_str(&text) {
        Ok(r) => r,
        Err(e) => {
            return GateResult::new(
                id,
                d.tier,
                d.language,
                d.advisory,
                Status::InfrastructureFailure,
                &format!("cannot parse {}: {e}", rules_path.display()),
            );
        }
    };
    if rules.architecture.forbidden_edge.is_empty() {
        return GateResult::new(
            id,
            d.tier,
            d.language,
            d.advisory,
            Status::NotApplicable,
            &format!(
                "no forbidden dependency edges are declared in {}; architecture invariants are Phase 1 work (§6)",
                rules_path.display()
            ),
        );
    }

    let mut violations: Vec<String> = Vec::new();
    for m in &ctx.rust_manifests_production {
        // `--no-deps` restricts `packages` to the workspace's own members, so
        // the model is evaluated over *declared* edges rather than over the
        // whole resolve graph. Whether the product actually links a particular
        // source of a crate is a different question with a different owner.
        let cmd =
            Cmd::new("cargo", &["metadata", "--format-version", "1", "--no-deps", "--manifest-path", m, "--locked"]);
        let res = exec::run(ctx.repo_root, &cmd, Duration::from_secs(ctx.policy.execution.gate_timeout_secs));
        if !res.success() {
            return GateResult::new(
                id,
                d.tier,
                d.language,
                d.advisory,
                Status::InfrastructureFailure,
                &format!("`{}` failed:\n{}", res.command, res.tail(15)),
            );
        }
        let meta: serde_json::Value = match serde_json::from_str(&res.stdout) {
            Ok(v) => v,
            Err(e) => {
                return GateResult::new(
                    id,
                    d.tier,
                    d.language,
                    d.advisory,
                    Status::InfrastructureFailure,
                    &format!("cannot parse cargo metadata output: {e}"),
                );
            }
        };
        let packages = meta.get("packages").and_then(|p| p.as_array()).cloned().unwrap_or_default();
        for pkg in &packages {
            let name = pkg.get("name").and_then(|n| n.as_str()).unwrap_or("");
            for dep in pkg.get("dependencies").and_then(|d| d.as_array()).cloned().unwrap_or_default() {
                // Normal and build dependencies only: a dev-dependency does not
                // cross an architecture boundary in the shipped artefact.
                if dep.get("kind").and_then(|k| k.as_str()) == Some("dev") {
                    continue;
                }
                let dep_name = dep.get("name").and_then(|n| n.as_str()).unwrap_or("");
                for edge in rules.architecture.forbidden_edge.iter().filter(|e| e.applies_to(m)) {
                    if super::glob::matches(&edge.from, name) && super::glob::matches(&edge.to, dep_name) {
                        violations.push(format!("  [{m}] {name} -> {dep_name}: {}", edge.reason));
                    }
                }
            }
        }
    }

    if violations.is_empty() {
        GateResult::new(
            id,
            d.tier,
            d.language,
            d.advisory,
            Status::Pass,
            &format!(
                "{} forbidden edge rule(s) hold across the in-scope workspaces",
                rules.architecture.forbidden_edge.len()
            ),
        )
    } else {
        GateResult::new(
            id,
            d.tier,
            d.language,
            d.advisory,
            Status::QualityFailure,
            &format!("forbidden dependency edges:\n{}", violations.join("\n")),
        )
    }
}

/// Rust manifests, TS projects and Python projects a run should target.
pub fn targets(policy: &Policy, mode: Mode, facts: &Facts) -> (Vec<String>, Vec<String>, Vec<String>, Vec<String>) {
    let rust_all = scope::rust_manifests(policy, &[ScopeClass::Production, ScopeClass::Tooling]);
    let rust_prod = scope::rust_manifests(policy, &[ScopeClass::Production]);

    // TypeScript and Python gates are diff-conditional (§14.1), so target only
    // the projects the diff actually touches — except in `full` mode, which has
    // no diff and covers everything.
    let (ts, py) = if mode == Mode::Full {
        (
            scope::ts_projects(policy, &[ScopeClass::Production, ScopeClass::Tooling]),
            scope::python_projects(policy, &[ScopeClass::Production, ScopeClass::Tooling]),
        )
    } else {
        let mut ts: Vec<String> = Vec::new();
        let mut py: Vec<String> = Vec::new();
        for c in &facts.classified {
            let Some(rule) = policy.scope.rule.iter().find(|r| r.id == c.rule) else { continue };
            match c.language.as_deref() {
                Some("typescript") | Some("javascript") => {
                    if let Some(p) = &rule.ts_project {
                        if !ts.contains(p) {
                            ts.push(p.clone());
                        }
                    }
                }
                Some("python") => {
                    if let Some(p) = &rule.python_project {
                        if !py.contains(p) {
                            py.push(p.clone());
                        }
                    }
                }
                _ => {}
            }
        }
        (ts, py)
    };
    (rust_all, rust_prod, ts, py)
}

#[cfg(test)]
mod tests {
    use super::super::tools::{MatchMode, ToolReport, ToolStatus};
    use super::*;

    fn test_policy() -> Policy {
        let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../.quality/policy.toml")).unwrap();
        Policy::parse(&text).unwrap()
    }

    fn tool(name: &str, status: ToolStatus) -> ToolReport {
        ToolReport {
            name: name.to_string(),
            expected_version: "1.2.3".into(),
            detected_version: if status == ToolStatus::Ok { Some("1.2.3".into()) } else { None },
            mode: MatchMode::Exact,
            status,
            advisory: false,
            conditional: false,
            remediation: format!("cargo install --locked {name}@1.2.3"),
            detect_command: format!("{name} --version"),
        }
    }

    struct Fixture {
        policy: Policy,
        facts: Facts,
        changes: ChangeSet,
        protected: ProtectedMatcher,
        waivers: WaiverSummary,
        registry: Registry,
    }

    /// One clippy JSON line, as cargo actually emits it.
    fn diag(file: &str, line: u64, code: Option<&str>, level: &str, text: &str) -> String {
        let code = match code {
            Some(c) => format!(r#"{{"code":"{c}"}}"#),
            None => "null".to_string(),
        };
        format!(
            r#"{{"reason":"compiler-message","message":{{"level":"{level}","code":{code},"rendered":"{level}: {text}\n --> {file}:{line}","spans":[{{"file_name":"{file}","line_start":{line},"is_primary":true}}]}}}}"#
        )
    }

    #[test]
    fn only_findings_in_files_the_fork_owns_are_counted() {
        let owned =
            super::super::forkowned::ForkOwnership::for_test(&["storage/keyspace/slate.rs", "durability/wal.rs"], 742);
        let stdout = [
            // ours -> counted
            diag("storage/keyspace/slate.rs", 10, Some("clippy::collapsible_if"), "warning", "collapse it"),
            // upstream's -> NOT counted, however loud
            diag("resource/profile.rs", 306, Some("clippy::collapsible_if"), "warning", "collapse it"),
            diag("concept/type_/entity.rs", 1, Some("clippy::needless_borrow"), "error", "borrow"),
            // generated build output is an ABSOLUTE path and is never ours
            diag("/repo/fork/typedb/target/debug/build/x/out/gen.rs", 4, Some("clippy::x"), "warning", "gen"),
            // a plain rustc warning in OUR file still counts: `-D warnings`
            // denied these too, and scoping by file must not quietly stop.
            diag("durability/wal.rs", 7, None, "warning", "unused import: `std::sync::Arc`"),
            // notes and helps are not findings
            diag("durability/wal.rs", 7, None, "note", "the lint level is defined here"),
            // not a diagnostic at all
            r#"{"reason":"compiler-artifact","target":{"name":"storage"}}"#.to_string(),
            "not json at all".to_string(),
        ]
        .join("\n");

        let (ours, upstream) = attribute_clippy(&stdout, &owned);
        assert_eq!(ours.len(), 2, "expected exactly our two findings, got {ours:?}");
        assert!(ours.iter().any(|f| f.contains("storage/keyspace/slate.rs")));
        assert!(ours.iter().any(|f| f.contains("unused import")));
        assert!(!ours.iter().any(|f| f.contains("resource/profile.rs")), "upstream file must not gate us");
        assert_eq!(upstream, 3, "the two upstream findings plus the generated one");
    }

    #[test]
    fn a_finding_on_an_upstream_line_of_a_file_we_touched_is_not_ours() {
        // The fork changed line 397 of this file and nothing else. A finding
        // at 120 is upstream's code sitting in a file we happened to edit, and
        // gating it would mean editing the upstream test corpus.
        let owned =
            super::super::forkowned::ForkOwnership::for_test_lines("concept/tests/test_statistics.rs", &[397], 742);
        let stdout = [
            diag("concept/tests/test_statistics.rs", 397, None, "warning", "ours"),
            diag("concept/tests/test_statistics.rs", 120, None, "warning", "upstream's"),
        ]
        .join("\n");
        let (ours, upstream) = attribute_clippy(&stdout, &owned);
        assert_eq!(ours.len(), 1, "only the line the fork wrote, got {ours:?}");
        assert!(ours[0].contains("ours"));
        assert_eq!(upstream, 1);
    }

    #[test]
    fn the_same_finding_reported_twice_is_counted_once() {
        let owned = super::super::forkowned::ForkOwnership::for_test(&["storage/factory.rs"], 742);
        // cargo re-emits diagnostics per target (lib, test, bench), so the same
        // line arrives several times and must not inflate the count.
        let one = diag("storage/factory.rs", 42, Some("clippy::collapsible_if"), "warning", "collapse it");
        let stdout = [one.clone(), one.clone(), one].join("\n");
        let (ours, _) = attribute_clippy(&stdout, &owned);
        assert_eq!(ours.len(), 1);
    }

    #[test]
    fn a_clean_owned_set_is_a_pass_even_with_upstream_noise() {
        let owned = super::super::forkowned::ForkOwnership::for_test(&["storage/factory.rs"], 742);
        let stdout = diag("resource/profile.rs", 306, Some("clippy::collapsible_if"), "warning", "collapse it");
        let (ours, upstream) = attribute_clippy(&stdout, &owned);
        assert!(ours.is_empty(), "upstream noise alone must not fail the gate");
        assert_eq!(upstream, 1);
    }

    fn fixture(reports: Vec<ToolReport>) -> Fixture {
        let policy = test_policy();
        let protected = ProtectedMatcher::union(None, &policy.protected.paths);
        Fixture {
            policy,
            facts: Facts::default(),
            changes: ChangeSet::default(),
            protected,
            waivers: WaiverSummary { total: 0, active: 0, expired: 0, invalid: 0, entries: Vec::new() },
            registry: Registry { reports },
        }
    }

    fn ctx<'a>(f: &'a Fixture, root: &'a Path) -> Ctx<'a> {
        Ctx {
            repo_root: root,
            policy: &f.policy,
            tools: &f.registry,
            mode: Mode::Pr,
            base_sha: None,
            facts: &f.facts,
            changes: &f.changes,
            protected: &f.protected,
            waivers: &f.waivers,
            rust_manifests_all: vec!["tools/Cargo.toml".into()],
            rust_manifests_production: vec!["tools/Cargo.toml".into()],
            ts_projects: vec!["control-plane".into()],
            python_projects: vec!["tools".into()],
            policy_digest: "sha256:aa".into(),
            toolchain_digest: "sha256:bb".into(),
        }
    }

    #[test]
    fn a_missing_tool_yields_infrastructure_failure_and_never_a_pass() {
        let f = fixture(vec![tool("cargo-nextest", ToolStatus::Absent)]);
        let root = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/.."));
        let r = run("rust.tests", &ctx(&f, root));
        assert_eq!(r.status, Status::InfrastructureFailure);
        assert_ne!(r.status, Status::Pass);
        assert!(r.blocks(), "a missing tool must block the merge decision");
        assert_eq!(r.remediation.as_deref(), Some("cargo install --locked cargo-nextest@1.2.3"));
        assert!(r.detail.contains("not installed"), "{}", r.detail);
        assert!(r.command.is_none(), "the gate must not have been attempted");
    }

    #[test]
    fn a_version_mismatch_yields_infrastructure_failure() {
        let mut t = tool("cargo-mutants", ToolStatus::VersionMismatch);
        t.detected_version = Some("26.0.0".into());
        let f = fixture(vec![t, tool("cargo-nextest", ToolStatus::Ok)]);
        let root = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/.."));
        let r = run("rust.mutation.diff", &ctx(&f, root));
        assert_eq!(r.status, Status::InfrastructureFailure);
        assert!(r.detail.contains("pinned to 1.2.3 but 26.0.0 is installed"), "{}", r.detail);
    }

    #[test]
    fn a_gate_naming_an_unpinned_tool_is_a_configuration_defect_not_a_pass() {
        let f = fixture(Vec::new());
        let root = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/.."));
        let r = run("rust.tests", &ctx(&f, root));
        assert_eq!(r.status, Status::InfrastructureFailure);
        assert!(r.detail.contains("not pinned"), "{}", r.detail);
    }

    #[test]
    fn an_unknown_gate_id_is_an_infrastructure_failure_not_a_silent_skip() {
        let f = fixture(Vec::new());
        let root = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/.."));
        let r = run("rust.invented_by_an_agent", &ctx(&f, root));
        assert_eq!(r.status, Status::InfrastructureFailure);
        assert!(r.detail.contains("no definition"));
    }

    #[test]
    fn insufficient_disk_refuses_the_gate_rather_than_half_running_it() {
        let mut f = fixture(vec![tool("clippy", ToolStatus::Ok)]);
        // Nobody has a exabyte free.
        f.policy.execution.min_free_disk_gb_heavy = 1_000_000_000.0;
        let root = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/.."));
        let r = run("rust.clippy", &ctx(&f, root));
        assert_eq!(r.status, Status::InfrastructureFailure);
        assert!(r.detail.contains("insufficient build space"), "{}", r.detail);
        assert!(r.remediation.as_deref().unwrap().contains("no quality conclusion"));
    }

    #[test]
    fn an_expired_waiver_makes_the_waiver_gate_fail() {
        let mut f = fixture(Vec::new());
        f.waivers = WaiverSummary {
            total: 1,
            active: 0,
            expired: 1,
            invalid: 0,
            entries: vec![super::super::waivers::ValidatedWaiver {
                id: "QW-0001".into(),
                kind: Some("mutation-equivalent".into()),
                path: Some("a.rs".into()),
                symbol: None,
                reason: Some("r".into()),
                owner: Some("o".into()),
                approved_by: Some("p".into()),
                issue: Some("#1".into()),
                created: Some("2026-01-01".into()),
                review_after: Some("2026-02-01".into()),
                status: super::super::waivers::WaiverStatus::Expired,
                problems: vec!["expired".into()],
            }],
        };
        let root = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/.."));
        let r = run("policy.waivers", &ctx(&f, root));
        assert_eq!(r.status, Status::QualityFailure);
    }

    #[test]
    fn the_protected_gate_reports_the_stable_machine_code() {
        let mut f = fixture(Vec::new());
        f.changes = ChangeSet {
            entries: vec![super::super::diff::ChangeEntry {
                status: "M".into(),
                path: ".quality/policy.toml".into(),
                previous_path: None,
            }],
        };
        let root = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/.."));
        let r = run("policy.protected", &ctx(&f, root));
        assert_eq!(r.status, Status::PolicyViolation);
        assert!(r.detail.starts_with(super::super::report::POLICY_VIOLATION_CODE), "{}", r.detail);
        assert!(r.remediation.as_deref().unwrap().contains("trusted base SHA"));
    }

    #[test]
    fn an_unclassified_source_path_fails_the_scope_gate() {
        let mut f = fixture(Vec::new());
        f.facts.unclassified = vec!["newservice/src/main.rs".into()];
        let root = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/.."));
        let r = run("policy.scope_classification", &ctx(&f, root));
        assert_eq!(r.status, Status::QualityFailure);
        assert!(r.detail.contains("no [[scope.rule]]"), "{}", r.detail);
    }

    #[test]
    fn commands_are_the_exact_commands_the_specification_prescribes() {
        let f = fixture(Vec::new());
        let root = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/.."));
        let c = ctx(&f, root);
        let display = |id: &str| commands(id, &c).iter().map(|x| x.display()).collect::<Vec<_>>();

        assert_eq!(display("rust.fmt"), vec!["cargo fmt --manifest-path tools/Cargo.toml --all -- --check"]);
        assert_eq!(
            display("rust.clippy"),
            vec![
                "cargo clippy --manifest-path tools/Cargo.toml --workspace --all-targets --all-features -- -D warnings"
            ]
        );
        assert_eq!(
            display("rust.tests"),
            vec!["cargo nextest run --manifest-path tools/Cargo.toml --workspace --all-features"]
        );
        let cov = display("rust.coverage");
        assert!(cov[1].contains("llvm-cov nextest"), "{:?}", cov);
        assert!(cov[1].contains("--lcov --output-path artifacts/quality/tools.lcov"), "{:?}", cov);
        let crap = display("rust.crap");
        assert!(crap[0].contains("--missing pessimistic"), "{:?}", crap);
        // Regression guard: `cargo machete <args>` misparses its own
        // subcommand name when spawned from inside a cargo-started process.
        assert_eq!(display("rust.machete"), vec!["cargo-machete --with-metadata tools"]);
        let mutation = display("rust.mutation.diff");
        assert!(mutation[0].contains("--in-diff artifacts/quality/pr.diff"), "{:?}", mutation);
        assert!(mutation[0].contains("--test-tool=nextest"), "{:?}", mutation);
    }

    #[test]
    fn the_crap_baseline_command_reads_the_base_not_the_pr_tree() {
        let f = fixture(Vec::new());
        let root = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/.."));
        let mut c = ctx(&f, root);
        c.base_sha = Some("f".repeat(40));
        let crap: Vec<String> = commands("rust.crap", &c).iter().map(|x| x.display()).collect();
        assert_eq!(crap.len(), 2, "with a base SHA the regression comparison is added");
        assert!(crap[1].contains("--baseline artifacts/quality/base/cargo-crap-tools.json"), "{:?}", crap);
        assert!(crap[1].contains("--fail-regression"), "{:?}", crap);
    }

    #[test]
    fn every_gate_the_matrix_can_select_has_a_definition() {
        let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../.quality/policy.toml")).unwrap();
        let policy = Policy::parse(&text).unwrap();
        // Facts that turn on every conditional row at once.
        let facts = Facts {
            rust_production: true,
            rust_any: true,
            typescript_production: true,
            typescript_any: true,
            python_any: true,
            unsafe_or_ffi: true,
            public_api: true,
            features: true,
            dependencies: true,
            fuzz_critical: true,
            architecture: true,
            ..Default::default()
        };
        for mode in [Mode::Fast, Mode::Pr, Mode::Full, Mode::PolicyCheck] {
            for g in super::super::diff::select_gates(mode, &policy, &facts) {
                assert!(definition(&g.id).is_some(), "gate `{}` selected in {:?} has no definition", g.id, mode);
            }
        }
    }

    #[test]
    fn every_definition_names_only_pinned_tools() {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../.quality/tools.lock.toml")).unwrap();
        let lock = super::super::tools::ToolsLock::parse(&text).unwrap();
        for d in all_definitions() {
            for t in d.tools {
                assert!(lock.get(t).is_some(), "gate `{}` requires unpinned tool `{t}`", d.id);
            }
        }
    }

    #[test]
    fn architecture_edges_respect_their_workspace_scope() {
        let scoped = ForbiddenEdge {
            workspace: Some("tools".into()),
            from: "xtask".into(),
            to: "tokio".into(),
            reason: "r".into(),
        };
        assert!(scoped.applies_to("tools/Cargo.toml"));
        assert!(!scoped.applies_to("fork/typedb/Cargo.toml"));

        let nested = ForbiddenEdge {
            workspace: Some("fork/typedb".into()),
            from: "a".into(),
            to: "b".into(),
            reason: "r".into(),
        };
        assert!(nested.applies_to("fork/typedb/Cargo.toml"));
        assert!(!nested.applies_to("tools/Cargo.toml"));

        let global = ForbiddenEdge { workspace: None, from: "a".into(), to: "b".into(), reason: "r".into() };
        assert!(global.applies_to("tools/Cargo.toml"));
        assert!(global.applies_to("fork/typedb/Cargo.toml"));
    }

    #[test]
    fn the_repository_architecture_rules_parse() {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../.quality/architecture/rust-dependencies.toml"
        ))
        .unwrap();
        let rules: ArchFile = toml::from_str(&text).expect("architecture rules must parse");
        for e in &rules.architecture.forbidden_edge {
            assert!(!e.reason.trim().is_empty(), "edge {} -> {} has no reason", e.from, e.to);
        }
    }

    #[test]
    fn gate_ids_are_unique() {
        let mut ids: Vec<&str> = all_definitions().iter().map(|d| d.id).collect();
        let n = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), n, "duplicate gate id in the catalogue");
    }

    #[test]
    fn campaign_gates_are_never_tier_a() {
        for d in all_definitions() {
            if d.weight == Weight::Campaign {
                assert_ne!(d.tier, "A", "gate `{}` is a campaign; it cannot be in the inner loop", d.id);
            }
        }
    }
}
