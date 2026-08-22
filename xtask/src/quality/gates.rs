//! Gate catalogue and execution.
//!
//! Every gate declares its tier, language, cost class, the pinned tools it
//! needs and whether it is advisory. Preconditions are checked before the gate
//! is attempted, and an unmet precondition is an `InfrastructureFailure`
//! carrying the exact remediation command — never a skip and never a pass.

use std::{path::Path, time::Duration};

use super::{
    capability,
    diff::{ChangeSet, Facts, Mode},
    exec::{self, Cmd, Weight},
    policy::{Policy, ProtectedMatcher, ScopeClass},
    report::{GateResult, ProtectedChange, Status},
    scope,
    tools::Registry,
    waivers::WaiverSummary,
};

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
    // R8-P0-03: a language's Tier-A contract includes its TESTS. Before this
    // the controller could report TypeScript typecheck/lint/dead-code/
    // architecture status and say nothing at all about whether the TypeScript
    // tests ran — the `npm test` steps lived in the workflow, outside the
    // report that is claimed as the authority.
    // Tools: none named. `node` and `npm` are TOOLCHAIN pins
    // ([toolchain.node] in .quality/tools.lock.toml), verified once by
    // `policy.toolchain_pin` on every run; naming a nonexistent [tool.node]
    // here would refuse the gate for a pin that is already enforced.
    def("ts.tests", "A", Some("typescript"), Weight::Light, &[], false),
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

/// Every gate id the controller can run. Used to prove the capability
/// inventory names exactly this set (R8-P1-07): one environment model means
/// neither side may drift.
pub fn all_ids() -> Vec<&'static str> {
    DEFS.iter().map(|d| d.id).collect()
}

/// R8-P1-07 item 5: what to clean, and nothing broader.
///
/// "Do not automatically delete broad targets, but report the exact affected
/// package and safe targeted clean command." A remediation that says
/// `cargo clean` costs the reader every other workspace's build tree — on a
/// machine where the fork alone is 20 GB that is an hour, and it is usually
/// not even the tree that filled the disk. So the advice names the manifest
/// the failing command was pointed at, and the package when the command names
/// one, and says explicitly that the broad form is not the remedy.
fn targeted_clean_advice(cmd: &Cmd) -> String {
    let Some(manifest) = exec::manifest_of(cmd) else {
        return "clean a build tree you are not using (`cargo clean --manifest-path <that tree>`); \
                do not clean this one blindly — a broad `cargo clean` discards every workspace's \
                cache, including trees this run still needs"
            .to_string();
    };
    let package =
        cmd.args.iter().position(|a| a == "-p" || a == "--package").and_then(|i| cmd.args.get(i + 1)).cloned();
    match package {
        Some(pkg) => format!(
            "targeted clean: `cargo clean --manifest-path {manifest} -p {pkg}` (that package only). \
             A bare `cargo clean` discards every workspace's cache and is not the remedy"
        ),
        None => format!(
            "targeted clean: `cargo clean --manifest-path {manifest}` (this workspace only). \
             A bare `cargo clean` discards every workspace's cache and is not the remedy"
        ),
    }
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
    /// What this machine can actually provide, probed once per run before
    /// anything is invoked (R8-P1-07).
    pub preflight: capability::Preflight,
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

/// Does `project`'s `package.json` declare `script`? Read as text and matched
/// on the exact JSON key so the controller needs no JSON dependency; a missing
/// or unreadable manifest answers `false`, which routes to the infrastructure
/// refusal above rather than to a pass.
fn declares_script(ctx: &Ctx, project: &str, script: &str) -> bool {
    std::fs::read_to_string(ctx.repo_root.join(project).join("package.json"))
        .ok()
        .and_then(|text| {
            let scripts = text.split("\"scripts\"").nth(1)?;
            let body = scripts.split('}').next()?;
            Some(body.contains(&format!("\"{script}\"")))
        })
        .unwrap_or(false)
}

const ARTIFACTS: &str = "artifacts/quality";

/// R8-P0-05: the machine-readable campaign inventory.
pub const CAMPAIGNS: &str = ".quality/campaigns.toml";

/// One campaign's declaration, read from [`CAMPAIGNS`].
///
/// Parsed with a deliberately small hand-rolled reader rather than a TOML
/// dependency: the controller must be able to say "this campaign is not
/// implementable" even in a tree where a dependency failed to build, and a
/// campaign inventory that cannot be read is itself an infrastructure fact.
#[derive(Debug, Clone, Default)]
pub struct Campaign {
    pub name: String,
    pub gate: String,
    pub implemented: bool,
    pub reason: String,
    pub owner_decision: Option<String>,
    pub requires_network_isolation: bool,
    /// `(manifest, packages)` pairs; empty packages means the whole workspace.
    pub shards: Vec<(String, Vec<String>)>,
    pub toolchain: Option<String>,
}

/// Every declared campaign, keyed by the gate id it governs.
pub fn campaigns(repo_root: &Path) -> Vec<Campaign> {
    let Ok(text) = std::fs::read_to_string(repo_root.join(CAMPAIGNS)) else { return Vec::new() };
    let mut out: Vec<Campaign> = Vec::new();
    let mut shard_manifest: Option<String> = None;
    let mut shard_packages: Vec<String> = Vec::new();
    let mut in_shard = false;
    let flush_shard = |out: &mut Vec<Campaign>, manifest: &mut Option<String>, packages: &mut Vec<String>| {
        if let (Some(m), Some(c)) = (manifest.take(), out.last_mut()) {
            c.shards.push((m, std::mem::take(packages)));
        }
        packages.clear();
    };
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with("[[campaign.") && line.contains(".shard]]") {
            flush_shard(&mut out, &mut shard_manifest, &mut shard_packages);
            in_shard = true;
            continue;
        }
        if line.starts_with("[campaign.") {
            flush_shard(&mut out, &mut shard_manifest, &mut shard_packages);
            in_shard = false;
            let name = line.trim_start_matches("[campaign.").trim_end_matches(']').to_string();
            out.push(Campaign { name, implemented: true, ..Default::default() });
            continue;
        }
        let Some(c) = out.last_mut() else { continue };
        let Some((key, value)) = line.split_once('=') else { continue };
        let (key, value) = (key.trim(), value.trim());
        let unquoted = value.trim_matches('"').to_string();
        match (in_shard, key) {
            (true, "manifest") => shard_manifest = Some(unquoted),
            (true, "packages") => {
                shard_packages = value
                    .trim_matches(['[', ']'].as_ref())
                    .split(',')
                    .map(|p| p.trim().trim_matches('"').to_string())
                    .filter(|p| !p.is_empty())
                    .collect();
            }
            (false, "gate") => c.gate = unquoted,
            (false, "implemented") => c.implemented = value == "true",
            (false, "owner_decision") => c.owner_decision = Some(unquoted),
            (false, "toolchain") => c.toolchain = Some(unquoted),
            (false, "requires_network_isolation") => c.requires_network_isolation = value == "true",
            (false, "not_implemented_reason") => {
                // the value is a triple-quoted block; keep the marker so the
                // full text can be read back from the file when reporting
                c.reason = "see .quality/campaigns.toml".to_string();
            }
            _ => {}
        }
    }
    flush_shard(&mut out, &mut shard_manifest, &mut shard_packages);
    out
}

/// The campaign governing `gate`, if the inventory declares one.
pub fn campaign_for(repo_root: &Path, gate: &str) -> Option<Campaign> {
    campaigns(repo_root).into_iter().find(|c| c.gate == gate)
}

/// R8-P0-05: an artefact path a command may be given AFTER its cwd changes.
///
/// The Rust CRAP commands ran `cargo crap ... --lcov artifacts/quality/x.lcov`
/// with `.in_dir(workspace)`, so the tool resolved the path below the
/// WORKSPACE and wrote (or failed to find) `fork/typedb/artifacts/quality/...`
/// instead of the repository artefact directory. Every artefact path is now
/// absolute before any cwd is applied.
fn artifact_path(repo_root: &Path, rel: &str) -> String {
    repo_root.join(rel).to_string_lossy().to_string()
}

/// R8-P0-03: the canonical per-project test script the `ts.tests` gate runs.
/// One name, declared by every TypeScript project in scope, so the controller
/// never has to guess which of `test` / `test:core` / `test:unit` is the one
/// whose failure should fail the gate.
pub const TS_TEST_SCRIPT: &str = "test:quality";

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
            let skip_overlays = overlay_tests_are_skippable(ctx);
            for m in &ctx.rust_manifests_all {
                if skip_overlays && overlay_of(ctx, m).is_some() {
                    continue;
                }
                let cmd = Cmd::new("cargo", &["nextest", "run", "--manifest-path", m, "--workspace", "--all-features"]);
                // An overlay workspace runs UPSTREAM's tests, and upstream's
                // server tests each bind fixed addresses (gRPC 11729,
                // monitoring 4104) because they were written assuming one
                // server at a time. nextest runs tests as parallel processes,
                // so they fight over those ports and lose — a red that is not
                // a defect. Every test binary is therefore invoked through a
                // wrapper that gives it its OWN network namespace, so each has
                // its own loopback and its own port space. Structural: it
                // keeps holding when upstream adds another server test, which
                // a hand-maintained list of serial tests would not.
                match (overlay_of(ctx, m), exec::host_target_triple()) {
                    // R8-P1-04: ISOLATION IF AVAILABLE, SERIAL IF NOT — never
                    // parallel and unisolated.
                    //
                    // `unshare(CLONE_NEWNET)` needs CAP_SYS_ADMIN in the
                    // current user namespace, which ordinary hosted runners
                    // and restricted agent sandboxes commonly deny. The
                    // previous wiring had two outcomes: isolated, or a refusal
                    // that stopped the gate. The audit's point is that there
                    // is a third, and it costs time rather than tests —
                    // nextest with global concurrency 1, so the fixed ports
                    // upstream's server tests bind are never contended.
                    //
                    // Which mechanism was selected is recorded in the gate's
                    // pass detail, so a report never leaves it implicit.
                    (Some((_, fork_root, _, _)), Some(triple))
                        if exec::network_namespaces_available(ctx.repo_root).is_ok() =>
                    {
                        let runner = ctx.repo_root.join(exec::NETNS_EXEC).to_string_lossy().to_string();
                        // Build FIRST, then stage, then run. The assembly
                        // archive is packaged from the server binaries this
                        // build produces, so it cannot be staged any earlier;
                        // and the behaviour suites read their Cucumber
                        // features through links that must exist next to the
                        // workspace actually under test.
                        out.push(
                            Cmd::new(
                                "cargo",
                                &["nextest", "run", "--manifest-path", m, "--workspace", "--all-features", "--no-run"],
                            )
                            .with_env(&exec::target_runner_var(&triple), &runner),
                        );
                        out.push(Cmd::new(
                            "python3",
                            &["tools/catalog/stage_test_fixtures.py", "--workspace-root", fork_root],
                        ));
                        // `.already_built()`: the `--no-run` command above is
                        // unconditional and precedes this one, so the build
                        // floor has already been met and paid. Asking for it
                        // again would refuse the run for want of the space
                        // that build just consumed.
                        out.push(cmd.with_env(&exec::target_runner_var(&triple), &runner).already_built());
                    }
                    // Isolation unavailable: SERIAL. Same corpus, same
                    // outcomes, more wall-clock — and no hand-maintained list
                    // of "tests that must not run in parallel", which would go
                    // stale the moment upstream adds another server test.
                    (Some((_, fork_root, _, _)), _) => {
                        out.push(Cmd::new(
                            "cargo",
                            &["nextest", "run", "--manifest-path", m, "--workspace", "--all-features", "--no-run"],
                        ));
                        out.push(Cmd::new(
                            "python3",
                            &["tools/catalog/stage_test_fixtures.py", "--workspace-root", fork_root],
                        ));
                        out.push(
                            Cmd::new(
                                "cargo",
                                &[
                                    "nextest",
                                    "run",
                                    "--manifest-path",
                                    m,
                                    "--workspace",
                                    "--all-features",
                                    "--test-threads",
                                    "1",
                                ],
                            )
                            .already_built(),
                        );
                    }
                    _ => out.push(cmd),
                }
            }
        }
        // R8-P1-05: EXPLICIT, SEPARATE policy per production workspace, and the
        // configuration digest bound into the report.
        //
        // The two trees have genuinely different licensing and source models:
        // the authored workspace is ours end to end and passes with no
        // exceptions at all, while the materialised TypeDB fork is an upstream
        // checkout whose members carry no per-crate license field, whose
        // dependencies include two source-locked git repositories, and whose
        // transitive graph carries advisories nobody here selected. One policy
        // could serve both only by widening the authored one to accommodate a
        // graph this project does not own.
        "rust.deny" => {
            for m in &ctx.rust_manifests_all {
                let workspace = m.trim_end_matches("/Cargo.toml");
                let config = format!("{workspace}/deny.toml");
                if ctx.repo_root.join(&config).is_file() {
                    out.push(Cmd::new("cargo", &["deny", "--manifest-path", m, "--config", &config, "check"]));
                    // and the per-crate clarifications must still describe the
                    // workspace they claim to: a member that appears or leaves
                    // without the list moving is the drift this catches.
                    if ctx.repo_root.join("tools/fork/deny_clarify.py").is_file() && workspace.starts_with("fork/") {
                        out.push(Cmd::new("python3", &["tools/fork/deny_clarify.py", "--check"]));
                        out.push(Cmd::new("python3", &["tools/fork/deny_clarify.py", "--check-wildcards"]));
                    }
                } else {
                    out.push(Cmd::new("cargo", &["deny", "--manifest-path", m, "check"]));
                }
            }
        }
        "rust.machete" => {
            // Plain binary, not the `cargo machete` subcommand form; see the
            // note on [tool.cargo-machete] in .quality/tools.lock.toml.
            for m in &ctx.rust_manifests_all {
                let workspace = m.trim_end_matches("/Cargo.toml");
                // R8-P1-05: a workspace whose manifests are GENERATED upstream
                // is reconciled against a committed baseline instead of being
                // hand-edited crate by crate — and the wrapper refuses an
                // incomplete analysis rather than reading its silence as
                // "no findings".
                if ctx.repo_root.join(format!("{workspace}/machete-baseline.json")).is_file() {
                    out.push(Cmd::new("python3", &["tools/fork/check_machete.py"]));
                } else {
                    out.push(Cmd::new("cargo-machete", &["--with-metadata", workspace]));
                }
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
            // R8-P0-05 item 6: coverage runs the SAME test corpus as
            // `rust.tests`, so it needs the same per-test network isolation.
            // Without it an overlay workspace's server tests fight over fixed
            // ports and the collisions are recorded as coverage failures —
            // the exact defect the isolation runner exists to prevent,
            // reintroduced by a second runner that did not wire it.
            let isolate = campaign_for(ctx.repo_root, id).is_some_and(|c| c.requires_network_isolation);
            for m in &ctx.rust_manifests_production {
                let lcov = artifact_path(ctx.repo_root, &format!("{ARTIFACTS}/{}.lcov", slug(m)));
                out.push(Cmd::new("cargo", &["llvm-cov", "clean", "--manifest-path", m, "--workspace"]));
                let mut cmd = Cmd::new(
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
                );
                if isolate {
                    if let (Some(_), Some(triple)) = (overlay_of(ctx, m), exec::host_target_triple()) {
                        let runner = ctx.repo_root.join(exec::NETNS_EXEC).to_string_lossy().to_string();
                        cmd = cmd.with_env(&exec::target_runner_var(&triple), &runner);
                    }
                }
                out.push(cmd);
            }
        }
        "rust.crap" => {
            for m in &ctx.rust_manifests_production {
                let s = slug(m);
                // R8-P0-05: ABSOLUTE before the cwd change below. These
                // commands run `.in_dir(dir)`, so a repository-relative path
                // resolved under the workspace and the LCOV the coverage gate
                // produced was never found.
                let lcov = artifact_path(ctx.repo_root, &format!("{ARTIFACTS}/{s}.lcov"));
                let json = artifact_path(ctx.repo_root, &format!("{ARTIFACTS}/cargo-crap-{s}.json"));
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
                    let baseline = artifact_path(ctx.repo_root, &format!("{ARTIFACTS}/base/cargo-crap-{s}.json"));
                    let delta = artifact_path(ctx.repo_root, &format!("{ARTIFACTS}/cargo-crap-delta-{s}.json"));
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
                            &artifact_path(ctx.repo_root, &format!("{ARTIFACTS}/{s}.lcov")),
                            "--missing",
                            &ctx.policy.crap.rust.missing_coverage,
                            "--format",
                            "json",
                            "--output",
                            &artifact_path(ctx.repo_root, &format!("{ARTIFACTS}/cargo-crap-trend-{s}.json")),
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
            let diff = artifact_path(ctx.repo_root, &format!("{ARTIFACTS}/pr.diff"));
            for m in &ctx.rust_manifests_production {
                out.push(Cmd::new(
                    "cargo",
                    &["mutants", "--manifest-path", m, "--workspace", "--in-diff", &diff, "--test-tool=nextest"],
                ));
            }
        }
        // R8-P0-05: SHARDED by authored package, from the campaign inventory.
        // The previous command mutated each entire production workspace —
        // including ~40 materialised upstream packages in the TypeDB fork —
        // which measures upstream's test suite and fits no credible budget.
        "rust.mutation.full" => {
            let campaign = campaign_for(ctx.repo_root, id);
            for (manifest, packages) in campaign.map(|c| c.shards).unwrap_or_default() {
                if !ctx.rust_manifests_production.contains(&manifest) {
                    continue; // the inventory names a workspace this run has no production scope for
                }
                if packages.is_empty() {
                    out.push(Cmd::new(
                        "cargo",
                        &["mutants", "--manifest-path", &manifest, "--workspace", "--test-tool=nextest"],
                    ));
                    continue;
                }
                for package in packages {
                    out.push(Cmd::new(
                        "cargo",
                        &["mutants", "--manifest-path", &manifest, "--package", &package, "--test-tool=nextest"],
                    ));
                }
            }
        }
        // R8-P0-05: SCOPED to the pure-Rust targets the inventory declares, on
        // the PINNED nightly. `cargo +nightly miri test --workspace` over a
        // tree that links RocksDB, protobuf and libclang is not a slow Miri
        // run — Miri cannot execute foreign functions, so it is one that
        // cannot start, and the runner installs no `nightly` alias either.
        "rust.miri" | "rust.miri.full" => {
            let campaign = campaign_for(ctx.repo_root, "rust.miri.full");
            let toolchain =
                campaign.as_ref().and_then(|c| c.toolchain.clone()).unwrap_or_else(|| "nightly".to_string());
            let plus = format!("+{toolchain}");
            for (manifest, packages) in campaign.map(|c| c.shards).unwrap_or_default() {
                if !ctx.rust_manifests_production.contains(&manifest) {
                    continue;
                }
                for package in packages {
                    out.push(Cmd::new(
                        "cargo",
                        &[&plus, "miri", "test", "--manifest-path", &manifest, "--package", &package],
                    ));
                }
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
        // R8-P0-03: one canonical script name per project. A declared
        // TypeScript project WITHOUT it is an INFRASTRUCTURE failure, never a
        // silent skip: "this project has no test command" must be visible in
        // the report, because the alternative is a green verdict about tests
        // that do not exist.
        "ts.tests" => {
            for p in &ctx.ts_projects {
                out.push(Cmd::new("npm", &["run", "--silent", TS_TEST_SCRIPT]).in_dir(p));
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

    // R8-P1-07: the environment PREFLIGHT, before anything is invoked.
    //
    // The audited controller discovered a missing native component the only way
    // it could: by running the build and reading a nonzero exit with no
    // recognised substring, which it recorded as a QualityFailure — a red
    // verdict about code that was never compiled. Capability is decided here
    // instead, structurally (a header by compiling it, a library by loading it,
    // a namespace by entering one), from the same inventory
    // `tools/dev/doctor.py` reports, which is what makes doctor and the gate
    // agree by construction rather than by two lists staying in step.
    if let Some(unmet) = ctx.preflight.unmet_for(id) {
        let mut r = GateResult::new(id, d.tier, d.language, d.advisory, Status::InfrastructureFailure, &unmet.detail);
        r.remediation = Some(unmet.remediation);
        return r;
    }

    // Build space. An ENOSPC part-way through a compile is indistinguishable
    // from a tool bug, so refuse up front and say exactly why. INTERNAL gates
    // only: they run no commands of their own (the trusted-baseline gate
    // compiles a whole worktree from inside Rust), so nothing else will check
    // them. Every other gate is checked per command below, which knows both
    // the workspace and whether the command compiles at all — a class number
    // applied on top of that only ever refuses a gate for space it does not
    // need, which is how a green machine turns red for no reason.
    let required = d.weight.required_free_gb(&ctx.policy.execution);
    if let Some(free) = exec::free_disk_gb(ctx.repo_root).filter(|_| is_internal(id)) {
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

    // R8-P0-05: a campaign the inventory declares NOT IMPLEMENTED is
    // infrastructure, and it says so. Not a pass, not a placeholder
    // NotApplicable that a workflow's prose can be read as "the campaign ran",
    // and not a non-advisory QualityFailure — which is a red verdict about
    // code, for a campaign that was never built.
    if let Some(campaign) = campaign_for(ctx.repo_root, id) {
        if !campaign.implemented {
            let mut r = GateResult::new(
                id,
                d.tier,
                d.language,
                d.advisory,
                Status::InfrastructureFailure,
                &format!(
                    "campaign `{}` is declared NOT IMPLEMENTED in {CAMPAIGNS}, so gate `{id}` did not \
                     run and no conclusion — green or red — may be drawn from it (R8-P0-05)",
                    campaign.name
                ),
            );
            r.remediation = Some(match &campaign.owner_decision {
                Some(od) => format!(
                    "either implement the campaign, or narrow the documented claim through owner \
                     decision {od}; {CAMPAIGNS} records the surfaces it must target"
                ),
                None => format!("implement the campaign or remove its declaration from {CAMPAIGNS}"),
            });
            return r;
        }
    }

    if is_internal(id) {
        return internal(id, d, ctx);
    }

    // An overlay workspace must NEVER be tested without isolation. Wiring the
    // runner in needs the host target triple, and if that could not be read the
    // commands above quietly degrade to a plain parallel run — which does not
    // fail, it manufactures port collisions and reports them as defects. That
    // is the worst available outcome, so it is refused here instead.
    // Scoped to the gate that EXECUTES the overlay's tests. `rust.fmt` and
    // `rust.clippy` name the same workspace but never start a server, so
    // demanding a runner of them refuses two gates that were working.
    if let Some(cmd) = cmds.iter().find(|c| {
        id == "rust.tests"
            && exec::is_cargo_invocation(&c.program)
            && exec::manifest_of(c).is_some_and(|m| overlay_of(ctx, &m).is_some())
            && !c.env.iter().any(|(k, _)| k.ends_with("_RUNNER"))
    }) {
        let mut r = GateResult::new(
            id,
            d.tier,
            d.language,
            d.advisory,
            Status::InfrastructureFailure,
            &format!(
                "gate `{id}` would run an overlay workspace's tests WITHOUT the per-test network                  isolation they need, because the host target triple could not be read from rustc"
            ),
        );
        r.command = Some(cmd.display());
        r.remediation = Some(
            "ensure `rustc -vV` reports a host triple; the gate was NOT run, because upstream's              server tests bind fixed ports and a parallel run without isolation produces failures              that are not defects"
                .to_string(),
        );
        return r;
    }

    // R8-P0-03: a declared TypeScript project that does not declare the
    // canonical test script cannot be tested, and "cannot be tested" must
    // never read as "tested and fine". `npm run <missing>` exits 1 with a
    // usage error, which the classifier would record as a QUALITY failure of
    // the code; that is the wrong half of the report. Refuse as
    // INFRASTRUCTURE, naming the project and the script, before anything runs.
    if id == "ts.tests" {
        if let Some(project) = ctx.ts_projects.iter().find(|p| !declares_script(ctx, p, TS_TEST_SCRIPT)) {
            let mut r = GateResult::new(
                id,
                d.tier,
                d.language,
                d.advisory,
                Status::InfrastructureFailure,
                &format!(
                    "TypeScript project `{project}` declares no `{TS_TEST_SCRIPT}` script, so gate \
                     `{id}` cannot say whether its tests pass (R8-P0-03)"
                ),
            );
            r.remediation = Some(format!(
                "add a \"{TS_TEST_SCRIPT}\" script to {project}/package.json running that project's \
                 deterministic, host-independent tests; capability-required integration tests belong \
                 in a separate script so their absence is reported as infrastructure, never as a pass"
            ));
            return r;
        }
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
        let need = d.weight.required_free_gb_for(&ctx.policy.execution, id, manifest.as_deref(), cmd.builds);
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
                    "free at least {:.1} GB, or run this gate on a machine with more disk; the \
                     command was not attempted and no quality conclusion may be drawn from this \
                     run. {}",
                    need - free,
                    targeted_clean_advice(cmd)
                ));
                return r;
            }
        }
        // If a command asks for network isolation, it must actually get it.
        // Running without it restores the very collisions it exists to
        // prevent, and reports them as though they were code defects.
        if cmd.env.iter().any(|(k, _)| k.ends_with("_RUNNER")) {
            if let Err(why) = exec::network_namespaces_available(ctx.repo_root) {
                let mut r = GateResult::new(
                    id,
                    d.tier,
                    d.language,
                    d.advisory,
                    Status::InfrastructureFailure,
                    &format!(
                        "gate `{id}` needs a private network namespace per test binary, and this \
                         machine cannot provide one: {why}"
                    ),
                );
                r.command = Some(cmd.display());
                r.remediation = Some(
                    "run where CAP_SYS_ADMIN or unprivileged user namespaces are available; the \
                     gate was NOT run without isolation, because upstream's server tests bind \
                     fixed ports and would collide, producing failures that are not defects"
                        .to_string(),
                );
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
        } else if res.exit_code == Some(exec::EXIT_CAPABILITY_UNAVAILABLE) {
            // R8-P0-03 / R8-P1-07: the STRUCTURAL infrastructure signal. A
            // gate command that cannot run for want of a host capability —
            // network namespaces, AF_UNIX, a readable /proc, a fixture, a
            // native library — exits with this exact code instead of hoping a
            // substring in its output is recognised. The distinction is not
            // cosmetic: a capability-required test that "fails" reads as a
            // defect in the code, and the next reader goes hunting for one.
            (
                Status::InfrastructureFailure,
                format!(
                    "`{}` reported a MISSING HOST CAPABILITY (exit {}), so it did not run and no \
                     quality conclusion may be drawn from it\n{}",
                    res.command,
                    exec::EXIT_CAPABILITY_UNAVAILABLE,
                    res.tail(25)
                ),
            )
        } else if res.exit_code == Some(exec::EXIT_NO_ISOLATION) {
            // tools/dev/netns_exec.py's own refusal code (R8-P1-04). It never
            // runs a test unisolated, so this is always "the host cannot
            // provide isolation", never "the test failed".
            (
                Status::InfrastructureFailure,
                format!(
                    "`{}` could not obtain per-test network isolation (exit {}); the tests were NOT \
                     run unisolated, which would manufacture port collisions and report them as \
                     defects\n{}",
                    res.command,
                    exec::EXIT_NO_ISOLATION,
                    res.tail(25)
                ),
            )
        } else if let Some(signal) = res.signal {
            // R8-P1-07: "signal/timeout/cancellation/ENOSPC -> infrastructure
            // unless a test deliberately asserts it". A child killed by the
            // OOM killer, by a cancelled CI job, or by a crashing linker has
            // NO exit code; `unwrap_or(-1)` would turn that into a number
            // indistinguishable from a failing assertion.
            (
                Status::InfrastructureFailure,
                format!(
                    "`{}` was KILLED by signal {signal}; it did not finish, so no quality \
                     conclusion may be drawn from it (out of memory, a cancelled job, or a \
                     crashing tool — none of them a statement about this code)\n{}",
                    res.command,
                    res.tail(25)
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
            r.remediation = Some(format!("free disk space and re-run the gate. {}", targeted_clean_advice(cmd)));
        }
        r.command = Some(res.command);
        r.cwd = cmd.cwd.clone();
        r.exit_code = res.exit_code;
        r.duration_ms = Some(total_ms);
        return r;
    }

    let mut r = GateResult::new(id, d.tier, d.language, d.advisory, Status::Pass, &pass_detail(id, ctx, cmds.len()));
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

/// Path prefixes that cannot change what an overlay workspace's tests DO.
///
/// Deliberately a list of what is INERT rather than a list of what is
/// relevant. `tools/**` is absent on purpose: `rust.tests` runs an overlay
/// through `tools/dev/netns_exec.py` and stages its fixtures with
/// `tools/catalog/stage_test_fixtures.py`, so a change there changes the run.
/// Anything not named here runs the corpus, which is the direction a mistake
/// should fail in.
const FORK_INERT_PREFIXES: &[&str] = &["docs/", "control-plane/"];

fn cannot_affect_an_overlay(path: &str) -> bool {
    path.ends_with(".md") || FORK_INERT_PREFIXES.iter().any(|p| path.starts_with(p))
}

/// May `rust.tests` skip the overlay workspaces this run?
///
/// OD-018, decided 2026-08-22: the fork corpus is 20-32 minutes, and running
/// it for a change that cannot touch it is the whole cost of the inner loop.
/// This is the same rule `targets()` already applies to the TypeScript and
/// Python gates, and it is scoped to `fast` alone — `pr`, the merge gate, and
/// `full` still execute every workspace, so nothing reaches the default branch
/// on the strength of this.
///
/// An EMPTY change set is not inert. `fast` with no diff is the "verify this
/// tree" run, and there is nothing there to prove irrelevant.
fn overlay_tests_are_skippable(ctx: &Ctx) -> bool {
    ctx.mode == Mode::Fast
        && !ctx.changes.is_empty()
        && ctx.changes.all_paths().iter().all(|p| cannot_affect_an_overlay(p))
}

fn overlay_of<'a>(_ctx: &Ctx, manifest: &str) -> Option<&'a (&'a str, &'a str, &'a str, &'a str)> {
    OVERLAYS.iter().find(|(m, _, _, _)| *m == manifest)
}

/// What a passing gate says it did — including what it deliberately did NOT
/// do. A skipped workspace that goes unmentioned reads as a workspace that
/// passed.
fn pass_detail(id: &str, ctx: &Ctx, n: usize) -> String {
    let mut detail = format!("{n} command(s) succeeded");
    // R8-P1-04: the report must say WHICH execution mechanism was selected. A
    // green `rust.tests` that ran serially and one that ran under per-test
    // network isolation are the same verdict about the code and a different
    // statement about how it was obtained, and a reader cannot tell them apart
    // from the exit code.
    if id == "rust.tests" && OVERLAYS.iter().any(|(m, ..)| ctx.rust_manifests_all.iter().any(|x| x == m)) {
        detail.push_str(match exec::network_namespaces_available(ctx.repo_root) {
            Ok(()) => "; overlay tests ran under PER-TEST NETWORK ISOLATION (each test binary in its own netns)",
            Err(_) => {
                "; overlay tests ran SERIALLY (--test-threads 1) because this host cannot provide \
                 network namespaces. Same corpus and same outcomes, more wall-clock; no test was \
                 skipped and nothing ran parallel-and-unisolated"
            }
        });
    }
    if id == "rust.tests" && overlay_tests_are_skippable(ctx) {
        let skipped: Vec<&str> = OVERLAYS.iter().map(|(m, ..)| *m).collect();
        detail.push_str(&format!(
            "; {} NOT executed — every changed path is documentation or control-plane, \
             which cannot change what its tests do (OD-018). `pr` and `full` run it.",
            skipped.join(", ")
        ));
    }
    detail
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
    use super::{
        super::tools::{MatchMode, ToolReport, ToolStatus},
        *,
    };

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
            // These unit tests exercise gate LOGIC on a fixture; probing the
            // host would make them assert facts about whatever machine runs
            // them. `capability.rs` owns the preflight's own tests.
            preflight: capability::Preflight::NotRun,
        }
    }

    /// R8-P1-07 item 5: the remediation names the exact tree, and says the
    /// broad form is not the remedy. A `cargo clean` suggestion costs every
    /// other workspace's cache — on this machine, the fork alone is 20 GB.
    #[test]
    fn the_clean_advice_names_one_tree_and_refuses_the_broad_form() {
        let cmd = Cmd::new("cargo", &["clippy", "--manifest-path", "fork/typedb/Cargo.toml"]);
        let advice = targeted_clean_advice(&cmd);
        assert!(advice.contains("--manifest-path fork/typedb/Cargo.toml"), "{advice}");
        assert!(advice.contains("not the remedy"), "{advice}");

        let scoped = Cmd::new("cargo", &["test", "--manifest-path", "tools/Cargo.toml", "-p", "xtask"]);
        let advice = targeted_clean_advice(&scoped);
        assert!(advice.contains("-p xtask"), "a command that names a package gets package advice: {advice}");

        // A command that builds no workspace cannot name one, and must not
        // invent a target to clean.
        let unknown = Cmd::new("npx", &["oxlint"]);
        let advice = targeted_clean_advice(&unknown);
        assert!(advice.contains("do not clean this one blindly"), "{advice}");
        assert!(!advice.contains("cargo clean --manifest-path tools"), "{advice}");
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
        // R8-P0-05: ABSOLUTE. These commands are given a cwd, so a
        // repository-relative artefact path resolves below the workspace.
        assert!(cov[1].contains("--lcov --output-path /"), "the LCOV path must be absolute: {cov:?}");
        assert!(cov[1].contains("artifacts/quality/tools.lcov"), "{cov:?}");
        let crap = display("rust.crap");
        assert!(crap[0].contains("--missing pessimistic"), "{:?}", crap);
        // Regression guard: `cargo machete <args>` misparses its own
        // subcommand name when spawned from inside a cargo-started process.
        assert_eq!(display("rust.machete"), vec!["cargo-machete --with-metadata tools"]);
        let mutation = display("rust.mutation.diff");
        assert!(mutation[0].contains("--in-diff /"), "the diff path must be absolute: {mutation:?}");
        assert!(mutation[0].contains("artifacts/quality/pr.diff"), "{mutation:?}");
        assert!(mutation[0].contains("--test-tool=nextest"), "{:?}", mutation);
    }

    fn changed(paths: &[&str]) -> ChangeSet {
        ChangeSet {
            entries: paths
                .iter()
                .map(|p| super::super::diff::ChangeEntry {
                    status: "M".into(),
                    path: (*p).to_string(),
                    previous_path: None,
                })
                .collect(),
        }
    }

    /// OD-018. The saving is the whole point (20-32 minutes), but every clause
    /// of the condition is load-bearing, so each gets an assertion.
    #[test]
    fn the_fork_corpus_is_skipped_only_for_a_diff_that_cannot_reach_it() {
        let f = fixture(Vec::new());
        let root = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/.."));
        let overlay = OVERLAYS[0].0;

        let runs_overlay = |mode: Mode, cs: &ChangeSet| {
            let mut c = ctx(&f, root);
            c.mode = mode;
            c.changes = cs;
            c.rust_manifests_all = vec!["tools/Cargo.toml".into(), overlay.into()];
            let cmds = commands("rust.tests", &c);
            cmds.iter().any(|x| x.display().contains(overlay))
        };

        let docs = changed(&["docs/agent-handoff/x.md", "control-plane/src/a.ts", "README.md"]);
        assert!(!runs_overlay(Mode::Fast, &docs), "a docs/control-plane diff must skip the corpus");

        // `pr` is the merge gate: it runs everything, whatever the diff.
        assert!(runs_overlay(Mode::Pr, &docs), "pr must never skip the corpus");

        // Nothing to prove irrelevant.
        assert!(runs_overlay(Mode::Fast, &changed(&[])), "an empty diff must not skip the corpus");

        // tools/** is how the corpus RUNS — the runner and the fixture staging
        // both live there. Skipping on it would be skipping on the thing under
        // test.
        for p in ["tools/dev/netns_exec.py", "tools/catalog/stage_test_fixtures.py"] {
            assert!(runs_overlay(Mode::Fast, &changed(&[p])), "{p} can change the run");
        }
        for p in ["fork/typedb/server/lib.rs", "xtask/src/quality/gates.rs", ".quality/policy.toml"] {
            assert!(runs_overlay(Mode::Fast, &changed(&[p])), "{p} is not inert");
        }

        // One non-inert path among inert ones still runs it.
        let mixed = changed(&["docs/x.md", "tools/catalog/run_u0.py"]);
        assert!(runs_overlay(Mode::Fast, &mixed), "a mixed diff must run the corpus");

        // And the skip is stated, never silent.
        let mut c = ctx(&f, root);
        c.mode = Mode::Fast;
        c.changes = &docs;
        c.rust_manifests_all = vec!["tools/Cargo.toml".into(), overlay.into()];
        let detail = pass_detail("rust.tests", &c, 1);
        assert!(detail.contains(overlay) && detail.contains("NOT executed"), "{detail}");
        assert!(!pass_detail("rust.clippy", &c, 1).contains("NOT executed"));
    }

    #[test]
    fn an_overlay_workspace_is_tested_through_the_isolation_wrapper() {
        let f = fixture(Vec::new());
        let root = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/.."));
        let mut c = ctx(&f, root);
        c.rust_manifests_all = vec![OVERLAYS[0].0.to_string()];
        let cmds = commands("rust.tests", &c);

        // build, stage, run — in that order. The archive is packaged from the
        // binaries the build produces, so staging cannot precede the build.
        assert_eq!(cmds.len(), 3, "{:?}", cmds.iter().map(|x| x.display()).collect::<Vec<_>>());
        assert!(cmds[0].display().contains("--no-run"), "{}", cmds[0].display());
        assert!(cmds[1].display().contains("stage_test_fixtures.py"), "{}", cmds[1].display());
        assert!(!cmds[2].display().contains("--no-run"), "{}", cmds[2].display());

        // Both cargo commands carry the runner; the run is not charged the
        // build floor a second time.
        for i in [0, 2] {
            let runner = cmds[i].env.iter().find(|(k, _)| k.ends_with("_RUNNER"));
            let (_, path) = runner.unwrap_or_else(|| panic!("command {i} must carry a runner: {}", cmds[i].display()));
            assert!(path.ends_with(exec::NETNS_EXEC), "{path}");
        }
        assert!(cmds[0].builds, "the --no-run command is the build");
        assert!(!cmds[2].builds, "the test run must not be charged the build floor again");
    }

    /// Regression: the refusal below is scoped to the gate that EXECUTES the
    /// overlay's tests. `rust.fmt` and `rust.clippy` name the same workspace
    /// and legitimately carry no runner — demanding one of them refused two
    /// gates that had been passing, which is how this test came to exist.
    #[test]
    fn lint_gates_on_an_overlay_are_not_asked_for_a_test_runner() {
        let f = fixture(Vec::new());
        let root = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/.."));
        let mut c = ctx(&f, root);
        c.rust_manifests_all = vec![OVERLAYS[0].0.to_string()];
        for id in ["rust.fmt", "rust.clippy"] {
            for cmd in commands(id, &c) {
                assert!(
                    !cmd.env.iter().any(|(k, _)| k.ends_with("_RUNNER")),
                    "{id} must not carry a runner: {}",
                    cmd.display()
                );
            }
            // Not "the gate passes" — the test fixture pins no tools, so it
            // cannot. The claim is narrower and exact: it is not refused for
            // want of ISOLATION.
            let r = run(id, &c);
            assert!(!r.detail.contains("network isolation"), "{id} refused for isolation: {}", r.detail);
        }
    }

    /// The failure this refuses is not a red gate — it is a GREEN-shaped one:
    /// running upstream's fixed-port server tests in parallel without isolation
    /// manufactures failures that read as defects.
    #[test]
    fn an_overlay_that_could_not_be_isolated_is_refused_not_run() {
        let f = fixture(Vec::new());
        let root = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/.."));
        let mut c = ctx(&f, root);
        c.rust_manifests_all = vec![OVERLAYS[0].0.to_string()];

        // Exactly what `commands` produces when the host triple is unreadable.
        let degraded =
            [Cmd::new("cargo", &["nextest", "run", "--manifest-path", OVERLAYS[0].0, "--workspace", "--all-features"])];
        let offender = degraded.iter().find(|x| {
            exec::is_cargo_invocation(&x.program)
                && exec::manifest_of(x).is_some_and(|m| overlay_of(&c, &m).is_some())
                && !x.env.iter().any(|(k, _)| k.ends_with("_RUNNER"))
        });
        assert!(offender.is_some(), "a runner-less overlay command must be detected");

        // …and the staging step, which names the same workspace as a
        // directory, must NOT be mistaken for one.
        let staging = Cmd::new("python3", &["tools/catalog/stage_test_fixtures.py", "--workspace-root", OVERLAYS[0].1]);
        assert!(!exec::is_cargo_invocation(&staging.program), "the staging step compiles nothing and needs no runner");
    }

    #[test]
    fn the_crap_baseline_command_reads_the_base_not_the_pr_tree() {
        let f = fixture(Vec::new());
        let root = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/.."));
        let mut c = ctx(&f, root);
        c.base_sha = Some("f".repeat(40));
        let crap: Vec<String> = commands("rust.crap", &c).iter().map(|x| x.display()).collect();
        assert_eq!(crap.len(), 2, "with a base SHA the regression comparison is added");
        // R8-P0-05: the baseline path is ABSOLUTE, because this command runs
        // with `.in_dir(tools)` and a relative path resolved to
        // `tools/artifacts/quality/...`, which is not where the trusted
        // baseline was written.
        assert!(crap[1].contains("--baseline /"), "the baseline path must be absolute: {crap:?}");
        assert!(crap[1].contains("artifacts/quality/base/cargo-crap-tools.json"), "{crap:?}");
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
