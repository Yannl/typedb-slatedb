//! `cargo xtask test-upstream --profile U0|U1|U2|U3|U4`.

use std::{collections::BTreeMap, path::Path, str::FromStr};

use anyhow::{bail, Context, Result};
use conformance_runner::{RunContext, TargetRun};
use corpus_catalog::model::{Catalog, ProfileId};

pub fn run(
    repo_root: &Path,
    profile: &str,
    typedb_root: Option<&Path>,
    behaviour_root: &Path,
    cargo_bin: &str,
    only: Option<&str>,
) -> Result<()> {
    let profile = ProfileId::from_str(profile)?;
    conformance_runner::check_environment_is_clean()?;

    let typedb_root = match typedb_root {
        Some(p) if p.is_absolute() => p.to_path_buf(),
        Some(p) => repo_root.join(p),
        None => repo_root.join("sources/typedb"),
    };
    let behaviour_root = if behaviour_root.is_absolute() {
        behaviour_root.to_path_buf()
    } else {
        repo_root.join(behaviour_root)
    };

    let catalog_path = repo_root
        .join("docs/evidence/phase-b")
        .join(format!("upstream-test-catalog-{profile}.json"));
    if !catalog_path.exists() {
        bail!(
            "no catalogue at {}; run `cargo xtask catalog-upstream-tests` first — the runner \
             reconciles against the locked denominator before running anything \
             (conformance plan step 5)",
            catalog_path.display()
        );
    }
    let catalog: Catalog = serde_json::from_slice(&std::fs::read(&catalog_path)?)?;

    // Bazel used to wire the behaviour corpus in as `data`; the runner stages it at the
    // exact path the unmodified upstream sources expect.
    let staged = conformance_runner::stage_behaviour_corpus(&typedb_root, &behaviour_root)?;
    println!("staged behaviour corpus at {}", staged.display());

    // Clear the previous run's artifacts before starting, rather than merging into them.
    //
    // A run writes one stdout/stderr pair per target plus two reports at the end. Merging
    // would leave logs from targets the catalogue no longer contains sitting beside current
    // ones, and — worse — a stale `coverage-report.json` would survive a run that crashed
    // before writing its own, which is exactly the file a later phase would cite as the
    // baseline. Owning the cleanup here also means no caller has to `rm -rf` the directory
    // by hand and leave the tree mid-delete if the run is interrupted.
    let evidence_dir = repo_root.join(format!("docs/evidence/phase-b/run-{profile}"));
    if evidence_dir.exists() {
        std::fs::remove_dir_all(&evidence_dir)
            .with_context(|| format!("clearing {}", evidence_dir.display()))?;
    }
    std::fs::create_dir_all(&evidence_dir)?;

    let ctx = RunContext {
        profile,
        workspace_root: typedb_root.clone(),
        evidence_dir: evidence_dir.clone(),
        cargo_bin: cargo_bin.to_string(),
        target_dir: repo_root.join("build").join(profile.to_string().to_lowercase()),
        extra_path: Some("/opt/protoc/bin".into()),
        // The profile's resolved configuration, set here rather than inherited from the
        // caller's shell. Shared with the catalogue's listing step so the two cannot drift.
        base_env: conformance_runner::parity_build_env(),
    };

    let selected: Vec<_> = catalog
        .targets
        .iter()
        .filter(|t| t.cargo_package.is_some())
        .filter(|t| only.is_none_or(|f| t.target_id.contains(f)))
        .collect();

    if only.is_some() {
        println!(
            "WARNING: --only={} restricts the run to {} of {} targets. This run cannot support \
             a release coverage claim.",
            only.unwrap_or_default(),
            selected.len(),
            catalog.targets.iter().filter(|t| t.cargo_package.is_some()).count()
        );
    }

    // Build everything before timing anything.
    //
    // Per-target timeouts are meant to bound *execution*. `run_target` invokes `cargo test`,
    // which compiles first, so any target still needing a build spends that time inside its
    // own budget — and `cargo test --no-run` does not cover `--bench` targets, so the eight
    // criterion benches were compiling inside a 900s window and would have been killed and
    // recorded as timeouts they never earned.
    println!("pre-building all harnesses so timeouts measure execution, not compilation");
    let mut warm = std::process::Command::new(cargo_bin);
    warm.args(["test", "--locked", "--workspace", "--no-run"])
        .arg("--benches")
        .arg("--tests")
        .arg("--bins")
        .arg("--lib")
        .current_dir(&typedb_root)
        .env("CARGO_TARGET_DIR", &ctx.target_dir)
        .envs(conformance_runner::parity_build_env());
    if let Some(extra) = &ctx.extra_path {
        let path = std::env::var("PATH").unwrap_or_default();
        warm.env("PATH", format!("{extra}:{path}"));
    }
    let warm_status = warm.status().context("pre-building the corpus")?;
    if !warm_status.success() {
        bail!(
            "pre-build failed ({warm_status}); a run that cannot build its corpus cannot              report coverage over it"
        );
    }

    let mut runs: Vec<TargetRun> = Vec::new();
    for (i, target) in selected.iter().enumerate() {
        println!("[{}/{}] {}", i + 1, selected.len(), target.target_id);
        let run = conformance_runner::run_target(&ctx, &catalog, target)
            .with_context(|| format!("running {}", target.target_id))?;
        println!(
            "        exit={:?} cases={} {}ms",
            run.exit_code,
            run.cases.len(),
            run.duration_ms
        );
        runs.push(run);
    }

    // Static checks have no Cargo entry point, so they are executed directly. Skipping them
    // would leave 154 of 271 targets permanently in `not_executed`; excusing them would be
    // 154 exclusions. Both are worse than porting the checks (ADR-0004).
    if only.is_none() {
        let static_targets: Vec<_> =
            catalog.targets.iter().filter(|t| t.cargo_package.is_none()).collect();
        let (build_targets, recon) = corpus_catalog::scan_build_files(&typedb_root)?;
        let by_label: std::collections::BTreeMap<&str, &corpus_catalog::BuildTestTarget> =
            build_targets.iter().map(|b| (b.label.as_str(), b)).collect();

        for (i, target) in static_targets.iter().enumerate() {
            let label = target.upstream_label.as_deref().unwrap_or_default();
            println!("[static {}/{}] {}", i + 1, static_targets.len(), target.target_id);
            let inputs = match by_label.get(label) {
                Some(bt) => conformance_runner::staticcheck::StaticCheckInputs {
                    rule: bt.rule.clone(),
                    package_dir: bt.build_file.trim_end_matches("BUILD").trim_end_matches('/').to_string(),
                    include: bt.other_attrs.get("include").cloned().unwrap_or_default(),
                    exclude: bt.other_attrs.get("exclude").cloned().unwrap_or_default(),
                    // `rustfmt_test` names Bazel targets, not files; resolve them to sources.
                    sources: bt
                        .other_attrs
                        .get("targets")
                        .map(|labels| {
                            labels
                                .iter()
                                .flat_map(|l| {
                                    let full = if l.starts_with("//") {
                                        l.clone()
                                    } else {
                                        format!("//{}{}", bt.build_file.trim_end_matches("BUILD").trim_end_matches('/'), l)
                                    };
                                    recon.rule_srcs.get(&full).cloned().unwrap_or_default()
                                })
                                .collect()
                        })
                        .unwrap_or_default(),
                },
                None => conformance_runner::staticcheck::StaticCheckInputs {
                    rule: "unresolved".into(),
                    ..Default::default()
                },
            };
            let run = conformance_runner::staticcheck::run_static_target(
                &typedb_root,
                &evidence_dir,
                profile,
                &catalog,
                target,
                &inputs,
            )?;
            println!("        exit={:?} cases={}", run.exit_code, run.cases.len());
            runs.push(run);
        }
    }

    let runs_path = evidence_dir.join("target-runs.json");
    std::fs::write(&runs_path, serde_json::to_string_pretty(&runs)? + "\n")?;

    let report = conformance_runner::summarise(&catalog, &runs, profile);
    let verdict = report.verdict();
    let report_path = evidence_dir.join("coverage-report.json");
    std::fs::write(
        &report_path,
        serde_json::to_string_pretty(&serde_json::json!({
            "report": report,
            "verdict": verdict,
            "restricted_by_only_filter": only,
        }))? + "\n",
    )?;

    println!("\n{profile} coverage");
    println!("  targets    : {}/{}", report.targets_executed, report.targets_total);
    println!("  leaf cases : {}/{}", report.leaf_cases_executed, report.leaf_cases_total);
    println!(
        "  passed={} failed={} ignored={} unknown={}",
        report.passed, report.failed, report.ignored, report.unknown
    );
    println!("  verdict    : {}", if verdict.green { "GREEN" } else { "NOT GREEN" });
    for reason in &verdict.reasons {
        println!("     - {reason}");
    }
    println!("evidence: {}", report_path.display());
    Ok(())
}
