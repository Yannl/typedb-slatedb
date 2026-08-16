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

    let evidence_dir = repo_root.join(format!("docs/evidence/phase-b/run-{profile}"));
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
