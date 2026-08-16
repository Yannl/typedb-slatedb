//! `cargo xtask catalog-upstream-tests` and `verify-cargo-parity`.

use std::{collections::BTreeMap, path::Path, process::Command};

use anyhow::{bail, Context, Result};
use corpus_catalog::{model::CaseDiscovery, CatalogInputs};

fn tool_version(bin: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(bin)
        .args(args)
        .output()
        .with_context(|| format!("running {bin} {args:?}"))?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn source_lock_digest(repo_root: &Path) -> Result<String> {
    let path = repo_root.join("source-lock/source-lock.json");
    if !path.exists() {
        bail!(
            "{} is missing; run `cargo xtask source-lock` first — the catalogue is bound to \
             an exact source graph",
            path.display()
        );
    }
    let lock: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    lock.get("source_graph_digest")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .context("source-lock.json has no source_graph_digest")
}

fn resolve_typedb_root(repo_root: &Path, given: Option<&Path>) -> std::path::PathBuf {
    match given {
        Some(p) if p.is_absolute() => p.to_path_buf(),
        Some(p) => repo_root.join(p),
        // U0 is defined on the pristine pin, so that is the default subject.
        None => repo_root.join("sources/typedb"),
    }
}

pub fn run(
    repo_root: &Path,
    typedb_root: Option<&Path>,
    behaviour_root: &Path,
    profile: &str,
    with_libtest_listing: bool,
    cargo_bin: &str,
) -> Result<()> {
    let typedb_root = resolve_typedb_root(repo_root, typedb_root);
    let behaviour_root = if behaviour_root.is_absolute() {
        behaviour_root.to_path_buf()
    } else {
        repo_root.join(behaviour_root)
    };

    let extra_path = Some("/opt/protoc/bin".to_string());
    let inputs = CatalogInputs {
        fork_root: &typedb_root,
        behaviour_root: &behaviour_root,
        source_lock_digest: source_lock_digest(repo_root)?,
        rustc: tool_version("rustc", &["--version"])?,
        cargo: tool_version(cargo_bin, &["--version"])?,
        target_triple: "x86_64-unknown-linux-gnu".into(),
        cargo_bin: cargo_bin.to_string(),
        extra_path: extra_path.clone(),
    };

    let mut out = corpus_catalog::generate(&inputs)?;

    if with_libtest_listing {
        let target_dir = repo_root.join("build").join(profile.to_lowercase());
        let listings =
            collect_libtest_listings(&typedb_root, cargo_bin, &out.catalog, &target_dir)?;
        corpus_catalog::enrich_libtest_cases(&mut out.catalog, &listings)?;
    }

    let evidence = repo_root.join("docs/evidence/phase-b");
    std::fs::create_dir_all(&evidence)?;

    let catalog_path = evidence.join(format!("upstream-test-catalog-{profile}.json"));
    std::fs::write(&catalog_path, serde_json::to_string_pretty(&out.catalog)? + "\n")?;

    let recon_path = evidence.join("cargo-build-reconciliation.json");
    std::fs::write(&recon_path, serde_json::to_string_pretty(&out.reconciliation)? + "\n")?;

    let build_path = evidence.join("build-test-targets.json");
    std::fs::write(&build_path, serde_json::to_string_pretty(&out.build_targets)? + "\n")?;

    // Validate against the contract's own schema, so the catalogue cannot drift from it.
    validate_against_schema(repo_root, &catalog_path)?;

    let c = &out.catalog;
    let by_kind = c.leaf_cases.iter().fold(BTreeMap::<String, usize>::new(), |mut m, l| {
        *m.entry(format!("{:?}", l.kind)).or_default() += 1;
        m
    });
    println!("catalogue: {}", catalog_path.display());
    println!("  source graph digest : {}", c.source_lock_digest);
    println!("  targets             : {}", c.targets.len());
    println!("  leaf cases          : {}", c.leaf_cases.len());
    for (kind, n) in &by_kind {
        println!("     {kind:<12} {n}");
    }
    println!(
        "  declared-ignored    : {}",
        c.leaf_cases.iter().filter(|l| l.declared_ignored).count()
    );
    println!("  required pairs      : {}", c.required_pairs.len());
    println!("  fixtures            : {}", c.fixtures.len());
    println!("  exclusions          : {}", c.exclusions.len());

    let r = &out.reconciliation;
    println!("reconciliation: {}", recon_path.display());
    println!("  matched Cargo<->BUILD : {}", r.matched.len());
    println!("  BUILD-only            : {}", r.build_only.len());
    println!("  Cargo-only            : {}", r.cargo_only.len());
    println!("  unknown rules         : {}", r.unknown_rules.len());
    println!("  unparsed BUILD files  : {}", r.unparsed_build_files.len());

    if !r.unknown_rules.is_empty() || !r.unparsed_build_files.is_empty() {
        bail!(
            "catalogue is not final: {} unknown rule(s) and {} unparsed BUILD file(s); \
             an unknown macro fails G0 (brief §21.10)",
            r.unknown_rules.len(),
            r.unparsed_build_files.len()
        );
    }
    Ok(())
}

/// Build the test harnesses and read their real case lists.
///
/// Case discovery comes from the built binary rather than from parsing source text, so a
/// `#[cfg]`-gated or macro-generated case cannot go missing (Appendix E.1-2, E.5-27).
fn collect_libtest_listings(
    typedb_root: &Path,
    cargo_bin: &str,
    catalog: &corpus_catalog::model::Catalog,
    target_dir: &Path,
) -> Result<BTreeMap<String, Vec<corpus_catalog::LibtestCase>>> {
    // One build for the whole workspace, then each harness is invoked directly.
    //
    // The obvious alternative — `cargo test -p <pkg> --<kind> <name> -- --list` per target —
    // costs ~106 cargo invocations, each re-checking freshness for the entire graph, and it
    // deadlocked in practice: cargo held the build-directory lock while blocked reading a
    // child pipe. Building once and exec'ing the harnesses removes both problems and makes
    // the listing depend on nothing but the binaries themselves.
    let path = std::env::var("PATH").unwrap_or_default();
    let build = Command::new(cargo_bin)
        .args(["test", "--locked", "--workspace", "--no-run", "--message-format=json"])
        .current_dir(typedb_root)
        // Never inherit a caller's target dir: a different one would silently rebuild the
        // corpus under different settings and list cases from a build nobody recorded.
        .env("CARGO_TARGET_DIR", target_dir)
        .env("CARGO_INCREMENTAL", "0")
        .env("CARGO_PROFILE_TEST_DEBUG", "0")
        .env("PATH", format!("/opt/protoc/bin:{path}"))
        .stderr(std::process::Stdio::inherit())
        .output()
        .context("building the test harnesses")?;
    if !build.status.success() {
        bail!("`cargo test --no-run` failed; the catalogue cannot list cases it cannot build");
    }

    // `compiler-artifact` messages carry the built executable for each test target.
    let mut executables: BTreeMap<(String, String), String> = BTreeMap::new();
    for line in String::from_utf8_lossy(&build.stdout).lines() {
        let Ok(msg) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        if msg.get("reason").and_then(|r| r.as_str()) != Some("compiler-artifact") {
            continue;
        }
        let Some(exe) = msg.get("executable").and_then(|e| e.as_str()) else { continue };
        // package_id is like `path+file:///…/storage#0.0.0` or `…#storage@0.0.0`.
        let pkg_id = msg.get("package_id").and_then(|p| p.as_str()).unwrap_or_default();
        let pkg = pkg_id
            .rsplit_once('#')
            .map(|(path, frag)| match frag.split_once('@') {
                Some((name, _)) => name.to_string(),
                None => path.rsplit('/').next().unwrap_or_default().to_string(),
            })
            .unwrap_or_default();
        let name = msg
            .pointer("/target/name")
            .and_then(|n| n.as_str())
            .unwrap_or_default()
            .to_string();
        executables.insert((pkg, name), exe.to_string());
    }

    let mut out = BTreeMap::new();
    let mut missing = Vec::new();
    for target in &catalog.targets {
        if target.case_discovery != CaseDiscovery::LibtestList {
            continue;
        }
        let (Some(pkg), Some(name)) = (&target.cargo_package, &target.cargo_target) else {
            continue;
        };
        let Some(exe) = executables.get(&(pkg.clone(), name.clone())) else {
            missing.push(target.target_id.clone());
            continue;
        };

        let output = Command::new(exe)
            .args(["--list", "--format", "terse"])
            .current_dir(typedb_root)
            .output()
            .with_context(|| format!("listing cases for {}", target.target_id))?;
        if !output.status.success() {
            bail!(
                "{} exited {:?} while listing its cases: {}",
                target.target_id,
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        out.insert(target.target_id.clone(), corpus_catalog::parse_libtest_list(&stdout)?);
    }

    // A catalogued target whose harness was never built is a hole in the denominator, not
    // a target with zero cases.
    if !missing.is_empty() {
        bail!(
            "{} catalogued target(s) produced no test executable, so their case lists are \
             unknown: {}",
            missing.len(),
            missing.join(", ")
        );
    }
    Ok(out)
}

fn validate_against_schema(repo_root: &Path, catalog_path: &Path) -> Result<()> {
    let schema_path = repo_root.join("contract/typedb-r2-v14-upstream-test-catalog.schema.json");
    let schema: serde_json::Value = serde_json::from_slice(&std::fs::read(&schema_path)?)?;
    let instance: serde_json::Value = serde_json::from_slice(&std::fs::read(catalog_path)?)?;
    let validator = jsonschema::validator_for(&schema)
        .map_err(|e| anyhow::anyhow!("compiling catalogue schema: {e}"))?;
    let errors: Vec<String> = validator.iter_errors(&instance).map(|e| format!("{}: {e}", e.instance_path)).collect();
    if !errors.is_empty() {
        bail!(
            "catalogue does not validate against {}:\n  - {}",
            schema_path.display(),
            errors.join("\n  - ")
        );
    }
    Ok(())
}

/// `cargo xtask verify-cargo-parity` — the Bazel/Cargo drift auditor (brief §21.10).
pub fn verify_parity(repo_root: &Path, typedb_root: Option<&Path>) -> Result<()> {
    let typedb_root = resolve_typedb_root(repo_root, typedb_root);
    let (build_targets, recon) = corpus_catalog::scan_build_files(&typedb_root)?;

    let meta = corpus_catalog::cargo_meta::load(&typedb_root, "cargo", Some("/opt/protoc/bin"))?;
    let cargo_tests: Vec<String> = corpus_catalog::cargo_meta::test_capable_targets(&meta)
        .into_iter()
        .map(|(p, t)| format!("{}::{}", p.name, t.name))
        .collect();

    println!("BUILD test-producing targets : {}", build_targets.len());
    println!("  rust_test                  : {}", build_targets.iter().filter(|b| b.rule == "rust_test").count());
    println!("  rustfmt_test               : {}", build_targets.iter().filter(|b| b.rule == "rustfmt_test").count());
    println!("  checkstyle_test            : {}", build_targets.iter().filter(|b| b.rule == "checkstyle_test").count());
    println!(
        "  release_validate_deps      : {} call site(s) -> {} Bazel test target(s)",
        build_targets.iter().filter(|b| b.rule == "release_validate_deps").count(),
        build_targets.iter().filter(|b| b.rule == "release_validate_deps").count() * 2
    );
    println!("Cargo test-capable targets   : {}", cargo_tests.len());
    println!("unknown BUILD rules          : {}", recon.unknown_rules.len());
    for r in &recon.unknown_rules {
        println!("    {r}");
    }
    println!("unparsed BUILD files         : {}", recon.unparsed_build_files.len());
    for r in &recon.unparsed_build_files {
        println!("    {r}");
    }

    if !recon.unknown_rules.is_empty() || !recon.unparsed_build_files.is_empty() {
        bail!("Cargo/BUILD parity is unproven while unknown rules or unparsed files remain");
    }
    println!("OK: every BUILD rule is a known test producer or a known non-test rule");
    Ok(())
}
