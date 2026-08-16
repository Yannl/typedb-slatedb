//! Cargo-side enumeration: packages and test-capable targets from `cargo metadata`.
//!
//! Only the fields the catalogue needs are modelled, so an unrelated schema change in
//! `cargo metadata` cannot break the denominator.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct CargoTarget {
    pub name: String,
    /// e.g. `["lib"]`, `["test"]`, `["bin"]`, `["bench"]`.
    pub kind: Vec<String>,
    pub src_path: PathBuf,
    #[serde(default)]
    pub required_features: Vec<String>,
    /// `true` when the target is compiled as a test harness by `cargo test`.
    #[serde(default)]
    pub test: bool,
    #[serde(default)]
    pub doctest: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CargoPackage {
    pub name: String,
    pub id: String,
    pub manifest_path: PathBuf,
    pub targets: Vec<CargoTarget>,
    #[serde(default)]
    pub features: std::collections::BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CargoMetadata {
    pub packages: Vec<CargoPackage>,
    pub workspace_members: Vec<String>,
    pub target_directory: PathBuf,
    pub workspace_root: PathBuf,
}

impl CargoMetadata {
    /// Packages that belong to this workspace, in stable name order.
    pub fn workspace_packages(&self) -> Vec<&CargoPackage> {
        let mut pkgs: Vec<_> = self
            .packages
            .iter()
            .filter(|p| self.workspace_members.contains(&p.id))
            .collect();
        pkgs.sort_by(|a, b| a.name.cmp(&b.name));
        pkgs
    }
}

/// Run `cargo metadata --locked --format-version 1` against a workspace root.
///
/// `--locked` is deliberate: a run that silently updates `Cargo.lock` would change the
/// denominator's dependency closure without evidence (brief §1.4, Appendix E.1-1).
pub fn load(workspace_root: &Path, cargo: &str, extra_path: Option<&str>) -> Result<CargoMetadata> {
    let mut cmd = std::process::Command::new(cargo);
    cmd.current_dir(workspace_root)
        .args(["metadata", "--locked", "--format-version", "1", "--no-deps"]);
    if let Some(p) = extra_path {
        let path = std::env::var("PATH").unwrap_or_default();
        cmd.env("PATH", format!("{p}:{path}"));
    }
    let out = cmd
        .output()
        .with_context(|| format!("running `{cargo} metadata` in {}", workspace_root.display()))?;
    if !out.status.success() {
        bail!(
            "`{cargo} metadata` failed in {}: {}",
            workspace_root.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    serde_json::from_slice(&out.stdout).context("parsing cargo metadata JSON")
}

/// Every target that carries test cases, as `(package, target)`.
///
/// This is deliberately wider than `cargo test`'s default set. Brief §22.2 puts
/// "examples/benches used as tests" in the denominator, and upstream declares its benches
/// as Bazel `rust_test` targets under `<crate>/benches:…` — so a `[[bench]]` target that
/// Cargo would only build under `cargo bench` is still an upstream test target. Omitting
/// them would drop 8 targets from the denominator while every command still reported green.
pub fn test_capable_targets(meta: &CargoMetadata) -> Vec<(&CargoPackage, &CargoTarget)> {
    let mut out = Vec::new();
    for pkg in meta.workspace_packages() {
        for target in &pkg.targets {
            if target.test || target.kind.iter().any(|k| k == "bench") {
                out.push((pkg, target));
            }
        }
    }
    out.sort_by(|a, b| (&a.0.name, &a.1.name).cmp(&(&b.0.name, &b.1.name)));
    out
}

impl CargoTarget {
    /// True for a `[[bench]]` target, which `cargo test` will not run by default.
    pub fn is_bench(&self) -> bool {
        self.kind.iter().any(|k| k == "bench")
    }

    /// True for the crate's own lib target, whose unit tests Bazel wraps in a
    /// `rust_test(crate = ":<name>")` "crate-unit" rule.
    pub fn is_lib(&self) -> bool {
        self.kind.iter().any(|k| k == "lib" || k == "rlib" || k == "proc-macro")
    }
}
