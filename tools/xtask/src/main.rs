//! `cargo xtask …` — the normative command boundary (brief §21.2).
//!
//! Every gate-relevant action is one of these subcommands, each of which writes raw,
//! machine-readable evidence under `docs/evidence/`. Nothing here decides a gate from
//! prose: the evidence files are the record and the summaries only cite them.

mod catalog;
mod doclint;
mod evidence;
mod assemble;
mod native;
mod lock;
mod runner;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "xtask", about = "TypeDB-on-R2 conformance and evidence tooling")]
struct Cli {
    /// Repository root. Defaults to the directory containing `tools/`.
    #[arg(long, global = true)]
    repo_root: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Resolve the pinned source graph and write `source-lock/source-lock.json`.
    SourceLock {
        /// Directory holding the pinned checkouts.
        #[arg(long, default_value = "sources")]
        sources: PathBuf,
    },
    /// Generate the upstream test denominator from the pinned checkout.
    CatalogUpstreamTests {
        /// TypeDB checkout to catalogue. Defaults to the pristine pin for U0.
        #[arg(long)]
        typedb_root: Option<PathBuf>,
        #[arg(long, default_value = "fixtures/typedb-behaviour")]
        behaviour_root: PathBuf,
        #[arg(long, default_value = "U0")]
        profile: String,
        /// Also build the corpus and read libtest cases from the real harnesses.
        #[arg(long)]
        with_libtest_listing: bool,
        #[arg(long, default_value = "cargo")]
        cargo_bin: String,
    },
    /// Check that Cargo manifests and BUILD files declare the same test targets.
    VerifyCargoParity {
        #[arg(long)]
        typedb_root: Option<PathBuf>,
    },
    /// Execute the catalogued corpus under one profile.
    TestUpstream {
        #[arg(long)]
        profile: String,
        #[arg(long)]
        typedb_root: Option<PathBuf>,
        #[arg(long, default_value = "fixtures/typedb-behaviour")]
        behaviour_root: PathBuf,
        #[arg(long, default_value = "cargo")]
        cargo_bin: String,
        /// Run only targets whose id contains this substring. Recorded in the evidence and
        /// never permitted for a release claim.
        #[arg(long)]
        only: Option<String>,
    },
    /// Lint the contract documents, schemas, patch ids and gate references.
    DocLint,
    /// Roll up per-phase evidence into a signed-shape summary.
    Evidence {
        #[arg(long)]
        phase: String,
    },
    /// Resolve and digest the native toolchain (the `NATIVE` class-U node, brief §1.3).
    NativeToolchain,
    /// Assemble the distribution archive the packaging tests need.
    Assemble {
        #[arg(long)]
        typedb_root: Option<std::path::PathBuf>,
        #[arg(long)]
        out_dir: Option<std::path::PathBuf>,
    },
}

fn default_repo_root() -> Result<PathBuf> {
    // `CARGO_MANIFEST_DIR` is `<repo>/tools/xtask`.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(std::path::Path::parent)
        .map(PathBuf::from)
        .context("locating repository root from CARGO_MANIFEST_DIR")
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let repo_root = match cli.repo_root {
        Some(p) => p,
        None => default_repo_root()?,
    };
    let repo_root = repo_root
        .canonicalize()
        .with_context(|| format!("resolving repo root {}", repo_root.display()))?;

    match cli.command {
        Command::SourceLock { sources } => lock::run(&repo_root, &sources),
        Command::CatalogUpstreamTests {
            typedb_root,
            behaviour_root,
            profile,
            with_libtest_listing,
            cargo_bin,
        } => catalog::run(
            &repo_root,
            typedb_root.as_deref(),
            &behaviour_root,
            &profile,
            with_libtest_listing,
            &cargo_bin,
        ),
        Command::VerifyCargoParity { typedb_root } => {
            catalog::verify_parity(&repo_root, typedb_root.as_deref())
        }
        Command::TestUpstream { profile, typedb_root, behaviour_root, cargo_bin, only } => {
            runner::run(
                &repo_root,
                &profile,
                typedb_root.as_deref(),
                &behaviour_root,
                &cargo_bin,
                only.as_deref(),
            )
        }
        Command::DocLint => doclint::run(&repo_root),
        Command::Evidence { phase } => evidence::run(&repo_root, &phase),
        Command::NativeToolchain => native::run(&repo_root),
        Command::Assemble { typedb_root, out_dir } => {
            assemble::run(&repo_root, typedb_root.as_deref(), out_dir.as_deref())
        }
    }
}
