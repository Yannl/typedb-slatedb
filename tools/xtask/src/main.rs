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
mod negative;
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
        /// `--fork-root` is an alias, for cataloguing an arbitrary fork checkout.
        #[arg(long, alias = "fork-root")]
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
        /// Override the source-lock file whose digest seals the catalogue. Defaults to this
        /// repo's `source-lock/source-lock.json`. Point it at the subject fork's own lock when
        /// cataloguing another checkout, so the evidence is sealed under *its* provenance.
        #[arg(long)]
        source_lock: Option<PathBuf>,
        /// When set, and no source-lock file is present, seal the catalogue under a digest
        /// computed from the fork tree itself instead of aborting. Makes a bare fork checkout
        /// (no pinned `sources/` graph) catalogable; the digest is recorded as fork-derived.
        #[arg(long)]
        allow_missing_source_lock: bool,
        /// Where to write the catalogue and reconciliation evidence. Defaults to
        /// `docs/evidence/phase-b`. Use a scratch dir when cataloguing a foreign fork so the
        /// in-repo evidence is not overwritten.
        #[arg(long)]
        evidence_dir: Option<PathBuf>,
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
    /// Prove the conformance apparatus fails when its inputs are deliberately broken.
    NegativeControls {
        #[arg(long)]
        typedb_root: Option<std::path::PathBuf>,
    },
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
            source_lock,
            allow_missing_source_lock,
            evidence_dir,
        } => catalog::run(
            &repo_root,
            typedb_root.as_deref(),
            &behaviour_root,
            &profile,
            with_libtest_listing,
            &cargo_bin,
            catalog::CatalogPaths {
                source_lock: source_lock.as_deref(),
                allow_missing_source_lock,
                evidence_dir: evidence_dir.as_deref(),
            },
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
        Command::NegativeControls { typedb_root } => {
            negative::run(&repo_root, typedb_root.as_deref())
        }
        Command::Assemble { typedb_root, out_dir } => {
            assemble::run(&repo_root, typedb_root.as_deref(), out_dir.as_deref())
        }
    }
}
