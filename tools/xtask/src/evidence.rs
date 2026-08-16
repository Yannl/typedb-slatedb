//! `cargo xtask evidence --phase <id>` — roll raw artifacts into a phase manifest.
//!
//! The manifest lists and digests the raw files; it never restates their conclusions.
//! A phase summary that cannot point at a digest here is a narrative, and narratives do
//! not turn gates green (AGENTS.md §1).

use std::path::Path;

use anyhow::{bail, Result};
use serde::Serialize;

#[derive(Debug, Serialize)]
struct Artifact {
    path: String,
    sha256: String,
    bytes: u64,
}

#[derive(Debug, Serialize)]
struct PhaseManifest {
    phase: String,
    artifact_count: usize,
    artifacts: Vec<Artifact>,
    /// SHA-256 over the ordered `(path, sha256)` pairs — the phase's single identity.
    manifest_digest: String,
}

pub fn run(repo_root: &Path, phase: &str) -> Result<()> {
    let dir = repo_root.join("docs/evidence").join(phase);
    if !dir.is_dir() {
        bail!("no evidence directory at {}", dir.display());
    }

    let mut paths: Vec<_> = walkdir::WalkDir::new(&dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
        .filter(|p| p.file_name().is_some_and(|n| n != "manifest.json"))
        .collect();
    paths.sort();

    if paths.is_empty() {
        bail!("{} contains no artifacts; an empty phase is not a completed phase", dir.display());
    }

    let mut artifacts = Vec::with_capacity(paths.len());
    let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
    for path in &paths {
        let rel = path.strip_prefix(repo_root)?.to_string_lossy().replace('\\', "/");
        let sha = source_lock::hash_file(path)?;
        sha2::Digest::update(&mut hasher, rel.as_bytes());
        sha2::Digest::update(&mut hasher, b"\0");
        sha2::Digest::update(&mut hasher, sha.as_bytes());
        sha2::Digest::update(&mut hasher, b"\n");
        artifacts.push(Artifact {
            path: rel,
            sha256: sha,
            bytes: std::fs::metadata(path)?.len(),
        });
    }

    let manifest = PhaseManifest {
        phase: phase.to_string(),
        artifact_count: artifacts.len(),
        artifacts,
        manifest_digest: hex::encode(sha2::Digest::finalize(hasher)),
    };

    let out = dir.join("manifest.json");
    std::fs::write(&out, serde_json::to_string_pretty(&manifest)? + "\n")?;
    println!("phase {phase}: {} artifacts", manifest.artifact_count);
    println!("manifest digest: {}", manifest.manifest_digest);
    println!("written: {}", out.display());
    Ok(())
}
