//! `cargo xtask source-lock` — resolve the pinned source graph (brief §1.1–§1.4).

use std::path::Path;

use anyhow::{bail, Context, Result};

pub fn run(repo_root: &Path, sources: &Path) -> Result<()> {
    let sources_root = if sources.is_absolute() {
        sources.to_path_buf()
    } else {
        repo_root.join(sources)
    };
    let sources_root = sources_root
        .canonicalize()
        .with_context(|| format!("resolving sources root {}", sources_root.display()))?;

    let lock = source_lock::build_lock(
        &sources_root,
        &source_lock::declared_graph(),
        source_lock::declared_unresolved(),
    )?;

    let out_dir = repo_root.join("source-lock");
    std::fs::create_dir_all(&out_dir)?;
    let out = out_dir.join("source-lock.json");
    std::fs::write(&out, serde_json::to_string_pretty(&lock)? + "\n")?;

    println!("source graph digest: {}", lock.source_graph_digest);
    println!("nodes: {}", lock.nodes.len());
    for node in &lock.nodes {
        println!(
            "  {:<13} {} {:<8} {} files  {}",
            node.spec.alias,
            &node.revision[..12],
            format!("{:?}", node.spec.role).to_lowercase(),
            node.file_count,
            node.spec.origin
        );
    }
    println!("unresolved (class U, blocking their gates): {}", lock.unresolved.len());
    for u in &lock.unresolved {
        println!("  {:<15} [{}] {}", u.alias, u.blocks_gate, u.what);
    }
    println!("written: {}", out.display());

    // A shipping or compiling node must be a clean, exact checkout. Proof-only reference
    // corpora may be shallow snapshots, since nothing they contain reaches the artifact.
    let mut problems = Vec::new();
    for node in &lock.nodes {
        if let Some(m) = &node.pin_mismatch {
            problems.push(format!("{}: {m}", node.spec.alias));
        }
        if node.dirty {
            problems.push(format!("{}: checkout is dirty", node.spec.alias));
        }
        if node.shallow && node.spec.role != source_lock::NodeRole::Proof {
            problems.push(format!(
                "{}: shallow checkout is not acceptable for a {:?} node",
                node.spec.alias, node.spec.role
            ));
        }
    }
    if !problems.is_empty() {
        bail!("source graph is not lockable:\n  - {}", problems.join("\n  - "));
    }
    Ok(())
}
