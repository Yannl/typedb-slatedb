//! Source-graph lock generation (brief §1.1–§1.4, §21.1 `WorkspaceLock`).
//!
//! Every node in the normative source graph is recorded with an immutable identity
//! (git revision + git tree object id) and an independently computed content digest,
//! so a claim about upstream source can be re-checked without trusting git.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Whether a node's bytes reach the release, only compile-time, or only proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NodeRole {
    /// Bytes (or derivatives) are in the shipped artifact.
    Ships,
    /// Needed to compile or generate shipped bytes, but not shipped itself.
    Compiles,
    /// Read-only evidence: fixtures, oracles, documentation, reference implementations.
    Proof,
}

/// How the node's identity was pinned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PinKind {
    /// Pinned directly to a full 40-hex commit.
    Commit,
    /// Pinned to a tag, resolved to a full commit at lock time.
    Tag,
    /// Single-commit snapshot of a reference corpus; commit still recorded.
    Snapshot,
}

/// One declared node of the normative source graph (brief §1.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceNodeSpec {
    /// Contract alias, e.g. `TB`, `SL`, `BH`.
    pub alias: String,
    /// Directory name under the sources root.
    pub name: String,
    /// `owner/repo` on GitHub.
    pub origin: String,
    pub pin_kind: PinKind,
    /// The tag when `pin_kind` is `Tag`, otherwise the expected commit (if contract-fixed).
    pub declared_pin: Option<String>,
    pub role: NodeRole,
    pub licence: String,
    pub purpose: String,
}

/// A resolved node: declared identity plus what is actually on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedSourceNode {
    #[serde(flatten)]
    pub spec: SourceNodeSpec,
    /// Full 40-hex commit actually checked out.
    pub revision: String,
    /// Git tree object id of that commit.
    pub git_tree: String,
    /// Content digest computed by this tool over the working tree, independent of git.
    pub content_digest: String,
    /// Number of files that went into `content_digest`.
    pub file_count: u64,
    /// Total bytes hashed.
    pub byte_count: u64,
    /// True when the checkout has modifications beyond fetcher marker files.
    pub dirty: bool,
    /// True for `--depth 1` checkouts (history not held locally).
    pub shallow: bool,
    /// Set when `declared_pin` is a commit and the checkout does not match it.
    pub pin_mismatch: Option<String>,
}

/// The generated `source-lock/source-lock.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceLock {
    pub schema_version: u32,
    pub generator: String,
    pub sources_root: String,
    pub nodes: Vec<ResolvedSourceNode>,
    /// SHA-256 over the canonical `(alias, revision, content_digest)` triples.
    pub source_graph_digest: String,
    /// Nodes whose identity or provenance is still open (evidence class `U`).
    pub unresolved: Vec<UnresolvedNode>,
}

/// An explicitly unresolved graph node. Class `U` is never silently promoted (brief §"Evidence classes").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnresolvedNode {
    pub alias: String,
    pub what: String,
    pub blocks_gate: String,
}

/// Marker files written by the fetchers; their presence is not source drift.
const FETCHER_MARKERS: [&str; 3] = [".resolved-tag", ".snapshot-revision", ".source-revision"];

fn git(dir: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .with_context(|| format!("running git {args:?} in {}", dir.display()))?;
    if !out.status.success() {
        bail!(
            "git {:?} in {} failed: {}",
            args,
            dir.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8(out.stdout)?.trim().to_string())
}

/// Hash a working tree: every non-`.git` file as `sha256(path)` then `sha256(bytes)`,
/// folded in sorted path order so the result is independent of filesystem iteration order.
pub fn hash_tree(root: &Path) -> Result<(String, u64, u64)> {
    let mut entries: BTreeMap<String, PathBuf> = BTreeMap::new();
    for entry in walkdir::WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| e.file_name() != ".git")
    {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(root)?
            .to_str()
            .ok_or_else(|| anyhow!("non-UTF-8 path {}", entry.path().display()))?
            .to_string();
        if FETCHER_MARKERS.contains(&rel.as_str()) {
            continue;
        }
        entries.insert(rel, entry.path().to_path_buf());
    }

    let mut outer = Sha256::new();
    let mut bytes_total = 0u64;
    for (rel, path) in &entries {
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        bytes_total += bytes.len() as u64;
        outer.update((rel.len() as u64).to_le_bytes());
        outer.update(rel.as_bytes());
        outer.update(Sha256::digest(&bytes));
    }
    Ok((
        hex::encode(outer.finalize()),
        entries.len() as u64,
        bytes_total,
    ))
}

/// SHA-256 of one file, lowercase hex.
pub fn hash_file(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

fn resolve_node(sources_root: &Path, spec: &SourceNodeSpec) -> Result<ResolvedSourceNode> {
    let dir = sources_root.join(&spec.name);
    if !dir.join(".git").exists() {
        bail!(
            "source node {} ({}) is not checked out at {}",
            spec.alias,
            spec.name,
            dir.display()
        );
    }

    let revision = git(&dir, &["rev-parse", "HEAD"])?;
    let git_tree = git(&dir, &["rev-parse", "HEAD^{tree}"])?;

    let dirty = git(&dir, &["status", "--porcelain"])?
        .lines()
        .any(|line| {
            let path = line.split_whitespace().last().unwrap_or_default();
            !FETCHER_MARKERS.contains(&path)
        });

    let shallow = dir.join(".git").join("shallow").exists();

    // A tag pin is resolved, not asserted; a commit pin must match byte for byte.
    let pin_mismatch = match (spec.pin_kind, spec.declared_pin.as_deref()) {
        (PinKind::Commit, Some(declared)) if declared != revision => Some(format!(
            "contract declares {declared}, checkout is at {revision}"
        )),
        (PinKind::Tag, Some(tag)) => {
            let resolved = git(&dir, &["rev-list", "-n1", tag]).unwrap_or_default();
            (resolved != revision).then(|| {
                format!("tag {tag} resolves to {resolved}, checkout is at {revision}")
            })
        }
        _ => None,
    };

    let (content_digest, file_count, byte_count) = hash_tree(&dir)?;

    Ok(ResolvedSourceNode {
        spec: spec.clone(),
        revision,
        git_tree,
        content_digest,
        file_count,
        byte_count,
        dirty,
        shallow,
        pin_mismatch,
    })
}

/// Resolve every declared node and fold them into a single graph digest.
pub fn build_lock(
    sources_root: &Path,
    specs: &[SourceNodeSpec],
    unresolved: Vec<UnresolvedNode>,
) -> Result<SourceLock> {
    let mut nodes = Vec::with_capacity(specs.len());
    for spec in specs {
        nodes.push(resolve_node(sources_root, spec)?);
    }
    nodes.sort_by(|a, b| a.spec.alias.cmp(&b.spec.alias));

    let mut hasher = Sha256::new();
    for node in &nodes {
        hasher.update(node.spec.alias.as_bytes());
        hasher.update(b"\0");
        hasher.update(node.revision.as_bytes());
        hasher.update(b"\0");
        hasher.update(node.content_digest.as_bytes());
        hasher.update(b"\n");
    }

    Ok(SourceLock {
        schema_version: 1,
        generator: concat!("source-lock ", env!("CARGO_PKG_VERSION")).to_string(),
        sources_root: sources_root.display().to_string(),
        nodes,
        source_graph_digest: hex::encode(hasher.finalize()),
        unresolved,
    })
}

/// The declared source graph: brief §1.1 plus addendum A17.5 and the owner's
/// directive to hold the Cloudflare OSS implementations and documentation locally.
pub fn declared_graph() -> Vec<SourceNodeSpec> {
    let n = |alias: &str,
             name: &str,
             origin: &str,
             pin_kind: PinKind,
             declared_pin: Option<&str>,
             role: NodeRole,
             licence: &str,
             purpose: &str| SourceNodeSpec {
        alias: alias.into(),
        name: name.into(),
        origin: origin.into(),
        pin_kind,
        declared_pin: declared_pin.map(str::to_string),
        role,
        licence: licence.into(),
        purpose: purpose.into(),
    };

    vec![
        n("TB", "typedb", "typedb/typedb", PinKind::Commit,
          Some("2256711abd532742dae8e822a9ad5cce63e69b1a"), NodeRole::Ships, "MPL-2.0",
          "soft-fork source and RocksDB/file-WAL semantic oracle"),
        n("SL", "slatedb", "slatedb/slatedb", PinKind::Commit,
          Some("f88be86d17ac53260d3684edbc8f82811d945b5c"), NodeRole::Ships, "Apache-2.0",
          "candidate object-store engine, version 0.15.0"),
        n("BH", "typedb-behaviour", "typedb/typedb-behaviour", PinKind::Commit,
          Some("ac5d5733a484cea1d8809a2968029a818fdae24f"), NodeRole::Proof, "MPL-2.0",
          "authoritative Cucumber feature corpus (scenario denominator)"),
        n("TBD", "typedb-dependencies", "typedb/dependencies", PinKind::Commit,
          Some("a5c51254088f343fb8b6a9668eaf99b35503dad4"), NodeRole::Proof, "MPL-2.0",
          "reconstruct generated Cargo/build metadata and artifact rules"),
        n("TBDIST", "typedb-bazel-distribution", "typedb/bazel-distribution", PinKind::Commit,
          Some("ab5bfc90274e2d34569d5bc22558314b551cdecd"), NodeRole::Proof, "Apache-2.0",
          "static target/macro/query audit oracle"),
        n("TQL", "typeql", "typedb/typeql", PinKind::Tag, Some("3.12.2"),
          NodeRole::Ships, "MPL-2.0", "TypeQL source/dependency identity"),
        n("TPROTO", "typedb-protocol", "typedb/typedb-protocol", PinKind::Tag, Some("3.12.0"),
          NodeRole::Ships, "MPL-2.0", "protocol source identity; frozen public API surface"),
        // Addendum A17.5: driver compatibility is a release gate.
        n("TDRIVER", "typedb-driver", "typedb/typedb-driver", PinKind::Tag, Some("3.12.3"),
          NodeRole::Proof, "MPL-2.0",
          "official polyglot driver suites (TS mandatory, Rust+Python minimal) as the compatibility denominator"),
        // Cloudflare graph: package identity is locked separately from source identity (§21.13).
        n("CF-CTR-SRC", "cloudflare-containers", "cloudflare/containers", PinKind::Snapshot, None,
          NodeRole::Ships, "MIT OR Apache-2.0", "container-lifecycle Durable Object helper"),
        n("CF-SDK", "cloudflare-workers-sdk", "cloudflare/workers-sdk", PinKind::Commit,
          Some("c576a8271503cc51babc1a8d0f2ef7d384f78742"), NodeRole::Compiles, "MIT OR Apache-2.0",
          "Wrangler, Miniflare and the Vitest worker pool"),
        // Reference implementations held locally so platform claims are read, never guessed.
        n("CF-WORKERD", "cloudflare-workerd", "cloudflare/workerd", PinKind::Snapshot, None,
          NodeRole::Proof, "Apache-2.0",
          "open-source Workers runtime: R2 bindings, Durable Object storage/alarms, container API"),
        n("CF-DOCS", "cloudflare-docs", "cloudflare/cloudflare-docs", PinKind::Snapshot, None,
          NodeRole::Proof, "Apache-2.0 / CC-BY-4.0",
          "official documentation source bytes for PlatformContractRecord claims"),
        n("CF-APISCHEMA", "cloudflare-api-schemas", "cloudflare/api-schemas", PinKind::Snapshot, None,
          NodeRole::Proof, "Apache-2.0",
          "Cloudflare/R2 OpenAPI schemas for control-plane request shapes"),
    ]
}

/// Graph nodes the fetchers deliberately do not guess (brief §1.1, `sources/UNRESOLVED.md`).
pub fn declared_unresolved() -> Vec<UnresolvedNode> {
    let u = |alias: &str, what: &str, gate: &str| UnresolvedNode {
        alias: alias.into(),
        what: what.into(),
        blocks_gate: gate.into(),
    };
    vec![
        u("TCONSOLE", "TypeDB Console 3.12.0 linux-x86_64 URL, SHA-256 and licence", "G1"),
        u("TLOADER", "TypeDB Loader 3.12.0 applicability to the selected corpus", "G1"),
        u("TB-BASE", "OCI digest for typedb/ubuntu:3.1.0-amd64 and the production base", "G0"),
        u("CF-CTR-PKG", "npm tarball integrity for @cloudflare/containers 0.3.7", "G0"),
        u("CF-VITEST", "npm tarball integrity for @cloudflare/vitest-pool-workers", "G0"),
        u("CF-WORKERD-PKG", "workerd runtime version selected by the locked Wrangler stack", "G0"),
        u("NATIVE", "compiler/linker/CMake/protoc/pkg-config/libc/TLS-root digests", "G0"),
        u("CF-ACCOUNT", "real-account probe context and probe evidence", "G1"),
    ]
}
