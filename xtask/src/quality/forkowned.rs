//! Which files under a fork overlay are actually OURS.
//!
//! `fork/typedb/` is a file overlay on a pinned upstream checkout, and it is
//! overwhelmingly upstream: 778 files, of which 29 are modified and 7 are new.
//! Linting the other 742 means adopting TypeDB's entire codebase as our own for
//! lint purposes — measured on 2026-08-21, that was 651 of 696 clippy findings,
//! 93.5% of them about code nobody here wrote or may change.
//!
//! Fixing those findings is not an option either: the fork's patch set IS its
//! identity (`fork_staging.staged_tree_sha256` in the workspace lock, which
//! every sealed evidence bundle binds), so cosmetic edits to upstream files
//! would grow it from 36 paths to hundreds and invalidate that identity.
//!
//! So ownership is DERIVED, never declared: a file is ours when its bytes
//! differ from the pinned upstream revision, or when upstream has no such file.
//! Nothing to keep in sync, and reverting a fork file to upstream's bytes
//! correctly stops gating it — it is upstream's code again.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

/// Files under the fork root whose content is not upstream's.
#[derive(Debug, Clone, Default)]
pub struct ForkOwnership {
    owned: BTreeSet<String>,
    pub upstream_identical: usize,
}

impl ForkOwnership {
    /// Construct an explicit ownership set. Tests only: real ownership is
    /// always DERIVED by `detect`, never declared.
    #[cfg(test)]
    pub fn for_test(owned: &[&str], upstream_identical: usize) -> ForkOwnership {
        ForkOwnership { owned: owned.iter().map(|s| s.to_string()).collect(), upstream_identical }
    }

    /// Is this path (relative to the fork root) ours to gate?
    pub fn owns(&self, rel: &str) -> bool {
        self.owned.contains(rel)
    }

    pub fn len(&self) -> usize {
        self.owned.len()
    }

    pub fn is_empty(&self) -> bool {
        self.owned.is_empty()
    }
}

/// The upstream revision the source lock pins, read from the lock rather than
/// from whatever the checkout happens to be sitting on.
pub fn locked_revision(repo_root: &Path, node_id: &str) -> Result<String, String> {
    let path = repo_root.join("source-lock/source-lock.json");
    let text = std::fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let doc: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("{} is not valid JSON: {e}", path.display()))?;
    doc.get("nodes")
        .and_then(|n| n.as_array())
        .ok_or_else(|| "source-lock.json has no `nodes` array".to_string())?
        .iter()
        .find(|n| n.get("id").and_then(|i| i.as_str()) == Some(node_id))
        .and_then(|n| n.get("revision").and_then(|r| r.as_str()))
        .map(str::to_string)
        .ok_or_else(|| format!("source-lock.json has no revision for node `{node_id}`"))
}

fn git(dir: &Path, args: &[&str]) -> Result<String, String> {
    let out =
        Command::new("git").arg("-C").arg(dir).args(args).output().map_err(|e| format!("could not run git: {e}"))?;
    if !out.status.success() {
        return Err(format!("git {} failed: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Every blob in the upstream tree at `revision`, as path -> object id.
fn upstream_blobs(checkout: &Path, revision: &str) -> Result<BTreeMap<String, String>, String> {
    let listing = git(checkout, &["ls-tree", "-r", revision])?;
    let mut map = BTreeMap::new();
    for line in listing.lines() {
        // "<mode> <type> <object>\t<path>"
        let (meta, path) = match line.split_once('\t') {
            Some(v) => v,
            None => continue,
        };
        let mut it = meta.split_whitespace();
        let (_mode, kind, oid) = match (it.next(), it.next(), it.next()) {
            (Some(a), Some(b), Some(c)) => (a, b, c),
            _ => continue,
        };
        if kind == "blob" {
            map.insert(path.to_string(), oid.to_string());
        }
    }
    Ok(map)
}

/// Directories and files that are NOT part of the overlay.
///
/// These mirror `SKIP_DIRS` and `FORK_ONLY` in `tools/fork/stage.py`, which is
/// the tool that actually stages the overlay. The two must agree on what the
/// fork's file set is: if they drift, one of them is gating or staging a set
/// the other does not recognise. FORK_ONLY entries are our own provenance
/// notes, never copied onto the upstream checkout.
const SKIP_DIRS: [&str; 3] = [".git", "target", "node_modules"];
const FORK_ONLY: [&str; 2] = ["PORT-LEDGER.md", "UPSTREAM-PROVENANCE"];

/// Files under `fork_root`, relative, matching stage.py's view of the overlay.
fn fork_files(root: &Path) -> Vec<String> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                // stage.py tests only the FIRST path segment, so a nested
                // directory of the same name is walked, exactly as there.
                let top = p
                    .strip_prefix(base)
                    .ok()
                    .and_then(|r| r.components().next().map(|c| c.as_os_str().to_string_lossy().to_string()));
                if top.as_deref().is_some_and(|t| SKIP_DIRS.contains(&t)) {
                    continue;
                }
                walk(&p, base, out);
            } else if let Ok(rel) = p.strip_prefix(base) {
                let rel = rel.to_string_lossy().replace('\\', "/");
                if FORK_ONLY.contains(&rel.as_str()) {
                    continue;
                }
                out.push(rel);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

/// Git object ids for many files in one process. `git hash-object` computes the
/// same sha1-of-blob git itself stores, so ids are directly comparable to
/// `ls-tree` output without reimplementing git's hashing.
fn hash_objects(repo_root: &Path, fork_root: &Path, rels: &[String]) -> Result<Vec<String>, String> {
    use std::io::Write;
    let mut child = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["hash-object", "--stdin-paths"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not run git hash-object: {e}"))?;
    {
        let mut stdin = child.stdin.take().ok_or("git hash-object stdin unavailable")?;
        for rel in rels {
            writeln!(stdin, "{}", fork_root.join(rel).display())
                .map_err(|e| format!("writing to git hash-object: {e}"))?;
        }
    }
    let out = child.wait_with_output().map_err(|e| format!("git hash-object: {e}"))?;
    if !out.status.success() {
        return Err(format!("git hash-object failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).lines().map(str::to_string).collect())
}

/// Compare the overlay against the pinned upstream tree.
pub fn detect(
    repo_root: &Path,
    fork_root_rel: &str,
    upstream_rel: &str,
    node_id: &str,
) -> Result<ForkOwnership, String> {
    let fork_root = repo_root.join(fork_root_rel);
    let checkout = repo_root.join(upstream_rel);
    if !checkout.join(".git").exists() {
        return Err(format!(
            "{upstream_rel} is not a git checkout — it is materialised from source-lock/ and is \
             gitignored; run `python3 tools/source-lock/materialize_sources.py` first"
        ));
    }
    let revision = locked_revision(repo_root, node_id)?;
    let upstream = upstream_blobs(&checkout, &revision)?;
    let rels = fork_files(&fork_root);
    let ids = hash_objects(repo_root, &fork_root, &rels)?;
    if ids.len() != rels.len() {
        return Err(format!(
            "git hash-object returned {} ids for {} files; refusing to guess the alignment",
            ids.len(),
            rels.len()
        ));
    }
    let mut owned = BTreeSet::new();
    let mut identical = 0usize;
    for (rel, id) in rels.iter().zip(ids.iter()) {
        match upstream.get(rel) {
            Some(up) if up == id => identical += 1,
            _ => {
                owned.insert(rel.clone());
            }
        }
    }
    Ok(ForkOwnership { owned, upstream_identical: identical })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_locked_revision_comes_from_the_lock_not_the_checkout() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let rev = locked_revision(root, "TB").expect("TB node must carry a revision");
        assert_eq!(rev.len(), 40, "a git revision is 40 hex characters, got {rev:?}");
        assert!(rev.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(locked_revision(root, "NO_SUCH_NODE").is_err());
    }

    #[test]
    fn ownership_answers_only_for_paths_it_was_given() {
        let o = ForkOwnership { owned: ["storage/slate.rs".to_string()].into_iter().collect(), upstream_identical: 7 };
        assert!(o.owns("storage/slate.rs"));
        assert!(!o.owns("resource/profile.rs"));
        assert!(!o.is_empty());
        assert_eq!(o.len(), 1);
    }

    #[test]
    fn an_absent_upstream_checkout_is_a_typed_error_not_a_silent_empty_set() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let e = detect(root, "fork/typedb", "sources/definitely-not-here", "TB")
            .expect_err("an absent checkout must not read as 'nothing is owned'");
        assert!(e.contains("materialize_sources.py"), "the error must name the remedy, got: {e}");
    }
}
