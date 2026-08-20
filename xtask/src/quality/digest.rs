//! Policy and toolchain digests (spec §4: every report carries both).
//!
//! Both digests are order-independent of directory iteration: inputs are
//! sorted before hashing so the same tree always yields the same digest on any
//! machine.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// `sha256:` prefixed hex digest of the given already-ordered key/value pairs.
///
/// Each pair is fed as `key\0len\0value\0` so that no concatenation ambiguity
/// exists between a long key and a short value.
pub fn digest_pairs(pairs: &[(String, Vec<u8>)]) -> String {
    let mut sorted: Vec<&(String, Vec<u8>)> = pairs.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut hasher = Sha256::new();
    for (k, v) in sorted {
        hasher.update(k.as_bytes());
        hasher.update([0u8]);
        hasher.update(v.len().to_le_bytes());
        hasher.update([0u8]);
        hasher.update(v);
        hasher.update([0u8]);
    }
    format!("sha256:{:x}", hasher.finalize())
}

/// Every regular file under `root`, repository-relative, sorted.
pub fn collect_files(root: &Path, rel_prefix: &str) -> std::io::Result<Vec<(String, PathBuf)>> {
    let mut out = Vec::new();
    walk(root, rel_prefix, &mut out)?;
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn walk(dir: &Path, rel: &str, out: &mut Vec<(String, PathBuf)>) -> std::io::Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let name = entry.file_name().to_string_lossy().to_string();
        let child_rel = if rel.is_empty() { name.clone() } else { format!("{rel}/{name}") };
        let path = entry.path();
        if path.is_dir() {
            walk(&path, &child_rel, out)?;
        } else if path.is_file() {
            out.push((child_rel, path));
        }
    }
    Ok(())
}

/// Digest of the whole `.quality/` tree plus any extra protected policy files
/// that exist. Missing files contribute the literal marker `<absent>` so that
/// deleting a policy file changes the digest rather than silently matching a
/// tree in which it never existed.
pub fn policy_digest(repo_root: &Path, extra: &[&str]) -> (String, Vec<String>) {
    let mut pairs: Vec<(String, Vec<u8>)> = Vec::new();
    let mut inputs: Vec<String> = Vec::new();

    if let Ok(files) = collect_files(&repo_root.join(".quality"), ".quality") {
        for (rel, path) in files {
            let bytes = std::fs::read(&path).unwrap_or_default();
            inputs.push(rel.clone());
            pairs.push((rel, bytes));
        }
    }
    for rel in extra {
        let path = repo_root.join(rel);
        let bytes = if path.is_file() { std::fs::read(&path).unwrap_or_default() } else { b"<absent>".to_vec() };
        inputs.push((*rel).to_string());
        pairs.push(((*rel).to_string(), bytes));
    }
    inputs.sort();
    inputs.dedup();
    (digest_pairs(&pairs), inputs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_stable_and_order_independent() {
        let a = vec![("a".to_string(), b"1".to_vec()), ("b".to_string(), b"2".to_vec())];
        let b = vec![("b".to_string(), b"2".to_vec()), ("a".to_string(), b"1".to_vec())];
        assert_eq!(digest_pairs(&a), digest_pairs(&b));
        assert!(digest_pairs(&a).starts_with("sha256:"));
        assert_eq!(digest_pairs(&a).len(), "sha256:".len() + 64);
    }

    #[test]
    fn digest_changes_when_any_input_changes() {
        let base = vec![("a".to_string(), b"1".to_vec())];
        let changed = vec![("a".to_string(), b"2".to_vec())];
        let renamed = vec![("z".to_string(), b"1".to_vec())];
        assert_ne!(digest_pairs(&base), digest_pairs(&changed));
        assert_ne!(digest_pairs(&base), digest_pairs(&renamed));
    }

    #[test]
    fn key_value_boundary_is_unambiguous() {
        // Without length framing these two would hash identically.
        let x = vec![("ab".to_string(), b"c".to_vec())];
        let y = vec![("a".to_string(), b"bc".to_vec())];
        assert_ne!(digest_pairs(&x), digest_pairs(&y));
    }
}
