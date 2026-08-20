//! Git plumbing. Every call is explicit and read-only: the controller never
//! mutates the repository it is judging.

use std::path::{Path, PathBuf};
use std::process::Command;

pub fn run(repo_root: &Path, args: &[&str]) -> Result<String, String> {
    let out =
        Command::new("git").arg("-C").arg(repo_root).args(args).output().map_err(|e| format!("git {args:?}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git {args:?} failed with {}: {}",
            out.status.code().map(|c| c.to_string()).unwrap_or_else(|| "signal".into()),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

pub fn run_bytes(repo_root: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let out =
        Command::new("git").arg("-C").arg(repo_root).args(args).output().map_err(|e| format!("git {args:?}: {e}"))?;
    if !out.status.success() {
        return Err(format!("git {args:?} failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(out.stdout)
}

/// Repository root, discovered from the current directory.
pub fn repo_root() -> Result<PathBuf, String> {
    let out = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|e| format!("git rev-parse --show-toplevel: {e}"))?;
    if !out.status.success() {
        return Err("not inside a git repository".to_string());
    }
    Ok(PathBuf::from(String::from_utf8_lossy(&out.stdout).trim()))
}

pub fn head_sha(repo_root: &Path) -> Result<String, String> {
    Ok(run(repo_root, &["rev-parse", "HEAD"])?.trim().to_string())
}

/// Resolve any revision to a full 40-character SHA. Fails loudly for an
/// unknown revision: a merge gate must not silently fall back to "no base".
pub fn resolve(repo_root: &Path, rev: &str) -> Result<String, String> {
    let sha = run(repo_root, &["rev-parse", "--verify", &format!("{rev}^{{commit}}")])
        .map_err(|e| format!("cannot resolve base revision {rev:?}: {e}"))?;
    Ok(sha.trim().to_string())
}

/// True when the working tree and index exactly match HEAD, ignoring untracked
/// files that git itself ignores. Evidence gathered from a dirty tree does not
/// correspond to `head_sha` and is flagged as such in the report.
pub fn worktree_clean(repo_root: &Path) -> Result<bool, String> {
    Ok(run(repo_root, &["status", "--porcelain", "--untracked-files=normal"])?.trim().is_empty())
}

/// File content at a revision, or `None` when the path did not exist there.
pub fn show_file(repo_root: &Path, rev: &str, path: &str) -> Option<String> {
    let out = Command::new("git").arg("-C").arg(repo_root).args(["show", &format!("{rev}:{path}")]).output().ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        None
    }
}

/// `git diff --name-status -M -z <base>...HEAD`, NUL-delimited so paths with
/// spaces or quotes cannot be mis-parsed.
pub fn diff_name_status(repo_root: &Path, base: &str) -> Result<Vec<u8>, String> {
    run_bytes(repo_root, &["diff", "--name-status", "-M", "-z", &format!("{base}...HEAD")])
}

/// Working-tree change set (tracked modifications plus untracked files), used
/// by `quality fast`, which has no base SHA.
pub fn worktree_name_status(repo_root: &Path) -> Result<Vec<u8>, String> {
    let mut bytes = run_bytes(repo_root, &["diff", "--name-status", "-M", "-z", "HEAD"])?;
    let untracked = run_bytes(repo_root, &["ls-files", "--others", "--exclude-standard", "-z"])?;
    for path in untracked.split(|b| *b == 0) {
        if path.is_empty() {
            continue;
        }
        bytes.extend_from_slice(b"A");
        bytes.push(0);
        bytes.extend_from_slice(path);
        bytes.push(0);
    }
    Ok(bytes)
}

/// Added lines of a diff, attributed to the file they were added to, for the
/// content-based §15 triggers (`unsafe`, FFI, `[features]`, public API).
///
/// Attribution matters: an `unsafe` token inside a documentation snippet or a
/// controller test fixture must not make an unrelated diff look like a change
/// to a raw-pointer surface.
pub fn added_lines_by_file(repo_root: &Path, base: Option<&str>) -> Result<Vec<(String, String)>, String> {
    let range = match base {
        Some(b) => format!("{b}...HEAD"),
        None => "HEAD".to_string(),
    };
    let text = run(repo_root, &["diff", "--unified=0", "--no-color", &range])?;
    Ok(parse_added_lines(&text))
}

/// Split `git diff --unified=0` output into (path, added text) pairs.
pub fn parse_added_lines(diff: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut current: Option<String> = None;
    for line in diff.lines() {
        if let Some(rest) = line.strip_prefix("+++ ") {
            let path = rest.trim();
            current = if path == "/dev/null" {
                None
            } else {
                Some(super::glob::normalize(path.strip_prefix("b/").unwrap_or(path)))
            };
            continue;
        }
        if line.starts_with("--- ") || line.starts_with("diff --git ") {
            continue;
        }
        if let (Some(path), Some(added)) = (current.as_ref(), line.strip_prefix('+')) {
            match out.iter_mut().find(|(p, _)| p == path) {
                Some((_, buf)) => {
                    buf.push('\n');
                    buf.push_str(added);
                }
                None => out.push((path.clone(), added.to_string())),
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn added_lines_are_attributed_to_their_file() {
        let diff = "diff --git a/src/a.rs b/src/a.rs\n\
                    --- a/src/a.rs\n\
                    +++ b/src/a.rs\n\
                    @@ -1,0 +2 @@\n\
                    +let p: *mut u8 = q;\n\
                    diff --git a/docs/note.md b/docs/note.md\n\
                    --- a/docs/note.md\n\
                    +++ b/docs/note.md\n\
                    @@ -1,0 +2 @@\n\
                    +we should never write unsafe code\n";
        let parsed = parse_added_lines(diff);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, "src/a.rs");
        assert!(parsed[0].1.contains("*mut u8"));
        assert_eq!(parsed[1].0, "docs/note.md");
        assert!(!parsed[0].1.contains("never write unsafe"));
    }

    #[test]
    fn a_deleted_file_contributes_no_added_lines() {
        let diff = "diff --git a/x.rs b/x.rs\n--- a/x.rs\n+++ /dev/null\n@@ -1 +0,0 @@\n-unsafe { }\n";
        assert!(parse_added_lines(diff).is_empty());
    }
}
