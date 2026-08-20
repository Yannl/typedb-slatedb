//! Git plumbing. Every call is explicit and read-only: the controller never
//! mutates the repository it is judging.

use std::path::{Path, PathBuf};
use std::process::Command;

pub fn run(repo_root: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .output()
        .map_err(|e| format!("git {args:?}: {e}"))?;
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
    let out = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .output()
        .map_err(|e| format!("git {args:?}: {e}"))?;
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

/// Added lines of a diff, used for the content-based §15 triggers
/// (`unsafe`, FFI, `[features]`, public API).
pub fn added_lines(repo_root: &Path, base: Option<&str>) -> Result<String, String> {
    let range = match base {
        Some(b) => format!("{b}...HEAD"),
        None => "HEAD".to_string(),
    };
    let text = run(repo_root, &["diff", "--unified=0", "--no-color", &range])?;
    Ok(text
        .lines()
        .filter(|l| l.starts_with('+') && !l.starts_with("+++"))
        .map(|l| &l[1..])
        .collect::<Vec<_>>()
        .join("\n"))
}
