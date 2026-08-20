//! Path glob matching for the protected-path list and the scope manifest.
//!
//! Deliberately small and deliberately explicit, because a matcher that is
//! subtly too permissive silently disables the anti-gaming core. Semantics:
//!
//! * `**`  matches zero or more whole path segments
//! * `*`   matches zero or more characters within one segment (never `/`)
//! * `?`   matches exactly one character within one segment (never `/`)
//! * everything else is literal
//!
//! Paths are compared as repository-relative, forward-slash, no leading `./`.

/// Normalise a repository-relative path for matching.
pub fn normalize(path: &str) -> String {
    let p = path.replace('\\', "/");
    let p = p.strip_prefix("./").unwrap_or(&p);
    p.trim_start_matches('/').to_string()
}

/// True if `path` matches `pattern`.
pub fn matches(pattern: &str, path: &str) -> bool {
    let pat = normalize(pattern);
    let pth = normalize(path);
    let pat_segs: Vec<&str> = pat.split('/').filter(|s| !s.is_empty()).collect();
    let path_segs: Vec<&str> = pth.split('/').filter(|s| !s.is_empty()).collect();
    match_segments(&pat_segs, &path_segs)
}

fn match_segments(pat: &[&str], path: &[&str]) -> bool {
    match pat.first() {
        None => path.is_empty(),
        Some(&"**") => {
            // `**` consumes zero or more segments.
            (0..=path.len()).any(|skip| match_segments(&pat[1..], &path[skip..]))
        }
        Some(seg) => {
            if path.is_empty() {
                return false;
            }
            match_one_segment(seg, path[0]) && match_segments(&pat[1..], &path[1..])
        }
    }
}

fn match_one_segment(pat: &str, seg: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let s: Vec<char> = seg.chars().collect();
    seg_inner(&p, &s)
}

fn seg_inner(pat: &[char], seg: &[char]) -> bool {
    match pat.first() {
        None => seg.is_empty(),
        Some('*') => (0..=seg.len()).any(|skip| seg_inner(&pat[1..], &seg[skip..])),
        Some('?') => !seg.is_empty() && seg_inner(&pat[1..], &seg[1..]),
        Some(c) => !seg.is_empty() && seg[0] == *c && seg_inner(&pat[1..], &seg[1..]),
    }
}

/// First matching pattern in `patterns`, if any. Order is significant: callers
/// rely on "first rule wins" for scope classification.
pub fn first_match<'a, I: IntoIterator<Item = &'a str>>(patterns: I, path: &str) -> Option<&'a str> {
    patterns.into_iter().find(|p| matches(p, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_paths() {
        assert!(matches("deny.toml", "deny.toml"));
        assert!(!matches("deny.toml", "sub/deny.toml"));
        assert!(!matches("deny.toml", "deny.tomlx"));
    }

    #[test]
    fn double_star_matches_any_depth_including_zero() {
        assert!(matches(".quality/**", ".quality/policy.toml"));
        assert!(matches(".quality/**", ".quality/waivers/quality-waivers.toml"));
        assert!(matches(".quality/**", ".quality"));
        assert!(!matches(".quality/**", "quality/policy.toml"));
        assert!(!matches(".quality/**", "docs/.quality/policy.toml"));
    }

    #[test]
    fn single_star_never_crosses_a_separator() {
        assert!(matches("control-plane/*", "control-plane/package.json"));
        assert!(!matches("control-plane/*", "control-plane/src/index.ts"));
        assert!(matches("*.md", "README.md"));
        assert!(!matches("*.md", "docs/README.md"));
    }

    #[test]
    fn leading_double_star_matches_at_any_depth() {
        assert!(matches("**/Cargo.toml", "Cargo.toml"));
        assert!(matches("**/Cargo.toml", "tools/Cargo.toml"));
        assert!(matches("**/Cargo.toml", "fork/typedb/common/error/Cargo.toml"));
        assert!(!matches("**/Cargo.toml", "tools/Cargo.lock"));
    }

    #[test]
    fn question_mark_is_one_char() {
        assert!(matches("a?c.rs", "abc.rs"));
        assert!(!matches("a?c.rs", "ac.rs"));
        assert!(!matches("a?c.rs", "a/c.rs"));
    }

    #[test]
    fn normalization_handles_dot_slash_and_backslash() {
        assert!(matches(".quality/**", "./.quality/policy.toml"));
        assert!(matches(".quality/**", ".quality\\policy.toml"));
    }

    #[test]
    fn protected_globs_do_not_over_match_neighbouring_names() {
        // Regression guard: a matcher that treated `*` as "any characters"
        // would let `.quality-notes/foo` masquerade as protected policy, or
        // worse, let `xtask-scratch/**` escape protection.
        assert!(!matches(".quality/**", ".quality-notes/foo"));
        assert!(!matches("xtask/**", "xtask-scratch/src/main.rs"));
        assert!(matches("xtask/**", "xtask/src/quality/policy.rs"));
    }

    #[test]
    fn first_match_is_order_sensitive() {
        let pats = ["tools/remote-wal-spike/**", "tools/**"];
        assert_eq!(first_match(pats, "tools/remote-wal-spike/src/lib.rs"), Some("tools/remote-wal-spike/**"));
        assert_eq!(first_match(pats, "tools/catalog/common.py"), Some("tools/**"));
        assert_eq!(first_match(pats, "docs/x.md"), None);
    }
}
