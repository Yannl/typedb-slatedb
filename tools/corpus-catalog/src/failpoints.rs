//! Failpoint-registry enumeration.
//!
//! Verified at TB `2256711a`:
//! * `common/fail_point/lib.rs` declares the registry through a `fail_points! { … }`
//!   macro that emits `pub const ALL: [&str; COUNT]` (L23-29 macro, L33+ member list).
//! * `tests/assembly/fail_points.rs` iterates `fail_point::ALL` twice — once in
//!   `test_fail_point_always` (L95) and once in `test_fail_point_chance` (L126).
//!
//! So the leaf-case count is `registry members × loop contexts`, not two opaque cases
//! (brief §22.2: "a composite Rust test that loops over many scenarios counts each
//! scenario/failpoint as a leaf case").

use anyhow::{bail, Result};

/// One `(failpoint, harness case)` pair — the executable leaf unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailpointCase {
    pub fail_point: String,
    /// The `#[test]` function that loops over the registry.
    pub loop_context: String,
}

/// Read the registry members out of the `fail_points! { … }` macro invocation.
pub fn parse_registry(lib_rs: &str) -> Result<Vec<String>> {
    // Find the invocation, not the `macro_rules!` definition.
    let mut search_from = 0usize;
    let body = loop {
        let Some(rel) = lib_rs[search_from..].find("fail_points!") else {
            bail!("no `fail_points!` invocation found in the fail_point crate");
        };
        let at = search_from + rel;
        let is_definition = lib_rs[..at].trim_end().ends_with("macro_rules!");
        let Some(open_rel) = lib_rs[at..].find('{') else {
            bail!("`fail_points!` at byte {at} has no opening brace");
        };
        let open = at + open_rel;
        let mut depth = 0usize;
        let mut close = None;
        for (i, ch) in lib_rs[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(open + i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(close) = close else {
            bail!("`fail_points!` at byte {at} has an unbalanced brace");
        };
        if !is_definition {
            break &lib_rs[open + 1..close];
        }
        search_from = close;
    };

    let members: Vec<String> = body
        .split(',')
        .map(|s| {
            // Strip comments and whitespace from each entry.
            s.lines()
                .map(|l| l.split("//").next().unwrap_or_default().trim())
                .filter(|l| !l.is_empty())
                .collect::<Vec<_>>()
                .join("")
        })
        .filter(|s| !s.is_empty())
        .collect();

    if members.is_empty() {
        bail!("`fail_points!` invocation parsed to zero members; refusing to emit an empty registry");
    }
    for m in &members {
        if !m.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_') {
            bail!("unexpected failpoint registry entry {m:?}; refusing to guess");
        }
    }
    Ok(members)
}

/// Find the `#[test]` functions that iterate `fail_point::ALL`.
///
/// Each such loop multiplies the registry, so missing one would undercount the
/// denominator and inventing one would overcount it. Both are failures.
pub fn parse_loop_contexts(harness_rs: &str) -> Result<Vec<String>> {
    let mut contexts = Vec::new();
    let mut current_fn: Option<String> = None;
    for line in harness_rs.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("fn ") {
            let name: String = rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
            if !name.is_empty() {
                current_fn = Some(name);
            }
        }
        if trimmed.contains("fail_point::ALL") && trimmed.starts_with("for ") {
            match &current_fn {
                Some(name) => {
                    if !contexts.contains(name) {
                        contexts.push(name.clone());
                    }
                }
                None => bail!("found a `fail_point::ALL` loop outside any function"),
            }
        }
    }
    if contexts.is_empty() {
        bail!("no `fail_point::ALL` loop found in the failpoint harness");
    }
    Ok(contexts)
}

/// Cross the registry with its loop contexts, in deterministic order.
pub fn expand(members: &[String], contexts: &[String]) -> Vec<FailpointCase> {
    let mut out = Vec::with_capacity(members.len() * contexts.len());
    for ctx in contexts {
        for m in members {
            out.push(FailpointCase { fail_point: m.clone(), loop_context: ctx.clone() });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIB: &str = r#"
macro_rules! fail_points {
    ($($name:ident),* $(,)?) => {
        const COUNT: usize = [$($name),*].len();
        pub const ALL: [&str; COUNT] = [$($name),*];
    };
}

fail_points! {
    CHECKPOINT_CLEANUP_FAIL,
    WAL_RECORD_UNFLUSHED,
}
"#;

    #[test]
    fn skips_the_macro_definition_and_reads_the_invocation() {
        let members = parse_registry(LIB).unwrap();
        assert_eq!(members, vec!["CHECKPOINT_CLEANUP_FAIL", "WAL_RECORD_UNFLUSHED"]);
    }

    #[test]
    fn finds_every_loop_context() {
        let harness = r#"
#[test]
fn test_fail_point_always() {
    for fail_point in fail_point::ALL {
    }
}

#[test]
fn test_fail_point_chance() {
    for fail_point in fail_point::ALL {
    }
}
"#;
        assert_eq!(
            parse_loop_contexts(harness).unwrap(),
            vec!["test_fail_point_always", "test_fail_point_chance"]
        );
    }

    #[test]
    fn expansion_is_members_times_contexts() {
        let members = parse_registry(LIB).unwrap();
        let contexts = vec!["a".to_string(), "b".to_string()];
        assert_eq!(expand(&members, &contexts).len(), 4);
    }

    #[test]
    fn refuses_to_emit_an_empty_registry() {
        assert!(parse_registry("fail_points! { }").is_err());
        assert!(parse_loop_contexts("fn nothing() {}").is_err());
    }
}
