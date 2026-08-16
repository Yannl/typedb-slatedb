//! Semantic port of `release_validate_deps` (CR-A-02).
//!
//! Upstream this is a Kotlin/JVM pair of Bazel test targets that no Cargo reading can see:
//! `_release_validate_deps_script_test` (a rule with `test = True`) plus a `kt_jvm_test`,
//! from TBD `tool/release/deps/rules.bzl` L29-70. The body is
//! `tool/release/deps/ValidateDeps.kt`, and it asserts exactly two things:
//!
//! 1. **L33-39** — every dependency named in `tagged_deps` appears under `tags` in the
//!    workspace refs, i.e. it is pinned by *tag* rather than by bare commit. A release must
//!    not ship against a snapshot dependency.
//! 2. **L40-50** — if `VERSION` is not itself an RC, no tagged dependency's tag may contain
//!    `rc`. A stable release must not depend on a release candidate.
//!
//! The port reads the same facts from the pinned sources. Upstream's `refs.json` is generated
//! by Bazel and does not exist in a Cargo checkout, so the tag declarations are read from
//! `MODULE.bazel` — which is what Bazel itself generates `refs.json` from, so this is the
//! same fact one step earlier rather than a different fact.

use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct DepValidation {
    pub version: String,
    pub version_is_rc: bool,
    pub tagged_deps: Vec<TaggedDep>,
    pub findings: Vec<String>,
    pub passed: bool,
}

#[derive(Debug, Serialize)]
pub struct TaggedDep {
    pub module_name: String,
    /// `None` when the module is declared some way other than by tag.
    pub tag: Option<String>,
}

/// The dependencies TypeDB's root BUILD passes as `tagged_deps`.
///
/// Upstream writes them `@typeql+` / `@typedb_protocol+`; the `@` and trailing `+` are Bazel
/// apparent-name syntax, and `ValidateDeps.kt` L27 strips the `@` before comparing.
const TAGGED_DEPS: [&str; 2] = ["typeql", "typedb_protocol"];

/// Read `git_override(module_name = "x", …, tag = "y")` declarations from MODULE.bazel.
fn declared_tags(module_bazel: &str) -> Vec<TaggedDep> {
    TAGGED_DEPS
        .iter()
        .map(|name| {
            // Find the override block naming this module, then its `tag =` within.
            let tag = module_bazel
                .split("module_name")
                .find(|block| block.starts_with(&format!(" = \"{name}\"")))
                .and_then(|block| {
                    let idx = block.find("tag = \"")?;
                    let rest = &block[idx + 7..];
                    rest.find('"').map(|end| rest[..end].to_string())
                });
            TaggedDep { module_name: name.to_string(), tag }
        })
        .collect()
}

pub fn validate(typedb_root: &Path) -> Result<DepValidation> {
    let version = std::fs::read_to_string(typedb_root.join("VERSION"))
        .context("reading VERSION")?
        .trim()
        .to_string();
    let module_bazel = std::fs::read_to_string(typedb_root.join("MODULE.bazel"))
        .context("reading MODULE.bazel")?;

    let tagged_deps = declared_tags(&module_bazel);
    let version_is_rc = version.to_lowercase().contains("rc");
    let mut findings = Vec::new();

    // Check 1 (ValidateDeps.kt L33-39): declared by tag, not by commit.
    for dep in &tagged_deps {
        if dep.tag.is_none() {
            findings.push(format!(
                "{} is expected to be declared by tag but MODULE.bazel declares no tag for it",
                dep.module_name
            ));
        }
    }

    // Check 2 (L40-50): a stable release must not depend on a release candidate.
    if !version_is_rc {
        for dep in &tagged_deps {
            if let Some(tag) = &dep.tag {
                if tag.to_lowercase().contains("rc") {
                    findings.push(format!(
                        "RC dependency in non-RC release {version}: {}: {tag}",
                        dep.module_name
                    ));
                }
            }
        }
    }

    Ok(DepValidation { version, version_is_rc, tagged_deps, passed: findings.is_empty(), findings })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODULE: &str = r#"
bazel_dep(name = "typeql", version = "0.0.0")
git_override(
    module_name = "typeql",
    remote = "https://github.com/typedb/typeql",
    tag = "3.12.2",
)
bazel_dep(name = "typedb_protocol", version = "0.0.0")
git_override(
    module_name = "typedb_protocol",
    remote = "https://github.com/typedb/typedb-protocol",
    tag = "3.12.0",
)
"#;

    #[test]
    fn reads_the_tag_of_each_dependency() {
        let deps = declared_tags(MODULE);
        assert_eq!(deps[0].tag.as_deref(), Some("3.12.2"));
        assert_eq!(deps[1].tag.as_deref(), Some("3.12.0"));
    }

    #[test]
    fn a_dependency_pinned_by_commit_has_no_tag() {
        // ValidateDeps.kt L33-39: a release must not ship against a snapshot dependency.
        let by_commit = MODULE.replace("tag = \"3.12.2\"", "commit = \"7f4cac93fa8e\"");
        let deps = declared_tags(&by_commit);
        assert!(deps[0].tag.is_none(), "a commit pin is not a tag pin");
    }

    #[test]
    fn a_module_name_that_is_a_prefix_of_another_is_not_confused() {
        // "typeql" is a prefix of nothing here, but the block search must anchor on the
        // closing quote rather than a prefix match, or `typedb` would match `typedb_protocol`.
        let deps = declared_tags(MODULE);
        assert_eq!(deps[1].module_name, "typedb_protocol");
        assert_eq!(deps[1].tag.as_deref(), Some("3.12.0"));
    }
}
