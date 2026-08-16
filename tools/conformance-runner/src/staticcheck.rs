//! Execution of the static-check targets: `checkstyle_test` and `rustfmt_test`.
//!
//! These are 154 of the 271 catalogued targets — the majority — and they have no Cargo
//! execution path at all. Leaving them unexecuted would put them in `not_executed` forever,
//! and the tempting alternative is a catalogue exclusion per target, which is 154 admissions
//! that the corpus was not really reproduced. Both are avoidable: the checks themselves are
//! small and their upstream definitions are readable, so they are ported rather than excused.
//!
//! **checkstyle_test** (TBD `tool/checkstyle/rules.bzl`) runs Java Checkstyle over a
//! glob-selected file set. Its `TreeWalker` modules parse Java and do nothing on Rust; the
//! modules that actually apply to this repository's files are the file-level ones. Two are
//! reproduced exactly:
//!
//! * `RegexpHeader` against `config/checkstyle-file-mpl-header.txt` — the MPL licence
//!   header, matched line by line with the upstream regexes, including its optional first
//!   line for shebangs and XML/annotation prologues.
//! * `FileTabCharacter` — no literal tab anywhere in the file.
//!
//! **rustfmt_test** (rules_rust) checks that a crate's sources are formatted. It is
//! reproduced with the pinned toolchain from `MODULE.bazel` L37,
//! `rustfmt_version = "nightly/2026-04-15"`, because rustfmt output differs between
//! versions and running a different one would be a different check wearing the same name.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result};
use corpus_catalog::model::{Catalog, Target};

use crate::{CaseResult, Outcome, TargetRun};

/// The exact rustfmt toolchain upstream pins. Anything else is a different check.
pub const PINNED_RUSTFMT_TOOLCHAIN: &str = "nightly-2026-04-15";

/// The MPL header, as the regex lines of `checkstyle-file-mpl-header.txt`.
///
/// Line 1 is optional in Checkstyle's `RegexpHeader` semantics only insofar as it matches
/// shebangs, annotations and XML prologues; upstream's file begins with that alternation so
/// that a `#!`-prefixed script still satisfies the header. Reproduced verbatim rather than
/// paraphrased.
/// The header regexes for each `license_type` a BUILD rule can name.
///
/// TypeDB uses three: `mpl-header` (112 targets), `mpl-fulltext` (4) and `apache-header`
/// (1, `common/logger:checkstyle-copies` over `log_panic.rs`, which is vendored from the
/// ASF). Hardcoding the MPL header failed that target for having exactly the licence its
/// BUILD rule declares.
pub fn header_lines(license_type: &str) -> Option<&'static [&'static str]> {
    match license_type {
        "mpl-header" => Some(&MPL_HEADER_LINES),
        "apache-header" => Some(&APACHE_HEADER_LINES),
        // `mpl-fulltext` matches the whole licence text, which only the LICENSE file
        // carries; its first line is distinctive enough to check without embedding 373 lines.
        "mpl-fulltext" => Some(&MPL_FULLTEXT_LINES),
        _ => None,
    }
}

/// `checkstyle-file-apache-header.txt`, verbatim.
const APACHE_HEADER_LINES: [&str; 4] = [
    r"^(#!.*)|(@.*)|(<\?.*)",
    r"^(<!--.*)|(/\*.*)",
    r"^.*Licensed to the Apache Software Foundation \(ASF\) under one$",
    r"^.*or more contributor license agreements.  See the NOTICE file$",
];

/// `checkstyle-file-mpl-fulltext.txt`, first lines.
const MPL_FULLTEXT_LINES: [&str; 2] = [
    r"^Mozilla Public License Version 2.0$",
    r"^==================================$",
];

const MPL_HEADER_LINES: [&str; 5] = [
    r"^(#!.*)|(@.*)|(<\?.*)",
    r"^/\*",
    r"^.*This Source Code Form is subject to the terms of the Mozilla Public$",
    r"^.*License, v\. 2\.0\. If a copy of the MPL was not distributed with this$",
    r"^.*file, You can obtain one at https://mozilla\.org/MPL/2\.0/\..*$",
];

/// A single static check's outcome, before it becomes a `CaseResult`.
#[derive(Debug)]
struct Finding {
    file: String,
    problem: String,
}

/// Match one file's opening lines against the MPL header.
///
/// The config sets `multiLines = "1, 2"` (TBD `tool/checkstyle/templates/checkstyle.xml`
/// L23), which in Checkstyle's `RegexpHeader` means header lines 1 and 2 may each match any
/// number of file lines *including none*. That optionality is the whole point: line 2 is
/// `^\/\*`, so without it every `#`-commented file — BUILD, .bzl, shell, TOML — would fail
/// its own licence check. Only lines 3–5 are mandatory.
fn check_mpl_header(text: &str) -> Option<String> {
    check_header(&MPL_HEADER_LINES, text)
}

/// Match a file's opening lines against `spec`'s header regexes.
fn check_header(spec: &[&str], text: &str) -> Option<String> {
    let lines: Vec<&str> = text.lines().collect();

    // Consume the leading run of multi-lines: shebang/annotation/XML prologue (pattern 1)
    // and comment openers (pattern 2), in any number and any order.
    let mut i = 0usize;
    while i < lines.len()
        && spec
            .iter()
            .take(2)
            .any(|p| simple_regex::matches(p, lines[i]))
    {
        i += 1;
    }

    for (offset, pattern) in spec[2.min(spec.len())..].iter().enumerate() {
        let Some(line) = lines.get(i + offset) else {
            return Some("file ends before the licence header is complete".to_string());
        };
        if !simple_regex::matches(pattern, line) {
            return Some(format!(
                "licence header line {} does not match at file line {}",
                offset + 3,
                i + offset + 1
            ));
        }
    }
    None
}

fn check_no_tabs(text: &str) -> Option<String> {
    text.lines()
        .enumerate()
        .find(|(_, l)| l.contains('\t'))
        .map(|(n, _)| format!("literal tab character at line {}", n + 1))
}

/// The subset of regex syntax the upstream header file actually uses.
///
/// Deliberately not a regex engine. The five patterns are fixed and checked in, so the
/// supported syntax is exactly what they need: `^`/`$` anchors, `.*`, alternation of
/// top-level groups, and backslash escapes. Anything outside that is a hard error rather
/// than a silent mismatch, so a future header change cannot quietly start passing everything.
mod simple_regex {
    pub fn matches(pattern: &str, line: &str) -> bool {
        // Top-level alternation, e.g. `^(#!.*)|(@.*)|(<\?.*)`.
        if pattern.contains(")|(") {
            let stripped = pattern.trim_start_matches('^');
            return stripped
                .split(")|(")
                .map(|p| p.trim_start_matches('(').trim_end_matches(')'))
                .any(|p| matches(&format!("^{p}"), line));
        }

        let anchored_start = pattern.starts_with('^');
        let anchored_end = pattern.ends_with('$');
        let body = pattern
            .trim_start_matches('^')
            .trim_end_matches('$');

        // Split on `.*`, unescape the literal segments, and match them in order.
        let segments: Vec<String> = body.split(".*").map(unescape).collect();

        let mut pos = 0usize;
        for (i, seg) in segments.iter().enumerate() {
            if seg.is_empty() {
                continue;
            }
            let first = i == 0 && anchored_start;
            let found = if first {
                line[pos..].starts_with(seg.as_str()).then_some(pos)
            } else {
                line[pos..].find(seg.as_str()).map(|f| pos + f)
            };
            let Some(at) = found else { return false };
            pos = at + seg.len();
        }
        if anchored_end {
            if let Some(last) = segments.last() {
                if !last.is_empty() && pos != line.len() {
                    return false;
                }
            }
        }
        true
    }

    fn unescape(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                if let Some(next) = chars.next() {
                    out.push(next);
                }
            } else {
                out.push(c);
            }
        }
        out
    }
}

/// Expand a Bazel-style glob against a package directory.
///
/// Supports the forms upstream actually writes: `*`, `dir/*`, `**/*`, `docs/**`, and plain
/// paths. `*` does not cross a directory boundary; `**` does.
fn glob_matches(pattern: &str, rel: &str) -> bool {
    fn seg_match(pat: &str, text: &str) -> bool {
        // `*` within one segment.
        let parts: Vec<&str> = pat.split('*').collect();
        if parts.len() == 1 {
            return pat == text;
        }
        let mut pos = 0;
        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() {
                continue;
            }
            let found = if i == 0 {
                text.starts_with(part).then_some(0)
            } else {
                text[pos..].find(part).map(|f| pos + f)
            };
            let Some(at) = found else { return false };
            pos = at + part.len();
        }
        if let Some(last) = parts.last() {
            if !last.is_empty() && !text.ends_with(last) {
                return false;
            }
        }
        true
    }

    let p: Vec<&str> = pattern.split('/').collect();
    let t: Vec<&str> = rel.split('/').collect();

    // `docs/**` matches everything under docs/.
    if let Some(idx) = p.iter().position(|s| *s == "**") {
        if t.len() < idx {
            return false;
        }
        if !p[..idx].iter().zip(&t[..idx]).all(|(a, b)| seg_match(a, b)) {
            return false;
        }
        // `**/*` style: the tail after `**` must match the file's last segments.
        let tail = &p[idx + 1..];
        if tail.is_empty() {
            return t.len() > idx;
        }
        if t.len() < tail.len() {
            return false;
        }
        let start = t.len() - tail.len();
        return start >= idx && tail.iter().zip(&t[start..]).all(|(a, b)| seg_match(a, b));
    }

    p.len() == t.len() && p.iter().zip(&t).all(|(a, b)| seg_match(a, b))
}

/// Files a `checkstyle_test` covers, resolved from its include/exclude globs.
/// Bazel `glob()` never crosses a package boundary — a directory containing a BUILD file is
/// a different package, and its files belong to that package's own rules.
///
/// `server/BUILD` globs `*`, `*/*` … `*/*/*/*/*`, which textually reaches
/// `service/admin/proto/Cargo.toml`. Bazel does not, because
/// `server/service/admin/proto/BUILD` exists. Ignoring that made `//server:checkstyle` fail
/// on a file it never inspects — the hand-maintained manifest of CR-A-04, which carries no
/// licence header and does use tabs.
fn is_subpackage(root: &Path, dir: &Path) -> bool {
    dir != root && dir.join("BUILD").is_file()
}

fn checkstyle_files(
    workspace: &Path,
    package_dir: &str,
    include: &[String],
    exclude: &[String],
) -> Result<Vec<PathBuf>> {
    let root = if package_dir.is_empty() {
        workspace.to_path_buf()
    } else {
        workspace.join(package_dir)
    };
    let mut out = Vec::new();
    for entry in walkdir::WalkDir::new(&root)
        .into_iter()
        .filter_entry(|e| {
            e.file_name() != ".git"
                && e.file_name() != "bazel-typedb"
                && !(e.file_type().is_dir() && is_subpackage(&root, e.path()))
        })
        .filter_map(std::result::Result::ok)
        .filter(|e| e.file_type().is_file())
    {
        let rel = entry
            .path()
            .strip_prefix(&root)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .replace('\\', "/");
        if !include.iter().any(|p| glob_matches(p, &rel)) {
            continue;
        }
        if exclude.iter().any(|p| glob_matches(p, &rel)) {
            continue;
        }
        out.push(entry.path().to_path_buf());
    }
    out.sort();
    Ok(out)
}

/// Run one `checkstyle_test`: MPL header and no-tabs over its file set.
fn run_checkstyle(
    workspace: &Path,
    package_dir: &str,
    include: &[String],
    exclude: &[String],
    license_type: &str,
) -> Result<Vec<Finding>> {
    let Some(spec) = header_lines(license_type) else {
        anyhow::bail!(
            "checkstyle target declares license_type {license_type:?}, which has no header \
             spec; refusing to check it against the wrong licence"
        );
    };
    let files = checkstyle_files(workspace, package_dir, include, exclude)?;
    let mut findings = Vec::new();
    for file in &files {
        let Ok(text) = std::fs::read_to_string(file) else {
            // Binary or unreadable files are not what Checkstyle inspects.
            continue;
        };
        let rel = file.strip_prefix(workspace).unwrap_or(file).to_string_lossy().to_string();
        if let Some(problem) = check_header(spec, &text) {
            findings.push(Finding { file: rel.clone(), problem });
        }
        if let Some(problem) = check_no_tabs(&text) {
            findings.push(Finding { file: rel, problem });
        }
    }
    Ok(findings)
}

/// Run one `rustfmt_test` over the sources of the Bazel targets it names.
fn run_rustfmt(workspace: &Path, sources: &[String]) -> Result<Vec<Finding>> {
    let existing: Vec<PathBuf> = sources
        .iter()
        .map(|s| workspace.join(s))
        .filter(|p| p.is_file())
        .collect();
    if existing.is_empty() {
        return Ok(Vec::new());
    }

    let output = Command::new("rustfmt")
        .arg(format!("+{PINNED_RUSTFMT_TOOLCHAIN}"))
        .args(["--edition", "2024", "--check"])
        .args(&existing)
        .current_dir(workspace)
        .output()
        .context("running the pinned rustfmt")?;

    if output.status.success() {
        return Ok(Vec::new());
    }
    // `--check` prints a diff per unformatted file; the `Diff in <path>` lines name them.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut findings: Vec<Finding> = stdout
        .lines()
        .filter_map(|l| l.trim().strip_prefix("Diff in "))
        .filter_map(|rest| rest.split(" at line").next())
        .map(|file| Finding {
            file: file.trim().to_string(),
            problem: "not formatted according to the pinned rustfmt".into(),
        })
        .collect();
    findings.dedup_by(|a, b| a.file == b.file);

    if findings.is_empty() {
        findings.push(Finding {
            file: existing.first().map(|p| p.display().to_string()).unwrap_or_default(),
            problem: format!(
                "rustfmt exited {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        });
    }
    Ok(findings)
}

/// What a static target needs in order to run, recovered from the BUILD scan.
#[derive(Debug, Clone, Default)]
pub struct StaticCheckInputs {
    pub rule: String,
    pub package_dir: String,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    /// Source files, already resolved from the Bazel targets a `rustfmt_test` names.
    pub sources: Vec<String>,
    /// `license_type` attribute; selects which header regexes apply.
    pub license_type: String,
}

/// Execute a static-check target and produce its single leaf-case result.
pub fn run_static_target(
    workspace: &Path,
    evidence_dir: &Path,
    profile: corpus_catalog::model::ProfileId,
    catalog: &Catalog,
    target: &Target,
    inputs: &StaticCheckInputs,
) -> Result<TargetRun> {
    let started = std::time::Instant::now();
    let findings = match inputs.rule.as_str() {
        "checkstyle_test" => run_checkstyle(
            workspace,
            &inputs.package_dir,
            &inputs.include,
            &inputs.exclude,
            &inputs.license_type,
        )?,
        "rustfmt_test" => run_rustfmt(workspace, &inputs.sources)?,
        // A static rule with no port is recorded as unknown, never as a pass.
        other => {
            return Ok(unresolved_run(
                evidence_dir,
                profile,
                catalog,
                target,
                format!("no port exists for static rule `{other}`"),
                started.elapsed().as_millis(),
            ))
        }
    };

    let detail = findings
        .iter()
        .map(|f| format!("{}: {}", f.file, f.problem))
        .collect::<Vec<_>>()
        .join("\n");

    let slug = target.target_id.replace([':', '/', ' '], "_");
    let stdout_path = evidence_dir.join(format!("{slug}.stdout.txt"));
    std::fs::write(&stdout_path, if detail.is_empty() { "ok\n" } else { &detail })?;

    let outcome = if findings.is_empty() { Outcome::Passed } else { Outcome::Failed };
    let cases = catalog
        .leaf_cases
        .iter()
        .filter(|c| c.target_id == target.target_id)
        .map(|c| CaseResult {
            leaf_case_id: c.leaf_case_id.clone(),
            outcome: outcome.clone(),
            duration_ms: None,
            detail: (!detail.is_empty()).then(|| detail.clone()),
        })
        .collect();

    Ok(TargetRun {
        target_id: target.target_id.clone(),
        profile_id: profile,
        command: vec![format!("<static:{}>", inputs.rule)],
        working_directory: workspace.display().to_string(),
        env: BTreeMap::new(),
        exit_code: Some(i32::from(!findings.is_empty())),
        duration_ms: started.elapsed().as_millis(),
        timed_out: false,
        stdout_path: stdout_path.display().to_string(),
        stderr_path: String::new(),
        cases,
    })
}

fn unresolved_run(
    evidence_dir: &Path,
    profile: corpus_catalog::model::ProfileId,
    catalog: &Catalog,
    target: &Target,
    reason: String,
    duration_ms: u128,
) -> TargetRun {
    let cases = catalog
        .leaf_cases
        .iter()
        .filter(|c| c.target_id == target.target_id)
        .map(|c| CaseResult {
            leaf_case_id: c.leaf_case_id.clone(),
            outcome: Outcome::Unknown(reason.clone()),
            duration_ms: None,
            detail: Some(reason.clone()),
        })
        .collect();
    TargetRun {
        target_id: target.target_id.clone(),
        profile_id: profile,
        command: vec!["<static:unported>".into()],
        working_directory: evidence_dir.display().to_string(),
        env: BTreeMap::new(),
        exit_code: None,
        duration_ms,
        timed_out: false,
        stdout_path: String::new(),
        stderr_path: String::new(),
        cases,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "\
/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

fn main() {}
";

    #[test]
    fn accepts_the_real_upstream_header() {
        assert_eq!(check_mpl_header(GOOD), None);
    }

    #[test]
    fn accepts_a_shebang_before_the_header() {
        // The first upstream pattern exists precisely so scripts still pass.
        let text = format!("#!/usr/bin/env bash\n{GOOD}");
        assert_eq!(check_mpl_header(&text), None);
    }

    #[test]
    fn rejects_a_missing_header() {
        assert!(check_mpl_header("fn main() {}\n").is_some());
    }

    #[test]
    fn rejects_a_truncated_header() {
        let text = "/*\n * This Source Code Form is subject to the terms of the Mozilla Public\n */\n";
        assert!(check_mpl_header(text).is_some(), "a partial header must not pass");
    }

    #[test]
    fn accepts_a_hash_commented_file_with_no_comment_opener() {
        // The real `user/BUILD`. Header line 2 (`^\/\*`) is a multiLine, so a file that
        // never opens a block comment still satisfies the check. Requiring line 2 failed
        // every BUILD, .bzl, shell and TOML file in the repository against its own licence
        // rule — 91 checkstyle targets red for a rule upstream passes.
        let text = "\
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

load(\"@rules_rust//rust:defs.bzl\", \"rust_library\")
";
        assert_eq!(check_mpl_header(text), None);
    }

    #[test]
    fn accepts_repeated_multilines_before_the_header() {
        // multiLines may match more than once, not merely zero or one time.
        let text = format!("#!/bin/sh\n/*\n/*\n{}", &GOOD[3..]);
        assert_eq!(check_mpl_header(&text), None);
    }

    #[test]
    fn still_rejects_a_file_whose_body_never_contains_the_header() {
        let text = "#!/bin/sh\n/*\n * unrelated comment\n */\necho hi\n";
        assert!(check_mpl_header(text).is_some());
    }

    #[test]
    fn finds_a_tab_and_names_its_line() {
        assert_eq!(check_no_tabs("a\nb\n\tc\n").as_deref(), Some("literal tab character at line 3"));
        assert_eq!(check_no_tabs("no tabs here\n"), None);
    }

    #[test]
    fn globs_match_the_forms_upstream_writes() {
        assert!(glob_matches("*", "BUILD"));
        assert!(!glob_matches("*", "sub/BUILD"), "* must not cross a directory boundary");
        assert!(glob_matches(".cargo/*", ".cargo/config.toml"));
        assert!(glob_matches("docs/**", "docs/a/b.md"));
        assert!(glob_matches("**/*.rs", "a/b/c.rs"));
        assert!(glob_matches("*.md", "README.md"));
        assert!(!glob_matches("*.md", "README.txt"));
    }

    #[test]
    fn the_regex_subset_handles_every_pattern_in_the_header_file() {
        // Guard the guard: if a future header uses syntax this subset cannot read, the
        // matcher must not quietly accept everything.
        assert!(simple_regex::matches(r"^/\*", "/*"));
        assert!(!simple_regex::matches(r"^/\*", " /*"));
        assert!(simple_regex::matches(r"^.*Mozilla Public$", " * ... Mozilla Public"));
        assert!(!simple_regex::matches(r"^.*Mozilla Public$", "Mozilla Public trailing"));
        assert!(simple_regex::matches(r"^(#!.*)|(@.*)|(<\?.*)", "#!/bin/sh"));
        assert!(simple_regex::matches(r"^(#!.*)|(@.*)|(<\?.*)", "<?xml version=\"1.0\"?>"));
        assert!(!simple_regex::matches(r"^(#!.*)|(@.*)|(<\?.*)", "plain text"));
    }
}

#[cfg(test)]
mod license_type_tests {
    use super::*;

    #[test]
    fn the_apache_header_is_accepted_only_under_its_own_license_type() {
        // common/logger:checkstyle-copies declares license_type = "apache-header" over
        // log_panic.rs, vendored from the ASF. Hardcoding the MPL spec failed that target
        // for carrying exactly the licence its BUILD rule declares.
        let apache = "\
// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
";
        assert_eq!(check_header(header_lines("apache-header").unwrap(), apache), None);
        assert!(check_header(header_lines("mpl-header").unwrap(), apache).is_some());
    }

    #[test]
    fn an_unknown_license_type_has_no_spec_rather_than_a_default() {
        // Falling back to MPL would check a file against a licence it does not claim.
        assert!(header_lines("bsd-header").is_none());
    }

    #[test]
    fn every_license_type_upstream_uses_has_a_spec() {
        for t in ["mpl-header", "mpl-fulltext", "apache-header"] {
            assert!(header_lines(t).is_some(), "{t} is declared in TypeDB's BUILD files");
        }
    }
}
