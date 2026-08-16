//! Scenario enumeration over the pinned `typedb-behaviour` corpus.
//!
//! The Cucumber leaf-case denominator must match what the upstream harness actually
//! runs. Verified against TB `2256711a` `tests/behaviour/steps/lib.rs`:
//!
//! * `Context::test` calls `.filter_run(glob, |_, _, sc| … !sc.tags.iter().any(is_ignore))`
//!   (L192-197) — so `@ignore` / `@ignore-typedb` scenarios are declared-ignored leaf
//!   cases: counted in the denominator, never counted as a pass.
//! * `is_ignore` is exactly `tag == "ignore" || tag == "ignore-typedb"` (L268-270).
//! * The same closure honours a `SCENARIO_FILTER` environment variable. The runner must
//!   never set it, because a name filter would silently shrink the denominator.
//! * `.repeat_failed()` (L179) wraps the *writer* (`writer::Repeat`), so it re-reports
//!   failures; it does not re-execute them. It is not a retry.
//!
//! A `Scenario Outline` contributes one leaf case per `Examples` row, matching Cucumber's
//! own expansion — never one opaque case for the whole outline.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scenario {
    /// Feature-file path relative to the behaviour corpus root.
    pub feature_path: String,
    pub feature_name: String,
    /// Scenario name after `Examples` substitution, as Cucumber reports it.
    pub name: String,
    /// 1-based line of the `Scenario:` / `Scenario Outline:` keyword.
    pub line: usize,
    /// Tags in scope: the scenario's own plus the feature's.
    pub tags: Vec<String>,
    /// Zero for a plain scenario; 1-based row index for an outline expansion.
    pub example_row: usize,
    /// True for a `Scenario Outline` whose `Examples` block has a header but no data rows.
    /// Cucumber generates nothing for it; it is neither a runnable case nor something to
    /// drop silently.
    pub no_example_rows: bool,
    /// True when a tag makes the upstream harness skip it.
    pub ignored: bool,
}

/// Which harness a behaviour target runs under, because the two disagree about tags.
///
/// This is not a stylistic difference. TB `2256711a` has two ignore predicates:
///
/// * `tests/behaviour/steps/lib.rs` L268-269 — `tag == "ignore" || tag == "ignore-typedb"`
/// * `tests/behaviour/service/http/http_steps/lib.rs` L243-245 —
///   `t == "ignore" || t == "ignore-typedb-http"`
///
/// So `@ignore-typedb-http` suppresses a scenario under the HTTP driver harness and *runs*
/// it under the native one, and `@ignore-typedb` does the reverse. "Is this scenario
/// ignored?" therefore has no answer until you say which target is asking. Treating the two
/// as one predicate silently mis-sizes the denominator in both directions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Harness {
    /// `tests/behaviour/steps` — the gRPC/native suites.
    Native,
    /// `tests/behaviour/service/http/http_steps` — the HTTP driver suites.
    Http,
}

pub fn is_ignore_for(harness: Harness, tag: &str) -> bool {
    match harness {
        Harness::Native => tag == "ignore" || tag == "ignore-typedb",
        Harness::Http => tag == "ignore" || tag == "ignore-typedb-http",
    }
}

fn parse_tags(line: &str) -> Vec<String> {
    line.split_whitespace()
        .filter(|t| t.starts_with('@'))
        .map(|t| t.trim_start_matches('@').to_string())
        .collect()
}

fn split_table_row(line: &str) -> Vec<String> {
    let trimmed = line.trim();
    let inner = trimmed
        .strip_prefix('|')
        .unwrap_or(trimmed)
        .strip_suffix('|')
        .unwrap_or(trimmed);
    inner.split('|').map(|c| c.trim().to_string()).collect()
}

/// Parse one `.feature` file into its leaf scenarios.
pub fn parse_feature(feature_path: &str, text: &str) -> Result<Vec<Scenario>> {
    parse_feature_for(Harness::Native, feature_path, text)
}

/// Parse a feature file, resolving ignore tags the way `harness` resolves them.
pub fn parse_feature_for(
    harness: Harness,
    feature_path: &str,
    text: &str,
) -> Result<Vec<Scenario>> {
    let mut out = Vec::new();
    let mut feature_name = String::new();
    let mut feature_tags: Vec<String> = Vec::new();
    let mut pending_tags: Vec<String> = Vec::new();

    // State of the outline currently being accumulated, if any.
    struct Outline {
        name: String,
        line: usize,
        tags: Vec<String>,
        headers: Vec<String>,
        rows: Vec<Vec<String>>,
        in_examples: bool,
    }
    let mut outline: Option<Outline> = None;

    let flush = |outline: Option<Outline>, out: &mut Vec<Scenario>, feature_name: &str| {
        let Some(o) = outline else { return };
        let ignored = o.tags.iter().any(|t| is_ignore_for(harness, t));
        if o.rows.is_empty() {
            // An outline whose Examples block is all comments generates zero scenarios —
            // `relationtype.feature` L1120-1156 is one, its only rows commented out. It is
            // surfaced as an exclusion by the caller rather than as a leaf case: a case that
            // can never execute would sit in `not_executed` forever and hold the gate red
            // for something upstream never intended to run.
            out.push(Scenario {
                feature_path: feature_path.to_string(),
                feature_name: feature_name.to_string(),
                name: o.name,
                line: o.line,
                tags: o.tags,
                example_row: 0,
                no_example_rows: true,
                ignored,
            });
            return;
        }
        for (idx, row) in o.rows.iter().enumerate() {
            let mut name = o.name.clone();
            for (h, v) in o.headers.iter().zip(row.iter()) {
                name = name.replace(&format!("<{h}>"), v);
            }
            // Substituting an empty cell leaves the name with the placeholder's surrounding
            // whitespace. `define.feature`'s "cannot set @card annotation with invalid
            // arguments <args>" has an empty first row, giving a name with a trailing space,
            // and Cucumber reports the trimmed form — so nine catalogued cases never matched
            // a result and nine reported scenarios looked uncatalogued, one pair per empty
            // cell. Match the harness: trim.
            let name = name.trim().to_string();
            out.push(Scenario {
                feature_path: feature_path.to_string(),
                feature_name: feature_name.to_string(),
                name,
                line: o.line,
                tags: o.tags.clone(),
                example_row: idx + 1,
                no_example_rows: false,
                ignored,
            });
        }
    };

    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with('@') {
            pending_tags = parse_tags(line);
            continue;
        }

        if let Some(rest) = line.strip_prefix("Feature:") {
            feature_name = rest.trim().to_string();
            feature_tags = std::mem::take(&mut pending_tags);
            continue;
        }

        if line.starts_with("Examples:") || line.starts_with("Scenarios:") {
            match outline.as_mut() {
                Some(o) => {
                    o.in_examples = true;
                    // A second Examples block appends rows to the same outline.
                }
                None => bail!("{feature_path}:{line_no}: Examples block outside a Scenario Outline"),
            }
            pending_tags.clear();
            continue;
        }

        let scenario_keyword = ["Scenario Outline:", "Scenario Template:", "Scenario:", "Example:"]
            .into_iter()
            .find(|kw| line.starts_with(kw));

        if let Some(kw) = scenario_keyword {
            flush(outline.take(), &mut out, &feature_name);
            let name = line[kw.len()..].trim().to_string();
            let mut tags = std::mem::take(&mut pending_tags);
            tags.extend(feature_tags.iter().cloned());
            let is_outline = kw.starts_with("Scenario Outline") || kw.starts_with("Scenario Template");
            if is_outline {
                outline = Some(Outline {
                    name,
                    line: line_no,
                    tags,
                    headers: Vec::new(),
                    rows: Vec::new(),
                    in_examples: false,
                });
            } else {
                let ignored = tags.iter().any(|t| is_ignore_for(harness, t));
                out.push(Scenario {
                    feature_path: feature_path.to_string(),
                    feature_name: feature_name.clone(),
                    name,
                    line: line_no,
                    tags,
                    example_row: 0,
                    no_example_rows: false,
                    ignored,
                });
            }
            continue;
        }

        // Table rows only matter inside an Examples block; step data tables are ignored.
        if line.starts_with('|') {
            if let Some(o) = outline.as_mut() {
                if o.in_examples {
                    let cells = split_table_row(line);
                    if o.headers.is_empty() {
                        o.headers = cells;
                    } else {
                        o.rows.push(cells);
                    }
                }
            }
            continue;
        }

        // Any other line is a step, Background, or Rule; it starts no new leaf case, but
        // it does end an Examples table.
        if let Some(o) = outline.as_mut() {
            if o.in_examples && !line.starts_with('|') {
                o.in_examples = false;
            }
        }
        pending_tags.clear();
    }

    flush(outline.take(), &mut out, &feature_name);
    Ok(out)
}

/// Parse every `.feature` file under `root`, in sorted path order.
pub fn parse_corpus(root: &std::path::Path) -> Result<Vec<Scenario>> {
    parse_corpus_for(Harness::Native, root)
}

/// Parse the whole corpus, resolving ignore tags the way `harness` resolves them.
pub fn parse_corpus_for(harness: Harness, root: &std::path::Path) -> Result<Vec<Scenario>> {
    let mut files: Vec<_> = walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path().extension().is_some_and(|x| x == "feature"))
        .map(|e| e.path().to_path_buf())
        .collect();
    files.sort();

    let mut out = Vec::new();
    for path in files {
        let rel = path.strip_prefix(root)?.to_string_lossy().replace('\\', "/");
        let text = std::fs::read_to_string(&path)?;
        out.extend(parse_feature_for(harness, &rel, &text)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_plain_scenarios() {
        let s = parse_feature(
            "x.feature",
            "Feature: F\n\n  Scenario: one\n    Given a\n\n  Scenario: two\n    Given b\n",
        )
        .unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].name, "one");
        assert_eq!(s[1].name, "two");
        assert!(!s[0].ignored);
    }

    #[test]
    fn expands_one_leaf_case_per_examples_row() {
        let s = parse_feature(
            "x.feature",
            "Feature: F\n  Scenario Outline: put <k>\n    Given <k> is <v>\n    Examples:\n      | k | v |\n      | a | 1 |\n      | b | 2 |\n",
        )
        .unwrap();
        assert_eq!(s.len(), 2, "an outline is not one opaque case");
        assert_eq!(s[0].name, "put a");
        assert_eq!(s[1].name, "put b");
        assert_eq!(s[0].example_row, 1);
        assert_eq!(s[1].example_row, 2);
    }

    #[test]
    fn marks_ignore_tags_without_dropping_them() {
        let s = parse_feature(
            "x.feature",
            "Feature: F\n  @ignore\n  Scenario: skipped\n    Given a\n  Scenario: run\n    Given b\n",
        )
        .unwrap();
        assert_eq!(s.len(), 2, "ignored scenarios stay in the denominator");
        assert!(s[0].ignored);
        assert!(!s[1].ignored);
    }

    #[test]
    fn honours_ignore_typedb_exactly_as_upstream_does() {
        let s = parse_feature(
            "x.feature",
            "Feature: F\n  @ignore-typedb\n  Scenario: a\n  @ignore-other\n  Scenario: b\n",
        )
        .unwrap();
        assert!(s[0].ignored);
        assert!(!s[1].ignored, "only `ignore` and `ignore-typedb` skip upstream");
    }

    #[test]
    fn feature_level_tags_propagate() {
        let s = parse_feature("x.feature", "@ignore\nFeature: F\n  Scenario: a\n").unwrap();
        assert!(s[0].ignored);
    }

    #[test]
    fn step_data_tables_are_not_examples_rows() {
        let s = parse_feature(
            "x.feature",
            "Feature: F\n  Scenario: a\n    Given rows:\n      | x |\n      | 1 |\n",
        )
        .unwrap();
        assert_eq!(s.len(), 1);
    }
}

#[cfg(test)]
mod outline_edge_cases {
    use super::*;

    #[test]
    fn an_examples_block_with_only_comments_generates_nothing() {
        // relationtype.feature L1120-1156: a header row, then only commented-out data.
        // Cucumber generates zero scenarios; recording one leaf case for it would hold the
        // gate red forever on something upstream never intended to run.
        let s = parse_feature(
            "f.feature",
            "\
Feature: F
  Scenario Outline: cannot set inherited @<annotation>
    When set annotation: @<annotation>
    Examples:
      | annotation |
      # abstract is not inherited
#      | cascade    |
",
        )
        .unwrap();
        assert_eq!(s.len(), 1);
        assert!(s[0].no_example_rows, "an all-comment Examples block has no data rows");
    }

    #[test]
    fn a_populated_outline_is_unaffected() {
        let s = parse_feature(
            "f.feature",
            "\
Feature: F
  Scenario Outline: sets @<annotation>
    When set annotation: @<annotation>
    Examples:
      | annotation |
      | abstract   |
      | unique     |
",
        )
        .unwrap();
        assert_eq!(s.len(), 2);
        assert!(s.iter().all(|x| !x.no_example_rows));
        assert_eq!(s[0].name, "sets @abstract");
        assert_eq!(s[1].name, "sets @unique");
    }
}

#[cfg(test)]
mod harness_specific_ignores {
    use super::*;

    const FEATURE: &str = "\
Feature: F
  @ignore-typedb-http
  Scenario: http only skips this
    Given a
  @ignore-typedb
  Scenario: native only skips this
    Given b
  @ignore
  Scenario: both skip this
    Given c
";

    #[test]
    fn each_harness_honours_only_its_own_ignore_tag() {
        // TB 2256711a has two predicates: steps/lib.rs L268-269 and
        // http_steps/lib.rs L243-245. A scenario tagged @ignore-typedb-http RUNS under the
        // native harness, and @ignore-typedb RUNS under the HTTP one. Collapsing them into
        // one predicate mis-sizes the denominator in both directions — under HTTP targets
        // the @ignore-typedb-http scenarios showed up as never-executed.
        let native = parse_feature_for(Harness::Native, "f.feature", FEATURE).unwrap();
        let http = parse_feature_for(Harness::Http, "f.feature", FEATURE).unwrap();

        let ignored = |v: &[Scenario], name: &str| {
            v.iter().find(|s| s.name == name).expect("scenario present").ignored
        };

        assert!(!ignored(&native, "http only skips this"), "native runs @ignore-typedb-http");
        assert!(ignored(&http, "http only skips this"));

        assert!(ignored(&native, "native only skips this"));
        assert!(!ignored(&http, "native only skips this"), "http runs @ignore-typedb");

        assert!(ignored(&native, "both skip this"));
        assert!(ignored(&http, "both skip this"), "plain @ignore suppresses everywhere");
    }

    #[test]
    fn an_empty_examples_cell_matches_the_trimmed_name_cucumber_reports() {
        let s = parse_feature(
            "f.feature",
            "Feature: F\n  Scenario Outline: cannot set @card with <args>\n    Given a\n    Examples:\n      | args |\n      |      |\n      | 1, 2 |\n",
        )
        .unwrap();
        assert_eq!(s[0].name, "cannot set @card with", "no trailing space");
        assert_eq!(s[1].name, "cannot set @card with 1, 2");
    }
}
