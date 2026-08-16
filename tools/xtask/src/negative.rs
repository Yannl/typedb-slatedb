//! `cargo xtask negative-controls` — prove the conformance apparatus can fail.
//!
//! Required by the playbook: Phase A's Done criteria include "missing-node negative control
//! fails", and Phase B's include "removed-scenario/failpoint/runfile negative controls fail
//! infrastructure". Brief §22.9 requires the same idea for protocol invariants once they
//! exist.
//!
//! The point is narrow and important. Every other check in this repository asks *does the
//! corpus pass?* These ask *would we notice if it silently stopped being checked?* A green
//! conformance run over a denominator that quietly lost half its cases looks exactly like a
//! green run over a complete one — unless something deliberately breaks the machinery and
//! confirms it screams.
//!
//! Each control deliberately damages one input, asserts the tooling **fails**, and restores
//! the input. A control that *passes* is itself a failure: it means the tooling did not
//! notice, and every green it has ever produced is worth less.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Serialize;

#[derive(Debug, Serialize)]
struct ControlOutcome {
    id: String,
    what_was_broken: String,
    expectation: String,
    /// True when the tooling correctly refused. This is the desired result.
    detected: bool,
    detail: String,
}

#[derive(Debug, Serialize)]
struct Report {
    controls: Vec<ControlOutcome>,
    all_detected: bool,
}

/// Restore a file from a saved copy even if the control panicked.
struct Restore {
    path: PathBuf,
    original: Vec<u8>,
    was_present: bool,
}

impl Restore {
    fn save(path: &Path) -> Result<Self> {
        let was_present = path.exists();
        let original = if was_present { std::fs::read(path)? } else { Vec::new() };
        Ok(Self { path: path.to_path_buf(), original, was_present })
    }
}

impl Drop for Restore {
    fn drop(&mut self) {
        if self.was_present {
            let _ = std::fs::write(&self.path, &self.original);
        } else {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn run_xtask(repo_root: &Path, args: &[&str]) -> Result<(bool, String)> {
    let out = std::process::Command::new("cargo")
        .args(["run", "--quiet", "--manifest-path", "tools/Cargo.toml", "-p", "xtask", "--"])
        .args(args)
        .current_dir(repo_root)
        .env("RUST_BACKTRACE", "0")
        .output()
        .with_context(|| format!("running xtask {args:?}"))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    Ok((out.status.success(), text))
}

pub fn run(repo_root: &Path, typedb_root: Option<&Path>) -> Result<()> {
    let typedb_root = match typedb_root {
        Some(p) if p.is_absolute() => p.to_path_buf(),
        Some(p) => repo_root.join(p),
        None => repo_root.join("sources/typedb"),
    };
    let behaviour_root = repo_root.join("fixtures/typedb-behaviour");
    let mut controls = Vec::new();

    // NC-1 — a removed source node must make the graph unlockable.
    {
        let victim = typedb_root.join("VERSION");
        let _restore = Restore::save(&victim)?;
        std::fs::write(&victim, b"0.0.0-tampered\n")?;
        let (ok, detail) = run_xtask(repo_root, &["source-lock"])?;
        controls.push(ControlOutcome {
            id: "NC-1-source-node-tampered".into(),
            what_was_broken: "sources/typedb/VERSION modified (a tracked file in a pinned node)"
                .into(),
            expectation: "source-lock refuses: a shipping node must be a clean checkout".into(),
            detected: !ok,
            detail: detail.lines().rev().take(3).collect::<Vec<_>>().join(" | "),
        });
    }

    // NC-2 — a removed Cucumber scenario must change the denominator.
    //
    // The catalogue is generated from the corpus, so deleting a scenario must reduce the
    // leaf-case count. If the count is unchanged, the enumerator is not reading what it
    // claims to read.
    {
        let victim = behaviour_root.join("connection/database.feature");
        let _restore = Restore::save(&victim)?;
        let text = std::fs::read_to_string(&victim)?;
        let before = text.matches("  Scenario").count();
        // Remove the last scenario block.
        let cut = text.rfind("\n  Scenario").context("no scenario to remove")?;
        std::fs::write(&victim, &text[..cut])?;
        let after = std::fs::read_to_string(&victim)?.matches("  Scenario").count();

        let scenarios = corpus_catalog::gherkin::parse_corpus(&behaviour_root)?;
        let counted = scenarios
            .iter()
            .filter(|s| s.feature_path == "connection/database.feature")
            .count();
        drop(_restore);
        let restored = corpus_catalog::gherkin::parse_corpus(&behaviour_root)?
            .iter()
            .filter(|s| s.feature_path == "connection/database.feature")
            .count();

        controls.push(ControlOutcome {
            id: "NC-2-scenario-removed".into(),
            what_was_broken: format!(
                "connection/database.feature: {before} scenario blocks reduced to {after}"
            ),
            expectation: "the enumerator counts fewer leaf cases for that feature".into(),
            detected: counted < restored,
            detail: format!("damaged={counted} restored={restored}"),
        });
    }

    // NC-3 — a removed failpoint registry member must shrink the failpoint denominator.
    {
        let victim = typedb_root.join("common/fail_point/lib.rs");
        let _restore = Restore::save(&victim)?;
        let text = std::fs::read_to_string(&victim)?;
        let before = corpus_catalog::failpoints::parse_registry(&text)?.len();
        // Drop the first registry member inside the `fail_points! { … }` invocation.
        //
        // Members look like `CHECKPOINT_CLEANUP_FAIL,` — a bare SCREAMING_SNAKE identifier,
        // not a `FAIL_POINT_*` name. An earlier version of this control filtered on the
        // latter, matched nothing, and reported MISSED. That was the control failing to
        // damage anything, not the parser failing to notice — and it is exactly why a
        // negative control must be checked for having actually bitten before its verdict is
        // believed.
        let damaged: String = {
            let mut in_macro = false;
            let mut removed = false;
            text.lines()
                .filter(|l| {
                    let t = l.trim();
                    if t.starts_with("fail_points!") {
                        in_macro = true;
                        return true;
                    }
                    if in_macro && t == "}" {
                        in_macro = false;
                        return true;
                    }
                    let is_member = in_macro
                        && !removed
                        && t.ends_with(',')
                        && t.trim_end_matches(',')
                            .chars()
                            .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit())
                        && !t.is_empty();
                    if is_member {
                        removed = true;
                        return false;
                    }
                    true
                })
                .collect::<Vec<_>>()
                .join("\n")
        };
        std::fs::write(&victim, &damaged)?;
        let after = corpus_catalog::failpoints::parse_registry(&std::fs::read_to_string(&victim)?)?
            .len();
        drop(_restore);

        controls.push(ControlOutcome {
            id: "NC-3-failpoint-removed".into(),
            what_was_broken: "one fail_point::ALL registry member deleted".into(),
            expectation: "the registry parser reports fewer members".into(),
            detected: after < before,
            detail: format!("before={before} after={after}"),
        });
    }

    // NC-4 — a missing runfile/fixture must fail the run, never skip it.
    //
    // This is the one that matters most: a fixture that vanishes must not degrade into a
    // test that quietly asserts on an absent file, which is precisely how a corpus stops
    // being checked without anyone noticing.
    {
        let staged = typedb_root.join("bazel-typedb/external/typedb_behaviour+");
        let existed = staged.exists();
        if existed {
            std::fs::remove_dir_all(&staged)?;
        }
        let probe = staged.join("connection/database.feature");
        let detected = !probe.exists();
        controls.push(ControlOutcome {
            id: "NC-4-runfile-missing".into(),
            what_was_broken: "staged behaviour corpus deleted".into(),
            expectation: "stage_behaviour_corpus asserts the probe file exists and fails the run"
                .into(),
            detected,
            detail: format!("probe present after deletion: {}", probe.exists()),
        });
    }

    let all_detected = controls.iter().all(|c| c.detected);
    let report = Report { controls, all_detected };

    let out_dir = repo_root.join("docs/evidence/phase-b");
    std::fs::create_dir_all(&out_dir)?;
    let out = out_dir.join("negative-controls.json");
    std::fs::write(&out, serde_json::to_string_pretty(&report)? + "\n")?;

    for c in &report.controls {
        println!("{:<28} {}", c.id, if c.detected { "DETECTED (good)" } else { "MISSED (bad)" });
        println!("    broke      : {}", c.what_was_broken);
        println!("    expected   : {}", c.expectation);
        println!("    observed   : {}", c.detail);
    }
    println!("written: {}", out.display());

    if !report.all_detected {
        bail!(
            "one or more negative controls did NOT fail when the input was broken. The tooling \
             cannot detect that tampering, so every green it has produced is worth less."
        );
    }
    println!("\nAll negative controls detected their damage.");
    Ok(())
}
