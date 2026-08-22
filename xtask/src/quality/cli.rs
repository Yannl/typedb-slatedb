//! Command-line wiring. Contains no policy semantics: every threshold, path
//! and rule comes from `.quality/`.

use std::{path::Path, process::ExitCode, time::Instant};

use super::{
    date,
    diff::{self, ChangeSet, Mode},
    digest, exec, gates, git, policy,
    report::{self, Decision, Status},
    scope, tools, waivers,
};

const USAGE: &str = "\
cargo xtask quality <MODE> [OPTIONS]

MODES
  fast                          Tier A inner loop: format, lint, tests, and the
                                controller's own self-checks. No campaign gates.
  pr --base <SHA>               Tier B merge gate: protected-policy check, Tier A,
                                architecture, duplication delta, trusted-base CRAP
                                regression, differential mutation.
  full                          Tier C: broad mutation, feature powerset, Miri,
                                long fuzz budgets, full duplication scan.
  policy-check --base <SHA>     Refuse an implementation diff that modifies
                                protected quality policy.
  verify-report [--path <FILE>] Refuse a report that does not certify HEAD.

OPTIONS
  --base <SHA>    Trusted base revision. Required by `pr` and `policy-check`.
  --path <FILE>   Report path for `verify-report`
                  (default artifacts/quality/quality-report.json).
  --plan          With `full`: PREFLIGHT only. Verify that every campaign the
                  inventory declares is implementable and that every tool it
                  needs is present, BEFORE spending hours compiling. Exit 3 if
                  anything would block; exit 0 if the campaign can run.
  -h, --help      This text.

EXIT CODES
  0 pass   1 quality failure   2 policy violation   3 infrastructure failure
";

pub fn run(args: Vec<String>) -> ExitCode {
    match dispatch(args) {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            eprintln!("xtask: {message}");
            // A controller that cannot run is an infrastructure failure, and
            // must never be mistaken for a quality pass.
            ExitCode::from(Decision::InfrastructureFailure.exit_code())
        }
    }
}

fn dispatch(args: Vec<String>) -> Result<u8, String> {
    let mut it = args.into_iter().peekable();
    let first = it.next().unwrap_or_default();
    if first == "-h" || first == "--help" || first.is_empty() {
        println!("{USAGE}");
        return Ok(0);
    }
    if first != "quality" {
        return Err(format!("unknown command {first:?}\n\n{USAGE}"));
    }

    let mode_word = it.next().ok_or_else(|| format!("missing mode\n\n{USAGE}"))?;
    let mut base: Option<String> = None;
    let mut path: Option<String> = None;
    let mut plan = false;
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--base" => base = Some(it.next().ok_or("--base requires a revision")?),
            "--path" => path = Some(it.next().ok_or("--path requires a file")?),
            "--plan" => plan = true,
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(0);
            }
            other => return Err(format!("unknown option {other:?}\n\n{USAGE}")),
        }
    }

    let repo_root = git::repo_root()?;
    match mode_word.as_str() {
        "fast" => quality(&repo_root, Mode::Fast, base),
        "pr" => quality(&repo_root, Mode::Pr, Some(base.ok_or("`quality pr` requires --base <SHA>")?)),
        "full" if plan => preflight(&repo_root),
        "full" => quality(&repo_root, Mode::Full, base),
        "policy-check" => {
            quality(&repo_root, Mode::PolicyCheck, Some(base.ok_or("`quality policy-check` requires --base <SHA>")?))
        }
        "verify-report" => verify_report(&repo_root, path.as_deref()),
        other => Err(format!("unknown mode {other:?}\n\n{USAGE}")),
    }
}

/// R8-P0-05: `cargo xtask quality full --plan`.
///
/// The audit's ninth requirement: "Add an end-to-end `full --plan`/preflight
/// that verifies all campaigns are implementable before spending hours
/// compiling." A six-hour Full run that dies in its last minute on a tool it
/// never had is not a verdict; it is six hours.
///
/// This answers three questions and nothing else, in seconds:
///   1. which gates would `full` select;
///   2. for each, does the campaign inventory declare it IMPLEMENTED;
///   3. is every tool it names present at its pinned version.
///
/// Exit 3 — the infrastructure code — if anything would block, so a scheduled
/// workflow can gate its own long job on this step.
fn preflight(repo_root: &Path) -> Result<u8, String> {
    let policy = policy::Policy::load(repo_root)?;
    let lock = tools::ToolsLock::load(repo_root)?;
    let registry = tools::Registry::detect_all(repo_root, &lock);
    let facts = diff::derive_facts(&policy, &ChangeSet::default(), &[]);
    let selected = diff::select_gates(Mode::Full, &policy, &facts);
    let campaigns = gates::campaigns(repo_root);

    let mut blocking: Vec<String> = Vec::new();
    println!("quality full --plan: {} gate(s) selected\n", selected.len());
    for g in &selected {
        let Some(d) = gates::definition(&g.id) else {
            blocking.push(format!("{}: selected but has no definition (controller defect)", g.id));
            continue;
        };
        let campaign = campaigns.iter().find(|c| c.gate == g.id);
        let mut notes: Vec<String> = Vec::new();
        if let Some(c) = campaign {
            if c.implemented {
                notes.push(format!("campaign {} implemented", c.name));
                if c.shards.is_empty() && d.weight == exec::Weight::Campaign {
                    notes.push("no shards declared".to_string());
                }
            } else {
                let why =
                    format!("{}: campaign `{}` is declared NOT IMPLEMENTED in {}", g.id, c.name, gates::CAMPAIGNS);
                notes.push("NOT IMPLEMENTED".to_string());
                if !d.advisory {
                    blocking.push(why);
                }
            }
        }
        if let Some(missing) = registry.unpinned(d.tools) {
            let why = format!("{}: tool `{missing}` is not pinned in the lock", g.id);
            notes.push(format!("unpinned tool {missing}"));
            blocking.push(why);
        } else if let Some(problem) = registry.first_problem(d.tools) {
            notes.push(format!("tool problem: {}", problem.problem()));
            if !d.advisory {
                blocking.push(format!("{}: {}", g.id, problem.problem()));
            }
        }
        let state = if notes.is_empty() { "ok".to_string() } else { notes.join("; ") };
        println!("  {:<26} {}", g.id, state);
    }

    if blocking.is_empty() {
        println!("\nPREFLIGHT: PASS — every selected Full gate is implementable on this host");
        return Ok(0);
    }
    eprintln!("\nPREFLIGHT: REFUSED — {} blocking condition(s):", blocking.len());
    for b in &blocking {
        eprintln!("  - {b}");
    }
    eprintln!(
        "\nRunning `full` now would spend its budget and then report on campaigns that could not \
         execute. Fix these first, or narrow the claim through {}.",
        gates::CAMPAIGNS
    );
    Ok(Decision::InfrastructureFailure.exit_code())
}

fn quality(repo_root: &Path, mode: Mode, base: Option<String>) -> Result<u8, String> {
    let started = Instant::now();

    let policy = policy::Policy::load(repo_root)?;
    let lock = tools::ToolsLock::load(repo_root)?;
    let registry = tools::Registry::detect_all(repo_root, &lock);

    let head_sha = git::head_sha(repo_root)?;
    let worktree_clean = git::worktree_clean(repo_root)?;
    let base_sha = match &base {
        Some(rev) => Some(git::resolve(repo_root, rev)?),
        None => None,
    };

    // ---- Change set. `fast` has no base, so it uses the working tree. ----
    let (changes, added) = match mode {
        Mode::Full => (ChangeSet::default(), Vec::new()),
        Mode::Fast => {
            let raw = git::worktree_name_status(repo_root)?;
            (ChangeSet::parse_z(&raw)?, git::added_lines_by_file(repo_root, None)?)
        }
        Mode::Pr | Mode::PolicyCheck => {
            let b = base_sha.as_deref().expect("pr and policy-check require a base");
            let raw = git::diff_name_status(repo_root, b)?;
            (ChangeSet::parse_z(&raw)?, git::added_lines_by_file(repo_root, Some(b))?)
        }
    };

    // ---- Protected list: trusted base UNION head. ----
    let base_protected: Option<Vec<String>> = base_sha.as_deref().and_then(|b| {
        let text = git::show_file(repo_root, b, policy::POLICY_PATH)?;
        policy::Policy::parse(&text).ok().map(|p| p.protected.paths)
    });
    let protected = policy::ProtectedMatcher::union(base_protected.as_deref(), &policy.protected.paths);
    if base_sha.is_some() && base_protected.is_none() {
        eprintln!(
            "xtask: note: {} does not exist at the base revision, so the protected list comes from the head tree \
             alone (bootstrap)",
            policy::POLICY_PATH
        );
    }

    let facts = diff::derive_facts(&policy, &changes, &added);
    let selected = diff::select_gates(mode, &policy, &facts);

    let (policy_digest, policy_digest_inputs) = digest::policy_digest(repo_root, policy::EXTRA_DIGEST_INPUTS);
    let toolchain_digest = digest::digest_pairs(&registry.digest_pairs());

    let waiver_file = waivers::WaiverFile::load(repo_root)?;
    let waiver_summary = waivers::validate(&waiver_file, &policy.exceptions, date::Date::today_utc());

    let (rust_all, rust_prod, ts_projects, python_projects) = gates::targets(&policy, mode, &facts);
    let ctx = gates::Ctx {
        repo_root,
        policy: &policy,
        tools: &registry,
        mode,
        base_sha: base_sha.clone(),
        facts: &facts,
        changes: &changes,
        protected: &protected,
        waivers: &waiver_summary,
        rust_manifests_all: rust_all,
        rust_manifests_production: rust_prod,
        ts_projects,
        python_projects,
        policy_digest: policy_digest.clone(),
        toolchain_digest: toolchain_digest.clone(),
    };

    // `cargo mutants --in-diff` consumes a real diff file; produce it from the
    // trusted range rather than letting a gate handcraft scope flags (§5.6).
    if selected.iter().any(|g| g.id == "rust.mutation.diff") {
        if let Some(b) = &base_sha {
            let dir = repo_root.join("artifacts/quality");
            std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
            let raw = git::run_bytes(repo_root, &["diff", "--binary", &format!("{b}...HEAD")])?;
            std::fs::write(dir.join("pr.diff"), raw).map_err(|e| format!("cannot write pr.diff: {e}"))?;
        }
    }

    let mut results = Vec::new();
    for g in &selected {
        let r = gates::run(&g.id, &ctx);
        println!("{:<28} {}", g.id, describe(&r.status));
        results.push(r);
    }

    let protected_changes = gates::protected_changes(&ctx);
    let scope_summary = report::ScopeSummary {
        changed_paths: changes.all_paths().len(),
        classified: facts.classified.clone(),
        unclassified: facts.unclassified.clone(),
    };

    let report = report::build(
        mode.as_str(),
        date::now_rfc3339_utc(),
        started.elapsed().as_millis(),
        head_sha,
        base_sha,
        worktree_clean,
        toolchain_digest,
        bootstrap_root(repo_root),
        policy_digest,
        policy_digest_inputs,
        protected_changes,
        registry.reports.clone(),
        waiver_summary,
        scope_summary,
        selected,
        results,
    );
    let written = report::write(repo_root, &report)?;

    print_summary(&report, &written);
    Ok(report.exit_code)
}

/// R8-P0-04: the bootstrap manifest's root, read back from the artefact
/// `tools/quality/bootstrap.py` wrote, so the report NAMES the tool set that
/// produced it. Deliberately parsed with a narrow scan rather than a JSON
/// dependency: this must never be the reason a report cannot be produced.
fn bootstrap_root(repo_root: &std::path::Path) -> Option<String> {
    let text = std::fs::read_to_string(repo_root.join("artifacts/quality/bootstrap-manifest.json")).ok()?;
    let at = text.find("\"bootstrap_root\"")?;
    let rest = &text[at..];
    let start = rest[rest.find(':')? + 1..].find('"')? + rest.find(':')? + 2;
    let value = &rest[start..];
    let end = value.find('"')?;
    Some(value[..end].to_string())
}

fn describe(status: &Status) -> &'static str {
    match status {
        Status::Pass => "pass",
        Status::QualityFailure => "QUALITY FAILURE",
        Status::PolicyViolation => "POLICY VIOLATION",
        Status::InfrastructureFailure => "INFRASTRUCTURE FAILURE",
        Status::NotApplicable => "n/a",
    }
}

fn print_summary(report: &report::Report, written: &Path) {
    println!();
    println!("mode                {}", report.mode);
    println!("head_sha            {}", report.head_sha);
    println!("base_sha            {}", report.base_sha.clone().unwrap_or_else(|| "-".into()));
    println!("worktree_clean      {}", report.worktree_clean);
    println!("policy_digest       {}", report.policy_digest);
    println!("toolchain_digest    {}", report.toolchain_digest);
    println!(
        "waivers             {} total, {} active, {} expired, {} invalid",
        report.waivers.total, report.waivers.active, report.waivers.expired, report.waivers.invalid
    );
    println!(
        "tools               {} pinned, {} unusable",
        report.tools.len(),
        report.tools.iter().filter(|t| !t.status.is_ok()).count()
    );
    if !report.protected_policy_changes.is_empty() {
        println!("protected changes   {}", report.protected_policy_changes.len());
        for c in &report.protected_policy_changes {
            println!("  {} {}  (matched `{}`, from {})", c.status, c.path, c.matched_pattern, c.source);
        }
    }
    if !report.scope.unclassified.is_empty() {
        println!("unclassified paths  {}", report.scope.unclassified.len());
        for p in &report.scope.unclassified {
            println!("  {p}");
        }
    }

    let failures: Vec<&report::GateResult> = report.gates.iter().filter(|g| g.blocks()).collect();
    if !failures.is_empty() {
        println!();
        println!("blocking findings:");
        for g in failures {
            println!("  [{}] {}", describe(&g.status), g.id);
            for line in g.detail.lines() {
                println!("      {line}");
            }
            if let Some(r) = &g.remediation {
                println!("      remediation: {r}");
            }
        }
    }

    let advisory: Vec<&report::GateResult> = report
        .gates
        .iter()
        .filter(|g| g.advisory && !matches!(g.status, Status::Pass | Status::NotApplicable))
        .collect();
    if !advisory.is_empty() {
        println!();
        println!("advisory (recorded, not blocking):");
        for g in advisory {
            println!("  [{}] {} — {}", describe(&g.status), g.id, g.detail.lines().next().unwrap_or_default());
        }
    }

    println!();
    println!(
        "blocking            {} policy violation(s), {} quality failure(s), {} infrastructure failure(s)",
        report.blocking.policy_violations, report.blocking.quality_failures, report.blocking.infrastructure_failures
    );
    println!("report              {}", written.display());
    if let Some(code) = &report.decision_code {
        println!("decision            {} ({code}), exit {}", report.decision.as_str(), report.exit_code);
    } else {
        println!("decision            {}, exit {}", report.decision.as_str(), report.exit_code);
    }
}

fn verify_report(repo_root: &Path, path: Option<&str>) -> Result<u8, String> {
    let rel = path.unwrap_or(report::REPORT_PATH);
    let full = repo_root.join(rel);
    let text = std::fs::read_to_string(&full).map_err(|e| format!("cannot read {}: {e}", full.display()))?;
    let header: report::ReportHeader =
        serde_json::from_str(&text).map_err(|e| format!("{rel} is not a valid quality report: {e}"))?;

    let head = git::head_sha(repo_root)?;
    let (policy_digest, _) = digest::policy_digest(repo_root, policy::EXTRA_DIGEST_INPUTS);

    match report::verify(&header, &head, Some(&policy_digest)) {
        Ok(()) => {
            println!("verify-report       pass");
            println!("  report            {rel}");
            println!("  head_sha          {head}");
            println!("  policy_digest     {policy_digest}");
            Ok(0)
        }
        Err(problems) => {
            println!("verify-report       REFUSED");
            for p in &problems {
                println!("  {p}");
            }
            // A report that does not certify HEAD is not evidence at all.
            Ok(Decision::QualityFailure.exit_code())
        }
    }
}

/// Exposed for the controller's own tests: the scope manifest must always be
/// self-consistent with the gate catalogue.
pub fn scope_selftest(policy: &policy::Policy) -> Result<(), String> {
    for rule in &policy.scope.rule {
        if rule.reason.trim().is_empty() {
            return Err(format!("scope rule `{}` has no reason", rule.id));
        }
        if rule.globs.is_empty() {
            return Err(format!("scope rule `{}` has no globs", rule.id));
        }
    }
    let ids: Vec<&str> = policy.scope.rule.iter().map(|r| r.id.as_str()).collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() != ids.len() {
        return Err("duplicate scope rule id".to_string());
    }
    let _ = scope::rust_manifests(policy, &[policy::ScopeClass::Production]);
    Ok(())
}
