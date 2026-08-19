#!/usr/bin/env python3
"""E-04: INDEPENDENT read-only verifier for an evidence bundle.

This tool deliberately does NOT import tools/catalog/verdict.py, common.py
or any other producer code. The small amount of duplicated parsing below is
the point: the producer derives the verdict and this verifier re-derives
everything it can from the BYTES with its own implementation, so a defect
(or a forgery) in the producer's implementation cannot vouch for itself.
What the two implementations share is the documented ALGORITHM (libtest
summary lines; the bundle root = sha256 over sorted "rel\\0sha\\n" pairs of
every consumed file; the plan root = sha256 over the canonical JSON of the
plan body; the row policy of tools/catalog/verdict.py), never the code.

R4-EVID-03a: the single `verified` flag conflated three different claims,
so a forged policy_verdict ("TOTAL_QUALITY_PASS") and a forged plan body
both used to sail through. The verifier now derives and reports THREE
explicit booleans:

  observation_integrity_verified
      the immutable bytes really are what they claim: every log exists,
      hash-binds, and reparses to its row's counts; the recomputed bundle
      root is bound by a seal (root-bound COMPLETE, sidecar manifest root,
      or a verdict's recorded bundle_root). Byte truth only - it says
      NOTHING about pass/fail policy.
  policy_adjudicated
      this verifier independently RE-DERIVED the policy verdict from the
      observation rows + the flake ledger (the row policy of verdict.py,
      reimplemented here), the recorded policy_verdict is schema-valid
      (exact enum {"GREEN","RED"}), the two verdicts AGREE, and the
      verdict's pinned policy inputs (ledger hash, plan root recomputed
      from the plan's canonical body bytes) match the policy files as they
      stand now.
  qualification_pass
      observation integrity AND agreeing GREEN adjudication AND a
      root-bound COMPLETE seal AND a present, schema-valid verdict - i.e.
      the bundle is current, sealed and policy-green. Absence of COMPLETE
      or of a verdict makes this false; under --qualification (alias
      --strict) that absence is FATAL (nonzero exit), in default mode it
      stays a loudly-reported issue so the historical archive remains
      byte-verifiable.

`verified` in the JSON output is kept for backward compatibility and is
EXACTLY observation_integrity_verified - byte integrity, never a pass.

For a bundle directory it verifies, all fail-closed:

  1. structure   - u0-results.json parses; no duplicate row target_id; no
                   two rows naming one log file.
  2. log binding - every row's raw log exists, lives inside the bundle dir,
                   and hashes to the row's log_sha256 or (legacy rows) to
                   the sidecar log-manifest.json entry; unbound bytes are
                   not evidence.
  3. reparse     - every log reparses (own minimal libtest parser) to
                   exactly the counts its row claims.
  4. ledger      - every ledger tolerance matching a row is checked against
                   the LOG: fingerprint failed-case names must equal the
                   log's failing names; the run profile must be one the
                   entry covers; expiries must be live.
  5. roots       - the bundle root is recomputed and must equal the sidecar
                   manifest root and any root a `COMPLETE <hex>` marker
                   binds (a legacy JSON COMPLETE is a named qualification
                   issue: byte-verifiable, never qualification-grade).
  6. verdicts    - every verdict*.json must carry policy_verdict in the
                   exact enum {"GREEN","RED"} with a consistent `green`
                   boolean, its recorded bundle_root must equal the
                   recomputed root, and its recorded observation must equal
                   the fresh observation this verifier derives from the
                   reparsed logs.
  7. re-derived  - the row policy verdict is INDEPENDENTLY re-derived here
     policy        (timeouts never ledgerable; exit code / failed count /
                   ignored count must equal what the live flake ledger
                   tolerates for that exact target, else RED; a ledger
                   entry matching no row is RED - stale exclusions are debt)
                   and compared with the recorded policy_verdict: a
                   recorded GREEN this verifier re-derives RED is an
                   anomaly, never a shrug.
  8. policy pins - the AUTHORITATIVE verdict (newest verdict-*.json, else
                   verdict.json) must carry policy_roots; the pinned
                   flake_ledger_sha256 must match the ledger bytes NOW and
                   the pinned plan_root must match the root this verifier
                   RECOMPUTES from the plan's canonical body (sorted-keys
                   compact JSON of the document minus its self-declared
                   plan_root, sha256 - same documented canonicalization as
                   tools/catalog/build_plan_v2.py, reimplemented here); a
                   plan whose self-declared root does not recompute from
                   its own body is a forged plan, an anomaly in itself.
  9. --require-current-source: every executed-tree identity the rows record
                   must match the CURRENT staged tree of sources/typedb
                   (recomputed here). A historical archive legitimately
                   FAILS this check - that failure is the correct behavior,
                   not a bug.

Exit code: 0 only if zero anomalies (and, under --qualification, only if
qualification_pass). Read-only: this tool never writes.

Usage:
  python3 tools/evidence/verify_all.py docs/evidence/G3/u2s3-full-3
  python3 tools/evidence/verify_all.py BUNDLE --qualification
  python3 tools/evidence/verify_all.py BUNDLE --require-current-source
"""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys

DEFAULT_REPO = pathlib.Path(__file__).resolve().parents[2]

# the exact policy enum tools/catalog/verdict.py may record; anything else
# ("TOTAL_QUALITY_PASS", "PASS", ...) is a forged or foreign verdict
POLICY_VERDICT_ENUM = ("GREEN", "RED")


# ------------------------------------------------------------ own primitives

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def reparse_counts(text):
    """Independent libtest summary parser: sum every `test result:` line."""
    counts = {"passed": 0, "failed": 0, "ignored": 0,
              "measured": 0, "filtered_out": 0}
    for line in text.splitlines():
        if not line.startswith("test result:"):
            continue
        for number, key in re.findall(
                r"(\d+) (passed|failed|ignored|measured|filtered out)", line):
            counts[key.replace(" ", "_")] += int(number)
    return counts


def reparse_failed_names(text):
    """Independent failing-case-name parser: verbose lines, terse lines,
    and the closing `failures:` list; the union is the log's truth."""
    names = set(re.findall(r"^test (\S+) \.\.\. FAILED\r?$", text, re.M))
    names |= set(re.findall(r"^(\S+) --- FAILED\r?$", text, re.M))
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.strip() == "failures:":
            for after in lines[i + 1:]:
                m = re.match(r"^ {4}(\S+)\s*$", after)
                if not m:
                    break
                names.add(m.group(1))
    return names


def bundle_rel(path, repo, bundle_dir):
    p = pathlib.Path(path).resolve()
    try:
        return p.relative_to(pathlib.Path(repo).resolve()).as_posix()
    except ValueError:
        pass
    try:
        return "<out>/" + p.relative_to(
            pathlib.Path(bundle_dir).resolve()).as_posix()
    except ValueError:
        return str(p)


def recompute_bundle_root(bundle_dir, rows, ledger_path, repo):
    """Same documented algorithm as the producer, independent code:
    sha256 over sorted `rel\\0sha\\n` pairs of the results JSON, every row's
    raw log, and the ledger; missing files are simply absent (their absence
    is reported elsewhere and the root then never matches a sealed one)."""
    files = [bundle_dir / "u0-results.json", ledger_path]
    for r in rows:
        if r.get("raw_log"):
            p = pathlib.Path(r["raw_log"])
            files.append(p if p.is_absolute() else repo / p)
    pairs = {}
    for f in files:
        if f.is_file():
            pairs[bundle_rel(f, repo, bundle_dir)] = sha256_file(f)
    h = hashlib.sha256()
    for rel in sorted(pairs):
        h.update(rel.encode() + b"\0" + pairs[rel].encode() + b"\n")
    return h.hexdigest()


def recompute_plan_root(plan_path):
    """Independent re-derivation of the plan's content-addressed root from
    its canonical BODY bytes: the document minus its self-declared
    `plan_root`, serialized sorted-keys/compact/ensure_ascii=False, sha256.
    Same documented canonicalization tools/catalog/build_plan_v2.py uses,
    reimplemented here on purpose.

    Returns (declared_root, recomputed_root) or (None, None) if unreadable.
    """
    try:
        doc = json.loads(plan_path.read_text())
    except (OSError, json.JSONDecodeError):
        return None, None
    if not isinstance(doc, dict):
        return None, None
    declared = doc.pop("plan_root", None)
    body = json.dumps(doc, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)
    return declared, hashlib.sha256(body.encode()).hexdigest()


def current_tree_identity(repo):
    """The staged-tree identity of sources/typedb as it stands NOW; same
    documented recipe as the producer (status lines + staged file bytes),
    reimplemented here."""
    tb = repo / "sources" / "typedb"
    if not (tb / ".git").exists() and not (tb / ".git").is_file():
        return None
    def git(*a):
        return subprocess.run(["git", "-C", str(tb), *a],
                              capture_output=True, text=True).stdout
    status = git("status", "--porcelain")
    h = hashlib.sha256()
    for line in sorted(status.splitlines()):
        rel = line[3:].strip().strip('"')
        h.update(line.encode() + b"\0")
        f = tb / rel
        if f.is_file():
            h.update(f.read_bytes())
    return {
        "checkout_revision": git("rev-parse", "HEAD").strip(),
        "dirty": bool(status.strip()),
        "staged_delta_files": len([l for l in status.splitlines() if l.strip()]),
        "staged_delta_sha256": h.hexdigest(),
    }


# ---------------------------------------------- independent policy re-derivation

def rederive_row_policy(adj_rows, ledger, ledger_problems):
    """The row policy of tools/catalog/verdict.py (classify_rows),
    REIMPLEMENTED here from the documented rules, never imported:

      - a timeout is never ledgerable;
      - exit code, failed count and ignored count must each equal exactly
        what the live flake ledger tolerates for that exact target id
        (zero for un-ledgered targets);
      - a ledger entry whose named cases disagree with its declared counts
        is self-inconsistent;
      - a ledger entry matching no row is a stale exclusion, RED.

    Counts are the FRESH ones this verifier reparsed from the raw logs
    wherever a log was readable, so an edited aggregate cannot vote.
    Returns (policy_anomalies, rederived_verdict).
    """
    anomalies = []
    matched = set()
    for row in sorted(adj_rows, key=lambda x: x["tid"]):
        tid = row["tid"]
        entry = ledger.get(tid)
        if entry is not None:
            matched.add(tid)
        exp_rc = entry.get("expected_exit_code", 0) if entry else 0
        exp_failed = entry.get("expected_failed", 0) if entry else 0
        exp_ignored = entry.get("expected_ignored", 0) if entry else 0
        if row["timed_out"]:
            anomalies.append(f"policy: {tid} TIMED OUT - never ledgerable, "
                             f"always a defect")
            continue
        if row["exit_code"] != exp_rc:
            anomalies.append(
                f"policy: {tid} exit code {row['exit_code']!r} but the "
                f"ledger-derived policy expects {exp_rc!r}"
                + ("" if entry else " (no ledger entry)"))
        if row["failed"] != exp_failed:
            anomalies.append(
                f"policy: {tid} has {row['failed']} failed case(s), policy "
                f"expects {exp_failed}"
                + ("" if entry else " (no ledger entry)"))
        if row["ignored"] != exp_ignored:
            anomalies.append(
                f"policy: {tid} has {row['ignored']} ignored case(s), policy "
                f"expects {exp_ignored}"
                + ("" if entry else " (no ledger entry)"))
        if entry and entry.get("cases") is not None \
                and len(entry["cases"]) != exp_failed + exp_ignored:
            anomalies.append(
                f"policy: ledger entry {tid} names {len(entry['cases'])} "
                f"case(s) but declares {exp_failed} failed + {exp_ignored} "
                f"ignored - self-inconsistent tolerance")
    for tid in sorted(set(ledger) - matched):
        anomalies.append(
            f"policy: ledger entry for {tid} matched no row in this bundle - "
            f"stale exclusions must be retired, not carried")
    rederived = "GREEN" if not (anomalies or ledger_problems) else "RED"
    return anomalies, rederived


# ----------------------------------------------------------------- verifier

def verify(bundle_dir, repo, ledger_path, plan_path, require_current_source,
           qualification=False):
    """Returns (integrity, policy, qual_issues, warnings, root, fresh, facts).

    integrity   - anomalies about the BYTES (structure, binding, reparse,
                  roots); any -> observation_integrity_verified is false.
    policy      - anomalies about ADJUDICATION (ledger structure/fit,
                  verdict schema/enum, cached-vs-fresh disagreement,
                  re-derived-vs-recorded disagreement, policy pins, plan
                  root); any -> policy_adjudicated is false.
    qual_issues - conditions that cannot carry a qualification claim
                  (missing/legacy COMPLETE, missing verdict). Fatal only
                  under --qualification; always loudly reported.
    """
    integrity, policy, qual_issues, warnings = [], [], [], []
    facts = {}

    results_file = bundle_dir / "u0-results.json"
    if not results_file.is_file():
        return ([f"bundle: {results_file} does not exist - nothing to verify"],
                [], [], [], None, {}, facts)
    data = json.loads(results_file.read_text())
    rows = data.get("results", [])
    file_profile = data.get("profile")

    manifest, manifest_root = {}, None
    mf = bundle_dir / "log-manifest.json"
    if mf.is_file():
        m = json.loads(mf.read_text())
        manifest = m.get("logs", {})
        manifest_root = m.get("bundle_root")

    # ---- ledger (own reading; expiry liveness checked, entries indexed)
    ledger, ledger_problems = {}, []
    if ledger_path.is_file():
        import datetime
        for e in json.loads(ledger_path.read_text()).get("entries", []):
            tid = e.get("target_id")
            if not tid:
                ledger_problems.append("ledger: entry with no target_id")
                continue
            if tid in ledger:
                ledger_problems.append(f"ledger: duplicate entry for {tid}")
                continue
            exp = e.get("expiry")
            if not exp:
                ledger_problems.append(f"ledger: {tid} has no expiry")
                continue
            if datetime.date.fromisoformat(exp) < datetime.date.today():
                ledger_problems.append(f"ledger: {tid} expired ({exp})")
                continue
            ledger[tid] = e
    else:
        ledger_problems.append(f"ledger: {ledger_path} does not exist")
    policy.extend(ledger_problems)

    # ---- rows: identity, binding, reparse, ledger-vs-log
    seen_ids, seen_logs = {}, {}
    adj_rows = []  # what the independent policy re-derivation adjudicates
    fresh = {"rows": 0, "nonzero_exit_rows": 0, "timed_out_rows": 0,
             "cases_passed": 0, "cases_failed": 0, "cases_ignored": 0}
    for r in rows:
        tid = r.get("target_id", "<no target_id>")
        if tid in seen_ids:
            integrity.append(f"rows: duplicate result row for {tid} - a row "
                             f"that appears twice inflates the corpus")
            continue
        seen_ids[tid] = r
        fresh["rows"] += 1
        if r.get("timed_out"):
            fresh["timed_out_rows"] += 1
        elif r.get("exit_code") != 0:
            fresh["nonzero_exit_rows"] += 1
        # adjudicate row-claimed counts by default; replaced below by the
        # fresh reparse whenever the log is readable
        adj = {"tid": tid, "exit_code": r.get("exit_code"),
               "timed_out": bool(r.get("timed_out")),
               "failed": r.get("failed", 0), "ignored": r.get("ignored", 0)}
        adj_rows.append(adj)
        raw_log = r.get("raw_log")
        if not raw_log:
            integrity.append(f"rows: {tid} records no raw log - a count "
                             f"without its log is an assertion, not evidence")
            continue
        p = pathlib.Path(raw_log)
        log = p if p.is_absolute() else repo / p
        if not log.is_file():
            integrity.append(f"rows: {tid} names raw log {raw_log} which does "
                             f"not exist - the evidence for its counts is gone")
            continue
        try:
            inside = log.resolve().is_relative_to(bundle_dir.resolve())
        except OSError:
            inside = False
        if not inside:
            integrity.append(f"rows: {tid} names raw log {raw_log} OUTSIDE the "
                             f"bundle dir")
            continue
        key = log.resolve()
        if key in seen_logs:
            integrity.append(f"rows: {tid} and {seen_logs[key]} both name log "
                             f"{raw_log} - one execution cannot vouch for two rows")
            continue
        seen_logs[key] = tid
        actual_sha = sha256_file(log)
        rel_in_dir = log.resolve().relative_to(bundle_dir.resolve()).as_posix()
        recorded = r.get("log_sha256")
        if recorded is not None:
            if recorded != actual_sha:
                integrity.append(f"rows: {tid} log hashes {actual_sha} but the "
                                 f"row recorded {recorded} - the log bytes changed")
        elif rel_in_dir in manifest:
            if manifest[rel_in_dir] != actual_sha:
                integrity.append(f"rows: {tid} log hashes {actual_sha} but the "
                                 f"sidecar manifest recorded {manifest[rel_in_dir]} "
                                 f"- the archived bytes changed")
        else:
            integrity.append(f"rows: {tid} log has no recorded hash and no "
                             f"sidecar manifest entry - unbound bytes are not "
                             f"evidence")
        text = log.read_text(errors="replace")
        counts = reparse_counts(text)
        for k, v in counts.items():
            if v != r.get(k, 0):
                integrity.append(f"rows: {tid} claims {k}={r.get(k, 0)} but its "
                                 f"log independently reparses to {k}={v} - the "
                                 f"aggregate contradicts its own evidence")
        adj["failed"], adj["ignored"] = counts["failed"], counts["ignored"]
        fresh["cases_passed"] += counts["passed"]
        fresh["cases_failed"] += counts["failed"]
        fresh["cases_ignored"] += counts["ignored"]
        # ledger tolerance vs the raw log
        entry = ledger.get(tid)
        if entry is None:
            continue
        prof = entry.get("profile")
        allowed = [prof] if isinstance(prof, str) else list(prof or [])
        row_profile = (r.get("run") or {}).get("profile") or file_profile
        if not allowed:
            policy.append(f"ledger: {tid} names no profile")
        elif row_profile not in allowed:
            policy.append(f"ledger: {tid} tolerance covers {allowed} but "
                          f"this run's profile is {row_profile!r}")
        fp = entry.get("fingerprint")
        if fp is None:
            if entry.get("expected_failed", 0) + entry.get("expected_ignored", 0) > 0:
                policy.append(f"ledger: {tid} tolerates cases it does not name")
            continue
        fp_failed = set(fp.get("failed") or [])
        log_failed = reparse_failed_names(text)
        if fp_failed != log_failed:
            ghosts = sorted(fp_failed - log_failed)
            unledgered = sorted(log_failed - fp_failed)
            policy.append(
                f"ledger: {tid} fingerprint does not match the log's failing "
                f"cases"
                + (f"; ghosts (ledgered, not failing): {ghosts}" if ghosts else "")
                + (f"; failing but unledgered: {unledgered}" if unledgered else ""))
        fp_ignored = set(fp.get("ignored") or [])
        if fp_ignored:
            log_ignored = set(re.findall(
                r"^test (\S+) \.\.\. ignored\b.*$", text, re.M))
            if log_ignored and fp_ignored != log_ignored:
                policy.append(f"ledger: {tid} ignored fingerprint "
                              f"{sorted(fp_ignored)} does not match the log's "
                              f"named ignored cases {sorted(log_ignored)}")
            elif not log_ignored:
                warnings.append(f"{tid}: terse log names no ignored cases; "
                                f"{len(fp_ignored)} ignored tolerance(s) verified "
                                f"by count only")

    # ---- roots
    root = recompute_bundle_root(bundle_dir, rows, ledger_path, repo)
    if manifest_root is not None and manifest_root != root:
        integrity.append(f"roots: recomputed bundle root {root} != sidecar "
                         f"manifest root {manifest_root} - some consumed file "
                         f"changed after the manifest was computed")
    complete_bound = False  # a COMPLETE that binds exactly the recomputed root
    marker = bundle_dir / "COMPLETE"
    if marker.is_file():
        first = (marker.read_text().splitlines() or [""])[0]
        m = re.match(r"^COMPLETE ([0-9a-f]{64})\s*$", first)
        if m:
            if m.group(1) != root:
                integrity.append(f"roots: COMPLETE binds root {m.group(1)} but "
                                 f"the bundle recomputes to {root} - the archive "
                                 f"was modified after it was sealed")
            else:
                complete_bound = True
        else:
            qual_issues.append(
                "COMPLETE carries no bundle root (legacy marker) - byte "
                "integrity rests on the sidecar manifest root, but a seal "
                "that binds no root is not qualification-grade")
    else:
        qual_issues.append("no COMPLETE marker - this bundle was never sealed "
                           "green; absence of the seal is fatal to any "
                           "qualification claim")

    # ---- verdicts: schema/enum + cached derivation vs fresh derivation
    verdict_files = sorted(bundle_dir.glob("verdict-*.json")) \
        + ([bundle_dir / "verdict.json"]
           if (bundle_dir / "verdict.json").is_file() else [])
    if not verdict_files:
        qual_issues.append(
            "no verdict file in the bundle - nothing claims a policy outcome "
            "(raw observation only); absence of a verdict is fatal to any "
            "qualification claim")
    authoritative = None
    ts_verdicts = sorted(bundle_dir.glob("verdict-*.json"))
    if ts_verdicts:
        authoritative = ts_verdicts[-1]
    elif (bundle_dir / "verdict.json").is_file():
        authoritative = bundle_dir / "verdict.json"
    verdict_root_bound = False
    for vf in verdict_files:
        v = json.loads(vf.read_text())
        pv = v.get("policy_verdict")
        if pv not in POLICY_VERDICT_ENUM:
            policy.append(
                f"verdicts: {vf.name} records policy_verdict {pv!r} which is "
                f"outside the exact enum {list(POLICY_VERDICT_ENUM)} - a "
                f"verdict this policy cannot produce is a forgery, not a "
                f"stronger pass")
        g = v.get("green")
        if not isinstance(g, bool):
            policy.append(f"verdicts: {vf.name} carries no boolean `green` - "
                          f"the verdict schema is violated")
        elif pv in POLICY_VERDICT_ENUM and g != (pv == "GREEN"):
            policy.append(f"verdicts: {vf.name} says green={g} but "
                          f"policy_verdict={pv!r} - self-contradictory verdict")
        vroot = v.get("bundle_root")
        if vroot is not None and vroot != root:
            policy.append(f"verdicts: {vf.name} records bundle_root {vroot} "
                          f"but the bytes recompute to {root} - the verdict "
                          f"no longer describes this bundle")
        elif vroot is not None and vf == authoritative:
            verdict_root_bound = True
        obs = v.get("observation")
        if obs is not None:
            for k, fresh_v in fresh.items():
                if obs.get(k) != fresh_v:
                    policy.append(
                        f"verdicts: {vf.name} observation {k}={obs.get(k)} but "
                        f"this verifier's independent reparse derives {k}="
                        f"{fresh_v} - producer-cached verdict and fresh reparse "
                        f"disagree")

    # ---- independent policy re-derivation vs the recorded verdict
    row_policy, rederived = rederive_row_policy(adj_rows, ledger,
                                                ledger_problems)
    facts["rederived_policy_verdict"] = rederived
    recorded_pv = None
    if authoritative is not None:
        recorded_pv = json.loads(authoritative.read_text()).get("policy_verdict")
    facts["recorded_policy_verdict"] = recorded_pv
    if recorded_pv == "GREEN" and rederived == "RED":
        policy.append(
            "policy: recorded verdict is GREEN but this verifier's "
            "independent policy re-derivation over the observation rows and "
            "the flake ledger derives RED - reasons: "
            + "; ".join(row_policy[:5])
            + (f"; and {len(row_policy) - 5} more" if len(row_policy) > 5 else ""))
        policy.extend(row_policy)
    elif recorded_pv == "RED" and rederived == "GREEN":
        warnings.append(
            "recorded verdict is RED but the row-level policy re-derives "
            "GREEN here - the recorded RED may rest on denominator/"
            "completeness anomalies this bundle-scoped verifier does not "
            "re-check; the recorded RED stands")
    elif recorded_pv in POLICY_VERDICT_ENUM and rederived == "RED":
        # recorded RED, re-derived RED: agreement; surface the reasons
        policy.extend(row_policy)
    elif recorded_pv is None and rederived == "RED":
        policy.extend(row_policy)

    # ---- policy pins (E-04) + plan root recomputed from canonical body
    plan_declared = plan_recomputed = None
    if plan_path.is_file():
        plan_declared, plan_recomputed = recompute_plan_root(plan_path)
        facts["plan_root_declared"] = plan_declared
        facts["plan_root_recomputed"] = plan_recomputed
    if authoritative is not None:
        v = json.loads(authoritative.read_text())
        pins = v.get("policy_roots")
        if not pins:
            policy.append(
                f"policy: {authoritative.name} carries no policy_roots - the "
                f"policy inputs are not hash-pinned, so a ledger/plan edit "
                f"could silently reclassify this observation")
        else:
            actual_ledger = sha256_file(ledger_path) if ledger_path.is_file() else None
            if pins.get("flake_ledger_sha256") != actual_ledger:
                policy.append(
                    f"policy: flake ledger now hashes {actual_ledger} but the "
                    f"verdict pinned {pins.get('flake_ledger_sha256')} - the "
                    f"policy changed after the verdict; re-derive, never "
                    f"reinterpret")
            if plan_path.is_file() and plan_recomputed is None:
                policy.append(f"policy: {plan_path} is unreadable")
            if pins.get("plan_root") is not None or plan_path.is_file():
                if plan_declared is not None \
                        and plan_declared != plan_recomputed:
                    policy.append(
                        f"policy: the plan self-declares plan_root "
                        f"{plan_declared} but its canonical body recomputes "
                        f"to {plan_recomputed} - the plan body was edited "
                        f"with the root retained; a self-asserted root is "
                        f"not the plan")
                if pins.get("plan_root") != plan_recomputed:
                    policy.append(
                        f"policy: plan root recomputes to {plan_recomputed} "
                        f"but the verdict pinned {pins.get('plan_root')} - the "
                        f"plan changed after the verdict; re-derive, never "
                        f"reinterpret")
    elif qualification and plan_path.is_file() \
            and plan_declared is not None and plan_declared != plan_recomputed:
        policy.append(
            f"policy: the plan self-declares plan_root {plan_declared} but "
            f"its canonical body recomputes to {plan_recomputed} - the plan "
            f"body was edited with the root retained")

    # ---- current-source (optional, expected to FAIL on historical archives)
    if require_current_source:
        current = current_tree_identity(repo)
        if current is None:
            integrity.append("current-source: sources/typedb is not a git "
                             "checkout here - cannot establish the current "
                             "tree, refusing to vouch")
        else:
            recorded_trees = {json.dumps(t, sort_keys=True) for t in
                              ((r.get("run") or {}).get("executed_tree")
                               for r in rows) if t}
            if not recorded_trees:
                integrity.append("current-source: the bundle records no "
                                 "executed-tree identity at all - it cannot be "
                                 "current-source evidence")
            for t_json in sorted(recorded_trees):
                t = json.loads(t_json)
                for k in ("checkout_revision", "dirty", "staged_delta_files",
                          "staged_delta_sha256"):
                    if t.get(k) != current.get(k):
                        integrity.append(
                            f"current-source: bundle tree {k}={t.get(k)!r} but "
                            f"the current staged tree has {k}={current.get(k)!r} "
                            f"- this bundle is evidence about a DIFFERENT tree")
                        break

    # ---- the three explicit claims (R4-EVID-03a)
    root_bound = complete_bound or (manifest_root == root) or verdict_root_bound
    if not root_bound:
        qual_issues.append(
            "the recomputed bundle root is bound by NO seal (no root-bound "
            "COMPLETE, no sidecar manifest root, no verdict bundle_root) - "
            "unbound bytes cannot claim integrity")
    facts["observation_integrity_verified"] = not integrity and root_bound
    facts["policy_adjudicated"] = (
        authoritative is not None and not policy
        and recorded_pv in POLICY_VERDICT_ENUM and recorded_pv == rederived)
    facts["qualification_pass"] = (
        facts["observation_integrity_verified"]
        and facts["policy_adjudicated"]
        and rederived == "GREEN"
        and complete_bound
        and not qual_issues)

    return integrity, policy, qual_issues, warnings, root, fresh, facts


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("bundle", type=pathlib.Path)
    ap.add_argument("--repo", type=pathlib.Path, default=DEFAULT_REPO)
    ap.add_argument("--ledger", type=pathlib.Path, default=None)
    ap.add_argument("--plan", type=pathlib.Path, default=None)
    ap.add_argument("--qualification", "--strict", action="store_true",
                    dest="qualification",
                    help="qualification mode: a missing/legacy COMPLETE, a "
                         "missing verdict, or any qualification issue is "
                         "FATAL (nonzero exit), and exit 0 requires "
                         "qualification_pass; default mode reports the same "
                         "issues loudly but keeps byte-verification of "
                         "historical archives possible")
    ap.add_argument("--require-current-source", action="store_true",
                    help="fail unless the bundle's executed tree matches the "
                         "current staged sources/typedb tree (a historical "
                         "archive legitimately fails this)")
    args = ap.parse_args()
    repo = args.repo.resolve()
    bundle = args.bundle if args.bundle.is_absolute() else repo / args.bundle
    ledger = args.ledger or (repo / "docs" / "evidence" / "flake-ledger.json")
    plan = args.plan or (repo / "docs" / "evidence" / "G1"
                         / "qualification-plan-v2.json")
    integrity, policy, qual_issues, warnings, root, fresh, facts = verify(
        bundle.resolve(), repo, ledger, plan, args.require_current_source,
        qualification=args.qualification)
    anomalies = integrity + policy
    for w in warnings:
        print(f"WARNING: {w}", file=sys.stderr)
    for q in qual_issues:
        print(f"QUALIFICATION-ISSUE{' (FATAL)' if args.qualification else ''}"
              f": {q}", file=sys.stderr)
    for a in anomalies:
        print(f"ANOMALY: {a}", file=sys.stderr)
    print(json.dumps({
        "verifier": "tools/evidence/verify_all.py (independent, read-only)",
        "bundle": str(bundle),
        "mode": "qualification" if args.qualification else "default",
        "recomputed_bundle_root": root,
        "fresh_observation": fresh,
        "recorded_policy_verdict": facts.get("recorded_policy_verdict"),
        "rederived_policy_verdict": facts.get("rederived_policy_verdict"),
        **({"plan_root_declared": facts["plan_root_declared"],
            "plan_root_recomputed": facts["plan_root_recomputed"]}
           if "plan_root_recomputed" in facts else {}),
        "anomalies": len(anomalies),
        "integrity_anomalies": len(integrity),
        "policy_anomalies": len(policy),
        "qualification_issues": len(qual_issues),
        "warnings": len(warnings),
        "observation_integrity_verified":
            facts.get("observation_integrity_verified", False),
        "policy_adjudicated": facts.get("policy_adjudicated", False),
        "qualification_pass": facts.get("qualification_pass", False),
        # backward compatibility: `verified` is EXACTLY
        # observation_integrity_verified (byte integrity, never a pass)
        "verified": facts.get("observation_integrity_verified", False),
    }, indent=1))
    if anomalies:
        return 1
    if args.qualification and (qual_issues
                               or not facts.get("qualification_pass")):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
