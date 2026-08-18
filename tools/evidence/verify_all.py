#!/usr/bin/env python3
"""E-04: INDEPENDENT read-only verifier for an evidence bundle.

This tool deliberately does NOT import tools/catalog/verdict.py, common.py
or any other producer code. The small amount of duplicated parsing below is
the point: the producer derives the verdict and this verifier re-derives
everything it can from the BYTES with its own implementation, so a defect
(or a forgery) in the producer's implementation cannot vouch for itself.
What the two implementations share is the documented ALGORITHM (libtest
summary lines; the bundle root = sha256 over sorted "rel\\0sha\\n" pairs of
every consumed file), never the code.

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
                   binds (a legacy JSON COMPLETE is a named warning).
  6. verdicts    - every verdict*.json in the bundle must agree with the
                   bytes: its recorded bundle_root must equal the recomputed
                   root and its recorded observation must equal the fresh
                   observation this verifier derives from the reparsed logs
                   (producer-cached verdict vs fresh reparse disagreement is
                   an anomaly, never a shrug).
  7. policy pins - the AUTHORITATIVE verdict (newest verdict-*.json, else
                   verdict.json) must carry policy_roots, and the pinned
                   flake_ledger_sha256 / plan_root must match the policy
                   files as they stand NOW: a policy edit without a re-run
                   is a mismatch here, never a silent reclassification.
  8. --require-current-source: every executed-tree identity the rows record
                   must match the CURRENT staged tree of sources/typedb
                   (recomputed here). A historical archive legitimately
                   FAILS this check - that failure is the correct behavior,
                   not a bug.

Exit code: 0 only if zero anomalies. Read-only: this tool never writes.

Usage:
  python3 tools/evidence/verify_all.py docs/evidence/G3/u2s3-full-3
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


# ----------------------------------------------------------------- verifier

def verify(bundle_dir, repo, ledger_path, plan_path, require_current_source):
    anomalies, warnings = [], []

    results_file = bundle_dir / "u0-results.json"
    if not results_file.is_file():
        return ([f"bundle: {results_file} does not exist - nothing to verify"],
                [], None, {})
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
    ledger = {}
    if ledger_path.is_file():
        import datetime
        for e in json.loads(ledger_path.read_text()).get("entries", []):
            tid = e.get("target_id")
            if not tid:
                anomalies.append("ledger: entry with no target_id")
                continue
            if tid in ledger:
                anomalies.append(f"ledger: duplicate entry for {tid}")
                continue
            exp = e.get("expiry")
            if not exp:
                anomalies.append(f"ledger: {tid} has no expiry")
                continue
            if datetime.date.fromisoformat(exp) < datetime.date.today():
                anomalies.append(f"ledger: {tid} expired ({exp})")
                continue
            ledger[tid] = e
    else:
        anomalies.append(f"ledger: {ledger_path} does not exist")

    # ---- rows: identity, binding, reparse, ledger-vs-log
    seen_ids, seen_logs = {}, {}
    fresh = {"rows": 0, "nonzero_exit_rows": 0, "timed_out_rows": 0,
             "cases_passed": 0, "cases_failed": 0, "cases_ignored": 0}
    for r in rows:
        tid = r.get("target_id", "<no target_id>")
        if tid in seen_ids:
            anomalies.append(f"rows: duplicate result row for {tid} - a row "
                             f"that appears twice inflates the corpus")
            continue
        seen_ids[tid] = r
        fresh["rows"] += 1
        if r.get("timed_out"):
            fresh["timed_out_rows"] += 1
        elif r.get("exit_code") != 0:
            fresh["nonzero_exit_rows"] += 1
        raw_log = r.get("raw_log")
        if not raw_log:
            anomalies.append(f"rows: {tid} records no raw log - a count "
                             f"without its log is an assertion, not evidence")
            continue
        p = pathlib.Path(raw_log)
        log = p if p.is_absolute() else repo / p
        if not log.is_file():
            anomalies.append(f"rows: {tid} names raw log {raw_log} which does "
                             f"not exist - the evidence for its counts is gone")
            continue
        try:
            inside = log.resolve().is_relative_to(bundle_dir.resolve())
        except OSError:
            inside = False
        if not inside:
            anomalies.append(f"rows: {tid} names raw log {raw_log} OUTSIDE the "
                             f"bundle dir")
            continue
        key = log.resolve()
        if key in seen_logs:
            anomalies.append(f"rows: {tid} and {seen_logs[key]} both name log "
                             f"{raw_log} - one execution cannot vouch for two rows")
            continue
        seen_logs[key] = tid
        actual_sha = sha256_file(log)
        rel_in_dir = log.resolve().relative_to(bundle_dir.resolve()).as_posix()
        recorded = r.get("log_sha256")
        if recorded is not None:
            if recorded != actual_sha:
                anomalies.append(f"rows: {tid} log hashes {actual_sha} but the "
                                 f"row recorded {recorded} - the log bytes changed")
        elif rel_in_dir in manifest:
            if manifest[rel_in_dir] != actual_sha:
                anomalies.append(f"rows: {tid} log hashes {actual_sha} but the "
                                 f"sidecar manifest recorded {manifest[rel_in_dir]} "
                                 f"- the archived bytes changed")
        else:
            anomalies.append(f"rows: {tid} log has no recorded hash and no "
                             f"sidecar manifest entry - unbound bytes are not "
                             f"evidence")
        text = log.read_text(errors="replace")
        counts = reparse_counts(text)
        for k, v in counts.items():
            if v != r.get(k, 0):
                anomalies.append(f"rows: {tid} claims {k}={r.get(k, 0)} but its "
                                 f"log independently reparses to {k}={v} - the "
                                 f"aggregate contradicts its own evidence")
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
            anomalies.append(f"ledger: {tid} names no profile")
        elif row_profile not in allowed:
            anomalies.append(f"ledger: {tid} tolerance covers {allowed} but "
                             f"this run's profile is {row_profile!r}")
        fp = entry.get("fingerprint")
        if fp is None:
            if entry.get("expected_failed", 0) + entry.get("expected_ignored", 0) > 0:
                anomalies.append(f"ledger: {tid} tolerates cases it does not name")
            continue
        fp_failed = set(fp.get("failed") or [])
        log_failed = reparse_failed_names(text)
        if fp_failed != log_failed:
            ghosts = sorted(fp_failed - log_failed)
            unledgered = sorted(log_failed - fp_failed)
            anomalies.append(
                f"ledger: {tid} fingerprint does not match the log's failing "
                f"cases"
                + (f"; ghosts (ledgered, not failing): {ghosts}" if ghosts else "")
                + (f"; failing but unledgered: {unledgered}" if unledgered else ""))
        fp_ignored = set(fp.get("ignored") or [])
        if fp_ignored:
            log_ignored = set(re.findall(
                r"^test (\S+) \.\.\. ignored\b.*$", text, re.M))
            if log_ignored and fp_ignored != log_ignored:
                anomalies.append(f"ledger: {tid} ignored fingerprint "
                                 f"{sorted(fp_ignored)} does not match the log's "
                                 f"named ignored cases {sorted(log_ignored)}")
            elif not log_ignored:
                warnings.append(f"{tid}: terse log names no ignored cases; "
                                f"{len(fp_ignored)} ignored tolerance(s) verified "
                                f"by count only")

    # ---- roots
    root = recompute_bundle_root(bundle_dir, rows, ledger_path, repo)
    if manifest_root is not None and manifest_root != root:
        anomalies.append(f"roots: recomputed bundle root {root} != sidecar "
                         f"manifest root {manifest_root} - some consumed file "
                         f"changed after the manifest was computed")
    marker = bundle_dir / "COMPLETE"
    if marker.is_file():
        first = (marker.read_text().splitlines() or [""])[0]
        m = re.match(r"^COMPLETE ([0-9a-f]{64})\s*$", first)
        if m:
            if m.group(1) != root:
                anomalies.append(f"roots: COMPLETE binds root {m.group(1)} but "
                                 f"the bundle recomputes to {root} - the archive "
                                 f"was modified after it was sealed")
        else:
            warnings.append("COMPLETE carries no bundle root (legacy marker); "
                            "integrity rests on the sidecar manifest root")
    else:
        warnings.append("no COMPLETE marker - this bundle was never sealed green")

    # ---- verdicts: cached derivation vs this verifier's fresh derivation
    verdict_files = sorted(bundle_dir.glob("verdict-*.json")) \
        + ([bundle_dir / "verdict.json"]
           if (bundle_dir / "verdict.json").is_file() else [])
    if not verdict_files:
        warnings.append("no verdict file in the bundle - nothing claims a "
                        "policy outcome (raw observation only)")
    authoritative = None
    ts_verdicts = sorted(bundle_dir.glob("verdict-*.json"))
    if ts_verdicts:
        authoritative = ts_verdicts[-1]
    elif (bundle_dir / "verdict.json").is_file():
        authoritative = bundle_dir / "verdict.json"
    for vf in verdict_files:
        v = json.loads(vf.read_text())
        vroot = v.get("bundle_root")
        if vroot is not None and vroot != root:
            anomalies.append(f"verdicts: {vf.name} records bundle_root {vroot} "
                             f"but the bytes recompute to {root} - the verdict "
                             f"no longer describes this bundle")
        obs = v.get("observation")
        if obs is not None:
            for k, fresh_v in fresh.items():
                if obs.get(k) != fresh_v:
                    anomalies.append(
                        f"verdicts: {vf.name} observation {k}={obs.get(k)} but "
                        f"this verifier's independent reparse derives {k}="
                        f"{fresh_v} - producer-cached verdict and fresh reparse "
                        f"disagree")

    # ---- policy pins (E-04)
    if authoritative is not None:
        v = json.loads(authoritative.read_text())
        pins = v.get("policy_roots")
        if not pins:
            anomalies.append(
                f"policy: {authoritative.name} carries no policy_roots - the "
                f"policy inputs are not hash-pinned, so a ledger/plan edit "
                f"could silently reclassify this observation")
        else:
            actual_ledger = sha256_file(ledger_path) if ledger_path.is_file() else None
            if pins.get("flake_ledger_sha256") != actual_ledger:
                anomalies.append(
                    f"policy: flake ledger now hashes {actual_ledger} but the "
                    f"verdict pinned {pins.get('flake_ledger_sha256')} - the "
                    f"policy changed after the verdict; re-derive, never "
                    f"reinterpret")
            actual_plan_root = None
            if plan_path.is_file():
                try:
                    actual_plan_root = json.loads(
                        plan_path.read_text()).get("plan_root")
                except json.JSONDecodeError:
                    anomalies.append(f"policy: {plan_path} is unreadable")
            if pins.get("plan_root") != actual_plan_root:
                anomalies.append(
                    f"policy: plan root is now {actual_plan_root} but the "
                    f"verdict pinned {pins.get('plan_root')} - the plan changed "
                    f"after the verdict; re-derive, never reinterpret")

    # ---- current-source (optional, expected to FAIL on historical archives)
    if require_current_source:
        current = current_tree_identity(repo)
        if current is None:
            anomalies.append("current-source: sources/typedb is not a git "
                             "checkout here - cannot establish the current "
                             "tree, refusing to vouch")
        else:
            recorded_trees = {json.dumps(t, sort_keys=True) for t in
                              ((r.get("run") or {}).get("executed_tree")
                               for r in rows) if t}
            if not recorded_trees:
                anomalies.append("current-source: the bundle records no "
                                 "executed-tree identity at all - it cannot be "
                                 "current-source evidence")
            for t_json in sorted(recorded_trees):
                t = json.loads(t_json)
                for k in ("checkout_revision", "dirty", "staged_delta_files",
                          "staged_delta_sha256"):
                    if t.get(k) != current.get(k):
                        anomalies.append(
                            f"current-source: bundle tree {k}={t.get(k)!r} but "
                            f"the current staged tree has {k}={current.get(k)!r} "
                            f"- this bundle is evidence about a DIFFERENT tree")
                        break

    return anomalies, warnings, root, fresh


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("bundle", type=pathlib.Path)
    ap.add_argument("--repo", type=pathlib.Path, default=DEFAULT_REPO)
    ap.add_argument("--ledger", type=pathlib.Path, default=None)
    ap.add_argument("--plan", type=pathlib.Path, default=None)
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
    anomalies, warnings, root, fresh = verify(
        bundle.resolve(), repo, ledger, plan, args.require_current_source)
    for w in warnings:
        print(f"WARNING: {w}", file=sys.stderr)
    for a in anomalies:
        print(f"ANOMALY: {a}", file=sys.stderr)
    print(json.dumps({
        "verifier": "tools/evidence/verify_all.py (independent, read-only)",
        "bundle": str(bundle),
        "recomputed_bundle_root": root,
        "fresh_observation": fresh,
        "anomalies": len(anomalies),
        "warnings": len(warnings),
        "verified": not anomalies,
    }, indent=1))
    return 1 if anomalies else 0


if __name__ == "__main__":
    sys.exit(main())
