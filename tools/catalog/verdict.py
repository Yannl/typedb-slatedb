#!/usr/bin/env python3
"""One fail-closed verdict policy, shared by every evidence producer.

The defect class this module exists to kill: a producer that writes red rows
into an evidence file and then exits zero, so CI (and a reader skimming the
process result) records a green run over a red corpus. Both current producers
had it - `run_static.py` wrote FAIL/ERROR rows with rc=0, and `run_u0.py` had
no terminal verdict at all.

The rules are deliberately few and deliberately unconditional:

  1. A run is GREEN only if every row is accounted for by policy.
  2. The ONLY policy that may tolerate an anomaly is the committed
     flake/exclusion ledger (`docs/evidence/flake-ledger.json`), matched by
     exact target id AND exact counts AND exact exit code.
  3. Anything not matched - a failure, an ignore, a nonzero exit, a timeout,
     a crash rc, a required target that produced no row, a required target
     that produced a row with zero cases - is RED.
  4. There is no flag that turns a red verdict green. A partial selection
     narrows the *denominator* (and says so in the verdict), never the bar.

`verdict_exit_code()` is what a producer returns from `main()`.

The E-P0-06/07/10 audit added a second defect class this module now kills:
a verifier that trusts the JSON AGGREGATES and never reopens the raw logs.
Every one of these mutations of an archived run re-derived GREEN: deleted
logs, duplicated rows, edited counts, forged log paths, forged provenance
digests, ghost ledger cases. `verify_bundle()` below is the answer - the
verdict is a function of the BYTES, not of the summary somebody wrote about
the bytes: every log must exist, hash-match its binding, and REPARSE to the
counts its row claims; and a bundle root over everything the verdict
consumed is bound into the COMPLETE marker so post-hoc edits of any consumed
file (including the results JSON itself) are a root mismatch, not a shrug.
"""

import datetime
import hashlib
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import common  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parents[2]
LEDGER = REPO / "docs" / "evidence" / "flake-ledger.json"
PLAN = REPO / "docs" / "evidence" / "G1" / "qualification-plan-v2.json"
# the post-hoc hash binding for archives sealed before rows recorded log
# hashes and before COMPLETE carried a bundle root (see verify_bundle)
LOG_MANIFEST_NAME = "log-manifest.json"


def load_ledger(path=None):
    """target_id -> entry. Expired entries are dropped AND reported: an
    expired exclusion must stop the line, never silently keep excluding.

    E-P0-07 additions, all fail-closed:
      - duplicate target_id is a problem (two policies for one target means
        whichever the dict kept silently won);
      - every entry must bind the storage `profile`(s) it covers (a tolerance
        observed on one lane must not silently excuse another lane);
      - every entry that tolerates failed/ignored cases must carry a
        `fingerprint` naming them ({"failed": [...], "ignored": [...]});
        verify_bundle() then checks those names against the RAW LOG, so a
        ledger full of ghost case names is red, not camouflage.
    """
    path = path or LEDGER
    problems = []
    entries = {}
    if not path.exists():
        return entries, problems
    for e in json.loads(path.read_text()).get("entries", []):
        tid = e.get("target_id")
        if not tid:
            problems.append("ledger: entry with no target_id")
            continue
        if tid in entries:
            problems.append(
                f"ledger: duplicate entry for {tid} - one target, "
                f"one policy; two entries means one silently wins"
            )
            continue
        if not e.get("reason"):
            problems.append(f"ledger: {tid} has no reason - exclusions must be explained")
        if not e.get("profile"):
            problems.append(
                f"ledger: {tid} names no profile - a tolerance must "
                f"say which storage lane(s) it was observed on"
            )
        exp_f = e.get("expected_failed", 0)
        exp_i = e.get("expected_ignored", 0)
        fp = e.get("fingerprint")
        if exp_f + exp_i > 0 and fp is None:
            problems.append(
                f"ledger: {tid} tolerates {exp_f} failed + {exp_i} "
                f"ignored case(s) but carries no fingerprint naming them"
            )
        if fp is not None:
            if len(fp.get("failed") or []) != exp_f:
                problems.append(
                    f"ledger: {tid} fingerprint names "
                    f"{len(fp.get('failed') or [])} failed case(s) but the "
                    f"entry declares expected_failed={exp_f}"
                )
            if len(fp.get("ignored") or []) != exp_i:
                problems.append(
                    f"ledger: {tid} fingerprint names "
                    f"{len(fp.get('ignored') or [])} ignored case(s) but the "
                    f"entry declares expected_ignored={exp_i}"
                )
        expiry = e.get("expiry")
        if not expiry:
            problems.append(f"ledger: {tid} has no expiry - open-ended exclusions are forbidden")
            continue
        if datetime.date.fromisoformat(expiry) < datetime.date.today():
            problems.append(f"ledger: {tid} expired ({expiry}) - re-justify or retire it")
            continue
        entries[tid] = e
    return entries, problems


def compute_policy_roots(ledger_path=None, plan_path=None):
    """E-04: hash-pin the POLICY inputs a verdict rests on.

    A verdict is observation x policy. The E-P0-07 audit showed a policy
    change (a relaxed flake ledger) turning the same observation from red to
    green without a re-run and without a trace. Pinning the exact ledger
    bytes and the plan's content-addressed root INTO the verdict makes any
    later policy edit a detectable mismatch (tools/evidence/verify_all.py
    recomputes both and refuses a bundle whose policy moved under it).
    A missing file pins None - honest absence, never a fabricated hash.
    """
    ledger_path = pathlib.Path(ledger_path) if ledger_path else LEDGER
    plan_path = pathlib.Path(plan_path) if plan_path else PLAN
    roots: dict[str, str | None] = {"flake_ledger_sha256": None, "plan_root": None}
    if ledger_path.is_file():
        roots["flake_ledger_sha256"] = common.sha256_file(ledger_path)
    if plan_path.is_file():
        try:
            roots["plan_root"] = json.loads(plan_path.read_text()).get("plan_root")
        except (json.JSONDecodeError, OSError):
            pass  # unreadable plan pins None; the verifier reports the gap
    return roots


def _cases(row):
    return (
        row.get("passed", 0) + row.get("failed", 0) + row.get("ignored", 0) + row.get("measured", 0)
    )


def classify_rows(results, ledger, expected_case_bearing=None):
    """Anomaly list for a set of executable result rows.

    `expected_case_bearing` is the set of target ids the catalogue says
    contain at least one leaf case. A row for such a target that reports zero
    cases is red: it is indistinguishable from a binary that silently ran
    nothing, which is exactly how a corpus shrinks without anyone noticing.
    """
    anomalies = []
    matched = set()
    for r in sorted(results, key=lambda x: x["target_id"]):
        tid = r["target_id"]
        entry = ledger.get(tid)
        if entry is not None:
            matched.add(tid)
        exp_failed = entry.get("expected_failed", 0) if entry else 0
        exp_ignored = entry.get("expected_ignored", 0) if entry else 0
        exp_rc = entry.get("expected_exit_code", 0) if entry else 0

        if r.get("timed_out"):
            anomalies.append(f"{tid}: TIMED OUT - never ledgerable, always a defect")
            continue
        rc = r.get("exit_code")
        if rc != exp_rc:
            anomalies.append(
                f"{tid}: exit code {rc!r} but policy expects {exp_rc!r}"
                + ("" if entry else " (no ledger entry)")
            )
        failed, ignored = r.get("failed", 0), r.get("ignored", 0)
        if failed != exp_failed:
            anomalies.append(
                f"{tid}: {failed} failed case(s), policy expects {exp_failed}"
                + ("" if entry else " (no ledger entry)")
            )
        if ignored != exp_ignored:
            anomalies.append(
                f"{tid}: {ignored} ignored case(s), policy expects {exp_ignored}"
                + ("" if entry else " (no ledger entry)")
            )
        if entry and entry.get("cases") is not None:
            # the ledger names the exact cases; their count must agree with
            # the counts it also declares, or the entry is self-inconsistent
            if len(entry["cases"]) != exp_failed + exp_ignored:
                anomalies.append(
                    f"ledger: {tid} names {len(entry['cases'])} case(s) but declares "
                    f"{exp_failed} failed + {exp_ignored} ignored"
                )
        if expected_case_bearing is not None and tid in expected_case_bearing and _cases(r) == 0:
            anomalies.append(
                f"{tid}: ran to completion with ZERO cases although the catalogue "
                f"records leaf cases for it - the corpus silently shrank here"
            )
    for tid in sorted(set(ledger) - matched):
        anomalies.append(
            f"ledger: entry for {tid} matched no row in this run - stale "
            f"exclusions must be retired, not carried"
        )
    return anomalies


def denominator_anomalies(results, required_target_ids, declared_exclusions=None):
    """Exact set equality between what had to run and what did run."""
    declared = dict(declared_exclusions or {})
    ran = {r["target_id"] for r in results}
    required = set(required_target_ids)
    out = []
    for tid in sorted(required - ran):
        reason = declared.get(tid)
        if not reason:
            out.append(f"denominator: required target {tid} produced NO result row")
    for tid in sorted(ran - required):
        out.append(f"denominator: {tid} produced a result row but is not a required target")
    for tid in sorted(declared):
        if tid in ran:
            out.append(f"denominator: {tid} is declared not-executed but produced a row anyway")
    # Whether an exclusion's SUBJECT resolves to a real catalogue target is a
    # catalogue question, not a run question: validate_catalog.py owns it, and
    # duplicating it here only produced false anomalies for targets that are
    # legitimately absent from the executable denominator.
    return out


# ------------------------------------------------------- bundle verification


def _resolve_log(raw_log, repo):
    p = pathlib.Path(raw_log)
    return p if p.is_absolute() else (repo / p)


def _bundle_rel(path, repo, results_dir):
    """Stable identity of a consumed file inside the bundle root: repo-relative
    when possible (so a byte-identical bundle hashes identically wherever the
    repo is checked out), out-dir-relative otherwise."""
    p = pathlib.Path(path).resolve()
    try:
        return p.relative_to(pathlib.Path(repo).resolve()).as_posix()
    except ValueError:
        pass
    try:
        return "<out>/" + p.relative_to(pathlib.Path(results_dir).resolve()).as_posix()
    except ValueError:
        return str(p)


def compute_bundle_root(results_dir, results, ledger_path=None, repo=None):
    """sha256 over the sorted (relative path, sha256) pairs of every file this
    verdict consumed: the results JSON, every row's raw log, and the ledger.

    Returns (root_hex, {rel_path: sha256}). Files that do not exist are simply
    absent from the pairs - their absence is ALREADY an anomaly from
    verify_bundle, and the root is then never bound green.
    """
    results_dir = pathlib.Path(results_dir)
    repo = pathlib.Path(repo) if repo else REPO
    ledger_path = pathlib.Path(ledger_path) if ledger_path else LEDGER
    files = [results_dir / "u0-results.json", ledger_path]
    for r in results:
        if r.get("raw_log"):
            files.append(_resolve_log(r["raw_log"], repo))
    pairs = {}
    for f in files:
        if f.is_file():
            pairs[_bundle_rel(f, repo, results_dir)] = common.sha256_file(f)
    h = hashlib.sha256()
    for rel in sorted(pairs):
        h.update(rel.encode() + b"\0" + pairs[rel].encode() + b"\n")
    return h.hexdigest(), pairs


def verify_bundle(
    results_dir, results, ledger, file_profile=None, ledger_path=None, repo=None, unsealed_ok=False
):
    """The audit-mandated layer: verify the BYTES a verdict rests on.

    Returns (anomalies, warnings, bundle_root). Checks, all fail-closed:

      - every row's raw log EXISTS, lives inside the results dir, and its
        sha256 matches the row's recorded `log_sha256`; rows sealed before
        hashing was recorded (the u2s3-full-3 archive) are checked against the
        committed sidecar `log-manifest.json` instead; a row bound by NEITHER
        is red - unbound bytes are not evidence;
      - every log REPARSES (common.parse_libtest_counts) to exactly the counts
        its row claims - an edited aggregate over an untouched log is a
        contradiction, never a number to trust (E-P0-06);
      - duplicate row ids and two rows naming one log file are red (a
        duplicated row inflates the corpus without running anything);
      - every ledger tolerance that applies to a row is verified against the
        LOG: the fingerprint's failed-case names must be exactly the failing
        names the log prints, and the run's profile must be one the entry
        covers (E-P0-07 ghost cases / wrong lane);
      - the recomputed bundle root must equal the root the sidecar manifest
        recorded, and the root a `COMPLETE <hex>` marker binds; a bare legacy
        COMPLETE (predates root binding) is a named WARNING, not silence.
    """
    results_dir = pathlib.Path(results_dir)
    repo = pathlib.Path(repo) if repo else REPO
    ledger_path = pathlib.Path(ledger_path) if ledger_path else LEDGER
    anomalies, warnings = [], []

    manifest = {}
    manifest_root = None
    mf = results_dir / LOG_MANIFEST_NAME
    if mf.is_file():
        m = json.loads(mf.read_text())
        manifest = m.get("logs", {})
        manifest_root = m.get("bundle_root")

    seen_ids = {}
    seen_logs = {}
    for r in results:
        tid = r.get("target_id", "<no target_id>")
        if tid in seen_ids:
            anomalies.append(
                f"bundle: duplicate result row for {tid} - a row "
                f"that appears twice inflates the corpus without "
                f"running anything"
            )
            continue
        seen_ids[tid] = r
        raw_log = r.get("raw_log")
        if not raw_log:
            anomalies.append(
                f"bundle: {tid} records no raw log - a count "
                f"without its log is an assertion, not evidence"
            )
            continue
        log = _resolve_log(raw_log, repo)
        try:
            inside = log.resolve().is_relative_to(results_dir.resolve())
        except OSError:
            inside = False
        if not log.is_file():
            anomalies.append(
                f"bundle: {tid} names raw log {raw_log} which does "
                f"not exist - the evidence for its counts is gone"
            )
            continue
        if not inside:
            anomalies.append(
                f"bundle: {tid} names raw log {raw_log} OUTSIDE the "
                f"evidence dir {results_dir} - logs must live in the "
                f"bundle they justify"
            )
            continue
        key = log.resolve()
        if key in seen_logs:
            anomalies.append(
                f"bundle: {tid} and {seen_logs[key]} both name log "
                f"{raw_log} - one execution cannot vouch for two rows"
            )
            continue
        seen_logs[key] = tid
        actual_sha = common.sha256_file(log)
        rel_in_dir = log.resolve().relative_to(results_dir.resolve()).as_posix()
        recorded = r.get("log_sha256")
        if recorded is not None:
            if recorded != actual_sha:
                anomalies.append(
                    f"bundle: {tid} log {raw_log} hashes {actual_sha} "
                    f"but the row recorded {recorded} - the log was "
                    f"rewritten after the row was"
                )
        elif rel_in_dir in manifest:
            if manifest[rel_in_dir] != actual_sha:
                anomalies.append(
                    f"bundle: {tid} log {raw_log} hashes {actual_sha} "
                    f"but the sidecar manifest recorded "
                    f"{manifest[rel_in_dir]} - the archived bytes changed"
                )
        else:
            anomalies.append(
                f"bundle: {tid} log {raw_log} has no recorded hash and "
                f"no sidecar manifest entry - unbound bytes are not "
                f"evidence (add {LOG_MANIFEST_NAME} for legacy archives)"
            )
        text = log.read_text(errors="replace")
        parsed = common.parse_libtest_counts(text)
        for k, v in parsed.items():
            if v != r.get(k, 0):
                anomalies.append(
                    f"bundle: {tid} row claims {k}={r.get(k, 0)} but its "
                    f"log reparses to {k}={v} - the aggregate "
                    f"contradicts the evidence it summarizes"
                )
        # ---- ledger fingerprint vs the raw log (E-P0-07) ----
        entry = ledger.get(tid)
        if entry is None:
            continue
        prof = entry.get("profile")
        allowed = [prof] if isinstance(prof, str) else list(prof or [])
        row_profile = (r.get("run") or {}).get("profile") or file_profile
        if not allowed:
            anomalies.append(
                f"ledger: {tid} names no profile - a tolerance must "
                f"say which storage lane(s) it covers"
            )
        elif row_profile not in allowed:
            anomalies.append(
                f"ledger: {tid} tolerance covers profile(s) {allowed} "
                f"but this run's profile is {row_profile!r} - a "
                f"tolerance observed on one lane excuses no other"
            )
        fp = entry.get("fingerprint")
        if fp is None:
            if entry.get("expected_failed", 0) + entry.get("expected_ignored", 0) > 0:
                anomalies.append(
                    f"ledger: {tid} tolerates cases it does not name - "
                    f"add a fingerprint or retire the entry"
                )
            continue
        fp_failed = set(fp.get("failed") or [])
        log_failed = common.parse_libtest_failed_cases(text)
        if fp_failed != log_failed:
            ghosts = sorted(fp_failed - log_failed)
            unledgered = sorted(log_failed - fp_failed)
            anomalies.append(
                f"ledger: {tid} fingerprint does not match the log's failing cases"
                + (f"; ledgered but NOT failing in the log (ghosts): {ghosts}" if ghosts else "")
                + (f"; failing in the log but NOT ledgered: {unledgered}" if unledgered else "")
            )
        fp_ignored = set(fp.get("ignored") or [])
        if fp_ignored:
            log_ignored = common.parse_libtest_ignored_cases(text)
            if log_ignored and fp_ignored != log_ignored:
                anomalies.append(
                    f"ledger: {tid} fingerprint ignored cases "
                    f"{sorted(fp_ignored)} do not match the log's "
                    f"named ignored cases {sorted(log_ignored)}"
                )
            elif not log_ignored:
                # terse libtest output prints `i` with no name; the COUNT is
                # still bound (parse_libtest_counts above), the NAMES are not.
                # Honest gap, named - never silently claimed as verified.
                warnings.append(
                    f"{tid}: log is terse-format and names no ignored "
                    f"cases; {len(fp_ignored)} ignored tolerance(s) "
                    f"verified by count only, not by name"
                )

    root, _pairs = compute_bundle_root(results_dir, results, ledger_path=ledger_path, repo=repo)
    if manifest_root is not None and manifest_root != root:
        anomalies.append(
            f"bundle: recomputed root {root} != sidecar manifest root "
            f"{manifest_root} - some consumed file changed after the "
            f"manifest was computed"
        )
    marker = results_dir / "COMPLETE"
    if marker.is_file():
        marker_text = marker.read_text()
        m = re.match(
            r"^COMPLETE ([0-9a-f]{64})\s*$",
            marker_text.splitlines()[0] if marker_text.strip() else "",
        )
        if m:
            if m.group(1) != root:
                anomalies.append(
                    f"bundle: COMPLETE binds root {m.group(1)} but the "
                    f"bundle recomputes to {root} - the archive was "
                    f"modified after it was sealed"
                )
        else:
            warnings.append(
                f"COMPLETE carries no bundle root (legacy marker, "
                f"predates root binding) - archive integrity rests on "
                f"the sidecar manifest and this verdict's recorded "
                f"bundle_root {root}; future runs seal 'COMPLETE <root>'"
            )
    elif not unsealed_ok:
        # unsealed_ok is for the LIVE producer, which verifies immediately
        # before sealing; every re-reader must see the missing seal named
        warnings.append(
            "no COMPLETE marker in the results dir - this bundle was "
            "never sealed green (mid-run, red, or pre-verdict)"
        )
    return anomalies, warnings, root


def compute_observation(results):
    """The RAW observation, before any ledger tolerance is applied. E-P0-07:
    a verdict that prints only the policy outcome hides what actually
    happened; both must always travel together."""
    return {
        "rows": len(results),
        "nonzero_exit_rows": sum(
            1 for r in results if not r.get("timed_out") and r.get("exit_code") != 0
        ),
        "timed_out_rows": sum(1 for r in results if r.get("timed_out")),
        "cases_passed": sum(r.get("passed", 0) for r in results),
        "cases_failed": sum(r.get("failed", 0) for r in results),
        "cases_ignored": sum(r.get("ignored", 0) for r in results),
    }


def human_line(observation, green, ledgered_rows):
    """The one line a human reads. NEVER a bare GREEN: the raw observation
    (with the reds the ledger tolerates still visible) always precedes the
    policy outcome."""
    o = observation
    return (
        f"OBSERVATION: {o['rows']} rows, {o['nonzero_exit_rows']} nonzero exit(s), "
        f"{o['timed_out_rows']} timeout(s), {o['cases_failed']} failed case(s), "
        f"{o['cases_ignored']} ignored case(s); "
        f"POLICY: {'GREEN' if green else 'RED'} ({ledgered_rows} ledgered)"
    )


def verdict_exit_code(
    anomalies,
    complete_selection,
    out_dir=None,
    extra=None,
    observation=None,
    warnings=None,
    bundle_root=None,
    verdict_filename="verdict.json",
    write_complete=True,
):
    """Write the verdict file (+ a COMPLETE marker on green) and return 0/1.

    The verdict now carries BOTH the raw `observation` and the ledger-filtered
    `policy_verdict` (E-P0-07), plus the `bundle_root` that binds every byte it
    consumed. Write order on the live path: verdict first, COMPLETE LAST -
    a crash between the two leaves an unsealed dir, never a sealed lie.
    `write_complete=False` is the re-derivation mode: an existing archive's
    COMPLETE is verified evidence, never rewritten by a re-reader.
    """
    green = not anomalies and complete_selection
    verdict = {
        "green": green,
        "policy_verdict": "GREEN" if green else "RED",
        "complete_selection": complete_selection,
        "anomaly_count": len(anomalies),
        "anomalies": anomalies,
        **({"warnings": warnings} if warnings else {}),
        **({"observation": observation} if observation is not None else {}),
        **({"bundle_root": bundle_root} if bundle_root is not None else {}),
        **(extra or {}),
    }
    if out_dir is not None:
        out_dir = pathlib.Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / verdict_filename).write_text(json.dumps(verdict, indent=1) + "\n")
        marker = out_dir / "COMPLETE"
        if write_complete:
            if green:
                if bundle_root:
                    marker.write_text(f"COMPLETE {bundle_root}\n")
                else:
                    marker.write_text(
                        json.dumps(
                            {"green": True, "written_by": "tools/catalog/verdict.py"}, indent=1
                        )
                        + "\n"
                    )
            elif marker.exists():
                # a re-run that goes red must not leave a stale green marker behind
                marker.unlink()
    return 0 if green else 1
