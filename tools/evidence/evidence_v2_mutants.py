#!/usr/bin/env python3
"""E-04 executed negative controls for the INDEPENDENT verifier.

Each control copies the sealed u2s3-full-3 archive (plus the policy files it
is judged under) into a temp tree, applies exactly ONE mutation, runs
tools/evidence/verify_all.py as a real subprocess against the copy, and
requires a nonzero exit naming the defect. A control that passes silently is
itself a failure. Where a mutation touches a file whose hash other layers
record, the mutation also regenerates every SHALLOWER binding the way a
diligent forger would (sidecar manifest hashes/root, COMPLETE root) - each
control then proves the DEEPEST remaining binding still catches the edit.

Controls:
  0. intact copy verifies (control of controls - rejections prove nothing
     if the clean case is rejected too);
  1. deleted log;
  2. edited count (row aggregate changed; manifest + COMPLETE regenerated;
     the log itself untouched -> the independent reparse catches it);
  3. duplicated row;
  4. tampered COMPLETE (seals a root the bytes do not recompute to);
  5. policy-file edit WITHOUT re-run (flake ledger byte change; manifest +
     COMPLETE regenerated -> only the verdict's pinned policy_roots still
     tell the truth);
  6. verifier-vs-producer disagreement (log edited, row counts and every
     shallower binding regenerated to match, verdict left stale -> the
     cached verdict's observation/bundle_root contradict the fresh reparse);
  7. --require-current-source FAILS on the pristine HISTORICAL archive
     (that failure is correct behavior and is asserted, not excused).

Usage: python3 tools/evidence/evidence_v2_mutants.py
"""
import atexit
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]
VERIFIER = HERE / "verify_all.py"
ARCHIVE_REL = pathlib.Path("docs") / "evidence" / "G3" / "u2s3-full-3"
LEDGER_REL = pathlib.Path("docs") / "evidence" / "flake-ledger.json"
PLAN_REL = pathlib.Path("docs") / "evidence" / "G1" / "qualification-plan-v2.json"

failures = []
checks = 0


def expect(label, condition, detail=""):
    global checks
    checks += 1
    if not condition:
        failures.append(label)
    print(f"  {'PASS' if condition else 'FAIL'}  {label}")
    if not condition and detail:
        print(f"    {detail}", file=sys.stderr)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def make_pristine():
    tree = pathlib.Path(tempfile.mkdtemp(prefix="ev2-pristine-"))
    atexit.register(shutil.rmtree, tree, True)
    (tree / ARCHIVE_REL).mkdir(parents=True)
    for f in (REPO / ARCHIVE_REL).iterdir():
        if f.is_file():
            shutil.copy2(f, tree / ARCHIVE_REL / f.name)
    (tree / LEDGER_REL).parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(REPO / LEDGER_REL, tree / LEDGER_REL)
    (tree / PLAN_REL).parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(REPO / PLAN_REL, tree / PLAN_REL)
    return tree


def run_verifier(tree, bundle=None, extra=()):
    p = subprocess.run(
        [sys.executable, str(VERIFIER), str(bundle or (tree / ARCHIVE_REL)),
         "--repo", str(tree), "--ledger", str(tree / LEDGER_REL),
         "--plan", str(tree / PLAN_REL), *extra],
        capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def recompute_root(tree):
    """The documented bundle-root algorithm (results json + logs + ledger),
    used here only to play the diligent forger regenerating shallow layers."""
    ad = tree / ARCHIVE_REL
    rows = json.loads((ad / "u0-results.json").read_text())["results"]
    files = [ad / "u0-results.json", tree / LEDGER_REL]
    for r in rows:
        if r.get("raw_log"):
            p = pathlib.Path(r["raw_log"])
            files.append(p if p.is_absolute() else tree / p)
    pairs = {}
    for f in files:
        if f.is_file():
            pairs[f.resolve().relative_to(tree.resolve()).as_posix()] = sha256_file(f)
    h = hashlib.sha256()
    for rel in sorted(pairs):
        h.update(rel.encode() + b"\0" + pairs[rel].encode() + b"\n")
    return h.hexdigest()


def refresh_shallow(tree, log_names=(), reseal_complete=False):
    """What a forger does after tampering: recompute sidecar manifest hashes
    and root; optionally reseal COMPLETE with the recomputed root."""
    ad = tree / ARCHIVE_REL
    m = json.loads((ad / "log-manifest.json").read_text())
    for name in log_names:
        m["logs"][name] = sha256_file(ad / name)
    root = recompute_root(tree)
    m["bundle_root"] = root
    (ad / "log-manifest.json").write_text(json.dumps(m, indent=1) + "\n")
    if reseal_complete:
        (ad / "COMPLETE").write_text(f"COMPLETE {root}\n")
    return root


def edit_rows(tree, fn):
    rf = tree / ARCHIVE_REL / "u0-results.json"
    data = json.loads(rf.read_text())
    fn(data["results"])
    rf.write_text(json.dumps(data, indent=1) + "\n")


def control(label, mutate, needle=None, extra=(), expect_ok=False):
    tree = make_pristine()
    if mutate:
        mutate(tree)
    rc, out = run_verifier(tree, extra=extra)
    if expect_ok:
        held = rc == 0
    else:
        held = rc != 0 and (needle is None or needle in out)
    expect(label, held, detail=f"rc={rc} tail: {out[-700:]}")


def main():
    print("evidence-v2 mutants (REAL subprocess: tools/evidence/verify_all.py "
          "over a mutated archive copy)")

    # 0. control of controls
    control("intact archive copy verifies", None, expect_ok=True)

    # 1. deleted log
    control("deleted raw log is rejected",
            lambda t: (t / ARCHIVE_REL / "storage__storage.log").unlink(),
            needle="does not exist")

    # 2. edited count: the forger edits the aggregate and regenerates the
    # manifest and the seal; the LOG is untouched, so only the independent
    # reparse still tells the truth
    def edited_count(tree):
        def fn(rows):
            r = next(r for r in rows if r["passed"] > 1)
            r["passed"] -= 1
        edit_rows(tree, fn)
        refresh_shallow(tree, reseal_complete=True)
        # the forger also rewrites every verdict's recorded root
        for vf in (tree / ARCHIVE_REL).glob("verdict*.json"):
            v = json.loads(vf.read_text())
            v["bundle_root"] = recompute_root(tree)
            vf.write_text(json.dumps(v, indent=1) + "\n")
    control("edited count (manifest/COMPLETE/verdict roots regenerated) "
            "fails the independent reparse", edited_count,
            needle="independently reparses to")

    # 3. duplicated row
    def dup_row(tree):
        edit_rows(tree, lambda rows: rows.append(dict(rows[0])))
        refresh_shallow(tree)
    control("duplicated result row is rejected", dup_row, needle="duplicate")

    # 4. tampered COMPLETE: seals a root the bytes do not recompute to
    control("tampered COMPLETE (foreign sealed root) is rejected",
            lambda t: (t / ARCHIVE_REL / "COMPLETE").write_text(
                "COMPLETE " + "0" * 64 + "\n"),
            needle="COMPLETE binds root")

    # 5. policy edit without re-run: ledger byte change, shallow layers
    # regenerated; the verdict's pinned policy_roots must catch it
    def policy_edit(tree):
        lf = tree / LEDGER_REL
        data = json.loads(lf.read_text())
        data["entries"][0]["expiry"] = "2028-01-01"  # semantically live edit
        lf.write_text(json.dumps(data, indent=2) + "\n")
        refresh_shallow(tree, reseal_complete=True)
    control("policy (flake ledger) edited without a re-run is caught by the "
            "pinned policy_roots", policy_edit,
            needle="the policy changed after the verdict")

    # 6. verifier-vs-producer disagreement: log edited, row counts and all
    # shallow bindings regenerated to agree with the edited log; the CACHED
    # verdict still records the old observation and old root
    def cached_verdict_stale(tree):
        log = tree / ARCHIVE_REL / "cache__cache.log"
        log.write_text(log.read_text(errors="replace")
                       + "\ntest result: ok. 1 passed; 0 failed; 0 ignored; "
                         "0 measured; 0 filtered out; finished in 0.00s\n")
        def fn(rows):
            r = next(r for r in rows if r["target_id"] == "cache:cache")
            r["passed"] += 1
            r["log_sha256"] = sha256_file(log)
        edit_rows(tree, fn)
        refresh_shallow(tree, ["cache__cache.log"], reseal_complete=True)
    control("producer-cached verdict vs fresh reparse disagreement is "
            "rejected", cached_verdict_stale, needle="disagree")

    # 7. the historical archive must FAIL --require-current-source against
    # the REAL repo's current staged tree (read-only invocation, real paths)
    p = subprocess.run(
        [sys.executable, str(VERIFIER), str(REPO / ARCHIVE_REL),
         "--require-current-source"], capture_output=True, text=True)
    expect("--require-current-source FAILS on the historical archive "
           "(correct behavior, asserted)",
           p.returncode != 0 and "current-source" in (p.stdout + p.stderr),
           detail=f"rc={p.returncode} tail: {(p.stdout + p.stderr)[-700:]}")
    # ...and the same invocation WITHOUT the flag verifies (the archive is
    # intact; it is merely not current-source evidence)
    p = subprocess.run(
        [sys.executable, str(VERIFIER), str(REPO / ARCHIVE_REL)],
        capture_output=True, text=True)
    expect("the committed archive verifies without --require-current-source",
           p.returncode == 0,
           detail=f"rc={p.returncode} tail: {(p.stdout + p.stderr)[-700:]}")

    print(f"\nevidence-v2 mutants: {checks - len(failures)}/{checks} controls held")
    for f in failures:
        print(f"MUTANT NOT KILLED: {f}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
