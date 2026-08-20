#!/usr/bin/env python3
"""Executed negative controls for the leaf evidence producer and verifier.

The claim under test is NOT "the verifier has checks". It is: this producer
cannot report a covered leaf without a real execution that really printed
that outcome. So every control below copies a REAL sealed leaf bundle into a
temp tree, applies exactly ONE mutation, and runs
tools/qualification/verify_leaf.py as a REAL SUBPROCESS against the copy,
requiring a nonzero exit that names the defect. A control that passes
silently is itself a failure, and control 0 checks the clean case is
accepted - rejections prove nothing if everything is rejected.

Every mutation is applied the way a DILIGENT FORGER would: after tampering,
the harness regenerates every SHALLOWER binding (each row's recorded
log_sha256, the sidecar manifest's file hashes and root, the verdict's root,
and the COMPLETE seal), so each control proves the DEEPEST remaining binding
still catches the edit rather than proving that a stale hash was noticed.

Controls (the brief's eight, plus the clean case and two seal controls):

  0.  intact copy verifies                       (control of controls)
  1.  empty log
  2.  truncated log (its libtest summary removed)
  3.  a case list that does not match the log (one per-case line deleted
      from the log; the forger also fixes the row's parsed_cases)
  4.  an edited outcome (PASSED -> FAILED in the JSON, log untouched)
  5.  a target that never ran (its row removed, its leaves kept)
  6.  a dirty tree presented as clean (tree_state, dirty, staged_delta_files
      and diverging_paths all forged)
  6b. the same forgery ALSO fabricating the staged-delta digest - undetectable
      from inside the bundle, and caught only by --corroborate-tree. Recorded
      as an explicit LIMIT of the scheme, not hidden.
  7.  a leaf bound to the wrong target_id
  8.  a zero-case target claiming coverage
  9.  a deleted log
  10. a COMPLETE marker sealing a root the bytes do not recompute to
  11. the coverage reporter counts ZERO rows from a refused bundle
      (tools/qualification/leaf_coverage.py, also a real subprocess)

Usage: python3 tools/qualification/leaf_mutants.py [--bundle DIR]
"""
import argparse
import atexit
import copy
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
import leaf_common as lc  # noqa: E402

VERIFIER = HERE / "verify_leaf.py"
COVERAGE = HERE / "leaf_coverage.py"

failures, checks = [], 0


def expect(label, ok, detail="", verb=("KILLED", "SURVIVED")):
    global checks
    checks += 1
    if not ok:
        failures.append(label)
    print(f"  {verb[0] if ok else verb[1]}  {label}")
    if not ok and detail:
        print(f"      {detail}", file=sys.stderr)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class Copy:
    """A mutable copy of a real bundle inside a temp tree, laid out at the
    same repo-relative path so `raw_log` resolves under --repo TREE."""

    def __init__(self, src_rel):
        self.tree = pathlib.Path(tempfile.mkdtemp(prefix="leaf-mutant-"))
        atexit.register(shutil.rmtree, self.tree, True)
        self.rel = pathlib.Path(src_rel)
        dst = self.tree / self.rel
        dst.mkdir(parents=True)
        for f in (REPO / self.rel).iterdir():
            if f.is_file():
                shutil.copy2(f, dst / f.name)
        self.dir = dst

    def load(self):
        return json.loads((self.dir / lc.RESULTS_NAME).read_text())

    def save(self, bundle):
        (self.dir / lc.RESULTS_NAME).write_text(json.dumps(bundle, indent=1) + "\n")

    def refresh(self, bundle=None):
        """Everything a forger regenerates after tampering: each row's
        log_sha256, the sidecar manifest, the verdict root, the COMPLETE seal."""
        bundle = bundle if bundle is not None else self.load()
        for t in bundle.get("targets", []):
            log = self.tree / t["raw_log"]
            if log.is_file():
                t["log_sha256"] = sha256_file(log)
        by_log = {t["raw_log"]: t["log_sha256"] for t in bundle.get("targets", [])}
        for lf in bundle.get("leaves", []):
            if lf["raw_log"] in by_log:
                lf["log_sha256"] = by_log[lf["raw_log"]]
        self.save(bundle)
        root, pairs = lc.compute_bundle_root(self.dir, bundle, self.tree)
        (self.dir / "bundle-manifest.json").write_text(
            json.dumps({"bundle_root": root, "files": pairs}, indent=1) + "\n")
        vf = self.dir / "leaf-verdict.json"
        if vf.is_file():
            v = json.loads(vf.read_text())
            v["bundle_root"] = root
            v.setdefault("observation", {})["leaves"] = len(bundle.get("leaves") or [])
            vf.write_text(json.dumps(v, indent=1) + "\n")
        (self.dir / "COMPLETE").write_text(f"COMPLETE {root}\n")
        return root

    def verify(self, extra=()):
        p = subprocess.run([sys.executable, str(VERIFIER), str(self.dir),
                            "--repo", str(self.tree), *extra],
                           capture_output=True, text=True)
        return p.returncode, p.stdout + p.stderr

    def coverage(self):
        p = subprocess.run([sys.executable, str(COVERAGE), "--leaf", str(self.dir),
                            "--repo", str(self.tree)],
                           capture_output=True, text=True)
        return p.returncode, p.stdout + p.stderr


def control(label, src, mutate, needle=None, extra=(), expect_ok=False):
    c = Copy(src)
    if mutate:
        mutate(c)
    rc, out = c.verify(extra)
    ok = (rc == 0) if expect_ok else (rc != 0 and (needle is None or needle in out))
    expect(label, ok, detail=f"rc={rc} tail: {out[-900:]}")
    return c


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bundle", default="docs/evidence/G3/leaf/u1-full-1",
                    help="a real sealed leaf bundle to mutate (repo-relative)")
    args = ap.parse_args()
    src = args.bundle
    if not (REPO / src / lc.RESULTS_NAME).is_file():
        sys.exit(f"{src} is not a leaf bundle - the controls mutate REAL "
                 f"evidence copies, never a fixture invented for the test")
    print(f"leaf mutants (REAL subprocess: tools/qualification/verify_leaf.py "
          f"over a mutated COPY of {src})")

    def pick_target(bundle, min_leaves=2):
        counts = {}
        for lf in bundle["leaves"]:
            counts[lf["runner_row_id"]] = counts.get(lf["runner_row_id"], 0) + 1
        for t in bundle["targets"]:
            if counts.get(t["runner_row_id"], 0) >= min_leaves:
                return t
        raise SystemExit("no target with enough leaves to mutate")

    # 0 -------------------------------------------------------------- clean
    control("0  intact bundle copy verifies (control of controls)",
            src, None, expect_ok=True)

    # 1 --------------------------------------------------------- empty log
    def empty_log(c):
        b = c.load()
        t = pick_target(b)
        (c.tree / t["raw_log"]).write_bytes(b"")
        c.refresh(b)
    control("1  empty log", src, empty_log, needle="log reparses to")

    # 2 ------------------------------------------------------ truncated log
    def truncate(c):
        b = c.load()
        t = pick_target(b)
        p = c.tree / t["raw_log"]
        lines = p.read_text().splitlines()
        keep = [l for l in lines if not l.startswith("test result:")][: len(lines) // 2]
        p.write_text("\n".join(keep) + "\n")
        c.refresh(b)
    control("2  truncated log (libtest summary removed)", src, truncate,
            needle="no libtest summary line")

    # 3 ------------------------------- case list that does not match the log
    def desync(c):
        b = c.load()
        t = pick_target(b)
        p = c.tree / t["raw_log"]
        lines = p.read_text().splitlines()
        idx = next(i for i, l in enumerate(lines)
                   if l.startswith("test ") and l.rstrip().endswith("... ok"))
        del lines[idx]
        p.write_text("\n".join(lines) + "\n")
        # the diligent forger also corrects the row's parsed_cases so only the
        # reconciliation against the log's OWN summary is left to catch it
        t["parsed_cases"] -= 1
        c.refresh(b)
    control("3  case list does not match the log (one per-case line deleted, "
            "parsed_cases corrected by the forger)", src, desync,
            needle="contradicts the log it was read from")

    # 4 ----------------------------------------------------- edited outcome
    def edit_outcome(c):
        b = c.load()
        lf = next(l for l in b["leaves"] if l["outcome"] == "PASSED")
        lf["outcome"] = "FAILED"
        c.refresh(b)
    control("4  edited outcome (PASSED -> FAILED in the JSON, log untouched)",
            src, edit_outcome, needle="an edited outcome over an untouched log")

    # 5 --------------------------------------------- a target that never ran
    def ghost_target(c):
        b = c.load()
        t = pick_target(b)
        b["targets"] = [x for x in b["targets"] if x is not t]
        c.refresh(b)
    control("5  a target that never ran (row removed, its leaves kept)",
            src, ghost_target, needle="a leaf from a target that never ran")

    # 6 ------------------------------- a dirty tree presented as clean
    def fake_clean(c):
        b = c.load()
        tr = b["executed_tree"]
        tr["tree_state"] = "PRISTINE"
        tr["dirty"] = False
        tr["staged_delta_files"] = 0
        tr["diverging_paths"] = []
        tr["unstaged_fork_patches"] = []
        tr["unexplained_paths"] = []
        c.refresh(b)
    control("6  a dirty tree presented as clean (tree_state/dirty/"
            "staged_delta_files/diverging_paths all forged)", src, fake_clean,
            needle="not the digest of an empty delta")

    # 6b ------------------------- the same forgery, digest fabricated too
    def fake_clean_total(c):
        b = c.load()
        tr = b["executed_tree"]
        tr["tree_state"] = "PRISTINE"
        tr["dirty"] = False
        tr["staged_delta_files"] = 0
        tr["diverging_paths"] = []
        tr["unstaged_fork_patches"] = []
        tr["unexplained_paths"] = []
        tr["staged_delta_sha256"] = hashlib.sha256(b"").hexdigest()
        c.refresh(b)
    control("6b a dirty tree presented as clean WITH the staged-delta digest "
            "fabricated - caught only by --corroborate-tree", src,
            fake_clean_total, needle="corroboration refuses the claim",
            extra=("--corroborate-tree",))
    # and the honest statement of the limit: without corroboration it survives
    c = Copy(src)
    fake_clean_total(c)
    rc, _out = c.verify()
    expect("6c LIMIT ASSERTED (expected ACCEPTANCE, not a kill): without "
           "--corroborate-tree the same total forgery is NOT detectable from "
           "inside the bundle alone, because the producer writes the tree "
           "record and nothing inside the bundle can pin it", rc == 0,
           detail=f"expected the un-corroborated verify to accept it, rc={rc}",
           verb=("HOLDS", "UNEXPECTED"))

    # 7 ------------------------------------ a leaf bound to the wrong target
    def wrong_target(c):
        b = c.load()
        rids = [t["runner_row_id"] for t in b["targets"]]
        lf = next(l for l in b["leaves"])
        other = next(t for t in b["targets"]
                     if t["runner_row_id"] != lf["runner_row_id"]
                     and t.get("catalog_target_id"))
        lf["catalog_target_id"] = other["catalog_target_id"]
        lf["runner_row_id"] = other["runner_row_id"]
        lf["leaf_case_id"] = f"{other['catalog_target_id']}::{lf['case_name']}"
        assert rids
        c.refresh(b)
    control("7  a leaf bound to the wrong target_id", src, wrong_target,
            needle="the catalogue declares no leaf")

    # 8 ------------------------------- a zero-case target claiming coverage
    def zero_case(c):
        b = c.load()
        t = pick_target(b)
        p = c.tree / t["raw_log"]
        p.write_text("\nrunning 0 tests\n\ntest result: ok. 0 passed; 0 failed; "
                     "0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n\n")
        t["counts"] = {"passed": 0, "failed": 0, "ignored": 0, "measured": 0,
                       "filtered_out": 0}
        t["parsed_cases"] = 0
        t["publishable"] = True
        t["refusals"] = []
        b["leaves"] = [l for l in b["leaves"]
                       if l["runner_row_id"] != t["runner_row_id"]]
        c.refresh(b)
    control("8  a zero-case target claiming coverage", src, zero_case,
            needle="vacuous evidence claiming coverage")

    # 9 ----------------------------------------------------- a deleted log
    def delete_log(c):
        b = c.load()
        t = pick_target(b)
        (c.tree / t["raw_log"]).unlink()
        # the forger cannot rehash a file that is gone, but regenerates the
        # rest so only the missing-bytes rule is left
        root, pairs = lc.compute_bundle_root(c.dir, b, c.tree)
        (c.dir / "bundle-manifest.json").write_text(
            json.dumps({"bundle_root": root, "files": pairs}, indent=1) + "\n")
        v = json.loads((c.dir / "leaf-verdict.json").read_text())
        v["bundle_root"] = root
        (c.dir / "leaf-verdict.json").write_text(json.dumps(v, indent=1) + "\n")
        (c.dir / "COMPLETE").write_text(f"COMPLETE {root}\n")
    control("9  a deleted log", src, delete_log, needle="does not exist")

    # 10 ------------------------------------------------ tampered COMPLETE
    control("10 COMPLETE sealing a root the bytes do not recompute to", src,
            lambda c: (c.dir / "COMPLETE").write_text("COMPLETE " + "0" * 64 + "\n"),
            needle="the archive was modified after it was sealed")

    # 12 --------------------------- a leaf repointed at another case's line
    def wrong_line(c):
        b = c.load()
        rid_counts = {}
        for lf in b["leaves"]:
            rid_counts.setdefault(lf["runner_row_id"], []).append(lf)
        group = next(v for v in rid_counts.values() if len(v) >= 2)
        a, other = group[0], group[1]
        a["log_line"], a["outcome_line"] = other["log_line"], other["outcome_line"]
        c.refresh(b)
    control("12 a leaf repointed at another case's log line", src, wrong_line,
            needle="an edited outcome over an untouched log")

    # 13 ---------------- a FILTERED run presented as a full enumeration
    def filtered(c):
        b = c.load()
        t = pick_target(b)
        p2 = c.tree / t["raw_log"]
        txt = p2.read_text()
        i = txt.index("test result:")
        j = txt.index("\n", i)
        line = txt[i:j].replace("0 filtered out", "3 filtered out")
        p2.write_text(txt[:i] + line + txt[j:])
        t["counts"]["filtered_out"] = 3
        c.refresh(b)
    control("13 a filtered run (filtered_out > 0) presented as a full leaf "
            "enumeration", src, filtered, needle="filtered_out=3")

    # 11 ------------------- the coverage reporter counts nothing from a refusal
    def leaf_family_covered(report):
        # ONLY the families this producer supplies. Other lanes (the driver
        # rows) legitimately cover rows from their own sealed evidence, and
        # counting them here would make this control pass or fail for reasons
        # that have nothing to do with the mutation.
        return sum(v.get("COVERED", 0)
                   for k, v in report["by_family"].items()
                   if k.startswith("cargo-"))

    c = Copy(src)
    _rc0, out0 = c.coverage()
    clean = json.loads(out0[out0.index("{"):out0.rindex("}") + 1])
    c2 = Copy(src)
    edit_outcome(c2)
    _rc1, out1 = c2.coverage()
    mutated = json.loads(out1[out1.index("{"):out1.rindex("}") + 1])
    expect(f"11 leaf_coverage counts 0 cargo-family rows from a refused bundle "
           f"(the same bundle intact covers {leaf_family_covered(clean)})",
           leaf_family_covered(clean) > 0 and leaf_family_covered(mutated) == 0
           and mutated["leaf_bundles"][0]["anomalies"],
           detail=f"intact={leaf_family_covered(clean)} "
                  f"mutated={leaf_family_covered(mutated)} "
                  f"anomalies={len(mutated['leaf_bundles'][0]['anomalies'])}")

    print(f"\n{checks - len(failures)}/{checks} controls held "
          f"({len(failures)} SURVIVED)")
    for f in failures:
        print(f"SURVIVED: {f}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
