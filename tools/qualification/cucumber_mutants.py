#!/usr/bin/env python3
"""Executed negative controls for the cucumber leaf producer and verifier.

The claim under test is not "the verifier has checks". It is: NO cucumber
plan row can be reported covered without an archived execution that really
printed that scenario and really recorded it passing. So every control below
copies a REAL sealed cucumber bundle AND the sealed leaf bundle(s) it derives
from into a temp tree, applies exactly ONE mutation, and runs
tools/qualification/verify_cucumber_leaf.py as a REAL SUBPROCESS against the
copy, requiring a nonzero exit that names the defect.

Every mutation is applied the way a DILIGENT FORGER would. After tampering,
the harness regenerates every SHALLOWER binding: the source leaf bundle's
per-target log_sha256, its sidecar manifest, its verdict root and its
COMPLETE seal; then the cucumber bundle's per-log and per-leaf log_sha256,
its manifest, its verdict and its COMPLETE seal. Each control therefore
proves the DEEPEST remaining binding catches the edit, not that a stale hash
was noticed. Control 0 checks the clean copy is ACCEPTED - rejections prove
nothing if everything is rejected - and control T asserts a positive property
of the real archive rather than a rejection.

Controls, and the defect each one is:

  0   an intact copy verifies                        (control of controls)
  T   the torn-line scenario IS covered              (positive property)
  1   a scenario deleted from a log
  2   an outcome flipped in the JSON, log untouched
  2b  a log whose cucumber summary reports a failure, published anyway
  3   a scenario bound to the wrong plan row (two leaves swapped)
  4   an example index off by one (a template's example bindings rotated,
      with display name, leaf id, anchor and runtime name all forged to match)
  4b  two examples whose substituted names are IDENTICAL, swapped - 224 such
      groups exist in this corpus, one of them 9 examples wide, so this is the
      common case and not a corner: every byte-level readback still succeeds
      and only the ordinal binding can catch it
  5   a per-template reconciliation that disagrees with the catalogue
  5b  one example's leaf row dropped (a template whose runtime count no longer
      matches the examples the catalogue declares)
  6   a FILTERED run presented as a full enumeration
  7   an empty log
  8   a truncated log (its tail, summary included, removed)
  9   a tag-excluded scenario published as covered
  10  the not_run list suppressed, so unrun scenarios look absent
  11  a COMPLETE marker sealing a root the bytes do not recompute to
  12  a deleted log
  13  a source leaf bundle that is no longer sealed
  14  a publishable log silently withheld, hiding a whole feature
  15  a log repointed outside the sealed bundle that vouches for it
  16  leaf_coverage.py counts ZERO cucumber rows from a refused bundle

Usage: python3 tools/qualification/cucumber_mutants.py [--bundle DIR]
"""

import argparse
import atexit
import collections
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "tools" / "catalog"))
import common  # noqa: E402
import leaf_common as lc  # noqa: E402
import cucumber_common as cc  # noqa: E402

VERIFIER = HERE / "verify_cucumber_leaf.py"
COVERAGE = HERE / "leaf_coverage.py"

failures, checks = [], 0
na: list[str] = []


def expect(label, ok, detail="", verb=("KILLED", "SURVIVED")):
    global checks
    checks += 1
    if not ok:
        failures.append(label)
    print(f"  {verb[0] if ok else verb[1]}  {label}")
    if not ok and detail:
        print(f"      {detail}", file=sys.stderr)


def not_applicable(label, detail=""):
    """R8-P2-02: a control with no positive subject IN THIS DATA.

    Distinct from SURVIVED, and distinct from held. The round-8 audit found
    control T reported as missing/survived on `cucumber-u2-3` simply because
    that bundle happens to contain no torn line — a data-dependent verdict
    dressed as a semantic one, which is neither "the verifier accepts a
    forgery" nor "the verifier is proved". It is counted separately, never
    toward "all controls held", and the semantic property it exists for is
    proved by a DETERMINISTIC synthetic subject instead.
    """
    na.append(label)
    print(f"  N/A      {label}")
    if detail:
        print(f"      {detail}")


class Copy:
    """A mutable copy of a real cucumber bundle and its sealed sources, laid
    out at the same repo-relative paths so every `raw_log` resolves under
    --repo TREE and nothing can reach the real archive."""

    def __init__(self, src_rel):
        self.tree = pathlib.Path(tempfile.mkdtemp(prefix="cuke-mutant-"))
        atexit.register(shutil.rmtree, self.tree, True)
        self.rel = pathlib.Path(src_rel)
        self.dir = self._clone(self.rel)
        bundle = self.load()
        self.sources = [pathlib.Path(s["bundle"]) for s in bundle["sources"]]
        for s in self.sources:
            self._clone(s)

    def _clone(self, rel):
        dst = self.tree / rel
        dst.mkdir(parents=True, exist_ok=True)
        for f in (REPO / rel).iterdir():
            if f.is_file():
                shutil.copy2(f, dst / f.name)
        return dst

    def load(self):
        return json.loads((self.dir / cc.RESULTS_NAME).read_text())

    def save(self, bundle):
        (self.dir / cc.RESULTS_NAME).write_text(json.dumps(bundle, indent=1) + "\n")

    def owner_log(self, bundle=None, min_leaves=5):
        """The raw_log of an owning log with enough leaves to mutate."""
        bundle = bundle if bundle is not None else self.load()
        n = collections.Counter(leaf["raw_log"] for leaf in bundle["leaves"])
        for raw, k in n.most_common():
            if k >= min_leaves:
                return raw
        raise SystemExit("no owning log with enough leaves to mutate")

    def reseal_sources(self):
        """Everything a forger fixes inside each sealed LEAF bundle after
        touching one of its logs: every row's log_sha256, the sidecar
        manifest, the verdict's root and the COMPLETE marker."""
        for rel in self.sources:
            d = self.tree / rel
            rf = d / lc.RESULTS_NAME
            b = json.loads(rf.read_text())
            for t in b.get("targets", []):
                p = self.tree / t["raw_log"]
                if p.is_file():
                    t["log_sha256"] = common.sha256_file(p)
            by_log = {t["raw_log"]: t["log_sha256"] for t in b.get("targets", [])}
            for lf in b.get("leaves", []):
                if lf["raw_log"] in by_log:
                    lf["log_sha256"] = by_log[lf["raw_log"]]
            rf.write_text(json.dumps(b, indent=1) + "\n")
            root, pairs = lc.compute_bundle_root(d, b, self.tree)
            (d / "bundle-manifest.json").write_text(
                json.dumps({"bundle_root": root, "files": pairs}, indent=1) + "\n"
            )
            vf = d / "leaf-verdict.json"
            if vf.is_file():
                v = json.loads(vf.read_text())
                v["bundle_root"] = root
                vf.write_text(json.dumps(v, indent=1) + "\n")
            (d / "COMPLETE").write_text(f"COMPLETE {root}\n")

    def refresh(self, bundle=None, reseal_sources=True):
        bundle = bundle if bundle is not None else self.load()
        if reseal_sources:
            self.reseal_sources()
        shas = {}
        for s in bundle.get("sources", []):
            for lg in s.get("logs", []):
                p = self.tree / lg["raw_log"]
                if p.is_file():
                    shas[lg["raw_log"]] = common.sha256_file(p)
                    lg["log_sha256"] = shas[lg["raw_log"]]
                    if "log_sha256_recomputed" in lg:
                        lg["log_sha256_recomputed"] = shas[lg["raw_log"]]
        for lf in bundle.get("leaves", []):
            if lf["raw_log"] in shas:
                lf["log_sha256"] = shas[lf["raw_log"]]
        self.save(bundle)
        root, pairs = cc.compute_bundle_root(self.dir, bundle, self.tree)
        (self.dir / cc.MANIFEST_NAME).write_text(
            json.dumps({"bundle_root": root, "files": pairs}, indent=1) + "\n"
        )
        vf = self.dir / cc.VERDICT_NAME
        if vf.is_file():
            v = json.loads(vf.read_text())
            v["bundle_root"] = root
            obs = v.setdefault("observation", {})
            obs["leaves"] = len(bundle.get("leaves") or [])
            obs["scenarios_not_run"] = len(bundle.get("not_run") or [])
            vf.write_text(json.dumps(v, indent=1) + "\n")
        (self.dir / "COMPLETE").write_text(f"COMPLETE {root}\n")
        return root

    def verify(self, extra=()):
        p = subprocess.run(
            [sys.executable, str(VERIFIER), str(self.dir), "--repo", str(self.tree), *extra],
            capture_output=True,
            text=True,
        )
        return p.returncode, p.stdout + p.stderr

    def coverage(self):
        p = subprocess.run(
            [sys.executable, str(COVERAGE), "--cucumber", str(self.dir), "--repo", str(self.tree)],
            capture_output=True,
            text=True,
        )
        return p.returncode, p.stdout + p.stderr


def control(label, src, mutate, needle=None, extra=(), expect_ok=False):
    c = Copy(src)
    if mutate:
        mutate(c)
    rc, out = c.verify(extra)
    ok = (rc == 0) if expect_ok else (rc != 0 and (needle is None or needle in out))
    expect(
        label,
        ok,
        detail=f"rc={rc} tail: {out[-1200:]}",
        verb=("ACCEPTED", "WRONGLY REFUSED") if expect_ok else ("KILLED", "SURVIVED"),
    )
    return c


# ------------------------------------------------------------- mutations


def _log_lines(c, raw):
    return (c.tree / raw).read_text(errors="replace").splitlines()


def _write_log(c, raw, lines):
    (c.tree / raw).write_text("\n".join(lines) + "\n")


def fuse_feature_marker(c):
    """R8-P2-02: build the torn-line shape deterministically, from real bytes.

    Concurrent libtest writers interleave: one thread's `Feature: <title> ::
    <scenario>` announcement lands appended to another thread's partial line,
    so the marker sits at a column > 1. The scanner is written to accept the
    marker anywhere in a line for exactly that reason, and control Ts proves it
    — by taking a leaf whose marker IS at column 1, prefixing its line with a
    realistic fragment of another writer's output, and moving the leaf's
    recorded column to match.

    Nothing else changes: same scenario, same log, same outcome. If the scanner
    only ever looked at column 1, this bundle would stop verifying.
    """
    b = c.load()
    victim = next((leaf for leaf in b["leaves"] if leaf.get("log_column") == 1), None)
    if victim is None:
        raise SystemExit("no column-1 leaf to fuse — control Ts has no subject to build from")
    raw = victim["raw_log"]
    lines = _log_lines(c, raw)
    n = victim["log_line"]
    # a real fragment of another writer's line, chosen to contain no
    # `Feature: ` marker of its own
    prefix = "test integration::concurrent::other_writer ... "
    lines[n - 1] = prefix + lines[n - 1]
    _write_log(c, raw, lines)
    # every leaf pointing at THIS line moves with it; leaves on other lines of
    # the same log are untouched, which is what makes this one edit
    for leaf in b["leaves"]:
        if leaf["raw_log"] == raw and leaf["log_line"] == n:
            leaf["log_column"] = leaf["log_column"] + len(prefix)
    c.refresh(b)


def delete_scenario(c):
    b = c.load()
    raw = c.owner_log(b)
    victim = next(leaf for leaf in b["leaves"] if leaf["raw_log"] == raw)
    lines = _log_lines(c, raw)
    del lines[victim["log_line"] - 1]
    _write_log(c, raw, lines)
    b["leaves"] = [leaf for leaf in b["leaves"] if leaf is not victim]
    # the forger renumbers everything the deletion shifted and corrects the
    # scan count, so only the runtime's OWN tally and the P3 sequence remain
    for leaf in b["leaves"]:
        if leaf["raw_log"] == raw and leaf["log_line"] > victim["log_line"]:
            leaf["log_line"] -= 1
    for s in b["sources"]:
        for lg in s["logs"]:
            if lg["raw_log"] == raw:
                lg["scanned_scenarios"] -= 1
    # a diligent forger also renumbers the SEALED source bundle's own libtest
    # leaf rows, so that bundle still re-verifies and the only thing left to
    # catch the edit is the cucumber runtime's own scenario tally
    for rel in c.sources:
        rf = c.tree / rel / lc.RESULTS_NAME
        sb = json.loads(rf.read_text())
        for lf in sb.get("leaves", []):
            if lf["raw_log"] == raw:
                for k in ("log_line", "outcome_line"):
                    if lf.get(k, 0) > victim["log_line"]:
                        lf[k] -= 1
        rf.write_text(json.dumps(sb, indent=1) + "\n")
    for f in b["features"]:
        if (f.get("owner") or {}).get("raw_log") == raw:
            f["leaves_published"] -= 1
    c.refresh(b)


def flip_outcome(c):
    b = c.load()
    b["leaves"][0]["outcome"] = "FAILED"
    c.refresh(b)


def summary_reports_failure(c):
    b = c.load()
    raw = c.owner_log(b)
    lines = _log_lines(c, raw)
    for i, line in enumerate(lines):
        if line.strip() == "[Summary]":
            m = lines[i + 2].strip()
            n = int(m.split()[0])
            lines[i + 2] = f"{n} scenarios ({n - 1} passed, 1 failed)"
            break
    _write_log(c, raw, lines)
    c.refresh(b)


def swap_two_leaves(c):
    b = c.load()
    raw = c.owner_log(b)
    same = [leaf for leaf in b["leaves"] if leaf["raw_log"] == raw]
    a, d = same[0], same[1]
    for k in (
        "leaf_case_id",
        "display_name",
        "runtime_name",
        "template",
        "example_index",
        "example_total",
        "anchor",
        "declaration_line",
        "scenario_ordinal_in_feature",
    ):
        a[k], d[k] = d[k], a[k]
    c.refresh(b)


def rotate_example_indices(c):
    """An off-by-one in the example binding, forged as thoroughly as possible:
    a template's example rows are rotated by one across its leaf rows, with
    leaf id, display name, anchor, example index AND the runtime name all
    rewritten to the rotated example - only the log line stays put."""
    b = c.load()
    groups = collections.defaultdict(list)
    for leaf in b["leaves"]:
        if leaf["template"]:
            groups[(leaf["target_id"], leaf["template"], leaf["declaration_line"])].append(leaf)
    key = next(k for k, v in sorted(groups.items()) if len(v) >= 3)
    g = sorted(groups[key], key=lambda leaf: leaf["example_index"])
    fields = ("leaf_case_id", "display_name", "runtime_name", "example_index", "anchor")
    vals = [{k: leaf[k] for k in fields} for leaf in g]
    for i, leaf in enumerate(g):
        for k in fields:
            leaf[k] = vals[(i + 1) % len(vals)][k]
    c.refresh(b)


def swap_identical_names(c):
    """The ONE mutation a name-based join can never catch: two examples of the
    same template whose substituted names are IDENTICAL, with their leaf ids,
    example indices and anchors exchanged. Every byte-level readback still
    succeeds - the two log lines are character-for-character the same - so only
    the ORDINAL binding (the i-th runtime scenario is example i) is left."""
    b = c.load()
    g = collections.defaultdict(list)
    for leaf in b["leaves"]:
        if leaf["template"]:
            g[
                (
                    leaf["target_id"],
                    leaf["template"],
                    leaf["declaration_line"],
                    leaf["runtime_name"],
                )
            ].append(leaf)
    pair = next(v for _k, v in sorted(g.items()) if len(v) >= 2)[:2]
    a, d = pair
    for k in ("leaf_case_id", "display_name", "example_index", "anchor"):
        a[k], d[k] = d[k], a[k]
    c.refresh(b)


def forge_template_counts(c):
    b = c.load()
    f = next(x for x in b["features"] if x["templates"])
    f["templates"][0]["catalogued_examples"] += 3
    f["templates"][0]["runtime_matched"] += 3
    f["templates"][0]["runnable_examples"] += 3
    c.refresh(b)


def drop_one_example(c):
    b = c.load()
    victim = next(leaf for leaf in b["leaves"] if leaf["template"])
    b["leaves"] = [leaf for leaf in b["leaves"] if leaf is not victim]
    for f in b["features"]:
        if f["target_id"] == victim["target_id"]:
            f["leaves_published"] -= 1
            for t in f["templates"]:
                if (
                    t["template"] == victim["template"]
                    and t["declaration_line"] == victim["declaration_line"]
                ):
                    t["catalogued_examples"] -= 1
                    t["runnable_examples"] -= 1
                    t["runtime_matched"] -= 1
                    t["example_indices_bound"] = [
                        i for i in t["example_indices_bound"] if i != victim["example_index"]
                    ]
    c.refresh(b)


def filtered_run(c):
    b = c.load()
    raw = c.owner_log(b)
    lines = _log_lines(c, raw)
    for i, line in enumerate(lines):
        if line.startswith("test result:"):
            lines[i] = line.replace("0 filtered out", "3 filtered out")
            break
    _write_log(c, raw, lines)
    # the forger also corrects the SEALED source bundle's recorded counts, so
    # the source still re-verifies and only this producer's own rule is left
    for rel in c.sources:
        rf = c.tree / rel / lc.RESULTS_NAME
        sb = json.loads(rf.read_text())
        for t in sb["targets"]:
            if t["raw_log"] == raw:
                t["counts"]["filtered_out"] = 3
        rf.write_text(json.dumps(sb, indent=1) + "\n")
    c.refresh(b)


def empty_log(c):
    b = c.load()
    (c.tree / c.owner_log(b)).write_bytes(b"")
    c.refresh(b)


def truncate_log(c):
    b = c.load()
    raw = c.owner_log(b)
    lines = _log_lines(c, raw)
    _write_log(c, raw, lines[: len(lines) // 2])
    c.refresh(b)


def publish_ignored(c):
    b = c.load()
    victim = b["not_run"][0]
    donor = next(leaf for leaf in b["leaves"] if leaf["target_id"] == victim["target_id"])
    new = dict(donor)
    new.update({"leaf_case_id": victim["leaf_case_id"], "display_name": victim["display_name"]})
    b["leaves"].append(new)
    b["not_run"] = [x for x in b["not_run"] if x is not victim]
    c.refresh(b)


def suppress_not_run(c):
    b = c.load()
    b["not_run"] = []
    for f in b["features"]:
        f["not_run"] = 0
    c.refresh(b)


def delete_log(c):
    b = c.load()
    raw = c.owner_log(b)
    (c.tree / raw).unlink()
    c.refresh(b)


def unseal_source(c):
    b = c.load()
    (c.tree / b["sources"][0]["bundle"] / "COMPLETE").write_text("COMPLETE " + "0" * 64 + "\n")
    # deliberately NOT resealing the sources: that is the mutation
    c.refresh(b, reseal_sources=False)


def withhold_log(c):
    b = c.load()
    raw = c.owner_log(b)
    for s in b["sources"]:
        for lg in s["logs"]:
            if lg["raw_log"] == raw:
                lg["publishable"] = False
                lg["refusals"] = ["withheld"]
    b["leaves"] = [leaf for leaf in b["leaves"] if leaf["raw_log"] != raw]
    for f in b["features"]:
        if (f.get("owner") or {}).get("raw_log") == raw:
            f["owner"], f["leaves_published"], f["templates"] = None, 0, []
    c.refresh(b)


def log_outside_bundle(c):
    b = c.load()
    raw = c.owner_log(b)
    outside = pathlib.Path("docs/evidence/G3/leaf/elsewhere") / pathlib.Path(raw).name
    (c.tree / outside).parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(c.tree / raw, c.tree / outside)
    for s in b["sources"]:
        for lg in s["logs"]:
            if lg["raw_log"] == raw:
                lg["raw_log"] = str(outside)
    for leaf in b["leaves"]:
        if leaf["raw_log"] == raw:
            leaf["raw_log"] = str(outside)
    c.refresh(b)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--bundle",
        default="docs/evidence/G3/leaf/cucumber-u2-1",
        help="a real sealed cucumber leaf bundle (repo-relative)",
    )
    args = ap.parse_args()
    src = args.bundle
    if not (REPO / src / cc.RESULTS_NAME).is_file():
        sys.exit(
            f"{src} is not a cucumber leaf bundle - the controls mutate "
            f"REAL evidence copies, never a fixture invented for the test"
        )
    print(
        f"cucumber mutants (REAL subprocess: verify_cucumber_leaf.py over a "
        f"mutated COPY of {src} and its sealed sources)"
    )

    control("0  intact bundle copy verifies (control of controls)", src, None, expect_ok=True)

    # T ------------------------------------------- positive property control
    #
    # R8-P2-02: this is now TWO controls, because the audited single one
    # conflated a semantic property with a property of one bundle's bytes.
    #
    #   Ts  the SEMANTIC control. A deterministic synthetic subject is built
    #       from real sealed bytes — one scenario's `Feature:` marker is FUSED
    #       into another writer's line, exactly the shape concurrent libtest
    #       output produces — and the verifier must still VERIFY, i.e. the
    #       scanner must still find that scenario at its non-1 column. It has
    #       a positive subject by construction, in every bundle, forever.
    #   Tr  the DATA control. Does the real bundle under test happen to carry
    #       a torn line? Informative, N/A when it does not, and never counted
    #       toward "all controls held".
    control(
        "Ts a scenario whose 'Feature:' marker is FUSED into another writer's "
        "line (deterministic synthetic subject) is still found and covered",
        src,
        fuse_feature_marker,
        expect_ok=True,
    )

    b = json.loads((REPO / src / cc.RESULTS_NAME).read_text())
    torn = [leaf for leaf in b["leaves"] if leaf["log_column"] > 1]
    label = (
        f"Tr the REAL archive {src} carries a torn 'Feature:' line "
        f"({len(torn)} such leaf/leaves"
        + (
            f", e.g. {torn[0]['raw_log'].rsplit('/', 1)[-1]}:{torn[0]['log_line']} "
            f"col {torn[0]['log_column']})"
            if torn
            else ")"
        )
    )
    if torn:
        expect(label, True, verb=("HOLDS", "MISSING"))
    else:
        not_applicable(
            label,
            detail="this bundle's runtime happened not to interleave; the SEMANTIC property "
            "is proved by control Ts against a synthetic subject, which is why that control "
            "exists (R8-P2-02).",
        )

    control(
        "1  a scenario deleted from a log (the forger renumbers the source "
        "bundle's own leaf rows too)",
        src,
        delete_scenario,
        needle="summaries count",
    )
    control(
        "2  an outcome flipped in the JSON, log untouched",
        src,
        flip_outcome,
        needle="ALL_PASSED_SUMMARY is the only derivation",
    )
    control(
        "2b a log whose cucumber summary reports a failure, published anyway",
        src,
        summary_reports_failure,
        needle="not all-passed",
    )
    control(
        "3  a scenario bound to the wrong plan row (two leaves swapped)",
        src,
        swap_two_leaves,
        needle="do not say what it claims",
    )
    control(
        "4  an example index off by one (a template's bindings rotated, "
        "leaf id / display name / anchor / runtime name all forged)",
        src,
        rotate_example_indices,
        needle="the row points at bytes that do not say what it claims",
    )
    control(
        "4b two examples with IDENTICAL substituted names swapped - every "
        "byte readback still succeeds, so ONLY the ordinal binding can "
        "catch it",
        src,
        swap_identical_names,
        needle="ordinal binding is wrong",
    )
    control(
        "5  a per-template reconciliation that disagrees with the catalogue",
        src,
        forge_template_counts,
        needle="the expansion and the log give",
    )
    control(
        "5b one example's leaf row dropped (template runtime count no "
        "longer matches the catalogue's examples)",
        src,
        drop_one_example,
        needle="have no leaf row",
    )
    control(
        "6  a FILTERED run presented as a full enumeration",
        src,
        filtered_run,
        needle="filtered_out=3",
    )
    control("7  an empty log", src, empty_log, needle="no libtest 'test result:'")
    control(
        "8  a truncated log (tail and summary removed)",
        src,
        truncate_log,
        needle="marked publishable but re-derivation refuses it",
    )
    control(
        "9  a tag-excluded scenario published as covered",
        src,
        publish_ignored,
        needle="yet the bundle publishes an outcome for it",
    )
    control("10 the not_run list suppressed", src, suppress_not_run, needle="absent from not_run")
    control(
        "11 COMPLETE sealing a root the bytes do not recompute to",
        src,
        lambda c: (c.dir / "COMPLETE").write_text("COMPLETE " + "0" * 64 + "\n"),
        needle="the archive was modified after it was sealed",
    )
    control("12 a deleted log", src, delete_log, needle="named as publishable")
    control(
        "13 a source leaf bundle that is no longer sealed",
        src,
        unseal_source,
        needle="does not re-verify",
    )
    control(
        "14 a publishable log silently withheld, hiding a whole feature",
        src,
        withhold_log,
        needle="silently withheld log hides evidence",
    )
    control(
        "15 a log repointed outside the sealed bundle that vouches for it",
        src,
        log_outside_bundle,
        needle="reads a log the sealed source bundle",
    )

    # 16 ------------------ the coverage reporter counts nothing from a refusal
    def cuke_covered(report):
        return report["by_family"].get("cucumber", {}).get("COVERED", 0)

    c = Copy(src)
    _rc0, out0 = c.coverage()
    clean = json.loads(out0[out0.index("{") : out0.rindex("}") + 1])
    c2 = Copy(src)
    flip_outcome(c2)
    _rc1, out1 = c2.coverage()
    mutated = json.loads(out1[out1.index("{") : out1.rindex("}") + 1])
    expect(
        f"16 leaf_coverage counts 0 cucumber rows from a refused bundle "
        f"(the same bundle intact covers {cuke_covered(clean)})",
        cuke_covered(clean) > 0
        and cuke_covered(mutated) == 0
        and mutated["cucumber_leaf_bundles"][0]["anomalies"],
        detail=f"intact={cuke_covered(clean)} mutated={cuke_covered(mutated)}",
    )

    # R8-P2-02: N/A is reported separately and never counted as held. A suite
    # that says "21/21 held" while one of them had nothing to act on is making
    # a claim about proof it did not obtain.
    print(
        f"\n{checks - len(failures)}/{checks} controls held ({len(failures)} SURVIVED"
        + (f", {len(na)} NOT APPLICABLE to this bundle's data" if na else "")
        + ")"
    )
    for f in failures:
        print(f"SURVIVED: {f}", file=sys.stderr)
    for label in na:
        print(f"NOT APPLICABLE: {label}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
