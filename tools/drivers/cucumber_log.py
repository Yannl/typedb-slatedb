#!/usr/bin/env python3
"""Leaf-level parser for the official Rust driver behaviour suite's output.

The upstream suite (`Context::test` in
sources/typedb-driver/rust/tests/behaviour/steps/lib.rs) is ONE libtest case
per feature file. Its libtest summary line is therefore worthless as
qualification evidence: `1 passed` says nothing about which of the file's 43
scenarios ran. The per-scenario truth is in the cucumber `writer::Basic`
stream the suite prints, and this module extracts it.

Output shape (SingletonParser wraps every scenario in its own Feature):

    Feature: <feature name> :: <scenario display name>
      Scenario[ Outline]: <scenario display name>
       ✔  Given ...          passed step
       ✔> Given ...          passed BACKGROUND step
       ✘  When ...           failed step
       ✘> When ...           failed background step
       ?  Then ...           skipped step
       ✘  Scenario's before hook failed <path>:<line>:<col>
    [Summary]
    N features
    M scenarios (a passed, b skipped, c failed)[ with r retries]
    S steps (...)
    [P parsing errors][, ][H hook errors]

Everything this parser returns is derived from those bytes. It NEVER invents
an outcome: a scenario block with no step lines at all is `EMPTY`, not
`PASSED`, and the caller must treat `EMPTY` as a hard anomaly.

Self-checks the caller is expected to enforce (see run_rust_behaviour.py):
  * len(primary scenarios) == the summary's feature and scenario totals;
  * the passed/failed/skipped tally re-derived per scenario == the summary's;
  * the observed display-name SEQUENCE == the sequence gherkin_leaves.py
    derives from the feature file.
Any disagreement means the log and the run do not describe the same thing,
which is exactly the forgery/truncation class this lane must refuse.
"""

import re

FEATURE_RE = re.compile(r"^Feature: (.*?) :: (.*)$")
SCENARIO_RE = re.compile(r"^ {2}(Scenario Outline|Scenario Template|Scenario|Example): (.*)$")
STEP_RE = re.compile(r"^ {3}(✔>|✔|✘>|✘|\?>|\?)\s")
HOOK_FAIL_RE = re.compile(r"^\s*✘\s+Scenario's (before|after) hook failed")
SUMMARY_RE = re.compile(r"^\[Summary\]\s*$")
LIBTEST_RESULT_RE = re.compile(
    r"^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
    r"(\d+) measured; (\d+) filtered out"
)

PASSED, FAILED, SKIPPED, EMPTY = "PASSED", "FAILED", "SKIPPED", "EMPTY"


class CucumberLogError(Exception):
    pass


def _strip_ansi(text):
    return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)


def parse(text):
    """-> dict with keys: scenarios, repeat_scenarios, summary, libtest,
    saw_summary. `scenarios` is the PRIMARY (pre-[Summary]) sequence."""
    text = _strip_ansi(text)
    lines = text.splitlines()

    summary_at = None
    for i, ln in enumerate(lines):
        if SUMMARY_RE.match(ln):
            summary_at = i
            break

    primary = _scan_blocks(lines[:summary_at] if summary_at is not None else lines)
    repeat = _scan_blocks(lines[summary_at:]) if summary_at is not None else []

    summary = _parse_summary(lines[summary_at:]) if summary_at is not None else None
    libtest = None
    for ln in lines:
        m = LIBTEST_RESULT_RE.match(ln)
        if m:
            libtest = {
                "outcome": m.group(1),
                "passed": int(m.group(2)),
                "failed": int(m.group(3)),
                "ignored": int(m.group(4)),
                "measured": int(m.group(5)),
                "filtered_out": int(m.group(6)),
            }
    return {
        "scenarios": primary,
        "repeat_scenarios": repeat,
        "summary": summary,
        "libtest": libtest,
        "saw_summary": summary_at is not None,
    }


def _scan_blocks(lines):
    blocks = []
    cur = None
    for idx, ln in enumerate(lines):
        mf = FEATURE_RE.match(ln)
        if mf:
            if cur is not None:
                blocks.append(_finish(cur))
            cur = {
                "feature_name": mf.group(1),
                "feature_scenario": mf.group(2),
                "scenario_keyword": None,
                "scenario_name": None,
                "steps": [],
                "hook_failed": False,
                "line_index": idx,
            }
            continue
        if cur is None:
            continue
        ms = SCENARIO_RE.match(ln)
        if ms:
            if cur["scenario_name"] is not None:
                raise CucumberLogError(
                    f"line {idx + 1}: a second Scenario line inside one "
                    f"SingletonParser feature block ({cur['feature_scenario']!r}); "
                    f"the log does not have the shape this lane executes"
                )
            cur["scenario_keyword"], cur["scenario_name"] = ms.group(1), ms.group(2)
            continue
        if HOOK_FAIL_RE.match(ln):
            cur["hook_failed"] = True
            continue
        mst = STEP_RE.match(ln)
        if mst:
            cur["steps"].append(mst.group(1))
    if cur is not None:
        blocks.append(_finish(cur))
    return blocks


def _finish(b):
    marks = b["steps"]
    passed = sum(1 for m in marks if m.startswith("✔"))
    failed = sum(1 for m in marks if m.startswith("✘"))
    skipped = sum(1 for m in marks if m.startswith("?"))
    if b["hook_failed"] or failed:
        status = FAILED
    elif skipped:
        status = SKIPPED
    elif passed:
        status = PASSED
    else:
        status = EMPTY
    b.update(
        {
            "steps_passed": passed,
            "steps_failed": failed,
            "steps_skipped": skipped,
            "status": status,
            "steps_total": len(marks),
        }
    )
    del b["steps"]
    return b


def _parse_summary(lines):
    out = {
        "features": None,
        "rules": None,
        "scenarios": None,
        "steps": None,
        "parsing_errors": 0,
        "hook_errors": 0,
        "raw": [],
    }
    stat_re = re.compile(
        r"^(\d+) (features?|rules?|scenarios?|steps?)"
        r"(?: \(([^)]*)\))?(?: with (\d+) retr(?:y|ies))?\s*$"
    )
    err_re = re.compile(r"(\d+) (parsing errors?|hook errors?)")
    for ln in lines[1:]:
        s = ln.strip()
        if not s:
            continue
        out["raw"].append(s)
        m = stat_re.match(s)
        if m:
            key = m.group(2).rstrip("s") if not m.group(2).endswith("ss") else m.group(2)
            key = {
                "feature": "features",
                "features": "features",
                "rule": "rules",
                "rules": "rules",
                "scenario": "scenarios",
                "scenarios": "scenarios",
                "step": "steps",
                "steps": "steps",
            }[m.group(2)]
            stats = {
                "total": int(m.group(1)),
                "passed": 0,
                "skipped": 0,
                "failed": 0,
                "retried": int(m.group(4) or 0),
            }
            for n, what in re.findall(r"(\d+) (passed|skipped|failed)", m.group(3) or ""):
                stats[what] = int(n)
            out[key] = stats
            continue
        for n, what in err_re.findall(s):
            out["parsing_errors" if what.startswith("parsing") else "hook_errors"] += int(n)
        if s.startswith("test result:") or s.startswith("test test"):
            continue
    return out
