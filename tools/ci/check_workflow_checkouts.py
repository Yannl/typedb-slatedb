#!/usr/bin/env python3
"""Every `actions/checkout` must drop its credentials (spec §19).

WHY THIS EXISTS RATHER THAN RELYING ON ZIZMOR.

The round-6 CI hardening fixed two checkouts that were leaving the job's
GitHub token persisted in `.git/config` (zizmor's `artipacked`), and the
zizmor job was believed to protect that fix. It does not. Measured:

    persist-credentials flipped to true, one checkout
      zizmor --persona=auditor   -> artipacked fires (2 hits)
      zizmor --persona=pedantic  -> 0
      zizmor --persona=regular   -> 0     <- the persona the gate runs at

At the gate's persona the finding is counted as "suppressed", so a
regression would have gone through green. Raising the whole gate to
`auditor` is not the answer either: the clean tree produces 52 findings
there (46 informational, 4 low), so the gate would either be red forever
or acquire a severity floor -- and a floor silently swallows unrelated
future findings, which is the failure mode this repository keeps refusing.

So the specific invariant gets its own exact, fail-closed check. zizmor
keeps its job for everything else.

Exceptions must be declared below with a reason. There are none today, and
"the job pushes" is the only reason that could ever be legitimate.

usage:
  python3 tools/ci/check_workflow_checkouts.py
  python3 tools/ci/check_workflow_checkouts.py --self-test
"""

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
WORKFLOWS = REPO / ".github" / "workflows"

# key: "<file>:<job>" -> reason. A job that genuinely needs to push may live
# here; nothing else may. Wildcards are deliberately not supported.
CREDENTIALED_CHECKOUT_ALLOWLIST: dict[str, str] = {}

CHECKOUT = re.compile(r"uses:\s*actions/checkout@")
PERSIST = re.compile(r"^\s*persist-credentials:\s*(\S+)")
JOB = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")


def audit(text: str, path_label: str) -> list[str]:
    """Return one problem string per offending checkout.

    Deliberately line-based rather than YAML-object-based: the property is
    about the `with:` block that FOLLOWS a checkout step, and a line scan
    reports the exact line a human has to go fix.
    """
    problems = []
    lines = text.splitlines()
    job = "(top level)"
    for i, line in enumerate(lines):
        m = JOB.match(line)
        if m:
            job = m.group(1)
        if not CHECKOUT.search(line):
            continue
        indent = len(line) - len(line.lstrip())
        # scan the step's own block only: stop at the next line that starts a
        # sibling or shallower element
        persisted = None
        for nxt in lines[i + 1 :]:
            if not nxt.strip():
                continue
            nindent = len(nxt) - len(nxt.lstrip())
            if nindent <= indent and nxt.lstrip().startswith("- "):
                break
            if nindent < indent:
                break
            pm = PERSIST.match(nxt)
            if pm:
                persisted = pm.group(1)
                break
        key = f"{path_label}:{job}"
        if persisted == "false":
            continue
        if key in CREDENTIALED_CHECKOUT_ALLOWLIST:
            continue
        where = f"{path_label}:{i + 1} (job `{job}`)"
        if persisted is None:
            problems.append(
                f"{where}: actions/checkout does not set "
                "`persist-credentials: false`, so the job's token is written "
                "into .git/config and is readable by anything that runs after"
            )
        else:
            problems.append(f"{where}: actions/checkout sets `persist-credentials: {persisted}`")
    return problems


def self_test() -> int:
    """The check must fail on the thing it exists to catch."""
    cases = [
        (
            "guarded",
            """jobs:
  a:
    steps:
      - uses: actions/checkout@abc # v4
        with:
          persist-credentials: false
""",
            0,
        ),
        (
            "absent",
            """jobs:
  a:
    steps:
      - uses: actions/checkout@abc # v4
""",
            1,
        ),
        (
            "explicit true",
            """jobs:
  a:
    steps:
      - uses: actions/checkout@abc # v4
        with:
          persist-credentials: true
""",
            1,
        ),
        (
            "guarded then unguarded",
            """jobs:
  a:
    steps:
      - uses: actions/checkout@abc # v4
        with:
          persist-credentials: false
  b:
    steps:
      - uses: actions/checkout@abc # v4
        with:
          fetch-depth: 0
""",
            1,
        ),
    ]
    failures = []
    for name, text, want in cases:
        got = len(audit(text, "synthetic.yml"))
        ok = got == want
        print(f"  {'ok  ' if ok else 'FAIL'} {name}: {got} problem(s), want {want}")
        if not ok:
            failures.append(name)
    print(
        f"checkout-credential self-test: {len(cases) - len(failures)}/{len(cases)} "
        f"cases behaved as specified"
    )
    return 1 if failures else 0


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        return self_test()
    if not WORKFLOWS.is_dir():
        print(f"REFUSED: {WORKFLOWS} does not exist", file=sys.stderr)
        return 2
    problems, checked = [], 0
    for path in sorted(WORKFLOWS.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        checked += len(CHECKOUT.findall(text))
        problems += audit(text, path.name)
    for p in problems:
        print(f"  {p}")
    if problems:
        print(
            f"CHECKOUT CREDENTIAL GATE: FAIL ({len(problems)} of {checked} "
            "checkout step(s) keep their token)"
        )
        return 1
    print(
        f"CHECKOUT CREDENTIAL GATE: PASS ({checked} checkout step(s), all "
        f"persist-credentials: false, {len(CREDENTIALED_CHECKOUT_ALLOWLIST)} "
        "declared exception(s))"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
