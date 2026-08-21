#!/usr/bin/env python3
"""R6-SUPPLY-01 - the dependency-advisory gate.

`npm audit` on its own is not a gate: it prints a number that a human is
expected to look at. This tool turns that number into a fail-closed decision
against a machine-readable policy (tools/ci/dependency-advisory-policy.json):

  * every advisory the audit reports must have an UNEXPIRED exception row
    carrying advisory id, workspace, package, affected version range,
    reachability analysis, reason, compensating control, owner and expiry -
    otherwise the run FAILS as an unlisted (new) advisory;
  * an exception whose `expires` date has passed FAILS, even though the
    advisory itself is unchanged: a time-boxed acceptance that nobody
    re-reviewed is an expired decision, not a standing one;
  * an exception granted for longer than `policy.max_exception_days` FAILS at
    write time, so "expiry" cannot be defeated by setting it to 2099;
  * an exception that no longer matches any live advisory FAILS: the policy
    file must describe risk we actually carry, never risk we used to carry;
  * `--lockfile` additionally checks the supply-chain provenance floor - every
    resolved entry in package-lock.json must come from an allowed registry and
    carry an `integrity` digest, so an unpinned or unverifiable artifact cannot
    enter the tree unnoticed.

Modes
-----
    check_npm_advisories.py                       # audit every workspace
    check_npm_advisories.py --workspace stack     # one workspace
    check_npm_advisories.py --lockfile            # lockfile provenance only
    check_npm_advisories.py --audit-json F --workspace W
                                                  # decide over a captured
                                                  # `npm audit --json` document
                                                  # (no network)
    check_npm_advisories.py --self-test           # behavioral mutants

Exit codes: 0 PASS, 1 policy FAIL, 2 usage/IO error.
"""

from __future__ import annotations

import argparse
import copy
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import date, datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = REPO_ROOT / "tools" / "ci" / "dependency-advisory-policy.json"
SCHEMA = "typedb-r2/dependency-advisory-policy@1"

REQUIRED_EXCEPTION_FIELDS = (
    "advisory",
    "workspace",
    "package",
    "affected_versions",
    "severity",
    "reachability",
    "reason",
    "compensating_control",
    "owner",
    "expires",
)


class PolicyError(Exception):
    """A policy document that cannot be trusted to decide anything."""


# ---------------------------------------------------------------------------
# policy
# ---------------------------------------------------------------------------


def load_policy(path: Path) -> dict:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise PolicyError(f"policy file missing: {path}")
    except json.JSONDecodeError as exc:
        raise PolicyError(f"policy file is not valid JSON: {path}: {exc}")
    if doc.get("schema") != SCHEMA:
        raise PolicyError(f"policy schema must be {SCHEMA!r}, got {doc.get('schema')!r}")
    if not isinstance(doc.get("workspaces"), list) or not doc["workspaces"]:
        raise PolicyError("policy declares no workspaces")
    if not isinstance(doc.get("exceptions"), list):
        raise PolicyError("policy.exceptions must be a list (use [] for none)")
    pol = doc.get("policy")
    if not isinstance(pol, dict):
        raise PolicyError("policy.policy block missing")
    for key in ("max_exception_days", "stale_exception", "unlisted_advisory", "expired_exception"):
        if key not in pol:
            raise PolicyError(f"policy.policy.{key} missing")
    return doc


def parse_day(value: str, where: str) -> date:
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except (TypeError, ValueError):
        raise PolicyError(f"{where}: expiry must be an ISO 'YYYY-MM-DD' day, got {value!r}")


# ---------------------------------------------------------------------------
# npm audit
# ---------------------------------------------------------------------------


def run_npm_audit(workspace_dir: Path, audit_args: list[str]) -> dict:
    npm = shutil.which("npm")
    if npm is None:
        raise PolicyError("npm is not on PATH; cannot audit")
    proc = subprocess.run(
        [npm, "audit", "--json", *audit_args],
        cwd=str(workspace_dir),
        capture_output=True,
        text=True,
    )
    # npm audit exits nonzero WHEN it finds advisories; that is data, not failure.
    # A missing/garbled document, on the other hand, must never read as "clean".
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise PolicyError(
            f"`npm audit --json {' '.join(audit_args)}` in {workspace_dir} produced no parseable "
            f"JSON (exit {proc.returncode}). stderr:\n{proc.stderr.strip()[:2000]}"
        )


def advisories_from_audit(audit: dict) -> dict[str, dict]:
    """Flatten `npm audit --json` (v2/v3 shape) to {advisory_id: record}.

    npm reports two kinds of node: a package with its OWN advisories (`via`
    entries that are objects, each carrying a GHSA url) and a package that is
    only vulnerable because a dependency is (`via` entries that are strings).
    Only the first kind carries an advisory identity, so only the first kind
    can be excepted; the second kind clears automatically when its root does.
    """
    out: dict[str, dict] = {}
    vulns = audit.get("vulnerabilities")
    if not isinstance(vulns, dict):
        raise PolicyError(
            "audit document has no 'vulnerabilities' object - refusing to read it as clean"
        )
    for pkg_name, node in vulns.items():
        for via in node.get("via", []):
            if not isinstance(via, dict):
                continue  # transitive-only: no advisory identity of its own
            ident = via.get("url") or via.get("source")
            if ident is None:
                raise PolicyError(f"advisory on {pkg_name} carries neither url nor source: {via!r}")
            ident = str(ident).rstrip("/").split("/")[-1]
            out[ident] = {
                "advisory": ident,
                "package": via.get("name", pkg_name),
                "severity": via.get("severity", node.get("severity", "unknown")),
                "title": via.get("title", ""),
                "affected_versions": via.get("range", node.get("range", "")),
            }
    return out


def audit_totals(audit: dict) -> dict:
    meta = audit.get("metadata", {}).get("vulnerabilities", {})
    return {k: meta.get(k, 0) for k in ("info", "low", "moderate", "high", "critical", "total")}


# ---------------------------------------------------------------------------
# the decision
# ---------------------------------------------------------------------------


def evaluate_workspace(policy: dict, ws: dict, audit: dict, today: date) -> list[str]:
    failures: list[str] = []
    pol = policy["policy"]
    max_days = int(pol["max_exception_days"])
    live = advisories_from_audit(audit)
    exceptions = [e for e in policy["exceptions"] if e.get("workspace") == ws["id"]]

    seen: set[str] = set()
    for exc in exceptions:
        where = f"exception {exc.get('advisory', '<no id>')} ({ws['id']})"
        missing = [f for f in REQUIRED_EXCEPTION_FIELDS if not exc.get(f)]
        if missing:
            failures.append(f"{where}: missing required field(s): {', '.join(missing)}")
            continue
        ident = exc["advisory"]
        if ident in seen:
            failures.append(f"{where}: duplicate exception row for the same advisory")
            continue
        seen.add(ident)

        expires = parse_day(exc["expires"], where)
        if (expires - today).days > max_days:
            failures.append(
                f"{where}: expiry {expires.isoformat()} is {(expires - today).days} days out, "
                f"policy.max_exception_days is {max_days} - an unbounded acceptance is not an exception"
            )
        if expires < today and pol["expired_exception"] == "fail":
            failures.append(
                f"{where}: EXPIRED on {expires.isoformat()} (today {today.isoformat()}) - "
                f"re-review with {exc['owner']} and either remediate or re-date the row"
            )
        if ident not in live and pol["stale_exception"] == "fail":
            failures.append(
                f"{where}: STALE - no live advisory matches it any more; delete the row "
                f"(the policy file must state risk we carry, never risk we used to carry)"
            )

    if pol["unlisted_advisory"] == "fail":
        for ident, rec in sorted(live.items()):
            if ident not in seen:
                failures.append(
                    f"NEW ADVISORY with no exception ({ws['id']}): {ident} "
                    f"[{rec['severity']}] {rec['package']}@{rec['affected_versions']} - {rec['title']!r}. "
                    f"Remediate it, or add a reviewed, time-boxed row to "
                    f"tools/ci/dependency-advisory-policy.json"
                )
    return failures


# ---------------------------------------------------------------------------
# lockfile provenance
# ---------------------------------------------------------------------------


def check_lockfile(policy: dict, ws: dict, root: Path) -> list[str]:
    lock_path = root / ws["path"] / "package-lock.json"
    failures: list[str] = []
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return [
            f"{ws['id']}: package-lock.json is absent - an unlocked install has no supply-chain identity"
        ]
    except json.JSONDecodeError as exc:
        return [f"{ws['id']}: package-lock.json is not valid JSON: {exc}"]
    if lock.get("lockfileVersion", 0) < 3:
        failures.append(
            f"{ws['id']}: lockfileVersion {lock.get('lockfileVersion')} < 3 (no per-package integrity guarantees)"
        )
    allowed = tuple(policy["policy"]["allowed_registries"])
    for path, entry in sorted((lock.get("packages") or {}).items()):
        if path == "" or entry.get("link"):
            continue  # the workspace root / a local link has no registry identity
        resolved = entry.get("resolved")
        if resolved is None:
            failures.append(f"{ws['id']}: {path} has no `resolved` URL")
            continue
        if not resolved.startswith(allowed):
            failures.append(
                f"{ws['id']}: {path} resolves outside the allowed registries: {resolved}"
            )
        if not entry.get("integrity"):
            failures.append(f"{ws['id']}: {path} has no `integrity` digest ({resolved})")
    return failures


# ---------------------------------------------------------------------------
# self-test (behavioral mutants over the real decision function)
# ---------------------------------------------------------------------------


def _mutant_audit(advisories: list[tuple[str, str, str, str]]) -> dict:
    vulns = {}
    for ident, pkg, sev, rng in advisories:
        vulns[pkg] = {
            "severity": sev,
            "range": rng,
            "via": [
                {
                    "source": 0,
                    "name": pkg,
                    "url": f"https://github.com/advisories/{ident}",
                    "severity": sev,
                    "title": f"{pkg} synthetic",
                    "range": rng,
                }
            ],
        }
    return {"vulnerabilities": vulns, "metadata": {"vulnerabilities": {"total": len(advisories)}}}


def _base_policy() -> dict:
    return {
        "schema": SCHEMA,
        "document": "self-test fixture",
        "policy": {
            "max_exception_days": 90,
            "stale_exception": "fail",
            "unlisted_advisory": "fail",
            "expired_exception": "fail",
            "allowed_registries": ["https://registry.npmjs.org/"],
        },
        "workspaces": [{"id": "ws", "path": "ws", "audit_args": ["--omit=dev"]}],
        "exceptions": [],
    }


def _exception(ident: str, expires: str) -> dict:
    return {
        "advisory": ident,
        "workspace": "ws",
        "package": "leftpad",
        "affected_versions": "<1.0.0",
        "severity": "high",
        "reachability": "unreachable: the vulnerable entrypoint is never called by any command this repo runs",
        "reason": "self-test fixture",
        "compensating_control": "self-test fixture",
        "owner": "self-test",
        "expires": expires,
    }


def _lock_identity(doc: dict) -> dict:
    return doc


def _lock_drop_integrity(doc: dict) -> dict:
    doc["packages"]["node_modules/a"].pop("integrity")
    return doc


def _lock_foreign_registry(doc: dict) -> dict:
    doc["packages"]["node_modules/a"]["resolved"] = "https://evil.example/a.tgz"
    return doc


def _lock_version_2(doc: dict) -> dict:
    doc["lockfileVersion"] = 2
    return doc


def self_test() -> int:
    today = date(2026, 8, 20)
    live = _mutant_audit([("GHSA-aaaa-bbbb-cccc", "leftpad", "high", "<1.0.0")])
    # `expect` is None for a case that must be refused outright rather than
    # refused with a particular message in it.
    cases: list[tuple[str, dict, dict, str | None]] = []

    # 1. control: the exact live advisory has a valid, unexpired exception -> PASS
    pol = _base_policy()
    pol["exceptions"] = [_exception("GHSA-aaaa-bbbb-cccc", "2026-10-01")]
    cases.append(("CONTROL: live advisory with a valid unexpired exception passes", pol, live, ""))

    # 2. mutant: the exception expired yesterday
    pol = _base_policy()
    pol["exceptions"] = [_exception("GHSA-aaaa-bbbb-cccc", "2026-08-19")]
    cases.append(("MUTANT expired-exception", pol, live, "EXPIRED"))

    # 3. mutant: a new advisory nobody excepted
    pol = _base_policy()
    pol["exceptions"] = [_exception("GHSA-aaaa-bbbb-cccc", "2026-10-01")]
    two = _mutant_audit(
        [
            ("GHSA-aaaa-bbbb-cccc", "leftpad", "high", "<1.0.0"),
            ("GHSA-dddd-eeee-ffff", "rightpad", "critical", "*"),
        ]
    )
    cases.append(("MUTANT new-unlisted-advisory", pol, two, "NEW ADVISORY with no exception"))

    # 4. mutant: an exception that outlives the policy's maximum window
    pol = _base_policy()
    pol["exceptions"] = [_exception("GHSA-aaaa-bbbb-cccc", "2099-01-01")]
    cases.append(("MUTANT unbounded-expiry", pol, live, "policy.max_exception_days"))

    # 5. mutant: an exception for a risk that no longer exists
    pol = _base_policy()
    pol["exceptions"] = [
        _exception("GHSA-aaaa-bbbb-cccc", "2026-10-01"),
        _exception("GHSA-9999-9999-9999", "2026-10-01"),
    ]
    cases.append(("MUTANT stale-exception", pol, live, "STALE"))

    # 6. mutant: an exception missing its compensating control
    pol = _base_policy()
    broken = _exception("GHSA-aaaa-bbbb-cccc", "2026-10-01")
    broken["compensating_control"] = ""
    pol["exceptions"] = [broken]
    cases.append(
        ("MUTANT exception-without-compensating-control", pol, live, "missing required field")
    )

    # 7. mutant: an empty/garbled audit document must never read as clean
    pol = _base_policy()
    cases.append(("MUTANT audit-document-without-vulnerabilities-key", pol, {"metadata": {}}, None))

    failures = 0
    for name, pol, audit, expect in cases:
        try:
            found = evaluate_workspace(pol, pol["workspaces"][0], audit, today)
            err = None
        except PolicyError as exc:
            found, err = [], str(exc)
        if expect == "":
            ok = not found and err is None
            detail = f"expected PASS, got {found or err}"
        elif expect is None:
            ok = err is not None
            detail = f"expected a PolicyError, got failures={found}"
        else:
            ok = any(expect in f for f in found)
            detail = f"expected a failure containing {expect!r}, got {found or err}"
        print(f"  {'ok  ' if ok else 'FAIL'} {name}")
        if not ok:
            print(f"       {detail}")
            failures += 1

    # 8. lockfile provenance mutants, executed over real files on disk
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "ws").mkdir()
        good = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "x"},
                "node_modules/a": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
                    "integrity": "sha512-deadbeef",
                },
            },
        }
        pol = _base_policy()
        for name, mutate, expect in [
            ("CONTROL: registry-resolved, integrity-carrying lockfile passes", _lock_identity, ""),
            (
                "MUTANT lockfile-entry-without-integrity",
                _lock_drop_integrity,
                "no `integrity` digest",
            ),
            (
                "MUTANT lockfile-entry-from-a-foreign-registry",
                _lock_foreign_registry,
                "outside the allowed registries",
            ),
            ("MUTANT lockfile-version-2", _lock_version_2, "lockfileVersion 2"),
        ]:
            doc = mutate(copy.deepcopy(good))
            (root / "ws" / "package-lock.json").write_text(json.dumps(doc), encoding="utf-8")
            found = check_lockfile(pol, pol["workspaces"][0], root)
            ok = (not found) if expect == "" else any(expect in f for f in found)
            print(f"  {'ok  ' if ok else 'FAIL'} {name}")
            if not ok:
                print(f"       expected {expect!r}, got {found}")
                failures += 1

    print()
    if failures:
        print(f"advisory-policy self-test: {failures} case(s) FAILED")
        return 1
    print(f"advisory-policy self-test: all {len(cases) + 4} cases behaved as specified")
    return 0


# ---------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--policy", default=str(POLICY_PATH))
    ap.add_argument("--workspace", action="append", help="limit to this workspace id (repeatable)")
    ap.add_argument(
        "--audit-json",
        help="decide over a captured `npm audit --json` document instead of running npm",
    )
    ap.add_argument(
        "--lockfile", action="store_true", help="ALSO run the lockfile provenance check"
    )
    ap.add_argument(
        "--lockfile-only", action="store_true", help="run ONLY the lockfile provenance check"
    )
    ap.add_argument("--today", help="override today's date (YYYY-MM-DD) - for tests")
    ap.add_argument(
        "--self-test", action="store_true", help="run the checker's own behavioral mutants"
    )
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    try:
        policy = load_policy(Path(args.policy))
    except PolicyError as exc:
        print(f"POLICY ERROR: {exc}", file=sys.stderr)
        return 2

    today = parse_day(args.today, "--today") if args.today else datetime.now(timezone.utc).date()
    workspaces = policy["workspaces"]
    if args.workspace:
        known = {w["id"] for w in workspaces}
        unknown = set(args.workspace) - known
        if unknown:
            print(
                f"unknown workspace(s): {', '.join(sorted(unknown))}; known: {', '.join(sorted(known))}",
                file=sys.stderr,
            )
            return 2
        workspaces = [w for w in workspaces if w["id"] in set(args.workspace)]
    if args.audit_json and len(workspaces) != 1:
        print("--audit-json needs exactly one --workspace", file=sys.stderr)
        return 2

    failures: list[str] = []
    for ws in workspaces:
        ws_dir = REPO_ROOT / ws["path"]
        if args.lockfile or args.lockfile_only:
            failures.extend(check_lockfile(policy, ws, REPO_ROOT))
        if args.lockfile_only:
            continue
        try:
            if args.audit_json:
                audit = json.loads(Path(args.audit_json).read_text(encoding="utf-8"))
            else:
                if not (ws_dir / "package.json").exists():
                    failures.append(f"{ws['id']}: {ws_dir} has no package.json")
                    continue
                audit = run_npm_audit(ws_dir, ws.get("audit_args", []))
            totals = audit_totals(audit)
            print(
                f"{ws['id']}: npm audit {' '.join(ws.get('audit_args', []))} -> "
                f"total={totals['total']} critical={totals['critical']} high={totals['high']} "
                f"moderate={totals['moderate']} low={totals['low']}"
            )
            failures.extend(evaluate_workspace(policy, ws, audit, today))
        except PolicyError as exc:
            failures.append(f"{ws['id']}: {exc}")

    print()
    if failures:
        print(f"DEPENDENCY ADVISORY POLICY: FAIL ({len(failures)} finding(s))")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(
        "DEPENDENCY ADVISORY POLICY: PASS (every reported advisory has an unexpired, reviewed exception)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
