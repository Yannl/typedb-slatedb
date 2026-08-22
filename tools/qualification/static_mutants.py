#!/usr/bin/env python3
"""Executed negative controls for the STATIC_CHECK leaf producer and verifier.

The claim under test is not "the verifier has checks". It is: **a static leaf
bundle cannot report a pass it did not earn.** So every control copies the
REAL sealed bundle into a temp tree, applies exactly ONE mutation, and runs
`verify_static_leaf.py` as a REAL SUBPROCESS against the copy, requiring a
nonzero exit that names the defect.

Every mutation is applied the way a DILIGENT FORGER would: after tampering,
the harness regenerates every SHALLOWER binding — the row's `log_sha256`, the
manifest's file digests and root, and the COMPLETE marker — so each control
proves the DEEPEST remaining binding catches the edit, not that a stale hash
was noticed.

Control 11 is the one that matters most, and the reason `verify_static_leaf`
re-implements the tab and header predicates instead of importing them: it puts
a TAB into a file in a shadow tree, updates the log's FILE digest to match (as
a forger would), and leaves the verdict saying PASS. Nothing about the seal,
the file set or the digests is wrong. Only an independent re-derivation of the
check itself can catch it.

usage:
  python3 tools/qualification/static_mutants.py [--bundle DIR]
"""

import argparse
import hashlib
import os
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]
DEFAULT_BUNDLE = REPO / "docs" / "evidence" / "G3" / "leaf" / "static-u0-1"
VERIFIER = HERE / "verify_static_leaf.py"
RESULTS_NAME = "static-leaf-results.json"


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class Case:
    """One mutable copy of the bundle, inside a shadow repo."""

    def __init__(self, tmp: pathlib.Path, bundle: pathlib.Path):
        """R8-P2-01: accept a bundle given by a RELATIVE path, and one copied
        OUTSIDE the repository.

        The harness used to call `bundle.relative_to(REPO)` on whatever it was
        handed. A relative `--bundle docs/...` (resolved against the caller's
        cwd, not REPO) or a bundle copied to /tmp for inspection raised
        ValueError before a single control executed — the suite reported
        nothing rather than reporting that it could not run. Both are now
        deliberate: the path is normalised first, and a bundle outside the
        repository is placed at its canonical evidence location inside the
        shadow tree so the verifier's repo-relative bookkeeping still holds.
        """
        self.repo = tmp
        bundle = bundle.resolve()
        if bundle.is_relative_to(REPO):
            rel = bundle.relative_to(REPO)
        else:
            # an external copy: give it the canonical evidence location, which
            # is what the bundle's own manifest paths are expressed against
            rel = DEFAULT_BUNDLE.relative_to(REPO).parent / bundle.name
        self.dir = tmp / rel
        self.dir.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(bundle, self.dir)
        # the tree the verifier re-derives against; symlinked, and replaced by
        # a real copy only for the control that needs to edit it
        (tmp / "sources").mkdir(exist_ok=True)
        (tmp / "sources" / "typedb").symlink_to(REPO / "sources" / "typedb")
        for extra in ("docs/evidence/G1",):
            src = REPO / extra
            dst = tmp / extra
            dst.parent.mkdir(parents=True, exist_ok=True)
            if not dst.exists():
                dst.symlink_to(src)

    @property
    def body(self) -> dict:
        return json.loads((self.dir / RESULTS_NAME).read_text())

    def write_body(self, body: dict) -> None:
        (self.dir / RESULTS_NAME).write_text(json.dumps(body, indent=1) + "\n")

    def unshadow_tree(self) -> pathlib.Path:
        """Replace the symlinked tree with a real, editable copy."""
        link = self.repo / "sources" / "typedb"
        link.unlink()
        shutil.copytree(REPO / "sources" / "typedb", link, symlinks=True, ignore=_ignore_heavy)
        return link

    def refresh(self) -> None:
        """Regenerate every shallower binding, as a forger would."""
        body = self.body
        for row in body.get("targets") or []:
            log = self.repo / row["raw_log"]
            if log.is_file():
                row["log_sha256"] = sha256_file(log)
                row["log_bytes"] = log.stat().st_size
        for leaf in body.get("leaves") or []:
            log = self.repo / leaf["raw_log"]
            if log.is_file():
                leaf["log_sha256"] = sha256_file(log)
        self.write_body(body)
        files = {
            str(p.relative_to(self.repo)): sha256_file(p)
            for p in sorted(self.dir.iterdir())
            if p.is_file() and p.name not in ("COMPLETE", "bundle-manifest.json")
        }
        root = hashlib.sha256(
            "".join(f"{k}\n{v}\n" for k, v in sorted(files.items())).encode()
        ).hexdigest()
        (self.dir / "bundle-manifest.json").write_text(
            json.dumps({"bundle_root": root, "files": files}, indent=1) + "\n"
        )
        (self.dir / "COMPLETE").write_text(f"COMPLETE {root}\n")


def _ignore_heavy(_directory, names):
    return [n for n in names if n in (".git", "target", "bazel-bin", "bazel-out", "typedb-logs")]


def first_target(body: dict, rule: str) -> dict:
    return next(t for t in body["targets"] if t["rule"] == rule and t["publishable"])


def run_verifier(case: Case, env_overrides: dict | None = None) -> tuple[int, str]:
    import os

    env = dict(os.environ)
    if env_overrides:
        env.update(env_overrides)
    proc = subprocess.run(
        [sys.executable, str(VERIFIER), str(case.dir), "--repo", str(case.repo)]
        if _verifier_takes_repo()
        else [sys.executable, str(VERIFIER), str(case.dir)],
        capture_output=True,
        text=True,
        cwd=case.repo,
        env=env,
    )
    return proc.returncode, proc.stdout + proc.stderr


def _verifier_takes_repo() -> bool:
    return "--repo" in VERIFIER.read_text()


# --------------------------------------------------------------- the controls


def m_clean(_case: Case) -> None:
    """Control of controls: an untouched copy must VERIFY."""


def m_result_line_removed(case: Case) -> None:
    row = first_target(case.body, "checkstyle")
    log = case.repo / row["raw_log"]
    log.write_text(
        "\n".join(ln for ln in log.read_text().splitlines() if "RESULT" not in ln) + "\n"
    )


def m_verdict_flipped(case: Case) -> None:
    row = first_target(case.body, "checkstyle")
    log = case.repo / row["raw_log"]
    log.write_text(log.read_text().replace("RESULT       PASS", "RESULT       FAIL"))


def m_leaf_outcome_edited(case: Case) -> None:
    body = case.body
    body["leaves"][0]["outcome"] = "FAILED"
    case.write_body(body)


def m_file_digest_forged(case: Case) -> None:
    row = first_target(case.body, "checkstyle")
    log = case.repo / row["raw_log"]
    lines = log.read_text().splitlines()
    for i, ln in enumerate(lines):
        if ln.startswith("FILE"):
            # the DIGEST only: the path must stay intact, or the control tests
            # the file-set check instead of the digest binding it aims at
            _key, _digest, path = ln.split(None, 2)
            lines[i] = f"FILE         {'0' * 64} {path}"
            break
    log.write_text("\n".join(lines) + "\n")


def m_file_dropped(case: Case) -> None:
    row = first_target(case.body, "checkstyle")
    log = case.repo / row["raw_log"]
    lines = log.read_text().splitlines()
    kept, dropped = [], False
    for ln in lines:
        if ln.startswith("FILE") and not dropped:
            dropped = True
            continue
        kept.append(ln)
    # a forger fixes the count too
    kept = [
        ln.replace(
            f"files={sum(1 for x in lines if x.startswith('FILE'))}",
            f"files={sum(1 for x in kept if x.startswith('FILE'))}",
        )
        if ln.startswith("RESULT")
        else ln
        for ln in kept
    ]
    log.write_text("\n".join(kept) + "\n")


def m_log_deleted(case: Case) -> None:
    row = first_target(case.body, "checkstyle")
    (case.repo / row["raw_log"]).unlink()


def m_refused_target_publishes(case: Case) -> None:
    body = case.body
    body["targets"][0]["publishable"] = False
    body["targets"][0]["refusals"] = ["synthetic refusal"]
    case.write_body(body)


def m_junk_line(case: Case) -> None:
    row = first_target(case.body, "checkstyle")
    log = case.repo / row["raw_log"]
    log.write_text(log.read_text() + "THIS IS NOT A STATIC CHECK LOG\n")


def m_unsealed_root(_case: Case) -> None:
    """The seal is edited AFTER the refresh, so nothing recomputes to it."""


def m_leaf_set_shrunk(case: Case) -> None:
    body = case.body
    body["leaves"] = body["leaves"][1:]
    case.write_body(body)


def m_tab_hidden_behind_a_pass(case: Case) -> None:
    """The control the independent predicate exists for.

    A tab goes into a checked file in a shadow tree; the log's FILE digest is
    updated to match, as a forger would; the verdict still says PASS. The
    seal, the file set and every digest are consistent. Only re-deriving the
    check itself catches it.
    """
    tree = case.unshadow_tree()
    row = first_target(case.body, "checkstyle")
    log = case.repo / row["raw_log"]
    lines = log.read_text().splitlines()
    target_rel = None
    for i, ln in enumerate(lines):
        if ln.startswith("FILE") and ln.rstrip().endswith(".rs"):
            target_rel = ln.split()[-1]
            path = tree / target_rel
            path.write_text(path.read_text() + "\ttrailing tab line\n")
            lines[i] = f"FILE         {sha256_file(path)} {target_rel}"
            break
    if target_rel is None:
        raise RuntimeError("no .rs file in the first checkstyle log to tamper with")
    log.write_text("\n".join(lines) + "\n")


def m_relative_bundle_path(_case: Case) -> None:
    """R8-P2-01 portability: the harness is handed a RELATIVE bundle path.

    No mutation of the bundle at all — the subject is the harness. Before the
    normalisation in `Case.__init__`, this raised ValueError from
    `relative_to(REPO)` before any control ran, so a suite invoked the ordinary
    way from a different cwd reported nothing instead of reporting that it
    could not run.
    """


def m_non_default_cargo_home(_case: Case) -> None:
    """R8-P2-01 portability: rustfmt is resolved with a non-default CARGO_HOME.

    Also not a mutation of the bundle. The producer and verifier used to
    hardcode `~/.cargo/bin/rustfmt`; under a different CARGO_HOME that file
    does not exist, and the check that claims to have run could not have. The
    control runs the verifier with `CARGO_HOME` pointed at an empty directory
    and requires it to still VERIFY — i.e. to have resolved a real rustfmt some
    other way rather than crash or, worse, pass without running it.
    """


CONTROLS = [
    ("0  an intact copy verifies", m_clean, None),
    ("1  the RESULT line removed", m_result_line_removed, "no RESULT line"),
    ("2  the verdict flipped in the log", m_verdict_flipped, "re-derivation says"),
    ("3  a leaf outcome edited, log untouched", m_leaf_outcome_edited, "leaf outcome"),
    ("4  a FILE digest forged", m_file_digest_forged, "has changed since the check read it"),
    (
        "5  a checked file dropped from the log",
        m_file_dropped,
        "file set is not what the rule resolves",
    ),
    ("6  an archived log deleted", m_log_deleted, "is absent"),
    (
        "7  a refused target still publishing leaves",
        m_refused_target_publishes,
        "refused target published",
    ),
    ("8  a junk line in the log", m_junk_line, "not static-check log grammar"),
    (
        "9  COMPLETE sealing a root the bytes do not recompute to",
        m_unsealed_root,
        "COMPLETE marker",
    ),
    ("10 a leaf silently dropped from a published target", m_leaf_set_shrunk, "catalogue"),
    (
        "11 a TAB hidden behind a PASS, every binding refreshed",
        m_tab_hidden_behind_a_pass,
        "re-derivation says",
    ),
    ("12 the bundle given by a RELATIVE path", m_relative_bundle_path, None),
    ("13 rustfmt resolved under a non-default CARGO_HOME", m_non_default_cargo_home, None),
]


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--bundle", type=pathlib.Path, default=DEFAULT_BUNDLE)
    args = ap.parse_args()
    if not (args.bundle / RESULTS_NAME).is_file():
        print(f"REFUSED: {args.bundle} is not a static leaf bundle", file=sys.stderr)
        return 2

    killed = survived = 0
    for label, mutate, needle in CONTROLS:
        with tempfile.TemporaryDirectory(prefix="static-mutants-") as tmp:
            # R8-P2-01 control 12: hand the harness the path the caller
            # actually typed, un-normalised, exactly as an ordinary invocation
            # from another cwd would.
            given = (
                pathlib.Path(os.path.relpath(args.bundle, pathlib.Path.cwd()))
                if mutate is m_relative_bundle_path
                else args.bundle
            )
            case = Case(pathlib.Path(tmp), given)
            mutate(case)
            case.refresh()
            if mutate is m_unsealed_root:
                # break the seal AFTER the refresh, so it is the only defect
                (case.dir / "COMPLETE").write_text("COMPLETE " + "0" * 64 + "\n")
            overrides = None
            if mutate is m_non_default_cargo_home:
                # R8-P2-01 control 13: a CARGO_HOME with no bin/rustfmt in it
                empty_home = pathlib.Path(tmp) / "empty-cargo-home"
                (empty_home / "bin").mkdir(parents=True, exist_ok=True)
                overrides = {"CARGO_HOME": str(empty_home)}
            rc, out = run_verifier(case, overrides)
            if needle is None:
                if rc == 0:
                    print(f"  ACCEPTED {label}")
                    killed += 1
                else:
                    print(f"  BROKEN   {label} — a clean copy was rejected:\n{out[-1200:]}")
                    survived += 1
                continue
            if rc != 0 and needle in out:
                print(f"  KILLED   {label}")
                killed += 1
            elif rc != 0:
                print(f"  KILLED*  {label} — rejected, but not for the expected reason")
                print(f"           expected {needle!r}; got: {out.strip().splitlines()[-1][:160]}")
                survived += 1
            else:
                print(f"  SURVIVED {label} — the verifier ACCEPTED it")
                survived += 1

    print(f"\nstatic mutants: {killed}/{len(CONTROLS)} held ({survived} SURVIVED)")
    return 1 if survived else 0


if __name__ == "__main__":
    raise SystemExit(main())
