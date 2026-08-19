#!/usr/bin/env python3
"""Executed mutants for the Mode-Q semantic validator (round-3 E-01).

Builds a synthetic-but-self-consistent Mode-Q bundle in a temp directory
(pinned to the REAL TB revision/tree from source-lock.json and to REAL
catalogue target ids, so the baseline exercises the same cross-checks CI
does), asserts the validator accepts it, then applies one corruption at a
time — each mutant MUST make the validator exit 1:

  junk-file            an unaccounted file dropped into the bundle
                       (the audit's exact counterexample)
  truncated-raw        cquery stdout truncated after its hash was recorded
  wrong-source-pin     source_commit is a commit other than the pinned one
  omitted-target       a target enumerated but missing from the crosswalk
  duplicate-target     the same target listed twice
  nonzero-exit         cquery.exit_code recorded as 101

R4-MODEQ-01 additions (the round-4 synthetic-artifact counterexample):
  junk-stdout          stdout replaced by "THIS IS NOT BAZEL OUTPUT" with
                       hashes and root diligently regenerated — the cquery
                       line grammar must reject it
  argv-echo            argv ['echo', 'cquery'] — containing the string
                       'cquery' is not an invocation; argv[0] must be an
                       approved bazel/bazelisk basename
  wrong-workspace-hash a well-shaped (64-hex) workspace_lock_sha256 that is
                       not the sha256 of the current workspace lock
  two-to-one-crosswalk two Bazel labels mapped onto one catalogue id —
                       the bijection policy (empty n:1 allowlist) rejects it
  path-traversal-ref   crosswalk_file referencing '../' — referenced names
                       must be safe basenames inside the bundle

A validator that accepts any of these proves nothing; this script exits 1
if any mutant survives (or if the healthy baseline is rejected).
"""
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]
VALIDATOR = HERE / "validate_modeq.py"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_bundle(out: pathlib.Path) -> None:
    lock = json.loads((REPO / "source-lock" / "source-lock.json").read_text())
    tb = next(n for n in lock["nodes"] if n.get("id") == "TB")
    catalog = json.loads((REPO / "docs" / "evidence" / "G1" / "upstream-test-catalog.json").read_text())
    cat_ids = [t["target_id"] for t in catalog["targets"][:2]]

    targets = ["//answer:answer_test", "//storage:storage_test"]
    stdout = ("\n".join(targets) + "\n").encode()
    stderr = b"INFO: Analyzed 2 targets.\n"
    crosswalk = json.dumps(
        [{"bazel_target": t, "catalog_target_id": c} for t, c in zip(targets, cat_ids)],
        indent=2,
    ).encode() + b"\n"

    out.mkdir(parents=True)
    (out / "cquery-stdout.txt").write_bytes(stdout)
    (out / "cquery-stderr.txt").write_bytes(stderr)
    (out / "crosswalk.json").write_bytes(crosswalk)

    manifest = {
        "schema": "modeq-bundle/v1",
        "bazel": {"binary_sha256": sha256_bytes(b"synthetic-bazelisk-binary"), "version": "7.4.1"},
        "invocation": {
            "argv": ["bazel", "cquery", "deps(//...)", "--output=label"],
            "env": {"USER": "modeq", "PATH": "/usr/bin"},
            "toolchain": "bazel 7.4.1 / remote-disabled / linux-x86_64",
            "source_commit": tb["revision"],
            "source_tree": tb["tree"],
            "workspace_lock_sha256": sha256_bytes((REPO / "source-lock" / "workspace-lock.json").read_bytes()),
        },
        "cquery": {
            "stdout_file": "cquery-stdout.txt",
            "stdout_sha256": sha256_bytes(stdout),
            "stderr_file": "cquery-stderr.txt",
            "stderr_sha256": sha256_bytes(stderr),
            "exit_code": 0,
        },
        "targets": targets,
        "crosswalk_file": "crosswalk.json",
        "root": "",
    }
    # content-addressed root over every non-manifest file
    lines = []
    for name in sorted(p.name for p in out.iterdir()):
        lines.append(f"{name}\n{hashlib.sha256((out / name).read_bytes()).hexdigest()}\n")
    manifest["root"] = hashlib.sha256("".join(lines).encode()).hexdigest()
    (out / "modeq.json").write_text(json.dumps(manifest, indent=2) + "\n")


def run_validator(bundle: pathlib.Path) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(VALIDATOR), "--dir", str(bundle)],
        capture_output=True, text=True,
    )
    return proc.returncode, proc.stdout + proc.stderr


def edit_manifest(bundle: pathlib.Path, mutate) -> None:
    path = bundle / "modeq.json"
    doc = json.loads(path.read_text())
    mutate(doc)
    path.write_text(json.dumps(doc, indent=2) + "\n")


def reseal(bundle: pathlib.Path) -> None:
    """What a diligent forger does after tampering with raw files: refresh
    the recorded stdout/stderr hashes and the content-addressed root so only
    the SEMANTIC checks can still catch the edit."""
    def fn(doc):
        for role in ("stdout", "stderr"):
            fname = doc["cquery"].get(f"{role}_file")
            if isinstance(fname, str) and "/" not in fname and (bundle / fname).is_file():
                doc["cquery"][f"{role}_sha256"] = sha256_bytes((bundle / fname).read_bytes())
        lines = []
        for name in sorted(p.name for p in bundle.iterdir() if p.name != "modeq.json"):
            lines.append(f"{name}\n{sha256_bytes((bundle / name).read_bytes())}\n")
        doc["root"] = hashlib.sha256("".join(lines).encode()).hexdigest()
    edit_manifest(bundle, fn)


def main() -> int:
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        baseline = pathlib.Path(tmp) / "baseline"
        build_bundle(baseline)
        code, out = run_validator(baseline)
        if code != 0:
            print("MUTANT HARNESS BROKEN: the healthy baseline bundle was rejected:")
            print(out)
            return 1
        print("baseline ok: self-consistent synthetic bundle => VALID (exit 0)")

        def mutant(name: str, corrupt) -> None:
            nonlocal failures
            target = pathlib.Path(tmp) / name
            shutil.copytree(baseline, target)
            corrupt(target)
            code, out = run_validator(target)
            if code == 0:
                print(f"MUTANT SURVIVED: {name} was accepted by the validator")
                print("  " + out.replace("\n", "\n  "))
                failures += 1
            else:
                reason = next((l.strip() for l in out.splitlines() if l.strip().startswith("- ")), "")
                print(f"mutant killed: {name} => exit {code} {reason}")

        mutant("junk-file", lambda b: (b / "junk.txt").write_text("the audit's junk file\n"))
        mutant(
            "truncated-raw",
            lambda b: (b / "cquery-stdout.txt").write_bytes(
                (b / "cquery-stdout.txt").read_bytes()[:5]
            ),
        )
        mutant(
            "wrong-source-pin",
            lambda b: edit_manifest(
                b, lambda d: d["invocation"].__setitem__("source_commit", "0" * 40)
            ),
        )
        mutant(
            "omitted-target",
            lambda b: (b / "crosswalk.json").write_text(
                json.dumps(json.loads((b / "crosswalk.json").read_text())[:1], indent=2) + "\n"
            ),
        )
        mutant(
            "duplicate-target",
            lambda b: edit_manifest(
                b, lambda d: d.__setitem__("targets", d["targets"] + [d["targets"][0]])
            ),
        )
        mutant(
            "nonzero-exit",
            lambda b: edit_manifest(b, lambda d: d["cquery"].__setitem__("exit_code", 101)),
        )

        # ---- R4-MODEQ-01: the round-4 synthetic-artifact counterexample ----

        def junk_stdout(b):
            (b / "cquery-stdout.txt").write_bytes(b"THIS IS NOT BAZEL OUTPUT\n")
            reseal(b)  # hashes/root diligently regenerated; only the grammar is left
        mutant("junk-stdout", junk_stdout)

        mutant(
            "argv-echo",
            lambda b: edit_manifest(
                b, lambda d: d["invocation"].__setitem__("argv", ["echo", "cquery"])
            ),
        )

        mutant(
            "wrong-workspace-hash",
            lambda b: edit_manifest(
                b, lambda d: d["invocation"].__setitem__(
                    "workspace_lock_sha256", "0" * 64)  # well-shaped, wrong
            ),
        )

        def two_to_one(b):
            xw = json.loads((b / "crosswalk.json").read_text())
            xw[1]["catalog_target_id"] = xw[0]["catalog_target_id"]  # 2 labels -> 1 id
            (b / "crosswalk.json").write_text(json.dumps(xw, indent=2) + "\n")
            reseal(b)
        mutant("two-to-one-crosswalk", two_to_one)

        def path_traversal(b):
            (b.parent / "evil-crosswalk.json").write_text(
                (b / "crosswalk.json").read_text())
            edit_manifest(b, lambda d: d.__setitem__(
                "crosswalk_file", "../evil-crosswalk.json"))
        mutant("path-traversal-ref", path_traversal)

    if failures:
        print(f"modeq mutants: {failures} SURVIVED")
        return 1
    print("modeq mutants: all 11 killed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
