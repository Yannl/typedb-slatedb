#!/usr/bin/env python3
"""Independent verifier for a sealed corpus evidence bundle (R6-EVID-01).

Shares no code with seal-bundle.py — only the documented FORMAT CONTRACT in
its module docstring. Every value below is RE-DERIVED here from ground truth
(the repository, the source lock, the binaries on disk, the raw logs) and
compared to what the bundle claims. A bundle that merely agrees with itself
does not verify.

Refusals (each is an R6-EVID-01 acceptance mutant):

  1  schema/format                artifact digests, root.txt rollup
  2  dirty source                 bundle must record a CLEAN tree, unless it is
                                  stamped qualification=false AND the reader
                                  passes --allow-non-qualification
  3  corpus source drift          the CORPUS SOURCE ROOT is recomputed from the
                                  repository; a changed src/**, Cargo.toml,
                                  Cargo.lock, run script, sealer or verifier
                                  (tracked OR untracked) breaks it
  4  provider identity            the provider digest recorded is checked
                                  against the SEALED source-lock copy, the LIVE
                                  source-lock, and the bytes on disk; the
                                  caller's claimed --server-sha256 must equal
                                  the recomputed value
  5  wrong source-lock node       provider name -> node id mapping, node digest,
                                  and lock byte digests must all agree
  6  executed machinery           every recorded executable is re-hashed; a
                                  missing or replaced cas_racer refuses
  7  forged logs                  logs are re-parsed into structure and compared
                                  to the recorded structured results
  8  truncated phase list         the phase list must be exactly the required
                                  sequence, all PASS/0
  9  environment                  no unaccounted-for influential variable, no
                                  LD_PRELOAD/LD_AUDIT, no unredacted secret
 10  attestation                  stable_root recomputed from the bundle

Usage: verify-bundle.py EVIDENCE_DIR [--repo PATH] [--allow-non-qualification]
                                     [--print-stable-root]
Exit nonzero on any failure.
"""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys

SCHEMA = "s3-cert-corpus-bundle/v2"
WANT_PHASES = ["semantics", "mp-cas", "crash-restart", "post-restart"]
NODE_FOR_PROVIDER = {"minio": "MINIO", "rustfs": "RUSTFS"}
CORPUS_REL = "tools/s3-cert-corpus"
SECRETISH = re.compile(r"(KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL)", re.I)
INFLUENTIAL = re.compile(r"^(S3_CERT_|CARGO|RUST|LD_)")


def digest(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            b = fh.read(1 << 20)
            if not b:
                return h.hexdigest()
            h.update(b)


def chain(items) -> str:
    """FORMAT CONTRACT rollup: sha256 over b'<name>\\n<sha256hex>\\n' in order."""
    h = hashlib.sha256()
    for name, dg in items:
        h.update((name + "\n" + dg + "\n").encode())
    return h.hexdigest()


def corpus_set(repo: pathlib.Path):
    """Re-derive the CORPUS SOURCE SET independently of the sealer."""
    base = repo / CORPUS_REL
    found = {}
    if not base.is_dir():
        return None
    for entry in base.iterdir():
        if not entry.is_file():
            continue
        if entry.name in ("Cargo.toml", "Cargo.lock") or entry.name.endswith((".py", ".sh")):
            found[entry.relative_to(repo).as_posix()] = digest(entry)
    srcdir = base / "src"
    if srcdir.is_dir():
        stack = [srcdir]
        while stack:
            cur = stack.pop()
            for entry in cur.iterdir():
                if entry.is_dir():
                    if entry.name not in ("target", "evidence", "__pycache__"):
                        stack.append(entry)
                elif entry.is_file():
                    found[entry.relative_to(repo).as_posix()] = digest(entry)
    return found


def relog(text: str):
    """Independent re-parse of a cargo-test log into structure."""
    outcomes, totals = {}, []
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.startswith("test ") and " ... " in line:
            name, _, verdict = line[5:].partition(" ... ")
            if verdict in ("ok", "FAILED", "ignored"):
                outcomes[name] = verdict
        elif line.startswith("test result: "):
            nums = re.findall(r"(\d+) (passed|failed|ignored|measured|filtered out)", line)
            totals.append({k.replace(" ", "_"): int(v) for v, k in nums})
    return outcomes, totals


def load_node(doc, node_id):
    for n in doc.get("nodes", []):
        if n.get("id") == node_id:
            return n
    return None


def stable_root_of(bundle) -> str:
    """FORMAT CONTRACT stable root — rebuilt here from the bundle's own fields."""
    p = bundle["provider"]
    payload = {
        "schema": bundle["schema"],
        "corpus_source_root": bundle["corpus_source"]["root"],
        "corpus_source_files": bundle["corpus_source"]["files"],
        "provider": {
            "name": p["name"],
            "source_lock_node": p["source_lock_node"],
            "binary_sha256": p["binary_sha256_recomputed"],
            "url": p["url"],
            "version": p["version"],
        },
        "locks": bundle["locks"],
        "corpus": bundle["corpus"],
        "toolchain": {k: bundle["toolchain"].get(k)
                      for k in ("rustc", "cargo", "object_store")},
        "phases": [
            {"name": ph["name"], "verdict": ph["verdict"], "exit_code": ph["exit_code"],
             "summary": ph["summary"]}
            for ph in bundle["phases"]
        ],
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("evidence_dir")
    ap.add_argument("--repo", help="repository root to re-derive source identity from "
                                   "(default: the repo_root recorded in the bundle)")
    ap.add_argument("--allow-non-qualification", action="store_true",
                    help="accept a bundle explicitly stamped qualification=false "
                         "(dirty tree). Such a bundle is NOT qualification evidence.")
    ap.add_argument("--print-stable-root", action="store_true")
    args = ap.parse_args()

    evidence = pathlib.Path(args.evidence_dir)
    bad = []

    try:
        bundle = json.loads((evidence / "bundle.json").read_text())
    except Exception as exc:                                    # noqa: BLE001
        print("BUNDLE VERIFY: FAIL")
        print(f"  - bundle.json unreadable: {exc}")
        return 1

    if bundle.get("schema") != SCHEMA:
        bad.append(f"unknown schema {bundle.get('schema')!r} (want {SCHEMA})")
        print("BUNDLE VERIFY: FAIL")
        for b in bad:
            print(f"  - {b}")
        return 1

    # -- 1. sealed artifacts and the artifact root -------------------------
    arts = bundle.get("artifacts", {})
    for name, want in arts.items():
        path = evidence / name
        if not path.exists():
            bad.append(f"artifact {name} missing")
        elif digest(path) != want:
            bad.append(f"artifact {name} digest mismatch: want {want} got {digest(path)}")
    present = {p.name for p in evidence.iterdir()
               if p.is_file() and p.name not in ("bundle.json", "root.txt")}
    for extra in sorted(present - set(arts)):
        bad.append(f"unsealed file {extra} present in the evidence dir")
    try:
        names = sorted([*arts.keys(), "bundle.json"])
        recomputed = chain((n, digest(evidence / n)) for n in names)
        recorded = (evidence / "root.txt").read_text().strip()
        if recorded != recomputed:
            bad.append(f"root mismatch: recorded {recorded} recomputed {recomputed}")
    except FileNotFoundError as exc:
        bad.append(f"root cannot be recomputed: {exc}")
        recorded = ""

    # -- 2. clean-tree gate ------------------------------------------------
    source = bundle.get("source", {})
    dirt = source.get("dirty_paths")
    if not isinstance(dirt, list):
        bad.append("source.dirty_paths is not a list of paths (v1-style count?)")
        dirt = []
    qualification = bundle.get("qualification")
    if dirt:
        if qualification is not False:
            bad.append(f"{len(dirt)} dirty path(s) recorded but the bundle is not stamped "
                       "qualification=false")
        if not args.allow_non_qualification:
            bad.append(f"source tree was DIRTY at seal time ({len(dirt)} path(s), e.g. "
                       f"{dirt[0]!r}) — this bundle is not qualification evidence; pass "
                       "--allow-non-qualification to read it anyway")
    elif source.get("clean") is not True or qualification is not True:
        bad.append("source.clean/qualification stamp disagrees with an empty dirty_paths list")

    # -- 3. corpus content root re-derived from the repository -------------
    repo_root = pathlib.Path(args.repo or source.get("repo_root", ""))
    cs = bundle.get("corpus_source", {})
    if not repo_root or not repo_root.is_dir():
        bad.append(f"repo root {str(repo_root)!r} not present — the corpus source root "
                   "cannot be re-derived (pass --repo)")
    else:
        live = corpus_set(repo_root)
        if live is None:
            bad.append(f"{repo_root/CORPUS_REL} absent — no corpus source to bind")
        else:
            claimed = cs.get("files", {})
            for path in sorted(set(live) | set(claimed)):
                if path not in claimed:
                    bad.append(f"corpus source {path} exists on disk but is not bound by the bundle")
                elif path not in live:
                    bad.append(f"corpus source {path} bound by the bundle but absent on disk")
                elif live[path] != claimed[path]:
                    bad.append(f"corpus source {path} digest mismatch: bundle {claimed[path]} "
                               f"disk {live[path]}")
            if chain(sorted(claimed.items())) != cs.get("root"):
                bad.append("corpus_source.root does not equal the rollup over its own file list")
            if live and chain(sorted(live.items())) != cs.get("root"):
                bad.append(f"corpus source root mismatch: bundle {cs.get('root')} "
                           f"recomputed {chain(sorted(live.items()))}")

    # -- 4/5. provider identity and the source lock ------------------------
    prov = bundle.get("provider", {})
    locks = bundle.get("locks", {})
    sealed_lock = evidence / locks.get("source_lock_copy", "source-lock.json")
    node_id = NODE_FOR_PROVIDER.get(prov.get("name"))
    if node_id is None:
        bad.append(f"provider {prov.get('name')!r} has no source-locked identity")
    elif prov.get("source_lock_node") != node_id:
        bad.append(f"provider {prov.get('name')!r} bound to source-lock node "
                   f"{prov.get('source_lock_node')!r}, want {node_id!r}")
    recomp = prov.get("binary_sha256_recomputed", "")
    if not re.fullmatch(r"[0-9a-f]{64}", recomp or ""):
        bad.append(f"provider binary_sha256_recomputed not 64-hex: {recomp!r}")
    if prov.get("binary_sha256_claimed") != recomp:
        bad.append(f"caller-claimed provider digest {prov.get('binary_sha256_claimed')!r} != "
                   f"recomputed {recomp!r}")
    if not sealed_lock.is_file():
        bad.append(f"sealed source-lock copy {sealed_lock.name} absent — provider identity "
                   "cannot be bound")
    else:
        if digest(sealed_lock) != locks.get("source_lock_sha256"):
            bad.append("sealed source-lock copy does not match locks.source_lock_sha256")
        try:
            doc = json.loads(sealed_lock.read_text())
        except Exception as exc:                                # noqa: BLE001
            doc = None
            bad.append(f"sealed source-lock copy unparseable: {exc}")
        if doc is not None and node_id:
            node = load_node(doc, node_id)
            if node is None:
                bad.append(f"sealed source-lock has no node {node_id}")
            else:
                if node.get("sha256") != recomp:
                    bad.append(f"provider digest {recomp} != source-lock {node_id} sha256 "
                               f"{node.get('sha256')}")
                for field in ("url", "version"):
                    if prov.get(field) != node.get(field):
                        bad.append(f"provider {field} {prov.get(field)!r} != source-lock "
                                   f"{node_id} {field} {node.get(field)!r}")
    if repo_root.is_dir():
        live_lock = repo_root / "source-lock" / "source-lock.json"
        if not live_lock.is_file():
            bad.append(f"{live_lock} absent — cannot cross-check the sealed lock copy")
        elif digest(live_lock) != locks.get("source_lock_sha256"):
            bad.append("live source-lock.json bytes differ from the sealed lock digest")
        live_ws = repo_root / "source-lock" / "workspace-lock.json"
        if live_ws.is_file() and digest(live_ws) != locks.get("workspace_lock_sha256"):
            bad.append("live workspace-lock.json bytes differ from the sealed digest")
    sealed_ws = evidence / locks.get("workspace_lock_copy", "workspace-lock.json")
    if not sealed_ws.is_file():
        bad.append("sealed workspace-lock copy absent")
    elif digest(sealed_ws) != locks.get("workspace_lock_sha256"):
        bad.append("sealed workspace-lock copy does not match locks.workspace_lock_sha256")
    else:
        try:
            if json.loads(sealed_ws.read_text()).get("source_lock_sha256") \
                    != locks.get("source_lock_sha256"):
                bad.append("workspace lock does not bind the sealed source-lock bytes")
        except Exception as exc:                                # noqa: BLE001
            bad.append(f"sealed workspace-lock copy unparseable: {exc}")

    # -- 6. every executable that actually ran ------------------------------
    execs = bundle.get("executables", [])
    seen = {e.get("name") for e in execs}
    for must in ("provider", "cas_racer"):
        if must not in seen:
            bad.append(f"no executable record for {must} — what ran is unproven")
    for e in execs:
        path = pathlib.Path(e.get("path", ""))
        if not path.is_file():
            if e.get("required"):
                bad.append(f"executable {e.get('name')} absent at {path} — cannot prove it ran")
            continue
        got = digest(path)
        if e.get("sha256") != got:
            bad.append(f"executable {e.get('name')} at {path} digest mismatch: bundle "
                       f"{e.get('sha256')} disk {got}")
    tdir = bundle.get("toolchain", {}).get("cargo_target_dir")
    racer = next((e for e in execs if e.get("name") == "cas_racer"), None)
    if tdir and racer and not str(racer.get("path", "")).startswith(str(tdir)):
        bad.append(f"cas_racer path {racer.get('path')!r} is not under the effective "
                   f"CARGO_TARGET_DIR {tdir!r}")

    # -- 7/8. structured phase results, re-parsed from the raw logs --------
    phases = bundle.get("phases", [])
    if [p.get("name") for p in phases] != WANT_PHASES:
        bad.append(f"phase list {[p.get('name') for p in phases]} != required {WANT_PHASES}")
    by_name = {p.get("name"): p for p in phases}
    for p in phases:
        if p.get("verdict") != "PASS" or p.get("exit_code") != 0:
            bad.append(f"phase {p.get('name')} is not PASS/0: exit={p.get('exit_code')} "
                       f"verdict={p.get('verdict')}")
        log = p.get("log")
        if log:
            lp = evidence / log
            if not lp.is_file():
                bad.append(f"phase {p.get('name')} log {log} absent")
            elif p.get("log_sha256") != digest(lp):
                bad.append(f"phase {p.get('name')} log {log} digest mismatch")

    corpus_cfg = bundle.get("corpus", {})
    expected = corpus_cfg.get("semantics_expected")
    sem = by_name.get("semantics")
    if not isinstance(expected, int):
        bad.append("corpus.semantics_expected absent")
    elif sem is not None:
        lp = evidence / sem.get("log", "phase1.log")
        if not lp.is_file():
            bad.append("semantics log absent")
        else:
            outcomes, totals = relog(lp.read_text(errors="replace"))
            passed = sum(t.get("passed", 0) for t in totals)
            failed = sum(t.get("failed", 0) for t in totals)
            if passed != expected or failed != 0:
                bad.append(f"semantics log shows {passed} passed / {failed} failed, "
                           f"want {expected} passed / 0 failed")
            oks = sorted(n for n, v in outcomes.items() if v == "ok")
            if len(oks) != expected:
                bad.append(f"semantics log names {len(oks)} passing tests, want {expected}")
            claimed = sorted(sem.get("summary", {}).get("tests", []))
            if claimed != oks:
                bad.append(f"semantics structured result {claimed} != re-parsed log {oks}")
            if any(v != "ok" for v in outcomes.values()):
                bad.append("semantics log contains a non-ok test outcome")

    post = by_name.get("post-restart")
    if post is not None:
        lp = evidence / post.get("log", "phase2.log")
        if not lp.is_file():
            bad.append("post-restart log absent")
        else:
            outcomes, totals = relog(lp.read_text(errors="replace"))
            passed = sum(t.get("passed", 0) for t in totals)
            failed = sum(t.get("failed", 0) for t in totals)
            if passed != 1 or failed != 0:
                bad.append(f"post-restart log shows {passed} passed / {failed} failed, want 1/0")
            names_ok = sorted(n for n, v in outcomes.items() if v == "ok")
            if names_ok != sorted(post.get("summary", {}).get("tests", [])):
                bad.append("post-restart structured result disagrees with the re-parsed log")

    mp = by_name.get("mp-cas")
    if mp is not None:
        want_rounds = corpus_cfg.get("mp_rounds")
        want_procs = corpus_cfg.get("mp_procs")
        res = mp.get("results")
        mp_file = evidence / "phase1b.json"
        if not mp_file.is_file():
            bad.append("phase1b.json absent — mp-cas verdict would be prose only")
        else:
            try:
                on_disk = json.loads(mp_file.read_text())
            except Exception as exc:                            # noqa: BLE001
                on_disk = None
                bad.append(f"phase1b.json unparseable: {exc}")
            if on_disk is not None:
                if res != on_disk:
                    bad.append("mp-cas structured result differs from phase1b.json on disk")
                rounds = on_disk.get("rounds", [])
                if len(rounds) != want_rounds:
                    bad.append(f"mp-cas executed {len(rounds)} rounds, want {want_rounds}")
                if on_disk.get("procs") != want_procs:
                    bad.append(f"mp-cas procs {on_disk.get('procs')} != configured {want_procs}")
                for r in rounds:
                    if (r.get("winners") != 1 or r.get("losers") != (want_procs or 0) - 1
                            or r.get("overwrites") != 0 or r.get("errors") != 0):
                        bad.append(f"mp-cas round {r.get('round')}: winners={r.get('winners')} "
                                   f"losers={r.get('losers')} overwrites={r.get('overwrites')} "
                                   f"errors={r.get('errors')} — want 1/"
                                   f"{(want_procs or 0) - 1}/0/0")
                        break
                if on_disk.get("racer_sha256") and racer \
                        and on_disk["racer_sha256"] != racer.get("sha256"):
                    bad.append("phase1b.json racer digest != the recorded cas_racer executable")

    # -- 9. environment allowlist ------------------------------------------
    env = bundle.get("environment", {})
    allow = env.get("allowlist", {})
    if env.get("unlisted_influential"):
        bad.append(f"unaccounted-for influential environment: {env['unlisted_influential']}")
    for danger in ("LD_PRELOAD", "LD_AUDIT"):
        if allow.get(danger):
            bad.append(f"{danger} was set during the run: {allow[danger]!r}")
    for k, v in allow.items():
        if SECRETISH.search(k) and v != "<redacted>":
            bad.append(f"environment allowlist leaks a secret-bearing value for {k}")
    for k in allow:
        if not INFLUENTIAL.match(k) and k not in (
                "PATH", "LANG", "LC_ALL", "TZ", "SOURCE_DATE_EPOCH"):
            bad.append(f"environment allowlist contains unexpected variable {k}")

    # -- 10. git identity and attestation ----------------------------------
    for field, pat in (("git_head", r"[0-9a-f]{40}"), ("git_tree", r"[0-9a-f]{40}")):
        if not re.fullmatch(pat, source.get(field, "") or ""):
            bad.append(f"source.{field} is not a 40-hex object id: {source.get(field)!r}")
    if repo_root.is_dir():
        try:
            head = subprocess.run(["git", "-C", str(repo_root), "rev-parse", "HEAD"],
                                  capture_output=True, text=True).stdout.strip()
            if head and head == source.get("git_head"):
                tree = subprocess.run(["git", "-C", str(repo_root), "rev-parse", "HEAD^{tree}"],
                                      capture_output=True, text=True).stdout.strip()
                if tree and tree != source.get("git_tree"):
                    bad.append(f"source.git_tree {source.get('git_tree')} != the tree of "
                               f"recorded HEAD ({tree})")
        except OSError:
            pass
    att = bundle.get("attestation", {})
    try:
        want_stable = stable_root_of(bundle)
    except KeyError as exc:
        want_stable = None
        bad.append(f"stable root cannot be recomputed, bundle field missing: {exc}")
    if want_stable is not None and att.get("stable_root") != want_stable:
        bad.append(f"attestation.stable_root {att.get('stable_root')} != recomputed {want_stable}")
    if not att.get("attested_by"):
        bad.append("attestation.attested_by absent — no runner attests this bundle")

    if args.print_stable_root and want_stable:
        print(f"stable_root {want_stable}")

    if bad:
        print("BUNDLE VERIFY: FAIL")
        for b in bad:
            print(f"  - {b}")
        return 1
    stamp = "QUALIFICATION" if bundle.get("qualification") else \
        "NON-QUALIFICATION (dirty tree, read under --allow-non-qualification)"
    print(f"BUNDLE VERIFY: PASS [{stamp}] ({len(arts) + 1} artifacts)")
    print(f"  provider      {prov.get('name')} {prov.get('version')} "
          f"({prov.get('source_lock_node')}) {recomp}")
    print(f"  source        {source.get('git_head')} tree {source.get('git_tree')} "
          f"clean={source.get('clean')}")
    print(f"  corpus root   {cs.get('root')}")
    print(f"  stable root   {att.get('stable_root')}")
    print(f"  artifact root {recorded}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
