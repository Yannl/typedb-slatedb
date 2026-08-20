#!/usr/bin/env python3
"""Executed negative controls for the S3 corpus evidence chain (R6-EVID-01).

Round 5 produced a corpus bundle that recorded `"dirty_paths": 2` and still
verified PASS, and whose provider digest was nothing but the caller's own
claim. This file re-applies every forgery the round-6 audit demands, each
against a REAL invocation of the real `seal-bundle.py` / `verify-bundle.py`
CLIs, and asserts the evidence chain refuses it.

Method — nothing here touches the repository:

  * a SHADOW REPO is built in a temp dir: a byte-copy of
    tools/s3-cert-corpus (so the corpus content root is genuine), a
    source-lock whose RUSTFS node pins a small stand-in provider binary, a
    matching workspace lock, and one git commit so the clean-tree gate has
    something real to measure;
  * a SYNTHETIC evidence dir carries the artifacts a real run produces
    (phases.tsv, phase1.log, phase1b.log/json, phase2.log, server.log,
    commands.jsonl) in the shapes cargo and the racer actually emit;
  * the real sealer seals it and the real verifier verifies it — the
    POSITIVE CONTROL, which must pass, or the mutants below would be killed
    for the wrong reason;
  * each mutant re-runs the pipeline with exactly one thing corrupted and
    must be REFUSED. Bundle- and file-level mutants RESEAL root.txt and
    every artifact digest, so the mutated bundle stays internally
    SELF-CONSISTENT: a mutant that only trips the rollup would prove nothing
    about source authenticity, which is the exact hole R6-EVID-01 names.

A mutant "holds" only when the refusal is non-zero AND the refusal output
names a reason matching the expectation for that mutant — a generic or
silent failure would be as unreviewable as a false green.

Run: python3 tools/s3-cert-corpus/evidence_mutants.py
Exit 0 only if every mutant is killed and both positive controls hold.
"""

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]
SEAL = HERE / "seal-bundle.py"
VERIFY = HERE / "verify-bundle.py"
REAL_LOCK = REPO / "source-lock" / "source-lock.json"

# Deterministic stand-in bytes: the stable root must be reproducible across
# checkouts, so the provider content may not vary between baselines.
FAKE_PROVIDER_BYTES = b"stand-in provider binary for R6-EVID-01 controls\n"

SEMANTIC_TESTS = [
    "semantics::cas_create_race_hardened_rounds",
    "semantics::conditional_create_exactly_one_winner",
    "semantics::conditional_update_exact_etag",
    "semantics::etag_update_race_exactly_one_winner",
    "semantics::list_pagination_no_missing_no_duplicate",
    "semantics::missing_key_is_typed_not_found",
    "semantics::multipart_complete_and_abort",
    "semantics::persisted_objects_survive_server_crash_restart",
    "semantics::put_get_head_byte_exact",
    "semantics::range_get_exact_slice",
    "semantics::write_persistence_witnesses",
]
MP_ROUNDS, MP_PROCS = 20, 8


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_file(p: pathlib.Path) -> str:
    return sha256_bytes(p.read_bytes())


def lock_node(doc, node_id):
    return next(n for n in doc["nodes"] if n.get("id") == node_id)


# ---------------------------------------------------------------------------
# baseline construction
# ---------------------------------------------------------------------------


def cargo_log(tests, passed) -> str:
    filtered = 11 - passed if passed < 11 else 0
    lines = [
        "    Finished `test` profile [unoptimized] target(s) in 0.19s",
        "     Running unittests src/lib.rs (target/debug/deps/s3_cert_corpus-deadbeef)",
        "",
        f"running {len(tests)} tests",
    ]
    lines += [f"test {t} ... ok" for t in tests]
    lines += [
        "",
        f"test result: ok. {passed} passed; 0 failed; 0 ignored; 0 measured; "
        f"{filtered} filtered out; finished in 75.61s",
        "",
        "     Running unittests src/bin/cas_racer.rs (target/debug/deps/cas_racer-cafe)",
        "",
        "running 0 tests",
        "",
        "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; "
        "finished in 0.00s",
        "",
    ]
    return "\n".join(lines)


def build_base(root: pathlib.Path, racer_bytes: bytes = b"stand-in cas_racer\n") -> dict:
    """Shadow repo + synthetic evidence inputs. Nothing is sealed yet."""
    repo = root / "repo"
    provider_dir = root / "provider"
    target = root / "target"
    evidence = root / "evidence"
    for d in (repo / "source-lock", provider_dir, target / "debug", evidence):
        d.mkdir(parents=True, exist_ok=True)

    # corpus source: a real byte-copy, so the content root is genuine
    shutil.copytree(
        HERE,
        repo / "tools" / "s3-cert-corpus",
        ignore=shutil.ignore_patterns("target", "evidence", "__pycache__"),
    )

    # provider stand-in + a source lock that pins exactly its bytes
    provider = provider_dir / "rustfs-1.0.0-rc.2"
    provider.write_bytes(FAKE_PROVIDER_BYTES)
    provider.chmod(0o755)
    real = json.loads(REAL_LOCK.read_text())
    node = dict(lock_node(real, "RUSTFS"))
    node["sha256"] = sha256_bytes(FAKE_PROVIDER_BYTES)
    shadow_lock = {
        "document": "shadow lock for R6-EVID-01 controls",
        "nodes": [node, dict(lock_node(real, "MINIO"))],
    }
    lock_path = repo / "source-lock" / "source-lock.json"
    lock_path.write_text(json.dumps(shadow_lock, indent=1, sort_keys=True) + "\n")
    (repo / "source-lock" / "workspace-lock.json").write_text(
        json.dumps(
            {"document": "shadow workspace lock", "source_lock_sha256": sha256_file(lock_path)},
            indent=1,
            sort_keys=True,
        )
        + "\n"
    )

    racer = target / "debug" / "cas_racer"
    racer.write_bytes(racer_bytes)
    racer.chmod(0o755)

    # synthetic evidence artifacts, in the shapes a real run emits
    (evidence / "phase1.log").write_text(cargo_log(SEMANTIC_TESTS, 11))
    (evidence / "phase2.log").write_text(
        cargo_log(["semantics::persisted_objects_survive_server_crash_restart"], 1)
    )
    rounds = [
        {
            "round": r,
            "key": f"cert/mp-cas/round-{r}",
            "winners": 1,
            "losers": MP_PROCS - 1,
            "overwrites": 0,
            "errors": 0,
        }
        for r in range(1, MP_ROUNDS + 1)
    ]
    (evidence / "phase1b.json").write_text(
        json.dumps(
            {
                "kind": "mp-cas",
                "procs": MP_PROCS,
                "racer_path": str(racer),
                "racer_sha256": sha256_file(racer),
                "rounds": rounds,
            },
            indent=1,
        )
        + "\n"
    )
    (evidence / "phase1b.log").write_text(
        "".join(
            f"round {r['round']}: winners=1 losers={MP_PROCS - 1} overwrites=0 errors=0\n"
            for r in rounds
        )
    )
    (evidence / "server.log").write_text("shadow provider log\n")
    (evidence / "commands.jsonl").write_text(
        json.dumps({"label": "start-server", "cwd": str(repo), "argv": [str(provider)]}) + "\n"
    )
    (evidence / "phases.tsv").write_text(
        "semantics\t0\tphase1.log\t11 tests\n"
        f"mp-cas\t0\tphase1b.log\t{MP_ROUNDS} rounds x {MP_PROCS} procs\n"
        "crash-restart\t0\tserver.log\tkill -9 pid=1 at 2026-08-20T00:00:00Z; restarted pid=2\n"
        "post-restart\t0\tphase2.log\twitnesses byte-exact after kill -9\n"
    )

    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True, capture_output=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.email=controls@local",
            "-c",
            "user.name=controls",
            "commit",
            "-q",
            "-m",
            "shadow base",
        ],
        check=True,
        capture_output=True,
    )
    return {
        "root": root,
        "repo": repo,
        "provider": provider,
        "racer": racer,
        "target": target,
        "evidence": evidence,
        "lock": lock_path,
    }


def clone_sealed(base: dict, dst_root: pathlib.Path) -> dict:
    """Copy an ALREADY SEALED baseline to a new location.

    Every absolute path the bundle records is rewritten to the copy and the
    bundle is resealed, so the clone is a fully valid bundle in its own right
    — which is what makes each mutant below a single-variable experiment
    instead of a path artefact. The stable root is path-independent by
    construction and is deliberately NOT recomputed here.
    """
    shutil.copytree(base["root"], dst_root)
    old, new = str(base["root"]), str(dst_root)
    ev = dst_root / "evidence"
    for name in ("bundle.json", "phase1b.json", "commands.jsonl"):
        p = ev / name
        if p.is_file():
            p.write_text(p.read_text().replace(old, new))
    reseal(ev, json.loads((ev / "bundle.json").read_text()))
    return {
        "root": dst_root,
        "repo": dst_root / "repo",
        "provider": dst_root / "provider" / "rustfs-1.0.0-rc.2",
        "racer": dst_root / "target" / "debug" / "cas_racer",
        "target": dst_root / "target",
        "evidence": ev,
        "lock": dst_root / "repo" / "source-lock" / "source-lock.json",
    }


def seal(base, server_sha256=None, allow_dirty=False):
    argv = [
        sys.executable,
        str(SEAL),
        str(base["evidence"]),
        "--provider",
        "rustfs",
        "--server-bin",
        str(base["provider"]),
        "--server-sha256",
        server_sha256 or sha256_file(base["provider"]),
        "--endpoint",
        "http://127.0.0.1:39301",
        "--repo",
        str(base["repo"]),
        "--racer",
        str(base["racer"]),
        "--cargo-target-dir",
        str(base["target"]),
        "--semantics-expected",
        "11",
        "--mp-rounds",
        str(MP_ROUNDS),
        "--mp-procs",
        str(MP_PROCS),
    ]
    if allow_dirty:
        argv.append("--allow-dirty")
    return subprocess.run(argv, capture_output=True, text=True)


def verify(base, extra=()):
    return subprocess.run(
        [sys.executable, str(VERIFY), str(base["evidence"]), "--repo", str(base["repo"]), *extra],
        capture_output=True,
        text=True,
    )


# ---------------------------------------------------------------------------
# reseal helpers — keep a mutated bundle INTERNALLY self-consistent
# ---------------------------------------------------------------------------


def reseal(evidence: pathlib.Path, bundle: dict):
    """Rewrite bundle.json, refresh every artifact digest, recompute root.txt."""
    bundle["artifacts"] = {
        p.name: sha256_file(p)
        for p in sorted(evidence.iterdir())
        if p.is_file() and p.name not in ("bundle.json", "root.txt")
    }
    (evidence / "bundle.json").write_text(json.dumps(bundle, indent=1) + "\n")
    h = hashlib.sha256()
    for name in sorted([*bundle["artifacts"], "bundle.json"]):
        h.update(f"{name}\n{sha256_file(evidence / name)}\n".encode())
    (evidence / "root.txt").write_text(h.hexdigest() + "\n")


def load(evidence: pathlib.Path) -> dict:
    return json.loads((evidence / "bundle.json").read_text())


def exe(bundle, name):
    return next(e for e in bundle["executables"] if e["name"] == name)


# ---------------------------------------------------------------------------
# mutants
# ---------------------------------------------------------------------------


def m_dirty_tracked_source(base):
    """The exact round-5 shape: a TRACKED corpus source edited, sealed anyway."""
    p = base["repo"] / "tools" / "s3-cert-corpus" / "src" / "lib.rs"
    p.write_text(p.read_text() + "\n// smuggled change at an unchanged git_head\n")


def m_dirty_untracked_exec_source(base):
    """An UNTRACKED executable source file — invisible to a bare `git_head`."""
    (base["repo"] / "tools" / "s3-cert-corpus" / "src" / "bin" / "smuggled.rs").write_text(
        "fn main() { /* an extra binary nobody committed */ }\n"
    )


def m_v1_dirty_count(base):
    """Round-5 literal: a COUNT of dirty paths, stamped as qualification."""
    b = load(base["evidence"])
    b["source"]["dirty_paths"] = 2
    b["source"]["clean"] = True
    b["qualification"] = True
    b["qualification_disqualifiers"] = []
    reseal(base["evidence"], b)


def m_wrong_provider_digest(base):
    b = load(base["evidence"])
    forged = "f" * 64
    b["provider"]["binary_sha256_recomputed"] = forged
    b["provider"]["binary_sha256_claimed"] = forged
    exe(b, "provider")["sha256"] = forged
    reseal(base["evidence"], b)


def m_lied_server_sha256(base):
    """The caller's --server-sha256 claim disagrees with the bytes."""
    b = load(base["evidence"])
    b["provider"]["binary_sha256_claimed"] = "a" * 64
    reseal(base["evidence"], b)


def m_wrong_source_lock_node(base):
    """rustfs evidence bound to the MINIO lock node."""
    b = load(base["evidence"])
    b["provider"]["source_lock_node"] = "MINIO"
    reseal(base["evidence"], b)


def m_tampered_lock_copy(base):
    """The sealed source-lock copy's provider digest edited after the fact."""
    ev = base["evidence"]
    doc = json.loads((ev / "source-lock.json").read_text())
    lock_node(doc, "RUSTFS")["sha256"] = "b" * 64
    (ev / "source-lock.json").write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    b = load(ev)
    b["locks"]["source_lock_sha256"] = sha256_file(ev / "source-lock.json")
    reseal(ev, b)


def m_custom_target_dir(base):
    """The round-6 portability defect: a racer taken from a hardcoded
    tools/s3-cert-corpus/target path while cargo built somewhere else."""
    hardcoded = base["repo"] / "tools" / "s3-cert-corpus" / "target" / "debug"
    hardcoded.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(base["racer"], hardcoded / "cas_racer")
    b = load(base["evidence"])
    exe(b, "cas_racer")["path"] = str(hardcoded / "cas_racer")
    reseal(base["evidence"], b)


def m_missing_racer(base):
    base["racer"].unlink()


def m_replaced_racer(base):
    base["racer"].write_bytes(b"a different racer than the one that ran\n")


def m_source_edited_after_seal(base):
    """Content-root binding: a TRACKED corpus source changed after sealing."""
    m_dirty_tracked_source(base)


def m_source_added_after_seal(base):
    """Content-root binding: an UNTRACKED executable source appears after sealing."""
    m_dirty_untracked_exec_source(base)


def m_forged_phase1_log(base):
    """Naive forgery: rewrite the log bytes, leave the seal alone."""
    (base["evidence"] / "phase1.log").write_text(
        cargo_log(SEMANTIC_TESTS, 11).replace("75.61s", "0.01s")
    )


def m_forged_phase1_log_resealed(base):
    """Self-consistent forgery: fabricated test names, all digests refreshed."""
    ev = base["evidence"]
    fake = [f"semantics::fabricated_{i}" for i in range(11)]
    (ev / "phase1.log").write_text(cargo_log(fake, 11))
    b = load(ev)
    for p in b["phases"]:
        if p["name"] == "semantics":
            p["log_sha256"] = sha256_file(ev / "phase1.log")
    reseal(ev, b)


def m_phase1_log_short(base):
    """A skipped corpus: the log says 10, the bundle still claims 11."""
    ev = base["evidence"]
    (ev / "phase1.log").write_text(cargo_log(SEMANTIC_TESTS[:10], 10))
    b = load(ev)
    for p in b["phases"]:
        if p["name"] == "semantics":
            p["log_sha256"] = sha256_file(ev / "phase1.log")
    reseal(ev, b)


def m_truncated_phase_list(base):
    b = load(base["evidence"])
    b["phases"] = [p for p in b["phases"] if p["name"] != "crash-restart"]
    reseal(base["evidence"], b)


def m_mp_round_regressed(base):
    """One CAS round with two winners, recorded honestly and resealed."""
    ev = base["evidence"]
    mp = json.loads((ev / "phase1b.json").read_text())
    mp["rounds"][6].update({"winners": 2, "losers": MP_PROCS - 2})
    (ev / "phase1b.json").write_text(json.dumps(mp, indent=1) + "\n")
    b = load(ev)
    for p in b["phases"]:
        if p["name"] == "mp-cas":
            p["results"] = mp
            p["summary"]["winners_total"] = sum(r["winners"] for r in mp["rounds"])
            p["summary"]["losers_total"] = sum(r["losers"] for r in mp["rounds"])
    reseal(ev, b)


def m_mp_json_dropped(base):
    """Structured mp-cas result removed — a prose-only CAS verdict."""
    ev = base["evidence"]
    (ev / "phase1b.json").unlink()
    reseal(ev, load(ev))


def m_forged_stable_root(base):
    b = load(base["evidence"])
    b["attestation"]["stable_root"] = "c" * 64
    reseal(base["evidence"], b)


def m_ld_preload(base):
    b = load(base["evidence"])
    b["environment"]["allowlist"]["LD_PRELOAD"] = "/tmp/shim.so"
    reseal(base["evidence"], b)


def m_unlisted_env(base):
    b = load(base["evidence"])
    b["environment"]["unlisted_influential"] = ["RUSTFLAGS_SMUGGLED"]
    reseal(base["evidence"], b)


def m_unsealed_extra_file(base):
    (base["evidence"] / "notes.txt").write_text("an artifact nobody sealed\n")


# Mutants applied to a CLONE of the sealed positive control: (name, fn,
# verify args, expected refusal substring).
POST_SEAL_MUTANTS = [
    (
        "tracked corpus source edited AFTER sealing (content-root binding)",
        m_source_edited_after_seal,
        (),
        "src/lib.rs digest mismatch",
    ),
    (
        "untracked executable source added AFTER sealing (src/bin/smuggled.rs)",
        m_source_added_after_seal,
        (),
        "not bound by the bundle",
    ),
    (
        "round-5 shape: dirty_paths recorded as a COUNT, stamped qualification",
        m_v1_dirty_count,
        (),
        "not a list of paths",
    ),
    (
        "wrong provider digest (vs the source-locked node)",
        m_wrong_provider_digest,
        (),
        "source-lock RUSTFS sha256",
    ),
    (
        "caller-lied --server-sha256 (recorded claim != recomputed)",
        m_lied_server_sha256,
        (),
        "caller-claimed provider digest",
    ),
    (
        "wrong source-lock node (rustfs evidence bound to MINIO)",
        m_wrong_source_lock_node,
        (),
        "bound to source-lock node",
    ),
    (
        "tampered sealed source-lock copy",
        m_tampered_lock_copy,
        (),
        "live source-lock.json bytes differ",
    ),
    (
        "custom target directory (racer taken from a hardcoded target path)",
        m_custom_target_dir,
        (),
        "not under the effective",
    ),
    ("missing racer (the executable that ran is gone)", m_missing_racer, (), "cas_racer absent"),
    (
        "replaced racer (different bytes than the one that ran)",
        m_replaced_racer,
        (),
        "cas_racer at",
    ),
    (
        "forged phase1.log (bytes rewritten, seal untouched)",
        m_forged_phase1_log,
        (),
        "phase1.log digest mismatch",
    ),
    (
        "forged phase1.log (fabricated tests, fully resealed)",
        m_forged_phase1_log_resealed,
        (),
        "structured result",
    ),
    ("truncated corpus: phase1.log shows 10 of 11 tests", m_phase1_log_short, (), "want 11 passed"),
    ("truncated phase list (crash-restart dropped)", m_truncated_phase_list, (), "!= required"),
    ("mp-cas round with two winners (resealed honestly)", m_mp_round_regressed, (), "winners=2"),
    (
        "structured mp-cas result deleted (prose-only CAS verdict)",
        m_mp_json_dropped,
        (),
        "phase1b.json absent",
    ),
    ("forged attestation.stable_root", m_forged_stable_root, (), "stable_root"),
    ("LD_PRELOAD set during the run", m_ld_preload, (), "LD_PRELOAD was set"),
    (
        "unaccounted-for influential environment variable",
        m_unlisted_env,
        (),
        "unaccounted-for influential",
    ),
    ("unsealed file smuggled into the evidence dir", m_unsealed_extra_file, (), "unsealed file"),
]

# Mutants that must be present BEFORE sealing: the dirt is the mutation.
PRE_SEAL_MUTANTS = [
    (
        "dirty TRACKED source sealed under the opt-out, read as qualification",
        m_dirty_tracked_source,
        "DIRTY at seal time",
    ),
    (
        "dirty UNTRACKED executable source sealed under the opt-out",
        m_dirty_untracked_exec_source,
        "DIRTY at seal time",
    ),
]


# ---------------------------------------------------------------------------


def report(results, name, ok, reason):
    results.append((name, ok, reason))
    print(f"{'KILLED  ' if ok else 'SURVIVED'} {name}\n           {reason[:170]}")


def refusal_reasons(v):
    return [line.strip()[2:] for line in v.stdout.splitlines() if line.startswith("  - ")]


def run_all() -> int:
    results = []
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="evid-mutants-"))
    try:
        # ---- positive control -------------------------------------------
        control = build_base(tmp / "control")
        r = seal(control)
        if r.returncode != 0:
            print("POSITIVE CONTROL FAILED — the sealer refused a clean baseline:")
            print(r.stdout + r.stderr)
            return 1
        v = verify(control)
        if v.returncode != 0:
            print("POSITIVE CONTROL FAILED — the verifier refused a clean baseline:")
            print(v.stdout + v.stderr)
            return 1
        print("POSITIVE CONTROL: a clean baseline seals and verifies")
        print("   " + "\n   ".join(v.stdout.strip().splitlines()))
        print()
        control_stable = load(control["evidence"])["attestation"]["stable_root"]

        # ---- refusals that fire BEFORE/AT seal time ----------------------
        for label, kind in [
            ("dirty TRACKED source refused BEFORE execution (--preflight)", "preflight-t"),
            ("dirty UNTRACKED source refused BEFORE execution (--preflight)", "preflight-u"),
            ("dirty source refused at seal time (no opt-out)", "seal-dirty"),
            ("caller-lied --server-sha256 refused at seal time", "seal-lie"),
            ("provider binary off the source lock refused at seal time", "seal-unlocked"),
            ("truncated phases.tsv refused at seal time", "seal-truncate"),
        ]:
            b = build_base(tmp / f"seal-{kind}")
            if kind == "preflight-t":
                m_dirty_tracked_source(b)
                r = subprocess.run(
                    [sys.executable, str(SEAL), "--preflight", "--repo", str(b["repo"])],
                    capture_output=True,
                    text=True,
                )
                ok = r.returncode != 0 and "working tree is dirty" in r.stderr
            elif kind == "preflight-u":
                m_dirty_untracked_exec_source(b)
                r = subprocess.run(
                    [sys.executable, str(SEAL), "--preflight", "--repo", str(b["repo"])],
                    capture_output=True,
                    text=True,
                )
                ok = r.returncode != 0 and "working tree is dirty" in r.stderr
            elif kind == "seal-dirty":
                m_dirty_tracked_source(b)
                r = seal(b)
                ok = r.returncode != 0 and "working tree is dirty" in r.stderr
            elif kind == "seal-lie":
                r = seal(b, server_sha256="d" * 64)
                ok = r.returncode != 0 and "caller claimed" in r.stderr
            elif kind == "seal-unlocked":
                b["provider"].write_bytes(b"a provider binary nobody locked\n")
                r = seal(b)
                ok = r.returncode != 0 and "source-lock" in r.stderr
            else:  # seal-truncate
                tsv = b["evidence"] / "phases.tsv"
                tsv.write_text(
                    "".join(
                        line + "\n"
                        for line in tsv.read_text().splitlines()
                        if not line.startswith("crash-restart")
                    )
                )
                r = seal(b)
                ok = r.returncode != 0 and "phase list" in r.stderr
            report(results, label, ok, (r.stderr.strip().splitlines() or ["<no output>"])[0])
            shutil.rmtree(b["root"], ignore_errors=True)

        # ---- mutants that must be present before sealing -----------------
        for name, fn, expect in PRE_SEAL_MUTANTS:
            b = build_base(tmp / f"pre-{abs(hash(name))}")
            fn(b)
            r = seal(b, allow_dirty=True)
            if r.returncode != 0:
                report(
                    results,
                    name,
                    False,
                    f"seal unexpectedly refused under --allow-dirty: {r.stderr.strip()}",
                )
            else:
                v = verify(b)
                reasons = refusal_reasons(v)
                hit = next((x for x in reasons if expect in x), None)
                report(
                    results,
                    name,
                    v.returncode != 0 and hit is not None,
                    hit or (reasons[0] if reasons else v.stdout.strip() or "<no output>"),
                )
                stamp = load(b["evidence"])
                if stamp.get("qualification") is not False:
                    report(
                        results,
                        name + " [stamped non-qualification]",
                        False,
                        "bundle was not stamped qualification=false",
                    )
            shutil.rmtree(b["root"], ignore_errors=True)

        # ---- mutants applied to a clone of the sealed control ------------
        for i, (name, fn, vargs, expect) in enumerate(POST_SEAL_MUTANTS):
            b = clone_sealed(control, tmp / f"post-{i:02d}")
            fn(b)
            v = verify(b, vargs)
            reasons = refusal_reasons(v)
            hit = next((x for x in reasons if expect in x), None)
            report(
                results,
                name,
                v.returncode != 0 and hit is not None,
                hit or (reasons[0] if reasons else v.stdout.strip() or "<no output>"),
            )
            shutil.rmtree(b["root"], ignore_errors=True)

        # ---- reproduction control ----------------------------------------
        fresh = build_base(tmp / "fresh-checkout", racer_bytes=b"a differently built cas_racer\n")
        r = seal(fresh)
        second = (
            load(fresh["evidence"])["attestation"]["stable_root"] if r.returncode == 0 else None
        )
        if second and second == control_stable:
            print()
            print(
                "POSITIVE CONTROL: a fresh clean checkout — different paths, git history, "
                "seal time and racer build —"
            )
            print(f"   reproduces stable_root {second}")
        else:
            print(
                f"POSITIVE CONTROL FAILED — stable root not reproducible: "
                f"{control_stable} vs {second}"
            )
            results.append(
                (
                    "stable-root reproduction across a fresh checkout",
                    False,
                    f"{control_stable} != {second}",
                )
            )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    killed = [r for r in results if r[1]]
    survived = [r for r in results if not r[1]]
    print()
    print(
        f"evidence mutants: {len(killed)} killed, {len(survived)} survived "
        f"(of {len(results)} executed)"
    )
    if survived:
        print("SURVIVING MUTANTS — the evidence chain is false-green:")
        for name, _, reason in survived:
            print(f"  - {name}: {reason}")
        return 1
    print("EVIDENCE MUTANTS: ALL KILLED")
    return 0


if __name__ == "__main__":
    os.environ.pop("S3_CERT_ALLOW_DIRTY", None)
    sys.exit(run_all())
