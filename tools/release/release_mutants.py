#!/usr/bin/env python3
"""Executed mutants for the release pipeline (round-6 R6-QUAL-01).

Each mutant is a specific way someone could promote something that was not
actually built, tested and signed. A mutant is KILLED when the pipeline
refuses it with the expected typed code. A mutant that survives is a hole,
and this suite exits non-zero if any survives.

The mutants operate on a REAL promoted release directory, copied to a
temporary tree and tampered with there — never on a synthetic fixture that
might not resemble what the tool actually writes.

usage:
  python3 tools/release/release_mutants.py --source <releases-dir>/<digest>
  python3 tools/release/release_mutants.py            # finds the newest
"""
import argparse
import contextlib
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
import ed25519_ref as ed  # noqa: E402
import release as rel  # noqa: E402

DEFAULT_RELEASES = REPO / "docs" / "evidence" / "G3" / "releases"


def run(argv):
    """Run the CLI in-process; return (exit_code, stdout+stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = rel.main(argv)
        except SystemExit as e:      # argparse
            code = e.code if isinstance(e.code, int) else 1
    return code, out.getvalue() + err.getvalue()


class Suite:
    def __init__(self, source):
        self.source = pathlib.Path(source).resolve()
        self.digest = self.source.name
        self.killed = []
        self.survived = []

    @contextlib.contextmanager
    def tampered(self, name):
        """A private copy of the release directory to mutate."""
        with tempfile.TemporaryDirectory(prefix=f"release-mutant-{name}-") as tmp:
            releases = pathlib.Path(tmp) / "releases"
            (releases).mkdir()
            shutil.copytree(self.source, releases / self.digest)
            yield releases

    def expect(self, name, argv, code_fragment, expect_exit=(1, 2)):
        exit_code, text = run(argv)
        if exit_code in expect_exit and code_fragment in text:
            self.killed.append(name)
            print(f"KILLED   {name}: {code_fragment}")
        else:
            self.survived.append((name, exit_code, text.strip()[:400]))
            print(f"SURVIVED {name}: expected {code_fragment!r}, "
                  f"got exit={exit_code}\n{text.strip()[:400]}")

    def verify_argv(self, releases, extra=()):
        return ["--releases", str(releases), "verify", "--digest", self.digest,
                *extra]


def edit_json(path, mutate):
    doc = json.loads(path.read_text())
    mutate(doc)
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default=None,
                    help="a promoted release directory to mutate")
    args = ap.parse_args()

    source = args.source
    if source is None:
        candidates = [d for d in sorted(DEFAULT_RELEASES.glob("*"))
                      if (d / "promotion.json").exists()]
        if not candidates:
            print("no promoted release found; run build/test/promote first",
                  file=sys.stderr)
            return 2
        source = candidates[-1]
    s = Suite(source)
    print(f"mutating a copy of {s.source.relative_to(REPO)}\n")

    # a promoted, untampered copy must VERIFY — otherwise every kill below
    # would be meaningless (the "refuses everything" degenerate suite)
    with s.tampered("control") as releases:
        code, text = run(s.verify_argv(releases))
        if code != 0:
            print(f"CONTROL FAILED: an untampered copy did not verify "
                  f"(exit={code})\n{text}", file=sys.stderr)
            return 2
        print("CONTROL  untampered copy verifies (exit 0)\n")

    d = s.digest

    # --- lane result tampering ------------------------------------------
    def make_lane_fail(r, lane, verdict_word):
        """Turn a passing lane into a consistently-recorded FAILING lane.

        Used as the STARTING POINT for the mutants that matter: laundering a
        red lane is only interesting when the red lane is otherwise
        self-consistent, so the pipeline cannot dismiss it on some unrelated
        integrity error.
        """
        log = r / d / f"lanes/{lane}.log"
        log.write_text(log.read_text().replace(f"{verdict_word}: PASS",
                                               f"{verdict_word}: FAIL"))
        digest_now = rel.sha256_file(log)
        edit_json(r / d / f"lanes/{lane}.json",
                  lambda doc: doc.update(passed=False, attempt=1,
                                         log_sha256=digest_now))
        (r / d / f"lanes/{lane}.attempts.jsonl").write_text(json.dumps(
            {"attempt": 1, "artifact_sha256": d, "passed": False,
             "log_sha256": digest_now}, sort_keys=True,
            separators=(",", ":")) + "\n")
        (r / d / "promotion.json").unlink()
        (r / d / "signature.json").unlink()
        return digest_now

    with s.tampered("lane-json-flip") as r:
        # a genuinely failing lane, then the JSON alone edited to green, then
        # promoted so the signature covers the lie: only re-deriving the
        # verdict from the log's own bytes catches this
        log_digest = make_lane_fail(r, "artifact-exec", "exec")
        edit_json(r / d / "lanes/artifact-exec.json",
                  lambda doc: doc.update(passed=True))
        (r / d / "lanes/artifact-exec.attempts.jsonl").write_text(json.dumps(
            {"attempt": 1, "artifact_sha256": d, "passed": True,
             "log_sha256": log_digest}, sort_keys=True,
            separators=(",", ":")) + "\n")
        s.expect("failing lane laundered by editing its JSON verdict",
                 ["--releases", str(r), "promote", "--digest", d,
                  "--key-id", "dev-public"], "LANE_VERDICT_CONTRADICTION")

    with s.tampered("lane-log-edit") as r:
        p = r / d / "lanes/artifact-layout.log"
        p.write_text(p.read_text().replace("layout: PASS", "layout: PASS\nextra"))
        s.expect("lane log bytes edited", s.verify_argv(r), "LANE_LOG_UNBOUND")

    with s.tampered("lane-log-edit-rehash") as r:
        p = r / d / "lanes/artifact-layout.log"
        p.write_text(p.read_text() + "tampered\n")
        edit_json(r / d / "lanes/artifact-layout.json",
                  lambda doc: doc.update(log_sha256=rel.sha256_file(p)))
        s.expect("lane log edited AND re-hashed", s.verify_argv(r), "ROOT_MISMATCH")

    with s.tampered("lane-missing") as r:
        (r / d / "lanes/artifact-health.json").unlink()
        s.expect("required lane result deleted", s.verify_argv(r),
                 "REQUIRED_LANE_MISSING")

    with s.tampered("lane-foreign-artifact") as r:
        edit_json(r / d / "lanes/artifact-exec.json",
                  lambda doc: doc.update(artifact_sha256="0" * 64))
        s.expect("lane bound to another artifact", s.verify_argv(r),
                 "LANE_BOUND_TO_OTHER_ARTIFACT")

    with s.tampered("lane-rebuilt-during") as r:
        edit_json(r / d / "lanes/artifact-exec.json",
                  lambda doc: doc.update(artifact_sha256_after="0" * 64))
        s.expect("artifact changed during the lane", s.verify_argv(r),
                 "LANE_BOUND_TO_OTHER_ARTIFACT")

    # --- attempt ledger --------------------------------------------------
    with s.tampered("attempts-removed") as r:
        (r / d / "lanes/artifact-exec.attempts.jsonl").unlink()
        s.expect("attempt ledger deleted", s.verify_argv(r),
                 "LANE_ATTEMPTS_MISSING")

    def add_retry(r, lane):
        """Make `lane` look like it needed two attempts, consistently."""
        log_digest = rel.sha256_file(r / d / f"lanes/{lane}.log")
        (r / d / f"lanes/{lane}.attempts.jsonl").write_text("".join(
            json.dumps({"attempt": i, "artifact_sha256": d, "passed": True,
                        "log_sha256": log_digest},
                       sort_keys=True, separators=(",", ":")) + "\n"
            for i in (1, 2)))
        edit_json(r / d / f"lanes/{lane}.json", lambda doc: doc.update(attempt=2))

    with s.tampered("attempts-truncated") as r:
        # a lane that really needed two attempts, then the ledger truncated
        # so the retry disappears: the stored result no longer IS the last
        # recorded attempt, which is the only thing that makes retries
        # visible at all
        (r / d / "promotion.json").unlink()
        (r / d / "signature.json").unlink()
        add_retry(r, "artifact-layout")
        p = r / d / "lanes/artifact-layout.attempts.jsonl"
        p.write_text(p.read_text().splitlines()[0] + "\n")
        s.expect("retry hidden by truncating the attempt ledger",
                 ["--releases", str(r), "promote", "--digest", d,
                  "--key-id", "dev-public"], "LANE_RESULT_NOT_LAST_ATTEMPT")

    with s.tampered("attempts-retry-visible") as r:
        # the honest case: a retried lane may still promote, but the retry
        # must be a recorded release-grade blocker rather than invisible
        (r / d / "promotion.json").unlink()
        (r / d / "signature.json").unlink()
        add_retry(r, "artifact-layout")
        code, text = run(["--releases", str(r), "promote", "--digest", d,
                          "--key-id", "dev-public"])
        if code != 0:
            print(f"SURVIVED honest retry could not promote at all: {text[:300]}")
            s.survived.append(("retried lane promotes but is flagged", code,
                               text[:300]))
        else:
            s.expect("retried lane is flagged, not hidden",
                     s.verify_argv(r, ("--release-grade",)),
                     "LANE_RETRIED(artifact-layoutx2)")

    # --- directory / root ------------------------------------------------
    with s.tampered("junk-file") as r:
        (r / d / "notes.txt").write_text("an unaccounted file\n")
        s.expect("unaccounted file added to the release directory",
                 s.verify_argv(r), "ROOT_MISMATCH")

    with s.tampered("record-edited") as r:
        edit_json(r / d / "release.json",
                  lambda doc: doc["artifact"].update(member_root="f" * 64))
        s.expect("release record edited after signing", s.verify_argv(r),
                 "ROOT_MISMATCH")

    with s.tampered("promotion-edited") as r:
        edit_json(r / d / "promotion.json",
                  lambda doc: doc.update(promotion_class="RELEASE"))
        s.expect("promotion class upgraded after signing", s.verify_argv(r),
                 "ROOT_MISMATCH")

    # --- signature -------------------------------------------------------
    with s.tampered("signature-forged") as r:
        # 64 bytes of well-formed but wrong signature: a length-invalid
        # value would be rejected as malformed before either implementation
        # got to judge it, which would test nothing
        edit_json(r / d / "signature.json",
                  lambda doc: doc.update(signature="ab" * 64))
        s.expect("signature bytes replaced", s.verify_argv(r), "SIGNATURE_INVALID")

    with s.tampered("signature-removed") as r:
        (r / d / "signature.json").unlink()
        s.expect("signature deleted", s.verify_argv(r), "PROMOTION_UNSIGNED")

    with s.tampered("signature-other-key") as r:
        # a VALID signature over the same root, by a key nobody trusts
        rogue_seed = bytes(range(32))
        sig = r / d / "signature.json"
        doc = json.loads(sig.read_text())
        msg = doc["signed_message"].encode()
        doc["public_key"] = ed.public_key(rogue_seed).hex()
        doc["signature"] = ed.sign(rogue_seed, msg).hex()
        sig.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
        s.expect("valid signature by an untrusted key", s.verify_argv(r),
                 "SIGNING_KEY_SUBSTITUTED")

    with s.tampered("signature-unknown-key-id") as r:
        edit_json(r / d / "signature.json",
                  lambda doc: doc.update(key_id="not-a-registered-key"))
        s.expect("signature claiming an unregistered key id", s.verify_argv(r),
                 "UNTRUSTED_SIGNING_KEY")

    with s.tampered("signature-second-opinion") as r:
        # the two Ed25519 implementations must agree; point the independent
        # one at a stub that always disagrees
        stub = pathlib.Path(r).parent / "always-not-verified.mjs"
        stub.write_text('process.stdout.write("NOT_VERIFIED\\n");\n')
        original = rel.NODE_ED25519
        rel.NODE_ED25519 = stub
        try:
            s.expect("independent verifier disagrees with the Python one",
                     s.verify_argv(r), "SIGNATURE_IMPLEMENTATION_DISAGREEMENT")
        finally:
            rel.NODE_ED25519 = original

    with s.tampered("signature-second-opinion-absent") as r:
        original = rel.NODE_ED25519
        rel.NODE_ED25519 = pathlib.Path("/nonexistent/ed25519_node.mjs")
        try:
            s.expect("independent verifier unavailable", s.verify_argv(r),
                     "SIGNATURE_SECOND_OPINION_UNAVAILABLE")
        finally:
            rel.NODE_ED25519 = original

    # --- artifact identity ----------------------------------------------
    with s.tampered("artifact-substituted") as r:
        with tempfile.TemporaryDirectory() as tmp:
            fake = pathlib.Path(tmp) / "typedb-all-linux-x86_64.tar.gz"
            with tarfile.open(fake, "w:gz") as tf:
                member = tarfile.TarInfo("typedb-all-linux-x86_64-0.0.0/LICENSE")
                member.size = 5
                tf.addfile(member, io.BytesIO(b"hello"))
            s.expect("a different artifact presented under this digest",
                     s.verify_argv(r, ("--artifact", str(fake))),
                     "ARTIFACT_DIGEST_MISMATCH")

    # --- promotion preconditions -----------------------------------------
    with s.tampered("promote-failing-lane") as r:
        make_lane_fail(r, "artifact-exec", "exec")
        s.expect("promotion attempted with a failing required lane",
                 ["--releases", str(r), "promote", "--digest", d,
                  "--key-id", "dev-public"], "REQUIRED_LANE_FAILED")

    with s.tampered("promote-unknown-key") as r:
        (r / d / "promotion.json").unlink()
        (r / d / "signature.json").unlink()
        s.expect("promotion with an unregistered signing key",
                 ["--releases", str(r), "promote", "--digest", d,
                  "--key-id", "attacker-key"], "UNTRUSTED_SIGNING_KEY")

    with s.tampered("release-grade-development") as r:
        s.expect("development-class promotion claimed as release grade",
                 s.verify_argv(r, ("--release-grade",)),
                 "PROMOTION_CLASS_DEVELOPMENT")

    with s.tampered("record-immutable") as r:
        edit_json(r / d / "release.json",
                  lambda doc: doc.update(state="TAMPERED"))
        s.expect("rebuilding over an existing record with new content",
                 ["--releases", str(r), "build"], "RELEASE_RECORD_IMMUTABLE",
                 expect_exit=(2,))

    # --- lane implementation binding -------------------------------------
    with s.tampered("lane-not-implemented") as r:
        s.expect("a required lane that names no implementation",
                 s.verify_argv(r, ("--require", "artifact-layout,/bin/true")),
                 "LANE_NOT_IMPLEMENTED", expect_exit=(2,))

    print()
    print(f"release mutants: {len(s.killed)} killed, {len(s.survived)} survived")
    for name, code, text in s.survived:
        print(f"  SURVIVED {name} (exit {code})")
    return 1 if s.survived else 0


if __name__ == "__main__":
    sys.exit(main())
