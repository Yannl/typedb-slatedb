#!/usr/bin/env python3
"""R6-PORT-01 - one immutable release identity, resolvable in every posture.

The round-6 audit materialised the repository with `git archive` (no `.git`)
and two of the 26 probe controls failed, because preflight and the approval
suite resolve the release commit by shelling out to `git rev-parse HEAD`.
A source release without `.git` could not prove its own identity, so the
approval envelope - which is BOUND to the release commit - could not be
validated at all.

The fix is not "require a checkout". It is to make the identity a build
artifact that travels with the source:

  posture              where the identity comes from            verified?
  -------------------- ---------------------------------------- ---------
  git checkout         `git rev-parse HEAD` (authoritative)      by git
  git archive          RELEASE-IDENTITY.json, `$Format:%H$`      by git at export
                       expanded by git's `export-subst`
  release tarball      RELEASE-IDENTITY.json written by          by identity_digest
  / installed package  `--generate`, carrying identity_digest    (and by the
                                                                 release manifest
                                                                 that records it)
  none of the above    typed SOURCE_IDENTITY_UNAVAILABLE         n/a - refuse

The last row matters as much as the others: a posture with no identity must
REFUSE, never guess a commit and never silently continue with "UNKNOWN".

Usage
-----
    release_identity.py                       # resolve and print the identity
    release_identity.py --json                # machine-readable
    release_identity.py --require-verified    # fail unless the identity is
                                              # git-authoritative or digest-verified
    release_identity.py --generate --out DIR  # write a populated, digest-bound
                                              # RELEASE-IDENTITY.json (release build)
    release_identity.py --check               # the committed template is well-formed
                                              # and .gitattributes marks it export-subst

Exit codes: 0 resolved (and verified, under --require-verified), 1 refused, 2 usage.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
IDENTITY_FILENAME = "RELEASE-IDENTITY.json"
SCHEMA = "typedb-r2/release-identity@1"
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
PLACEHOLDER_RE = re.compile(r"^\$Format:.*\$$")

# `identity_digest` is computed over the body WITHOUT itself; `note` is prose
# and is excluded so wording can be improved without breaking a signed digest.
DIGEST_EXCLUDED = ("identity_digest", "note")


class SourceIdentityUnavailable(Exception):
    """No posture could establish the release commit. Refuse; do not guess."""


def canonical_digest(body: dict) -> str:
    payload = {k: v for k, v in body.items() if k not in DIGEST_EXCLUDED}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _git(root: Path, *args: str) -> str | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return out.stdout.strip()


def resolve(root: Path | None = None) -> dict:
    """Resolve the release identity for whatever posture this tree is in.

    Returns {release_commit, posture, verified, dirty_paths, detail}.
    Raises SourceIdentityUnavailable when nothing can establish it.
    """
    root = Path(root or REPO_ROOT)

    # 1. A real checkout is authoritative: it can also report dirtiness, which
    #    an archive can never do, so it always wins when it is available.
    head = _git(root, "rev-parse", "HEAD")
    if head and SHA1_RE.match(head):
        status = _git(root, "status", "--porcelain")
        dirty = len([ln for ln in (status or "").splitlines() if ln.strip()]) if status is not None else None
        return {
            "release_commit": head,
            "posture": "git-checkout",
            "verified": True,
            "dirty_paths": dirty,
            "detail": "resolved from git HEAD in a working checkout",
        }

    # 2. No .git. The identity file is the only thing that can speak.
    path = root / IDENTITY_FILENAME
    try:
        body = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SourceIdentityUnavailable(
            f"no .git and no {IDENTITY_FILENAME}: this materialisation cannot prove which "
            f"commit it is. Re-materialise from a checkout, from `git archive` (which expands "
            f"the identity file), or from a release tarball built by "
            f"`tools/release/release_identity.py --generate`."
        )
    except json.JSONDecodeError as exc:
        raise SourceIdentityUnavailable(f"{IDENTITY_FILENAME} is not valid JSON: {exc}")

    if body.get("schema") != SCHEMA:
        raise SourceIdentityUnavailable(f"{IDENTITY_FILENAME} schema is {body.get('schema')!r}, expected {SCHEMA!r}")

    commit = body.get("release_commit")
    if isinstance(commit, str) and PLACEHOLDER_RE.match(commit):
        raise SourceIdentityUnavailable(
            f"{IDENTITY_FILENAME} still carries the unexpanded {commit} placeholder and there is no "
            f"`.git` to fall back to. This tree was copied out of a checkout rather than exported: "
            f"`git archive` would have expanded it (see .gitattributes export-subst), and a release "
            f"build would have populated it."
        )
    if not isinstance(commit, str) or not SHA1_RE.match(commit):
        raise SourceIdentityUnavailable(f"{IDENTITY_FILENAME} release_commit is not a 40-hex commit: {commit!r}")

    digest = body.get("identity_digest")
    if digest is None:
        # git-archive posture: git itself expanded the token at export time, so
        # the value is trustworthy exactly as far as the archive is, and there
        # is nothing extra to verify. Say so rather than implying more.
        return {
            "release_commit": commit,
            "posture": body.get("provenance", "git-archive-export-subst"),
            "verified": False,
            "dirty_paths": None,
            "detail": "expanded by git at archive-export time; no identity_digest to re-verify",
        }

    recomputed = canonical_digest(body)
    if recomputed != digest:
        raise SourceIdentityUnavailable(
            f"{IDENTITY_FILENAME} identity_digest does not match its own body "
            f"(recorded {digest}, recomputed {recomputed}) - the identity file has been altered"
        )
    return {
        "release_commit": commit,
        "posture": body.get("provenance", "release-artifact"),
        "verified": True,
        "dirty_paths": body.get("dirty_paths"),
        "detail": "identity_digest recomputed from the file's canonical body and matched",
    }


def generate(root: Path, out_dir: Path) -> dict:
    """Write a populated, digest-bound identity file for a release artifact."""
    head = _git(root, "rev-parse", "HEAD")
    if not head or not SHA1_RE.match(head):
        raise SourceIdentityUnavailable(
            "a release identity can only be GENERATED from a real checkout - "
            "that is the only posture that knows the commit and the tree state"
        )
    tree = _git(root, "rev-parse", "HEAD^{tree}")
    status = _git(root, "status", "--porcelain") or ""
    dirty = [ln[3:] for ln in status.splitlines() if ln.strip()]
    body = {
        "schema": SCHEMA,
        "provenance": "release-artifact",
        "release_commit": head,
        "release_commit_short": head[:12],
        "release_tree": tree,
        "committed_at": _git(root, "show", "-s", "--format=%cI", "HEAD"),
        "refnames": _git(root, "log", "-1", "--format=%D") or "",
        "dirty_paths": dirty,
        "identity_digest": None,
        "note": (
            "Generated by tools/release/generate_release_identity.py for a release artifact. "
            "identity_digest is sha256 over this body with `identity_digest` and `note` removed, "
            "serialised as compact sorted JSON. The release artifact manifest records this digest, "
            "so altering the identity invalidates the signed artifact."
        ),
    }
    body["identity_digest"] = canonical_digest(body)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / IDENTITY_FILENAME).write_text(json.dumps(body, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return body


def check_template(root: Path) -> list[str]:
    """The committed template must stay a template, and stay export-subst'd."""
    problems: list[str] = []
    path = root / IDENTITY_FILENAME
    try:
        body = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return [f"{IDENTITY_FILENAME} is not committed - `git archive` would carry no identity at all"]
    except json.JSONDecodeError as exc:
        return [f"{IDENTITY_FILENAME} is not valid JSON: {exc}"]

    if body.get("schema") != SCHEMA:
        problems.append(f"{IDENTITY_FILENAME} schema must be {SCHEMA!r}")
    for field in ("release_commit", "release_commit_short", "committed_at", "refnames"):
        value = body.get(field)
        if not (isinstance(value, str) and PLACEHOLDER_RE.match(value)):
            problems.append(
                f"{IDENTITY_FILENAME} field {field!r} must stay an unexpanded $Format:...$ placeholder "
                f"in the committed template (found {value!r}); a hardcoded commit here would make every "
                f"future export claim one stale identity"
            )
    if body.get("identity_digest") is not None:
        problems.append(f"{IDENTITY_FILENAME} identity_digest must be null in the committed template")

    attrs = root / ".gitattributes"
    if not attrs.exists():
        problems.append(".gitattributes is missing, so `git archive` will not expand the identity tokens")
    elif not re.search(rf"^{re.escape(IDENTITY_FILENAME)}\s+export-subst\s*$", attrs.read_text(encoding="utf-8"), re.M):
        problems.append(f".gitattributes does not mark {IDENTITY_FILENAME} `export-subst`")
    return problems


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=str(REPO_ROOT))
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--require-verified", action="store_true")
    ap.add_argument("--generate", action="store_true")
    ap.add_argument("--out", help="output directory for --generate (default: --root)")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args(argv)
    root = Path(args.root).resolve()

    if args.check:
        problems = check_template(root)
        if problems:
            print("RELEASE IDENTITY TEMPLATE: FAIL")
            for p in problems:
                print(f"  - {p}")
            return 1
        print("RELEASE IDENTITY TEMPLATE: PASS (placeholders intact, export-subst declared)")
        return 0

    try:
        if args.generate:
            body = generate(root, Path(args.out) if args.out else root)
            print(json.dumps(body, indent=2) if args.json else
                  f"wrote {IDENTITY_FILENAME}: {body['release_commit']} "
                  f"(digest {body['identity_digest'][:16]}…, dirty_paths {len(body['dirty_paths'])})")
            return 0
        ident = resolve(root)
    except SourceIdentityUnavailable as exc:
        print(json.dumps({"outcome": "SOURCE_IDENTITY_UNAVAILABLE", "detail": str(exc)}, indent=2)
              if args.json else f"SOURCE_IDENTITY_UNAVAILABLE: {exc}", file=sys.stderr)
        return 1

    if args.require_verified and not ident["verified"]:
        print(f"RELEASE IDENTITY NOT VERIFIED: {ident['detail']}", file=sys.stderr)
        return 1
    print(json.dumps(ident, indent=2) if args.json else
          f"{ident['release_commit']}  posture={ident['posture']} verified={ident['verified']} "
          f"dirty_paths={ident['dirty_paths']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
