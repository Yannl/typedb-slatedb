#!/usr/bin/env python3
"""Build once, test THAT artifact, promote by digest (round-6 R6-QUAL-01).

The audit's release requirement is one sentence: "Produce an immutable
release artifact once, test that exact artifact, and promote by digest."
Everything here exists to make the three verbs impossible to fake:

  build     hashes the artifact and writes an IMMUTABLE record under
            docs/evidence/G3/releases/<artifact-sha256>/. The digest is the
            directory name, so a rebuild is a different release, never an
            update of this one. Re-running build on identical bytes is a
            no-op; re-running it on different bytes under the same name is
            refused.
  test      runs one named lane against the artifact identified BY DIGEST.
            The artifact is re-hashed before and after the lane, so a
            rebuild during the lane is caught rather than silently
            attributed to the old digest. Results are bound to the digest.
  promote   refuses unless the record exists, the artifact still hashes to
            the digest, EVERY required lane has a passing result bound to
            this exact digest, and the evidence root is signed by a trusted
            key. Promotion never names a branch, a tag or a path — only the
            digest.
  verify    re-derives all of it from the bytes, including re-parsing each
            lane log's own verdict line rather than trusting the JSON, and
            checks the root signature with TWO independent Ed25519
            implementations (pure Python here, Node's crypto there), failing
            closed if they disagree.

Honesty constraints this tool enforces rather than documents:

  * `--release-grade` refuses a SYNTHETIC profile (a run with overridden
    artifact or required-lane set), a development-class signing key, an
    unbound source identity, and a dirty working tree. There is currently
    NO production key in tools/release/trusted-release-keys.json, so a
    release-grade promotion is structurally impossible today — which is the
    true state of this repository, not a limitation of this tool.
  * this pipeline qualifies an ARTIFACT, not the product. It says nothing
    about the 23,138-row leaf plan, Mode Q or the official driver lanes.
"""

import argparse
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import sys
import tarfile
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import ed25519_ref as ed  # noqa: E402
import lanes as lanes_mod  # noqa: E402
import release_identity  # noqa: E402

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]
NODE_ED25519 = HERE / "ed25519_node.mjs"
DEFAULT_ARTIFACT = REPO / "sources" / "assembly-artifacts" / "typedb-all-linux-x86_64.tar.gz"
DEFAULT_RELEASES = REPO / "docs" / "evidence" / "G3" / "releases"
LANE_MANIFEST = HERE / "required-lanes.json"
TRUSTED_KEYS = HERE / "trusted-release-keys.json"
SOURCE_LOCK = REPO / "source-lock" / "source-lock.json"
SIGNATURE_FILE = "signature.json"


class Refusal(Exception):
    """A typed refusal. The message starts with a stable UPPER_SNAKE code."""


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def canonical(obj):
    """Canonical JSON bytes: sorted keys, no insignificant whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def write_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def member_root(tar_path):
    """Digest over the artifact's MEMBERS, not just its compressed bytes.

    Two tarballs can differ byte-for-byte (gzip mtime, member order) while
    shipping identical content, and — far more dangerous — a re-tar can
    keep a familiar-looking name while swapping one member. This root is
    computed over `name\\0mode\\0size\\0sha256` of every regular member, so
    it is stable across repacking and sensitive to any content or
    permission change.
    """
    lines = []
    with tarfile.open(tar_path, "r:*") as tf:
        for member in tf:
            if member.isdir():
                continue
            if not member.isfile():
                raise Refusal(
                    f"ARTIFACT_NON_REGULAR_MEMBER {member.name} "
                    f"(type={member.type!r}) — an artifact must contain only "
                    "directories and regular files"
                )
            fh = tf.extractfile(member)
            h = hashlib.sha256()
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
            lines.append(f"{member.name}\0{member.mode:o}\0{member.size}\0{h.hexdigest()}\n")
    return sha256_bytes("".join(sorted(lines)).encode("utf-8")), len(lines)


def git(*argv):
    try:
        r = subprocess.run(
            ["git", "-C", str(REPO), *argv], capture_output=True, text=True, timeout=120
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout.strip() if r.returncode == 0 else None


def source_identity():
    """Commit/tree/dirt of the tree that produced the artifact.

    R6-PORT-01: a `git archive` materialisation has no `.git`, so git is
    allowed to be absent. The first version of this function then fell back
    to `RELEASE_SOURCE_COMMIT`/`RELEASE_SOURCE_TREE`, which is an
    UNAUTHENTICATED channel: anyone able to set an environment variable
    could name the commit a release claims to be cut from. Those variables
    are now a last resort recorded as such, and the preferred archive
    source is `tools/release/release_identity.py`, whose RELEASE-IDENTITY.json
    is bound by a digest over its own body.

    `bound_by` records which of the three actually spoke, and anything
    weaker than git or a verified identity file is a release-grade blocker
    rather than a silent equivalence.
    """
    commit = git("rev-parse", "HEAD")
    tree = git("rev-parse", "HEAD^{tree}")

    identity, identity_digest, identity_verified = None, None, False
    try:
        identity = release_identity.resolve(REPO)
    except Exception:  # noqa: BLE001
        # An unresolvable identity is a normal posture (a bare tarball), not
        # an error here: it simply leaves the identity unbound below.
        identity = None
    if identity is not None:
        identity_verified = bool(identity.get("verified"))
        identity_digest = identity.get("identity_digest")
        if commit and identity.get("release_commit") and commit != identity["release_commit"]:
            raise Refusal(
                f"SOURCE_IDENTITY_CONFLICT git={commit} identity-file={identity['release_commit']}"
            )

    env_commit = os.environ.get("RELEASE_SOURCE_COMMIT") or None
    env_tree = os.environ.get("RELEASE_SOURCE_TREE") or None
    if commit and env_commit and commit != env_commit:
        raise Refusal(f"SOURCE_IDENTITY_CONFLICT git={commit} env={env_commit}")
    if tree and env_tree and tree != env_tree:
        raise Refusal(f"SOURCE_TREE_CONFLICT git={tree} env={env_tree}")
    if identity is not None and env_commit and identity.get("release_commit") != env_commit:
        raise Refusal(
            f"SOURCE_IDENTITY_CONFLICT identity-file="
            f"{identity.get('release_commit')} env={env_commit}"
        )

    status = git("status", "--porcelain")
    dirty = sorted(line[3:] for line in status.splitlines()) if status else []
    if identity is not None and status is None and identity.get("dirty_paths") is not None:
        dirty = [f"(identity-file reports {identity['dirty_paths']} dirty paths)"]

    if commit:
        bound_by = "git"
    elif identity is not None and identity.get("release_commit"):
        bound_by = "release-identity-file"
    elif env_commit:
        bound_by = "environment"  # unauthenticated
    else:
        bound_by = None

    return {
        "commit": commit or (identity or {}).get("release_commit") or env_commit,
        "tree": tree or env_tree,
        "bound_by": bound_by,
        "identity_posture": (identity or {}).get("posture"),
        "identity_verified": identity_verified,
        "identity_digest": identity_digest,
        "dirty_paths": dirty,
        "dirty_paths_known": status is not None
        or (identity is not None and identity.get("dirty_paths") is not None),
        "source_lock_sha256": (sha256_file(SOURCE_LOCK) if SOURCE_LOCK.exists() else None),
    }


def toolchain_identity():
    def ver(argv):
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            return None
        return (r.stdout + r.stderr).strip().splitlines()[0] if (r.stdout or r.stderr) else None

    return {
        "python": sys.version.split()[0],
        "node": ver(["node", "--version"]),
        "cargo": ver(["cargo", "--version"]),
        "platform": f"{os.uname().sysname}-{os.uname().machine}",
    }


# --------------------------------------------------------------------------
# release directory model
# --------------------------------------------------------------------------


def release_dir(releases, digest):
    return pathlib.Path(releases) / digest


def release_files(rdir, exclude=(SIGNATURE_FILE,)):
    """Every file under the release dir, relative-posix, sorted."""
    out = []
    for p in sorted(rdir.rglob("*")):
        if p.is_dir():
            continue
        rel = p.relative_to(rdir).as_posix()
        if rel in exclude:
            continue
        out.append((rel, p))
    return out


def evidence_root(rdir):
    """sha256 over sorted "relpath\\0sha256\\n" of every file but the signature.

    Same algorithm the catalogue bundle root uses, for the same reason: the
    root binds every byte in the directory, so an added junk file, a
    removed lane, or an edited log all change it.
    """
    lines = [f"{rel}\0{sha256_file(p)}\n" for rel, p in release_files(rdir)]
    return sha256_bytes("".join(sorted(lines)).encode("utf-8")), len(lines)


def load_required_lanes(manifest_path):
    manifest = read_json(manifest_path)
    if manifest.get("schema") != "release-lanes/v1":
        raise Refusal(f"LANE_MANIFEST_SCHEMA {manifest.get('schema')!r}")
    ids = list(manifest["required"])
    unknown = [i for i in ids if i not in lanes_mod.LANES]
    if unknown:
        raise Refusal(
            f"LANE_NOT_IMPLEMENTED {unknown} — a lane id must name a Python "
            "implementation in tools/release/lanes.py; a manifest cannot "
            "introduce a lane by naming a command"
        )
    if not ids:
        raise Refusal(
            "LANE_MANIFEST_EMPTY — promotion with no required lane would be a promotion of nothing"
        )
    return ids


def load_trusted_keys():
    doc = read_json(TRUSTED_KEYS)
    if doc.get("schema") != "release-trusted-keys/v1":
        raise Refusal(f"TRUSTED_KEYS_SCHEMA {doc.get('schema')!r}")
    by_id = {}
    for entry in doc["keys"]:
        if entry["class"] not in ("production", "development-public"):
            raise Refusal(f"TRUSTED_KEY_CLASS {entry['class']!r}")
        if not (
            isinstance(entry["public_key"], str)
            and len(entry["public_key"]) == 64
            and all(c in "0123456789abcdef" for c in entry["public_key"])
        ):
            raise Refusal(f"TRUSTED_KEY_MALFORMED {entry['key_id']!r}")
        if entry["key_id"] in by_id:
            raise Refusal(f"TRUSTED_KEY_DUPLICATE {entry['key_id']!r}")
        by_id[entry["key_id"]] = entry
    return by_id


def resolve_seed(entry):
    """The 32-byte signing seed for a trusted key entry.

    A production seed may ONLY come from the environment: a repository path
    for a production key would mean the authority to promote is whatever
    the checkout says it is. The development-public key is the opposite by
    construction — its seed is committed in the clear precisely so it
    carries no authority.
    """
    env_name = f"RELEASE_SIGNING_SEED_FILE_{entry['key_id'].upper().replace('-', '_')}"
    path = os.environ.get(env_name) or os.environ.get("RELEASE_SIGNING_SEED_FILE")
    if path is None:
        if entry["class"] != "development-public":
            raise Refusal(
                f"RELEASE_SIGNING_KEY_ABSENT {entry['key_id']} — set {env_name} "
                "to a file holding the 32-byte hex seed; a production seed is "
                "never read from the repository"
            )
        path = REPO / entry["seed_file"]
    seed_path = pathlib.Path(path)
    if not seed_path.exists():
        raise Refusal(f"RELEASE_SIGNING_SEED_MISSING {seed_path}")
    if entry["class"] == "production":
        mode = stat.S_IMODE(seed_path.stat().st_mode)
        if mode & 0o077:
            raise Refusal(f"RELEASE_SIGNING_SEED_PERMISSIVE {seed_path} mode={mode:04o}")
    seed_hex = seed_path.read_text(encoding="utf-8").strip()
    if len(seed_hex) != 64 or any(c not in "0123456789abcdef" for c in seed_hex):
        raise Refusal(f"RELEASE_SIGNING_SEED_MALFORMED {seed_path}")
    seed = bytes.fromhex(seed_hex)
    if ed.public_key(seed).hex() != entry["public_key"]:
        raise Refusal(
            f"RELEASE_SIGNING_SEED_MISMATCH {entry['key_id']} — the seed does "
            "not derive the public key recorded in the trusted-key list"
        )
    return seed


def node_verify(pub_hex, msg, sig_hex):
    """Second opinion from Node's crypto; shares no code with ed25519_ref."""
    try:
        r = subprocess.run(
            ["node", str(NODE_ED25519), "verify", pub_hex, msg.hex(), sig_hex],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as err:
        return f"UNAVAILABLE:{err}"
    return r.stdout.strip() or f"NODE_ERROR:{r.stderr.strip()[:200]}"


def verify_signature_twice(pub_hex, msg, sig_hex):
    """True only when both implementations verify; a disagreement is fatal."""
    py = ed.verify(bytes.fromhex(pub_hex), msg, bytes.fromhex(sig_hex))
    node = node_verify(pub_hex, msg, sig_hex)
    if (
        node.startswith("UNAVAILABLE")
        or node.startswith("NODE_ERROR")
        or node.startswith("MALFORMED")
    ):
        raise Refusal(
            f"SIGNATURE_SECOND_OPINION_UNAVAILABLE {node} — the release root "
            "is verified by two independent implementations; one is not a "
            "quorum"
        )
    if py != (node == "VERIFIED"):
        raise Refusal(
            f"SIGNATURE_IMPLEMENTATION_DISAGREEMENT python={py} node={node} — "
            "one of the two Ed25519 implementations is wrong; refusing to "
            "guess which"
        )
    return py


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------


def cmd_build(args):
    artifact = pathlib.Path(args.artifact).resolve()
    if not artifact.exists():
        raise Refusal(f"ARTIFACT_MISSING {artifact}")
    digest = sha256_file(artifact)
    mroot, members = member_root(artifact)
    profile = "RELEASE" if artifact == DEFAULT_ARTIFACT.resolve() else "SYNTHETIC"
    record = {
        "schema": "release-artifact/v1",
        "profile": profile,
        "artifact": {
            "name": artifact.name,
            "sha256": digest,
            "size": artifact.stat().st_size,
            "member_root": mroot,
            "members": members,
        },
        "source": source_identity(),
        "toolchain": toolchain_identity(),
        "state": "BUILT",
    }
    rdir = release_dir(args.releases, digest)
    record_path = rdir / "release.json"
    if record_path.exists():
        existing = read_json(record_path)
        if canonical(existing) != canonical(record):
            raise Refusal(
                "RELEASE_RECORD_IMMUTABLE — a record for this digest exists "
                "with different content; a release is built once. Differing "
                "keys: "
                + ", ".join(
                    sorted(
                        k for k in set(existing) | set(record) if existing.get(k) != record.get(k)
                    )
                )
            )
        print(f"BUILD UNCHANGED {digest}")
        return 0
    write_json(record_path, record)
    print(f"BUILD {digest} profile={profile} members={members} member_root={mroot}")
    print(f"record: {record_path.relative_to(REPO)}")
    return 0


def cmd_test(args):
    artifact = pathlib.Path(args.artifact).resolve()
    if args.lane not in lanes_mod.LANES:
        raise Refusal(
            f"LANE_NOT_IMPLEMENTED {args.lane!r} — known lanes: {sorted(lanes_mod.LANES)}"
        )
    digest = args.digest or sha256_file(artifact)
    rdir = release_dir(args.releases, digest)
    if not (rdir / "release.json").exists():
        raise Refusal(
            f"RELEASE_NOT_BUILT {digest} — run `build` first; a lane "
            "result must attach to a recorded release"
        )
    before = sha256_file(artifact)
    if before != digest:
        raise Refusal(
            f"ARTIFACT_DIGEST_MISMATCH file={before} requested={digest} — the "
            "artifact on disk is not the one this release names. Testing the "
            "exact artifact is the point of the pipeline"
        )
    with tempfile.TemporaryDirectory(prefix="release-lane-") as tmp:
        extract = pathlib.Path(tmp) / "x"
        extract.mkdir()
        with tarfile.open(artifact, "r:*") as tf:
            for member in tf.getmembers():
                target = (extract / member.name).resolve()
                if not str(target).startswith(str(extract.resolve()) + os.sep):
                    raise Refusal(f"ARTIFACT_PATH_ESCAPE {member.name}")
            tf.extractall(extract)
        roots = [p for p in extract.iterdir()]
        tree = roots[0] if len(roots) == 1 and roots[0].is_dir() else extract
        passed, log = lanes_mod.LANES[args.lane](tree, read_json(rdir / "release.json"))
    after = sha256_file(artifact)
    if after != digest:
        raise Refusal(
            f"ARTIFACT_CHANGED_DURING_LANE before={digest} after={after} — the "
            "artifact was rebuilt while its own lane was running; this result "
            "belongs to neither digest"
        )
    log_rel = f"lanes/{args.lane}.log"
    log_path = rdir / log_rel
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(log + "\n", encoding="utf-8")
    log_digest = sha256_file(log_path)
    # Append-only attempt ledger. Re-running a lane until it goes green is
    # the oldest way to launder a flaky release, and overwriting the result
    # file would hide it completely. Every attempt is recorded; `verify`
    # requires the stored result to BE the last attempt and reports the
    # count, and a required lane that needed more than one attempt is a
    # release-grade blocker rather than an invisible retry.
    attempts_path = rdir / f"lanes/{args.lane}.attempts.jsonl"
    prior = (
        len(attempts_path.read_text(encoding="utf-8").strip().splitlines())
        if attempts_path.exists()
        else 0
    )
    attempt = {
        "attempt": prior + 1,
        "artifact_sha256": digest,
        "passed": bool(passed),
        "log_sha256": log_digest,
    }
    with open(attempts_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(attempt, sort_keys=True, separators=(",", ":")) + "\n")
    result = {
        "schema": "release-lane-result/v1",
        "lane": args.lane,
        "artifact_sha256": digest,
        "artifact_sha256_after": after,
        "passed": bool(passed),
        "attempt": prior + 1,
        "log_file": log_rel,
        "log_sha256": log_digest,
    }
    write_json(rdir / f"lanes/{args.lane}.json", result)
    print(f"LANE {args.lane} {'PASS' if passed else 'FAIL'} attempt={prior + 1} artifact={digest}")
    return 0 if passed else 1


def lane_verdict_from_log(text):
    """Re-derive a lane's verdict from its own last line.

    The JSON `passed` flag is a producer claim; this reads the bytes the
    lane actually wrote. `verify` requires the two to agree, so editing the
    JSON to turn a red lane green contradicts the log instead of promoting.
    """
    lines = [ln for ln in text.strip().splitlines() if ln.strip()]
    if not lines:
        return None
    last = lines[-1].strip()
    if last.endswith(": PASS"):
        return True
    if last.endswith(": FAIL"):
        return False
    return None


def collect(rdir, required, artifact_path, digest):
    """Everything `promote` and `verify` need, derived from bytes."""
    issues = []
    record = read_json(rdir / "release.json")
    if record["artifact"]["sha256"] != digest:
        issues.append(f"RECORD_DIGEST_MISMATCH {record['artifact']['sha256']}")
    if artifact_path is not None and artifact_path.exists():
        live = sha256_file(artifact_path)
        if live != digest:
            issues.append(f"ARTIFACT_DIGEST_MISMATCH live={live}")
        else:
            mroot, _ = member_root(artifact_path)
            if mroot != record["artifact"]["member_root"]:
                issues.append(f"MEMBER_ROOT_MISMATCH live={mroot}")
    lane_states = {}
    for lane in required:
        rpath = rdir / f"lanes/{lane}.json"
        if not rpath.exists():
            issues.append(f"REQUIRED_LANE_MISSING {lane}")
            lane_states[lane] = None
            continue
        res = read_json(rpath)
        lane_states[lane] = res
        if res.get("lane") != lane:
            issues.append(f"LANE_ID_MISMATCH {lane} != {res.get('lane')}")
        if res.get("artifact_sha256") != digest or res.get("artifact_sha256_after") != digest:
            issues.append(
                f"LANE_BOUND_TO_OTHER_ARTIFACT {lane} "
                f"{res.get('artifact_sha256')}/"
                f"{res.get('artifact_sha256_after')}"
            )
        log_path = rdir / res.get("log_file", "")
        if not log_path.exists():
            issues.append(f"LANE_LOG_MISSING {lane}")
            continue
        if sha256_file(log_path) != res.get("log_sha256"):
            issues.append(
                f"LANE_LOG_UNBOUND {lane} — log bytes do not hash to the recorded log_sha256"
            )
            continue
        attempts_path = rdir / f"lanes/{lane}.attempts.jsonl"
        if not attempts_path.exists():
            issues.append(
                f"LANE_ATTEMPTS_MISSING {lane} — a result without its "
                "append-only attempt ledger hides retries"
            )
        else:
            entries = [
                json.loads(ln)
                for ln in attempts_path.read_text(encoding="utf-8").splitlines()
                if ln.strip()
            ]
            if not entries:
                issues.append(f"LANE_ATTEMPTS_EMPTY {lane}")
            else:
                last = entries[-1]
                if [e["attempt"] for e in entries] != list(range(1, len(entries) + 1)):
                    issues.append(f"LANE_ATTEMPTS_NOT_SEQUENTIAL {lane}")
                if (
                    last.get("log_sha256") != res.get("log_sha256")
                    or bool(last.get("passed")) != bool(res.get("passed"))
                    or last.get("attempt") != res.get("attempt")
                ):
                    issues.append(
                        f"LANE_RESULT_NOT_LAST_ATTEMPT {lane} — the stored "
                        "result is not the final recorded attempt"
                    )
                res["_attempts"] = len(entries)
        derived = lane_verdict_from_log(log_path.read_text(encoding="utf-8"))
        if derived is None:
            issues.append(
                f"LANE_LOG_UNPARSEABLE {lane} — no trailing '<name>: PASS|FAIL' verdict line"
            )
        elif derived != bool(res.get("passed")):
            issues.append(
                f"LANE_VERDICT_CONTRADICTION {lane} json={res.get('passed')} log={derived}"
            )
        elif not derived:
            issues.append(f"REQUIRED_LANE_FAILED {lane}")
    # a lane result present but not required is fine; a lane result for a
    # DIFFERENT artifact sitting in this directory is not
    for rpath in sorted((rdir / "lanes").glob("*.json")) if (rdir / "lanes").exists() else []:
        res = read_json(rpath)
        if res.get("artifact_sha256") != digest:
            issues.append(f"FOREIGN_LANE_RESULT {rpath.name} bound to {res.get('artifact_sha256')}")
    return record, lane_states, issues


def cmd_promote(args):
    digest = args.digest
    rdir = release_dir(args.releases, digest)
    if not (rdir / "release.json").exists():
        raise Refusal(f"RELEASE_NOT_BUILT {digest}")
    required = args.require.split(",") if args.require else load_required_lanes(LANE_MANIFEST)
    unknown = [lane for lane in required if lane not in lanes_mod.LANES]
    if unknown:
        raise Refusal(f"LANE_NOT_IMPLEMENTED {unknown}")
    artifact = pathlib.Path(args.artifact).resolve() if args.artifact else None
    record, _lane_states, issues = collect(rdir, required, artifact, digest)
    if issues:
        raise Refusal("PROMOTION_REFUSED " + "; ".join(issues))
    keys = load_trusted_keys()
    entry = keys.get(args.key_id)
    if entry is None:
        raise Refusal(
            f"UNTRUSTED_SIGNING_KEY {args.key_id!r} — not in "
            f"{TRUSTED_KEYS.relative_to(REPO)} (trusted: {sorted(keys)})"
        )
    seed = resolve_seed(entry)
    promotion = {
        "schema": "release-promotion/v1",
        "artifact_sha256": digest,
        "member_root": record["artifact"]["member_root"],
        "required_lanes": sorted(required),
        "profile": record["profile"],
        "promotion_class": ("RELEASE" if entry["class"] == "production" else "DEVELOPMENT"),
        "signing_key_id": entry["key_id"],
        "signing_key_class": entry["class"],
    }
    if args.require:
        promotion["required_lanes_overridden"] = True
    write_json(rdir / "promotion.json", promotion)
    root, files = evidence_root(rdir)
    msg = f"typedb-r2/release-root/v1\n{digest}\n{root}\n".encode("utf-8")
    sig = ed.sign(seed, msg)
    pub = ed.public_key(seed).hex()
    if not verify_signature_twice(pub, msg, sig.hex()):
        raise Refusal(
            "SIGNATURE_SELF_CHECK_FAILED — the freshly produced "
            "signature does not verify; refusing to record it"
        )
    write_json(
        rdir / SIGNATURE_FILE,
        {
            "schema": "release-signature/v1",
            "signed_message": msg.decode("utf-8"),
            "artifact_sha256": digest,
            "root": root,
            "root_files": files,
            "key_id": entry["key_id"],
            "public_key": pub,
            "signature": sig.hex(),
        },
    )
    print(
        f"PROMOTED {digest} class={promotion['promotion_class']} "
        f"profile={record['profile']} root={root} lanes={len(required)}"
    )
    if promotion["promotion_class"] != "RELEASE":
        print(
            "NOTE: signed by a development-class key — this is NOT a "
            "release-grade promotion and `verify --release-grade` refuses it."
        )
    return 0


def cmd_verify(args):
    digest = args.digest
    rdir = release_dir(args.releases, digest)
    if not rdir.exists():
        raise Refusal(f"RELEASE_ABSENT {digest}")
    if not (rdir / "release.json").exists():
        raise Refusal(f"RELEASE_NOT_BUILT {digest}")
    required = args.require.split(",") if args.require else load_required_lanes(LANE_MANIFEST)
    # `promote` refused an unimplemented lane id; `verify` did not, so a
    # caller could ask it to "verify" a lane set containing a name no lane
    # implements and read the resulting report as a check that ran.
    unknown = [lane for lane in required if lane not in lanes_mod.LANES]
    if unknown:
        raise Refusal(f"LANE_NOT_IMPLEMENTED {unknown} — known lanes: {sorted(lanes_mod.LANES)}")
    artifact = pathlib.Path(args.artifact).resolve() if args.artifact else None
    record, _lane_states, issues = collect(rdir, required, artifact, digest)

    promo_path, sig_path = rdir / "promotion.json", rdir / SIGNATURE_FILE
    promoted = promo_path.exists()
    signature_verified = False
    promotion = None
    if promoted:
        promotion = read_json(promo_path)
        if promotion.get("artifact_sha256") != digest:
            issues.append("PROMOTION_DIGEST_MISMATCH")
        if sorted(promotion.get("required_lanes", [])) != sorted(required):
            issues.append(
                f"PROMOTION_LANE_SET_MISMATCH promoted="
                f"{sorted(promotion.get('required_lanes', []))} "
                f"required-now={sorted(required)}"
            )
        if promotion.get("member_root") != record["artifact"]["member_root"]:
            issues.append("PROMOTION_MEMBER_ROOT_MISMATCH")
        if not sig_path.exists():
            issues.append(
                "PROMOTION_UNSIGNED — a promotion record without a signature binds nothing"
            )
        else:
            sig = read_json(sig_path)
            root, files = evidence_root(rdir)
            if sig.get("root") != root:
                issues.append(
                    f"ROOT_MISMATCH recorded={sig.get('root')} "
                    f"recomputed={root} ({files} files) — a file in "
                    "the release directory changed after signing"
                )
            expect_msg = f"typedb-r2/release-root/v1\n{digest}\n{root}\n"
            if sig.get("signed_message") != expect_msg:
                issues.append(
                    "SIGNED_MESSAGE_MISMATCH — the signature does not cover this digest and root"
                )
            keys = load_trusted_keys()
            entry = keys.get(sig.get("key_id"))
            if entry is None:
                issues.append(f"UNTRUSTED_SIGNING_KEY {sig.get('key_id')!r}")
            elif entry["public_key"] != sig.get("public_key"):
                issues.append(
                    f"SIGNING_KEY_SUBSTITUTED {sig.get('key_id')!r} — the "
                    "recorded public key is not the trusted one for this id"
                )
            elif verify_signature_twice(
                sig["public_key"], sig["signed_message"].encode("utf-8"), sig["signature"]
            ):
                signature_verified = True
            else:
                issues.append(
                    "SIGNATURE_INVALID — both implementations rejected the recorded signature"
                )

    grade_issues = []
    if record["profile"] != "RELEASE":
        grade_issues.append(f"PROFILE_{record['profile']}")
    if promotion and promotion.get("promotion_class") != "RELEASE":
        grade_issues.append(f"PROMOTION_CLASS_{promotion.get('promotion_class')}")
    if promotion and promotion.get("required_lanes_overridden"):
        grade_issues.append("REQUIRED_LANES_OVERRIDDEN")
    src = record["source"]
    if not src.get("commit"):
        grade_issues.append("SOURCE_IDENTITY_UNBOUND")
    elif src.get("bound_by") == "environment":
        # an environment variable is not evidence of anything
        grade_issues.append("SOURCE_IDENTITY_UNAUTHENTICATED")
    elif src.get("bound_by") == "release-identity-file" and not src.get("identity_verified"):
        grade_issues.append("SOURCE_IDENTITY_FILE_UNVERIFIED")
    if not src.get("dirty_paths_known"):
        grade_issues.append("SOURCE_DIRT_UNKNOWN")
    elif src.get("dirty_paths"):
        grade_issues.append(f"SOURCE_TREE_DIRTY({len(src['dirty_paths'])})")
    for lane, res in sorted(_lane_states.items()):
        if res and res.get("_attempts", 1) > 1:
            grade_issues.append(f"LANE_RETRIED({lane}x{res['_attempts']})")
    if not promoted:
        grade_issues.append("NOT_PROMOTED")
    if not signature_verified:
        grade_issues.append("SIGNATURE_NOT_VERIFIED")

    report = {
        "artifact_sha256": digest,
        "profile": record["profile"],
        "required_lanes": sorted(required),
        "promoted": promoted,
        "promotion_class": promotion.get("promotion_class") if promotion else None,
        "signature_verified": signature_verified,
        "lane_attempts": {
            lane: (res or {}).get("_attempts") for lane, res in sorted(_lane_states.items())
        },
        "integrity_issues": issues,
        "release_grade_blockers": grade_issues,
        "release_grade": not issues and not grade_issues,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    if issues:
        print("VERIFY: FAILED", file=sys.stderr)
        return 1
    if args.release_grade and grade_issues:
        print("VERIFY: NOT RELEASE GRADE — " + "; ".join(grade_issues), file=sys.stderr)
        return 1
    print("VERIFY: OK" + ("" if not grade_issues else " (not release grade)"), file=sys.stderr)
    return 0


def cmd_list(args):
    root = pathlib.Path(args.releases)
    if not root.exists():
        print("(no releases)")
        return 0
    for d in sorted(root.iterdir()):
        if not (d / "release.json").exists():
            continue
        rec = read_json(d / "release.json")
        promo = read_json(d / "promotion.json") if (d / "promotion.json").exists() else None
        print(
            f"{d.name} profile={rec['profile']} state={rec['state']} "
            f"promotion={promo['promotion_class'] if promo else 'NONE'}"
        )
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--releases", default=str(DEFAULT_RELEASES), help="release evidence directory")
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="record an immutable release for an artifact")
    b.add_argument("--artifact", default=str(DEFAULT_ARTIFACT))
    b.set_defaults(fn=cmd_build)

    t = sub.add_parser("test", help="run one lane against the exact artifact")
    t.add_argument("--artifact", default=str(DEFAULT_ARTIFACT))
    t.add_argument("--digest", default=None)
    t.add_argument("--lane", required=True)
    t.set_defaults(fn=cmd_test)

    p = sub.add_parser("promote", help="promote a digest after every required lane")
    p.add_argument("--digest", required=True)
    p.add_argument("--artifact", default=str(DEFAULT_ARTIFACT))
    p.add_argument("--key-id", required=True)
    p.add_argument(
        "--require",
        default=None,
        help="override the required lane set (marks the promotion "
        "as overridden; never release grade)",
    )
    p.set_defaults(fn=cmd_promote)

    v = sub.add_parser("verify", help="re-derive everything from the bytes")
    v.add_argument("--digest", required=True)
    v.add_argument("--artifact", default=str(DEFAULT_ARTIFACT))
    v.add_argument("--require", default=None)
    v.add_argument(
        "--release-grade", action="store_true", help="fail unless this is a release-grade promotion"
    )
    v.set_defaults(fn=cmd_verify)

    ls = sub.add_parser("list", help="list recorded releases")
    ls.set_defaults(fn=cmd_list)

    args = ap.parse_args(argv)
    try:
        return args.fn(args)
    except Refusal as err:
        print(f"REFUSED: {err}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
