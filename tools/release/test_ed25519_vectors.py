#!/usr/bin/env python3
"""RFC 8032 §7.1 test vectors for tools/release/ed25519_ref.py.

A signer nobody checked is not a signer. These are the published vectors,
so a bug in the pure-Python implementation shows up here rather than as a
release signature that only this file believes in.
"""

import hashlib
import pathlib
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import ed25519_ref as ed  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parents[2]
NODE_ED25519 = pathlib.Path(__file__).resolve().parent / "ed25519_node.mjs"

# (seed, public, message, signature) — RFC 8032 §7.1 TEST 1, TEST 2, TEST 3
VECTORS = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8"
        "821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085"
        "ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18f"
        "f9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
]


def node(argv):
    """Run the independent Node implementation; its first stdout line."""
    r = subprocess.run(["node", str(NODE_ED25519), *argv], capture_output=True, text=True)
    return r.stdout.strip() or f"NODE_ERROR:{r.stderr.strip()[:200]}"


def cross_implementation_checks():
    """The two implementations must agree on keys, signatures and rejections.

    Published vectors prove correctness on four fixed inputs. This proves
    the property release.py actually relies on: for arbitrary seeds and
    message lengths (including the empty message and messages longer than
    one SHA-512 block), Python and Node produce the SAME public key and the
    SAME signature, each verifies the other's, and both reject tampering.
    Seeds and messages are derived deterministically so a failure is
    reproducible.
    """
    failures = []
    for i in range(8):
        seed = hashlib.sha256(f"release-cross-seed/{i}".encode()).digest()
        msg = hashlib.sha512(f"release-cross-msg/{i}".encode()).digest() * (i * 3)
        pub_py = ed.public_key(seed)
        pub_node = node(["pub", seed.hex()])
        if pub_node != pub_py.hex():
            failures.append(f"cross {i}: public key py={pub_py.hex()} node={pub_node}")
            continue
        sig_py = ed.sign(seed, msg)
        sig_node = node(["sign", seed.hex(), msg.hex()])
        if sig_node != sig_py.hex():
            failures.append(f"cross {i}: signature py={sig_py.hex()} node={sig_node}")
            continue
        if not ed.verify(pub_py, msg, bytes.fromhex(sig_node)):
            failures.append(f"cross {i}: python rejected node's signature")
        if node(["verify", pub_py.hex(), msg.hex(), sig_py.hex()]) != "VERIFIED":
            failures.append(f"cross {i}: node rejected python's signature")
        other = hashlib.sha256(f"release-cross-other/{i}".encode()).digest()
        if ed.verify(ed.public_key(other), msg, sig_py):
            failures.append(f"cross {i}: python accepted a wrong-key signature")
        if node(["verify", ed.public_key(other).hex(), msg.hex(), sig_py.hex()]) != "NOT_VERIFIED":
            failures.append(f"cross {i}: node accepted a wrong-key signature")
    return failures


def published_vector_checks():
    """Every RFC 8032 §7.1 vector, plus the rejections a verifier must make."""
    failures = []
    for i, (seed_h, pub_h, msg_h, sig_h) in enumerate(VECTORS, 1):
        seed = bytes.fromhex(seed_h)
        msg = bytes.fromhex(msg_h)
        want_pub = bytes.fromhex(pub_h)
        want_sig = bytes.fromhex(sig_h)
        got_pub = ed.public_key(seed)
        if got_pub != want_pub:
            failures.append(f"vector {i}: public key {got_pub.hex()} != {pub_h}")
            continue
        got_sig = ed.sign(seed, msg)
        if got_sig != want_sig:
            failures.append(f"vector {i}: signature {got_sig.hex()} != {sig_h}")
            continue
        if not ed.verify(want_pub, msg, want_sig):
            failures.append(f"vector {i}: verify rejected the published signature")
        # a one-bit flip anywhere must be rejected
        bad = bytearray(want_sig)
        bad[0] ^= 1
        if ed.verify(want_pub, msg, bytes(bad)):
            failures.append(f"vector {i}: verify accepted a corrupted signature")
        bad_msg = bytearray(msg) + b"\x00"
        if ed.verify(want_pub, bytes(bad_msg), want_sig):
            failures.append(f"vector {i}: verify accepted a modified message")
        if node(["verify", want_pub.hex(), msg.hex(), want_sig.hex()]) != "VERIFIED":
            failures.append(f"vector {i}: independent Node verifier rejected a published signature")
        if node(["verify", want_pub.hex(), msg.hex(), bytes(bad).hex()]) != "NOT_VERIFIED":
            failures.append(f"vector {i}: independent Node verifier accepted a corrupted signature")

    return failures


def main():
    failures = published_vector_checks()
    failures.extend(cross_implementation_checks())

    for f in failures:
        print("FAIL:", f)
    print(
        f"ed25519: {len(VECTORS)} RFC 8032 vectors + 8 cross-implementation "
        f"agreements checked, {len(failures)} failures"
    )
    return 1 if failures else 0


# --- pytest entry points ---------------------------------------------------
# The checks are written to RETURN their failures so `main()` can report all of
# them in one pass. pytest collects functions, so these wrap the same functions
# rather than restating the checks: one body, two callers. Without them the
# `py.pytest` gate collected nothing at all and exited 5 — a tier-A gate with
# nothing to run, which is indistinguishable in a report from one that ran and
# was satisfied.


def test_rfc8032_published_vectors():
    failures = published_vector_checks()
    assert not failures, "\n".join(failures)


def test_python_and_node_implementations_agree():
    failures = cross_implementation_checks()
    assert not failures, "\n".join(failures)


if __name__ == "__main__":
    sys.exit(main())
