"""Ed25519 (RFC 8032) in pure Python — the signing primitive for release roots.

Why a hand-rolled implementation lives in this repository:

  * `cryptography` is installed but its Rust bindings abort this interpreter
    (`pyo3_runtime.PanicException` on any key operation), and PyNaCl is not
    installed. The evidence toolchain is Python, so it needs *a* signer.
  * More importantly, the release-root signature is checked twice, by two
    independent implementations that never share code: this module and
    `verify_signature.mjs` (Node's `crypto`, a different codebase in a
    different language). `release.py` fails closed if the two disagree.
    A defect in this file therefore cannot silently vouch for a forged
    signature; it can only produce a loud contradiction.

This is the reference implementation from RFC 8032 §6 with no
constant-time claims. It signs release evidence roots on a developer or CI
machine; it never touches a live secret path, and it must not be used where
side-channel resistance matters.

`test_ed25519_vectors.py` runs the RFC 8032 §7.1 vectors against it.
"""

import hashlib

# curve parameters (RFC 8032 §5.1)
P = 2**255 - 19
Q = 2**252 + 27742317777372353535851937790883648493


def _sha512(b):
    return hashlib.sha512(b).digest()


def _sha512_modq(b):
    return int.from_bytes(_sha512(b), "little") % Q


def _modp_inv(x):
    return pow(x, P - 2, P)


D = -121665 * _modp_inv(121666) % P
MODP_SQRT_M1 = pow(2, (P - 1) // 4, P)

# points are extended homogeneous coordinates (X, Y, Z, T) with x=X/Z, y=Y/Z


def _point_add(a, b):
    A = (a[1] - a[0]) * (b[1] - b[0]) % P
    B = (a[1] + a[0]) * (b[1] + b[0]) % P
    C = 2 * a[3] * b[3] * D % P
    Dd = 2 * a[2] * b[2] % P
    E, F, G, H = B - A, Dd - C, Dd + C, B + A
    return (E * F % P, G * H % P, F * G % P, E * H % P)


def _point_mul(s, p):
    q = (0, 1, 1, 0)  # neutral element
    while s > 0:
        if s & 1:
            q = _point_add(q, p)
        p = _point_add(p, p)
        s >>= 1
    return q


def _point_equal(a, b):
    if (a[0] * b[2] - b[0] * a[2]) % P != 0:
        return False
    return (a[1] * b[2] - b[1] * a[2]) % P == 0


def _recover_x(y, sign):
    if y >= P:
        return None
    x2 = (y * y - 1) * _modp_inv(D * y * y + 1)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * MODP_SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


_G_Y = 4 * _modp_inv(5) % P
_G_X = _recover_x(_G_Y, 0)
if _G_X is None:
    # RFC 8032 §5.1.5: the base point's x exists by construction. Reaching here
    # means P, D or _recover_x has been altered, and every signature this module
    # then produced would be wrong in a way no test vector could explain.
    raise AssertionError("ed25519: the base point has no x coordinate; curve constants are corrupt")
G = (_G_X, _G_Y, 1, _G_X * _G_Y % P)


def _point_compress(p):
    zinv = _modp_inv(p[2])
    x = p[0] * zinv % P
    y = p[1] * zinv % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _point_decompress(s):
    if len(s) != 32:
        raise ValueError("ed25519: compressed point must be 32 bytes")
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def _secret_expand(secret):
    if len(secret) != 32:
        raise ValueError("ed25519: seed must be 32 bytes")
    h = _sha512(secret)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return (a, h[32:])


def public_key(seed):
    """32-byte public key for a 32-byte seed."""
    a, _ = _secret_expand(seed)
    return _point_compress(_point_mul(a, G))


def sign(seed, msg):
    """64-byte Ed25519 signature (PureEdDSA) over `msg`."""
    a, prefix = _secret_expand(seed)
    pub = _point_compress(_point_mul(a, G))
    r = _sha512_modq(prefix + msg)
    R = _point_mul(r, G)
    Rs = _point_compress(R)
    h = _sha512_modq(Rs + pub + msg)
    s = (r + h * a) % Q
    return Rs + int.to_bytes(s, 32, "little")


def verify(pub, msg, signature):
    """True iff `signature` is a valid Ed25519 signature of `msg` under `pub`.

    Returns False (never raises) for every malformed input, so a caller can
    treat "not verified" as one outcome.
    """
    try:
        if len(pub) != 32 or len(signature) != 64:
            return False
        A = _point_decompress(pub)
        if A is None:
            return False
        Rs = signature[:32]
        R = _point_decompress(Rs)
        if R is None:
            return False
        s = int.from_bytes(signature[32:], "little")
        if s >= Q:
            return False
        h = _sha512_modq(Rs + pub + msg)
        sB = _point_mul(s, G)
        hA = _point_mul(h, A)
        return _point_equal(sB, _point_add(R, hA))
    except (ValueError, TypeError):
        return False
