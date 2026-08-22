#!/usr/bin/env python3
"""The shared, versioned object-namespace codec (R8-P2-05).

The audit's finding: `s3_gc.py`'s namespace parser "covers the current legacy
`<root>/<encoded-local-keyspace>/<fv>/<materialisation>` shape but will not
cover the declared controller `MaterialisationNamespace` shape when that seam
is wired." It was a COPY of segment positions the Rust adapter owns, and a copy
of a layout is a layout that will disagree — silently, and about which objects
belong to which database.

So the grammar is declared once, in `schemas/materialisation-namespace.json`,
and this module reads it. Nothing here hardcodes a segment index, a version
list or an escape rule; adding v3 in the schema teaches every reader at once.
A Rust test in `slate.rs` asserts the schema still describes what the adapter
actually writes, so the declaration cannot drift away from the code either.

The escape is `slate.rs::encode_segment_byte`: `=` is the only escape character
(`=s` for `/`, `==` for `=`, `=xHH` for any byte outside `[A-Za-z0-9._-]`),
which makes it injective — distinct byte strings never share an encoding, so
decoding is unambiguous and two identities can never alias.
"""

from __future__ import annotations

import json
import pathlib
import re
import string

REPO = pathlib.Path(__file__).resolve().parents[2]
SCHEMA = REPO / "schemas" / "materialisation-namespace.json"

UNRESERVED = set(string.ascii_letters + string.digits + "._-")


class NamespaceError(ValueError):
    """A key that does not decode. Never a guess: a maintenance tool that
    guesses which database an object belongs to is worse than one that says it
    does not know."""


def schema(path: pathlib.Path | None = None) -> dict:
    return json.loads((path or SCHEMA).read_text())


def encode_segment(value: str) -> str:
    """Injectively encode one opaque identifier, byte for byte."""
    out = []
    for byte in value.encode("utf-8"):
        char = chr(byte)
        if char in UNRESERVED:
            out.append(char)
        elif char == "/":
            out.append("=s")
        elif char == "=":
            out.append("==")
        else:
            out.append(f"=x{byte:02x}")
    return "".join(out)


def decode_segment(encoded: str) -> str:
    """Invert `encode_segment`, refusing anything the encoder cannot produce.

    Accepting a malformed escape would quietly turn one identity into another —
    the precise failure the injective encoding exists to make impossible.
    """
    out = bytearray()
    i = 0
    while i < len(encoded):
        char = encoded[i]
        if char != "=":
            if char not in UNRESERVED:
                raise NamespaceError(
                    f"segment {encoded!r} contains {char!r}, which the encoder never emits raw"
                )
            out.extend(char.encode())
            i += 1
            continue
        marker = encoded[i + 1 : i + 2]
        if marker == "s":
            out.extend(b"/")
            i += 2
        elif marker == "=":
            out.extend(b"=")
            i += 2
        elif marker == "x":
            hexits = encoded[i + 2 : i + 4]
            if len(hexits) != 2 or any(c not in "0123456789abcdef" for c in hexits):
                raise NamespaceError(f"segment {encoded!r} has a malformed =x escape at {i}")
            out.append(int(hexits, 16))
            i += 4
        else:
            raise NamespaceError(f"segment {encoded!r} has an unknown escape {'=' + marker!r}")
    return out.decode("utf-8", errors="strict")


def parse(key: str, root_prefix: str, doc: dict | None = None) -> dict:
    """Decode one object key into `{version, <named segments>}`.

    Versions are tried in declaration order and the FIRST whose shape and
    constraints match wins, so the schema's order is the disambiguation rule
    rather than a heuristic buried here.
    """
    doc = doc or schema()
    if not key.startswith(root_prefix + "/"):
        raise NamespaceError(f"{key!r} is not under the root prefix {root_prefix!r}")
    parts = key[len(root_prefix) + 1 :].split("/")

    problems = []
    for version in doc["versions"]:
        names = version["segments"]
        if len(parts) < len(names):
            problems.append(f"{version['id']}: needs {len(names)} segments, key has {len(parts)}")
            continue
        try:
            decoded = {name: decode_segment(parts[i]) for i, name in enumerate(names)}
        except NamespaceError as error:
            problems.append(f"{version['id']}: {error}")
            continue
        # The literal `keyspace/` directory (slate.rs::DB_SUBDIR) must follow
        # the namespace. This — not a guess about which shape looks likelier —
        # is what keeps a v1 key from decoding as a v2 one and vice versa.
        follows = version.get("followed_by")
        if follows is not None and parts[len(names) : len(names) + 1] != [follows]:
            problems.append(
                f"{version['id']}: the segment after the namespace is "
                f"{parts[len(names) : len(names) + 1] or ['<end of key>']}, not {[follows]}"
            )
            continue
        constraints = version.get("constraints", {})
        broken = [
            f"{field} {decoded[field]!r} does not match {pattern}"
            for field, pattern in constraints.items()
            if not re.match(pattern, decoded[field])
        ]
        if broken:
            problems.append(f"{version['id']}: " + "; ".join(broken))
            continue
        return {"version": version["id"], **decoded}
    raise NamespaceError(f"{key!r} matches no declared namespace version: " + " | ".join(problems))


def object_prefix(fields: dict, root_prefix: str, version_id: str, doc: dict | None = None) -> str:
    """The inverse of `parse`, so a fixture can be built from identifiers
    rather than from a string somebody typed."""
    doc = doc or schema()
    version = next((v for v in doc["versions"] if v["id"] == version_id), None)
    if version is None:
        raise NamespaceError(f"no declared namespace version {version_id!r}")
    missing = [name for name in version["segments"] if name not in fields]
    if missing:
        raise NamespaceError(f"{version_id} needs {missing}")
    return "/".join([root_prefix, *(encode_segment(fields[name]) for name in version["segments"])])
