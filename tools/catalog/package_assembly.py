#!/usr/bin/env python3
"""BT-P2/BT-P4 (partial): reproduce the Bazel `assemble-typedb-all` archive
from Cargo-built binaries, without executing Bazel.

Layout reproduced from TB root BUILD at the pin (anchors):
  - package-layout-server-files (BUILD L84-93): typedb wrapper (//binary:typedb),
    server/typedb_server_bin, server/config.yml, admin/typedb_admin_bin, LICENSE
  - console-repackaged (BUILD L153-165): console/typedb_console_bin selected out
    of the pinned Console artifact archive
  - loader-repackaged (BUILD L167-179): loader/typedb_loader_bin from the pinned
    Loader artifact archive
  - assemble-all-linux-x86_64-targz (BUILD L210-219): package_dir
    typedb-all-linux-x86_64-{version}; dev version is 0.0.0 exactly as
    tests/assembly/assembly.rs expects (it renames <name>-0.0.0 ->
    typedb-extracted).

Binary permissions 0744 per binary_permissions (BUILD L59); the wrapper needs
exec permission for the test to spawn it.
"""
import gzip
import hashlib
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[2]
TB = REPO / "sources" / "typedb"
FIX = REPO / "sources" / "fixtures"
VERSION = "0.0.0"
NAME = f"typedb-all-linux-x86_64-{VERSION}"
# built straight into the install location; nothing is left inside the
# pinned checkout (an intermediate there reads as staging drift to
# tools/fork/stage.py and the source-lock lint)
OUT = REPO / "sources" / "assembly-artifacts" / "typedb-all-linux-x86_64.tar.gz"

CONSOLE_SHA = "058145121f478f2f8ad10991cd17e64e12957b93e0836ac180fe9d095a4c4e40"
LOADER_SHA = "c46fba13d835701e43778a2ea1e2dbf0e031d206c55c6c8fec28e03c274d37f9"


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def main():
    server_bin = TB / "target" / "debug" / "typedb_server_bin"
    admin_bin = TB / "target" / "debug" / "typedb_admin_bin"
    for b in (server_bin, admin_bin):
        if not b.exists():
            sys.exit(f"missing cargo-built binary: {b} (run cargo build first)")

    console_tar = FIX / "console" / "typedb-console-linux-x86_64-3.12.0.tar.gz"
    loader_tar = FIX / "loader" / "typedb-loader-linux-x86_64-3.12.0.tar.gz"
    assert sha256(console_tar) == CONSOLE_SHA, "console fixture hash mismatch"
    assert sha256(loader_tar) == LOADER_SHA, "loader fixture hash mismatch"

    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        root = td / NAME
        (root / "server").mkdir(parents=True)
        (root / "admin").mkdir()
        shutil.copy2(TB / "binary" / "typedb", root / "typedb")
        (root / "typedb").chmod(0o755)
        shutil.copy2(TB / "LICENSE", root / "LICENSE")
        shutil.copy2(server_bin, root / "server" / "typedb_server_bin")
        shutil.copy2(TB / "server" / "config.yml", root / "server" / "config.yml")
        shutil.copy2(admin_bin, root / "admin" / "typedb_admin_bin")

        # console: artifact strip prefix typedb-console-linux-x86_64-3.12.0,
        # select subpath console/typedb_console_bin (BUILD L153-158)
        for tarball, sub, dest in (
            (console_tar, "console/typedb_console_bin", root / "console"),
            (loader_tar, "loader/typedb_loader_bin", root / "loader"),
        ):
            with tarfile.open(tarball) as tf:
                member = None
                for m in tf.getmembers():
                    parts = m.name.split("/", 1)
                    if len(parts) == 2 and parts[1] == sub:
                        member = m
                        break
                if member is None:
                    sys.exit(f"{tarball}: subpath {sub} not found")
                dest.mkdir(parents=True, exist_ok=True)
                with tf.extractfile(member) as src, \
                        open(dest / pathlib.Path(sub).name, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                (dest / pathlib.Path(sub).name).chmod(0o755)

        for f in root.rglob("*"):
            if f.is_file() and f.suffix not in (".yml",) and f.name not in ("LICENSE",):
                f.chmod(f.stat().st_mode | 0o111)

        # Deterministic packaging: sorted entry order, zeroed mtimes/ownership,
        # gzip header mtime 0. Two packagings of the same binaries then produce
        # the same digest, which is what makes the per-run
        # `assembly_archive_sha256` in the corpus results a usable identity
        # (the binaries themselves are not bit-reproducible; the packaging
        # step no longer adds a second source of variance on top).
        def normalise(ti: tarfile.TarInfo) -> tarfile.TarInfo:
            ti.mtime = 0
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = "root"
            # modes too: mkdir/copy2 inherit the build machine's umask, and
            # tar records them — without canonicalisation the digest differs
            # between umask 022 and 002 machines even for identical bytes.
            ti.mode = 0o755 if (ti.isdir() or ti.mode & 0o100) else 0o644
            return ti

        entries = [(root, NAME)] + [
            (p, f"{NAME}/{p.relative_to(root).as_posix()}")
            for p in sorted(root.rglob("*"), key=lambda p: p.relative_to(root).as_posix())
        ]
        OUT.parent.mkdir(parents=True, exist_ok=True)
        with open(OUT, "wb") as raw, \
                gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz, \
                tarfile.open(fileobj=gz, mode="w", format=tarfile.GNU_FORMAT) as tf:
            for path, arcname in entries:
                tf.add(path, arcname=arcname, recursive=False, filter=normalise)

    # this is the location the corpus runner (run_u0.py) hard-links from; a
    # stale copy here silently runs assembly tests against an old binary
    print(f"installed {OUT} sha256={sha256(OUT)}")


if __name__ == "__main__":
    main()
