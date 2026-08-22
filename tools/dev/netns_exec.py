#!/usr/bin/env python3
"""Run a command in a PRIVATE network namespace, with loopback up.

WHY THIS EXISTS
---------------
TypeDB's server tests each start a real server, and that server binds FIXED
addresses — gRPC 127.0.0.1:11729, monitoring 127.0.0.1:4104. Upstream wrote
them assuming one server at a time, which is true under `cargo test` (one
binary, libtest threads inside it) and true under this repository's own
`run_leaf.py` (one target at a time). It is NOT true under `cargo nextest`,
which runs tests as separate processes in parallel: two servers race for
11729 and the loser dies with

    Fatal uncaught kj::Exception: ::bind(...): Address already in use

That is a false red — the same tests pass 10/10 in every sealed lane bundle.

The fix is to stop making them share a network. A process in its own network
namespace has its OWN loopback and its own port space, so every test can bind
11729 and none of them collide. This is STRUCTURAL: it keeps working when
upstream adds another server test, which is exactly what a hand-maintained
list of "tests that must run serially" would not do.

Used as a cargo target runner, so cargo and nextest invoke every test binary
through it:

    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER=tools/dev/netns_exec.py

MECHANICS
---------
`unshare(CLONE_NEWNET)` is called in-process via ctypes rather than by
execing util-linux's `unshare`, so this costs one process, not two, on a path
that runs once per test.

A fresh namespace's `lo` exists but is DOWN. Binding to 127.0.0.1 still
succeeds, which is a trap: the failure shows up later as `Network is
unreachable` on connect. `lo` is therefore brought UP here, via SIOCSIFFLAGS,
because `ip`/iproute2 is not a dependency this repository has and adding one
to make a gate work is the wrong trade.

REFUSALS
--------
This never falls back to running without isolation. A fallback would silently
restore the collisions it exists to prevent, and the resulting red would look
like a code defect. If the namespace cannot be created it exits 79
(EX_UNAVAILABLE-ish, distinct from any libtest exit code) with the reason.
"""

import ctypes
import ctypes.util
import fcntl
import os
import pathlib
import shutil
import socket
import struct
import sys
import typing

REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "catalog"))

CLONE_NEWNET = 0x40000000

# <linux/sockios.h> / <net/if.h>
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914
IFF_UP = 0x1
IFF_RUNNING = 0x40

# Distinct from libtest's own exit codes (0, 101) and from nextest's, so a
# harness can tell "isolation unavailable" from "the test failed".
EXIT_NO_ISOLATION = 79


def refuse(message: str) -> "typing.NoReturn":
    """Refuse with EXACTLY `EXIT_NO_ISOLATION`.

    R8-P1-04: every refusal here used to be `sys.exit(<string>)`. Python's
    `sys.exit` with a non-integer argument prints the string to stderr and
    exits **1** — so a script whose whole contract is "79 means isolation is
    unavailable, not a test failure" advertised 79 in its own message and
    returned 1, which is indistinguishable from an ordinary failure. Measured:

        netns_exec: unshare(CLONE_NEWNET) failed: Operation not permitted ...
          exit 79
        ACTUAL_RC=1

    The exit code is the machine-readable half of this contract, so it is the
    half that must not be prose.
    """
    print(message, file=sys.stderr)
    raise SystemExit(EXIT_NO_ISOLATION)


# Where per-process assembly working directories live, under the workspace's
# `target/`. Named here so the staging step can clear it before a run.
NETNS_ISO_DIR = "netns-iso"


def unshare_net() -> None:
    """Move this process into a fresh network namespace."""
    libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
    if libc.unshare(CLONE_NEWNET) != 0:
        err = ctypes.get_errno()
        refuse(
            f"netns_exec: unshare(CLONE_NEWNET) failed: {os.strerror(err)} (errno {err}).\n"
            f"  This needs CAP_SYS_ADMIN, or unprivileged user namespaces.\n"
            f"  Refusing to run WITHOUT isolation: the tests bind fixed ports and would\n"
            f"  collide under a parallel runner, producing failures that are not defects.\n"
            f"  exit {EXIT_NO_ISOLATION}"
        )


def loopback_up() -> None:
    """Bring `lo` up in the CURRENT namespace.

    A down `lo` still accepts bind() and only fails at connect(), so skipping
    this produces a confusing failure far from its cause.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            flags = struct.unpack(
                "16sh", fcntl.ioctl(s, SIOCGIFFLAGS, struct.pack("16sh", b"lo", 0))
            )[1]
            fcntl.ioctl(s, SIOCSIFFLAGS, struct.pack("16sh", b"lo", flags | IFF_UP | IFF_RUNNING))
        except OSError as e:
            refuse(
                f"netns_exec: could not bring loopback up: {e}.\n"
                f"  Without it 127.0.0.1 binds but never connects.\n"
                f"  exit {EXIT_NO_ISOLATION}"
            )


def workspace_root_of(binary: str):
    """The cargo workspace whose `target/` this test binary was built into.

    Derived from the binary's own path (`<root>/target/debug/deps/<name>-<hash>`)
    rather than from an env var, so it is right by construction for whichever
    workspace the runner was invoked from — there is no second place to keep in
    sync when a gate points at a different tree.
    """
    for parent in pathlib.Path(binary).resolve().parents:
        if parent.name == "target":
            return parent.parent
    return None


def assembly_staging(binary: str):
    """The isolated working directory the assembly-family targets need.

    `tests/assembly/assembly.rs` extracts the packaged server INTO ITS CWD and
    reads `typedb-all-linux-x86_64.tar.gz` from there. Under `run_leaf.py` each
    such target gets a private directory with the archive hard-linked in; under
    a parallel runner they would otherwise all extract a ~250 MB tree into the
    same place and race.

    Which targets need it, and the env they need, are taken from
    `run_u0.ASSEMBLY_TARGETS` / `ASSEMBLY_ENV` rather than restated here: a
    second copy of that list is a copy that drifts.

    Returns (cwd, extra_env) or (None, {}) when this binary needs no staging.
    """
    try:
        import run_u0
    except ImportError:
        return None, {}
    # nextest passes the built binary, named `<target>-<hash>`.
    stem = pathlib.Path(binary).name.rsplit("-", 1)[0]
    if stem not in run_u0.ASSEMBLY_TARGETS:
        return None, {}
    root = workspace_root_of(binary)
    if root is None:
        refuse(
            f"netns_exec: cannot tell which workspace built {binary} (no `target/` "
            f"ancestor), so cannot tell which assembly archive belongs to it.\n"
            f"  Refusing rather than guess: the wrong archive makes {stem} certify a\n"
            f"  server that is not the one under test.\n"
            f"  exit {EXIT_NO_ISOLATION}"
        )
    archive = run_u0.assembly_archive_for(root)
    if not archive.is_file():
        refuse(
            f"netns_exec: {stem} needs {archive}, which is absent.\n"
            f"  Build it with `python3 tools/catalog/package_assembly.py "
            f"--workspace-root {root}`\n"
            f"  AFTER that tree's server binaries exist. Refusing to run the target\n"
            f"  without it: it would fail for a missing fixture and look like a defect.\n"
            f"  exit {EXIT_NO_ISOLATION}"
        )
    # Under the workspace's own `target/`, not /tmp: the archive is hard-linked
    # in, which only works on the same filesystem, and `cargo clean` then owns
    # the cleanup. One directory per PROCESS because nextest runs each test as
    # its own process — several tests of the same target extract concurrently.
    iso = root / "target" / NETNS_ISO_DIR / f"{stem}-{os.getpid()}"
    if iso.exists():
        shutil.rmtree(iso)
    (iso / "tests" / "assembly").mkdir(parents=True)
    os.link(archive, iso / archive.name)
    script = root / "tests" / "assembly" / "script.tql"
    if script.is_file():
        shutil.copy2(script, iso / "tests" / "assembly" / "script.tql")
    return iso, dict(run_u0.ASSEMBLY_ENV)


def main() -> int:
    if len(sys.argv) < 2:
        sys.exit(f"usage: {sys.argv[0]} <command> [args...]")
    cwd, extra_env = assembly_staging(sys.argv[1])
    unshare_net()
    loopback_up()
    if cwd is not None:
        os.chdir(cwd)
        os.environ.update(extra_env)
    # The stack the server threads need; run_leaf.py sets the same.
    os.environ.setdefault("RUST_MIN_STACK", str(64 * 1024 * 1024))
    os.execvp(sys.argv[1], sys.argv[1:])  # never returns


if __name__ == "__main__":
    main()
