# Troubleshooting

Ordered by how often each has actually happened here.

## "Is this me, the tooling, or upstream?"

Start with the question the whole repository is built to answer. In this project's history the
answer was *the tooling* twelve times, *upstream* four times, and *the environment* twice — so
suspect your own harness first.

## The build ran out of disk

The workspace build with debug info exceeds 24 GB. `tools/u0-build-env.sh` disables it. If you
see `No space left on device`, delete `build/` and re-run — deletes still succeed when writes
fail.

## `source-lock` says a checkout is dirty

Only **tracked** file changes count. If it fires, you edited a pinned source. Untracked run
residue — `typedb-logs/`, staged fixture trees, the assembly archive — is excluded by design
and recorded separately.

## A behaviour target reports zero cases

Almost always a fixture or feature-flag problem, not a test problem.

* `does not contain this feature: bazel` → something is passing `--features bazel`. It must not.
* `Could not read path: …typedb_behaviour…` → fixture staging did not cover that spelling; see
  [working with upstream](working-with-upstream.md).

## A packaging test fails on a missing archive

`cargo xtask assemble` builds it. It needs the U0 build (server, admin) and Console:

```bash
cargo build --release -p typedb-console --locked \
  --manifest-path sources/typedb-console/Cargo.toml
cargo xtask assemble
```

The archive must reach the test as a **bare filename in the working directory**.
`fail_points.rs` does string surgery — `tar -xf $A && mv ${A%.tar.gz}-0.0.0 …` — so `tar`
writes to the cwd while `mv` keeps the variable's path prefix. An absolute path cannot work.
The runner stages it correctly; a manual invocation must too.

## Cases come back `Unknown`

The runner could not classify the output. Read `<target>.stdout.txt` in the run's evidence
directory. Common causes: a `tracing` subscriber writing to fd 1 between a test name and its
verdict, or a cucumber summary disagreeing with the parsed scenario count.

**Do not "fix" this by making the parser assume a pass.** An `Unknown` is the tooling telling
you it does not know, which is the one thing it must be free to say.

## A run hangs

Targets have timeouts and the runner kills the whole process group. If a *manual* cargo
invocation hangs, check for an orphaned `typedb_server_bin` holding a port or data directory:

```bash
pkill -f typedb_server_bin
rm -rf sources/typedb/typedb-extracted sources/typedb/typedb-logs
```

Per-target `cargo test` invocations have deadlocked here while holding the build-directory
lock, with no compiler running — build once with `--no-run`, then invoke harnesses directly.

## Everything failed after a container restart

Check the tree first: `git status`, then that `build/u0` and `build/console` still exist.
Long-running work should go through a background task so a restart does not lose it.
