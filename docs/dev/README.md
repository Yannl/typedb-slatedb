# Developer documentation

For people working *on* this repository. If you want to know what the system is, start at
[`docs/architecture.md`](../architecture.md).

## Contents

| Document | Read it when |
|---|---|
| [Getting started](getting-started.md) | First clone; you need a working tree and a green tool build |
| [Repository layout](repository-layout.md) | You are unsure where something belongs, or why there are three workspaces |
| [Conformance tooling](conformance-tooling.md) | You are changing the catalogue, the runner, or how results are classified |
| [Working with upstream](working-with-upstream.md) | You are patching TypeDB, bumping a pin, or hit a fixture problem |
| [Troubleshooting](troubleshooting.md) | Something failed and you want to know whether it is you, the tooling, or upstream |

## The one rule worth stating up front

**Absence of a result is never success.** The tooling is built so that anything it cannot read,
attribute, or execute is reported loudly rather than skipped quietly. If you find yourself
making a check more permissive to get a green, stop — that is the failure mode this repository
is designed to prevent, and it has already caught twelve real defects in its own harness
([Phase B summary](../evidence/phase-b/summary.md)).

Relaxing a check is legitimate when it fires on something real and unfixable — for example
upstream's own `@ignore` tags, which the fork cannot un-skip and which are therefore recorded
as owned exclusions. It is not legitimate because the check is inconvenient.

## Current state

Gate G0/Phase B. The source graph is locked, the upstream test denominator is generated, and
the U0 baseline is measured. **No storage-engine work has begun** — `sources/slatedb` is a
pinned checkout, not a wired component.

What that means for you day to day: everything in this repository is currently about
*establishing what upstream does* so that a later change can be shown not to have altered it.
