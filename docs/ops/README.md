# Operations documentation

**Scope note, stated first because it changes what this folder is.**

There is no deployed service. No storage-engine work has begun, no container image exists, and
nothing has been deployed to Cloudflare. So "operations" here means **operating the conformance
programme** — the gates, the evidence, the pins — not operating a database.

Deployment and incident runbooks are listed in [planned.md](planned.md) with the acceptance
criteria that would let them be written. They are deliberately empty rather than speculative: a
runbook for a system that does not exist cannot be followed, and would be indistinguishable
from one that can.

## What can be operated today

| Document | Purpose |
|---|---|
| [Running the gates](running-the-gates.md) | Executing G0/G1 checks and reading the verdict |
| [Evidence handling](evidence-handling.md) | What is produced, what is authoritative, what to keep |
| [Source pin changes](source-pin-changes.md) | Procedure when an upstream pin moves |
| [Planned runbooks](planned.md) | What is not yet writable, and what would unblock each |

## Operating principle

Every claim this programme makes is backed by a regenerable artifact and the command that
produced it. If you cannot point at a digest, you do not have evidence — you have a summary.

When a gate is red, the correct first action is to read *why* from the coverage report, not to
re-run. Re-running a non-deterministic failure until it passes is the exact behaviour the
no-false-green rules exist to prevent.
