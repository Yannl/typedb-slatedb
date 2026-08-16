# V16 Cloudflare source/codebase matrix

This matrix separates source code that can be cloned/pinned from platform behavior available only through official contracts and real-account probes.

| Component | Source code/package to pin | Official runtime contract | Why code is insufficient | Release evidence |
|---|---|---|---|---|
| Container lifecycle helper | `cloudflare/containers` + `@cloudflare/containers` tarball | Container architecture, rollouts, limits, egress | helper code cannot prove scheduler placement, rollout timing, shutdown or account limits | package↔source mapping, lifecycle mutation tests, deployed probes |
| Wrangler/deploy | `cloudflare/workers-sdk` + `wrangler` | deploy and rollout docs | CLI code/version cannot prove backend rollout completion/behavior | exact CLI package, raw deploy/rollout observations |
| local Workers test runtime | `@cloudflare/vitest-pool-workers`, Miniflare, workerd selected by lock | Workers/DO runtime docs | local emulation is not production | local differential plus real-account probes |
| Durable Object controller | project source + generated schemas/reducer | DO rules, alarms, limits, lifecycle | application source cannot prove runtime gates, overload or retry scheduling | interleaving/alarm/overload/restart probes |
| R2 S3 client | SlateDB `object_store 0.14.0` and project wrapper | R2 S3 compatibility, consistency, limits | SDK translation and service behavior can diverge | exact SDK real-R2 conformance |
| R2 temporary credentials | project signer/gateway source | temporary-credential docs | local JWT logic cannot prove service enforcement or revocation timing | action/path/TTL/revocation probes |
| R2 Bucket Locks | IaC/policy generator source | Bucket Lock docs/API | source cannot prove policy deployment/enforcement | policy export plus overwrite/delete probes |
| Gateway Worker | project source + Workers packages | Workers limits | code cannot prove isolate memory/connection/subrequest behavior | streaming/load/fault probes |
| Container image | Dockerfile/base/source/server binary | Container limits/image/rollout docs | build digest cannot prove runtime lifecycle/placement | tested-equals-shipped plus deployed lifecycle tests |
| Recovery/backup admin | project tool source | R2/DO account contracts | tool code cannot prove credential separation/lock administration | restore drill, old-authority negative test, policy audit |

## Candidate current package facts to re-resolve at G0

- `@cloudflare/containers`: candidate `0.3.7`.
- Wrangler: candidate `4.123.0`, workers-sdk release commit short ID `c576a82`.
- `@cloudflare/vitest-pool-workers`: candidate `0.21.3`.
- Miniflare: candidate `5.20260811.1-alpha` if selected transitively.
- workerd: candidate `1.20260811.1` if selected by the locked stack.
- Workers compatibility date: explicit release value; never “today”.

These are not final until `pnpm-lock.yaml`, npm integrity and source mapping are archived.
