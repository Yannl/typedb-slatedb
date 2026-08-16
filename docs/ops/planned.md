# Planned runbooks

Not yet writable. Each entry states what it would cover and what must exist first. They are
empty on purpose: a runbook for a system that does not exist cannot be followed, and would be
indistinguishable from one that can.

| Runbook | Would cover | Blocked on |
|---|---|---|
| **Local stack (L1)** | Bring up MinIO + SlateDB-backed TypeDB; run U1 against it | the storage binding; `cargo xtask local-stack` |
| **Local stack (L2)** | `wrangler dev` with Worker + container + local R2 | L1; a container image; `TB-BASE` |
| **Deployment** | Deploy to Cloudflare; roll back | L2 green; `CF-ACCOUNT` |
| **Incident: storage unavailable** | R2 unreachable or throttling | a deployed system to observe |
| **Incident: recovery after crash** | Verify state after abrupt termination | the storage binding; note that upstream's two WAL-recovery tests are `todo!()`, so this cannot inherit their assurance |
| **Capacity and cost** | Sizing, cold start, spend | measurements, of which there are none |
| **Backup and restore** | Point-in-time recovery | a durability design |

## Why these are empty rather than drafted

Three of them — recovery, capacity, backup — depend on behaviour nobody has measured. Writing
plausible steps now would produce a document that reads as operational knowledge and contains
none. The failure mode is specific: an operator follows it during an incident and it is wrong.

The recovery entry is the sharpest example. Upstream's own corpus does not fully verify
recovery — `storage/tests/test_recovery.rs` L64-74 declares two WAL-recovery tests with bare
`todo!()` bodies. Any recovery runbook must therefore rest on verification this programme adds,
not on assurance inherited from upstream.
