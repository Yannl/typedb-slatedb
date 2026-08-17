# V16 Cloudflare real-account probe plan

All probes run against disposable staging resources created from the exact release package lock. Raw requests, responses, account/product flags, SDK versions, Worker compatibility date, source/image/config digests, seeds, and cleanup evidence are archived.

## P-R2-01 — Conditions and ambiguity

Test single-part create/update/read with exact `If-None-Match` and `If-Match`, concurrent writers, timeout before and after server commit, duplicate same-operation requests, wrong expected version, and full byte/hash readback.

**Pass:** exact success/conflict/ambiguous classification; no unconditional downgrade; same operation resolves without duplicate authority.

## P-R2-02 — Temporary credential action and path scope

Mint credentials with exact `PutObject`, multipart, `HeadObject`/`GetObject`, and copy actions. Attempt every forbidden read/write/list/delete/admin operation inside and outside exact objects/prefixes.

**Pass:** all forbidden actions are denied; no pre-G13 credential can delete or change bucket/lock/lifecycle configuration; parent revocation and expiry are measured.

## P-R2-03 — Bucket Locks

Preconfigure coarse authority/materialisation/backup rules. Test existing and new objects, overwrite, single/bulk delete, multipart completion, overlapping rules, date/duration/indefinite conditions, policy retrieval and unauthorized policy mutation.

**Pass:** locked mutations fail as documented; expected policy is continuously machine-verifiable; runtime principals cannot alter it.

## P-R2-04 — Checksums and multipart identity

Test single and multipart checksum headers, full-object CRC64NVME, composite SHA-256, part retry with identical bytes, attempted changed-byte retry under same part, failed replacement, completion, exact full-object application SHA-256, abort and abandoned upload inventory.

**Pass:** provider checksum types never substitute for application SHA-256; changed bytes require new `UploadAttemptId`; final bytes match manifest.

## P-R2-05 — Consistency and same-key pressure

Test direct S3/Workers binding read-after-write, list, metadata, delete in isolated test buckets; concurrent same-key writes; deliberate same-key rate pressure and 429 behavior. Do not involve public-domain CDN caching.

**Pass:** observed behavior matches contract and adapter classifications; overload is bounded and never creates an incorrect success.

## P-DO-01 — Request interleaving

Instrument each non-storage `await` in controller procedures. Send conflicting finalisation/session/epoch/checkpoint requests while the first invocation is paused.

**Pass:** prepare/finalise or outbox structure produces one legal reducer trace; no stale post-await validation commits.

## P-DO-02 — Alarm durability

Exercise duplicate alarm delivery, handler throw, six automatic retries, reset/code update, no alarm, delayed alarm, manual reschedule, and external watchdog.

**Pass:** required work remains reconstructible and eventually rescheduled; no transition relies on automatic retry count.

## P-DO-03 — Overload and storage budgets

Drive controller above configured QPS, queue, row, byte, outbox and archival thresholds. Inject archival outage and approach SQLite hard limits without crossing production emergency thresholds.

**Pass:** mutations shed before unsafe growth; recovery/repair/archival capacity remains; no blind retry storm; explicit metrics/alerts fire.

## P-DO-04 — Incarnation and old-authority rejection

Rotate controller incarnation and parent credentials while old DO and containers remain alive. Attempt capability mint, event publication, WAL finalisation, manifest publication and lifecycle report.

**Pass:** all old-authority attempts are rejected or produce unreachable orphan bytes.

## P-CTR-01 — Lifecycle state machine

Exercise cold start, concurrent start, start timeout, port-ready timeout, stop while starting, duplicate stop, destroy, process exit, lifecycle DO reset, code update, stale callback and platform start rate limit.

**Pass:** `DatabaseContainerDO` converges to platform truth without granting database authority; controller can safely retry lifecycle intentions.

## P-CTR-02 — Mixed rollout

Deploy Worker/controller N with image N−1 running, then image N; inject failed rollout step, slow convergence, rollback and old-image restart.

**Pass:** compatibility envelope admits only declared tuples; unsupported image never becomes database-ready; deployment completion requires observed convergence.

## P-CTR-03 — Sleep and shutdown

Test default inactivity, custom `sleepAfter`, controller-denied hibernation, open transaction, recovery, checkpoint, SIGTERM, deadline expiry and SIGKILL.

**Pass:** no unsafe inactivity stop; graceful shutdown is optional; arbitrary kill recovers acknowledged state.

## P-CTR-04 — Networking and placement

Force/observe lifecycle DO and container in separate locations where possible; test internal HTTP, egress allowlist, `enableInternet=false`, runtime CA failure, long streaming response and client disconnect.

**Pass:** no colocation assumption; HTTP backpressure works; unauthorized egress is denied; possibly committed operations remain queryable.

## P-WORKER-01 — Gateway bounds

Stream objects around configured thresholds, slow sender/receiver, R2 5xx/timeout, six-connection saturation, high subrequest count and isolate memory pressure.

**Pass:** bounded memory, permits and backpressure; no full buffering; no success receipt before exact remote resolution.

## Evidence format

Each probe emits:

```text
PlatformProbeEvidence {
  probe_id,
  source_lock_digest,
  platform_contract_lock_digest,
  account_profile_digest,
  compatibility_date,
  package_lock_digest,
  image_digest?,
  config_digest,
  started_at,
  raw_request_log_ref,
  raw_response_log_ref,
  fault_schedule,
  seed,
  observed_metrics,
  expected_outcome,
  actual_outcome,
  pass,
  artifact_digests
}
```
