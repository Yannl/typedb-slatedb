# Service identity and key topology (R5-SEC-08)

**Status:** describes the code as of the round-5 R5-SEC-01/03 implementation. Every statement cites the file that enforces it. This is the implemented map, not the target architecture; unimplemented layers are listed at the end as explicit gaps.

## The one rule

**TypeDB end-user authentication is NOT service authentication.** TypeDB's user/password (and driver TLS) authenticates *clients to the TypeDB server*. It authenticates nothing between Cloudflare components: not the TypeDB workload to the Worker, not the Worker to a ControllerDO, not provisioning, not S3. Those are separate principals with their own workload identity, listed below. No component in this control plane consults TypeDB user auth for anything (`control-plane/src/**` contains no TypeDB-auth integration by design).

## Principals and what each one holds

| Principal | Runs where | Holds | Can mint | Can verify |
|---|---|---|---|---|
| **Issuer** (per-run script today; private issuer service per R5-SEC-02 follow-up) | `control-plane/scripts/issuer.mjs` (managed local runs), `core/key-config.ts` dev seeds (local-dev), `core/issuer.ts` (the only minting code) | Ed25519 **private** keys: one keypair per scope (`cap:<env>/<slot>`, `prov:<env>/<slot>`) | capability + provision tokens (schema v3) | — |
| **Gateway Worker** | `src/controller/worker-entry.ts` | **Public** verification keyrings (vars `CONTROLLER_CAPABILITY_PUBLIC_KEYS`, `CONTROLLER_PROVISION_PUBLIC_KEYS`), env name | nothing (no private material resolves — `core/key-config.ts` managed branch) | capability + provision tokens (frame check before any DO contact) |
| **DatabaseControllerDO** | `src/controller/database-controller.ts` | same public keyrings **plus** the symmetric journal MAC secret `CONTROLLER_JOURNAL_KEY` | nothing under managed (`issueCapability` throws `CAPABILITY_ISSUANCE_UNAVAILABLE`; only local-dev resolves the dev signing key) | authoritative re-verification + nonce claim; journal MAC write/verify |
| **DatabaseContainerDO** | `src/container/database-container.ts` | no key material | nothing | nothing yet (advisory observation store; provisioning binding is the open R5-SEC-06 finding, out of scope here) |
| **TypeDB workload (Rust client)** | `tools/remote-wal-spike` | bearer capability tokens it was issued | nothing | nothing |

## Who calls what

```
TypeDB client ──(TypeDB user auth + TLS)──▶ TypeDB server           [not service auth]
TypeDB workload ──(x-capability: v3 token)──▶ Gateway Worker        [worker-entry.ts frameCheck]
Issuer (script/loopback HTTP 127.0.0.1, bearer) ──issues──▶ workload [scripts/issuer.mjs]
Provisioner (issuer side) ──(x-provision: v3 PROVISION token)──▶ POST /provision ──▶ ControllerDO.provision  [worker-entry.ts, database-controller.ts]
Gateway Worker ──(typed RPC on registry-derived DO id)──▶ ControllerDO   [routeBinding/controllerDoName, registry.ts]
Gateway Worker ──(R2 binding PAYLOADS)──▶ R2 bucket                  [wrangler.toml]
```

## Token model (schema v3, `core/capability.ts` / `core/issuer.ts`)

- `base64url(canonicalJson(payload)) + "." + hex(Ed25519 signature)`; closed field set, `v:3`, `alg:"Ed25519"`, `kid`, env/tenant/database binding triple, method, per-method mandatory restrictions, incarnation, single-use nonce, expiry.
- **Mint/verify separation is cryptographic, not procedural:** verification needs only the 32-byte public key; minting needs the PKCS#8 private key, which no runtime posture except local-dev resolves (`core/key-config.ts`). The round-5 audit's §2.3 "verifier keys can mint" HMAC property is closed; executed mutants: `core/capability.test.ts`, `core/registry.test.ts`, `core/managed-construction.test.ts` ("stolen managed env cannot mint"), `provisioning.workerd.test.ts`.
- **Scopes:** ordinary capabilities verify under the `cap` keyring; the PROVISION power (the only way to bind a ControllerDO to its tenant/database registry record) verifies under the distinct `prov` keyring. Distinctness is enforced at config parse (`key-config.ts`).

## Rotation and revocation

- **Capability/provision keys:** two-slot keyring per scope (`current` + `previous`), parsed from the deployment var (`<kid>=<hex>[,!<kid>=<hex>]`, `!` = retired). Rotation = deploy new current + previous live (overlap window), then redeploy with previous marked `!` (typed `CAPABILITY_KID_RETIRED`), then drop it (`CAPABILITY_KID_UNKNOWN`). Tested in `core/capability.test.ts` (rotation mutant).
- **Journal key** (`CONTROLLER_JOURNAL_KEY`, secret): **deliberately symmetric** (HMAC-SHA-256, `core/journal-crypto.ts`). Its writer and verifier are the *same* DatabaseControllerDO — an asymmetric journal key would add a private key to the runtime without removing any authority from it. Rotation = `wrangler secret put` (journal re-verification across a key change is a recovery procedure, out of scope here).
- **Token-level revocation:** expiry (minutes), single-use nonce claim (`ControllerCore.claimCapability`), incarnation bump (`INCARNATION_BUMP` invalidates all outstanding tokens of a controller incarnation), session fencing (use-time `assertActiveReader`).
- **Dev material:** committed INSECURE Ed25519 seeds/publics (`key-config.ts` `DEV_*`); the managed profile refuses them explicitly, exactly like the old dev constants, and additionally refuses the retired v2 HMAC input names (`RETIRED_MANAGED_INPUTS`).

## Configuration surface (R5-SEC-01, single source)

Managed runtime inputs are declared once in `control-plane/src/controller/core/key-requirements.mjs`, consumed verbatim by `resolveKeyConfig` and re-declared by the canonical graph (`stack/graph.data.mjs`); `stack/wrangler-check.mjs` fails pre-deployment on any skew, and `core/managed-construction.test.ts` proves the graph-declared names boot. Public keys and the environment are **vars**; only the journal key is a **secret**.

## S3 / R2 credentials

The Worker reaches R2 through the platform `PAYLOADS` binding (no held S3 credential; `wrangler.toml`). The TypeDB/SlateDB S3 lane (native MinIO/RustFS locally, real R2 later) uses S3 credentials held by the storage workload — per-database scoping, delete-denial, and issuance ancestry are the open R5-SEC audit items owned by the storage/lifecycle workstreams, not implemented here.

## Deployment posture: the service boundary stays private (R8-P2-04)

The round-8 audit reviewed the authorization split and asked for **no second
identity model**: TypeDB authenticates database users; control-plane and
storage operations use short-lived machine capabilities; the managed Worker
holds verifier keys only. Adding a password or JWT layer inside the storage
adapter would not replace TypeDB auth — it would duplicate it, and two identity
models is how a system ends up with one that is not maintained.

What the audit requires instead is that the boundary itself stay private. Each
requirement below names where it is ENFORCED, or says plainly that it is not.

| Requirement | Enforced by | State |
|---|---|---|
| No public `workers.dev` or preview URL | `control-plane/wrangler.toml` (`workers_dev = false`, `preview_urls = false`) and `stack/wrangler-check.mjs`, which fails pre-deployment if either is anything but explicitly `false` in BOTH the config and the canonical graph | **machine-checked** |
| Controller ↔ container over private in-runtime addressing, not a public URL | Both Durable Objects are reached by typed RPC on a registry-derived DO id (`registry.ts`, `worker-entry.ts`); `.quality/architecture/dependency-cruiser.cjs` refuses a production import across the two DOs in either direction, so neither can grow a second route into the other | **machine-checked** |
| Body cap on every pre-auth surface | `MAX_REQUEST_BODY_BYTES` (8 MiB) and `MAX_STRUCTURAL_BODY_BYTES` (256 KiB) in `worker-entry.ts`; an absent or over-declared `content-length` is refused (`REQUEST_BODY_TOO_LARGE`, `REQUEST_BODY_LENGTH_MISMATCH`, `REQUEST_BODY_INCOMPLETE`), proved by executed tests | **implemented** |
| Rate limit on every pre-auth surface | — | **OPEN: OD-026.** A per-isolate bucket is not a deployment-wide limit, and the native binding needs an owner-set budget. Safe today only because no route is declared; the first route makes it load-bearing the same day |
| Outer service identity (Cloudflare Access / mTLS) if an HTTP route is ever exposed | — | **OPEN: OD-026.** The capability remains required underneath either way; the outer identity is defence in depth, never a replacement |
| R2 credentials least privilege, bucket-scoped, runtime without delete | The Worker holds NO S3 credential — it reaches R2 through the platform `PAYLOADS` binding. The native SlateDB lane's runtime store is wrapped in `NoDeleteStore` (`fork/typedb/storage/keyspace/slate.rs`), which refuses a delete before it reaches the provider, so the runtime path contains no delete request to be misconfigured into working | **implemented for the runtime path;** issuance ancestry and bucket scoping are deployment-side and remain owner-side |
| Maintenance authority separate from runtime authority | `tools/maintenance/s3_gc.py` is report-only and contains no delete request at all; deletion arrives with G13, behind its gate record, together with the separated IAM principal | **implemented (by absence, deliberately)** |
| No capability, key material or S3 secret in logs | The GC tool passes credentials to `curl` on a private config-file FD, never in argv (R8-P2-05, proved by `test_the_bucket_secret_never_appears_in_the_child_process_argv`); `resolveKeysOr500` returns a stable `KEY_CONFIG_INVALID` code plus a correlation id to the caller and logs the detail internally (R8-P2-03) | **implemented** |

The two OPEN rows are OD-026 and are deliberately not closed by prose. While
they are open, no gate may be claimed on the strength of the safe default —
that is the registry's own rule, and it is the reason this table records a
dash rather than a paragraph explaining why a dash is fine.

## Explicit gaps (owned elsewhere, not silently claimed)

- Private issuer as a deployed service + Rust client lifecycle issuance (R5-SEC-02 follow-up; the loopback HTTP issuer in `scripts/issuer.mjs` is its local seam).
- ContainerDO provisioning binding and a real Container resource (R5-SEC-06/07).
- Read-fence TOCTOU across the two DO hops (R5-SEC-05, recorded in `worker-entry.ts`).
- Confidentiality profile (OD-008) remains an owner decision.
