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

## Explicit gaps (owned elsewhere, not silently claimed)

- Private issuer as a deployed service + Rust client lifecycle issuance (R5-SEC-02 follow-up; the loopback HTTP issuer in `scripts/issuer.mjs` is its local seam).
- ContainerDO provisioning binding and a real Container resource (R5-SEC-06/07).
- Read-fence TOCTOU across the two DO hops (R5-SEC-05, recorded in `worker-entry.ts`).
- Confidentiality profile (OD-008) remains an owner decision.
