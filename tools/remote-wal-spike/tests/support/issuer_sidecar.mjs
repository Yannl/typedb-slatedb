/*
 * R5-SEC-02: the private-issuer SIDECAR the Rust stack lanes spawn.
 *
 * The Rust client is a pure BEARER of issuer-granted v3 tokens - it holds
 * no signing material and constructs no tokens. Each stack test therefore
 * boots this sidecar next to `wrangler dev`: a loopback-only,
 * bearer-authenticated HTTP issuer (control-plane/scripts/issuer.mjs
 * startIssuerServer - POST /issue {spec} -> {token}, POST /provision-token
 * {binding} -> {token}), exactly the production issuance topology executed
 * locally.
 *
 * Two modes, selected by argv:
 *
 *   managed    per-run EPHEMERAL Ed25519 keypairs (createIssuer). The
 *              PRIVATE halves live and die in this process; the printed
 *              runtimeVars are the PUBLIC verification keyrings +
 *              environment name the managed worker boots from (the exact
 *              graph-declared inputs, R5-SEC-01/03).
 *
 *   local-dev  the committed DEV-INSECURE Ed25519 keys under the exact dev
 *              kids (cap:local / prov:local), matching the keyring the
 *              local-dev worker profile pins. Same wire surface as
 *              managed mode, so ONE Rust client speaks to both lanes.
 *              The mint spec mirrors scripts/issuer.mjs createIssuer's
 *              (that function cannot be reused here: it generates fresh
 *              keys and slotted kids, which the local-dev runtime's
 *              pinned dev keyring would refuse). Restriction enforcement
 *              is NOT mirrored - it comes from the real
 *              core/issuer.ts mintCapabilityToken both modes sign with.
 *
 * Usage:
 *   node --experimental-strip-types issuer_sidecar.mjs \
 *     <control-plane-dir> <managed|local-dev> <environment> <tenantId> <bearer>
 *
 * Prints ONE JSON line {ok, url, port, runtimeVars} once serving, then
 * stays alive until killed. Any startup failure prints {ok:false, error}
 * and exits nonzero.
 */

import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const [controlPlaneDir, mode, environment, tenantId, bearerToken] = process.argv.slice(2);

const DEFAULT_TTL_MS = 60_000;
const MAX_TTL_MS = 3_600_000;

function clampTtl(ttlMs) {
  return Math.min(Math.max(ttlMs ?? DEFAULT_TTL_MS, 1), MAX_TTL_MS);
}

try {
  if (!controlPlaneDir || !environment || !tenantId || !bearerToken
      || (mode !== "managed" && mode !== "local-dev")) {
    throw new Error("usage: issuer_sidecar.mjs <control-plane-dir> <managed|local-dev> <environment> <tenantId> <bearer>");
  }
  const load = (relative) => import(pathToFileURL(join(controlPlaneDir, relative)).href);
  const { createIssuer, startIssuerServer } = await load("scripts/issuer.mjs");

  let issuer;
  if (mode === "managed") {
    issuer = await createIssuer({ environment, tenantId });
  } else {
    const core = await load("src/controller/core/issuer.ts");
    const keyConfig = await load("src/controller/core/key-config.ts");
    const capability = await load("src/controller/core/capability.ts");
    if (environment !== keyConfig.DEV_ENVIRONMENT) {
      throw new Error(`local-dev issuance is pinned to environment ${keyConfig.DEV_ENVIRONMENT}`);
    }
    const capabilitySigningKey = keyConfig.devCapabilitySigningKey();
    const provisionSigningKey = keyConfig.devProvisionSigningKey();
    issuer = {
      environment: keyConfig.DEV_ENVIRONMENT,
      tenantId,
      /** Same spec surface as createIssuer's mintCapability, signed with
       *  the dev capability key under the exact (slotless) dev kid. */
      async mintCapability(spec) {
        const {
          principal = "issuer-driver", databaseId, method, session, generation, digest, maxBytes,
          ttlMs, incarnation = 1, tenantId: specTenant,
        } = spec ?? {};
        if (typeof databaseId !== "string" || typeof method !== "string"
            || !capability.isKnownCapabilityMethod(method)) {
          throw new Error(`ISSUE_SPEC_INVALID: databaseId + known method required (got ${JSON.stringify({ databaseId, method })})`);
        }
        const expiresAtMs = Date.now() + clampTtl(ttlMs);
        // issuer-derived content-addressed PUT_PAYLOAD key (F9)
        const key = method === "PUT_PAYLOAD" && digest !== undefined ? `p/${databaseId}/${digest}` : undefined;
        const payload = {
          v: 3, alg: "Ed25519", kid: keyConfig.DEV_CAPABILITY_KID, env: keyConfig.DEV_ENVIRONMENT,
          tenantId: specTenant ?? tenantId, principal, databaseId, method,
          ...(session !== undefined ? { session } : {}),
          ...(generation !== undefined ? { generation: String(generation) } : {}),
          ...(key !== undefined ? { key } : {}),
          ...(digest !== undefined ? { digest } : {}),
          ...(maxBytes !== undefined ? { maxBytes } : {}),
          incarnation, nonce: randomUUID(), expiresAtMs,
        };
        return { token: await core.mintCapabilityToken(capabilitySigningKey, payload), key, expiresAtMs, incarnation };
      },
      async mintProvision(binding, { ttlMs, principal } = {}) {
        return core.mintProvisionToken(provisionSigningKey, binding, {
          nonce: randomUUID(),
          expiresAtMs: Date.now() + clampTtl(ttlMs),
          kid: keyConfig.DEV_PROVISION_KID,
          ...(principal !== undefined ? { principal } : {}),
        });
      },
      runtimeVars() { return {}; },
    };
  }

  const server = await startIssuerServer(issuer, { bearerToken });
  process.stdout.write(`${JSON.stringify({
    ok: true, url: server.url, port: server.port, runtimeVars: issuer.runtimeVars(),
  })}\n`);
} catch (error) {
  process.stdout.write(`${JSON.stringify({ ok: false, error: String(error?.message ?? error) })}\n`);
  process.exit(1);
}
