/*
 * R5-SEC-03 ISSUER SIDE (reusable): per-run ephemeral Ed25519 keypairs +
 * v3 token minting + a minimal loopback HTTP issuance endpoint.
 *
 * This module IS the private issuer for local managed runs. It generates
 * one keypair per scope (ordinary capabilities, provisioning), keeps the
 * PRIVATE halves in-process, and hands out:
 *
 *   - runtimeVars(): the PUBLIC verification material + environment name
 *     the managed runtime boots from (exactly the graph-declared
 *     deployment vars, R5-SEC-01);
 *   - mintCapability(spec) / mintProvision(binding): in-process issuance
 *     for drivers and tests;
 *   - startIssuerServer(): a 127.0.0.1-only, bearer-authenticated HTTP
 *     issuance endpoint:
 *         POST /issue            {spec}    -> {ok, token, key?, expiresAtMs}
 *         POST /provision-token  {binding} -> {ok, token}
 *     This is the seam the R5-SEC-02 follow-up's Rust client will use for
 *     managed-local issuance (the managed worker surface deliberately has
 *     no /capability route).
 *
 * Imported by managed-stack-e2e.mjs and the issuer-http node test; runs
 * under `node --experimental-strip-types` because it shares the exact core
 * modules the worker runs.
 */

import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { generateEd25519KeyPair } from "../src/shared/ed25519.ts";
import { mintCapabilityToken, mintProvisionToken } from "../src/controller/core/issuer.ts";
import { hex } from "../src/shared/journal-crypto.ts";
import { capabilityKid, provisionKid, validOpaqueId } from "../src/shared/registry.ts";
import { isKnownCapabilityMethod } from "../src/shared/capability.ts";

const DEFAULT_TTL_MS = 60_000;
const MAX_TTL_MS = 3_600_000;
const MAX_BODY_BYTES = 64 * 1024;

/**
 * Create one run's private issuer for `environment`. Key slot 1 of each
 * scope; rotation runs mint a second issuer and merge runtimeVars.
 */
export async function createIssuer({ environment, tenantId = "tenant-a", slot = 1 } = {}) {
  if (!validOpaqueId(environment)) throw new Error(`issuer environment must be a normalized id: ${environment}`);
  const cap = await generateEd25519KeyPair();
  const prov = await generateEd25519KeyPair();
  const capKid = `${capabilityKid(environment)}/${slot}`;
  const provKid = `${provisionKid(environment)}/${slot}`;

  /** Build + sign one ordinary capability from an issuance spec. */
  async function mintCapability(spec) {
    const {
      principal = "issuer-driver", databaseId, method, session, generation, digest, maxBytes,
      ttlMs, incarnation = 1, tenantId: specTenant,
    } = spec ?? {};
    if (typeof databaseId !== "string" || typeof method !== "string" || !isKnownCapabilityMethod(method)) {
      throw new Error(`ISSUE_SPEC_INVALID: databaseId + known method required (got ${JSON.stringify({ databaseId, method })})`);
    }
    const expiresAtMs = Date.now() + Math.min(Math.max(ttlMs ?? DEFAULT_TTL_MS, 1), MAX_TTL_MS);
    // PUT_PAYLOAD keys are issuer-derived and content-addressed - the
    // caller never selects an object key (F9)
    const key = method === "PUT_PAYLOAD" && digest !== undefined ? `p/${databaseId}/${digest}` : undefined;
    const payload = {
      v: 3, alg: "Ed25519", kid: capKid, env: environment,
      tenantId: specTenant ?? tenantId, principal, databaseId, method,
      ...(session !== undefined ? { session } : {}),
      ...(generation !== undefined ? { generation: String(generation) } : {}),
      ...(key !== undefined ? { key } : {}),
      ...(digest !== undefined ? { digest } : {}),
      ...(maxBytes !== undefined ? { maxBytes } : {}),
      incarnation, nonce: randomUUID(), expiresAtMs,
    };
    return { token: await mintCapabilityToken(cap.privateKeyPkcs8, payload), key, expiresAtMs, incarnation };
  }

  async function mintProvision(binding, { ttlMs, principal } = {}) {
    return mintProvisionToken(prov.privateKeyPkcs8, binding, {
      nonce: randomUUID(),
      expiresAtMs: Date.now() + Math.min(Math.max(ttlMs ?? DEFAULT_TTL_MS, 1), MAX_TTL_MS),
      kid: provKid,
      ...(principal !== undefined ? { principal } : {}),
    });
  }

  return {
    environment,
    tenantId,
    capabilityKid: capKid,
    provisionKid: provKid,
    capabilityPublicKeyHex: hex(cap.publicKey),
    provisionPublicKeyHex: hex(prov.publicKey),
    /** PUBLIC managed runtime inputs — everything the deployed side gets. */
    runtimeVars() {
      return {
        CONTROLLER_ENVIRONMENT: environment,
        CONTROLLER_CAPABILITY_PUBLIC_KEYS: `${capKid}=${hex(cap.publicKey)}`,
        CONTROLLER_PROVISION_PUBLIC_KEYS: `${provKid}=${hex(prov.publicKey)}`,
      };
    },
    mintCapability,
    mintProvision,
    /** Deliberately exposed PRIVATE halves for adversarial tests (forging
     *  cross-scope tokens). Never handed to any runtime. */
    _private: {
      capabilityPrivateKeyPkcs8: cap.privateKeyPkcs8,
      provisionPrivateKeyPkcs8: prov.privateKeyPkcs8,
    },
  };
}

/**
 * Minimal loopback HTTP issuance mode. 127.0.0.1 ONLY (any other host is a
 * construction error, not a config knob), bearer-authenticated, bounded
 * JSON bodies, typed refusals. Returns { url, port, close() }.
 */
export async function startIssuerServer(issuer, { host = "127.0.0.1", port = 0, bearerToken } = {}) {
  if (host !== "127.0.0.1") {
    throw new Error("ISSUER_LOOPBACK_ONLY: the local issuer binds 127.0.0.1 and nothing else");
  }
  if (typeof bearerToken !== "string" || bearerToken.length < 16) {
    throw new Error("ISSUER_BEARER_REQUIRED: a bearer token of at least 16 chars is mandatory");
  }

  const respond = (res, status, body) => {
    const bytes = Buffer.from(JSON.stringify(body));
    res.writeHead(status, { "content-type": "application/json", "content-length": String(bytes.length) });
    res.end(bytes);
  };

  const readBody = (req) => new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on("data", (chunk) => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        reject(new Error("BODY_TOO_LARGE"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });

  const server = createServer(async (req, res) => {
    try {
      const presented = req.headers.authorization;
      if (presented !== `Bearer ${bearerToken}`) {
        return respond(res, 401, { ok: false, error: "ISSUER_UNAUTHORIZED" });
      }
      if (req.method !== "POST" || (req.url !== "/issue" && req.url !== "/provision-token")) {
        return respond(res, 404, { ok: false, error: "NOT_FOUND" });
      }
      let body;
      try {
        body = JSON.parse((await readBody(req)).toString("utf8"));
      } catch (error) {
        return respond(res, error?.message === "BODY_TOO_LARGE" ? 413 : 400,
          { ok: false, error: error?.message === "BODY_TOO_LARGE" ? "BODY_TOO_LARGE" : "MALFORMED_JSON" });
      }
      if (typeof body !== "object" || body === null || Array.isArray(body)) {
        return respond(res, 400, { ok: false, error: "MALFORMED_JSON" });
      }
      if (req.url === "/issue") {
        try {
          const issued = await issuer.mintCapability(body.spec ?? body);
          return respond(res, 200, { ok: true, ...issued });
        } catch (error) {
          return respond(res, 400, { ok: false, error: "ISSUE_SPEC_INVALID", detail: String(error?.message ?? error) });
        }
      }
      // /provision-token
      const binding = body.binding ?? body;
      if (!validOpaqueId(binding?.tenantId) || !validOpaqueId(binding?.databaseId)) {
        return respond(res, 400, { ok: false, error: "INVALID_BINDING" });
      }
      const token = await issuer.mintProvision({
        environment: issuer.environment, tenantId: binding.tenantId, databaseId: binding.databaseId,
      }, { ttlMs: body.ttlMs });
      return respond(res, 200, { ok: true, token });
    } catch (error) {
      return respond(res, 500, { ok: false, error: "ISSUER_INTERNAL", detail: String(error?.message ?? error) });
    }
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, resolve);
  });
  const actualPort = server.address().port;
  return {
    url: `http://${host}:${actualPort}`,
    port: actualPort,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}
