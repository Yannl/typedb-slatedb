/*
 * R4 PR1: opaque tenant/database registry primitives + the private-issuer
 * key hierarchy (mint/verify separation).
 *
 * REGISTRY. Production routing must not trust a caller-supplied database id
 * (audit 4.3/4.4 item 1): the durable record is
 *
 *     TenantId <-> opaque DatabaseId <-> expected controller DO id <-> environment
 *
 * held as the ControllerDO's own provisioned binding (the simplest durable
 * home that kills first-call squatting: the DO id IS derived from the
 * record, and the DO refuses every ordinary call until the record exists).
 * This module owns the pure parts: identifier syntax, the deterministic
 * DO-name derivation, and the provisioning capability check. Identifiers
 * are NORMALIZED AND BOUNDED (audit 4.7): lowercase ASCII letters, digits
 * and interior hyphens only, at most 64 chars - no slashes, controls,
 * homoglyphs or oversized ids can reach a DO name, an object key or a
 * token audience.
 *
 * KEY HIERARCHY (audit 4.4 item 3). The private issuer holds a single
 * non-exportable ROOT. Every verifier-facing key is DERIVED per scope:
 *
 *     scope key = HMAC-SHA-256(root, "typedb-cap-key/v2|" + kid)
 *     kid       = "cap:<environment>"  (ordinary capabilities)
 *               | "prov:<environment>" (the internal PROVISION power)
 *
 * A component that only verifies ordinary capabilities receives ONLY the
 * "cap:<env>" key: it cannot recover the root, cannot derive any other
 * scope, and in particular cannot mint the PROVISION capability that binds
 * databases (the registry write power stays with the issuer). This is the
 * strongest separation available under symmetric MACs inside the
 * synchronous core (see journal-crypto.ts for why crypto here is sync);
 * within ONE scope, verify material is still mint-capable - the recorded
 * asymmetric upgrade seam is exactly this module: reimplement
 * mintProvisionToken/checkProvisionToken (and the capability MAC in
 * capability.ts) over signatures without touching any caller.
 */

import { hmacSha256, utf8 } from "./journal-crypto.ts";
import {
  checkCapability, mintCapability, type CapabilityCheck, type CapabilityPayload,
} from "./capability.ts";

/** Normalized, bounded identifier syntax shared by tenant ids, opaque
 *  database ids and environment names: lowercase alphanumerics with
 *  interior hyphens, 1..64 chars. */
const OPAQUE_ID = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;

export function validOpaqueId(value: unknown): value is string {
  return typeof value === "string" && OPAQUE_ID.test(value);
}

/** The one registry record shape: which tenant, which opaque database,
 *  which environment. The expected controller DO id is DERIVED from it
 *  (controllerDoName), never stored separately - the mapping cannot skew. */
export interface ProvisionBinding {
  environment: string;
  tenantId: string;
  databaseId: string;
}

export type BindingCheck =
  | { ok: true; binding: ProvisionBinding }
  | { ok: false; error: "INVALID_BINDING"; field: "environment" | "tenantId" | "databaseId" };

/** Validate a wire-shaped binding fail-closed: every field must be a
 *  normalized bounded id. Returns the narrowed binding or the typed field
 *  refusal - never throws on wire input. */
export function checkBinding(value: {
  environment?: unknown; tenantId?: unknown; databaseId?: unknown;
}): BindingCheck {
  if (!validOpaqueId(value.environment)) return { ok: false, error: "INVALID_BINDING", field: "environment" };
  if (!validOpaqueId(value.tenantId)) return { ok: false, error: "INVALID_BINDING", field: "tenantId" };
  if (!validOpaqueId(value.databaseId)) return { ok: false, error: "INVALID_BINDING", field: "databaseId" };
  return {
    ok: true,
    binding: {
      environment: value.environment, tenantId: value.tenantId, databaseId: value.databaseId,
    },
  };
}

export function bindingsEqual(a: ProvisionBinding, b: ProvisionBinding): boolean {
  return a.environment === b.environment && a.tenantId === b.tenantId && a.databaseId === b.databaseId;
}

/**
 * The expected controller DO name for a registry record: domain-separated
 * over environment + tenant + opaque database id. Unambiguous because every
 * segment is slash-free by OPAQUE_ID. The Worker derives idFromName from
 * THIS (via the verified token's binding), never from a caller-supplied
 * database id alone; the DO re-checks its stored binding on every call.
 */
export function controllerDoName(binding: ProvisionBinding): string {
  return `ctl/${binding.environment}/${binding.tenantId}/${binding.databaseId}`;
}

/** Key ids: the capability scope and the provisioning scope of one
 *  environment. The kid travels in the token (schema v2) and is verified
 *  against the scope the checking key actually belongs to. */
export function capabilityKid(environment: string): string {
  return `cap:${environment}`;
}

export function provisionKid(environment: string): string {
  return `prov:${environment}`;
}

/** Derive one scope's key from the issuer root. The ROOT never leaves the
 *  issuer; runtimes are provisioned with the derived keys only. */
export function deriveScopedKey(issuerRoot: Uint8Array, kid: string): Uint8Array {
  return hmacSha256(issuerRoot, utf8(`typedb-cap-key/v2|${kid}`));
}

export function deriveCapabilityKey(issuerRoot: Uint8Array, environment: string): Uint8Array {
  return deriveScopedKey(issuerRoot, capabilityKid(environment));
}

export function deriveProvisionKey(issuerRoot: Uint8Array, environment: string): Uint8Array {
  return deriveScopedKey(issuerRoot, provisionKid(environment));
}

/**
 * Mint the internal PROVISION capability (issuer side; tests and the local
 * managed stack mint it in-process from the run's ephemeral root). It is a
 * schema-v2 token under the PROVISION scope key: the binding rides in the
 * token's env/tenantId/databaseId fields, so the Worker's frame check and
 * the DO's authoritative check reuse the one token verifier.
 */
export function mintProvisionToken(
  provisionKey: Uint8Array,
  binding: ProvisionBinding,
  options: { nonce: string; expiresAtMs: number; principal?: string },
): string {
  const payload: CapabilityPayload = {
    v: 2,
    kid: provisionKid(binding.environment),
    env: binding.environment,
    tenantId: binding.tenantId,
    principal: options.principal ?? "provisioner",
    databaseId: binding.databaseId,
    method: "PROVISION",
    // provisioning happens before any controller incarnation is relevant
    // (the DO may not even exist); the incarnation field is fixed at 0 and
    // deliberately NOT checked for PROVISION (see checkProvisionToken).
    incarnation: 0,
    nonce: options.nonce,
    expiresAtMs: options.expiresAtMs,
  };
  return mintCapability(provisionKey, payload);
}

/** Verify a PROVISION token against the exact binding being provisioned.
 *  MAC under the provisioning scope key, schema v2, method PROVISION,
 *  env/tenant/database exact - a token for another tenant's database (or
 *  another environment) refuses before any durable work. */
export function checkProvisionToken(
  provisionKey: Uint8Array,
  token: string,
  expect: { binding: ProvisionBinding; nowMs: number },
): CapabilityCheck {
  return checkCapability(provisionKey, token, {
    method: "PROVISION",
    databaseId: expect.binding.databaseId,
    env: expect.binding.environment,
    tenantId: expect.binding.tenantId,
    nowMs: expect.nowMs,
  });
}
