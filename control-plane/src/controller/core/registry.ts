/*
 * R4 PR1: opaque tenant/database registry primitives + the provisioning
 * token check (mint/verify separation).
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
 * KEY MODEL (R5-SEC-03). The round-4 design derived per-scope HMAC keys
 * from an issuer root; within one scope, verify material was mint-capable
 * (the audit's §2.3 executable proof). That hierarchy is GONE. Each scope
 * is now its own Ed25519 KEYPAIR:
 *
 *     kid = "cap:<environment>[/<slot>]"   ordinary capabilities
 *         | "prov:<environment>[/<slot>]"  the internal PROVISION power
 *
 * The issuer holds the private halves (core/issuer.ts); every runtime
 * verifier holds ONLY the public keyrings (core/key-config.ts). A
 * component that verifies ordinary capabilities cannot mint them, cannot
 * derive any other scope, and in particular cannot mint the PROVISION
 * capability that binds databases — cryptographically, not by key-handling
 * discipline.
 */

import {
  verifyCapabilityToken, type CapabilityCheck, type VerificationKeyring,
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

/** Kid roots: the capability scope and the provisioning scope of one
 *  environment. The kid travels in the token (schema v3) and is verified
 *  against the keyring the checking side actually holds; a rotation slot
 *  appends "/<n>" (capability.ts kidNamesScope). */
export function capabilityKid(environment: string): string {
  return `cap:${environment}`;
}

export function provisionKid(environment: string): string {
  return `prov:${environment}`;
}

/** Verify a PROVISION token against the exact binding being provisioned.
 *  Ed25519 signature under the provisioning-scope PUBLIC keyring, schema
 *  v3, method PROVISION, env/tenant/database exact - a token for another
 *  tenant's database (or another environment) refuses before any durable
 *  work. Async because WebCrypto verification is (R5-SEC-03). */
export function verifyProvisionToken(
  provisionKeyring: VerificationKeyring,
  token: string,
  expect: { binding: ProvisionBinding; nowMs: number },
): Promise<CapabilityCheck> {
  return verifyCapabilityToken(provisionKeyring, token, {
    method: "PROVISION",
    databaseId: expect.binding.databaseId,
    env: expect.binding.environment,
    tenantId: expect.binding.tenantId,
    nowMs: expect.nowMs,
  });
}
