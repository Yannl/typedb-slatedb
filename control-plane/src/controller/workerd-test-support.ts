/*
 * Shared fixtures for the workerd (vitest-pool-workers) suites - test-only.
 *
 * R4 PR1: a controller authority serves NOTHING until it is provisioned
 * (registry binding), so every workerd suite that exercises a database
 * first runs the provisioning transaction - exactly as the real bootstrap
 * does. R5-SEC-03: provisioning is an ISSUER-SIDE act — the token is
 * SIGNED with the committed dev-insecure provision keypair (key-config.ts;
 * never resolved into any runtime), and the local-dev worker/DO verify it
 * against the dev provision PUBLIC key.
 */

import { SELF } from "cloudflare:test";
import { DEV_ENVIRONMENT, DEV_PROVISION_KID, devProvisionSigningKey } from "./core/key-config.ts";
import { controllerDoName, type ProvisionBinding } from "./core/registry.ts";
import { mintProvisionToken } from "./core/issuer.ts";
import type { DatabaseControllerDO } from "./database-controller.ts";

export const LOCAL_TENANT = "local";

export function localBinding(databaseId: string, tenantId = LOCAL_TENANT): ProvisionBinding {
  return { environment: DEV_ENVIRONMENT, tenantId, databaseId };
}

export function devProvisionToken(binding: ProvisionBinding): Promise<string> {
  return mintProvisionToken(devProvisionSigningKey(), binding, {
    nonce: crypto.randomUUID(), expiresAtMs: Date.now() + 60_000, kid: DEV_PROVISION_KID,
  });
}

/** Provision a database through the worker's production bootstrap route. */
export async function provisionViaSelf(databaseId: string, tenantId = LOCAL_TENANT): Promise<Response> {
  const binding = localBinding(databaseId, tenantId);
  return SELF.fetch("https://facade.local/provision", {
    method: "POST",
    headers: { "content-type": "application/json", "x-provision": await devProvisionToken(binding) },
    body: JSON.stringify({ tenantId, databaseId }),
  });
}

/** Provision directly on a DO instance (runInDurableObject suites). */
export async function provisionInstance(
  instance: DatabaseControllerDO, databaseId: string, tenantId = LOCAL_TENANT,
): Promise<void> {
  const binding = localBinding(databaseId, tenantId);
  const result = await instance.provision(await devProvisionToken(binding), binding);
  if (!result.ok) throw new Error(`test provisioning failed: ${JSON.stringify(result)}`);
}

/** The registry-derived DO name the worker routes this binding to. */
export function localDoName(databaseId: string, tenantId = LOCAL_TENANT): string {
  return controllerDoName(localBinding(databaseId, tenantId));
}
