/*
 * Shared fixtures for the workerd (vitest-pool-workers) suites - test-only.
 *
 * R4 PR1: a controller authority serves NOTHING until it is provisioned
 * (registry binding), so every workerd suite that exercises a database
 * first runs the provisioning transaction - exactly as the real bootstrap
 * does. The local-dev posture's provisioning scope key is the loud dev
 * constant (key-config.ts), so tests mint the PROVISION capability
 * in-process the same way the local stack driver does.
 */

import { SELF } from "cloudflare:test";
import { utf8 } from "./core/journal-crypto.ts";
import { DEV_ENVIRONMENT, DEV_PROVISION_KEY } from "./core/key-config.ts";
import { controllerDoName, mintProvisionToken, type ProvisionBinding } from "./core/registry.ts";
import type { DatabaseControllerDO } from "./database-controller.ts";

export const LOCAL_TENANT = "local";

export function localBinding(databaseId: string, tenantId = LOCAL_TENANT): ProvisionBinding {
  return { environment: DEV_ENVIRONMENT, tenantId, databaseId };
}

export function devProvisionToken(binding: ProvisionBinding): string {
  return mintProvisionToken(utf8(DEV_PROVISION_KEY), binding, {
    nonce: crypto.randomUUID(), expiresAtMs: Date.now() + 60_000,
  });
}

/** Provision a database through the worker's production bootstrap route. */
export async function provisionViaSelf(databaseId: string, tenantId = LOCAL_TENANT): Promise<Response> {
  const binding = localBinding(databaseId, tenantId);
  return SELF.fetch("https://facade.local/provision", {
    method: "POST",
    headers: { "content-type": "application/json", "x-provision": devProvisionToken(binding) },
    body: JSON.stringify({ tenantId, databaseId }),
  });
}

/** Provision directly on a DO instance (runInDurableObject suites). */
export function provisionInstance(
  instance: DatabaseControllerDO, databaseId: string, tenantId = LOCAL_TENANT,
): void {
  const binding = localBinding(databaseId, tenantId);
  const result = instance.provision(devProvisionToken(binding), binding);
  if (!result.ok) throw new Error(`test provisioning failed: ${JSON.stringify(result)}`);
}

/** The registry-derived DO name the worker routes this binding to. */
export function localDoName(databaseId: string, tenantId = LOCAL_TENANT): string {
  return controllerDoName(localBinding(databaseId, tenantId));
}
