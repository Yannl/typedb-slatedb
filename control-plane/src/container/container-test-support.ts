/*
 * Shared fixtures for the container workerd suites — test-only.
 *
 * R5-SEC-06: a container authority serves NOTHING until it is provisioned,
 * so every suite that exercises observations first runs the provisioning
 * transaction — exactly as the real controller bootstrap will. Provisioning
 * is an ISSUER-SIDE act (R5-SEC-03): the token is SIGNED with the committed
 * dev-insecure provision keypair (key-config.ts; never resolved into any
 * runtime), and the local-dev DO verifies it against the dev provision
 * PUBLIC key.
 */

import { env } from "cloudflare:test";
import {
  DEV_ENVIRONMENT, DEV_PROVISION_KID, devProvisionSigningKey,
} from "../shared/key-config.ts";
import { mintProvisionToken } from "../controller/core/issuer.ts";
import type { ProvisionBinding } from "../shared/registry.ts";
import {
  containerDoName,
  type ContainerIdentity, type ContainerRuntimeDescriptor, type DatabaseContainerDO,
} from "./database-container.ts";

export const LOCAL_TENANT = "local";

interface TestEnv {
  CONTAINER: DurableObjectNamespace<DatabaseContainerDO>;
}
export const containerTestEnv = env as unknown as TestEnv;

export function containerBinding(databaseId: string, tenantId = LOCAL_TENANT): ProvisionBinding {
  return { environment: DEV_ENVIRONMENT, tenantId, databaseId };
}

/** The DO stub at the REGISTRY-DERIVED name for a binding — the only name
 *  a correctly routed worker would use, and the only instance the
 *  provisioning transaction accepts for that binding. */
export function containerStub(binding: ProvisionBinding) {
  return containerTestEnv.CONTAINER.get(
    containerTestEnv.CONTAINER.idFromName(containerDoName(binding)));
}

export function devContainerProvisionToken(binding: ProvisionBinding): Promise<string> {
  return mintProvisionToken(devProvisionSigningKey(), binding, {
    nonce: crypto.randomUUID(), expiresAtMs: Date.now() + 60_000, kid: DEV_PROVISION_KID,
  });
}

/** The declared container-runtime descriptor of the local lane (R5-SEC-07:
 *  a DECLARED image identity — no Docker exists here; the seam the real
 *  Container resource binds to later). */
export const TEST_RUNTIME: ContainerRuntimeDescriptor = {
  imageDigest: `sha256:${"ab".repeat(32)}`,
  configDigest: "cd".repeat(32),
  expectedPort: 7000,
  protocolVersion: "typedb-container-control/1",
};

export function testIdentity(databaseId: string, overrides: Partial<ContainerIdentity> = {}): ContainerIdentity {
  return {
    databaseId, generation: 3, incarnation: 7, startupSessionId: "sess-ctr-1", ...overrides,
  };
}

/** The full wire shape of one provisioning request for a binding. */
export function provisionWire(
  binding: ProvisionBinding,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  const identity = testIdentity(binding.databaseId);
  return {
    environment: binding.environment,
    tenantId: binding.tenantId,
    databaseId: binding.databaseId,
    generation: identity.generation,
    incarnation: identity.incarnation,
    startupSessionId: identity.startupSessionId,
    containerRuntime: { ...TEST_RUNTIME },
    ...overrides,
  };
}

/** Provision an instance with the standard fixture identity/runtime; throws
 *  on refusal so positive-path suites stay terse. */
export async function provisionContainerInstance(
  instance: DatabaseContainerDO, binding: ProvisionBinding,
): Promise<void> {
  const result = await instance.provision(
    await devContainerProvisionToken(binding), provisionWire(binding));
  if (!result.ok) throw new Error(`test container provisioning failed: ${JSON.stringify(result)}`);
}
