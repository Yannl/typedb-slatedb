/*
 * R5-SEC-06 mandatory security mutants at the ContainerDO provisioning seam,
 * under REAL workerd — mirrors the ControllerDO suite
 * (controller/provisioning.workerd.test.ts):
 *
 *   - direct unbound observation (read AND write) -> typed refusal, ZERO
 *     side effects (the first-call squat is dead);
 *   - an ordinary caller attempting to bind: no observation call binds, and
 *     the strongest forgery — the CAPABILITY issuer key signing a
 *     provision-shaped token — fails the provisioning signature;
 *   - two tenants race the first call -> exactly one binding wins, the
 *     loser gets a typed refusal, the record is never partial/overwritten;
 *   - wrong-but-valid principal (a genuine token for ANOTHER database or
 *     tenant) -> refused;
 *   - the caller-controlled database id is ignored in favor of the VERIFIED
 *     token binding (a wire id the token does not bind refuses);
 *   - stale controller incarnation -> typed refusal at provisioning AND on
 *     ordinary calls;
 *   - provisioning replay is idempotent (identical record only).
 */
import { runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { devCapabilitySigningKey } from "../shared/key-config.ts";
import { mintProvisionToken } from "../controller/core/issuer.ts";
import { containerDoName, type DatabaseContainerDO } from "./database-container.ts";
import {
  containerBinding, containerStub, containerTestEnv, devContainerProvisionToken,
  provisionWire, TEST_RUNTIME, testIdentity,
} from "./container-test-support.ts";

const RUNTIME_CLAIM = {
  imageDigest: TEST_RUNTIME.imageDigest, protocolVersion: TEST_RUNTIME.protocolVersion,
};

function observation() {
  return { kind: "STARTED", at: Date.now(), processNonce: "proc-A" };
}

describe("R5-SEC-06 ContainerDO provisioning seam mutants (workerd)", () => {
  it("MUTANT (direct unbound observation): reads and writes on an unprovisioned DO fail typed with zero side effects", async () => {
    const binding = containerBinding("ctr-unbound");
    await runInDurableObject(containerStub(binding), async (instance: DatabaseContainerDO) => {
      const identity = testIdentity(binding.databaseId);
      expect(instance.recordObservation(identity, observation(), RUNTIME_CLAIM))
        .toEqual({ ok: false, error: "CONTAINER_UNPROVISIONED" });
      expect(instance.getObservations(identity))
        .toEqual({ ok: false, error: "CONTAINER_UNPROVISIONED" });
      // the HTTP ingress refuses identically
      const viaHttp = await instance.fetch(new Request("https://container/observe", {
        method: "POST",
        body: JSON.stringify({ identity, observation: observation(), containerRuntime: RUNTIME_CLAIM }),
      }));
      expect(viaHttp.status).toBe(403);
      expect(((await viaHttp.json()) as { error: string }).error).toBe("CONTAINER_UNPROVISIONED");
      // the squat check: NO call above bound anything
      expect(instance.getProvisionRecord()).toBeNull();
    });
  });

  it("MUTANT (squat via forged provisioning): capability-scope signing material cannot provision; the DO stays unbound", async () => {
    const binding = containerBinding("ctr-squat");
    await runInDurableObject(containerStub(binding), async (instance: DatabaseContainerDO) => {
      // the strongest ordinary-caller forgery: a provision-SHAPED token
      // signed with the CAPABILITY issuer key — the signature cannot
      // validate under the provisioning scope's public key (R5-SEC-03)
      const forged = await mintProvisionToken(devCapabilitySigningKey(), binding, {
        nonce: crypto.randomUUID(), expiresAtMs: Date.now() + 60_000,
      });
      const result = await instance.provision(forged, provisionWire(binding));
      expect(result).toEqual({ ok: false, error: "CAPABILITY_SIGNATURE_INVALID" });
      expect(instance.getProvisionRecord()).toBeNull();
      // and garbage tokens never bind either
      expect(await instance.provision("not-a-token", provisionWire(binding)))
        .toEqual({ ok: false, error: "CAPABILITY_MALFORMED" });
      expect(instance.getProvisionRecord()).toBeNull();
    });
  });

  it("MUTANT (two-tenant race): exactly one binding wins; the loser is typed; no partial or overwritten record", async () => {
    const bindingA = containerBinding("race-db", "tenant-a");
    const bindingB = containerBinding("race-db", "tenant-b");
    await runInDurableObject(containerStub(bindingA), async (instance: DatabaseContainerDO) => {
      // tenant A wins the first provisioning of ITS derived DO
      const first = await instance.provision(await devContainerProvisionToken(bindingA), provisionWire(bindingA));
      expect(first).toMatchObject({ ok: true, created: true });
      // tenant B races with a token genuinely valid for ITS OWN binding —
      // but this instance is not tenant B's derived DO identity: refused
      // before any durable work
      const cross = await instance.provision(await devContainerProvisionToken(bindingB), provisionWire(bindingB));
      expect(cross).toEqual({ ok: false, error: "PROVISION_DO_MISROUTED" });
      // a second provisioner for the SAME derived DO but a DIFFERENT record
      // (new generation) is the typed conflict loser
      const conflicting = await instance.provision(
        await devContainerProvisionToken(bindingA), provisionWire(bindingA, { generation: 4 }));
      expect(conflicting).toEqual({ ok: false, error: "PROVISION_CONFLICT" });
      // no partial or overwritten binding: the record is exactly A's original
      const record = instance.getProvisionRecord();
      expect(record?.binding).toEqual(bindingA);
      expect(record?.identity).toEqual(testIdentity(bindingA.databaseId));
      expect(record?.doName).toBe(containerDoName(bindingA));
      expect(record?.containerRuntime).toEqual(TEST_RUNTIME);
      // the winner's exact replay stays idempotent
      const replay = await instance.provision(await devContainerProvisionToken(bindingA), provisionWire(bindingA));
      expect(replay).toMatchObject({ ok: true, created: false });
    });
  });

  it("MUTANT (wrong-but-valid principal): a genuine token for another database or tenant is refused, nothing binds", async () => {
    const binding = containerBinding("ctr-principal");
    const otherDb = containerBinding("ctr-principal-other");
    const otherTenant = containerBinding("ctr-principal", "tenant-x");
    await runInDurableObject(containerStub(binding), async (instance: DatabaseContainerDO) => {
      // a token for ANOTHER DATABASE presented with this DO's wire binding:
      // the token's audience does not bind this database -> refused
      const wrongDb = await instance.provision(await devContainerProvisionToken(otherDb), provisionWire(binding));
      expect(wrongDb).toEqual({ ok: false, error: "CAPABILITY_AUDIENCE_MISMATCH" });
      // a token for ANOTHER TENANT of the same database id -> refused
      const wrongTenant = await instance.provision(await devContainerProvisionToken(otherTenant), provisionWire(binding));
      expect(wrongTenant).toEqual({ ok: false, error: "CAPABILITY_TENANT_MISMATCH" });
      expect(instance.getProvisionRecord()).toBeNull();
    });
  });

  it("MUTANT (caller-controlled database id): the wire id carries no authority — only the VERIFIED token binding provisions", async () => {
    const tokenBinding = containerBinding("ctr-honest-db");
    await runInDurableObject(containerStub(tokenBinding), async (instance: DatabaseContainerDO) => {
      const token = await devContainerProvisionToken(tokenBinding);
      // the caller swaps in a database id the token does not bind: the
      // token/wire cross-check refuses before any durable work
      const swapped = await instance.provision(
        token, provisionWire(tokenBinding, { databaseId: "victim-db" }));
      expect(swapped).toEqual({ ok: false, error: "CAPABILITY_AUDIENCE_MISMATCH" });
      expect(instance.getProvisionRecord()).toBeNull();
      // with the honest wire, the SAME token provisions exactly its own binding
      const honest = await instance.provision(token, provisionWire(tokenBinding));
      expect(honest).toMatchObject({ ok: true, created: true });
      expect(instance.getProvisionRecord()?.binding).toEqual(tokenBinding);
    });
  });

  it("MUTANT (stale controller incarnation): refused at provisioning replay AND on ordinary calls", async () => {
    const binding = containerBinding("ctr-stale");
    await runInDurableObject(containerStub(binding), async (instance: DatabaseContainerDO) => {
      const current = await instance.provision(await devContainerProvisionToken(binding), provisionWire(binding));
      expect(current).toMatchObject({ ok: true, created: true });
      const bound = testIdentity(binding.databaseId);
      // a superseded controller replays its OLD provisioning (lower
      // incarnation): typed as STALE, the standing record survives
      const stale = await instance.provision(
        await devContainerProvisionToken(binding),
        provisionWire(binding, { incarnation: bound.incarnation - 1 }));
      expect(stale).toEqual({ ok: false, error: "PROVISION_STALE_CONTROLLER" });
      expect(instance.getProvisionRecord()?.identity.incarnation).toBe(bound.incarnation);
      // an ordinary caller presenting the stale incarnation is refused typed
      const staleCall = instance.recordObservation(
        { ...bound, incarnation: bound.incarnation - 1 }, observation(), RUNTIME_CLAIM);
      expect(staleCall).toEqual({ ok: false, error: "DO_CONTAINER_BINDING_MISMATCH" });
    });
  });

  it("MUTANT (provision replay): the identical provisioning transaction is idempotent — same record, created:false", async () => {
    const binding = containerBinding("ctr-replay");
    await runInDurableObject(containerStub(binding), async (instance: DatabaseContainerDO) => {
      const first = await instance.provision(await devContainerProvisionToken(binding), provisionWire(binding));
      expect(first).toMatchObject({ ok: true, created: true });
      // replay with a FRESH token (nonces differ) but the identical record
      const replay = await instance.provision(await devContainerProvisionToken(binding), provisionWire(binding));
      expect(replay).toMatchObject({ ok: true, created: false });
      if (first.ok && replay.ok) expect(replay.record).toEqual(first.record);
      // ...and a divergent containerRuntime is NOT a replay: typed conflict
      const divergent = await instance.provision(
        await devContainerProvisionToken(binding),
        provisionWire(binding, {
          containerRuntime: { ...TEST_RUNTIME, imageDigest: `sha256:${"ff".repeat(32)}` },
        }));
      expect(divergent).toEqual({ ok: false, error: "PROVISION_CONFLICT" });
    });
  });

  it("provisioning validates the containerRuntime descriptor fail-closed, naming the field (R5-SEC-07 seam)", async () => {
    const binding = containerBinding("ctr-descriptor");
    await runInDurableObject(containerStub(binding), async (instance: DatabaseContainerDO) => {
      const token = await devContainerProvisionToken(binding);
      const cases: Array<[Record<string, unknown>, string]> = [
        [{ containerRuntime: undefined }, "containerRuntime"],
        [{ containerRuntime: { ...TEST_RUNTIME, imageDigest: "latest" } }, "imageDigest"],
        [{ containerRuntime: { ...TEST_RUNTIME, configDigest: "beef" } }, "configDigest"],
        [{ containerRuntime: { ...TEST_RUNTIME, expectedPort: 0 } }, "expectedPort"],
        [{ containerRuntime: { ...TEST_RUNTIME, expectedPort: 65536 } }, "expectedPort"],
        [{ containerRuntime: { ...TEST_RUNTIME, protocolVersion: "" } }, "protocolVersion"],
      ];
      for (const [override, field] of cases) {
        expect(await instance.provision(token, provisionWire(binding, override)))
          .toEqual({ ok: false, error: "CONTAINER_RUNTIME_INVALID", field });
      }
      expect(instance.getProvisionRecord()).toBeNull();
      // the well-formed descriptor provisions, and the record carries it
      const ok = await instance.provision(token, provisionWire(binding));
      expect(ok).toMatchObject({ ok: true, created: true });
      expect(instance.getProvisionRecord()?.containerRuntime).toEqual(TEST_RUNTIME);
    });
  });

  it("a mis-routed DO id cannot be provisioned even with a fully valid token (derived-identity check)", async () => {
    const binding = containerBinding("ctr-misroute");
    // an attacker-chosen / arbitrary DO name, NOT the registry derivation
    const foreignStub = containerTestEnv.CONTAINER.get(
      containerTestEnv.CONTAINER.idFromName("attacker-chosen-name"));
    await runInDurableObject(foreignStub, async (instance: DatabaseContainerDO) => {
      const result = await instance.provision(
        await devContainerProvisionToken(binding), provisionWire(binding));
      expect(result).toEqual({ ok: false, error: "PROVISION_DO_MISROUTED" });
      expect(instance.getProvisionRecord()).toBeNull();
    });
  });
});
