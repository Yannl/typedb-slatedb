/*
 * R8-P2-03: /live and /ready mean different things, and the old /health meant
 * neither.
 *
 * The audited endpoint returned `{ ok: true, runtime: "workerd", stack:
 * "L1-local" }` BEFORE resolving any managed configuration. Two consequences,
 * both pinned here:
 *
 *   * it said "ok" on a deployment whose key configuration was absent or
 *     malformed - so a load balancer would keep sending traffic to a Worker
 *     that refuses every authenticated route;
 *   * it reported `stack: "L1-local"` unconditionally, including in managed
 *     posture, where it is simply false - and posture is exactly what a
 *     readiness probe is asked about.
 *
 * Separately, `resolveKeysOr500` returned the raw `KeyConfigError.message` to
 * the caller: environment variable names, keyring entry indices, supplied
 * `kid` values, profile strings and the structure of the malformed input. That
 * is a map of the deployment's key configuration, handed to whoever can reach
 * the route. The caller now gets a stable code and a correlation id; the
 * detail is logged.
 *
 * These run in workerd (`SELF`) because the entry module imports
 * `cloudflare:workers`, so the routing cannot be exercised under plain node.
 */
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

const BASE = "https://controller.local";

describe("R8-P2-03 liveness and readiness are distinct", () => {
  it("/live answers without consulting any dependency", async () => {
    const res = await SELF.fetch(`${BASE}/live`);
    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown>;
    expect(body.ok).toBe(true);
    expect(body.probe).toBe("live");
    // the old endpoint's unconditional `stack: "L1-local"` claim is gone
    expect(body.stack).toBeUndefined();
  });

  it("/health is a retained alias of /live and says so", async () => {
    const res = await SELF.fetch(`${BASE}/health`);
    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown>;
    expect(body.probe).toBe("live");
    expect(String(body.note)).toMatch(/alias of \/live/);
    expect(body.stack).toBeUndefined();
  });

  it("/ready reports the deployment's TRUE posture, not a constant", async () => {
    // this suite runs against wrangler.local-dev.toml, whose
    // CONTROLLER_SURFACE is "local-dev"; a managed deployment reports
    // "managed", which the old endpoint could not express at all.
    const res = await SELF.fetch(`${BASE}/ready`);
    const body = await res.json() as Record<string, unknown>;
    expect(body.probe).toBe("ready");
    expect(body.posture).toBe("local-dev");
    expect(res.status).toBe(200);
    expect(body.ok).toBe(true);
  });

  it("neither probe returns key-configuration detail", async () => {
    for (const path of ["/live", "/ready", "/health"]) {
      const text = await (await SELF.fetch(`${BASE}${path}`)).text();
      for (const secretish of [
        "DEV_ISSUER_SECRET",
        "CONTROLLER_KEY_PROFILE",
        "keyring",
        "kid",
        "CAPABILITY_VERIFY",
      ]) {
        expect(text, `${path} names ${secretish}`).not.toContain(secretish);
      }
    }
  });

  it("an unready refusal carries a correlation id, and a ready one does not need to", async () => {
    // Shape assertion on the ready path: the 503 branch is exercised by the
    // managed-posture unit lane (a workerd test cannot un-provision the
    // binding this pool created), so what is pinned HERE is that the ready
    // response carries no detail field to leak through.
    const body = await (await SELF.fetch(`${BASE}/ready`)).json() as Record<string, unknown>;
    expect(body.detail).toBeUndefined();
    expect(Object.keys(body).sort()).toEqual(["ok", "posture", "probe", "runtime"]);
  });
});
