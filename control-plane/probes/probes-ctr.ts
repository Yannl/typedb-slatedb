/*
 * P-CTR-01 .. P-CTR-04 and P-WORKER-01
 * (contract/typedb-r2-v16-platform-probes.md).
 *
 * Same endpoint contract in real mode (deployed probe-harness Worker) and
 * mock mode (deterministic fake): /ctr/* and /worker/*. Every assertion
 * is declared with its required modes (round-3 P-05).
 *
 * R4-CF-04 classification: every assertion here is class "provider-fact".
 * The harness (probes/harness-worker.ts in real mode, the in-process fake
 * in mock mode) simulates container lifecycle / rollout / sleep /
 * networking and gateway bounds as a labeled reference protocol
 * ({harness:true, simulated:true} where a Worker cannot faithfully run
 * the real platform behavior) — evidence of the pattern, never product
 * conformance by itself.
 */

import type { ProbeContext, ProbeImpl } from "./probe.ts";
import { asJson, BOTH, harnessGet, harnessPost } from "./probe.ts";

// ---------------------------------------------------------------------------
// P-CTR-01 — Lifecycle state machine.
// ---------------------------------------------------------------------------

const pCTR_01: ProbeImpl = {
  id: "P-CTR-01",
  expected:
    "lifecycle converges to platform truth: concurrent start idempotent, " +
    "stop-while-starting converges, duplicate stop is a no-op, stale " +
    "callbacks are rejected and never corrupt state",
  assertions: [
    { id: "reset-ok", title: "lifecycle reset", class: "provider-fact", required_in: BOTH },
    { id: "cold-start", title: "cold start enters starting@gen1", class: "provider-fact", required_in: BOTH },
    { id: "concurrent-start-idempotent", title: "concurrent start is idempotent, no second instance", class: "provider-fact", required_in: BOTH },
    { id: "stop-while-starting-converges", title: "stop while starting converges", class: "provider-fact", required_in: BOTH },
    { id: "duplicate-stop-noop", title: "duplicate stop is an explicit no-op", class: "provider-fact", required_in: BOTH },
    { id: "restart-advances-generation", title: "restart advances the generation", class: "provider-fact", required_in: BOTH },
    { id: "current-callback-completes", title: "current-generation callback completes startup", class: "provider-fact", required_in: BOTH },
    { id: "stale-callback-rejected", title: "stale lifecycle callback rejected", class: "provider-fact", required_in: BOTH },
    { id: "truth-intact", title: "platform truth intact after stale callback", class: "provider-fact", required_in: BOTH },
  ],
  async run(ctx: ProbeContext): Promise<void> {
    const reset = await harnessPost(ctx, "/ctr/lifecycle/reset");
    ctx.check("reset-ok", reset.status === 200, `got ${reset.status}`);

    // Cold start, then a concurrent duplicate start: one instance only.
    const start1 = asJson(await harnessPost(ctx, "/ctr/lifecycle/start"));
    ctx.check("cold-start", start1.state === "starting" && Number(start1.generation) === 1, `got ${JSON.stringify(start1)}`);
    const start2 = asJson(await harnessPost(ctx, "/ctr/lifecycle/start"));
    ctx.check(
      "concurrent-start-idempotent",
      start2.idempotent === true && Number(start2.generation) === 1,
      `got ${JSON.stringify(start2)}`,
    );

    // Stop while starting must converge to stopped, not wedge.
    const stop1 = asJson(await harnessPost(ctx, "/ctr/lifecycle/stop"));
    ctx.check("stop-while-starting-converges", stop1.state === "stopped", `got ${JSON.stringify(stop1)}`);
    const stop2 = asJson(await harnessPost(ctx, "/ctr/lifecycle/stop"));
    ctx.check("duplicate-stop-noop", stop2.noop === true, `got ${JSON.stringify(stop2)}`);

    // Restart and complete startup via the port-ready callback.
    const start3 = asJson(await harnessPost(ctx, "/ctr/lifecycle/start"));
    ctx.check("restart-advances-generation", Number(start3.generation) === 2, `got ${JSON.stringify(start3)}`);
    const ready = asJson(await harnessPost(ctx, "/ctr/lifecycle/port-ready", { generation: 2 }));
    ctx.check("current-callback-completes", ready.state === "running", `got ${JSON.stringify(ready)}`);

    // A stale callback from the previous generation must be ignored.
    const stale = await harnessPost(ctx, "/ctr/lifecycle/port-ready", { generation: 1 });
    ctx.check("stale-callback-rejected", stale.status === 409, `got ${stale.status}`);
    const status = asJson(await harnessGet(ctx, "/ctr/lifecycle/status"));
    ctx.check(
      "truth-intact",
      status.state === "running" && Number(status.generation) === 2,
      `got ${JSON.stringify(status)}`,
    );
  },
};

// ---------------------------------------------------------------------------
// P-CTR-02 — Mixed rollout.
// ---------------------------------------------------------------------------

const pCTR_02: ProbeImpl = {
  id: "P-CTR-02",
  expected:
    "only declared (worker, image) tuples are admitted; an unsupported " +
    "image never becomes database-ready; completion requires observed " +
    "convergence",
  assertions: [
    { id: "reset-ok", title: "rollout reset", class: "provider-fact", required_in: BOTH },
    { id: "declared-tuple-admitted", title: "declared tuple (worker 2, image 1) admitted", class: "provider-fact", required_in: BOTH },
    { id: "not-ready-before-convergence", title: "deployment is not complete before observed convergence", class: "provider-fact", required_in: BOTH },
    { id: "convergence-observed", title: "convergence observed", class: "provider-fact", required_in: BOTH },
    { id: "ready-after-convergence", title: "declared tuple becomes ready only after convergence", class: "provider-fact", required_in: BOTH },
    { id: "undeclared-tuple-refused", title: "undeclared tuple (worker 2, image 0) refused", class: "provider-fact", required_in: BOTH },
    { id: "unsupported-never-ready", title: "unsupported image never database-ready", class: "provider-fact", required_in: BOTH },
  ],
  async run(ctx: ProbeContext): Promise<void> {
    // Worker N=2 declares compatibility with images N-1=1 and N=2.
    const reset = await harnessPost(ctx, "/ctr/rollout/reset", { workerVersion: 2, supportedImages: [1, 2] });
    ctx.check("reset-ok", reset.status === 200, `got ${reset.status}`);

    // Deploy worker N with image N-1 running: admitted, but NOT ready
    // until convergence is actually observed.
    const dep1 = await harnessPost(ctx, "/ctr/rollout/deploy", { image: 1 });
    ctx.check("declared-tuple-admitted", dep1.status === 200, `got ${dep1.status}`);
    const preConverge = asJson(await harnessGet(ctx, "/ctr/rollout/status"));
    ctx.check("not-ready-before-convergence", preConverge.ready === false, `got ${JSON.stringify(preConverge)}`);
    const obs = await harnessPost(ctx, "/ctr/rollout/observe-convergence");
    ctx.check("convergence-observed", obs.status === 200, `got ${obs.status}`);
    const postConverge = asJson(await harnessGet(ctx, "/ctr/rollout/status"));
    ctx.check(
      "ready-after-convergence",
      postConverge.ready === true && Number(postConverge.image) === 1,
      `got ${JSON.stringify(postConverge)}`,
    );

    // An undeclared image (old-image restart after rollback) must be
    // refused by the envelope and must never become database-ready.
    const dep0 = await harnessPost(ctx, "/ctr/rollout/deploy", { image: 0 });
    ctx.check("undeclared-tuple-refused", dep0.status === 409, `got ${dep0.status}`);
    const after = asJson(await harnessGet(ctx, "/ctr/rollout/status"));
    ctx.check(
      "unsupported-never-ready",
      !(after.ready === true && Number(after.image) === 0),
      `got ${JSON.stringify(after)}`,
    );
  },
};

// ---------------------------------------------------------------------------
// P-CTR-03 — Sleep and shutdown.
// ---------------------------------------------------------------------------

const pCTR_03: ProbeImpl = {
  id: "P-CTR-03",
  expected:
    "no inactivity stop while a transaction is open (controller-denied " +
    "hibernation); safe inactivity stop otherwise; acknowledged state " +
    "survives SIGKILL",
  assertions: [
    { id: "reset-ok", title: "sleep state reset", class: "provider-fact", required_in: BOTH },
    { id: "w1-acked", title: "write w1 acknowledged", class: "provider-fact", required_in: BOTH },
    { id: "no-stop-with-open-txn", title: "no inactivity stop while a transaction is open", class: "provider-fact", required_in: BOTH },
    { id: "hibernation-denied", title: "hibernation was actively denied", class: "provider-fact", required_in: BOTH },
    { id: "safe-stop-when-idle", title: "safe inactivity stop occurs once no work is open", class: "provider-fact", required_in: BOTH },
    { id: "w2-acked", title: "write w2 acknowledged", class: "provider-fact", required_in: BOTH },
    { id: "kill-applied", title: "SIGKILL applied", class: "provider-fact", required_in: BOTH },
    { id: "acked-survives-kill", title: "acknowledged state recovered intact after kill", class: "provider-fact", required_in: BOTH },
  ],
  async run(ctx: ProbeContext): Promise<void> {
    const reset = await harnessPost(ctx, "/ctr/sleep/reset", { sleepAfter: 3 });
    ctx.check("reset-ok", reset.status === 200, `got ${reset.status}`);

    const w1 = await harnessPost(ctx, "/ctr/sleep/write", { data: "w1" });
    ctx.check("w1-acked", asJson(w1).acked === true, "acked flag compared");

    // Idle past sleepAfter WITH an open transaction: stopping would be
    // unsafe, so the controller must deny hibernation.
    await harnessPost(ctx, "/ctr/sleep/txn-open");
    for (let i = 0; i < 4; i++) await harnessPost(ctx, "/ctr/sleep/tick");
    const busy = asJson(await harnessGet(ctx, "/ctr/sleep/state"));
    ctx.check("no-stop-with-open-txn", busy.state === "running", `got state=${busy.state}`);
    ctx.check("hibernation-denied", Number(busy.deniedStops) >= 1, `got ${busy.deniedStops}`);

    // Close the transaction: the default inactivity stop is now safe.
    await harnessPost(ctx, "/ctr/sleep/txn-close");
    await harnessPost(ctx, "/ctr/sleep/tick");
    const idle = asJson(await harnessGet(ctx, "/ctr/sleep/state"));
    ctx.check("safe-stop-when-idle", idle.state === "stopped", `got ${idle.state}`);

    // Arbitrary kill: acknowledged state must survive recovery.
    await harnessPost(ctx, "/ctr/sleep/recover");
    const w2 = await harnessPost(ctx, "/ctr/sleep/write", { data: "w2" });
    ctx.check("w2-acked", asJson(w2).acked === true, "acked flag compared");
    const kill = asJson(await harnessPost(ctx, "/ctr/sleep/kill"));
    ctx.check("kill-applied", kill.state === "killed", `got ${kill.state}`);
    await harnessPost(ctx, "/ctr/sleep/recover");
    const recovered = asJson(await harnessGet(ctx, "/ctr/sleep/state"));
    ctx.check(
      "acked-survives-kill",
      recovered.state === "running" && JSON.stringify(recovered.acked) === JSON.stringify(["w1", "w2"]),
      `got ${JSON.stringify(recovered.acked)}`,
    );
  },
};

// ---------------------------------------------------------------------------
// P-CTR-04 — Networking and placement.
// ---------------------------------------------------------------------------

const pCTR_04: ProbeImpl = {
  id: "P-CTR-04",
  expected:
    "no colocation assumption; unauthorized egress denied; " +
    "enableInternet=false denies all egress; possibly-committed operations " +
    "remain queryable after client disconnect",
  assertions: [
    { id: "reset-ok", title: "network state reset", class: "provider-fact", required_in: BOTH },
    { id: "not-colocated", title: "DO and container are NOT colocated", class: "provider-fact", required_in: BOTH },
    { id: "internal-http-ok", title: "internal HTTP works across locations", class: "provider-fact", required_in: BOTH },
    { id: "allowlisted-egress-ok", title: "allowlisted egress permitted", class: "provider-fact", required_in: BOTH },
    { id: "unauthorized-egress-denied", title: "unauthorized egress denied", class: "provider-fact", required_in: BOTH },
    { id: "internet-off-denies-all", title: "enableInternet=false denies all egress", class: "provider-fact", required_in: BOTH },
    { id: "disconnect-observed", title: "client observes the disconnect", class: "provider-fact", required_in: BOTH },
    { id: "committed-still-queryable", title: "possibly-committed operation remains queryable", class: "provider-fact", required_in: BOTH },
  ],
  async run(ctx: ProbeContext): Promise<void> {
    const reset = await harnessPost(ctx, "/ctr/net/reset", {
      allowlist: ["registry.internal"],
      enableInternet: true,
    });
    ctx.check("reset-ok", reset.status === 200, `got ${reset.status}`);

    // Lifecycle DO and container in separate locations; internal HTTP works.
    const placement = asJson(await harnessGet(ctx, "/ctr/net/placement"));
    ctx.check("not-colocated", placement.doLocation !== placement.containerLocation, `got ${JSON.stringify(placement)}`);
    ctx.check("internal-http-ok", placement.internalHttp === "ok", `got ${placement.internalHttp}`);

    // Egress allowlist enforcement.
    const allowed = await harnessPost(ctx, "/ctr/net/egress", { host: "registry.internal" });
    ctx.check("allowlisted-egress-ok", allowed.status === 200, `got ${allowed.status}`);
    const denied = await harnessPost(ctx, "/ctr/net/egress", { host: "exfil.example.com" });
    ctx.check("unauthorized-egress-denied", denied.status === 403, `got ${denied.status}`);

    // enableInternet=false: even allowlisted egress is dead.
    await harnessPost(ctx, "/ctr/net/config", { enableInternet: false });
    const offline = await harnessPost(ctx, "/ctr/net/egress", { host: "registry.internal" });
    ctx.check("internet-off-denies-all", offline.status === 403, `got ${offline.status}`);
    await harnessPost(ctx, "/ctr/net/config", { enableInternet: true });

    // Client disconnect during a mutating call: the operation may have
    // committed; it must remain queryable, never lost in ambiguity.
    const prep = asJson(await harnessPost(ctx, "/ctr/net/op-prepare"));
    const opId = String(prep.opId);
    const disc = await harnessPost(ctx, "/ctr/net/commit-with-disconnect", { opId });
    ctx.check("disconnect-observed", disc.status === 599, `got ${disc.status}`);
    const op = asJson(await harnessGet(ctx, `/ctr/net/op/${opId}`));
    ctx.check("committed-still-queryable", op.state === "committed", `got ${JSON.stringify(op)}`);
  },
};

// ---------------------------------------------------------------------------
// P-WORKER-01 — Gateway bounds.
// ---------------------------------------------------------------------------

const pWORKER_01: ProbeImpl = {
  id: "P-WORKER-01",
  expected:
    "streaming stays within the buffer bound (no full buffering); no " +
    "success receipt before exact remote resolution; six-connection " +
    "saturation queues instead of failing incorrectly",
  assertions: [
    { id: "reset-ok", title: "gateway reset", class: "provider-fact", required_in: BOTH },
    { id: "stream-complete", title: "streamed object is complete", class: "provider-fact", required_in: BOTH },
    { id: "stream-pattern-exact", title: "streamed bytes match the deterministic pattern", class: "provider-fact", required_in: BOTH },
    { id: "buffer-bounded", title: "gateway held at most the buffer bound in memory (no full buffering)", class: "provider-fact", required_in: BOTH },
    { id: "upstream-5xx-surfaces", title: "upstream 5xx surfaces as gateway failure", class: "provider-fact", required_in: BOTH },
    { id: "no-premature-receipt", title: "no success receipt issued for an unresolved remote operation", class: "provider-fact", required_in: BOTH },
    { id: "permits-capped-at-six", title: "connection permits capped at six", class: "provider-fact", required_in: BOTH },
    { id: "excess-queued", title: "excess connection queued, not dropped", class: "provider-fact", required_in: BOTH },
    { id: "no-incorrect-success", title: "saturation produced no incorrect success", class: "provider-fact", required_in: BOTH },
  ],
  async run(ctx: ProbeContext): Promise<void> {
    const BOUND = 65536;
    const SIZE = 1048576; // 16x the bound: full buffering is unmistakable
    const reset = await harnessPost(ctx, "/worker/gateway/reset", { bufferBound: BOUND });
    ctx.check("reset-ok", reset.status === 200, `got ${reset.status}`);

    // Stream an object well above the bound.
    const stream = await harnessGet(ctx, `/worker/gateway/stream?bytes=${SIZE}`);
    ctx.check("stream-complete", stream.status === 200 && stream.body.length === SIZE, `got ${stream.body.length} bytes`);
    ctx.check(
      "stream-pattern-exact",
      stream.body[0] === 0 && stream.body[SIZE - 1] === (SIZE - 1) % 251,
      "first/last pattern bytes compared",
    );
    const maxBuffered = Number(stream.headers["x-max-buffered-bytes"]);
    ctx.check(
      "buffer-bounded",
      Number.isFinite(maxBuffered) && maxBuffered <= BOUND,
      `held ${maxBuffered} bytes, bound ${BOUND}`,
    );

    // Upstream R2 5xx: failure surfaces; no success receipt is minted
    // before exact remote resolution.
    const upstreamFail = await harnessGet(ctx, "/worker/gateway/object?fail=r2-500");
    ctx.check("upstream-5xx-surfaces", upstreamFail.status === 502, `got ${upstreamFail.status}`);
    ctx.check(
      "no-premature-receipt",
      upstreamFail.headers["x-success-receipt"] === "none",
      `got ${upstreamFail.headers["x-success-receipt"]}`,
    );

    // Six-connection saturation: excess demand queues; nothing is
    // reported successful that did not run.
    const sat = asJson(await harnessPost(ctx, "/worker/gateway/saturate", { connections: 7 }));
    ctx.check("permits-capped-at-six", Number(sat.peakConcurrent) === 6, `got ${sat.peakConcurrent}`);
    ctx.check("excess-queued", Number(sat.queued) === 1, `got ${sat.queued}`);
    ctx.check("no-incorrect-success", sat.incorrectSuccess === false, `got ${sat.incorrectSuccess}`);
  },
};

export const CTR_PROBES: ReadonlyArray<ProbeImpl> = [pCTR_01, pCTR_02, pCTR_03, pCTR_04];
export const WORKER_PROBES: ReadonlyArray<ProbeImpl> = [pWORKER_01];
