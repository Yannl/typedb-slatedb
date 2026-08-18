/*
 * P-CTR-01 .. P-CTR-04 and P-WORKER-01
 * (contract/typedb-r2-v16-platform-probes.md).
 *
 * Same endpoint contract in real mode (deployed probe-harness Worker) and
 * mock mode (deterministic fake): /ctr/* and /worker/*.
 */

import type { ProbeContext, ProbeImpl } from "./probe.ts";
import { asJson, harnessGet, harnessPost } from "./probe.ts";

// ---------------------------------------------------------------------------
// P-CTR-01 — Lifecycle state machine.
// ---------------------------------------------------------------------------

const pCTR_01: ProbeImpl = {
  id: "P-CTR-01",
  expected:
    "lifecycle converges to platform truth: concurrent start idempotent, " +
    "stop-while-starting converges, duplicate stop is a no-op, stale " +
    "callbacks are rejected and never corrupt state",
  async run(ctx: ProbeContext): Promise<void> {
    const reset = await harnessPost(ctx, "/ctr/lifecycle/reset");
    ctx.check(reset.status === 200, `lifecycle reset (got ${reset.status})`);

    // Cold start, then a concurrent duplicate start: one instance only.
    const start1 = asJson(await harnessPost(ctx, "/ctr/lifecycle/start"));
    ctx.check(start1.state === "starting" && Number(start1.generation) === 1, `cold start enters starting@gen1 (got ${JSON.stringify(start1)})`);
    const start2 = asJson(await harnessPost(ctx, "/ctr/lifecycle/start"));
    ctx.check(
      start2.idempotent === true && Number(start2.generation) === 1,
      `concurrent start is idempotent, no second instance (got ${JSON.stringify(start2)})`,
    );

    // Stop while starting must converge to stopped, not wedge.
    const stop1 = asJson(await harnessPost(ctx, "/ctr/lifecycle/stop"));
    ctx.check(stop1.state === "stopped", `stop while starting converges (got ${JSON.stringify(stop1)})`);
    const stop2 = asJson(await harnessPost(ctx, "/ctr/lifecycle/stop"));
    ctx.check(stop2.noop === true, `duplicate stop is an explicit no-op (got ${JSON.stringify(stop2)})`);

    // Restart and complete startup via the port-ready callback.
    const start3 = asJson(await harnessPost(ctx, "/ctr/lifecycle/start"));
    ctx.check(Number(start3.generation) === 2, `restart advances the generation (got ${JSON.stringify(start3)})`);
    const ready = asJson(await harnessPost(ctx, "/ctr/lifecycle/port-ready", { generation: 2 }));
    ctx.check(ready.state === "running", `current-generation callback completes startup (got ${JSON.stringify(ready)})`);

    // A stale callback from the previous generation must be ignored.
    const stale = await harnessPost(ctx, "/ctr/lifecycle/port-ready", { generation: 1 });
    ctx.check(stale.status === 409, `stale lifecycle callback rejected (got ${stale.status})`);
    const status = asJson(await harnessGet(ctx, "/ctr/lifecycle/status"));
    ctx.check(
      status.state === "running" && Number(status.generation) === 2,
      `platform truth intact after stale callback (got ${JSON.stringify(status)})`,
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
  async run(ctx: ProbeContext): Promise<void> {
    // Worker N=2 declares compatibility with images N-1=1 and N=2.
    const reset = await harnessPost(ctx, "/ctr/rollout/reset", { workerVersion: 2, supportedImages: [1, 2] });
    ctx.check(reset.status === 200, `rollout reset (got ${reset.status})`);

    // Deploy worker N with image N-1 running: admitted, but NOT ready
    // until convergence is actually observed.
    const dep1 = await harnessPost(ctx, "/ctr/rollout/deploy", { image: 1 });
    ctx.check(dep1.status === 200, `declared tuple (worker 2, image 1) admitted (got ${dep1.status})`);
    const preConverge = asJson(await harnessGet(ctx, "/ctr/rollout/status"));
    ctx.check(
      preConverge.ready === false,
      `deployment is not complete before observed convergence (got ${JSON.stringify(preConverge)})`,
    );
    const obs = await harnessPost(ctx, "/ctr/rollout/observe-convergence");
    ctx.check(obs.status === 200, `convergence observed (got ${obs.status})`);
    const postConverge = asJson(await harnessGet(ctx, "/ctr/rollout/status"));
    ctx.check(
      postConverge.ready === true && Number(postConverge.image) === 1,
      `declared tuple becomes ready only after convergence (got ${JSON.stringify(postConverge)})`,
    );

    // An undeclared image (old-image restart after rollback) must be
    // refused by the envelope and must never become database-ready.
    const dep0 = await harnessPost(ctx, "/ctr/rollout/deploy", { image: 0 });
    ctx.check(dep0.status === 409, `undeclared tuple (worker 2, image 0) refused (got ${dep0.status})`);
    const after = asJson(await harnessGet(ctx, "/ctr/rollout/status"));
    ctx.check(
      !(after.ready === true && Number(after.image) === 0),
      `unsupported image never database-ready (got ${JSON.stringify(after)})`,
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
  async run(ctx: ProbeContext): Promise<void> {
    const reset = await harnessPost(ctx, "/ctr/sleep/reset", { sleepAfter: 3 });
    ctx.check(reset.status === 200, `sleep state reset (got ${reset.status})`);

    const w1 = await harnessPost(ctx, "/ctr/sleep/write", { data: "w1" });
    ctx.check(asJson(w1).acked === true, "write w1 acknowledged");

    // Idle past sleepAfter WITH an open transaction: stopping would be
    // unsafe, so the controller must deny hibernation.
    await harnessPost(ctx, "/ctr/sleep/txn-open");
    for (let i = 0; i < 4; i++) await harnessPost(ctx, "/ctr/sleep/tick");
    const busy = asJson(await harnessGet(ctx, "/ctr/sleep/state"));
    ctx.check(
      busy.state === "running",
      `no inactivity stop while a transaction is open (got state=${busy.state})`,
    );
    ctx.check(Number(busy.deniedStops) >= 1, `hibernation was actively denied (got ${busy.deniedStops})`);

    // Close the transaction: the default inactivity stop is now safe.
    await harnessPost(ctx, "/ctr/sleep/txn-close");
    await harnessPost(ctx, "/ctr/sleep/tick");
    const idle = asJson(await harnessGet(ctx, "/ctr/sleep/state"));
    ctx.check(idle.state === "stopped", `safe inactivity stop occurs once no work is open (got ${idle.state})`);

    // Arbitrary kill: acknowledged state must survive recovery.
    await harnessPost(ctx, "/ctr/sleep/recover");
    const w2 = await harnessPost(ctx, "/ctr/sleep/write", { data: "w2" });
    ctx.check(asJson(w2).acked === true, "write w2 acknowledged");
    const kill = asJson(await harnessPost(ctx, "/ctr/sleep/kill"));
    ctx.check(kill.state === "killed", `SIGKILL applied (got ${kill.state})`);
    await harnessPost(ctx, "/ctr/sleep/recover");
    const recovered = asJson(await harnessGet(ctx, "/ctr/sleep/state"));
    ctx.check(
      recovered.state === "running" && JSON.stringify(recovered.acked) === JSON.stringify(["w1", "w2"]),
      `acknowledged state recovered intact after kill (got ${JSON.stringify(recovered.acked)})`,
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
  async run(ctx: ProbeContext): Promise<void> {
    const reset = await harnessPost(ctx, "/ctr/net/reset", {
      allowlist: ["registry.internal"],
      enableInternet: true,
    });
    ctx.check(reset.status === 200, `network state reset (got ${reset.status})`);

    // Lifecycle DO and container in separate locations; internal HTTP works.
    const placement = asJson(await harnessGet(ctx, "/ctr/net/placement"));
    ctx.check(
      placement.doLocation !== placement.containerLocation,
      `DO and container are NOT colocated (got ${JSON.stringify(placement)})`,
    );
    ctx.check(placement.internalHttp === "ok", "internal HTTP works across locations");

    // Egress allowlist enforcement.
    const allowed = await harnessPost(ctx, "/ctr/net/egress", { host: "registry.internal" });
    ctx.check(allowed.status === 200, `allowlisted egress permitted (got ${allowed.status})`);
    const denied = await harnessPost(ctx, "/ctr/net/egress", { host: "exfil.example.com" });
    ctx.check(denied.status === 403, `unauthorized egress denied (got ${denied.status})`);

    // enableInternet=false: even allowlisted egress is dead.
    await harnessPost(ctx, "/ctr/net/config", { enableInternet: false });
    const offline = await harnessPost(ctx, "/ctr/net/egress", { host: "registry.internal" });
    ctx.check(offline.status === 403, `enableInternet=false denies all egress (got ${offline.status})`);
    await harnessPost(ctx, "/ctr/net/config", { enableInternet: true });

    // Client disconnect during a mutating call: the operation may have
    // committed; it must remain queryable, never lost in ambiguity.
    const prep = asJson(await harnessPost(ctx, "/ctr/net/op-prepare"));
    const opId = String(prep.opId);
    const disc = await harnessPost(ctx, "/ctr/net/commit-with-disconnect", { opId });
    ctx.check(disc.status === 599, `client observes the disconnect (got ${disc.status})`);
    const op = asJson(await harnessGet(ctx, `/ctr/net/op/${opId}`));
    ctx.check(op.state === "committed", `possibly-committed operation remains queryable (got ${JSON.stringify(op)})`);
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
  async run(ctx: ProbeContext): Promise<void> {
    const BOUND = 65536;
    const SIZE = 1048576; // 16x the bound: full buffering is unmistakable
    const reset = await harnessPost(ctx, "/worker/gateway/reset", { bufferBound: BOUND });
    ctx.check(reset.status === 200, `gateway reset (got ${reset.status})`);

    // Stream an object well above the bound.
    const stream = await harnessGet(ctx, `/worker/gateway/stream?bytes=${SIZE}`);
    ctx.check(stream.status === 200 && stream.body.length === SIZE, `streamed object is complete (got ${stream.body.length} bytes)`);
    ctx.check(
      stream.body[0] === 0 && stream.body[SIZE - 1] === (SIZE - 1) % 251,
      "streamed bytes match the deterministic pattern",
    );
    const maxBuffered = Number(stream.headers["x-max-buffered-bytes"]);
    ctx.check(
      Number.isFinite(maxBuffered) && maxBuffered <= BOUND,
      `gateway held at most ${maxBuffered} bytes in memory (bound ${BOUND}) — no full buffering`,
    );

    // Upstream R2 5xx: failure surfaces; no success receipt is minted
    // before exact remote resolution.
    const upstreamFail = await harnessGet(ctx, "/worker/gateway/object?fail=r2-500");
    ctx.check(upstreamFail.status === 502, `upstream 5xx surfaces as gateway failure (got ${upstreamFail.status})`);
    ctx.check(
      upstreamFail.headers["x-success-receipt"] === "none",
      "no success receipt issued for an unresolved remote operation",
    );

    // Six-connection saturation: excess demand queues; nothing is
    // reported successful that did not run.
    const sat = asJson(await harnessPost(ctx, "/worker/gateway/saturate", { connections: 7 }));
    ctx.check(Number(sat.peakConcurrent) === 6, `connection permits capped at six (got ${sat.peakConcurrent})`);
    ctx.check(Number(sat.queued) === 1, `excess connection queued, not dropped (got ${sat.queued})`);
    ctx.check(sat.incorrectSuccess === false, "saturation produced no incorrect success");
  },
};

export const CTR_PROBES: ReadonlyArray<ProbeImpl> = [pCTR_01, pCTR_02, pCTR_03, pCTR_04];
export const WORKER_PROBES: ReadonlyArray<ProbeImpl> = [pWORKER_01];
