/*
 * P-DO-01 .. P-DO-04 (contract/typedb-r2-v16-platform-probes.md).
 *
 * These probes drive the probe-harness surface (/do/*): a deployed
 * harness Worker in real mode (CF_PROBE_HARNESS_URL), the deterministic
 * in-process fake in mock mode. The endpoint contract is identical in
 * both, so the assertions below are the normative semantics, not mock
 * conveniences.
 */

import type { ProbeContext, ProbeImpl } from "./probe.ts";
import { asJson, harnessGet, harnessPost } from "./probe.ts";

// ---------------------------------------------------------------------------
// P-DO-01 — Request interleaving.
// ---------------------------------------------------------------------------

const pDO_01: ProbeImpl = {
  id: "P-DO-01",
  expected:
    "a controller procedure paused at a non-storage await never commits " +
    "stale post-await validation; exactly one legal reducer trace",
  async run(ctx: ProbeContext): Promise<void> {
    const reset = await harnessPost(ctx, "/do/interleave/reset");
    ctx.check(reset.status === 200, `interleave state reset (got ${reset.status})`);

    // Start the slow operation and deliberately do NOT await it: it parks
    // at its instrumented non-storage await point (the gate).
    const slowPromise = harnessPost(ctx, "/do/interleave/slow-op", { value: "slow-A" });

    // Land a conflicting commit while the first invocation is paused.
    const conflict = await harnessPost(ctx, "/do/interleave/conflict", { value: "conflict-B" });
    ctx.check(conflict.status === 200, `conflicting commit lands while first op is parked (got ${conflict.status})`);

    // Release the gate; the parked operation resumes with stale validation.
    const release = await harnessPost(ctx, "/do/interleave/release");
    ctx.check(release.status === 200, `gate released (got ${release.status})`);

    const slow = await slowPromise;
    ctx.check(
      slow.status === 409,
      `resumed operation must NOT commit its stale validation (got ${slow.status})`,
    );

    const trace = asJson(await harnessGet(ctx, "/do/interleave/trace"));
    ctx.check(Number(trace.commits) === 1, `exactly one commit in the reducer trace (got ${trace.commits})`);
    ctx.check(String(trace.value) === "conflict-B", `committed value is the winner's (got ${trace.value})`);
    const t = trace.trace as string[];
    ctx.check(
      Array.isArray(t) && t.includes("slow:read@v1") && t.includes("conflict:commit") && t.includes("slow:rejected-stale"),
      `trace is the one legal interleaving (got ${JSON.stringify(trace.trace)})`,
    );
  },
};

// ---------------------------------------------------------------------------
// P-DO-02 — Alarm durability.
// ---------------------------------------------------------------------------

const pDO_02: ProbeImpl = {
  id: "P-DO-02",
  expected:
    "duplicate delivery is idempotent; handler throw retries; after DO " +
    "reset the required work is reconstructed from durable intent and " +
    "eventually rescheduled — no transition relies on retry counts",
  async run(ctx: ProbeContext): Promise<void> {
    const reset = await harnessPost(ctx, "/do/alarm/reset-all");
    ctx.check(reset.status === 200, `alarm state reset (got ${reset.status})`);

    // Work scheduled at virtual t=2, handler throws on first delivery.
    await harnessPost(ctx, "/do/alarm/schedule", { workId: "work-1", at: 2 });
    await harnessPost(ctx, "/do/alarm/config", { throwFirst: true });

    const t1 = asJson(await harnessPost(ctx, "/do/alarm/tick"));
    ctx.check(JSON.stringify(t1.results) === '["not-due"]', `alarm not delivered early (got ${JSON.stringify(t1.results)})`);
    const t2 = asJson(await harnessPost(ctx, "/do/alarm/tick"));
    ctx.check(JSON.stringify(t2.results) === '["threw"]', `first delivery throws, platform retries (got ${JSON.stringify(t2.results)})`);

    // Duplicate delivery on the retry tick: work applies exactly once.
    const t3 = asJson(await harnessPost(ctx, "/do/alarm/tick", undefined, { "x-mock-duplicate": "1" }));
    ctx.check(
      JSON.stringify(t3.results) === '["done","duplicate-ignored"]',
      `duplicate delivery is idempotent (got ${JSON.stringify(t3.results)})`,
    );
    const s1 = asJson(await harnessGet(ctx, "/do/alarm/state"));
    ctx.check(Number(s1.workCount) === 1, `work-1 applied exactly once (got ${s1.workCount})`);

    // DO reset / code update: the in-memory alarm evaporates. The durable
    // intent must reconstruct and reschedule the outstanding work.
    await harnessPost(ctx, "/do/alarm/schedule", { workId: "work-2", at: 5 });
    const doReset = await harnessPost(ctx, "/do/alarm/do-reset");
    ctx.check(doReset.status === 200, `DO reset accepted (got ${doReset.status})`);
    const s2 = asJson(await harnessGet(ctx, "/do/alarm/state"));
    ctx.check(
      s2.alarmScheduled === true,
      `outstanding work rescheduled from durable intent after reset (got alarmScheduled=${s2.alarmScheduled})`,
    );

    const t4 = asJson(await harnessPost(ctx, "/do/alarm/tick")); // t=4: not due
    ctx.check(JSON.stringify(t4.results) === '["not-due"]', `rescheduled alarm respects its time (got ${JSON.stringify(t4.results)})`);
    const t5 = asJson(await harnessPost(ctx, "/do/alarm/tick")); // t=5: due
    ctx.check(JSON.stringify(t5.results) === '["done"]', `rescheduled work completes (got ${JSON.stringify(t5.results)})`);
    const s3 = asJson(await harnessGet(ctx, "/do/alarm/state"));
    ctx.check(Number(s3.workCount) === 2, `both required work items eventually done (got ${s3.workCount})`);
  },
};

// ---------------------------------------------------------------------------
// P-DO-03 — Overload and storage budgets.
// ---------------------------------------------------------------------------

const pDO_03: ProbeImpl = {
  id: "P-DO-03",
  expected:
    "mutations shed at the soft budget, before unsafe growth toward the " +
    "hard limit; shedding is explicit (reason header, metrics, alert), " +
    "never a blind acceptance",
  async run(ctx: ProbeContext): Promise<void> {
    const SOFT = 8;
    const HARD = 12;
    const reset = await harnessPost(ctx, "/do/overload/reset", { softBudgetRows: SOFT, hardLimitRows: HARD });
    ctx.check(reset.status === 200, `overload state reset (got ${reset.status})`);

    // Drive well past both budgets.
    const results = [];
    for (let i = 0; i < 20; i++) results.push(await harnessPost(ctx, "/do/overload/mutate"));
    const accepted = results.filter((r) => r.status === 200);
    const shed = results.filter((r) => r.status === 429);
    ctx.check(
      accepted.length + shed.length === results.length,
      "every mutation is either accepted or explicitly shed",
    );
    ctx.check(accepted.length === SOFT, `acceptance stops exactly at the soft budget (got ${accepted.length})`);
    ctx.check(
      shed.every((r) => r.headers["x-shed-reason"] === "row-budget"),
      "every shed response carries an explicit shed reason",
    );

    const metrics = asJson(await harnessGet(ctx, "/do/overload/metrics"));
    ctx.check(
      Number(metrics.rows) <= SOFT && Number(metrics.rows) < HARD,
      `stored rows (${metrics.rows}) held at the soft budget, far from the hard limit`,
    );
    ctx.check(Number(metrics.shedCount) === 20 - SOFT, `metrics count every shed mutation (got ${metrics.shedCount})`);
    ctx.check(metrics.alertFired === true, "overload alert fired");
  },
};

// ---------------------------------------------------------------------------
// P-DO-04 — Incarnation and old-authority rejection.
// ---------------------------------------------------------------------------

const pDO_04: ProbeImpl = {
  id: "P-DO-04",
  expected:
    "every privileged action attempted with a superseded incarnation's " +
    "authority is rejected; current incarnation is unaffected",
  async run(ctx: ProbeContext): Promise<void> {
    const reset = await harnessPost(ctx, "/do/authority/reset");
    ctx.check(reset.status === 200, `authority state reset (got ${reset.status})`);

    const mint1 = asJson(await harnessPost(ctx, "/do/authority/mint"));
    const oldToken = String(mint1.token);
    const before = await harnessPost(ctx, "/do/authority/act", { action: "pre-rotation-op" }, { "x-authority-token": oldToken });
    ctx.check(before.status === 200, `current-incarnation authority works before rotation (got ${before.status})`);

    // Rotate while the old DO/containers (holding oldToken) remain alive.
    const rotate = asJson(await harnessPost(ctx, "/do/authority/rotate"));
    ctx.check(Number(rotate.incarnation) === 2, `incarnation rotated (got ${rotate.incarnation})`);

    // Every old-authority attempt from the contract's list must die.
    const actions = ["mint-capability", "publish-event", "finalize-wal", "publish-manifest", "lifecycle-report"];
    for (const action of actions) {
      const res = await harnessPost(ctx, "/do/authority/act", { action }, { "x-authority-token": oldToken });
      ctx.check(res.status === 401, `old-authority ${action} rejected (got ${res.status})`);
    }

    // A token minted under the new incarnation still works.
    const mint2 = asJson(await harnessPost(ctx, "/do/authority/mint"));
    const fresh = await harnessPost(ctx, "/do/authority/act", { action: "post-rotation-op" }, { "x-authority-token": String(mint2.token) });
    ctx.check(fresh.status === 200, `new-incarnation authority unaffected (got ${fresh.status})`);

    // The action log must show no effect from any rejected attempt.
    const log = asJson(await harnessGet(ctx, "/do/authority/actions"));
    ctx.check(
      JSON.stringify(log.actions) === JSON.stringify(["pre-rotation-op", "post-rotation-op"]),
      `no old-authority action produced an effect (got ${JSON.stringify(log.actions)})`,
    );
  },
};

export const DO_PROBES: ReadonlyArray<ProbeImpl> = [pDO_01, pDO_02, pDO_03, pDO_04];
