/*
 * P-DO-01 .. P-DO-04 (contract/typedb-r2-v16-platform-probes.md).
 *
 * These probes drive the probe-harness surface (/do/*): a deployed
 * harness Worker in real mode (CF_PROBE_HARNESS_URL), the deterministic
 * in-process fake in mock mode. The endpoint contract is identical in
 * both, so the assertions below are the normative semantics, not mock
 * conveniences. Every assertion is declared with its required modes
 * (round-3 P-05).
 */

import type { ProbeContext, ProbeImpl } from "./probe.ts";
import { asJson, BOTH, harnessGet, harnessPost } from "./probe.ts";

// ---------------------------------------------------------------------------
// P-DO-01 — Request interleaving.
// ---------------------------------------------------------------------------

const pDO_01: ProbeImpl = {
  id: "P-DO-01",
  expected:
    "a controller procedure paused at a non-storage await never commits " +
    "stale post-await validation; exactly one legal reducer trace",
  assertions: [
    { id: "reset-ok", title: "interleave state reset", required_in: BOTH },
    { id: "conflict-lands", title: "conflicting commit lands while first op is parked", required_in: BOTH },
    { id: "gate-released", title: "gate released", required_in: BOTH },
    { id: "stale-commit-rejected", title: "resumed operation must NOT commit its stale validation", required_in: BOTH },
    { id: "single-commit", title: "exactly one commit in the reducer trace", required_in: BOTH },
    { id: "winner-value", title: "committed value is the winner's", required_in: BOTH },
    { id: "legal-trace", title: "trace is the one legal interleaving", required_in: BOTH },
  ],
  async run(ctx: ProbeContext): Promise<void> {
    const reset = await harnessPost(ctx, "/do/interleave/reset");
    ctx.check("reset-ok", reset.status === 200, `got ${reset.status}`);

    // Start the slow operation and deliberately do NOT await it: it parks
    // at its instrumented non-storage await point (the gate).
    const slowPromise = harnessPost(ctx, "/do/interleave/slow-op", { value: "slow-A" });

    // Land a conflicting commit while the first invocation is paused.
    const conflict = await harnessPost(ctx, "/do/interleave/conflict", { value: "conflict-B" });
    ctx.check("conflict-lands", conflict.status === 200, `got ${conflict.status}`);

    // Release the gate; the parked operation resumes with stale validation.
    const release = await harnessPost(ctx, "/do/interleave/release");
    ctx.check("gate-released", release.status === 200, `got ${release.status}`);

    const slow = await slowPromise;
    ctx.check("stale-commit-rejected", slow.status === 409, `got ${slow.status}`);

    const trace = asJson(await harnessGet(ctx, "/do/interleave/trace"));
    ctx.check("single-commit", Number(trace.commits) === 1, `got ${trace.commits}`);
    ctx.check("winner-value", String(trace.value) === "conflict-B", `got ${trace.value}`);
    const t = trace.trace as string[];
    ctx.check(
      "legal-trace",
      Array.isArray(t) && t.includes("slow:read@v1") && t.includes("conflict:commit") && t.includes("slow:rejected-stale"),
      `got ${JSON.stringify(trace.trace)}`,
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
  assertions: [
    { id: "reset-ok", title: "alarm state reset", required_in: BOTH },
    { id: "not-delivered-early", title: "alarm not delivered early", required_in: BOTH },
    { id: "throw-retries", title: "first delivery throws, platform retries", required_in: BOTH },
    { id: "duplicate-idempotent", title: "duplicate delivery is idempotent", required_in: BOTH },
    { id: "work-once", title: "work-1 applied exactly once", required_in: BOTH },
    { id: "do-reset-accepted", title: "DO reset accepted", required_in: BOTH },
    { id: "rescheduled-from-intent", title: "outstanding work rescheduled from durable intent after reset", required_in: BOTH },
    { id: "reschedule-respects-time", title: "rescheduled alarm respects its time", required_in: BOTH },
    { id: "rescheduled-completes", title: "rescheduled work completes", required_in: BOTH },
    { id: "all-work-done", title: "both required work items eventually done", required_in: BOTH },
  ],
  async run(ctx: ProbeContext): Promise<void> {
    const reset = await harnessPost(ctx, "/do/alarm/reset-all");
    ctx.check("reset-ok", reset.status === 200, `got ${reset.status}`);

    // Work scheduled at virtual t=2, handler throws on first delivery.
    await harnessPost(ctx, "/do/alarm/schedule", { workId: "work-1", at: 2 });
    await harnessPost(ctx, "/do/alarm/config", { throwFirst: true });

    const t1 = asJson(await harnessPost(ctx, "/do/alarm/tick"));
    ctx.check("not-delivered-early", JSON.stringify(t1.results) === '["not-due"]', `got ${JSON.stringify(t1.results)}`);
    const t2 = asJson(await harnessPost(ctx, "/do/alarm/tick"));
    ctx.check("throw-retries", JSON.stringify(t2.results) === '["threw"]', `got ${JSON.stringify(t2.results)}`);

    // Duplicate delivery on the retry tick: work applies exactly once.
    const t3 = asJson(await harnessPost(ctx, "/do/alarm/tick", undefined, { "x-mock-duplicate": "1" }));
    ctx.check(
      "duplicate-idempotent",
      JSON.stringify(t3.results) === '["done","duplicate-ignored"]',
      `got ${JSON.stringify(t3.results)}`,
    );
    const s1 = asJson(await harnessGet(ctx, "/do/alarm/state"));
    ctx.check("work-once", Number(s1.workCount) === 1, `got ${s1.workCount}`);

    // DO reset / code update: the in-memory alarm evaporates. The durable
    // intent must reconstruct and reschedule the outstanding work.
    await harnessPost(ctx, "/do/alarm/schedule", { workId: "work-2", at: 5 });
    const doReset = await harnessPost(ctx, "/do/alarm/do-reset");
    ctx.check("do-reset-accepted", doReset.status === 200, `got ${doReset.status}`);
    const s2 = asJson(await harnessGet(ctx, "/do/alarm/state"));
    ctx.check("rescheduled-from-intent", s2.alarmScheduled === true, `got alarmScheduled=${s2.alarmScheduled}`);

    const t4 = asJson(await harnessPost(ctx, "/do/alarm/tick")); // t=4: not due
    ctx.check("reschedule-respects-time", JSON.stringify(t4.results) === '["not-due"]', `got ${JSON.stringify(t4.results)}`);
    const t5 = asJson(await harnessPost(ctx, "/do/alarm/tick")); // t=5: due
    ctx.check("rescheduled-completes", JSON.stringify(t5.results) === '["done"]', `got ${JSON.stringify(t5.results)}`);
    const s3 = asJson(await harnessGet(ctx, "/do/alarm/state"));
    ctx.check("all-work-done", Number(s3.workCount) === 2, `got ${s3.workCount}`);
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
  assertions: [
    { id: "reset-ok", title: "overload state reset", required_in: BOTH },
    { id: "accepted-or-shed", title: "every mutation is either accepted or explicitly shed", required_in: BOTH },
    { id: "soft-budget-exact", title: "acceptance stops exactly at the soft budget", required_in: BOTH },
    { id: "shed-reason-explicit", title: "every shed response carries an explicit shed reason", required_in: BOTH },
    { id: "rows-held-at-soft", title: "stored rows held at the soft budget, far from the hard limit", required_in: BOTH },
    { id: "shed-count-metrics", title: "metrics count every shed mutation", required_in: BOTH },
    { id: "alert-fired", title: "overload alert fired", required_in: BOTH },
  ],
  async run(ctx: ProbeContext): Promise<void> {
    const SOFT = 8;
    const HARD = 12;
    const reset = await harnessPost(ctx, "/do/overload/reset", { softBudgetRows: SOFT, hardLimitRows: HARD });
    ctx.check("reset-ok", reset.status === 200, `got ${reset.status}`);

    // Drive well past both budgets.
    const results = [];
    for (let i = 0; i < 20; i++) results.push(await harnessPost(ctx, "/do/overload/mutate"));
    const accepted = results.filter((r) => r.status === 200);
    const shed = results.filter((r) => r.status === 429);
    ctx.check("accepted-or-shed", accepted.length + shed.length === results.length, `${accepted.length}+${shed.length}/${results.length}`);
    ctx.check("soft-budget-exact", accepted.length === SOFT, `got ${accepted.length}`);
    ctx.check(
      "shed-reason-explicit",
      shed.every((r) => r.headers["x-shed-reason"] === "row-budget"),
      "x-shed-reason compared on every shed response",
    );

    const metrics = asJson(await harnessGet(ctx, "/do/overload/metrics"));
    ctx.check(
      "rows-held-at-soft",
      Number(metrics.rows) <= SOFT && Number(metrics.rows) < HARD,
      `rows ${metrics.rows}, soft ${SOFT}, hard ${HARD}`,
    );
    ctx.check("shed-count-metrics", Number(metrics.shedCount) === 20 - SOFT, `got ${metrics.shedCount}`);
    ctx.check("alert-fired", metrics.alertFired === true, `got ${metrics.alertFired}`);
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
  assertions: [
    { id: "reset-ok", title: "authority state reset", required_in: BOTH },
    { id: "current-authority-works", title: "current-incarnation authority works before rotation", required_in: BOTH },
    { id: "rotation-applied", title: "incarnation rotated", required_in: BOTH },
    { id: "old-authority-rejected", title: "every old-authority privileged action rejected", required_in: BOTH },
    { id: "new-authority-unaffected", title: "new-incarnation authority unaffected", required_in: BOTH },
    { id: "no-old-authority-effect", title: "no old-authority action produced an effect", required_in: BOTH },
  ],
  async run(ctx: ProbeContext): Promise<void> {
    const reset = await harnessPost(ctx, "/do/authority/reset");
    ctx.check("reset-ok", reset.status === 200, `got ${reset.status}`);

    const mint1 = asJson(await harnessPost(ctx, "/do/authority/mint"));
    const oldToken = String(mint1.token);
    const before = await harnessPost(ctx, "/do/authority/act", { action: "pre-rotation-op" }, { "x-authority-token": oldToken });
    ctx.check("current-authority-works", before.status === 200, `got ${before.status}`);

    // Rotate while the old DO/containers (holding oldToken) remain alive.
    const rotate = asJson(await harnessPost(ctx, "/do/authority/rotate"));
    ctx.check("rotation-applied", Number(rotate.incarnation) === 2, `got ${rotate.incarnation}`);

    // Every old-authority attempt from the contract's list must die.
    const actions = ["mint-capability", "publish-event", "finalize-wal", "publish-manifest", "lifecycle-report"];
    for (const action of actions) {
      const res = await harnessPost(ctx, "/do/authority/act", { action }, { "x-authority-token": oldToken });
      ctx.check("old-authority-rejected", res.status === 401, `${action}: got ${res.status}`);
    }

    // A token minted under the new incarnation still works.
    const mint2 = asJson(await harnessPost(ctx, "/do/authority/mint"));
    const fresh = await harnessPost(ctx, "/do/authority/act", { action: "post-rotation-op" }, { "x-authority-token": String(mint2.token) });
    ctx.check("new-authority-unaffected", fresh.status === 200, `got ${fresh.status}`);

    // The action log must show no effect from any rejected attempt.
    const log = asJson(await harnessGet(ctx, "/do/authority/actions"));
    ctx.check(
      "no-old-authority-effect",
      JSON.stringify(log.actions) === JSON.stringify(["pre-rotation-op", "post-rotation-op"]),
      `got ${JSON.stringify(log.actions)}`,
    );
  },
};

export const DO_PROBES: ReadonlyArray<ProbeImpl> = [pDO_01, pDO_02, pDO_03, pDO_04];
