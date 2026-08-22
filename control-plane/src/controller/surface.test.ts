/*
 * PR0 containment refusal matrix (audit C-P0-01/03/09): which routes exist
 * on the production surface. The classifier is a pure function (surface.ts);
 * the wiring - `env.CONTROLLER_SURFACE !== "local-dev" && devOnlyRoute(path)`
 * refusing before any parsing/capability/DO/R2 work - lives at the top of
 * worker-entry.ts fetch, and the local-dev posture is exercised end-to-end
 * by scripts/local-stack-e2e.mjs (which uses every dev-only route).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { devOnlyRoute } from "./surface.ts";

test("production physically excludes issuance, register/fence, budgets, batch, admin, outbox, audit", () => {
  const excluded = [
    "/capability",
    "/session/register",
    "/session/fence",
    "/budgets",
    "/wal/finalize-batch",
    "/admin/db1/incarnation/bump",
    "/outbox/db1",
    "/outbox/db1/ack",
    "/wal/db1/3/audit",
  ];
  for (const path of excluded) {
    assert.ok(devOnlyRoute(path), `${path} must be dev-only`);
  }
});

test("the production protocol surface stays reachable", () => {
  const production = [
    // R8-P2-03: liveness and readiness are separate probes; /health is a
    // retained alias of /live.
    "/live",
    "/ready",
    "/health",
    // R4 PR1: the internal provisioning transaction is the PRODUCTION
    // bootstrap route - its authorization is the PROVISION capability
    // (private-issuer scope key), not surface gating
    "/provision",
    "/session/reserve",
    "/session/attest",
    "/session/activate",
    "/session/renew",
    "/session/drain",
    "/session/revoke",
    "/payload/p%2Fdb1%2Fabc",
    "/wal/finalize",
    "/wal/db1/3/0",
    "/wal/db1/3/head",
    "/wal/db1/3/iterator",
    "/wal/db1/3/scan",
    "/wal/db1/3/last",
    "/wal/db1/3/operation/op-1",
    "/journal/db1/verify",
    "/journal/db1/verify-anchored",
    "/checkpoint/db1/3/cut",
    "/checkpoint/db1/cut/c-1/activate",
    "/checkpoint/db1/3/active",
  ];
  for (const path of production) {
    assert.equal(devOnlyRoute(path), false, `${path} must remain on the production surface`);
  }
});

test("aliases of excluded routes do not slip through the classifier", () => {
  // the classifier matches the worker's own routing exactly: these aliases
  // are 404s in the router anyway, but none of them may CLASSIFY as
  // production while routing to a dev surface
  assert.ok(devOnlyRoute("/wal/any-db/12345/audit"), "audit matches for every db/generation");
  assert.ok(devOnlyRoute("/outbox/other-db/ack"));
  assert.ok(devOnlyRoute("/admin/x/incarnation/bump"));
});
