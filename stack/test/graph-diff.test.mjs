// Graph differential tests + executed mutant (b): change a binding name in
// a graph copy → the differential must fail.
import { test } from "node:test";
import assert from "node:assert/strict";
import { toGraph } from "../graph.data.mjs";
import { diffGraphs } from "../graph-diff.mjs";

const clone = (g) => JSON.parse(JSON.stringify(g));

test("a graph equals itself", () => {
  const g = toGraph("local-native");
  const r = diffGraphs(g, clone(g));
  assert.equal(r.equal, true);
  assert.deepEqual(r.violations, []);
});

test("native vs container variants differ only in allowlisted fields", () => {
  const r = diffGraphs(toGraph("local-native"), toGraph("local-container"));
  assert.equal(r.equal, true, JSON.stringify(r.violations));
  assert.ok(r.allowedDiffs.some((d) => d.path === "execution"));
});

test("native vs cloudflare-real differs only in allowlisted fields", () => {
  const r = diffGraphs(toGraph("local-native"), toGraph("cloudflare-real"));
  assert.equal(r.equal, true, JSON.stringify(r.violations));
  const paths = r.allowedDiffs.map((d) => d.path);
  assert.ok(paths.includes("s3.endpoint"), "endpoint may differ");
  assert.ok(paths.includes("s3.provider"), "provider identity may differ");
});

test("MUTANT b: renamed binding fails the differential", () => {
  const a = toGraph("local-native");
  const b = clone(a);
  const payloads = b.worker.bindings.find((x) => x.name === "PAYLOADS");
  payloads.name = "PAYLOADS_V2";
  const r = diffGraphs(a, b);
  assert.equal(r.equal, false, "renamed binding must be a violation");
  assert.ok(
    r.violations.some((v) => String(v.path).includes("PAYLOADS")),
    JSON.stringify(r.violations),
  );
});

test("MUTANT: flipped sqlite backing on a binding fails the differential", () => {
  // sqlite/container are covered by bindingKey, not just the positional skip:
  // a silent sqlite:true->false (which would change new_sqlite_classes and the
  // required DO migration) must surface as a by-name violation, never vanish.
  const a = toGraph("local-native");
  const b = clone(a);
  b.worker.bindings.find((x) => x.name === "CONTROLLER").sqlite = false;
  const r = diffGraphs(a, b);
  assert.equal(r.equal, false, "flipped sqlite backing must be a violation");
  assert.ok(
    r.violations.some((v) => String(v.path).includes("CONTROLLER")),
    JSON.stringify(r.violations),
  );
});

test("changed DO class name fails the differential", () => {
  const a = toGraph("local-native");
  const b = clone(a);
  b.worker.bindings.find((x) => x.name === "CONTROLLER").className = "EvilDO";
  const r = diffGraphs(a, b);
  assert.equal(r.equal, false);
});

test("changed compatibility date fails the differential", () => {
  const a = toGraph("local-native");
  const b = clone(a);
  b.worker.compatibilityDate = "2026-01-01";
  const r = diffGraphs(a, b);
  assert.equal(r.equal, false);
  assert.ok(r.violations.some((v) => v.path === "worker.compatibilityDate"));
});

test("changed backend identity (silent file-WAL fallback) fails hard", () => {
  const a = toGraph("local-native");
  const b = clone(a);
  b.s3.backend = "local-fs";
  const r = diffGraphs(a, b);
  assert.equal(r.equal, false);
  assert.ok(r.violations.some((v) => v.path === "s3.backend"));
});

test("declared budget/limits divergence fails hard", () => {
  const a = toGraph("local-native");
  const b = clone(a);
  b.worker.limits = { cpu_ms: 50 };
  const r = diffGraphs(a, b);
  assert.equal(r.equal, false);
  assert.ok(r.violations.some((v) => String(v.path).startsWith("worker.limits")));
});

test("allowed endpoint difference alone still passes", () => {
  const a = toGraph("local-native");
  const b = clone(a);
  b.s3.endpoint = "http://127.0.0.1:39999";
  const r = diffGraphs(a, b);
  assert.equal(r.equal, true, JSON.stringify(r.violations));
});
