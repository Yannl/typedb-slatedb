// R5-SEC-07: the graph's container-execution claim must be HONEST. No lane
// in this repository has ever exercised a real Cloudflare Container, so a
// graph declaring `execution: "container"` must carry — in the graph itself,
// not in a comment — the declared-ahead/advisory marker that stops any
// reader from mistaking a declared container topology for an exercised one.
import { test } from "node:test";
import assert from "node:assert/strict";
import { EXECUTION_FACETS, toGraph, canonicalJson } from "../graph.data.mjs";
import { diffGraphs } from "../graph-diff.mjs";

test("the container execution facet is explicitly declared-ahead/advisory (R5-SEC-07)", () => {
  const facet = EXECUTION_FACETS.container;
  assert.equal(facet.status, "declared-ahead", "container execution must be marked declared-ahead");
  assert.equal(facet.declaredAhead, true);
  assert.equal(facet.advisory, true);
  assert.match(facet.note, /no real Cloudflare Container/i,
    "the note must say outright that no real container has been exercised");
  // native, by contrast, is the mode local lanes actually run
  assert.equal(EXECUTION_FACETS.native.status, "exercised");
  assert.equal(EXECUTION_FACETS.native.declaredAhead, false);
});

test("every graph variant emits the honesty table, and each variant's own execution mode resolves in it", () => {
  for (const variant of ["local-native", "local-parity", "local-container", "cloudflare-real"]) {
    const g = toGraph(variant);
    assert.ok(g.executionFacets, `${variant} must carry executionFacets`);
    const facet = g.executionFacets[g.execution];
    assert.ok(facet, `${variant}'s execution mode '${g.execution}' must resolve in executionFacets`);
    if (g.execution === "container") {
      assert.equal(facet.declaredAhead, true,
        `${variant} declares a container topology; the facet must mark it declared-ahead`);
    }
  }
});

test("MUTANT: a graph whose container facet claims 'exercised' would be a lie — the marker is load-bearing, not decorative", () => {
  const g = toGraph("local-container");
  // the emitted marker survives canonicalization (it reaches digests and
  // any consumer of the canonical graph JSON, not just module importers)
  const emitted = JSON.parse(canonicalJson(g));
  assert.equal(emitted.execution, "container");
  assert.equal(emitted.executionFacets.container.status, "declared-ahead");
  assert.equal(emitted.executionFacets.container.declaredAhead, true);
});

test("the honesty table is identical across variants: the differential gains no new paths from it", () => {
  const r = diffGraphs(toGraph("local-native"), toGraph("local-container"));
  assert.equal(r.equal, true, JSON.stringify(r.violations));
  assert.ok(
    !r.allowedDiffs.some((d) => String(d.path).startsWith("executionFacets")),
    "executionFacets must not differ between variants",
  );
});
