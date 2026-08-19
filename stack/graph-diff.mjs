// Graph differential: compare two normalized stack graphs.
//
// Modes of the parity ladder (model/native/parity/container/cloudflare-real)
// share ONE logical graph; only an explicit allowlist of fields may differ
// between two variants. Anything else — binding names, DO class names,
// compatibility date, route classes, budgets/limits, backend identity —
// differing is a HARD failure: that is exactly the drift class the audit
// forbids ("no mode may silently satisfy another mode's required
// assertion").
//
// R4-STACK-01: the differential additionally validates EVERY graph's
// security posture INDEPENDENTLY before comparing. The round-4 audit's
// surviving semantic mutant was two graphs passing the diff because both
// carried the same unsafe local-dev vars; equality is not safety. A graph
// declaring securityPosture:"managed" must carry exactly the managed vars
// and none of the forbidden dev vars, whatever the other graph says.
//
// R4-STACK-08: bindings are compared by STABLE NAME, never by array
// position, and per-field variation is allowed only on the NAMED binding
// it belongs to: bucketName may differ only on the PAYLOADS r2 binding,
// declaredAhead only on the CONTAINER binding. An attacker-bucket on the
// Controller binding or a silently deactivated PAYLOADS binding is a
// violation.

import { PRODUCTION_FORBIDDEN_VARS, SECURITY_POSTURES } from "./graph.data.mjs";

export const ALLOWED_DIFF_PATHS = Object.freeze([
  "variant",
  "execution",
  "worker.provider",
  // WHERE managed secrets come from is provider identity (dev constants /
  // local ephemeral managed / provisioned); the POSTURE controls whether
  // dev constants are even permitted, and is validated per graph above.
  "worker.secretSource",
  "s3.provider",
  "s3.endpoint",
]);

// Fields that legitimately differ ONLY BECAUSE the two graphs declare
// different security postures. When both graphs declare the SAME posture,
// any difference here is a violation like any other.
const POSTURE_DIFF_PATHS = Object.freeze([
  "securityPosture",
  /^worker\.vars\./,
  /^worker\.forbiddenVars\b/,
]);

// Per-binding-name field variation allowlist (R4-STACK-08).
const BINDING_FIELD_ALLOWLIST = Object.freeze({
  // physical bucket name is provider identity (typedb-payloads-local vs
  // typedb-payloads); allowed ONLY on the named PAYLOADS r2 binding
  PAYLOADS: Object.freeze(["bucketName"]),
  // activation state of the declared-ahead ContainerDO binding may differ
  // while a lane lags the class landing; the binding itself may not
  CONTAINER: Object.freeze(["declaredAhead"]),
});

function pathMatches(patterns, pathStr) {
  return patterns.some((p) => (typeof p === "string" ? p === pathStr : p.test(pathStr)));
}

function isObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function diffInto(a, b, trail, out) {
  if (Array.isArray(a) && Array.isArray(b)) {
    const n = Math.max(a.length, b.length);
    for (let i = 0; i < n; i++) diffInto(a[i], b[i], `${trail}[${i}]`, out);
    return;
  }
  if (isObject(a) && isObject(b)) {
    for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) {
      diffInto(a[k], b[k], trail ? `${trail}.${k}` : k, out);
    }
    return;
  }
  if (JSON.stringify(a) !== JSON.stringify(b)) {
    out.push({ path: trail, a, b });
  }
}

/**
 * R4-STACK-01: validate ONE graph's security posture against its own
 * declaration. Returns a list of violations (empty = posture holds).
 * This runs per graph, independent of any comparison: two graphs that
 * agree on unsafe values still each fail here.
 */
export function assertPostureInvariants(graph) {
  const violations = [];
  const posture = graph?.securityPosture;
  const spec = SECURITY_POSTURES[posture];
  if (!spec) {
    violations.push({
      path: "securityPosture",
      detail: `graph declares unknown security posture '${posture}' — every graph must declare one`,
    });
    return violations;
  }
  const vars = graph?.worker?.vars ?? {};
  for (const [k, v] of Object.entries(spec.vars)) {
    if (vars[k] !== v) {
      violations.push({
        path: `worker.vars.${k}`,
        detail: `posture '${posture}' requires ${k}=${JSON.stringify(v)}, graph has ${JSON.stringify(vars[k])}`,
      });
    }
  }
  for (const k of spec.forbiddenVars) {
    if (k in vars) {
      violations.push({
        path: `worker.vars.${k}`,
        detail: `posture '${posture}' FORBIDS var ${k} (fail-closed: its absence closes routes); graph carries ${JSON.stringify(vars[k])}`,
      });
    }
  }
  // No extra vars beyond the posture's exact allowlist: an unexpected var
  // is an unreviewed knob, not a convenience (exact allowlist, not denylist).
  for (const k of Object.keys(vars)) {
    if (!(k in spec.vars)) {
      violations.push({
        path: `worker.vars.${k}`,
        detail: `var ${k} is not part of posture '${posture}' — vars are an exact allowlist`,
      });
    }
  }
  // The managed posture must also structurally forbid the dev vars.
  if (posture === "managed") {
    for (const k of PRODUCTION_FORBIDDEN_VARS) {
      if (k in vars) {
        violations.push({ path: `worker.vars.${k}`, detail: `managed graph carries forbidden dev var ${k}` });
      }
    }
  }
  // Public exposure is disabled in every posture.
  if (graph?.worker?.workersDev !== false) {
    violations.push({ path: "worker.workersDev", detail: "workers.dev exposure must be explicitly false" });
  }
  if (graph?.worker?.previewUrls !== false) {
    violations.push({ path: "worker.previewUrls", detail: "preview URLs must be explicitly false" });
  }
  return violations;
}

/**
 * Compare two normalized graphs. Returns
 *   { equal, allowedDiffs, violations }
 * where violations are posture violations of EITHER graph plus differences
 * outside the allowlist — any violation means the two graphs do not
 * describe the same safe stack.
 */
export function diffGraphs(a, b) {
  const violations = [];
  const allowedDiffs = [];

  // --- per-graph posture invariants first (R4-STACK-01) ---
  for (const [label, g] of [["a", a], ["b", b]]) {
    for (const v of assertPostureInvariants(g)) {
      violations.push({ path: `${label}:${v.path}`, a: v.detail, b: "(posture invariant)" });
    }
  }
  const posturesDiffer = a?.securityPosture !== b?.securityPosture;

  // --- bindings: compared by STABLE NAME (R4-STACK-08) ---
  const aB = new Map((a.worker?.bindings ?? []).map((x) => [x.name, x]));
  const bB = new Map((b.worker?.bindings ?? []).map((x) => [x.name, x]));
  for (const name of new Set([...aB.keys(), ...bB.keys()])) {
    const x = aB.get(name);
    const y = bB.get(name);
    if (!x || !y) {
      violations.push({ path: `worker.bindings{${name}}`, a: x ?? undefined, b: y ?? undefined });
      continue;
    }
    const fieldAllow = BINDING_FIELD_ALLOWLIST[name] ?? [];
    for (const k of new Set([...Object.keys(x), ...Object.keys(y)])) {
      if (JSON.stringify(x[k]) === JSON.stringify(y[k])) continue;
      const d = { path: `worker.bindings{${name}}.${k}`, a: x[k], b: y[k] };
      if (fieldAllow.includes(k)) allowedDiffs.push(d);
      else violations.push(d);
    }
  }

  // --- everything else: positional walk minus the bindings subtree ---
  const raw = [];
  diffInto({ ...a, worker: { ...a.worker, bindings: undefined } }, { ...b, worker: { ...b.worker, bindings: undefined } }, "", raw);
  for (const d of raw) {
    if (pathMatches(ALLOWED_DIFF_PATHS, d.path)) {
      allowedDiffs.push(d);
    } else if (pathMatches(POSTURE_DIFF_PATHS, d.path)) {
      // vars/posture/secretSource may differ ONLY as a consequence of two
      // DIFFERENT declared postures, each already validated above. The
      // same posture disagreeing on vars is ordinary drift: violation.
      if (posturesDiffer) allowedDiffs.push(d);
      else violations.push(d);
    } else {
      violations.push(d);
    }
  }
  return { equal: violations.length === 0, allowedDiffs, violations };
}

export function formatReport({ equal, allowedDiffs, violations }) {
  const lines = [];
  for (const d of allowedDiffs) {
    lines.push(`  ~ allowed   ${d.path}: ${JSON.stringify(d.a)} -> ${JSON.stringify(d.b)}`);
  }
  for (const d of violations) {
    lines.push(`  ! VIOLATION ${d.path}: ${JSON.stringify(d.a)} != ${JSON.stringify(d.b)}`);
  }
  lines.push(equal ? "GRAPH DIFF: PASS (postures hold; no differences outside the allowlist)" : "GRAPH DIFF: FAIL");
  return lines.join("\n");
}

// CLI: node graph-diff.mjs <a.json> <b.json>
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const invokedDirectly =
  process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  const [aFile, bFile] = process.argv.slice(2);
  if (!aFile || !bFile) {
    console.error("usage: node graph-diff.mjs <a.json> <b.json>");
    process.exit(2);
  }
  const a = JSON.parse(readFileSync(aFile, "utf8"));
  const b = JSON.parse(readFileSync(bFile, "utf8"));
  const result = diffGraphs(a, b);
  console.log(formatReport(result));
  if (!result.equal) process.exit(1);
}
