// Graph differential: compare two normalized stack graphs.
//
// Modes of the parity ladder (model/native/container/cloudflare-real) share
// ONE logical graph; only an explicit allowlist of fields may differ
// between two variants. Anything else — binding names, DO class names,
// compatibility date, route classes, budgets/limits, backend identity —
// differing is a HARD failure: that is exactly the drift class the audit
// forbids ("no mode may silently satisfy another mode's required
// assertion").
//
// Allowlisted difference classes (audit PR3):
//   - endpoints            (s3.endpoint)
//   - secret VALUES        (never part of the graph; secretSource label may
//                           differ between dev-constants and provisioned)
//   - provider identity    (s3.provider, worker.provider, r2 provider,
//                           bucket physical name local vs production)
//   - execution lane       (execution: native vs container, variant label)

export const ALLOWED_DIFF_PATHS = Object.freeze([
  "variant",
  "execution",
  "worker.provider",
  "worker.secretSource",
  "s3.provider",
  "s3.endpoint",
  // physical bucket name is provider identity (typedb-payloads-local vs
  // typedb-payloads); the BINDING name PAYLOADS may never differ
  /^worker\.bindings\[\d+\]\.bucketName$/,
  // activation state of a declared-ahead binding may differ while a lane
  // lags a class landing; the binding itself (name/class/type) may not
  /^worker\.bindings\[\d+\]\.declaredAhead$/,
]);

function allowed(pathStr) {
  return ALLOWED_DIFF_PATHS.some((p) =>
    typeof p === "string" ? p === pathStr : p.test(pathStr),
  );
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
 * Compare two normalized graphs. Returns
 *   { equal, allowedDiffs, violations }
 * where violations are differences OUTSIDE the allowlist — any violation
 * means the two graphs do not describe the same stack.
 *
 * Bindings are additionally compared as a NAMED SET first: a missing,
 * added, or renamed binding is always a violation, reported by name —
 * positional array drift must not masquerade as an allowlisted field diff.
 */
export function diffGraphs(a, b) {
  const violations = [];
  const allowedDiffs = [];

  // The set-level binding identity MUST cover every field the positional walk
  // below skips (line ~97), or a difference in it is caught by neither path.
  // sqlite/container are backend-shape flags (they drive new_sqlite_classes /
  // the container lane): a silent sqlite:true->false is exactly the shape drift
  // this differential exists to catch, so it belongs in the key.
  const bindingKey = (x) =>
    `${x.name}:${x.type}:${x.className ?? ""}:${x.sqlite ?? ""}:${x.container ?? ""}`;
  const aB = new Map((a.worker?.bindings ?? []).map((x) => [x.name, x]));
  const bB = new Map((b.worker?.bindings ?? []).map((x) => [x.name, x]));
  for (const name of new Set([...aB.keys(), ...bB.keys()])) {
    const x = aB.get(name);
    const y = bB.get(name);
    if (!x || !y) {
      violations.push({
        path: `worker.bindings{${name}}`,
        a: x ? bindingKey(x) : undefined,
        b: y ? bindingKey(y) : undefined,
      });
    } else if (bindingKey(x) !== bindingKey(y)) {
      violations.push({ path: `worker.bindings{${name}}`, a: bindingKey(x), b: bindingKey(y) });
    }
  }

  const raw = [];
  diffInto(a, b, "", raw);
  for (const d of raw) {
    // set-level binding violations already reported above; skip the
    // positional duplicates for name/type/className mismatches
    if (/^worker\.bindings\[\d+\]\.(name|type|className|sqlite|container)$/.test(d.path)) continue;
    if (allowed(d.path)) allowedDiffs.push(d);
    else violations.push(d);
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
  lines.push(equal ? "GRAPH DIFF: PASS (no differences outside the allowlist)" : "GRAPH DIFF: FAIL");
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
