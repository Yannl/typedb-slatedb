// Wrangler consistency check: the committed control-plane/wrangler.toml is
// RETAINED (vitest-pool-workers, wrangler dev lanes still read it) but it
// is no longer an independent source of truth — this check parses it and
// fails on any drift from the canonical graph's wrangler-equivalent view
// (graph.data.mjs). Runs now via `stack check-wrangler` / node --test and
// is CI-runnable (pure node, offline, exit code is the verdict).

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { REPO_ROOT, toWranglerView } from "./graph.data.mjs";

export const WRANGLER_TOML = path.join(REPO_ROOT, "control-plane", "wrangler.toml");

// ---------------------------------------------------------------------------
// Minimal TOML parser for wrangler.toml's subset: [table], [[array table]],
// key = "string" | ["string", ...]. Anything else in the file is a parse
// FAILURE (fail closed: a construct this parser cannot see is a construct
// this check cannot verify).
// ---------------------------------------------------------------------------

export function parseToml(text) {
  const root = {};
  let current = root;
  for (const [lineNo, rawLine] of text.split("\n").entries()) {
    const line = rawLine.replace(/(^|\s)#.*$/, "").trim();
    if (line === "") continue;
    let m;
    if ((m = line.match(/^\[\[([A-Za-z0-9_.-]+)\]\]$/))) {
      const keys = m[1].split(".");
      let node = root;
      for (const k of keys.slice(0, -1)) node = node[k] ??= {};
      const last = keys[keys.length - 1];
      node[last] ??= [];
      if (!Array.isArray(node[last])) throw new Error(`toml line ${lineNo + 1}: ${m[1]} is not an array table`);
      current = {};
      node[last].push(current);
    } else if ((m = line.match(/^\[([A-Za-z0-9_.-]+)\]$/))) {
      const keys = m[1].split(".");
      let node = root;
      for (const k of keys) node = node[k] ??= {};
      current = node;
    } else if ((m = line.match(/^([A-Za-z0-9_-]+)\s*=\s*(.+)$/))) {
      current[m[1]] = parseTomlValue(m[2].trim(), lineNo + 1);
    } else {
      throw new Error(`toml line ${lineNo + 1}: unsupported syntax: ${rawLine.trim()}`);
    }
  }
  return root;
}

function parseTomlValue(v, lineNo) {
  if (v.startsWith('"') && v.endsWith('"')) return v.slice(1, -1);
  if (v.startsWith("[") && v.endsWith("]")) {
    const inner = v.slice(1, -1).trim();
    if (inner === "") return [];
    return inner.split(",").map((x) => parseTomlValue(x.trim(), lineNo));
  }
  if (v === "true") return true;
  if (v === "false") return false;
  if (/^-?\d+$/.test(v)) return Number(v);
  throw new Error(`toml line ${lineNo}: unsupported value: ${v}`);
}

// ---------------------------------------------------------------------------
// The check
// ---------------------------------------------------------------------------

function eq(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

/**
 * Compare the parsed wrangler.toml against the graph's wrangler view.
 * Returns a list of drift findings (empty = consistent).
 */
export function checkWrangler({
  tomlPath = WRANGLER_TOML,
  repoRoot = REPO_ROOT,
  tomlText,
} = {}) {
  const view = toWranglerView(repoRoot);
  const findings = [];
  let toml;
  try {
    toml = parseToml(tomlText ?? readFileSync(tomlPath, "utf8"));
  } catch (err) {
    return [`wrangler.toml unparseable: ${err.message}`];
  }

  const drift = (what, want, got) =>
    findings.push(`${what}: graph says ${JSON.stringify(want)}, wrangler.toml says ${JSON.stringify(got)}`);

  if (toml.name !== view.name) drift("worker name", view.name, toml.name);
  if (toml.main !== view.main) drift("main entry", view.main, toml.main);
  if (toml.compatibility_date !== view.compatibility_date) {
    drift("compatibility_date", view.compatibility_date, toml.compatibility_date);
  }

  const declaredAheadNames = new Set(view.declared_ahead.map((b) => b.name));
  const declaredAheadClasses = new Set(view.declared_ahead.map((b) => b.class_name));

  // DO bindings: exact set equality on {name, class_name} for active
  // bindings; a declared-ahead binding may be absent, but if present its
  // class name must already match the graph.
  const tomlDo = (toml.durable_objects?.bindings ?? []).map((b) => ({
    name: b.name,
    class_name: b.class_name,
  }));
  const wantDo = new Map(view.durable_objects.map((b) => [b.name, b.class_name]));
  const aheadDo = new Map(view.declared_ahead.filter((b) => b.type === "durable_object_namespace").map((b) => [b.name, b.class_name]));
  for (const b of tomlDo) {
    if (wantDo.has(b.name)) {
      if (wantDo.get(b.name) !== b.class_name) drift(`DO binding ${b.name} class`, wantDo.get(b.name), b.class_name);
      wantDo.delete(b.name);
    } else if (aheadDo.has(b.name)) {
      if (aheadDo.get(b.name) !== b.class_name) drift(`DO binding ${b.name} (declared-ahead) class`, aheadDo.get(b.name), b.class_name);
    } else {
      drift(`DO binding ${b.name}`, undefined, b.class_name);
    }
  }
  for (const [name, cls] of wantDo) drift(`DO binding ${name} missing from wrangler.toml`, cls, undefined);

  // migrations: every active sqlite class must appear in some migration's
  // new_sqlite_classes; unknown classes must not (declared-ahead classes
  // may appear only once their binding does)
  const sqliteClasses = (toml.migrations ?? []).flatMap((m) => m.new_sqlite_classes ?? []);
  for (const cls of view.new_sqlite_classes) {
    if (!sqliteClasses.includes(cls)) drift(`new_sqlite_classes missing`, cls, sqliteClasses);
  }
  for (const cls of sqliteClasses) {
    if (!view.new_sqlite_classes.includes(cls) && !declaredAheadClasses.has(cls)) {
      drift(`unexpected sqlite class in migrations`, view.new_sqlite_classes, cls);
    }
  }

  // R2 buckets: exact set equality (binding AND bucket_name)
  const tomlR2 = (toml.r2_buckets ?? []).map((b) => ({ binding: b.binding, bucket_name: b.bucket_name }));
  if (!eq([...tomlR2].sort((a, b) => a.binding.localeCompare(b.binding)), [...view.r2_buckets].sort((a, b) => a.binding.localeCompare(b.binding)))) {
    drift("r2_buckets", view.r2_buckets, tomlR2);
  }

  // vars: exact key AND value equality for the local posture
  if (!eq(canonicalVars(toml.vars ?? {}), canonicalVars(view.vars))) {
    drift("[vars]", view.vars, toml.vars ?? {});
  }

  // production posture invariants
  const prod = toml.env?.production ?? {};
  const prodVars = prod.vars ?? {};
  for (const [k, v] of Object.entries(view.production.vars)) {
    if (prodVars[k] !== v) drift(`[env.production.vars] ${k}`, v, prodVars[k]);
  }
  for (const k of view.production.forbidden_vars) {
    if (k in prodVars) {
      findings.push(`[env.production.vars] must NOT set ${k} (unset is the fail-closed posture), wrangler.toml sets ${JSON.stringify(prodVars[k])}`);
    }
  }
  const prodDo = (prod.durable_objects?.bindings ?? []).map((b) => ({ name: b.name, class_name: b.class_name }));
  for (const want of view.production.durable_objects) {
    const got = prodDo.find((b) => b.name === want.name);
    if (!got) drift(`[env.production] DO binding ${want.name}`, want.class_name, undefined);
    else if (got.class_name !== want.class_name) drift(`[env.production] DO binding ${want.name} class`, want.class_name, got.class_name);
  }
  for (const got of prodDo) {
    if (!view.production.durable_objects.some((b) => b.name === got.name) && !declaredAheadNames.has(got.name)) {
      drift(`[env.production] unexpected DO binding ${got.name}`, undefined, got.class_name);
    }
  }
  const prodR2 = (prod.r2_buckets ?? []).map((b) => ({ binding: b.binding, bucket_name: b.bucket_name }));
  if (!eq([...prodR2].sort((a, b) => a.binding.localeCompare(b.binding)), [...view.production.r2_buckets].sort((a, b) => a.binding.localeCompare(b.binding)))) {
    drift("[env.production] r2_buckets", view.production.r2_buckets, prodR2);
  }

  return findings;
}

function canonicalVars(vars) {
  const out = {};
  for (const k of Object.keys(vars).sort()) out[k] = vars[k];
  return out;
}

// CLI: node wrangler-check.mjs
const invokedDirectly =
  process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  const findings = checkWrangler();
  if (findings.length === 0) {
    console.log("WRANGLER CONSISTENCY: PASS (control-plane/wrangler.toml matches the canonical graph)");
  } else {
    console.log("WRANGLER CONSISTENCY: FAIL");
    for (const f of findings) console.log(`  - ${f}`);
    process.exit(1);
  }
}
