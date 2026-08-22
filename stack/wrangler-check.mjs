// Wrangler consistency check (R4-STACK-01 two-file posture split).
//
// The canonical graph (stack/graph.data.mjs) is the single source of
// truth. Wrangler configs are RETAINED (vitest-pool-workers and wrangler
// dev lanes read them) but never independent truth — this check parses
// BOTH committed configs and fails on any drift:
//
//   control-plane/wrangler.toml            <=> the MANAGED posture view
//                                              (default deploy, fail-closed)
//   control-plane/wrangler.local-dev.toml  <=> the developer-convenience
//                                              posture view (explicit -c only)
//
// R4-STACK-10: the Durable Object migration history is an append-only
// LEDGER (graph.data.mjs MIGRATION_LEDGER). The exact ordered (tag,
// classes) sequence must appear identically in both files; removing,
// reordering or retagging a historical migration is a failure. Vars are
// checked as exact allowlists in BOTH directions (an extra var is drift,
// not a convenience).
//
// Runs via `stack check-wrangler` / node --test; pure node, offline,
// exit code is the verdict.

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { REPO_ROOT, toGraph, toWranglerView } from "./graph.data.mjs";
// R5-SEC-01: the runtime's OWN declaration of what the managed profile
// consumes (core/key-config.ts imports this exact module) — the graph must
// declare the same set, or the deploy would pass config checks and then
// refuse to boot. Enforced here, BEFORE any deployment.
import {
  MANAGED_DEPLOYMENT_VARS, MANAGED_FIXED_VARS, MANAGED_SECRETS,
} from "../control-plane/src/shared/key-requirements.mjs";

export const WRANGLER_TOML = path.join(REPO_ROOT, "control-plane", "wrangler.toml");
export const WRANGLER_LOCAL_DEV_TOML = path.join(REPO_ROOT, "control-plane", "wrangler.local-dev.toml");

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
 * Check ONE parsed wrangler config against ONE posture view. `label` names
 * the file in findings. Returns drift findings (empty = consistent).
 */
export function checkOneConfig(toml, postureView, declaredAhead, label) {
  const findings = [];
  const drift = (what, want, got) =>
    findings.push(`${label} ${what}: graph says ${JSON.stringify(want)}, config says ${JSON.stringify(got)}`);

  if (toml.name !== postureView.name) drift("worker name", postureView.name, toml.name);
  if (toml.main !== postureView.main) drift("main entry", postureView.main, toml.main);
  if (toml.compatibility_date !== postureView.compatibility_date) {
    drift("compatibility_date", postureView.compatibility_date, toml.compatibility_date);
  }
  // Public exposure must be EXPLICITLY disabled in both files.
  if (toml.workers_dev !== false) drift("workers_dev", false, toml.workers_dev);
  if (toml.preview_urls !== false) drift("preview_urls", false, toml.preview_urls);

  const declaredAheadNames = new Set(declaredAhead.map((b) => b.name));
  const declaredAheadClasses = new Set(declaredAhead.map((b) => b.class_name));

  // DO bindings: exact set equality on {name, class_name} for active
  // bindings; a declared-ahead binding may be absent, but if present its
  // class name must already match the graph.
  const tomlDo = (toml.durable_objects?.bindings ?? []).map((b) => ({
    name: b.name,
    class_name: b.class_name,
  }));
  const wantDo = new Map(postureView.durable_objects.map((b) => [b.name, b.class_name]));
  const aheadDo = new Map(
    declaredAhead.filter((b) => b.type === "durable_object_namespace").map((b) => [b.name, b.class_name]),
  );
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
  for (const [name, cls] of wantDo) drift(`DO binding ${name} missing`, cls, undefined);

  // MIGRATION LEDGER (R4-STACK-10): exact ordered (tag, classes) equality.
  // Not membership — ORDER and TAGS are part of the ledger. A trailing
  // appended entry whose classes are all declared-ahead is permitted (a
  // migration may land with its class), nothing else.
  const tomlMigrations = (toml.migrations ?? []).map((m) => ({
    tag: m.tag,
    new_sqlite_classes: m.new_sqlite_classes ?? [],
  }));
  const ledger = postureView.migration_ledger;
  for (let i = 0; i < Math.max(ledger.length, tomlMigrations.length); i++) {
    const want = ledger[i];
    const got = tomlMigrations[i];
    if (want && got) {
      if (want.tag !== got.tag) drift(`migration[${i}] tag (ledger is append-only)`, want.tag, got.tag);
      else if (!eq(want.new_sqlite_classes, got.new_sqlite_classes)) {
        drift(`migration[${i}] (${want.tag}) classes (history is immutable)`, want.new_sqlite_classes, got.new_sqlite_classes);
      }
    } else if (want && !got) {
      drift(`migration[${i}] (${want.tag}) missing from config`, want, undefined);
    } else if (!want && got) {
      const allAhead = (got.new_sqlite_classes ?? []).every((c) => declaredAheadClasses.has(c));
      if (!allAhead) drift(`migration[${i}] not in the canonical ledger`, undefined, got);
    }
  }

  // R2 buckets: exact set equality (binding AND bucket_name).
  const tomlR2 = (toml.r2_buckets ?? []).map((b) => ({ binding: b.binding, bucket_name: b.bucket_name }));
  if (
    !eq(
      [...tomlR2].sort((a, b) => a.binding.localeCompare(b.binding)),
      [...postureView.r2_buckets].sort((a, b) => a.binding.localeCompare(b.binding)),
    )
  ) {
    drift("r2_buckets", postureView.r2_buckets, tomlR2);
  }

  // Vars: exact allowlist BOTH ways — a missing var is drift AND an extra
  // var is drift; forbidden vars must be absent whatever their value.
  const vars = toml.vars ?? {};
  for (const [k, v] of Object.entries(postureView.vars)) {
    if (vars[k] !== v) drift(`[vars] ${k}`, v, vars[k]);
  }
  for (const k of Object.keys(vars)) {
    if (!(k in postureView.vars)) drift(`[vars] unexpected ${k} (vars are an exact allowlist)`, undefined, vars[k]);
  }
  for (const k of postureView.forbidden_vars) {
    if (k in vars) {
      findings.push(
        `${label} [vars] must NOT set ${k} (unset is the fail-closed posture), config sets ${JSON.stringify(vars[k])}`,
      );
    }
  }
  // No [env.*] escape hatch: postures are separate FILES now; an embedded
  // env section could smuggle a second posture past this check.
  if (toml.env !== undefined) {
    findings.push(`${label} contains [env.*] sections — postures are separate files, not embedded environments`);
  }
  return findings;
}

/**
 * R5-SEC-01 managed BOOTABILITY: the graph's declared managed inputs
 * (fixed vars + deployment var names + secret names) must equal the
 * runtime's requirement list (key-requirements.mjs) — name-complete in
 * BOTH directions. A graph that omits a required input describes a
 * deployment that cannot boot; one that adds an undeclared name carries an
 * unreviewed runtime input. Pure over its arguments so tests can execute
 * the drop-each-input mutants directly.
 */
export function bootabilityFindings({ fixedVars, deploymentVars, secrets }) {
  const findings = [];
  for (const [name, value] of Object.entries(MANAGED_FIXED_VARS)) {
    if (fixedVars?.[name] !== value) {
      findings.push(`managed boot: graph must fix [vars] ${name}=${JSON.stringify(value)}, declares ${JSON.stringify(fixedVars?.[name])}`);
    }
  }
  const compare = (label, declared, required) => {
    const declaredSet = new Set(declared ?? []);
    for (const name of required) {
      if (!declaredSet.has(name)) {
        findings.push(`managed boot: required ${label} ${name} is not declared by the graph — the deployment cannot boot`);
      }
    }
    for (const name of declaredSet) {
      if (!required.includes(name)) {
        findings.push(`managed boot: graph declares ${label} ${name} the runtime does not consume — unreviewed input`);
      }
    }
  };
  compare("deployment var", deploymentVars, MANAGED_DEPLOYMENT_VARS);
  compare("secret", secrets, MANAGED_SECRETS);
  return findings;
}

/**
 * Check BOTH committed configs against their posture views. Optional
 * overrides ({managedText, localDevText}) support tests.
 */
export function checkWrangler({
  repoRoot = REPO_ROOT,
  managedPath = WRANGLER_TOML,
  localDevPath = WRANGLER_LOCAL_DEV_TOML,
  managedText,
  localDevText,
} = {}) {
  const view = toWranglerView(repoRoot);
  const findings = [];
  // R5-SEC-01: the managed view must be a BOOTABLE declaration before the
  // committed files are even compared — a graph/runtime skew fails here.
  findings.push(...bootabilityFindings({
    fixedVars: view.managed.vars,
    deploymentVars: view.managed.deployment_vars,
    secrets: toGraph("cloudflare-real", repoRoot).worker.secretSchema,
  }));
  for (const [label, text, pathToRead, posture] of [
    ["wrangler.toml(managed)", managedText, managedPath, view.managed],
    ["wrangler.local-dev.toml", localDevText, localDevPath, view.local_dev],
  ]) {
    let toml;
    try {
      toml = parseToml(text ?? readFileSync(pathToRead, "utf8"));
    } catch (err) {
      findings.push(`${label} unparseable: ${err.message}`);
      continue;
    }
    findings.push(...checkOneConfig(toml, posture, view.declared_ahead, label));
  }
  return findings;
}

// CLI: node wrangler-check.mjs
const invokedDirectly =
  process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  const findings = checkWrangler();
  if (findings.length === 0) {
    console.log(
      "WRANGLER CONSISTENCY: PASS (managed default + explicit local-dev config both match the canonical graph)",
    );
  } else {
    console.log("WRANGLER CONSISTENCY: FAIL");
    for (const f of findings) console.log(`  - ${f}`);
    process.exit(1);
  }
}
