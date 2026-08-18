// No-cloud guard for the local stack (audit §6.7 safety rule).
//
// Alchemy runs resources WITHOUT a local provider in the cloud
// automatically. A zero-risk local command therefore has to prove, before
// starting anything, that nothing in the graph can reach Cloudflare:
//
//   1. staticScan(): the graph file must not use `remote()` (Alchemy's
//      opt-out of local emulation), must not import live/bridge modules,
//      and every resource constructor it invokes must be on the explicit
//      allowlist of kinds with a local provider. Unknown kinds are
//      REFUSED, not assumed local (fail closed).
//   2. assertNoCloudCredentials()/sanitizedEnv(): the local command
//      hard-fails if Cloudflare credentials are present in the
//      environment, and every child process is spawned with them
//      explicitly removed — no credential can leak into a local run even
//      if the static scan were wrong.
//   3. assertDevIdentities(): after (or during) a run, every resource
//      Alchemy persisted must be providerMode "local" and carry a `dev:`
//      physical identity (Alchemy's LOCAL_ID_PREFIX convention).

import { readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import path from "node:path";

// ---------------------------------------------------------------------------
// 1. static scan
// ---------------------------------------------------------------------------

// Resource constructors with a local provider that this stack permits.
// Everything else — including other Cloudflare kinds that happen to have
// local providers — is refused until deliberately added here.
export const ALLOWED_RESOURCE_KINDS = Object.freeze([
  "Cloudflare.Worker",
  "Cloudflare.DurableObject",
  "Cloudflare.R2.Bucket",
  "Cloudflare.Container",
]);

// Module specifiers the graph file may import. The root "alchemy" module
// is allowed for Stack/localState — any use of its `remote` export is
// still refused by the pattern and named-import scans below.
const ALLOWED_IMPORTS = [
  /^alchemy$/,
  /^alchemy\/Cloudflare$/,
  /^effect(\/[\w-]+)*$/,
  /^node:/,
  /^\.\.?\//, // repo-relative modules (graph.data.mjs)
];

// Any of these anywhere in the graph source is an immediate refusal.
const FORBIDDEN_PATTERNS = [
  { re: /\bremote\s*\(/, why: "remote() opts resources OUT of local emulation (live cloud even under `alchemy dev`)" },
  { re: /ProviderMode\s*\.\s*remote/, why: "ProviderMode.remote is the remote() combinator" },
  { re: /alchemy\/Cloudflare\/Live/, why: "alchemy/Cloudflare/Live is the live-provider surface" },
  { re: /alchemy\/Cloudflare\/Bridge/, why: "Bridge connects local workers to live cloud resources" },
  { re: /\bCLOUDFLARE_API_TOKEN\b/, why: "the graph must not reference Cloudflare credentials" },
];

function scanImports(source, violations) {
  const importRe = /(?:^|\n)\s*import\s+(?:[^'"]*?from\s+)?["']([^"']+)["']/g;
  let m;
  while ((m = importRe.exec(source)) !== null) {
    const spec = m[1];
    if (!ALLOWED_IMPORTS.some((re) => re.test(spec))) {
      violations.push(`forbidden import "${spec}" (allowlist: alchemy/Cloudflare, node:*, relative modules)`);
    }
  }
}

function scanResourceKinds(source, violations) {
  // Every `Cloudflare.<Path.To.Ctor>(` invocation must resolve to an
  // allowlisted kind. This deliberately over-matches (member calls like
  // Cloudflare.R2.Bucket count once per call site) and under-trusts:
  // aliased/renamed imports were already excluded by the import allowlist
  // (only `alchemy/Cloudflare` may be imported, and the namespace-object
  // scan below pins its local name).
  const nsNames = new Set();
  const nsRe = /import\s+\*\s+as\s+(\w+)\s+from\s+["']alchemy\/Cloudflare["']/g;
  let m;
  while ((m = nsRe.exec(source)) !== null) nsNames.add(m[1]);
  const named = /import\s+\{([^}]*)\}\s+from\s+["']alchemy\/Cloudflare["']/g;
  while ((m = named.exec(source)) !== null) {
    violations.push(
      `named imports from alchemy/Cloudflare are refused (${m[1].trim()}): use a namespace import so every resource kind is auditable as Cloudflare.<Kind>(...)`,
    );
  }
  const namedRoot = /import\s+\{([^}]*)\}\s+from\s+["']alchemy["']/g;
  while ((m = namedRoot.exec(source)) !== null) {
    if (/\bremote\b/.test(m[1])) {
      violations.push(
        `named import of remote from "alchemy" is refused: remote() opts resources out of local emulation`,
      );
    }
  }
  // only the local file/in-memory state stores are permitted; a cloud
  // state store is itself a live resource
  const stateRe = /\.\s*state\s*\(/g;
  while ((m = stateRe.exec(source)) !== null) {
    violations.push(
      "cloud state store (.state()) is refused: use Alchemy.localState() — a remote state store is a live resource",
    );
  }
  for (const ns of nsNames) {
    // resource constructors are Capitalized (Cloudflare.R2.Bucket,
    // Cloudflare.Worker); lowercase members (Cloudflare.providers) are
    // layer/helper functions, not resources
    const callRe = new RegExp(String.raw`\b${ns}((?:\.\w+)*\.[A-Z]\w*)\s*\(`, "g");
    while ((m = callRe.exec(source)) !== null) {
      const kind = `Cloudflare${m[1]}`;
      if (!ALLOWED_RESOURCE_KINDS.includes(kind)) {
        violations.push(
          `resource kind ${kind} is not on the local-provider allowlist (${ALLOWED_RESOURCE_KINDS.join(", ")}) — refusing: unallowlisted kinds may deploy to the cloud`,
        );
      }
    }
  }
}

/** Scan graph source text; returns a list of violations (empty = clean). */
export function staticScanSource(source) {
  const violations = [];
  // strip line comments so documentation may NAME the forbidden things
  const code = source
    .split("\n")
    .map((l) => l.replace(/^\s*\/\/.*$/, "").replace(/([^:])\/\/[^"']*$/, "$1"))
    .join("\n")
    .replace(/\/\*[\s\S]*?\*\//g, "");
  for (const { re, why } of FORBIDDEN_PATTERNS) {
    if (re.test(code)) violations.push(`forbidden pattern ${re}: ${why}`);
  }
  scanImports(code, violations);
  scanResourceKinds(code, violations);
  return violations;
}

/** Scan a graph file (default: stack/alchemy.run.ts). */
export function staticScan(file) {
  return staticScanSource(readFileSync(file, "utf8"));
}

// ---------------------------------------------------------------------------
// 2. credential guard
// ---------------------------------------------------------------------------

export const CLOUD_CREDENTIAL_VARS = Object.freeze([
  "CLOUDFLARE_API_TOKEN",
  "CLOUDFLARE_ACCOUNT_ID",
  "CLOUDFLARE_API_KEY",
  "CLOUDFLARE_EMAIL",
  "CF_API_TOKEN",
  "CF_ACCOUNT_ID",
  "ALCHEMY_PROFILE",
]);

/** Hard-fail if any Cloudflare credential is present in `env`. */
export function assertNoCloudCredentials(env = process.env) {
  const present = CLOUD_CREDENTIAL_VARS.filter(
    (k) => env[k] !== undefined && env[k] !== "",
  );
  if (present.length > 0) {
    throw new Error(
      `no-cloud guard: refusing to start the local stack with Cloudflare credentials in the environment: ${present.join(", ")}. ` +
        `The local command must not be able to touch a real account — unset them (they are also stripped from every child env, but a set credential signals intent this guard will not guess about).`,
    );
  }
}

/** Copy of `env` with every cloud credential removed — for child spawns. */
export function sanitizedEnv(env = process.env) {
  const out = { ...env };
  for (const k of CLOUD_CREDENTIAL_VARS) delete out[k];
  return out;
}

// ---------------------------------------------------------------------------
// 3. dev: identity assertion (Alchemy LOCAL_ID_PREFIX convention)
// ---------------------------------------------------------------------------

export const LOCAL_ID_PREFIX = "dev:";

function* walkJsonFiles(dir) {
  for (const name of readdirSync(dir)) {
    const p = path.join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) yield* walkJsonFiles(p);
    else if (name.endsWith(".json")) yield p;
  }
}

function collectLiveMarkers(value, file, out, trail = "$") {
  if (Array.isArray(value)) {
    value.forEach((v, i) => collectLiveMarkers(v, file, out, `${trail}[${i}]`));
    return;
  }
  if (value && typeof value === "object") {
    if (value.providerMode !== undefined && value.providerMode !== "local") {
      out.push(`${file}: ${trail}.providerMode = ${JSON.stringify(value.providerMode)} (expected "local")`);
    }
    for (const [k, v] of Object.entries(value)) {
      collectLiveMarkers(v, file, out, `${trail}.${k}`);
    }
  }
}

function hasLocalIdentity(value) {
  if (typeof value === "string") return value.startsWith(LOCAL_ID_PREFIX);
  if (Array.isArray(value)) return value.some(hasLocalIdentity);
  if (value && typeof value === "object")
    return Object.values(value).some(hasLocalIdentity);
  return false;
}

/**
 * Assert every resource state Alchemy persisted under `stateDir` was
 * reconciled locally: providerMode must be "local" everywhere it appears,
 * and each resource state file must carry at least one `dev:` physical
 * identity marker. Returns the list of violations (empty = clean). A
 * missing state dir is clean-by-vacuity ONLY when `allowMissing` — the dev
 * command passes false after a run, so "no state was written" cannot fake
 * a pass.
 */
export function assertDevIdentities(stateDir, { allowMissing = false } = {}) {
  const violations = [];
  if (!existsSync(stateDir)) {
    if (!allowMissing) violations.push(`state dir missing: ${stateDir}`);
    return violations;
  }
  let sawResource = false;
  for (const file of walkJsonFiles(stateDir)) {
    let doc;
    try {
      doc = JSON.parse(readFileSync(file, "utf8"));
    } catch {
      violations.push(`${file}: unparseable state file`);
      continue;
    }
    sawResource = true;
    collectLiveMarkers(doc, file, violations);
    if (!hasLocalIdentity(doc)) {
      violations.push(`${file}: no "${LOCAL_ID_PREFIX}" physical identity marker anywhere in persisted state — resource may have been reconciled live`);
    }
  }
  if (!sawResource && !allowMissing) {
    violations.push(`state dir ${stateDir} contains no resource state`);
  }
  return violations;
}
