// No-cloud guard for the local stack (audit §6.7 safety rule).
//
// Alchemy runs resources WITHOUT a local provider in the cloud
// automatically. A zero-risk local command therefore has to prove, before
// starting anything, that nothing in the graph can reach Cloudflare:
//
//   1. staticScan(): TRANSITIVE lexical scan (R4-STACK-06). Starting from
//      the graph file, every relative import (./x, ../x — with
//      .ts/.mjs/.js/index resolution) is resolved recursively and every
//      reachable module is scanned; an unresolvable relative import is
//      itself a violation. Each module must not use `remote()` (Alchemy's
//      opt-out of local emulation), must not import live/bridge modules,
//      must not alias the audited namespaces (const X = Cloudflare) or
//      reach into them with computed member access (Alchemy[...]), and
//      every resource constructor it invokes must be on the explicit
//      allowlist of kinds with a local provider. Unknown kinds are
//      REFUSED, not assumed local (fail closed).
//
//      HONESTY NOTE: this scan is and remains a LEXICAL APPROXIMATION —
//      it is not a resolved module graph with data flow (eval, dynamic
//      property names built at runtime, re-exports through package
//      specifiers and other indirection are beyond it). It exists to fail
//      fast and loudly on the obvious/accidental cases. The LOAD-BEARING
//      layers are (2) and (3): runtime credential absence/stripping means
//      no child can authenticate to Cloudflare even if the scan is
//      wrong, and the exact resource-state schema validation refuses any
//      persisted resource that is not provably local-shaped.
//   2. assertNoCloudCredentials()/sanitizedEnv(): the local command
//      hard-fails if Cloudflare credentials are present in the
//      environment, and every child process is spawned with them
//      explicitly removed — no credential can leak into a local run even
//      if the static scan were wrong.
//   3. assertDevIdentities(): after (or during) a run, every resource
//      state Alchemy persisted must match an EXACT typed shape for its
//      kind (R4-STACK-06): allowlisted resourceType, top-level
//      providerMode === "local", and the kind's own physical-identity
//      fields (e.g. R2's attr.bucketName must be `dev:`-prefixed; a
//      Worker's attr.url must be loopback). A stray "dev:..." string in
//      an unrelated field can no longer bless a resource.

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
// still refused by the pattern and named-import scans below. Relative
// modules are allowed BUT are resolved and scanned transitively by
// staticScan() (R4-STACK-06) — an import is never a scan boundary.
const ALLOWED_IMPORTS = [
  /^alchemy$/,
  /^alchemy\/Cloudflare$/,
  /^effect(\/[\w-]+)*$/,
  /^node:/,
  /^\.\.?\//, // repo-relative modules (graph.data.mjs) — scanned transitively
];

// Any of these anywhere in a scanned module is an immediate refusal.
const FORBIDDEN_PATTERNS = [
  { re: /\bremote\s*\(/, why: "remote() opts resources OUT of local emulation (live cloud even under `alchemy dev`)" },
  { re: /ProviderMode\s*\.\s*remote/, why: "ProviderMode.remote is the remote() combinator" },
  { re: /alchemy\/Cloudflare\/Live/, why: "alchemy/Cloudflare/Live is the live-provider surface" },
  { re: /alchemy\/Cloudflare\/Bridge/, why: "Bridge connects local workers to live cloud resources" },
  // Unquoted identifier/property usage reads the credential
  // (process.env.CLOUDFLARE_API_TOKEN); a QUOTED occurrence is only
  // naming it — the graph's own R4-STACK-02 refusal block lists the var
  // names as string literals in order to refuse them, which is the one
  // legitimate mention. (Computed reads through a quoted name evade this
  // lexical rule; the runtime layers strip the credential itself.)
  { re: /(?<!["'])\bCLOUDFLARE_API_TOKEN\b(?!["'])/, why: "the graph must not use Cloudflare credentials (unquoted credential identifier)" },
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

/** Namespace identifiers bound to the audited alchemy modules. */
function auditedNamespaceNames(source) {
  const names = new Set();
  const nsRe = /import\s+\*\s+as\s+(\w+)\s+from\s+["'](?:alchemy|alchemy\/Cloudflare)["']/g;
  let m;
  while ((m = nsRe.exec(source)) !== null) names.add(m[1]);
  return names;
}

/**
 * R4-STACK-06: aliasing (`const X = Cloudflare`) and computed member
 * access (`Alchemy["remote"]`) both defeat the pattern scans above, so
 * both are refused outright. Aliases of aliases are chased to a fixpoint.
 * (Still lexical — see the header honesty note.)
 */
function scanAliasingAndComputedAccess(source, violations) {
  const nsNames = auditedNamespaceNames(source);
  const aliases = new Map(); // alias name → what it aliases
  let grew = true;
  while (grew) {
    grew = false;
    for (const name of [...nsNames, ...aliases.keys()]) {
      // "<ident> = <Name>" NOT followed by property access/call/template —
      // i.e. the namespace OBJECT itself is being rebound
      const assignRe = new RegExp(String.raw`\b(\w+)\s*=\s*${name}\s*(?![\w.($\[\`])`, "g");
      let m;
      while ((m = assignRe.exec(source)) !== null) {
        const alias = m[1];
        if (alias === name || nsNames.has(alias) || aliases.has(alias)) continue;
        aliases.set(alias, aliases.get(name) ?? name);
        grew = true;
      }
    }
  }
  for (const [alias, src] of aliases) {
    const used = new RegExp(String.raw`\b${alias}\s*[.\[]`).test(source);
    violations.push(
      `alias "${alias} = ${src}" of an audited namespace${used ? " (used with property access)" : ""} — refused: aliasing defeats the lexical resource audit; use the namespace object directly`,
    );
  }
  for (const name of [...nsNames, ...aliases.keys()]) {
    if (new RegExp(String.raw`\b${name}\s*\[`).test(source)) {
      violations.push(
        `computed member access ${name}[...] is not statically auditable — refused: spell resource kinds as literal ${name}.<Kind> member expressions`,
      );
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

/** Strip comments so documentation may NAME the forbidden things. */
function stripComments(source) {
  return source
    .split("\n")
    .map((l) => l.replace(/^\s*\/\/.*$/, "").replace(/([^:])\/\/[^"']*$/, "$1"))
    .join("\n")
    .replace(/\/\*[\s\S]*?\*\//g, "");
}

/** Scan graph source text; returns a list of violations (empty = clean). */
export function staticScanSource(source) {
  const violations = [];
  const code = stripComments(source);
  for (const { re, why } of FORBIDDEN_PATTERNS) {
    if (re.test(code)) violations.push(`forbidden pattern ${re}: ${why}`);
  }
  scanImports(code, violations);
  scanAliasingAndComputedAccess(code, violations);
  scanResourceKinds(code, violations);
  return violations;
}

// --- transitive resolution (R4-STACK-06) -----------------------------------

const RESOLUTION_SUFFIXES = ["", ".ts", ".mts", ".mjs", ".js", "/index.ts", "/index.mjs", "/index.js"];

function relativeImportSpecs(code) {
  const specs = [];
  const patterns = [
    /(?:^|\n)\s*import\s+(?:[^'"]*?from\s+)?["'](\.\.?\/[^"']+)["']/g, // static import
    /(?:^|\n)\s*export\s+[^'"\n]*?from\s+["'](\.\.?\/[^"']+)["']/g, // re-export
    /\bimport\s*\(\s*["'](\.\.?\/[^"']+)["']\s*\)/g, // dynamic import with a literal
  ];
  for (const re of patterns) {
    let m;
    while ((m = re.exec(code)) !== null) specs.push(m[1]);
  }
  return specs;
}

function resolveRelativeImport(fromDir, spec) {
  const base = path.resolve(fromDir, spec);
  for (const suffix of RESOLUTION_SUFFIXES) {
    const candidate = base + suffix;
    try {
      if (existsSync(candidate) && statSync(candidate).isFile()) return candidate;
    } catch {}
  }
  return null;
}

/**
 * Scan a graph file (default root: stack/alchemy.run.ts) AND every module
 * reachable from it through relative imports (cycle-safe). A violation
 * anywhere in the reachable graph is a violation of the root; a relative
 * import the scanner cannot resolve is refused rather than skipped.
 */
export function staticScan(file) {
  const rootFile = path.resolve(file);
  const violations = [];
  const visited = new Set();
  const queue = [rootFile];
  while (queue.length > 0) {
    const f = queue.shift();
    if (visited.has(f)) continue; // cycle-safe
    visited.add(f);
    let source;
    try {
      source = readFileSync(f, "utf8");
    } catch (err) {
      violations.push(`${path.basename(f)}: unreadable module (${err.code ?? err}) — refusing`);
      continue;
    }
    const label = f === rootFile ? null : path.basename(f);
    for (const v of staticScanSource(source)) {
      violations.push(label ? `${label}: ${v}` : v);
    }
    for (const spec of relativeImportSpecs(stripComments(source))) {
      const resolved = resolveRelativeImport(path.dirname(f), spec);
      if (resolved === null) {
        violations.push(
          `${label ?? path.basename(f)}: unresolvable relative import "${spec}" — refusing (the transitive scan must see every reachable module)`,
        );
      } else {
        queue.push(resolved);
      }
    }
  }
  return violations;
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

/**
 * Alchemy's LOCAL providers still resolve CLOUDFLARE_ACCOUNT_ID from the
 * environment (AuthProvider getEnvRequired) even when nothing leaves the
 * machine. The local stack therefore injects this SYNTHETIC all-zero id —
 * a value no real Cloudflare account carries — into the child env, and
 * every guard (here and alchemy.run.ts's execution-mode assertion)
 * accepts EXACTLY this value and refuses anything else.
 */
export const LOCAL_SYNTHETIC_ACCOUNT_ID = "00000000000000000000000000000000";

/**
 * Alchemy also resolves the full credential chain (token or key+email)
 * even for purely-local providers. This SELF-EVIDENTLY FAKE token can
 * never authenticate; any accidental live API call fails closed with an
 * auth error instead of touching an account. Only this exact value is
 * accepted by the guards.
 */
export const LOCAL_SYNTHETIC_API_TOKEN = "alchemy-local-placeholder-never-a-real-token";

/** Hard-fail if any Cloudflare credential is present in `env`. */
export function assertNoCloudCredentials(env = process.env) {
  const present = CLOUD_CREDENTIAL_VARS.filter(
    (k) => env[k] !== undefined && env[k] !== ""
      && !(k === "CLOUDFLARE_ACCOUNT_ID" && env[k] === LOCAL_SYNTHETIC_ACCOUNT_ID)
      && !(k === "CLOUDFLARE_API_TOKEN" && env[k] === LOCAL_SYNTHETIC_API_TOKEN),
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
// 3. dev: identity assertion — exact per-kind resource-state schemas
//    (R4-STACK-06; Alchemy LOCAL_ID_PREFIX convention)
// ---------------------------------------------------------------------------

export const LOCAL_ID_PREFIX = "dev:";

const LOOPBACK_HOSTNAMES = new Set(["localhost", "127.0.0.1", "[::1]"]);

function isLoopbackHttpUrl(u) {
  try {
    const p = new URL(u);
    return p.protocol === "http:" && LOOPBACK_HOSTNAMES.has(p.hostname);
  } catch {
    return false;
  }
}

/**
 * Exact expected shape of a LOCALLY-reconciled resource state row, per
 * kind. Validation is on the kind's own identity fields — a "dev:" string
 * nested in some unrelated field proves nothing and blesses nothing.
 * Kinds without a schema here are refused (fail closed) even when they
 * are on the static allowlist.
 */
export const RESOURCE_IDENTITY_SCHEMAS = Object.freeze({
  "Cloudflare.R2.Bucket": (doc, file, out) => {
    const name = doc.attr?.bucketName;
    if (typeof name !== "string" || !name.startsWith(LOCAL_ID_PREFIX)) {
      out.push(
        `${file}: Cloudflare.R2.Bucket attr.bucketName ${JSON.stringify(name)} is not a "${LOCAL_ID_PREFIX}"-prefixed local physical identity — resource may have been reconciled live`,
      );
    }
  },
  "Cloudflare.Worker": (doc, file, out) => {
    if (typeof doc.attr?.workerId !== "string" || doc.attr.workerId.length === 0) {
      out.push(`${file}: Cloudflare.Worker state has no attr.workerId`);
    }
    const urls = [
      ...(typeof doc.attr?.url === "string" ? [doc.attr.url] : []),
      ...(Array.isArray(doc.attr?.urls) ? doc.attr.urls : []),
    ];
    if (urls.length === 0) {
      out.push(`${file}: Cloudflare.Worker state exposes no attr.url — cannot prove a loopback-only dev surface`);
    }
    for (const u of urls) {
      if (!isLoopbackHttpUrl(u)) {
        out.push(`${file}: Cloudflare.Worker url ${JSON.stringify(u)} is not a loopback http dev URL — resource may have been reconciled live`);
      }
    }
    if (doc.props?.workersDev === true) {
      out.push(`${file}: Cloudflare.Worker state requests a public workers.dev surface`);
    }
  },
});

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

/**
 * Assert every resource state Alchemy persisted under `stateDir` was
 * reconciled locally. A state row (any JSON doc carrying `resourceType`)
 * must: name an allowlisted kind, carry top-level providerMode "local",
 * and satisfy that kind's exact identity schema above. providerMode
 * anywhere else in any file must also be "local". Returns the list of
 * violations (empty = clean). A missing state dir is clean-by-vacuity
 * ONLY when `allowMissing` — the dev command passes false after a run, so
 * "no state was written" cannot fake a pass.
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
    collectLiveMarkers(doc, file, violations);
    if (doc && typeof doc === "object" && !Array.isArray(doc) && "resourceType" in doc) {
      sawResource = true;
      const kind = doc.resourceType;
      if (typeof kind !== "string" || !ALLOWED_RESOURCE_KINDS.includes(kind)) {
        violations.push(
          `${file}: resourceType ${JSON.stringify(kind)} is not on the local-provider allowlist (${ALLOWED_RESOURCE_KINDS.join(", ")})`,
        );
        continue;
      }
      if (doc.providerMode !== "local") {
        violations.push(
          `${file}: ${kind} providerMode ${JSON.stringify(doc.providerMode)} — expected exactly "local"`,
        );
      }
      const schema = RESOURCE_IDENTITY_SCHEMAS[kind];
      if (!schema) {
        violations.push(
          `${file}: no runtime identity schema is defined for resource kind ${kind} — refusing (fail closed: define the exact expected local shape before allowing it)`,
        );
      } else {
        schema(doc, file, violations);
      }
    }
  }
  if (!sawResource && !allowMissing) {
    violations.push(`state dir ${stateDir} contains no resource state`);
  }
  return violations;
}
