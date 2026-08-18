// Canonical logical graph of the TypeDB-on-R2 stack (single source of truth).
//
// This module is pure data + pure functions, importable offline with zero
// dependencies. Everything that names the topology lives HERE and only here:
//   - alchemy.run.ts (the Alchemy IaC program) imports these constants;
//   - wrangler-check.mjs verifies the committed control-plane/wrangler.toml
//     against the wrangler-equivalent view derived from this graph;
//   - graph-diff.mjs compares normalized graphs produced by toGraph();
//   - cli.mjs emits the normalized graph (`stack graph`) and digests it into
//     the run-identity manifest.
//
// Round-3 audit A-01 / §6.7: Alchemy is the canonical orchestrator for the
// Cloudflare-facing half (Worker + DatabaseControllerDO + local R2 binding);
// Alchemy's local R2 has NO S3 endpoint (§6.3), so the TypeDB/SlateDB S3
// half is a pinned native MinIO (source-lock node MINIO), never Alchemy R2.

import { readFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";

export const STACK_DIR = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(STACK_DIR, "..");

// ---------------------------------------------------------------------------
// Identity constants (must match control-plane/wrangler.toml — enforced by
// wrangler-check.mjs, which parses the toml and fails on any drift)
// ---------------------------------------------------------------------------

export const WORKER_NAME = "typedb-r2-control-plane";
export const WORKER_ENTRY = "control-plane/src/controller/worker-entry.ts";
export const COMPATIBILITY_DATE = "2025-11-01";

export const CONTROLLER_BINDING = "CONTROLLER";
export const CONTROLLER_CLASS = "DatabaseControllerDO";

// DatabaseContainerDO: the ContainerDO class is being made real by the
// container workstream. The binding/namespace is DECLARED here now so the
// canonical graph already carries it; it becomes ACTIVE (included in the
// Alchemy env and required in wrangler.toml) automatically once the class
// is actually exported from the worker entry — see containerDoExported().
// Until then it is declaredAhead: present in the logical graph, excluded
// from the strict wrangler comparison, never sent to any runtime.
export const CONTAINER_BINDING = "CONTAINER";
export const CONTAINER_CLASS = "DatabaseContainerDO";

export const PAYLOADS_BINDING = "PAYLOADS";
export const PAYLOADS_BUCKET_LOCAL = "typedb-payloads-local";
export const PAYLOADS_BUCKET_PRODUCTION = "typedb-payloads";

// Plain-text vars of the LOCAL posture (wrangler.toml [vars]).
export const LOCAL_VARS = Object.freeze({
  CONTROLLER_KEY_PROFILE: "local-dev",
  // ONLY this exact value opens dev-only routes (PR0 containment); the
  // production env deliberately does not set it — unset closes routes.
  CONTROLLER_SURFACE: "local-dev",
});

// Production posture invariants (wrangler.toml [env.production]).
export const PRODUCTION_VARS = Object.freeze({
  CONTROLLER_KEY_PROFILE: "managed",
});
// Vars that MUST NOT appear in the production env: their absence is the
// fail-closed posture (losing the var closes routes, never opens them).
export const PRODUCTION_FORBIDDEN_VARS = Object.freeze(["CONTROLLER_SURFACE"]);

// Secret schema (managed posture provisions these via `wrangler secret put`;
// local-dev falls back to loud dev constants — core/key-config.ts).
export const SECRET_SCHEMA = Object.freeze([
  "CONTROLLER_CAPABILITY_KEY",
  "CONTROLLER_ISSUER_SECRET",
  "CONTROLLER_JOURNAL_KEY",
]);

// ---------------------------------------------------------------------------
// Predicates
// ---------------------------------------------------------------------------

/**
 * True once the worker entry actually exports DatabaseContainerDO. Guards
 * the declared-ahead ContainerDO binding so the Alchemy graph builds and
 * validates while the class does not exist yet.
 */
export function containerDoExported(repoRoot = REPO_ROOT) {
  const entry = path.join(repoRoot, WORKER_ENTRY);
  if (!existsSync(entry)) return false;
  const src = readFileSync(entry, "utf8");
  // export class DatabaseContainerDO ... | export { DatabaseContainerDO }
  return new RegExp(
    String.raw`export\s+(?:class\s+${CONTAINER_CLASS}\b|\{[^}]*\b${CONTAINER_CLASS}\b[^}]*\})`,
  ).test(src);
}

// ---------------------------------------------------------------------------
// Normalized graph
// ---------------------------------------------------------------------------

export const GRAPH_SCHEMA = "typedb-r2-stack/graph@1";

/**
 * The normalized desired graph. `variant` selects the S3/provider half:
 *   - "local-native":   Alchemy local providers + native MinIO S3 (mode
 *                       `native`; the only variant runnable with zero
 *                       Cloudflare credentials)
 *   - "local-container":same graph, ContainerDO lane executes the OCI image
 *                       (requires Docker; L2)
 *   - "cloudflare-real":same logical declarations against real R2/DO (L3)
 *
 * graph-diff.mjs enforces that ONLY the allowlisted fields may differ
 * between variants (endpoints, secret values, provider identity, execution
 * lane); binding names, class names, compat date, budgets and backend
 * identity must be byte-identical.
 */
export function toGraph(variant = "local-native", repoRoot = REPO_ROOT) {
  const variants = {
    "local-native": {
      execution: "native",
      s3Provider: "minio",
      s3Endpoint: "http://127.0.0.1:${run.minio.port}",
      r2Provider: "alchemy-local-r2",
      doProvider: "alchemy-workerd-local",
      routeClass: "local-loopback",
      secretSource: "dev-constants",
    },
    "local-container": {
      execution: "container",
      s3Provider: "minio",
      s3Endpoint: "http://127.0.0.1:${run.minio.port}",
      r2Provider: "alchemy-local-r2",
      doProvider: "alchemy-workerd-local",
      routeClass: "local-loopback",
      secretSource: "dev-constants",
    },
    "cloudflare-real": {
      execution: "container",
      s3Provider: "cloudflare-r2",
      s3Endpoint: "https://${account}.r2.cloudflarestorage.com",
      r2Provider: "cloudflare-r2",
      doProvider: "cloudflare-workerd",
      routeClass: "local-loopback", // no public routes are declared in any variant
      secretSource: "provisioned-secrets",
    },
  };
  const v = variants[variant];
  if (!v) throw new Error(`unknown graph variant: ${variant}`);
  const containerActive = containerDoExported(repoRoot);

  const bindings = [
    {
      name: CONTROLLER_BINDING,
      type: "durable_object_namespace",
      className: CONTROLLER_CLASS,
      sqlite: true,
      declaredAhead: false,
    },
    {
      name: CONTAINER_BINDING,
      type: "durable_object_namespace",
      className: CONTAINER_CLASS,
      sqlite: true,
      container: true,
      // stays in the logical graph either way; only its activation flips
      declaredAhead: !containerActive,
    },
    {
      name: PAYLOADS_BINDING,
      type: "r2_bucket",
      bucketName:
        variant === "cloudflare-real"
          ? PAYLOADS_BUCKET_PRODUCTION
          : PAYLOADS_BUCKET_LOCAL,
      declaredAhead: false,
    },
  ];

  return {
    schema: GRAPH_SCHEMA,
    app: "typedb-r2",
    variant,
    execution: v.execution,
    worker: {
      name: WORKER_NAME,
      entry: WORKER_ENTRY,
      compatibilityDate: COMPATIBILITY_DATE,
      routeClass: v.routeClass,
      provider: v.doProvider,
      bindings,
      vars: { ...LOCAL_VARS },
      secretSchema: [...SECRET_SCHEMA],
      secretSource: v.secretSource,
      // budget/limit class: none declared — a variant that declares limits
      // while another does not is a hard differential failure
      limits: null,
    },
    s3: {
      consumer: "typedb-slatedb (object_store AmazonS3Builder, SigV4)",
      provider: v.s3Provider,
      endpoint: v.s3Endpoint,
      // backend identity: the storage backend class the stack runs on.
      // "s3" everywhere — a variant silently degrading to file WAL/LocalFS
      // would change this and MUST hard-fail the differential.
      backend: "s3",
    },
  };
}

/**
 * Wrangler-equivalent view of the graph: what control-plane/wrangler.toml
 * must say for the same topology. declaredAhead bindings are reported
 * separately — absent from the strict comparison until activated.
 */
export function toWranglerView(repoRoot = REPO_ROOT) {
  const g = toGraph("local-native", repoRoot);
  const active = g.worker.bindings.filter((b) => !b.declaredAhead);
  const ahead = g.worker.bindings.filter((b) => b.declaredAhead);
  return {
    name: g.worker.name,
    main: path.posix.relative("control-plane", WORKER_ENTRY),
    compatibility_date: g.worker.compatibilityDate,
    durable_objects: active
      .filter((b) => b.type === "durable_object_namespace")
      .map((b) => ({ name: b.name, class_name: b.className })),
    new_sqlite_classes: active
      .filter((b) => b.type === "durable_object_namespace" && b.sqlite)
      .map((b) => b.className),
    r2_buckets: active
      .filter((b) => b.type === "r2_bucket")
      .map((b) => ({ binding: b.name, bucket_name: b.bucketName })),
    vars: { ...g.worker.vars },
    production: {
      vars: { ...PRODUCTION_VARS },
      forbidden_vars: [...PRODUCTION_FORBIDDEN_VARS],
      durable_objects: active
        .filter((b) => b.type === "durable_object_namespace")
        .map((b) => ({ name: b.name, class_name: b.className })),
      r2_buckets: active
        .filter((b) => b.type === "r2_bucket")
        .map((b) => ({ binding: b.name, bucket_name: PAYLOADS_BUCKET_PRODUCTION })),
    },
    declared_ahead: ahead.map((b) => ({
      name: b.name,
      class_name: b.className,
      type: b.type,
    })),
  };
}

// ---------------------------------------------------------------------------
// Canonical JSON (stable key order, LF, trailing newline) + digest
// ---------------------------------------------------------------------------

export function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    const out = {};
    for (const k of Object.keys(value).sort()) out[k] = canonicalize(value[k]);
    return out;
  }
  return value;
}

export function canonicalJson(value) {
  return `${JSON.stringify(canonicalize(value), null, 2)}\n`;
}

export function graphDigest(graph) {
  return createHash("sha256").update(canonicalJson(graph)).digest("hex");
}
