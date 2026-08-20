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
// half is a pinned NATIVE S3 backend (a source-locked provider binary),
// never Alchemy R2.
//
// Round-6 R6-LOCAL-01: which native provider that is, is no longer welded
// into the graph. The provider is a parameter with a named default
// (LOCAL_S3_PROVIDER_DEFAULT) and a named comparator
// (LOCAL_S3_PROVIDER_COMPARATOR); `stack dev/up`, the graph and
// native-fidelity.mjs all select it the same way. Whether the default is
// QUALIFIED is a separate, executable question answered by local-parity.mjs
// — this file only names the topology, it never grades it.

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

// ---------------------------------------------------------------------------
// Native S3 provider identity (R6-LOCAL-01). These are the ONLY places a
// local S3 provider is named; supervisors, the CLI and native-fidelity all
// resolve through them.
// ---------------------------------------------------------------------------

/**
 * The provider agent/native-local development runs by default. RustFS is
 * the audit's promotion candidate and is the configured default here; the
 * question "has the promotion lane actually been executed and passed?" is
 * answered at runtime by local-parity.mjs's executable gate, never by this
 * constant and never by a comment.
 */
export const LOCAL_S3_PROVIDER_DEFAULT = "rustfs";
/** Kept as a provider-diversity comparator (R6-LOCAL-01: do not delete). */
export const LOCAL_S3_PROVIDER_COMPARATOR = "minio";
export const LOCAL_S3_PROVIDERS = Object.freeze([
  LOCAL_S3_PROVIDER_DEFAULT,
  LOCAL_S3_PROVIDER_COMPARATOR,
]);

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

// Plain-text vars of the LOCAL developer-convenience posture. This posture
// (dev issuer, dev-only admin routes) is explicitly NON-PARITY: it exists
// for fast local iteration only, and no graph carrying it may ever be
// deployed or compared as production truth (R4-STACK-01).
export const LOCAL_VARS = Object.freeze({
  CONTROLLER_KEY_PROFILE: "local-dev",
  // ONLY this exact value opens dev-only routes (PR0 containment); the
  // managed posture deliberately does not set it — unset closes routes.
  CONTROLLER_SURFACE: "local-dev",
});

// Managed posture invariants (wrangler.toml top-level / production).
export const PRODUCTION_VARS = Object.freeze({
  CONTROLLER_KEY_PROFILE: "managed",
});
// R5-SEC-01/03: managed DEPLOYMENT vars — names declared here, values
// supplied per deployment (`wrangler deploy --var` / the managed E2E boot
// script), never baked into the committed wrangler.toml. They are PUBLIC
// runtime inputs (the environment name and the two Ed25519 verification
// keyrings), not secrets: the managed runtime verifies tokens but holds no
// signing material. stack/wrangler-check.mjs cross-validates this list
// against the runtime's own requirement declaration
// (control-plane/src/controller/core/key-requirements.mjs), so the graph
// and resolveKeyConfig cannot skew — that skew is exactly how the round-5
// audit's "managed graph cannot boot" defect happened.
export const PRODUCTION_DEPLOYMENT_VARS = Object.freeze([
  "CONTROLLER_ENVIRONMENT",
  "CONTROLLER_CAPABILITY_PUBLIC_KEYS",
  "CONTROLLER_PROVISION_PUBLIC_KEYS",
]);
// Vars that MUST NOT appear in any managed-posture graph: their absence is
// the fail-closed posture (losing the var closes routes, never opens them).
export const PRODUCTION_FORBIDDEN_VARS = Object.freeze(["CONTROLLER_SURFACE"]);

// R5-SEC-07 HONESTY: what each `execution` value actually means TODAY.
// The graph's `execution: "container"` used to read as if a Cloudflare
// Container process were exercised; it never has been — no lane in this
// repository has ever started a real Container resource (no Docker in the
// local sandbox, and Alchemy local cannot run one). This table is emitted
// into EVERY graph (identical across variants, so the graph differential
// is unaffected) and is the same declared-ahead convention the CONTAINER
// DO binding uses: a reader resolving a graph's `execution` mode through
// EXECUTION_FACETS can never mistake a declared container topology for an
// exercised one. The facet flips to exercised only when a Docker-capable
// lane actually starts the pinned image and the ContainerDO control
// protocol binds to it (the provisioned containerRuntime descriptor in
// control-plane/src/container/database-container.ts is that seam).
export const EXECUTION_FACETS = Object.freeze({
  native: Object.freeze({
    status: "exercised",
    declaredAhead: false,
    note: "native process execution is what local lanes actually run",
  }),
  container: Object.freeze({
    status: "declared-ahead",
    declaredAhead: true,
    advisory: true,
    note:
      "DECLARED topology only: no real Cloudflare Container process has ever "
      + "been started or exercised by any lane; the ContainerDO holds a "
      + "provisioned identity and ADVISORY observations, not a container "
      + "lifecycle. Requires a Docker-capable lane / the real Container "
      + "resource (matrix CF-02).",
  }),
});

// The two declared security postures. Every graph variant names its
// posture explicitly; the graph differential validates each graph's vars
// against its DECLARED posture independently, so two graphs can never
// pass merely by sharing the same unsafe values (the round-4 audit's
// surviving semantic mutant: cloudflare-real carrying local-dev vars).
export const SECURITY_POSTURES = Object.freeze({
  // Non-parity local iteration: dev issuer + dev admin routes. No
  // deployment vars: the committed dev keypairs need no provisioning.
  "developer-convenience": Object.freeze({
    vars: LOCAL_VARS,
    deploymentVars: Object.freeze([]),
    forbiddenVars: Object.freeze([]),
  }),
  // Production-shaped: managed keys, closed surface, no dev vars. Used by
  // cloudflare-real AND by the local parity lane (which supplies local
  // ephemeral managed material rather than dev constants).
  managed: Object.freeze({
    vars: PRODUCTION_VARS,
    deploymentVars: PRODUCTION_DEPLOYMENT_VARS,
    forbiddenVars: PRODUCTION_FORBIDDEN_VARS,
  }),
});

// Secret schema (managed posture provisions these via `wrangler secret put`;
// local-dev falls back to loud dev constants — core/key-config.ts).
// R5-SEC-03: exactly ONE secret remains. The capability/provision material
// became PUBLIC Ed25519 verification keys (deployment vars above); the
// issuer credential left the runtime entirely (issuance is issuer-side);
// the journal MAC key stays a symmetric secret BY DESIGN — its writer and
// verifier are the same DatabaseControllerDO (R5-SEC-08).
export const SECRET_SCHEMA = Object.freeze([
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
export function toGraph(variant = "local-native", repoRoot = REPO_ROOT, options = {}) {
  const s3Provider = options.s3Provider ?? LOCAL_S3_PROVIDER_DEFAULT;
  if (!LOCAL_S3_PROVIDERS.includes(s3Provider)) {
    throw new Error(
      `unknown local S3 provider ${JSON.stringify(s3Provider)} — known: ${LOCAL_S3_PROVIDERS.join(", ")}`,
    );
  }
  // provider-neutral endpoint template: the run manifest resolves it from
  // the supervised S3 component, whichever provider that is
  const localS3Endpoint = "http://127.0.0.1:${run.s3.port}";
  const variants = {
    "local-native": {
      execution: "native",
      s3Provider,
      s3Endpoint: localS3Endpoint,
      r2Provider: "alchemy-local-r2",
      doProvider: "alchemy-workerd-local",
      routeClass: "local-loopback",
      secretSource: "dev-constants",
      securityPosture: "developer-convenience",
    },
    // Local PARITY lane: identical local providers, but the MANAGED
    // security posture — local ephemeral managed secrets, closed surface,
    // no dev routes. This is the lane whose green may be compared with
    // cloudflare-real; local-native's convenience posture may not.
    "local-parity": {
      execution: "native",
      s3Provider,
      s3Endpoint: localS3Endpoint,
      r2Provider: "alchemy-local-r2",
      doProvider: "alchemy-workerd-local",
      routeClass: "local-loopback",
      secretSource: "local-ephemeral-managed",
      securityPosture: "managed",
    },
    "local-container": {
      execution: "container",
      s3Provider,
      s3Endpoint: localS3Endpoint,
      r2Provider: "alchemy-local-r2",
      doProvider: "alchemy-workerd-local",
      routeClass: "local-loopback",
      secretSource: "dev-constants",
      securityPosture: "developer-convenience",
    },
    "cloudflare-real": {
      execution: "container",
      s3Provider: "cloudflare-r2",
      s3Endpoint: "https://${account}.r2.cloudflarestorage.com",
      r2Provider: "cloudflare-r2",
      doProvider: "cloudflare-workerd",
      routeClass: "local-loopback", // no public routes are declared in any variant
      secretSource: "provisioned-secrets",
      securityPosture: "managed",
    },
  };
  const v = variants[variant];
  if (!v) throw new Error(`unknown graph variant: ${variant}`);
  const containerActive = containerDoExported(repoRoot);
  // R4-STACK-01: a graph's vars come from its DECLARED posture — the
  // cloudflare-real graph carries the managed vars and structurally cannot
  // carry a forbidden dev var. The posture invariant is additionally
  // re-validated per graph by graph-diff.mjs assertPostureInvariants.
  const posture = SECURITY_POSTURES[v.securityPosture];

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
    // R5-SEC-07: the honesty table rides in every graph so `execution` can
    // never be read without its facet status (identical across variants —
    // the differential sees no new paths).
    executionFacets: EXECUTION_FACETS,
    securityPosture: v.securityPosture,
    worker: {
      name: WORKER_NAME,
      entry: WORKER_ENTRY,
      compatibilityDate: COMPATIBILITY_DATE,
      routeClass: v.routeClass,
      provider: v.doProvider,
      bindings,
      vars: { ...posture.vars },
      deploymentVars: [...posture.deploymentVars],
      forbiddenVars: [...posture.forbiddenVars],
      // Public workers.dev / preview URLs are disabled in EVERY variant:
      // an implicit public route is an unsafe default, not a convenience.
      workersDev: false,
      previewUrls: false,
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

// MIGRATION LEDGER (R4-STACK-10): the append-only, order- and
// tag-immutable Durable Object migration history. wrangler-check.mjs
// requires the EXACT ordered sequence in every wrangler config; removing,
// reordering or retagging a historical entry fails the check. New
// migrations are APPENDED here (and to both config files) only.
export const MIGRATION_LEDGER = Object.freeze([
  Object.freeze({ tag: "v1", new_sqlite_classes: Object.freeze(["DatabaseControllerDO"]) }),
  Object.freeze({ tag: "v2", new_sqlite_classes: Object.freeze(["DatabaseContainerDO"]) }),
]);

/**
 * Wrangler-equivalent view of the graph: what the two wrangler configs
 * must say for the same topology (R4-STACK-01 split):
 *   - wrangler.toml            => the MANAGED posture (default deploy);
 *   - wrangler.local-dev.toml  => the developer-convenience posture,
 *                                 selected only by explicit -c.
 * declaredAhead bindings are reported separately — absent from the strict
 * comparison until activated.
 */
export function toWranglerView(repoRoot = REPO_ROOT) {
  const g = toGraph("local-native", repoRoot);
  const active = g.worker.bindings.filter((b) => !b.declaredAhead);
  const ahead = g.worker.bindings.filter((b) => b.declaredAhead);
  const doBindings = active
    .filter((b) => b.type === "durable_object_namespace")
    .map((b) => ({ name: b.name, class_name: b.className }));
  const sqliteClasses = active
    .filter((b) => b.type === "durable_object_namespace" && b.sqlite)
    .map((b) => b.className);
  const shared = {
    name: g.worker.name,
    main: path.posix.relative("control-plane", WORKER_ENTRY),
    compatibility_date: g.worker.compatibilityDate,
    workers_dev: false,
    preview_urls: false,
    durable_objects: doBindings,
    new_sqlite_classes: sqliteClasses,
    migration_ledger: MIGRATION_LEDGER.map((m) => ({ tag: m.tag, new_sqlite_classes: [...m.new_sqlite_classes] })),
  };
  return {
    managed: {
      ...shared,
      vars: { ...PRODUCTION_VARS },
      deployment_vars: [...PRODUCTION_DEPLOYMENT_VARS],
      forbidden_vars: [...PRODUCTION_FORBIDDEN_VARS],
      r2_buckets: active
        .filter((b) => b.type === "r2_bucket")
        .map((b) => ({ binding: b.name, bucket_name: PAYLOADS_BUCKET_PRODUCTION })),
    },
    local_dev: {
      ...shared,
      vars: { ...LOCAL_VARS },
      deployment_vars: [],
      forbidden_vars: [],
      r2_buckets: active
        .filter((b) => b.type === "r2_bucket")
        .map((b) => ({ binding: b.name, bucket_name: b.bucketName })),
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
