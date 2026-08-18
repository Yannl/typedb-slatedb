// Canonical Alchemy graph for the TypeDB-on-R2 control plane (audit A-01,
// §6.7): ONE program owns the Worker, the DatabaseControllerDO namespace,
// the declared DatabaseContainerDO namespace, the PAYLOADS R2 binding, the
// compatibility date and the var/secret schema. The committed
// control-plane/wrangler.toml is NOT maintained independently: stack
// `check-wrangler` (wrangler-check.mjs) fails on any drift between it and
// this graph's wrangler-equivalent view.
//
// LOCAL-ONLY BY CONSTRUCTION. This file must stay runnable with zero
// Cloudflare credentials under `stack/cli.mjs dev`:
//   - no `remote()` / live / bridge imports — the no-cloud guard
//     (no-cloud-guard.mjs) statically scans this file and refuses to start
//     anything if one appears;
//   - only resource kinds with a LOCAL provider are allowed (Worker,
//     DurableObject, R2 Bucket, Container) — anything else is refused;
//   - state is the local file store, never a cloud state store;
//   - the runtime guard asserts every emulated resource id is `dev:` and
//     hard-fails if CLOUDFLARE_API_TOKEN / CLOUDFLARE_ACCOUNT_ID are set.
//
// The S3 half is deliberately NOT here: Alchemy's local R2 exposes a Worker
// binding only — no S3 endpoint, no SigV4, no XML API (§6.3) — so the
// TypeDB/SlateDB `object_store` path runs against the pinned native MinIO
// (source-lock node MINIO, supervised by minio.mjs), never against a facade.

import * as Alchemy from "alchemy";
import * as Cloudflare from "alchemy/Cloudflare";
import * as Effect from "effect/Effect";
import path from "node:path";
import {
  COMPATIBILITY_DATE,
  CONTAINER_BINDING,
  CONTAINER_CLASS,
  CONTROLLER_BINDING,
  CONTROLLER_CLASS,
  LOCAL_VARS,
  PAYLOADS_BINDING,
  PAYLOADS_BUCKET_LOCAL,
  REPO_ROOT,
  WORKER_ENTRY,
  WORKER_NAME,
  containerDoExported,
} from "./graph.data.mjs";

// R2 bucket for payload bytes. In `alchemy dev` this is Alchemy's local R2
// simulator (Miniflare-derived DO-SQLite metadata + disk blobs); the local
// provider fabricates a `dev:`-prefixed physical identity, which the
// runtime guard asserts after bring-up.
export const Payloads = Cloudflare.R2.Bucket(PAYLOADS_BINDING, {
  name: PAYLOADS_BUCKET_LOCAL,
});

// DatabaseContainerDO — DECLARED AHEAD. The container workstream is making
// the class real; the namespace is part of the canonical graph now
// (graph.data.mjs carries it with a declaredAhead flag), but the binding is
// only handed to Alchemy once the worker entry actually exports the class —
// otherwise bundling/migrations would name a class that does not exist and
// the graph would stop validating offline. The L2 container-execution lane
// additionally attaches the production OCI image via Cloudflare.Container
// on a Docker-capable runner (blocked here: no Docker daemon, and the
// PRODUCTION_BASE image is still architecture_choice_required in the lock).
const containerActive = containerDoExported(REPO_ROOT);

const bindings: Record<string, unknown> = {
  [CONTROLLER_BINDING]: Cloudflare.DurableObject(CONTROLLER_BINDING, {
    // SQLite-backed: alchemy v2 puts every NEW DO class in
    // new_sqlite_classes (WorkerProvider), matching wrangler.toml's
    // migrations.new_sqlite_classes.
    className: CONTROLLER_CLASS,
  }),
  [PAYLOADS_BINDING]: Payloads,
  // Plain-text vars (exact wrangler.toml [vars] posture). Secrets
  // (CONTROLLER_JOURNAL_KEY / CONTROLLER_CAPABILITY_KEY /
  // CONTROLLER_ISSUER_SECRET) are deliberately NOT set in the local
  // posture: key-config.ts falls back to loud dev constants under
  // CONTROLLER_KEY_PROFILE=local-dev, and the managed posture provisions
  // them as real secrets outside this local-only program.
  ...LOCAL_VARS,
};

if (containerActive) {
  bindings[CONTAINER_BINDING] = Cloudflare.DurableObject(CONTAINER_BINDING, {
    className: CONTAINER_CLASS,
  });
}

export const ControlPlane = Cloudflare.Worker(WORKER_NAME, {
  name: WORKER_NAME,
  main: path.join(REPO_ROOT, WORKER_ENTRY),
  compatibility: { date: COMPATIBILITY_DATE },
  // no workers.dev surface: the local stack serves on loopback only, and
  // the graph declares no public route class anywhere
  workersDev: false,
  env: bindings,
});

export default Alchemy.Stack(
  "typedb-r2",
  {
    providers: Cloudflare.providers(),
    // local file state only — a cloud state store would itself be a live
    // resource and is exactly what the no-cloud guard exists to prevent
    state: Alchemy.localState(),
  },
  Effect.gen(function* () {
    const payloads = yield* Payloads;
    const worker = yield* ControlPlane;
    return { payloads, worker };
  }),
);
