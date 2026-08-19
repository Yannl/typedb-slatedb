/*
 * CF-P1 / R5-SEC-06/07/09: `DatabaseContainerDO` — the container's DURABLE
 * CONTROL-PROTOCOL authority (brief §4.1.3, audit C-08).
 *
 * WHAT IS REAL TODAY vs WHAT IS NOT (R5-SEC-07 honesty):
 *
 *   REAL, exercised under workerd locally:
 *     - the registry-PROVISIONED identity of this authority: an Ed25519
 *       schema-v3 PROVISION capability (verified against the provisioning
 *       public keyring, core/registry.ts + core/capability.ts) binds this DO
 *       exactly once to environment/tenant/database/generation/controller
 *       incarnation/startup session, to its DERIVED DO name, and to a typed
 *       `containerRuntime` descriptor (image digest, config digest, expected
 *       port, protocol version);
 *     - ADVISORY lifecycle observations: bounded rows AND bounded bytes,
 *       recorded/read only under the provisioned identity, cross-checked
 *       against the bound image digest + protocol version on every write;
 *     - the HTTP ingress seam (`fetch` POST /observe) with a stream-capped
 *       body reader that counts ACTUAL bytes and never trusts Content-Length.
 *
 *   NOT REAL YET (future work, gated on a Docker-capable lane / the real
 *   Cloudflare Container resource — matrix CF-02, graph.data.mjs
 *   EXECUTION_FACETS marks the container execution facet declared-ahead):
 *     - no actual container PROCESS exists behind this DO: nothing here
 *       starts, stops, drains, health-probes or proxies a TypeDB image. The
 *       bound `containerRuntime.imageDigest` is a DECLARED value the
 *       provisioner asserts; when the real Container resource lands, the
 *       control protocol binds to that exact image identity and start/stop/
 *       drain lifecycle control attaches to this same provisioned record.
 *
 * By construction this DO holds NO authority tables and NO capability to
 * allocate TypeSequence/AppendLsn/ControlSeq, epochs, command outcomes,
 * checkpoints, pins, or deletes (inv. 148–150). Everything it stores is an
 * ADVISORY observation the controller treats as a hint, never as authority
 * (inv. 149): there is deliberately no method on this surface that grants,
 * fences, sequences, or resolves anything. Loss, duplication, reordering, or
 * outright fabrication of an observation can therefore never move database
 * authority — an observation is data, not a decision.
 *
 * Structural rules enforced here, mirroring `DatabaseControllerDO`:
 *  - R5-SEC-06: this authority serves NOTHING until it is PROVISIONED. The
 *    old first-authenticated-call bind is GONE: only the `provision`
 *    transaction — authorized by a PROVISION capability minted under the
 *    separate provisioning-scope Ed25519 keypair — may write the binding,
 *    exactly once. An ordinary observation call on an unbound DO fails with
 *    a typed refusal and ZERO side effects; a call presenting any identity
 *    other than the provisioned one is a typed refusal BEFORE any write.
 *    The provisioning transaction additionally verifies this DO instance IS
 *    the registry-derived identity (containerDoName), so a valid token
 *    cannot be spent on a mis-routed or attacker-chosen DO id;
 *  - R5-SEC-09: the observation store is bounded in ROWS and BYTES — per
 *    UTF-8-byte field caps, an aggregate stored-byte budget, and a typed
 *    refusal (naming the offending field) past any cap. Refusal, never
 *    truncation-as-success: advisory data may always be refused (inv. 149);
 *  - alarms only wake the idempotent GC reducer; schedule state is durable
 *    and every pass re-arms into the future with bounded backoff (inv. 154).
 */

import { DurableObject } from "cloudflare:workers";
import { resolveKeyConfig } from "../controller/core/key-config.ts";
import {
  checkBinding, verifyProvisionToken, type ProvisionBinding,
} from "../controller/core/registry.ts";
import type { VerificationKeyring } from "../controller/core/capability.ts";

/** The identity a container instance is bound to. All four components are
 *  load-bearing: a container serves ONE database, at ONE generation, under
 *  ONE controller incarnation, for ONE startup session. Since R5-SEC-06 the
 *  identity is fixed by the PROVISIONING transaction — presenting it never
 *  binds anything, it only has to MATCH the provisioned record. */
export interface ContainerIdentity {
  databaseId: string;
  generation: number;
  incarnation: number;
  startupSessionId: string;
}

/**
 * R5-SEC-07: the typed container-runtime descriptor the provisioning
 * transaction records — the seam the future real Container resource binds
 * to. Locally the image digest is a DECLARED value (no Docker exists in
 * this lane); it is bound at provision time and VERIFIED on every later
 * observation write, so when a real container process reports, an old or
 * foreign image fails typed.
 */
export interface ContainerRuntimeDescriptor {
  /** OCI image identity, "sha256:<64 hex>". Declared by the provisioner
   *  locally; the exact image the real Container resource must run. */
  imageDigest: string;
  /** sha256 hex (64 chars) over the container's resolved launch
   *  configuration (env/ports/entrypoint) as the provisioner computed it. */
  configDigest: string;
  /** the TCP port the container process is expected to serve (1..65535). */
  expectedPort: number;
  /** control-protocol version string the container must speak. */
  protocolVersion: string;
}

/** The full provisioned record: registry binding + container identity +
 *  derived DO name + runtime descriptor. Written exactly once, atomically. */
export interface ContainerProvisionRecord {
  binding: ProvisionBinding;
  identity: ContainerIdentity;
  doName: string;
  containerRuntime: ContainerRuntimeDescriptor;
}

/** A single advisory lifecycle observation. `processNonce` distinguishes the
 *  process instance that produced it (a restart under the same identity is a
 *  new nonce); `at` is the PRODUCER's wall clock and is advisory only — it is
 *  never used to order or gate any authority decision. */
export interface Observation {
  kind: string;
  at: number;
  processNonce: string;
  detail?: string;
}

/** Bounded observation ring capacity in ROWS (audit C-08 backpressure). */
export const MAX_OBSERVATIONS = 1024;

/** GC row low-water mark: the idempotent alarm trims the ring back to this
 *  many most-recent rows, so the hard refusal is a backstop, not a wedge. */
export const OBSERVATION_LOW_WATER = 512;

/*
 * R5-SEC-09: BYTE caps. Rows alone do not bound storage — 1024 rows of
 * multi-megabyte details would exhaust DO storage/memory. All caps are
 * UTF-8 BYTES (TextEncoder), never UTF-16 code units, so a multibyte
 * character cannot smuggle 3x the budget past a .length check. Every cap
 * violation is a TYPED refusal naming the field — never a silent truncation
 * presented as success.
 */
/** Max UTF-8 bytes of one observation `kind`. */
export const MAX_OBSERVATION_KIND_BYTES = 64;
/** Max UTF-8 bytes of one observation `processNonce`. */
export const MAX_OBSERVATION_NONCE_BYTES = 64;
/** Max UTF-8 bytes of one observation `detail`. */
export const MAX_OBSERVATION_DETAIL_BYTES = 4096;
/** Aggregate stored-byte budget across the whole ring (variable-length
 *  fields: kind + processNonce + detail). Past it, writes refuse typed. */
export const MAX_OBSERVATION_STORED_BYTES = 256 * 1024;
/** GC byte low-water mark: the alarm also trims until the stored bytes fit
 *  back under this, so a budget refusal self-heals like the row refusal. */
export const OBSERVATION_STORED_BYTES_LOW_WATER = MAX_OBSERVATION_STORED_BYTES / 2;
/** Total HTTP request-body cap of the /observe ingress, enforced on ACTUAL
 *  streamed bytes (readBodyCapped) — Content-Length is never trusted. */
export const MAX_OBSERVATION_REQUEST_BYTES = 16 * 1024;

/** Max UTF-8 bytes of the provisioned startupSessionId / protocolVersion. */
export const MAX_PROVISION_FIELD_BYTES = 64;

/** Default page size for getObservations; hard-capped at the ring size. */
const DEFAULT_OBSERVATION_PAGE = 256;

/** Kinds the container lifecycle produces. Free-form strings are accepted (an
 *  observation is opaque advisory data), but the known set is documented. */
export type ObservationKind =
  | "STARTED" | "STOPPED" | "PLATFORM_ERROR" | "HEALTH_OK" | "HEALTH_FAIL";

/**
 * The registry-derived container DO name (R5-SEC-06): the ONE name the
 * worker may route a container binding to, and the name the provisioning
 * transaction verifies this instance was created under. Domain-separated
 * ("ctr/", vs the controller's "ctl/") and unambiguous because every
 * segment is slash-free by the registry's OPAQUE_ID syntax.
 */
export function containerDoName(binding: ProvisionBinding): string {
  return `ctr/${binding.environment}/${binding.tenantId}/${binding.databaseId}`;
}

const UTF8_ENCODER = new TextEncoder();
const UTF8_DECODER = new TextDecoder();

function utf8ByteLength(value: string): number {
  return UTF8_ENCODER.encode(value).byteLength;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isSafeCount(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

const IMAGE_DIGEST = /^sha256:[0-9a-f]{64}$/;
const HEX_DIGEST = /^[0-9a-f]{64}$/;

/** Typed refusals of the provisioned-identity gate: every ordinary call to
 *  an authority that has not been provisioned — or that presents any
 *  identity other than the provisioned one — fails closed with one of
 *  these, with ZERO side effects (nothing here ever binds). */
export type ContainerBindingRefusal =
  | { ok: false; error: "CONTAINER_UNPROVISIONED" }
  | { ok: false; error: "CONTAINER_IDENTITY_MALFORMED" }
  | { ok: false; error: "DO_CONTAINER_BINDING_MISMATCH" };

export type ContainerProvisionResult =
  | { ok: true; created: boolean; record: ContainerProvisionRecord }
  | { ok: false; error: string; field?: string };

export type RecordObservationResult =
  | { ok: true; advisory: true; seq: number }
  | ContainerBindingRefusal
  | { ok: false; error: "CONTAINER_RUNTIME_MISMATCH"; field: "imageDigest" | "protocolVersion" }
  | { ok: false; error: "OBSERVATION_MALFORMED" }
  | { ok: false; error: "OBSERVATION_FIELD_TOO_LARGE"; field: "kind" | "processNonce" | "detail"; maxBytes: number; actualBytes: number }
  | { ok: false; error: "OBSERVATION_LIMIT_EXCEEDED" }
  | { ok: false; error: "OBSERVATION_BUDGET_EXCEEDED"; maxBytes: number; storedBytes: number };

/** Env the container DO consumes: the shared key-configuration inputs
 *  (core/key-config.ts — the provisioning PUBLIC keyring + environment are
 *  what this class needs) plus its own namespace binding, used to verify
 *  the instance really is the registry-derived DO identity. */
export interface ContainerEnv {
  CONTROLLER_KEY_PROFILE?: string;
  CONTROLLER_JOURNAL_KEY?: string;
  CONTROLLER_ENVIRONMENT?: string;
  CONTROLLER_CAPABILITY_PUBLIC_KEYS?: string;
  CONTROLLER_PROVISION_PUBLIC_KEYS?: string;
  CONTROLLER_ISSUER_SECRET?: string;
  CONTROLLER_CAPABILITY_KEY?: string;
  CONTROLLER_PROVISION_KEY?: string;
  CONTAINER?: DurableObjectNamespace;
}

/**
 * Stream-capped body read (R5-SEC-09): counts ACTUAL bytes as they arrive
 * and aborts past the cap — a lying, absent, or chunk-encoded
 * Content-Length can never make more than `maxBytes + one chunk` transit,
 * and never a full oversized body materialize. Returns null when the cap
 * is exceeded.
 */
export async function readBodyCapped(body: ReadableStream<Uint8Array> | null, maxBytes: number): Promise<Uint8Array | null> {
  if (body === null) return new Uint8Array(0);
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value === undefined) continue;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel("body exceeds cap");
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

export class DatabaseContainerDO extends DurableObject {
  private sql: SqlStorage;
  private readonly provisionKeyring: VerificationKeyring;
  private readonly environment: string;
  private readonly namespace: DurableObjectNamespace | undefined;

  constructor(state: DurableObjectState, env: ContainerEnv) {
    super(state, env as never);
    this.sql = state.storage.sql;
    // Fail closed on key configuration exactly like the controller (Q-24):
    // resolveKeyConfig THROWS on a managed deployment with absent/empty/
    // malformed/dev-constant keys, which fails DO construction, which makes
    // every route on this authority refuse. Only the provisioning PUBLIC
    // keyring + environment are consumed here: this DO can verify the
    // PROVISION capability and can mint nothing (R5-SEC-03).
    const keys = resolveKeyConfig(env);
    this.provisionKeyring = keys.provisionKeyring;
    this.environment = keys.environment;
    this.namespace = env.CONTAINER;
    // DO-runtime tables only — this authority owns NO projection/sequence
    // tables by construction (inv. 148). container_provision is the
    // single-row provisioned binding (written only by the provisioning
    // transaction); observations is the bounded advisory ring (byte_size
    // carries each row's UTF-8 variable-field bytes for the aggregate
    // budget); container_alarm_schedule mirrors the controller's durable
    // alarm state.
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS container_provision(
        key TEXT PRIMARY KEY CHECK(key='binding'),
        environment TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        database_id TEXT NOT NULL,
        generation INTEGER NOT NULL,
        incarnation INTEGER NOT NULL,
        startup_session_id TEXT NOT NULL,
        do_name TEXT NOT NULL,
        image_digest TEXT NOT NULL,
        config_digest TEXT NOT NULL,
        expected_port INTEGER NOT NULL,
        protocol_version TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS observations(
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        database_id TEXT NOT NULL,
        generation INTEGER NOT NULL,
        incarnation INTEGER NOT NULL,
        startup_session_id TEXT NOT NULL,
        process_nonce TEXT NOT NULL,
        kind TEXT NOT NULL,
        at INTEGER NOT NULL,
        detail TEXT,
        byte_size INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS container_alarm_schedule(
        task TEXT PRIMARY KEY,
        next_due_at INTEGER NOT NULL,
        interval_ms INTEGER NOT NULL DEFAULT 60000,
        attempts INTEGER NOT NULL DEFAULT 0
      );
    `);
  }

  /** The provisioned record of this authority, or null before provisioning.
   *  One row, written only inside the provisioning transaction — a partial
   *  record is structurally impossible. */
  private provisionedRecord(): ContainerProvisionRecord | null {
    const rows = this.sql.exec(`SELECT * FROM container_provision WHERE key='binding'`).toArray();
    if (!rows.length) return null;
    const row = rows[0];
    return {
      binding: {
        environment: String(row.environment),
        tenantId: String(row.tenant_id),
        databaseId: String(row.database_id),
      },
      identity: {
        databaseId: String(row.database_id),
        generation: Number(row.generation),
        incarnation: Number(row.incarnation),
        startupSessionId: String(row.startup_session_id),
      },
      doName: String(row.do_name),
      containerRuntime: {
        imageDigest: String(row.image_digest),
        configDigest: String(row.config_digest),
        expectedPort: Number(row.expected_port),
        protocolVersion: String(row.protocol_version),
      },
    };
  }

  /** True iff this instance's DO id IS the registry-derived identity for
   *  the binding (idFromName(containerDoName)). Verified via the DO's own
   *  namespace binding; absent that, via the id's creation name. */
  private isDerivedInstanceFor(doName: string): boolean {
    if (this.namespace !== undefined) {
      return this.namespace.idFromName(doName).equals(this.ctx.id);
    }
    return this.ctx.id.name === doName;
  }

  /**
   * R5-SEC-06: the provisioning transaction — the ONLY path that binds this
   * uninitialized authority, and it binds exactly once. Authorized by an
   * Ed25519 schema-v3 PROVISION capability verified against the
   * provisioning-scope PUBLIC keyring in this DO's own environment; the
   * token's env/tenantId/databaseId must EXACTLY equal the binding being
   * provisioned, so the caller-supplied fields carry no authority of their
   * own — a token for another tenant's database refuses before any durable
   * work, and ordinary capability-scope material cannot produce a valid
   * signature at all. The transaction additionally verifies this instance
   * is the DERIVED DO identity for the binding (a valid token spent on a
   * mis-routed or attacker-chosen DO id refuses), then writes the full
   * record — registry binding, container identity, derived name, and the
   * containerRuntime descriptor (R5-SEC-07 seam) — in one synchronous
   * transaction. Racing provisioners are serialized by the DO: the first
   * writes the record; an identical replay is idempotent; anything else is
   * a typed conflict (stale controller incarnations named as such) and the
   * standing record is never overwritten.
   */
  async provision(
    token: string,
    wire: {
      environment?: unknown; tenantId?: unknown; databaseId?: unknown;
      generation?: unknown; incarnation?: unknown; startupSessionId?: unknown;
      containerRuntime?: {
        imageDigest?: unknown; configDigest?: unknown; expectedPort?: unknown; protocolVersion?: unknown;
      };
    },
  ): Promise<ContainerProvisionResult> {
    const checked = checkBinding(wire);
    if (!checked.ok) return checked;
    const binding = checked.binding;
    if (binding.environment !== this.environment) {
      return { ok: false, error: "PROVISION_ENVIRONMENT_MISMATCH" };
    }
    // container identity fields
    if (!isSafeCount(wire.generation)) return { ok: false, error: "PROVISION_IDENTITY_INVALID", field: "generation" };
    if (!isSafeCount(wire.incarnation)) return { ok: false, error: "PROVISION_IDENTITY_INVALID", field: "incarnation" };
    if (!isNonEmptyString(wire.startupSessionId)
        || utf8ByteLength(wire.startupSessionId) > MAX_PROVISION_FIELD_BYTES) {
      return { ok: false, error: "PROVISION_IDENTITY_INVALID", field: "startupSessionId" };
    }
    // containerRuntime descriptor (R5-SEC-07): typed, mandatory, bounded
    const runtime = wire.containerRuntime;
    if (typeof runtime !== "object" || runtime === null) {
      return { ok: false, error: "CONTAINER_RUNTIME_INVALID", field: "containerRuntime" };
    }
    if (typeof runtime.imageDigest !== "string" || !IMAGE_DIGEST.test(runtime.imageDigest)) {
      return { ok: false, error: "CONTAINER_RUNTIME_INVALID", field: "imageDigest" };
    }
    if (typeof runtime.configDigest !== "string" || !HEX_DIGEST.test(runtime.configDigest)) {
      return { ok: false, error: "CONTAINER_RUNTIME_INVALID", field: "configDigest" };
    }
    if (!isSafeCount(runtime.expectedPort) || runtime.expectedPort < 1 || runtime.expectedPort > 65535) {
      return { ok: false, error: "CONTAINER_RUNTIME_INVALID", field: "expectedPort" };
    }
    if (!isNonEmptyString(runtime.protocolVersion)
        || utf8ByteLength(runtime.protocolVersion) > MAX_PROVISION_FIELD_BYTES) {
      return { ok: false, error: "CONTAINER_RUNTIME_INVALID", field: "protocolVersion" };
    }
    const record: ContainerProvisionRecord = {
      binding,
      identity: {
        databaseId: binding.databaseId,
        generation: wire.generation,
        incarnation: wire.incarnation,
        startupSessionId: wire.startupSessionId,
      },
      doName: containerDoName(binding),
      containerRuntime: {
        imageDigest: runtime.imageDigest,
        configDigest: runtime.configDigest,
        expectedPort: runtime.expectedPort,
        protocolVersion: runtime.protocolVersion,
      },
    };
    // async signature verification FIRST (R5-SEC-03); the binding write
    // below stays one synchronous transaction with no await inside it. The
    // token's own env/tenant/database must equal the binding EXACTLY — the
    // wire fields select the record, the TOKEN authorizes it.
    const verdict = await verifyProvisionToken(this.provisionKeyring, token, {
      binding, nowMs: Date.now(),
    });
    if (!verdict.ok) return verdict;
    // derived-identity check (R5-SEC-06): a genuine PROVISION token cannot
    // be spent on any DO other than the one derived from its own binding —
    // squatting a neighboring or attacker-chosen DO id is structurally dead.
    if (!this.isDerivedInstanceFor(record.doName)) {
      return { ok: false, error: "PROVISION_DO_MISROUTED" };
    }
    return this.ctx.storage.transactionSync(() => {
      const bound = this.provisionedRecord();
      if (bound !== null) {
        if (JSON.stringify(bound) === JSON.stringify(record)) {
          // idempotent replay of the exact same provisioning
          return { ok: true as const, created: false, record: bound };
        }
        if (record.identity.incarnation < bound.identity.incarnation) {
          // a superseded controller replaying an old provisioning is named
          // as STALE, distinctly from an ordinary conflicting provisioner
          return { ok: false as const, error: "PROVISION_STALE_CONTROLLER" };
        }
        // the race loser (or any later conflicting provisioner): typed
        // refusal, the standing record is never overwritten or blended
        return { ok: false as const, error: "PROVISION_CONFLICT" };
      }
      this.sql.exec(
        `INSERT INTO container_provision(
           key, environment, tenant_id, database_id, generation, incarnation,
           startup_session_id, do_name, image_digest, config_digest, expected_port, protocol_version)
         VALUES ('binding', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        record.binding.environment, record.binding.tenantId, record.binding.databaseId,
        record.identity.generation, record.identity.incarnation, record.identity.startupSessionId,
        record.doName, record.containerRuntime.imageDigest, record.containerRuntime.configDigest,
        record.containerRuntime.expectedPort, record.containerRuntime.protocolVersion,
      );
      return { ok: true as const, created: true, record };
    });
  }

  /** Read the provisioned record (controller bootstrap verification /
   *  tests). Null means unprovisioned — and unprovisioned serves nothing. */
  getProvisionRecord(): ContainerProvisionRecord | null {
    return this.provisionedRecord();
  }

  /**
   * The provisioned-identity gate for every ordinary call (R5-SEC-06): an
   * authority with NO provisioned record refuses with a typed error and
   * ZERO side effects (only `provision` ever writes the record), and a
   * provisioned authority refuses any call presenting an identity that is
   * not exactly the provisioned one. Returns the record on success so
   * callers can cross-check the runtime descriptor too.
   */
  private requireIdentity(identity: ContainerIdentity):
    { ok: true; record: ContainerProvisionRecord } | ContainerBindingRefusal {
    if (!isNonEmptyString(identity?.databaseId) || !isNonEmptyString(identity?.startupSessionId)
        || !isSafeCount(identity?.generation) || !isSafeCount(identity?.incarnation)) {
      return { ok: false, error: "CONTAINER_IDENTITY_MALFORMED" };
    }
    const record = this.provisionedRecord();
    if (record === null) return { ok: false, error: "CONTAINER_UNPROVISIONED" };
    const bound = record.identity;
    if (bound.databaseId !== identity.databaseId
        || bound.generation !== identity.generation
        || bound.incarnation !== identity.incarnation
        || bound.startupSessionId !== identity.startupSessionId) {
      // covers the stale-controller-incarnation caller and every other
      // foreign identity: typed refusal BEFORE any write
      return { ok: false, error: "DO_CONTAINER_BINDING_MISMATCH" };
    }
    return { ok: true, record };
  }

  /**
   * Record one advisory lifecycle observation (gated by the PROVISIONED
   * identity; the caller must additionally present the bound image digest
   * and protocol version — an old image or foreign protocol fails typed,
   * R5-SEC-07). Returns `advisory: true` to make the contract explicit at
   * the RPC boundary: this call can never grant, fence, or sequence
   * anything (inv. 149). Backpressure is rows AND bytes (R5-SEC-09): past
   * MAX_OBSERVATIONS rows, past any per-field UTF-8 byte cap, or past the
   * aggregate stored-byte budget the call is refused with a typed error
   * naming the limit — never truncated — and the alarm GC drains the ring
   * back under both low-water marks.
   */
  recordObservation(
    identity: ContainerIdentity,
    observation: Observation,
    runtime: { imageDigest?: string; protocolVersion?: string },
  ): RecordObservationResult {
    const gate = this.requireIdentity(identity);
    if (!gate.ok) return gate;
    const bound = gate.record.containerRuntime;
    if (runtime?.imageDigest !== bound.imageDigest) {
      return { ok: false, error: "CONTAINER_RUNTIME_MISMATCH", field: "imageDigest" };
    }
    if (runtime?.protocolVersion !== bound.protocolVersion) {
      return { ok: false, error: "CONTAINER_RUNTIME_MISMATCH", field: "protocolVersion" };
    }
    if (!isNonEmptyString(observation?.kind) || !isNonEmptyString(observation?.processNonce)
        || !isSafeCount(observation?.at)
        || (observation.detail !== undefined && typeof observation.detail !== "string")) {
      return { ok: false, error: "OBSERVATION_MALFORMED" };
    }
    // R5-SEC-09 per-field UTF-8 byte caps: typed refusal names the field
    const kindBytes = utf8ByteLength(observation.kind);
    if (kindBytes > MAX_OBSERVATION_KIND_BYTES) {
      return { ok: false, error: "OBSERVATION_FIELD_TOO_LARGE", field: "kind", maxBytes: MAX_OBSERVATION_KIND_BYTES, actualBytes: kindBytes };
    }
    const nonceBytes = utf8ByteLength(observation.processNonce);
    if (nonceBytes > MAX_OBSERVATION_NONCE_BYTES) {
      return { ok: false, error: "OBSERVATION_FIELD_TOO_LARGE", field: "processNonce", maxBytes: MAX_OBSERVATION_NONCE_BYTES, actualBytes: nonceBytes };
    }
    const detailBytes = observation.detail === undefined ? 0 : utf8ByteLength(observation.detail);
    if (detailBytes > MAX_OBSERVATION_DETAIL_BYTES) {
      return { ok: false, error: "OBSERVATION_FIELD_TOO_LARGE", field: "detail", maxBytes: MAX_OBSERVATION_DETAIL_BYTES, actualBytes: detailBytes };
    }
    const rowBytes = kindBytes + nonceBytes + detailBytes;
    const totals = this.sql
      .exec(`SELECT COUNT(*) AS n, COALESCE(SUM(byte_size), 0) AS bytes FROM observations`)
      .one() as { n: number; bytes: number };
    if (Number(totals.n) >= MAX_OBSERVATIONS) {
      return { ok: false, error: "OBSERVATION_LIMIT_EXCEEDED" };
    }
    // aggregate stored-byte budget (R5-SEC-09): refusal, never truncation
    if (Number(totals.bytes) + rowBytes > MAX_OBSERVATION_STORED_BYTES) {
      return {
        ok: false, error: "OBSERVATION_BUDGET_EXCEEDED",
        maxBytes: MAX_OBSERVATION_STORED_BYTES, storedBytes: Number(totals.bytes),
      };
    }
    const inserted = this.sql.exec(
      `INSERT INTO observations(
         database_id, generation, incarnation, startup_session_id, process_nonce, kind, at, detail, byte_size)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING seq`,
      identity.databaseId, identity.generation, identity.incarnation, identity.startupSessionId,
      observation.processNonce, observation.kind, observation.at,
      observation.detail === undefined ? null : observation.detail,
      rowBytes,
    ).one() as { seq: number };
    return { ok: true, advisory: true, seq: Number(inserted.seq) };
  }

  /**
   * Read advisory observations back (gated by the provisioned identity).
   * `advisory: true` again marks that the caller is reading a hint, not
   * authority: nothing about the returned rows constrains any authority
   * decision the controller makes.
   */
  getObservations(identity: ContainerIdentity, opts?: { limit?: number; sinceSeq?: number }):
    { ok: true; advisory: true; observations: (Observation & { seq: number })[] }
    | ContainerBindingRefusal {
    const gate = this.requireIdentity(identity);
    if (!gate.ok) return gate;
    const rawLimit = opts?.limit;
    const limit = isSafeCount(rawLimit) && rawLimit > 0
      ? Math.min(rawLimit, MAX_OBSERVATIONS)
      : DEFAULT_OBSERVATION_PAGE;
    const sinceSeq = isSafeCount(opts?.sinceSeq) ? Number(opts?.sinceSeq) : 0;
    const rows = this.sql.exec(
      `SELECT seq, kind, at, process_nonce, detail FROM observations
       WHERE seq > ? ORDER BY seq ASC LIMIT ?`,
      sinceSeq, limit,
    ).toArray();
    const observations = rows.map((row) => ({
      seq: Number(row.seq),
      kind: String(row.kind),
      at: Number(row.at),
      processNonce: String(row.process_nonce),
      ...(row.detail === null ? {} : { detail: String(row.detail) }),
    }));
    return { ok: true, advisory: true, observations };
  }

  /**
   * HTTP ingress seam (R5-SEC-07/09): the surface the future real container
   * process reports through. POST /observe with a JSON body
   * `{ identity, observation, containerRuntime }`; the body is read through
   * the stream-capped reader (ACTUAL bytes, Content-Length never trusted)
   * and dispatched to the same gated recordObservation as the RPC path —
   * one enforcement point, two transports.
   */
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method !== "POST" || url.pathname !== "/observe") {
      return Response.json({ error: "NOT_FOUND" }, { status: 404 });
    }
    const body = await readBodyCapped(request.body, MAX_OBSERVATION_REQUEST_BYTES);
    if (body === null) {
      return Response.json(
        { error: "OBSERVATION_REQUEST_TOO_LARGE", maxBytes: MAX_OBSERVATION_REQUEST_BYTES },
        { status: 413 },
      );
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(UTF8_DECODER.decode(body));
    } catch {
      return Response.json({ error: "OBSERVATION_REQUEST_MALFORMED" }, { status: 400 });
    }
    if (typeof parsed !== "object" || parsed === null) {
      return Response.json({ error: "OBSERVATION_REQUEST_MALFORMED" }, { status: 400 });
    }
    const { identity, observation, containerRuntime } = parsed as {
      identity?: ContainerIdentity; observation?: Observation;
      containerRuntime?: { imageDigest?: string; protocolVersion?: string };
    };
    const result = this.recordObservation(
      identity as ContainerIdentity, observation as Observation, containerRuntime ?? {});
    if (result.ok) return Response.json(result, { status: 200 });
    const status =
      result.error === "CONTAINER_UNPROVISIONED"
        || result.error === "DO_CONTAINER_BINDING_MISMATCH"
        || result.error === "CONTAINER_RUNTIME_MISMATCH" ? 403
      : result.error === "OBSERVATION_LIMIT_EXCEEDED"
        || result.error === "OBSERVATION_BUDGET_EXCEEDED" ? 429
      : 400;
    return Response.json(result, { status });
  }

  /** Register (or reschedule) a periodic task and arm the alarm (durable
   *  schedule state; mirrors DatabaseControllerDO.scheduleTask). */
  async scheduleTask(task: string, intervalMs: number): Promise<void> {
    const now = Date.now();
    this.sql.exec(
      `INSERT OR REPLACE INTO container_alarm_schedule(task, next_due_at, interval_ms, attempts)
       VALUES (?, ?, ?, 0)`,
      task, now + intervalMs, intervalMs,
    );
    await this.armAlarm();
  }

  /**
   * Alarms: at-least-once wakeups driving idempotent reducers only (inv. 154,
   * mirrors DatabaseControllerDO.alarm). Progress is re-derived from durable
   * state, never from the invocation count. Every pass advances next_due_at
   * (success: now+interval; failure: bounded exponential backoff) so the alarm
   * is always re-armed into the future — an unchanged past timestamp would
   * busy-loop the DO.
   */
  async alarm(): Promise<void> {
    const now = Date.now();
    const due = this.sql
      .exec(`SELECT task, interval_ms, attempts FROM container_alarm_schedule WHERE next_due_at <= ?`, now)
      .toArray();
    for (const row of due) {
      try {
        this.runScheduledTask(String(row.task));
        this.sql.exec(
          `UPDATE container_alarm_schedule SET attempts = 0, next_due_at = ? WHERE task = ?`,
          now + Number(row.interval_ms), row.task,
        );
      } catch {
        this.sql.exec(
          `UPDATE container_alarm_schedule SET attempts = attempts + 1, next_due_at = ? WHERE task = ?`,
          now + Math.min(60_000 * 2 ** Number(row.attempts), 3_600_000),
          row.task,
        );
      }
    }
    await this.armAlarm();
  }

  /** Dispatch table for scheduled work; every handler MUST be idempotent. */
  private runScheduledTask(task: string): void {
    switch (task) {
      case "observation-gc":
        // idempotent: trim the advisory ring under both low-water marks,
        // oldest first. Dropping advisory observations never moves authority.
        this.gcObservations();
        return;
      default:
        throw new Error(`unknown scheduled task: ${task}`);
    }
  }

  /**
   * Trim the observation ring until it fits BOTH low-water marks —
   * OBSERVATION_LOW_WATER most-recent rows AND
   * OBSERVATION_STORED_BYTES_LOW_WATER aggregate bytes (R5-SEC-09) —
   * dropping oldest first. Exposed for the alarm and directly for tests;
   * idempotent.
   */
  gcObservations(): { pruned: number } {
    const rows = this.sql
      .exec(`SELECT seq, byte_size FROM observations ORDER BY seq DESC`)
      .toArray() as { seq: number; byte_size: number }[];
    let kept = 0;
    let keptBytes = 0;
    let cutoff: number | null = null; // delete every seq <= cutoff
    for (const row of rows) {
      if (kept >= OBSERVATION_LOW_WATER
          || keptBytes + Number(row.byte_size) > OBSERVATION_STORED_BYTES_LOW_WATER) {
        cutoff = Number(row.seq);
        break;
      }
      kept += 1;
      keptBytes += Number(row.byte_size);
    }
    if (cutoff === null) return { pruned: 0 };
    this.sql.exec(`DELETE FROM observations WHERE seq <= ?`, cutoff);
    return { pruned: rows.length - kept };
  }

  private async armAlarm(): Promise<void> {
    const next = this.sql
      .exec(`SELECT MIN(next_due_at) AS n FROM container_alarm_schedule`)
      .one() as { n: number | null };
    if (next.n !== null) await this.ctx.storage.setAlarm(Number(next.n));
  }
}
