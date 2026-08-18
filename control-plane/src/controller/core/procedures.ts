/*
 * CT-P1/CT-P3/CT-P5 (deterministic lane): the DatabaseControllerDO's
 * authoritative SQLite procedures as a runtime-agnostic core.
 *
 * The same module drives (a) the node test harness over better-sqlite3 today
 * and (b) the DO class over `state.storage.sql` behind the G2 gate — both
 * expose synchronous SQL execution, which is exactly the contract these
 * procedures require: NO awaits between validation and commit (inv. 151).
 *
 * Load-bearing rules implemented here:
 *  - late atomic allocation: TypeSequence/AppendLsn/ControlSeq are allocated
 *    inside the single synchronous finalisation transaction, after
 *    revalidation, never at reservation time;
 *  - exact-once by operation identity: (database, generation, operationId) is
 *    unique; replay with the same request digest returns the original result,
 *    replay with a different digest is a typed conflict;
 *  - the status record (unsequenced logical key) is a singleton per
 *    (database, generation, logicalKey): duplicate identical writes are
 *    idempotent, conflicting writes are rejected — never both accepted;
 *  - the outbox row is written in the SAME transaction as the projection
 *    mutation; publishing is an idempotent drain keyed by control_seq;
 *  - bounded admission: outbox depth and payload budgets are enforced
 *    fail-closed with typed errors BEFORE any allocation;
 *  - exact indexes: lookups by (generation, lsn) and by operation id are
 *    exact — a missing row is a typed NOT_FOUND, never treated as EOF.
 */

import { bytesEqual, canonicalJson, fromHex as fromHexInternal, hex, hmacSha256, sha256, utf8 } from "./journal-crypto.ts";

export interface SqlRow {
  [column: string]: unknown;
}

/** Minimal synchronous SQL surface shared by DO SqlStorage and better-sqlite3. */
export interface SyncSql {
  exec(sql: string, ...params: unknown[]): SqlRow[];
  /** Run fn inside a transaction; rollback if it throws. Must be synchronous. */
  transaction<T>(fn: () => T): T;
}

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS wal_tail(
    database_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    append_lsn BLOB NOT NULL,
    type_sequence BLOB NOT NULL,
    sequencing_kind TEXT NOT NULL CHECK(sequencing_kind IN ('SEQUENCED','UNSEQUENCED')),
    payload_key TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    payload_length INTEGER NOT NULL,
    finalization_operation_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    unsequenced_logical_key TEXT,
    startup_session_id TEXT NOT NULL,
    control_seq BLOB NOT NULL,
    record_type INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(database_id, generation, append_lsn),
    UNIQUE(database_id, generation, finalization_operation_id)
  );
  CREATE UNIQUE INDEX IF NOT EXISTS wal_status_singleton
    ON wal_tail(database_id, generation, unsequenced_logical_key)
    WHERE unsequenced_logical_key IS NOT NULL;
  CREATE TABLE IF NOT EXISTS control_outbox(
    control_seq BLOB PRIMARY KEY,
    database_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    canonical_body TEXT NOT NULL,
    published INTEGER NOT NULL DEFAULT 0,
    prev_hash BLOB NOT NULL,
    entry_hash BLOB NOT NULL,
    mac BLOB NOT NULL
  );
  CREATE TABLE IF NOT EXISTS budgets(
    database_id TEXT PRIMARY KEY,
    max_unpublished_outbox INTEGER NOT NULL,
    max_payload_length INTEGER NOT NULL,
    max_tail_records INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS checkpoint_cuts(
    cut_id TEXT PRIMARY KEY,
    database_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    incarnation INTEGER NOT NULL,
    cut_control_seq BLOB NOT NULL,
    head_lsn BLOB,
    head_type_sequence BLOB,
    journal_length INTEGER NOT NULL,
    journal_head_hash BLOB NOT NULL,
    -- ABANDONED is reserved (no writer yet): a cut whose restore evidence
    -- will never arrive; kept in the CHECK so adding the transition is not
    -- a schema migration
    state TEXT NOT NULL CHECK(state IN ('PENDING','ACTIVE','SUPERSEDED','ABANDONED')),
    materializations TEXT,
    logical_digest TEXT
  );
  CREATE TABLE IF NOT EXISTS capability_nonces(
    nonce TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS controller_meta(
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions(
    database_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    startup_session_id TEXT NOT NULL,
    fenced INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(database_id, generation, startup_session_id)
  );
`;

/* V16 exactness rule (F7): authoritative u64 sequence values (AppendLsn,
 * TypeSequence, ControlSeq) are exact over the FULL u64 range. In SQL they
 * are 8-byte big-endian blobs - SQLite compares blobs bytewise, so ORDER BY,
 * MAX() and range predicates order exactly as the u64s do, with no i64 cast
 * and no 2^53 cliff. In JS they are bigint end to end; on the JSON wire they
 * are decimal strings (JSON numbers stop being exact at 2^53). Legacy rows
 * that stored INTEGER sequences fail CLOSED in u64FromSql - a typed
 * representation violation, never a silent reinterpretation. */

const U64_MAX = (1n << 64n) - 1n;

/** Batch envelope (directive 12.6): a batch is one authority envelope with
 *  an id and a canonical digest, not an unnamed list of requests. */
export interface BatchEnvelope {
  batchOperationId: string;
  /** optional and only ever CHECKED against the server's computation */
  batchDigest?: string;
}

/** K and byte ceilings for one batch. Both are containment defaults, not
 *  approved SLOs (docs/owner-decisions.json). */
export const MAX_BATCH_MEMBERS = 64;
export const MAX_BATCH_BYTES = 8 * 1024 * 1024;

/** Q-10/Q-12: immutable platform-safe maxima that configured budgets must
 *  sit BELOW. A budget is a narrowing of these, never a widening: a budget
 *  row carrying 2^60 tail records is a typo or an attack, and either way it
 *  must not become the admission policy. Containment defaults, not SLOs. */
export const MAX_PAYLOAD_LENGTH_CEILING = 8 * 1024 * 1024;
export const MAX_OUTBOX_DEPTH_CEILING = 100_000;
export const MAX_TAIL_RECORDS_CEILING = 10_000_000;

/** Exact non-negative safe integer in [1, ceiling], or the field name that
 *  failed. Floats, negatives, zero, NaN, strings and overflow all refuse -
 *  a coerced budget is an unreviewed policy. */
function validateBudgetField(name: string, value: unknown, ceiling: number): string | null {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1 || value > ceiling) {
    return name;
  }
  return null;
}

/** The WalDescriptor column list (descriptorOf's contract): one string, so
 *  the four read surfaces cannot drift a column apart. */
const WAL_DESCRIPTOR_COLUMNS =
  `append_lsn, type_sequence, sequencing_kind, record_type, payload_key, payload_digest,
              payload_length, unsequenced_logical_key`;

/** Lease sanity window (12.4): exact integer, 1 s .. 24 h. Shared by
 *  activation and renewal so the bounds cannot drift apart. */
function invalidLease(leaseMs: number): { ok: false; error: "INVALID_LEASE"; observed: number } | null {
  if (typeof leaseMs !== "number" || !Number.isSafeInteger(leaseMs)
      || leaseMs < 1_000 || leaseMs > 24 * 60 * 60 * 1000) {
    return { ok: false, error: "INVALID_LEASE", observed: leaseMs };
  }
  return null;
}

/** The control outbox is per DATABASE, not per generation: control events
 *  outlive the generation that produced them. Its usage counter therefore
 *  needs a generation slot that no real generation can occupy. */
const OUTBOX_GENERATION = -1;

/** Encode an exact u64 as its 8-byte big-endian SQL blob. */
export function u64Blob(value: bigint, context: string): Uint8Array {
  if (value < 0n || value > U64_MAX) {
    throw new Error(`INTEGER_RANGE_VIOLATION: ${context}=${value} outside u64`);
  }
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, value);
  return bytes;
}

/** Decode an authoritative sequence read back from SQL. Blobs only: any
 *  other representation under a sequence column is a corruption of the
 *  storage contract and fails closed. */
export function u64FromSql(value: unknown, context: string): bigint {
  const bytes =
    value instanceof Uint8Array ? value : value instanceof ArrayBuffer ? new Uint8Array(value) : null;
  if (bytes === null || bytes.byteLength !== 8) {
    throw new Error(
      `INTEGER_REPRESENTATION_VIOLATION: ${context} is not an 8-byte big-endian blob; ` +
        `pre-blob rows must be migrated, never reinterpreted`,
    );
  }
  return new DataView(bytes.buffer, bytes.byteOffset, 8).getBigUint64(0);
}

/** Parse a u64 from the wire/API boundary: decimal string (the canonical
 *  JSON encoding), exact-integer number (legacy-client convenience inside
 *  the exact range), or bigint. Everything else - floats, negatives,
 *  overflow, NaN - is a typed violation, never a coercion. */
export function u64FromWire(value: unknown, context: string): bigint {
  let parsed: bigint;
  if (typeof value === "bigint") parsed = value;
  else if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) parsed = BigInt(value);
  else if (typeof value === "string" && /^\d+$/.test(value)) parsed = BigInt(value);
  else throw new Error(`INTEGER_RANGE_VIOLATION: ${context}=${String(value)} is not an exact u64`);
  if (parsed > U64_MAX) {
    throw new Error(`INTEGER_RANGE_VIOLATION: ${context}=${parsed} outside u64`);
  }
  return parsed;
}

export type Typed<TOk> = { ok: true } & TOk;
export type TypedErr =
  | { ok: false; error: "ADMISSION_REJECTED_OUTBOX_DEPTH"; limit: number }
  | { ok: false; error: "ADMISSION_REJECTED_PAYLOAD_LENGTH"; limit: number }
  | { ok: false; error: "ADMISSION_REJECTED_TAIL_BUDGET"; limit: number }
  | { ok: false; error: "OPERATION_DIGEST_CONFLICT" }
  | { ok: false; error: "STATUS_CONFLICT" }
  | { ok: false; error: "SESSION_FENCED" }
  | { ok: false; error: "SESSION_UNKNOWN" }
  | { ok: false; error: "NOT_FOUND" }
  // batch envelope (directive 12.6)
  | { ok: false; error: "EMPTY_BATCH" }
  | { ok: false; error: "BATCH_ENVELOPE_REQUIRED" }
  | { ok: false; error: "BATCH_MIXED_SCOPE" }
  | { ok: false; error: "BATCH_TOO_MANY_MEMBERS"; limit: number }
  | { ok: false; error: "BATCH_TOO_MANY_BYTES"; limit: number }
  | { ok: false; error: "BATCH_DIGEST_MISMATCH" }
  | { ok: false; error: "BATCH_DIGEST_CONFLICT" }
  // Q-12: a database with no validated budget row denies writes
  | { ok: false; error: "ADMISSION_REJECTED_NO_BUDGET" }
  // Q-10: authority-sized wire values are exact or refused, never coerced
  | { ok: false; error: "INVALID_BUDGET"; field: string }
  | { ok: false; error: "INVALID_PAYLOAD_LENGTH"; observed: unknown }
  // Q-03 / 12.4 lifecycle
  | { ok: false; error: "SESSION_ID_ALREADY_USED" }
  | { ok: false; error: "SESSION_NOT_RESERVED" }
  | { ok: false; error: "SESSION_NOT_ATTESTED" }
  | { ok: false; error: "PROCESS_NONCE_MISMATCH" }
  | { ok: false; error: "STALE_INCARNATION"; current: number }
  | { ok: false; error: "GENERATION_MISMATCH"; reserved: number }
  | { ok: false; error: "SESSION_NOT_ACTIVE"; state: string }
  | { ok: false; error: "SESSION_LEASE_EXPIRED" }
  | { ok: false; error: "INVALID_LEASE"; observed: unknown };

export interface FinalizeRequest {
  databaseId: string;
  generation: number;
  startupSessionId: string;
  operationId: string;
  requestDigest: string;
  sequencingKind: "SEQUENCED" | "UNSEQUENCED";
  /** TypeDB durability record type (u8); catalogued so type-filtered replay
   *  (`iter_type_from`, `find_last_type`) is a server-side index scan rather
   *  than a payload fetch per record. */
  recordType: number;
  logicalKey: string | null;
  payloadKey: string;
  payloadDigest: string;
  payloadLength: number;
}

/** One catalogued WAL tail row, as returned by the scan/last read paths.
 *  Sequence values are exact u64 bigints (F7 blob representation). */
export interface WalDescriptor {
  appendLsn: bigint;
  typeSequence: bigint;
  sequencingKind: string;
  recordType: number;
  payloadKey: string;
  payloadDigest: string;
  payloadLength: number;
  logicalKey: string | null;
}

export type FinalizeResult = Typed<{ appendLsn: bigint; typeSequence: bigint; controlSeq: bigint; replayed: boolean }> | TypedErr;

/** 32 zero bytes: the hash-chain genesis ancestor. */
const GENESIS_HASH = new Uint8Array(32);

export class ControllerCore {
  private readonly sql: SyncSql;
  /** Commit-time journal MAC key (F8). The dev default is deliberately loud;
   *  production provisioning of a managed secret is a G2 gate item. */
  private readonly journalKey: Uint8Array;

  private readonly wallClock: () => number;

  constructor(sql: SyncSql, options?: { journalKey?: Uint8Array; now?: () => number }) {
    this.sql = sql;
    this.journalKey = options?.journalKey ?? utf8("dev-insecure-journal-key");
    this.wallClock = options?.now ?? Date.now;
    this.migrate();
  }

  /**
   * Controller time (§12.4): a persisted, nondecreasing floor over the wall
   * clock. Every lease computation reads THIS, never Date.now() directly,
   * so a backward clock jump cannot extend a lease - the floor simply stops
   * advancing until the wall clock catches up. Forward jumps make leases
   * expire early, which fails closed (a new session is required; expiry is
   * terminal, there is no resurrection).
   */
  controllerNow(): number {
    const wall = this.wallClock();
    const rows = this.sql.exec(`SELECT value FROM controller_meta WHERE key='time_floor_ms'`);
    const floor = rows.length ? Number(rows[0].value) : 0;
    if (wall > floor) {
      this.sql.exec(
        `INSERT INTO controller_meta(key, value) VALUES ('time_floor_ms', ?)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value`, wall);
      return wall;
    }
    return floor;
  }

  /**
   * Ordered, transactional, idempotent schema migration (Q-09).
   *
   * The previous sequence could not migrate an existing database at all:
   * the declarative schema script created `wal_type_scan` over
   * `wal_tail(record_type)` and ran BEFORE the `ALTER TABLE ... ADD COLUMN
   * record_type` that introduces the column. On a fresh database that works
   * (CREATE TABLE already declares the column); on a database created before
   * the column existed, the CREATE INDEX raises "no such column" inside the
   * schema script, the whole script aborts, and construction fails - so the
   * ALTER meant to fix it was unreachable. The ordering, not the SQL, was
   * the defect.
   *
   * The fix is to make order explicit and recorded: declarative tables
   * first, additive columns second (driven by PRAGMA table_info, so it is
   * correct on both fresh and old databases), dependent indexes last, each
   * step transactional and stamped in `schema_migrations`.
   *
   * NOTE (F7 blob representation): rows written before the u64-blob change
   * stored INTEGER sequences; they are NOT migrated - u64FromSql fails
   * closed on them with a typed representation violation rather than
   * reinterpreting them.
   */
  private migrate(): void {
    this.sql.exec(`CREATE TABLE IF NOT EXISTS schema_migrations(
      version INTEGER PRIMARY KEY,
      applied_at_ms INTEGER NOT NULL
    )`);
    const applied = new Set(
      this.sql.exec(`SELECT version FROM schema_migrations`).map((r) => Number(r.version)),
    );
    for (const step of ControllerCore.MIGRATIONS) {
      if (applied.has(step.version)) continue;
      this.sql.transaction(() => {
        step.up(this.sql);
        this.sql.exec(`INSERT INTO schema_migrations(version, applied_at_ms) VALUES (?,?)`,
          step.version, Date.now());
      });
    }
  }

  /** Columns added after the original table shape. Applied by name against
   *  PRAGMA table_info, so the step is a no-op on a fresh database (where
   *  CREATE TABLE already declares them) and additive on an old one. */
  private static readonly ADDITIVE_COLUMNS: ReadonlyArray<{ table: string; column: string; ddl: string }> = [
    { table: "wal_tail", column: "record_type", ddl: "INTEGER NOT NULL DEFAULT 0" },
  ];

  private static readonly MIGRATIONS: ReadonlyArray<{ version: number; up: (sql: SyncSql) => void }> = [
    { version: 1, up: (sql) => { sql.exec(SCHEMA); } },
    {
      version: 2,
      up: (sql) => {
        for (const { table, column, ddl } of ControllerCore.ADDITIVE_COLUMNS) {
          const present = sql.exec(`PRAGMA table_info(${table})`).some((r) => String(r.name) === column);
          if (!present) sql.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${ddl}`);
        }
      },
    },
    {
      version: 3,
      up: (sql) => {
        // dependent on the v2 column: never earlier than the column itself
        sql.exec(`CREATE INDEX IF NOT EXISTS wal_type_scan
                  ON wal_tail(database_id, generation, record_type, append_lsn)`);
      },
    },
    {
      version: 4,
      up: (sql) => {
        // Q-11: durable idempotency aliases. A status-singleton dedupe
        // answers a FRESH operation id with the original record's receipt;
        // without an alias that operation id exists nowhere, so a client
        // that lost the response a second time can never re-resolve the
        // receipt it was given. The alias makes the answer durable and
        // queryable under the id the client actually used.
        sql.exec(`CREATE TABLE IF NOT EXISTS operation_aliases(
          database_id TEXT NOT NULL,
          generation INTEGER NOT NULL,
          operation_id TEXT NOT NULL,
          append_lsn BLOB NOT NULL,
          request_digest TEXT NOT NULL,
          PRIMARY KEY(database_id, generation, operation_id)
        )`);
      },
    },
    {
      version: 5,
      up: (sql) => {
        // Q-17: append cost must be bounded by the REQUEST, not by history.
        // Admission used to answer "how deep is the outbox?" and "how long is
        // the tail?" with COUNT(*) over the whole table on every single
        // finalisation, so append latency grew with the database's history -
        // and the outbox count had no index to lean on at all. These are
        // transactionally maintained singletons instead, backfilled here so
        // an existing database is correct from the first open.
        sql.exec(`CREATE TABLE IF NOT EXISTS usage_counters(
          database_id TEXT NOT NULL,
          generation INTEGER NOT NULL,
          scope TEXT NOT NULL,
          value INTEGER NOT NULL,
          PRIMARY KEY(database_id, generation, scope)
        )`);
        // ordered unpublished drain: partial index so peek/ack walk an index
        // rather than filtering the whole journal
        sql.exec(`CREATE INDEX IF NOT EXISTS outbox_unpublished
                  ON control_outbox(control_seq) WHERE published=0`);
        for (const row of sql.exec(
          `SELECT database_id, generation, COUNT(*) AS n FROM wal_tail
           GROUP BY database_id, generation`)) {
          sql.exec(`INSERT OR REPLACE INTO usage_counters(database_id, generation, scope, value)
                    VALUES (?,?,'tail',?)`, row.database_id, row.generation, row.n);
        }
        for (const row of sql.exec(
          `SELECT database_id, COUNT(*) AS n FROM control_outbox WHERE published=0
           GROUP BY database_id`)) {
          sql.exec(`INSERT OR REPLACE INTO usage_counters(database_id, generation, scope, value)
                    VALUES (?,${OUTBOX_GENERATION},'outbox_unpublished',?)`, row.database_id, row.n);
        }
      },
    },
    {
      version: 6,
      up: (sql) => {
        // Directive 12.6: /wal/finalize-batch was deployable while the v16
        // batch schema was absent - no BatchOperationId, no canonical batch
        // digest, no K/byte limits, and no way to answer a replayed batch
        // with its original results. This is that identity.
        sql.exec(`CREATE TABLE IF NOT EXISTS batch_operations(
          database_id TEXT NOT NULL,
          generation INTEGER NOT NULL,
          batch_operation_id TEXT NOT NULL,
          batch_digest TEXT NOT NULL,
          member_count INTEGER NOT NULL,
          member_operation_ids TEXT NOT NULL,
          control_seq BLOB,
          PRIMARY KEY(database_id, generation, batch_operation_id)
        )`);
      },
    },
    {
      version: 7,
      up: (sql) => {
        // Q-03 / directive 12.4: the startup-session lifecycle. Activation
        // is the ONLY operation that fences; a session id that never went
        // through reserve -> attest -> activate is not an authority, however
        // fresh or random it is.
        sql.exec(`CREATE TABLE IF NOT EXISTS startup_sessions(
          database_id TEXT NOT NULL,
          startup_session_id TEXT NOT NULL,
          generation INTEGER NOT NULL,
          incarnation INTEGER NOT NULL,
          holder TEXT NOT NULL,
          process_nonce TEXT,
          state TEXT NOT NULL CHECK(state IN
            ('RESERVED','ATTESTED','ACTIVE','DRAINING','REVOKED','EXPIRED','ABANDONED')),
          lease_deadline_ms INTEGER,
          reserved_at_ms INTEGER NOT NULL,
          activated_at_ms INTEGER,
          PRIMARY KEY(database_id, startup_session_id)
        )`);
        sql.exec(`CREATE INDEX IF NOT EXISTS startup_sessions_live
                  ON startup_sessions(database_id, state)`);
      },
    },
    {
      version: 8,
      up: (sql) => {
        // Q-17: the lazy expiry sweep in burnCapabilityNonce deletes by
        // expires_at, which had no index - a full table scan of every live
        // nonce on EVERY capability burn. Range walk instead.
        sql.exec(`CREATE INDEX IF NOT EXISTS capability_nonce_expiry
                  ON capability_nonces(expires_at)`);
      },
    },
  ];

  // ------------------------------------------------------------------
  // Q-03 / directive 12.4: the startup-session lifecycle.
  //
  // The pre-fix behaviour was takeover-at-open: any fresh session id could
  // fence every live actor by calling register. The lifecycle splits
  // identity from authority. Reservation and attestation grant NOTHING;
  // activation is one transaction that revalidates reservation, attestation
  // nonce, controller incarnation and generation before it fences anyone;
  // authority then lives under a controller-time lease that every
  // finalisation revalidates, and expiry is terminal - a dead session is
  // replaced, never resurrected.
  //
  // Pre-G2 honesty: on the L1 facade the caller of these procedures is
  // gated by SESSION_ADMIN capabilities, not by real container attestation
  // - the external attestation root and provider-enforced routing are
  // real-platform work and stay OPEN. What this closes is the PROTOCOL
  // hole: there is no longer any code path in which an unactivated id
  // fences an authority or appends under one.
  // ------------------------------------------------------------------

  /** The one startup_sessions point read every lifecycle procedure starts
   *  from; null = no reservation ever existed under this id. */
  private startupSession(databaseId: string, startupSessionId: string): Record<string, unknown> | null {
    const rows = this.sql.exec(
      `SELECT * FROM startup_sessions WHERE database_id=? AND startup_session_id=?`,
      databaseId, startupSessionId);
    return rows.length ? rows[0] : null;
  }

  /** Reserve a session id. Grants nothing; single-use per id (a reused id
   *  is a permanent refusal - ids are identities, not slots). Idempotent
   *  for an exact repeat of the same reservation while still RESERVED. */
  reserveSession(databaseId: string, generation: number, startupSessionId: string, holder: string):
    Typed<{ state: "RESERVED" }> | TypedErr {
    if (typeof startupSessionId !== "string" || startupSessionId.length === 0
        || typeof holder !== "string" || holder.length === 0) {
      return { ok: false as const, error: "SESSION_NOT_RESERVED" as const };
    }
    return this.sql.transaction(() => {
      const row = this.startupSession(databaseId, startupSessionId);
      if (row) {
        if (String(row.state) === "RESERVED" && Number(row.generation) === generation
            && String(row.holder) === holder) {
          return { ok: true as const, state: "RESERVED" as const }; // idempotent retry
        }
        return { ok: false as const, error: "SESSION_ID_ALREADY_USED" as const };
      }
      this.sql.exec(
        `INSERT INTO startup_sessions(database_id, startup_session_id, generation, incarnation,
           holder, state, reserved_at_ms) VALUES (?,?,?,?,?,'RESERVED',?)`,
        databaseId, startupSessionId, generation, this.currentIncarnation(), holder,
        this.controllerNow());
      return { ok: true as const, state: "RESERVED" as const };
    });
  }

  /** Bind the reservation to one process. Still grants nothing. A second
   *  process presenting a different nonce finds the reservation no longer
   *  RESERVED and is refused (SESSION_NOT_RESERVED - the id is spent for
   *  it); it never becomes a race winner. */
  attestSession(databaseId: string, startupSessionId: string, processNonce: string):
    Typed<{ state: "ATTESTED" }> | TypedErr {
    if (typeof processNonce !== "string" || processNonce.length === 0) {
      return { ok: false as const, error: "PROCESS_NONCE_MISMATCH" as const };
    }
    return this.sql.transaction(() => {
      const row = this.startupSession(databaseId, startupSessionId);
      if (!row) return { ok: false as const, error: "SESSION_NOT_RESERVED" as const };
      const state = String(row.state);
      if (state === "ATTESTED" && String(row.process_nonce) === processNonce) {
        return { ok: true as const, state: "ATTESTED" as const }; // idempotent retry
      }
      if (state !== "RESERVED") return { ok: false as const, error: "SESSION_NOT_RESERVED" as const };
      this.sql.exec(
        `UPDATE startup_sessions SET state='ATTESTED', process_nonce=?
         WHERE database_id=? AND startup_session_id=?`,
        processNonce, databaseId, startupSessionId);
      return { ok: true as const, state: "ATTESTED" as const };
    });
  }

  /**
   * The ONE transaction that authorizes takeover (12.4). Verifies, inside
   * the transaction: the reservation exists and is ATTESTED; the presented
   * process nonce is the attested one; the controller incarnation has not
   * moved since reservation; the generation is the reserved one; the lease
   * is a sane duration. Only then does it fence the predecessors and
   * establish the active session under a controller-time lease.
   */
  activateSession(
    databaseId: string, startupSessionId: string,
    proof: { processNonce: string; generation: number; leaseMs: number },
  ): Typed<{ leaseDeadlineMs: number; fencedPredecessors: number }> | TypedErr {
    const badLease = invalidLease(proof.leaseMs);
    if (badLease) return badLease;
    return this.sql.transaction(() => {
      const row = this.startupSession(databaseId, startupSessionId);
      if (!row) return { ok: false as const, error: "SESSION_NOT_RESERVED" as const };
      const state = String(row.state);
      const now = this.controllerNow();
      if (state === "ACTIVE" && String(row.process_nonce) === proof.processNonce) {
        // lost-response retry of a completed activation: same outcome again
        return { ok: true as const, leaseDeadlineMs: Number(row.lease_deadline_ms),
                 fencedPredecessors: 0 };
      }
      if (state !== "ATTESTED") return { ok: false as const, error: "SESSION_NOT_ATTESTED" as const };
      if (String(row.process_nonce) !== proof.processNonce) {
        return { ok: false as const, error: "PROCESS_NONCE_MISMATCH" as const };
      }
      const currentIncarnation = this.currentIncarnation();
      if (Number(row.incarnation) !== currentIncarnation) {
        // the controller moved on since this reservation: the reservation is
        // evidence about a superseded authority, not this one
        return { ok: false as const, error: "STALE_INCARNATION" as const, current: currentIncarnation };
      }
      if (Number(row.generation) !== proof.generation) {
        return { ok: false as const, error: "GENERATION_MISMATCH" as const, reserved: Number(row.generation) };
      }
      const leaseDeadlineMs = now + proof.leaseMs;
      // fence-and-establish: exactly the legacy takeover semantics, but
      // reachable ONLY through the verified protocol above
      const fencedCount = Number(this.sql.exec(
        `SELECT COUNT(*) AS n FROM sessions WHERE database_id=? AND startup_session_id<>? AND fenced=0`,
        databaseId, startupSessionId)[0].n);
      this.sql.exec(
        `UPDATE sessions SET fenced=1 WHERE database_id=? AND startup_session_id<>?`,
        databaseId, startupSessionId);
      this.sql.exec(
        `UPDATE startup_sessions SET state='ACTIVE', lease_deadline_ms=?, activated_at_ms=?
         WHERE database_id=? AND startup_session_id=?`,
        leaseDeadlineMs, now, databaseId, startupSessionId);
      this.sql.exec(
        `INSERT OR IGNORE INTO sessions(database_id, generation, startup_session_id) VALUES (?,?,?)`,
        databaseId, proof.generation, startupSessionId);
      this.sql.exec(
        `UPDATE startup_sessions SET state='REVOKED'
         WHERE database_id=? AND startup_session_id<>? AND state IN ('ACTIVE','DRAINING')`,
        databaseId, startupSessionId);
      this.appendCommand(databaseId, "SESSION_ACTIVATED", {
        databaseId, generation: proof.generation, startupSessionId,
        fencedPredecessors: fencedCount, leaseDeadlineMs,
      });
      return { ok: true as const, leaseDeadlineMs, fencedPredecessors: fencedCount };
    });
  }

  /** Extend an unexpired lease from controller time. An expired lease is
   *  TERMINAL: renewal refuses and the state moves to EXPIRED - a backward
   *  clock jump cannot resurrect it because controllerNow never decreases. */
  renewLease(databaseId: string, startupSessionId: string, leaseMs: number):
    Typed<{ leaseDeadlineMs: number }> | TypedErr {
    const badLease = invalidLease(leaseMs);
    if (badLease) return badLease;
    return this.sql.transaction(() => {
      const row = this.startupSession(databaseId, startupSessionId);
      if (!row) return { ok: false as const, error: "SESSION_NOT_RESERVED" as const };
      const state = String(row.state);
      if (state !== "ACTIVE" && state !== "DRAINING") {
        return { ok: false as const, error: "SESSION_NOT_ACTIVE" as const, state };
      }
      const now = this.controllerNow();
      if (Number(row.lease_deadline_ms) <= now) {
        this.expireSession(databaseId, startupSessionId);
        return { ok: false as const, error: "SESSION_LEASE_EXPIRED" as const };
      }
      const leaseDeadlineMs = now + leaseMs;
      // deliberately NOT journaled: renewals are high-volume heartbeats that
      // change no authority relationship (same holder, same scope); the
      // journaled transitions are the ones that create, move or end
      // authority (activate/drain/revoke/expire/fence)
      this.sql.exec(
        `UPDATE startup_sessions SET lease_deadline_ms=? WHERE database_id=? AND startup_session_id=?`,
        leaseDeadlineMs, databaseId, startupSessionId);
      return { ok: true as const, leaseDeadlineMs };
    });
  }

  /** ACTIVE -> DRAINING: authority retained for in-flight work under the
   *  existing lease; a successor's activation (or revoke/expiry) ends it. */
  beginDrain(databaseId: string, startupSessionId: string):
    Typed<{ state: "DRAINING" }> | TypedErr {
    return this.sql.transaction(() => {
      const row = this.startupSession(databaseId, startupSessionId);
      if (!row) return { ok: false as const, error: "SESSION_NOT_RESERVED" as const };
      const state = String(row.state);
      if (state === "DRAINING") return { ok: true as const, state: "DRAINING" as const };
      if (state !== "ACTIVE") return { ok: false as const, error: "SESSION_NOT_ACTIVE" as const, state };
      this.sql.exec(
        `UPDATE startup_sessions SET state='DRAINING' WHERE database_id=? AND startup_session_id=?`,
        databaseId, startupSessionId);
      this.appendCommand(databaseId, "SESSION_DRAINING", { databaseId, startupSessionId });
      return { ok: true as const, state: "DRAINING" as const };
    });
  }

  /** Revoke a session's authority outright (terminal). */
  revokeSession(databaseId: string, startupSessionId: string): Typed<{ state: "REVOKED" }> | TypedErr {
    return this.sql.transaction(() => {
      const row = this.startupSession(databaseId, startupSessionId);
      if (!row) return { ok: false as const, error: "SESSION_NOT_RESERVED" as const };
      if (String(row.state) === "REVOKED") return { ok: true as const, state: "REVOKED" as const };
      this.sql.exec(
        `UPDATE startup_sessions SET state='REVOKED' WHERE database_id=? AND startup_session_id=?`,
        databaseId, startupSessionId);
      this.sql.exec(
        `UPDATE sessions SET fenced=1 WHERE database_id=? AND startup_session_id=?`,
        databaseId, startupSessionId);
      this.appendCommand(databaseId, "SESSION_REVOKED", { databaseId, startupSessionId });
      return { ok: true as const, state: "REVOKED" as const };
    });
  }

  /** Terminal expiry, journaled. Caller holds the transaction. */
  private expireSession(databaseId: string, startupSessionId: string): void {
    this.sql.exec(
      `UPDATE startup_sessions SET state='EXPIRED' WHERE database_id=? AND startup_session_id=?`,
      databaseId, startupSessionId);
    this.appendCommand(databaseId, "SESSION_LEASE_EXPIRED", { databaseId, startupSessionId });
  }

  /**
   * Lifecycle gate for authority-bearing mutations (12.4): a
   * lifecycle-managed session must be ACTIVE or DRAINING with an unexpired
   * controller-time lease BEFORE counters/outbox are consumed. A session
   * with no lifecycle row is the legacy L1 lane (registerSession routes
   * through the lifecycle, so post-migration cores always have rows; the
   * no-row case covers databases migrated with live legacy sessions).
   */
  private requireLeasedAuthority(databaseId: string, startupSessionId: string):
    { ok: true } | { ok: false; error: "SESSION_NOT_ACTIVE"; state: string }
    | { ok: false; error: "SESSION_LEASE_EXPIRED" } {
    const row = this.startupSession(databaseId, startupSessionId);
    if (!row) return { ok: true };
    const state = String(row.state);
    if (state !== "ACTIVE" && state !== "DRAINING") {
      return { ok: false as const, error: "SESSION_NOT_ACTIVE" as const, state };
    }
    if (Number(row.lease_deadline_ms) <= this.controllerNow()) {
      this.expireSession(databaseId, startupSessionId);
      return { ok: false as const, error: "SESSION_LEASE_EXPIRED" as const };
    }
    return { ok: true };
  }

  /**
   * Legacy register: the L1 lane's one-call takeover, REWIRED THROUGH the
   * lifecycle (Q-03 / 12.4) rather than fencing directly.
   *
   * The three reference lanes (this core, remote-wal-spike, protocol-models)
   * pin register-fences-predecessor (ADR-0006), and the directive requires
   * that only the lifecycle protocol authorizes takeover. Both hold at once
   * by making register a macro: reserve -> attest -> activate in one
   * transaction, with a synthetic holder ("legacy-register") and process
   * nonce and a default lease. The observable trace is unchanged; the
   * MECHANISM is now exactly one - `activateSession` is the only code that
   * fences, and every register leaves a lifecycle row with a real lease
   * that finalisation revalidates.
   *
   * A generation ROLLOVER by the incumbent actor re-reserves under the same
   * id (ids are single-use for NEW actors, but the same live actor moving
   * generations is the documented rollover case) - handled by treating an
   * ACTIVE self re-register as a lease renewal + generation update.
   */
  registerSession(databaseId: string, generation: number, startupSessionId: string): void {
    const LEGACY_LEASE_MS = 15 * 60 * 1000;
    this.sql.transaction(() => {
      // a superseded (fenced) actor can never re-take authority - the
      // models' session counter only moves forward
      const fencedRows = this.sql.exec(
        `SELECT 1 FROM sessions WHERE database_id=? AND startup_session_id=? AND fenced=1 LIMIT 1`,
        databaseId, startupSessionId,
      );
      if (fencedRows.length) return;

      const lifecycle = this.startupSession(databaseId, startupSessionId);
      const nonce = `legacy-nonce-${startupSessionId}`;
      if (lifecycle && ["ACTIVE", "DRAINING"].includes(String(lifecycle.state))) {
        // idempotent re-register / rollover by the live actor: refresh the
        // lease, record the (possibly new) generation, fence nobody
        this.sql.exec(
          `UPDATE startup_sessions SET lease_deadline_ms=?, generation=?
           WHERE database_id=? AND startup_session_id=?`,
          this.controllerNow() + LEGACY_LEASE_MS, generation, databaseId, startupSessionId);
        const known = this.sql.exec(
          `SELECT 1 FROM sessions WHERE database_id=? AND generation=? AND startup_session_id=?`,
          databaseId, generation, startupSessionId).length > 0;
        this.sql.exec(
          `INSERT OR IGNORE INTO sessions(database_id, generation, startup_session_id) VALUES (?,?,?)`,
          databaseId, generation, startupSessionId);
        if (!known) {
          this.appendCommand(databaseId, "SESSION_REGISTERED", {
            databaseId, generation, startupSessionId, fencedPredecessors: 0,
          });
        }
        return;
      }
      const reserved = this.reserveSession(databaseId, generation, startupSessionId, "legacy-register");
      if (!reserved.ok) throw new Error(`legacy register: reserve failed: ${reserved.error}`);
      const attested = this.attestSession(databaseId, startupSessionId, nonce);
      if (!attested.ok) throw new Error(`legacy register: attest failed: ${attested.error}`);
      const activated = this.activateSession(databaseId, startupSessionId, {
        processNonce: nonce, generation, leaseMs: LEGACY_LEASE_MS,
      });
      if (!activated.ok) throw new Error(`legacy register: activate failed: ${activated.error}`);
    });
  }

  fenceSession(databaseId: string, startupSessionId: string): void {
    // The authority unit is the ACTOR (see registerSession): fencing revokes
    // the actor's append authority across every generation it registered —
    // a per-generation fence would leave a rollover-spanning actor half
    // fenced (blocked from re-registering, still able to append elsewhere).
    this.sql.transaction(() => {
      const live = Number(this.sql.exec(
        `SELECT COUNT(*) AS n FROM sessions WHERE database_id=? AND startup_session_id=? AND fenced=0`,
        databaseId, startupSessionId,
      )[0].n);
      this.sql.exec(
        `UPDATE sessions SET fenced=1 WHERE database_id=? AND startup_session_id=?`,
        databaseId, startupSessionId,
      );
      // the lifecycle row moves with the fence: a fenced actor's session is
      // REVOKED, not left nominally ACTIVE under a lease nobody honours
      this.sql.exec(
        `UPDATE startup_sessions SET state='REVOKED'
         WHERE database_id=? AND startup_session_id=? AND state IN ('ACTIVE','DRAINING')`,
        databaseId, startupSessionId,
      );
      if (live > 0) {
        this.appendCommand(databaseId, "SESSION_FENCED", { databaseId, startupSessionId });
      }
    });
  }

  /**
   * Donor A4: per-procedure actor revalidation AT THE CORE, beneath the
   * capability layer.
   *
   * The capability layer proves a token was issued to an actor; it cannot
   * prove the actor is still the authority when the token is USED. A
   * capability has a TTL, so there is a window in which a session is fenced
   * and its already-minted, still-unexpired token keeps working - the
   * fenced actor could still move budgets, ack the outbox out from under
   * the live actor, or read the operation surface. The window closes only
   * where the authority state actually lives, which is here.
   *
   * No holder attribution is returned (v16 inv. 38 / ADR-0006): a fenced
   * actor learns that it is fenced, never who superseded it.
   */
  private requireLiveSession(databaseId: string, startupSessionId: string):
    { ok: true } | { ok: false; error: "SESSION_UNKNOWN" | "SESSION_FENCED" } {
    if (typeof startupSessionId !== "string" || startupSessionId.length === 0) {
      return { ok: false, error: "SESSION_UNKNOWN" };
    }
    const rows = this.sql.exec(
      `SELECT fenced FROM sessions WHERE database_id=? AND startup_session_id=?`,
      databaseId, startupSessionId,
    );
    if (!rows.length) return { ok: false, error: "SESSION_UNKNOWN" };
    // an actor spans generations; it is live only if NO row for it is fenced
    if (rows.some((r) => Number(r.fenced) === 1)) return { ok: false, error: "SESSION_FENCED" };
    return { ok: true };
  }

  setBudgets(
    databaseId: string,
    b: { maxUnpublishedOutbox: number; maxPayloadLength: number; maxTailRecords: number },
    startupSessionId: string,
  ): { ok: true } | { ok: false; error: "SESSION_UNKNOWN" | "SESSION_FENCED" }
    | { ok: false; error: "INVALID_BUDGET"; field: string }
    | { ok: false; error: "SESSION_NOT_ACTIVE"; state: string }
    | { ok: false; error: "SESSION_LEASE_EXPIRED" } {
    // the whole procedure is one transaction: requireLeasedAuthority can
    // expire a session (an UPDATE plus a journaled command), and that
    // multi-statement mutation must never run auto-committed
    return this.sql.transaction(() => {
      const authority = this.requireLiveSession(databaseId, startupSessionId);
      if (!authority.ok) return authority;
      const leased = this.requireLeasedAuthority(databaseId, startupSessionId);
      if (!leased.ok) return leased;
      // Q-10: budgets are authority-sized values; exact or refused. Validated
      // BELOW the immutable platform ceilings - a budget widens nothing.
      const bad =
        validateBudgetField("maxUnpublishedOutbox", b.maxUnpublishedOutbox, MAX_OUTBOX_DEPTH_CEILING)
        ?? validateBudgetField("maxPayloadLength", b.maxPayloadLength, MAX_PAYLOAD_LENGTH_CEILING)
        ?? validateBudgetField("maxTailRecords", b.maxTailRecords, MAX_TAIL_RECORDS_CEILING);
      if (bad !== null) return { ok: false as const, error: "INVALID_BUDGET" as const, field: bad };
      this.sql.exec(
        `INSERT OR REPLACE INTO budgets(database_id, max_unpublished_outbox, max_payload_length, max_tail_records)
         VALUES (?,?,?,?)`,
        databaseId, b.maxUnpublishedOutbox, b.maxPayloadLength, b.maxTailRecords,
      );
      this.appendCommand(databaseId, "BUDGETS_SET", { databaseId, ...b, startupSessionId });
      return { ok: true as const };
    });
  }

  /**
   * WAL finalisation with late atomic allocation (CT-P3). The payload is
   * assumed uploaded and receipt-verified BEFORE this call; everything below
   * is one synchronous transaction.
   */
  finalizeWalRecord(req: FinalizeRequest): FinalizeResult {
    return this.sql.transaction(() => this.finalizeStep(req));
  }

  /**
   * Directive 12.6: a batch is ONE authority envelope with an identity.
   *
   * `/wal/finalize-batch` was deployable while the v16 batch schema was
   * absent: no `BatchOperationId`, no canonical batch digest, no K/byte
   * limits, and - the part that actually bites - no way to answer a replayed
   * batch. A client whose response was lost had to either re-send (and get
   * per-member replays, which works only because members carry their own
   * ids) or guess. The envelope makes the batch itself replayable and makes
   * "the same id with different members" a permanent conflict rather than a
   * second, different batch under a name that was already used.
   *
   * The digest is computed here from the members' own canonical digests, in
   * order; a caller-supplied `batchDigest` is only ever checked against it
   * (Q-18's rule, applied to the envelope).
   */
  finalizeBatch(reqs: FinalizeRequest[], envelope?: BatchEnvelope): FinalizeResult[] | TypedErr {
    if (reqs.length === 0) return { ok: false as const, error: "EMPTY_BATCH" as const };
    if (reqs.length > MAX_BATCH_MEMBERS) {
      return { ok: false as const, error: "BATCH_TOO_MANY_MEMBERS" as const, limit: MAX_BATCH_MEMBERS };
    }
    const declaredBytes = reqs.reduce((n, r) => n + (Number(r.payloadLength) || 0), 0);
    if (declaredBytes > MAX_BATCH_BYTES) {
      return { ok: false as const, error: "BATCH_TOO_MANY_BYTES" as const, limit: MAX_BATCH_BYTES };
    }
    if (envelope === undefined) {
      // A batch with no identity cannot be replayed, conflicted or audited.
      // Refusing is the release-baseline posture the directive asks for:
      // one-record finalization always works, batching needs its envelope.
      return { ok: false as const, error: "BATCH_ENVELOPE_REQUIRED" as const };
    }
    const { databaseId, generation } = reqs[0];
    // one batch, one authority scope: the envelope is recorded under
    // (databaseId, generation), so a member from another scope would be
    // replayable nowhere. The HTTP route already enforces same-database;
    // the core is directly callable, so it must not trust that.
    if (reqs.some((r) => r.databaseId !== databaseId || r.generation !== generation)) {
      return { ok: false as const, error: "BATCH_MIXED_SCOPE" as const };
    }
    const computedDigest = this.batchDigest(envelope.batchOperationId, reqs);
    if (envelope.batchDigest !== undefined && envelope.batchDigest !== computedDigest) {
      return { ok: false as const, error: "BATCH_DIGEST_MISMATCH" as const };
    }
    const prior = this.sql.exec(
      `SELECT batch_digest, member_operation_ids FROM batch_operations
       WHERE database_id=? AND generation=? AND batch_operation_id=?`,
      databaseId, generation, envelope.batchOperationId,
    );
    if (prior.length && String(prior[0].batch_digest) !== computedDigest) {
      // one batch id, one set of members, forever
      return { ok: false as const, error: "BATCH_DIGEST_CONFLICT" as const };
    }
    try {
      return this.sql.transaction(() => {
        const results: FinalizeResult[] = [];
        for (const req of reqs) {
          const r = this.finalizeStep(req);
          if (!r.ok) throw new BatchAbort(r); // rollback of every prior record
          results.push(r);
        }
        this.sql.exec(
          `INSERT OR IGNORE INTO batch_operations(database_id, generation, batch_operation_id,
             batch_digest, member_count, member_operation_ids, control_seq)
           VALUES (?,?,?,?,?,?,?)`,
          databaseId, generation, envelope.batchOperationId, computedDigest, reqs.length,
          JSON.stringify(reqs.map((r) => r.operationId)),
          // reqs is non-empty (EMPTY_BATCH refused) and every failed member
          // threw BatchAbort above, so the first result is a success
          u64Blob((results[0] as { controlSeq: bigint }).controlSeq, "control_seq"),
        );
        return results;
      });
    } catch (e) {
      if (e instanceof BatchAbort) return e.result;
      throw e;
    }
  }

  /** Canonical batch digest: the ordered members' own canonical request
   *  digests under the batch id, in a domain-separated envelope. Reordering
   *  the members is a DIFFERENT batch - order is part of the contract. */
  private batchDigest(batchOperationId: string, reqs: FinalizeRequest[]): string {
    return hex(sha256(utf8(canonicalJson({
      domain: "wal-finalize-batch/v1",
      batchOperationId,
      members: reqs.map((r) => r.requestDigest),
    }))));
  }

  /** One finalisation step; assumes the caller holds the open transaction. */
  private finalizeStep(req: FinalizeRequest): FinalizeResult {
    // session revalidation (stale-actor fencing) MUST precede the replay
    // lookup: brief inv. 38 — fencing cannot revoke a durable record, but it
    // DOES prevent the old holder from having it reported back. A fenced
    // session retrying a lost-response finalize therefore gets SESSION_FENCED,
    // never the replayed receipt (matches remote-wal-spike Controller::finalize
    // and protocol-models WalState::finalize, which both fence first).
    const session = this.sql.exec(
      `SELECT fenced FROM sessions WHERE database_id=? AND generation=? AND startup_session_id=?`,
      req.databaseId, req.generation, req.startupSessionId,
    );
    if (!session.length) return { ok: false as const, error: "SESSION_UNKNOWN" as const };
    if (Number(session[0].fenced)) {
      // A stale actor receives EXACTLY `SESSION_FENCED` - no result fields
      // and NO holder attribution (v16 inv. 38, ADR-0006, and the
      // convergence directive's §12.5 correction).
      //
      // The previous version returned `fencedBy`, reasoning that the id was
      // no longer a credential once finalize capabilities became
      // session-bound. Two things are wrong with that. The attribution was
      // read from "any unfenced session of this database" without the
      // generation/materialisation authority scope, so it could name a
      // session that is not the holder of the scope the caller asked about;
      // and a refusal surface that answers "who is the writer now?" to an
      // actor that has just been superseded is an identity oracle whose
      // safety depends on every OTHER control staying perfect. Attribution
      // belongs in privileged audit telemetry, which is where the
      // SESSION_REGISTERED/SESSION_FENCED command-ledger entries already
      // record it from the correctly scoped durable transition.
      return { ok: false as const, error: "SESSION_FENCED" as const };
    }

    // Q-03 / 12.4: authority is LEASED. The fence check above says the actor
    // was not superseded; this says its lease is still running on controller
    // time. Both must hold before any counter or outbox row is consumed.
    const leased = this.requireLeasedAuthority(req.databaseId, req.startupSessionId);
    if (!leased.ok) return leased;

    // exact-once replay by operation identity
    const replay = this.sql.exec(
      `SELECT append_lsn, type_sequence, control_seq, request_digest FROM wal_tail
       WHERE database_id=? AND generation=? AND finalization_operation_id=?`,
      req.databaseId, req.generation, req.operationId,
    );
    if (replay.length) {
      if (replay[0].request_digest === req.requestDigest) {
        return {
          ok: true as const,
          appendLsn: u64FromSql(replay[0].append_lsn, "append_lsn"),
          typeSequence: u64FromSql(replay[0].type_sequence, "type_sequence"),
          controlSeq: u64FromSql(replay[0].control_seq, "control_seq"),
          replayed: true,
        };
      }
      return { ok: false as const, error: "OPERATION_DIGEST_CONFLICT" as const };
    }

    // status singleton dedupe MUST precede admission: a duplicate identical
    // status (lost-response recovery under a fresh operationId) allocates
    // nothing, so budget pressure must never block it - otherwise the
    // documented recovery path wedges permanently once the tail reaches its
    // budget.
    if (req.logicalKey !== null) {
      const existing = this.sql.exec(
        `SELECT append_lsn, type_sequence, control_seq, payload_digest FROM wal_tail
         WHERE database_id=? AND generation=? AND unsequenced_logical_key=?`,
        req.databaseId, req.generation, req.logicalKey,
      );
      if (existing.length) {
        // duplicate identical status: idempotent accept of the original;
        // conflicting status: typed rejection. Never both accepted.
        if (existing[0].payload_digest === req.payloadDigest) {
          // Q-11: make the answer durable under the id the CLIENT used.
          // Returning the original record's receipt for a fresh operation id
          // without recording the mapping left that operation queryable
          // nowhere - a second lost response had nothing to resolve against.
          const aliasConflict = this.recordOperationAlias(req, existing[0].append_lsn as Uint8Array);
          if (aliasConflict) return aliasConflict;
          return {
            ok: true as const,
            appendLsn: u64FromSql(existing[0].append_lsn, "append_lsn"),
            typeSequence: u64FromSql(existing[0].type_sequence, "type_sequence"),
            controlSeq: u64FromSql(existing[0].control_seq, "control_seq"),
            replayed: true,
          };
        }
        return { ok: false as const, error: "STATUS_CONFLICT" as const };
      }
    }

    // Q-10: payloadLength is authority-sized (it is compared against the
    // budget and stored); a float, negative, NaN or non-number must refuse
    // here, never coerce or compare as garbage
    if (typeof req.payloadLength !== "number" || !Number.isSafeInteger(req.payloadLength)
        || req.payloadLength < 0) {
      return { ok: false as const, error: "INVALID_PAYLOAD_LENGTH" as const, observed: req.payloadLength };
    }

    // bounded admission, fail-closed, BEFORE any allocation. Q-12: a missing
    // budget row DENIES writes - "no budget means unlimited" inverted the
    // fail direction, and a database nobody configured admitted everything.
    // The check sits after replay/dedupe deliberately: a lost-response retry
    // allocates nothing and must still get its receipt.
    const budget = this.sql.exec(`SELECT * FROM budgets WHERE database_id=?`, req.databaseId)[0];
    if (!budget) {
      return { ok: false as const, error: "ADMISSION_REJECTED_NO_BUDGET" as const };
    }
    if (req.payloadLength > Number(budget.max_payload_length)) {
      return { ok: false as const, error: "ADMISSION_REJECTED_PAYLOAD_LENGTH" as const, limit: Number(budget.max_payload_length) };
    }
    const unpublished = this.usage(req.databaseId, OUTBOX_GENERATION, "outbox_unpublished");
    if (unpublished >= Number(budget.max_unpublished_outbox)) {
      return { ok: false as const, error: "ADMISSION_REJECTED_OUTBOX_DEPTH" as const, limit: Number(budget.max_unpublished_outbox) };
    }
    const tail = this.usage(req.databaseId, req.generation, "tail");
    if (tail >= Number(budget.max_tail_records)) {
      return { ok: false as const, error: "ADMISSION_REJECTED_TAIL_BUDGET" as const, limit: Number(budget.max_tail_records) };
    }

    // late atomic allocation: contiguous AppendLsn, monotone TypeSequence
    // (sequenced records advance it; unsequenced reuse the current one),
    // global ControlSeq - all inside the caller's transaction. head() is ONE
    // seek down the primary-key index (see its Q-17 note; the latency-ratio
    // control in query-plans.test.ts kills any regression to a prefix walk);
    // its -1n empty sentinel + 1n is exactly the first LSN, 0n.
    const head = this.head(req.databaseId, req.generation);
    const appendLsn = head.headLsn + 1n;
    const typeSequence =
      req.sequencingKind === "SEQUENCED" ? head.headTypeSequence + 1n : head.headTypeSequence;
    const controlSeq = this.nextControlSeq();

    this.sql.exec(
      `INSERT INTO wal_tail(database_id, generation, append_lsn, type_sequence, sequencing_kind,
         payload_key, payload_digest, payload_length, finalization_operation_id, request_digest,
         unsequenced_logical_key, startup_session_id, control_seq, record_type)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      req.databaseId, req.generation, u64Blob(appendLsn, "append_lsn"), u64Blob(typeSequence, "type_sequence"),
      req.sequencingKind,
      req.payloadKey, req.payloadDigest, req.payloadLength, req.operationId, req.requestDigest,
      req.logicalKey, req.startupSessionId, u64Blob(controlSeq, "control_seq"), req.recordType,
    );
    this.bumpUsage(req.databaseId, req.generation, "tail", 1);
    // outbox row in the SAME transaction as the projection mutation (section
    // 7.4). Sequence values are canonically DECIMAL STRINGS in the body:
    // JSON numbers stop being exact at 2^53. The row is a hash-chained,
    // commit-time-MACed journal entry (F8): the body is CANONICAL JSON
    // (sorted keys, byte-deterministic), the entry hash binds
    // (prev_hash, control_seq, kind, body), and the MAC signs the entry
    // hash with the controller's journal key - all inside this synchronous
    // transaction, so no entry can ever exist unchained or unsigned.
    const body = canonicalJson({ databaseId: req.databaseId, generation: req.generation,
                                 appendLsn: appendLsn.toString(), typeSequence: typeSequence.toString(),
                                 sequencingKind: req.sequencingKind, recordType: req.recordType,
                                 payloadKey: req.payloadKey,
                                 payloadDigest: req.payloadDigest, logicalKey: req.logicalKey });
    this.appendJournalEntry(controlSeq, req.databaseId, "WAL_RECORD_FINALIZED", body);
    return { ok: true as const, appendLsn, typeSequence, controlSeq, replayed: false };
  }

  /**
   * Controller incarnation (F9 boundary; F7c groundwork): capabilities are
   * minted under the current incarnation and die with it. Starts at 1;
   * every bump is itself a journaled control event (the authenticated
   * journal is the record of authority changes, not only WAL events).
   */
  currentIncarnation(): number {
    const rows = this.sql.exec(`SELECT value FROM controller_meta WHERE key='incarnation'`);
    return rows.length ? Number(rows[0].value) : 1;
  }

  bumpIncarnation(): number {
    return this.sql.transaction(() => {
      const next = this.currentIncarnation() + 1;
      this.sql.exec(
        `INSERT INTO controller_meta(key, value) VALUES ('incarnation', ?)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
        String(next),
      );
      this.appendCommand("@controller", "CONTROLLER_INCARNATION_BUMPED", { incarnation: next });
      return next;
    });
  }

  /**
   * Burn a capability nonce (F9 single-use rule): true exactly once per
   * nonce. Transactional check-and-insert; expired burns are pruned lazily
   * so the table stays bounded by the live-token window.
   */
  burnCapabilityNonce(nonce: string, expiresAtMs: number, nowMs: number): boolean {
    return this.sql.transaction(() => {
      this.sql.exec(`DELETE FROM capability_nonces WHERE expires_at <= ?`, nowMs);
      const seen = this.sql.exec(`SELECT 1 FROM capability_nonces WHERE nonce=?`, nonce);
      if (seen.length) return false;
      this.sql.exec(`INSERT INTO capability_nonces(nonce, expires_at) VALUES (?,?)`, nonce, expiresAtMs);
      return true;
    });
  }

  /** Allocate the next global ControlSeq (exact bytewise-u64 max + 1). */
  private nextControlSeq(): bigint {
    const max = this.sql.exec(`SELECT MAX(control_seq) AS c FROM control_outbox`)[0].c;
    return max === null ? 1n : u64FromSql(max, "max_control_seq") + 1n;
  }

  /** Journal one authority COMMAND (F7r): allocates the next ControlSeq and
   *  chain-appends inside the caller's transaction. The authenticated
   *  journal is thereby the totally-ordered record of every journaled
   *  authority mutation, not only of WAL finalisations. Returns the entry's
   *  identity so a caller can anchor against it without re-walking the
   *  chain. */
  private appendCommand(databaseId: string, kind: string, body: Record<string, unknown>):
    { controlSeq: bigint; entryHash: Uint8Array } {
    const controlSeq = this.nextControlSeq();
    const entryHash = this.appendJournalEntry(controlSeq, databaseId, kind, canonicalJson(body));
    return { controlSeq, entryHash };
  }

  /**
   * CheckpointCut protocol core (F6r, inv. 99-103 groundwork): the
   * controller-owned cut record. `openCheckpointCut` captures - in ONE
   * synchronous transaction - the WAL head of the generation, the control
   * head, the controller incarnation, and the journal anchor
   * (length + head hash) as of the cut, journaled as CHECKPOINT_CUT_OPENED
   * (the cut event itself is part of the anchored prefix that follows it).
   * Activation (`activateCheckpointCut`) transitions PENDING -> ACTIVE only
   * when the caller presents restore evidence (materialisation ids + an
   * independently computed logical digest - inv. 102's scratch-restore
   * proof), supersedes the previous ACTIVE cut, and is itself journaled.
   * Exactly one ACTIVE cut per (database, generation) can exist (inv. 81's
   * single-active-materialisation, at the cut level).
   *
   * The stored journal anchor also closes part of the F8 truncation gap:
   * `verifyJournalAnchored` proves the journal is an EXTENSION of the
   * anchored prefix. The anchor lives in the same SQLite as the journal,
   * so it defends against bugs and partial restores, not against an
   * attacker with database write access - THAT requires the immutable R2
   * RecoveryAnchor publication (still staged, F8 remainder).
   */
  openCheckpointCut(databaseId: string, generation: number, cutId: string):
    Typed<{ cutId: string; headLsn: bigint; headTypeSequence: bigint; cutControlSeq: bigint;
            journalLength: number; journalHeadHash: string }> | { ok: false; error: "CUT_EXISTS" } {
    return this.sql.transaction(() => {
      const existing = this.sql.exec(`SELECT 1 FROM checkpoint_cuts WHERE cut_id=?`, cutId);
      if (existing.length) return { ok: false as const, error: "CUT_EXISTS" as const };
      const head = this.head(databaseId, generation);
      const verdict = this.verifyJournal();
      if (!verdict.ok) {
        // a cut over an inconsistent journal must never be recorded
        throw new Error(`CHECKPOINT_CUT_REFUSED: journal ${verdict.error} at ${verdict.atControlSeq}`);
      }
      const cut = this.appendCommand(databaseId, "CHECKPOINT_CUT_OPENED", {
        databaseId, generation, cutId,
        headLsn: head.headLsn.toString(), headTypeSequence: head.headTypeSequence.toString(),
        journalLength: verdict.length, journalHeadHash: verdict.headHash,
      });
      // the anchored prefix includes the cut event itself: the verify above
      // proved the chain at (length, headHash), and the appended entry is
      // the new head - one derived anchor, not a second O(journal) walk
      const anchored = { length: verdict.length + 1, headHash: hex(cut.entryHash) };
      this.sql.exec(
        `INSERT INTO checkpoint_cuts(cut_id, database_id, generation, incarnation, cut_control_seq,
           head_lsn, head_type_sequence, journal_length, journal_head_hash, state)
         VALUES (?,?,?,?,?,?,?,?,?,'PENDING')`,
        cutId, databaseId, generation, this.currentIncarnation(),
        u64Blob(cut.controlSeq, "cut_control_seq"),
        head.headLsn < 0n ? null : u64Blob(head.headLsn, "head_lsn"),
        u64Blob(head.headTypeSequence, "head_type_sequence"),
        anchored.length, fromHexInternal(anchored.headHash),
      );
      return {
        ok: true as const, cutId, headLsn: head.headLsn, headTypeSequence: head.headTypeSequence,
        cutControlSeq: cut.controlSeq, journalLength: anchored.length, journalHeadHash: anchored.headHash,
      };
    });
  }

  activateCheckpointCut(databaseId: string, cutId: string, evidence: { materializations: string[]; logicalDigest: string }):
    Typed<{ cutId: string; superseded: string | null }>
    | { ok: false; error: "CUT_NOT_FOUND" | "CUT_NOT_PENDING" | "CUT_EVIDENCE_MISSING" } {
    return this.sql.transaction(() => {
      const rows = this.sql.exec(
        `SELECT state, generation FROM checkpoint_cuts WHERE cut_id=? AND database_id=?`, cutId, databaseId);
      if (!rows.length) return { ok: false as const, error: "CUT_NOT_FOUND" as const };
      if (String(rows[0].state) !== "PENDING") return { ok: false as const, error: "CUT_NOT_PENDING" as const };
      if (!evidence.materializations.length || !evidence.logicalDigest) {
        // inv. 102: activation only from verified restore evidence - an
        // empty evidence set fails closed
        return { ok: false as const, error: "CUT_EVIDENCE_MISSING" as const };
      }
      const generation = Number(rows[0].generation);
      const active = this.sql.exec(
        `SELECT cut_id FROM checkpoint_cuts WHERE database_id=? AND generation=? AND state='ACTIVE'`,
        databaseId, generation);
      const superseded = active.length ? String(active[0].cut_id) : null;
      if (superseded !== null) {
        this.sql.exec(`UPDATE checkpoint_cuts SET state='SUPERSEDED' WHERE cut_id=?`, superseded);
      }
      this.sql.exec(
        `UPDATE checkpoint_cuts SET state='ACTIVE', materializations=?, logical_digest=? WHERE cut_id=?`,
        JSON.stringify(evidence.materializations.slice().sort()), evidence.logicalDigest, cutId,
      );
      this.appendCommand(databaseId, "CHECKPOINT_CUT_ACTIVATED", {
        databaseId, generation, cutId, superseded,
        materializations: evidence.materializations.slice().sort(),
        logicalDigest: evidence.logicalDigest,
      });
      return { ok: true as const, cutId, superseded };
    });
  }

  activeCheckpointCut(databaseId: string, generation: number):
    Typed<{ cutId: string; headLsn: bigint | null; journalLength: number; journalHeadHash: string;
            materializations: string[]; logicalDigest: string }> | { ok: false; error: "NOT_FOUND" } {
    const rows = this.sql.exec(
      `SELECT cut_id, head_lsn, journal_length, journal_head_hash, materializations, logical_digest
       FROM checkpoint_cuts WHERE database_id=? AND generation=? AND state='ACTIVE'`,
      databaseId, generation);
    if (!rows.length) return { ok: false, error: "NOT_FOUND" };
    return {
      ok: true,
      cutId: String(rows[0].cut_id),
      headLsn: rows[0].head_lsn === null ? null : u64FromSql(rows[0].head_lsn, "head_lsn"),
      journalLength: Number(rows[0].journal_length),
      journalHeadHash: hex(asHash(rows[0].journal_head_hash, "journal_head_hash")),
      materializations: JSON.parse(String(rows[0].materializations ?? "[]")) as string[],
      logicalDigest: String(rows[0].logical_digest ?? ""),
    };
  }

  /**
   * Journal verification against the newest recorded cut anchor (F8+F6r):
   * beyond the chain checks, the journal must be an EXTENSION of the
   * anchored prefix - at least `journalLength` entries, with the running
   * hash at exactly that position equal to the anchored head hash. A
   * truncation (or rewrite) at or below the anchor is now DETECTED; only
   * the un-anchored tail after the newest cut remains chain-consistent to
   * truncate, and every new cut shrinks that window.
   */
  verifyJournalAnchored():
    | { ok: true; length: number; headHash: string; anchor: { length: number; headHash: string } | null }
    | { ok: false; error: string; atControlSeq?: string } {
    const verdict = this.verifyJournal();
    if (!verdict.ok) return verdict;
    const anchors = this.sql.exec(
      `SELECT journal_length, journal_head_hash FROM checkpoint_cuts ORDER BY cut_control_seq DESC LIMIT 1`);
    if (!anchors.length) return { ...verdict, anchor: null };
    const anchorLength = Number(anchors[0].journal_length);
    const anchorHash = hex(asHash(anchors[0].journal_head_hash, "journal_head_hash"));
    if (verdict.length < anchorLength) {
      return { ok: false, error: "JOURNAL_TRUNCATED_BELOW_ANCHOR" };
    }
    const prefixHash = this.journalHashAt(anchorLength);
    if (prefixHash !== anchorHash) {
      return { ok: false, error: "JOURNAL_ANCHOR_MISMATCH" };
    }
    return { ...verdict, anchor: { length: anchorLength, headHash: anchorHash } };
  }

  /** Running chain hash after the first `length` entries (0 = genesis):
   *  one index seek to the length-th row, not a walk of the prefix. */
  private journalHashAt(length: number): string {
    if (length === 0) return hex(GENESIS_HASH);
    const rows = this.sql.exec(
      `SELECT entry_hash FROM control_outbox ORDER BY control_seq LIMIT 1 OFFSET ?`, length - 1);
    if (!rows.length) return hex(GENESIS_HASH);
    return hex(asHash(rows[0].entry_hash, "entry_hash"));
  }

  /**
   * Read a transactionally maintained usage counter (Q-17).
   *
   * Missing means zero: a database that has never appended has no row, and
   * inventing one at open would be a write on a read path.
   */
  private usage(databaseId: string, generation: number, scope: string): number {
    const rows = this.sql.exec(
      `SELECT value FROM usage_counters WHERE database_id=? AND generation=? AND scope=?`,
      databaseId, generation, scope,
    );
    return rows.length ? Number(rows[0].value) : 0;
  }

  /** Move a usage counter by `delta` inside the caller's transaction. The
   *  upsert and the row it accounts for are always in the SAME transaction,
   *  so a rollback cannot leave the counter describing a row that is not
   *  there (or vice versa). */
  private bumpUsage(databaseId: string, generation: number, scope: string, delta: number): void {
    this.sql.exec(
      `INSERT INTO usage_counters(database_id, generation, scope, value) VALUES (?,?,?,?)
       ON CONFLICT(database_id, generation, scope) DO UPDATE SET value = value + ?`,
      databaseId, generation, scope, delta, delta,
    );
  }

  /** Chain-append one journal/outbox row; returns the entry hash (= the new
   *  chain head). Caller holds the transaction. */
  private appendJournalEntry(controlSeq: bigint, databaseId: string, kind: string, canonicalBody: string): Uint8Array {
    const tail = this.sql.exec(`SELECT entry_hash FROM control_outbox ORDER BY control_seq DESC LIMIT 1`);
    const prevHash = tail.length ? asHash(tail[0].entry_hash, "prev entry_hash") : GENESIS_HASH;
    const entryHash = sha256(prevHash, u64Blob(controlSeq, "control_seq"), utf8(kind), utf8(canonicalBody));
    const mac = hmacSha256(this.journalKey, entryHash);
    this.sql.exec(
      `INSERT INTO control_outbox(control_seq, database_id, kind, canonical_body, prev_hash, entry_hash, mac)
       VALUES (?,?,?,?,?,?,?)`,
      u64Blob(controlSeq, "control_seq"), databaseId, kind, canonicalBody, prevHash, entryHash, mac,
    );
    this.bumpUsage(databaseId, OUTBOX_GENERATION, "outbox_unpublished", 1);
    return entryHash;
  }

  /**
   * Journal authentication audit (F8): walk the WHOLE outbox in ControlSeq
   * order and verify contiguity from 1, hash-chain linkage from the genesis
   * ancestor, each entry hash against its (prev, seq, kind, body) preimage,
   * and each commit-time MAC under the journal key. Any deviation is a
   * typed failure naming the first bad sequence. What this cannot detect -
   * by construction - is truncation of the TAIL: that requires an external
   * RecoveryAnchor (staged F8 remainder), which is why the verdict reports
   * `length` and `headHash` for the caller to anchor externally.
   */
  verifyJournal():
    | { ok: true; length: number; headHash: string }
    | { ok: false; error: "JOURNAL_GAP" | "JOURNAL_CHAIN_BROKEN" | "JOURNAL_HASH_MISMATCH" | "JOURNAL_MAC_INVALID"; atControlSeq: string } {
    const rows = this.sql.exec(
      `SELECT control_seq, kind, canonical_body, prev_hash, entry_hash, mac FROM control_outbox ORDER BY control_seq`,
    );
    let expectedSeq = 1n;
    let expectedPrev: Uint8Array = GENESIS_HASH;
    for (const row of rows) {
      const seq = u64FromSql(row.control_seq, "control_seq");
      const at = seq.toString();
      if (seq !== expectedSeq) return { ok: false, error: "JOURNAL_GAP", atControlSeq: at };
      const prevHash = asHash(row.prev_hash, "prev_hash");
      const entryHash = asHash(row.entry_hash, "entry_hash");
      const mac = asHash(row.mac, "mac");
      if (!bytesEqual(prevHash, expectedPrev)) return { ok: false, error: "JOURNAL_CHAIN_BROKEN", atControlSeq: at };
      const recomputed = sha256(prevHash, u64Blob(seq, "control_seq"), utf8(String(row.kind)), utf8(String(row.canonical_body)));
      if (!bytesEqual(entryHash, recomputed)) return { ok: false, error: "JOURNAL_HASH_MISMATCH", atControlSeq: at };
      if (!bytesEqual(mac, hmacSha256(this.journalKey, entryHash))) {
        return { ok: false, error: "JOURNAL_MAC_INVALID", atControlSeq: at };
      }
      expectedPrev = entryHash;
      expectedSeq = seq + 1n;
    }
    return { ok: true, length: rows.length, headHash: hex(expectedPrev) };
  }

  /** Idempotent outbox drain: publish everything unpublished, exactly once.
   *  STAGED, not shipped: no DO route or alarm task calls this yet - the
   *  delivered contract is peek/ack; this is the planned push path. */
  drainOutbox(publish: (row: { controlSeq: bigint; kind: string; body: string }) => void): number {
    // Publishing is external I/O; the mark and its counter move in ONE
    // transaction per row, so a crash between publish and mark yields
    // at-least-once delivery to the bus (deduplicated downstream by
    // control_seq) and can never leave the counter describing a row state
    // that is not there.
    const rows = this.sql.exec(
      `SELECT control_seq, database_id, kind, canonical_body FROM control_outbox
       WHERE published=0 ORDER BY control_seq`,
    );
    let published = 0;
    for (const row of rows) {
      publish({ controlSeq: u64FromSql(row.control_seq, "control_seq"), kind: String(row.kind), body: String(row.canonical_body) });
      this.sql.transaction(() => {
        this.sql.exec(`UPDATE control_outbox SET published=1 WHERE control_seq=?`, row.control_seq);
        this.bumpUsage(String(row.database_id), OUTBOX_GENERATION, "outbox_unpublished", -1);
      });
      published += 1;
    }
    return published;
  }

  /**
   * At-least-once consumer contract: peek returns unpublished rows WITHOUT
   * marking; the consumer acks after durable processing. A lost ack response
   * redelivers on the next peek; consumers dedupe by control_seq.
   */
  outboxPeek(limit: number): { controlSeq: bigint; kind: string; body: string }[] {
    return this.sql
      .exec(`SELECT control_seq, kind, canonical_body FROM control_outbox
             WHERE published=0 ORDER BY control_seq LIMIT ?`, limit)
      .map((row) => ({
        controlSeq: u64FromSql(row.control_seq, "control_seq"),
        kind: String(row.kind),
        body: String(row.canonical_body),
      }));
  }

  outboxAck(databaseId: string, upToControlSeq: bigint, startupSessionId: string):
    Typed<{ acked: number }> | { ok: false; error: "SESSION_UNKNOWN" | "SESSION_FENCED" }
    | { ok: false; error: "SESSION_NOT_ACTIVE"; state: string }
    | { ok: false; error: "SESSION_LEASE_EXPIRED" } {
    const bound = u64Blob(upToControlSeq, "up_to_control_seq");
    return this.sql.transaction(() => {
      // guards INSIDE the transaction: lease expiry mutates (see setBudgets)
      const authority = this.requireLiveSession(databaseId, startupSessionId);
      if (!authority.ok) return authority;
      const leasedAck = this.requireLeasedAuthority(databaseId, startupSessionId);
      if (!leasedAck.ok) return leasedAck;
      // bounded by the ack window, not by history: the partial index over
      // unpublished rows makes this a range walk, and the counter it
      // maintains is what admission reads
      // scoped to the acking database: the ack is per-database authority, and
      // an unscoped UPDATE would let one database's consumer mark another's
      // control events published. One DO per database hides this in
      // production; it is wrong wherever a core holds more than one.
      const before = Number(this.sql.exec(
        `SELECT COUNT(*) AS n FROM control_outbox
         WHERE database_id=? AND published=0 AND control_seq <= ?`, databaseId, bound)[0].n);
      this.sql.exec(
        `UPDATE control_outbox SET published=1
         WHERE database_id=? AND published=0 AND control_seq <= ?`, databaseId, bound);
      if (before > 0) this.bumpUsage(databaseId, OUTBOX_GENERATION, "outbox_unpublished", -before);
      return { ok: true as const, acked: before };
    });
  }

  /** Exact lookup (CT-P5): missing rows are typed NOT_FOUND, never EOF. */
  exactLookup(databaseId: string, generation: number, appendLsn: bigint):
    Typed<{ payloadKey: string; payloadDigest: string; typeSequence: bigint; recordType: number }>
    | { ok: false; error: "NOT_FOUND" } {
    const rows = this.sql.exec(
      `SELECT payload_key, payload_digest, type_sequence, record_type FROM wal_tail
       WHERE database_id=? AND generation=? AND append_lsn=?`,
      databaseId, generation, u64Blob(appendLsn, "append_lsn"),
    );
    if (!rows.length) return { ok: false, error: "NOT_FOUND" };
    return {
      ok: true,
      payloadKey: String(rows[0].payload_key),
      payloadDigest: String(rows[0].payload_digest),
      typeSequence: u64FromSql(rows[0].type_sequence, "type_sequence"),
      recordType: Number(rows[0].record_type),
    };
  }

  /** Fixed iterator snapshot (CT-P3): head is pinned at open; reads are
   *  exact. `-1n` is the empty-head sentinel (a JS value only - it never
   *  touches the u64 blob encoding). */
  /**
   * Pin an iteration snapshot and hand back an OPAQUE, server-owned id
   * (Q-12 / directive 12.6).
   *
   * Returning only `headLsn` and then accepting a caller-supplied
   * `throughLsn` on every page is not a pinned view: the client holds the
   * cut, so it can widen it between pages and observe appends made after
   * iteration started (inv. 41-42) - or narrow it, and silently skip
   * records a consumer believes it replayed. The snapshot id is MACed over
   * (database, generation, head, incarnation), so the bound travels back
   * unforgeably and the server, not the caller, decides what the cut was.
   *
   * The id is stateless by design: it carries the cut rather than naming a
   * row, so pinning costs no storage and a controller restart invalidates
   * every outstanding snapshot through the incarnation binding - which is
   * the correct behaviour, since a new incarnation may have recovered to a
   * different frontier.
   */
  openIterator(databaseId: string, generation: number):
    { headLsn: bigint; snapshotId: string } {
    const head = this.sql.exec(
      `SELECT MAX(append_lsn) AS lsn FROM wal_tail WHERE database_id=? AND generation=?`,
      databaseId, generation,
    )[0];
    const headLsn = head.lsn === null ? -1n : u64FromSql(head.lsn, "max_append_lsn");
    return { headLsn, snapshotId: this.mintSnapshotId(databaseId, generation, headLsn) };
  }

  private snapshotPreimage(databaseId: string, generation: number, headLsn: bigint): Uint8Array {
    return utf8(canonicalJson({
      domain: "wal-iteration-snapshot/v1",
      databaseId,
      generation,
      headLsn: headLsn.toString(),
      incarnation: this.currentIncarnation(),
    }));
  }

  private mintSnapshotId(databaseId: string, generation: number, headLsn: bigint): string {
    const mac = hmacSha256(this.journalKey, this.snapshotPreimage(databaseId, generation, headLsn));
    return `${headLsn.toString()}.${hex(mac)}`;
  }

  /**
   * Resolve a snapshot id back to its pinned head, or refuse.
   *
   * A caller may not supply a raw `throughLsn`; it must present the id it
   * was given. Anything else - a forged MAC, a rewritten head, an id minted
   * under a superseded incarnation - is a typed refusal, never a scan over
   * a cut nobody pinned.
   */
  resolveSnapshot(databaseId: string, generation: number, snapshotId: string):
    Typed<{ headLsn: bigint }> | { ok: false; error: "INVALID_SNAPSHOT_ID" } {
    if (typeof snapshotId !== "string") return { ok: false, error: "INVALID_SNAPSHOT_ID" };
    const dot = snapshotId.lastIndexOf(".");
    if (dot <= 0) return { ok: false, error: "INVALID_SNAPSHOT_ID" };
    const headText = snapshotId.slice(0, dot);
    const macHex = snapshotId.slice(dot + 1);
    if (!/^-?\d+$/.test(headText) || !/^[0-9a-f]{64}$/.test(macHex)) {
      return { ok: false, error: "INVALID_SNAPSHOT_ID" };
    }
    const headLsn = BigInt(headText);
    const expected = hmacSha256(this.journalKey, this.snapshotPreimage(databaseId, generation, headLsn));
    if (!bytesEqual(expected, fromHexInternal(macHex))) return { ok: false, error: "INVALID_SNAPSHOT_ID" };
    return { ok: true, headLsn };
  }

  /**
   * WAL head: the highest AppendLsn AND the highest TypeSequence. The
   * durability client's `current()`/`previous()` need the TypeSequence —
   * the audit's `maxLsn` is a physical position, not a sequence number.
   */
  head(databaseId: string, generation: number): { headLsn: bigint; headTypeSequence: bigint } {
    // one PK-index seek: the newest row carries both maxima (TypeSequence is
    // nondecreasing in append order) - see the Q-17 note in finalizeStep
    const head = this.sql.exec(
      `SELECT append_lsn AS lsn, type_sequence AS ts
       FROM wal_tail WHERE database_id=? AND generation=?
       ORDER BY append_lsn DESC LIMIT 1`,
      databaseId, generation,
    )[0] ?? { lsn: null, ts: null };
    return {
      headLsn: head.lsn === null ? -1n : u64FromSql(head.lsn, "max_append_lsn"),
      headTypeSequence: head.ts === null ? 0n : u64FromSql(head.ts, "max_type_sequence"),
    };
  }

  /**
   * Ordered replay scan (physical AppendLsn order — the reference WAL's
   * iteration order), filtered by `type_sequence >= fromTypeSequence` and
   * optionally by record type, bounded by `throughLsn` (the pinned iterator
   * snapshot: pages of one logical iteration must not observe later
   * appends) and paged by (`fromLsn`, `limit`).
   */
  scan(
    databaseId: string,
    generation: number,
    opts: { fromTypeSequence: bigint; fromLsn: bigint; throughLsn: bigint; recordType: number | null; limit: number },
  ): { records: WalDescriptor[]; nextFromLsn: bigint | null } {
    // a non-positive limit would page nothing yet compute nextFromLsn from an
    // empty slice (crash); clamp defensively — the HTTP route validates, but
    // the DO method is directly callable
    const limit = Math.max(1, Math.floor(opts.limit));
    // an empty generation pins headLsn=-1n; a scan bounded by it is exactly
    // empty (u64 blobs cannot encode the sentinel, so answer before SQL)
    if (opts.throughLsn < 0n) return { records: [], nextFromLsn: null };
    const typeFilter = opts.recordType === null ? "" : "AND record_type=?";
    const params: unknown[] = [
      databaseId, generation,
      u64Blob(opts.fromTypeSequence, "from_type_sequence"),
      u64Blob(opts.fromLsn < 0n ? 0n : opts.fromLsn, "from_lsn"),
      u64Blob(opts.throughLsn, "through_lsn"),
    ];
    if (opts.recordType !== null) params.push(opts.recordType);
    params.push(limit + 1); // one extra row decides whether a next page exists
    const rows = this.sql.exec(
      `SELECT ${WAL_DESCRIPTOR_COLUMNS}
       FROM wal_tail
       WHERE database_id=? AND generation=? AND type_sequence>=? AND append_lsn>=? AND append_lsn<=?
         ${typeFilter}
       ORDER BY append_lsn LIMIT ?`,
      ...params,
    );
    const page = rows.slice(0, limit).map((row) => descriptorOf(row));
    const nextFromLsn = rows.length > limit ? page[page.length - 1].appendLsn + 1n : null;
    return { records: page, nextFromLsn };
  }

  /**
   * Exact lookup by operation identity (V16: an already-finalized operation
   * remains queryable by operation ID after its former session is fenced).
   * This is the READ surface: authority checks gate mutation and the
   * finalize-retry REPORTING path (inv. 38 / ADR-0006 - a fenced actor's
   * identical retry gets SESSION_FENCED, never the receipt), but they never
   * hide the immutable durable record itself: lost-response recovery and
   * forensics by the CURRENT actor resolve here.
   */
  queryOperation(databaseId: string, generation: number, operationId: string, startupSessionId: string):
    Typed<{ record: WalDescriptor; requestDigest: string; controlSeq: bigint }>
    | TypedErr | { ok: false; error: "SESSION_UNKNOWN" | "SESSION_FENCED" } {
    // "by the CURRENT actor" is the whole point of this surface: a fenced
    // actor must not keep reading the immutable history it can no longer
    // extend, and its unexpired WAL_READ capability must not let it.
    const authority = this.requireLiveSession(databaseId, startupSessionId);
    if (!authority.ok) return authority;
    let rows = this.sql.exec(
      `SELECT ${WAL_DESCRIPTOR_COLUMNS}, request_digest, control_seq
       FROM wal_tail WHERE database_id=? AND generation=? AND finalization_operation_id=?`,
      databaseId, generation, operationId,
    );
    if (!rows.length) {
      // Q-11: an operation answered by status-singleton dedupe resolves
      // through its durable alias to the record it was answered with
      const alias = this.sql.exec(
        `SELECT append_lsn FROM operation_aliases
         WHERE database_id=? AND generation=? AND operation_id=?`,
        databaseId, generation, operationId,
      );
      if (!alias.length) return { ok: false, error: "NOT_FOUND" };
      rows = this.sql.exec(
        `SELECT ${WAL_DESCRIPTOR_COLUMNS}, request_digest, control_seq
         FROM wal_tail WHERE database_id=? AND generation=? AND append_lsn=?`,
        databaseId, generation, alias[0].append_lsn,
      );
      if (!rows.length) return { ok: false, error: "NOT_FOUND" };
    }
    return {
      ok: true,
      record: descriptorOf(rows[0]),
      requestDigest: String(rows[0].request_digest),
      controlSeq: u64FromSql(rows[0].control_seq, "control_seq"),
    };
  }

  /**
   * Record `operationId -> the physical record it was answered with`.
   *
   * Returns a typed conflict when the same operation id was already aliased
   * with a different request digest: one operation id may resolve to exactly
   * one answer, and a second, different request under it is a client defect,
   * never a silent re-point.
   */
  private recordOperationAlias(
    req: FinalizeRequest, appendLsn: Uint8Array,
  ): { ok: false; error: "OPERATION_DIGEST_CONFLICT" } | null {
    const prior = this.sql.exec(
      `SELECT request_digest FROM operation_aliases
       WHERE database_id=? AND generation=? AND operation_id=?`,
      req.databaseId, req.generation, req.operationId,
    );
    if (prior.length && String(prior[0].request_digest) !== req.requestDigest) {
      return { ok: false as const, error: "OPERATION_DIGEST_CONFLICT" as const };
    }
    this.sql.exec(
      `INSERT OR IGNORE INTO operation_aliases(database_id, generation, operation_id, append_lsn, request_digest)
       VALUES (?,?,?,?,?)`,
      req.databaseId, req.generation, req.operationId, appendLsn, req.requestDigest,
    );
    return null;
  }

  /** Last record of a type in physical order (`find_last_type`). */
  lastByType(databaseId: string, generation: number, recordType: number):
    Typed<{ record: WalDescriptor }> | { ok: false; error: "NOT_FOUND" } {
    const rows = this.sql.exec(
      `SELECT ${WAL_DESCRIPTOR_COLUMNS}
       FROM wal_tail WHERE database_id=? AND generation=? AND record_type=?
       ORDER BY append_lsn DESC LIMIT 1`,
      databaseId, generation, recordType,
    );
    if (!rows.length) return { ok: false, error: "NOT_FOUND" };
    return { ok: true, record: descriptorOf(rows[0]) };
  }

  /** Contiguity audit: the tail must have no LSN holes. */
  auditContiguity(databaseId: string, generation: number): { contiguous: boolean; count: number; maxLsn: bigint } {
    const r = this.sql.exec(
      `SELECT COUNT(*) AS n, MAX(append_lsn) AS m
       FROM wal_tail WHERE database_id=? AND generation=?`,
      databaseId, generation,
    )[0];
    const maxLsn = r.m === null ? -1n : u64FromSql(r.m, "max_append_lsn");
    return { contiguous: BigInt(Number(r.n)) === maxLsn + 1n, count: Number(r.n), maxLsn };
  }
}

/** A 32-byte hash/MAC column read back from SQL; anything else fails closed. */
function asHash(value: unknown, context: string): Uint8Array {
  const bytes =
    value instanceof Uint8Array ? value : value instanceof ArrayBuffer ? new Uint8Array(value) : null;
  if (bytes === null || bytes.byteLength !== 32) {
    throw new Error(`JOURNAL_REPRESENTATION_VIOLATION: ${context} is not a 32-byte hash`);
  }
  return bytes;
}

function descriptorOf(row: SqlRow): WalDescriptor {
  return {
    appendLsn: u64FromSql(row.append_lsn, "append_lsn"),
    typeSequence: u64FromSql(row.type_sequence, "type_sequence"),
    sequencingKind: String(row.sequencing_kind),
    recordType: Number(row.record_type),
    payloadKey: String(row.payload_key),
    payloadDigest: String(row.payload_digest),
    payloadLength: Number(row.payload_length),
    logicalKey: row.unsequenced_logical_key === null ? null : String(row.unsequenced_logical_key),
  };
}

class BatchAbort extends Error {
  readonly result: TypedErr;

  constructor(result: TypedErr) {
    super(`batch aborted: ${result.error}`);
    this.result = result;
  }
}
