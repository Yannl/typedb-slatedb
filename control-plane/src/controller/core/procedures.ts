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

export const SCHEMA = `
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

export const U64_MAX = (1n << 64n) - 1n;

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

/** Non-sequence integers (generation, budgets, payload lengths) remain JS
 *  numbers, guarded to the exact range - they are human/config-scale, and a
 *  value outside 2^53 is an invariant catastrophe that fails closed. */
export function exactU64(value: unknown, context: string): number {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < -1) {
    throw new Error(`INTEGER_RANGE_VIOLATION: ${context}=${String(value)} outside exact JS integer range`);
  }
  return n;
}

export type Typed<TOk> = { ok: true } & TOk;
export type TypedErr =
  | { ok: false; error: "ADMISSION_REJECTED_OUTBOX_DEPTH"; limit: number }
  | { ok: false; error: "ADMISSION_REJECTED_PAYLOAD_LENGTH"; limit: number }
  | { ok: false; error: "ADMISSION_REJECTED_TAIL_BUDGET"; limit: number }
  | { ok: false; error: "OPERATION_DIGEST_CONFLICT" }
  | { ok: false; error: "STATUS_CONFLICT" }
  | { ok: false; error: "SESSION_FENCED"; fencedBy: string | null }
  | { ok: false; error: "SESSION_UNKNOWN" }
  | { ok: false; error: "NOT_FOUND" };

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

  constructor(sql: SyncSql, options?: { journalKey?: Uint8Array }) {
    this.sql = sql;
    this.journalKey = options?.journalKey ?? utf8("dev-insecure-journal-key");
    this.migrate();
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
  ];

  /**
   * Register a session AND fence every other live session of the database
   * (takeover-at-open). Both Rust reference lanes already do this
   * (remote-wal-spike `Controller::register`, protocol-models
   * `WalState::register`); a register that leaves the predecessor able to
   * append would let two processes allocate concurrently after a restart —
   * exactly the divergence class ADR-0006's three-lane rule exists to
   * prevent. Re-registering the same session is idempotent and fences
   * nothing of its own.
   */
  registerSession(databaseId: string, generation: number, startupSessionId: string): void {
    this.sql.transaction(() => {
      // The authority unit is the ACTOR (startup session), not the
      // (generation, session) pair: one live process may span a generation
      // rollover without fencing itself. A superseded (fenced) actor can
      // never re-take authority — the models' session counter only moves
      // forward — so its re-register is a no-op, leaving it fenced and the
      // current owner untouched.
      const fencedRows = this.sql.exec(
        `SELECT 1 FROM sessions WHERE database_id=? AND startup_session_id=? AND fenced=1 LIMIT 1`,
        databaseId, startupSessionId,
      );
      if (fencedRows.length) return;
      // command ledger (F7r): the fence-and-register is journaled ONLY when
      // it changes authority state - an idempotent re-register writes no
      // ledger entry (replaying the ledger must reproduce state exactly,
      // and a no-op that appends would break trace equivalence)
      const fencedCount = Number(this.sql.exec(
        `SELECT COUNT(*) AS n FROM sessions WHERE database_id=? AND startup_session_id<>? AND fenced=0`,
        databaseId, startupSessionId,
      )[0].n);
      const known = this.sql.exec(
        `SELECT 1 FROM sessions WHERE database_id=? AND generation=? AND startup_session_id=?`,
        databaseId, generation, startupSessionId,
      ).length > 0;
      this.sql.exec(
        `UPDATE sessions SET fenced=1 WHERE database_id=? AND startup_session_id<>?`,
        databaseId, startupSessionId,
      );
      this.sql.exec(
        `INSERT OR IGNORE INTO sessions(database_id, generation, startup_session_id) VALUES (?,?,?)`,
        databaseId, generation, startupSessionId,
      );
      if (!known || fencedCount > 0) {
        this.appendCommand(databaseId, "SESSION_REGISTERED", {
          databaseId, generation, startupSessionId, fencedPredecessors: fencedCount,
        });
      }
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
  ): { ok: true } | { ok: false; error: "SESSION_UNKNOWN" | "SESSION_FENCED" } {
    const authority = this.requireLiveSession(databaseId, startupSessionId);
    if (!authority.ok) return authority;
    this.sql.transaction(() => {
      this.sql.exec(
        `INSERT OR REPLACE INTO budgets(database_id, max_unpublished_outbox, max_payload_length, max_tail_records)
         VALUES (?,?,?,?)`,
        databaseId, b.maxUnpublishedOutbox, b.maxPayloadLength, b.maxTailRecords,
      );
      this.appendCommand(databaseId, "BUDGETS_SET", { databaseId, ...b, startupSessionId });
    });
    return { ok: true };
  }

  /**
   * WAL finalisation with late atomic allocation (CT-P3). The payload is
   * assumed uploaded and receipt-verified BEFORE this call; everything below
   * is one synchronous transaction.
   */
  finalizeWalRecord(req: FinalizeRequest): FinalizeResult {
    return this.sql.transaction(() => this.finalizeStep(req));
  }

  /** Batch candidate (J.4): N records finalised in ONE transaction - all or nothing. */
  finalizeBatch(reqs: FinalizeRequest[]): FinalizeResult[] | TypedErr {
    try {
      return this.sql.transaction(() => {
        const results: FinalizeResult[] = [];
        for (const req of reqs) {
          const r = this.finalizeStep(req);
          if (!r.ok) throw new BatchAbort(r); // rollback of every prior record
          results.push(r);
        }
        return results;
      });
    } catch (e) {
      if (e instanceof BatchAbort) return e.result;
      throw e;
    }
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
      // Attribution, not a credential (donor A3): the fenced actor learns
      // WHO superseded it — the first question in a fence incident is "who
      // is the writer now?". This disclosure is only SAFE because the
      // session id is no longer sufficient to write: WAL_FINALIZE authority
      // requires a capability BOUND to the session (worker-entry's finalize
      // guard passes the session; capability.ts enforces the binding), and
      // the controller issues a session-bound finalize capability only to
      // the actor it admitted as that session. A leaked id without such a
      // capability finalizes nothing. Served from the authority row
      // read-only; it can never change this call's outcome.
      const live = this.sql.exec(
        `SELECT startup_session_id FROM sessions WHERE database_id=? AND fenced=0 LIMIT 1`,
        req.databaseId,
      );
      return {
        ok: false as const,
        error: "SESSION_FENCED" as const,
        fencedBy: live.length ? String(live[0].startup_session_id) : null,
      };
    }

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

    // bounded admission, fail-closed, BEFORE any allocation
    const budget = this.sql.exec(`SELECT * FROM budgets WHERE database_id=?`, req.databaseId)[0];
    if (budget) {
      if (req.payloadLength > Number(budget.max_payload_length)) {
        return { ok: false as const, error: "ADMISSION_REJECTED_PAYLOAD_LENGTH" as const, limit: Number(budget.max_payload_length) };
      }
      const unpublished = Number(
        this.sql.exec(
          `SELECT COUNT(*) AS n FROM control_outbox WHERE database_id=? AND published=0`,
          req.databaseId,
        )[0].n,
      );
      if (unpublished >= Number(budget.max_unpublished_outbox)) {
        return { ok: false as const, error: "ADMISSION_REJECTED_OUTBOX_DEPTH" as const, limit: Number(budget.max_unpublished_outbox) };
      }
      const tail = Number(
        this.sql.exec(
          `SELECT COUNT(*) AS n FROM wal_tail WHERE database_id=? AND generation=?`,
          req.databaseId, req.generation,
        )[0].n,
      );
      if (tail >= Number(budget.max_tail_records)) {
        return { ok: false as const, error: "ADMISSION_REJECTED_TAIL_BUDGET" as const, limit: Number(budget.max_tail_records) };
      }
    }

    // late atomic allocation: contiguous AppendLsn, monotone TypeSequence
    // (sequenced records advance it; unsequenced reuse the current one),
    // global ControlSeq - all inside the caller's transaction. MAX over the
    // BE-blob columns is exact bytewise u64 ordering; an empty head is NULL
    // (never a -1 sentinel, which has no u64 blob encoding).
    const head = this.sql.exec(
      `SELECT MAX(append_lsn) AS lsn, MAX(type_sequence) AS ts
       FROM wal_tail WHERE database_id=? AND generation=?`,
      req.databaseId, req.generation,
    )[0];
    const appendLsn = head.lsn === null ? 0n : u64FromSql(head.lsn, "max_append_lsn") + 1n;
    const headTypeSequence = head.ts === null ? 0n : u64FromSql(head.ts, "max_type_sequence");
    const typeSequence = req.sequencingKind === "SEQUENCED" ? headTypeSequence + 1n : headTypeSequence;
    const maxControl = this.sql.exec(`SELECT MAX(control_seq) AS c FROM control_outbox`)[0].c;
    const controlSeq = maxControl === null ? 1n : u64FromSql(maxControl, "max_control_seq") + 1n;

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
      const maxControl = this.sql.exec(`SELECT MAX(control_seq) AS c FROM control_outbox`)[0].c;
      const controlSeq = maxControl === null ? 1n : u64FromSql(maxControl, "max_control_seq") + 1n;
      this.appendJournalEntry(
        controlSeq, "@controller", "CONTROLLER_INCARNATION_BUMPED",
        canonicalJson({ incarnation: next }),
      );
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

  /** Journal one authority COMMAND (F7r command ledger): allocates the next
   *  ControlSeq and chain-appends inside the caller's transaction. The
   *  authenticated journal is thereby the totally-ordered command ledger of
   *  every authority mutation, not only of WAL finalisations. */
  private appendCommand(databaseId: string, kind: string, body: Record<string, unknown>): bigint {
    const maxControl = this.sql.exec(`SELECT MAX(control_seq) AS c FROM control_outbox`)[0].c;
    const controlSeq = maxControl === null ? 1n : u64FromSql(maxControl, "max_control_seq") + 1n;
    this.appendJournalEntry(controlSeq, databaseId, kind, canonicalJson(body));
    return controlSeq;
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
      const cutControlSeq = this.appendCommand(databaseId, "CHECKPOINT_CUT_OPENED", {
        databaseId, generation, cutId,
        headLsn: head.headLsn.toString(), headTypeSequence: head.headTypeSequence.toString(),
        journalLength: verdict.length, journalHeadHash: verdict.headHash,
      });
      // re-derive the anchor AFTER the cut event so the anchored prefix
      // includes the cut itself
      const anchored = this.verifyJournal();
      if (!anchored.ok) throw new Error("CHECKPOINT_CUT_REFUSED: journal broke while cutting");
      this.sql.exec(
        `INSERT INTO checkpoint_cuts(cut_id, database_id, generation, incarnation, cut_control_seq,
           head_lsn, head_type_sequence, journal_length, journal_head_hash, state)
         VALUES (?,?,?,?,?,?,?,?,?,'PENDING')`,
        cutId, databaseId, generation, this.currentIncarnation(),
        u64Blob(cutControlSeq, "cut_control_seq"),
        head.headLsn < 0n ? null : u64Blob(head.headLsn, "head_lsn"),
        u64Blob(head.headTypeSequence, "head_type_sequence"),
        anchored.length, fromHexInternal(anchored.headHash),
      );
      return {
        ok: true as const, cutId, headLsn: head.headLsn, headTypeSequence: head.headTypeSequence,
        cutControlSeq, journalLength: anchored.length, journalHeadHash: anchored.headHash,
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
            materializations: string[]; logicalDigest: string }> | TypedErr {
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

  /** Running chain hash after the first `length` entries (0 = genesis). */
  private journalHashAt(length: number): string {
    const rows = this.sql.exec(
      `SELECT entry_hash FROM control_outbox ORDER BY control_seq LIMIT ?`, length);
    if (!rows.length) return hex(GENESIS_HASH);
    return hex(asHash(rows[rows.length - 1].entry_hash, "entry_hash"));
  }

  /** Chain-append one journal/outbox row. Caller holds the transaction. */
  private appendJournalEntry(controlSeq: bigint, databaseId: string, kind: string, canonicalBody: string): void {
    const tail = this.sql.exec(`SELECT entry_hash FROM control_outbox ORDER BY control_seq DESC LIMIT 1`);
    const prevHash = tail.length ? asHash(tail[0].entry_hash, "prev entry_hash") : GENESIS_HASH;
    const entryHash = sha256(prevHash, u64Blob(controlSeq, "control_seq"), utf8(kind), utf8(canonicalBody));
    const mac = hmacSha256(this.journalKey, entryHash);
    this.sql.exec(
      `INSERT INTO control_outbox(control_seq, database_id, kind, canonical_body, prev_hash, entry_hash, mac)
       VALUES (?,?,?,?,?,?,?)`,
      u64Blob(controlSeq, "control_seq"), databaseId, kind, canonicalBody, prevHash, entryHash, mac,
    );
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

  /** Idempotent outbox drain: publish everything unpublished, exactly once. */
  drainOutbox(publish: (row: { controlSeq: bigint; kind: string; body: string }) => void): number {
    // Publishing is external I/O; the marking is transactional per row so a
    // crash between publish and mark yields at-least-once delivery to the
    // bus, deduplicated downstream by control_seq (the exactly-once identity).
    const rows = this.sql.exec(
      `SELECT control_seq, kind, canonical_body FROM control_outbox WHERE published=0 ORDER BY control_seq`,
    );
    let published = 0;
    for (const row of rows) {
      publish({ controlSeq: u64FromSql(row.control_seq, "control_seq"), kind: String(row.kind), body: String(row.canonical_body) });
      this.sql.exec(`UPDATE control_outbox SET published=1 WHERE control_seq=?`, row.control_seq);
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
    Typed<{ acked: number }> | { ok: false; error: "SESSION_UNKNOWN" | "SESSION_FENCED" } {
    const authority = this.requireLiveSession(databaseId, startupSessionId);
    if (!authority.ok) return authority;
    const bound = u64Blob(upToControlSeq, "up_to_control_seq");
    return this.sql.transaction(() => {
      const before = Number(this.sql.exec(
        `SELECT COUNT(*) AS n FROM control_outbox WHERE published=0 AND control_seq <= ?`, bound)[0].n);
      this.sql.exec(`UPDATE control_outbox SET published=1 WHERE published=0 AND control_seq <= ?`, bound);
      return { ok: true as const, acked: before };
    });
  }

  /** Exact lookup (CT-P5): missing rows are typed NOT_FOUND, never EOF. */
  exactLookup(databaseId: string, generation: number, appendLsn: bigint):
    Typed<{ payloadKey: string; payloadDigest: string; typeSequence: bigint; recordType: number }> | TypedErr {
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
  openIterator(databaseId: string, generation: number): { headLsn: bigint } {
    const head = this.sql.exec(
      `SELECT MAX(append_lsn) AS lsn FROM wal_tail WHERE database_id=? AND generation=?`,
      databaseId, generation,
    )[0];
    return { headLsn: head.lsn === null ? -1n : u64FromSql(head.lsn, "max_append_lsn") };
  }

  /**
   * WAL head: the highest AppendLsn AND the highest TypeSequence. The
   * durability client's `current()`/`previous()` need the TypeSequence —
   * the audit's `maxLsn` is a physical position, not a sequence number.
   */
  head(databaseId: string, generation: number): { headLsn: bigint; headTypeSequence: bigint } {
    const head = this.sql.exec(
      `SELECT MAX(append_lsn) AS lsn, MAX(type_sequence) AS ts
       FROM wal_tail WHERE database_id=? AND generation=?`,
      databaseId, generation,
    )[0];
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
      `SELECT append_lsn, type_sequence, sequencing_kind, record_type, payload_key, payload_digest,
              payload_length, unsequenced_logical_key
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
      `SELECT append_lsn, type_sequence, sequencing_kind, record_type, payload_key, payload_digest,
              payload_length, unsequenced_logical_key, request_digest, control_seq
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
        `SELECT append_lsn, type_sequence, sequencing_kind, record_type, payload_key, payload_digest,
                payload_length, unsequenced_logical_key, request_digest, control_seq
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
  lastByType(databaseId: string, generation: number, recordType: number): Typed<{ record: WalDescriptor }> | TypedErr {
    const rows = this.sql.exec(
      `SELECT append_lsn, type_sequence, sequencing_kind, record_type, payload_key, payload_digest,
              payload_length, unsequenced_logical_key
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

export class BatchAbort extends Error {
  readonly result: TypedErr;

  constructor(result: TypedErr) {
    super(`batch aborted: ${result.error}`);
    this.result = result;
  }
}
