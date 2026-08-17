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
    append_lsn INTEGER NOT NULL,
    type_sequence INTEGER NOT NULL,
    sequencing_kind TEXT NOT NULL CHECK(sequencing_kind IN ('SEQUENCED','UNSEQUENCED')),
    payload_key TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    payload_length INTEGER NOT NULL,
    finalization_operation_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    unsequenced_logical_key TEXT,
    startup_session_id TEXT NOT NULL,
    control_seq INTEGER NOT NULL,
    record_type INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(database_id, generation, append_lsn),
    UNIQUE(database_id, generation, finalization_operation_id)
  );
  CREATE UNIQUE INDEX IF NOT EXISTS wal_status_singleton
    ON wal_tail(database_id, generation, unsequenced_logical_key)
    WHERE unsequenced_logical_key IS NOT NULL;
  CREATE INDEX IF NOT EXISTS wal_type_scan
    ON wal_tail(database_id, generation, record_type, append_lsn);
  CREATE TABLE IF NOT EXISTS control_outbox(
    control_seq INTEGER PRIMARY KEY,
    database_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    canonical_body TEXT NOT NULL,
    published INTEGER NOT NULL DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS budgets(
    database_id TEXT PRIMARY KEY,
    max_unpublished_outbox INTEGER NOT NULL,
    max_payload_length INTEGER NOT NULL,
    max_tail_records INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions(
    database_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    startup_session_id TEXT NOT NULL,
    fenced INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(database_id, generation, startup_session_id)
  );
`;

/** V16 exactness rule: authoritative u64 sequence values (AppendLsn,
 *  TypeSequence, ControlSeq) must stay exact. SQLite stores i64 and
 *  JavaScript `number` is exact only to 2^53-1, so any sequence at or beyond
 *  that bound - or non-integral, or below the -1 empty-head sentinel - is an
 *  invariant catastrophe and fails CLOSED here instead of silently rounding.
 *  (The full fixed-width big-endian blob representation is staged:
 *  docs/reviews/v16-convergence-audit.md F7.) */
function exactU64(value: unknown, context: string): number {
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

/** One catalogued WAL tail row, as returned by the scan/last read paths. */
export interface WalDescriptor {
  appendLsn: number;
  typeSequence: number;
  sequencingKind: string;
  recordType: number;
  payloadKey: string;
  payloadDigest: string;
  payloadLength: number;
  logicalKey: string | null;
}

export type FinalizeResult = Typed<{ appendLsn: number; typeSequence: number; controlSeq: number; replayed: boolean }> | TypedErr;

export class ControllerCore {
  private readonly sql: SyncSql;

  constructor(sql: SyncSql) {
    this.sql = sql;
    this.sql.exec(SCHEMA);
    // pre-record_type dev state (CREATE TABLE IF NOT EXISTS cannot add
    // columns to an existing table): additive migration, idempotent
    try {
      this.sql.exec(`ALTER TABLE wal_tail ADD COLUMN record_type INTEGER NOT NULL DEFAULT 0`);
    } catch {
      // column already exists
    }
  }

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
      this.sql.exec(
        `UPDATE sessions SET fenced=1 WHERE database_id=? AND startup_session_id<>?`,
        databaseId, startupSessionId,
      );
      this.sql.exec(
        `INSERT OR IGNORE INTO sessions(database_id, generation, startup_session_id) VALUES (?,?,?)`,
        databaseId, generation, startupSessionId,
      );
    });
  }

  fenceSession(databaseId: string, startupSessionId: string): void {
    // The authority unit is the ACTOR (see registerSession): fencing revokes
    // the actor's append authority across every generation it registered —
    // a per-generation fence would leave a rollover-spanning actor half
    // fenced (blocked from re-registering, still able to append elsewhere).
    this.sql.exec(
      `UPDATE sessions SET fenced=1 WHERE database_id=? AND startup_session_id=?`,
      databaseId, startupSessionId,
    );
  }

  setBudgets(databaseId: string, b: { maxUnpublishedOutbox: number; maxPayloadLength: number; maxTailRecords: number }): void {
    this.sql.exec(
      `INSERT OR REPLACE INTO budgets(database_id, max_unpublished_outbox, max_payload_length, max_tail_records)
       VALUES (?,?,?,?)`,
      databaseId, b.maxUnpublishedOutbox, b.maxPayloadLength, b.maxTailRecords,
    );
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
      // Attribution, not authority (hydradb comparative review): the fenced
      // actor learns WHO superseded it — epochs/fences alone carry no
      // identity, and the first question in a fence incident is "who is the
      // writer now?". Served from the authority row read-only; it can never
      // change the outcome.
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
          appendLsn: exactU64(replay[0].append_lsn, "append_lsn"),
          typeSequence: exactU64(replay[0].type_sequence, "type_sequence"),
          controlSeq: exactU64(replay[0].control_seq, "control_seq"),
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
          return {
            ok: true as const,
            appendLsn: exactU64(existing[0].append_lsn, "append_lsn"),
            typeSequence: exactU64(existing[0].type_sequence, "type_sequence"),
            controlSeq: exactU64(existing[0].control_seq, "control_seq"),
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
    // global ControlSeq - all inside the caller's transaction.
    const head = this.sql.exec(
      `SELECT COALESCE(MAX(append_lsn), -1) AS lsn, COALESCE(MAX(type_sequence), 0) AS ts
       FROM wal_tail WHERE database_id=? AND generation=?`,
      req.databaseId, req.generation,
    )[0];
    const appendLsn = exactU64(head.lsn, "max_append_lsn") + 1;
    const typeSequence =
      req.sequencingKind === "SEQUENCED" ? exactU64(head.ts, "max_type_sequence") + 1 : exactU64(head.ts, "max_type_sequence");
    const controlSeq =
      exactU64(this.sql.exec(`SELECT COALESCE(MAX(control_seq), 0) AS c FROM control_outbox`)[0].c, "max_control_seq") + 1;

    this.sql.exec(
      `INSERT INTO wal_tail(database_id, generation, append_lsn, type_sequence, sequencing_kind,
         payload_key, payload_digest, payload_length, finalization_operation_id, request_digest,
         unsequenced_logical_key, startup_session_id, control_seq, record_type)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      req.databaseId, req.generation, appendLsn, typeSequence, req.sequencingKind,
      req.payloadKey, req.payloadDigest, req.payloadLength, req.operationId, req.requestDigest,
      req.logicalKey, req.startupSessionId, controlSeq, req.recordType,
    );
    // outbox row in the SAME transaction as the projection mutation (section 7.4)
    this.sql.exec(
      `INSERT INTO control_outbox(control_seq, database_id, kind, canonical_body)
       VALUES (?,?,?,?)`,
      controlSeq, req.databaseId, "WAL_RECORD_FINALIZED",
      JSON.stringify({ databaseId: req.databaseId, generation: req.generation, appendLsn, typeSequence,
                       sequencingKind: req.sequencingKind, recordType: req.recordType,
                       payloadKey: req.payloadKey,
                       payloadDigest: req.payloadDigest, logicalKey: req.logicalKey }),
    );
    return { ok: true as const, appendLsn, typeSequence, controlSeq, replayed: false };
  }

  /** Idempotent outbox drain: publish everything unpublished, exactly once. */
  drainOutbox(publish: (row: { controlSeq: number; kind: string; body: string }) => void): number {
    // Publishing is external I/O; the marking is transactional per row so a
    // crash between publish and mark yields at-least-once delivery to the
    // bus, deduplicated downstream by control_seq (the exactly-once identity).
    const rows = this.sql.exec(
      `SELECT control_seq, kind, canonical_body FROM control_outbox WHERE published=0 ORDER BY control_seq`,
    );
    let published = 0;
    for (const row of rows) {
      publish({ controlSeq: Number(row.control_seq), kind: String(row.kind), body: String(row.canonical_body) });
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
  outboxPeek(limit: number): { controlSeq: number; kind: string; body: string }[] {
    return this.sql
      .exec(`SELECT control_seq, kind, canonical_body FROM control_outbox
             WHERE published=0 ORDER BY control_seq LIMIT ?`, limit)
      .map((row) => ({ controlSeq: Number(row.control_seq), kind: String(row.kind), body: String(row.canonical_body) }));
  }

  outboxAck(upToControlSeq: number): number {
    return this.sql.transaction(() => {
      const before = Number(this.sql.exec(
        `SELECT COUNT(*) AS n FROM control_outbox WHERE published=0 AND control_seq <= ?`, upToControlSeq)[0].n);
      this.sql.exec(`UPDATE control_outbox SET published=1 WHERE published=0 AND control_seq <= ?`, upToControlSeq);
      return before;
    });
  }

  /** Exact lookup (CT-P5): missing rows are typed NOT_FOUND, never EOF. */
  exactLookup(databaseId: string, generation: number, appendLsn: number):
    Typed<{ payloadKey: string; payloadDigest: string; typeSequence: number; recordType: number }> | TypedErr {
    const rows = this.sql.exec(
      `SELECT payload_key, payload_digest, type_sequence, record_type FROM wal_tail
       WHERE database_id=? AND generation=? AND append_lsn=?`,
      databaseId, generation, appendLsn,
    );
    if (!rows.length) return { ok: false, error: "NOT_FOUND" };
    return {
      ok: true,
      payloadKey: String(rows[0].payload_key),
      payloadDigest: String(rows[0].payload_digest),
      typeSequence: Number(rows[0].type_sequence),
      recordType: Number(rows[0].record_type),
    };
  }

  /** Fixed iterator snapshot (CT-P3): head is pinned at open; reads are exact. */
  openIterator(databaseId: string, generation: number): { headLsn: number } {
    const head = this.sql.exec(
      `SELECT COALESCE(MAX(append_lsn), -1) AS lsn FROM wal_tail WHERE database_id=? AND generation=?`,
      databaseId, generation,
    )[0];
    return { headLsn: Number(head.lsn) };
  }

  /**
   * WAL head: the highest AppendLsn AND the highest TypeSequence. The
   * durability client's `current()`/`previous()` need the TypeSequence —
   * the audit's `maxLsn` is a physical position, not a sequence number.
   */
  head(databaseId: string, generation: number): { headLsn: number; headTypeSequence: number } {
    const head = this.sql.exec(
      `SELECT COALESCE(MAX(append_lsn), -1) AS lsn, COALESCE(MAX(type_sequence), 0) AS ts
       FROM wal_tail WHERE database_id=? AND generation=?`,
      databaseId, generation,
    )[0];
    return { headLsn: Number(head.lsn), headTypeSequence: Number(head.ts) };
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
    opts: { fromTypeSequence: number; fromLsn: number; throughLsn: number; recordType: number | null; limit: number },
  ): { records: WalDescriptor[]; nextFromLsn: number | null } {
    // a non-positive limit would page nothing yet compute nextFromLsn from an
    // empty slice (crash); clamp defensively — the HTTP route validates, but
    // the DO method is directly callable
    const limit = Math.max(1, Math.floor(opts.limit));
    const typeFilter = opts.recordType === null ? "" : "AND record_type=?";
    const params: unknown[] = [databaseId, generation, opts.fromTypeSequence, opts.fromLsn, opts.throughLsn];
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
    const nextFromLsn = rows.length > limit ? page[page.length - 1].appendLsn + 1 : null;
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
  queryOperation(databaseId: string, generation: number, operationId: string):
    Typed<{ record: WalDescriptor; requestDigest: string; controlSeq: number }> | TypedErr {
    const rows = this.sql.exec(
      `SELECT append_lsn, type_sequence, sequencing_kind, record_type, payload_key, payload_digest,
              payload_length, unsequenced_logical_key, request_digest, control_seq
       FROM wal_tail WHERE database_id=? AND generation=? AND finalization_operation_id=?`,
      databaseId, generation, operationId,
    );
    if (!rows.length) return { ok: false, error: "NOT_FOUND" };
    return {
      ok: true,
      record: descriptorOf(rows[0]),
      requestDigest: String(rows[0].request_digest),
      controlSeq: exactU64(rows[0].control_seq, "control_seq"),
    };
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
  auditContiguity(databaseId: string, generation: number): { contiguous: boolean; count: number; maxLsn: number } {
    const r = this.sql.exec(
      `SELECT COUNT(*) AS n, COALESCE(MAX(append_lsn), -1) AS m
       FROM wal_tail WHERE database_id=? AND generation=?`,
      databaseId, generation,
    )[0];
    return { contiguous: Number(r.n) === Number(r.m) + 1, count: Number(r.n), maxLsn: Number(r.m) };
  }
}

function descriptorOf(row: SqlRow): WalDescriptor {
  return {
    appendLsn: exactU64(row.append_lsn, "append_lsn"),
    typeSequence: exactU64(row.type_sequence, "type_sequence"),
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
