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
    PRIMARY KEY(database_id, generation, append_lsn),
    UNIQUE(database_id, generation, finalization_operation_id)
  );
  CREATE UNIQUE INDEX IF NOT EXISTS wal_status_singleton
    ON wal_tail(database_id, generation, unsequenced_logical_key)
    WHERE unsequenced_logical_key IS NOT NULL;
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

export type Typed<TOk> = { ok: true } & TOk;
export type TypedErr =
  | { ok: false; error: "ADMISSION_REJECTED_OUTBOX_DEPTH"; limit: number }
  | { ok: false; error: "ADMISSION_REJECTED_PAYLOAD_LENGTH"; limit: number }
  | { ok: false; error: "ADMISSION_REJECTED_TAIL_BUDGET"; limit: number }
  | { ok: false; error: "OPERATION_DIGEST_CONFLICT" }
  | { ok: false; error: "STATUS_CONFLICT" }
  | { ok: false; error: "SESSION_FENCED" }
  | { ok: false; error: "SESSION_UNKNOWN" }
  | { ok: false; error: "NOT_FOUND" };

export interface FinalizeRequest {
  databaseId: string;
  generation: number;
  startupSessionId: string;
  operationId: string;
  requestDigest: string;
  sequencingKind: "SEQUENCED" | "UNSEQUENCED";
  logicalKey: string | null;
  payloadKey: string;
  payloadDigest: string;
  payloadLength: number;
}

export type FinalizeResult = Typed<{ appendLsn: number; typeSequence: number; controlSeq: number; replayed: boolean }> | TypedErr;

export class ControllerCore {
  private readonly sql: SyncSql;

  constructor(sql: SyncSql) {
    this.sql = sql;
    this.sql.exec(SCHEMA);
  }

  registerSession(databaseId: string, generation: number, startupSessionId: string): void {
    this.sql.exec(
      `INSERT OR IGNORE INTO sessions(database_id, generation, startup_session_id) VALUES (?,?,?)`,
      databaseId, generation, startupSessionId,
    );
  }

  fenceSession(databaseId: string, generation: number, startupSessionId: string): void {
    this.sql.exec(
      `UPDATE sessions SET fenced=1 WHERE database_id=? AND generation=? AND startup_session_id=?`,
      databaseId, generation, startupSessionId,
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
          appendLsn: Number(replay[0].append_lsn),
          typeSequence: Number(replay[0].type_sequence),
          controlSeq: Number(replay[0].control_seq),
          replayed: true,
        };
      }
      return { ok: false as const, error: "OPERATION_DIGEST_CONFLICT" as const };
    }

    // session revalidation (stale-actor fencing)
    const session = this.sql.exec(
      `SELECT fenced FROM sessions WHERE database_id=? AND generation=? AND startup_session_id=?`,
      req.databaseId, req.generation, req.startupSessionId,
    );
    if (!session.length) return { ok: false as const, error: "SESSION_UNKNOWN" as const };
    if (Number(session[0].fenced)) return { ok: false as const, error: "SESSION_FENCED" as const };

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
            appendLsn: Number(existing[0].append_lsn),
            typeSequence: Number(existing[0].type_sequence),
            controlSeq: Number(existing[0].control_seq),
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
    const appendLsn = Number(head.lsn) + 1;
    const typeSequence = req.sequencingKind === "SEQUENCED" ? Number(head.ts) + 1 : Number(head.ts);
    const controlSeq =
      Number(this.sql.exec(`SELECT COALESCE(MAX(control_seq), 0) AS c FROM control_outbox`)[0].c) + 1;

    this.sql.exec(
      `INSERT INTO wal_tail(database_id, generation, append_lsn, type_sequence, sequencing_kind,
         payload_key, payload_digest, payload_length, finalization_operation_id, request_digest,
         unsequenced_logical_key, startup_session_id, control_seq)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      req.databaseId, req.generation, appendLsn, typeSequence, req.sequencingKind,
      req.payloadKey, req.payloadDigest, req.payloadLength, req.operationId, req.requestDigest,
      req.logicalKey, req.startupSessionId, controlSeq,
    );
    // outbox row in the SAME transaction as the projection mutation (section 7.4)
    this.sql.exec(
      `INSERT INTO control_outbox(control_seq, database_id, kind, canonical_body)
       VALUES (?,?,?,?)`,
      controlSeq, req.databaseId, "WAL_RECORD_FINALIZED",
      JSON.stringify({ databaseId: req.databaseId, generation: req.generation, appendLsn, typeSequence,
                       sequencingKind: req.sequencingKind, payloadKey: req.payloadKey,
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
    Typed<{ payloadKey: string; payloadDigest: string; typeSequence: number }> | TypedErr {
    const rows = this.sql.exec(
      `SELECT payload_key, payload_digest, type_sequence FROM wal_tail
       WHERE database_id=? AND generation=? AND append_lsn=?`,
      databaseId, generation, appendLsn,
    );
    if (!rows.length) return { ok: false, error: "NOT_FOUND" };
    return {
      ok: true,
      payloadKey: String(rows[0].payload_key),
      payloadDigest: String(rows[0].payload_digest),
      typeSequence: Number(rows[0].type_sequence),
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

export class BatchAbort extends Error {
  readonly result: TypedErr;

  constructor(result: TypedErr) {
    super(`batch aborted: ${result.error}`);
    this.result = result;
  }
}
