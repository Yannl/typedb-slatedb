/*
 * CF-P1: `DatabaseControllerDO` — the database authority (brief §4.1.2).
 *
 * Skeleton demonstrating the load-bearing structural rules; the full
 * procedure set (CT-P1..CT-P5) lands behind the G2 gate.
 *
 * Structural rules enforced here by construction:
 *  - does NOT extend the Cloudflare Container class (inv. 148);
 *  - every authoritative procedure is prepare -> [external I/O] -> one
 *    synchronous SQLite finalisation with revalidation; there is no `await`
 *    between final validation and commit (inv. 151, P-DO-01);
 *  - the transactional outbox row is inserted in the same SQLite
 *    transaction as the projection mutation (§7.4);
 *  - alarms only wake the idempotent outbox/archival reducer; schedule
 *    state is durable (inv. 154, P-DO-02);
 *  - lifecycle reports from DatabaseContainerDO are advisory observations,
 *    never authority (inv. 149).
 */

import { DurableObject } from "cloudflare:workers";

export interface Env {
  CONTAINER_LIFECYCLE: DurableObjectNamespace;
}

export class DatabaseControllerDO extends DurableObject {
  private sql: SqlStorage;

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.sql = state.storage.sql;
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS databases(
        database_id TEXT PRIMARY KEY,
        current_generation INTEGER NOT NULL,
        lifecycle_state TEXT NOT NULL,
        controller_incarnation_id INTEGER NOT NULL,
        control_head_seq INTEGER NOT NULL,
        journal_durable_seq INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS wal_tail(
        database_id TEXT NOT NULL,
        generation INTEGER NOT NULL,
        append_lsn INTEGER NOT NULL,
        type_sequence BLOB NOT NULL,          -- exact 8-byte big-endian
        sequencing_kind TEXT NOT NULL,
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
      CREATE UNIQUE INDEX IF NOT EXISTS wal_tail_status_singleton
        ON wal_tail(database_id, generation, unsequenced_logical_key)
        WHERE unsequenced_logical_key IS NOT NULL;
      CREATE TABLE IF NOT EXISTS control_outbox(
        control_seq INTEGER PRIMARY KEY,
        canonical_body BLOB NOT NULL,
        signing_key_id TEXT NOT NULL,         -- selected at commit time (§7.4)
        published INTEGER NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS alarm_schedule(
        task TEXT PRIMARY KEY,
        next_due_at INTEGER NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0
      );
    `);
  }

  /**
   * WAL finalisation (CT-P3 skeleton). The payload was already uploaded and
   * verified through the object data path; this procedure performs the
   * single-transaction late atomic allocation. All awaited work (receipt
   * verification against R2) happens BEFORE this synchronous block.
   */
  finalizeWalRecord(req: {
    databaseId: string;
    generation: number;
    startupSessionId: string;
    operationId: string;
    requestDigest: string;
    sequenced: boolean;
    logicalKey: string | null;
    payloadKey: string;
    payloadDigest: string;
    payloadLength: number;
  }): { ok: true; appendLsn: number } | { ok: false; error: string } {
    // one synchronous SQLite transaction: validate -> allocate -> outbox.
    // (storage.transactionSync exists on SQLite-backed DOs; no awaits inside.)
    return this.ctx.storage.transactionSync(() => {
      const replay = this.sql
        .exec(
          `SELECT append_lsn, request_digest FROM wal_tail
           WHERE database_id=? AND generation=? AND finalization_operation_id=?`,
          req.databaseId, req.generation, req.operationId,
        )
        .toArray();
      if (replay.length) {
        if (replay[0].request_digest === req.requestDigest) {
          return { ok: true as const, appendLsn: Number(replay[0].append_lsn) };
        }
        return { ok: false as const, error: "OPERATION_DIGEST_CONFLICT" };
      }
      // ... session/epoch/lifecycle revalidation + singleton checks and the
      // late atomic allocation of TypeSequence/AppendLsn/ControlSeq land
      // here (CT-P2/CT-P3); the outbox row is inserted in this same
      // transaction.
      return { ok: false as const, error: "NOT_IMPLEMENTED_BEFORE_G2" };
    });
  }

  /** Alarms: at-least-once wakeups driving an idempotent reducer only. */
  async alarm(): Promise<void> {
    const due = this.sql
      .exec(`SELECT task, next_due_at, attempts FROM alarm_schedule`)
      .toArray();
    for (const row of due) {
      try {
        // idempotent: outbox flush / archival step; progress is re-derived
        // from durable state, never from the alarm invocation count.
      } catch {
        this.sql.exec(
          `UPDATE alarm_schedule SET attempts = attempts + 1, next_due_at = ?
           WHERE task = ?`,
          Date.now() + Math.min(60_000 * 2 ** Number(row.attempts), 3_600_000),
          row.task,
        );
      }
    }
    const next = this.sql
      .exec(`SELECT MIN(next_due_at) AS n FROM alarm_schedule`)
      .one() as { n: number | null };
    if (next.n !== null) await this.ctx.storage.setAlarm(next.n);
  }
}
