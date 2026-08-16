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

import {
  ControllerCore,
  type FinalizeRequest,
  type FinalizeResult,
  type SqlRow,
  type SyncSql,
} from "./core/procedures.ts";

export interface Env {
  CONTAINER_LIFECYCLE: DurableObjectNamespace;
}

export class DatabaseControllerDO extends DurableObject {
  private sql: SqlStorage;

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.sql = state.storage.sql;
    // authoritative projection tables (wal_tail/control_outbox/budgets/
    // sessions) are owned by ControllerCore's SCHEMA - single source of truth
    // shared with the node test lane; only DO-runtime tables live here
    this.core();
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS databases(
        database_id TEXT PRIMARY KEY,
        current_generation INTEGER NOT NULL,
        lifecycle_state TEXT NOT NULL,
        controller_incarnation_id INTEGER NOT NULL,
        control_head_seq INTEGER NOT NULL,
        journal_durable_seq INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS alarm_schedule(
        task TEXT PRIMARY KEY,
        next_due_at INTEGER NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0
      );
    `);
  }

  /**
   * WAL finalisation (CT-P3): delegates to the runtime-agnostic
   * ControllerCore over an adapter binding DO SqlStorage + transactionSync
   * to the SyncSql contract (validated by the node test suite over a real
   * SQLite). The payload was already uploaded and receipt-verified through
   * the object data path BEFORE this call; the core performs the single
   * synchronous validate -> allocate -> outbox transaction.
   */
  finalizeWalRecord(req: FinalizeRequest): FinalizeResult {
    return this.core().finalizeWalRecord(req);
  }

  finalizeBatch(reqs: FinalizeRequest[]): ReturnType<ControllerCore["finalizeBatch"]> {
    return this.core().finalizeBatch(reqs);
  }

  registerSession(databaseId: string, generation: number, startupSessionId: string): void {
    this.core().registerSession(databaseId, generation, startupSessionId);
  }

  fenceSession(databaseId: string, generation: number, startupSessionId: string): void {
    this.core().fenceSession(databaseId, generation, startupSessionId);
  }

  setBudgets(databaseId: string, budgets: Parameters<ControllerCore["setBudgets"]>[1]): void {
    this.core().setBudgets(databaseId, budgets);
  }

  exactLookup(databaseId: string, generation: number, appendLsn: number): ReturnType<ControllerCore["exactLookup"]> {
    return this.core().exactLookup(databaseId, generation, appendLsn);
  }

  auditContiguity(databaseId: string, generation: number): ReturnType<ControllerCore["auditContiguity"]> {
    return this.core().auditContiguity(databaseId, generation);
  }

  private core(): ControllerCore {
    const sql = this.sql;
    const storage = this.ctx.storage;
    const adapter: SyncSql = {
      exec: (query: string, ...params: unknown[]) => sql.exec(query, ...params).toArray() as SqlRow[],
      transaction: <T,>(fn: () => T): T => storage.transactionSync(fn),
    };
    return new ControllerCore(adapter);
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
