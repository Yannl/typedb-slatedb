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
  private readonly controllerCore: ControllerCore;

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.sql = state.storage.sql;
    // authoritative projection tables (wal_tail/control_outbox/budgets/
    // sessions) are owned by ControllerCore's SCHEMA - single source of truth
    // shared with the node test lane; built ONCE per DO instantiation (the
    // constructor runs the schema DDL). Only DO-runtime tables live here.
    const sql = this.sql;
    const storage = this.ctx.storage;
    const adapter: SyncSql = {
      exec: (query: string, ...params: unknown[]) => sql.exec(query, ...params).toArray() as SqlRow[],
      transaction: <T,>(fn: () => T): T => storage.transactionSync(fn),
    };
    this.controllerCore = new ControllerCore(adapter);
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
        interval_ms INTEGER NOT NULL DEFAULT 60000,
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

  fenceSession(databaseId: string, startupSessionId: string): void {
    this.core().fenceSession(databaseId, startupSessionId);
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

  head(databaseId: string, generation: number): ReturnType<ControllerCore["head"]> {
    return this.core().head(databaseId, generation);
  }

  openIterator(databaseId: string, generation: number): ReturnType<ControllerCore["openIterator"]> {
    return this.core().openIterator(databaseId, generation);
  }

  scan(
    databaseId: string,
    generation: number,
    opts: Parameters<ControllerCore["scan"]>[2],
  ): ReturnType<ControllerCore["scan"]> {
    return this.core().scan(databaseId, generation, opts);
  }

  lastByType(databaseId: string, generation: number, recordType: number): ReturnType<ControllerCore["lastByType"]> {
    return this.core().lastByType(databaseId, generation, recordType);
  }

  queryOperation(databaseId: string, generation: number, operationId: string): ReturnType<ControllerCore["queryOperation"]> {
    return this.core().queryOperation(databaseId, generation, operationId);
  }

  outboxPeek(limit: number): ReturnType<ControllerCore["outboxPeek"]> {
    return this.core().outboxPeek(limit);
  }

  outboxAck(upToControlSeq: number): number {
    return this.core().outboxAck(upToControlSeq);
  }

  private core(): ControllerCore {
    return this.controllerCore;
  }

  /** Register (or reschedule) a periodic task and arm the alarm. */
  async scheduleTask(task: string, intervalMs: number): Promise<void> {
    const now = Date.now();
    this.sql.exec(
      `INSERT OR REPLACE INTO alarm_schedule(task, next_due_at, interval_ms, attempts)
       VALUES (?,?,?,0)`,
      task, now + intervalMs, intervalMs,
    );
    await this.armAlarm();
  }

  /**
   * Alarms: at-least-once wakeups driving idempotent reducers only. Progress
   * is re-derived from durable state, never from the invocation count. Every
   * pass MUST advance next_due_at (success: now+interval; failure: bounded
   * exponential backoff) so the alarm is always re-armed into the future -
   * an unchanged past timestamp would busy-loop the DO.
   */
  async alarm(): Promise<void> {
    const now = Date.now();
    const due = this.sql
      .exec(`SELECT task, interval_ms, attempts FROM alarm_schedule WHERE next_due_at <= ?`, now)
      .toArray();
    for (const row of due) {
      try {
        this.runScheduledTask(String(row.task));
        this.sql.exec(
          `UPDATE alarm_schedule SET attempts = 0, next_due_at = ? WHERE task = ?`,
          now + Number(row.interval_ms), row.task,
        );
      } catch {
        this.sql.exec(
          `UPDATE alarm_schedule SET attempts = attempts + 1, next_due_at = ? WHERE task = ?`,
          now + Math.min(60_000 * 2 ** Number(row.attempts), 3_600_000),
          row.task,
        );
      }
    }
    await this.armAlarm();
  }

  /** Dispatch table for scheduled work; all handlers must be idempotent. */
  private runScheduledTask(task: string): void {
    switch (task) {
      // outbox delivery is consumer-driven (peek/ack); no push tasks are
      // scheduled yet. Unknown tasks throw so the backoff path bounds them.
      default:
        throw new Error(`unknown scheduled task: ${task}`);
    }
  }

  private async armAlarm(): Promise<void> {
    const next = this.sql
      .exec(`SELECT MIN(next_due_at) AS n FROM alarm_schedule`)
      .one() as { n: number | null };
    if (next.n !== null) await this.ctx.storage.setAlarm(Number(next.n));
  }
}
