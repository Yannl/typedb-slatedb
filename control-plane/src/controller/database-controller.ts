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
import { fromHex, utf8 } from "./core/journal-crypto.ts";
import {
  checkCapability, mintCapability, MAX_CAPABILITY_BYTES, REQUIRED_RESTRICTIONS,
  type CapabilityCheck, type CapabilityPayload,
} from "./core/capability.ts";

export interface Env {
  CONTAINER_LIFECYCLE: DurableObjectNamespace;
  /** Hex journal MAC key (F8). Unset = the core's loud dev default; a
   *  managed secret is a G2 provisioning item. */
  CONTROLLER_JOURNAL_KEY?: string;
  /** Hex capability MAC key (F9) - distinct from the journal key. */
  CONTROLLER_CAPABILITY_KEY?: string;
}

export class DatabaseControllerDO extends DurableObject {
  private sql: SqlStorage;
  private readonly controllerCore: ControllerCore;
  private readonly capabilityKey: Uint8Array;

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
      // SqlStorage binds blobs as ArrayBuffer; the core hands them over as
      // Uint8Array (the u64 BE sequence encoding, F7) - convert here
      exec: (query: string, ...params: unknown[]) =>
        sql
          .exec(
            query,
            ...params.map((param) =>
              param instanceof Uint8Array
                ? param.buffer.slice(param.byteOffset, param.byteOffset + param.byteLength)
                : param,
            ),
          )
          .toArray() as SqlRow[],
      transaction: <T,>(fn: () => T): T => storage.transactionSync(fn),
    };
    this.controllerCore = new ControllerCore(adapter, {
      journalKey: env.CONTROLLER_JOURNAL_KEY ? fromHex(env.CONTROLLER_JOURNAL_KEY) : undefined,
    });
    this.capabilityKey = env.CONTROLLER_CAPABILITY_KEY
      ? fromHex(env.CONTROLLER_CAPABILITY_KEY)
      : utf8("dev-insecure-capability-key");
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

  finalizeBatch(
    reqs: FinalizeRequest[], envelope?: Parameters<ControllerCore["finalizeBatch"]>[1],
  ): ReturnType<ControllerCore["finalizeBatch"]> {
    return this.core().finalizeBatch(reqs, envelope);
  }

  registerSession(databaseId: string, generation: number, startupSessionId: string): void {
    this.core().registerSession(databaseId, generation, startupSessionId);
  }

  fenceSession(databaseId: string, startupSessionId: string): void {
    this.core().fenceSession(databaseId, startupSessionId);
  }

  setBudgets(
    databaseId: string,
    budgets: Parameters<ControllerCore["setBudgets"]>[1],
    startupSessionId: string,
  ): ReturnType<ControllerCore["setBudgets"]> {
    return this.core().setBudgets(databaseId, budgets, startupSessionId);
  }

  exactLookup(databaseId: string, generation: number, appendLsn: bigint): ReturnType<ControllerCore["exactLookup"]> {
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

  queryOperation(
    databaseId: string, generation: number, operationId: string, startupSessionId: string,
  ): ReturnType<ControllerCore["queryOperation"]> {
    return this.core().queryOperation(databaseId, generation, operationId, startupSessionId);
  }

  resolveSnapshot(databaseId: string, generation: number, snapshotId: string):
    ReturnType<ControllerCore["resolveSnapshot"]> {
    return this.core().resolveSnapshot(databaseId, generation, snapshotId);
  }

  outboxPeek(limit: number): ReturnType<ControllerCore["outboxPeek"]> {
    return this.core().outboxPeek(limit);
  }

  outboxAck(
    databaseId: string, upToControlSeq: bigint, startupSessionId: string,
  ): ReturnType<ControllerCore["outboxAck"]> {
    return this.core().outboxAck(databaseId, upToControlSeq, startupSessionId);
  }

  verifyJournal(): ReturnType<ControllerCore["verifyJournal"]> {
    return this.core().verifyJournal();
  }

  /**
   * Mint a capability (F9). In production this surface is controller-
   * internal (issued to authenticated principals during session admission);
   * on the L1 lane the facade exposes it openly - the local Worker is
   * scaffolding, not a security boundary (parity plan), and the contract
   * under proof is the DATA PATH's refusal matrix, not local issuance.
   * PUT_PAYLOAD capabilities derive the object key from the CONTENT DIGEST
   * (`p/<databaseId>/<sha256hex>`): the caller never selects an R2 key.
   */
  issueCapability(spec: {
    principal: string;
    databaseId: string;
    method: string;
    session?: string;
    digest?: string;
    maxBytes?: number;
    ttlMs?: number;
  }): { token: string; key?: string; expiresAtMs: number; incarnation: number } {
    const incarnation = this.core().currentIncarnation();
    const expiresAtMs = Date.now() + Math.min(Math.max(spec.ttlMs ?? 60_000, 1), 3_600_000);
    const key = spec.method === "PUT_PAYLOAD" && spec.digest !== undefined
      ? `p/${spec.databaseId}/${spec.digest}`
      : undefined;
    // Issuance is fail-closed on the same restriction table verification
    // enforces. Minting a PUT_PAYLOAD token with no digest/budget used to
    // produce a token that authorized ANY key, ANY body and ANY length; it
    // now produces nothing at all, so the two ends cannot disagree about
    // what a capability is allowed to leave unbound.
    const derived: Record<string, unknown> = {
      session: spec.session, key, digest: spec.digest, maxBytes: spec.maxBytes,
    };
    for (const required of REQUIRED_RESTRICTIONS[spec.method] ?? []) {
      if (derived[required] === undefined) {
        throw new Error(`CAPABILITY_RESTRICTION_MISSING: ${spec.method} requires ${required}`);
      }
    }
    if (spec.maxBytes !== undefined
        && (!Number.isSafeInteger(spec.maxBytes) || spec.maxBytes < 0 || spec.maxBytes > MAX_CAPABILITY_BYTES)) {
      throw new Error(
        `CAPABILITY_BUDGET_ABOVE_CEILING: ${spec.maxBytes} exceeds the ${MAX_CAPABILITY_BYTES}-byte data-path ceiling`);
    }
    const payload: CapabilityPayload = {
      principal: spec.principal,
      databaseId: spec.databaseId,
      method: spec.method,
      ...(spec.session !== undefined ? { session: spec.session } : {}),
      ...(key !== undefined ? { key } : {}),
      ...(spec.digest !== undefined ? { digest: spec.digest } : {}),
      ...(spec.maxBytes !== undefined ? { maxBytes: spec.maxBytes } : {}),
      incarnation,
      nonce: crypto.randomUUID(),
      expiresAtMs,
    };
    return { token: mintCapability(this.capabilityKey, payload), key, expiresAtMs, incarnation };
  }

  /**
   * Verify-and-burn a capability for one request (F9). MAC, expiry,
   * incarnation, method, audience, key, digest and budget are checked
   * synchronously; the nonce burn is the transactional single-use rule -
   * a second use of a valid token is CAPABILITY_REPLAYED.
   */
  useCapability(
    token: string,
    expect: { method: string; databaseId: string; session?: string; key?: string; bodyDigest?: string; bodyLength?: number },
  ): CapabilityCheck | { ok: false; error: "CAPABILITY_REPLAYED" } {
    const nowMs = Date.now();
    const checked = checkCapability(this.capabilityKey, token, {
      ...expect,
      currentIncarnation: this.core().currentIncarnation(),
      nowMs,
    });
    if (!checked.ok) return checked;
    if (!this.core().burnCapabilityNonce(checked.payload.nonce, checked.payload.expiresAtMs, nowMs)) {
      return { ok: false, error: "CAPABILITY_REPLAYED" };
    }
    return checked;
  }

  bumpIncarnation(): number {
    return this.core().bumpIncarnation();
  }

  openCheckpointCut(databaseId: string, generation: number, cutId: string): ReturnType<ControllerCore["openCheckpointCut"]> {
    return this.core().openCheckpointCut(databaseId, generation, cutId);
  }

  activateCheckpointCut(
    databaseId: string,
    cutId: string,
    evidence: Parameters<ControllerCore["activateCheckpointCut"]>[2],
  ): ReturnType<ControllerCore["activateCheckpointCut"]> {
    return this.core().activateCheckpointCut(databaseId, cutId, evidence);
  }

  activeCheckpointCut(databaseId: string, generation: number): ReturnType<ControllerCore["activeCheckpointCut"]> {
    return this.core().activeCheckpointCut(databaseId, generation);
  }

  verifyJournalAnchored(): ReturnType<ControllerCore["verifyJournalAnchored"]> {
    return this.core().verifyJournalAnchored();
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
