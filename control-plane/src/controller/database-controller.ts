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
import { resolveKeyConfig } from "./core/key-config.ts";
import {
  checkCapability, isKnownCapabilityMethod, mintCapability, MAX_CAPABILITY_BYTES, REQUIRED_RESTRICTIONS,
  type CapabilityCheck, type CapabilityPayload,
} from "./core/capability.ts";
import {
  bindingsEqual, checkBinding, checkProvisionToken, type ProvisionBinding,
} from "./core/registry.ts";

/** Typed refusals of the registry-binding gate (R4 PR1): every ordinary
 *  call to an authority that has not been provisioned - or that is
 *  provisioned as a DIFFERENT tenant/database/environment than the caller's
 *  verified token names - fails closed with one of these. */
export type BindingRefusal =
  | { ok: false; error: "DATABASE_UNPROVISIONED" }
  | { ok: false; error: "DO_BINDING_MISMATCH" };

export interface Env {
  /** Q-24: key posture. "managed" (the default when unset - a lost variable
   *  refuses, it never downgrades) requires provisioned hex keys via the
   *  variables below; "local-dev" is the L1 scaffolding posture with loud
   *  dev constants. Resolution and policy: core/key-config.ts. */
  CONTROLLER_KEY_PROFILE?: string;
  CONTROLLER_JOURNAL_KEY?: string;
  CONTROLLER_CAPABILITY_KEY?: string;
  /** R4 PR1: PROVISION-scope verification key + environment name. */
  CONTROLLER_PROVISION_KEY?: string;
  CONTROLLER_ENVIRONMENT?: string;
  CONTROLLER_ISSUER_SECRET?: string;
}

export class DatabaseControllerDO extends DurableObject {
  private sql: SqlStorage;
  private readonly controllerCore: ControllerCore;
  private readonly capabilityKey: Uint8Array;
  private readonly provisionKey: Uint8Array;
  private readonly environment: string;

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
    // Q-24: fail closed on key configuration. resolveKeyConfig THROWS on a
    // managed deployment with absent/empty/malformed/dev-constant keys,
    // which fails DO construction, which makes every route on this
    // authority refuse - there is no downgrade path from inside the
    // process, and no route that serves before the check runs.
    const keys = resolveKeyConfig(env);
    this.controllerCore = new ControllerCore(adapter, { journalKey: keys.journalKey });
    this.capabilityKey = keys.capabilityKey;
    this.provisionKey = keys.provisionKey;
    this.environment = keys.environment;
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
      CREATE TABLE IF NOT EXISTS do_binding(
        key TEXT PRIMARY KEY CHECK(key IN ('environment','tenant_id','database_id')),
        value TEXT NOT NULL
      );
    `);
  }

  /** The provisioned registry record of this authority, or null before
   *  provisioning. Three rows so the binding is one durable fact per
   *  field, written only inside the provisioning transaction. */
  private boundBinding(): ProvisionBinding | null {
    const rows = this.sql.exec(`SELECT key, value FROM do_binding`).toArray();
    if (!rows.length) return null;
    const byKey = new Map(rows.map((row) => [String(row.key), String(row.value)]));
    const environment = byKey.get("environment");
    const tenantId = byKey.get("tenant_id");
    const databaseId = byKey.get("database_id");
    if (environment === undefined || tenantId === undefined || databaseId === undefined) {
      // a partial binding must be impossible (single provisioning
      // transaction); observing one is a consistency violation, not a state
      throw new Error("DO_BINDING_CORRUPT: partial provisioning record");
    }
    return { environment, tenantId, databaseId };
  }

  /**
   * R4 PR1: the provisioning transaction - the ONLY path that binds this
   * uninitialized authority to a registry record, and it binds exactly
   * once. The caller (worker /provision route) has already frame-checked
   * the PROVISION token; this re-verifies it AUTHORITATIVELY under the
   * DO's own provisioning-scope key and environment, then writes the
   * binding + initial budgets + the DATABASE_PROVISIONED journal row in
   * one synchronous transaction. Two racing provisioners are serialized by
   * the DO: the first writes the record, the second gets the idempotent
   * replay (identical binding) or the typed conflict (different binding) -
   * never a partial or overwritten binding.
   */
  provision(
    token: string,
    wireBinding: { environment?: unknown; tenantId?: unknown; databaseId?: unknown },
    budgets?: { maxUnpublishedOutbox: number; maxPayloadLength: number; maxTailRecords: number },
  ):
    | { ok: true; created: boolean; binding: ProvisionBinding }
    | { ok: false; error: string; field?: string } {
    const checked = checkBinding(wireBinding);
    if (!checked.ok) return checked;
    const binding = checked.binding;
    if (binding.environment !== this.environment) {
      return { ok: false, error: "PROVISION_ENVIRONMENT_MISMATCH" };
    }
    const verdict = checkProvisionToken(this.provisionKey, token, {
      binding, nowMs: this.controllerCore.controllerNow(),
    });
    if (!verdict.ok) return verdict;
    return this.ctx.storage.transactionSync(() => {
      const bound = this.boundBinding();
      if (bound !== null) {
        if (bindingsEqual(bound, binding)) return { ok: true as const, created: false, binding: bound };
        // the race loser (or a later conflicting provisioner): typed
        // refusal, the standing record is never overwritten
        return { ok: false as const, error: "PROVISION_CONFLICT" };
      }
      const provisioned = this.controllerCore.provisionDatabase(binding, budgets);
      if (!provisioned.ok) return provisioned;
      this.sql.exec(`INSERT INTO do_binding(key, value) VALUES ('environment', ?)`, binding.environment);
      this.sql.exec(`INSERT INTO do_binding(key, value) VALUES ('tenant_id', ?)`, binding.tenantId);
      this.sql.exec(`INSERT INTO do_binding(key, value) VALUES ('database_id', ?)`, binding.databaseId);
      return { ok: true as const, created: true, binding };
    });
  }

  /** Read the provisioned registry record (worker bootstrap verification /
   *  tests). Null means unprovisioned - and unprovisioned serves nothing. */
  getBinding(): ProvisionBinding | null {
    return this.boundBinding();
  }

  /**
   * The registry-binding gate for the capability entry points (R4 PR1,
   * audit 4.4 items 1-2): an authority with NO provisioned record refuses
   * every ordinary call with a typed error and NO binding side effect
   * (first-call squatting is dead - only `provision` writes the record),
   * and a provisioned authority refuses any call whose verified token
   * names a different tenant/database/environment than the record.
   */
  private requireBinding(expect: { databaseId: string; tenantId?: string }): BindingRefusal | null {
    const bound = this.boundBinding();
    if (bound === null) return { ok: false, error: "DATABASE_UNPROVISIONED" };
    if (bound.environment !== this.environment || bound.databaseId !== expect.databaseId
        || (expect.tenantId !== undefined && bound.tenantId !== expect.tenantId)) {
      return { ok: false, error: "DO_BINDING_MISMATCH" };
    }
    return null;
  }

  /**
   * Immutable database binding (audit C-P0-02), now backed by the
   * provisioned registry record: every direct authority procedure asserts
   * the presented identity is exactly the provisioned one. These RPCs sit
   * BEHIND the worker's capability verification (which already answers the
   * typed requireBinding refusals), so a violation here is a mis-routed or
   * forged internal call - it throws as a hard defense-in-depth failure
   * rather than a wire shape. Unlike the pre-PR1 first-authenticated-call
   * binding, this NEVER writes: an unprovisioned authority cannot be bound
   * by any amount of calling.
   */
  private bind(databaseId: string): void {
    if (typeof databaseId !== "string" || databaseId.length === 0) {
      throw new Error("DO_DATABASE_BINDING_VIOLATION: empty database identity");
    }
    const bound = this.boundBinding();
    if (bound === null) {
      throw new Error("DO_DATABASE_BINDING_VIOLATION: authority is not provisioned");
    }
    if (bound.databaseId !== databaseId) {
      throw new Error(
        `DO_DATABASE_BINDING_VIOLATION: this authority is bound to another database; ` +
          `presented ${JSON.stringify(databaseId)}`,
      );
    }
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
    this.bind(req.databaseId);
    return this.controllerCore.finalizeWalRecord(req);
  }

  finalizeBatch(
    reqs: FinalizeRequest[], envelope?: Parameters<ControllerCore["finalizeBatch"]>[1],
  ): ReturnType<ControllerCore["finalizeBatch"]> {
    if (reqs.length) this.bind(reqs[0].databaseId);
    return this.controllerCore.finalizeBatch(reqs, envelope);
  }

  registerSession(databaseId: string, generation: number, startupSessionId: string): void {
    this.bind(databaseId);
    this.controllerCore.registerSession(databaseId, generation, startupSessionId);
  }

  reserveSession(databaseId: string, generation: number, startupSessionId: string, holder: string):
    ReturnType<ControllerCore["reserveSession"]> {
    this.bind(databaseId);
    return this.controllerCore.reserveSession(databaseId, generation, startupSessionId, holder);
  }

  attestSession(databaseId: string, startupSessionId: string, processNonce: string):
    ReturnType<ControllerCore["attestSession"]> {
    this.bind(databaseId);
    return this.controllerCore.attestSession(databaseId, startupSessionId, processNonce);
  }

  activateSession(
    databaseId: string, startupSessionId: string,
    proof: Parameters<ControllerCore["activateSession"]>[2],
  ): ReturnType<ControllerCore["activateSession"]> {
    this.bind(databaseId);
    return this.controllerCore.activateSession(databaseId, startupSessionId, proof);
  }

  renewLease(databaseId: string, startupSessionId: string, leaseMs: number):
    ReturnType<ControllerCore["renewLease"]> {
    this.bind(databaseId);
    return this.controllerCore.renewLease(databaseId, startupSessionId, leaseMs);
  }

  beginDrain(databaseId: string, startupSessionId: string): ReturnType<ControllerCore["beginDrain"]> {
    this.bind(databaseId);
    return this.controllerCore.beginDrain(databaseId, startupSessionId);
  }

  revokeSession(databaseId: string, startupSessionId: string): ReturnType<ControllerCore["revokeSession"]> {
    this.bind(databaseId);
    return this.controllerCore.revokeSession(databaseId, startupSessionId);
  }

  fenceSession(databaseId: string, startupSessionId: string): void {
    this.bind(databaseId);
    this.controllerCore.fenceSession(databaseId, startupSessionId);
  }

  /** R4-SEC-05: use-time revalidation for read authority (see core). */
  assertActiveReader(databaseId: string, startupSessionId: string, generation: number):
    ReturnType<ControllerCore["assertActiveReader"]> {
    this.bind(databaseId);
    return this.controllerCore.assertActiveReader(databaseId, startupSessionId, generation);
  }

  setBudgets(
    databaseId: string,
    budgets: Parameters<ControllerCore["setBudgets"]>[1],
    startupSessionId: string,
  ): ReturnType<ControllerCore["setBudgets"]> {
    this.bind(databaseId);
    return this.controllerCore.setBudgets(databaseId, budgets, startupSessionId);
  }

  exactLookup(databaseId: string, generation: number, appendLsn: bigint): ReturnType<ControllerCore["exactLookup"]> {
    this.bind(databaseId);
    return this.controllerCore.exactLookup(databaseId, generation, appendLsn);
  }

  auditContiguity(databaseId: string, generation: number): ReturnType<ControllerCore["auditContiguity"]> {
    this.bind(databaseId);
    return this.controllerCore.auditContiguity(databaseId, generation);
  }

  head(databaseId: string, generation: number): ReturnType<ControllerCore["head"]> {
    this.bind(databaseId);
    return this.controllerCore.head(databaseId, generation);
  }

  openIterator(databaseId: string, generation: number): ReturnType<ControllerCore["openIterator"]> {
    this.bind(databaseId);
    return this.controllerCore.openIterator(databaseId, generation);
  }

  scan(
    databaseId: string,
    generation: number,
    opts: Parameters<ControllerCore["scan"]>[2],
  ): ReturnType<ControllerCore["scan"]> {
    this.bind(databaseId);
    return this.controllerCore.scan(databaseId, generation, opts);
  }

  lastByType(databaseId: string, generation: number, recordType: number): ReturnType<ControllerCore["lastByType"]> {
    this.bind(databaseId);
    return this.controllerCore.lastByType(databaseId, generation, recordType);
  }

  queryOperation(
    databaseId: string, generation: number, operationId: string, startupSessionId: string,
  ): ReturnType<ControllerCore["queryOperation"]> {
    this.bind(databaseId);
    return this.controllerCore.queryOperation(databaseId, generation, operationId, startupSessionId);
  }

  resolveSnapshot(databaseId: string, generation: number, snapshotId: string):
    ReturnType<ControllerCore["resolveSnapshot"]> {
    this.bind(databaseId);
    return this.controllerCore.resolveSnapshot(databaseId, generation, snapshotId);
  }

  outboxPeek(limit: number): ReturnType<ControllerCore["outboxPeek"]> {
    return this.controllerCore.outboxPeek(limit);
  }

  outboxAck(
    databaseId: string, upToControlSeq: bigint, startupSessionId: string,
  ): ReturnType<ControllerCore["outboxAck"]> {
    this.bind(databaseId);
    return this.controllerCore.outboxAck(databaseId, upToControlSeq, startupSessionId);
  }

  verifyJournal(): ReturnType<ControllerCore["verifyJournal"]> {
    return this.controllerCore.verifyJournal();
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
    generation?: number;
    digest?: string;
    maxBytes?: number;
    ttlMs?: number;
  }): { token: string; key?: string; expiresAtMs: number; incarnation: number } {
    // R4 PR1: issuance embeds the PROVISIONED binding (env + tenant), so it
    // is impossible before provisioning - the dev issuer cannot be used to
    // squat an unbound authority either.
    const binding = this.boundBinding();
    if (binding === null) throw new Error("DATABASE_UNPROVISIONED: cannot issue before provisioning");
    this.bind(spec.databaseId);
    // R4-SEC-04: the method space is a CLOSED registry; an unknown method
    // would fall through the restriction table as a restriction-free
    // bearer token, so issuance refuses it outright.
    if (!isKnownCapabilityMethod(spec.method)) {
      throw new Error(`CAPABILITY_METHOD_UNKNOWN: ${spec.method}`);
    }
    const incarnation = this.controllerCore.currentIncarnation();
    // audit C-05: expiry is measured on the persisted nondecreasing
    // controller clock, not Date.now() - a backward wall-clock jump cannot
    // mint a token that outlives its intended window, and verification reads
    // the same floor, so issuance and checking never disagree about "now".
    const expiresAtMs = this.controllerCore.controllerNow()
      + Math.min(Math.max(spec.ttlMs ?? 60_000, 1), 3_600_000);
    const key = spec.method === "PUT_PAYLOAD" && spec.digest !== undefined
      ? `p/${spec.databaseId}/${spec.digest}`
      : undefined;
    // audit C-05: finalize tokens bind the generation as a canonical decimal
    // string so a rollover invalidates them (checked in checkCapability)
    const generation = spec.generation !== undefined ? String(spec.generation) : undefined;
    // Issuance is fail-closed on the same restriction table verification
    // enforces. Minting a PUT_PAYLOAD token with no digest/budget used to
    // produce a token that authorized ANY key, ANY body and ANY length; it
    // now produces nothing at all, so the two ends cannot disagree about
    // what a capability is allowed to leave unbound.
    const derived: Record<string, unknown> = {
      session: spec.session, generation, key, digest: spec.digest, maxBytes: spec.maxBytes,
    };
    for (const required of REQUIRED_RESTRICTIONS[spec.method] ?? []) {
      if (derived[required] === undefined) {
        throw new Error(`CAPABILITY_RESTRICTION_MISSING: ${spec.method} requires ${required}`);
      }
    }
    if (spec.generation !== undefined
        && (!Number.isSafeInteger(spec.generation) || spec.generation < 0)) {
      throw new Error(`CAPABILITY_GENERATION_INVALID: ${spec.generation}`);
    }
    if (spec.maxBytes !== undefined
        && (!Number.isSafeInteger(spec.maxBytes) || spec.maxBytes < 0 || spec.maxBytes > MAX_CAPABILITY_BYTES)) {
      throw new Error(
        `CAPABILITY_BUDGET_ABOVE_CEILING: ${spec.maxBytes} exceeds the ${MAX_CAPABILITY_BYTES}-byte data-path ceiling`);
    }
    const payload: CapabilityPayload = {
      v: 2,
      kid: `cap:${binding.environment}`,
      env: binding.environment,
      tenantId: binding.tenantId,
      principal: spec.principal,
      databaseId: spec.databaseId,
      method: spec.method,
      ...(spec.session !== undefined ? { session: spec.session } : {}),
      ...(generation !== undefined ? { generation } : {}),
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
   * Verify-and-claim a capability for one request (F9, audit C-P0-08). MAC,
   * expiry, incarnation, method, audience, key, digest and budget are
   * checked synchronously; the claim is the transactional single-REQUEST
   * rule - the nonce is durably bound to `useDigest` (the canonical digest
   * of the one request being authorized), so an IDENTICAL retry after a
   * lost response is admitted again (every authorized procedure is
   * idempotent by operation identity and reproduces its original outcome),
   * while a DIFFERENT request under a used token is CAPABILITY_REPLAYED.
   */
  useCapability(
    token: string,
    expect: { method: string; databaseId: string; tenantId?: string; session?: string; generation?: string;
              key?: string; bodyDigest?: string; bodyLength?: number },
    useDigest: string,
  ): (CapabilityCheck & { claim?: { fresh: boolean; terminal: boolean; response: string | null } })
    | { ok: false; error: "CAPABILITY_REPLAYED" }
    | BindingRefusal {
    // R4 PR1: the registry-binding gate FIRST, as a typed refusal with no
    // side effect - an unprovisioned authority cannot be bound (or even
    // touched) by an ordinary authenticated call, and a provisioned one
    // refuses a token naming another tenant/database than its record.
    const unbound = this.requireBinding(expect);
    if (unbound !== null) return unbound;
    // audit C-05: verification reads the same controller clock issuance used
    const nowMs = this.controllerCore.controllerNow();
    const checked = checkCapability(this.capabilityKey, token, {
      ...expect,
      env: this.environment,
      currentIncarnation: this.controllerCore.currentIncarnation(),
      nowMs,
    });
    if (!checked.ok) return checked;
    const claimed = this.controllerCore.claimCapability(
      checked.payload.nonce, useDigest, checked.payload.expiresAtMs, nowMs);
    if (!claimed.ok) return claimed;
    // audit C-02: hand the claim outcome back so the worker replays a
    // terminal use's stored response instead of re-executing the effect
    return { ...checked, claim: { fresh: claimed.fresh, terminal: claimed.terminal, response: claimed.response } };
  }

  /**
   * Verify a capability WITHOUT claiming a durable use row (audit C-07).
   * Read routes are side-effect-free, so recording a durable IN_FLIGHT row
   * per read made reads write to SQLite and grow the control tables. This
   * still enforces MAC, expiry, incarnation, method, audience and session -
   * a stale-incarnation or fenced-session read is refused - it simply does
   * not consume the single-request replay slot that only mutations need.
   */
  checkCapabilityOnly(
    token: string,
    expect: { method: string; databaseId: string; tenantId?: string; session?: string; generation?: string;
              key?: string; bodyDigest?: string; bodyLength?: number },
  ): CapabilityCheck | BindingRefusal {
    const unbound = this.requireBinding(expect);
    if (unbound !== null) return unbound;
    return checkCapability(this.capabilityKey, token, {
      ...expect,
      env: this.environment,
      currentIncarnation: this.controllerCore.currentIncarnation(),
      nowMs: this.controllerCore.controllerNow(),
    });
  }

  /** Record the terminal outcome + stored response of a claimed use
   *  (audit C-02). Transition-checked and quarantining in the core. */
  resolveCapabilityUse(
    nonce: string, state: "RESOLVED_SUCCESS" | "RESOLVED_REJECTED" | "AMBIGUOUS", response?: string,
  ): void {
    this.controllerCore.resolveCapabilityUse(nonce, state, response);
  }

  bumpIncarnation(): number {
    return this.controllerCore.bumpIncarnation();
  }

  openCheckpointCut(databaseId: string, generation: number, cutId: string): ReturnType<ControllerCore["openCheckpointCut"]> {
    this.bind(databaseId);
    return this.controllerCore.openCheckpointCut(databaseId, generation, cutId);
  }

  activateCheckpointCut(
    databaseId: string,
    cutId: string,
    evidence: Parameters<ControllerCore["activateCheckpointCut"]>[2],
  ): ReturnType<ControllerCore["activateCheckpointCut"]> {
    this.bind(databaseId);
    return this.controllerCore.activateCheckpointCut(databaseId, cutId, evidence);
  }

  activeCheckpointCut(databaseId: string, generation: number): ReturnType<ControllerCore["activeCheckpointCut"]> {
    this.bind(databaseId);
    return this.controllerCore.activeCheckpointCut(databaseId, generation);
  }

  verifyJournalAnchored(): ReturnType<ControllerCore["verifyJournalAnchored"]> {
    return this.controllerCore.verifyJournalAnchored();
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
