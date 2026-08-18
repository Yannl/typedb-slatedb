/*
 * CF-P1: `DatabaseContainerDO` — the container's DURABLE CONTROL-PROTOCOL
 * authority (brief §4.1.3, audit C-08).
 *
 * This is the control-plane side of a database container: the durable,
 * authenticated surface through which a running container (or, in native
 * mode, a substituted process) reports lifecycle OBSERVATIONS, and through
 * which the controller reads them back. Per §7.4 the control protocol and its
 * binding MUST exist in every deployment mode — container, native, staging,
 * production — even though the actual container PROCESS lifecycle (image
 * start/stop, port readiness, HTTP proxying via `@cloudflare/containers`) is
 * a real-platform residual (matrix CF-02). Modelling the control authority as
 * a plain SQLite Durable Object (rather than a `Container` subclass, whose
 * constructor throws unless a container image is bound) is what lets the
 * intended lifecycle authority be exercised locally under `runInDurableObject`
 * with no container runtime present.
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
 *  - the DO durably binds the FULL container identity
 *    (databaseId, generation, incarnation, startupSessionId) on its first
 *    authenticated call; every later call must present exactly that identity
 *    or fail closed (a foreign or mis-routed call is refused BEFORE any write,
 *    audit C-P0-02 / C-08). The first call must carry a well-formed identity —
 *    an empty or malformed one binds nothing (no first-arbitrary-caller bind);
 *  - an unbounded producer cannot grow storage without bound: the observation
 *    store is a bounded ring with a typed refusal past its limit, drained by
 *    an idempotent alarm-driven GC;
 *  - alarms only wake the idempotent GC reducer; schedule state is durable and
 *    every pass re-arms into the future with bounded backoff (inv. 154).
 */

import { DurableObject } from "cloudflare:workers";

/** The identity a container instance is bound to. All four components are
 *  load-bearing: a container serves ONE database, at ONE generation, under
 *  ONE controller incarnation, for ONE startup session. */
export interface ContainerIdentity {
  databaseId: string;
  generation: number;
  incarnation: number;
  startupSessionId: string;
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

/** Bounded observation ring capacity (audit C-08 backpressure). Past this the
 *  DO refuses new observations with a typed error so a runaway producer cannot
 *  grow durable storage without bound. Advisory data, so refusing (rather than
 *  silently unbounded growth) is always safe (inv. 149). */
export const MAX_OBSERVATIONS = 1024;

/** GC low-water mark: the idempotent alarm trims the ring back to this many
 *  most-recent rows, so the hard refusal is a backstop, not a permanent wedge. */
export const OBSERVATION_LOW_WATER = 512;

/** Default page size for getObservations; hard-capped at the ring size. */
const DEFAULT_OBSERVATION_PAGE = 256;

/** Kinds the container lifecycle produces. Free-form strings are accepted (an
 *  observation is opaque advisory data), but the known set is documented. */
export type ObservationKind =
  | "STARTED" | "STOPPED" | "PLATFORM_ERROR" | "HEALTH_OK" | "HEALTH_FAIL";

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isSafeCount(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

export class DatabaseContainerDO extends DurableObject {
  private sql: SqlStorage;

  constructor(state: DurableObjectState, env: unknown) {
    super(state, env as never);
    this.sql = state.storage.sql;
    // DO-runtime tables only — this authority owns NO projection/sequence
    // tables by construction (inv. 148). container_binding is the immutable
    // identity fence; observations is the bounded advisory ring;
    // container_alarm_schedule mirrors the controller's durable alarm state.
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS container_binding(
        key TEXT PRIMARY KEY CHECK(key='identity'),
        database_id TEXT NOT NULL,
        generation INTEGER NOT NULL,
        incarnation INTEGER NOT NULL,
        startup_session_id TEXT NOT NULL
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
        detail TEXT
      );
      CREATE TABLE IF NOT EXISTS container_alarm_schedule(
        task TEXT PRIMARY KEY,
        next_due_at INTEGER NOT NULL,
        interval_ms INTEGER NOT NULL DEFAULT 60000,
        attempts INTEGER NOT NULL DEFAULT 0
      );
    `);
  }

  /**
   * Immutable container-identity binding and route fence (audit C-08, mirrors
   * DatabaseControllerDO.bind). The FIRST authenticated call durably binds the
   * full identity; every later call must present exactly that identity or fail
   * closed here, BEFORE any observation is written. A first call carrying an
   * empty or malformed identity binds nothing and is refused — there is no
   * first-arbitrary-caller bind. This is the authentication of the
   * controller↔container envelope on the local surface: the full production
   * tenant/environment registry is a platform-blocked remainder (matrix CF-02)
   * recorded in the ledger.
   */
  private bind(identity: ContainerIdentity): void {
    if (!isNonEmptyString(identity?.databaseId) || !isNonEmptyString(identity?.startupSessionId)
        || !isSafeCount(identity?.generation) || !isSafeCount(identity?.incarnation)) {
      throw new Error("DO_CONTAINER_BINDING_VIOLATION: malformed container identity");
    }
    const bound = this.sql
      .exec(`SELECT database_id, generation, incarnation, startup_session_id FROM container_binding WHERE key='identity'`)
      .toArray();
    if (!bound.length) {
      this.sql.exec(
        `INSERT INTO container_binding(key, database_id, generation, incarnation, startup_session_id)
         VALUES ('identity', ?, ?, ?, ?)`,
        identity.databaseId, identity.generation, identity.incarnation, identity.startupSessionId,
      );
      return;
    }
    const row = bound[0];
    if (String(row.database_id) !== identity.databaseId
        || Number(row.generation) !== identity.generation
        || Number(row.incarnation) !== identity.incarnation
        || String(row.startup_session_id) !== identity.startupSessionId) {
      throw new Error(
        `DO_CONTAINER_BINDING_VIOLATION: this container authority is bound to another identity; ` +
          `presented ${JSON.stringify(identity)}`,
      );
    }
  }

  /**
   * Record one advisory lifecycle observation (authenticated by the identity
   * fence). Returns `advisory: true` to make the contract explicit at the RPC
   * boundary: this call can never grant, fence, or sequence anything (inv.
   * 149). Backpressure: once the ring holds MAX_OBSERVATIONS rows the call is
   * refused with a typed error rather than growing storage without bound; the
   * alarm GC drains it back to the low-water mark.
   */
  recordObservation(identity: ContainerIdentity, observation: Observation):
    { ok: true; advisory: true; seq: number } | { ok: false; error: string } {
    this.bind(identity);
    if (!isNonEmptyString(observation?.kind) || !isNonEmptyString(observation?.processNonce)) {
      return { ok: false, error: "OBSERVATION_MALFORMED" };
    }
    if (!isSafeCount(observation?.at)) {
      return { ok: false, error: "OBSERVATION_MALFORMED" };
    }
    const count = Number(
      (this.sql.exec(`SELECT COUNT(*) AS n FROM observations`).one() as { n: number }).n);
    if (count >= MAX_OBSERVATIONS) {
      return { ok: false, error: "OBSERVATION_LIMIT_EXCEEDED" };
    }
    const inserted = this.sql.exec(
      `INSERT INTO observations(
         database_id, generation, incarnation, startup_session_id, process_nonce, kind, at, detail)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING seq`,
      identity.databaseId, identity.generation, identity.incarnation, identity.startupSessionId,
      observation.processNonce, observation.kind, observation.at,
      observation.detail === undefined ? null : String(observation.detail),
    ).one() as { seq: number };
    return { ok: true, advisory: true, seq: Number(inserted.seq) };
  }

  /**
   * Read advisory observations back (authenticated by the identity fence).
   * `advisory: true` again marks that the caller is reading a hint, not
   * authority: nothing about the returned rows constrains any authority
   * decision the controller makes.
   */
  getObservations(identity: ContainerIdentity, opts?: { limit?: number; sinceSeq?: number }):
    { ok: true; advisory: true; observations: (Observation & { seq: number })[] }
    | { ok: false; error: string } {
    this.bind(identity);
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
        // idempotent: trim the advisory ring to the low-water mark, oldest
        // first. Dropping advisory observations can never move authority.
        this.gcObservations();
        return;
      default:
        throw new Error(`unknown scheduled task: ${task}`);
    }
  }

  /** Trim the observation ring to OBSERVATION_LOW_WATER most-recent rows.
   *  Exposed for the alarm and directly for tests; idempotent. */
  gcObservations(): { pruned: number } {
    const before = Number(
      (this.sql.exec(`SELECT COUNT(*) AS n FROM observations`).one() as { n: number }).n);
    if (before <= OBSERVATION_LOW_WATER) return { pruned: 0 };
    this.sql.exec(
      `DELETE FROM observations WHERE seq NOT IN (
         SELECT seq FROM observations ORDER BY seq DESC LIMIT ?
       )`,
      OBSERVATION_LOW_WATER,
    );
    const after = Number(
      (this.sql.exec(`SELECT COUNT(*) AS n FROM observations`).one() as { n: number }).n);
    return { pruned: before - after };
  }

  private async armAlarm(): Promise<void> {
    const next = this.sql
      .exec(`SELECT MIN(next_due_at) AS n FROM container_alarm_schedule`)
      .one() as { n: number | null };
    if (next.n !== null) await this.ctx.storage.setAlarm(Number(next.n));
  }
}
