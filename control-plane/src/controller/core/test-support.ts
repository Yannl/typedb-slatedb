/*
 * Shared fixtures for the controller-core node test suites (test-only,
 * never imported by production code). One better-sqlite3 SyncSql adapter,
 * one FinalizeRequest factory, one register+budget boot — previously
 * duplicated per suite, where a divergence would make two suites test
 * subtly different harnesses while appearing to test one.
 */

import Database from "better-sqlite3";
import { ControllerCore, type FinalizeRequest, type SyncSql } from "./procedures.ts";

export type TestDb = InstanceType<typeof Database>;

/** SyncSql over better-sqlite3. `observe` (when given) sees every
 *  single-statement exec before it runs — the query-plans suite records
 *  hot-path SQL through it. */
export function sqlOver(db: TestDb, observe?: (sql: string, params: unknown[]) => void): SyncSql {
  return {
    exec(query: string, ...params: unknown[]) {
      if (params.length === 0 && /;\s*\S/.test(query)) {
        db.exec(query);
        return [];
      }
      observe?.(query, params);
      const stmt = db.prepare(query);
      if (stmt.reader) return stmt.all(...params) as Record<string, unknown>[];
      stmt.run(...params);
      return [];
    },
    transaction<T>(fn: () => T): T {
      return db.transaction(fn)();
    },
  };
}

export function makeSql(): { sql: SyncSql; db: TestDb } {
  const db = new Database(":memory:");
  return { sql: sqlOver(db), db };
}

/** FinalizeRequest factory: ids are `${prefix}-N`, suite-wide defaults are
 *  fixed at creation, per-call overrides win. The payload key is
 *  CONTENT-ADDRESSED from the resolved digest (`p/<db>/<digest>`, the
 *  canonical scheme the worker enforces - audit C-P0-07), so an
 *  identical-content retry carries the identical key, exactly as the real
 *  protocol produces it. */
export function reqFactory(prefix: string, defaults: Partial<FinalizeRequest> = {}) {
  let opCounter = 0;
  return (overrides: Partial<FinalizeRequest> = {}): FinalizeRequest => {
    opCounter += 1;
    const id = `${prefix}-${opCounter}`;
    const merged = {
      databaseId: "db1",
      generation: 1,
      startupSessionId: "sess-1",
      operationId: id,
      requestDigest: `digest-${id}`,
      sequencingKind: "SEQUENCED" as const,
      recordType: 2, // CommitRecord's durability record type
      logicalKey: null,
      payloadDigest: `pd-${id}`,
      payloadLength: 10,
      ...defaults,
      ...overrides,
    };
    return {
      payloadKey: `p/${merged.databaseId}/${merged.payloadDigest}`,
      ...merged,
    } as FinalizeRequest;
  };
}

export const TEST_BUDGETS = {
  maxUnpublishedOutbox: 10_000,
  maxPayloadLength: 1_000_000,
  maxTailRecords: 1_000_000,
} as const;

/** A registered, budgeted core over a fresh database. Q-12: a database with
 *  no budget row denies writes, so every booted fixture carries one. */
export function boot(options: {
  journalKey?: Uint8Array;
  now?: () => number;
  generation?: number;
  budgets?: { maxUnpublishedOutbox: number; maxPayloadLength: number; maxTailRecords: number };
  observe?: (sql: string, params: unknown[]) => void;
} = {}): { core: ControllerCore; db: TestDb } {
  const db = new Database(":memory:");
  const core = new ControllerCore(sqlOver(db, options.observe), {
    journalKey: options.journalKey,
    now: options.now,
  });
  const generation = options.generation ?? 1;
  core.registerSession("db1", generation, "sess-1");
  const budgeted = core.setBudgets("db1", options.budgets ?? TEST_BUDGETS, "sess-1");
  if (!budgeted.ok) throw new Error(`fixture budget refused: ${JSON.stringify(budgeted)}`);
  return { core, db };
}
