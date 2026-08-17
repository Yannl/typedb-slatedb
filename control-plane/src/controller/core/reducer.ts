/*
 * CT-P0/G1 requirement: SQL/reducer trace equivalence.
 *
 * A pure reducer over the outbox event stream. Replaying every published
 * WAL_RECORD_FINALIZED event must reconstruct exactly the state the SQLite
 * projection holds — proven in the test suite over generated schedules.
 *
 * Sequence values (F7): events carry appendLsn/typeSequence as canonical
 * decimal strings (exact over the full u64 range); the reducer parses them
 * through the same fail-closed boundary the SQL projection uses and tracks
 * them as bigints.
 */

import { u64FromWire } from "./procedures.ts";

export interface WalRecordEvent {
  databaseId: string;
  generation: number;
  /** decimal-string u64 (numbers accepted for legacy events inside 2^53) */
  appendLsn: string | number;
  typeSequence: string | number;
  sequencingKind: "SEQUENCED" | "UNSEQUENCED";
  recordType: number;
  payloadKey: string;
  payloadDigest: string;
  logicalKey: string | null;
}

export interface ReducedGeneration {
  headLsn: bigint;
  typeSequenceHead: bigint;
  records: Map<bigint, { payloadKey: string; payloadDigest: string; typeSequence: bigint; recordType: number }>;
  statusByLogicalKey: Map<string, bigint>; // logicalKey -> appendLsn
}

export interface ReducedState {
  generations: Map<string, ReducedGeneration>; // `${databaseId}#${generation}`
}

export function emptyState(): ReducedState {
  return { generations: new Map() };
}

/** Pure, deterministic, event-at-a-time. Throws on any contiguity violation:
 *  a reducer that silently tolerates holes would mask allocator defects. */
export function applyEvent(state: ReducedState, event: WalRecordEvent): ReducedState {
  const appendLsn = u64FromWire(event.appendLsn, "event.appendLsn");
  const typeSequence = u64FromWire(event.typeSequence, "event.typeSequence");
  const key = `${event.databaseId}#${event.generation}`;
  const generation = state.generations.get(key) ?? {
    headLsn: -1n,
    typeSequenceHead: 0n,
    records: new Map(),
    statusByLogicalKey: new Map(),
  };
  if (appendLsn !== generation.headLsn + 1n) {
    throw new Error(`reducer contiguity violation: expected lsn ${generation.headLsn + 1n}, got ${appendLsn}`);
  }
  const expectedTypeSequence =
    event.sequencingKind === "SEQUENCED" ? generation.typeSequenceHead + 1n : generation.typeSequenceHead;
  if (typeSequence !== expectedTypeSequence) {
    throw new Error(
      `reducer type-sequence violation: expected ${expectedTypeSequence}, got ${typeSequence}`,
    );
  }
  if (event.logicalKey !== null && generation.statusByLogicalKey.has(event.logicalKey)) {
    throw new Error(`reducer status-singleton violation: duplicate logical key ${event.logicalKey}`);
  }

  const records = new Map(generation.records);
  records.set(appendLsn, {
    payloadKey: event.payloadKey,
    payloadDigest: event.payloadDigest,
    typeSequence,
    // outbox rows published before the record_type migration carry no
    // recordType in their canonical body; normalize to 0 — the same value
    // the SQL migration backfills — so replay of migrated state stays
    // trace-equivalent with the projection
    recordType: event.recordType ?? 0,
  });
  const statusByLogicalKey = new Map(generation.statusByLogicalKey);
  if (event.logicalKey !== null) statusByLogicalKey.set(event.logicalKey, appendLsn);

  const generations = new Map(state.generations);
  generations.set(key, {
    headLsn: appendLsn,
    typeSequenceHead: typeSequence,
    records,
    statusByLogicalKey,
  });
  return { generations };
}

export function replay(events: WalRecordEvent[]): ReducedState {
  return events.reduce(applyEvent, emptyState());
}
