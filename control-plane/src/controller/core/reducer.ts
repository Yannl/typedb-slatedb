/*
 * CT-P0/G1 requirement: SQL/reducer trace equivalence.
 *
 * A pure reducer over the outbox event stream. Replaying every published
 * WAL_RECORD_FINALIZED event must reconstruct exactly the state the SQLite
 * projection holds — proven in the test suite over generated schedules.
 */

export interface WalRecordEvent {
  databaseId: string;
  generation: number;
  appendLsn: number;
  typeSequence: number;
  sequencingKind: "SEQUENCED" | "UNSEQUENCED";
  recordType: number;
  payloadKey: string;
  payloadDigest: string;
  logicalKey: string | null;
}

export interface ReducedGeneration {
  headLsn: number;
  typeSequenceHead: number;
  records: Map<number, { payloadKey: string; payloadDigest: string; typeSequence: number; recordType: number }>;
  statusByLogicalKey: Map<string, number>; // logicalKey -> appendLsn
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
  const key = `${event.databaseId}#${event.generation}`;
  const generation = state.generations.get(key) ?? {
    headLsn: -1,
    typeSequenceHead: 0,
    records: new Map(),
    statusByLogicalKey: new Map(),
  };
  if (event.appendLsn !== generation.headLsn + 1) {
    throw new Error(`reducer contiguity violation: expected lsn ${generation.headLsn + 1}, got ${event.appendLsn}`);
  }
  const expectedTypeSequence =
    event.sequencingKind === "SEQUENCED" ? generation.typeSequenceHead + 1 : generation.typeSequenceHead;
  if (event.typeSequence !== expectedTypeSequence) {
    throw new Error(
      `reducer type-sequence violation: expected ${expectedTypeSequence}, got ${event.typeSequence}`,
    );
  }
  if (event.logicalKey !== null && generation.statusByLogicalKey.has(event.logicalKey)) {
    throw new Error(`reducer status-singleton violation: duplicate logical key ${event.logicalKey}`);
  }

  const records = new Map(generation.records);
  records.set(event.appendLsn, {
    payloadKey: event.payloadKey,
    payloadDigest: event.payloadDigest,
    typeSequence: event.typeSequence,
    // outbox rows published before the record_type migration carry no
    // recordType in their canonical body; normalize to 0 — the same value
    // the SQL migration backfills — so replay of migrated state stays
    // trace-equivalent with the projection
    recordType: event.recordType ?? 0,
  });
  const statusByLogicalKey = new Map(generation.statusByLogicalKey);
  if (event.logicalKey !== null) statusByLogicalKey.set(event.logicalKey, event.appendLsn);

  const generations = new Map(state.generations);
  generations.set(key, {
    headLsn: event.appendLsn,
    typeSequenceHead: event.typeSequence,
    records,
    statusByLogicalKey,
  });
  return { generations };
}

export function replay(events: WalRecordEvent[]): ReducedState {
  return events.reduce(applyEvent, emptyState());
}
