/*
 * F8 (authenticated control journal) test battery.
 *
 * 1. Known-answer tests pin the sync crypto to FIPS 180-4 / RFC 4231
 *    vectors - a transcription bug in the local SHA-256/HMAC cannot pass.
 * 2. Canonical-encoding determinism: key order cannot change the bytes.
 * 3. Chain construction + verification over real finalisations.
 * 4. The tamper matrix: body edit, kind edit, reorder, interior deletion,
 *    forged-without-key rewrite - each detected with a typed error naming
 *    the first bad sequence. Tail truncation is DOCUMENTED as out of scope
 *    (needs the external RecoveryAnchor - staged F8 remainder) and the test
 *    pins exactly that boundary so the gap stays visible.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type Database from "better-sqlite3";
import { ControllerCore, u64Blob } from "./procedures.ts";
import { canonicalJson, framedHash, fromHex, hex, hmacSha256, sha256, utf8 } from "../../shared/journal-crypto.ts";
import { boot as bootFixture, makeSql, reqFactory } from "./test-support.ts";

const KEY = utf8("journal-test-key");

const req = reqFactory("jop");

function boot(): { core: ControllerCore; db: InstanceType<typeof Database> } {
  return bootFixture({ journalKey: KEY });
}

test("SHA-256 known-answer vectors (FIPS 180-4)", () => {
  assert.equal(hex(sha256(utf8(""))), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  assert.equal(hex(sha256(utf8("abc"))), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  assert.equal(
    hex(sha256(utf8("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))),
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
  );
  // chunked input must hash identically to the concatenation
  assert.equal(hex(sha256(utf8("ab"), utf8("c"))), hex(sha256(utf8("abc"))));
  // block-boundary lengths (55/56/64 bytes straddle the padding split)
  for (const n of [55, 56, 63, 64, 65, 119, 120]) {
    const a = sha256(utf8("x".repeat(n)));
    const b = sha256(...Array.from({ length: n }, () => utf8("x")));
    assert.equal(hex(a), hex(b), `chunking must not change the ${n}-byte digest`);
  }
});

test("HMAC-SHA-256 known-answer vectors (RFC 4231)", () => {
  // case 1
  assert.equal(
    hex(hmacSha256(fromHex("0b".repeat(20)), utf8("Hi There"))),
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
  );
  // case 2 ("Jefe")
  assert.equal(
    hex(hmacSha256(utf8("Jefe"), utf8("what do ya want for nothing?"))),
    "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
  );
  // case 6: key longer than the block size (forces the key-hash path)
  assert.equal(
    hex(hmacSha256(fromHex("aa".repeat(131)), utf8("Test Using Larger Than Block-Size Key - Hash Key First"))),
    "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
  );
});

test("canonical JSON is byte-deterministic and rejects ambiguous values", () => {
  const a = canonicalJson({ b: 1, a: [{ y: null, x: "s" }], c: true });
  const b = canonicalJson({ c: true, a: [{ x: "s", y: null }], b: 1 });
  assert.equal(a, b);
  assert.equal(a, '{"a":[{"x":"s","y":null}],"b":1,"c":true}');
  assert.throws(() => canonicalJson({ n: 1n }), /bigint/);
  assert.throws(() => canonicalJson({ n: Infinity }), /non-finite/);
});

test("the journal chains and verifies over real finalisations", () => {
  const { core } = boot();
  for (let i = 0; i < 5; i++) assert.ok(core.finalizeWalRecord(req()).ok);
  const verdict = core.verifyJournal();
  assert.ok(verdict.ok, JSON.stringify(verdict));
  assert.equal(verdict.length, 7); // register + fixture BUDGETS_SET + 5 finalisations
  assert.equal(verdict.headHash.length, 64);
  // draining/acking must not touch authentication state
  core.drainOutbox(() => {});
  const after = core.verifyJournal();
  assert.ok(after.ok && after.headHash === verdict.headHash);
});

test("tamper matrix: every interior manipulation is a typed detection", () => {
  // body edit
  {
    const { core, db } = boot();
    for (let i = 0; i < 4; i++) core.finalizeWalRecord(req());
    db.prepare(`UPDATE control_outbox SET canonical_body = replace(canonical_body, 'SEQUENCED', 'UNSEQUENCED')
                WHERE control_seq = ?`).run(u64Blob(3n, "t"));
    const v = core.verifyJournal();
    assert.deepEqual(v, { ok: false, error: "JOURNAL_HASH_MISMATCH", atControlSeq: "3" });
  }
  // kind edit
  {
    const { core, db } = boot();
    for (let i = 0; i < 3; i++) core.finalizeWalRecord(req());
    db.prepare(`UPDATE control_outbox SET kind = 'FORGED_KIND' WHERE control_seq = ?`).run(u64Blob(4n, "t"));
    const v = core.verifyJournal();
    assert.deepEqual(v, { ok: false, error: "JOURNAL_HASH_MISMATCH", atControlSeq: "4" });
  }
  // reorder (swap two bodies wholesale, hashes included): linkage breaks
  {
    const { core, db } = boot();
    for (let i = 0; i < 4; i++) core.finalizeWalRecord(req());
    const row3 = db.prepare(`SELECT canonical_body, prev_hash, entry_hash, mac FROM control_outbox WHERE control_seq=?`).get(u64Blob(3n, "t")) as Record<string, unknown>;
    const row4 = db.prepare(`SELECT canonical_body, prev_hash, entry_hash, mac FROM control_outbox WHERE control_seq=?`).get(u64Blob(4n, "t")) as Record<string, unknown>;
    const put = db.prepare(`UPDATE control_outbox SET canonical_body=?, prev_hash=?, entry_hash=?, mac=? WHERE control_seq=?`);
    put.run(row4.canonical_body, row4.prev_hash, row4.entry_hash, row4.mac, u64Blob(3n, "t"));
    put.run(row3.canonical_body, row3.prev_hash, row3.entry_hash, row3.mac, u64Blob(4n, "t"));
    const v = core.verifyJournal();
    assert.ok(!v.ok && v.error === "JOURNAL_CHAIN_BROKEN" && v.atControlSeq === "3", JSON.stringify(v));
  }
  // interior deletion: contiguity gap
  {
    const { core, db } = boot();
    for (let i = 0; i < 4; i++) core.finalizeWalRecord(req());
    db.prepare(`DELETE FROM control_outbox WHERE control_seq = ?`).run(u64Blob(3n, "t"));
    const v = core.verifyJournal();
    assert.deepEqual(v, { ok: false, error: "JOURNAL_GAP", atControlSeq: "4" });
  }
  // database substitution: re-attributing an entry to another database is
  // a hash mismatch, because the v2 framing binds the database identity
  // (audit C-P1-04 - under v1 the hash did not cover database_id at all)
  {
    const { core, db } = boot();
    for (let i = 0; i < 3; i++) core.finalizeWalRecord(req());
    db.prepare(`UPDATE control_outbox SET database_id = 'db-OTHER' WHERE control_seq = ?`).run(u64Blob(3n, "t"));
    const v = core.verifyJournal();
    assert.deepEqual(v, { ok: false, error: "JOURNAL_HASH_MISMATCH", atControlSeq: "3" });
  }
  // repartition: moving bytes across the kind/body boundary is a hash
  // mismatch. Under the v1 unframed concatenation ("AB","C") and ("A","BC")
  // were ONE preimage; the length framing makes them distinct.
  {
    const { core, db } = boot();
    for (let i = 0; i < 3; i++) core.finalizeWalRecord(req());
    const row = db.prepare(`SELECT kind, canonical_body FROM control_outbox WHERE control_seq=?`)
      .get(u64Blob(3n, "t")) as { kind: string; canonical_body: string };
    // shift the body's first byte onto the end of the kind: same bytes, new partition
    db.prepare(`UPDATE control_outbox SET kind=?, canonical_body=? WHERE control_seq=?`)
      .run(row.kind + row.canonical_body[0], row.canonical_body.slice(1), u64Blob(3n, "t"));
    const v = core.verifyJournal();
    assert.deepEqual(v, { ok: false, error: "JOURNAL_HASH_MISMATCH", atControlSeq: "3" });
  }
  // forged rewrite WITHOUT the key: the attacker knows the (public) v2
  // framing and recomputes valid hashes for a modified suffix, but cannot
  // mint valid MACs
  {
    const { core, db } = boot();
    for (let i = 0; i < 3; i++) core.finalizeWalRecord(req());
    const rows = db.prepare(`SELECT control_seq, database_id, kind, canonical_body, prev_hash FROM control_outbox ORDER BY control_seq`).all() as Record<string, unknown>[];
    // rewrite entry 2's body and recompute its hash + entry 3's linkage,
    // using a WRONG key for the MACs (the real key never leaves the core)
    const forgedBody = String(rows[2].canonical_body).replace('"generation":1', '"generation":9');
    assert.notEqual(forgedBody, String(rows[2].canonical_body), "the forged edit must actually change the body");
    const entryHash = (row: Record<string, unknown>, prev: Uint8Array, seq: bigint, body: string) =>
      framedHash("typedb-journal-entry/v2",
        prev, u64Blob(seq, "t"), utf8(String(row.database_id)), utf8(String(row.kind)), utf8(body));
    const forgedHash3 = entryHash(rows[2], rows[2].prev_hash as Uint8Array, 3n, forgedBody);
    const forgedMac3 = hmacSha256(utf8("wrong-key"), forgedHash3);
    const forgedHash4 = entryHash(rows[3], forgedHash3, 4n, String(rows[3].canonical_body));
    const forgedMac4 = hmacSha256(utf8("wrong-key"), forgedHash4);
    const put = db.prepare(`UPDATE control_outbox SET canonical_body=?, prev_hash=?, entry_hash=?, mac=? WHERE control_seq=?`);
    put.run(forgedBody, rows[2].prev_hash, forgedHash3, forgedMac3, u64Blob(3n, "t"));
    put.run(String(rows[3].canonical_body), forgedHash3, forgedHash4, forgedMac4, u64Blob(4n, "t"));
    const v = core.verifyJournal();
    assert.deepEqual(v, { ok: false, error: "JOURNAL_MAC_INVALID", atControlSeq: "3" });
  }
});

test("boundary pin: tail truncation is invisible to PLAIN chain verification", () => {
  // This test EXISTS to keep the limitation visible: deleting the journal
  // tail yields a shorter but internally consistent chain. The CheckpointCut
  // anchor (controller-state.test.ts) now DETECTS truncation at or below the
  // newest cut via verifyJournalAnchored; the un-anchored tail window and
  // the adversarial rewrite-with-DB-access case close with the immutable R2
  // RecoveryAnchor publication (staged F8 remainder).
  const { core, db } = boot();
  for (let i = 0; i < 4; i++) core.finalizeWalRecord(req());
  const before = core.verifyJournal();
  assert.ok(before.ok && before.length === 6); // register + fixture budgets + 4 finalisations
  db.prepare(`DELETE FROM control_outbox WHERE control_seq = ?`).run(u64Blob(6n, "t"));
  const truncated = core.verifyJournal();
  assert.ok(truncated.ok, "truncation is undetectable without the external anchor - by construction");
  assert.equal(truncated.length, 5);
  assert.notEqual(truncated.headHash, before.headHash,
    "the head hash DOES change - an external anchor of (length, headHash) detects truncation");
});

test("a wrong journal key fails verification wholesale", () => {
  const { sql, db } = makeSql();
  const core = new ControllerCore(sql, { journalKey: KEY });
  core.registerSession("db1", 1, "sess-1");
  core.setBudgets("db1", { maxUnpublishedOutbox: 100, maxPayloadLength: 1000, maxTailRecords: 100 }, "sess-1");
  core.finalizeWalRecord(req());
  const wrongKeyView = new ControllerCore(sql, { journalKey: utf8("other-key") });
  const v = wrongKeyView.verifyJournal();
  assert.deepEqual(v, { ok: false, error: "JOURNAL_MAC_INVALID", atControlSeq: "1" });
  void db;
});
