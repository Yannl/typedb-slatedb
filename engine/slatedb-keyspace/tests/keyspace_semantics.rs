/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Semantics TypeDB's storage layer depends on, checked against a real SlateDB over a local
//! object store. These are properties whose loss would corrupt the database, not a smoke test
//! of the API surface.

use std::sync::Arc;

use object_store::{local::LocalFileSystem, ObjectStore};
use slatedb_keyspace::{Backend, Batch, KeyspaceId, KeyspaceSet, StoreConfig, Tuning};

fn open() -> (KeyspaceSet, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store: Arc<dyn ObjectStore> =
        Arc::new(LocalFileSystem::new_with_prefix(dir.path()).unwrap());
    (KeyspaceSet::open("/typedb", store).unwrap(), dir)
}

#[test]
fn put_then_get_round_trips() {
    let (set, _dir) = open();
    let ks = set.keyspace(KeyspaceId(0));
    ks.put(b"alpha", b"one").unwrap();
    assert_eq!(ks.get(b"alpha").unwrap().as_deref(), Some(&b"one"[..]));
    assert_eq!(ks.get(b"missing").unwrap(), None);
}

#[test]
fn keyspaces_are_isolated() {
    // The whole partitioning scheme rests on this: the same logical key in two keyspaces must
    // be two distinct entries, or unrelated parts of the database silently alias.
    let (set, _dir) = open();
    set.keyspace(KeyspaceId(0)).put(b"k", b"from-0").unwrap();
    set.keyspace(KeyspaceId(1)).put(b"k", b"from-1").unwrap();
    assert_eq!(set.keyspace(KeyspaceId(0)).get(b"k").unwrap().as_deref(), Some(&b"from-0"[..]));
    assert_eq!(set.keyspace(KeyspaceId(1)).get(b"k").unwrap().as_deref(), Some(&b"from-1"[..]));
}

#[test]
fn get_prev_finds_the_greatest_key_at_or_below() {
    // RocksDB's seek_for_prev. TypeDB uses it to locate a key's predecessor, so an off-by-one
    // here reads the wrong record rather than failing loudly.
    let (set, _dir) = open();
    let ks = set.keyspace(KeyspaceId(3));
    for k in [b"a".as_ref(), b"c".as_ref(), b"e".as_ref()] {
        ks.put(k, b"v").unwrap();
    }

    let (k, _) = ks.get_prev(b"d").unwrap().expect("c precedes d");
    assert_eq!(k, b"c");

    let (k, _) = ks.get_prev(b"c").unwrap().expect("an exact hit is included");
    assert_eq!(k, b"c", "seek_for_prev is <=, not <");

    assert!(ks.get_prev(b"0").unwrap().is_none(), "nothing at or below the first key");
}

#[test]
fn get_prev_does_not_cross_into_a_lower_keyspace() {
    // Subtle and severe: without a keyspace lower bound a descending scan runs past the start
    // of its own keyspace and returns a key belonging to another, which TypeDB would then
    // decode with the wrong schema.
    let (set, _dir) = open();
    set.keyspace(KeyspaceId(0)).put(b"zzz", b"other-keyspace").unwrap();
    let ks = set.keyspace(KeyspaceId(1));
    assert!(ks.get_prev(b"aaa").unwrap().is_none(), "must not see keyspace 0's data");

    ks.put(b"aaa", b"mine").unwrap();
    let (k, v) = ks.get_prev(b"bbb").unwrap().unwrap();
    assert_eq!((k.as_slice(), v.as_ref()), (&b"aaa"[..], &b"mine"[..]));
}

#[test]
fn iteration_is_ordered_and_bounded_to_its_keyspace() {
    let (set, _dir) = open();
    set.keyspace(KeyspaceId(0)).put(b"zzz", b"other").unwrap();
    set.keyspace(KeyspaceId(2)).put(b"aaa", b"other").unwrap();

    let ks = set.keyspace(KeyspaceId(1));
    for k in [b"b".as_ref(), b"a".as_ref(), b"c".as_ref()] {
        ks.put(k, b"v").unwrap();
    }

    let mut iter = ks.iterate_from(b"").unwrap();
    let mut seen = Vec::new();
    while let Some((k, _)) = iter.advance().unwrap() {
        seen.push(k.to_vec());
    }
    assert_eq!(seen, vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()], "ordered, and only ours");
}

#[test]
fn iteration_starts_at_or_after_the_seek_key() {
    let (set, _dir) = open();
    let ks = set.keyspace(KeyspaceId(4));
    for k in [b"a".as_ref(), b"b".as_ref(), b"c".as_ref()] {
        ks.put(k, b"v").unwrap();
    }
    let mut iter = ks.iterate_from(b"b").unwrap();
    assert_eq!(iter.advance().unwrap().map(|(k, _)| k.to_vec()), Some(b"b".to_vec()));
    assert_eq!(iter.advance().unwrap().map(|(k, _)| k.to_vec()), Some(b"c".to_vec()));
    assert_eq!(iter.advance().unwrap().map(|(k, _)| k.to_vec()), None);
}

#[test]
fn a_batch_spanning_keyspaces_applies_atomically() {
    let (set, _dir) = open();
    let mut batch = Batch::new();
    batch.put(KeyspaceId(0), b"x", b"1");
    batch.put(KeyspaceId(1), b"y", b"2");
    set.write(batch).unwrap();

    assert_eq!(set.keyspace(KeyspaceId(0)).get(b"x").unwrap().as_deref(), Some(&b"1"[..]));
    assert_eq!(set.keyspace(KeyspaceId(1)).get(b"y").unwrap().as_deref(), Some(&b"2"[..]));
}

#[test]
fn delete_removes_only_its_own_keyspace_entry() {
    let (set, _dir) = open();
    set.keyspace(KeyspaceId(0)).put(b"k", b"zero").unwrap();
    set.keyspace(KeyspaceId(1)).put(b"k", b"one").unwrap();
    set.keyspace(KeyspaceId(0)).delete(b"k").unwrap();
    assert_eq!(set.keyspace(KeyspaceId(0)).get(b"k").unwrap(), None);
    assert_eq!(set.keyspace(KeyspaceId(1)).get(b"k").unwrap().as_deref(), Some(&b"one"[..]));
}

#[test]
fn data_survives_close_and_reopen() {
    // Durability across a process boundary — the property the whole substitution exists to
    // preserve. One directory, opened twice, rather than a single live handle.
    let dir = tempfile::tempdir().unwrap();
    let store: Arc<dyn ObjectStore> =
        Arc::new(LocalFileSystem::new_with_prefix(dir.path()).unwrap());

    {
        let set = KeyspaceSet::open("/typedb", store.clone()).unwrap();
        set.keyspace(KeyspaceId(2)).put(b"persisted", b"value").unwrap();
        set.flush().unwrap();
        set.close().unwrap();
    }

    let reopened = KeyspaceSet::open("/typedb", store).unwrap();
    assert_eq!(
        reopened.keyspace(KeyspaceId(2)).get(b"persisted").unwrap().as_deref(),
        Some(&b"value"[..]),
        "an acknowledged, flushed write must survive reopen"
    );
}

#[test]
fn clear_empties_one_keyspace_and_leaves_the_others_alone() {
    let dir = tempfile::tempdir().unwrap();
    let set = KeyspaceSet::open_local(dir.path()).unwrap();
    let a = set.keyspace(KeyspaceId(0));
    let b = set.keyspace(KeyspaceId(1));

    for i in 0u8..8 {
        a.put(&[i], b"a").unwrap();
        b.put(&[i], b"b").unwrap();
    }

    assert_eq!(a.clear().unwrap(), 8);

    // A cleared keyspace reads as empty...
    assert!(a.get(&[3]).unwrap().is_none());
    assert!(a.iterate_from(&[]).unwrap().advance().unwrap().is_none());
    // ...and its neighbour is untouched. This is the assertion that would catch a `clear`
    // that forgot its prefix and wiped the whole store, which reads as a passing test if you
    // only ever check that the target keyspace is empty.
    assert_eq!(b.get(&[3]).unwrap().unwrap().as_ref(), b"b");
    assert_eq!(b.stats().unwrap().0, 8);
}

#[test]
fn clear_on_an_empty_keyspace_is_a_no_op_not_an_error() {
    // SlateDB rejects an empty write batch, so a `clear` that unconditionally wrote one would
    // fail on an already-empty keyspace — exactly the empty-batch trap that broke commits.
    let dir = tempfile::tempdir().unwrap();
    let set = KeyspaceSet::open_local(dir.path()).unwrap();
    assert_eq!(set.keyspace(KeyspaceId(0)).clear().unwrap(), 0);
}

#[test]
fn stats_counts_only_its_own_keyspace() {
    let dir = tempfile::tempdir().unwrap();
    let set = KeyspaceSet::open_local(dir.path()).unwrap();
    set.keyspace(KeyspaceId(0)).put(b"k", b"12345").unwrap();
    set.keyspace(KeyspaceId(1)).put(b"k", b"1").unwrap();

    let (keys, bytes) = set.keyspace(KeyspaceId(0)).stats().unwrap();
    assert_eq!(keys, 1);
    // The logical key, not the prefixed physical one.
    assert_eq!(bytes, 1 + 5);
}

#[test]
fn a_checkpoint_makes_prior_writes_readable_from_a_copy_of_the_store() {
    // The real contract TypeDB depends on: after `checkpoint`, the store's files on disk are a
    // complete, openable database. Copying them and reopening the copy is exactly what the
    // recovery path does, so testing anything less would not test the thing that matters.
    let dir = tempfile::tempdir().unwrap();
    let copy = tempfile::tempdir().unwrap();
    let set = KeyspaceSet::open_local(dir.path()).unwrap();
    for i in 0u8..32 {
        set.keyspace(KeyspaceId(0)).put(&[i], b"durable").unwrap();
    }
    set.checkpoint().unwrap();

    copy_dir(dir.path(), copy.path());
    drop(set);

    let restored = KeyspaceSet::open_local(copy.path()).unwrap();
    for i in 0u8..32 {
        assert_eq!(
            restored.keyspace(KeyspaceId(0)).get(&[i]).unwrap().expect("key must survive").as_ref(),
            b"durable",
            "key {i} was lost across checkpoint and restore"
        );
    }
}

fn copy_dir(from: &std::path::Path, to: &std::path::Path) {
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            std::fs::create_dir_all(&target).unwrap();
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

#[test]
fn a_write_is_visible_immediately_and_survives_dropping_its_durability_handle() {
    // The engine discards the WriteHandle that `write_with_options` returns, which is what
    // makes commits asynchronous-durable and keeps an object-store round trip out of TypeDB's
    // commit path. That is only sound because dropping the handle cannot cancel the write.
    //
    // If it ever could, every read-your-writes assertion would still pass — the memtable would
    // answer correctly — and the loss would only appear after a restart. So this test does both
    // halves: read back through the live handle, then reopen from disk and read again.
    let dir = tempfile::tempdir().unwrap();
    let set = KeyspaceSet::open_local(dir.path()).unwrap();

    let mut batch = Batch::new();
    for i in 0u8..64 {
        batch.put(KeyspaceId(0), &[i], b"v");
    }
    set.write(batch).unwrap();

    // Visible without any flush.
    assert_eq!(set.keyspace(KeyspaceId(0)).stats().unwrap().0, 64);

    // And still there once an explicit barrier has run and the store is reopened.
    set.flush().unwrap();
    set.close().unwrap();
    drop(set);

    let reopened = KeyspaceSet::open_local(dir.path()).unwrap();
    assert_eq!(
        reopened.keyspace(KeyspaceId(0)).stats().unwrap().0,
        64,
        "writes acknowledged before flush must survive the explicit barrier"
    );
}

// ---------------------------------------------------------------------------------------
// Cost and lifetime properties.
//
// These check the shape of the work done rather than the answer produced. That is unusual for
// a test suite, and deliberate: against object storage the difference between an O(1) and an
// O(n) implementation of the same correct function is the difference between a viable service
// and an unaffordable one, and nothing else in the corpus would notice the substitution.
// ---------------------------------------------------------------------------------------

#[test]
fn store_size_is_answered_from_the_manifest_without_scanning() {
    // A small L0 threshold so a modest write actually produces an SST; the default is 64 MB,
    // which no reasonable test would reach.
    let dir = tempfile::tempdir().unwrap();
    let mut tuning = Tuning::local();
    tuning.l0_sst_size_bytes = 64 * 1024;
    let set = KeyspaceSet::open_with(
        StoreConfig { backend: Backend::Local { path: dir.path().to_path_buf() }, tuning },
    )
    .unwrap();

    assert_eq!(set.size_bytes(), 0, "an empty store occupies nothing");

    let mut batch = Batch::new();
    for i in 0u32..4000 {
        batch.put(KeyspaceId(0), &i.to_be_bytes(), &[b'v'; 64]);
    }
    set.write(batch).unwrap();
    set.flush().unwrap();

    // The memtable is promoted to an L0 SST asynchronously, so poll rather than assume it has
    // happened by the time `flush` returns.
    let mut size = 0;
    for _ in 0..100 {
        size = set.size_bytes();
        if size > 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(size > 0, "a store holding 4000 entries should report a non-zero size, got {size}");
}

#[test]
fn a_polled_estimate_is_memoized_while_the_exact_count_is_not() {
    // The property that matters for cost: TypeDB polls this every 15 seconds, so repeating the
    // scan on every call is what must not happen. A long TTL makes "did it recompute?"
    // observable — the estimate must ignore writes the exact scan still sees.
    let dir = tempfile::tempdir().unwrap();
    let set = KeyspaceSet::open_local(dir.path())
        .unwrap()
        .with_estimate_ttl(std::time::Duration::from_secs(3600));
    let keyspace = set.keyspace(KeyspaceId(0));

    for i in 0u8..3 {
        keyspace.put(&[i], b"v").unwrap();
    }
    assert_eq!(keyspace.estimated_stats().unwrap().0, 3);

    for i in 3u8..8 {
        keyspace.put(&[i], b"v").unwrap();
    }
    assert_eq!(
        keyspace.estimated_stats().unwrap().0,
        3,
        "a memoized estimate inside its TTL must not pay for a second scan"
    );
    assert_eq!(
        keyspace.stats().unwrap().0,
        8,
        "the exact count is never memoized, so it sees every write"
    );
}

#[test]
fn an_expired_estimate_is_recomputed() {
    let dir = tempfile::tempdir().unwrap();
    let set =
        KeyspaceSet::open_local(dir.path()).unwrap().with_estimate_ttl(std::time::Duration::ZERO);
    let keyspace = set.keyspace(KeyspaceId(0));

    keyspace.put(b"a", b"v").unwrap();
    assert_eq!(keyspace.estimated_stats().unwrap().0, 1);
    keyspace.put(b"b", b"v").unwrap();
    assert_eq!(
        keyspace.estimated_stats().unwrap().0,
        2,
        "a zero TTL means every call recomputes, so the memo must not become a leak"
    );
}

#[test]
fn clearing_more_than_one_chunk_removes_everything_and_spares_siblings() {
    // Above the engine's per-batch chunk limit, so the clear must span several batches. A
    // single-batch implementation passes every smaller test and then holds an entire keyspace
    // in memory the first time one gets large.
    const KEYS: u32 = 25_000;

    let dir = tempfile::tempdir().unwrap();
    let set = KeyspaceSet::open_local(dir.path()).unwrap();

    let mut batch = Batch::new();
    for i in 0..KEYS {
        batch.put(KeyspaceId(0), &i.to_be_bytes(), b"v");
    }
    batch.put(KeyspaceId(1), b"survivor", b"v");
    set.write(batch).unwrap();

    let cleared = set.keyspace(KeyspaceId(0)).clear().unwrap();
    assert_eq!(cleared as u32, KEYS, "every key must be counted exactly once across chunks");
    assert_eq!(set.keyspace(KeyspaceId(0)).stats().unwrap().0, 0);
    assert_eq!(
        set.keyspace(KeyspaceId(1)).get(b"survivor").unwrap().as_deref(),
        Some(&b"v"[..]),
        "a chunked clear must still respect the keyspace boundary"
    );
}

#[test]
fn a_cursor_is_independent_of_the_handle_that_opened_it() {
    // `set.keyspace(id)` is a temporary. A cursor that borrowed it would not survive the end of
    // the expression, which is what previously forced a caller wanting to store one to
    // transmute a borrow to `'static`. Holding cursors in a collection is the cheapest way to
    // state that the borrow is gone: this does not compile if `KeyspaceIterator` regains a
    // lifetime parameter.
    let dir = tempfile::tempdir().unwrap();
    let set = KeyspaceSet::open_local(dir.path()).unwrap();
    for i in 0u8..4 {
        set.keyspace(KeyspaceId(0)).put(&[i], b"v").unwrap();
        set.keyspace(KeyspaceId(1)).put(&[i], b"w").unwrap();
    }

    let mut cursors: Vec<slatedb_keyspace::KeyspaceIterator> = vec![
        set.keyspace(KeyspaceId(0)).iterate_from(&[]).unwrap(),
        set.keyspace(KeyspaceId(1)).iterate_from(&[]).unwrap(),
    ];

    assert_eq!(cursors[0].advance().unwrap(), Some((&[0u8][..], &b"v"[..])));
    assert_eq!(cursors[1].advance().unwrap(), Some((&[0u8][..], &b"w"[..])));
}

#[test]
fn a_store_knows_whether_its_files_are_local() {
    // TypeDB checkpoints by copying the store's directory. That is meaningful for a local
    // store and meaningless for a remote one, whose local directory holds at most a block
    // cache — so the checkpoint path has to be able to tell them apart. Getting this wrong is
    // silent: the copy succeeds and produces an unrestorable checkpoint.
    let dir = tempfile::tempdir().unwrap();
    let local = KeyspaceSet::open_local(dir.path()).unwrap();
    assert_eq!(local.local_directory(), Some(dir.path()));

    let remote_dir = tempfile::tempdir().unwrap();
    let store: Arc<dyn ObjectStore> =
        Arc::new(LocalFileSystem::new_with_prefix(remote_dir.path()).unwrap());
    let remote = KeyspaceSet::open("/typedb", store).unwrap();
    assert_eq!(
        remote.local_directory(),
        None,
        "a store reached through an ObjectStore handle must not claim a local directory, even \
         when that handle happens to be backed by one"
    );
}

#[test]
fn a_checkpoint_pin_expires_instead_of_being_held_forever() {
    // A checkpoint keeps every SST it references alive, so GC cannot reclaim them while it
    // exists. SlateDB's default lifetime is None — never expires — and TypeDB checkpoints
    // every 60 seconds, so inheriting that default accrues 1,440 permanent pins a day and
    // storage that only ever grows. The expiry must actually be recorded on the checkpoint,
    // not merely intended.
    let dir = tempfile::tempdir().unwrap();
    let set = KeyspaceSet::open_local(dir.path()).unwrap();
    set.keyspace(KeyspaceId(0)).put(b"k", b"v").unwrap();

    let id = set.checkpoint().unwrap();
    let checkpoint = set
        .checkpoints()
        .unwrap()
        .into_iter()
        .find(|checkpoint| checkpoint.id == id)
        .expect("the checkpoint just taken should be listed");
    assert!(
        checkpoint.expire_time.is_some(),
        "a checkpoint with no expiry pins its SSTs against garbage collection forever"
    );
}

#[test]
fn a_checkpoint_can_be_cloned_into_a_new_store_without_copying_data() {
    // O3's mechanism. TypeDB's RocksDB path checkpoints by copying a directory of files, which
    // has nothing to copy when the store lives in an object store. SlateDB's clone writes a
    // manifest at a new prefix that *references* the checkpoint's SSTs, so a restore moves no
    // data at all — the property that makes point-in-time recovery affordable on a store billed
    // per operation.
    let dir = tempfile::tempdir().unwrap();
    let store: Arc<dyn ObjectStore> =
        Arc::new(LocalFileSystem::new_with_prefix(dir.path()).unwrap());

    let set = KeyspaceSet::open("/source", Arc::clone(&store)).unwrap();
    for i in 0u8..16 {
        set.keyspace(KeyspaceId(0)).put(&[i], b"before-checkpoint").unwrap();
    }
    let checkpoint = set.checkpoint().unwrap();

    // Diverge after the checkpoint. The clone must show the pinned past, not this.
    set.keyspace(KeyspaceId(0)).put(b"later", b"after-checkpoint").unwrap();
    set.flush().unwrap();

    slatedb_keyspace::clone_checkpoint(Arc::clone(&store), "/source", checkpoint, "/restored")
        .expect("clone the checkpoint into a fresh prefix");

    let restored = KeyspaceSet::open("/restored", store).unwrap();
    assert_eq!(
        restored.keyspace(KeyspaceId(0)).get(&[3]).unwrap().as_deref(),
        Some(&b"before-checkpoint"[..]),
        "the clone must carry everything the checkpoint pinned"
    );
    assert!(
        restored.keyspace(KeyspaceId(0)).get(b"later").unwrap().is_none(),
        "and nothing written after it — a restore that includes later writes is not a restore"
    );
}

#[test]
fn releasing_a_checkpoint_reclaims_its_pin() {
    // The expiry on CHECKPOINT_LIFETIME is a backstop for a caller that forgets. A caller that
    // releases should get the SSTs back to garbage collection immediately rather than an hour
    // later, which on a store checkpointed every 60 seconds is the whole difference.
    let dir = tempfile::tempdir().unwrap();
    let set = KeyspaceSet::open_local(dir.path()).unwrap();
    set.keyspace(KeyspaceId(0)).put(b"k", b"v").unwrap();

    let id = set.checkpoint().unwrap();
    assert!(set.checkpoints().unwrap().iter().any(|c| c.id == id));

    set.release_checkpoint(id).unwrap();
    assert!(
        !set.checkpoints().unwrap().iter().any(|c| c.id == id),
        "a released checkpoint must be gone from the manifest, not merely expiring later"
    );
}
