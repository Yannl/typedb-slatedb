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
use slatedb_keyspace::{Batch, KeyspaceId, KeyspaceSet};

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
