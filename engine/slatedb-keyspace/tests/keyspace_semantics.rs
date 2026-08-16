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
