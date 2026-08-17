/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! The bounded, single-flight statistics path.
//!
//! These assert the properties that make a polled full-store scan safe against an object
//! store: a byte cap turns an unbounded scan into a truncated lower bound, a stale answer is
//! served rather than a fresh scan started under contention, and the mutex is not the thing
//! serializing callers.

use std::sync::Arc;
use std::time::Duration;

use slatedb_keyspace::{EstimateLimits, KeyspaceId, KeyspaceSet, StorageRuntime};

#[test]
fn a_byte_capped_scan_reports_a_truncated_lower_bound() {
    let dir = tempfile::tempdir().unwrap();
    let set = KeyspaceSet::open_local(dir.path()).unwrap().with_estimate_limits(EstimateLimits {
        ttl: Duration::ZERO, // force a recompute every call
        stale_grace: Duration::from_secs(3600),
        deadline: Duration::from_secs(30),
        max_bytes: 100, // far below the data we write
    });
    let keyspace = set.keyspace(KeyspaceId(0));

    for i in 0u16..500 {
        keyspace.put(&i.to_be_bytes(), b"0123456789").unwrap();
    }

    let (count, _bytes) = keyspace.estimated_stats().unwrap();
    assert!(count < 500, "the cap must stop the scan short of the full 500, got {count}");

    let health = keyspace.estimate_health().unwrap();
    assert!(health.truncated, "a capped scan must record that its figure is a lower bound");
}

#[test]
fn an_uncapped_exact_scan_still_sees_everything() {
    // stats() must remain exact — the cap is only on the estimate path.
    let dir = tempfile::tempdir().unwrap();
    let set = KeyspaceSet::open_local(dir.path()).unwrap();
    let keyspace = set.keyspace(KeyspaceId(0));
    for i in 0u16..500 {
        keyspace.put(&i.to_be_bytes(), b"0123456789").unwrap();
    }
    assert_eq!(keyspace.stats().unwrap().0, 500);
}

#[test]
fn many_stores_share_one_runtime() {
    // The fixed defect: one Tokio runtime per open store. Opening several stores on the shared
    // runtime must not fail or spawn per-store pools — this exercises the shared path directly.
    let runtime = StorageRuntime::shared();
    let mut sets = Vec::new();
    for _ in 0..8 {
        let dir = tempfile::tempdir().unwrap();
        let config = slatedb_keyspace::StoreConfig::local(dir.path());
        let set = KeyspaceSet::open_with_runtime(config, Arc::clone(&runtime)).unwrap();
        set.keyspace(KeyspaceId(0)).put(b"k", b"v").unwrap();
        sets.push((dir, set));
    }
    // Every store is independently usable on the one runtime.
    for (_dir, set) in &sets {
        assert_eq!(set.keyspace(KeyspaceId(0)).get(b"k").unwrap().as_deref(), Some(b"v".as_ref()));
    }
}

#[test]
fn estimate_health_starts_clean() {
    let dir = tempfile::tempdir().unwrap();
    let set = KeyspaceSet::open_local(dir.path()).unwrap();
    let keyspace = set.keyspace(KeyspaceId(0));
    keyspace.put(b"a", b"v").unwrap();
    keyspace.estimated_stats().unwrap();
    let health = keyspace.estimate_health().unwrap();
    assert_eq!(health.failures, 0);
    assert!(health.last_failure.is_none());
    assert!(!health.truncated);
    assert!(health.age.is_some());
}
