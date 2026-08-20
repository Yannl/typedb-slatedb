//! The pinned SlateDB over a LocalFS object store vs the ordered-map oracle.
//!
//! Each check maps to a TypeDB keyspace-layer assumption the U2 swap relies
//! on; a failure here means TB-P7 must NOT proceed on the current pin.

use std::{collections::BTreeMap, sync::Arc};

use slatedb::{object_store::local::LocalFileSystem, Db, WriteBatch};
use storage_diff_spike::{apply_to_oracle, generate_workload, prefix_bounds, Op, Oracle};

async fn full_scan(db: &Db) -> BTreeMap<Vec<u8>, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut iter = db.scan::<std::ops::RangeFull>(..).await.expect("scan open");
    while let Some(kv) = iter.next().await.expect("scan next") {
        out.insert(kv.key.to_vec(), kv.value.to_vec());
    }
    out
}

async fn range_scan(db: &Db, start: Vec<u8>, end: Vec<u8>) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    let mut iter = db.scan(start..end).await.expect("range scan open");
    while let Some(kv) = iter.next().await.expect("range next") {
        out.push((kv.key.to_vec(), kv.value.to_vec()));
    }
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn slatedb_localfs_matches_ordered_oracle() {
    let dir = std::env::temp_dir().join(format!("slatedb-diff-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = Arc::new(LocalFileSystem::new_with_prefix(&dir).unwrap());

    let db = Db::open("diff/db", store.clone()).await.expect("open slatedb");
    let mut oracle: Oracle = Oracle::new();

    // seeded workload; mirror every op into both sides.
    // R6-HYGIENE-01, documented allowance: the seed is grouped to spell
    // "slatedb", which is the point of a fixed differential seed - it is
    // recognisable in logs and evidence. clippy's regrouping to `0x051a_7edb`
    // is the same number and loses that. The VALUE is load-bearing (changing
    // it changes the workload and therefore the archived evidence), the
    // grouping is not.
    #[allow(clippy::unusual_byte_groupings)]
    let workload = generate_workload(0x51a7ed_b, 1500);
    for (i, op) in workload.iter().enumerate() {
        match op {
            Op::Put(k, v) => {
                db.put(k, v).await.expect("put");
            }
            Op::Delete(k) => {
                db.delete(k).await.expect("delete");
            }
            Op::Batch(entries) => {
                let mut batch = WriteBatch::new();
                for (k, v) in entries {
                    match v {
                        Some(v) => batch.put(k, v),
                        None => batch.delete(k),
                    }
                }
                db.write(batch).await.expect("batch write");
            }
        }
        apply_to_oracle(&mut oracle, op);

        // read-your-writes on the touched keys, immediately after each op
        if let Op::Put(k, _) | Op::Delete(k) = op {
            let got = db.get(k).await.expect("get");
            assert_eq!(got.as_deref(), oracle.get(k).map(|v| v.as_slice()), "read-your-writes at step {i}");
        }

        // periodic full equivalence: order AND content
        if i % 250 == 249 {
            let scanned = full_scan(&db).await;
            assert_eq!(scanned, oracle, "full-scan equivalence at step {i}");
        }
    }

    // batch atomicity witness: a batch that puts K1..K3 and deletes K4 must be
    // all-visible
    let (k1, k2, k3, k4) = (vec![9u8, 1], vec![9u8, 2], vec![9u8, 3], vec![9u8, 4]);
    db.put(&k4, b"pre").await.unwrap();
    let mut batch = WriteBatch::new();
    batch.put(&k1, b"a");
    batch.put(&k2, b"b");
    batch.put(&k3, b"c");
    batch.delete(&k4);
    db.write(batch).await.unwrap();
    for (k, expect) in [(&k1, Some(&b"a"[..])), (&k2, Some(&b"b"[..])), (&k3, Some(&b"c"[..])), (&k4, None)] {
        assert_eq!(db.get(k).await.unwrap().as_deref(), expect, "batch atomicity");
    }
    oracle.insert(k1, b"a".to_vec());
    oracle.insert(k2, b"b".to_vec());
    oracle.insert(k3, b"c".to_vec());
    oracle.remove(&k4);

    // prefix-range scans: every prefix range equals the oracle's view,
    // in byte order, half-open bounds
    for prefix in [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xFF] {
        let (start, end) = prefix_bounds(prefix);
        let (scanned, expected): (Vec<_>, Vec<_>) = match end {
            Some(end) => (
                range_scan(&db, start.clone(), end.clone()).await,
                oracle.range(start..end).map(|(k, v)| (k.clone(), v.clone())).collect(),
            ),
            None => {
                // top prefix: unbounded upper end
                let mut out = Vec::new();
                let mut iter = db.scan(start.clone()..).await.expect("open");
                while let Some(kv) = iter.next().await.expect("next") {
                    out.push((kv.key.to_vec(), kv.value.to_vec()));
                }
                (out, oracle.range(start..).map(|(k, v)| (k.clone(), v.clone())).collect())
            }
        };
        assert_eq!(scanned, expected, "prefix {prefix} range equivalence");
    }

    // reopen durability: flush, close, reopen over the same LocalFS store -
    // the full state must survive byte-for-byte
    db.flush().await.expect("flush");
    db.close().await.expect("close");
    let reopened = Db::open("diff/db", store).await.expect("reopen");
    let scanned = full_scan(&reopened).await;
    assert_eq!(scanned, oracle, "reopen durability equivalence");
    reopened.close().await.unwrap();

    std::fs::remove_dir_all(&dir).ok();
}

/// Negative control: the differential harness must actually detect
/// divergence - a corrupted oracle must fail the comparison.
#[tokio::test(flavor = "multi_thread")]
async fn negative_control_detects_divergence() {
    let dir = std::env::temp_dir().join(format!("slatedb-diff-neg-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = Arc::new(LocalFileSystem::new_with_prefix(&dir).unwrap());
    let db = Db::open("neg/db", store).await.unwrap();

    db.put(b"k", b"engine-value").await.unwrap();
    let mut oracle = Oracle::new();
    oracle.insert(b"k".to_vec(), b"different-oracle-value".to_vec());

    let scanned = full_scan(&db).await;
    assert_ne!(scanned, oracle, "harness must detect a planted divergence");
    db.close().await.unwrap();
    std::fs::remove_dir_all(&dir).ok();
}
