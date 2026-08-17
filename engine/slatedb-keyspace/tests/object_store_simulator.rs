/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! The lane running against real object storage over HTTP.
//!
//! Everything else in this suite talks to a `LocalFileSystem` object store, which exercises the
//! same Rust code path and none of the network. What is untested there is exactly what R2 adds:
//! SigV4 signing, endpoint and addressing style, conditional-put semantics, and the cost of each
//! operation. Those are the parts where a mistake is invisible locally and expensive or
//! corrupting in production.
//!
//! # The two backends, and why both
//!
//! `build/simulator` brings up three processes. **MinIO** is a faithful S3 implementation and is
//! authoritative for the protocol: if the `AmazonS3Builder` configuration is wrong, MinIO
//! rejects it the way any S3 service would. **workerd** runs an S3 façade over a real R2 binding
//! through Miniflare, and is authoritative for R2's storage semantics — above all conditional
//! put, which is what SlateDB's manifest compare-and-swap is built on and therefore what the
//! single-writer guarantee rests on. Neither substitutes for the other.
//!
//! The third process is an **operation counter** in front of MinIO that classifies requests the
//! way R2 bills them. It exists so the cost claims this backend was tuned around stop being
//! assertions in a comment and become assertions in a test.
//!
//! # Running these
//!
//! ```text
//! build/simulator/sim.sh up
//! TYPEDB_SIM_ENDPOINT=http://127.0.0.1:9100 cargo test --test object_store_simulator
//! ```
//!
//! Without `TYPEDB_SIM_ENDPOINT` every test here returns immediately. That is deliberate opt-in
//! rather than an automatic probe: a suite that quietly skips when its dependency is missing
//! reports success for work it did not do, and this is the suite whose absence would be least
//! noticed.

use std::{sync::Arc, time::Duration};

use slatedb_keyspace::{Batch, KeyspaceId, KeyspaceSet, R2Credentials, StoreConfig, Tuning};

/// The counting proxy in front of MinIO. Protocol fidelity, plus a bill.
fn counted_endpoint() -> Option<String> {
    std::env::var("TYPEDB_SIM_ENDPOINT").ok()
}

/// The workerd R2 shim. R2's own conditional-put implementation.
fn workerd_endpoint() -> String {
    std::env::var("TYPEDB_SIM_WORKERD").unwrap_or_else(|_| "http://127.0.0.1:9200".to_string())
}

fn credentials(endpoint: &str) -> R2Credentials {
    R2Credentials {
        account_id: "simulator".to_string(),
        bucket: "typedb".to_string(),
        access_key_id: "typedbtest".to_string(),
        secret_access_key: "typedbtest123".to_string(),
        endpoint: Some(endpoint.to_string()),
    }
}

/// A distinct prefix per test, so tests sharing one bucket cannot see each other's objects.
///
/// Derived from the test's own name rather than a random value: a leftover prefix from a failed
/// run should be inspectable and overwritable by the next run of the same test, not accumulate
/// as anonymous debris.
fn store_for(test: &str, endpoint: &str, tuning: Tuning) -> KeyspaceSet {
    let credentials = credentials(endpoint);
    let mut config = StoreConfig::r2(format!("it/{test}"), &credentials).expect("build R2 store");
    config.tuning = tuning;
    KeyspaceSet::open_with(config).expect("open against the simulator")
}

fn cache_dir(test: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("typedb-sim-cache/{test}"))
}

/// Object-storage tuning with the block cache pointed somewhere test-local.
fn tuning_for(test: &str) -> Tuning {
    Tuning::object_storage().with_cache_dir(cache_dir(test))
}

/// Tuning for tests that assert on operation counts.
///
/// SlateDB polls the manifest on a timer, so a long-running test can have a background poll land
/// inside its measurement window and be charged for traffic the code under test never issued.
/// Pushing the interval past any plausible test duration makes the count reflect the operation
/// being measured rather than how long the suite happened to take to reach it — without it the
/// assertion passes or fails on timing, which is the kind of flake that gets rerun rather than
/// read.
fn quiet_tuning_for(test: &str) -> Tuning {
    let mut tuning = tuning_for(test);
    tuning.manifest_poll_interval = Duration::from_secs(3600);
    tuning
}

// ---------------------------------------------------------------------------------------
// Operation accounting
// ---------------------------------------------------------------------------------------

#[derive(Debug, Default)]
struct Ops {
    class_a: u64,
    class_b: u64,
    free: u64,
}

impl Ops {
    fn total(&self) -> u64 {
        self.class_a + self.class_b + self.free
    }
}

/// Read the proxy's tally.
///
/// Hand-parsed rather than pulling in a JSON dependency for three integers: the shape is fixed
/// by `op-counter.mjs` next door, and a serde dependency in this crate's dev-dependencies would
/// outlive the reason for it.
fn read_ops(endpoint: &str) -> Ops {
    let body = http_get(&format!("{endpoint}/__ops"));
    let field = |name: &str| -> u64 {
        body.split(&format!("\"{name}\""))
            .nth(1)
            .and_then(|rest| rest.split(|c: char| c == ',' || c == '\n' || c == '}').next())
            .and_then(|value| value.trim_start_matches(':').trim().parse().ok())
            .unwrap_or(0)
    };
    Ops { class_a: field("A"), class_b: field("B"), free: field("free") }
}

fn reset_ops(endpoint: &str) {
    let _ = http_get(&format!("{endpoint}/__ops/reset"));
}

/// A minimal blocking HTTP GET.
///
/// The crate has no HTTP client of its own and does not want one; `object_store` owns that
/// concern. This talks only to the counter's control plane on loopback.
fn http_get(url: &str) -> String {
    use std::io::{Read, Write};

    let rest = url.strip_prefix("http://").expect("loopback http url");
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let mut stream = std::net::TcpStream::connect(authority).expect("connect to op-counter");
    write!(stream, "GET /{path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n")
        .expect("write request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");
    response
}

/// Skip the body of a test when the simulator is not running.
macro_rules! require_simulator {
    () => {
        match counted_endpoint() {
            Some(endpoint) => endpoint,
            None => {
                eprintln!("skipped: set TYPEDB_SIM_ENDPOINT (see build/simulator/sim.sh up)");
                return;
            }
        }
    };
}

// ---------------------------------------------------------------------------------------
// Protocol: does the S3 configuration this crate ships actually work?
// ---------------------------------------------------------------------------------------

#[test]
fn the_r2_configuration_round_trips_against_a_real_s3_service() {
    let endpoint = require_simulator!();
    let set = store_for("roundtrip", &endpoint, tuning_for("roundtrip"));

    let keyspace = set.keyspace(KeyspaceId(0));
    keyspace.put(b"alpha", b"one").unwrap();
    keyspace.put(b"beta", b"two").unwrap();

    assert_eq!(keyspace.get(b"alpha").unwrap().as_deref(), Some(&b"one"[..]));

    // Ordering and range bounds survive the wire, which is the property every iterator in
    // TypeDB depends on and the one a serialization mistake would quietly break.
    let mut seen = Vec::new();
    let mut cursor = keyspace.iterate_from(&[]).unwrap();
    while let Some((key, _)) = cursor.advance().unwrap() {
        seen.push(key.to_vec());
    }
    assert_eq!(seen, vec![b"alpha".to_vec(), b"beta".to_vec()]);

    set.flush().unwrap();
    set.close().unwrap();
}

#[test]
fn data_written_through_the_network_survives_a_reopen() {
    let endpoint = require_simulator!();

    {
        let set = store_for("reopen", &endpoint, tuning_for("reopen"));
        let mut batch = Batch::new();
        for i in 0u16..500 {
            batch.put(KeyspaceId(1), &i.to_be_bytes(), b"payload");
        }
        set.write(batch).unwrap();
        set.flush().unwrap();
        set.close().unwrap();
    }

    // A fresh cache directory, so the reopen cannot be answered from local disk. Without this
    // the test would pass against an empty bucket.
    let mut tuning = Tuning::object_storage();
    tuning = tuning.with_cache_dir(cache_dir("reopen-cold"));
    let reopened = store_for("reopen", &endpoint, tuning);
    assert_eq!(
        reopened.keyspace(KeyspaceId(1)).stats().unwrap().0,
        500,
        "every acknowledged, flushed write must be readable from object storage alone"
    );
}

#[test]
fn r2s_own_conditional_put_backs_the_manifest_commit() {
    // Against workerd, so the compare-and-swap is evaluated by R2's implementation of
    // If-Match/If-None-Match rather than MinIO's. This is the mechanism the single-writer
    // guarantee rests on: if it silently degraded to an unconditional put, two writers would
    // both believe they hold the lease and the manifest would fork.
    if counted_endpoint().is_none() {
        eprintln!("skipped: set TYPEDB_SIM_ENDPOINT (see build/simulator/sim.sh up)");
        return;
    }
    let endpoint = workerd_endpoint();
    let set = store_for("workerd", &endpoint, tuning_for("workerd"));

    set.keyspace(KeyspaceId(0)).put(b"through-r2", b"value").unwrap();
    assert_eq!(
        set.keyspace(KeyspaceId(0)).get(b"through-r2").unwrap().as_deref(),
        Some(&b"value"[..])
    );
    set.flush().unwrap();
    set.close().unwrap();
}

// ---------------------------------------------------------------------------------------
// Cost: the claims this backend was tuned around, measured
// ---------------------------------------------------------------------------------------

#[test]
fn a_commit_spanning_every_keyspace_costs_one_write() {
    // Finding 08. `Keyspaces::write` used to loop, issuing one object-store write per keyspace
    // a commit touched — the shape RocksDB forces, where each keyspace is its own database.
    // Against SlateDB they share one store, so the loop multiplied the most frequent operation
    // in the system by the number of keyspaces for no benefit. Nothing but an operation count
    // can see the difference.
    let endpoint = require_simulator!();
    let set = store_for("one-write", &endpoint, quiet_tuning_for("one-write"));

    // Settle the store before measuring, so open-time traffic is not attributed to the commit.
    set.keyspace(KeyspaceId(0)).put(b"warm", b"up").unwrap();
    set.flush().unwrap();

    reset_ops(&endpoint);

    let mut batch = Batch::new();
    for keyspace in 0u8..5 {
        batch.put(KeyspaceId(keyspace), b"committed", b"value");
    }
    set.write(batch).unwrap();
    set.flush().unwrap();

    let ops = read_ops(&endpoint);
    assert!(
        ops.class_a <= 2,
        "a commit touching 5 keyspaces should cost one write plus at most a manifest update, \
         got {} Class A operations: {ops:?}",
        ops.class_a
    );
}

#[test]
fn polling_the_store_size_costs_nothing() {
    // Finding 02. TypeDB's diagnostics loop asks for this every 15 seconds, and the obvious
    // implementation scans. Against object storage that is a standing demand to drag the whole
    // database across the network four times a minute, forever, while idle. The manifest already
    // holds the answer, and the handle already holds the manifest.
    let endpoint = require_simulator!();
    let set = store_for("free-metrics", &endpoint, quiet_tuning_for("free-metrics"));

    let mut batch = Batch::new();
    for i in 0u16..2000 {
        batch.put(KeyspaceId(0), &i.to_be_bytes(), &[b'x'; 128]);
    }
    set.write(batch).unwrap();
    set.flush().unwrap();

    reset_ops(&endpoint);

    // Sixty polls is fifteen minutes of the real diagnostics loop.
    let mut last = 0;
    for _ in 0..60 {
        last = set.size_bytes();
    }

    let ops = read_ops(&endpoint);
    assert_eq!(
        ops.total(),
        0,
        "sixty size polls must not touch the network at all, got {ops:?} (size reported {last})"
    );
    let _ = last;
}

#[test]
fn a_memoized_estimate_scans_once_not_once_per_poll() {
    // Finding 02, the half that cannot be answered from the manifest. The scan remains, so what
    // is under test is that it happens once per TTL rather than once per caller.
    let endpoint = require_simulator!();
    let set = store_for("memo", &endpoint, quiet_tuning_for("memo"))
        .with_estimate_ttl(Duration::from_secs(3600));

    let mut batch = Batch::new();
    for i in 0u16..2000 {
        batch.put(KeyspaceId(0), &i.to_be_bytes(), &[b'x'; 128]);
    }
    set.write(batch).unwrap();
    set.flush().unwrap();

    let keyspace = set.keyspace(KeyspaceId(0));
    keyspace.estimated_stats().unwrap();

    reset_ops(&endpoint);
    for _ in 0..60 {
        keyspace.estimated_stats().unwrap();
    }

    let ops = read_ops(&endpoint);
    assert_eq!(
        ops.total(),
        0,
        "sixty polls inside one TTL must be served from the memo, got {ops:?}"
    );
}

#[test]
fn reading_back_what_was_just_written_stays_on_the_machine() {
    // The block cache with `cache_on_flush`, which is the whole reason the R2 profile spends
    // local disk. An agent that ingests a document and immediately queries it is the common
    // case for a knowledge base, and without the cache that read leaves the machine to fetch
    // bytes this process produced moments ago.
    let endpoint = require_simulator!();
    let set = store_for("warm-read", &endpoint, quiet_tuning_for("warm-read"));

    let mut batch = Batch::new();
    for i in 0u16..1000 {
        batch.put(KeyspaceId(2), &i.to_be_bytes(), b"ingested document chunk");
    }
    set.write(batch).unwrap();
    set.flush().unwrap();

    reset_ops(&endpoint);
    for i in 0u16..1000 {
        assert!(set.keyspace(KeyspaceId(2)).get(&i.to_be_bytes()).unwrap().is_some());
    }

    let ops = read_ops(&endpoint);
    assert!(
        ops.class_b < 200,
        "1000 reads of just-written data should mostly be served locally, got {ops:?}"
    );
}

// ---------------------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------------------

#[test]
fn a_second_writer_fences_the_first() {
    // Finding O5's premise. The R2 profile assumes a single writer and polls the manifest every
    // 30 seconds accordingly. That assumption is only safe if a second writer opening the same
    // store is *detected* rather than silently tolerated — SlateDB fences by writer epoch, and
    // this checks the mechanism survives the trip through R2's conditional put.
    let endpoint = require_simulator!();

    let first = store_for("fencing", &endpoint, tuning_for("fencing"));
    first.keyspace(KeyspaceId(0)).put(b"before", b"fence").unwrap();
    first.flush().unwrap();

    // Opening the same prefix again bumps the writer epoch, fencing the first handle.
    let second = store_for("fencing", &endpoint, tuning_for("fencing-2"));
    second.keyspace(KeyspaceId(0)).put(b"after", b"fence").unwrap();
    second.flush().unwrap();

    assert_eq!(
        second.keyspace(KeyspaceId(0)).get(b"before").unwrap().as_deref(),
        Some(&b"fence"[..]),
        "the new writer must see what the fenced one committed"
    );

    // The fenced writer must not be able to keep committing as though it still held the store.
    // Whether the failure arrives at the write or at the flush is SlateDB's business; that it
    // arrives is not.
    let fenced = first.keyspace(KeyspaceId(0)).put(b"zombie", b"write");
    let flushed = first.flush();
    assert!(
        fenced.is_err() || flushed.is_err(),
        "a fenced writer silently accepting writes is the split-brain this check exists for"
    );
}

#[test]
fn concurrent_readers_share_one_store_safely() {
    // The engine hands out `Keyspace` handles by borrow and memoizes estimates behind a mutex.
    // Under real network latency the windows are wide enough to matter, which they are not
    // against a local filesystem.
    let endpoint = require_simulator!();
    let set = Arc::new(store_for("concurrent", &endpoint, tuning_for("concurrent")));

    let mut batch = Batch::new();
    for i in 0u16..500 {
        batch.put(KeyspaceId(3), &i.to_be_bytes(), b"shared");
    }
    set.write(batch).unwrap();
    set.flush().unwrap();

    let handles: Vec<_> = (0..4)
        .map(|_| {
            let set = Arc::clone(&set);
            std::thread::spawn(move || {
                for i in 0u16..500 {
                    assert!(set.keyspace(KeyspaceId(3)).get(&i.to_be_bytes()).unwrap().is_some());
                }
                set.keyspace(KeyspaceId(3)).estimated_stats().unwrap()
            })
        })
        .collect();

    for handle in handles {
        let (keys, _) = handle.join().expect("no reader may panic");
        assert_eq!(keys, 500);
    }
}

#[test]
fn the_key_count_reads_sst_metadata_rather_than_the_data() {
    // O2, measured. The count now sums per-SST row counts out of each SST's stats block, so its
    // cost tracks the number of SSTs and not the number of keys. The assertion is deliberately
    // on operations rather than on wall-clock: a scan of this store would be thousands of block
    // reads, and only an operation count distinguishes that from a handful of small ranged ones.
    let endpoint = require_simulator!();
    let mut tuning = quiet_tuning_for("sst-metadata");
    tuning.l0_sst_size_bytes = 64 * 1024;
    let set = store_for("sst-metadata", &endpoint, tuning);

    let mut batch = Batch::new();
    for i in 0u16..8000 {
        batch.put(KeyspaceId(0), &i.to_be_bytes(), &[b'v'; 64]);
    }
    set.write(batch).unwrap();
    set.flush().unwrap();

    // Let the memtable reach L0, so there is real SST metadata to read.
    for _ in 0..100 {
        if set.estimated_key_count().unwrap() > 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    reset_ops(&endpoint);
    let counted = set.estimated_key_count().unwrap();
    let ops = read_ops(&endpoint);

    assert!(counted > 0, "the store holds 8000 rows, so the count must not be zero");
    assert!(
        ops.total() < 64,
        "counting rows should cost a read per SST, not a read per block of data: {ops:?}"
    );
}
