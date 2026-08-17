//! TB-P4 → L1: the Rust remote-WAL client against the control plane running
//! on real workerd (`wrangler dev --local`) with payloads through the local
//! R2 data path. The test boots the stack itself, so `cargo test -p
//! remote-wal-spike --test l1_stack` is a one-command local verification.

use std::{
    net::TcpStream,
    os::unix::process::CommandExt,
    process::{Child, Command, Stdio},
    thread::sleep,
    time::{Duration, Instant},
};

use remote_wal_spike::{
    hex, sha256,
    l1_client::{FinalizeHttpRequest, L1Client},
};

fn port() -> u16 {
    // unique per test process: avoids collisions with dev instances and any
    // previously leaked server
    8800 + (std::process::id() % 400) as u16
}

struct Stack(Child);

impl Drop for Stack {
    fn drop(&mut self) {
        // wrangler spawns workerd grandchildren; kill the whole process group
        // (the child was spawned as its own group leader)
        let _ = Command::new("kill").args(["-9", "--", &format!("-{}", self.0.id())]).status();
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn boot_stack() -> Stack {
    let control_plane_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../control-plane");
    let port = port();
    let child = Command::new("npx")
        .args(["wrangler", "dev", "--local", "--port", &port.to_string()])
        .current_dir(control_plane_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .expect("failed to spawn wrangler dev - is the control-plane npm install done?");
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "wrangler dev did not open port {port} within 120s");
        sleep(Duration::from_millis(500));
    }
    Stack(child)
}

#[test]
fn rust_client_full_protocol_against_workerd() {
    let _stack = boot_stack();
    let client = L1Client::new(format!("http://127.0.0.1:{}", port()));
    // health may lag the port opening by a moment
    let deadline = Instant::now() + Duration::from_secs(30);
    while client.health().is_err() {
        assert!(Instant::now() < deadline, "health never became ok");
        sleep(Duration::from_millis(300));
    }

    // unique namespace per run: wrangler dev persists local DO state on disk
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let db = &format!("rust-e2e-{}-{nonce}", std::process::id());
    client.register_session(db, 1, "sess-r").unwrap();

    // upload + digest agreement
    let payload = b"rust-commit-record-1";
    let digest = hex(&sha256(payload));
    let uploaded = client.upload_payload("rust/g1/p1", payload).unwrap();
    assert_eq!(uploaded.sha256hex, digest);
    assert_eq!(uploaded.length, payload.len() as u64);

    let request = FinalizeHttpRequest {
        database_id: db.into(),
        generation: 1,
        startup_session_id: "sess-r".into(),
        operation_id: "rop-1".into(),
        request_digest: "rrd-1".into(),
        sequencing_kind: "SEQUENCED".into(),
        record_type: 2,
        logical_key: None,
        payload_key: "rust/g1/p1".into(),
        payload_digest: digest.clone(),
        payload_length: payload.len() as u64,
    };

    // finalize allocates lsn 0
    let (status, outcome) = client.finalize(&request).unwrap();
    assert_eq!(status, 200);
    assert_eq!(outcome.append_lsn, Some(0));
    assert_eq!(outcome.replayed, Some(false));

    // lost-response ambiguity: identical re-submission replays identically
    let (_, replay) = client.finalize(&request).unwrap();
    assert_eq!(replay.append_lsn, Some(0));
    assert_eq!(replay.replayed, Some(true));

    // divergent digest for the same operation identity is a typed conflict
    let mut tampered = request.clone();
    tampered.request_digest = "rrd-TAMPERED".into();
    let (status, conflict) = client.finalize(&tampered).unwrap();
    assert_eq!(status, 409);
    assert_eq!(conflict.error.as_deref(), Some("OPERATION_DIGEST_CONFLICT"));

    // payload digest mismatch rejected in the data path (422), before the DO
    let mut wrong_payload = request.clone();
    wrong_payload.operation_id = "rop-2".into();
    wrong_payload.request_digest = "rrd-2".into();
    wrong_payload.payload_digest = "0".repeat(64);
    let (status, rejected) = client.finalize(&wrong_payload).unwrap();
    assert_eq!(status, 422);
    assert_eq!(rejected.error.as_deref(), Some("PAYLOAD_DIGEST_MISMATCH"));

    // exact read-back returns the exact bytes; miss is typed 404
    let (status, read) = client.read_exact(db, 1, 0).unwrap();
    assert_eq!(status, 200);
    assert_eq!(read.payload_digest.as_deref(), Some(digest.as_str()));
    let (status, miss) = client.read_exact(db, 1, 7).unwrap();
    assert_eq!(status, 404);
    assert_eq!(miss.error.as_deref(), Some("NOT_FOUND"));

    // unsequenced record of a different type (statistics-shaped): TypeSequence
    // must NOT advance while the physical LSN does
    let stats_payload = b"rust-statistics-1";
    let stats_digest = hex(&sha256(stats_payload));
    client.upload_payload("rust/g1/stats1", stats_payload).unwrap();
    let mut stats = request.clone();
    stats.operation_id = "rop-stats".into();
    stats.request_digest = "rrd-stats".into();
    stats.sequencing_kind = "UNSEQUENCED".into();
    stats.record_type = 10;
    stats.payload_key = "rust/g1/stats1".into();
    stats.payload_digest = stats_digest;
    stats.payload_length = stats_payload.len() as u64;
    let (status, stats_outcome) = client.finalize(&stats).unwrap();
    assert_eq!(status, 200);
    assert_eq!(stats_outcome.append_lsn, Some(1));
    assert_eq!(stats_outcome.type_sequence, Some(1));

    // head: TypeSequence and physical LSN diverge exactly here
    let head = client.head(db, 1).unwrap();
    assert!(head.ok);
    assert_eq!(head.head_lsn, 1);
    assert_eq!(head.head_type_sequence, 1);

    // pinned iterator + ordered scan with inline verified payloads
    let iterator = client.open_iterator(db, 1).unwrap();
    assert!(iterator.ok);
    assert_eq!(iterator.head_lsn, 1);
    let scan = client.scan(db, 1, 1, 0, iterator.head_lsn, None, 100).unwrap();
    assert!(scan.ok);
    assert_eq!(
        scan.records.iter().map(|r| (r.append_lsn, r.type_sequence, r.record_type)).collect::<Vec<_>>(),
        vec![(0, 1, 2), (1, 1, 10)]
    );
    assert_eq!(scan.next_from_lsn, None);
    // type filter is a catalogue property
    let typed = client.scan(db, 1, 0, 0, iterator.head_lsn, Some(10), 100).unwrap();
    assert_eq!(typed.records.len(), 1);
    assert_eq!(typed.records[0].append_lsn, 1);

    // find_last_type equivalent: last record of the statistics type
    let (status, last) = client.last_by_type(db, 1, 10).unwrap();
    assert_eq!(status, 200);
    assert_eq!(last.record.as_ref().map(|r| r.append_lsn), Some(1));
    let (status, last_miss) = client.last_by_type(db, 1, 99).unwrap();
    assert_eq!(status, 404);
    assert_eq!(last_miss.error.as_deref(), Some("NOT_FOUND"));

    // batch finalize: all-or-nothing, contiguous allocation
    let batch_payload = b"rust-batch-1";
    let batch_digest = hex(&sha256(batch_payload));
    client.upload_payload("rust/g1/b1", batch_payload).unwrap();
    let mut batch_member = request.clone();
    batch_member.operation_id = "rop-b1".into();
    batch_member.request_digest = "rrd-b1".into();
    batch_member.payload_key = "rust/g1/b1".into();
    batch_member.payload_digest = batch_digest;
    batch_member.payload_length = batch_payload.len() as u64;
    let (status, batch) = client.finalize_batch(std::slice::from_ref(&batch_member)).unwrap();
    assert_eq!(status, 200);
    assert!(batch.ok);
    assert_eq!(batch.results.as_ref().map(|r| r.len()), Some(1));
    assert_eq!(batch.results.unwrap()[0].append_lsn, Some(2));

    // register-fences-predecessor (three-lane pin): a new actor's register
    // revokes this session's authority
    client.register_session(db, 1, "sess-r2").unwrap();
    let mut post_takeover = request.clone();
    post_takeover.operation_id = "rop-3".into();
    post_takeover.request_digest = "rrd-3".into();
    let (status, fenced) = client.finalize(&post_takeover).unwrap();
    assert_eq!(status, 409);
    assert_eq!(fenced.error.as_deref(), Some("SESSION_FENCED"));

    // explicit fencing of the new actor too
    client.fence_session(db, 1, "sess-r2").unwrap();
    let mut post_fence = request.clone();
    post_fence.startup_session_id = "sess-r2".into();
    post_fence.operation_id = "rop-4".into();
    post_fence.request_digest = "rrd-4".into();
    let (status, fenced2) = client.finalize(&post_fence).unwrap();
    assert_eq!(status, 409);
    assert_eq!(fenced2.error.as_deref(), Some("SESSION_FENCED"));

    // contiguity audit over everything that allocated
    let audit = client.audit(db, 1).unwrap();
    assert!(audit.contiguous);
    assert_eq!(audit.count, 3);
    assert_eq!(audit.max_lsn, 2);
}
