//! R6-PERF-01 performance qualification: the streaming route measured
//! against the JSON+base64 route it is supposed to replace, with REGRESSION
//! BUDGETS that fail the test rather than print a number.
//!
//! What is measured, and how:
//!
//!   - allocations and peak live bytes: a counting global allocator with
//!     PER-THREAD accounting. `cargo test` gives each test its own thread
//!     and the mock server runs on its own, so the numbers below are the
//!     client's footprint and nothing else. This is the measurement that
//!     actually decides the finding - a route that "streams" but buffers
//!     the record shows up here immediately, deterministically, with no
//!     timing noise;
//!   - RSS: `/proc/self/status` `VmHWM` (peak resident) around the run;
//!   - CPU: `/proc/self/stat` utime+stime ticks;
//!   - latency: wall clock;
//!   - object operations: the number of guarded worker requests the server
//!     observed. On the real surface each exact read is exactly one R2 get,
//!     so an equal count means the streaming route did not buy its memory
//!     profile with extra round trips.
//!
//! Budget policy, stated honestly: the allocation, RSS, wire-byte and
//! operation-count budgets are DETERMINISTIC and tight. The CPU and latency
//! budgets are RELATIVE and deliberately loose, because a debug-profile
//! benchmark over an in-process loopback socket is not a latency lab - they
//! are sized to catch a structural regression (re-reading the spool,
//! hashing twice, buffering) rather than to police percent-level drift.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use remote_wal_spike::{
    hex,
    l1_client::{L1Client, L1Config},
    l1_stream::{RecordConsumer, RecordMeta, ReplayBounds, SpoolDir, SpoolPolicy, VerifiedPayload, MAX_RECORD_BYTES},
    sha256,
};

// ---------------------------------------------------------------------------
// Per-thread allocation accounting.
// ---------------------------------------------------------------------------

thread_local! {
    static LIVE: Cell<i64> = const { Cell::new(0) };
    static PEAK: Cell<i64> = const { Cell::new(0) };
    static TOTAL: Cell<u64> = const { Cell::new(0) };
}

fn note_alloc(size: usize) {
    let _ = LIVE.try_with(|live| {
        let now = live.get() + size as i64;
        live.set(now);
        let _ = PEAK.try_with(|peak| {
            if now > peak.get() {
                peak.set(now);
            }
        });
        let _ = TOTAL.try_with(|total| total.set(total.get() + size as u64));
    });
}

fn note_dealloc(size: usize) {
    let _ = LIVE.try_with(|live| live.set(live.get() - size as i64));
}

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            note_alloc(layout.size());
        }
        ptr
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            note_alloc(layout.size());
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        note_dealloc(layout.size());
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let out = unsafe { System.realloc(ptr, layout, new_size) };
        if !out.is_null() {
            note_dealloc(layout.size());
            note_alloc(new_size);
        }
        out
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn reset_accounting() {
    LIVE.with(|live| live.set(0));
    PEAK.with(|peak| peak.set(0));
    TOTAL.with(|total| total.set(0));
}

fn peak_live_bytes() -> u64 {
    PEAK.with(|peak| peak.get().max(0) as u64)
}

fn total_allocated_bytes() -> u64 {
    TOTAL.with(|total| total.get())
}

// ---------------------------------------------------------------------------
// Process-level counters.
// ---------------------------------------------------------------------------

fn proc_status_kb(field: &str) -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix(field) {
            return rest.trim_start_matches(':').split_whitespace().next().and_then(|v| v.parse().ok()).unwrap_or(0);
        }
    }
    0
}

/// utime + stime in clock ticks. Only ever used as a RATIO, so the tick
/// length never has to be discovered.
fn cpu_ticks() -> u64 {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    // the comm field is parenthesised and may itself contain spaces, so the
    // numeric fields start after the LAST ')'
    let Some((_, tail)) = stat.rsplit_once(')') else { return 0 };
    let fields: Vec<&str> = tail.split_whitespace().collect();
    // stat field 14 (utime) is index 11 of the post-comm tail; 15 (stime) is 12
    let utime: u64 = fields.get(11).and_then(|v| v.parse().ok()).unwrap_or(0);
    let stime: u64 = fields.get(12).and_then(|v| v.parse().ok()).unwrap_or(0);
    utime + stime
}

// ---------------------------------------------------------------------------
// A server that answers the SAME record in both shapes, chosen by `accept`.
// ---------------------------------------------------------------------------

struct Corpus {
    records: Vec<(Vec<u8>, String)>,
    head_lsn: u64,
}

impl Corpus {
    fn new(record_bytes: usize, distinct: usize, head_lsn: u64) -> Corpus {
        let mut records = Vec::with_capacity(distinct);
        for index in 0..distinct {
            let mut bytes = vec![0u8; record_bytes];
            let mut state = 0x5DEE_CE66_D000_0000u64 ^ index as u64;
            for slot in bytes.chunks_mut(8) {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let word = state.to_le_bytes();
                slot.copy_from_slice(&word[..slot.len()]);
            }
            let digest = hex(&sha256(&bytes));
            records.push((bytes, digest));
        }
        Corpus { records, head_lsn }
    }

    fn at(&self, lsn: u64) -> &(Vec<u8>, String) {
        &self.records[(lsn as usize) % self.records.len()]
    }
}

#[derive(Default)]
struct Counters {
    guarded_requests: AtomicU64,
    wire_body_bytes: AtomicU64,
}

struct Server {
    base: String,
    counters: Arc<Counters>,
}

fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut acc = 0u32;
        for (index, byte) in chunk.iter().enumerate() {
            acc |= u32::from(*byte) << (16 - 8 * index);
        }
        for slot in 0..4 {
            if slot < chunk.len() + 1 {
                out.push(ALPHABET[((acc >> (18 - 6 * slot)) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn read_head(stream: &mut TcpStream) -> Option<(String, String, Option<String>, usize)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8_lossy(&buf[..end]).to_string();
    let mut lines = head.lines();
    let mut request_line = lines.next()?.split_whitespace();
    let method = request_line.next()?.to_string();
    let path = request_line.next()?.to_string();
    let mut accept = None;
    let mut content_length = 0usize;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            match name.to_ascii_lowercase().as_str() {
                "accept" => accept = Some(value.trim().to_string()),
                "content-length" => content_length = value.trim().parse().unwrap_or(0),
                _ => {}
            }
        }
    }
    // drain any body so the client's write completes
    let mut body = buf[end + 4..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Some((method, path, accept, content_length))
}

impl Server {
    fn start(corpus: Arc<Corpus>) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().unwrap();
        let counters = Arc::new(Counters::default());
        let shared = Arc::clone(&counters);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let Some((method, path, accept, _)) = read_head(&mut stream) else { continue };
                if method == "POST" && (path == "/issue" || path == "/provision-token") {
                    let body = r#"{"ok":true,"token":"cap","expiresAtMs":1,"incarnation":1}"#;
                    let _ = stream.write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    );
                    continue;
                }
                shared.guarded_requests.fetch_add(1, Ordering::Relaxed);
                if path.ends_with("/head") {
                    let body = format!(
                        r#"{{"ok":true,"headLsn":"{}","headTypeSequence":"{}"}}"#,
                        corpus.head_lsn,
                        corpus.head_lsn + 1
                    );
                    let _ = stream.write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    );
                    continue;
                }
                let lsn: u64 = path.rsplit('/').next().and_then(|v| v.parse().ok()).unwrap_or(0);
                let (bytes, digest) = corpus.at(lsn);
                let streaming = accept.as_deref() == Some("application/octet-stream");
                if streaming {
                    let content_digest = format!("sha-256=:{}:", base64_encode(&sha256(bytes)));
                    let head = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\ncontent-length: {}\r\n\
                         content-digest: {content_digest}\r\nx-payload-sha256: {digest}\r\n\
                         x-payload-length: {}\r\nx-append-lsn: {lsn}\r\nx-type-sequence: {}\r\n\
                         x-record-type: 2\r\nconnection: close\r\n\r\n",
                        bytes.len(),
                        bytes.len(),
                        lsn + 1,
                    );
                    if stream.write_all(head.as_bytes()).is_err() {
                        continue;
                    }
                    for chunk in bytes.chunks(64 * 1024) {
                        if stream.write_all(chunk).is_err() {
                            break;
                        }
                    }
                    shared.wire_body_bytes.fetch_add(bytes.len() as u64, Ordering::Relaxed);
                } else {
                    let body = format!(
                        r#"{{"ok":true,"payloadKey":"p/db/{digest}","payloadDigest":"{digest}","typeSequence":"{}","recordType":2,"payloadBase64":"{}"}}"#,
                        lsn + 1,
                        base64_encode(bytes)
                    );
                    let head = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(head.as_bytes());
                    let _ = stream.write_all(body.as_bytes());
                    shared.wire_body_bytes.fetch_add(body.len() as u64, Ordering::Relaxed);
                }
                let _ = stream.flush();
            }
        });
        Server { base: format!("http://{addr}"), counters }
    }
}

fn client(base: String) -> L1Client {
    let client = L1Client::new(L1Config {
        base: base.clone(),
        issuer_base: base,
        issuer_bearer: "bench".into(),
        principal: "bench".into(),
        tenant_id: "tenant-a".into(),
    });
    client.bind_actor("session-a", 1);
    client
}

fn spool_dir(label: &str) -> SpoolDir {
    let nanos =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or_default();
    SpoolDir::open(std::env::temp_dir().join(format!("l1-bench-{label}-{}-{nanos}", std::process::id())))
        .expect("spool dir")
}

/// Applies nothing but the proof: verifies identity and drops the bytes, so
/// a multi-GiB replay does not become a multi-GiB `Vec`.
#[derive(Default)]
struct CountingConsumer {
    applied: u64,
    acknowledged: u64,
    bytes: u64,
    faults: Vec<String>,
}

impl RecordConsumer for CountingConsumer {
    fn apply(&mut self, meta: &RecordMeta, payload: &VerifiedPayload) -> Result<(), String> {
        if payload.digest() != meta.payload_digest || payload.len() != meta.payload_length {
            self.faults.push(format!("lsn {} identity drift", meta.append_lsn));
        }
        self.applied += 1;
        self.bytes += payload.len();
        Ok(())
    }
    fn acknowledge(&mut self, _meta: &RecordMeta) -> Result<(), String> {
        self.acknowledged += 1;
        Ok(())
    }
}

#[derive(Debug)]
struct Measurement {
    label: &'static str,
    records: u64,
    payload_bytes: u64,
    wall: Duration,
    cpu_ticks: u64,
    peak_live_bytes: u64,
    total_allocated_bytes: u64,
    wire_body_bytes: u64,
    guarded_requests: u64,
    rss_hwm_delta_kb: u64,
}

impl Measurement {
    fn report(&self) {
        println!(
            "  {:<18} records={:<4} payload={:>10} wire={:>10} ops={:<4} wall={:>9?} cpu_ticks={:<5} \
             peak_live={:>10} total_alloc={:>12} rss_hwm_delta={}kB",
            self.label,
            self.records,
            self.payload_bytes,
            self.wire_body_bytes,
            self.guarded_requests,
            self.wall,
            self.cpu_ticks,
            self.peak_live_bytes,
            self.total_allocated_bytes,
            self.rss_hwm_delta_kb,
        );
    }
}

const RECORD_BYTES: usize = 4 * 1024 * 1024;
const BENCH_RECORDS: u64 = 4;

fn measure_json_route(corpus: Arc<Corpus>) -> Measurement {
    let server = Server::start(Arc::clone(&corpus));
    let client = client(server.base.clone());
    let rss_before = proc_status_kb("VmHWM");
    reset_accounting();
    let cpu_before = cpu_ticks();
    let started = Instant::now();
    let mut payload_bytes = 0u64;
    for lsn in 0..BENCH_RECORDS {
        let (status, outcome) = client.read_exact("db", 1, lsn).expect("json read");
        assert_eq!(status, 200);
        let encoded = outcome.payload_base64.expect("payload");
        let bytes = remote_wal_spike::l1_client::base64_decode(&encoded).expect("base64");
        // the buffered route's own contract: the consumer holds the record
        assert_eq!(hex(&sha256(&bytes)), outcome.payload_digest.clone().unwrap());
        payload_bytes += bytes.len() as u64;
    }
    let wall = started.elapsed();
    let cpu = cpu_ticks() - cpu_before;
    Measurement {
        label: "json+base64",
        records: BENCH_RECORDS,
        payload_bytes,
        wall,
        cpu_ticks: cpu,
        peak_live_bytes: peak_live_bytes(),
        total_allocated_bytes: total_allocated_bytes(),
        wire_body_bytes: server.counters.wire_body_bytes.load(Ordering::Relaxed),
        guarded_requests: server.counters.guarded_requests.load(Ordering::Relaxed),
        rss_hwm_delta_kb: proc_status_kb("VmHWM").saturating_sub(rss_before),
    }
}

fn measure_stream_route(corpus: Arc<Corpus>) -> Measurement {
    let server = Server::start(Arc::clone(&corpus));
    let client = client(server.base.clone());
    let dir = spool_dir("stream");
    let rss_before = proc_status_kb("VmHWM");
    reset_accounting();
    let cpu_before = cpu_ticks();
    let started = Instant::now();
    let mut payload_bytes = 0u64;
    for lsn in 0..BENCH_RECORDS {
        let mut options = remote_wal_spike::l1_stream::StreamOptions::default();
        let read = client
            .read_exact_streaming(
                "db",
                1,
                lsn,
                SpoolPolicy::Cache { dir: &dir, max_bytes: MAX_RECORD_BYTES },
                &mut options,
            )
            .expect("streaming read");
        payload_bytes += read.payload.len();
        read.payload.discard().expect("release the cache entry");
    }
    let wall = started.elapsed();
    let cpu = cpu_ticks() - cpu_before;
    Measurement {
        label: "octet-stream",
        records: BENCH_RECORDS,
        payload_bytes,
        wall,
        cpu_ticks: cpu,
        peak_live_bytes: peak_live_bytes(),
        total_allocated_bytes: total_allocated_bytes(),
        wire_body_bytes: server.counters.wire_body_bytes.load(Ordering::Relaxed),
        guarded_requests: server.counters.guarded_requests.load(Ordering::Relaxed),
        rss_hwm_delta_kb: proc_status_kb("VmHWM").saturating_sub(rss_before),
    }
}

// ---------------------------------------------------------------------------
// The budgets.
// ---------------------------------------------------------------------------

#[test]
fn streaming_beats_json_base64_within_every_regression_budget() {
    let corpus = Arc::new(Corpus::new(RECORD_BYTES, 2, BENCH_RECORDS - 1));
    let json = measure_json_route(Arc::clone(&corpus));
    let stream = measure_stream_route(Arc::clone(&corpus));
    println!("\nR6-PERF-01 streaming qualification ({RECORD_BYTES}-byte records):");
    json.report();
    stream.report();

    let record = RECORD_BYTES as u64;
    assert_eq!(json.payload_bytes, record * BENCH_RECORDS, "the baseline read the whole corpus");
    assert_eq!(stream.payload_bytes, record * BENCH_RECORDS, "the streaming route read the whole corpus");

    // ---- BUDGET 1: the streaming route must not hold a record ----------
    // 1 MiB is a quarter of one record: enough headroom for the 64 KiB
    // chunk, the TLS/HTTP buffers and the issuance JSON, and far too little
    // for a 4 MiB payload to hide in.
    const STREAM_PEAK_LIVE_BUDGET: u64 = 1024 * 1024;
    assert!(
        stream.peak_live_bytes <= STREAM_PEAK_LIVE_BUDGET,
        "streaming peak live bytes {} exceeded the {STREAM_PEAK_LIVE_BUDGET}-byte budget: the route is buffering",
        stream.peak_live_bytes
    );

    // ---- BUDGET 2: the comparison must stay honest ----------------------
    // If the baseline ever stops buffering, these budgets are measuring
    // nothing and must fail loudly rather than pass by coincidence.
    assert!(
        json.peak_live_bytes > record,
        "the json+base64 baseline peaked at {} bytes, below one {record}-byte record: \
         the control is no longer buffering and this comparison is void",
        json.peak_live_bytes
    );

    // ---- BUDGET 3: allocation churn ------------------------------------
    assert!(
        stream.total_allocated_bytes * 4 <= json.total_allocated_bytes,
        "streaming allocated {} bytes against the baseline's {}: expected at most a quarter",
        stream.total_allocated_bytes,
        json.total_allocated_bytes
    );

    // ---- BUDGET 4: bytes on the wire ------------------------------------
    // base64 is 4/3 plus a JSON envelope; the streaming route is exactly
    // the payload. A regression that reintroduced any encoding shows here.
    assert_eq!(stream.wire_body_bytes, record * BENCH_RECORDS, "the streaming wire body IS the payload");
    assert!(
        stream.wire_body_bytes * 4 <= json.wire_body_bytes * 3,
        "streaming moved {} wire bytes against the baseline's {}: expected at most 75%",
        stream.wire_body_bytes,
        json.wire_body_bytes
    );

    // ---- BUDGET 5: object operations ------------------------------------
    // one exact read is one R2 get on the real surface; the streaming route
    // must not buy its memory profile with extra round trips
    assert_eq!(
        stream.guarded_requests, json.guarded_requests,
        "streaming spent {} guarded requests against the baseline's {}",
        stream.guarded_requests, json.guarded_requests
    );

    // ---- BUDGET 6: peak RSS ---------------------------------------------
    const STREAM_RSS_BUDGET_KB: u64 = 32 * 1024;
    assert!(
        stream.rss_hwm_delta_kb <= STREAM_RSS_BUDGET_KB,
        "streaming grew peak RSS by {}kB, over the {STREAM_RSS_BUDGET_KB}kB budget",
        stream.rss_hwm_delta_kb
    );

    // ---- BUDGET 7/8: CPU and latency, relative and deliberately loose ---
    // sized to catch a structural regression, not percent-level drift
    assert!(
        stream.cpu_ticks <= json.cpu_ticks.max(1) * 3,
        "streaming burned {} cpu ticks against the baseline's {}: over the 3x structural budget",
        stream.cpu_ticks,
        json.cpu_ticks
    );
    assert!(
        stream.wall <= json.wall * 3,
        "streaming took {:?} against the baseline's {:?}: over the 3x structural budget",
        stream.wall,
        json.wall
    );
}

// ---------------------------------------------------------------------------
// Multi-GiB logical stream under bounded RSS.
// ---------------------------------------------------------------------------

/// Replay a LOGICAL stream of `$L1_STREAM_SOAK_BYTES` bytes (default 64 MiB
/// so the default `cargo test` stays quick) through the streaming route and
/// assert the process footprint stays bounded regardless of the total.
///
/// The stream is SYNTHESISED: an in-process server serves a small pool of
/// distinct 8 MiB records over loopback as many times as the total requires.
/// Nothing is pushed to a real provider - the local harness has no
/// credentials and the finding explicitly allows synthesis - but every byte
/// really does cross a socket, get hashed, get spooled to disk, get proven
/// and get released, which is the part the RSS bound is about.
#[test]
fn a_multi_gib_logical_stream_replays_under_a_bounded_rss() {
    let total: u64 =
        std::env::var("L1_STREAM_SOAK_BYTES").ok().and_then(|v| v.parse().ok()).unwrap_or(64 * 1024 * 1024);
    let record_bytes = MAX_RECORD_BYTES as usize;
    let records = total.div_ceil(record_bytes as u64);
    let corpus = Arc::new(Corpus::new(record_bytes, 4, records - 1));
    let server = Server::start(Arc::clone(&corpus));
    let client = client(server.base.clone());
    let dir = spool_dir("soak");
    let mut consumer = CountingConsumer::default();

    let rss_before = proc_status_kb("VmHWM");
    reset_accounting();
    let started = Instant::now();
    let report = client
        .replay_streaming(
            "db",
            1,
            0,
            ReplayBounds { max_records: records, max_record_bytes: MAX_RECORD_BYTES, page_records: 256 },
            SpoolPolicy::Cache { dir: &dir, max_bytes: MAX_RECORD_BYTES },
            &mut consumer,
        )
        .unwrap_or_else(|(report, error)| panic!("soak replay failed after {report:?}: {error}"));
    let wall = started.elapsed();
    let rss_delta = proc_status_kb("VmHWM").saturating_sub(rss_before);
    let peak_live = peak_live_bytes();

    println!(
        "\nR6-PERF-01 soak: {} logical bytes over {} records in {:?} \
         (peak_live={peak_live} rss_hwm_delta={rss_delta}kB rss_hwm={}kB)",
        report.bytes,
        report.applied,
        wall,
        proc_status_kb("VmHWM"),
    );

    assert!(consumer.faults.is_empty(), "identity drift: {:?}", consumer.faults);
    assert_eq!(report.applied, records);
    assert_eq!(report.acknowledged, records);
    assert_eq!(report.bytes, records * record_bytes as u64);
    assert!(report.bytes >= total, "the logical stream was smaller than asked for");

    // O(chunk), not O(stream): the budgets below do NOT scale with the
    // total, which is the whole claim.
    const SOAK_PEAK_LIVE_BUDGET: u64 = 1024 * 1024;
    const SOAK_RSS_BUDGET_KB: u64 = 64 * 1024;
    assert!(
        peak_live <= SOAK_PEAK_LIVE_BUDGET,
        "soak peak live bytes {peak_live} exceeded the {SOAK_PEAK_LIVE_BUDGET}-byte budget"
    );
    assert!(
        rss_delta <= SOAK_RSS_BUDGET_KB,
        "soak grew peak RSS by {rss_delta}kB, over the {SOAK_RSS_BUDGET_KB}kB budget"
    );

    // and the cache is empty: every record was released after it was
    // applied, so disk is O(record) too
    assert!(dir.committed_digests().expect("list").is_empty());
}

// ---------------------------------------------------------------------------
// Upload-side footprint.
// ---------------------------------------------------------------------------

#[test]
fn a_streaming_upload_never_holds_the_record() {
    use remote_wal_spike::l1_stream::{fingerprint, SyntheticSource};

    let source = SyntheticSource { length: MAX_RECORD_BYTES, seed: 99 };
    let measured = fingerprint(&source, MAX_RECORD_BYTES).expect("measure");
    let digest = measured.digest.clone();
    let length = measured.length;

    // a receipt-only server: it drains the body and answers the receipt
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    let observed = Arc::new(AtomicU64::new(0));
    let seen_digest = Arc::new(std::sync::Mutex::new(String::new()));
    let counted = Arc::clone(&observed);
    let recorded = Arc::clone(&seen_digest);
    let expected = digest.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut buf = Vec::new();
            let mut chunk = [0u8; 8192];
            let end = loop {
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break pos;
                }
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => return,
                    Ok(read) => buf.extend_from_slice(&chunk[..read]),
                }
            };
            let head = String::from_utf8_lossy(&buf[..end]).to_string();
            let method = head.split_whitespace().next().unwrap_or_default().to_string();
            if method == "POST" {
                let body = format!(r#"{{"ok":true,"token":"cap","key":"p/db/{expected}"}}"#);
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                );
                continue;
            }
            let content_length: usize = head
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase().strip_prefix("content-length:").map(str::trim).map(str::to_string)
                })
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            // hash the uploaded body incrementally: the SERVER must not
            // buffer it either, or this test measures its own harness
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            let mut total = buf.len() - end - 4;
            hasher.update(&buf[end + 4..]);
            while total < content_length {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        hasher.update(&chunk[..read]);
                        total += read;
                    }
                }
            }
            counted.store(total as u64, Ordering::Relaxed);
            let raw: [u8; 32] = hasher.finalize().into();
            *recorded.lock().unwrap() = hex(&raw);
            let body = format!(
                r#"{{"key":"p/db/{expected}","sha256hex":"{expected}","length":{content_length},"deduplicated":false}}"#
            );
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            );
        }
    });

    let client = client(format!("http://{addr}"));
    reset_accounting();
    let receipt = client.upload_payload_streaming("db", &source, MAX_RECORD_BYTES).expect("upload");
    let peak = peak_live_bytes();
    println!("\nR6-PERF-01 upload: {length} bytes, peak_live={peak}");

    assert_eq!(receipt.digest, digest);
    assert_eq!(observed.load(Ordering::Relaxed), length);
    assert_eq!(*seen_digest.lock().unwrap(), digest, "the exact bytes arrived");

    // BUDGET: an 8 MiB record must never be resident. 1 MiB leaves room for
    // the chunk buffers on both passes and the HTTP machinery.
    const UPLOAD_PEAK_LIVE_BUDGET: u64 = 1024 * 1024;
    assert!(
        peak <= UPLOAD_PEAK_LIVE_BUDGET,
        "streaming upload peaked at {peak} live bytes for a {length}-byte record, \
         over the {UPLOAD_PEAK_LIVE_BUDGET}-byte budget"
    );
}
