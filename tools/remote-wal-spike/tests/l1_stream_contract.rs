//! R6-PERF-01 acceptance suite for the STREAMING data path, driven against a
//! byte-level mock that can do the things a real network and a real Worker
//! can do and a JSON fixture cannot: corrupt one chunk in the middle of a
//! transfer, stop early, frame chunked, send more than it declared, drip
//! slowly, reset the connection, and fence between records.
//!
//! Every failure case asserts the SAME two things, because they are the
//! invariant the finding is about:
//!
//!   - the call produced no `VerifiedPayload` (there is no other way to get
//!     bytes out of the streaming path, so "no payload" means "no bytes");
//!   - the consumer applied nothing and acknowledged nothing, and the
//!     content-addressed spool published no entry - not even a partial.

use std::{
    collections::VecDeque,
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

use remote_wal_spike::{
    hex,
    l1_client::{L1Client, L1Config, L1Error, ScanQuery},
    l1_stream::{
        fingerprint, Flow, IntegrityFault, RecordingConsumer, ReplayBounds, SpoolDir, SpoolPolicy, StreamError,
        StreamOptions, SyntheticSource, MAX_RECORD_BYTES, MAX_SCAN_PAGE_RECORDS,
    },
    sha256,
};

const BEARER: &str = "stream-contract-issuer-bearer-0123456789";
/// The mock's transmit granularity: four chunks over a 64 KiB record, so
/// "first", "middle" and "last" are genuinely different positions on the
/// wire rather than three names for one buffer.
const MOCK_CHUNK: usize = 16 * 1024;

// ---------------------------------------------------------------------------
// Byte-level mock: a private issuer plus a scriptable worker surface.
// ---------------------------------------------------------------------------

/// How the mock actually puts the body on the wire.
#[derive(Debug, Clone)]
enum Sent {
    /// content-length framed, all bytes, correct
    Clean,
    /// content-length framed, all bytes, chunk `usize` flipped: the length
    /// is right and only the DIGEST can catch it
    Corrupt(usize),
    /// content-length framed, then stop after `usize` bytes and close
    Truncate(usize),
    /// `transfer-encoding: chunked`, correct bytes, no content-length
    Chunked,
    /// chunked framing with chunk `usize` flipped
    ChunkedCorrupt(usize),
    /// content-length framed, then send `usize` bytes MORE than declared
    Extra(usize),
    /// chunked framing (no content-length), then `usize` bytes MORE than
    /// `x-payload-length` advertises: the one framing where the transport
    /// cannot bound the body for us
    ChunkedExtra(usize),
    /// correct bytes, dripped with a pause between chunks (slow server)
    Slow(Duration),
    /// send `usize` bytes then hard-close the socket in BOTH directions
    /// mid-record (a crashed/restarted peer). `SO_LINGER`-driven RST needs
    /// the unstable `tcp_linger` API, so this is a bidirectional shutdown:
    /// the client still observes the transfer dying before its declared
    /// length, which is the property under test.
    Reset(usize),
}

#[derive(Debug, Clone)]
struct StreamReply {
    bytes: Vec<u8>,
    sent: Sent,
    lsn: u64,
    type_sequence: u64,
    record_type: u8,
    /// override the advertised length (self-contradicting metadata probes)
    declared_length: Option<u64>,
    /// override the RFC 9530 content-digest
    content_digest: Option<String>,
    /// override the content-type (a JSON answer to a stream request)
    content_type: Option<String>,
    /// override the echoed x-append-lsn
    echo_lsn: Option<u64>,
}

impl StreamReply {
    fn clean(bytes: Vec<u8>, lsn: u64) -> StreamReply {
        StreamReply {
            bytes,
            sent: Sent::Clean,
            lsn,
            type_sequence: lsn + 1,
            record_type: 2,
            declared_length: None,
            content_digest: None,
            content_type: None,
            echo_lsn: None,
        }
    }
    fn sent(mut self, sent: Sent) -> StreamReply {
        self.sent = sent;
        self
    }
}

#[derive(Debug, Clone)]
enum Reply {
    Json(u16, String),
    Stream(StreamReply),
}

/// One observed request.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path: String,
    accept: Option<String>,
    content_length: Option<String>,
    transfer_encoding: Option<String>,
    body: Vec<u8>,
}

struct Mock {
    base: String,
    seen: Arc<Mutex<Vec<Seen>>>,
    /// bytes the mock actually put on the wire for stream replies
    served_bytes: Arc<AtomicU64>,
}

fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let mut acc = 0u32;
        for (index, byte) in chunk.iter().enumerate() {
            acc |= u32::from(*byte) << (16 - 8 * index);
        }
        let produced = chunk.len() + 1;
        for slot in 0..4 {
            if slot < produced {
                out.push(ALPHABET[((acc >> (18 - 6 * slot)) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn digest_of(bytes: &[u8]) -> String {
    hex(&sha256(bytes))
}

/// Mint a token the way the private issuer does, enforcing the required
/// restrictions so an under-restricted spec still dies at issuance.
fn issue_or_refuse(spec: &serde_json::Value) -> (u16, String) {
    let method = spec["method"].as_str().unwrap_or_default().to_string();
    let required: &[&str] = match method.as_str() {
        "PUT_PAYLOAD" => &["digest", "maxBytes"],
        "WAL_READ" | "WAL_FINALIZE" => &["session", "generation"],
        "JOURNAL_VERIFY" | "PROVISION" => &[],
        _ => &["session"],
    };
    for restriction in required {
        let present = match *restriction {
            "session" => spec["session"].as_str().is_some_and(|s| !s.is_empty()),
            "generation" => spec["generation"].as_u64().is_some(),
            "digest" => spec["digest"].as_str().is_some_and(|s| !s.is_empty()),
            "maxBytes" => spec["maxBytes"].as_u64().is_some(),
            _ => false,
        };
        if !present {
            return (
                400,
                format!(
                    r#"{{"ok":false,"error":"ISSUE_SPEC_INVALID","detail":"CAPABILITY_RESTRICTION_MISSING: {method} requires {restriction}"}}"#
                ),
            );
        }
    }
    let key = if method == "PUT_PAYLOAD" {
        format!(
            r#","key":"p/{}/{}""#,
            spec["databaseId"].as_str().unwrap_or_default(),
            spec["digest"].as_str().unwrap_or_default()
        )
    } else {
        String::new()
    };
    (200, format!(r#"{{"ok":true,"token":"cap-{method}","expiresAtMs":1,"incarnation":1{key}}}"#))
}

fn read_request(stream: &mut TcpStream) -> Option<Seen> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.lines();
    let mut request_line = lines.next()?.split_whitespace();
    let method = request_line.next()?.to_string();
    let path = request_line.next()?.to_string();
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    let get = |name: &str| headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
    let content_length: usize = get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Some(Seen {
        method,
        path,
        accept: get("accept"),
        content_length: get("content-length"),
        transfer_encoding: get("transfer-encoding"),
        body,
    })
}

fn write_stream_reply(stream: &mut TcpStream, reply: &StreamReply, served: &AtomicU64) {
    let digest = digest_of(&reply.bytes);
    let declared = reply.declared_length.unwrap_or(reply.bytes.len() as u64);
    let content_digest =
        reply.content_digest.clone().unwrap_or_else(|| format!("sha-256=:{}:", base64_encode(&sha256(&reply.bytes))));
    let content_type = reply.content_type.clone().unwrap_or_else(|| "application/octet-stream".to_string());
    let chunked = matches!(reply.sent, Sent::Chunked | Sent::ChunkedCorrupt(_) | Sent::ChunkedExtra(_));
    let framing =
        if chunked { "transfer-encoding: chunked\r\n".to_string() } else { format!("content-length: {declared}\r\n") };
    let head = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\n{framing}content-digest: {content_digest}\r\n\
         x-payload-sha256: {digest}\r\nx-payload-length: {declared}\r\nx-append-lsn: {}\r\n\
         x-type-sequence: {}\r\nx-record-type: {}\r\nconnection: close\r\n\r\n",
        reply.echo_lsn.unwrap_or(reply.lsn),
        reply.type_sequence,
        reply.record_type,
    );
    if stream.write_all(head.as_bytes()).is_err() {
        return;
    }
    let mut chunks: Vec<Vec<u8>> = reply.bytes.chunks(MOCK_CHUNK).map(<[u8]>::to_vec).collect();
    if chunks.is_empty() {
        chunks.push(Vec::new());
    }
    let corrupt_at = match reply.sent {
        Sent::Corrupt(index) | Sent::ChunkedCorrupt(index) => Some(index.min(chunks.len() - 1)),
        _ => None,
    };
    if let Some(index) = corrupt_at {
        if let Some(byte) = chunks[index].first_mut() {
            *byte ^= 0xff;
        }
    }
    let cut = match reply.sent {
        Sent::Truncate(n) | Sent::Reset(n) => Some(n),
        _ => None,
    };
    let mut written = 0usize;
    for chunk in &chunks {
        let mut payload: &[u8] = chunk;
        if let Some(limit) = cut {
            if written >= limit {
                break;
            }
            let room = limit - written;
            if room < payload.len() {
                payload = &payload[..room];
            }
        }
        let ok = if chunked {
            stream
                .write_all(format!("{:x}\r\n", payload.len()).as_bytes())
                .and_then(|()| stream.write_all(payload))
                .and_then(|()| stream.write_all(b"\r\n"))
                .is_ok()
        } else {
            stream.write_all(payload).is_ok()
        };
        if !ok {
            return;
        }
        written += payload.len();
        served.fetch_add(payload.len() as u64, Ordering::Relaxed);
        let _ = stream.flush();
        if let Sent::Slow(pause) = reply.sent {
            thread::sleep(pause);
        }
    }
    match reply.sent {
        Sent::Extra(extra) => {
            let _ = stream.write_all(&vec![0xAAu8; extra]);
            served.fetch_add(extra as u64, Ordering::Relaxed);
        }
        Sent::ChunkedExtra(extra) => {
            let payload = vec![0xAAu8; extra];
            let _ = stream
                .write_all(format!("{extra:x}\r\n").as_bytes())
                .and_then(|()| stream.write_all(&payload))
                .and_then(|()| stream.write_all(b"\r\n"));
            served.fetch_add(extra as u64, Ordering::Relaxed);
        }
        _ => {}
    }
    if chunked && cut.is_none() {
        let _ = stream.write_all(b"0\r\n\r\n");
    }
    if let Sent::Reset(_) = reply.sent {
        // the peer went away mid-record; it did not finish the body
        let _ = stream.shutdown(Shutdown::Both);
    }
}

impl Mock {
    fn serve(script: Vec<Reply>) -> Mock {
        Mock::serve_on(TcpListener::bind("127.0.0.1:0").expect("bind"), script)
    }

    fn serve_on(listener: TcpListener, script: Vec<Reply>) -> Mock {
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let served_bytes = Arc::new(AtomicU64::new(0));
        let recorder = Arc::clone(&seen);
        let served = Arc::clone(&served_bytes);
        thread::spawn(move || {
            let mut remaining: VecDeque<Reply> = script.into_iter().collect();
            for stream in listener.incoming().take(256) {
                let Ok(mut stream) = stream else { return };
                let Some(request) = read_request(&mut stream) else { continue };
                recorder.lock().unwrap().push(request.clone());
                let issuer_route =
                    request.method == "POST" && (request.path == "/issue" || request.path == "/provision-token");
                if issuer_route {
                    let body: serde_json::Value =
                        serde_json::from_slice(&request.body).unwrap_or(serde_json::Value::Null);
                    let spec = if body.get("spec").is_some() { body["spec"].clone() } else { body };
                    let (status, reply) = issue_or_refuse(&spec);
                    let response = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
                        reply.len()
                    );
                    let _ = stream.write_all(response.as_bytes());
                    continue;
                }
                match remaining.pop_front() {
                    Some(Reply::Stream(reply)) => write_stream_reply(&mut stream, &reply, &served),
                    Some(Reply::Json(status, body)) => {
                        let response = format!(
                            "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = stream.write_all(response.as_bytes());
                    }
                    None => {
                        let body = r#"{"ok":false,"error":"MOCK_SCRIPT_EXHAUSTED"}"#;
                        let response = format!(
                            "HTTP/1.1 599 X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = stream.write_all(response.as_bytes());
                    }
                }
            }
        });
        Mock { base: format!("http://{addr}"), seen, served_bytes }
    }

    fn requests(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

fn client(base: String) -> L1Client {
    let client = L1Client::new(L1Config {
        base: base.clone(),
        issuer_base: base,
        issuer_bearer: BEARER.to_string(),
        principal: "stream-contract".to_string(),
        tenant_id: "tenant-a".to_string(),
    });
    client.bind_actor("session-a", 1);
    client
}

fn spool_dir(label: &str) -> SpoolDir {
    let nanos =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or_default();
    SpoolDir::open(std::env::temp_dir().join(format!("l1-stream-{label}-{}-{nanos}", std::process::id())))
        .expect("spool dir")
}

/// A 64 KiB record: four wire chunks, so first/middle/last are distinct.
fn record(seed: u64) -> Vec<u8> {
    record_of(seed, 4)
}

/// A record of `chunks` wire chunks. Anything larger than the client's own
/// `STREAM_CHUNK_BYTES` is necessarily read incrementally, whatever the
/// socket buffers do.
fn record_of(seed: u64, chunks: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; chunks * MOCK_CHUNK];
    let mut state = seed;
    for slot in bytes.chunks_mut(8) {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let word = state.to_le_bytes();
        slot.copy_from_slice(&word[..slot.len()]);
    }
    bytes
}

/// Assert the shared post-condition of every failure case.
fn assert_nothing_escaped(dir: &SpoolDir, consumer: &RecordingConsumer, context: &str) {
    assert!(
        dir.committed_digests().expect("list").is_empty(),
        "{context}: a cache entry was published for unverified bytes"
    );
    assert!(std::fs::read_dir(dir.root()).unwrap().next().is_none(), "{context}: a partial survived the refusal");
    assert!(consumer.applied.is_empty(), "{context}: a record was applied");
    assert!(consumer.acknowledged.is_empty(), "{context}: a record was acknowledged");
}

// ---------------------------------------------------------------------------
// The happy path, and the proof that it IS the streaming path.
// ---------------------------------------------------------------------------

#[test]
fn streaming_read_negotiates_octet_stream_and_publishes_only_after_proof() {
    let bytes = record(1);
    let mock = Mock::serve(vec![Reply::Stream(StreamReply::clean(bytes.clone(), 7))]);
    let client = client(mock.base.clone());
    let dir = spool_dir("clean");
    let mut options = StreamOptions::default();
    let read = client
        .read_exact_streaming("db", 1, 7, SpoolPolicy::Cache { dir: &dir, max_bytes: MAX_RECORD_BYTES }, &mut options)
        .expect("clean stream verifies");

    assert_eq!(read.meta.append_lsn, 7);
    assert_eq!(read.meta.payload_length, bytes.len() as u64);
    assert_eq!(read.meta.payload_digest, digest_of(&bytes));
    assert_eq!(read.payload.to_vec().unwrap(), bytes);
    assert!(read.payload.is_cached(), "the cache policy must produce a cache entry");
    assert!(read.payload.reverify().unwrap(), "the committed entry re-proves");
    assert_eq!(dir.committed_digests().unwrap(), vec![digest_of(&bytes)]);

    // the request ACTUALLY negotiated the streaming variant: a wildcard
    // accept does not select it at the Worker, so nothing but the exact
    // media type would do
    let guarded = mock.requests().into_iter().find(|r| r.path.starts_with("/wal/")).expect("read request");
    assert_eq!(guarded.accept.as_deref(), Some("application/octet-stream"));
}

#[test]
fn the_default_read_route_is_untouched_and_never_negotiates_the_stream() {
    // R6-PERF-01 keeps the buffered JSON route as the DEFAULT until a
    // consumer is safe. This pins that `read_exact` did not quietly acquire
    // the streaming shape: the Worker only streams on an EXPLICIT
    // `application/octet-stream` accept, and a wildcard does not select it.
    let payload = b"the buffered route's bytes";
    let digest = digest_of(payload);
    let mock = Mock::serve(vec![Reply::Json(
        200,
        format!(
            r#"{{"ok":true,"payloadKey":"p/db/{digest}","payloadDigest":"{digest}","typeSequence":"1","recordType":2,"payloadBase64":"{}"}}"#,
            base64_encode(payload)
        ),
    )]);
    let client = client(mock.base.clone());
    let (status, outcome) = client.read_exact("db", 1, 0).expect("buffered read");
    assert_eq!(status, 200);
    assert_eq!(outcome.payload_digest.as_deref(), Some(digest.as_str()));
    let guarded = mock.requests().into_iter().find(|r| r.path.starts_with("/wal/")).expect("read request");
    let accept = guarded.accept.unwrap_or_default();
    assert!(
        !accept.to_ascii_lowercase().contains("application/octet-stream"),
        "the default route must not negotiate the stream, but sent accept: {accept:?}"
    );
}

#[test]
fn a_chunked_response_is_streamed_and_verified() {
    let bytes = record(2);
    let mock = Mock::serve(vec![Reply::Stream(StreamReply::clean(bytes.clone(), 0).sent(Sent::Chunked))]);
    let client = client(mock.base.clone());
    let dir = spool_dir("chunked");
    let mut options = StreamOptions::default();
    let read = client
        .read_exact_streaming("db", 1, 0, SpoolPolicy::Cache { dir: &dir, max_bytes: MAX_RECORD_BYTES }, &mut options)
        .expect("chunked stream verifies");
    assert_eq!(read.payload.to_vec().unwrap(), bytes);
}

// ---------------------------------------------------------------------------
// Corruption: first, middle, last chunk. Same length every time, so ONLY the
// end-to-end digest can catch them - which is the point.
// ---------------------------------------------------------------------------

#[test]
fn a_corrupt_first_chunk_applies_nothing() {
    corrupt_case(Sent::Corrupt(0), "first");
}

#[test]
fn a_corrupt_middle_chunk_applies_nothing() {
    corrupt_case(Sent::Corrupt(2), "middle");
}

#[test]
fn a_corrupt_last_chunk_applies_nothing() {
    corrupt_case(Sent::Corrupt(3), "last");
}

#[test]
fn a_corrupt_chunk_under_chunked_framing_applies_nothing() {
    corrupt_case(Sent::ChunkedCorrupt(1), "chunked");
}

fn corrupt_case(sent: Sent, label: &str) {
    let bytes = record(3);
    let mock = Mock::serve(vec![
        Reply::Json(200, r#"{"ok":true,"headLsn":"0","headTypeSequence":"1"}"#.into()),
        Reply::Stream(StreamReply::clean(bytes.clone(), 0).sent(sent)),
    ]);
    let client = client(mock.base.clone());
    let dir = spool_dir(label);
    let mut consumer = RecordingConsumer::default();
    let (report, error) = client
        .replay_streaming(
            "db",
            1,
            0,
            ReplayBounds::default(),
            SpoolPolicy::Cache { dir: &dir, max_bytes: MAX_RECORD_BYTES },
            &mut consumer,
        )
        .expect_err("a corrupt transfer must refuse");
    assert!(
        matches!(&error, L1Error::Stream(StreamError::Integrity(IntegrityFault::DigestMismatch { length, .. }))
            if *length == bytes.len() as u64),
        "{label}: {error}"
    );
    assert_eq!(report.applied, 0);
    assert_eq!(report.acknowledged, 0);
    assert_eq!(report.aborted_at_lsn, Some(0), "{label}: the in-flight record is named and unapplied");
    // the mock DID put a corrupt prefix on the wire - the client just has
    // nowhere to put it
    assert!(mock.served_bytes.load(Ordering::Relaxed) > 0, "{label}: the mock served nothing, so nothing was proven");
    assert_nothing_escaped(&dir, &consumer, label);
}

// ---------------------------------------------------------------------------
// Framing faults.
// ---------------------------------------------------------------------------

#[test]
fn a_truncated_response_applies_nothing() {
    let bytes = record(4);
    let mock = Mock::serve(vec![
        Reply::Json(200, r#"{"ok":true,"headLsn":"0","headTypeSequence":"1"}"#.into()),
        Reply::Stream(StreamReply::clean(bytes.clone(), 0).sent(Sent::Truncate(MOCK_CHUNK + 11))),
    ]);
    let client = client(mock.base.clone());
    let dir = spool_dir("truncated");
    let mut consumer = RecordingConsumer::default();
    let (report, error) = client
        .replay_streaming(
            "db",
            1,
            0,
            ReplayBounds::default(),
            SpoolPolicy::Cache { dir: &dir, max_bytes: MAX_RECORD_BYTES },
            &mut consumer,
        )
        .expect_err("a truncated transfer must refuse");
    assert!(
        matches!(
            &error,
            L1Error::Stream(StreamError::Integrity(
                IntegrityFault::TransferAborted { .. } | IntegrityFault::LengthMismatch { .. }
            ))
        ),
        "{error}"
    );
    assert_eq!(report.applied, 0);
    assert_nothing_escaped(&dir, &consumer, "truncated");
}

#[test]
fn a_connection_reset_mid_stream_applies_nothing() {
    let bytes = record(5);
    let mock = Mock::serve(vec![Reply::Stream(StreamReply::clean(bytes.clone(), 0).sent(Sent::Reset(MOCK_CHUNK * 2)))]);
    let client = client(mock.base.clone());
    let dir = spool_dir("reset");
    let mut options = StreamOptions::default();
    let error = client
        .read_exact_streaming("db", 1, 0, SpoolPolicy::Cache { dir: &dir, max_bytes: MAX_RECORD_BYTES }, &mut options)
        .expect_err("a reset transfer must refuse");
    assert!(matches!(&error, L1Error::Stream(StreamError::Integrity(_))), "{error}");
    assert_nothing_escaped(&dir, &RecordingConsumer::default(), "reset");
}

#[test]
fn a_content_length_framed_overrun_cannot_smuggle_bytes_into_the_record() {
    // Under content-length framing the extra bytes are not part of the
    // message at all: the transport ends the body at the declared length.
    // The record is therefore intact and verifies - and, crucially, the
    // trailing bytes are nowhere in it.
    let bytes = record(6);
    let mock = Mock::serve(vec![Reply::Stream(StreamReply::clean(bytes.clone(), 0).sent(Sent::Extra(4096)))]);
    let client = client(mock.base.clone());
    let dir = spool_dir("overrun-sized");
    let mut options = StreamOptions::default();
    let read = client
        .read_exact_streaming("db", 1, 0, SpoolPolicy::Cache { dir: &dir, max_bytes: MAX_RECORD_BYTES }, &mut options)
        .expect("a length-framed message ends where it says it ends");
    assert_eq!(read.payload.to_vec().unwrap(), bytes);
    assert_eq!(read.payload.len(), bytes.len() as u64);
}

#[test]
fn a_chunked_overrun_is_refused_mid_transfer() {
    // Chunked framing is the case where the transport cannot bound the body
    // for us: the declared record length lives only in `x-payload-length`,
    // so the SPOOL has to enforce it.
    let bytes = record(6);
    let mock = Mock::serve(vec![Reply::Stream(StreamReply::clean(bytes.clone(), 0).sent(Sent::ChunkedExtra(4096)))]);
    let client = client(mock.base.clone());
    let dir = spool_dir("overrun-chunked");
    let mut options = StreamOptions::default();
    let error = client
        .read_exact_streaming("db", 1, 0, SpoolPolicy::Cache { dir: &dir, max_bytes: MAX_RECORD_BYTES }, &mut options)
        .expect_err("an overrun must refuse");
    assert!(
        matches!(&error, L1Error::Stream(StreamError::Integrity(IntegrityFault::Overrun { declared, .. }))
            if *declared == bytes.len() as u64),
        "{error}"
    );
    assert_nothing_escaped(&dir, &RecordingConsumer::default(), "overrun-chunked");
}

// ---------------------------------------------------------------------------
// Metadata that contradicts itself is refused BEFORE the body.
// ---------------------------------------------------------------------------

#[test]
fn a_response_whose_content_digest_contradicts_its_hex_digest_is_refused_pre_body() {
    let bytes = record(7);
    let mut reply = StreamReply::clean(bytes.clone(), 0);
    reply.content_digest = Some(format!("sha-256=:{}:", base64_encode(&sha256(b"something else"))));
    let mock = Mock::serve(vec![Reply::Stream(reply)]);
    let client = client(mock.base.clone());
    let dir = spool_dir("contradiction");
    let mut options = StreamOptions::default();
    let error = client
        .read_exact_streaming("db", 1, 0, SpoolPolicy::Cache { dir: &dir, max_bytes: MAX_RECORD_BYTES }, &mut options)
        .expect_err("self-contradicting metadata must refuse");
    assert!(
        matches!(&error, L1Error::Stream(StreamError::Integrity(IntegrityFault::HeaderInconsistent(_)))),
        "{error}"
    );
    assert_nothing_escaped(&dir, &RecordingConsumer::default(), "contradiction");
}

#[test]
fn a_json_answer_to_a_stream_request_is_never_silently_accepted() {
    let bytes = record(8);
    let mut reply = StreamReply::clean(bytes, 0);
    reply.content_type = Some("application/json".into());
    let mock = Mock::serve(vec![Reply::Stream(reply)]);
    let client = client(mock.base.clone());
    let dir = spool_dir("json-fallback");
    let mut options = StreamOptions::default();
    let error = client
        .read_exact_streaming("db", 1, 0, SpoolPolicy::Cache { dir: &dir, max_bytes: MAX_RECORD_BYTES }, &mut options)
        .expect_err("a JSON answer to a negotiated stream must refuse");
    assert!(
        matches!(&error, L1Error::Stream(StreamError::Integrity(IntegrityFault::HeaderInconsistent(detail)))
            if detail.contains("content-type")),
        "{error}"
    );
}

#[test]
fn a_response_for_a_different_record_is_refused() {
    let bytes = record(9);
    let mut reply = StreamReply::clean(bytes, 3);
    reply.echo_lsn = Some(4);
    let mock = Mock::serve(vec![Reply::Stream(reply)]);
    let client = client(mock.base.clone());
    let dir = spool_dir("wrong-lsn");
    let mut options = StreamOptions::default();
    let error = client
        .read_exact_streaming("db", 1, 3, SpoolPolicy::Cache { dir: &dir, max_bytes: MAX_RECORD_BYTES }, &mut options)
        .expect_err("a response for another lsn must refuse");
    assert!(
        matches!(&error, L1Error::Stream(StreamError::Integrity(IntegrityFault::HeaderInconsistent(detail)))
            if detail.contains("lsn")),
        "{error}"
    );
}

#[test]
fn an_oversize_record_is_refused_before_the_body_is_read() {
    let bytes = record(10);
    let mut reply = StreamReply::clean(bytes, 0);
    // advertise a record far above the caller's policy bound; the mock
    // sends NOTHING, so a client that refused after reading would hang
    // rather than pass
    reply.declared_length = Some(64 * 1024 * 1024);
    reply.sent = Sent::Truncate(0);
    let mock = Mock::serve(vec![Reply::Stream(reply)]);
    let client = client(mock.base.clone());
    let dir = spool_dir("oversize");
    let mut options = StreamOptions::default();
    let error = client
        .read_exact_streaming("db", 1, 0, SpoolPolicy::Cache { dir: &dir, max_bytes: 1024 * 1024 }, &mut options)
        .expect_err("an over-bound record must refuse");
    assert!(matches!(&error, L1Error::Stream(StreamError::Oversize { declared: 67108864, limit: 1048576 })), "{error}");
    assert_eq!(mock.served_bytes.load(Ordering::Relaxed), 0, "no body byte was read");
}

#[test]
fn the_caller_expected_digest_pins_which_record_it_is_reading() {
    let bytes = record(11);
    let mock = Mock::serve(vec![Reply::Stream(StreamReply::clean(bytes, 0))]);
    let client = client(mock.base.clone());
    let dir = spool_dir("expect");
    let other = digest_of(b"a record the caller was not asking for");
    let mut options = StreamOptions { expect_digest: Some(&other), progress: None };
    let error = client
        .read_exact_streaming("db", 1, 0, SpoolPolicy::Cache { dir: &dir, max_bytes: MAX_RECORD_BYTES }, &mut options)
        .expect_err("a substituted record must refuse");
    assert!(
        matches!(&error, L1Error::Stream(StreamError::Integrity(IntegrityFault::HeaderInconsistent(_)))),
        "{error}"
    );
    assert_nothing_escaped(&dir, &RecordingConsumer::default(), "expect");
}

// ---------------------------------------------------------------------------
// Consumer-driven cases: cancellation, slowness.
// ---------------------------------------------------------------------------

#[test]
fn cancellation_mid_stream_applies_nothing_and_publishes_nothing() {
    let bytes = record(12);
    let mock =
        Mock::serve(vec![Reply::Stream(StreamReply::clean(bytes, 0).sent(Sent::Slow(Duration::from_millis(2))))]);
    let client = client(mock.base.clone());
    let dir = spool_dir("cancel");
    let mut cancelled_at = 0u64;
    let error = {
        let mut cancel = |written: u64| {
            cancelled_at = written;
            Flow::Cancel
        };
        let mut options = StreamOptions { expect_digest: None, progress: Some(&mut cancel) };
        client
            .read_exact_streaming(
                "db",
                1,
                0,
                SpoolPolicy::Cache { dir: &dir, max_bytes: MAX_RECORD_BYTES },
                &mut options,
            )
            .expect_err("a cancelled transfer must refuse")
    };
    assert!(matches!(&error, L1Error::Stream(StreamError::Cancelled { .. })), "{error}");
    assert!(cancelled_at > 0, "cancellation happened mid-stream, after real bytes");
    assert_nothing_escaped(&dir, &RecordingConsumer::default(), "cancel");
}

#[test]
fn a_slow_consumer_still_verifies_and_never_sees_a_prefix() {
    // 384 KiB: six times the client's 64 KiB transfer chunk, so the read
    // loop CANNOT complete in one call however the socket buffers
    let bytes = record_of(13, 24);
    let mock = Mock::serve(vec![Reply::Stream(StreamReply::clean(bytes.clone(), 0))]);
    let client = client(mock.base.clone());
    let dir = spool_dir("slow-consumer");
    let mut observed = Vec::new();
    let read = {
        let mut slow = |written: u64| {
            observed.push(written);
            thread::sleep(Duration::from_millis(5));
            Flow::Continue
        };
        let mut options = StreamOptions { expect_digest: None, progress: Some(&mut slow) };
        client
            .read_exact_streaming(
                "db",
                1,
                0,
                SpoolPolicy::Cache { dir: &dir, max_bytes: MAX_RECORD_BYTES },
                &mut options,
            )
            .expect("a slow consumer still completes")
    };
    assert_eq!(read.payload.to_vec().unwrap(), bytes);
    // the hook saw progress - i.e. the transfer really was incremental -
    // and yet the hook was never handed a single byte
    assert!(observed.len() >= 6, "the transfer was not incremental: {observed:?}");
    assert_eq!(observed.last().copied(), Some(bytes.len() as u64));
}

#[test]
fn a_slow_server_dripping_chunks_still_verifies() {
    let bytes = record(14);
    let mock = Mock::serve(vec![Reply::Stream(
        StreamReply::clean(bytes.clone(), 0).sent(Sent::Slow(Duration::from_millis(20))),
    )]);
    let client = client(mock.base.clone());
    let dir = spool_dir("slow-server");
    let mut options = StreamOptions::default();
    let read = client
        .read_exact_streaming("db", 1, 0, SpoolPolicy::Cache { dir: &dir, max_bytes: MAX_RECORD_BYTES }, &mut options)
        .expect("a dripped transfer still completes");
    assert_eq!(read.payload.to_vec().unwrap(), bytes);
}

// ---------------------------------------------------------------------------
// Fence during a streaming replay, and restart.
// ---------------------------------------------------------------------------

#[test]
fn a_fence_during_a_streaming_replay_stops_it_with_the_in_flight_record_unapplied() {
    let first = record(15);
    let second = record(16);
    let mock = Mock::serve(vec![
        // head: three records in the cut
        Reply::Json(200, r#"{"ok":true,"headLsn":"2","headTypeSequence":"3"}"#.into()),
        Reply::Stream(StreamReply::clean(first.clone(), 0)),
        Reply::Stream(StreamReply::clean(second.clone(), 1)),
        // ... and now a successor activation fenced this actor: the Worker
        // revalidates live authority at use time, so the NEXT read is a
        // typed 409 carrying no bytes at all
        Reply::Json(409, r#"{"ok":false,"error":"SESSION_NOT_ACTIVE"}"#.into()),
    ]);
    let client = client(mock.base.clone());
    let dir = spool_dir("fence");
    let mut consumer = RecordingConsumer::default();
    let (report, error) = client
        .replay_streaming(
            "db",
            1,
            0,
            ReplayBounds::default(),
            SpoolPolicy::Cache { dir: &dir, max_bytes: MAX_RECORD_BYTES },
            &mut consumer,
        )
        .expect_err("a fence must stop the replay");
    assert!(
        matches!(&error, L1Error::Protocol { status: 409, body } if body.contains("SESSION_NOT_ACTIVE")),
        "{error}"
    );
    assert_eq!(report.applied, 2, "exactly the records proven before the fence");
    assert_eq!(report.acknowledged, 2);
    assert_eq!(report.last_applied_lsn, Some(1));
    assert_eq!(report.aborted_at_lsn, Some(2), "the fenced record is named and was never applied");
    assert_eq!(consumer.applied.len(), 2);
    assert_eq!(consumer.applied[0].1, first);
    assert_eq!(consumer.applied[1].1, second);
    assert_eq!(consumer.acknowledged, vec![0, 1]);
    // applied records released their cache entries; the fenced one never
    // created one
    assert!(dir.committed_digests().unwrap().is_empty());
    assert!(std::fs::read_dir(dir.root()).unwrap().next().is_none());
}

#[test]
fn a_restart_after_a_stream_died_mid_record_resumes_without_adopting_the_prefix() {
    let bytes = record(17);
    let digest = digest_of(&bytes);
    // one spool directory across BOTH lifetimes: this is the same node
    // coming back up, not a clean slate
    let dir = spool_dir("restart");
    let root = dir.root().to_path_buf();

    // lifetime 1: the peer dies half way through the record
    {
        let mock = Mock::serve(vec![Reply::Stream(
            StreamReply::clean(bytes.clone(), 0).sent(Sent::Reset(MOCK_CHUNK * 2 + 7)),
        )]);
        let client = client(mock.base.clone());
        let mut options = StreamOptions::default();
        let error = client
            .read_exact_streaming(
                "db",
                1,
                0,
                SpoolPolicy::Cache { dir: &dir, max_bytes: MAX_RECORD_BYTES },
                &mut options,
            )
            .expect_err("the dead transfer must refuse");
        assert!(matches!(&error, L1Error::Stream(StreamError::Integrity(_))), "{error}");
    }
    // simulate a HARD kill: a partial that Drop never got to remove
    std::fs::write(root.join(format!(".partial-{}-killed", std::process::id())), &bytes[..MOCK_CHUNK]).unwrap();

    // lifetime 2: restart. The partial is swept, nothing is adoptable, and
    // the retry against a healthy peer succeeds.
    let restarted = SpoolDir::open(&root).expect("reopen the spool");
    assert!(restarted.committed_digests().unwrap().is_empty(), "a partial is not an entry");
    assert!(restarted.adopt(&digest, bytes.len() as u64).unwrap().is_none(), "nothing adoptable after the crash");
    assert!(std::fs::read_dir(&root).unwrap().next().is_none(), "restart swept the partial");

    let mock = Mock::serve(vec![Reply::Stream(StreamReply::clean(bytes.clone(), 0))]);
    let client = client(mock.base.clone());
    let mut options = StreamOptions::default();
    let read = client
        .read_exact_streaming(
            "db",
            1,
            0,
            SpoolPolicy::Cache { dir: &restarted, max_bytes: MAX_RECORD_BYTES },
            &mut options,
        )
        .expect("the retry after restart verifies");
    assert_eq!(read.payload.to_vec().unwrap(), bytes);
    // and NOW the entry is adoptable - because it was proven
    let adopted = restarted.adopt(&digest, bytes.len() as u64).unwrap().expect("adoptable");
    assert_eq!(adopted.to_vec().unwrap(), bytes);
}

#[test]
fn a_consumer_refusal_leaves_the_record_unacknowledged() {
    let first = record(18);
    let second = record(19);
    let mock = Mock::serve(vec![
        Reply::Json(200, r#"{"ok":true,"headLsn":"1","headTypeSequence":"2"}"#.into()),
        Reply::Stream(StreamReply::clean(first.clone(), 0)),
        Reply::Stream(StreamReply::clean(second, 1)),
    ]);
    let client = client(mock.base.clone());
    let dir = spool_dir("consumer-refusal");
    let mut consumer = RecordingConsumer { refuse_lsn: Some(1), ..Default::default() };
    let (report, _error) = client
        .replay_streaming(
            "db",
            1,
            0,
            ReplayBounds::default(),
            SpoolPolicy::Cache { dir: &dir, max_bytes: MAX_RECORD_BYTES },
            &mut consumer,
        )
        .expect_err("a refusing consumer stops the replay");
    assert_eq!(report.applied, 1);
    assert_eq!(report.acknowledged, 1);
    assert_eq!(report.aborted_at_lsn, Some(1));
    assert_eq!(consumer.acknowledged, vec![0], "the refused record was never acknowledged");
}

// ---------------------------------------------------------------------------
// The upload half.
// ---------------------------------------------------------------------------

#[test]
fn streaming_upload_declares_its_length_and_never_frames_chunked() {
    let bytes = record(20);
    let digest = digest_of(&bytes);
    let source = remote_wal_spike::l1_stream::BytesSource(bytes.clone());
    let mock = Mock::serve(vec![Reply::Json(
        200,
        format!(r#"{{"key":"p/db/{digest}","sha256hex":"{digest}","length":{},"deduplicated":false}}"#, bytes.len()),
    )]);
    let client = client(mock.base.clone());
    let receipt = client.upload_payload_streaming("db", &source, MAX_RECORD_BYTES).expect("upload");
    assert_eq!(receipt.digest, digest);
    assert_eq!(receipt.length, bytes.len() as u64);
    assert_eq!(receipt.key, format!("p/db/{digest}"));

    let put = mock.requests().into_iter().find(|r| r.method == "PUT").expect("a PUT happened");
    assert_eq!(put.content_length.as_deref(), Some(bytes.len().to_string().as_str()));
    assert!(put.transfer_encoding.is_none(), "the Worker refuses an undeclared body with 411");
    assert_eq!(put.body, bytes, "the exact bytes travelled, unencoded");
    // the capability was minted for the measured digest and the measured
    // budget - the issuer would have refused a spec without them
    let issue = mock
        .requests()
        .into_iter()
        .find(|r| r.path == "/issue" && r.body.windows(11).any(|w| w == b"PUT_PAYLOAD"))
        .expect("a PUT_PAYLOAD issuance happened");
    let spec: serde_json::Value = serde_json::from_slice(&issue.body).unwrap();
    assert_eq!(spec["spec"]["digest"], digest);
    assert_eq!(spec["spec"]["maxBytes"], bytes.len());
}

#[test]
fn a_synthetic_multi_megabyte_source_uploads_without_ever_being_buffered() {
    // 6 MiB: under the 8 MiB data-path ceiling, well over anything that
    // could be mistaken for an incidental buffer
    let source = SyntheticSource { length: 6 * 1024 * 1024, seed: 42 };
    let measured = fingerprint(&source, MAX_RECORD_BYTES).expect("measure");
    let mock = Mock::serve(vec![Reply::Json(
        200,
        format!(
            r#"{{"key":"p/db/{}","sha256hex":"{}","length":{},"deduplicated":false}}"#,
            measured.digest, measured.digest, measured.length
        ),
    )]);
    let client = client(mock.base.clone());
    let receipt = client.upload_payload_streaming("db", &source, MAX_RECORD_BYTES).expect("upload");
    assert_eq!(receipt.digest, measured.digest);
    let put = mock.requests().into_iter().find(|r| r.method == "PUT").expect("a PUT happened");
    assert_eq!(put.body.len() as u64, measured.length);
    assert_eq!(digest_of(&put.body), measured.digest);
}

#[test]
fn an_oversize_source_is_refused_before_a_capability_is_ever_requested() {
    let source = SyntheticSource { length: MAX_RECORD_BYTES + 1, seed: 1 };
    let mock = Mock::serve(vec![]);
    let client = client(mock.base.clone());
    let error = client
        .upload_payload_streaming("db", &source, MAX_RECORD_BYTES)
        .expect_err("an over-ceiling record must refuse");
    assert!(matches!(&error, L1Error::Stream(StreamError::Oversize { limit: MAX_RECORD_BYTES, .. })), "{error}");
    assert!(mock.requests().is_empty(), "no issuance, no PUT: refused before authority was even asked for");
}

// ---------------------------------------------------------------------------
// Bounded pagination.
// ---------------------------------------------------------------------------

#[test]
fn an_over_wide_scan_page_is_refused_rather_than_silently_clamped() {
    let mock = Mock::serve(vec![]);
    let client = client(mock.base.clone());
    let mut query = ScanQuery::new("2.abc", 0, MAX_SCAN_PAGE_RECORDS + 1);
    let error = client.scan("db", 1, &query).expect_err("an over-wide page must refuse");
    assert!(
        matches!(&error, L1Error::Stream(StreamError::Oversize { declared, limit })
            if *declared == u64::from(MAX_SCAN_PAGE_RECORDS) + 1 && *limit == u64::from(MAX_SCAN_PAGE_RECORDS)),
        "{error}"
    );
    query.limit = 0;
    assert!(client.scan("db", 1, &query).is_err(), "a zero-record page is not a page");
    query.limit = 10;
    query.max_bytes = Some(64 * 1024 * 1024);
    assert!(client.scan("db", 1, &query).is_err(), "an over-budget page must refuse");
    assert!(mock.requests().is_empty(), "nothing left the client");
}

#[test]
fn replay_bounds_cap_the_number_of_records_one_call_will_visit() {
    let mock = Mock::serve(vec![
        Reply::Json(200, r#"{"ok":true,"headLsn":"9","headTypeSequence":"10"}"#.into()),
        Reply::Stream(StreamReply::clean(record(21), 0)),
        Reply::Stream(StreamReply::clean(record(22), 1)),
    ]);
    let client = client(mock.base.clone());
    let dir = spool_dir("bounded");
    let mut consumer = RecordingConsumer::default();
    let bounds = ReplayBounds { max_records: 2, ..ReplayBounds::default() };
    let report = client
        .replay_streaming(
            "db",
            1,
            0,
            bounds,
            SpoolPolicy::Cache { dir: &dir, max_bytes: MAX_RECORD_BYTES },
            &mut consumer,
        )
        .expect("a bounded replay stops at its bound");
    assert_eq!(report.applied, 2, "the bound stopped it well before the head at lsn 9");
    assert_eq!(consumer.acknowledged, vec![0, 1]);
}

#[test]
fn a_record_over_the_replay_bound_is_refused_without_being_applied() {
    let big = vec![0u8; 3 * MOCK_CHUNK];
    let mock = Mock::serve(vec![
        Reply::Json(200, r#"{"ok":true,"headLsn":"0","headTypeSequence":"1"}"#.into()),
        Reply::Stream(StreamReply::clean(big, 0)),
    ]);
    let client = client(mock.base.clone());
    let dir = spool_dir("record-bound");
    let mut consumer = RecordingConsumer::default();
    let bounds = ReplayBounds { max_record_bytes: MOCK_CHUNK as u64, ..ReplayBounds::default() };
    let (report, error) = client
        .replay_streaming(
            "db",
            1,
            0,
            bounds,
            SpoolPolicy::Cache { dir: &dir, max_bytes: MOCK_CHUNK as u64 },
            &mut consumer,
        )
        .expect_err("an over-bound record must refuse");
    assert!(matches!(&error, L1Error::Stream(StreamError::Oversize { .. })), "{error}");
    assert_eq!(report.applied, 0);
    assert_nothing_escaped(&dir, &consumer, "record-bound");
}
