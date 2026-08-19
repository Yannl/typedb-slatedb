//! Wire-contract regressions for the L1 client, against a local mock stack
//! (no workerd needed) made of a VALIDATING capability issuer plus scripted
//! responses for the non-issuance routes:
//!
//!  - R4-SEC-03: the previous mock handed back a token WITHOUT reading the
//!    issuance body - a client that omitted a required restriction (the
//!    finalize/read generation) still went green here while the real Worker
//!    refuses at mint time. The mock now enforces the Worker's closed
//!    method registry and per-method REQUIRED restrictions
//!    (control-plane/src/controller/core/capability.ts
//!    REQUIRED_RESTRICTIONS) on every `POST /capability` body, answering
//!    the Worker's own error shapes (CAPABILITY_METHOD_UNKNOWN /
//!    CAPABILITY_RESTRICTION_MISSING) - so an under-restricted mint fails
//!    HERE, before the guarded route is ever reached;
//!  - fail-closed admin calls: `register_session` reports success ONLY on
//!    HTTP 200 `{"ok": true}` — a misrouted 404 or an `ok:false` body with a
//!    200 status must surface as a typed protocol error, never as success
//!    (a caller could otherwise believe a fence/registration exists that
//!    was never installed);
//!  - credentialed issuance: an issuer refusal is a typed issuance error;
//!  - exact u64s: sequence values arrive as canonical decimal strings; a
//!    JSON number or an alias like "00" is a typed DECODE error, never a
//!    rounded or coerced read.

use std::{
    collections::VecDeque,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
    thread,
};

use remote_wal_spike::l1_client::{
    CapabilityMethod, FinalizeHttpRequest, L1Client, L1Error, MintRestrictions, SequencingKind,
    DEV_ISSUER_SECRET,
};

// ---------------------------------------------------------------------------
// The validating mock issuer + scripted route responder.
// ---------------------------------------------------------------------------

/// The Worker's CLOSED capability-method registry with each method's
/// MANDATORY mint-time restrictions - a mirror of REQUIRED_RESTRICTIONS in
/// `control-plane/src/controller/core/capability.ts` as issuance enforces
/// it (`issueCapability`): "session" must be a nonempty string; "generation"
/// must be a nonnegative-integer JSON NUMBER on the issuance wire (the token
/// then binds its canonical decimal string form). PUT_PAYLOAD's required
/// `key` is issuer-DERIVED from the digest, so at mint time it reduces to
/// the digest being present.
const REQUIRED_RESTRICTIONS: &[(&str, &[&str])] = &[
    ("PUT_PAYLOAD", &["digest", "maxBytes"]),
    ("WAL_FINALIZE", &["session", "generation"]),
    ("WAL_READ", &["session", "generation"]),
    ("OUTBOX", &[]),
    ("SESSION_REGISTER", &["session", "generation"]),
    ("SESSION_RESERVE", &["session", "generation"]),
    ("SESSION_ATTEST", &["session"]),
    ("SESSION_ACTIVATE", &["session", "generation"]),
    ("SESSION_RENEW", &["session"]),
    ("SESSION_DRAIN", &["session"]),
    ("SESSION_REVOKE", &["session"]),
    ("SESSION_FENCE", &["session"]),
    ("BUDGETS_SET", &["session"]),
    ("CHECKPOINT_OPEN", &["session", "generation"]),
    ("CHECKPOINT_ACTIVATE", &["session", "generation"]),
    ("INCARNATION_BUMP", &[]),
    ("JOURNAL_VERIFY", &[]),
];

/// One request the mock observed on the wire.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path: String,
    body: serde_json::Value,
    capability: Option<String>,
}

/// Validate one issuance body EXACTLY the way the real issuer does at mint
/// time, and answer either the typed refusal or a grant. The minted token
/// text encodes the restrictions the issuer bound (`cap-<METHOD>-s=<session>
/// -g=<generation>`), so a later guarded request can be asserted to present
/// a token carrying the exact values the client threaded into issuance.
fn issue_or_refuse(spec: &serde_json::Value) -> (&'static str, String) {
    let method = spec["method"].as_str().unwrap_or_default().to_string();
    // closed registry: an unknown method (e.g. the retired SESSION_ADMIN)
    // is refused outright, never treated as restriction-free
    let Some((_, required)) = REQUIRED_RESTRICTIONS.iter().find(|(name, _)| *name == method) else {
        return ("403 Forbidden",
            format!(r#"{{"ok":false,"error":"CAPABILITY_METHOD_UNKNOWN","method":"{method}"}}"#));
    };
    // mandatory-by-method restrictions: absence (or the wrong JSON type) is
    // refusal, not permission - a token missing one would be WIDER, and
    // handing it back is exactly the false green R4-SEC-03 named
    for &restriction in *required {
        let present = match restriction {
            "session" => spec["session"].as_str().is_some_and(|s| !s.is_empty()),
            "generation" => spec["generation"].as_u64().is_some(),
            "digest" => spec["digest"].as_str().is_some_and(|s| !s.is_empty()),
            "maxBytes" => spec["maxBytes"].as_u64().is_some(),
            _ => false,
        };
        if !present {
            return ("403 Forbidden",
                format!(r#"{{"ok":false,"error":"CAPABILITY_RESTRICTION_MISSING","restriction":"{restriction}"}}"#));
        }
    }
    let mut token = format!("cap-{method}");
    if let Some(session) = spec["session"].as_str() {
        token.push_str(&format!("-s={session}"));
    }
    if let Some(generation) = spec["generation"].as_u64() {
        token.push_str(&format!("-g={generation}"));
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
    ("200 OK", format!(r#"{{"ok":true,"token":"{token}","expiresAtMs":1,"incarnation":1{key}}}"#))
}

/// Read one full HTTP request (request line, the headers this mock cares
/// about, and a content-length-delimited body) from the stream.
fn read_request(stream: &mut TcpStream) -> Option<(String, String, Option<String>, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.lines();
    let mut request_line = lines.next()?.split_whitespace();
    let method = request_line.next()?.to_string();
    let path = request_line.next()?.to_string();
    let mut content_length = 0usize;
    let mut capability = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else { continue };
        match name.to_ascii_lowercase().as_str() {
            "content-length" => content_length = value.trim().parse().unwrap_or(0),
            "x-capability" => capability = Some(value.trim().to_string()),
            _ => {}
        }
    }
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Some((method, path, capability, body))
}

struct Mock {
    base: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Mock {
    /// Serve `POST /capability` through the validating issuer above (or the
    /// forced `issuance_override` answer, for issuer-refusal cases) and every
    /// other route from `script` (one (status line, JSON body) per request,
    /// in order). Every request is recorded; an exhausted script answers a
    /// typed refusal rather than hanging the client.
    fn serve(
        script: &'static [(&'static str, &'static str)],
        issuance_override: Option<(&'static str, &'static str)>,
    ) -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        thread::spawn(move || {
            let mut remaining: VecDeque<(&str, &str)> = script.iter().copied().collect();
            // bounded accept loop: a runaway retrying client cannot pin this
            // thread past any plausible test's request count
            for stream in listener.incoming().take(64) {
                let Ok(mut stream) = stream else { return };
                let Some((method, path, capability, body)) = read_request(&mut stream) else { continue };
                let body_json: serde_json::Value =
                    serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
                recorder.lock().unwrap().push(Seen {
                    method: method.clone(),
                    path: path.clone(),
                    body: body_json.clone(),
                    capability,
                });
                let (status, reply) = if method == "POST" && path == "/capability" {
                    match issuance_override {
                        Some((status, reply)) => (status, reply.to_string()),
                        None => issue_or_refuse(&body_json),
                    }
                } else {
                    match remaining.pop_front() {
                        Some((status, reply)) => (status, reply.to_string()),
                        None => ("599 Script Exhausted",
                                 r#"{"ok":false,"error":"MOCK_SCRIPT_EXHAUSTED"}"#.to_string()),
                    }
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
                    reply.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        Mock { base: format!("http://{addr}"), seen }
    }

    fn requests_to(&self, path: &str) -> Vec<Seen> {
        self.seen.lock().unwrap().iter().filter(|r| r.path == path).cloned().collect()
    }
}

fn client(base: String) -> L1Client {
    L1Client::new(base, "contract-test", DEV_ISSUER_SECRET)
}

fn finalize_request() -> FinalizeHttpRequest {
    FinalizeHttpRequest {
        database_id: "db".into(),
        generation: 1,
        startup_session_id: "session-a".into(),
        operation_id: "op-1".into(),
        sequencing_kind: SequencingKind::Sequenced,
        record_type: 2,
        logical_key: None,
        payload_key: "p/db/00".into(),
        payload_digest: "00".into(),
        payload_length: 2,
    }
}

// ---------------------------------------------------------------------------
// R4-SEC-03/04/05: issuance restriction + method-registry enforcement.
// ---------------------------------------------------------------------------

#[test]
fn finalize_mint_without_generation_is_refused_before_finalize() {
    // A WAL_FINALIZE mint that omits the generation must die at ISSUANCE
    // with the Worker's CAPABILITY_RESTRICTION_MISSING - the guarded
    // /wal/finalize route must never be reached. (The fixed client always
    // threads request.generation; this probes the mint the pre-fix client
    // used to send, proving the mock is no longer a false green.)
    let mock = Mock::serve(&[], None);
    let client = client(mock.base.clone());
    match client.issue("db", CapabilityMethod::WalFinalize,
        MintRestrictions { session: Some("session-a"), ..Default::default() }) {
        Err(L1Error::Issuance { status: 403, body }) => {
            assert!(body.contains("CAPABILITY_RESTRICTION_MISSING"), "{body}");
            assert!(body.contains("generation"), "the refusal names the missing restriction: {body}");
        }
        other => panic!("a generation-less finalize mint must be a typed Issuance refusal, got {other:?}"),
    }
    assert!(mock.requests_to("/wal/finalize").is_empty(), "refused BEFORE finalize");
}

#[test]
fn read_mint_without_generation_is_refused_before_the_read() {
    // R4-SEC-05: WAL_READ is actor-bound exactly like finalize - session AND
    // generation are mandatory at mint time.
    let mock = Mock::serve(&[], None);
    let client = client(mock.base.clone());
    match client.issue("db", CapabilityMethod::WalRead,
        MintRestrictions { session: Some("session-a"), ..Default::default() }) {
        Err(L1Error::Issuance { status: 403, body }) => {
            assert!(body.contains("CAPABILITY_RESTRICTION_MISSING"), "{body}");
            assert!(body.contains("generation"), "{body}");
        }
        other => panic!("a generation-less read mint must be a typed Issuance refusal, got {other:?}"),
    }
    // and symmetrically for a session-less mint
    match client.issue("db", CapabilityMethod::WalRead,
        MintRestrictions { generation: Some(1), ..Default::default() }) {
        Err(L1Error::Issuance { status: 403, body }) => {
            assert!(body.contains("CAPABILITY_RESTRICTION_MISSING") && body.contains("session"), "{body}");
        }
        other => panic!("a session-less read mint must be a typed Issuance refusal, got {other:?}"),
    }
}

#[test]
fn reads_without_a_bound_actor_refuse_client_side() {
    // No default and no zero fallback exists for the actor generation: a
    // read before register_session/bind_actor is a typed ActorUnbound
    // refusal with NO wire traffic at all.
    let mock = Mock::serve(&[], None);
    let client = client(mock.base.clone());
    match client.head("db", 1) {
        Err(L1Error::ActorUnbound) => {}
        other => panic!("an unbound-actor read must be ActorUnbound, got {other:?}"),
    }
    assert!(mock.seen.lock().unwrap().is_empty(), "nothing may reach the wire");
}

#[test]
fn legacy_session_admin_method_is_refused_as_unknown() {
    // R4-SEC-04: the generic SESSION_ADMIN bearer method no longer exists;
    // the client cannot even spell it (no enum variant), so this posts the
    // raw issuance body a legacy client would send and asserts the mock's
    // closed-registry refusal - the same CAPABILITY_METHOD_UNKNOWN the
    // Worker's issuer answers.
    let mock = Mock::serve(&[], None);
    let config = ureq::config::Config::builder().http_status_as_error(false).build();
    let agent = config.new_agent();
    let mut response = agent
        .post(format!("{}/capability", mock.base))
        .header("x-issuer-authorization", DEV_ISSUER_SECRET)
        .send_json(serde_json::json!({
            "principal": "contract-test", "databaseId": "db", "method": "SESSION_ADMIN",
            "session": "session-a", "generation": 1, "ttlMs": 60_000,
        }))
        .expect("transport");
    assert_eq!(response.status().as_u16(), 403);
    let body: serde_json::Value = response.body_mut().read_json().expect("json body");
    assert_eq!(body["error"], "CAPABILITY_METHOD_UNKNOWN");
}

#[test]
fn happy_path_threads_the_exact_generation_through_every_mint() {
    const REGISTER_OK: (&str, &str) = ("200 OK", r#"{"ok":true}"#);
    const FINALIZED: (&str, &str) =
        ("200 OK", r#"{"ok":true,"appendLsn":"0","typeSequence":"1","controlSeq":"1","replayed":false}"#);
    const HEAD: (&str, &str) = ("200 OK", r#"{"ok":true,"headLsn":"0","headTypeSequence":"1"}"#);
    let mock = Mock::serve(&[REGISTER_OK, FINALIZED, HEAD], None);
    let client = client(mock.base.clone());

    client.register_session("db", 7, "session-a").expect("register");
    let mut request = finalize_request();
    request.generation = 7;
    let (status, outcome) = client.finalize(&request).expect("finalize");
    assert_eq!(status, 200);
    assert!(outcome.ok);
    client.head("db", 7).expect("head");

    // every mint named its exact method and carried the EXACT generation as
    // a JSON number - the validating issuer would have refused otherwise
    let mints = mock.requests_to("/capability");
    assert_eq!(mints.len(), 3, "one single-use mint per request");
    assert!(mints.iter().all(|mint| mint.method == "POST"), "issuance is POST /capability");
    for (mint, method) in mints.iter().zip(["SESSION_REGISTER", "WAL_FINALIZE", "WAL_READ"]) {
        assert_eq!(mint.body["method"], method);
        assert_eq!(mint.body["session"], "session-a", "{method} names the exact actor");
        assert_eq!(mint.body["generation"], 7, "{method} carries the exact generation, as a number");
    }

    // the finalize call presented the token whose payload the issuer bound
    // to exactly (session-a, 7), and its body claims that same generation
    let finalizes = mock.requests_to("/wal/finalize");
    assert_eq!(finalizes.len(), 1);
    assert_eq!(finalizes[0].capability.as_deref(), Some("cap-WAL_FINALIZE-s=session-a-g=7"));
    assert_eq!(finalizes[0].body["generation"], 7);
    assert_eq!(finalizes[0].body["startupSessionId"], "session-a");
}

// ---------------------------------------------------------------------------
// Fail-closed admin calls + credentialed issuance.
// ---------------------------------------------------------------------------

#[test]
fn issuance_refusal_is_a_typed_issuance_error() {
    let mock = Mock::serve(&[], Some(("401 Unauthorized", r#"{"ok":false,"error":"ISSUER_UNAUTHORIZED"}"#)));
    match client(mock.base.clone()).register_session("db", 1, "session-a") {
        Err(L1Error::Issuance { status: 401, body }) => {
            assert!(body.contains("ISSUER_UNAUTHORIZED"), "body preserved for diagnosis: {body}");
        }
        other => panic!("refused issuance must be a typed Issuance error, got {other:?}"),
    }
}

#[test]
fn register_on_json_404_is_a_typed_protocol_error_not_success() {
    let mock = Mock::serve(&[("404 Not Found", r#"{"ok":false,"error":"NOT_FOUND"}"#)], None);
    match client(mock.base.clone()).register_session("db", 1, "session-a") {
        Err(L1Error::Protocol { status: 404, body }) => {
            assert!(body.contains("NOT_FOUND"), "body preserved for diagnosis: {body}");
        }
        other => panic!("register over a 404 must be Protocol error, got {other:?}"),
    }
}

#[test]
fn register_on_ok_false_200_is_a_typed_protocol_error() {
    // status 200 but the effect was refused: still not success
    let mock = Mock::serve(&[("200 OK", r#"{"ok":false,"error":"REFUSED"}"#)], None);
    match client(mock.base.clone()).register_session("db", 1, "session-a") {
        Err(L1Error::Protocol { status: 200, body }) => assert!(body.contains("REFUSED")),
        other => panic!("register with ok:false must be Protocol error, got {other:?}"),
    }
}

#[test]
fn register_on_ok_true_200_succeeds() {
    let mock = Mock::serve(&[("200 OK", r#"{"ok":true}"#)], None);
    client(mock.base.clone()).register_session("db", 1, "session-a").expect("200 ok:true is success");
}

// ---------------------------------------------------------------------------
// Exact u64 wire codec.
// ---------------------------------------------------------------------------

#[test]
fn numeric_append_lsn_is_a_decode_error_never_a_coercion() {
    // F7: sequence values are decimal STRINGS on the wire. A server (or
    // proxy) answering with JSON numbers reintroduces the 2^53 cliff; the
    // client must refuse the response, not round it.
    let mock = Mock::serve(
        &[("200 OK", r#"{"ok":true,"appendLsn":0,"typeSequence":1,"controlSeq":1,"replayed":false}"#)],
        None,
    );
    match client(mock.base.clone()).finalize(&finalize_request()) {
        Err(L1Error::Decode(detail)) => {
            assert!(detail.contains("string"), "decode error names the type drift: {detail}");
        }
        other => panic!("numeric appendLsn must be a Decode error, got {other:?}"),
    }
}

#[test]
fn aliased_decimal_is_a_decode_error() {
    // "00" is an alias of 0: one value has one encoding (C-P1-02)
    let mock = Mock::serve(
        &[("200 OK", r#"{"ok":true,"appendLsn":"00","typeSequence":"1","controlSeq":"1","replayed":false}"#)],
        None,
    );
    match client(mock.base.clone()).finalize(&finalize_request()) {
        Err(L1Error::Decode(detail)) => assert!(detail.contains("canonical"), "{detail}"),
        other => panic!("aliased decimal must be a Decode error, got {other:?}"),
    }
}

#[test]
fn full_range_u64_decodes_exactly() {
    let mock = Mock::serve(
        &[(
            "200 OK",
            r#"{"ok":true,"appendLsn":"18446744073709551615","typeSequence":"18446744073709551615","controlSeq":"1","replayed":false}"#,
        )],
        None,
    );
    let (status, outcome) = client(mock.base.clone()).finalize(&finalize_request()).expect("canonical strings decode");
    assert_eq!(status, 200);
    assert_eq!(outcome.append_lsn, Some(u64::MAX), "no 2^53 cliff");
    assert_eq!(outcome.type_sequence, Some(u64::MAX));
}
