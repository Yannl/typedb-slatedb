//! Wire-contract regressions for the L1 client against a local mock stack
//! (no workerd, no node needed): a VALIDATING PRIVATE ISSUER plus scripted
//! responses for the managed worker routes.
//!
//! R5-SEC-02 reshaped what this file has to mock. The client no longer
//! mints anything and no longer speaks a dev route: it is a pure BEARER of
//! issuer-granted tokens, obtained over HTTP from the private issuer
//! (`control-plane/scripts/issuer.mjs` startIssuerServer:
//! bearer-authenticated, `POST /issue {spec} -> {token}`,
//! `POST /provision-token {binding} -> {token}`). So the mock here IS an
//! issuer, and it validates issuance the way the real one does:
//!
//!  - R4-SEC-03/04/05: the CLOSED capability-method registry and the
//!    per-method REQUIRED restrictions
//!    (`control-plane/src/controller/core/capability.ts`
//!    REQUIRED_RESTRICTIONS) are enforced on every `POST /issue` spec,
//!    answering the real issuer's shapes (HTTP 400 `ISSUE_SPEC_INVALID`
//!    with a `detail` naming `CAPABILITY_METHOD_UNKNOWN` /
//!    `CAPABILITY_RESTRICTION_MISSING`, exactly as
//!    `core/issuer.ts mintCapabilityToken` throws and the issuer server
//!    wraps). An under-restricted spec therefore dies AT ISSUANCE — no
//!    token is ever produced and the guarded route is never reached;
//!  - bearer authentication: an unauthenticated issuance is a typed
//!    `Issuance` refusal (401), never a silent grant;
//!  - fail-closed lifecycle calls: a transition reports success ONLY on
//!    HTTP 200 `{"ok": true}` — a misrouted 404 or an `ok:false` body with
//!    a 200 status must surface as a typed protocol error, never as
//!    success (a caller could otherwise believe an activation exists that
//!    was never installed);
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

use remote_wal_spike::{
    hex,
    l1_client::{CapabilityMethod, FinalizeHttpRequest, L1Client, L1Config, L1Error, MintRestrictions, SequencingKind},
    sha256,
};

const BEARER: &str = "contract-issuer-bearer-0123456789";

// ---------------------------------------------------------------------------
// The validating mock private issuer + scripted worker-route responder.
// ---------------------------------------------------------------------------

/// The Worker's CLOSED capability-method registry with each method's
/// MANDATORY mint-time restrictions — a mirror of REQUIRED_RESTRICTIONS in
/// `control-plane/src/controller/core/capability.ts`. `session` must be a
/// nonempty string; `generation` must be a nonnegative-integer JSON NUMBER
/// on the issuance wire (the token then binds its canonical decimal string
/// form). PUT_PAYLOAD's required `key` is issuer-DERIVED from the digest,
/// so at mint time it reduces to the digest being present — exactly how
/// `createIssuer.mintCapability` builds it.
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
    ("PROVISION", &[]),
];

/// The dev-only ROUTE methods: they exist in the registry (the local-dev
/// posture still serves those routes) but the managed client must never
/// request one. `client_methods_exclude_every_dev_only_route_method` pins
/// that the client's closed enum cannot even spell them.
const DEV_ONLY_ROUTE_METHODS: &[&str] =
    &["SESSION_REGISTER", "SESSION_FENCE", "BUDGETS_SET", "INCARNATION_BUMP", "OUTBOX"];

/// One request the mock observed on the wire.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path: String,
    body: serde_json::Value,
    capability: Option<String>,
    provision: Option<String>,
    authorization: Option<String>,
}

/// Validate one issuance spec EXACTLY the way the real issuer does at mint
/// time, and answer either the typed refusal or a grant. The minted token
/// text encodes the restrictions the issuer bound
/// (`cap-<METHOD>-s=<session>-g=<generation>`), so a later guarded request
/// can be asserted to present a token carrying the exact values the client
/// threaded into issuance.
fn issue_or_refuse(spec: &serde_json::Value) -> (u16, String) {
    let method = spec["method"].as_str().unwrap_or_default().to_string();
    // closed registry: an unknown method (e.g. the retired SESSION_ADMIN)
    // is refused outright, never treated as restriction-free
    let Some((_, required)) = REQUIRED_RESTRICTIONS.iter().find(|(name, _)| *name == method) else {
        return (
            400,
            format!(r#"{{"ok":false,"error":"ISSUE_SPEC_INVALID","detail":"CAPABILITY_METHOD_UNKNOWN: {method}"}}"#),
        );
    };
    // mandatory-by-method restrictions: absence (or the wrong JSON type) is
    // refusal, not permission — a token missing one would be WIDER, and
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
            return (
                400,
                format!(
                    r#"{{"ok":false,"error":"ISSUE_SPEC_INVALID","detail":"CAPABILITY_RESTRICTION_MISSING: {method} requires {restriction}"}}"#
                ),
            );
        }
    }
    let mut token = format!("cap-{method}");
    if let Some(session) = spec["session"].as_str() {
        token.push_str(&format!("-s={session}"));
    }
    if let Some(generation) = spec["generation"].as_u64() {
        token.push_str(&format!("-g={generation}"));
    }
    // PUT_PAYLOAD keys are ISSUER-DERIVED and content-addressed (F9): the
    // caller never selects an object key
    let key = if method == "PUT_PAYLOAD" {
        format!(
            r#","key":"p/{}/{}""#,
            spec["databaseId"].as_str().unwrap_or_default(),
            spec["digest"].as_str().unwrap_or_default()
        )
    } else {
        String::new()
    };
    (200, format!(r#"{{"ok":true,"token":"{token}","expiresAtMs":1,"incarnation":1{key}}}"#))
}

/// `POST /provision-token`: the real issuer validates the binding ids and
/// mints under the SEPARATE provisioning-scope key.
fn provision_or_refuse(body: &serde_json::Value) -> (u16, String) {
    let binding = if body.get("binding").is_some() { &body["binding"] } else { body };
    let valid = |value: &serde_json::Value| {
        value.as_str().is_some_and(|s| {
            !s.is_empty()
                && s.len() <= 64
                && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !s.starts_with('-')
                && !s.ends_with('-')
        })
    };
    if !valid(&binding["tenantId"]) || !valid(&binding["databaseId"]) {
        return (400, r#"{"ok":false,"error":"INVALID_BINDING"}"#.to_string());
    }
    let token = format!(
        "prov-{}-{}",
        binding["tenantId"].as_str().unwrap_or_default(),
        binding["databaseId"].as_str().unwrap_or_default()
    );
    (200, format!(r#"{{"ok":true,"token":"{token}"}}"#))
}

/// (method, path, lowercased headers, body bytes) of one parsed request.
type ParsedRequest = (String, String, Vec<(String, String)>, Vec<u8>);

/// Read one full HTTP request (request line, the headers this mock cares
/// about, and a content-length-delimited body) from the stream.
fn read_request(stream: &mut TcpStream) -> Option<ParsedRequest> {
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
    let mut headers = Vec::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else { continue };
        let name = name.to_ascii_lowercase();
        if name == "content-length" {
            content_length = value.trim().parse().unwrap_or(0);
        }
        headers.push((name, value.trim().to_string()));
    }
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Some((method, path, headers, body))
}

struct Mock {
    base: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Mock {
    /// Serve the ISSUER routes (`/issue`, `/provision-token`) through the
    /// validating issuer above — or the forced `issuance_override` answer,
    /// for issuer-refusal cases — and every WORKER route from `script`
    /// (one (status, JSON body) per request, in order). Every request is
    /// recorded; an exhausted script answers a typed refusal rather than
    /// hanging the client.
    fn serve(script: Vec<(u16, String)>, issuance_override: Option<(u16, String)>) -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        thread::spawn(move || {
            let mut remaining: VecDeque<(u16, String)> = script.into_iter().collect();
            // bounded accept loop: a runaway retrying client cannot pin this
            // thread past any plausible test's request count
            for stream in listener.incoming().take(64) {
                let Ok(mut stream) = stream else { return };
                let Some((method, path, headers, body)) = read_request(&mut stream) else { continue };
                let header = |name: &str| headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
                let body_json: serde_json::Value = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
                recorder.lock().unwrap().push(Seen {
                    method: method.clone(),
                    path: path.clone(),
                    body: body_json.clone(),
                    capability: header("x-capability"),
                    provision: header("x-provision"),
                    authorization: header("authorization"),
                });
                let issuer_route = method == "POST" && (path == "/issue" || path == "/provision-token");
                let (status, reply) = if issuer_route {
                    // the real issuer authenticates EVERY route before it
                    // looks at a body: anonymous issuance mints nothing
                    if header("authorization").as_deref() != Some(&format!("Bearer {BEARER}")) {
                        (401, r#"{"ok":false,"error":"ISSUER_UNAUTHORIZED"}"#.to_string())
                    } else if let Some((status, reply)) = issuance_override.clone() {
                        (status, reply)
                    } else if path == "/issue" {
                        let spec =
                            if body_json.get("spec").is_some() { body_json["spec"].clone() } else { body_json.clone() };
                        issue_or_refuse(&spec)
                    } else {
                        provision_or_refuse(&body_json)
                    }
                } else {
                    match remaining.pop_front() {
                        Some((status, reply)) => (status, reply),
                        None => (599, r#"{"ok":false,"error":"MOCK_SCRIPT_EXHAUSTED"}"#.to_string()),
                    }
                };
                let response = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
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

/// The client under test: worker base and issuer base both point at the
/// mock (their route spaces are disjoint), so ONE server observes the whole
/// bearer topology — where authority is obtained and where it is spent.
fn client(base: String) -> L1Client {
    L1Client::new(L1Config {
        base: base.clone(),
        issuer_base: base,
        issuer_bearer: BEARER.to_string(),
        principal: "contract-test".to_string(),
        tenant_id: "tenant-a".to_string(),
    })
}

fn ok(body: &str) -> (u16, String) {
    (200, body.to_string())
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
// The mock validates like the real issuer, so an under-restricted spec dies
// BEFORE any token exists.
// ---------------------------------------------------------------------------

#[test]
fn finalize_spec_without_generation_dies_at_issuance() {
    // A WAL_FINALIZE spec that omits the generation must die at ISSUANCE
    // with the issuer's CAPABILITY_RESTRICTION_MISSING — the guarded
    // /wal/finalize route must never be reached, and no token may exist.
    let mock = Mock::serve(vec![], None);
    let client = client(mock.base.clone());
    match client.issue(
        "db",
        CapabilityMethod::WalFinalize,
        MintRestrictions { session: Some("session-a"), ..Default::default() },
    ) {
        Err(L1Error::Issuance { status: 400, body }) => {
            assert!(body.contains("CAPABILITY_RESTRICTION_MISSING"), "{body}");
            assert!(body.contains("generation"), "the refusal names the missing restriction: {body}");
            assert!(!body.contains("\"token\""), "a refused issuance produces NO token: {body}");
        }
        other => panic!("a generation-less finalize spec must be a typed Issuance refusal, got {other:?}"),
    }
    assert!(mock.requests_to("/wal/finalize").is_empty(), "refused BEFORE finalize");
}

#[test]
fn read_spec_without_generation_or_session_dies_at_issuance() {
    // R4-SEC-05: WAL_READ is actor-bound exactly like finalize — session AND
    // generation are mandatory at mint time.
    let mock = Mock::serve(vec![], None);
    let client = client(mock.base.clone());
    match client.issue(
        "db",
        CapabilityMethod::WalRead,
        MintRestrictions { session: Some("session-a"), ..Default::default() },
    ) {
        Err(L1Error::Issuance { status: 400, body }) => {
            assert!(body.contains("CAPABILITY_RESTRICTION_MISSING") && body.contains("generation"), "{body}");
        }
        other => panic!("a generation-less read spec must be a typed Issuance refusal, got {other:?}"),
    }
    match client.issue("db", CapabilityMethod::WalRead, MintRestrictions { generation: Some(1), ..Default::default() })
    {
        Err(L1Error::Issuance { status: 400, body }) => {
            assert!(body.contains("CAPABILITY_RESTRICTION_MISSING") && body.contains("session"), "{body}");
        }
        other => panic!("a session-less read spec must be a typed Issuance refusal, got {other:?}"),
    }
}

#[test]
fn payload_spec_without_digest_or_budget_dies_at_issuance() {
    // PUT_PAYLOAD binds the exact content digest AND a byte budget; the
    // issuer-derived key follows from the digest, so a digest-less spec can
    // produce no key at all.
    let mock = Mock::serve(vec![], None);
    let client = client(mock.base.clone());
    for restrict in [
        MintRestrictions { max_bytes: Some(7), ..Default::default() },
        MintRestrictions { digest: Some("ab"), ..Default::default() },
    ] {
        match client.issue("db", CapabilityMethod::PutPayload, restrict) {
            Err(L1Error::Issuance { status: 400, body }) => {
                assert!(body.contains("CAPABILITY_RESTRICTION_MISSING"), "{body}");
            }
            other => panic!("an under-restricted payload spec must be refused, got {other:?}"),
        }
    }
    assert!(mock.seen.lock().unwrap().iter().all(|r| r.path == "/issue"), "nothing reached a worker route");
}

#[test]
fn retired_session_admin_method_is_refused_by_the_closed_registry() {
    // R4-SEC-04: the generic SESSION_ADMIN bearer method no longer exists;
    // the client cannot even spell it (no enum variant), so this posts the
    // raw issuance spec a legacy client would send and asserts the issuer's
    // closed-registry refusal.
    let mock = Mock::serve(vec![], None);
    let config = ureq::config::Config::builder().http_status_as_error(false).build();
    let agent = config.new_agent();
    let mut response = agent
        .post(format!("{}/issue", mock.base))
        .header("authorization", format!("Bearer {BEARER}"))
        .send_json(serde_json::json!({ "spec": {
            "principal": "contract-test", "databaseId": "db", "method": "SESSION_ADMIN",
            "session": "session-a", "generation": 1, "ttlMs": 60_000,
        }}))
        .expect("transport");
    assert_eq!(response.status().as_u16(), 400);
    let body: serde_json::Value = response.body_mut().read_json().expect("json body");
    assert_eq!(body["error"], "ISSUE_SPEC_INVALID");
    assert!(body["detail"].as_str().unwrap_or_default().contains("CAPABILITY_METHOD_UNKNOWN"), "{body}");
}

#[test]
fn client_methods_exclude_every_dev_only_route_method() {
    // R5-SEC-02: the managed surface has no /session/register, /session/fence,
    // /budgets, /admin/* or /outbox/* route. The client's method enum is
    // closed and deliberately omits their capability methods, so no code
    // path — not even a mistaken one — can request authority for them.
    let spelled: Vec<String> = [
        CapabilityMethod::SessionReserve,
        CapabilityMethod::SessionAttest,
        CapabilityMethod::SessionActivate,
        CapabilityMethod::SessionRenew,
        CapabilityMethod::WalFinalize,
        CapabilityMethod::WalRead,
        CapabilityMethod::PutPayload,
        CapabilityMethod::JournalVerify,
    ]
    .iter()
    .map(|method| {
        remote_wal_spike::l1_client::issuance_spec("p", "db", *method, &MintRestrictions::default())["method"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    })
    .collect();
    for dev_only in DEV_ONLY_ROUTE_METHODS {
        assert!(!spelled.iter().any(|m| m == dev_only), "the managed client must not be able to request {dev_only}");
    }
    // and every method it CAN spell is in the worker's closed registry
    for method in &spelled {
        assert!(
            REQUIRED_RESTRICTIONS.iter().any(|(name, _)| name == method),
            "{method} is not a known capability method"
        );
    }
}

#[test]
fn reads_without_a_bound_actor_refuse_client_side() {
    // No default and no zero fallback exists for the actor generation: a
    // read before activation/bind_actor is a typed ActorUnbound refusal with
    // NO wire traffic at all — not even an issuance request.
    let mock = Mock::serve(vec![], None);
    let client = client(mock.base.clone());
    match client.head("db", 1) {
        Err(L1Error::ActorUnbound) => {}
        other => panic!("an unbound-actor read must be ActorUnbound, got {other:?}"),
    }
    assert!(mock.seen.lock().unwrap().is_empty(), "nothing may reach the wire");
}

// ---------------------------------------------------------------------------
// The managed lifecycle, end to end against the mock.
// ---------------------------------------------------------------------------

#[test]
fn managed_bootstrap_threads_the_exact_actor_through_every_issuance() {
    let payload: &[u8] = b"contract-record";
    let digest = hex(&sha256(payload));
    let mock = Mock::serve(
        vec![
            ok(r#"{"ok":true,"created":true}"#),                                // POST /provision
            ok(r#"{"ok":true}"#),                                               // /session/reserve
            ok(r#"{"ok":true}"#),                                               // /session/attest
            ok(r#"{"ok":true,"leaseDeadlineMs":1000,"fencedPredecessors":0}"#), // /session/activate
            ok(&format!(r#"{{"key":"p/db/{digest}","sha256hex":"{digest}","length":{}}}"#, payload.len())),
            ok(r#"{"ok":true,"appendLsn":"0","typeSequence":"1","controlSeq":"1","replayed":false}"#),
            ok(r#"{"ok":true,"headLsn":"0","headTypeSequence":"1"}"#),
        ],
        None,
    );
    let client = client(mock.base.clone());

    assert!(client.provision("db", None).expect("provision").created);
    client.reserve_session("db", 7, "session-a", "holder-1").expect("reserve");
    client.attest_session("db", "session-a", "pn-1").expect("attest");
    let activation = client.activate_session("db", 7, "session-a", "pn-1", 60_000).expect("activate");
    assert_eq!((activation.lease_deadline_ms, activation.fenced_predecessors), (1000, 0));
    let receipt = client.upload_payload("db", payload).expect("upload");
    assert_eq!(receipt.key, format!("p/db/{digest}"), "the key is issuer-derived, never client-chosen");
    let mut request = finalize_request();
    request.generation = 7;
    request.payload_from(&receipt);
    let (status, outcome) = client.finalize(&request).expect("finalize");
    assert_eq!(status, 200);
    assert!(outcome.ok);
    // activation bound the actor: this read needs no explicit bind
    client.head("db", 7).expect("head");

    // provisioning authority came from the SEPARATE provisioning scope, and
    // was presented as x-provision — never as an ordinary capability
    let provision_grants = mock.requests_to("/provision-token");
    assert_eq!(provision_grants.len(), 1, "one provisioning grant per provisioning call");
    assert_eq!(provision_grants[0].body["binding"]["tenantId"], "tenant-a");
    let provisions = mock.requests_to("/provision");
    assert_eq!(provisions.len(), 1);
    assert_eq!(provisions[0].provision.as_deref(), Some("prov-tenant-a-db"));
    assert!(provisions[0].capability.is_none(), "provisioning is not an ordinary capability");

    // every issuance named its exact method and carried the EXACT actor as
    // the method requires — the validating issuer would have refused
    // otherwise — and each was bearer-authenticated
    let issuances = mock.requests_to("/issue");
    let methods: Vec<&str> = issuances.iter().map(|i| i.body["spec"]["method"].as_str().unwrap_or_default()).collect();
    assert_eq!(
        methods,
        vec!["SESSION_RESERVE", "SESSION_ATTEST", "SESSION_ACTIVATE", "PUT_PAYLOAD", "WAL_FINALIZE", "WAL_READ"],
        "one single-use grant per request, in protocol order",
    );
    assert!(issuances.iter().all(|i| i.method == "POST"), "issuance is POST /issue");
    assert!(
        issuances.iter().all(|i| i.authorization.as_deref() == Some(&format!("Bearer {BEARER}"))),
        "issuance is bearer-authenticated"
    );
    for issuance in &issuances {
        let spec = &issuance.body["spec"];
        let method = spec["method"].as_str().unwrap();
        if REQUIRED_RESTRICTIONS.iter().any(|(name, r)| *name == method && r.contains(&"generation")) {
            assert_eq!(spec["generation"], 7, "{method} carries the exact generation, as a JSON number");
        }
        if REQUIRED_RESTRICTIONS.iter().any(|(name, r)| *name == method && r.contains(&"session")) {
            assert_eq!(spec["session"], "session-a", "{method} names the exact actor");
        }
    }

    // the finalize call presented the token whose payload the issuer bound
    // to exactly (session-a, 7), and its body claims that same generation
    let finalizes = mock.requests_to("/wal/finalize");
    assert_eq!(finalizes.len(), 1);
    assert_eq!(finalizes[0].capability.as_deref(), Some("cap-WAL_FINALIZE-s=session-a-g=7"));
    assert_eq!(finalizes[0].body["generation"], 7);
    assert_eq!(finalizes[0].body["startupSessionId"], "session-a");
    // Q-18: the dedupe digest is SERVER-derived — no requestDigest on the wire
    assert!(finalizes[0].body.get("requestDigest").is_none(), "requestDigest is not a wire field");
}

#[test]
fn a_non_canonical_issuer_key_is_refused_before_the_upload() {
    // The issuer derives the object key; a grant naming any other key is a
    // protocol violation the client refuses to act on rather than uploading
    // under a key it was not authorized for.
    let mock = Mock::serve(
        vec![],
        Some((200, r#"{"ok":true,"token":"cap-PUT_PAYLOAD","key":"p/other-db/deadbeef"}"#.to_string())),
    );
    let client = client(mock.base.clone());
    match client.upload_payload("db", b"bytes") {
        Err(L1Error::Decode(detail)) => {
            assert!(detail.contains("canonical"), "{detail}");
        }
        other => panic!("a non-canonical issuer key must refuse the upload, got {other:?}"),
    }
    assert!(mock.seen.lock().unwrap().iter().all(|r| r.path == "/issue"), "nothing was uploaded");
}

// ---------------------------------------------------------------------------
// Fail-closed lifecycle calls + credentialed issuance.
// ---------------------------------------------------------------------------

#[test]
fn issuance_refusal_is_a_typed_issuance_error() {
    let mock = Mock::serve(vec![], Some((401, r#"{"ok":false,"error":"ISSUER_UNAUTHORIZED"}"#.to_string())));
    match client(mock.base.clone()).reserve_session("db", 1, "session-a", "holder") {
        Err(L1Error::Issuance { status: 401, body }) => {
            assert!(body.contains("ISSUER_UNAUTHORIZED"), "body preserved for diagnosis: {body}");
        }
        other => panic!("refused issuance must be a typed Issuance error, got {other:?}"),
    }
}

#[test]
fn anonymous_issuance_is_refused_by_the_issuer() {
    // the bearer credential is the client's ONLY credential; without it the
    // issuer mints nothing (and the client can obtain no authority at all)
    let mock = Mock::serve(vec![], None);
    let anonymous = L1Client::new(L1Config {
        base: mock.base.clone(),
        issuer_base: mock.base.clone(),
        issuer_bearer: "not-the-bearer".to_string(),
        principal: "contract-test".to_string(),
        tenant_id: "tenant-a".to_string(),
    });
    match anonymous.issue("db", CapabilityMethod::JournalVerify, MintRestrictions::default()) {
        Err(L1Error::Issuance { status: 401, body }) => assert!(body.contains("ISSUER_UNAUTHORIZED"), "{body}"),
        other => panic!("an unauthenticated issuance must refuse, got {other:?}"),
    }
}

#[test]
fn a_lifecycle_transition_on_json_404_is_a_typed_protocol_error_not_success() {
    let mock = Mock::serve(vec![(404, r#"{"ok":false,"error":"NOT_FOUND"}"#.to_string())], None);
    match client(mock.base.clone()).activate_session("db", 1, "session-a", "pn-1", 60_000) {
        Err(L1Error::Protocol { status: 404, body }) => {
            assert!(body.contains("NOT_FOUND"), "body preserved for diagnosis: {body}");
        }
        other => panic!("activation over a 404 must be a Protocol error, got {other:?}"),
    }
}

#[test]
fn a_lifecycle_transition_on_ok_false_200_is_a_typed_protocol_error() {
    // status 200 but the effect was refused: still not success — a caller
    // must never believe an activation exists that was never installed
    let mock = Mock::serve(vec![(200, r#"{"ok":false,"error":"SESSION_UNKNOWN"}"#.to_string())], None);
    match client(mock.base.clone()).activate_session("db", 1, "session-a", "pn-1", 60_000) {
        Err(L1Error::Protocol { status: 200, body }) => assert!(body.contains("SESSION_UNKNOWN"), "{body}"),
        other => panic!("activation with ok:false must be a Protocol error, got {other:?}"),
    }
}

#[test]
fn an_activation_without_its_lease_fields_is_a_decode_error() {
    // the lease deadline and fenced count are the OUTCOME of the one fencing
    // transition; a 200 that omits them is drift, not a success to assume
    let mock = Mock::serve(vec![(200, r#"{"ok":true}"#.to_string())], None);
    match client(mock.base.clone()).activate_session("db", 1, "session-a", "pn-1", 60_000) {
        Err(L1Error::Decode(detail)) => assert!(detail.contains("leaseDeadlineMs"), "{detail}"),
        other => panic!("a lease-less activation must be a Decode error, got {other:?}"),
    }
}

#[test]
fn provisioning_reports_replay_without_claiming_creation() {
    let mock = Mock::serve(vec![(200, r#"{"ok":true,"created":false}"#.to_string())], None);
    let outcome = client(mock.base.clone()).provision("db", None).expect("idempotent replay is success");
    assert!(!outcome.created, "a replayed binding must not be reported as created");
}

// ---------------------------------------------------------------------------
// Exact u64 wire codec.
// ---------------------------------------------------------------------------

#[test]
fn numeric_append_lsn_is_a_decode_error_never_a_coercion() {
    // F7: sequence values are decimal STRINGS on the wire. A server (or
    // proxy) answering with JSON numbers reintroduces the 2^53 cliff; the
    // client must refuse the response, not round it.
    let mock =
        Mock::serve(vec![ok(r#"{"ok":true,"appendLsn":0,"typeSequence":1,"controlSeq":1,"replayed":false}"#)], None);
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
        vec![ok(r#"{"ok":true,"appendLsn":"00","typeSequence":"1","controlSeq":"1","replayed":false}"#)],
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
        vec![ok(
            r#"{"ok":true,"appendLsn":"18446744073709551615","typeSequence":"18446744073709551615","controlSeq":"1","replayed":false}"#,
        )],
        None,
    );
    let (status, outcome) = client(mock.base.clone()).finalize(&finalize_request()).expect("canonical strings decode");
    assert_eq!(status, 200);
    assert_eq!(outcome.append_lsn, Some(u64::MAX), "no 2^53 cliff");
    assert_eq!(outcome.type_sequence, Some(u64::MAX));
}
