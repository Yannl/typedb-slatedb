//! Wire-contract regressions for the L1 client, against a scripted one-shot
//! HTTP responder (no workerd needed):
//!
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
    io::{Read, Write},
    net::TcpListener,
    thread,
};

use remote_wal_spike::l1_client::{
    FinalizeHttpRequest, L1Client, L1Error, SequencingKind, DEV_ISSUER_SECRET,
};

/// Scripted HTTP responder: serves the given (status line, JSON body) pairs
/// in request order, then repeats the last one for a bounded number of
/// extra requests so a client retry cannot hang the test.
fn serve_script(script: &'static [(&'static str, &'static str)]) -> String {
    assert!(!script.is_empty());
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for (served, stream) in listener.incoming().take(script.len() + 4).enumerate() {
            let mut stream = match stream {
                Ok(s) => s,
                Err(_) => return,
            };
            let mut buf = [0u8; 8192];
            let _ = stream.read(&mut buf);
            let (status_line, body) = script[served.min(script.len() - 1)];
            let resp = format!(
                "HTTP/1.1 {status_line}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    format!("http://{addr}")
}

const ISSUED: (&str, &str) =
    ("200 OK", r#"{"ok":true,"token":"cap-token","expiresAtMs":1,"incarnation":1}"#);

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

#[test]
fn issuance_refusal_is_a_typed_issuance_error() {
    let base = serve_script(&[("401 Unauthorized", r#"{"ok":false,"error":"ISSUER_UNAUTHORIZED"}"#)]);
    match client(base).register_session("db", 1, "session-a") {
        Err(L1Error::Issuance { status: 401, body }) => {
            assert!(body.contains("ISSUER_UNAUTHORIZED"), "body preserved for diagnosis: {body}");
        }
        other => panic!("refused issuance must be a typed Issuance error, got {other:?}"),
    }
}

#[test]
fn register_on_json_404_is_a_typed_protocol_error_not_success() {
    let base = serve_script(&[ISSUED, ("404 Not Found", r#"{"ok":false,"error":"NOT_FOUND"}"#)]);
    match client(base).register_session("db", 1, "session-a") {
        Err(L1Error::Protocol { status: 404, body }) => {
            assert!(body.contains("NOT_FOUND"), "body preserved for diagnosis: {body}");
        }
        other => panic!("register over a 404 must be Protocol error, got {other:?}"),
    }
}

#[test]
fn register_on_ok_false_200_is_a_typed_protocol_error() {
    // status 200 but the effect was refused: still not success
    let base = serve_script(&[ISSUED, ("200 OK", r#"{"ok":false,"error":"REFUSED"}"#)]);
    match client(base).register_session("db", 1, "session-a") {
        Err(L1Error::Protocol { status: 200, body }) => assert!(body.contains("REFUSED")),
        other => panic!("register with ok:false must be Protocol error, got {other:?}"),
    }
}

#[test]
fn register_on_ok_true_200_succeeds() {
    let base = serve_script(&[ISSUED, ("200 OK", r#"{"ok":true}"#)]);
    client(base).register_session("db", 1, "session-a").expect("200 ok:true is success");
}

#[test]
fn numeric_append_lsn_is_a_decode_error_never_a_coercion() {
    // F7: sequence values are decimal STRINGS on the wire. A server (or
    // proxy) answering with JSON numbers reintroduces the 2^53 cliff; the
    // client must refuse the response, not round it.
    let base = serve_script(&[ISSUED,
        ("200 OK", r#"{"ok":true,"appendLsn":0,"typeSequence":1,"controlSeq":1,"replayed":false}"#)]);
    match client(base).finalize(&finalize_request()) {
        Err(L1Error::Decode(detail)) => {
            assert!(detail.contains("string"), "decode error names the type drift: {detail}");
        }
        other => panic!("numeric appendLsn must be a Decode error, got {other:?}"),
    }
}

#[test]
fn aliased_decimal_is_a_decode_error() {
    // "00" is an alias of 0: one value has one encoding (C-P1-02)
    let base = serve_script(&[ISSUED,
        ("200 OK", r#"{"ok":true,"appendLsn":"00","typeSequence":"1","controlSeq":"1","replayed":false}"#)]);
    match client(base).finalize(&finalize_request()) {
        Err(L1Error::Decode(detail)) => assert!(detail.contains("canonical"), "{detail}"),
        other => panic!("aliased decimal must be a Decode error, got {other:?}"),
    }
}

#[test]
fn full_range_u64_decodes_exactly() {
    let base = serve_script(&[ISSUED,
        ("200 OK",
         r#"{"ok":true,"appendLsn":"18446744073709551615","typeSequence":"18446744073709551615","controlSeq":"1","replayed":false}"#)]);
    let (status, outcome) = client(base).finalize(&finalize_request()).expect("canonical strings decode");
    assert_eq!(status, 200);
    assert_eq!(outcome.append_lsn, Some(u64::MAX), "no 2^53 cliff");
    assert_eq!(outcome.type_sequence, Some(u64::MAX));
}
