//! Regression (review finding): `register_session`/`fence_session` must fail
//! closed on any response that is not HTTP 200 `{"ok": true}`. A misrouted
//! base URL hitting a catch-all 404 with a parseable JSON error body used to
//! be reported as success — the caller then believed a fence was installed
//! that never was.

use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
};

use remote_wal_spike::l1_client::{L1Client, L1Error};

/// One-shot HTTP responder returning a fixed status + JSON body.
fn serve_once(status_line: &'static str, body: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        // serve a handful of requests so a client retry cannot hang the test
        for stream in listener.incoming().take(4) {
            let mut stream = match stream {
                Ok(s) => s,
                Err(_) => return,
            };
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let resp = format!(
                "HTTP/1.1 {status_line}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    format!("http://{addr}")
}

#[test]
fn fence_on_json_404_is_a_typed_protocol_error_not_success() {
    let base = serve_once("404 Not Found", r#"{"ok":false,"error":"NOT_FOUND"}"#);
    let client = L1Client::new(base);
    match client.fence_session("db", 1, "session-a") {
        Err(L1Error::Protocol { status: 404, body }) => {
            assert!(body.contains("NOT_FOUND"), "body preserved for diagnosis: {body}");
        }
        other => panic!("fence over a 404 must be Protocol error, got {other:?}"),
    }
}

#[test]
fn register_on_ok_false_200_is_a_typed_protocol_error() {
    // status 200 but the effect was refused: still not success
    let base = serve_once("200 OK", r#"{"ok":false,"error":"REFUSED"}"#);
    let client = L1Client::new(base);
    match client.register_session("db", 1, "session-a") {
        Err(L1Error::Protocol { status: 200, body }) => {
            assert!(body.contains("REFUSED"));
        }
        other => panic!("register with ok:false must be Protocol error, got {other:?}"),
    }
}

#[test]
fn register_on_ok_true_200_succeeds() {
    let base = serve_once("200 OK", r#"{"ok":true}"#);
    let client = L1Client::new(base);
    client.register_session("db", 1, "session-a").expect("200 ok:true is success");
}
