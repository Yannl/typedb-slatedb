//! MANAGED LANE (R5-SEC-02): the EXACT Rust client against the
//! PRODUCTION-SHAPED control-plane surface.
//!
//! `wrangler dev --local -c wrangler.toml` is the fail-closed posture a
//! default deploy selects: `CONTROLLER_SURFACE` is unset, so every
//! dev-only route is physically absent (worker-entry.ts devOnlyRoute), and
//! the managed key profile resolves ONLY public verification keyrings — the
//! runtime holds no signing material at all. Authority therefore cannot
//! come from the worker: it comes from the PRIVATE ISSUER sidecar
//! (control-plane/scripts/issuer.mjs via tests/support/issuer_sidecar.mjs),
//! which generates per-run ephemeral Ed25519 keypairs, keeps the private
//! halves in its own process, and hands the worker only the PUBLIC
//! keyrings + environment name it boots from.
//!
//! What this lane proves, and where:
//!   - dev-only routes answer 404 on managed, from Rust, with the client's
//!     own transport — `dev_only_routes_are_absent_on_the_managed_surface`
//!     (and the suite's journal check proves those probes left ZERO state);
//!   - the whole product protocol — provision, reserve -> attest ->
//!     activate -> renew, payload upload, finalize, identical-retry replay,
//!     exact read, head, pinned iterator + paged scan, last-by-type,
//!     takeover fencing — runs on that surface under issuer-granted tokens
//!     only: `l1_suite::run`, the SAME suite the local-dev lane runs.
//!
//! `cargo test -p remote-wal-spike --test l1_managed_stack` (requires the
//! control-plane npm install).

use std::time::Duration;

use remote_wal_spike::{
    l1_client::{L1Client, L1Config},
    l1_suite,
};

#[path = "support/stack.rs"]
// shared across both live lanes; each lane uses the part it needs
#[allow(dead_code)]
mod stack;

/// Distinct band from the local-dev lane's (8800+) so both can run in the
/// same `cargo test` invocation.
fn port() -> u16 {
    9200 + (std::process::id() % 200) as u16
}

/// One dev-route probe: method, path, optional JSON body, extra headers.
type DevProbe = (&'static str, String, Option<serde_json::Value>, Vec<(&'static str, &'static str)>);

/// A managed deployment must name its OWN environment; `local` is reserved
/// for the dev profile and is refused here by key-config.
const MANAGED_ENVIRONMENT: &str = "managed-rust";
const TENANT: &str = "tenant-a";
/// The committed DEV-INSECURE issuance credential. Worthless on managed:
/// the route it authenticates does not exist there.
const DEV_ISSUER_SECRET: &str = "dev-insecure-issuer-secret";

#[test]
fn rust_client_full_protocol_against_the_managed_surface() {
    let bearer = stack::fresh_secret("l1-managed-issuer-bearer");
    // per-run ephemeral keypairs; runtime_vars are the PUBLIC halves +
    // environment name — exactly the graph-declared managed inputs
    let issuer = stack::spawn_issuer("managed", MANAGED_ENVIRONMENT, TENANT, &bearer);
    assert!(
        !issuer.runtime_vars.is_empty(),
        "the managed issuer must publish the runtime's public verification keyrings"
    );
    let mut vars = issuer.runtime_vars.clone();
    // the journal MAC key is SYMMETRIC by design (writer = verifier = the
    // same DO); it is the one managed secret, fresh per run
    vars.push(("CONTROLLER_JOURNAL_KEY".to_string(), stack::fresh_secret("l1-managed-journal")));
    let _worker = stack::spawn_wrangler("wrangler.toml", port(), &vars);

    let client = L1Client::new(L1Config {
        base: format!("http://127.0.0.1:{}", port()),
        issuer_base: issuer.url.clone(),
        issuer_bearer: bearer,
        principal: "l1-managed-stack-test".to_string(),
        tenant_id: TENANT.to_string(),
    });
    l1_suite::wait_healthy(&client, Duration::from_secs(60)).expect("managed stack never became healthy");

    let db = stack::unique_database_id("rust-managed");

    // ---- posture first: the dev-only surface does not exist here -------
    // Probed BEFORE the bootstrap so the suite's journal-length check (and
    // its opening DATABASE_UNPROVISIONED check) prove these probes left NO
    // DO/registry/journal state behind.
    let gen = 1u64;
    let dev_routes: Vec<DevProbe> = vec![
        // the dev issuance route, presented WITH the committed dev issuer
        // credential: on managed there is nothing to authenticate against
        (
            "POST",
            "/capability".into(),
            Some(serde_json::json!({ "principal": "p", "databaseId": db, "method": "WAL_READ" })),
            vec![("x-issuer-authorization", DEV_ISSUER_SECRET)],
        ),
        (
            "POST",
            "/session/register".into(),
            Some(serde_json::json!({ "databaseId": db, "generation": gen, "startupSessionId": "sess-probe" })),
            vec![],
        ),
        (
            "POST",
            "/session/fence".into(),
            Some(serde_json::json!({ "databaseId": db, "generation": gen, "startupSessionId": "sess-probe" })),
            vec![],
        ),
        (
            "POST",
            "/budgets".into(),
            Some(serde_json::json!({ "databaseId": db, "maxUnpublishedOutbox": 1,
                                  "maxPayloadLength": 1, "maxTailRecords": 1 })),
            vec![],
        ),
        (
            "POST",
            "/wal/finalize-batch".into(),
            Some(serde_json::json!({ "batchOperationId": "b", "requests": [] })),
            vec![],
        ),
        ("POST", format!("/admin/{db}/incarnation/bump"), Some(serde_json::json!({})), vec![]),
        ("GET", format!("/outbox/{db}?limit=10"), None, vec![]),
        ("POST", format!("/outbox/{db}/ack"), Some(serde_json::json!({ "upToControlSeq": "1" })), vec![]),
        ("GET", format!("/wal/{db}/{gen}/audit"), None, vec![]),
    ];
    let mut absent = 0u32;
    for (method, path, body, headers) in &dev_routes {
        let probe = client
            .probe(method, path, body.as_ref(), headers)
            .unwrap_or_else(|e| panic!("dev-route probe {method} {path} transport failed: {e}"));
        assert_eq!(
            (probe.0, &probe.1["error"]),
            (404, &serde_json::Value::String("NOT_FOUND".into())),
            "dev route {method} {path} must be ABSENT on the managed surface, got {probe:?}",
        );
        absent += 1;
        println!("PASS  dev route {method} {} is absent on the managed surface", path.split('?').next().unwrap());
    }
    assert_eq!(absent as usize, dev_routes.len(), "every dev route must have been probed");

    // ---- the exact product protocol, issuer-granted authority only -----
    let report = l1_suite::run(&client, &db);
    println!("L1 MANAGED STACK: {} passed, {} failed", report.passed, report.failed);
    assert!(
        report.all_passed(),
        "managed protocol suite: {} passed, {} failed (fail-closed on zero checks)",
        report.passed,
        report.failed,
    );
}
