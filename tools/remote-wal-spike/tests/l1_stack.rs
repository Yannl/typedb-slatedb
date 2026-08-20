//! LOCAL-DEV LANE: the Rust remote-WAL client against the control plane
//! running on real workerd (`wrangler dev --local -c
//! wrangler.local-dev.toml`) with payloads through the local R2 data path.
//!
//! The developer-convenience posture is NON-PARITY by construction (it
//! additionally opens `/capability` and the dev admin routes), but the
//! client no longer speaks any of those: it bears tokens from the same
//! PRIVATE ISSUER topology the managed lane uses, here signing with the
//! committed DEV-INSECURE keypairs the local-dev key profile pins
//! (`tests/support/issuer_sidecar.mjs` in `local-dev` mode). So this lane
//! proves the exact managed-surface protocol ALSO runs green on the dev
//! posture — one suite, two postures, no forked proof.
//!
//! `cargo test -p remote-wal-spike --test l1_stack` is a one-command local
//! verification (requires the control-plane npm install).

use std::time::Duration;

use remote_wal_spike::{
    l1_client::{L1Client, L1Config},
    l1_suite,
};

#[path = "support/stack.rs"]
// shared across both live lanes; each lane uses the part it needs
#[allow(dead_code)]
mod stack;

/// Unique per test process: avoids collisions with dev instances, with the
/// managed lane (different band), and with any previously leaked server.
fn port() -> u16 {
    8800 + (std::process::id() % 200) as u16
}

/// The local-dev key profile pins the environment name `local` and the
/// committed dev keypairs; the sidecar signs with exactly those.
const LOCAL_DEV_ENVIRONMENT: &str = "local";
const TENANT: &str = "tenant-a";

#[test]
fn rust_client_full_protocol_against_workerd_local_dev() {
    let bearer = stack::fresh_secret("l1-stack-issuer-bearer");
    let issuer = stack::spawn_issuer("local-dev", LOCAL_DEV_ENVIRONMENT, TENANT, &bearer);
    // the local-dev posture resolves its own key material from the profile:
    // the only per-run var is the port, so no --var is needed here
    let _worker = stack::spawn_wrangler("wrangler.local-dev.toml", port(), &[]);

    let client = L1Client::new(L1Config {
        base: format!("http://127.0.0.1:{}", port()),
        issuer_base: issuer.url.clone(),
        issuer_bearer: bearer,
        principal: "l1-stack-test".to_string(),
        tenant_id: TENANT.to_string(),
    });
    // health may lag the port opening by a moment
    l1_suite::wait_healthy(&client, Duration::from_secs(60)).expect("stack never became healthy");

    // unique namespace per run: local DO state persists on disk between runs
    let db = stack::unique_database_id("rust-dev");
    let report = l1_suite::run(&client, &db);
    println!("L1 LOCAL-DEV STACK: {} passed, {} failed", report.passed, report.failed);

    // Posture asymmetry, proven from Rust with the SAME client method: the
    // dev-only contiguity audit is SERVED here and answers 404 on the
    // managed surface (l1_managed_stack). The suite deliberately never
    // touches it, which is why the suite runs identically on both lanes.
    // The suite left the client bound to the successor actor in generation
    // 2, which holds exactly its own first record.
    let audit =
        client.audit(&db, 2).expect("the developer-convenience posture must still serve the dev-only audit route");
    println!("PASS  dev-only audit route is SERVED on the local-dev posture ({audit:?})");
    assert!(audit.ok && audit.contiguous && audit.count == 1, "dev-only audit route answered {audit:?}",);

    assert!(
        report.all_passed(),
        "protocol suite: {} passed, {} failed (fail-closed on zero checks)",
        report.passed,
        report.failed,
    );
}
