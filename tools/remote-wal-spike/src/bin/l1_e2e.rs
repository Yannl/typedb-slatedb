//! `l1-e2e`: drive the L1 protocol suite against a running control plane.
//!
//! Usage: cargo run --bin l1-e2e -- [baseUrl]
//!   baseUrl defaults to http://127.0.0.1:8788 (a `wrangler dev` instance);
//!   L1_ISSUER_SECRET overrides the local-dev issuer credential.
//!
//! Exit code 0 only when every check passed AND at least one check ran
//! (fail-closed: an empty run is a failure).

use std::process::ExitCode;
use std::time::Duration;

use remote_wal_spike::l1_client::{L1Client, DEV_ISSUER_SECRET};
use remote_wal_spike::l1_suite;

fn main() -> ExitCode {
    let base = std::env::args().nth(1).unwrap_or_else(|| "http://127.0.0.1:8788".to_string());
    let issuer_secret =
        std::env::var("L1_ISSUER_SECRET").unwrap_or_else(|_| DEV_ISSUER_SECRET.to_string());
    let client = L1Client::new(&base, "l1-e2e-driver", issuer_secret);

    if let Err(error) = l1_suite::wait_healthy(&client, Duration::from_secs(30)) {
        eprintln!("FAIL  {base} is not serving the control plane: {error}");
        return ExitCode::FAILURE;
    }

    // unique namespace per run: wrangler dev persists local DO state on disk
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let database_id = format!("l1-e2e-{}-{nanos}", std::process::id());
    println!("L1 client e2e against {base} (database {database_id})");

    let report = l1_suite::run(&client, &database_id);
    println!(
        "\nL1 CLIENT E2E: {} passed, {} failed{}",
        report.passed,
        report.failed,
        if report.all_passed() { " — ALL PASS" } else { " — FAILURE" }
    );
    if report.all_passed() { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}
