//! `l1-e2e`: drive the L1 protocol suite against a running control plane
//! plus a running PRIVATE ISSUER (R5-SEC-02).
//!
//! The client holds no signing material, so this driver needs BOTH
//! endpoints: the managed worker surface it spends authority on, and the
//! private issuer it obtains authority from
//! (`control-plane/scripts/issuer.mjs` startIssuerServer, or the sidecar
//! `tests/support/issuer_sidecar.mjs`).
//!
//! Usage: cargo run --bin l1-e2e -- [baseUrl] [issuerUrl]
//!   baseUrl    defaults to http://127.0.0.1:8788 (a `wrangler dev`)
//!   issuerUrl  defaults to $L1_ISSUER_URL, else http://127.0.0.1:8799
//!   $L1_ISSUER_BEARER  the issuer's bearer credential (REQUIRED: the
//!                      issuer refuses anonymous callers, and there is no
//!                      default credential to fall back to)
//!   $L1_TENANT         tenant to provision under (default tenant-a)
//!
//! Exit code 0 only when every check passed AND at least one check ran
//! (fail-closed: an empty run is a failure).

use std::{process::ExitCode, time::Duration};

use remote_wal_spike::{
    l1_client::{L1Client, L1Config},
    l1_suite,
};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let base = args.next().unwrap_or_else(|| "http://127.0.0.1:8788".to_string());
    let issuer_base = args
        .next()
        .or_else(|| std::env::var("L1_ISSUER_URL").ok())
        .unwrap_or_else(|| "http://127.0.0.1:8799".to_string());
    let Ok(issuer_bearer) = std::env::var("L1_ISSUER_BEARER") else {
        eprintln!(
            "FAIL  L1_ISSUER_BEARER is required: the client bears issuer-granted tokens and \
                   the private issuer refuses anonymous issuance (no default credential exists)"
        );
        return ExitCode::FAILURE;
    };
    let tenant_id = std::env::var("L1_TENANT").unwrap_or_else(|_| "tenant-a".to_string());

    let client = L1Client::new(L1Config {
        base: base.clone(),
        issuer_base: issuer_base.clone(),
        issuer_bearer,
        principal: "l1-e2e-driver".to_string(),
        tenant_id,
    });

    if let Err(error) = l1_suite::wait_healthy(&client, Duration::from_secs(30)) {
        eprintln!("FAIL  {base} is not serving the control plane: {error}");
        return ExitCode::FAILURE;
    }

    // unique namespace per run: wrangler dev persists local DO state on disk
    let nanos =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or_default();
    let database_id = format!("l1-e2e-{}-{nanos}", std::process::id());
    println!("L1 client e2e against {base} (issuer {issuer_base}, database {database_id})");

    let report = l1_suite::run(&client, &database_id);
    println!(
        "\nL1 CLIENT E2E: {} passed, {} failed{}",
        report.passed,
        report.failed,
        if report.all_passed() { " — ALL PASS" } else { " — FAILURE" }
    );
    if report.all_passed() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
