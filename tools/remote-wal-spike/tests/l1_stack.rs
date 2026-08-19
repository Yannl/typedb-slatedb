//! The Rust remote-WAL client against the control plane running on real
//! workerd (`wrangler dev --local`) with payloads through the local R2 data
//! path. The test boots the stack itself into an ISOLATED state directory
//! (never the checkout's `.wrangler/state`, which a developer instance may
//! own), then runs the exact same protocol suite as the `l1-e2e` binary —
//! one suite, so this proof cannot fork from the driver.
//!
//! `cargo test -p remote-wal-spike --test l1_stack` is a one-command local
//! verification (requires the control-plane npm install).

use std::{
    net::TcpStream,
    os::unix::process::CommandExt,
    process::{Child, Command, Stdio},
    thread::sleep,
    time::{Duration, Instant},
};

use remote_wal_spike::{
    l1_client::{L1Client, DEV_ISSUER_SECRET},
    l1_suite,
};

fn port() -> u16 {
    // unique per test process: avoids collisions with dev instances and any
    // previously leaked server
    8800 + (std::process::id() % 400) as u16
}

struct Stack(Child);

impl Drop for Stack {
    fn drop(&mut self) {
        // wrangler spawns workerd grandchildren; kill the whole process group
        // (the child was spawned as its own group leader)
        let _ = Command::new("kill").args(["-9", "--", &format!("-{}", self.0.id())]).status();
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn boot_stack() -> Stack {
    let control_plane_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../control-plane");
    let port = port();
    // isolated persistence: a fresh DO/R2 state dir per test process, so the
    // test never touches (or races) a developer's .wrangler/state
    let persist_to = std::env::temp_dir().join(format!("l1-stack-state-{}", std::process::id()));
    let child = Command::new("npx")
        .args([
            "wrangler", "dev", "--local",
            // R4-STACK-01: the DEFAULT wrangler.toml is the managed
            // fail-closed posture (no CONTROLLER_SURFACE - /capability and
            // the dev admin routes answer 404). The local lane must be
            // NAMED to be selected; this is the config the managed-surface
            // stack checks verify as the developer-convenience posture.
            "-c", "wrangler.local-dev.toml",
            "--port", &port.to_string(),
            "--persist-to", &persist_to.to_string_lossy(),
        ])
        .current_dir(control_plane_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .expect("failed to spawn wrangler dev - is the control-plane npm install done?");
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "wrangler dev did not open port {port} within 120s");
        sleep(Duration::from_millis(500));
    }
    Stack(child)
}

#[test]
fn rust_client_full_protocol_against_workerd() {
    let _stack = boot_stack();
    let client = L1Client::new(format!("http://127.0.0.1:{}", port()), "l1-stack-test", DEV_ISSUER_SECRET);
    // health may lag the port opening by a moment
    l1_suite::wait_healthy(&client, Duration::from_secs(60)).expect("stack never became healthy");

    // unique namespace per run: local DO state persists on disk between runs
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let db = format!("rust-e2e-{}-{nanos}", std::process::id());

    let report = l1_suite::run(&client, &db);
    assert!(
        report.all_passed(),
        "protocol suite: {} passed, {} failed (fail-closed on zero checks)",
        report.passed,
        report.failed,
    );
}
