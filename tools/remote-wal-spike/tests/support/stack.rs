//! Shared boot plumbing for the live stack lanes: spawn the PRIVATE ISSUER
//! sidecar (`tests/support/issuer_sidecar.mjs` over the control-plane's
//! real issuer modules) and `wrangler dev` on a named config with per-run
//! vars, into isolated per-run state. Test-only - the protocol under proof
//! lives in `l1_suite`, not here.

use std::{
    io::{BufRead, BufReader},
    net::TcpStream,
    os::unix::process::CommandExt,
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

pub const CONTROL_PLANE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../control-plane");

/// A spawned process-group leader; drop kills the WHOLE group (wrangler
/// spawns workerd grandchildren, npx spawns wrangler).
pub struct ProcGroup(Child);

impl Drop for ProcGroup {
    fn drop(&mut self) {
        let _ = Command::new("kill").args(["-9", "--", &format!("-{}", self.0.id())]).status();
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A fresh per-run secret: 64 lowercase hex chars (32 bytes) - long enough
/// for the issuer bearer minimum and for a managed journal MAC key.
pub fn fresh_secret(label: &str) -> String {
    let nanos =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock after epoch").as_nanos();
    let seed = format!("{label}:{}:{}", std::process::id(), nanos);
    remote_wal_spike::hex(&remote_wal_spike::sha256(seed.as_bytes()))
}

pub struct IssuerSidecar {
    // held for its Drop (kills the sidecar's process group)
    _proc: ProcGroup,
    pub url: String,
    /// managed mode: the PUBLIC runtime inputs (environment name +
    /// verification keyrings) the worker boots from; empty for local-dev.
    pub runtime_vars: Vec<(String, String)>,
}

/// Spawn the issuer sidecar and wait for its one-line JSON announcement.
pub fn spawn_issuer(mode: &str, environment: &str, tenant: &str, bearer: &str) -> IssuerSidecar {
    let sidecar = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/support/issuer_sidecar.mjs");
    let mut child = Command::new("node")
        .args(["--experimental-strip-types", sidecar, CONTROL_PLANE_DIR, mode, environment, tenant, bearer])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .expect("failed to spawn the issuer sidecar - is node installed?");
    let stdout = child.stdout.take().expect("sidecar stdout");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut line = String::new();
        let _ = BufReader::new(stdout).read_line(&mut line);
        let _ = tx.send(line);
    });
    let proc = ProcGroup(child);
    let line = rx.recv_timeout(Duration::from_secs(60)).expect("issuer sidecar announced nothing within 60s");
    let parsed: serde_json::Value =
        serde_json::from_str(line.trim()).unwrap_or_else(|e| panic!("sidecar announcement not JSON ({e}): {line:?}"));
    assert!(parsed["ok"] == serde_json::Value::Bool(true), "issuer sidecar failed to start: {line}");
    let url = parsed["url"].as_str().expect("sidecar url").to_string();
    let runtime_vars = parsed["runtimeVars"]
        .as_object()
        .map(|vars| {
            vars.iter().map(|(key, value)| (key.clone(), value.as_str().unwrap_or_default().to_string())).collect()
        })
        .unwrap_or_default();
    IssuerSidecar { _proc: proc, url, runtime_vars }
}

/// Boot `wrangler dev --local` on `config` with per-run `--var`s into an
/// isolated persistence dir (never the checkout's `.wrangler/state`, which
/// a developer instance may own), and wait for the port to open.
pub fn spawn_wrangler(config: &str, port: u16, vars: &[(String, String)]) -> ProcGroup {
    let persist_to = std::env::temp_dir().join(format!("l1-stack-{}-{}", port, std::process::id()));
    let mut args: Vec<String> = vec![
        "wrangler".into(),
        "dev".into(),
        "--local".into(),
        "-c".into(),
        config.into(),
        "--port".into(),
        port.to_string(),
        "--persist-to".into(),
        persist_to.to_string_lossy().into_owned(),
    ];
    for (key, value) in vars {
        args.push("--var".into());
        args.push(format!("{key}:{value}"));
    }
    let child = Command::new("npx")
        .args(&args)
        .current_dir(CONTROL_PLANE_DIR)
        // non-interactive + no telemetry: a prompt or a metrics round trip
        // would otherwise stall the boot behind a closed stdin
        .env("CI", "1")
        .env("WRANGLER_SEND_METRICS", "false")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .expect("failed to spawn wrangler dev - is the control-plane npm install done?");
    let group = ProcGroup(child);
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "wrangler dev did not open port {port} within 180s");
        thread::sleep(Duration::from_millis(500));
    }
    group
}

/// A per-run unique database id (local DO state persists on disk between
/// runs). Normalized shape: lowercase alphanumerics + hyphens.
pub fn unique_database_id(prefix: &str) -> String {
    let nanos =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock after epoch").as_nanos();
    format!("{prefix}-{}-{nanos}", std::process::id())
}
