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
        // workerd binds a DEBUG INSPECTOR port as well as the HTTP one, and it
        // defaults to a FIXED 9229. `--port` does not move it. Two stack tests
        // running concurrently therefore each got their own HTTP port and then
        // fought over 9229, and the loser died with
        //   Fatal uncaught kj::Exception: ::bind(...): Address already in use;
        //   toString() = 127.0.0.1:9229
        // which surfaced only as "did not open port" because this spawn threw
        // wrangler's output away. Derived from the HTTP port, which is already
        // unique per test binary, so the inspector is unique too.
        "--inspector-port".into(),
        (port + 1000).to_string(),
    ];
    for (key, value) in vars {
        args.push("--var".into());
        args.push(format!("{key}:{value}"));
    }
    let log_path = std::env::temp_dir().join(format!("l1-stack-wrangler-{port}-{}.log", std::process::id()));
    let _ = std::fs::remove_file(&log_path);
    let child = Command::new("npx")
        .args(&args)
        .current_dir(CONTROL_PLANE_DIR)
        // non-interactive + no telemetry: a prompt or a metrics round trip
        // would otherwise stall the boot behind a closed stdin
        .env("CI", "1")
        .env("WRANGLER_SEND_METRICS", "false")
        // Captured to a file, never discarded: when this boot fails, the
        // reason is ONLY in wrangler's own output, and throwing it away turns
        // a diagnosable failure into a bare "did not open port" with nothing
        // to act on.
        .stdout(Stdio::from(log_file(&log_path)))
        .stderr(Stdio::from(log_file(&log_path)))
        .process_group(0)
        .spawn()
        .expect("failed to spawn wrangler dev - is the control-plane npm install done?");
    let group = ProcGroup(child);
    let deadline = Instant::now() + Duration::from_secs(boot_timeout_secs());
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        if Instant::now() >= deadline {
            let log = std::fs::read_to_string(&log_path).unwrap_or_default();
            let tail: Vec<&str> = log.lines().filter(|l| !l.trim().is_empty()).collect();
            let tail = tail[tail.len().saturating_sub(30)..].join("\n");
            panic!(
                "wrangler dev did not open port {port} within {}s.\n\
                 Read the output below before assuming a timeout: a bind conflict on an\n\
                 ancillary port (the inspector) presents identically. A genuinely slow boot\n\
                 can be given more room with L1_STACK_BOOT_TIMEOUT_SECS.\n\
                 --- wrangler output ({}) ---\n{tail}",
                boot_timeout_secs(),
                log_path.display(),
            );
        }
        thread::sleep(Duration::from_millis(500));
    }
    group
}

/// How long the worker gets to open its port.
///
/// The default is unchanged at 180s, and this is NOT the fix for the failure
/// that motivated capturing the output — that was a hard bind conflict on the
/// inspector port, which no timeout would have cured. It exists so a genuinely
/// slow or loaded machine can say so, without weakening the assertion: the
/// port must still open.
fn boot_timeout_secs() -> u64 {
    std::env::var("L1_STACK_BOOT_TIMEOUT_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(180)
}

fn log_file(path: &std::path::Path) -> std::fs::File {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("cannot open a log file for wrangler output")
}

/// A per-run unique database id (local DO state persists on disk between
/// runs). Normalized shape: lowercase alphanumerics + hyphens.
pub fn unique_database_id(prefix: &str) -> String {
    let nanos =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock after epoch").as_nanos();
    format!("{prefix}-{}-{nanos}", std::process::id())
}
