//! Process execution and environment preconditions.
//!
//! A gate that cannot run is `InfrastructureFailure`, never a pass and never a
//!
//! R8-P0-03 / R8-P1-07: two STRUCTURAL exit codes carry that distinction from a
//! child process back to the controller, so classification never rests on
//! recognising a substring of someone else's error text.
//! silent skip (spec §4). That includes a gate killed by the timeout: a hung
//! gate must not be able to look green.

use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Debug, Clone)]
pub struct Cmd {
    pub program: String,
    pub args: Vec<String>,
    /// Repository-relative working directory.
    pub cwd: Option<String>,
    /// Extra environment for THIS command, applied after the hermetic cargo
    /// defaults so a gate overrides them deliberately, never by accident.
    pub env: Vec<(String, String)>,
    /// Does this command COMPILE the workspace it names?
    ///
    /// The per-workspace disk floor sizes a build. Applying it to a command
    /// that only runs what a previous command in the same gate already built
    /// double-counts: the space the floor protects is by then already spent
    /// and sitting in `target/`, so the check would refuse the run for lacking
    /// room to do work it is not going to do.
    pub builds: bool,
}

impl Cmd {
    pub fn new(program: &str, args: &[&str]) -> Cmd {
        Cmd {
            program: program.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            cwd: None,
            env: Vec::new(),
            // Derived, not declared: a cargo invocation may compile, anything
            // else may not. A new gate therefore gets the protective answer
            // without having to remember the field.
            builds: is_cargo_invocation(program),
        }
    }

    pub fn in_dir(mut self, dir: &str) -> Cmd {
        self.cwd = Some(dir.to_string());
        self
    }

    /// Mark a command as running inside a tree an EARLIER command of the same
    /// gate has already built. Only correct when that build is unconditional
    /// and precedes this command in the same `commands_for` sequence.
    pub fn already_built(mut self) -> Cmd {
        self.builds = false;
        self
    }

    pub fn with_env(mut self, key: &str, value: &str) -> Cmd {
        self.env.push((key.to_string(), value.to_string()));
        self
    }

    pub fn display(&self) -> String {
        let mut s = String::new();
        if let Some(cwd) = &self.cwd {
            s.push_str(&format!("(cd {cwd} && "));
        }
        s.push_str(&self.program);
        for a in &self.args {
            s.push(' ');
            s.push_str(&shell_quote(a));
        }
        if self.cwd.is_some() {
            s.push(')');
        }
        s
    }
}

fn shell_quote(s: &str) -> String {
    if s.is_empty() || s.chars().any(|c| c.is_whitespace() || "\"'`$&|;<>()*?[]{}\\!#~".contains(c)) {
        format!("'{}'", s.replace('\'', r"'\''"))
    } else {
        s.to_string()
    }
}

#[derive(Debug, Clone)]
pub struct CmdResult {
    pub command: String,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub spawn_error: Option<String>,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u128,
}

impl CmdResult {
    pub fn success(&self) -> bool {
        self.exit_code == Some(0) && !self.timed_out && self.spawn_error.is_none()
    }

    /// Last few lines of combined output, for the report `detail` field.
    pub fn tail(&self, lines: usize) -> String {
        let combined = format!("{}\n{}", self.stdout.trim_end(), self.stderr.trim_end());
        let all: Vec<&str> = combined.lines().filter(|l| !l.trim().is_empty()).collect();
        let start = all.len().saturating_sub(lines);
        all[start..].join("\n")
    }
}

/// Run a command under `repo_root`, capturing output, with a hard timeout.
pub fn run(repo_root: &Path, cmd: &Cmd, timeout: Duration) -> CmdResult {
    let started = Instant::now();
    let display = cmd.display();
    let dir: PathBuf = match &cmd.cwd {
        Some(c) => repo_root.join(c),
        None => repo_root.to_path_buf(),
    };

    let mut builder = Command::new(&cmd.program);
    builder.args(&cmd.args).current_dir(&dir);
    // R8-P0-04: the repository's own hash-locked Python environment comes FIRST
    // on PATH for every gate command. `tools/quality/bootstrap.py` installs
    // `.quality/requirements.lock` into `.quality/.venv`, and this is what makes
    // the gates RUN that closure instead of whatever the base image shipped —
    // which is the difference between "the version is pinned" and "these exact
    // bytes ran". Absent venv: the PATH is untouched, and the tool-presence
    // check reports the missing tool as infrastructure, as it always did.
    if let Some(venv_bin) = quality_venv_bin(repo_root) {
        let existing = std::env::var_os("PATH").unwrap_or_default();
        let mut entries = vec![venv_bin.clone()];
        entries.extend(std::env::split_paths(&existing));
        if let Ok(joined) = std::env::join_paths(entries) {
            builder.env("PATH", joined);
        }
        builder.env("VIRTUAL_ENV", venv_bin.parent().unwrap_or(&venv_bin));
    }
    // Cargo invocations run under the SAME hermetic settings the evidence
    // runners use (tools/catalog/common.py CARGO_ENV). This is not a tuning
    // knob: with cargo's defaults, `cargo test --no-run` over the TypeDB fork
    // consumed 20 GB and died on ENOSPC; with these, the same build finishes in
    // 8.9 GB. A gate that cannot be attempted on ordinary hardware is not a
    // gate, and a controller that builds differently from the runners it is
    // meant to certify is measuring a different tree.
    if is_cargo_invocation(&cmd.program) {
        builder
            .env("CARGO_INCREMENTAL", "0")
            .env("CARGO_PROFILE_DEV_DEBUG", "false")
            .env("CARGO_PROFILE_TEST_DEBUG", "false");
    }
    // Applied LAST so a gate can deliberately override the hermetic defaults.
    for (k, v) in &cmd.env {
        builder.env(k, v);
    }
    let child = builder.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn();

    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            return CmdResult {
                command: display,
                exit_code: None,
                timed_out: false,
                spawn_error: Some(e.to_string()),
                stdout: String::new(),
                stderr: String::new(),
                duration_ms: started.elapsed().as_millis(),
            };
        }
    };

    // Drain the pipes on background threads so a chatty gate cannot deadlock on
    // a full pipe buffer while we are polling for the timeout. The buffers are
    // shared rather than returned from `join`, because a killed child can leave
    // grandchildren holding the write end of the pipe: joining would then block
    // for as long as the orphan lives, defeating the timeout it is enforcing.
    let out_buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let err_buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let out_handle = spawn_reader(child.stdout.take(), Arc::clone(&out_buf));
    let err_handle = spawn_reader(child.stderr.take(), Arc::clone(&err_buf));

    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if started.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    timed_out = true;
                    break None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => break None,
        }
    };

    if !timed_out {
        // The child exited on its own, so the pipes are closing; collect
        // everything it wrote.
        let _ = out_handle.join();
        let _ = err_handle.join();
    }
    let stdout = snapshot(&out_buf);
    let stderr = snapshot(&err_buf);

    CmdResult {
        command: display,
        exit_code: status.and_then(|s| s.code()),
        timed_out,
        spawn_error: None,
        stdout,
        stderr,
        duration_ms: started.elapsed().as_millis(),
    }
}

/// The wrapper that gives each test binary its own loopback and port space.
pub const NETNS_EXEC: &str = "tools/dev/netns_exec.py";

/// The host target triple, from rustc itself rather than a guess.
///
/// Needed to name `CARGO_TARGET_<TRIPLE>_RUNNER`, which is how cargo and
/// nextest are told to invoke every test binary through a wrapper.
pub fn host_target_triple() -> Option<String> {
    let out = Command::new("rustc").arg("-vV").output().ok()?;
    String::from_utf8_lossy(&out.stdout).lines().find_map(|l| l.strip_prefix("host: ")).map(|t| t.trim().to_string())
}

/// `CARGO_TARGET_<TRIPLE>_RUNNER`, in cargo's spelling: uppercase, dashes to
/// underscores.
pub fn target_runner_var(triple: &str) -> String {
    format!("CARGO_TARGET_{}_RUNNER", triple.to_uppercase().replace('-', "_"))
}

/// Can this machine give a process its own network namespace?
///
/// Probed by actually doing it, not by inspecting capabilities: the answer
/// depends on the kernel, the container runtime and the user at once, and only
/// the real syscall knows. A gate that needs isolation must report
/// InfrastructureFailure when it is unavailable rather than run without it —
/// running without it restores exactly the port collisions the isolation
/// exists to prevent, and reports them as though they were code defects.
pub fn network_namespaces_available(repo_root: &Path) -> Result<(), String> {
    let wrapper = repo_root.join(NETNS_EXEC);
    if !wrapper.is_file() {
        return Err(format!("{NETNS_EXEC} is missing"));
    }
    let out = Command::new(&wrapper)
        .args(["python3", "-c", "import socket; socket.socket().bind(('127.0.0.1', 11729))"])
        .output()
        .map_err(|e| format!("could not run {NETNS_EXEC}: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
}

/// Does this program invoke cargo, and so need the hermetic build settings?
///
/// Covers both `cargo <subcommand>` and the `cargo-foo` binaries some gates
/// call directly (see the note on cargo-machete in .quality/tools.lock.toml).
pub fn is_cargo_invocation(program: &str) -> bool {
    program == "cargo" || program.starts_with("cargo-")
}

fn spawn_reader<R: std::io::Read + Send + 'static>(
    pipe: Option<R>,
    buf: Arc<Mutex<Vec<u8>>>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let Some(mut pipe) = pipe else { return };
        let mut chunk = [0u8; 8192];
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if let Ok(mut b) = buf.lock() {
                        b.extend_from_slice(&chunk[..n]);
                    }
                }
            }
        }
    })
}

fn snapshot(buf: &Arc<Mutex<Vec<u8>>>) -> String {
    buf.lock().map(|b| String::from_utf8_lossy(&b).to_string()).unwrap_or_default()
}

/// Free space, in gigabytes, on the filesystem holding `path`.
///
/// Uses `df -Pk`, which is POSIX-specified output, rather than adding a libc
/// dependency to the controller.
pub fn free_disk_gb(path: &Path) -> Option<f64> {
    let out = Command::new("df").arg("-Pk").arg(path).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().nth(1)?;
    let available_kb: f64 = line.split_whitespace().nth(3)?.parse().ok()?;
    Some(available_kb / 1024.0 / 1024.0)
}

/// How much build space a gate needs before it may be attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Weight {
    /// Parses sources or shells out to a non-compiling tool.
    Light,
    /// Invokes rustc / a test runner / coverage instrumentation.
    Heavy,
    /// Mutation, feature powersets, long fuzz budgets.
    Campaign,
}

impl Weight {
    pub fn required_free_gb(self, exec: &super::policy::Execution) -> f64 {
        match self {
            Weight::Light => exec.min_free_disk_gb_light,
            Weight::Heavy => exec.min_free_disk_gb_heavy,
            Weight::Campaign => exec.min_free_disk_gb_campaign,
        }
    }

    /// The floor for one command, which knows which workspace it builds.
    ///
    /// The class default is a floor, never a ceiling: a workspace override may
    /// only raise it. Light gates parse sources and are unaffected by how big
    /// the workspace's build tree would be, so they keep the class number.
    pub fn required_free_gb_for(
        self,
        exec: &super::policy::Execution,
        gate_id: &str,
        manifest: Option<&str>,
        builds: bool,
    ) -> f64 {
        let base = self.required_free_gb(exec);
        if self == Weight::Light {
            return base;
        }
        // A command that compiles nothing is sized like a light one. The
        // gate-level class floor still applies before any command runs, so
        // this removes a double-count, not the protection: without it the
        // three-command form of `rust.tests` refuses its own test RUN for
        // lacking the space its own preceding BUILD just consumed.
        if !builds {
            return exec.min_free_disk_gb_light;
        }
        let Some(m) = manifest else { return base };
        // Most specific first. Two gates differ enormously on the SAME
        // workspace: `clippy` type-checks, while `nextest` links every test
        // binary, and on the TypeDB fork that is the difference between a few
        // GB and 23+. A workspace-wide number would refuse the cheap gate to
        // protect the expensive one.
        exec.workspace_free_disk_gb
            .get(&format!("{gate_id}@{m}"))
            .or_else(|| exec.workspace_free_disk_gb.get(m))
            .map_or(base, |o| o.max(base))
    }
}

/// Which workspace a command builds, read from its own arguments so a new gate
/// cannot forget to declare it.
pub fn manifest_of(cmd: &Cmd) -> Option<String> {
    let mut it = cmd.args.iter();
    while let Some(a) = it.next() {
        if a == "--manifest-path" {
            return it.next().cloned();
        }
        if let Some(rest) = a.strip_prefix("--manifest-path=") {
            return Some(rest.to_string());
        }
    }
    // `cargo-machete` and friends take the workspace DIRECTORY, not the
    // manifest; normalise so both forms hit the same policy key.
    cmd.args
        .iter()
        .find(|a| !a.starts_with('-') && (Path::new(a).join("Cargo.toml").is_file()))
        .map(|d| format!("{}/Cargo.toml", d.trim_end_matches('/')))
}

/// The repository-owned Python quality environment's `bin` directory, if the
/// bootstrap has created it (R8-P0-04). Returning `None` is not a failure: the
/// per-gate tool check is what decides whether a missing tool is a refusal.
pub fn quality_venv_bin(repo_root: &Path) -> Option<PathBuf> {
    let bin = repo_root.join(".quality").join(".venv").join(if cfg!(windows) { "Scripts" } else { "bin" });
    bin.is_dir().then_some(bin)
}

/// R8-P0-03 / R8-P1-07: "this host cannot provide a capability I need".
///
/// A gate command exits with this code to say it did NOT run — no assertion
/// was evaluated, no conclusion may be drawn — because AF_UNIX, a readable
/// `/proc`, a fixture, a native library or another host capability is absent.
/// The controller maps it to `InfrastructureFailure`. Chosen to match the
/// controller's own infrastructure exit code, so a nested `cargo xtask quality`
/// propagates the same meaning outward.
pub const EXIT_CAPABILITY_UNAVAILABLE: i32 = 3;

/// `tools/dev/netns_exec.py`'s refusal code: per-test network isolation is
/// unavailable and the runner refused to run the tests without it (R8-P1-04).
/// Distinct from libtest's 0/101 and from nextest's codes, so "isolation
/// unavailable" is never read as "the test failed".
pub const EXIT_NO_ISOLATION: i32 = 79;

/// Is this failure the disk running out, rather than anything about the code?
///
/// ENOSPC part-way through a compile is the least ambiguous infrastructure
/// signal there is, and typing it as a QualityFailure sends the next reader
/// hunting for a defect in code that compiles perfectly well.
pub fn looks_like_enospc(text: &str) -> bool {
    const MARKS: [&str; 3] = ["No space left on device", "os error 28", "ENOSPC"];
    MARKS.iter().any(|m| text.contains(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_display_is_copy_pasteable() {
        let c = Cmd::new("cargo", &["fmt", "--manifest-path", "tools/Cargo.toml", "--all", "--", "--check"]);
        assert_eq!(c.display(), "cargo fmt --manifest-path tools/Cargo.toml --all -- --check");
        let c = Cmd::new("npx", &["--no-install", "tsc", "--noEmit"]).in_dir("control-plane");
        assert_eq!(c.display(), "(cd control-plane && npx --no-install tsc --noEmit)");
    }

    #[test]
    fn arguments_needing_quoting_are_quoted() {
        let c = Cmd::new("sh", &["-c", "echo hi"]);
        assert_eq!(c.display(), "sh -c 'echo hi'");
    }

    #[test]
    fn a_missing_program_is_a_spawn_error_not_a_success() {
        let r = run(Path::new("."), &Cmd::new("definitely-not-a-real-tool-xyzzy", &[]), Duration::from_secs(5));
        assert!(!r.success());
        assert!(r.spawn_error.is_some());
        assert_eq!(r.exit_code, None);
    }

    #[test]
    fn a_nonzero_exit_is_not_a_success() {
        let r = run(Path::new("."), &Cmd::new("sh", &["-c", "exit 7"]), Duration::from_secs(10));
        assert_eq!(r.exit_code, Some(7));
        assert!(!r.success());
    }

    #[test]
    fn a_hung_command_times_out_and_is_not_a_success() {
        let started = Instant::now();
        let r = run(Path::new("."), &Cmd::new("sh", &["-c", "sleep 30"]), Duration::from_millis(300));
        assert!(r.timed_out);
        assert!(!r.success());
        // A killed child can leave a grandchild holding the pipe. The timeout
        // must still return promptly, or a hung gate would hang the controller
        // that is supposed to be enforcing the limit.
        assert!(started.elapsed() < Duration::from_secs(5), "timeout took {:?}", started.elapsed());
    }

    #[test]
    fn output_written_before_a_timeout_is_still_captured() {
        let r = run(
            Path::new("."),
            &Cmd::new("sh", &["-c", "printf 'partial output\n'; sleep 30"]),
            Duration::from_millis(500),
        );
        assert!(r.timed_out);
        assert!(r.stdout.contains("partial output"), "stdout was {:?}", r.stdout);
    }

    #[test]
    fn output_is_captured_and_tailed() {
        let r = run(
            Path::new("."),
            &Cmd::new("sh", &["-c", "printf 'a\\nb\\nc\\n'; printf 'e\\n' >&2"]),
            Duration::from_secs(10),
        );
        assert!(r.success());
        assert_eq!(r.tail(2), "c\ne");
    }

    #[test]
    fn the_runner_variable_is_spelled_the_way_cargo_reads_it() {
        assert_eq!(target_runner_var("x86_64-unknown-linux-gnu"), "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER");
        assert_eq!(target_runner_var("aarch64-apple-darwin"), "CARGO_TARGET_AARCH64_APPLE_DARWIN_RUNNER");
    }

    #[test]
    fn the_host_triple_comes_from_rustc_not_a_guess() {
        let t = host_target_triple().expect("rustc must report its host triple");
        assert!(t.contains('-'), "a target triple has dashes, got {t:?}");
        assert!(!t.contains(' '), "and no spaces, got {t:?}");
    }

    #[test]
    fn a_per_command_env_is_applied_on_top_of_the_hermetic_defaults() {
        let c = Cmd::new("env", &[]).with_env("XTASK_PROBE", "applied");
        let r = run(Path::new("/"), &c, Duration::from_secs(30));
        assert!(r.stdout.contains("XTASK_PROBE=applied"), "per-command env must reach the child");
    }

    /// The property the whole isolation scheme rests on: two processes may hold
    /// the SAME fixed port at the same time. If this ever stops being true, the
    /// server tests go back to fighting over 11729 and the gate lies.
    #[test]
    fn two_isolated_processes_can_hold_the_same_port() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        if network_namespaces_available(root).is_err() {
            // Recorded, not silently skipped: on a machine without namespaces
            // the gate itself reports InfrastructureFailure, which is the
            // behaviour this test's absence must not be mistaken for.
            eprintln!("network namespaces unavailable here; the gate refuses rather than mis-reports");
            return;
        }
        let wrapper = root.join(NETNS_EXEC);
        let hold = "import socket,time; s=socket.socket(); s.bind(('127.0.0.1',11729)); s.listen(1); print('bound'); time.sleep(1.5)";
        let spawn = || {
            Command::new(&wrapper)
                .args(["python3", "-c", hold])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn isolated holder")
        };
        let (a, b) = (spawn(), spawn());
        for (who, child) in [("first", a), ("second", b)] {
            let out = child.wait_with_output().expect("holder finished");
            assert!(
                out.status.success() && String::from_utf8_lossy(&out.stdout).contains("bound"),
                "the {who} isolated process failed to bind 11729: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    #[test]
    fn only_cargo_invocations_get_the_hermetic_build_env() {
        assert!(is_cargo_invocation("cargo"));
        assert!(is_cargo_invocation("cargo-machete"), "gates that call a cargo-* binary directly");
        assert!(!is_cargo_invocation("env"));
        assert!(!is_cargo_invocation("npx"), "the control-plane gates must keep their own environment");
        assert!(!is_cargo_invocation("cargoloader"), "a mere prefix match would be wrong");

        // And the real spawn must not INJECT the setting into a non-cargo
        // program. It may still INHERIT one: this very test runs under `cargo
        // nextest`, which the controller itself spawns hermetically, so the
        // test process already carries CARGO_INCREMENTAL=0 and any child would
        // too. Asserting mere absence confuses inheritance with injection —
        // and the gate caught exactly that mistake here. The invariant is that
        // a non-cargo child sees what the PARENT had, unchanged.
        let inherited = std::env::var("CARGO_INCREMENTAL").ok();
        let plain = run(Path::new("/"), &Cmd::new("env", &[]), Duration::from_secs(30));
        let observed = plain.stdout.lines().find_map(|l| l.strip_prefix("CARGO_INCREMENTAL=").map(str::to_string));
        assert_eq!(
            observed, inherited,
            "a non-cargo program must inherit the parent environment unchanged, never have the \
             hermetic build settings imposed on it"
        );
    }

    #[test]
    fn enospc_is_recognised_in_any_of_its_spellings() {
        assert!(looks_like_enospc(
            "error: failed to write to `target/debug/deps/full.rmeta`: No space left on device (os error 28)"
        ));
        assert!(looks_like_enospc("ENOSPC: no space left"));
        // and a real compile error must NOT be mistaken for one
        assert!(!looks_like_enospc("error[E0308]: mismatched types"));
        assert!(!looks_like_enospc("error: manual `Range::contains` implementation"));
    }

    #[test]
    fn a_workspace_override_may_only_raise_the_class_floor() {
        let mut e = super::super::policy::Execution {
            min_free_disk_gb_light: 0.5,
            min_free_disk_gb_heavy: 12.0,
            min_free_disk_gb_campaign: 40.0,
            fail_on_unclassified_source: true,
            gate_timeout_secs: 3600,
            workspace_free_disk_gb: Default::default(),
        };
        e.workspace_free_disk_gb.insert("fork/typedb/Cargo.toml".into(), 30.0);
        e.workspace_free_disk_gb.insert("tools/Cargo.toml".into(), 1.0);

        let fork = Some("fork/typedb/Cargo.toml");
        // named workspace raises it, for any gate
        assert_eq!(Weight::Heavy.required_free_gb_for(&e, "rust.clippy", fork, true), 30.0);
        // an override BELOW the class floor cannot lower it
        assert_eq!(Weight::Heavy.required_free_gb_for(&e, "rust.clippy", Some("tools/Cargo.toml"), true), 12.0);
        // unnamed workspace keeps the class number
        assert_eq!(Weight::Heavy.required_free_gb_for(&e, "rust.clippy", Some("other/Cargo.toml"), true), 12.0);
        assert_eq!(Weight::Heavy.required_free_gb_for(&e, "rust.clippy", None, true), 12.0);
        // light gates parse sources; workspace size is irrelevant to them
        assert_eq!(Weight::Light.required_free_gb_for(&e, "rust.fmt", fork, true), 0.5);

        // a gate-specific key beats the workspace key, for that gate only
        e.workspace_free_disk_gb.insert("rust.tests@fork/typedb/Cargo.toml".into(), 45.0);
        assert_eq!(Weight::Heavy.required_free_gb_for(&e, "rust.tests", fork, true), 45.0);
        assert_eq!(Weight::Heavy.required_free_gb_for(&e, "rust.clippy", fork, true), 30.0);

        // A command that compiles nothing is not asked a second time for the
        // space its own gate's build already spent.
        assert_eq!(Weight::Heavy.required_free_gb_for(&e, "rust.tests", fork, false), 0.5);
    }

    #[test]
    fn a_command_names_the_workspace_it_builds() {
        let c = Cmd::new("cargo", &["clippy", "--manifest-path", "fork/typedb/Cargo.toml", "--workspace"]);
        assert_eq!(manifest_of(&c).as_deref(), Some("fork/typedb/Cargo.toml"));
        let eq = Cmd::new("cargo", &["clippy", "--manifest-path=tools/Cargo.toml"]);
        assert_eq!(manifest_of(&eq).as_deref(), Some("tools/Cargo.toml"));
        let none = Cmd::new("sh", &["-c", "true"]);
        assert_eq!(manifest_of(&none), None);
    }

    #[test]
    fn free_disk_reports_a_plausible_number() {
        let gb = free_disk_gb(Path::new(".")).expect("df must work on this platform");
        assert!((0.0..1_000_000.0).contains(&gb));
    }
}
