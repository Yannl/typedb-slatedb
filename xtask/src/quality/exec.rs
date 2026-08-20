//! Process execution and environment preconditions.
//!
//! A gate that cannot run is `InfrastructureFailure`, never a pass and never a
//! silent skip (spec §4). That includes a gate killed by the timeout: a hung
//! gate must not be able to look green.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Cmd {
    pub program: String,
    pub args: Vec<String>,
    /// Repository-relative working directory.
    pub cwd: Option<String>,
}

impl Cmd {
    pub fn new(program: &str, args: &[&str]) -> Cmd {
        Cmd { program: program.to_string(), args: args.iter().map(|s| s.to_string()).collect(), cwd: None }
    }

    pub fn in_dir(mut self, dir: &str) -> Cmd {
        self.cwd = Some(dir.to_string());
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

    let child = Command::new(&cmd.program)
        .args(&cmd.args)
        .current_dir(&dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();

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
    fn free_disk_reports_a_plausible_number() {
        let gb = free_disk_gb(Path::new(".")).expect("df must work on this platform");
        assert!((0.0..1_000_000.0).contains(&gb));
    }
}
