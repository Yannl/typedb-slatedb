//! `cargo xtask native-toolchain` — resolve the `NATIVE` class-U node.
//!
//! Brief §1.3 lists the native toolchain as an unresolved input blocking G0: the
//! compiler, linker, archiver, CMake, protoc, pkg-config, libc and TLS roots that the build
//! actually invokes. Until they are pinned, "U0 and U1 were built identically" is a claim
//! about Rust only — `librocksdb-sys` compiles a large C++ tree with whatever `cc` is on
//! PATH, and a different libstdc++ can change behaviour without touching a line of Rust.
//!
//! This records what *this* machine used, with content digests where a digest is meaningful
//! and reported versions where the artifact is a system library resolved at link time. It
//! does not invent digests for things it cannot hash.

use std::{collections::BTreeMap, path::Path, process::Command};

use anyhow::{Context, Result};
use serde::Serialize;

#[derive(Debug, Serialize)]
struct Tool {
    role: String,
    /// Resolved absolute path, or `null` when the tool was not found.
    path: Option<String>,
    /// SHA-256 of the binary itself. Absent when the path could not be read.
    sha256: Option<String>,
    /// First line of the tool's own `--version` output.
    version: Option<String>,
}

#[derive(Debug, Serialize)]
struct NativeToolchain {
    target_triple: String,
    tools: BTreeMap<String, Tool>,
    /// Shared libraries the built server actually links, from `ldd`.
    linked_libraries: Vec<LinkedLibrary>,
    /// TLS trust anchors, digested as a set.
    tls_roots: Option<TlsRoots>,
    /// One digest over everything above.
    native_toolchain_digest: String,
    /// Inputs this command could not resolve, named rather than omitted.
    unresolved: Vec<String>,
}

#[derive(Debug, Serialize)]
struct LinkedLibrary {
    soname: String,
    resolved_path: Option<String>,
    sha256: Option<String>,
}

#[derive(Debug, Serialize)]
struct TlsRoots {
    path: String,
    sha256: String,
    certificate_count: usize,
}

/// PATH as the build sees it — `protoc` is pinned under /opt and is not on the login PATH,
/// so looking it up without this recorded it as missing from a build that uses it.
fn build_path() -> String {
    let base = std::env::var("PATH").unwrap_or_default();
    format!("/opt/protoc/bin:{base}")
}

fn which(bin: &str) -> Option<String> {
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin}"))
        .env("PATH", build_path())
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!s.is_empty()).then_some(s)
}

fn first_line(bin: &str, arg: &str) -> Option<String> {
    first_line_with(bin, &[arg], &[])
}

/// Run `bin args` with `env` overrides and take the first output line.
fn first_line_with(bin: &str, args: &[&str], env: &[(&str, &str)]) -> Option<String> {
    let mut cmd = Command::new(bin);
    cmd.args(args).env("PATH", build_path());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().ok()?;
    let text = if out.stdout.is_empty() { out.stderr } else { out.stdout };
    String::from_utf8_lossy(&text).lines().next().map(|l| l.trim().to_string())
}

fn tool(role: &str, bin: &str, version_arg: &str) -> Tool {
    tool_in(role, bin, version_arg, &[])
}

/// Record a tool as the build invokes it.
///
/// The toolchain overrides are load-bearing. `rustc --version` on a bare PATH reports the
/// *default* toolchain — 1.94.1 here — while the corpus is built on the 1.93.0 parity lane
/// and formatted by nightly-2026-04-15. Recording the defaults would attest to a toolchain
/// no part of this programme uses.
fn tool_in(role: &str, bin: &str, version_arg: &str, env: &[(&str, &str)]) -> Tool {
    let path = which(bin);
    Tool {
        role: role.to_string(),
        sha256: path.as_deref().and_then(|p| source_lock::hash_file(Path::new(p)).ok()),
        version: first_line_with(bin, &[version_arg], env),
        path,
    }
}

/// Shared objects the built server binary links, resolved and digested.
fn linked_libraries(server_bin: &Path) -> Vec<LinkedLibrary> {
    let Ok(out) = Command::new("ldd").arg(server_bin).output() else { return Vec::new() };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            // `libstdc++.so.6 => /lib/x86_64-linux-gnu/libstdc++.so.6 (0x…)`
            let (soname, rest) = line.split_once(" => ")?;
            let resolved = rest.split(" (").next().map(str::trim).filter(|p| !p.is_empty());
            Some(LinkedLibrary {
                soname: soname.trim().to_string(),
                sha256: resolved.and_then(|p| source_lock::hash_file(Path::new(p)).ok()),
                resolved_path: resolved.map(str::to_string),
            })
        })
        .collect()
}

fn tls_roots() -> Option<TlsRoots> {
    // The bundle this environment presents to outbound TLS, including the agent proxy's CA.
    for candidate in ["/etc/ssl/certs/ca-certificates.crt", "/root/.ccr/ca-bundle.crt"] {
        let path = Path::new(candidate);
        if !path.is_file() {
            continue;
        }
        let text = std::fs::read_to_string(path).unwrap_or_default();
        return Some(TlsRoots {
            path: candidate.to_string(),
            sha256: source_lock::hash_file(path).ok()?,
            certificate_count: text.matches("BEGIN CERTIFICATE").count(),
        });
    }
    None
}

pub fn run(repo_root: &Path) -> Result<()> {
    // Every native tool the build actually invokes. `cc`/`c++` matter most: librocksdb-sys
    // compiles RocksDB's C++ tree, so the C++ compiler and its runtime are as much a part of
    // the build's identity as rustc is.
    let mut tools = BTreeMap::new();

    // The three Rust tools are recorded under the exact toolchain the lane pins, not the
    // machine default.
    let lane = [("RUSTUP_TOOLCHAIN", conformance_runner::PARITY_BUILD_ENV[0].1)];
    tools.insert(
        "rustc".to_string(),
        tool_in("Rust compiler (parity lane)", "rustc", "--version", &lane),
    );
    tools.insert(
        "cargo".to_string(),
        tool_in("Rust build driver (parity lane)", "cargo", "--version", &lane),
    );
    tools.insert(
        "rustfmt_pinned".to_string(),
        tool_in(
            "rustfmt pinned by MODULE.bazel L37",
            "rustfmt",
            "--version",
            &[("RUSTUP_TOOLCHAIN", conformance_runner::staticcheck::PINNED_RUSTFMT_TOOLCHAIN)],
        ),
    );

    for (key, role, bin, arg) in [
        ("cc", "C compiler", "cc", "--version"),
        ("cxx", "C++ compiler (RocksDB)", "c++", "--version"),
        ("ld", "linker", "ld", "--version"),
        ("ar", "archiver", "ar", "--version"),
        ("cmake", "CMake", "cmake", "--version"),
        ("make", "make", "make", "--version"),
        ("protoc", "protobuf compiler", "protoc", "--version"),
        ("pkg_config", "pkg-config", "pkg-config", "--version"),
        ("git", "source resolution", "git", "--version"),
    ] {
        tools.insert(key.to_string(), tool(role, bin, arg));
    }

    let server_bin = repo_root.join("build/u0/debug/typedb_server_bin");
    let linked = if server_bin.is_file() { linked_libraries(&server_bin) } else { Vec::new() };

    let mut unresolved = Vec::new();
    if linked.is_empty() {
        unresolved.push(
            "linked shared libraries: build/u0/debug/typedb_server_bin is absent, so the \
             libc/libstdc++ the server actually loads was not observed"
                .to_string(),
        );
    }
    for (key, t) in &tools {
        if t.path.is_none() {
            unresolved.push(format!("{key}: not present on PATH"));
        }
    }
    let roots = tls_roots();
    if roots.is_none() {
        unresolved.push("TLS trust anchors: no CA bundle found at a known path".to_string());
    }

    // One digest over the ordered record, so a toolchain change is a single visible delta.
    let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
    for (key, t) in &tools {
        sha2::Digest::update(&mut hasher, key.as_bytes());
        sha2::Digest::update(&mut hasher, b"\0");
        sha2::Digest::update(&mut hasher, t.sha256.as_deref().unwrap_or("-").as_bytes());
        sha2::Digest::update(&mut hasher, b"\0");
        sha2::Digest::update(&mut hasher, t.version.as_deref().unwrap_or("-").as_bytes());
        sha2::Digest::update(&mut hasher, b"\n");
    }
    for l in &linked {
        sha2::Digest::update(&mut hasher, l.soname.as_bytes());
        sha2::Digest::update(&mut hasher, b"\0");
        sha2::Digest::update(&mut hasher, l.sha256.as_deref().unwrap_or("-").as_bytes());
        sha2::Digest::update(&mut hasher, b"\n");
    }
    if let Some(r) = &roots {
        sha2::Digest::update(&mut hasher, r.sha256.as_bytes());
    }

    let record = NativeToolchain {
        target_triple: "x86_64-unknown-linux-gnu".into(),
        tools,
        linked_libraries: linked,
        tls_roots: roots,
        native_toolchain_digest: hex::encode(sha2::Digest::finalize(hasher)),
        unresolved,
    };

    let out_dir = repo_root.join("docs/evidence/phase-a");
    std::fs::create_dir_all(&out_dir)?;
    let out = out_dir.join("native-toolchain.json");
    std::fs::write(&out, serde_json::to_string_pretty(&record)? + "\n")
        .with_context(|| format!("writing {}", out.display()))?;

    println!("native toolchain digest: {}", record.native_toolchain_digest);
    for (key, t) in &record.tools {
        println!(
            "  {key:<16} {}",
            t.version.as_deref().unwrap_or("<not found>")
        );
    }
    println!("  linked libraries : {}", record.linked_libraries.len());
    if let Some(r) = &record.tls_roots {
        println!("  TLS roots        : {} certificates ({})", r.certificate_count, r.path);
    }
    println!("  unresolved       : {}", record.unresolved.len());
    for u in &record.unresolved {
        println!("     - {u}");
    }
    println!("written: {}", out.display());
    Ok(())
}
