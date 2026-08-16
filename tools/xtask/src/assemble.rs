//! `cargo xtask assemble` — build the distribution archive the assembly tests need.
//!
//! Upstream produces this with Bazel (`//:assemble-typedb-all` -> `pkg_tar`), which this lane
//! cannot run. The 46 packaging tests were therefore failing on a missing
//! `$TYPEDB_ASSEMBLY_ARCHIVE`, and that was first reported as blocked on two unobtainable
//! artifacts. It was not: TypeDB Console and Loader are one Cargo workspace at
//! `console-3.12.0`, so the archive can be assembled from source.
//!
//! The layout is read out of TB's root `BUILD` rather than guessed:
//!
//! * `package-layout-server-files` L85-93 — `typedb_server_bin` -> `server/typedb_server_bin`,
//!   `typedb_admin_bin` -> `admin/typedb_admin_bin`, `config.yml` -> `server/config.yml`,
//!   plus `binary/typedb` (the launcher) and `LICENSE` at the root.
//! * `console-repackaged` L155-165 — the console binary under `console/`, named
//!   `typedb_console_bin` (the launcher execs exactly that path, `binary/typedb` L51-52).
//! * `assemble-all-linux-x86_64-targz` L211-219 — `package_dir =
//!   "typedb-all-linux-x86_64-{version}"`, `out = "typedb-all-linux-x86_64.tar.gz"`.
//!
//! The `{version}` is `0.0.0`: `assembly.rs` L42 derives the directory name by replacing
//! `.tar.gz` with `-0.0.0`, so the test itself fixes it regardless of the VERSION file.
//!
//! This is a **semantic** reproduction, not a byte-identical one. Bazel's tar differs in
//! ordering, timestamps and permissions bits, so anything depending on the archive's own
//! digest must not treat this as equivalent.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// Directory version segment, fixed by `tests/assembly/assembly.rs` L42.
const PACKAGE_VERSION: &str = "0.0.0";
const ARCHIVE_NAME: &str = "typedb-all-linux-x86_64.tar.gz";

struct Entry {
    /// Path inside the archive's top-level directory.
    dest: &'static str,
    /// Absolute source path.
    src: PathBuf,
    executable: bool,
}

pub fn run(repo_root: &Path, typedb_root: Option<&Path>, out_dir: Option<&Path>) -> Result<()> {
    let typedb_root = match typedb_root {
        Some(p) if p.is_absolute() => p.to_path_buf(),
        Some(p) => repo_root.join(p),
        None => repo_root.join("sources/typedb"),
    };
    let console_root = repo_root.join("sources/typedb-console");
    let u0 = repo_root.join("build/u0/debug");
    let console_build = repo_root.join("build/console/release");

    // The archive lands in the build tree, never in a source checkout. Dropping it beside the
    // sources is what made `typedb-logs/` and friends pollute the source graph digest before.
    let out_dir = match out_dir {
        Some(p) if p.is_absolute() => p.to_path_buf(),
        Some(p) => repo_root.join(p),
        None => repo_root.join("build/assembly"),
    };

    let entries = vec![
        Entry { dest: "typedb", src: typedb_root.join("binary/typedb"), executable: true },
        Entry { dest: "LICENSE", src: typedb_root.join("LICENSE"), executable: false },
        Entry {
            dest: "server/typedb_server_bin",
            src: u0.join("typedb_server_bin"),
            executable: true,
        },
        Entry {
            dest: "server/config.yml",
            src: typedb_root.join("server/config.yml"),
            executable: false,
        },
        Entry {
            dest: "admin/typedb_admin_bin",
            src: u0.join("typedb_admin_bin"),
            executable: true,
        },
        Entry {
            dest: "console/typedb_console_bin",
            src: console_build.join("typedb-console"),
            executable: true,
        },
    ];

    // Name every missing input at once. Reporting them one per run turns a five-minute fix
    // into five runs.
    let missing: Vec<String> = entries
        .iter()
        .filter(|e| !e.src.is_file())
        .map(|e| format!("{} (for {})", e.src.display(), e.dest))
        .collect();
    if !missing.is_empty() {
        bail!(
            "cannot assemble: {} input(s) missing:\n  - {}\n\nBuild them first:\n  \
             server/admin: cargo xtask test-upstream --profile U0  (or `cargo test --no-run` \
             in {})\n  console:      cargo build --release -p typedb-console --locked  (in {})",
            missing.len(),
            missing.join("\n  - "),
            typedb_root.display(),
            console_root.display()
        );
    }

    let pkg_dir_name = format!("typedb-all-linux-x86_64-{PACKAGE_VERSION}");
    let staging = out_dir.join(&pkg_dir_name);
    if staging.exists() {
        std::fs::remove_dir_all(&staging)?;
    }
    std::fs::create_dir_all(&staging)?;

    for entry in &entries {
        let dest = staging.join(entry.dest);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(&entry.src, &dest)
            .with_context(|| format!("copying {} -> {}", entry.src.display(), dest.display()))?;
        if entry.executable {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))?;
        }
    }

    let archive = out_dir.join(ARCHIVE_NAME);
    let status = std::process::Command::new("tar")
        .args(["-czf", ARCHIVE_NAME, &pkg_dir_name])
        .current_dir(&out_dir)
        .status()
        .context("running tar")?;
    if !status.success() {
        bail!("tar failed ({status})");
    }

    let digest = source_lock::hash_file(&archive)?;
    let bytes = std::fs::metadata(&archive)?.len();

    println!("assembled {}", archive.display());
    println!("  contents  : {} files under {pkg_dir_name}/", entries.len());
    println!("  size      : {bytes} bytes");
    println!("  sha256    : {digest}");
    println!();
    println!("This is a semantic reproduction of Bazel's //:assemble-typedb-all, not a");
    println!("byte-identical one: tar ordering, timestamps and permission bits differ.");
    println!();
    println!("Run the packaging tests with:");
    println!("  TYPEDB_ASSEMBLY_ARCHIVE={} cargo test -p typedb_server_bin --test test_assembly", archive.display());
    Ok(())
}
