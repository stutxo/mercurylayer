use std::collections::BTreeMap;
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, ensure, Context, Result};
use serde::Serialize;

use super::repository;

const REQUIRED_TOOLCHAIN: &str = "1.92.0";
const REQUIRED_COMMANDS: &[&str] = &["cargo", "docker", "git", "rustc", "rustup"];

#[derive(Debug, Serialize)]
pub struct DoctorReport {
    status: &'static str,
    repo_root: PathBuf,
    rust_toolchain: RustToolchainReport,
    commands: BTreeMap<String, PathBuf>,
}

#[derive(Debug, Serialize)]
struct RustToolchainReport {
    required: &'static str,
    rustc_version: String,
}

pub fn run(repo_root: &Path) -> Result<DoctorReport> {
    repository::validate_repo_root(repo_root)?;
    let mut commands = BTreeMap::new();
    for name in REQUIRED_COMMANDS {
        commands.insert((*name).to_owned(), find_command(name)?);
    }

    let rustc_version = inspect_required_toolchain(&commands["rustup"])?;
    Ok(DoctorReport {
        status: "ok",
        repo_root: repo_root.to_path_buf(),
        rust_toolchain: RustToolchainReport {
            required: REQUIRED_TOOLCHAIN,
            rustc_version,
        },
        commands,
    })
}

fn find_command(name: &str) -> Result<PathBuf> {
    let path = env::var_os("PATH").context("PATH is not set")?;
    find_command_in(name, &path)
}

fn find_command_in(name: &str, path: &OsStr) -> Result<PathBuf> {
    ensure!(
        !name.contains(std::path::MAIN_SEPARATOR),
        "command name must not contain a path separator"
    );
    for directory in env::split_paths(path) {
        if directory.as_os_str().is_empty() {
            continue;
        }
        let candidate = directory.join(name);
        let Ok(metadata) = fs::metadata(&candidate) else {
            continue;
        };
        if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 {
            return Ok(candidate);
        }
    }
    bail!("required command {name:?} is not available on PATH")
}

fn inspect_required_toolchain(rustup: &Path) -> Result<String> {
    let output = Command::new(rustup)
        .args(["run", REQUIRED_TOOLCHAIN, "rustc", "--version"])
        .output()
        .context("inspect required Rust toolchain")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "Rust toolchain {REQUIRED_TOOLCHAIN} is unavailable: {}",
            stderr.trim()
        );
    }
    let version = String::from_utf8(output.stdout)
        .context("rustc --version returned non-UTF-8 output")?
        .trim()
        .to_owned();
    validate_rustc_version(&version)?;
    Ok(version)
}

fn validate_rustc_version(version: &str) -> Result<()> {
    let mut fields = version.split_ascii_whitespace();
    ensure!(
        fields.next() == Some("rustc"),
        "unexpected rustc version output"
    );
    ensure!(
        fields.next() == Some(REQUIRED_TOOLCHAIN),
        "required rustc {REQUIRED_TOOLCHAIN}, observed {version:?}"
    );
    ensure!(fields.next().is_some(), "incomplete rustc version output");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::OpenOptionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn rustc_version_requires_the_exact_toolchain() {
        validate_rustc_version("rustc 1.92.0 (ded5c06cf 2025-12-08)").unwrap();
        assert!(validate_rustc_version("rustc 1.91.1 (other)").is_err());
        assert!(validate_rustc_version("cargo 1.92.0 (other)").is_err());
        assert!(validate_rustc_version("rustc 1.92.0").is_err());
    }

    #[test]
    fn command_search_requires_an_executable_regular_file() {
        let directory = std::env::temp_dir().join(format!(
            "bip448-doctor-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let command = directory.join("controlled-command");
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&command)
            .unwrap();
        assert!(find_command_in("controlled-command", directory.as_os_str()).is_err());
        fs::set_permissions(&command, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            find_command_in("controlled-command", directory.as_os_str()).unwrap(),
            command
        );
        fs::remove_file(command).unwrap();
        fs::remove_dir(directory).unwrap();
    }
}
