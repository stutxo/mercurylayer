use std::collections::BTreeMap;
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};
use serde::Serialize;

use super::argv::{ArgvCommand, CommandRunner, SystemCommandRunner};
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
    let mut runner = SystemCommandRunner;
    run_with(repo_root, &mut runner)
}

fn run_with(repo_root: &Path, runner: &mut impl CommandRunner) -> Result<DoctorReport> {
    repository::validate_repo_root(repo_root)?;
    let mut commands = BTreeMap::new();
    for name in REQUIRED_COMMANDS {
        commands.insert((*name).to_owned(), find_command(name)?);
    }

    let rustc_version = inspect_required_toolchain(repo_root, &commands["rustup"], runner)?;
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

fn inspect_required_toolchain(
    repo_root: &Path,
    rustup: &Path,
    runner: &mut impl CommandRunner,
) -> Result<String> {
    let command =
        ArgvCommand::new(rustup, repo_root).args(["run", REQUIRED_TOOLCHAIN, "rustc", "--version"]);
    let output = runner
        .run(&command)
        .context("inspect required Rust toolchain")?;
    if !output.success {
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
    use crate::workflow::argv::CommandOutput;

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

    #[test]
    fn required_toolchain_inspection_uses_the_injected_argv_runner() {
        let root = Path::new("/controlled/repository");
        let rustup = Path::new("/controlled/bin/rustup");
        let mut runner = RecordingRunner::returning(CommandOutput::success(
            b"rustc 1.92.0 (ded5c06cf 2025-12-08)\n".to_vec(),
        ));

        assert_eq!(
            inspect_required_toolchain(root, rustup, &mut runner).unwrap(),
            "rustc 1.92.0 (ded5c06cf 2025-12-08)"
        );
        let command = runner.command.unwrap();
        assert_eq!(command.program(), rustup.as_os_str());
        assert_eq!(
            command.args_slice(),
            ["run", "1.92.0", "rustc", "--version"]
        );
        assert_eq!(command.current_dir, root);
        assert!(command.environment.is_empty());
        assert!(!command.environment_is_cleared());
    }

    #[test]
    fn required_toolchain_failure_keeps_the_existing_diagnostic() {
        let mut runner = RecordingRunner::returning(CommandOutput::failure(
            1,
            b"toolchain '1.92.0' is not installed\n".to_vec(),
        ));
        let error = inspect_required_toolchain(
            Path::new("/controlled/repository"),
            Path::new("/controlled/bin/rustup"),
            &mut runner,
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "Rust toolchain 1.92.0 is unavailable: toolchain '1.92.0' is not installed"
        );
    }

    struct RecordingRunner {
        output: Option<CommandOutput>,
        command: Option<ArgvCommand>,
    }

    impl RecordingRunner {
        fn returning(output: CommandOutput) -> Self {
            Self {
                output: Some(output),
                command: None,
            }
        }
    }

    impl CommandRunner for RecordingRunner {
        fn run(&mut self, command: &ArgvCommand) -> Result<CommandOutput> {
            assert!(self.command.replace(command.clone()).is_none());
            Ok(self.output.take().unwrap())
        }
    }
}
