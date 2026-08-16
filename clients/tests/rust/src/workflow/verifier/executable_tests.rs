use std::ffi::OsStr;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use uuid::Uuid;

use super::*;
use crate::workflow::argv::{ArgvCommand, CommandRunner, SystemCommandRunner};

const LIVE_TEST: &str =
    "workflow::verifier::executable::tests::proc_self_reexec_survives_launch_path_replacement";
const INITIAL_ROLE: &str = "initial-role";
const REEXEC_ROLE: &str = "reexec-role";
const INITIAL_READY: &str = "initial-ready";
const REPLACEMENT_READY: &str = "replacement-ready";
const INITIAL_IDENTITY: &str = "initial-identity.json";
const REEXEC_IDENTITY: &str = "reexec-identity.json";

struct Temp(PathBuf);

impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("bip448-proc-exe-{}", Uuid::new_v4()));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path.canonicalize().unwrap())
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn helper_command_is_literal_sanitized_and_hidden() {
    let root = Path::new("/controlled/repository");
    let command = helper_command(root).unwrap();
    assert_eq!(command.program(), OsStr::new(PROC_SELF_EXE));
    assert_eq!(command.args_slice(), [HIDDEN_HELPER]);
    assert_eq!(command.current_dir, root);
    assert!(command.environment_is_cleared());
    assert!(command.environment.is_empty());
}

#[test]
fn executable_validation_seams_fail_closed() -> anyhow::Result<()> {
    let temp = Temp::new();
    let executable = temp.0.join("executable");
    write_elf(&executable, 0o700);
    assert!(inspect(&executable, super::super::real_uid()?).is_ok());
    assert!(inspect(&executable, super::super::real_uid()?.wrapping_add(1)).is_err());

    for mode in [0o600, 0o702, 0o4700] {
        fs::set_permissions(&executable, fs::Permissions::from_mode(mode)).unwrap();
        assert!(inspect(&executable, super::super::real_uid()?).is_err());
    }
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let malformed = temp.0.join("not-elf");
    write_bytes(&malformed, 0o700, b"not an executable");
    assert!(inspect(&malformed, super::super::real_uid()?).is_err());
    assert!(inspect(&temp.0, super::super::real_uid()?).is_err());

    let other = temp.0.join("other");
    write_elf(&other, 0o700);
    let expected = fs::metadata(&executable).unwrap();
    let actual = fs::metadata(&other).unwrap();
    assert_ne!(expected.ino(), actual.ino());
    assert!(require_same_content_identity(&expected, &actual).is_err());
    Ok(())
}

#[test]
fn proc_self_reexec_survives_launch_path_replacement() {
    let current = std::env::current_dir().unwrap();
    if current.join(REEXEC_ROLE).is_file() {
        let identity = inspect(PROC_SELF_EXE, super::super::real_uid().unwrap()).unwrap();
        fs::write(
            current.join(REEXEC_IDENTITY),
            serde_json::to_vec(&identity).unwrap(),
        )
        .unwrap();
        return;
    }
    if current.join(INITIAL_ROLE).is_file() {
        run_initial_child(&current);
        return;
    }

    let temp = Temp::new();
    fs::write(temp.0.join(INITIAL_ROLE), b"").unwrap();
    let launch = temp.0.join("controller-helper");
    fs::copy(std::env::current_exe().unwrap(), &launch).unwrap();
    let launched = fs::metadata(&launch).unwrap();
    let launch_for_child = launch.clone();
    let directory_for_child = temp.0.clone();
    let child = thread::spawn(move || {
        let command = ArgvCommand::new(launch_for_child, &directory_for_child)
            .clear_environment()
            .args(["--exact", LIVE_TEST, "--nocapture", "--test-threads=1"]);
        SystemCommandRunner.run(&command)
    });

    wait_for(&temp.0.join(INITIAL_READY));
    fs::remove_file(&launch).unwrap();
    fs::copy("/bin/false", &launch).unwrap();
    assert_ne!(launched.ino(), fs::metadata(&launch).unwrap().ino());
    fs::write(temp.0.join(REPLACEMENT_READY), b"").unwrap();

    let output = child.join().unwrap().unwrap();
    assert!(
        output.success && output.code == Some(0) && output.signal.is_none(),
        "replacement-path reexec child failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let initial: ExecutableIdentity =
        serde_json::from_slice(&fs::read(temp.0.join(INITIAL_IDENTITY)).unwrap()).unwrap();
    let reexec: ExecutableIdentity =
        serde_json::from_slice(&fs::read(temp.0.join(REEXEC_IDENTITY)).unwrap()).unwrap();
    assert_eq!(initial, reexec);
}

fn run_initial_child(directory: &Path) {
    let initial = inspect(PROC_SELF_EXE, super::super::real_uid().unwrap()).unwrap();
    fs::write(
        directory.join(INITIAL_IDENTITY),
        serde_json::to_vec(&initial).unwrap(),
    )
    .unwrap();
    fs::write(directory.join(INITIAL_READY), b"").unwrap();
    wait_for(&directory.join(REPLACEMENT_READY));
    fs::remove_file(directory.join(INITIAL_ROLE)).unwrap();
    fs::write(directory.join(REEXEC_ROLE), b"").unwrap();

    let command = command(
        directory,
        ["--exact", LIVE_TEST, "--nocapture", "--test-threads=1"],
    )
    .unwrap();
    assert_eq!(command.program(), OsStr::new(PROC_SELF_EXE));
    assert!(command.environment_is_cleared());
    let output = SystemCommandRunner.run(&command).unwrap();
    assert!(
        output.success
            && output.code == Some(0)
            && output.signal.is_none()
            && output.stderr.is_empty(),
        "pinned proc reexec failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let reexec: ExecutableIdentity =
        serde_json::from_slice(&fs::read(directory.join(REEXEC_IDENTITY)).unwrap()).unwrap();
    assert_eq!(initial, reexec);
}

fn wait_for(path: &Path) {
    for _ in 0..500 {
        if path.is_file() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for {}", path.display());
}

fn write_elf(path: &Path, mode: u32) {
    write_bytes(path, mode, b"\x7fELFcontrolled-test-content");
}

fn write_bytes(path: &Path, mode: u32, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
