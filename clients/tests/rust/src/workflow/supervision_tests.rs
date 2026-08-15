use std::fs;
use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{SignalWatch, TestSignalSession, SIGINT, SIGTERM};
use crate::workflow::argv::{ArgvCommand, CommandRunner, SystemCommandRunner};
use crate::workflow::cli::Command as WorkflowCommand;
use crate::workflow::error::WorkflowError;
use crate::workflow::evidence;
use crate::workflow::model::{PortMap, Project, RunPaths};
use crate::workflow::project_lock::ProjectLock;

const DIRECTORY_ENV: &str = "BIP448_SUPERVISION_TEST_DIRECTORY";
const SIGNAL_ENV: &str = "BIP448_SUPERVISION_TEST_SIGNAL";
const CONTROLLER_HELPER: &str = "workflow::supervision::tests::signal_watch_controller_helper";
const CHILD_HELPER: &str = "workflow::supervision::tests::signal_watch_child_helper";
const GRANDCHILD_HELPER: &str = "workflow::supervision::tests::signal_watch_grandchild_helper";
const EXIT_HELPER: &str = "workflow::supervision::tests::ordinary_exit_helper";
const SIGNAL_EXIT_HELPER: &str = "workflow::supervision::tests::ordinary_signal_helper";
const STREAM_BYTES: usize = 128 * 1_024;

struct Temp(PathBuf);

impl Temp {
    fn new(prefix: &str) -> Self {
        let path = std::env::temp_dir().join(format!("{prefix}-{}", Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        Self(path.canonicalize().unwrap())
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn host_signal_watch_forwards_int_and_term_without_lingering_processes() {
    for signal in [SIGINT, SIGTERM] {
        let directory = Temp::new("bip448-host-signal");
        let controller = Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", CONTROLLER_HELPER, "--nocapture"])
            .env(DIRECTORY_ENV, &directory.0)
            .env(SIGNAL_ENV, signal.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let child = wait_for_pid(&directory.0.join("child.pid"));
        let grandchild = wait_for_pid(&directory.0.join("grandchild.pid"));
        wait_for_file(&directory.0.join("grandchild.ready"));

        send_pid_signal(i32::try_from(controller.id()).unwrap(), signal).unwrap();
        let output = controller.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(128 + signal));
        assert!(output.status.signal().is_none());
        wait_for_file(&directory.0.join("controller.complete"));
        wait_for_process_exit(child);
        wait_for_process_exit(grandchild);

        let stdout = fs::read(directory.0.join("captured.stdout")).unwrap();
        let stderr = fs::read(directory.0.join("captured.stderr")).unwrap();
        assert_payload(&stdout, b'o', "child stdout end");
        assert_payload(&stderr, b'e', "child stderr end");
        assert!(directory.0.join("child.reaped-grandchild").is_file());
    }
}

#[test]
fn ordinary_exit_and_child_signal_statuses_are_unchanged() {
    let directory = Temp::new("bip448-ordinary-exit");
    let mut runner = SystemCommandRunner;
    let output = runner
        .run(&test_binary_command(EXIT_HELPER, &directory.0))
        .unwrap();
    assert!(!output.success);
    assert_eq!(output.code, Some(23));
    assert_eq!(output.signal, None);

    let directory = Temp::new("bip448-ordinary-signal");
    let path = directory.0.clone();
    let killer = thread::spawn(move || {
        let pid = wait_for_pid(&path.join("ordinary.pid"));
        send_pid_signal(pid, SIGTERM).unwrap();
    });
    let output = runner
        .run(&test_binary_command(SIGNAL_EXIT_HELPER, &directory.0))
        .unwrap();
    killer.join().unwrap();
    assert!(!output.success);
    assert_eq!(output.code, None);
    assert_eq!(output.signal, Some(SIGTERM));
}

#[test]
fn signalled_mutation_writes_signal_evidence_hashes_logs_and_releases_lock() {
    let root = Temp::new("bip448-signal-evidence");
    initialize_git_repository(&root.0);
    let project = Project::parse("signal_evidence_1").unwrap();
    create_completed_configuration_evidence(&root.0, &project);
    let directory = root.0.join("helper");
    fs::create_dir(&directory).unwrap();

    let (_session, sender) = TestSignalSession::install().unwrap();
    let ready = directory.join("grandchild.ready");
    let interrupter = thread::spawn(move || {
        wait_for_file(&ready);
        sender.send(SIGTERM);
    });
    let command = WorkflowCommand::Test {
        project: project.clone(),
        target: "bip448_primitive_spike".into(),
        test: "bip448_template_signature_rebinds_prevout_on_inquisition".into(),
    };
    let raw = vec![
        "test".into(),
        "--project".into(),
        project.to_string(),
        "--target".into(),
        "bip448_primitive_spike".into(),
        "--test".into(),
        "bip448_template_signature_rebinds_prevout_on_inquisition".into(),
    ];
    let result = evidence::execute_mutation(&root.0, &command, &raw, |_| {
        let mut runner = SystemCommandRunner;
        let output = runner.run(&test_binary_command(CHILD_HELPER, &directory))?;
        evidence::capture_test_output(&output.stdout, &output.stderr);
        Err(WorkflowError::from(anyhow::anyhow!(
            "supervised helper was interrupted"
        )))
    });
    interrupter.join().unwrap();
    assert_eq!(result.unwrap_err().exit_code(), 143);

    let operation = find_operation(&root.0, &project, "test");
    let result: Value =
        serde_json::from_slice(&fs::read(operation.join("result.json")).unwrap()).unwrap();
    assert_eq!(result["outcome"]["kind"], "signal");
    assert_eq!(result["outcome"]["exit_code"], 143);
    assert_eq!(result["outcome"]["signal"], SIGTERM);
    assert_eq!(result["first_failing_child"]["signal"], SIGTERM);
    for name in ["test.stdout", "test.stderr"] {
        let bytes = fs::read(operation.join(name)).unwrap();
        let stored = &result["test_logs"][name.strip_prefix("test.").unwrap()];
        assert_eq!(stored["bytes"], bytes.len() as u64);
        assert_eq!(
            stored["sha256"],
            hash_bytes(b"bip448-operation-test-log-v1", &bytes)
        );
    }
    drop(ProjectLock::acquire(&root.0, &project).unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn signal_watch_controller_helper() {
    let Some(directory) = helper_directory() else {
        return;
    };
    let signal = helper_signal();
    let watch = SignalWatch::install().unwrap();
    let output = watch
        .scope(async {
            let mut runner = SystemCommandRunner;
            runner
                .run(&test_binary_command(CHILD_HELPER, &directory))
                .unwrap()
        })
        .await;
    fs::write(directory.join("captured.stdout"), &output.stdout).unwrap();
    fs::write(directory.join("captured.stderr"), &output.stderr).unwrap();
    assert!(!output.success);
    assert_eq!(output.code, None);
    assert_eq!(output.signal, Some(signal));
    fs::write(directory.join("controller.complete"), b"complete\n").unwrap();
    std::process::exit(128 + signal);
}

#[tokio::test(flavor = "current_thread")]
#[ignore]
async fn signal_watch_child_helper() {
    let Some(directory) = helper_directory() else {
        return;
    };
    let mut interrupts =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).unwrap();
    let mut terminations =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
    let mut grandchild = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", GRANDCHILD_HELPER, "--nocapture"])
        .env(DIRECTORY_ENV, &directory)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    fs::write(
        directory.join("child.pid"),
        format!("{}\n", std::process::id()),
    )
    .unwrap();
    fs::write(
        directory.join("grandchild.pid"),
        format!("{}\n", grandchild.id()),
    )
    .unwrap();
    write_payload(std::io::stdout().lock(), b'o', "child stdout end");
    write_payload(std::io::stderr().lock(), b'e', "child stderr end");

    let signal = tokio::select! {
        value = interrupts.recv() => {
            assert!(value.is_some());
            SIGINT
        }
        value = terminations.recv() => {
            assert!(value.is_some());
            SIGTERM
        }
    };
    let status = grandchild.wait().unwrap();
    assert_eq!(status.signal(), Some(signal));
    fs::write(directory.join("child.reaped-grandchild"), b"reaped\n").unwrap();
}

#[test]
#[ignore]
fn signal_watch_grandchild_helper() {
    let Some(directory) = helper_directory() else {
        return;
    };
    fs::write(directory.join("grandchild.ready"), b"ready\n").unwrap();
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}

#[test]
#[ignore]
fn ordinary_exit_helper() {
    if helper_directory().is_some() {
        std::process::exit(23);
    }
}

#[test]
#[ignore]
fn ordinary_signal_helper() {
    let Some(directory) = helper_directory() else {
        return;
    };
    fs::write(
        directory.join("ordinary.pid"),
        format!("{}\n", std::process::id()),
    )
    .unwrap();
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}

fn test_binary_command(test: &str, directory: &Path) -> ArgvCommand {
    ArgvCommand::new(std::env::current_exe().unwrap(), directory)
        .args(["--ignored", "--exact", test, "--nocapture"])
        .env(DIRECTORY_ENV, directory)
}

fn helper_directory() -> Option<PathBuf> {
    std::env::var_os(DIRECTORY_ENV).map(PathBuf::from)
}

fn helper_signal() -> i32 {
    std::env::var(SIGNAL_ENV).unwrap().parse::<i32>().unwrap()
}

fn write_payload(mut writer: impl Write, byte: u8, suffix: &str) {
    writer
        .write_all(format!("{suffix} begin\n").as_bytes())
        .unwrap();
    writer.write_all(&vec![byte; STREAM_BYTES]).unwrap();
    writer
        .write_all(format!("\n{suffix}\n").as_bytes())
        .unwrap();
    writer.flush().unwrap();
}

fn assert_payload(bytes: &[u8], byte: u8, suffix: &str) {
    let payload = vec![byte; STREAM_BYTES];
    assert!(bytes.windows(STREAM_BYTES).any(|window| window == payload));
    assert!(String::from_utf8_lossy(bytes).contains(suffix));
}

fn wait_for_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.is_file() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_pid(path: &Path) -> i32 {
    wait_for_file(path);
    fs::read_to_string(path).unwrap().trim().parse().unwrap()
}

fn wait_for_process_exit(pid: i32) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Path::new(&format!("/proc/{pid}")).exists() {
        assert!(
            Instant::now() < deadline,
            "process {pid} remained after supervision"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn send_pid_signal(pid: i32, signal: i32) -> std::io::Result<()> {
    if unsafe { kill(pid, signal) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn initialize_git_repository(root: &Path) {
    fs::create_dir(root.join("target")).unwrap();
    fs::write(root.join(".gitignore"), b"/target/\n/helper/\n").unwrap();
    fs::write(root.join("tracked"), b"tracked\n").unwrap();
    run_git(root, &["init", "--quiet", "--object-format=sha1"]);
    run_git(root, &["add", ".gitignore", "tracked"]);
    run_git(
        root,
        &[
            "-c",
            "user.name=BIP448 Test",
            "-c",
            "user.email=bip448@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "base",
        ],
    );
}

fn run_git(root: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(root)
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?} failed");
}

fn create_completed_configuration_evidence(root: &Path, project: &Project) {
    let command = WorkflowCommand::Configure {
        project: project.clone(),
        ports: PortMap::from_base(26000).unwrap(),
    };
    let raw = vec![
        "configure".into(),
        "--project".into(),
        project.to_string(),
        "--base-port".into(),
        "26000".into(),
    ];
    evidence::execute_mutation(root, &command, &raw, |_| Ok("configured".into())).unwrap();
}

fn find_operation(root: &Path, project: &Project, command: &str) -> PathBuf {
    let operations = RunPaths::new(root, project)
        .run_directory
        .join("operations");
    fs::read_dir(operations)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            let started: Value =
                serde_json::from_slice(&fs::read(path.join("started.json")).unwrap()).unwrap();
            started["command"] == command
        })
        .unwrap()
}

fn hash_bytes(domain: &[u8], bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update((domain.len() as u64).to_be_bytes());
    hash.update(domain);
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
    hex::encode(hash.finalize())
}

unsafe extern "C" {
    fn kill(pid: i32, signal: i32) -> i32;
}
