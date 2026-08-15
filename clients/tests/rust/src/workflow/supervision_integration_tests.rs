use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use uuid::Uuid;

use super::{SIGINT, SIGTERM};

const FIXTURE_DIRECTORY_ENV: &str = "BIP448_SIGNAL_FIXTURE_DIRECTORY";
const PRESTART_PROJECT_ENV: &str = "BIP448_SIGNAL_PRESTART_PROJECT";
const PRESTART_HELPER: &str =
    "workflow::supervision::integration_tests::prestart_controller_helper";
const DOCTOR_HELPER: &str = "workflow::supervision::integration_tests::doctor_controller_helper";

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
fn prestart_source_capture_maps_int_and_term_and_cleans_the_process_group() {
    let root = Temp::new("bip448-prestart-signal");
    let blocker = compile_blocker(&root.0);
    let bin = root.0.join("bin");
    fs::create_dir(&bin).unwrap();
    symlink(&blocker, bin.join("git")).unwrap();

    for signal in [SIGINT, SIGTERM] {
        let case = make_case(&root.0, "prestart", signal);
        let project = format!("prestart_sig_{}", short_id());
        let output = run_signalled_controller(PRESTART_HELPER, &case, &bin, signal, |command| {
            command.env(PRESTART_PROJECT_ENV, &project);
        });
        assert_controller_result(&case, signal, &output);
        assert!(
            !repository_root()
                .join("target/bip448-runs")
                .join(project)
                .exists(),
            "pre-start source capture must not create operation evidence"
        );
    }
}

#[test]
fn doctor_maps_int_and_term_and_cleans_the_process_group() {
    let root = Temp::new("bip448-doctor-signal");
    let blocker = compile_blocker(&root.0);
    let bin = root.0.join("bin");
    fs::create_dir(&bin).unwrap();
    for name in ["cargo", "docker", "git", "rustc", "rustup"] {
        symlink(&blocker, bin.join(name)).unwrap();
    }

    for signal in [SIGINT, SIGTERM] {
        let case = make_case(&root.0, "doctor", signal);
        let output = run_signalled_controller(DOCTOR_HELPER, &case, &bin, signal, |_| {});
        assert_controller_result(&case, signal, &output);
    }
}

#[test]
fn workflow_production_processes_only_spawn_in_the_system_runner() {
    let workflow = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/workflow");
    let mut sources = Vec::new();
    collect_rust_sources(&workflow, &mut sources);
    sources.sort();
    assert!(!sources.is_empty());

    for path in sources {
        let name = path.file_name().unwrap().to_str().unwrap();
        if matches!(
            name,
            "supervision_tests.rs" | "supervision_integration_tests.rs"
        ) {
            continue;
        }
        let source = fs::read_to_string(&path).unwrap();
        let mut inside_system_runner = false;
        for (index, line) in source.lines().enumerate() {
            if line == "impl CommandRunner for SystemCommandRunner {" {
                assert_eq!(name, "argv.rs");
                inside_system_runner = true;
            } else if inside_system_runner && line == "struct SupervisedChild {" {
                inside_system_runner = false;
            }
            let raw_import = line.contains("std::process::Command")
                || (line.contains("use std::process") && line.contains("Command"));
            let raw_execution = contains_bare_command_new(line) || line.contains(".spawn()");
            assert!(
                (!raw_import || name == "argv.rs")
                    && (!raw_execution || name == "argv.rs" && inside_system_runner)
                    && !line.contains(".output()"),
                "raw process execution outside SystemCommandRunner at {}:{}: {line}",
                path.display(),
                index + 1
            );
        }
        assert!(
            !inside_system_runner,
            "unterminated SystemCommandRunner impl"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn prestart_controller_helper() {
    let Some(directory) = fixture_directory() else {
        return;
    };
    let project = std::env::var(PRESTART_PROJECT_ENV).unwrap();
    let code = crate::workflow::run([
        OsString::from("configure"),
        OsString::from("--project"),
        OsString::from(project),
        OsString::from("--base-port"),
        OsString::from("28000"),
    ])
    .await;
    fs::write(directory.join("controller.code"), format!("{code}\n")).unwrap();
    std::process::exit(code);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn doctor_controller_helper() {
    let Some(directory) = fixture_directory() else {
        return;
    };
    let code = crate::workflow::run([OsString::from("doctor")]).await;
    fs::write(directory.join("controller.code"), format!("{code}\n")).unwrap();
    std::process::exit(code);
}

fn run_signalled_controller(
    helper: &str,
    directory: &Path,
    path: &Path,
    signal: i32,
    configure: impl FnOnce(&mut Command),
) -> std::process::Output {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--ignored", "--exact", helper, "--nocapture"])
        .current_dir(repository_root())
        .env("PATH", path)
        .env(FIXTURE_DIRECTORY_ENV, directory)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure(&mut command);
    let controller = command.spawn().unwrap();
    let child = wait_for_pid(&directory.join("child.pid"));
    let grandchild = wait_for_pid(&directory.join("grandchild.pid"));
    wait_for_file(&directory.join("grandchild.ready"));

    send_pid_signal(i32::try_from(controller.id()).unwrap(), signal).unwrap();
    let output = controller.wait_with_output().unwrap();
    wait_for_process_exit(child);
    wait_for_process_exit(grandchild);
    assert!(directory.join("child.reaped-grandchild").is_file());
    output
}

fn assert_controller_result(directory: &Path, signal: i32, output: &std::process::Output) {
    assert_eq!(output.status.code(), Some(128 + signal));
    assert_eq!(
        fs::read_to_string(directory.join("controller.code"))
            .unwrap()
            .trim()
            .parse::<i32>()
            .unwrap(),
        128 + signal
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!("workflow interrupted by signal {signal}")),
        "unexpected controller stderr: {stderr}"
    );
}

fn compile_blocker(directory: &Path) -> PathBuf {
    let source = directory.join("blocker.rs");
    let binary = directory.join("blocker");
    fs::write(&source, BLOCKER_SOURCE).unwrap();
    let status = Command::new("rustc")
        .args(["--edition=2021", "-o"])
        .arg(&binary)
        .arg(&source)
        .status()
        .unwrap();
    assert!(status.success(), "compile Rust process-group fixture");
    binary
}

fn make_case(root: &Path, name: &str, signal: i32) -> PathBuf {
    let path = root.join(format!("{name}-{signal}"));
    fs::create_dir(&path).unwrap();
    path
}

fn short_id() -> String {
    Uuid::new_v4().simple().to_string()[..8].to_owned()
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
}

fn fixture_directory() -> Option<PathBuf> {
    std::env::var_os(FIXTURE_DIRECTORY_ENV).map(PathBuf::from)
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

fn collect_rust_sources(directory: &Path, sources: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_rust_sources(&path, sources);
        } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
            sources.push(path);
        }
    }
}

fn contains_bare_command_new(line: &str) -> bool {
    line.match_indices("Command::new(").any(|(index, _)| {
        index == 0
            || !line.as_bytes()[index - 1].is_ascii_alphanumeric()
                && line.as_bytes()[index - 1] != b'_'
    })
}

unsafe extern "C" {
    fn kill(pid: i32, signal: i32) -> i32;
}

const BLOCKER_SOURCE: &str = r#"
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::thread;
use std::time::Duration;

const DIRECTORY_ENV: &str = "BIP448_SIGNAL_FIXTURE_DIRECTORY";
const ROLE_ENV: &str = "BIP448_SIGNAL_FIXTURE_ROLE";
static SIGNAL: AtomicI32 = AtomicI32::new(0);

extern "C" fn record_signal(value: i32) {
    SIGNAL.store(value, Ordering::SeqCst);
}

fn main() {
    let directory = PathBuf::from(env::var_os(DIRECTORY_ENV).unwrap());
    if env::var_os(ROLE_ENV).is_some() {
        fs::write(directory.join("grandchild.ready"), b"ready\n").unwrap();
        loop {
            thread::sleep(Duration::from_secs(1));
        }
    }

    unsafe {
        signal(2, record_signal as usize);
        signal(15, record_signal as usize);
    }
    let mut grandchild = Command::new(env::current_exe().unwrap())
        .env(ROLE_ENV, "grandchild")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    fs::write(directory.join("child.pid"), format!("{}\n", std::process::id())).unwrap();
    fs::write(directory.join("grandchild.pid"), format!("{}\n", grandchild.id())).unwrap();
    loop {
        let received = SIGNAL.load(Ordering::SeqCst);
        if received != 0 {
            let _ = grandchild.wait().unwrap();
            fs::write(directory.join("child.reaped-grandchild"), b"reaped\n").unwrap();
            std::process::exit(128 + received);
        }
        thread::sleep(Duration::from_millis(5));
    }
}

unsafe extern "C" {
    fn signal(value: i32, handler: usize) -> usize;
}
"#;
