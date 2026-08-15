use std::collections::VecDeque;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde_json::Value;
use uuid::Uuid;

use super::super::argv::{ArgvCommand, ChildFailure, CommandOutput, CommandRunner};
use super::super::error::WorkflowError;
use super::super::lifecycle;
use super::super::model::Project;
use super::super::project_lock::ProjectLock;
use super::readout;
use super::record::{Clock, OutcomeKind, SourceIdentity, MAX_CONTROLLER_ERROR_BYTES};
use super::store::{combine_action_and_finalization, IdSource, Operation};

struct Temp(PathBuf);

impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("bip448-evidence-{}", Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        fs::create_dir(path.join("target")).unwrap();
        Self(path.canonicalize().unwrap())
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

struct FixedClock(VecDeque<&'static str>);

impl Clock for FixedClock {
    fn now_utc(&mut self) -> Result<String> {
        Ok(self.0.pop_front().unwrap().to_owned())
    }
}

struct FixedId(&'static str);

impl IdSource for FixedId {
    fn next_id(&mut self) -> String {
        self.0.to_owned()
    }
}

fn source() -> SourceIdentity {
    SourceIdentity {
        head: "a".repeat(40),
        status_sha256: "b".repeat(64),
        clean: true,
    }
}

fn start(root: &Path, project: &Project, id: &'static str, configure: bool) -> Operation {
    Operation::start_with(
        root,
        project,
        "test",
        vec!["--project".into(), project.to_string()],
        source(),
        configure,
        &mut FixedClock(VecDeque::from(["2026-08-15T01:02:03Z"])),
        &mut FixedId(id),
    )
    .unwrap()
}

#[test]
fn started_precedes_logs_and_result_which_is_written_last() {
    let root = Temp::new();
    let project = Project::parse("evidence_1").unwrap();
    let id = "11111111-1111-4111-8111-111111111111";
    let operation = start(&root.0, &project, id, true);
    let directory = root
        .0
        .join("target/bip448-runs/evidence_1/operations")
        .join(id);

    assert!(directory.join("started.json").is_file());
    assert!(!directory.join("result.json").exists());
    assert!(!directory.join("test.stdout").exists());
    let incomplete = readout::scan(&root.0, &project).unwrap();
    assert_eq!(incomplete.len(), 1);
    assert!(incomplete[0].incomplete);

    super::capture_test_output(b"exact stdout\n", b"exact stderr\n");
    operation
        .finish_with(
            &Ok("passed".into()),
            None,
            &mut FixedClock(VecDeque::from(["2026-08-15T01:02:04Z"])),
        )
        .unwrap();

    let completed = readout::scan(&root.0, &project).unwrap();
    assert!(!completed[0].incomplete);
    let logs = completed[0]
        .result
        .as_ref()
        .unwrap()
        .test_logs
        .as_ref()
        .unwrap();
    assert_eq!(logs.stdout.bytes, 13);
    assert_eq!(logs.stderr.bytes, 13);
    assert_eq!(
        fs::read(directory.join("test.stdout")).unwrap(),
        b"exact stdout\n"
    );
    assert_eq!(
        fs::read(directory.join("test.stderr")).unwrap(),
        b"exact stderr\n"
    );
    for path in [directory.clone(), directory.parent().unwrap().to_path_buf()] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o7777,
            0o700
        );
    }
    for name in ["started.json", "test.stdout", "test.stderr", "result.json"] {
        assert_eq!(
            fs::metadata(directory.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
    }
}

#[test]
fn malformed_alien_and_symlink_evidence_fail_closed() {
    for poison in ["malformed", "alien", "symlink"] {
        let root = Temp::new();
        let project = Project::parse("poison_1").unwrap();
        let id = "22222222-2222-4222-8222-222222222222";
        let operation = start(&root.0, &project, id, true);
        operation
            .finish_with(
                &Ok("passed".into()),
                None,
                &mut FixedClock(VecDeque::from(["2026-08-15T01:02:04Z"])),
            )
            .unwrap();
        let directory = root
            .0
            .join("target/bip448-runs/poison_1/operations")
            .join(id);
        match poison {
            "malformed" => fs::write(directory.join("result.json"), b"{}\n").unwrap(),
            "alien" => fs::write(directory.join("alien"), b"bad").unwrap(),
            "symlink" => {
                fs::remove_file(directory.join("started.json")).unwrap();
                symlink("result.json", directory.join("started.json")).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            readout::scan(&root.0, &project).is_err(),
            "accepted {poison}"
        );
    }
}

#[test]
fn evidence_finalization_never_masks_the_primary_child_exit() {
    let error = combine_action_and_finalization(
        Err(WorkflowError::child_exit(101, "Cargo child failed")),
        Err(anyhow::anyhow!("disk full")),
    )
    .unwrap_err();
    assert_eq!(error.exit_code(), 101);
    assert!(error.to_string().contains("Cargo child failed"));
    assert!(error.to_string().contains("disk full"));
}

struct LogsRunner {
    seen: Vec<ArgvCommand>,
}

impl CommandRunner for LogsRunner {
    fn run(&mut self, command: &ArgvCommand) -> Result<CommandOutput> {
        self.seen.push(command.clone());
        Ok(CommandOutput::success(
            "service | 2026-08-15T01:02:03Z line\n",
        ))
    }
}

#[test]
fn checkpoint_and_logs_read_during_held_mutation_lock_without_shell() {
    let root = Temp::new();
    let metadata = lifecycle::evidence_test_metadata(&root.0);
    let project = metadata.project().clone();
    let operation = start(
        &root.0,
        &project,
        "33333333-3333-4333-8333-333333333333",
        true,
    );
    let _held = ProjectLock::acquire(&root.0, &project).unwrap();

    let status = lifecycle::evidence_test_absent_status(&root.0, &metadata).unwrap();
    let checkpoint = readout::checkpoint_with_status(&root.0, &metadata, status).unwrap();
    let value: Value = serde_json::from_str(&checkpoint).unwrap();
    assert_eq!(value["operations"][0]["incomplete"], true);

    let mut runner = LogsRunner { seen: Vec::new() };
    let logs = readout::logs_with(&root.0, &metadata, &mut runner).unwrap();
    assert_eq!(runner.seen.len(), 1);
    let argv = runner.seen[0].encoded_argv();
    assert_eq!(argv[0], "docker");
    assert!(!argv
        .iter()
        .any(|arg| matches!(arg.as_str(), "sh" | "bash" | "-c")));
    assert_eq!(&argv[1..4], ["compose", "-p", metadata.project().as_str()]);
    assert_eq!(
        &argv[6..],
        ["logs", "--no-color", "--timestamps", "--tail", "200"]
    );
    let value: Value = serde_json::from_str(&logs).unwrap();
    assert_eq!(value["compose"]["argv"], serde_json::json!(argv));

    let action: Result<String, WorkflowError> = Err(WorkflowError::from(anyhow::anyhow!(
        "HTTP readiness remained incomplete at the deadline"
    )));
    operation
        .finish_with(
            &action,
            None,
            &mut FixedClock(VecDeque::from(["2026-08-15T01:02:04Z"])),
        )
        .unwrap();
    let status = lifecycle::evidence_test_absent_status(&root.0, &metadata).unwrap();
    let checkpoint = readout::checkpoint_with_status(&root.0, &metadata, status).unwrap();
    let value: Value = serde_json::from_str(&checkpoint).unwrap();
    assert_eq!(
        value["operations"][0]["result"]["controller_error"],
        "HTTP readiness remained incomplete at the deadline"
    );
    assert_eq!(
        value["operations"][0]["result"]["first_failing_child"],
        Value::Null
    );
}

#[test]
fn controller_error_is_byte_bounded_without_changing_operational_outcome() {
    let root = Temp::new();
    let project = Project::parse("bounded_error_1").unwrap();
    let operation = start(
        &root.0,
        &project,
        "44444444-4444-4444-8444-444444444444",
        true,
    );
    let action: Result<String, WorkflowError> =
        Err(WorkflowError::from(anyhow::anyhow!("{}", "x".repeat(4096))));
    operation
        .finish_with(
            &action,
            None,
            &mut FixedClock(VecDeque::from(["2026-08-15T01:02:04Z"])),
        )
        .unwrap();

    let records = readout::scan(&root.0, &project).unwrap();
    let result = records[0].result.as_ref().unwrap();
    let error = result.controller_error.as_ref().unwrap();
    assert_eq!(error.len(), MAX_CONTROLLER_ERROR_BYTES);
    assert!(error.ends_with("..."));
    assert_eq!(
        result.outcome.kind,
        super::record::OutcomeKind::OperationalError
    );
    assert_eq!(result.outcome.exit_code, Some(1));
}

#[test]
fn operational_action_keeps_substantive_child_but_stays_operational() {
    for (project_name, id, child) in [
        (
            "operational_pg_1",
            "55555555-5555-4555-8555-555555555551",
            child_failure(
                &["docker", "exec", "container", "pg_isready"],
                Some(3),
                None,
            ),
        ),
        (
            "operational_volume_1",
            "55555555-5555-4555-8555-555555555552",
            child_failure(
                &["docker", "volume", "inspect", "managed-volume"],
                Some(1),
                None,
            ),
        ),
    ] {
        let root = Temp::new();
        let project = Project::parse(project_name).unwrap();
        let operation = start(&root.0, &project, id, true);
        let action: Result<String, WorkflowError> = Err(WorkflowError::from(anyhow::anyhow!(
            "controller rejected an unexpected child outcome"
        )));
        operation
            .finish_with(
                &action,
                Some(child.clone()),
                &mut FixedClock(VecDeque::from(["2026-08-15T01:02:04Z"])),
            )
            .unwrap();

        let records = readout::scan(&root.0, &project).unwrap();
        let result = records[0].result.as_ref().unwrap();
        assert_eq!(result.outcome.kind, OutcomeKind::OperationalError);
        assert_eq!(result.outcome.exit_code, Some(1));
        assert_eq!(result.outcome.signal, None);
        assert_eq!(result.first_failing_child.as_ref(), Some(&child));
        assert_eq!(
            result.controller_error.as_deref(),
            Some("controller rejected an unexpected child outcome")
        );
    }
}

#[test]
fn child_exit_uses_matching_signal_or_exit_and_falls_back_to_propagated_status() {
    for (project_name, id, code, child, kind, signal) in [
        (
            "child_exit_1",
            "66666666-6666-4666-8666-666666666666",
            23,
            child_failure(&["cargo", "test", "exact"], Some(23), None),
            OutcomeKind::ExitCode,
            None,
        ),
        (
            "child_signal_1",
            "77777777-7777-4777-8777-777777777777",
            143,
            child_failure(&["cargo", "test", "exact"], None, Some(15)),
            OutcomeKind::Signal,
            Some(15),
        ),
        (
            "child_fallback_1",
            "88888888-8888-4888-8888-888888888888",
            17,
            child_failure(&["cargo", "test", "exact"], Some(23), None),
            OutcomeKind::ExitCode,
            None,
        ),
    ] {
        let root = Temp::new();
        let project = Project::parse(project_name).unwrap();
        let operation = start(&root.0, &project, id, true);
        let action: Result<String, WorkflowError> = Err(WorkflowError::child_exit(
            code,
            "primary product child failed",
        ));
        operation
            .finish_with(
                &action,
                Some(child.clone()),
                &mut FixedClock(VecDeque::from(["2026-08-15T01:02:04Z"])),
            )
            .unwrap();

        let records = readout::scan(&root.0, &project).unwrap();
        let result = records[0].result.as_ref().unwrap();
        assert_eq!(result.outcome.kind, kind);
        assert_eq!(result.outcome.exit_code, Some(code));
        assert_eq!(result.outcome.signal, signal);
        assert_eq!(result.first_failing_child.as_ref(), Some(&child));
        assert_eq!(result.controller_error, None);
        assert_eq!(action.as_ref().unwrap_err().exit_code(), code);
    }
}

#[test]
fn incomplete_operations_block_five_mutations_but_down_is_separate_and_allowed() {
    let root = Temp::new();
    let project = Project::parse("incomplete_gate_1").unwrap();
    let later = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    let earlier = "11111111-2222-4333-8444-555555555555";
    crash_after_started(&root.0, &project, later, true);
    crash_after_started(&root.0, &project, earlier, false);

    let expected_ids = format!("{earlier},{later}");
    for command in ["configure", "build", "up", "bootstrap", "test"] {
        let error = super::incomplete::reject_mutation(&root.0, &project, command).unwrap_err();
        let message = error.to_string();
        assert!(message.contains(&format!("blocks {command}")));
        assert!(message.contains(&expected_ids));
    }
    super::incomplete::reject_mutation(&root.0, &project, "down").unwrap();

    let down = Operation::start_with(
        &root.0,
        &project,
        "down",
        vec!["--project".into(), project.to_string()],
        source(),
        false,
        &mut FixedClock(VecDeque::from(["2026-08-15T01:02:05Z"])),
        &mut FixedId("dddddddd-dddd-4ddd-8ddd-dddddddddddd"),
    )
    .unwrap();
    down.finish_with(
        &Ok("down".into()),
        None,
        &mut FixedClock(VecDeque::from(["2026-08-15T01:02:06Z"])),
    )
    .unwrap();

    let records = readout::scan(&root.0, &project).unwrap();
    let incomplete = records
        .iter()
        .filter(|record| record.incomplete)
        .map(|record| record.operation_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(incomplete, [earlier, later]);
    let down = records
        .iter()
        .find(|record| {
            record
                .started
                .as_ref()
                .is_some_and(|started| started.command == "down")
        })
        .unwrap();
    assert!(!down.incomplete);
    assert_eq!(
        down.result.as_ref().unwrap().outcome.kind,
        OutcomeKind::Success
    );
}

fn crash_after_started(root: &Path, project: &Project, id: &'static str, configure: bool) {
    let root = root.to_path_buf();
    let project = project.clone();
    std::thread::spawn(move || {
        let _operation = Operation::start_with(
            &root,
            &project,
            "test",
            vec!["--project".into(), project.to_string()],
            source(),
            configure,
            &mut FixedClock(VecDeque::from(["2026-08-15T01:02:03Z"])),
            &mut FixedId(id),
        )
        .unwrap();
    })
    .join()
    .unwrap();
}

fn child_failure(argv: &[&str], exit_code: Option<i32>, signal: Option<i32>) -> ChildFailure {
    ChildFailure {
        argv: argv.iter().map(|value| (*value).to_owned()).collect(),
        exit_code,
        signal,
    }
}
