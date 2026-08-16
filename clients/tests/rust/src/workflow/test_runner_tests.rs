use std::collections::VecDeque;
use std::path::Path;
use std::{cell::RefCell, rc::Rc};

use anyhow::Result;

use super::*;
use crate::workflow::model::{ImageMap, PortMap, Project};

const TARGET: &str = "bip448_primitive_spike";
const IDENTITY: &str = "bip448_template_signature_rebinds_prevout_on_inquisition";

struct Gate {
    calls: usize,
    events: Option<Rc<RefCell<Vec<&'static str>>>>,
}

impl ReadyGate for Gate {
    fn require_ready(
        &mut self,
        _repo_root: &Path,
        metadata: &StackMetadata,
    ) -> Result<ProjectSpec> {
        self.calls += 1;
        if let Some(events) = &self.events {
            events.borrow_mut().push("ready");
        }
        Ok(spec(metadata))
    }
}

struct ScriptedRunner {
    outputs: VecDeque<CommandOutput>,
    seen: Vec<ArgvCommand>,
    events: Option<Rc<RefCell<Vec<&'static str>>>>,
}

impl ScriptedRunner {
    fn new(outputs: impl IntoIterator<Item = CommandOutput>) -> Self {
        Self {
            outputs: outputs.into_iter().collect(),
            seen: Vec::new(),
            events: None,
        }
    }
}

impl CommandRunner for ScriptedRunner {
    fn run(&mut self, command: &ArgvCommand) -> Result<CommandOutput> {
        if let Some(events) = &self.events {
            let event = if command.args_slice().iter().any(|arg| arg == "--list") {
                "discover"
            } else {
                "test"
            };
            events.borrow_mut().push(event);
        }
        self.seen.push(command.clone());
        self.outputs
            .pop_front()
            .ok_or_else(|| anyhow::anyhow!("unexpected Cargo invocation"))
    }
}

fn metadata() -> StackMetadata {
    StackMetadata::new(
        Path::new("/repo"),
        Project::parse("runner_test").unwrap(),
        PortMap::from_base(24600).unwrap(),
    )
}

fn spec(metadata: &StackMetadata) -> ProjectSpec {
    metadata.project_spec(
        ImageMap::new(
            metadata.project(),
            "mercurylayer/mercury-server:bip448-test-aaaaaaaaaaaaaaaa",
            "mercurylayer/token-server-v2:bip448-test-bbbbbbbbbbbbbbbb",
            "mercurylayer/lockbox:bip448-test-cccccccccccccccc",
            "mercurylayer/lockbox:bip448-test-cccccccccccccccc-rng-runner_test",
        )
        .unwrap(),
    )
}

fn discovery(identities: &[&str]) -> Vec<u8> {
    let mut output = identities
        .iter()
        .map(|identity| format!("{identity}: test\n"))
        .collect::<String>();
    let noun = if identities.len() == 1 {
        "test"
    } else {
        "tests"
    };
    output.push_str(&format!("\n{} {noun}, 0 benchmarks\n", identities.len()));
    output.into_bytes()
}

#[test]
fn exact_success_discovers_then_runs_once_with_sanitized_environment() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut runner = ScriptedRunner::new([
        CommandOutput::success(discovery(&[IDENTITY])),
        CommandOutput::success(b"one exact test passed\n"),
    ]);
    runner.events = Some(events.clone());
    let mut gate = Gate {
        calls: 0,
        events: Some(events.clone()),
    };
    let inherited = [
        (OsString::from("PATH"), OsString::from("/controlled/bin")),
        (OsString::from("ML_TEST_PROJECT"), OsString::from("poison")),
        (OsString::from("ML_TEST_UNKNOWN"), OsString::from("poison")),
        (
            OsString::from("RUSTUP_TOOLCHAIN"),
            OsString::from("nightly"),
        ),
    ];
    let report = execute_with(
        Path::new("/repo"),
        &metadata(),
        TARGET,
        IDENTITY,
        inherited,
        &mut runner,
        &mut gate,
    )
    .unwrap();

    assert_eq!(report.report.status, "passed");
    assert_eq!(report.metadata, metadata());
    assert!(report.rng_adoption.is_none());
    assert_eq!(gate.calls, 2);
    assert_eq!(runner.seen.len(), 2);
    assert_eq!(*events.borrow(), ["ready", "discover", "test", "ready"]);
    assert!(runner.outputs.is_empty());
    let discovery_args = runner.seen[0]
        .args_slice()
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        discovery_args,
        [
            "test",
            "--locked",
            "--test",
            TARGET,
            "--",
            "--ignored",
            "--list"
        ]
    );
    let test_args = runner.seen[1]
        .args_slice()
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        test_args,
        [
            "test",
            "--locked",
            "--test",
            TARGET,
            IDENTITY,
            "--",
            "--ignored",
            "--exact",
            "--nocapture",
            "--test-threads=1"
        ]
    );
    for command in &runner.seen {
        assert_eq!(command.program(), OsStr::new("cargo"));
        assert!(command.environment_is_cleared());
        assert_eq!(
            command.environment.get(OsStr::new("PATH")),
            Some(&OsString::from("/controlled/bin"))
        );
        assert_eq!(
            command.environment.get(OsStr::new("ML_TEST_PROJECT")),
            Some(&OsString::from("runner_test"))
        );
        assert_eq!(
            command.environment.get(OsStr::new("RUSTUP_TOOLCHAIN")),
            Some(&OsString::from("1.92.0"))
        );
        assert!(!command
            .environment
            .contains_key(OsStr::new("ML_TEST_UNKNOWN")));
    }
}

#[test]
fn discovery_mismatch_stops_before_actual_execution() {
    let mut runner = ScriptedRunner::new([CommandOutput::success(discovery(&["wrong"]))]);
    let mut gate = Gate {
        calls: 0,
        events: None,
    };
    let error = execute_with(
        Path::new("/repo"),
        &metadata(),
        TARGET,
        IDENTITY,
        [],
        &mut runner,
        &mut gate,
    )
    .unwrap_err();
    assert!(error.to_string().contains("frozen MATRIX"));
    assert_eq!(runner.seen.len(), 1);
    assert_eq!(gate.calls, 1);
}

#[test]
fn actual_child_exit_and_signal_are_propagated_without_retry() {
    for (output, expected) in [
        (CommandOutput::failure(101, "test failed\n"), 101),
        (
            CommandOutput {
                success: false,
                code: None,
                signal: Some(15),
                stdout: Vec::new(),
                stderr: b"terminated\n".to_vec(),
            },
            143,
        ),
    ] {
        let mut runner =
            ScriptedRunner::new([CommandOutput::success(discovery(&[IDENTITY])), output]);
        let mut gate = Gate {
            calls: 0,
            events: None,
        };
        let error = execute_with(
            Path::new("/repo"),
            &metadata(),
            TARGET,
            IDENTITY,
            [],
            &mut runner,
            &mut gate,
        )
        .unwrap_err();
        assert_eq!(error.exit_code(), expected);
        assert_eq!(runner.seen.len(), 2);
        assert_eq!(gate.calls, 1);
    }
}

#[test]
fn discovery_parser_requires_exact_identities_order_and_summary() {
    assert_eq!(
        parse_discovery(&discovery(&[IDENTITY])).unwrap(),
        [IDENTITY]
    );
    for malformed in [
        format!("{IDENTITY}: test\n"),
        format!("{IDENTITY}: bench\n\n1 test, 0 benchmarks\n"),
        format!("{IDENTITY}: test\n\n2 tests, 0 benchmarks\n"),
        format!("{IDENTITY}: test\n\n1 test, 1 benchmark\n"),
    ] {
        assert!(parse_discovery(malformed.as_bytes()).is_err());
    }

    let matrix = matrix::select(TARGET, IDENTITY).unwrap();
    assert!(ensure_frozen_discovery(matrix, &[IDENTITY.into()]).is_ok());
    assert!(ensure_frozen_discovery(matrix, &["wrong".into()]).is_err());

    let functional = matrix::MATRIX
        .iter()
        .find(|entry| entry.target == "functional")
        .unwrap();
    let lexical = functional
        .tests
        .iter()
        .rev()
        .map(|identity| (*identity).to_owned())
        .collect::<Vec<_>>();
    assert!(ensure_frozen_discovery(functional, &lexical).is_ok());
    assert!(ensure_frozen_discovery(
        functional,
        &functional
            .tests
            .iter()
            .map(|identity| (*identity).to_owned())
            .collect::<Vec<_>>()
    )
    .is_err());
}

#[test]
fn invalid_matrix_pair_is_rejected_before_readiness_or_cargo() {
    let mut runner = ScriptedRunner::new([]);
    let mut gate = Gate {
        calls: 0,
        events: None,
    };
    let error = execute_with(
        Path::new("/repo"),
        &metadata(),
        TARGET,
        "substring",
        [],
        &mut runner,
        &mut gate,
    )
    .unwrap_err();
    assert!(error.is_usage());
    assert_eq!(gate.calls, 0);
    assert!(runner.seen.is_empty());
}
