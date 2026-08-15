use std::collections::VecDeque;
use std::path::Path;

use anyhow::Result;

use super::*;
use crate::workflow::model::{ImageMap, PortMap, Project, ProjectSpec};

const CONTAINER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ADDRESS: &str = "bcrt1qtestaddress";

struct Gate {
    calls: usize,
}

impl ReadyGate for Gate {
    fn require_ready(&mut self, repo_root: &Path, metadata: &StackMetadata) -> Result<ProjectSpec> {
        self.calls += 1;
        Ok(spec(repo_root, metadata))
    }
}

struct ScriptedRunner {
    outputs: VecDeque<CommandOutput>,
    seen: Vec<ArgvCommand>,
}

impl ScriptedRunner {
    fn new(outputs: impl IntoIterator<Item = CommandOutput>) -> Self {
        Self {
            outputs: outputs.into_iter().collect(),
            seen: Vec::new(),
        }
    }
}

impl CommandRunner for ScriptedRunner {
    fn run(&mut self, command: &ArgvCommand) -> Result<CommandOutput> {
        self.seen.push(command.clone());
        self.outputs
            .pop_front()
            .ok_or_else(|| anyhow::anyhow!("unexpected argv command"))
    }
}

fn metadata() -> StackMetadata {
    StackMetadata::new(
        Path::new("/repo"),
        Project::parse("bootstrap_test").unwrap(),
        PortMap::from_base(24500).unwrap(),
    )
}

fn spec(_root: &Path, metadata: &StackMetadata) -> ProjectSpec {
    metadata.project_spec(
        ImageMap::new(
            metadata.project(),
            "mercurylayer/mercury-server:bip448-test-aaaaaaaaaaaaaaaa",
            "mercurylayer/token-server-v2:bip448-test-bbbbbbbbbbbbbbbb",
            "mercurylayer/lockbox:bip448-test-cccccccccccccccc",
            "mercurylayer/lockbox:bip448-test-cccccccccccccccc-rng-bootstrap_test",
        )
        .unwrap(),
    )
}

fn ok(stdout: impl Into<Vec<u8>>) -> CommandOutput {
    CommandOutput::success(stdout)
}

fn prefix() -> Vec<CommandOutput> {
    vec![
        ok(format!("{CONTAINER}\n")),
        ok(b"[]\n"),
        ok(br#"{"wallets":[]}"#),
        ok(br#"{"name":"mercury_test"}"#),
        ok(br#"["mercury_test"]"#),
    ]
}

fn hashes() -> Vec<u8> {
    serde_json::to_vec(
        &(0..101)
            .map(|index| format!("{index:064x}"))
            .collect::<Vec<_>>(),
    )
    .unwrap()
}

#[test]
fn fresh_require_zero_performs_one_exact_zero_to_101_transition() {
    let mut outputs = prefix();
    outputs.extend([
        ok(b"0.00000000\n"),
        ok(b"0\n"),
        ok(format!("{ADDRESS}\n")),
        ok(hashes()),
        ok(b"101\n"),
        ok(b"50.00000000\n"),
    ]);
    let mut runner = ScriptedRunner::new(outputs);
    let mut gate = Gate { calls: 0 };
    let report = execute_with(
        Path::new("/repo"),
        &metadata(),
        true,
        &mut runner,
        &mut gate,
    )
    .unwrap();

    assert_eq!(gate.calls, 2);
    assert_eq!(report.blocks_mined, 101);
    assert_eq!(
        (report.initial_height, report.final_height),
        (Some(0), Some(101))
    );
    assert_eq!(report.final_confirmed_spendable_balance, "50.00000000");
    assert!(runner.outputs.is_empty());
    let argv = runner
        .seen
        .iter()
        .map(|command| {
            command
                .args_slice()
                .iter()
                .map(|value| value.to_str().unwrap())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        argv.iter()
            .filter(|args| args.contains(&"generatetoaddress"))
            .count(),
        1
    );
    assert!(argv
        .iter()
        .any(|args| args.ends_with(&["getbalance", "*", "1", "false"])));
    assert!(argv
        .iter()
        .all(|args| !args.iter().any(|arg| *arg == "sh" || *arg == "-c")));
}

#[test]
fn positive_confirmed_balance_is_an_exact_no_op() {
    let outputs = [
        ok(format!("{CONTAINER}\n")),
        ok(br#"["mercury_test"]"#),
        ok(b"1.25000000\n"),
    ];
    let mut runner = ScriptedRunner::new(outputs);
    let mut gate = Gate { calls: 0 };
    let report = execute_with(
        Path::new("/repo"),
        &metadata(),
        false,
        &mut runner,
        &mut gate,
    )
    .unwrap();
    assert_eq!(gate.calls, 2);
    assert_eq!(report.blocks_mined, 0);
    assert_eq!((report.initial_height, report.final_height), (None, None));
    assert_eq!(runner.seen.len(), 3);
    assert!(runner.outputs.is_empty());
}

#[test]
fn ordinary_zero_balance_mines_once_without_a_height_shortcut() {
    let mut outputs = prefix();
    outputs.extend([
        ok(b"0\n"),
        ok(b"50\n"),
        ok(format!("{ADDRESS}\n")),
        ok(hashes()),
        ok(b"151\n"),
        ok(b"50.00000000\n"),
    ]);
    let mut runner = ScriptedRunner::new(outputs);
    let mut gate = Gate { calls: 0 };
    let report = execute_with(
        Path::new("/repo"),
        &metadata(),
        false,
        &mut runner,
        &mut gate,
    )
    .unwrap();

    assert_eq!(gate.calls, 2);
    assert_eq!(report.blocks_mined, 101);
    assert_eq!(
        (report.initial_height, report.final_height),
        (Some(50), Some(151))
    );
    assert_eq!(
        runner
            .seen
            .iter()
            .filter(|command| command
                .args_slice()
                .iter()
                .any(|arg| arg == "generatetoaddress"))
            .count(),
        1
    );
}

#[test]
fn require_zero_rejects_prefunding_without_mining_or_post_ready() {
    let outputs = [
        ok(format!("{CONTAINER}\n")),
        ok(br#"["mercury_test"]"#),
        ok(b"0.00000001\n"),
    ];
    let mut runner = ScriptedRunner::new(outputs);
    let mut gate = Gate { calls: 0 };
    let error = execute_with(
        Path::new("/repo"),
        &metadata(),
        true,
        &mut runner,
        &mut gate,
    )
    .unwrap_err();
    assert!(error.to_string().contains("pre-funded"));
    assert_eq!(gate.calls, 1);
    assert_eq!(runner.seen.len(), 3);
}

#[test]
fn malformed_negative_and_nonfinite_balances_fail_closed() {
    for value in ["", "alphabetic", "-1", "-0", "NaN", "inf"] {
        assert!(parse_balance(value).is_err(), "accepted {value:?}");
    }
    for value in ["0", "0.0", "\t0.00000000\r\n", "0.00000001", "1"] {
        assert!(parse_balance(value).is_ok(), "rejected {value:?}");
    }
}

#[test]
fn runner_failure_stops_at_the_first_substantive_error() {
    let mut runner = ScriptedRunner::new([CommandOutput::failure(125, "daemon unavailable\n")]);
    let mut gate = Gate { calls: 0 };
    let error = execute_with(
        Path::new("/repo"),
        &metadata(),
        false,
        &mut runner,
        &mut gate,
    )
    .unwrap_err();
    assert!(error.to_string().contains("daemon unavailable"));
    assert_eq!(gate.calls, 1);
    assert_eq!(runner.seen.len(), 1);
}
