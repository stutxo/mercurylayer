#[path = "test_runner_reconcile.rs"]
mod reconcile;
#[cfg(test)]
#[path = "test_runner_tests.rs"]
mod tests;

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::Path;

use anyhow::{ensure, Context, Result};
use serde::Serialize;

use super::argv::{ArgvCommand, CommandOutput, CommandRunner, SystemCommandRunner};
use super::error::WorkflowError;
use super::matrix::{self, MatrixTarget};
use super::model::{canonical_json, ProjectSpec, StackMetadata};
use super::ready_gate::{LiveReadyGate, ReadyGate};
pub(super) use reconcile::{RngAdoptionRecord, RNG_RECONCILIATION_TARGET, RNG_RECONCILIATION_TEST};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct TestReport {
    project: String,
    target: String,
    test: String,
    status: String,
    stdout: String,
    stderr: String,
    rng_adoption: Option<RngAdoptionRecord>,
}

pub(super) struct TestExecution {
    pub(super) output: String,
    pub(super) metadata: StackMetadata,
    pub(super) rng_adoption: Option<RngAdoptionRecord>,
}

pub(super) fn execute(
    repo_root: &Path,
    metadata: &StackMetadata,
    target: &str,
    identity: &str,
) -> Result<TestExecution, WorkflowError> {
    let mut runner = SystemCommandRunner;
    let mut gate = LiveReadyGate;
    let inherited = std::env::vars_os().collect::<Vec<_>>();
    let execution = execute_with(
        repo_root,
        metadata,
        target,
        identity,
        inherited,
        &mut runner,
        &mut gate,
    )?;
    let output = canonical_json(&execution.report).map_err(WorkflowError::from)?;
    Ok(TestExecution {
        output,
        metadata: execution.metadata,
        rng_adoption: execution.rng_adoption,
    })
}

#[derive(Debug)]
struct TestExecutionInner {
    report: TestReport,
    metadata: StackMetadata,
    rng_adoption: Option<RngAdoptionRecord>,
}

fn execute_with<R, G, I>(
    repo_root: &Path,
    metadata: &StackMetadata,
    target: &str,
    identity: &str,
    inherited: I,
    runner: &mut R,
    gate: &mut G,
) -> Result<TestExecutionInner, WorkflowError>
where
    R: CommandRunner,
    G: ReadyGate,
    I: IntoIterator<Item = (OsString, OsString)>,
{
    let matrix = matrix::select(target, identity).map_err(WorkflowError::usage)?;
    let spec = gate
        .require_ready(repo_root, metadata)
        .context("require exact ready stack before BIP448 test")?;
    let environment = sanitized_environment(inherited, &spec)?;

    let discovery = runner.run(&cargo_discovery(repo_root, target, &environment)?)?;
    if !discovery.success {
        super::argv::record_failure(
            &cargo_discovery(repo_root, target, &environment)?,
            &discovery,
        );
        return Err(child_failure("Cargo ignored-test discovery", &discovery));
    }
    ensure_success_status(&discovery, "Cargo ignored-test discovery")?;
    let discovered = parse_discovery(&discovery.stdout)?;
    ensure_frozen_discovery(matrix, &discovered)?;

    let output = runner.run(&cargo_test(repo_root, target, identity, &environment)?)?;
    super::evidence::capture_test_output(&output.stdout, &output.stderr);
    if !output.success {
        super::argv::record_failure(
            &cargo_test(repo_root, target, identity, &environment)?,
            &output,
        );
        return Err(child_failure("exact BIP448 Cargo test", &output));
    }
    ensure_success_status(&output, "exact BIP448 Cargo test")?;
    let boundary = reconcile::after_success(repo_root, metadata, target, identity, runner, gate)?;

    let report = TestReport {
        project: boundary.metadata.project().to_string(),
        target: target.into(),
        test: identity.into(),
        status: "passed".into(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        rng_adoption: boundary.adoption.clone(),
    };
    Ok(TestExecutionInner {
        report,
        metadata: boundary.metadata,
        rng_adoption: boundary.adoption,
    })
}

fn cargo_discovery(
    repo_root: &Path,
    target: &str,
    environment: &BTreeMap<OsString, OsString>,
) -> Result<ArgvCommand> {
    Ok(cargo_command(repo_root, environment).args([
        "test",
        "--locked",
        "--test",
        target,
        "--",
        "--ignored",
        "--list",
    ]))
}

fn cargo_test(
    repo_root: &Path,
    target: &str,
    identity: &str,
    environment: &BTreeMap<OsString, OsString>,
) -> Result<ArgvCommand> {
    Ok(cargo_command(repo_root, environment).args([
        "test",
        "--locked",
        "--test",
        target,
        identity,
        "--",
        "--ignored",
        "--exact",
        "--nocapture",
        "--test-threads=1",
    ]))
}

fn cargo_command(repo_root: &Path, environment: &BTreeMap<OsString, OsString>) -> ArgvCommand {
    ArgvCommand::new("cargo", &repo_root.join("clients/tests/rust"))
        .clear_environment()
        .envs(environment.clone())
}

fn sanitized_environment<I>(
    inherited: I,
    spec: &ProjectSpec,
) -> Result<BTreeMap<OsString, OsString>>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    let mut environment = inherited
        .into_iter()
        .filter(|(name, _)| !is_managed_name(name))
        .collect::<BTreeMap<_, _>>();
    let managed = spec.managed_environment()?;
    ensure!(
        managed.len() == 24,
        "ProjectSpec did not produce the exact 24-variable managed environment"
    );
    environment.extend(
        managed
            .into_iter()
            .map(|(name, value)| (OsString::from(name), OsString::from(value))),
    );
    Ok(environment)
}

fn is_managed_name(name: &OsStr) -> bool {
    if let Some(name) = name.to_str() {
        return name.starts_with("ML_TEST_")
            || matches!(
                name,
                "COMPOSE_PROJECT_NAME" | "ML_SETTINGS_FILE" | "ML_NETWORK" | "RUSTUP_TOOLCHAIN"
            );
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let name = name.as_bytes();
        name.starts_with(b"ML_TEST_")
            || [
                b"COMPOSE_PROJECT_NAME".as_slice(),
                b"ML_SETTINGS_FILE".as_slice(),
                b"ML_NETWORK".as_slice(),
                b"RUSTUP_TOOLCHAIN".as_slice(),
            ]
            .contains(&name)
    }
    #[cfg(not(unix))]
    {
        false
    }
}

fn parse_discovery(stdout: &[u8]) -> Result<Vec<String>> {
    let stdout = std::str::from_utf8(stdout).context("Cargo test discovery output is not UTF-8")?;
    let mut lines = stdout
        .lines()
        .map(|line| line.trim_end_matches('\r'))
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let summary = lines
        .pop()
        .context("Cargo test discovery output has no libtest summary")?;
    let identities = lines
        .into_iter()
        .map(|line| {
            let identity = line
                .strip_suffix(": test")
                .context("Cargo test discovery contains a malformed identity line")?;
            ensure!(
                !identity.is_empty(),
                "Cargo test discovery contains an empty identity"
            );
            Ok(identity.to_owned())
        })
        .collect::<Result<Vec<_>>>()?;
    let noun = if identities.len() == 1 {
        "test"
    } else {
        "tests"
    };
    ensure!(
        summary == format!("{} {noun}, 0 benchmarks", identities.len()),
        "Cargo test discovery summary does not match the parsed ignored inventory"
    );
    Ok(identities)
}

fn ensure_frozen_discovery(matrix: &MatrixTarget, discovered: &[String]) -> Result<()> {
    // libtest's --list output is lexical, while MATRIX keeps the reviewed
    // scenario order. Derive the list order from MATRIX instead of maintaining
    // a second inventory.
    let mut expected = matrix.tests.iter().copied().collect::<Vec<_>>();
    expected.sort_unstable();
    let actual = discovered.iter().map(String::as_str).collect::<Vec<_>>();
    ensure!(
        actual == expected,
        "ignored test discovery for {} differs from its frozen MATRIX identities or order: expected {expected:?}, found {actual:?}",
        matrix.target
    );
    Ok(())
}

fn ensure_success_status(output: &CommandOutput, context: &str) -> Result<()> {
    ensure!(
        output.code == Some(0) && output.signal.is_none(),
        "{context} returned an inconsistent success status"
    );
    Ok(())
}

fn child_failure(context: &str, output: &CommandOutput) -> WorkflowError {
    let code = propagated_exit(output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    WorkflowError::child_exit(
        code,
        format!(
            "{context} failed with exit {code}\n--- child stdout ---\n{stdout}\n--- child stderr ---\n{stderr}"
        ),
    )
}

fn propagated_exit(output: &CommandOutput) -> i32 {
    match (output.code, output.signal) {
        (Some(code @ 1..=255), None) => code,
        (None, Some(signal @ 1..=127)) => 128 + signal,
        _ => 1,
    }
}
