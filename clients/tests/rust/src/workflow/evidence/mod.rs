mod incomplete;
mod readout;
mod record;
mod store;

#[cfg(test)]
mod tests;

use std::path::Path;

use anyhow::Context;

use super::argv::{begin_failure_capture, finish_failure_capture};
use super::cli::Command;
use super::error::WorkflowError;
use super::matrix::MATRIX;
use super::model::Project;
use super::model::StackMetadata;
use super::project_lock::ProjectLock;
use super::supervision;

pub(super) fn capture_test_output(stdout: &[u8], stderr: &[u8]) {
    store::capture_test_output(stdout, stderr);
}

pub(super) struct MatrixTargetOperation {
    operation: store::Operation,
}

impl MatrixTargetOperation {
    pub(super) fn start(
        repo_root: &Path,
        project: &Project,
        target: &str,
        tests: &[&str],
    ) -> Result<Self, WorkflowError> {
        let source = store::source_identity(repo_root)
            .context("capture source for first-invocation MATRIX binary record")?;
        let mut arguments = vec!["--target".into(), target.into()];
        for test in tests {
            arguments.push("--test".into());
            arguments.push((*test).into());
        }
        let operation = store::Operation::start_auxiliary(
            repo_root,
            project,
            "verify-matrix-target",
            arguments,
            source,
            false,
        )
        .context("start complete first-invocation MATRIX binary record")?;
        Ok(Self { operation })
    }

    pub(super) fn finish<T>(self, action: Result<T, WorkflowError>) -> Result<T, WorkflowError> {
        let finalization = self.operation.finish_generic(&action, None);
        store::combine_generic(action, finalization)
    }
}

pub(super) fn require_complete_matrix_records(
    repo_root: &Path,
    project: &Project,
) -> anyhow::Result<()> {
    let records = readout::scan(repo_root, project)?
        .into_iter()
        .filter(|summary| {
            summary
                .started
                .as_ref()
                .is_some_and(|started| started.command == "verify-matrix-target")
        })
        .collect::<Vec<_>>();
    anyhow::ensure!(
        records.len() == MATRIX.len(),
        "authoritative evidence has {} MATRIX target records instead of {}",
        records.len(),
        MATRIX.len()
    );
    for target in MATRIX {
        let mut expected_arguments = vec!["--target".to_owned(), target.target.to_owned()];
        for test in target.tests {
            expected_arguments.push("--test".into());
            expected_arguments.push((*test).into());
        }
        let matches = records
            .iter()
            .filter(|summary| {
                summary
                    .started
                    .as_ref()
                    .is_some_and(|started| started.arguments == expected_arguments)
            })
            .collect::<Vec<_>>();
        anyhow::ensure!(
            matches.len() == 1,
            "MATRIX target {} lacks one exact first-invocation evidence record",
            target.target
        );
        let result = matches[0]
            .result
            .as_ref()
            .context("MATRIX target evidence record is incomplete")?;
        anyhow::ensure!(
            result.outcome.kind == record::OutcomeKind::Success
                && result.outcome.exit_code == Some(0)
                && result.outcome.signal.is_none(),
            "MATRIX target {} evidence is not a canonical success",
            target.target
        );
    }
    Ok(())
}

pub(super) fn execute_mutation(
    repo_root: &Path,
    command: &Command,
    raw_arguments: &[String],
    action: impl FnOnce(&str) -> Result<String, WorkflowError>,
) -> Result<String, WorkflowError> {
    let (project, name) = command
        .mutation()
        .context("non-mutating command passed to evidence executor")?;
    if raw_arguments.first().map(String::as_str) != Some(name) {
        return Err(WorkflowError::from(anyhow::anyhow!(
            "raw command does not match parsed mutation"
        )));
    }
    let source = store::source_identity(repo_root)
        .context("capture clean operation source before project lock")?;
    let _lock =
        ProjectLock::acquire(repo_root, project).context("serialize BIP448 project mutation")?;
    incomplete::reject_mutation(repo_root, project, name)?;
    let operation = store::Operation::start(
        repo_root,
        project,
        name,
        raw_arguments[1..].to_vec(),
        source,
        name == "configure",
    )
    .context("start durable operation evidence")?;
    begin_failure_capture().map_err(WorkflowError::from)?;
    let rechecked = store::source_identity(repo_root)
        .context("recheck operation source after project lock and started record");
    let action = match rechecked {
        Ok(current) if &current == operation.source() => action(operation.operation_id()),
        Ok(_) => Err(WorkflowError::from(anyhow::anyhow!(
            "source changed while waiting for the project workflow lock"
        ))),
        Err(error) => Err(WorkflowError::from(error)),
    };
    let child = finish_failure_capture();
    let action = promote_forwarded_signal(action, child.as_ref());
    let finalization = operation.finish(&action, child);
    store::combine_action_and_finalization(action, finalization)
}

pub(super) fn execute_authoritative(
    repo_root: &Path,
    primary: &Project,
    control: &Project,
    raw_arguments: &[String],
    action: impl FnOnce(&str, &str) -> Result<String, WorkflowError>,
) -> Result<String, WorkflowError> {
    if raw_arguments.first().map(String::as_str) != Some("verify") {
        return Err(WorkflowError::from(anyhow::anyhow!(
            "raw command does not match authoritative verify"
        )));
    }
    let source = store::source_identity(repo_root)
        .context("capture clean authoritative source before project locks")?;
    let (first, second) = if primary.as_str() < control.as_str() {
        (primary, control)
    } else {
        (control, primary)
    };
    let _first_lock =
        ProjectLock::acquire(repo_root, first).context("serialize first paired BIP448 project")?;
    let _second_lock = ProjectLock::acquire(repo_root, second)
        .context("serialize second paired BIP448 project")?;
    incomplete::reject_mutation(repo_root, primary, "verify")?;
    incomplete::reject_mutation(repo_root, control, "verify")?;

    let control_arguments = vec![
        "--primary-project".into(),
        primary.to_string(),
        "--control-project".into(),
        control.to_string(),
    ];
    let control_operation = store::Operation::start_auxiliary(
        repo_root,
        control,
        "verify-control",
        control_arguments,
        source.clone(),
        true,
    )
    .context("start durable control-project verification evidence")?;
    let primary_operation = match store::Operation::start(
        repo_root,
        primary,
        "verify",
        raw_arguments[1..].to_vec(),
        source,
        true,
    ) {
        Ok(operation) => operation,
        Err(error) => {
            let failure = Err(WorkflowError::from(
                error.context("start durable primary verification evidence"),
            ));
            let finalization = control_operation.finish(&failure, None);
            return store::combine_action_and_finalization(failure, finalization);
        }
    };

    begin_failure_capture().map_err(WorkflowError::from)?;
    let rechecked = store::source_identity(repo_root)
        .context("recheck authoritative source after paired locks and started records");
    let result = match rechecked {
        Ok(current) if &current == primary_operation.source() => action(
            primary_operation.operation_id(),
            control_operation.operation_id(),
        ),
        Ok(_) => Err(WorkflowError::from(anyhow::anyhow!(
            "source changed while waiting for paired workflow locks"
        ))),
        Err(error) => Err(WorkflowError::from(error)),
    };
    let child = finish_failure_capture();
    let result = promote_forwarded_signal(result, child.as_ref());
    let primary_finalization = primary_operation.finish(&result, child.clone());
    let control_finalization = control_operation.finish(&result, child);
    let finalization = match (primary_finalization, control_finalization) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(primary_error), Err(control_error)) => Err(anyhow::anyhow!(
            "primary evidence finalization failed: {primary_error:#}; control evidence finalization also failed: {control_error:#}"
        )),
    };
    store::combine_action_and_finalization(result, finalization)
}

fn promote_forwarded_signal(
    action: Result<String, WorkflowError>,
    child: Option<&super::argv::ChildFailure>,
) -> Result<String, WorkflowError> {
    let Some(signal) = supervision::forwarded_signal() else {
        return action;
    };
    if child.is_some_and(|failure| failure.signal == Some(signal)) {
        return Err(WorkflowError::child_exit(
            128 + signal,
            format!(
                "workflow interrupted by signal {signal} while a child process group was active"
            ),
        ));
    }
    action
}

pub(super) fn checkpoint(repo_root: &Path, metadata: &StackMetadata) -> anyhow::Result<String> {
    readout::checkpoint(repo_root, metadata)
}

pub(super) fn logs(repo_root: &Path, metadata: &StackMetadata) -> anyhow::Result<String> {
    readout::logs(repo_root, metadata)
}
