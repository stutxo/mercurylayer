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
use super::model::StackMetadata;
use super::project_lock::ProjectLock;
use super::supervision;

pub(super) fn capture_test_output(stdout: &[u8], stderr: &[u8]) {
    store::capture_test_output(stdout, stderr);
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
