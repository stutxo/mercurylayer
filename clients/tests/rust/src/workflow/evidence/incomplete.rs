use std::path::Path;

use anyhow::Context;

use super::super::error::WorkflowError;
use super::super::model::Project;

pub(super) fn reject_mutation(
    repo_root: &Path,
    project: &Project,
    command: &str,
) -> Result<(), WorkflowError> {
    let incomplete = super::readout::scan(repo_root, project)
        .context("scan existing operation evidence before mutation")?
        .into_iter()
        .filter(|record| record.incomplete && record.started.is_some())
        .map(|record| record.operation_id)
        .collect::<Vec<_>>();
    if command != "down" && !incomplete.is_empty() {
        return Err(WorkflowError::from(anyhow::anyhow!(
            "incomplete prior operation evidence blocks {command}: {}; only read-only diagnostics and down are allowed until explicit reset",
            incomplete.join(",")
        )));
    }
    Ok(())
}
