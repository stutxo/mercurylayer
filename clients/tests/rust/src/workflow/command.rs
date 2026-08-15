use anyhow::Context;

use super::cli::Command;
use super::doctor;
use super::error::WorkflowError;
use super::model::canonical_json;
use super::repository;
use super::storage;
use super::USAGE;

pub async fn execute(command: Command) -> Result<String, WorkflowError> {
    match command {
        Command::Help => Ok(format!("{USAGE}\n")),
        Command::Doctor => {
            let root = repository::active_root()?;
            canonical_json(&doctor::run(&root)?).map_err(WorkflowError::from)
        }
        Command::Configure { project, ports } => {
            let root = repository::active_root()?;
            let metadata = storage::configure(&root, project, ports)
                .context("configure BIP448 test workflow")?;
            canonical_json(&metadata).map_err(WorkflowError::from)
        }
        Command::Status { project } => {
            let root = repository::active_root()?;
            let metadata =
                storage::status(&root, &project).context("read BIP448 test workflow status")?;
            canonical_json(&metadata).map_err(WorkflowError::from)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn help_is_stable_and_does_not_touch_the_repository() {
        assert_eq!(execute(Command::Help).await.unwrap(), format!("{USAGE}\n"));
    }
}
