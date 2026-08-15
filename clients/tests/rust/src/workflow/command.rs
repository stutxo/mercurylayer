use anyhow::Context;

use super::bootstrap;
use super::build::{self, SystemCommandRunner};
use super::cli::Command;
use super::doctor;
use super::error::WorkflowError;
use super::lifecycle;
use super::model::canonical_json;
use super::repository;
use super::storage;
use super::test_runner;
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
        Command::Build { project, service } => {
            let root = repository::active_root()?;
            let metadata = storage::status(&root, &project)
                .context("read configured BIP448 build metadata")?;
            let mut runner = SystemCommandRunner;
            let updated = build::execute(&root, &metadata, service, &mut runner)
                .context("build BIP448 test images")?;
            storage::replace_metadata(&root, &project, &metadata, &updated)
                .context("commit BIP448 build metadata")?;
            canonical_json(&updated).map_err(WorkflowError::from)
        }
        Command::Up { project } => {
            let root = repository::active_root()?;
            let metadata = storage::status(&root, &project)
                .context("read configured BIP448 lifecycle metadata")?;
            canonical_json(&lifecycle::up(&root, &metadata)?).map_err(WorkflowError::from)
        }
        Command::Ready { project } => {
            let root = repository::active_root()?;
            let metadata = storage::status(&root, &project)
                .context("read configured BIP448 lifecycle metadata")?;
            canonical_json(&lifecycle::ready(&root, &metadata)?).map_err(WorkflowError::from)
        }
        Command::Status { project } => {
            let root = repository::active_root()?;
            let metadata =
                storage::status(&root, &project).context("read BIP448 test workflow status")?;
            canonical_json(&lifecycle::status(&root, &metadata)?).map_err(WorkflowError::from)
        }
        Command::Down { project } => {
            let root = repository::active_root()?;
            let metadata = storage::status(&root, &project)
                .context("read configured BIP448 lifecycle metadata")?;
            canonical_json(&lifecycle::down(&root, &metadata)?).map_err(WorkflowError::from)
        }
        Command::Bootstrap {
            project,
            require_zero,
        } => {
            let root = repository::active_root()?;
            let metadata = storage::status(&root, &project)
                .context("read configured BIP448 bootstrap metadata")?;
            bootstrap::execute(&root, &metadata, require_zero)
        }
        Command::Test {
            project,
            target,
            test,
        } => {
            let root = repository::active_root()?;
            let metadata =
                storage::status(&root, &project).context("read configured BIP448 test metadata")?;
            test_runner::execute(&root, &metadata, &target, &test)
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
