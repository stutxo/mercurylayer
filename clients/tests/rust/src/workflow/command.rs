use anyhow::Context;

use super::bootstrap;
use super::build::{self, SystemCommandRunner};
use super::cli::Command;
use super::doctor;
use super::error::WorkflowError;
use super::evidence;
use super::lifecycle;
use super::model::canonical_json;
use super::repository;
use super::storage;
use super::test_runner;
use super::USAGE;

pub async fn execute(command: Command, raw_arguments: &[String]) -> Result<String, WorkflowError> {
    if command.mutation().is_some() {
        let root = repository::active_root()?;
        let owned = command.clone();
        return evidence::execute_mutation(&root, &command, raw_arguments, |operation_id| {
            execute_mutation(&root, owned, operation_id)
        });
    }
    match command {
        Command::Help => Ok(format!("{USAGE}\n")),
        Command::Doctor => {
            let root = repository::active_root()?;
            canonical_json(&doctor::run(&root)?).map_err(WorkflowError::from)
        }
        Command::Configure { .. }
        | Command::Build { .. }
        | Command::Up { .. }
        | Command::Down { .. }
        | Command::Bootstrap { .. }
        | Command::Test { .. } => unreachable!("mutations are dispatched through evidence"),
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
        Command::Checkpoint { project } => {
            let root = repository::active_root()?;
            let metadata = storage::status(&root, &project)
                .context("read configured BIP448 checkpoint metadata")?;
            evidence::checkpoint(&root, &metadata).map_err(WorkflowError::from)
        }
        Command::Logs { project } => {
            let root = repository::active_root()?;
            let metadata =
                storage::status(&root, &project).context("read configured BIP448 logs metadata")?;
            evidence::logs(&root, &metadata).map_err(WorkflowError::from)
        }
    }
}

fn execute_mutation(
    root: &std::path::Path,
    command: Command,
    operation_id: &str,
) -> Result<String, WorkflowError> {
    match command {
        Command::Configure { project, ports } => {
            let metadata = storage::configure_prepared(root, project, ports, operation_id)
                .context("configure BIP448 test workflow")?;
            canonical_json(&metadata).map_err(WorkflowError::from)
        }
        Command::Build { project, service } => {
            let metadata =
                storage::status(root, &project).context("read configured BIP448 build metadata")?;
            let mut runner = SystemCommandRunner;
            let updated = build::execute(root, &metadata, service, &mut runner)
                .context("build BIP448 test images")?;
            storage::replace_metadata(root, &project, &metadata, &updated)
                .context("commit BIP448 build metadata")?;
            canonical_json(&updated).map_err(WorkflowError::from)
        }
        Command::Up { project } => {
            let metadata = storage::status(root, &project)
                .context("read configured BIP448 lifecycle metadata")?;
            canonical_json(&lifecycle::up(root, &metadata)?).map_err(WorkflowError::from)
        }
        Command::Down { project } => {
            let metadata = storage::status(root, &project)
                .context("read configured BIP448 lifecycle metadata")?;
            canonical_json(&lifecycle::down(root, &metadata)?).map_err(WorkflowError::from)
        }
        Command::Bootstrap {
            project,
            require_zero,
        } => {
            let metadata = storage::status(root, &project)
                .context("read configured BIP448 bootstrap metadata")?;
            bootstrap::execute(root, &metadata, require_zero)
        }
        Command::Test {
            project,
            target,
            test,
        } => {
            let metadata =
                storage::status(root, &project).context("read configured BIP448 test metadata")?;
            test_runner::execute(root, &metadata, &target, &test)
        }
        _ => unreachable!("only mutations reach mutation dispatcher"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn help_is_stable_and_does_not_touch_the_repository() {
        assert_eq!(
            execute(Command::Help, &["--help".into()]).await.unwrap(),
            format!("{USAGE}\n")
        );
    }
}
