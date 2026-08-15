mod execute;
mod fingerprint;
mod inputs;
mod plan;

#[cfg(test)]
mod execute_tests;
#[cfg(test)]
mod fingerprint_tests;
#[cfg(test)]
mod plan_tests;
#[cfg(test)]
mod test_support;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use super::cli::BuildService;
use super::model::StackMetadata;

const INQUISITION_COMMIT: &str = "f5365867662091c2dbf1b2d438b8bb477a3dcb6f";
const INQUISITION_BUILD_ARG: &str = "BITCOIN_INQUISITION_COMMIT";
const LOCKBOX_BUILD_ARG: &str = "LOCKBOX_ENABLE_TEST_RNG";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ArgvCommand {
    program: OsString,
    args: Vec<OsString>,
    current_dir: PathBuf,
}

impl ArgvCommand {
    fn new(program: impl Into<OsString>, current_dir: &Path) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            current_dir: current_dir.to_path_buf(),
        }
    }

    fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CommandOutput {
    success: bool,
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

pub(super) trait CommandRunner {
    fn run(&mut self, command: &ArgvCommand) -> Result<CommandOutput>;
}

pub(super) struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&mut self, command: &ArgvCommand) -> Result<CommandOutput> {
        let output = Command::new(&command.program)
            .args(&command.args)
            .current_dir(&command.current_dir)
            .output()
            .with_context(|| format!("execute argv command {command:?}"))?;
        Ok(CommandOutput {
            success: output.status.success(),
            code: output.status.code(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

pub(super) fn execute(
    repo_root: &Path,
    metadata: &StackMetadata,
    service: BuildService,
    runner: &mut impl CommandRunner,
) -> Result<StackMetadata> {
    execute::execute(repo_root, metadata, service, runner)
}

fn run_checked(runner: &mut impl CommandRunner, command: ArgvCommand) -> Result<CommandOutput> {
    let output = runner.run(&command)?;
    if !output.success {
        bail!(
            "argv command {command:?} failed with status {:?}: stdout={} stderr={}",
            output.code,
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output)
}
