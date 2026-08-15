use std::collections::BTreeMap;
#[cfg(test)]
use std::ffi::OsStr;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ArgvCommand {
    pub(super) program: OsString,
    pub(super) args: Vec<OsString>,
    pub(super) current_dir: PathBuf,
    pub(super) environment: BTreeMap<OsString, OsString>,
}

impl ArgvCommand {
    pub(super) fn new(program: impl Into<OsString>, current_dir: &Path) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            current_dir: current_dir.to_path_buf(),
            environment: BTreeMap::new(),
        }
    }

    pub(super) fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub(super) fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    pub(super) fn env(mut self, name: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.environment.insert(name.into(), value.into());
        self
    }

    #[cfg(test)]
    pub(super) fn program(&self) -> &OsStr {
        &self.program
    }

    #[cfg(test)]
    pub(super) fn args_slice(&self) -> &[OsString] {
        &self.args
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CommandOutput {
    pub(super) success: bool,
    pub(super) code: Option<i32>,
    pub(super) stdout: Vec<u8>,
    pub(super) stderr: Vec<u8>,
}

impl CommandOutput {
    #[cfg(test)]
    pub(super) fn success(stdout: impl Into<Vec<u8>>) -> Self {
        Self {
            success: true,
            code: Some(0),
            stdout: stdout.into(),
            stderr: Vec::new(),
        }
    }

    #[cfg(test)]
    pub(super) fn failure(code: i32, stderr: impl Into<Vec<u8>>) -> Self {
        Self {
            success: false,
            code: Some(code),
            stdout: Vec::new(),
            stderr: stderr.into(),
        }
    }
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
            .envs(&command.environment)
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
