use std::collections::BTreeMap;
#[cfg(test)]
use std::ffi::OsStr;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;

use anyhow::{Context, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ArgvCommand {
    pub(super) program: OsString,
    pub(super) args: Vec<OsString>,
    pub(super) current_dir: PathBuf,
    pub(super) environment: BTreeMap<OsString, OsString>,
    pub(super) clear_environment: bool,
}

impl ArgvCommand {
    pub(super) fn new(program: impl Into<OsString>, current_dir: &Path) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            current_dir: current_dir.to_path_buf(),
            environment: BTreeMap::new(),
            clear_environment: false,
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

    pub(super) fn envs<I, K, V>(mut self, environment: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<OsString>,
        V: Into<OsString>,
    {
        self.environment.extend(
            environment
                .into_iter()
                .map(|(name, value)| (name.into(), value.into())),
        );
        self
    }

    pub(super) fn clear_environment(mut self) -> Self {
        self.clear_environment = true;
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

    #[cfg(test)]
    pub(super) fn environment_is_cleared(&self) -> bool {
        self.clear_environment
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CommandOutput {
    pub(super) success: bool,
    pub(super) code: Option<i32>,
    pub(super) signal: Option<i32>,
    pub(super) stdout: Vec<u8>,
    pub(super) stderr: Vec<u8>,
}

impl CommandOutput {
    #[cfg(test)]
    pub(super) fn success(stdout: impl Into<Vec<u8>>) -> Self {
        Self {
            success: true,
            code: Some(0),
            signal: None,
            stdout: stdout.into(),
            stderr: Vec::new(),
        }
    }

    #[cfg(test)]
    pub(super) fn failure(code: i32, stderr: impl Into<Vec<u8>>) -> Self {
        Self {
            success: false,
            code: Some(code),
            signal: None,
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
        let mut process = Command::new(&command.program);
        process
            .args(&command.args)
            .current_dir(&command.current_dir);
        if command.clear_environment {
            process.env_clear();
        }
        let output = process
            .envs(&command.environment)
            .output()
            .with_context(|| format!("execute argv command {command:?}"))?;
        Ok(CommandOutput {
            success: output.status.success(),
            code: output.status.code(),
            #[cfg(unix)]
            signal: output.status.signal(),
            #[cfg(not(unix))]
            signal: None,
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}
