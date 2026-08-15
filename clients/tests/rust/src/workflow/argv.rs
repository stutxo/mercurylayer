use std::cell::RefCell;
use std::collections::BTreeMap;
#[cfg(test)]
use std::ffi::OsStr;
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::process::{CommandExt, ExitStatusExt};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::supervision;

thread_local! {
    static FAILURE_CAPTURE: RefCell<Option<Option<ChildFailure>>> = const { RefCell::new(None) };
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ChildFailure {
    pub(super) argv: Vec<String>,
    pub(super) exit_code: Option<i32>,
    pub(super) signal: Option<i32>,
}

pub(super) fn begin_failure_capture() -> Result<()> {
    FAILURE_CAPTURE.with(|slot| {
        let mut slot = slot.borrow_mut();
        anyhow::ensure!(slot.is_none(), "child failure capture is already active");
        *slot = Some(None);
        Ok(())
    })
}

pub(super) fn finish_failure_capture() -> Option<ChildFailure> {
    FAILURE_CAPTURE.with(|slot| slot.borrow_mut().take().flatten())
}

pub(super) fn record_failure(command: &ArgvCommand, output: &CommandOutput) {
    if output.success {
        return;
    }
    FAILURE_CAPTURE.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(captured) = slot.as_mut() else {
            return;
        };
        if captured.is_none() {
            *captured = Some(ChildFailure {
                argv: command.encoded_argv(),
                exit_code: output.code,
                signal: output.signal,
            });
        }
    });
}

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

    pub(super) fn encoded_argv(&self) -> Vec<String> {
        std::iter::once(&self.program)
            .chain(self.args.iter())
            .map(|value| match value.to_str() {
                Some(value) => value.to_owned(),
                #[cfg(unix)]
                None => {
                    use std::os::unix::ffi::OsStrExt;
                    format!("hex:{}", hex::encode(value.as_bytes()))
                }
                #[cfg(not(unix))]
                None => "<non-UTF-8>".to_owned(),
            })
            .collect()
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
            .current_dir(&command.current_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        if command.clear_environment {
            process.env_clear();
        }
        let child = process
            .envs(&command.environment)
            .spawn()
            .with_context(|| format!("execute argv command {command:?}"))?;
        let mut child = SupervisedChild::new(child)?;
        let stdout = child
            .child
            .stdout
            .take()
            .context("supervised child stdout was not piped")?;
        let stderr = child
            .child
            .stderr
            .take()
            .context("supervised child stderr was not piped")?;
        let stdout = thread::Builder::new()
            .name("bip448-child-stdout".into())
            .spawn(move || drain(stdout))
            .context("spawn supervised stdout drain")?;
        let stderr = thread::Builder::new()
            .name("bip448-child-stderr".into())
            .spawn(move || drain(stderr))
            .context("spawn supervised stderr drain")?;
        let process_group = child.process_group;
        let state = supervision::active();
        let (status, forwarded) = wait(&mut child.child, process_group, state.as_deref())
            .with_context(|| format!("wait for supervised argv command {command:?}"))?;
        wait_for_process_group_exit(process_group)?;
        child.complete = true;
        let stdout = join_drain(stdout, "stdout")?;
        let stderr = join_drain(stderr, "stderr")?;
        let output = CommandOutput {
            success: forwarded.is_none() && status.success(),
            code: if forwarded.is_some() {
                None
            } else {
                status.code()
            },
            #[cfg(unix)]
            signal: forwarded.or_else(|| status.signal()),
            #[cfg(not(unix))]
            signal: None,
            stdout,
            stderr,
        };
        if forwarded.is_some() {
            record_failure(command, &output);
        }
        Ok(output)
    }
}

struct SupervisedChild {
    child: Child,
    process_group: i32,
    complete: bool,
}

impl SupervisedChild {
    fn new(mut child: Child) -> Result<Self> {
        let process_group = match i32::try_from(child.id()) {
            Ok(value) => value,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error).context("supervised child PID exceeds i32");
            }
        };
        Ok(Self {
            child,
            process_group,
            complete: false,
        })
    }
}

impl Drop for SupervisedChild {
    fn drop(&mut self) {
        if self.complete {
            return;
        }
        // Fail closed after an internal supervision error. An incoming SIGKILL
        // cannot be handled, forwarded, or represented as durable evidence.
        unsafe {
            kill(-self.process_group, SIGKILL);
        }
        let _ = self.child.wait();
        let _ = wait_for_process_group_exit(self.process_group);
    }
}

fn wait(
    child: &mut std::process::Child,
    process_group: i32,
    state: Option<&supervision::SignalState>,
) -> Result<(ExitStatus, Option<i32>)> {
    let mut forwarded = None;
    loop {
        forward_received(state, process_group, &mut forwarded)?;
        if let Some(status) = child.try_wait().context("poll supervised child")? {
            forward_received(state, process_group, &mut forwarded)?;
            return Ok((status, forwarded));
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn forward_received(
    state: Option<&supervision::SignalState>,
    process_group: i32,
    forwarded: &mut Option<i32>,
) -> Result<()> {
    if forwarded.is_some() {
        return Ok(());
    }
    let Some((state, signal)) =
        state.and_then(|state| state.received().map(|signal| (state, signal)))
    else {
        return Ok(());
    };
    signal_process_group(process_group, signal)?;
    state.mark_forwarded(signal);
    *forwarded = Some(signal);
    Ok(())
}

fn drain(mut pipe: impl Read) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    pipe.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn join_drain(handle: thread::JoinHandle<std::io::Result<Vec<u8>>>, name: &str) -> Result<Vec<u8>> {
    handle
        .join()
        .map_err(|_| anyhow::anyhow!("supervised {name} drain panicked"))?
        .with_context(|| format!("drain supervised child {name}"))
}

fn signal_process_group(process_group: i32, signal: i32) -> Result<()> {
    let result = unsafe { kill(-process_group, signal) };
    if result == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(ESRCH) {
        return Ok(());
    }
    Err(error).with_context(|| {
        format!("forward signal {signal} to supervised process group {process_group}")
    })
}

fn wait_for_process_group_exit(process_group: i32) -> Result<()> {
    loop {
        let result = unsafe { kill(-process_group, 0) };
        if result == 0 {
            thread::sleep(Duration::from_millis(5));
            continue;
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(ESRCH) {
            return Ok(());
        }
        return Err(error).with_context(|| {
            format!("verify supervised process group {process_group} has exited")
        });
    }
}

const ESRCH: i32 = 3;
const SIGKILL: i32 = 9;

unsafe extern "C" {
    fn kill(pid: i32, signal: i32) -> i32;
}
