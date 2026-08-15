use std::cell::RefCell;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::super::argv::{ArgvCommand, ChildFailure, CommandRunner, SystemCommandRunner};
use super::super::error::WorkflowError;
use super::super::model::{canonical_json, Project, RunPaths};
use super::super::project_lock::{effective_uid, validate_owned_directory};
use super::record::{
    Clock, Outcome, OutcomeKind, ResultRecord, SourceIdentity, StartedRecord, StoredLog,
    SystemClock, TestLogs, EVIDENCE_VERSION, MAX_CONTROLLER_ERROR_BYTES,
};

const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;

thread_local! {
    static TEST_OUTPUT: RefCell<Option<Option<(Vec<u8>, Vec<u8>)>>> = const { RefCell::new(None) };
}

pub(super) trait IdSource {
    fn next_id(&mut self) -> String;
}

struct UuidSource;

impl IdSource for UuidSource {
    fn next_id(&mut self) -> String {
        Uuid::new_v4().to_string()
    }
}

pub(super) struct Operation {
    directory: PathBuf,
    started: StartedRecord,
}

impl Operation {
    pub(super) fn start(
        repo_root: &Path,
        project: &Project,
        command: &str,
        arguments: Vec<String>,
        source: SourceIdentity,
        configure: bool,
    ) -> Result<Self> {
        let mut clock = SystemClock;
        let mut ids = UuidSource;
        Self::start_with(
            repo_root, project, command, arguments, source, configure, &mut clock, &mut ids,
        )
    }

    pub(super) fn start_with(
        repo_root: &Path,
        project: &Project,
        command: &str,
        arguments: Vec<String>,
        source: SourceIdentity,
        configure: bool,
        clock: &mut impl Clock,
        ids: &mut impl IdSource,
    ) -> Result<Self> {
        source.validate()?;
        let owner = effective_uid()?;
        let paths = RunPaths::new(repo_root, project);
        prepare_run_tree(&paths, configure, owner)?;
        let operations = paths.run_directory.join("operations");
        ensure_private_directory(&operations, owner, true)?;

        let (operation_id, directory) = (0..8)
            .find_map(|_| {
                let id = ids.next_id();
                if validate_operation_id(&id).is_err() {
                    return Some(Err(anyhow::anyhow!(
                        "operation ID source returned a malformed UUID"
                    )));
                }
                let directory = operations.join(&id);
                match DirBuilder::new().mode(DIRECTORY_MODE).create(&directory) {
                    Ok(()) => Some(Ok((id, directory))),
                    Err(error) if error.kind() == ErrorKind::AlreadyExists => None,
                    Err(error) => Some(Err(error).with_context(|| {
                        format!(
                            "create operation evidence directory {}",
                            directory.display()
                        )
                    })),
                }
            })
            .transpose()?
            .context("could not allocate a collision-free operation ID")?;
        validate_private(&directory, FileKind::Directory, owner, DIRECTORY_MODE)?;
        let started = StartedRecord {
            version: EVIDENCE_VERSION,
            operation_id,
            project: project.to_string(),
            command: command.to_owned(),
            arguments,
            source,
            started_at: clock.now_utc()?,
        };
        started.validate(&started.operation_id, project.as_str())?;
        atomic_write_new(
            &directory.join("started.json"),
            canonical_json(&started)?.as_bytes(),
        )?;
        begin_test_capture()?;
        Ok(Self { directory, started })
    }

    pub(super) fn operation_id(&self) -> &str {
        &self.started.operation_id
    }

    pub(super) fn source(&self) -> &SourceIdentity {
        &self.started.source
    }

    pub(super) fn finish(
        self,
        action: &Result<String, WorkflowError>,
        child: Option<ChildFailure>,
    ) -> Result<()> {
        let mut clock = SystemClock;
        self.finish_with(action, child, &mut clock)
    }

    pub(super) fn finish_with(
        self,
        action: &Result<String, WorkflowError>,
        child: Option<ChildFailure>,
        clock: &mut impl Clock,
    ) -> Result<()> {
        let test_output = finish_test_capture();
        let test_logs = match test_output {
            Some((stdout, stderr)) => Some(TestLogs {
                stdout: write_log(&self.directory, "test.stdout", &stdout)?,
                stderr: write_log(&self.directory, "test.stderr", &stderr)?,
            }),
            None => None,
        };
        let (outcome, controller_error) = classify(action, child.as_ref());
        let first_failing_child = if action.is_err() { child } else { None };
        let result = ResultRecord {
            version: EVIDENCE_VERSION,
            operation_id: self.started.operation_id.clone(),
            project: self.started.project.clone(),
            command: self.started.command.clone(),
            finished_at: clock.now_utc()?,
            outcome,
            first_failing_child,
            controller_error,
            test_logs,
        };
        result.validate(&self.started)?;
        atomic_write_new(
            &self.directory.join("result.json"),
            canonical_json(&result)?.as_bytes(),
        )
    }
}

fn bounded_controller_error(mut value: String) -> String {
    if value.len() > MAX_CONTROLLER_ERROR_BYTES {
        let mut end = MAX_CONTROLLER_ERROR_BYTES - 3;
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        value.truncate(end);
        value.push_str("...");
    }
    value
}

pub(super) fn capture_test_output(stdout: &[u8], stderr: &[u8]) {
    TEST_OUTPUT.with(|slot| {
        if let Some(output) = slot.borrow_mut().as_mut() {
            *output = Some((stdout.to_vec(), stderr.to_vec()));
        }
    });
}

fn begin_test_capture() -> Result<()> {
    TEST_OUTPUT.with(|slot| {
        let mut slot = slot.borrow_mut();
        ensure!(slot.is_none(), "test output capture is already active");
        *slot = Some(None);
        Ok(())
    })
}

fn finish_test_capture() -> Option<(Vec<u8>, Vec<u8>)> {
    TEST_OUTPUT.with(|slot| slot.borrow_mut().take().flatten())
}

pub(super) fn source_identity(repo_root: &Path) -> Result<SourceIdentity> {
    let mut runner = SystemCommandRunner;
    source_identity_with(repo_root, &mut runner)
}

fn source_identity_with(
    repo_root: &Path,
    runner: &mut impl CommandRunner,
) -> Result<SourceIdentity> {
    let head_command =
        ArgvCommand::new("git", repo_root).args(["rev-parse", "--verify", "HEAD^{commit}"]);
    let head = runner.run(&head_command)?;
    if !head.success {
        super::super::argv::record_failure(&head_command, &head);
    }
    ensure!(
        head.success && head.code == Some(0) && head.signal.is_none(),
        "read source HEAD failed"
    );
    let head = String::from_utf8(head.stdout)
        .context("source HEAD is not UTF-8")?
        .trim()
        .to_owned();
    let status_command = ArgvCommand::new("git", repo_root).args([
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignored=no",
    ]);
    let status = runner.run(&status_command)?;
    if !status.success {
        super::super::argv::record_failure(&status_command, &status);
    }
    ensure!(
        status.success && status.code == Some(0) && status.signal.is_none(),
        "read source status failed"
    );
    let source = SourceIdentity {
        head,
        status_sha256: hash_bytes(b"bip448-operation-source-status-v1", &status.stdout),
        clean: status.stdout.is_empty(),
    };
    source.validate()?;
    Ok(source)
}

pub(super) fn combine_action_and_finalization(
    action: Result<String, WorkflowError>,
    finalization: Result<()>,
) -> Result<String, WorkflowError> {
    match (action, finalization) {
        (Ok(output), Ok(())) => Ok(output),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(_), Err(evidence)) => Err(WorkflowError::from(
            evidence.context("finalize operation evidence after successful command"),
        )),
        (Err(primary), Err(evidence)) => {
            let code = primary.exit_code();
            Err(WorkflowError::child_exit(
                code,
                format!("{primary}; operation evidence finalization also failed: {evidence:#}"),
            ))
        }
    }
}

fn classify(
    action: &Result<String, WorkflowError>,
    child: Option<&ChildFailure>,
) -> (Outcome, Option<String>) {
    match action {
        Ok(_) => (
            Outcome {
                kind: OutcomeKind::Success,
                exit_code: Some(0),
                signal: None,
            },
            None,
        ),
        Err(WorkflowError::ChildExit { code, .. }) => (child_exit_outcome(*code, child), None),
        Err(WorkflowError::Operational(error)) => (
            Outcome {
                kind: OutcomeKind::OperationalError,
                exit_code: Some(1),
                signal: None,
            },
            Some(bounded_controller_error(format!("{error:#}"))),
        ),
        Err(WorkflowError::Usage(message)) => (
            Outcome {
                kind: OutcomeKind::OperationalError,
                exit_code: Some(1),
                signal: None,
            },
            Some(bounded_controller_error(format!(
                "unexpected usage error after operation start: {message}"
            ))),
        ),
    }
}

fn child_exit_outcome(code: i32, child: Option<&ChildFailure>) -> Outcome {
    if let Some(signal) = child
        .and_then(|failure| failure.signal)
        .filter(|signal| code == 128 + signal)
    {
        return Outcome {
            kind: OutcomeKind::Signal,
            exit_code: Some(code),
            signal: Some(signal),
        };
    }
    Outcome {
        kind: OutcomeKind::ExitCode,
        exit_code: Some(code),
        signal: None,
    }
}

fn prepare_run_tree(paths: &RunPaths, configure: bool, owner: u32) -> Result<()> {
    let runs = paths
        .run_directory
        .parent()
        .context("run directory has no runs root")?;
    validate_owned_directory(
        runs.parent().context("runs root has no target parent")?,
        owner,
    )?;
    if configure {
        ensure_private_directory(runs, owner, true)?;
        match DirBuilder::new()
            .mode(DIRECTORY_MODE)
            .create(&paths.run_directory)
        {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                bail!(
                    "refusing to overwrite existing run directory {}",
                    paths.run_directory.display()
                )
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("create run directory {}", paths.run_directory.display())
                })
            }
        }
    }
    validate_private(
        &paths.run_directory,
        FileKind::Directory,
        owner,
        DIRECTORY_MODE,
    )
    .map(|_| ())
}

fn ensure_private_directory(path: &Path, owner: u32, create: bool) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound && create => {
            match DirBuilder::new().mode(DIRECTORY_MODE).create(path) {
                Ok(()) => {}
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("create private evidence directory {}", path.display())
                    })
                }
            }
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect private evidence directory {}", path.display()))
        }
        Ok(_) => {}
    }
    validate_private(path, FileKind::Directory, owner, DIRECTORY_MODE).map(|_| ())
}

pub(super) enum FileKind {
    Directory,
    Regular,
}

pub(super) fn validate_private(
    path: &Path,
    kind: FileKind,
    owner: u32,
    mode: u32,
) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect evidence path {}", path.display()))?;
    let right_kind = match kind {
        FileKind::Directory => metadata.is_dir(),
        FileKind::Regular => metadata.is_file(),
    };
    ensure!(
        right_kind && !metadata.file_type().is_symlink(),
        "evidence path {} has an unsupported type",
        path.display()
    );
    ensure!(
        metadata.uid() == owner,
        "evidence path {} is not owned by the effective UID",
        path.display()
    );
    ensure!(
        metadata.permissions().mode() & 0o7777 == mode,
        "evidence path {} has wrong mode",
        path.display()
    );
    Ok(metadata)
}

pub(super) fn atomic_write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect evidence output {}", path.display()))
        }
        Ok(_) => bail!("refusing to overwrite evidence file {}", path.display()),
    }
    let temporary = path.with_file_name(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|v| v.to_str())
            .context("evidence filename is not UTF-8")?,
        Uuid::new_v4()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(&temporary)
        .with_context(|| format!("create temporary evidence file {}", temporary.display()))?;
    let write = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::hard_link(&temporary, path)
            .with_context(|| format!("publish no-clobber evidence file {}", path.display()))?;
        fs::remove_file(&temporary)?;
        File::open(path.parent().context("evidence file has no parent")?)?.sync_all()?;
        Ok::<_, anyhow::Error>(())
    })();
    if let Err(error) = write {
        let _ = fs::remove_file(&temporary);
        return Err(error).with_context(|| format!("atomically write evidence {}", path.display()));
    }
    Ok(())
}

fn write_log(directory: &Path, name: &str, bytes: &[u8]) -> Result<StoredLog> {
    atomic_write_new(&directory.join(name), bytes)?;
    Ok(StoredLog {
        file: name.to_owned(),
        bytes: u64::try_from(bytes.len()).context("test log is too large")?,
        sha256: hash_bytes(b"bip448-operation-test-log-v1", bytes),
    })
}

pub(super) fn hash_bytes(domain: &[u8], bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(
        u64::try_from(domain.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hash.update(domain);
    hash.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hash.update(bytes);
    hex::encode(hash.finalize())
}

pub(super) fn validate_operation_id(value: &str) -> Result<()> {
    let parsed = Uuid::parse_str(value).context("operation directory is not a UUID")?;
    ensure!(
        parsed.to_string() == value,
        "operation UUID is not canonical"
    );
    Ok(())
}
