use std::fs::{self, File};
use std::io::{ErrorKind, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use anyhow::{ensure, Context, Result};
use serde::{de::DeserializeOwned, Serialize};

use super::super::argv::{CommandOutput, CommandRunner, SystemCommandRunner};
use super::super::lifecycle::{self, StatusReport};
use super::super::model::{canonical_json, Project, RunPaths, StackMetadata};
use super::super::project_lock::effective_uid;
use super::record::{ResultRecord, StartedRecord, TestLogs};
use super::store::{hash_bytes, validate_operation_id, validate_private, FileKind};

const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const MAX_RECORD_BYTES: u64 = 1_048_576;
const MAX_COMPOSE_LOG_BYTES: usize = 4 * 1_048_576;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OperationSummary {
    pub(super) operation_id: String,
    pub(super) incomplete: bool,
    pub(super) started: Option<StartedRecord>,
    pub(super) result: Option<ResultRecord>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CheckpointReport {
    version: u32,
    project: String,
    status: StatusReport,
    operations: Vec<OperationSummary>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct OperationLogReport {
    operation_id: String,
    summary: TestLogs,
    stdout: String,
    stderr: String,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ComposeLogReport {
    argv: Vec<String>,
    exit_code: Option<i32>,
    signal: Option<i32>,
    stdout: String,
    stderr: String,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct LogsReport {
    version: u32,
    project: String,
    operations: Vec<OperationLogReport>,
    compose: ComposeLogReport,
}

pub(super) fn checkpoint(repo_root: &Path, metadata: &StackMetadata) -> Result<String> {
    let status = lifecycle::status(repo_root, metadata)?;
    checkpoint_with_status(repo_root, metadata, status)
}

pub(super) fn checkpoint_with_status(
    repo_root: &Path,
    metadata: &StackMetadata,
    status: StatusReport,
) -> Result<String> {
    canonical_json(&CheckpointReport {
        version: 1,
        project: metadata.project().to_string(),
        status,
        operations: scan(repo_root, metadata.project())?,
    })
}

pub(super) fn logs(repo_root: &Path, metadata: &StackMetadata) -> Result<String> {
    let mut runner = SystemCommandRunner;
    logs_with(repo_root, metadata, &mut runner)
}

pub(super) fn logs_with(
    repo_root: &Path,
    metadata: &StackMetadata,
    runner: &mut impl CommandRunner,
) -> Result<String> {
    let summaries = scan(repo_root, metadata.project())?;
    let operations = summaries
        .iter()
        .filter_map(|summary| {
            summary
                .result
                .as_ref()
                .and_then(|result| result.test_logs.as_ref())
                .map(|logs| load_operation_logs(repo_root, metadata.project(), summary, logs))
        })
        .collect::<Result<Vec<_>>>()?;
    let (command, output) = lifecycle::compose_logs_with(repo_root, metadata, runner)?;
    let compose = compose_report(command.encoded_argv(), output)?;
    canonical_json(&LogsReport {
        version: 1,
        project: metadata.project().to_string(),
        operations,
        compose,
    })
}

pub(super) fn scan(repo_root: &Path, project: &Project) -> Result<Vec<OperationSummary>> {
    let owner = effective_uid()?;
    let operations = RunPaths::new(repo_root, project)
        .run_directory
        .join("operations");
    match fs::symlink_metadata(&operations) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect operation evidence {}", operations.display()))
        }
        Ok(_) => {}
    }
    validate_private(&operations, FileKind::Directory, owner, DIRECTORY_MODE)?;
    let mut entries = fs::read_dir(&operations)
        .with_context(|| format!("read operation evidence {}", operations.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    entries
        .into_iter()
        .map(|entry| scan_operation(&entry.path(), project, owner))
        .collect()
}

fn scan_operation(path: &Path, project: &Project, owner: u32) -> Result<OperationSummary> {
    validate_private(path, FileKind::Directory, owner, DIRECTORY_MODE)?;
    let operation_id = path
        .file_name()
        .and_then(|value| value.to_str())
        .context("operation directory name is not UTF-8")?
        .to_owned();
    validate_operation_id(&operation_id)?;
    let mut names = fs::read_dir(path)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    names.sort();
    for name in &names {
        let name = name
            .to_str()
            .context("operation evidence filename is not UTF-8")?;
        let temporary = valid_temporary_name(name);
        let allowed = matches!(
            name,
            "started.json" | "result.json" | "test.stdout" | "test.stderr"
        ) || temporary;
        ensure!(allowed, "alien operation evidence file {name:?}");
        match validate_private(&path.join(name), FileKind::Regular, owner, FILE_MODE) {
            Ok(_) => {}
            Err(error)
                if temporary
                    && error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|error| error.kind() == ErrorKind::NotFound) => {}
            Err(error) => return Err(error),
        }
    }

    let mut started = read_optional_canonical::<StartedRecord>(&path.join("started.json"), owner)?;
    let result = read_optional_canonical::<ResultRecord>(&path.join("result.json"), owner)?;
    if result.is_some() && started.is_none() {
        started = read_optional_canonical::<StartedRecord>(&path.join("started.json"), owner)?;
    }
    if let Some(started) = &started {
        started.validate(&operation_id, project.as_str())?;
    }
    if let Some(result) = &result {
        let started = started
            .as_ref()
            .context("result record exists without started record")?;
        result.validate(started)?;
        validate_result_logs(path, result, owner)?;
    }
    if result.is_none() {
        for name in ["test.stdout", "test.stderr"] {
            if path.join(name).exists() {
                validate_private(&path.join(name), FileKind::Regular, owner, FILE_MODE)?;
            }
        }
    }
    Ok(OperationSummary {
        operation_id,
        incomplete: result.is_none(),
        started,
        result,
    })
}

fn validate_result_logs(path: &Path, result: &ResultRecord, owner: u32) -> Result<()> {
    match &result.test_logs {
        Some(logs) => {
            validate_log(path, &logs.stdout, owner)?;
            validate_log(path, &logs.stderr, owner)?;
        }
        None => ensure!(
            !path.join("test.stdout").exists() && !path.join("test.stderr").exists(),
            "operation has unrecorded test log files"
        ),
    }
    Ok(())
}

fn validate_log(path: &Path, expected: &super::record::StoredLog, owner: u32) -> Result<Vec<u8>> {
    let file = path.join(&expected.file);
    let metadata = validate_private(&file, FileKind::Regular, owner, FILE_MODE)?;
    ensure!(
        metadata.len() == expected.bytes,
        "stored test log byte count mismatch"
    );
    let bytes = read_stable(&file, &metadata)?;
    ensure!(
        hash_bytes(b"bip448-operation-test-log-v1", &bytes) == expected.sha256,
        "stored test log digest mismatch"
    );
    Ok(bytes)
}

fn load_operation_logs(
    repo_root: &Path,
    project: &Project,
    summary: &OperationSummary,
    logs: &TestLogs,
) -> Result<OperationLogReport> {
    let owner = effective_uid()?;
    let directory = RunPaths::new(repo_root, project)
        .run_directory
        .join("operations")
        .join(&summary.operation_id);
    let stdout = String::from_utf8(validate_log(&directory, &logs.stdout, owner)?)
        .context("stored test stdout is not UTF-8")?;
    let stderr = String::from_utf8(validate_log(&directory, &logs.stderr, owner)?)
        .context("stored test stderr is not UTF-8")?;
    Ok(OperationLogReport {
        operation_id: summary.operation_id.clone(),
        summary: logs.clone(),
        stdout,
        stderr,
    })
}

fn read_optional_canonical<T: DeserializeOwned + Serialize>(
    path: &Path,
    owner: u32,
) -> Result<Option<T>> {
    let metadata = match fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect evidence record {}", path.display()))
        }
        Ok(_) => validate_private(path, FileKind::Regular, owner, FILE_MODE)?,
    };
    ensure!(
        metadata.len() <= MAX_RECORD_BYTES,
        "evidence record is too large"
    );
    let bytes = read_stable(path, &metadata)?;
    let value: T = serde_json::from_slice(&bytes).context("parse operation evidence JSON")?;
    ensure!(
        canonical_json(&value)?.as_bytes() == bytes,
        "operation evidence JSON is not canonical"
    );
    Ok(Some(value))
}

fn read_stable(path: &Path, before: &fs::Metadata) -> Result<Vec<u8>> {
    let mut file =
        File::open(path).with_context(|| format!("open evidence file {}", path.display()))?;
    let opened = file.metadata()?;
    ensure!(
        opened.dev() == before.dev() && opened.ino() == before.ino(),
        "evidence file changed while opening"
    );
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let after = fs::symlink_metadata(path)?;
    ensure!(
        after.dev() == before.dev()
            && after.ino() == before.ino()
            && after.len() == bytes.len() as u64
            && after.uid() == before.uid()
            && (after.permissions().mode() & 0o7777) == (before.permissions().mode() & 0o7777),
        "evidence file changed while reading"
    );
    Ok(bytes)
}

fn valid_temporary_name(name: &str) -> bool {
    [
        ".started.json.",
        ".result.json.",
        ".test.stdout.",
        ".test.stderr.",
    ]
    .iter()
    .find_map(|prefix| name.strip_prefix(prefix))
    .and_then(|rest| rest.strip_suffix(".tmp"))
    .is_some_and(|id| validate_operation_id(id).is_ok())
}

fn compose_report(argv: Vec<String>, output: CommandOutput) -> Result<ComposeLogReport> {
    ensure!(
        output.success && output.code == Some(0) && output.signal.is_none(),
        "Compose logs command failed"
    );
    ensure!(
        output.stdout.len() <= MAX_COMPOSE_LOG_BYTES
            && output.stderr.len() <= MAX_COMPOSE_LOG_BYTES,
        "Compose logs output exceeded the bounded limit"
    );
    Ok(ComposeLogReport {
        argv,
        exit_code: output.code,
        signal: output.signal,
        stdout: String::from_utf8(output.stdout).context("Compose log stdout is not UTF-8")?,
        stderr: String::from_utf8(output.stderr).context("Compose log stderr is not UTF-8")?,
    })
}
