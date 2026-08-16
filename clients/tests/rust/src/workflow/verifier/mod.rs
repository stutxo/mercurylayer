mod artifacts;
mod client_contract;
mod client_db;
pub(in crate::workflow) mod helper;
mod postgres;
mod postgres_columns;
mod postgres_compare;
mod postgres_contract;
mod postgres_objects;
mod report;
mod route_lexer;
mod routes;
mod settings;

#[cfg(test)]
mod tests;

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};

use super::argv::{record_failure, ArgvCommand, CommandOutput, CommandRunner, SystemCommandRunner};
use super::build;
use super::error::WorkflowError;
use super::lifecycle;
use super::model::{canonical_json, StackMetadata};
use artifacts::ArtifactGuard;
use report::{ClientDatabaseReport, PostgresReport, VerifyReport};

const HELPER_SETTINGS: &str = ".verify-client.Settings.toml";
const HELPER_DATABASE: &str = "verify-client.sqlite";
const MAX_HELPER_OUTPUT: usize = 4 * 1_048_576;

pub(super) fn execute(
    repo_root: &Path,
    metadata: &StackMetadata,
    _operation_id: &str,
) -> Result<String, WorkflowError> {
    execute_inner(repo_root, metadata).map_err(WorkflowError::from)
}

fn execute_inner(repo_root: &Path, metadata: &StackMetadata) -> Result<String> {
    let settings = settings::verify(metadata).context("verify exact generated client settings")?;
    let (mercury_token_routes, lockbox_routes) =
        routes::verify(repo_root).context("verify static server route inventories")?;

    lifecycle::ready(repo_root, metadata).context("require exact ready stack before verifier")?;
    lifecycle::require_exact_mercury_config(metadata)
        .context("directly verify Mercury /info/config")?;
    let mut runner = SystemCommandRunner;
    let build_before = build::verify_complete(repo_root, metadata, &mut runner)
        .context("verify source/build identity before direct checks")?;

    let client_database = run_client_helper(repo_root, metadata, &mut runner)?;
    let client_migration_sha256 = client_contract::verify(repo_root, &client_database)
        .context("verify exact client SQLite contract")?;

    let postgres_before_restart = run_postgres_helper(repo_root, metadata, &mut runner)?;
    postgres::verify(repo_root, &postgres_before_restart)
        .context("verify PostgreSQL contracts before restart")?;

    lifecycle::restart_mercury(repo_root, metadata, &mut runner)?;
    lifecycle::ready(repo_root, metadata).context("require exact ready stack after restart")?;
    let postgres_after_restart = run_postgres_helper(repo_root, metadata, &mut runner)?;
    postgres::verify(repo_root, &postgres_after_restart)
        .context("verify PostgreSQL contracts after restart")?;
    ensure!(
        postgres_after_restart == postgres_before_restart,
        "PostgreSQL migration row or catalogs changed across the exact Mercury restart"
    );

    let build_after = build::verify_complete(repo_root, metadata, &mut runner)
        .context("recheck source/build identity after direct checks")?;
    ensure!(
        build_after == build_before,
        "source/build identity changed while verifier was running"
    );
    lifecycle::ready(repo_root, metadata).context("final exact ready-stack recheck")?;

    let report = VerifyReport {
        version: 1,
        project: metadata.project().to_string(),
        status: "verified".into(),
        settings,
        mercury_token_routes,
        lockbox_routes,
        client_migration_sha256,
        client_database,
        postgres_before_restart,
        postgres_after_restart,
        mercury_restart_count: 1,
        build_identity_unchanged: true,
        ready_after_restart: true,
    };
    let output = canonical_json(&report)?;
    super::evidence::capture_test_output(output.as_bytes(), b"");
    Ok(output)
}

fn run_client_helper(
    repo_root: &Path,
    metadata: &StackMetadata,
    runner: &mut impl CommandRunner,
) -> Result<ClientDatabaseReport> {
    let directory = &metadata.paths().run_directory;
    let settings = directory.join(HELPER_SETTINGS);
    let database = directory.join(HELPER_DATABASE);
    let command = helper_command(repo_root)?
        .args([
            "client",
            "--project",
            metadata.project().as_str(),
            "--settings",
        ])
        .arg(&settings)
        .arg("--database")
        .arg(&database);
    let settings_contents = disposable_settings_contents(metadata, &database)?;
    let mut artifacts = ArtifactGuard::new(directory)?;
    artifacts.write_settings(settings_contents.as_bytes())?;
    artifacts.create_database()?;
    let action = (|| {
        let output = combine(
            runner.run(&command),
            artifacts.capture_helper_artifacts(),
            "capture supervised client verifier artifacts",
        )?;
        require_helper_success(&command, &output)?;
        let report = helper::decode_output::<ClientDatabaseReport>(&output.stdout)?;
        Ok(report)
    })();
    let cleanup = artifacts.cleanup();
    combine(action, cleanup, "client verifier artifact cleanup")
}

fn run_postgres_helper(
    repo_root: &Path,
    metadata: &StackMetadata,
    runner: &mut impl CommandRunner,
) -> Result<PostgresReport> {
    let command = helper_command(repo_root)?.args([
        "postgres",
        "--project",
        metadata.project().as_str(),
        "--mercury-url",
        metadata.endpoints().mercury_database_url.as_str(),
        "--lockbox-url",
        metadata.endpoints().lockbox_database_url.as_str(),
    ]);
    let output = runner.run(&command)?;
    require_helper_success(&command, &output)?;
    helper::decode_output(&output.stdout)
}

fn helper_command(repo_root: &Path) -> Result<ArgvCommand> {
    let executable = std::env::current_exe().context("resolve current Rust workflow executable")?;
    let metadata =
        fs::symlink_metadata(&executable).context("inspect current workflow executable")?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "workflow executable must be a regular non-symlink file"
    );
    Ok(ArgvCommand::new(executable, repo_root)
        .clear_environment()
        .arg("__bip448-verify-helper"))
}

fn require_helper_success(command: &ArgvCommand, output: &CommandOutput) -> Result<()> {
    if !output.success {
        record_failure(command, output);
    }
    ensure!(
        output.success && output.code == Some(0) && output.signal.is_none(),
        "supervised verifier helper failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    ensure!(
        output.stdout.len() <= MAX_HELPER_OUTPUT && output.stderr.len() <= MAX_HELPER_OUTPUT,
        "verifier helper output exceeded its byte bound"
    );
    ensure!(
        output.stderr.is_empty(),
        "successful verifier helper emitted stderr"
    );
    Ok(())
}

fn disposable_settings_contents(metadata: &StackMetadata, database: &Path) -> Result<String> {
    let original = metadata.settings_contents()?;
    let old = format!(
        "database_file = {}\n",
        serde_json::to_string(
            metadata
                .paths()
                .wallet_database
                .to_str()
                .context("wallet DB path is not UTF-8")?
        )?
    );
    let new = format!(
        "database_file = {}\n",
        serde_json::to_string(
            database
                .to_str()
                .context("disposable DB path is not UTF-8")?
        )?
    );
    ensure!(
        original.matches(&old).count() == 1,
        "ProjectSpec settings lack one exact database assignment"
    );
    Ok(original.replacen(&old, &new, 1))
}

fn client_artifacts(directory: &Path) -> Vec<PathBuf> {
    vec![
        directory.join(HELPER_SETTINGS),
        directory.join(HELPER_DATABASE),
        directory.join(format!("{HELPER_DATABASE}-wal")),
        directory.join(format!("{HELPER_DATABASE}-shm")),
    ]
}

fn real_uid() -> Result<u32> {
    let mut status = String::new();
    File::open("/proc/self/status")
        .context("open /proc/self/status for verifier real UID")?
        .read_to_string(&mut status)
        .context("read /proc/self/status for verifier real UID")?;
    let values = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .context("/proc/self/status has no Uid field")?
        .split_ascii_whitespace()
        .skip(1)
        .map(str::parse::<u32>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(values.len() == 4, "/proc/self/status has malformed UIDs");
    ensure!(
        values[0] == values[1],
        "verifier refuses a real/effective UID mismatch"
    );
    Ok(values[0])
}

fn combine<T>(action: Result<T>, cleanup: Result<()>, label: &str) -> Result<T> {
    match (action, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(cleanup)) => Err(cleanup).with_context(|| label.to_owned()),
        (Err(error), Err(cleanup)) => bail!("{error:#}; {label} also failed: {cleanup:#}"),
    }
}
