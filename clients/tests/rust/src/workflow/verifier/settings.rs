use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{ensure, Context, Result};

use super::super::model::StackMetadata;
use super::report::SettingsReport;

pub(super) fn verify(metadata: &StackMetadata) -> Result<SettingsReport> {
    let contents = fs::read_to_string(&metadata.paths().settings_file)
        .context("read generated verifier Settings.toml")?;
    verify_contents(metadata, &contents)
}

pub(super) fn verify_disposable_database(
    metadata: &StackMetadata,
    contents: &str,
    database: &Path,
) -> Result<()> {
    let database = database
        .to_str()
        .context("disposable client DB path is not UTF-8")?;
    parse_contents(metadata, contents, database)?;
    Ok(())
}

fn verify_contents(metadata: &StackMetadata, contents: &str) -> Result<SettingsReport> {
    ensure!(
        contents == metadata.settings_contents()?,
        "generated Settings.toml bytes differ from the current ProjectSpec"
    );
    let database = metadata
        .paths()
        .wallet_database
        .to_str()
        .context("controller wallet DB path is not UTF-8")?;
    parse_contents(metadata, contents, database)
}

fn parse_contents(
    metadata: &StackMetadata,
    contents: &str,
    database: &str,
) -> Result<SettingsReport> {
    let mut keys = BTreeMap::new();
    for line in contents.lines() {
        let (name, value) = line
            .split_once(" = ")
            .context("Settings.toml contains a non-canonical assignment")?;
        ensure!(
            !name.is_empty() && keys.insert(name.to_owned(), unquote(value)?).is_none(),
            "Settings.toml contains an empty or duplicate key"
        );
    }
    let expected = BTreeMap::from([
        (
            "statechain_entity".into(),
            metadata.endpoints().mercury_url.clone(),
        ),
        ("chain_backend".into(), "core".into()),
        (
            "core_rpc_url".into(),
            metadata.endpoints().core_rpc_url.clone(),
        ),
        ("core_rpc_auth".into(), "userpass".into()),
        ("core_rpc_user".into(), "mercury".into()),
        ("core_rpc_password".into(), "mercury".into()),
        ("network".into(), "regtest".into()),
        ("fee_rate_tolerance".into(), "5".into()),
        ("database_file".into(), database.into()),
        ("confirmation_target".into(), "2".into()),
        ("max_fee_rate".into(), "1".into()),
    ]);
    ensure!(
        keys == expected,
        "generated Settings.toml has missing, extra, or changed keys/values"
    );
    Ok(SettingsReport { keys })
}

fn unquote(value: &str) -> Result<String> {
    if let Some(inner) = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    {
        ensure!(
            !inner.contains(['"', '\n', '\r']),
            "Settings.toml string has unsupported escaping"
        );
        Ok(inner.replace("\\\\", "\\"))
    } else {
        ensure!(
            !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
            "Settings.toml scalar is not canonical"
        );
        Ok(value.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflow::model::{PortMap, Project};

    fn metadata() -> StackMetadata {
        StackMetadata::new(
            std::path::Path::new("/repo"),
            Project::parse("verify_1").unwrap(),
            PortMap::from_base(25000).unwrap(),
        )
    }

    #[test]
    fn exact_settings_pass_and_extra_missing_or_changed_values_fail() {
        let metadata = metadata();
        let exact = metadata.settings_contents().unwrap();
        assert_eq!(verify_contents(&metadata, &exact).unwrap().keys.len(), 11);
        for changed in [
            exact.replace("max_fee_rate = 1\n", ""),
            format!("{exact}extra = 1\n"),
            exact.replace("fee_rate_tolerance = 5", "fee_rate_tolerance = 6"),
        ] {
            assert!(verify_contents(&metadata, &changed).is_err());
        }

        let disposable = metadata.paths().run_directory.join("verify-client.sqlite");
        let disposable_contents = exact.replace(
            metadata.paths().wallet_database.to_str().unwrap(),
            disposable.to_str().unwrap(),
        );
        verify_disposable_database(&metadata, &disposable_contents, &disposable).unwrap();
        assert!(verify_disposable_database(
            &metadata,
            &disposable_contents,
            std::path::Path::new("/tmp/wrong.sqlite")
        )
        .is_err());
    }
}
