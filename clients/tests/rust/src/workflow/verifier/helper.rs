use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};

use super::super::model::{canonical_json, Project, StackMetadata};
use super::{client_db, postgres, HELPER_DATABASE, HELPER_SETTINGS};

enum HelperCommand {
    Client {
        project: Project,
        settings: PathBuf,
        database: PathBuf,
    },
    Postgres {
        project: Project,
        mercury_url: String,
        lockbox_url: String,
    },
}

pub(in crate::workflow) async fn run<I>(args: I) -> Result<String>
where
    I: IntoIterator<Item = OsString>,
{
    match parse(args)? {
        HelperCommand::Client {
            project,
            settings,
            database,
        } => {
            let (root, metadata) = bound_metadata(&project)?;
            validate_client_binding(&metadata, &settings, &database)?;
            let migration = fs::read_to_string(
                root.join("clients/libs/rust/migrations/0001_bip448_client_schema.sql"),
            )
            .context("read bound client migration source")?;
            let report = client_db::helper(&settings, &database, &migration).await?;
            validate_client_binding(&metadata, &settings, &database)?;
            canonical_json(&report)
        }
        HelperCommand::Postgres {
            project,
            mercury_url,
            lockbox_url,
        } => {
            let (_, metadata) = bound_metadata(&project)?;
            validate_pg_binding(&metadata, &mercury_url, &lockbox_url)?;
            canonical_json(&postgres::helper(&mercury_url, &lockbox_url).await?)
        }
    }
}

fn bound_metadata(project: &Project) -> Result<(PathBuf, StackMetadata)> {
    let root = super::super::repository::active_root()?;
    let metadata = super::super::storage::status(&root, project)
        .context("bind hidden verifier helper to canonical project metadata")?;
    validate_run_directory(&metadata)?;
    Ok((root, metadata))
}

fn validate_run_directory(metadata: &StackMetadata) -> Result<()> {
    let directory = &metadata.paths().run_directory;
    ensure!(
        directory.canonicalize()? == *directory,
        "verifier project run directory is not canonical"
    );
    let value = fs::symlink_metadata(directory)?;
    ensure!(
        value.is_dir()
            && !value.file_type().is_symlink()
            && value.uid() == super::real_uid()?
            && value.permissions().mode() & 0o7777 == 0o700,
        "verifier project run directory must be a real UID-owned mode-0700 directory"
    );
    Ok(())
}

fn validate_client_binding(
    metadata: &StackMetadata,
    settings: &Path,
    database: &Path,
) -> Result<()> {
    let directory = &metadata.paths().run_directory;
    ensure!(
        settings == directory.join(HELPER_SETTINGS)
            && database == directory.join(HELPER_DATABASE)
            && settings.parent() == Some(directory)
            && database.parent() == Some(directory),
        "client helper paths are not the exact project verifier artifacts"
    );
    validate_run_directory(metadata)?;
    validate_private_file(settings)?;
    validate_private_file(database)?;
    let contents = fs::read_to_string(settings).context("read bound verifier Settings.toml")?;
    ensure!(
        contents == super::disposable_settings_contents(metadata, database)?,
        "bound verifier Settings.toml or database_file assignment drifted"
    );
    super::settings::verify_disposable_database(metadata, &contents, database)
        .context("parse bound verifier Settings.toml and exact database_file")?;
    Ok(())
}

fn validate_private_file(path: &Path) -> Result<()> {
    ensure!(
        path.canonicalize()? == path,
        "helper file path is not canonical"
    );
    let value = fs::symlink_metadata(path)?;
    ensure!(
        value.is_file()
            && !value.file_type().is_symlink()
            && value.nlink() == 1
            && value.uid() == super::real_uid()?
            && value.permissions().mode() & 0o7777 == 0o600,
        "helper file must be one real UID-owned mode-0600 regular file"
    );
    Ok(())
}

fn validate_pg_binding(
    metadata: &StackMetadata,
    mercury_url: &str,
    lockbox_url: &str,
) -> Result<()> {
    let mercury_port = strict_pg_port(mercury_url, "mercury")?;
    let lockbox_port = strict_pg_port(lockbox_url, "enclave")?;
    ensure!(
        mercury_url == metadata.endpoints().mercury_database_url
            && lockbox_url == metadata.endpoints().lockbox_database_url
            && mercury_port == metadata.ports().mercury_database
            && lockbox_port == metadata.ports().lockbox_database,
        "PostgreSQL helper URLs/ports are not bound to the selected project"
    );
    Ok(())
}

fn strict_pg_port(value: &str, database: &str) -> Result<u16> {
    let prefix = "postgres://postgres:postgres@127.0.0.1:";
    let suffix = format!("/{database}");
    let port = value
        .strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(&suffix))
        .context("PostgreSQL helper URL is not the strict controller loopback grammar")?;
    ensure!(
        !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()),
        "PostgreSQL helper port is not decimal"
    );
    let parsed: u16 = port
        .parse()
        .context("PostgreSQL helper port is out of range")?;
    ensure!(
        parsed != 0 && parsed.to_string() == port,
        "PostgreSQL helper port is not canonical"
    );
    Ok(parsed)
}

fn parse<I>(args: I) -> Result<HelperCommand>
where
    I: IntoIterator<Item = OsString>,
{
    let args = args
        .into_iter()
        .map(|value| {
            value
                .into_string()
                .map_err(|_| anyhow::anyhow!("helper argument is not UTF-8"))
        })
        .collect::<Result<Vec<_>>>()?;
    match args.as_slice() {
        [mode, project_flag, project, settings_flag, settings, database_flag, database]
            if mode == "client"
                && project_flag == "--project"
                && settings_flag == "--settings"
                && database_flag == "--database" =>
        {
            Ok(HelperCommand::Client {
                project: Project::parse(project).map_err(anyhow::Error::msg)?,
                settings: PathBuf::from(settings),
                database: PathBuf::from(database),
            })
        }
        [mode, project_flag, project, mercury_flag, mercury_url, lockbox_flag, lockbox_url]
            if mode == "postgres"
                && project_flag == "--project"
                && mercury_flag == "--mercury-url"
                && lockbox_flag == "--lockbox-url" =>
        {
            strict_pg_port(mercury_url, "mercury")?;
            strict_pg_port(lockbox_url, "enclave")?;
            Ok(HelperCommand::Postgres {
                project: Project::parse(project).map_err(anyhow::Error::msg)?,
                mercury_url: mercury_url.clone(),
                lockbox_url: lockbox_url.clone(),
            })
        }
        _ => anyhow::bail!("malformed hidden verifier helper command"),
    }
}

pub(super) fn decode_output<T>(bytes: &[u8]) -> Result<T>
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let value: T = serde_json::from_slice(bytes).context("parse verifier helper report")?;
    ensure!(
        canonical_json(&value)?.as_bytes() == bytes,
        "verifier helper report is not canonical JSON with exactly one terminal LF"
    );
    Ok(value)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs::{DirBuilder, OpenOptions};
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

    use super::*;
    use crate::workflow::model::PortMap;
    use crate::workflow::verifier::report::SettingsReport;
    use uuid::Uuid;

    #[test]
    fn hidden_helper_parser_and_postgres_url_grammar_are_exact() {
        assert!(matches!(
            parse(
                [
                    "client",
                    "--project",
                    "verify_1",
                    "--settings",
                    "/run/.verify-client.Settings.toml",
                    "--database",
                    "/run/verify-client.sqlite",
                ]
                .map(OsString::from)
            )
            .unwrap(),
            HelperCommand::Client { .. }
        ));
        let exact = "postgres://postgres:postgres@127.0.0.1:25403/mercury";
        assert_eq!(strict_pg_port(exact, "mercury").unwrap(), 25403);
        for malformed in [
            "postgres://postgres:postgres@localhost:25403/mercury",
            "postgres://postgres:postgres@127.0.0.1:025403/mercury",
            "postgres://postgres:postgres@127.0.0.1:25403/mercury?x=1",
            "postgres://other:postgres@127.0.0.1:25403/mercury",
            "postgres://postgres:postgres@127.0.0.1:25403/mercury#x",
            "postgres://postgres:postgres@127.0.0.1:25403/enclave",
            "postgres://postgres:postgres@127.0.0.1:70000/mercury",
        ] {
            assert!(strict_pg_port(malformed, "mercury").is_err(), "{malformed}");
        }
    }

    #[test]
    fn client_paths_settings_and_postgres_ports_are_bound_to_exact_project_metadata() {
        let root = std::env::temp_dir().join(format!("bip448-helper-bind-{}", Uuid::new_v4()));
        DirBuilder::new().mode(0o700).create(&root).unwrap();
        let project = Project::parse("verify_1").unwrap();
        let metadata = StackMetadata::new(&root, project, PortMap::from_base(25400).unwrap());
        fs::create_dir_all(metadata.paths().run_directory.parent().unwrap()).unwrap();
        DirBuilder::new()
            .mode(0o700)
            .create(&metadata.paths().run_directory)
            .unwrap();
        let settings = metadata.paths().run_directory.join(HELPER_SETTINGS);
        let database = metadata.paths().run_directory.join(HELPER_DATABASE);
        fs::write(
            &settings,
            super::super::disposable_settings_contents(&metadata, &database).unwrap(),
        )
        .unwrap();
        fs::set_permissions(&settings, fs::Permissions::from_mode(0o600)).unwrap();
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&database)
            .unwrap();
        validate_client_binding(&metadata, &settings, &database).unwrap();
        validate_pg_binding(
            &metadata,
            &metadata.endpoints().mercury_database_url,
            &metadata.endpoints().lockbox_database_url,
        )
        .unwrap();

        assert!(
            validate_client_binding(&metadata, &metadata.paths().settings_file, &database).is_err()
        );
        assert!(
            validate_client_binding(&metadata, &settings, &metadata.paths().wallet_database)
                .is_err()
        );
        fs::write(&settings, "database_file = \"/tmp/wrong\"\n").unwrap();
        assert!(validate_client_binding(&metadata, &settings, &database).is_err());
        assert!(validate_pg_binding(
            &metadata,
            "postgres://postgres:postgres@127.0.0.1:25413/mercury",
            &metadata.endpoints().lockbox_database_url,
        )
        .is_err());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn decoder_requires_original_byte_exact_canonical_json_and_one_lf() {
        let report = SettingsReport {
            keys: BTreeMap::from([("a".into(), "1".into()), ("b".into(), "2".into())]),
        };
        let canonical = canonical_json(&report).unwrap();
        assert_eq!(
            decode_output::<SettingsReport>(canonical.as_bytes()).unwrap(),
            report
        );
        for invalid in [
            canonical.trim_end().as_bytes().to_vec(),
            format!("{canonical}\n").into_bytes(),
            b"{\"keys\": {\"a\":\"1\",\"b\":\"2\"}}\n".to_vec(),
            b"{\"keys\":{\"b\":\"2\",\"a\":\"1\"}}\n".to_vec(),
            b"{\"keys\":{\"a\":\"1\",\"b\":\"2\"},\"extra\":0}\n".to_vec(),
            format!("{canonical}x").into_bytes(),
        ] {
            assert!(decode_output::<SettingsReport>(&invalid).is_err());
        }
    }
}
