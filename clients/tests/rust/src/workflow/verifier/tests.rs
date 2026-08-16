use std::fs::{self, DirBuilder, OpenOptions};
use std::os::unix::fs::{symlink, DirBuilderExt, OpenOptionsExt, PermissionsExt};

use uuid::Uuid;

use super::*;

struct Temp(PathBuf);

impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("bip448-verifier-{}", Uuid::new_v4()));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path.canonicalize().unwrap())
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn regular(path: &Path, mode: u32) {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .unwrap();
}

#[test]
fn disposable_paths_modes_capture_and_cleanup_are_exact() {
    let temp = Temp::new();
    let mut guard = ArtifactGuard::new(&temp.0).unwrap();
    assert_eq!(
        guard
            .paths()
            .iter()
            .map(|path| path.file_name().unwrap().to_str().unwrap())
            .collect::<Vec<_>>(),
        [
            ".verify-client.Settings.toml",
            "verify-client.sqlite",
            "verify-client.sqlite-wal",
            "verify-client.sqlite-shm",
        ]
    );
    guard.write_settings(b"settings").unwrap();
    guard.create_database().unwrap();
    regular(&guard.paths()[2], 0o600);
    guard.capture_helper_artifacts().unwrap();
    guard.cleanup().unwrap();
    guard.cleanup().unwrap();
}

#[test]
fn symlink_hardlink_mode_and_identity_substitution_fail_closed_without_deletion() {
    for poison in ["symlink", "hardlink", "mode", "replacement"] {
        let temp = Temp::new();
        let mut guard = ArtifactGuard::new(&temp.0).unwrap();
        guard.write_settings(b"settings").unwrap();
        guard.create_database().unwrap();
        let database = guard.paths()[1].clone();
        fs::remove_file(&database).unwrap();
        match poison {
            "symlink" => symlink(&guard.paths()[0], &database).unwrap(),
            "hardlink" => fs::hard_link(&guard.paths()[0], &database).unwrap(),
            "mode" => regular(&database, 0o644),
            "replacement" => regular(&database, 0o600),
            _ => unreachable!(),
        }
        assert!(guard.cleanup().is_err(), "accepted {poison}");
        assert!(fs::symlink_metadata(&database).is_ok(), "deleted {poison}");
    }
}

#[test]
fn every_post_creation_failure_stage_runs_the_same_exact_cleanup() {
    for stage in [
        "write",
        "sync",
        "validation",
        "current_exe",
        "runner",
        "status",
        "signal",
        "decode",
        "contract",
    ] {
        let temp = Temp::new();
        let mut guard = ArtifactGuard::new(&temp.0).unwrap();
        guard.write_settings(b"settings").unwrap();
        guard.create_database().unwrap();
        let action: Result<()> = Err(anyhow::anyhow!("injected {stage} failure"));
        assert!(combine(action, guard.cleanup(), stage).is_err());
        assert!(guard.paths().iter().all(|path| !path.exists()), "{stage}");
    }
}

#[test]
fn helper_failure_exit_signal_stderr_and_decode_are_rejected() {
    let command = ArgvCommand::new("helper", Path::new("/tmp")).arg("hidden");
    assert!(require_helper_success(&command, &CommandOutput::failure(7, "failed")).is_err());
    assert!(require_helper_success(
        &command,
        &CommandOutput {
            success: false,
            code: None,
            signal: Some(15),
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    )
    .is_err());
    assert!(require_helper_success(
        &command,
        &CommandOutput {
            success: true,
            code: Some(0),
            signal: None,
            stdout: b"{}\n".to_vec(),
            stderr: b"warning".to_vec(),
        }
    )
    .is_err());
    assert!(helper::decode_output::<report::SettingsReport>(b"{}\n").is_err());
}

#[sqlx::test(migrations = false)]
#[ignore = "requires an explicitly selected disposable PostgreSQL superuser URL"]
async fn live_pg16_mercury_catalog_matches_authenticated_source(
    pool: sqlx::PgPool,
) -> anyhow::Result<()> {
    use sha2::{Digest, Sha256};

    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()?;
    super::super::repository::validate_repo_root(&root)?;
    let migration = fs::read(root.join("server/migrations/0001_bip448_schema.sql"))?;
    anyhow::ensure!(
        hex::encode(Sha256::digest(&migration))
            == "16bc984910b01a7986f47c3c8f219c9ad63f3fcb847c853faa932fa5b0eef726",
        "authenticated Mercury migration source digest drifted"
    );
    sqlx::raw_sql(std::str::from_utf8(&migration)?)
        .execute(&pool)
        .await?;
    let catalog = postgres::inspect(&pool, true).await?;
    postgres_contract::compare_catalog(
        "Mercury",
        &postgres_contract::exact_report().mercury,
        &catalog,
    )?;
    Ok(())
}

#[tokio::test]
#[ignore = "isolated real ClientConfig migration smoke mutates process environment"]
async fn real_client_config_helper_runs_full_catalog_and_preserves_sentinels() {
    let temp = Temp::new();
    let settings = temp.0.join(HELPER_SETTINGS);
    let database = temp.0.join(HELPER_DATABASE);
    let contents = format!(
        concat!(
            "statechain_entity = \"http://127.0.0.1:25400\"\n",
            "chain_backend = \"core\"\n",
            "core_rpc_url = \"http://127.0.0.1:25405\"\n",
            "core_rpc_auth = \"userpass\"\n",
            "core_rpc_user = \"mercury\"\n",
            "core_rpc_password = \"mercury\"\n",
            "network = \"regtest\"\n",
            "fee_rate_tolerance = 5\n",
            "database_file = {}\n",
            "confirmation_target = 2\n",
            "max_fee_rate = 1\n"
        ),
        serde_json::to_string(database.to_str().unwrap()).unwrap()
    );
    fs::write(&settings, contents).unwrap();
    fs::set_permissions(&settings, fs::Permissions::from_mode(0o600)).unwrap();
    regular(&database, 0o600);
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let migration =
        fs::read_to_string(root.join("clients/libs/rust/migrations/0001_bip448_client_schema.sql"))
            .unwrap();

    let report = client_db::helper(&settings, &database, &migration)
        .await
        .unwrap();
    assert_eq!(
        client_contract::verify(&root, &report).unwrap(),
        "caf67571223104362ec79d64e4ea9ffbf007b2eda8fd121fd217f08b8a7d084a"
    );
}
