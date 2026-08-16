use std::fs;
use std::path::Path;

use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};

use super::report::{ClientDatabaseReport, SqliteCatalog};
#[cfg(test)]
use super::report::{SqliteColumn, SqliteIndex};

const MIGRATION: &str = "clients/libs/rust/migrations/0001_bip448_client_schema.sql";
const MIGRATION_SHA256: &str = "caf67571223104362ec79d64e4ea9ffbf007b2eda8fd121fd217f08b8a7d084a";
const TABLE_COUNT: usize = 12;
const INDEX_COUNT: usize = 3;

pub(super) fn verify(repo_root: &Path, report: &ClientDatabaseReport) -> Result<String> {
    let migration = fs::read(repo_root.join(MIGRATION)).context("read client SQLite migration")?;
    let digest = hex::encode(Sha256::digest(&migration));
    ensure!(
        digest == MIGRATION_SHA256,
        "client SQLite migration SHA256 drifted"
    );
    std::str::from_utf8(&migration).context("client migration is not UTF-8")?;
    validate_expected(&report.reference_catalog)?;
    verify_report(&report.reference_catalog, report)?;
    Ok(digest)
}

fn validate_expected(catalog: &SqliteCatalog) -> Result<()> {
    ensure!(
        catalog.application_tables.len() == TABLE_COUNT
            && catalog.columns.len() == TABLE_COUNT
            && catalog.table_sql.len() == TABLE_COUNT
            && catalog.foreign_key_counts.len() == TABLE_COUNT,
        "SHA-pinned client migration does not materialize twelve complete application tables"
    );
    ensure!(
        catalog.indexes.len() == INDEX_COUNT
            && catalog.indexes.iter().all(|index| index.unique)
            && catalog
                .indexes
                .iter()
                .all(|index| index.normalized_sql.contains(" WHERE ")),
        "SHA-pinned client migration does not materialize three partial unique indexes"
    );
    ensure!(
        catalog.foreign_key_counts.values().all(|count| *count == 0) && catalog.backup_txs_absent,
        "SHA-pinned client migration contains a foreign key or legacy backup table"
    );
    Ok(())
}

fn verify_report(expected: &SqliteCatalog, report: &ClientDatabaseReport) -> Result<()> {
    ensure!(
        report.catalog == *expected,
        "live client SQLite tables, six-field columns, table SQL/CHECKs, indexes, or FKs drifted"
    );
    ensure!(
        report.migrations_applied_twice,
        "client migration did not remain singular and successful after two loads"
    );
    ensure!(
        report.sentinel_wallet_preserved && report.sentinel_statechain_preserved,
        "client migration rerun did not preserve deterministic wallet/statechain sentinels"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn exact() -> (SqliteCatalog, ClientDatabaseReport) {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let migration = fs::read_to_string(root.join(MIGRATION)).unwrap();
        let catalog = super::super::client_db::materialize_catalog(&migration)
            .await
            .unwrap();
        let report = ClientDatabaseReport {
            catalog: catalog.clone(),
            reference_catalog: catalog.clone(),
            migrations_applied_twice: true,
            sentinel_wallet_preserved: true,
            sentinel_statechain_preserved: true,
        };
        (catalog, report)
    }

    #[tokio::test]
    async fn exact_catalog_passes_and_missing_extra_field_check_or_index_drift_fails() {
        let (expected, report) = exact().await;
        verify_report(&expected, &report).unwrap();

        let mut missing = report.clone();
        missing.catalog.application_tables.pop();
        assert!(verify_report(&expected, &missing).is_err());

        let mut extra = report.clone();
        extra.catalog.columns.insert(
            "extra".into(),
            vec![SqliteColumn {
                ordinal: 0,
                name: "extra".into(),
                data_type: "TEXT".into(),
                not_null: 0,
                default_value: None,
                primary_key_ordinal: 0,
            }],
        );
        assert!(verify_report(&expected, &extra).is_err());

        let mut field = report.clone();
        field.catalog.columns.values_mut().next().unwrap()[0].data_type = "BLOB".into();
        assert!(verify_report(&expected, &field).is_err());

        let mut check = report.clone();
        check
            .catalog
            .table_sql
            .values_mut()
            .next()
            .unwrap()
            .push_str(" CHECK (0)");
        assert!(verify_report(&expected, &check).is_err());

        let mut index = report;
        index.catalog.indexes.push(SqliteIndex {
            name: "extra".into(),
            table: "wallet".into(),
            unique: false,
            columns: vec!["wallet_name".into()],
            normalized_sql: "CREATE INDEX extra ON wallet (wallet_name)".into(),
        });
        assert!(verify_report(&expected, &index).is_err());
    }
}
