use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{ensure, Context, Result};
use sqlx::Row;

use super::report::{ClientDatabaseReport, SqliteCatalog, SqliteColumn, SqliteIndex};

pub(super) async fn helper(
    settings: &Path,
    database: &Path,
    migration: &str,
) -> Result<ClientDatabaseReport> {
    ensure!(
        settings.parent() == database.parent(),
        "client helper Settings and DB must share the controller run directory"
    );
    std::env::set_var("ML_SETTINGS_FILE", settings);
    std::env::remove_var("ML_NETWORK");

    let first = mercuryrustlib::client_config::ClientConfig::load().await;
    sqlx::query("INSERT INTO wallet (wallet_name,wallet_json) VALUES ($1,$2)")
        .bind("bip448-verifier-sentinel")
        .bind("{\"sentinel\":\"wallet\"}")
        .execute(&first.pool)
        .await
        .context("insert deterministic verifier wallet sentinel")?;
    sqlx::query(
        "INSERT INTO bip448_statechains (wallet_name,statechain_id,aggregate_pubkey,\
         funding_txid,funding_vout,funding_value_sats,latest_state_number,challenge_delay,\
         amount_sats,network,record_json) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind("bip448-verifier-sentinel")
    .bind("bip448-verifier-statechain")
    .bind(format!("02{}", "11".repeat(32)))
    .bind("22".repeat(32))
    .bind(0_i64)
    .bind(100_000_i64)
    .bind(1_i64)
    .bind(144_i64)
    .bind(100_000_i64)
    .bind("regtest")
    .bind("{\"sentinel\":\"accepted-statechain\"}")
    .execute(&first.pool)
    .await
    .context("insert deterministic accepted statechain sentinel")?;
    first.pool.close().await;

    let second = mercuryrustlib::client_config::ClientConfig::load().await;
    let catalog = inspect_catalog(&second.pool).await?;
    let reference_catalog = materialize_catalog(migration).await?;
    let (migrations, successful_migrations): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*),COALESCE(SUM(CASE WHEN success=1 THEN 1 ELSE 0 END),0) \
         FROM _sqlx_migrations",
    )
    .fetch_one(&second.pool)
    .await?;
    let wallet: Option<String> = sqlx::query_scalar(
        "SELECT wallet_json FROM wallet WHERE wallet_name='bip448-verifier-sentinel'",
    )
    .fetch_optional(&second.pool)
    .await?;
    let statechain: Option<String> = sqlx::query_scalar(
        "SELECT record_json FROM bip448_statechains WHERE wallet_name='bip448-verifier-sentinel' \
         AND statechain_id='bip448-verifier-statechain'",
    )
    .fetch_optional(&second.pool)
    .await?;
    second.pool.close().await;
    Ok(ClientDatabaseReport {
        catalog,
        reference_catalog,
        migrations_applied_twice: migrations == 1 && successful_migrations == 1,
        sentinel_wallet_preserved: wallet.as_deref() == Some("{\"sentinel\":\"wallet\"}"),
        sentinel_statechain_preserved: statechain.as_deref()
            == Some("{\"sentinel\":\"accepted-statechain\"}"),
    })
}

pub(super) async fn materialize_catalog(migration: &str) -> Result<SqliteCatalog> {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .context("open source-backed in-memory SQLite catalog")?;
    sqlx::raw_sql(migration)
        .execute(&pool)
        .await
        .context("materialize SHA-pinned client migration in memory")?;
    let catalog = inspect_catalog(&pool).await?;
    pool.close().await;
    Ok(catalog)
}

pub(super) async fn inspect_catalog(pool: &sqlx::Pool<sqlx::Sqlite>) -> Result<SqliteCatalog> {
    let application_tables = sqlx::query_scalar::<_, String>(
        "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' \
         AND name <> '_sqlx_migrations' ORDER BY name",
    )
    .fetch_all(pool)
    .await?;

    let mut columns = BTreeMap::new();
    let mut table_sql = BTreeMap::new();
    let mut foreign_key_counts = BTreeMap::new();
    for table in &application_tables {
        let metadata = sqlx::query(
            "SELECT cid,name,type,\"notnull\",dflt_value,pk FROM pragma_table_info($1) \
             ORDER BY cid",
        )
        .bind(table)
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|row| {
            Ok(SqliteColumn {
                ordinal: row.try_get(0)?,
                name: row.try_get(1)?,
                data_type: row.try_get(2)?,
                not_null: row.try_get(3)?,
                default_value: row.try_get(4)?,
                primary_key_ordinal: row.try_get(5)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
        columns.insert(table.clone(), metadata);

        let sql: String =
            sqlx::query_scalar("SELECT sql FROM sqlite_schema WHERE type='table' AND name=$1")
                .bind(table)
                .fetch_one(pool)
                .await?;
        table_sql.insert(table.clone(), normalize_sql(&sql));

        let foreign_keys: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM pragma_foreign_key_list($1)")
                .bind(table)
                .fetch_one(pool)
                .await?;
        foreign_key_counts.insert(table.clone(), usize::try_from(foreign_keys)?);
    }

    let raw_indexes = sqlx::query_as::<_, (String, String, String)>(
        "SELECT name,tbl_name,sql FROM sqlite_schema WHERE type='index' AND sql IS NOT NULL \
         ORDER BY name",
    )
    .fetch_all(pool)
    .await?;
    let mut indexes = Vec::with_capacity(raw_indexes.len());
    for (name, table, sql) in raw_indexes {
        let unique: i64 =
            sqlx::query_scalar("SELECT \"unique\" FROM pragma_index_list($1) WHERE name=$2")
                .bind(&table)
                .bind(&name)
                .fetch_one(pool)
                .await?;
        let index_columns = sqlx::query_scalar::<_, String>(
            "SELECT name FROM pragma_index_info($1) ORDER BY seqno",
        )
        .bind(&name)
        .fetch_all(pool)
        .await?;
        indexes.push(SqliteIndex {
            name,
            table,
            unique: unique == 1,
            columns: index_columns,
            normalized_sql: normalize_sql(&sql),
        });
    }

    let backup_txs_absent: i64 = sqlx::query_scalar(
        "SELECT NOT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='backup_txs')",
    )
    .fetch_one(pool)
    .await?;
    Ok(SqliteCatalog {
        application_tables,
        columns,
        table_sql,
        indexes,
        foreign_key_counts,
        backup_txs_absent: backup_txs_absent == 1,
    })
}

pub(super) fn normalize_sql(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}
