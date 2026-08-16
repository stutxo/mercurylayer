use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Route {
    pub(super) service: String,
    pub(super) handler: String,
    pub(super) method: String,
    pub(super) path: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SettingsReport {
    pub(super) keys: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SqliteColumn {
    pub(super) ordinal: i64,
    pub(super) name: String,
    pub(super) data_type: String,
    pub(super) not_null: i64,
    pub(super) default_value: Option<String>,
    pub(super) primary_key_ordinal: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SqliteIndex {
    pub(super) name: String,
    pub(super) table: String,
    pub(super) unique: bool,
    pub(super) columns: Vec<String>,
    pub(super) normalized_sql: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SqliteCatalog {
    pub(super) application_tables: Vec<String>,
    pub(super) columns: BTreeMap<String, Vec<SqliteColumn>>,
    pub(super) table_sql: BTreeMap<String, String>,
    pub(super) indexes: Vec<SqliteIndex>,
    pub(super) foreign_key_counts: BTreeMap<String, usize>,
    pub(super) backup_txs_absent: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ClientDatabaseReport {
    pub(super) catalog: SqliteCatalog,
    pub(super) reference_catalog: SqliteCatalog,
    pub(super) migrations_applied_twice: bool,
    pub(super) sentinel_wallet_preserved: bool,
    pub(super) sentinel_statechain_preserved: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MigrationRow {
    pub(super) version: i64,
    pub(super) description: String,
    pub(super) installed_on: String,
    pub(super) success: bool,
    pub(super) checksum_hex: String,
    pub(super) execution_time: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PgIndex {
    pub(super) schema: String,
    pub(super) table: String,
    pub(super) name: String,
    pub(super) unique: bool,
    pub(super) primary: bool,
    pub(super) columns: Vec<String>,
    pub(super) predicate: Option<String>,
    pub(super) definition: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PgColumn {
    pub(super) schema: String,
    pub(super) table: String,
    pub(super) ordinal: i32,
    pub(super) name: String,
    pub(super) data_type: String,
    pub(super) nullable: bool,
    pub(super) default: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PgConstraint {
    pub(super) schema: String,
    pub(super) table: String,
    pub(super) name: String,
    pub(super) kind: String,
    pub(super) columns: Vec<String>,
    pub(super) definition: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PgCatalog {
    pub(super) tables: Vec<String>,
    pub(super) columns: Vec<PgColumn>,
    pub(super) constraints: Vec<PgConstraint>,
    pub(super) indexes: Vec<PgIndex>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PostgresReport {
    pub(super) mercury: PgCatalog,
    pub(super) mercury_migrations: Vec<MigrationRow>,
    pub(super) lockbox: PgCatalog,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct VerifyReport {
    pub(super) version: u32,
    pub(super) project: String,
    pub(super) status: String,
    pub(super) settings: SettingsReport,
    pub(super) mercury_token_routes: Vec<Route>,
    pub(super) lockbox_routes: Vec<Route>,
    pub(super) client_migration_sha256: String,
    pub(super) client_database: ClientDatabaseReport,
    pub(super) postgres_before_restart: PostgresReport,
    pub(super) postgres_after_restart: PostgresReport,
    pub(super) mercury_restart_count: u32,
    pub(super) build_identity_unchanged: bool,
    pub(super) ready_after_restart: bool,
}
