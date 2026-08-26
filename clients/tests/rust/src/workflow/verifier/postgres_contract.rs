use std::fs;
use std::path::Path;

use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};

use super::postgres_columns::{ColumnSpec, LOCKBOX_COLUMNS, MERCURY_COLUMNS};
use super::postgres_compare;
use super::postgres_objects::{
    ConstraintSpec, IndexSpec, LOCKBOX_CONSTRAINTS, LOCKBOX_INDEXES, MERCURY_CONSTRAINTS,
    MERCURY_INDEXES,
};
#[cfg(test)]
use super::report::MigrationRow;
use super::report::{PgCatalog, PgColumn, PgConstraint, PgIndex, PostgresReport};

const SERVER_SHA256: &str = "16bc984910b01a7986f47c3c8f219c9ad63f3fcb847c853faa932fa5b0eef726";
const LOCKBOX_SHA256: &str = "bac14d1159a1f8eb8bb0503587061acb7b4e4b5dca303f370e640062a7f3db9f";
const MIGRATION_SHA384: &str = "1b64ae4df869baac77e5193f76403ed309d096769ddc8cbf39570fb7400ff033d26a2f730863cf63330774f78eaa5fae";

pub(super) fn verify(repo_root: &Path, report: &PostgresReport) -> Result<()> {
    verify_source(
        repo_root,
        "server/migrations/0001_bip448_schema.sql",
        SERVER_SHA256,
    )?;
    verify_source(repo_root, "lockbox/src/db_manager.cpp", LOCKBOX_SHA256)?;
    compare_catalog("Mercury", &expected_mercury(), &report.mercury)?;
    compare_catalog("lockbox", &expected_lockbox(), &report.lockbox)?;
    postgres_compare::mercury_migrations(&report.mercury_migrations, MIGRATION_SHA384)?;
    Ok(())
}

pub(super) fn compare_catalog(
    service: &str,
    expected: &PgCatalog,
    actual: &PgCatalog,
) -> Result<()> {
    postgres_compare::catalog(service, expected, actual)
}

fn verify_source(root: &Path, relative: &str, expected: &str) -> Result<()> {
    let bytes = fs::read(root.join(relative)).with_context(|| format!("read {relative}"))?;
    ensure!(
        hex::encode(Sha256::digest(bytes)) == expected,
        "protected PostgreSQL schema source drifted: {relative}"
    );
    Ok(())
}

fn expected_mercury() -> PgCatalog {
    catalog(
        &[
            "bip448_signature_data",
            "lightning_latch",
            "signing_nonce_leases",
            "statechain_data",
            "statechain_transfer",
            "tokens",
        ],
        MERCURY_COLUMNS,
        MERCURY_CONSTRAINTS,
        MERCURY_INDEXES,
    )
}

fn expected_lockbox() -> PgCatalog {
    catalog(
        &[
            "bip448_keyupdate_receipt",
            "bip448_nonce_state",
            "generated_public_key",
        ],
        LOCKBOX_COLUMNS,
        LOCKBOX_CONSTRAINTS,
        LOCKBOX_INDEXES,
    )
}

fn catalog(
    tables: &[&str],
    columns: &[ColumnSpec],
    constraints: &[ConstraintSpec],
    indexes: &[IndexSpec],
) -> PgCatalog {
    PgCatalog {
        tables: tables.iter().map(|value| (*value).into()).collect(),
        columns: columns
            .iter()
            .map(
                |&(table, ordinal, name, data_type, nullable, default)| PgColumn {
                    schema: "public".into(),
                    table: table.into(),
                    ordinal,
                    name: name.into(),
                    data_type: data_type.into(),
                    nullable,
                    default: default.map(Into::into),
                },
            )
            .collect(),
        constraints: constraints
            .iter()
            .map(|&(table, name, kind, columns, definition)| PgConstraint {
                schema: "public".into(),
                table: table.into(),
                name: name.into(),
                kind: kind.into(),
                columns: columns.iter().map(|value| (*value).into()).collect(),
                definition: definition.into(),
            })
            .collect(),
        indexes: indexes
            .iter()
            .map(
                |&(table, name, unique, primary, columns, predicate)| PgIndex {
                    schema: "public".into(),
                    table: table.into(),
                    name: name.into(),
                    unique,
                    primary,
                    columns: columns.iter().map(|value| (*value).into()).collect(),
                    predicate: predicate.map(Into::into),
                    definition: format!(
                        "CREATE {}INDEX {name} ON public.{table} USING btree ({}){}",
                        if unique { "UNIQUE " } else { "" },
                        columns.join(", "),
                        predicate.map_or_else(String::new, |value| format!(" WHERE {value}"))
                    ),
                },
            )
            .collect(),
    }
}

#[cfg(test)]
pub(super) fn exact_report() -> PostgresReport {
    PostgresReport {
        mercury: expected_mercury(),
        mercury_migrations: vec![MigrationRow {
            version: 1,
            description: "bip448 schema".into(),
            installed_on: "time".into(),
            success: true,
            checksum_hex: MIGRATION_SHA384.into(),
            execution_time: 1,
        }],
        lockbox: expected_lockbox(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corrected_catalog_counts_and_named_objects_are_exact() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let exact = exact_report();
        verify(&root, &exact).unwrap();

        assert_eq!(exact.mercury.tables.len(), 6);
        assert_eq!(exact.mercury.columns.len(), 46);
        assert_eq!(exact.mercury.constraints.len(), 16);
        assert_eq!(exact.mercury.indexes.len(), 14);
        assert_eq!(exact.lockbox.tables.len(), 3);
        assert_eq!(exact.lockbox.columns.len(), 26);
        assert_eq!(exact.lockbox.constraints.len(), 17);
        assert_eq!(exact.lockbox.indexes.len(), 6);

        assert!(!exact
            .mercury
            .constraints
            .iter()
            .any(|value| value.name == "statechain_data_server_public_key_key"));
        assert!(!exact
            .mercury
            .indexes
            .iter()
            .any(|value| value.name == "statechain_data_server_public_key_key"));
        assert!(exact
            .mercury
            .constraints
            .iter()
            .any(|value| value.name == "statechain_data_server_public_key_ukey"));
        assert!(exact
            .mercury
            .indexes
            .iter()
            .any(|value| value.name == "statechain_data_server_public_key_ukey"));
        assert_eq!(
            exact
                .lockbox
                .constraints
                .iter()
                .find(|value| value.name == "bip448_nonce_state_negate_check")
                .unwrap()
                .definition,
            "CHECK (negate_seckey IS NULL OR (negate_seckey = ANY (ARRAY[0, 1])))"
        );
    }

    fn error(report: &PostgresReport) -> String {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        verify(&root, report).unwrap_err().to_string()
    }

    fn contains_all(message: &str, expected: &[&str]) {
        for value in expected {
            assert!(message.contains(value), "missing {value:?} in {message}");
        }
    }

    #[test]
    fn catalog_mutations_have_bounded_field_aware_diagnostics() {
        let exact = exact_report();
        let mut value = exact.clone();
        value.mercury.tables.pop();
        contains_all(
            &error(&value),
            &[
                "service=Mercury",
                "dimension=tables",
                "object=tokens",
                "index=5",
                "field=object",
                "actual=\"missing\"",
            ],
        );

        let mut value = exact.clone();
        value.mercury.tables.push("unexpected_table".into());
        contains_all(
            &error(&value),
            &[
                "service=Mercury",
                "dimension=tables",
                "object=unexpected_table",
                "index=6",
                "field=object",
                "expected=\"absent\"",
                "actual=\"unexpected\"",
            ],
        );

        let mut value = exact.clone();
        value.mercury.columns[0].nullable = true;
        contains_all(
            &error(&value),
            &[
                "service=Mercury",
                "dimension=columns",
                "object=public.bip448_signature_data.id",
                "index=0",
                "field=nullable",
                "expected=false",
                "actual=true",
            ],
        );

        let mut value = exact.clone();
        value.mercury.constraints[0].definition.push('x');
        contains_all(
            &error(&value),
            &[
                "service=Mercury",
                "dimension=constraints",
                "field=definition",
                "expected=",
                "actual=",
            ],
        );

        let mut value = exact.clone();
        value.mercury.indexes.pop();
        contains_all(
            &error(&value),
            &[
                "service=Mercury",
                "dimension=indexes",
                "object=public.tokens.tokens_token_id_key",
                "field=object",
                "actual=\"missing\"",
            ],
        );

        let mut value = exact.clone();
        value.lockbox.columns[0].nullable = !value.lockbox.columns[0].nullable;
        contains_all(
            &error(&value),
            &[
                "service=lockbox",
                "dimension=columns",
                "object=public.bip448_keyupdate_receipt.statechain_id",
                "field=nullable",
            ],
        );
    }

    #[test]
    fn migration_identity_and_value_diagnostics_are_field_specific() {
        let exact = exact_report();
        let mut value = exact.clone();
        value.mercury_migrations[0].version = 2;
        contains_all(
            &error(&value),
            &[
                "service=Mercury",
                "dimension=migrations",
                "object=migration-row",
                "index=0",
                "field=version",
                "expected=1",
                "actual=2",
            ],
        );

        let mut value = exact;
        value.mercury_migrations[0].checksum_hex.push('0');
        contains_all(
            &error(&value),
            &[
                "service=Mercury",
                "dimension=migrations",
                "field=checksum_hex",
                "expected=",
                "actual=",
            ],
        );
    }
}
