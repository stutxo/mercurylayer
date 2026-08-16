use std::fmt::Debug;

use anyhow::{anyhow, Result};

use super::report::{MigrationRow, PgCatalog, PgColumn, PgConstraint, PgIndex};

const MAX_DIAGNOSTIC_VALUE_CHARS: usize = 160;

pub(super) fn catalog(service: &str, expected: &PgCatalog, actual: &PgCatalog) -> Result<()> {
    identities(service, "tables", &expected.tables, &actual.tables)?;

    let expected_ids = expected.columns.iter().map(column_id).collect::<Vec<_>>();
    let actual_ids = actual.columns.iter().map(column_id).collect::<Vec<_>>();
    identities(service, "columns", &expected_ids, &actual_ids)?;
    for (index, (expected, actual)) in expected
        .columns
        .iter()
        .zip(actual.columns.iter())
        .enumerate()
    {
        compare_column(service, index, &expected_ids[index], expected, actual)?;
    }

    let expected_ids = expected
        .constraints
        .iter()
        .map(constraint_id)
        .collect::<Vec<_>>();
    let actual_ids = actual
        .constraints
        .iter()
        .map(constraint_id)
        .collect::<Vec<_>>();
    identities(service, "constraints", &expected_ids, &actual_ids)?;
    for (index, (expected, actual)) in expected
        .constraints
        .iter()
        .zip(actual.constraints.iter())
        .enumerate()
    {
        compare_constraint(service, index, &expected_ids[index], expected, actual)?;
    }

    let expected_ids = expected.indexes.iter().map(index_id).collect::<Vec<_>>();
    let actual_ids = actual.indexes.iter().map(index_id).collect::<Vec<_>>();
    identities(service, "indexes", &expected_ids, &actual_ids)?;
    for (index, (expected, actual)) in expected
        .indexes
        .iter()
        .zip(actual.indexes.iter())
        .enumerate()
    {
        compare_index(service, index, &expected_ids[index], expected, actual)?;
    }
    Ok(())
}

pub(super) fn mercury_migrations(actual: &[MigrationRow], expected_checksum: &str) -> Result<()> {
    let service = "Mercury";
    let dimension = "migrations";
    let object = "migration-row";
    if actual.is_empty() {
        return Err(mismatch(
            service, dimension, object, 0, "object", &"present", &"missing",
        ));
    }
    if actual.len() > 1 {
        return Err(mismatch(
            service,
            dimension,
            object,
            1,
            "object",
            &"absent",
            &"unexpected",
        ));
    }
    let row = &actual[0];
    compare_field(
        service,
        dimension,
        object,
        0,
        "version",
        &1_i64,
        &row.version,
    )?;
    if row.description != "bip448 schema" {
        return Err(mismatch(
            service,
            dimension,
            object,
            0,
            "description",
            &"bip448 schema",
            &row.description,
        ));
    }
    compare_field(
        service,
        dimension,
        object,
        0,
        "success",
        &true,
        &row.success,
    )?;
    if row.installed_on.trim().is_empty() {
        return Err(mismatch(
            service,
            dimension,
            object,
            0,
            "installed_on",
            &"non-empty",
            &row.installed_on,
        ));
    }
    if row.checksum_hex != expected_checksum {
        return Err(mismatch(
            service,
            dimension,
            object,
            0,
            "checksum_hex",
            &expected_checksum,
            &row.checksum_hex,
        ));
    }
    if row.execution_time < 0 {
        return Err(mismatch(
            service,
            dimension,
            object,
            0,
            "execution_time",
            &">= 0",
            &row.execution_time,
        ));
    }
    Ok(())
}

fn identities(
    service: &str,
    dimension: &str,
    expected: &[String],
    actual: &[String],
) -> Result<()> {
    for (index, object) in expected.iter().enumerate() {
        let required = expected[..=index]
            .iter()
            .filter(|candidate| *candidate == object)
            .count();
        let present = actual
            .iter()
            .filter(|candidate| *candidate == object)
            .count();
        if present < required {
            return Err(mismatch(
                service, dimension, object, index, "object", &"present", &"missing",
            ));
        }
    }
    for (index, object) in actual.iter().enumerate() {
        let present = actual[..=index]
            .iter()
            .filter(|candidate| *candidate == object)
            .count();
        let allowed = expected
            .iter()
            .filter(|candidate| *candidate == object)
            .count();
        if present > allowed {
            return Err(mismatch(
                service,
                dimension,
                object,
                index,
                "object",
                &"absent",
                &"unexpected",
            ));
        }
    }
    for (index, (expected, actual)) in expected.iter().zip(actual.iter()).enumerate() {
        if expected != actual {
            return Err(mismatch(
                service, dimension, expected, index, "order", expected, actual,
            ));
        }
    }
    Ok(())
}

fn compare_column(
    service: &str,
    index: usize,
    object: &str,
    expected: &PgColumn,
    actual: &PgColumn,
) -> Result<()> {
    compare_field(
        service,
        "columns",
        object,
        index,
        "schema",
        &expected.schema,
        &actual.schema,
    )?;
    compare_field(
        service,
        "columns",
        object,
        index,
        "table",
        &expected.table,
        &actual.table,
    )?;
    compare_field(
        service,
        "columns",
        object,
        index,
        "ordinal",
        &expected.ordinal,
        &actual.ordinal,
    )?;
    compare_field(
        service,
        "columns",
        object,
        index,
        "name",
        &expected.name,
        &actual.name,
    )?;
    compare_field(
        service,
        "columns",
        object,
        index,
        "data_type",
        &expected.data_type,
        &actual.data_type,
    )?;
    compare_field(
        service,
        "columns",
        object,
        index,
        "nullable",
        &expected.nullable,
        &actual.nullable,
    )?;
    compare_field(
        service,
        "columns",
        object,
        index,
        "default",
        &expected.default,
        &actual.default,
    )
}

fn compare_constraint(
    service: &str,
    index: usize,
    object: &str,
    expected: &PgConstraint,
    actual: &PgConstraint,
) -> Result<()> {
    compare_field(
        service,
        "constraints",
        object,
        index,
        "schema",
        &expected.schema,
        &actual.schema,
    )?;
    compare_field(
        service,
        "constraints",
        object,
        index,
        "table",
        &expected.table,
        &actual.table,
    )?;
    compare_field(
        service,
        "constraints",
        object,
        index,
        "name",
        &expected.name,
        &actual.name,
    )?;
    compare_field(
        service,
        "constraints",
        object,
        index,
        "kind",
        &expected.kind,
        &actual.kind,
    )?;
    compare_field(
        service,
        "constraints",
        object,
        index,
        "columns",
        &expected.columns,
        &actual.columns,
    )?;
    compare_field(
        service,
        "constraints",
        object,
        index,
        "definition",
        &expected.definition,
        &actual.definition,
    )
}

fn compare_index(
    service: &str,
    index: usize,
    object: &str,
    expected: &PgIndex,
    actual: &PgIndex,
) -> Result<()> {
    compare_field(
        service,
        "indexes",
        object,
        index,
        "schema",
        &expected.schema,
        &actual.schema,
    )?;
    compare_field(
        service,
        "indexes",
        object,
        index,
        "table",
        &expected.table,
        &actual.table,
    )?;
    compare_field(
        service,
        "indexes",
        object,
        index,
        "name",
        &expected.name,
        &actual.name,
    )?;
    compare_field(
        service,
        "indexes",
        object,
        index,
        "unique",
        &expected.unique,
        &actual.unique,
    )?;
    compare_field(
        service,
        "indexes",
        object,
        index,
        "primary",
        &expected.primary,
        &actual.primary,
    )?;
    compare_field(
        service,
        "indexes",
        object,
        index,
        "columns",
        &expected.columns,
        &actual.columns,
    )?;
    compare_field(
        service,
        "indexes",
        object,
        index,
        "predicate",
        &expected.predicate,
        &actual.predicate,
    )?;
    compare_field(
        service,
        "indexes",
        object,
        index,
        "definition",
        &expected.definition,
        &actual.definition,
    )
}

fn compare_field<T: Debug + PartialEq>(
    service: &str,
    dimension: &str,
    object: &str,
    index: usize,
    field: &str,
    expected: &T,
    actual: &T,
) -> Result<()> {
    if expected != actual {
        return Err(mismatch(
            service, dimension, object, index, field, expected, actual,
        ));
    }
    Ok(())
}

fn mismatch(
    service: &str,
    dimension: &str,
    object: &str,
    index: usize,
    field: &str,
    expected: &dyn Debug,
    actual: &dyn Debug,
) -> anyhow::Error {
    anyhow!(
        "PostgreSQL contract mismatch service={} dimension={} object={} index={} field={} expected={} actual={}",
        bounded(service),
        bounded(dimension),
        bounded(object),
        index,
        bounded(field),
        bounded_debug(expected),
        bounded_debug(actual),
    )
}

fn column_id(value: &PgColumn) -> String {
    format!("{}.{}.{}", value.schema, value.table, value.name)
}

fn constraint_id(value: &PgConstraint) -> String {
    format!("{}.{}.{}", value.schema, value.table, value.name)
}

fn index_id(value: &PgIndex) -> String {
    format!("{}.{}.{}", value.schema, value.table, value.name)
}

fn bounded_debug(value: &dyn Debug) -> String {
    bounded(&format!("{value:?}"))
}

fn bounded(value: &str) -> String {
    let mut chars = value.chars();
    let prefix = chars
        .by_ref()
        .take(MAX_DIAGNOSTIC_VALUE_CHARS)
        .collect::<String>();
    if chars.next().is_some() {
        format!("{prefix}…")
    } else {
        prefix
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_bound_every_untrusted_value() {
        let long = "x".repeat(MAX_DIAGNOSTIC_VALUE_CHARS * 4);
        let error = mismatch(&long, &long, &long, 0, &long, &long, &long).to_string();
        assert!(error.len() < MAX_DIAGNOSTIC_VALUE_CHARS * 8);
        assert!(error.contains('…'));
    }
}
