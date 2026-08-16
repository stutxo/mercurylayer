use std::path::Path;

use anyhow::{Context, Result};
use sqlx::postgres::PgPoolOptions;

use super::postgres_contract;
use super::report::{MigrationRow, PgCatalog, PgColumn, PgConstraint, PgIndex, PostgresReport};

const INDEX_QUERY: &str = "SELECT n.nspname,t.relname,i.relname,x.indisunique,x.indisprimary,\
     ARRAY(SELECT a.attname::text FROM unnest(x.indkey) WITH ORDINALITY keys(attnum,ord) \
       JOIN pg_catalog.pg_attribute a ON a.attrelid=t.oid AND a.attnum=keys.attnum \
       ORDER BY keys.ord),\
     pg_get_expr(x.indpred,x.indrelid,true),pg_get_indexdef(x.indexrelid,0,false) \
     FROM pg_catalog.pg_index x \
     JOIN pg_catalog.pg_class i ON i.oid=x.indexrelid \
     JOIN pg_catalog.pg_class t ON t.oid=x.indrelid \
     JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace \
     WHERE n.nspname='public' AND (NOT $1 OR t.relname <> '_sqlx_migrations') \
     ORDER BY t.relname,i.relname";

pub(super) async fn helper(mercury_url: &str, lockbox_url: &str) -> Result<PostgresReport> {
    let mercury = PgPoolOptions::new()
        .max_connections(1)
        .connect(mercury_url)
        .await
        .context("connect verifier to Mercury PostgreSQL")?;
    let lockbox = PgPoolOptions::new()
        .max_connections(1)
        .connect(lockbox_url)
        .await
        .context("connect verifier to lockbox PostgreSQL")?;

    let mercury_catalog = inspect(&mercury, true).await?;
    let mercury_migrations = sqlx::query_as::<_, (i64, String, String, bool, String, i64)>(
        "SELECT version,description,installed_on::text,success,encode(checksum,'hex'),execution_time \
         FROM _sqlx_migrations ORDER BY version",
    )
    .fetch_all(&mercury)
    .await?
    .into_iter()
    .map(
        |(version, description, installed_on, success, checksum_hex, execution_time)| {
            MigrationRow {
                version,
                description,
                installed_on,
                success,
                checksum_hex,
                execution_time,
            }
        },
    )
    .collect();
    let lockbox_catalog = inspect(&lockbox, false).await?;
    mercury.close().await;
    lockbox.close().await;
    Ok(PostgresReport {
        mercury: mercury_catalog,
        mercury_migrations,
        lockbox: lockbox_catalog,
    })
}

pub(super) async fn inspect(pool: &sqlx::PgPool, exclude_migrations: bool) -> Result<PgCatalog> {
    let tables = sqlx::query_scalar::<_, String>(
        "SELECT table_name FROM information_schema.tables WHERE table_schema='public' \
         AND table_type='BASE TABLE' AND (NOT $1 OR table_name <> '_sqlx_migrations') \
         ORDER BY table_name",
    )
    .bind(exclude_migrations)
    .fetch_all(pool)
    .await?;

    let columns = sqlx::query_as::<_, (String, String, i32, String, String, bool, Option<String>)>(
        "SELECT table_schema,table_name,ordinal_position,column_name,\
         CASE WHEN character_maximum_length IS NULL THEN data_type \
              ELSE data_type || '(' || character_maximum_length::text || ')' END,\
         is_nullable='YES',column_default FROM information_schema.columns \
         WHERE table_schema='public' AND (NOT $1 OR table_name <> '_sqlx_migrations') \
         ORDER BY table_name,ordinal_position",
    )
    .bind(exclude_migrations)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(
        |(schema, table, ordinal, name, data_type, nullable, default)| PgColumn {
            schema,
            table,
            ordinal,
            name,
            data_type,
            nullable,
            default: default.map(|value| normalize_sql(&value)),
        },
    )
    .collect();

    let constraints = sqlx::query_as::<_, (String, String, String, String, Vec<String>, String)>(
        "SELECT n.nspname,t.relname,c.conname,c.contype::text,\
         COALESCE(array_agg(a.attname ORDER BY keys.ord) \
           FILTER (WHERE a.attname IS NOT NULL),ARRAY[]::name[])::text[],\
         pg_get_constraintdef(c.oid,true) \
         FROM pg_catalog.pg_constraint c \
         JOIN pg_catalog.pg_class t ON t.oid=c.conrelid \
         JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace \
         LEFT JOIN LATERAL unnest(c.conkey) WITH ORDINALITY keys(attnum,ord) ON true \
         LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid=t.oid AND a.attnum=keys.attnum \
         WHERE n.nspname='public' AND (NOT $1 OR t.relname <> '_sqlx_migrations') \
         GROUP BY n.nspname,t.relname,c.conname,c.contype,c.oid \
         ORDER BY t.relname,c.conname",
    )
    .bind(exclude_migrations)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(
        |(schema, table, name, kind, columns, definition)| PgConstraint {
            schema,
            table,
            name,
            kind,
            columns,
            definition: normalize_definition(&definition),
        },
    )
    .collect();

    let indexes = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            bool,
            bool,
            Vec<String>,
            Option<String>,
            String,
        ),
    >(INDEX_QUERY)
    .bind(exclude_migrations)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(
        |(schema, table, name, unique, primary, columns, predicate, definition)| PgIndex {
            schema,
            table,
            name,
            unique,
            primary,
            columns,
            predicate: predicate.map(|value| normalize_predicate(&value)),
            definition: normalize_index_definition(&definition),
        },
    )
    .collect();
    Ok(PgCatalog {
        tables,
        columns,
        constraints,
        indexes,
    })
}

pub(super) fn verify(repo_root: &Path, report: &PostgresReport) -> Result<()> {
    postgres_contract::verify(repo_root, report)
}

fn normalize_sql(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn normalize_definition(value: &str) -> String {
    normalize_sql(&value.replace("::text", ""))
}

fn normalize_predicate(value: &str) -> String {
    let mut value = normalize_definition(value);
    loop {
        let Some(inner) = value
            .strip_prefix('(')
            .and_then(|value| value.strip_suffix(')'))
        else {
            break;
        };
        value = inner.trim().into();
    }
    value
}

fn normalize_index_definition(value: &str) -> String {
    let value = normalize_definition(value);
    if let Some((prefix, predicate)) = value.rsplit_once(" WHERE (") {
        if let Some(predicate) = predicate.strip_suffix(')') {
            return format!("{prefix} WHERE {predicate}");
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sql_normalization_is_deterministic_without_weakening_predicates() {
        assert_eq!(
            normalize_predicate(" ((server_partial_sig   IS NULL)) "),
            "server_partial_sig IS NULL"
        );
        assert_eq!(
            normalize_definition("CHECK ((signing_id)::text ~ 'x'::text)"),
            "CHECK ((signing_id) ~ 'x')"
        );
        assert_eq!(
            normalize_index_definition(
                "CREATE UNIQUE INDEX x ON public.t USING btree (id) \
                 WHERE (server_partial_sig IS NULL)"
            ),
            "CREATE UNIQUE INDEX x ON public.t USING btree (id) WHERE server_partial_sig IS NULL"
        );
    }

    #[test]
    fn index_query_uses_one_correlated_ordered_array_without_outer_aggregation() {
        assert!(!INDEX_QUERY.contains("GROUP BY"));
        assert!(!INDEX_QUERY.contains("array_agg"));
        assert!(INDEX_QUERY.contains("ARRAY(SELECT a.attname::text"));
        assert!(INDEX_QUERY.contains("unnest(x.indkey) WITH ORDINALITY"));
        assert!(INDEX_QUERY.contains("ORDER BY keys.ord)"));
        assert!(INDEX_QUERY.contains("pg_get_indexdef(x.indexrelid,0,false)"));
    }
}
