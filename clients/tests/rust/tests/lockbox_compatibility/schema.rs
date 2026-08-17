use super::*;

pub(super) async fn fresh_lockbox_schema_has_only_bip448_nonce_state_columns() -> Result<()> {
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    lockbox::wait_until_ready(&client).await?;

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(lockbox::database_url())
        .await
        .context("failed to connect to lockbox postgres")?;
    let tables: Vec<(String,)> = sqlx::query_as(
        "SELECT table_name FROM information_schema.tables \
         WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY table_name",
    )
    .fetch_all(&pool)
    .await?;
    assert_eq!(
        tables,
        vec![
            ("bip448_keyupdate_receipt".to_string(),),
            ("bip448_nonce_state".to_string(),),
            ("generated_public_key".to_string(),),
        ]
    );

    let columns: Vec<(String, String)> = sqlx::query_as(
        "SELECT table_name, column_name FROM information_schema.columns \
         WHERE table_schema = 'public' \
         AND table_name IN ('generated_public_key', 'bip448_nonce_state', 'bip448_keyupdate_receipt') \
         ORDER BY table_name, ordinal_position",
    )
    .fetch_all(&pool)
    .await?;
    let bip448_nonce_state_columns = columns
        .iter()
        .filter(|(table, _)| table == "bip448_nonce_state")
        .map(|(_, column)| column.as_str())
        .collect::<Vec<_>>();
    let generated_public_key_columns = columns
        .iter()
        .filter(|(table, _)| table == "generated_public_key")
        .map(|(_, column)| column.as_str())
        .collect::<Vec<_>>();

    assert_eq!(
        bip448_nonce_state_columns,
        vec![
            "id",
            "statechain_id",
            "signing_id",
            "key_generation",
            "public_nonce",
            "sealed_secnonce",
            "challenge",
            "negate_seckey",
            "partial_sig",
            "created_at",
            "updated_at",
        ]
    );
    assert_eq!(
        generated_public_key_columns,
        vec![
            "id",
            "statechain_id",
            "sealed_keypair",
            "public_key",
            "sig_count",
            "key_generation",
        ]
    );
    let receipt_columns = columns
        .iter()
        .filter(|(table, _)| table == "bip448_keyupdate_receipt")
        .map(|(_, column)| column.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        receipt_columns,
        vec![
            "statechain_id",
            "operation_id",
            "request_hash",
            "accepted_sig_count",
            "previous_key_generation",
            "resulting_key_generation",
            "previous_server_pubkey",
            "resulting_server_pubkey",
            "transfer_generation_pubkey",
        ]
    );
    assert!(!generated_public_key_columns.contains(&"sealed_secnonce"));
    assert!(!generated_public_key_columns.contains(&"public_nonce"));

    let bigint_properties: Vec<(String, String, String, String, Option<String>)> =
        sqlx::query_as(
            "SELECT table_name, column_name, data_type, is_nullable, column_default \
             FROM information_schema.columns WHERE table_schema='public' AND ( \
               (table_name='generated_public_key' AND column_name IN ('sig_count','key_generation')) OR \
               (table_name='bip448_nonce_state' AND column_name='key_generation') OR \
               (table_name='bip448_keyupdate_receipt' AND column_name IN \
                 ('accepted_sig_count','previous_key_generation','resulting_key_generation'))) \
             ORDER BY table_name, column_name",
        )
        .fetch_all(&pool)
        .await?;
    assert_eq!(
        bigint_properties,
        vec![
            (
                "bip448_keyupdate_receipt".to_string(),
                "accepted_sig_count".to_string(),
                "bigint".to_string(),
                "NO".to_string(),
                None,
            ),
            (
                "bip448_keyupdate_receipt".to_string(),
                "previous_key_generation".to_string(),
                "bigint".to_string(),
                "NO".to_string(),
                None,
            ),
            (
                "bip448_keyupdate_receipt".to_string(),
                "resulting_key_generation".to_string(),
                "bigint".to_string(),
                "NO".to_string(),
                None,
            ),
            (
                "bip448_nonce_state".to_string(),
                "key_generation".to_string(),
                "bigint".to_string(),
                "NO".to_string(),
                None,
            ),
            (
                "generated_public_key".to_string(),
                "key_generation".to_string(),
                "bigint".to_string(),
                "NO".to_string(),
                Some("0".to_string()),
            ),
            (
                "generated_public_key".to_string(),
                "sig_count".to_string(),
                "bigint".to_string(),
                "NO".to_string(),
                Some("0".to_string()),
            ),
        ]
    );

    let receipt_foreign_keys: Vec<(String, String)> = sqlx::query_as(
        "SELECT kcu.column_name, rc.delete_rule \
         FROM information_schema.table_constraints tc \
         JOIN information_schema.referential_constraints rc \
           ON rc.constraint_catalog=tc.constraint_catalog \
          AND rc.constraint_schema=tc.constraint_schema \
          AND rc.constraint_name=tc.constraint_name \
         JOIN information_schema.key_column_usage kcu \
           ON kcu.constraint_catalog=tc.constraint_catalog \
          AND kcu.constraint_schema=tc.constraint_schema \
          AND kcu.constraint_name=tc.constraint_name \
         WHERE tc.table_schema='public' \
           AND tc.table_name='bip448_keyupdate_receipt' \
           AND tc.constraint_type='FOREIGN KEY' \
         ORDER BY kcu.ordinal_position",
    )
    .fetch_all(&pool)
    .await?;
    assert_eq!(
        receipt_foreign_keys,
        vec![("statechain_id".to_string(), "CASCADE".to_string())]
    );

    Ok(())
}

pub(super) async fn fresh_mercury_schema_has_exact_bip448_tables_and_lease_columns() -> Result<()> {
    let _guard = common::test_guard();
    let client = mercury::http_client();
    mercury::wait_until_ready(&client).await?;

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(mercury::database_url())
        .await
        .context("failed to connect to mercury postgres")?;
    let tables = sqlx::query_scalar::<_, String>(
        "SELECT table_name FROM information_schema.tables \
         WHERE table_schema = 'public' AND table_type = 'BASE TABLE' \
           AND table_name <> '_sqlx_migrations' \
         ORDER BY table_name",
    )
    .fetch_all(&pool)
    .await?;
    assert_eq!(
        tables,
        vec![
            "bip448_signature_data",
            "lightning_latch",
            "signing_nonce_leases",
            "statechain_data",
            "statechain_transfer",
            "tokens",
        ]
    );

    let lease_columns = sqlx::query_scalar::<_, String>(
        "SELECT column_name FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = 'signing_nonce_leases' \
         ORDER BY ordinal_position",
    )
    .fetch_all(&pool)
    .await?;
    assert_eq!(
        lease_columns,
        vec![
            "statechain_id",
            "signing_id",
            "lease_token",
            "created_at",
            "updated_at",
        ]
    );
    assert!(!lease_columns.iter().any(|column| column == "protocol"));

    let old_signing_tables = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM information_schema.tables \
         WHERE table_schema = 'public' \
           AND table_name IN ('statechain_signature_data', 'statechain_signing_protocol')",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(old_signing_tables, 0);

    let lease_protocol_columns = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = 'signing_nonce_leases' \
           AND column_name = 'protocol'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(lease_protocol_columns, 0);

    Ok(())
}
