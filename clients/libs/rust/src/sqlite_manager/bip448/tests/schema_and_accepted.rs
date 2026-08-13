use super::super::accepted::upsert_bip448_statechain_record;
use super::support::*;

fn pre_materialized_initial_acceptance_fixture(
    retain_observed_outpoint: bool,
) -> Result<(
    Wallet,
    Bip448StatechainRecord,
    Bip448StateHistoryEntry,
    Bip448PendingDepositSigning,
)> {
    let (mut wallet, record, entry, _) = real_accepted_fixture(CoinStatus::UNCONFIRMED)?;
    let coin = wallet
        .coins
        .first_mut()
        .ok_or_else(|| anyhow!("initial-acceptance fixture Coin is missing"))?;
    if retain_observed_outpoint {
        coin.status = CoinStatus::IN_MEMPOOL;
    } else {
        coin.utxo_txid = None;
        coin.utxo_vout = None;
        coin.status = CoinStatus::INITIALISED;
    }
    coin.locktime = None;
    coin.public_nonce = None;
    coin.server_public_nonce = None;
    coin.blinding_factor = None;
    wallet.activities.clear();
    let pending = Bip448PendingDepositSigning {
        wallet_name: record.wallet_name.clone(),
        statechain_id: record.statechain_id.clone(),
        funding_txid: record.funding_outpoint.txid.clone(),
        funding_vout: record.funding_outpoint.vout,
        funding_value_sats: record.funding_outpoint.value_sats,
        update_template_hash: entry.update_template_hash.clone(),
        settlement_template_hash: entry.settlement_template_hash.clone(),
        state_locktime: entry.state_locktime,
        signing_id: record.latest_state.signing_metadata.signing_id.clone(),
        client_secret_nonce: "ab".repeat(132),
        client_public_nonce: entry.client_public_nonce.clone(),
        blinding_factor: entry.blinding_factor.clone(),
        server_public_nonce: Some(entry.server_public_nonce.clone()),
    };
    Ok((wallet, record, entry, pending))
}

async fn install_pre_materialized_initial_acceptance(
    pool: &Pool<Sqlite>,
    retain_observed_outpoint: bool,
    retain_pending: bool,
) -> Result<(
    Bip448StatechainRecord,
    Bip448StateHistoryEntry,
    Bip448PendingDepositSigning,
    String,
)> {
    let (wallet, record, entry, pending) =
        pre_materialized_initial_acceptance_fixture(retain_observed_outpoint)?;
    insert_wallet(pool, &wallet).await?;
    insert_bip448_pending_deposit_signing_if_absent(pool, &pending).await?;
    persist_bip448_initial_acceptance(pool, &record, &entry).await?;
    if !retain_pending {
        delete_bip448_pending_deposit_signing(
            pool,
            &pending.wallet_name,
            &pending.statechain_id,
            &pending.signing_id,
        )
        .await?;
    }
    let raw_wallet = get_bip448_raw_wallet_json(pool, &wallet.name).await?;
    Ok((record, entry, pending, raw_wallet))
}

async fn accepted_table_bytes(pool: &Pool<Sqlite>) -> Result<(Vec<String>, Vec<String>)> {
    let records = sqlx::query_scalar::<_, String>(
        "SELECT record_json FROM bip448_statechains ORDER BY wallet_name, statechain_id",
    )
    .fetch_all(pool)
    .await?;
    let history = sqlx::query_scalar::<_, String>(
        "SELECT entry_json FROM bip448_state_history \
         ORDER BY wallet_name, statechain_id, state_number",
    )
    .fetch_all(pool)
    .await?;
    Ok((records, history))
}

async fn initial_acceptance_recovery_storage(
    pool: &Pool<Sqlite>,
) -> Result<(String, Vec<String>, Vec<String>, Vec<String>)> {
    let wallet = get_bip448_raw_wallet_json(pool, "wallet").await?;
    let records = sqlx::query_scalar::<_, String>(
        "SELECT json_array(wallet_name,statechain_id,aggregate_pubkey,funding_txid,\
         funding_vout,funding_value_sats,latest_state_number,challenge_delay,amount_sats,\
         network,record_json,created_at,updated_at) FROM bip448_statechains \
         ORDER BY wallet_name,statechain_id",
    )
    .fetch_all(pool)
    .await?;
    let history = sqlx::query_scalar::<_, String>(
        "SELECT json_array(wallet_name,statechain_id,state_number,entry_json) \
         FROM bip448_state_history ORDER BY wallet_name,statechain_id,state_number",
    )
    .fetch_all(pool)
    .await?;
    let pending = sqlx::query_scalar::<_, String>(
        "SELECT json_array(wallet_name,statechain_id,update_template_hash,signing_id,\
         client_secret_nonce,client_public_nonce,blinding_factor,server_public_nonce,\
         state_locktime,funding_txid,funding_vout,funding_value_sats,\
         settlement_template_hash,created_at,updated_at) \
         FROM bip448_pending_deposit_signings ORDER BY wallet_name,statechain_id",
    )
    .fetch_all(pool)
    .await?;
    Ok((wallet, records, history, pending))
}

#[tokio::test]
async fn current_migrations_are_idempotent_and_preserve_bip448_wallet_state() -> Result<()> {
    let pool = migrated_pool().await?;
    let record = sample_bip448_record(1);
    let mut wallet = sample_wallet();
    let mut coin = wallet.get_new_coin()?;
    coin.statechain_protocol =
        Some(mercurylib::bip448_statechain::deposit::BIP448_COIN_PROTOCOL.into());
    coin.statechain_id = Some(record.statechain_id.clone());
    coin.aggregated_pubkey = Some(record.aggregate_pubkey.clone());
    coin.utxo_txid = Some(record.funding_outpoint.txid.clone());
    coin.utxo_vout = Some(record.funding_outpoint.vout);
    coin.amount = Some(u32::try_from(record.amount_sats)?);
    coin.locktime = Some(record.latest_state.state_locktime);
    coin.status = CoinStatus::CONFIRMED;
    wallet.coins.push(coin);
    insert_wallet(&pool, &wallet).await?;
    upsert_bip448_statechain_record(&pool, &record).await?;

    sqlx::migrate!("./migrations").run(&pool).await?;

    let roundtrip_wallet = get_wallet(&pool, &wallet.name).await?;
    let roundtrip_record =
        get_bip448_statechain(&pool, &wallet.name, &record.statechain_id).await?;
    assert_eq!(
        roundtrip_wallet.coins[0].statechain_protocol.as_deref(),
        Some(mercurylib::bip448_statechain::deposit::BIP448_COIN_PROTOCOL)
    );
    assert_eq!(
        roundtrip_wallet.coins[0].statechain_id,
        Some("statechain".into())
    );
    assert_eq!(roundtrip_record, record);

    Ok(())
}

#[tokio::test]
async fn fresh_bip448_client_schema_has_exact_application_tables() -> Result<()> {
    let pool = migrated_pool().await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    let tables = sqlx::query_scalar::<_, String>(
        "SELECT name FROM sqlite_schema \
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%' \
           AND name <> '_sqlx_migrations' \
         ORDER BY name",
    )
    .fetch_all(&pool)
    .await?;
    assert_eq!(
        tables,
        vec![
            "bip448_funding_bindings",
            "bip448_package_attempts",
            "bip448_pending_deposit_signings",
            "bip448_pending_transfer_signings",
            "bip448_scan_cursors",
            "bip448_scanned_outpoints",
            "bip448_state_history",
            "bip448_statechains",
            "bip448_transfer_intents",
            "bip448_transfer_messages",
            "bip448_withdrawal_attempts",
            "wallet",
        ]
    );

    let expected_columns = [
        (
            "bip448_scan_cursors",
            vec![
                "wallet_name",
                "script_pubkey",
                "coverage_start_height",
                "scan_revision",
                "last_scanned_height",
                "last_scanned_block_hash",
                "updated_at",
            ],
        ),
        (
            "bip448_funding_bindings",
            vec![
                "wallet_name",
                "statechain_id",
                "binding_index",
                "txid",
                "vout",
                "value_sats",
                "script_pubkey",
                "role",
                "observation_status",
                "funding_height",
                "spend_txid",
                "spend_height",
                "last_scanned_height",
                "owner_user_pubkey",
                "owner_state_number",
                "ownership_status",
                "first_seen_at",
                "last_seen_at",
            ],
        ),
        (
            "bip448_withdrawal_attempts",
            vec![
                "wallet_name",
                "statechain_id",
                "binding_index",
                "attempt_kind",
                "owner_user_pubkey",
                "owner_state_number",
                "source_txid",
                "source_vout",
                "source_value_sats",
                "source_script_pubkey",
                "destination_address",
                "destination_script_pubkey",
                "fee_rate_sat_per_vbyte",
                "fee_sats",
                "lock_time",
                "unsigned_tx_hex",
                "signing_id",
                "signed_statechain_id",
                "sign_first_payload_json",
                "client_secret_nonce",
                "client_public_nonce",
                "blinding_factor",
                "server_public_nonce",
                "message_hex",
                "output_pubkey",
                "client_partial_sig",
                "encoded_session",
                "sign_second_payload_json",
                "server_partial_sig",
                "aggregate_signature",
                "signed_tx_hex",
                "txid",
                "phase",
                "broadcast_status",
                "completion_status",
                "closing_tip_height",
                "closing_tip_hash",
                "closing_bindings_json",
                "created_at",
                "updated_at",
            ],
        ),
        (
            "bip448_transfer_intents",
            vec![
                "wallet_name",
                "statechain_id",
                "intent_id",
                "predecessor_intent_id",
                "activity_status",
                "intent_kind",
                "acknowledge_cooperative_duplicates",
                "recipient_address",
                "receiver_user_pubkey",
                "recipient_auth_pubkey",
                "batch_id",
                "sender_signed_statechain_id",
                "planned_state_number",
                "expected_signature_count",
                "previous_locktime",
                "prior_pending_signing_id",
                "prior_transfer_recipient_auth_pubkey",
                "prior_transfer_msg_hash",
                "reuse_pending",
                "reuse_signed_state",
                "clear_local_attempt",
                "generated_coin_user_pubkey",
                "generated_coin_auth_pubkey",
                "generated_coin_address",
                "phase",
                "server_x1",
                "current_pending_signing_id",
                "state_signing_phase",
                "server_partial_sig",
                "update_signature",
                "created_at",
                "updated_at",
            ],
        ),
    ];
    for (table, names) in expected_columns {
        let pragma = format!("PRAGMA table_info('{table}')");
        let metadata: Vec<(i64, String, String, i64, Option<String>, i64)> =
            sqlx::query_as(&pragma).fetch_all(&pool).await?;
        assert_eq!(metadata.len(), names.len(), "{table} column count");
        for (offset, (cid, name, ty, not_null, default_value, pk)) in metadata.iter().enumerate() {
            assert_eq!(*cid, i64::try_from(offset)?);
            assert_eq!(name, names[offset], "{table} column {offset}");
            let expected_type = if name == "fee_rate_sat_per_vbyte" {
                "REAL"
            } else if [
                "wallet_name",
                "script_pubkey",
                "last_scanned_block_hash",
                "statechain_id",
                "txid",
                "role",
                "observation_status",
                "spend_txid",
                "owner_user_pubkey",
                "ownership_status",
                "attempt_kind",
                "source_txid",
                "source_script_pubkey",
                "destination_address",
                "destination_script_pubkey",
                "unsigned_tx_hex",
                "signing_id",
                "signed_statechain_id",
                "sign_first_payload_json",
                "client_secret_nonce",
                "client_public_nonce",
                "blinding_factor",
                "server_public_nonce",
                "message_hex",
                "output_pubkey",
                "client_partial_sig",
                "encoded_session",
                "sign_second_payload_json",
                "server_partial_sig",
                "aggregate_signature",
                "signed_tx_hex",
                "phase",
                "broadcast_status",
                "completion_status",
                "closing_tip_hash",
                "closing_bindings_json",
                "intent_id",
                "predecessor_intent_id",
                "activity_status",
                "intent_kind",
                "recipient_address",
                "receiver_user_pubkey",
                "recipient_auth_pubkey",
                "batch_id",
                "sender_signed_statechain_id",
                "prior_pending_signing_id",
                "prior_transfer_recipient_auth_pubkey",
                "prior_transfer_msg_hash",
                "generated_coin_user_pubkey",
                "generated_coin_auth_pubkey",
                "generated_coin_address",
                "server_x1",
                "current_pending_signing_id",
                "update_signature",
                "state_signing_phase",
                "created_at",
                "updated_at",
                "first_seen_at",
                "last_seen_at",
            ]
            .contains(&name.as_str())
            {
                "TEXT"
            } else {
                "INTEGER"
            };
            assert_eq!(ty, expected_type, "{table}.{name} type");
            let nullable_columns: &[&str] = match table {
                "bip448_scan_cursors" => &[],
                "bip448_funding_bindings" => &["funding_height", "spend_txid", "spend_height"],
                "bip448_withdrawal_attempts" => &[
                    "server_public_nonce",
                    "message_hex",
                    "output_pubkey",
                    "client_partial_sig",
                    "encoded_session",
                    "sign_second_payload_json",
                    "server_partial_sig",
                    "aggregate_signature",
                    "signed_tx_hex",
                    "txid",
                    "closing_tip_height",
                    "closing_tip_hash",
                    "closing_bindings_json",
                ],
                "bip448_transfer_intents" => &[
                    "predecessor_intent_id",
                    "batch_id",
                    "prior_pending_signing_id",
                    "prior_transfer_recipient_auth_pubkey",
                    "prior_transfer_msg_hash",
                    "generated_coin_user_pubkey",
                    "generated_coin_auth_pubkey",
                    "generated_coin_address",
                    "server_x1",
                    "current_pending_signing_id",
                    "server_partial_sig",
                    "update_signature",
                ],
                _ => unreachable!(),
            };
            let nullable = nullable_columns.contains(&name.as_str());
            assert_eq!(
                *not_null,
                i64::from(!nullable),
                "{table}.{name} nullability"
            );
            let expected_default = if ["created_at", "updated_at", "first_seen_at", "last_seen_at"]
                .contains(&name.as_str())
            {
                Some("CURRENT_TIMESTAMP")
            } else {
                None
            };
            assert_eq!(
                default_value.as_deref(),
                expected_default,
                "{table}.{name} default"
            );
            let expected_pk = match (table, name.as_str()) {
                ("bip448_scan_cursors", "wallet_name")
                | ("bip448_funding_bindings", "wallet_name")
                | ("bip448_withdrawal_attempts", "wallet_name")
                | ("bip448_transfer_intents", "wallet_name") => 1,
                ("bip448_scan_cursors", "script_pubkey")
                | ("bip448_funding_bindings", "statechain_id")
                | ("bip448_withdrawal_attempts", "statechain_id")
                | ("bip448_transfer_intents", "statechain_id") => 2,
                ("bip448_funding_bindings", "binding_index")
                | ("bip448_withdrawal_attempts", "binding_index")
                | ("bip448_transfer_intents", "intent_id") => 3,
                _ => 0,
            };
            assert_eq!(*pk, expected_pk, "{table}.{name} PK ordinal");
        }
    }

    let indexes: Vec<(String, String)> = sqlx::query_as(
        "SELECT name,sql FROM sqlite_schema \
        WHERE type='index' AND name IN ('bip448_one_canonical_binding',\
        'bip448_one_active_withdrawal_signing','bip448_one_active_transfer_intent') ORDER BY name",
    )
    .fetch_all(&pool)
    .await?;
    assert_eq!(indexes.len(), 3);
    assert_eq!(indexes[0].0, "bip448_one_active_transfer_intent");
    assert!(indexes[0].1.contains("WHERE activity_status = 'Active'"));
    assert_eq!(indexes[1].0, "bip448_one_active_withdrawal_signing");
    assert!(indexes[1].1.contains("WHERE phase <> 'Signed'"));
    assert_eq!(indexes[2].0, "bip448_one_canonical_binding");
    assert!(indexes[2].1.contains("WHERE role = 'Canonical'"));
    for table in &tables {
        let pragma = format!("PRAGMA foreign_key_list('{table}')");
        let foreign_keys = sqlx::query(&pragma).fetch_all(&pool).await?;
        assert!(foreign_keys.is_empty(), "{table} introduced a foreign key");
    }
    let migration_sql = include_str!("../../../../migrations/0001_bip448_client_schema.sql");
    let normalized_migration = migration_sql
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for fragment in [
        "binding_index BETWEEN 0 AND 4294967295",
        "length(txid) = 64",
        "vout BETWEEN 0 AND 4294967295",
        "value_sats BETWEEN 0 AND 2100000000000000",
        "role IN ('Canonical', 'Duplicate')",
        "'Mempool', 'Unconfirmed', 'Confirmed', 'SpentMempool', 'SpentUnconfirmed', 'SpentConfirmed', 'Absent'",
        "owner_state_number BETWEEN 1 AND 4294967295",
        "ownership_status IN ('Current', 'Previous')",
        "binding_index = 0 AND role = 'Canonical'",
        "observation_status = 'SpentMempool' AND spend_txid IS NOT NULL AND spend_height IS NULL",
        "observation_status = 'Mempool' AND funding_height IS NULL",
        "attempt_kind IN ('Duplicate', 'Canonical')",
        "fee_rate_sat_per_vbyte > 0",
        "lock_time BETWEEN 0 AND 499999999",
        "'Prepared', 'FirstArmed', 'NonceStored', 'SecondArmed', 'Signed'",
        "'NotBroadcast', 'Accepted', 'Confirmed', 'NeedsRebroadcast', 'Conflicting', 'Conflicted'",
        "'NotApplicable', 'Open', 'CloseArmed', 'Closed'",
        "binding_index = 0 AND attempt_kind = 'Canonical'",
        "phase IN ('Prepared', 'FirstArmed') OR",
        "phase <> 'Signed' OR",
        "phase = 'Signed' OR broadcast_status = 'NotBroadcast'",
        "completion_status <> 'CloseArmed' OR",
        "completion_status <> 'Closed' OR",
        "predecessor_intent_id <> intent_id",
        "activity_status IN ('Active', 'Superseded')",
        "intent_kind IN ('UserTransfer', 'Cancellation')",
        "acknowledge_cooperative_duplicates IN (0, 1)",
        "planned_state_number BETWEEN 1 AND 4294967295",
        "expected_signature_count BETWEEN 1 AND 4294967295",
        "previous_locktime BETWEEN 500000000 AND 4294967294",
        "reuse_pending IN (0, 1)",
        "reuse_signed_state IN (0, 1)",
        "clear_local_attempt IN (0, 1)",
        "'Prepared', 'SenderArmed', 'X1Stored', 'SenderFinished', 'ReceiverAccepted'",
        "'NotStarted', 'FirstArmed', 'NonceStored', 'SecondArmed', 'Signed'",
        "intent_kind = 'UserTransfer' AND generated_coin_user_pubkey IS NULL",
        "phase IN ('Prepared', 'SenderArmed') AND server_x1 IS NULL",
        "prior_transfer_recipient_auth_pubkey IS NULL AND prior_transfer_msg_hash IS NULL",
        "reuse_pending = 0 OR prior_pending_signing_id IS NOT NULL",
        "reuse_signed_state = 0 OR reuse_pending = 1",
        "planned_state_number = expected_signature_count + 1",
        "reuse_pending = 0 OR clear_local_attempt = 0",
        "intent_kind = 'UserTransfer' OR batch_id IS NULL",
        "intent_kind = 'Cancellation' OR phase IN ('Prepared', 'SenderArmed', 'X1Stored')",
        "state_signing_phase = 'NotStarted' AND current_pending_signing_id IS NULL",
    ] {
        assert!(
            normalized_migration.contains(fragment),
            "missing named CHECK fragment: {fragment}"
        );
    }
    let uppercase = normalized_migration.to_ascii_uppercase();
    for forbidden in [" ALTER ", " TRIGGER ", " CREATE VIEW ", " BACKUP "] {
        assert!(
            !uppercase.contains(forbidden),
            "forbidden schema object: {forbidden}"
        );
    }

    let pending_deposit_columns: Vec<(i64, String, String, i64, Option<String>, i64)> =
        sqlx::query_as("PRAGMA table_info('bip448_pending_deposit_signings')")
            .fetch_all(&pool)
            .await?;
    assert_eq!(
        pending_deposit_columns,
        vec![
            (0, "wallet_name".into(), "TEXT".into(), 1, None, 1),
            (1, "statechain_id".into(), "TEXT".into(), 1, None, 2),
            (2, "update_template_hash".into(), "TEXT".into(), 1, None, 0),
            (3, "signing_id".into(), "TEXT".into(), 1, None, 0),
            (4, "client_secret_nonce".into(), "TEXT".into(), 1, None, 0),
            (5, "client_public_nonce".into(), "TEXT".into(), 1, None, 0),
            (6, "blinding_factor".into(), "TEXT".into(), 1, None, 0),
            (7, "server_public_nonce".into(), "TEXT".into(), 0, None, 0),
            (8, "state_locktime".into(), "INTEGER".into(), 0, None, 0),
            (9, "funding_txid".into(), "TEXT".into(), 0, None, 0),
            (10, "funding_vout".into(), "INTEGER".into(), 0, None, 0),
            (
                11,
                "funding_value_sats".into(),
                "INTEGER".into(),
                0,
                None,
                0
            ),
            (
                12,
                "settlement_template_hash".into(),
                "TEXT".into(),
                0,
                None,
                0
            ),
            (
                13,
                "created_at".into(),
                "TEXT".into(),
                1,
                Some("CURRENT_TIMESTAMP".into()),
                0
            ),
            (
                14,
                "updated_at".into(),
                "TEXT".into(),
                1,
                Some("CURRENT_TIMESTAMP".into()),
                0
            ),
        ]
    );

    let backup_txs_exists = sqlx::query_scalar::<_, i64>(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema \
         WHERE type = 'table' AND name = 'backup_txs')",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(backup_txs_exists, 0);

    Ok(())
}

#[tokio::test]
async fn wallet_and_accepted_record_persistence_canonicalize_txids() -> Result<()> {
    let pool = migrated_pool().await?;
    let mut wallet = sample_wallet();
    let mut coin = wallet.get_new_coin()?;
    coin.utxo_txid = Some("AA".repeat(32));
    coin.utxo_vout = Some(1);
    coin.tx_withdraw = Some("CC".repeat(32));
    wallet.coins.push(coin);
    insert_wallet(&pool, &wallet).await?;
    let stored_coin = get_wallet(&pool, &wallet.name).await?.coins.remove(0);
    assert_eq!(stored_coin.utxo_txid, Some("aa".repeat(32)));
    assert_eq!(stored_coin.tx_withdraw, Some("cc".repeat(32)));
    wallet.coins[0].utxo_txid = Some("not-a-txid".into());
    assert!(update_wallet(&pool, &wallet).await.is_err());
    wallet.coins[0].utxo_txid = Some("aa".repeat(32));
    wallet.coins[0].tx_withdraw = Some("not-a-txid".into());
    assert!(update_wallet(&pool, &wallet).await.is_err());

    let mut record = sample_bip448_record(1);
    record.funding_outpoint.txid = "AA".repeat(32);
    upsert_bip448_statechain_record(&pool, &record).await?;
    assert_eq!(
        get_bip448_statechain(&pool, &record.wallet_name, &record.statechain_id)
            .await?
            .funding_outpoint
            .txid,
        "aa".repeat(32)
    );
    Ok(())
}

#[tokio::test]
async fn bip448_latest_state_allows_single_step_transitions_and_exact_replay() -> Result<()> {
    let pool = migrated_pool().await?;
    let state_one = sample_bip448_record(1);
    let state_two = sample_bip448_record(2);
    let state_three = sample_bip448_record(3);

    upsert_bip448_statechain_record(&pool, &state_one).await?;
    let roundtrip =
        get_bip448_statechain(&pool, &state_one.wallet_name, &state_one.statechain_id).await?;
    assert_eq!(roundtrip, state_one);

    upsert_bip448_statechain_record(&pool, &state_two).await?;
    let roundtrip =
        get_bip448_statechain(&pool, &state_two.wallet_name, &state_two.statechain_id).await?;
    assert_eq!(roundtrip, state_two);

    upsert_bip448_statechain_record(&pool, &state_three).await?;
    let roundtrip =
        get_bip448_statechain(&pool, &state_three.wallet_name, &state_three.statechain_id).await?;
    assert_eq!(roundtrip, state_three);

    upsert_bip448_statechain_record(&pool, &state_three).await?;

    Ok(())
}

#[tokio::test]
async fn bip448_latest_state_rejects_immutable_identity_changes() -> Result<()> {
    let pool = migrated_pool().await?;
    let state_one = sample_bip448_record(1);
    upsert_bip448_statechain_record(&pool, &state_one).await?;

    let mut aggregate_pubkey = sample_bip448_record(2);
    aggregate_pubkey.aggregate_pubkey = "03".to_string() + &"12".repeat(32);
    let mut funding_outpoint = sample_bip448_record(2);
    funding_outpoint.funding_outpoint.vout = 1;
    let mut amount_sats = sample_bip448_record(2);
    amount_sats.amount_sats += 1;
    let mut network = sample_bip448_record(2);
    network.network = "bitcoin".to_string();
    let mut challenge_delay = sample_bip448_record(2);
    challenge_delay.challenge_delay += 1;

    for conflicting in [
        aggregate_pubkey,
        funding_outpoint,
        amount_sats,
        network,
        challenge_delay,
    ] {
        let error = upsert_bip448_statechain_record(&pool, &conflicting)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "BIP448 accepted state immutable identity mismatch"
        );
    }
    let persisted =
        get_bip448_statechain(&pool, &state_one.wallet_name, &state_one.statechain_id).await?;
    assert_eq!(persisted, state_one);

    Ok(())
}

#[tokio::test]
async fn bip448_latest_state_rejects_rollback_skip_and_divergent_same_state() -> Result<()> {
    let pool = migrated_pool().await?;
    let state_one = sample_bip448_record(1);
    let state_two = sample_bip448_record(2);
    let state_three = sample_bip448_record(3);
    upsert_bip448_statechain_record(&pool, &state_one).await?;
    upsert_bip448_statechain_record(&pool, &state_two).await?;
    upsert_bip448_statechain_record(&pool, &state_three).await?;

    let mut divergent_state_three = state_three.clone();
    divergent_state_three.latest_state.update_tx = "04000000".to_string();
    for rejected in [state_two, divergent_state_three] {
        let error = upsert_bip448_statechain_record(&pool, &rejected)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "BIP448 accepted state must be an exact replay or a monotonic single-step transition"
        );
    }
    let persisted =
        get_bip448_statechain(&pool, &state_three.wallet_name, &state_three.statechain_id).await?;
    assert_eq!(persisted, state_three);

    let skip_pool = migrated_pool().await?;
    upsert_bip448_statechain_record(&skip_pool, &state_one).await?;
    let error = upsert_bip448_statechain_record(&skip_pool, &state_three)
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "BIP448 accepted state must be an exact replay or a monotonic single-step transition"
    );

    Ok(())
}

#[tokio::test]
async fn bip448_accepted_state_rejects_unverified_cpfp_children() -> Result<()> {
    let pool = migrated_pool().await?;
    let mut rejected_insert = sample_bip448_record(1);
    rejected_insert
        .latest_state
        .cpfp_child_templates
        .push(sample_cpfp_child_template());

    let error = upsert_bip448_statechain_record(&pool, &rejected_insert)
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("cannot contain unverified CPFP child templates"));
    assert!(get_bip448_statechain_optional(
        &pool,
        &rejected_insert.wallet_name,
        &rejected_insert.statechain_id,
    )
    .await?
    .is_none());

    let accepted = sample_bip448_record(1);
    upsert_bip448_statechain_record(&pool, &accepted).await?;
    let mut rejected_update = sample_bip448_record(2);
    rejected_update
        .latest_state
        .cpfp_child_templates
        .push(sample_cpfp_child_template());

    let error = upsert_bip448_statechain_record(&pool, &rejected_update)
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("cannot contain unverified CPFP child templates"));
    let persisted =
        get_bip448_statechain(&pool, &accepted.wallet_name, &accepted.statechain_id).await?;
    assert_eq!(persisted, accepted);

    Ok(())
}

#[tokio::test]
async fn bip448_transfer_messages_round_trip_through_sqlite() -> Result<()> {
    let pool = migrated_pool().await?;
    let transfer_msg = sample_bip448_transfer_msg();
    let recipient_auth_pubkey = "02".to_string() + &"99".repeat(32);

    insert_or_update_bip448_transfer_msg(&pool, "wallet", &recipient_auth_pubkey, &transfer_msg)
        .await?;
    let roundtrip = get_bip448_transfer_msg(
        &pool,
        "wallet",
        &transfer_msg.statechain_id,
        &recipient_auth_pubkey,
    )
    .await?;

    assert_eq!(roundtrip, transfer_msg);
    assert_eq!(roundtrip.latest_state.anchors[0].script_pubkey, "51024e73");
    assert_eq!(roundtrip.latest_state.cpfp_child_templates.len(), 1);
    Ok(())
}

#[tokio::test]
async fn bip448_pending_deposit_signing_round_trips_and_is_deleted() -> Result<()> {
    let pool = migrated_pool().await?;
    let mut pending = Bip448PendingDepositSigning {
        wallet_name: "wallet".to_string(),
        statechain_id: "statechain".to_string(),
        funding_txid: "aa".repeat(32),
        funding_vout: 1,
        funding_value_sats: 100_000,
        update_template_hash: "11".repeat(32),
        settlement_template_hash: "12".repeat(32),
        state_locktime: 700_000_042,
        signing_id: "22".repeat(32),
        client_secret_nonce: "33".repeat(132),
        client_public_nonce: "44".repeat(66),
        blinding_factor: "55".repeat(32),
        server_public_nonce: None,
    };

    let inserted = insert_bip448_pending_deposit_signing_if_absent(&pool, &pending).await?;
    assert_eq!(inserted, pending);
    let roundtrip =
        get_bip448_pending_deposit_signing(&pool, &pending.wallet_name, &pending.statechain_id)
            .await?
            .expect("pending signing exists");
    assert_eq!(roundtrip, pending);

    pending.server_public_nonce = Some("66".repeat(66));
    update_bip448_pending_deposit_server_public_nonce(
        &pool,
        &pending.wallet_name,
        &pending.statechain_id,
        &pending.signing_id,
        pending.server_public_nonce.as_ref().unwrap(),
    )
    .await?;
    let with_server_nonce =
        get_bip448_pending_deposit_signing(&pool, &pending.wallet_name, &pending.statechain_id)
            .await?
            .expect("pending signing exists");
    assert_eq!(with_server_nonce, pending);

    delete_bip448_pending_deposit_signing(
        &pool,
        &pending.wallet_name,
        &pending.statechain_id,
        &pending.signing_id,
    )
    .await?;
    assert!(get_bip448_pending_deposit_signing(
        &pool,
        &pending.wallet_name,
        &pending.statechain_id,
    )
    .await?
    .is_none());
    pending.state_locktime = 1_000_000_001;
    pending.server_public_nonce = None;
    let error = insert_bip448_pending_transfer_signing_if_absent(&pool, &pending)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("coin's latest state"));
    let accepted = sample_bip448_record(3);
    pending.funding_txid = accepted.funding_outpoint.txid.clone();
    pending.funding_vout = accepted.funding_outpoint.vout;
    pending.funding_value_sats = accepted.funding_outpoint.value_sats;
    upsert_bip448_statechain_record(&pool, &accepted).await?;
    let persisted = insert_bip448_pending_transfer_signing_if_absent(&pool, &pending).await?;
    assert_eq!(persisted.state_locktime, 1_000_000_001);

    Ok(())
}

#[tokio::test]
async fn pending_insert_if_absent_keeps_one_locktime_and_template_identity() -> Result<()> {
    let pool = migrated_pool().await?;
    let first = Bip448PendingDepositSigning {
        wallet_name: "wallet".to_string(),
        statechain_id: "statechain".to_string(),
        funding_txid: "aa".repeat(32),
        funding_vout: 1,
        funding_value_sats: 100_000,
        update_template_hash: "11".repeat(32),
        settlement_template_hash: "12".repeat(32),
        state_locktime: 600_000_001,
        signing_id: "22".repeat(32),
        client_secret_nonce: "33".repeat(132),
        client_public_nonce: "44".repeat(66),
        blinding_factor: "55".repeat(32),
        server_public_nonce: None,
    };
    let mut competing = first.clone();
    competing.update_template_hash = "aa".repeat(32);
    competing.settlement_template_hash = "ab".repeat(32);
    competing.state_locktime = 900_000_001;
    competing.signing_id = "bb".repeat(32);
    competing.client_secret_nonce = "cc".repeat(132);

    let (first_result, competing_result) = tokio::join!(
        insert_bip448_pending_deposit_signing_if_absent(&pool, &first),
        insert_bip448_pending_deposit_signing_if_absent(&pool, &competing),
    );
    let first_result = first_result?;
    let competing_result = competing_result?;

    assert_eq!(first_result, competing_result);
    assert!(first_result == first || first_result == competing);
    assert_eq!(
        get_bip448_pending_deposit_signing(&pool, "wallet", "statechain")
            .await?
            .unwrap(),
        first_result
    );

    Ok(())
}

#[tokio::test]
async fn pending_row_without_randomized_locktime_fails_closed() -> Result<()> {
    let pool = migrated_pool().await?;
    sqlx::query(
        "INSERT INTO bip448_pending_deposit_signings (\
            wallet_name, statechain_id, update_template_hash, signing_id, \
            client_secret_nonce, client_public_nonce, blinding_factor\
         ) VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind("wallet")
    .bind("pre-phase-7-1")
    .bind("11".repeat(32))
    .bind("22".repeat(32))
    .bind("33".repeat(132))
    .bind("44".repeat(66))
    .bind("55".repeat(32))
    .execute(&pool)
    .await?;

    let error = get_bip448_pending_deposit_signing(&pool, "wallet", "pre-phase-7-1")
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("predates randomized locktime support"));

    Ok(())
}

#[tokio::test]
async fn accepted_record_without_explicit_locktime_is_not_silently_upgraded() -> Result<()> {
    let pool = migrated_pool().await?;
    let record = sample_bip448_record(1);
    upsert_bip448_statechain_record(&pool, &record).await?;

    let mut old_json = serde_json::to_value(&record)?;
    old_json["latest_state"]
        .as_object_mut()
        .unwrap()
        .remove("state_locktime");
    sqlx::query(
        "UPDATE bip448_statechains SET record_json = $1 \
         WHERE wallet_name = $2 AND statechain_id = $3",
    )
    .bind(serde_json::to_string(&old_json)?)
    .bind(&record.wallet_name)
    .bind(&record.statechain_id)
    .execute(&pool)
    .await?;

    let error = get_bip448_statechain(&pool, &record.wallet_name, &record.statechain_id)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("state_locktime"));

    Ok(())
}

#[tokio::test]
async fn bip448_initial_acceptance_is_atomic_exact_replay_or_full_rollback() -> Result<()> {
    let pool = migrated_pool().await?;
    let (wallet, record, entry, _) = real_accepted_fixture(CoinStatus::UNCONFIRMED)?;
    insert_wallet(&pool, &wallet).await?;
    persist_bip448_initial_acceptance(&pool, &record, &entry).await?;
    persist_bip448_initial_acceptance(&pool, &record, &entry).await?;
    assert_eq!(
        get_bip448_statechain(&pool, "wallet", "statechain").await?,
        record
    );
    assert_eq!(
        get_bip448_state_history(&pool, "wallet", "statechain").await?,
        vec![entry.clone()]
    );

    let fault_pool = migrated_pool().await?;
    insert_wallet(&fault_pool, &wallet).await?;
    let mut conflicting = entry.clone();
    conflicting.update_signature = "cc".repeat(64);
    sqlx::query("INSERT INTO bip448_state_history (wallet_name,statechain_id,state_number,entry_json) VALUES ($1,$2,1,$3)")
        .bind("wallet").bind("statechain").bind(serde_json::to_string(&conflicting)?)
        .execute(&fault_pool).await?;
    assert!(
        persist_bip448_initial_acceptance(&fault_pool, &record, &entry)
            .await
            .is_err()
    );
    assert!(
        get_bip448_statechain_optional(&fault_pool, "wallet", "statechain")
            .await?
            .is_none()
    );
    assert_eq!(
        get_bip448_state_history(&fault_pool, "wallet", "statechain").await?,
        vec![conflicting]
    );

    let record_only_pool = migrated_pool().await?;
    insert_wallet(&record_only_pool, &wallet).await?;
    upsert_bip448_statechain_record(&record_only_pool, &record).await?;
    assert!(
        persist_bip448_initial_acceptance(&record_only_pool, &record, &entry)
            .await
            .is_err()
    );
    assert_eq!(
        get_bip448_statechain(&record_only_pool, "wallet", "statechain").await?,
        record
    );
    assert!(
        get_bip448_state_history(&record_only_pool, "wallet", "statechain")
            .await?
            .is_empty()
    );

    let record_conflict_pool = migrated_pool().await?;
    insert_wallet(&record_conflict_pool, &wallet).await?;
    let mut other_record = record.clone();
    other_record.network = "signet".into();
    upsert_bip448_statechain_record(&record_conflict_pool, &other_record).await?;
    assert!(
        persist_bip448_initial_acceptance(&record_conflict_pool, &record, &entry)
            .await
            .is_err()
    );
    assert_eq!(
        get_bip448_statechain(&record_conflict_pool, "wallet", "statechain").await?,
        other_record
    );
    assert!(
        get_bip448_state_history(&record_conflict_pool, "wallet", "statechain")
            .await?
            .is_empty()
    );

    let write_fault_pool = migrated_pool().await?;
    insert_wallet(&write_fault_pool, &wallet).await?;
    sqlx::query(
        "INSERT INTO bip448_state_history \
         (wallet_name,statechain_id,state_number,entry_json) VALUES ('other','other',1,$1)",
    )
    .bind(serde_json::to_string(&entry)?)
    .execute(&write_fault_pool)
    .await?;
    sqlx::query(
        "CREATE UNIQUE INDEX test_bip448_history_fault ON bip448_state_history(entry_json)",
    )
    .execute(&write_fault_pool)
    .await?;
    assert!(
        persist_bip448_initial_acceptance(&write_fault_pool, &record, &entry)
            .await
            .is_err()
    );
    assert!(
        get_bip448_statechain_optional(&write_fault_pool, "wallet", "statechain")
            .await?
            .is_none()
    );
    assert!(
        get_bip448_state_history(&write_fault_pool, "wallet", "statechain")
            .await?
            .is_empty()
    );

    let pre_acceptance_pool = migrated_pool().await?;
    let mut pre_acceptance_wallet = wallet.clone();
    let pre_acceptance_coin = pre_acceptance_wallet
        .coins
        .first_mut()
        .ok_or_else(|| anyhow!("acceptance fixture Coin is missing"))?;
    pre_acceptance_coin.utxo_txid = None;
    pre_acceptance_coin.utxo_vout = None;
    pre_acceptance_coin.locktime = None;
    pre_acceptance_coin.public_nonce = None;
    pre_acceptance_coin.server_public_nonce = None;
    pre_acceptance_coin.blinding_factor = None;
    pre_acceptance_coin.status = CoinStatus::INITIALISED;
    insert_wallet(&pre_acceptance_pool, &pre_acceptance_wallet).await?;
    let pending = Bip448PendingDepositSigning {
        wallet_name: record.wallet_name.clone(),
        statechain_id: record.statechain_id.clone(),
        funding_txid: record.funding_outpoint.txid.clone(),
        funding_vout: record.funding_outpoint.vout,
        funding_value_sats: record.funding_outpoint.value_sats,
        update_template_hash: entry.update_template_hash.clone(),
        settlement_template_hash: entry.settlement_template_hash.clone(),
        state_locktime: entry.state_locktime,
        signing_id: record.latest_state.signing_metadata.signing_id.clone(),
        client_secret_nonce: "ab".repeat(132),
        client_public_nonce: entry.client_public_nonce.clone(),
        blinding_factor: entry.blinding_factor.clone(),
        server_public_nonce: Some(entry.server_public_nonce.clone()),
    };
    insert_bip448_pending_deposit_signing_if_absent(&pre_acceptance_pool, &pending).await?;
    persist_bip448_initial_acceptance(&pre_acceptance_pool, &record, &entry).await?;
    assert_eq!(
        get_bip448_statechain(&pre_acceptance_pool, "wallet", "statechain").await?,
        record
    );

    let missing_pending_pool = migrated_pool().await?;
    insert_wallet(&missing_pending_pool, &pre_acceptance_wallet).await?;
    assert!(
        persist_bip448_initial_acceptance(&missing_pending_pool, &record, &entry)
            .await
            .is_err()
    );
    assert!(
        get_bip448_statechain_optional(&missing_pending_pool, "wallet", "statechain")
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn initial_acceptance_restart_recovery_is_exact_atomic_and_fail_closed() -> Result<()> {
    for (retain_observed_outpoint, retain_pending) in [(false, true), (true, false)] {
        let pool = migrated_pool().await?;
        let (record, entry, pending, expected_raw_wallet) =
            install_pre_materialized_initial_acceptance(
                &pool,
                retain_observed_outpoint,
                retain_pending,
            )
            .await?;
        let accepted_before = accepted_table_bytes(&pool).await?;
        assert_eq!(
            recover_bip448_initial_acceptance_wallet(&pool, "wallet", &expected_raw_wallet,)
                .await?,
            Bip448InitialAcceptanceRecovery::Recovered
        );
        assert_eq!(accepted_table_bytes(&pool).await?, accepted_before);
        assert!(
            get_bip448_pending_deposit_signing(&pool, "wallet", "statechain")
                .await?
                .is_none()
        );
        let recovered_wallet = get_wallet(&pool, "wallet").await?;
        let recovered_coin = &recovered_wallet.coins[0];
        assert_eq!(
            recovered_coin.utxo_txid.as_deref(),
            Some(record.funding_outpoint.txid.as_str())
        );
        assert_eq!(recovered_coin.utxo_vout, Some(record.funding_outpoint.vout));
        assert_eq!(
            recovered_coin.locktime,
            Some(record.latest_state.state_locktime)
        );
        assert_eq!(
            recovered_coin.public_nonce.as_deref(),
            Some(entry.client_public_nonce.as_str())
        );
        assert_eq!(
            recovered_coin.server_public_nonce.as_deref(),
            Some(entry.server_public_nonce.as_str())
        );
        assert_eq!(
            recovered_coin.blinding_factor.as_deref(),
            Some(entry.blinding_factor.as_str())
        );
        assert_eq!(recovered_coin.status, CoinStatus::UNCONFIRMED);
        assert_eq!(recovered_wallet.activities.len(), 1);
        let activity = &recovered_wallet.activities[0];
        assert_eq!(
            activity.utxo,
            format!(
                "{}:{}",
                record.funding_outpoint.txid, record.funding_outpoint.vout
            )
        );
        assert_eq!(activity.amount, u32::try_from(record.amount_sats)?);
        assert_eq!(activity.action, "bip448_deposit");
        chrono::DateTime::parse_from_rfc3339(&activity.date)?;
        let recovered_raw_wallet = get_bip448_raw_wallet_json(&pool, "wallet").await?;
        assert_eq!(
            recover_bip448_initial_acceptance_wallet(&pool, "wallet", &recovered_raw_wallet,)
                .await?,
            Bip448InitialAcceptanceRecovery::Unchanged
        );
        assert_eq!(
            get_bip448_pending_deposit_signing(&pool, "wallet", "statechain").await?,
            None,
            "replay recreated the cleaned {} pending journal",
            pending.signing_id
        );
    }

    let corrupt_pending_pool = migrated_pool().await?;
    let (_, _, _, corrupt_expected_raw) =
        install_pre_materialized_initial_acceptance(&corrupt_pending_pool, false, true).await?;
    sqlx::query(
        "UPDATE bip448_pending_deposit_signings SET settlement_template_hash=$1 \
         WHERE wallet_name='wallet' AND statechain_id='statechain'",
    )
    .bind("cd".repeat(32))
    .execute(&corrupt_pending_pool)
    .await?;
    let corrupt_before = initial_acceptance_recovery_storage(&corrupt_pending_pool).await?;
    assert!(recover_bip448_initial_acceptance_wallet(
        &corrupt_pending_pool,
        "wallet",
        &corrupt_expected_raw,
    )
    .await
    .is_err());
    assert_eq!(
        initial_acceptance_recovery_storage(&corrupt_pending_pool).await?,
        corrupt_before
    );

    let partial_coin_pool = migrated_pool().await?;
    let (partial_record, _, _, _) =
        install_pre_materialized_initial_acceptance(&partial_coin_pool, false, true).await?;
    let mut partial_wallet = get_wallet(&partial_coin_pool, "wallet").await?;
    partial_wallet.coins[0].public_nonce = Some(
        partial_record
            .latest_state
            .signing_metadata
            .client_public_nonce
            .clone(),
    );
    update_wallet(&partial_coin_pool, &partial_wallet).await?;
    let partial_before = initial_acceptance_recovery_storage(&partial_coin_pool).await?;
    assert!(recover_bip448_initial_acceptance_wallet(
        &partial_coin_pool,
        "wallet",
        &partial_before.0,
    )
    .await
    .is_err());
    assert_eq!(
        initial_acceptance_recovery_storage(&partial_coin_pool).await?,
        partial_before
    );

    let multiple_coin_pool = migrated_pool().await?;
    let (_, _, _, _) =
        install_pre_materialized_initial_acceptance(&multiple_coin_pool, false, true).await?;
    let mut multiple_wallet = get_wallet(&multiple_coin_pool, "wallet").await?;
    multiple_wallet.coins.push(multiple_wallet.coins[0].clone());
    update_wallet(&multiple_coin_pool, &multiple_wallet).await?;
    let multiple_before = initial_acceptance_recovery_storage(&multiple_coin_pool).await?;
    assert!(recover_bip448_initial_acceptance_wallet(
        &multiple_coin_pool,
        "wallet",
        &multiple_before.0,
    )
    .await
    .is_err());
    assert_eq!(
        initial_acceptance_recovery_storage(&multiple_coin_pool).await?,
        multiple_before
    );

    let stale_wallet_pool = migrated_pool().await?;
    let (_, _, _, stale_expected_raw) =
        install_pre_materialized_initial_acceptance(&stale_wallet_pool, false, true).await?;
    let mut raced_wallet = get_wallet(&stale_wallet_pool, "wallet").await?;
    raced_wallet.blockheight = raced_wallet.blockheight.saturating_add(1);
    update_wallet(&stale_wallet_pool, &raced_wallet).await?;
    let raced_before = initial_acceptance_recovery_storage(&stale_wallet_pool).await?;
    assert_eq!(
        recover_bip448_initial_acceptance_wallet(
            &stale_wallet_pool,
            "wallet",
            &stale_expected_raw,
        )
        .await?,
        Bip448InitialAcceptanceRecovery::WalletChanged
    );
    assert_eq!(
        initial_acceptance_recovery_storage(&stale_wallet_pool).await?,
        raced_before
    );

    let rollback_pool = migrated_pool().await?;
    let (_, _, _, rollback_expected_raw) =
        install_pre_materialized_initial_acceptance(&rollback_pool, false, true).await?;
    sqlx::query(
        "CREATE TRIGGER test_initial_acceptance_recovery_fault \
         BEFORE DELETE ON bip448_pending_deposit_signings \
         BEGIN SELECT RAISE(ABORT, 'injected recovery fault'); END",
    )
    .execute(&rollback_pool)
    .await?;
    let rollback_before = initial_acceptance_recovery_storage(&rollback_pool).await?;
    assert!(recover_bip448_initial_acceptance_wallet(
        &rollback_pool,
        "wallet",
        &rollback_expected_raw,
    )
    .await
    .is_err());
    assert_eq!(
        initial_acceptance_recovery_storage(&rollback_pool).await?,
        rollback_before
    );
    Ok(())
}

#[tokio::test]
async fn bip448_initial_acceptance_requires_one_exact_real_wallet_coin() -> Result<()> {
    let (wallet, record, entry, _) = real_accepted_fixture(CoinStatus::UNCONFIRMED)?;

    let empty_pool = migrated_pool().await?;
    insert_wallet(&empty_pool, &sample_wallet()).await?;
    let before = accepted_table_bytes(&empty_pool).await?;
    assert!(
        persist_bip448_initial_acceptance(&empty_pool, &record, &entry)
            .await
            .is_err()
    );
    assert_eq!(accepted_table_bytes(&empty_pool).await?, before);

    let unrelated_pool = migrated_pool().await?;
    let mut unrelated_wallet = wallet.clone();
    unrelated_wallet.coins[0].statechain_id = Some("unrelated-statechain".into());
    insert_wallet(&unrelated_pool, &unrelated_wallet).await?;
    let before = accepted_table_bytes(&unrelated_pool).await?;
    assert!(
        persist_bip448_initial_acceptance(&unrelated_pool, &record, &entry)
            .await
            .is_err()
    );
    assert_eq!(accepted_table_bytes(&unrelated_pool).await?, before);

    let absent_wallet_pool = migrated_pool().await?;
    let before = accepted_table_bytes(&absent_wallet_pool).await?;
    assert!(
        persist_bip448_initial_acceptance(&absent_wallet_pool, &record, &entry)
            .await
            .is_err()
    );
    assert_eq!(accepted_table_bytes(&absent_wallet_pool).await?, before);

    let multiple_pool = migrated_pool().await?;
    let mut multiple_wallet = wallet.clone();
    multiple_wallet.coins.push(wallet.coins[0].clone());
    insert_wallet(&multiple_pool, &multiple_wallet).await?;
    let before = accepted_table_bytes(&multiple_pool).await?;
    assert!(
        persist_bip448_initial_acceptance(&multiple_pool, &record, &entry)
            .await
            .is_err()
    );
    assert_eq!(accepted_table_bytes(&multiple_pool).await?, before);

    for mutate in [
        |record: &mut Bip448StatechainRecord, entry: &mut Bip448StateHistoryEntry| {
            record.latest_state.update_tx.push_str("00");
            let _ = entry;
        },
        |record: &mut Bip448StatechainRecord, entry: &mut Bip448StateHistoryEntry| {
            let bad_signature = "00".repeat(64);
            record.latest_state.signing_metadata.update_signature = bad_signature.clone();
            entry.update_signature = bad_signature;
        },
        |record: &mut Bip448StatechainRecord, entry: &mut Bip448StateHistoryEntry| {
            let bad_nonce = "00".repeat(66);
            record.latest_state.signing_metadata.client_public_nonce = bad_nonce.clone();
            entry.client_public_nonce = bad_nonce;
        },
    ] {
        let malformed_pool = migrated_pool().await?;
        insert_wallet(&malformed_pool, &wallet).await?;
        let mut malformed_record = record.clone();
        let mut malformed_entry = entry.clone();
        mutate(&mut malformed_record, &mut malformed_entry);
        let before = accepted_table_bytes(&malformed_pool).await?;
        assert!(persist_bip448_initial_acceptance(
            &malformed_pool,
            &malformed_record,
            &malformed_entry,
        )
        .await
        .is_err());
        assert_eq!(accepted_table_bytes(&malformed_pool).await?, before);
    }
    Ok(())
}
