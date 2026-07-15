use anyhow::{anyhow, Result};
use mercurylib::{
    bip448_statechain::storage::Bip448StatechainRecord,
    transfer::bip448::Bip448TransferMsg,
    wallet::{BackupTx, Wallet},
};
use serde_json::json;
use sqlx::{Pool, Row, Sqlite};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip448PendingDepositSigning {
    pub wallet_name: String,
    pub statechain_id: String,
    pub update_template_hash: String,
    pub signing_id: String,
    pub client_secret_nonce: String,
    pub client_public_nonce: String,
    pub blinding_factor: String,
    pub server_public_nonce: Option<String>,
}

pub async fn insert_wallet(pool: &Pool<Sqlite>, wallet: &Wallet) -> Result<()> {
    let wallet_json = json!(wallet).to_string();

    let query = "INSERT INTO wallet (wallet_name, wallet_json) VALUES ($1, $2)";

    let _ = sqlx::query(query)
        .bind(wallet.name.clone())
        .bind(wallet_json)
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn get_wallet(pool: &Pool<Sqlite>, wallet_name: &str) -> Result<Wallet> {
    let query = "SELECT wallet_json FROM wallet WHERE wallet_name = $1";

    let row = sqlx::query(query).bind(wallet_name).fetch_one(pool).await?;

    if row.is_empty() {
        return Err(anyhow!("Wallet not found"));
    }

    let wallet_json: String = row.get(0);

    let wallet: Wallet = serde_json::from_str(&wallet_json)?;

    Ok(wallet)
}

pub async fn update_wallet(pool: &Pool<Sqlite>, wallet: &Wallet) -> Result<()> {
    let wallet_json = json!(wallet).to_string();

    let query = "UPDATE wallet SET wallet_json = $1 WHERE wallet_name = $2";

    let _ = sqlx::query(query)
        .bind(wallet_json)
        .bind(wallet.name.clone())
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn insert_backup_txs(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    backup_txs: &Vec<BackupTx>,
) -> Result<()> {
    let backup_txs_json = json!(backup_txs).to_string();

    let query = "INSERT INTO backup_txs (wallet_name, statechain_id, txs) VALUES ($1, $2, $3)";

    let _ = sqlx::query(query)
        .bind(wallet_name)
        .bind(statechain_id)
        .bind(backup_txs_json)
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn update_backup_txs(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    backup_txs: &Vec<BackupTx>,
) -> Result<()> {
    let backup_txs_json = json!(backup_txs).to_string();

    let query = "UPDATE backup_txs SET txs = $1 WHERE statechain_id = $2 AND wallet_name = $3";

    let _ = sqlx::query(query)
        .bind(backup_txs_json)
        .bind(statechain_id)
        .bind(wallet_name)
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn get_backup_txs(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<Vec<BackupTx>> {
    let query = "SELECT txs FROM backup_txs WHERE statechain_id = $1 AND wallet_name = $2";

    let row = sqlx::query(query)
        .bind(statechain_id)
        .bind(wallet_name)
        .fetch_one(pool)
        .await?;

    if row.is_empty() {
        return Err(anyhow!("Statechain id not found"));
    }

    let backup_txs_json: String = row.get(0);

    let backup_txs: Vec<BackupTx> = serde_json::from_str(&backup_txs_json)?;

    Ok(backup_txs)
}

pub async fn insert_or_update_backup_txs(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    backup_txs: &Vec<BackupTx>,
) -> Result<()> {
    let mut transaction = pool.begin().await?;

    let backup_txs_json = json!(backup_txs).to_string();

    let query = "DELETE FROM backup_txs WHERE statechain_id = $1 AND wallet_name = $2";

    let _ = sqlx::query(query)
        .bind(statechain_id)
        .bind(wallet_name)
        .execute(&mut *transaction)
        .await?;

    let query = "INSERT INTO backup_txs (statechain_id, wallet_name, txs) VALUES ($1, $2, $3)";

    let _ = sqlx::query(query)
        .bind(statechain_id)
        .bind(wallet_name)
        .bind(backup_txs_json)
        .execute(&mut *transaction)
        .await?;

    transaction.commit().await?;

    Ok(())
}

/// Persists a BIP448 statechain record. `record_json` is the single source of
/// truth (and the only column read back by `get_bip448_statechain`); the
/// individual columns are denormalized copies derived from the same `record`
/// purely so the table can be queried/indexed without parsing JSON. Because
/// they are always written from `record` in this one place, they cannot diverge
/// from `record_json`.
pub async fn insert_or_update_bip448_statechain(
    pool: &Pool<Sqlite>,
    record: &Bip448StatechainRecord,
) -> Result<()> {
    if !record.latest_state.cpfp_child_templates.is_empty() {
        return Err(anyhow!(
            "BIP448 accepted state cannot contain unverified CPFP child templates"
        ));
    }

    let record_json = serde_json::to_string(record)?;
    let query = "\
        INSERT INTO bip448_statechains (\
            wallet_name, statechain_id, aggregate_pubkey, funding_txid, funding_vout, \
            funding_value_sats, latest_state_number, challenge_delay, amount_sats, network, \
            record_json\
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
        ON CONFLICT(wallet_name, statechain_id) DO UPDATE SET \
            aggregate_pubkey = excluded.aggregate_pubkey, \
            funding_txid = excluded.funding_txid, \
            funding_vout = excluded.funding_vout, \
            funding_value_sats = excluded.funding_value_sats, \
            latest_state_number = excluded.latest_state_number, \
            challenge_delay = excluded.challenge_delay, \
            amount_sats = excluded.amount_sats, \
            network = excluded.network, \
            record_json = excluded.record_json, \
            updated_at = CURRENT_TIMESTAMP";

    let _ = sqlx::query(query)
        .bind(&record.wallet_name)
        .bind(&record.statechain_id)
        .bind(&record.aggregate_pubkey)
        .bind(&record.funding_outpoint.txid)
        .bind(i64::from(record.funding_outpoint.vout))
        .bind(record.funding_outpoint.value_sats as i64)
        .bind(i64::from(record.latest_state_number))
        .bind(i64::from(record.challenge_delay))
        .bind(record.amount_sats as i64)
        .bind(&record.network)
        .bind(record_json)
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn get_bip448_statechain(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<Bip448StatechainRecord> {
    let query = "\
        SELECT record_json \
        FROM bip448_statechains \
        WHERE wallet_name = $1 AND statechain_id = $2";

    let row = sqlx::query(query)
        .bind(wallet_name)
        .bind(statechain_id)
        .fetch_one(pool)
        .await?;

    let record_json: String = row.get(0);
    let record = serde_json::from_str(&record_json)?;

    Ok(record)
}

pub async fn get_bip448_statechain_optional(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<Option<Bip448StatechainRecord>> {
    let query = "\
        SELECT record_json \
        FROM bip448_statechains \
        WHERE wallet_name = $1 AND statechain_id = $2";

    let row = sqlx::query(query)
        .bind(wallet_name)
        .bind(statechain_id)
        .fetch_optional(pool)
        .await?;

    row.map(|row| {
        let record_json: String = row.get(0);
        serde_json::from_str(&record_json).map_err(anyhow::Error::from)
    })
    .transpose()
}

pub async fn insert_or_update_bip448_pending_deposit_signing(
    pool: &Pool<Sqlite>,
    signing: &Bip448PendingDepositSigning,
) -> Result<()> {
    let query = "\
        INSERT INTO bip448_pending_deposit_signings (\
            wallet_name, statechain_id, update_template_hash, signing_id, client_secret_nonce, \
            client_public_nonce, blinding_factor, server_public_nonce\
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
        ON CONFLICT(wallet_name, statechain_id) DO UPDATE SET \
            update_template_hash = excluded.update_template_hash, \
            signing_id = excluded.signing_id, \
            client_secret_nonce = excluded.client_secret_nonce, \
            client_public_nonce = excluded.client_public_nonce, \
            blinding_factor = excluded.blinding_factor, \
            server_public_nonce = excluded.server_public_nonce, \
            updated_at = CURRENT_TIMESTAMP";

    let _ = sqlx::query(query)
        .bind(&signing.wallet_name)
        .bind(&signing.statechain_id)
        .bind(&signing.update_template_hash)
        .bind(&signing.signing_id)
        .bind(&signing.client_secret_nonce)
        .bind(&signing.client_public_nonce)
        .bind(&signing.blinding_factor)
        .bind(&signing.server_public_nonce)
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn get_bip448_pending_deposit_signing(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<Option<Bip448PendingDepositSigning>> {
    let query = "\
        SELECT wallet_name, statechain_id, update_template_hash, signing_id, client_secret_nonce, \
               client_public_nonce, blinding_factor, server_public_nonce \
        FROM bip448_pending_deposit_signings \
        WHERE wallet_name = $1 AND statechain_id = $2";

    let row = sqlx::query(query)
        .bind(wallet_name)
        .bind(statechain_id)
        .fetch_optional(pool)
        .await?;

    Ok(row.map(|row| Bip448PendingDepositSigning {
        wallet_name: row.get(0),
        statechain_id: row.get(1),
        update_template_hash: row.get(2),
        signing_id: row.get(3),
        client_secret_nonce: row.get(4),
        client_public_nonce: row.get(5),
        blinding_factor: row.get(6),
        server_public_nonce: row.get(7),
    }))
}

pub async fn update_bip448_pending_deposit_server_public_nonce(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    signing_id: &str,
    server_public_nonce: &str,
) -> Result<()> {
    let query = "\
        UPDATE bip448_pending_deposit_signings \
        SET server_public_nonce = $1, updated_at = CURRENT_TIMESTAMP \
        WHERE wallet_name = $2 AND statechain_id = $3 AND signing_id = $4";

    let result = sqlx::query(query)
        .bind(server_public_nonce)
        .bind(wallet_name)
        .bind(statechain_id)
        .bind(signing_id)
        .execute(pool)
        .await?;

    if result.rows_affected() != 1 {
        return Err(anyhow!(
            "BIP448 pending deposit signing row not found for statechain {}",
            statechain_id
        ));
    }

    Ok(())
}

pub async fn delete_bip448_pending_deposit_signing(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<()> {
    let query =
        "DELETE FROM bip448_pending_deposit_signings WHERE wallet_name = $1 AND statechain_id = $2";

    let _ = sqlx::query(query)
        .bind(wallet_name)
        .bind(statechain_id)
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn insert_or_update_bip448_transfer_msg(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    recipient_auth_pubkey: &str,
    transfer_msg: &Bip448TransferMsg,
) -> Result<()> {
    let transfer_msg_json = serde_json::to_string(transfer_msg)?;
    let query = "\
        INSERT INTO bip448_transfer_messages (\
            wallet_name, statechain_id, recipient_auth_pubkey, transfer_msg_json\
        ) VALUES ($1, $2, $3, $4) \
        ON CONFLICT(wallet_name, statechain_id, recipient_auth_pubkey) DO UPDATE SET \
            transfer_msg_json = excluded.transfer_msg_json, \
            updated_at = CURRENT_TIMESTAMP";

    let _ = sqlx::query(query)
        .bind(wallet_name)
        .bind(&transfer_msg.statechain_id)
        .bind(recipient_auth_pubkey)
        .bind(transfer_msg_json)
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn get_bip448_transfer_msg(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    recipient_auth_pubkey: &str,
) -> Result<Bip448TransferMsg> {
    let query = "\
        SELECT transfer_msg_json \
        FROM bip448_transfer_messages \
        WHERE wallet_name = $1 AND statechain_id = $2 AND recipient_auth_pubkey = $3";

    let row = sqlx::query(query)
        .bind(wallet_name)
        .bind(statechain_id)
        .bind(recipient_auth_pubkey)
        .fetch_one(pool)
        .await?;

    let transfer_msg_json: String = row.get(0);
    let transfer_msg = serde_json::from_str(&transfer_msg_json)?;

    Ok(transfer_msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mercurylib::bip448_statechain::storage::{
        Bip448AnchorOutput, Bip448CpfpChildTemplate, Bip448CsfsKeyMetadata, Bip448FeeBumpPolicy,
        Bip448FundingOutpoint, Bip448LatestState, Bip448RecoveryTemplateRole,
        Bip448SigningMetadata, Bip448ValueSchedule,
    };
    use mercurylib::transfer::bip448::Bip448TransferMsg;
    use mercurylib::wallet::{CoinStatus, Settings};
    use sqlx::sqlite::SqlitePoolOptions;

    async fn migrated_pool() -> Result<Pool<Sqlite>> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await?;

        sqlx::migrate!("./migrations").run(&pool).await?;

        Ok(pool)
    }

    async fn table_exists(pool: &Pool<Sqlite>, table_name: &str) -> Result<bool> {
        let row =
            sqlx::query("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = $1 LIMIT 1")
                .bind(table_name)
                .fetch_optional(pool)
                .await?;

        Ok(row.is_some())
    }

    fn sample_wallet() -> Wallet {
        Wallet {
            name: "wallet".to_string(),
            mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            version: "0.1.0".to_string(),
            state_entity_endpoint: "http://statechain".to_string(),
            chain_backend: "core".to_string(),
            chain_endpoint: "http://127.0.0.1:18443".to_string(),
            network: "regtest".to_string(),
            blockheight: 42,
            initlock: 1000,
            interval: 10,
            activities: Vec::new(),
            coins: Vec::new(),
            settings: Settings {
                network: "regtest".to_string(),
                block_explorerURL: None,
                torProxyHost: None,
                torProxyPort: None,
                torProxyControlPassword: None,
                torProxyControlPort: None,
                statechainEntityApi: "http://statechain".to_string(),
                torStatechainEntityApi: None,
                chainBackend: "core".to_string(),
                chainUrl: "http://127.0.0.1:18443".to_string(),
                chainType: None,
                notifications: false,
                tutorials: false,
            },
        }
    }

    fn sample_latest_state(state_number: u32) -> Bip448LatestState {
        Bip448LatestState {
            state_number,
            challenge_delay: 144,
            update_tx: "02000000".to_string(),
            settlement_tx: "03000000".to_string(),
            update_template_hash: "11".repeat(32),
            settlement_template_hash: "22".repeat(32),
            state_output_script_pubkey: "5120".to_string() + &"33".repeat(32),
            funding_update_script: "51cecbcc".to_string(),
            funding_update_control_block: "c0".to_string() + &"44".repeat(32),
            state_update_script: "b175cecbcc".to_string(),
            state_update_control_block: "c0".to_string() + &"55".repeat(32),
            state_settlement_script: "20".to_string() + &"22".repeat(32) + "ce87",
            state_settlement_control_block: "c0".to_string() + &"66".repeat(32),
            csfs_key_metadata: Bip448CsfsKeyMetadata {
                aggregate_pubkey_parity_odd: true,
                negate_seckey: true,
            },
            signing_metadata: Bip448SigningMetadata {
                role: Bip448RecoveryTemplateRole::FundingUpdate,
                signing_id: "77".repeat(32),
                client_public_nonce: "88".repeat(66),
                server_public_nonce: "99".repeat(66),
                blinding_factor: "aa".repeat(32),
                update_template_hash: "11".repeat(32),
                update_signature: "bb".repeat(64),
                server_signature_count: u64::from(state_number),
            },
            fee_bump_policy: Bip448FeeBumpPolicy::ZeroFeeEphemeralAnchor,
            value_schedule: Bip448ValueSchedule {
                funding_value_sats: 100_000,
                update_input_value_sats: 100_000,
                update_state_output_value_sats: 100_000,
                settlement_input_value_sats: 100_000,
                settlement_recovery_output_value_sats: 100_000,
            },
            anchors: vec![Bip448AnchorOutput {
                tx_role: Bip448RecoveryTemplateRole::StateUpdate,
                output_index: 1,
                value_sats: 0,
                script_pubkey: "51024e73".to_string(),
            }],
            cpfp_child_templates: Vec::new(),
        }
    }

    fn sample_cpfp_child_template() -> Bip448CpfpChildTemplate {
        Bip448CpfpChildTemplate {
            parent_role: Bip448RecoveryTemplateRole::StateUpdate,
            anchor_output_index: 1,
            tx_hex: "03000000".to_string(),
            fee_sats: 1_000,
            target_feerate_sat_per_vbyte: Some(10),
        }
    }

    fn sample_bip448_record(state_number: u32) -> Bip448StatechainRecord {
        let latest_state = sample_latest_state(state_number);
        Bip448StatechainRecord {
            wallet_name: "wallet".to_string(),
            statechain_id: "statechain".to_string(),
            aggregate_pubkey: "02".to_string() + &"12".repeat(32),
            funding_outpoint: Bip448FundingOutpoint {
                txid: "34".repeat(32),
                vout: 0,
                value_sats: 100_000,
            },
            latest_state_number: latest_state.state_number,
            challenge_delay: latest_state.challenge_delay,
            amount_sats: 100_000,
            network: "regtest".to_string(),
            latest_state,
        }
    }

    fn sample_backup_txs() -> Vec<BackupTx> {
        vec![BackupTx {
            tx_n: 1,
            tx: "02000000".to_string(),
            client_public_nonce: "aa".to_string(),
            server_public_nonce: "bb".to_string(),
            client_public_key: "cc".to_string(),
            server_public_key: "dd".to_string(),
            blinding_factor: "ee".to_string(),
        }]
    }

    fn sample_bip448_transfer_msg() -> Bip448TransferMsg {
        let mut latest_state = sample_latest_state(2);
        latest_state
            .cpfp_child_templates
            .push(sample_cpfp_child_template());
        Bip448TransferMsg {
            statechain_id: "statechain".to_string(),
            transfer_signature: "ab".repeat(64),
            sender_user_public_key: "02".to_string() + &"12".repeat(32),
            receiver_user_public_key: "03".to_string() + &"13".repeat(32),
            server_public_key: "02".to_string() + &"14".repeat(32),
            aggregate_pubkey: "02".to_string() + &"15".repeat(32),
            funding_outpoint: Bip448FundingOutpoint {
                txid: "44".repeat(32),
                vout: 1,
                value_sats: 100_000,
            },
            latest_state_number: latest_state.state_number,
            challenge_delay: latest_state.challenge_delay,
            amount_sats: 100_000,
            network: "regtest".to_string(),
            value_schedule: latest_state.value_schedule.clone(),
            latest_state,
            server_signature_count: 2,
            t1: [9u8; 32],
        }
    }

    #[tokio::test]
    async fn migration_adds_bip448_tables_without_touching_legacy_wallet_data() -> Result<()> {
        let pool = migrated_pool().await?;

        assert!(table_exists(&pool, "wallet").await?);
        assert!(table_exists(&pool, "backup_txs").await?);
        assert!(table_exists(&pool, "bip448_statechains").await?);
        assert!(table_exists(&pool, "bip448_transfer_messages").await?);
        assert!(table_exists(&pool, "bip448_pending_deposit_signings").await?);

        let wallet = sample_wallet();
        insert_wallet(&pool, &wallet).await?;
        let backup_txs = sample_backup_txs();
        insert_backup_txs(&pool, &wallet.name, "legacy-statechain", &backup_txs).await?;

        let roundtrip_wallet = get_wallet(&pool, &wallet.name).await?;
        let roundtrip_backup_txs = get_backup_txs(&pool, &wallet.name, "legacy-statechain").await?;

        assert_eq!(roundtrip_wallet.name, wallet.name);
        assert_eq!(roundtrip_backup_txs.len(), 1);
        assert_eq!(roundtrip_backup_txs[0].tx_n, 1);

        Ok(())
    }

    #[tokio::test]
    async fn reapplying_bip448_migration_does_not_destroy_populated_legacy_data() -> Result<()> {
        let pool = migrated_pool().await?;
        let wallet = sample_wallet();
        insert_wallet(&pool, &wallet).await?;
        let backup_txs = sample_backup_txs();
        insert_backup_txs(&pool, &wallet.name, "legacy-statechain", &backup_txs).await?;

        // Re-run the additive 0002 migration statements against the ALREADY
        // POPULATED legacy database. A destructive DROP/ALTER in 0002 would wipe
        // the legacy rows asserted below; `CREATE TABLE IF NOT EXISTS` is a no-op.
        let migration_sql = include_str!("../migrations/0002_bip448_statechain_data.sql");
        for statement in migration_sql.split(';') {
            let statement = statement.trim();
            if !statement.is_empty() {
                sqlx::query(statement).execute(&pool).await?;
            }
        }

        let roundtrip_backup_txs = get_backup_txs(&pool, &wallet.name, "legacy-statechain").await?;
        assert_eq!(roundtrip_backup_txs.len(), 1);
        assert_eq!(roundtrip_backup_txs[0].tx_n, backup_txs[0].tx_n);
        assert_eq!(get_wallet(&pool, &wallet.name).await?.name, wallet.name);
        assert!(table_exists(&pool, "bip448_statechains").await?);

        Ok(())
    }

    #[tokio::test]
    async fn bip448_latest_state_records_round_trip_through_sqlite() -> Result<()> {
        let pool = migrated_pool().await?;
        let record = sample_bip448_record(1);

        insert_or_update_bip448_statechain(&pool, &record).await?;
        let roundtrip =
            get_bip448_statechain(&pool, &record.wallet_name, &record.statechain_id).await?;

        assert_eq!(roundtrip, record);

        let updated = sample_bip448_record(2);
        insert_or_update_bip448_statechain(&pool, &updated).await?;
        let roundtrip =
            get_bip448_statechain(&pool, &updated.wallet_name, &updated.statechain_id).await?;

        assert_eq!(roundtrip.latest_state_number, 2);
        assert_eq!(roundtrip.latest_state.state_number, 2);
        assert_eq!(
            roundtrip
                .latest_state
                .signing_metadata
                .server_signature_count,
            2
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

        let error = insert_or_update_bip448_statechain(&pool, &rejected_insert)
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
        insert_or_update_bip448_statechain(&pool, &accepted).await?;
        let mut rejected_update = sample_bip448_record(2);
        rejected_update
            .latest_state
            .cpfp_child_templates
            .push(sample_cpfp_child_template());

        insert_or_update_bip448_statechain(&pool, &rejected_update)
            .await
            .unwrap_err();
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

        insert_or_update_bip448_transfer_msg(
            &pool,
            "wallet",
            &recipient_auth_pubkey,
            &transfer_msg,
        )
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
            update_template_hash: "11".repeat(32),
            signing_id: "22".repeat(32),
            client_secret_nonce: "33".repeat(132),
            client_public_nonce: "44".repeat(66),
            blinding_factor: "55".repeat(32),
            server_public_nonce: None,
        };

        insert_or_update_bip448_pending_deposit_signing(&pool, &pending).await?;
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

        delete_bip448_pending_deposit_signing(&pool, &pending.wallet_name, &pending.statechain_id)
            .await?;
        assert!(get_bip448_pending_deposit_signing(
            &pool,
            &pending.wallet_name,
            &pending.statechain_id,
        )
        .await?
        .is_none());

        Ok(())
    }

    #[test]
    fn legacy_coin_status_import_remains_available_for_existing_callers() {
        assert_eq!(CoinStatus::CONFIRMED.to_string(), "CONFIRMED");
    }
}
