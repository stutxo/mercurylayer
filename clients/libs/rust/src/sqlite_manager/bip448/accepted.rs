use anyhow::{anyhow, Result};
use mercurylib::{
    bip448_statechain::{
        script,
        storage::{Bip448LatestState, Bip448StatechainRecord},
    },
    transfer::bip448::{Bip448StateHistoryEntry, Bip448TransferMsg},
};
use secp256k1::XOnlyPublicKey;
use sqlx::{Pool, Row, Sqlite};

use crate::{
    deposit::Bip448AcceptedDepositState,
    transfer_receiver::bip448_transfer_receiver::Bip448AcceptedTransferState,
};

use super::super::canonical_txid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip448PendingDepositSigning {
    pub wallet_name: String,
    pub statechain_id: String,
    pub funding_txid: String,
    pub funding_vout: u32,
    pub funding_value_sats: u64,
    pub update_template_hash: String,
    pub settlement_template_hash: String,
    pub state_locktime: u32,
    pub signing_id: String,
    pub client_secret_nonce: String,
    pub client_public_nonce: String,
    pub blinding_factor: String,
    pub server_public_nonce: Option<String>,
}
/// Persists a BIP448 statechain record. `record_json` is the single source of
/// truth (and the only column read back by `get_bip448_statechain`); the
/// individual columns are denormalized copies derived from the same `record`
/// purely so the table can be queried/indexed without parsing JSON. Because
/// they are always written from `record` in this one place, they cannot diverge
/// from `record_json`.
pub(crate) async fn insert_or_update_bip448_statechain(
    pool: &Pool<Sqlite>,
    accepted: &Bip448AcceptedDepositState,
) -> Result<()> {
    upsert_bip448_statechain_record(pool, accepted.record()).await
}

pub(crate) async fn insert_or_update_bip448_statechain_from_transfer(
    pool: &Pool<Sqlite>,
    accepted: &Bip448AcceptedTransferState,
) -> Result<()> {
    // A verified transfer can advance over signed superseded states. The typed
    // acceptance gate proves the complete history before this persistence step.
    upsert_bip448_statechain_record_with_policy(pool, accepted.record(), true).await
}

pub(super) fn validated_bip448_record_json(record: &Bip448StatechainRecord) -> Result<String> {
    if !record.latest_state.cpfp_child_templates.is_empty() {
        return Err(anyhow!(
            "BIP448 accepted state cannot contain unverified CPFP child templates"
        ));
    }
    if record.latest_state_number != record.latest_state.state_number {
        return Err(anyhow!(
            "BIP448 latest state number does not match the statechain record"
        ));
    }
    let state_locktime =
        bitcoin::absolute::LockTime::from_consensus(record.latest_state.state_locktime);
    if record.latest_state_number
        == mercurylib::bip448_statechain::deposit::INITIAL_BIP448_STATE_NUMBER
    {
        script::validate_initial_state_locktime(state_locktime)?;
    } else {
        script::validate_state_locktime(state_locktime)?;
    }

    Ok(serde_json::to_string(record)?)
}

pub(super) async fn upsert_bip448_statechain_record(
    pool: &Pool<Sqlite>,
    record: &Bip448StatechainRecord,
) -> Result<()> {
    upsert_bip448_statechain_record_with_policy(pool, record, false).await
}

async fn upsert_bip448_statechain_record_with_policy(
    pool: &Pool<Sqlite>,
    record: &Bip448StatechainRecord,
    allow_verified_transfer_skip: bool,
) -> Result<()> {
    let mut record = record.clone();
    record.funding_outpoint.txid = canonical_txid(&record.funding_outpoint.txid)?;
    let record = &record;
    let record_json = validated_bip448_record_json(record)?;
    let mut transaction = pool.begin().await?;
    let existing = sqlx::query(
        "SELECT record_json FROM bip448_statechains \
         WHERE wallet_name = $1 AND statechain_id = $2",
    )
    .bind(&record.wallet_name)
    .bind(&record.statechain_id)
    .fetch_optional(&mut *transaction)
    .await?;

    if let Some(row) = existing {
        let stored_json: String = row.get(0);
        if stored_json == record_json {
            transaction.commit().await?;
            return Ok(());
        }

        let stored: Bip448StatechainRecord = serde_json::from_str(&stored_json)?;
        if stored.wallet_name != record.wallet_name
            || stored.statechain_id != record.statechain_id
            || stored.aggregate_pubkey != record.aggregate_pubkey
            || stored.funding_outpoint != record.funding_outpoint
            || stored.amount_sats != record.amount_sats
            || stored.network != record.network
            || stored.challenge_delay != record.challenge_delay
        {
            return Err(anyhow!("BIP448 accepted state immutable identity mismatch"));
        }
        let valid_transition = if allow_verified_transfer_skip {
            record.latest_state_number > stored.latest_state_number
        } else {
            record.latest_state_number == stored.latest_state_number + 1
        };
        if !valid_transition {
            return Err(anyhow!(
                "BIP448 accepted state must be an exact replay or a monotonic single-step transition"
            ));
        }

        sqlx::query(
            "UPDATE bip448_statechains SET \
                latest_state_number = $1, record_json = $2, updated_at = CURRENT_TIMESTAMP \
             WHERE wallet_name = $3 AND statechain_id = $4",
        )
        .bind(i64::from(record.latest_state_number))
        .bind(record_json)
        .bind(&record.wallet_name)
        .bind(&record.statechain_id)
        .execute(&mut *transaction)
        .await?;
    } else {
        sqlx::query(
            "INSERT INTO bip448_statechains (\
                wallet_name, statechain_id, aggregate_pubkey, funding_txid, funding_vout, \
                funding_value_sats, latest_state_number, challenge_delay, amount_sats, network, \
                record_json\
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(&record.wallet_name)
        .bind(&record.statechain_id)
        .bind(&record.aggregate_pubkey)
        .bind(&record.funding_outpoint.txid)
        .bind(i64::from(record.funding_outpoint.vout))
        .bind(i64::try_from(record.funding_outpoint.value_sats)?)
        .bind(i64::from(record.latest_state_number))
        .bind(i64::from(record.challenge_delay))
        .bind(i64::try_from(record.amount_sats)?)
        .bind(&record.network)
        .bind(record_json)
        .execute(&mut *transaction)
        .await?;
    }

    transaction.commit().await?;
    Ok(())
}

pub(crate) fn history_entry(
    state: &Bip448LatestState,
    owner_public_key: XOnlyPublicKey,
) -> Bip448StateHistoryEntry {
    Bip448StateHistoryEntry {
        state_number: state.state_number,
        state_locktime: state.state_locktime,
        owner_public_key: owner_public_key.to_string(),
        update_template_hash: state.update_template_hash.clone(),
        settlement_template_hash: state.settlement_template_hash.clone(),
        update_signature: state.signing_metadata.update_signature.clone(),
        client_public_nonce: state.signing_metadata.client_public_nonce.clone(),
        server_public_nonce: state.signing_metadata.server_public_nonce.clone(),
        blinding_factor: state.signing_metadata.blinding_factor.clone(),
    }
}

pub async fn insert_bip448_state_history_entry(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    entry: &Bip448StateHistoryEntry,
) -> Result<()> {
    let entry_json = serde_json::to_string(entry)?;
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "INSERT INTO bip448_state_history \
            (wallet_name, statechain_id, state_number, entry_json) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT(wallet_name, statechain_id, state_number) DO NOTHING",
    )
    .bind(wallet_name)
    .bind(statechain_id)
    .bind(i64::from(entry.state_number))
    .bind(&entry_json)
    .execute(&mut *transaction)
    .await?;
    let stored: String = sqlx::query_scalar(
        "SELECT entry_json FROM bip448_state_history \
         WHERE wallet_name = $1 AND statechain_id = $2 AND state_number = $3",
    )
    .bind(wallet_name)
    .bind(statechain_id)
    .bind(i64::from(entry.state_number))
    .fetch_one(&mut *transaction)
    .await?;
    if stored != entry_json {
        return Err(anyhow!(
            "BIP448 state history conflicts with the persisted entry"
        ));
    }
    transaction.commit().await?;
    Ok(())
}

pub async fn get_bip448_state_history(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<Vec<Bip448StateHistoryEntry>> {
    sqlx::query_scalar::<_, String>(
        "SELECT entry_json FROM bip448_state_history \
         WHERE wallet_name = $1 AND statechain_id = $2 \
         ORDER BY state_number",
    )
    .bind(wallet_name)
    .bind(statechain_id)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|entry_json| serde_json::from_str(&entry_json).map_err(anyhow::Error::from))
    .collect()
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

pub async fn insert_bip448_pending_deposit_signing_if_absent(
    pool: &Pool<Sqlite>,
    signing: &Bip448PendingDepositSigning,
) -> Result<Bip448PendingDepositSigning> {
    script::validate_initial_state_locktime(bitcoin::absolute::LockTime::from_consensus(
        signing.state_locktime,
    ))?;
    let query = "\
        INSERT INTO bip448_pending_deposit_signings (\
            wallet_name, statechain_id, funding_txid, funding_vout, funding_value_sats, \
            update_template_hash, settlement_template_hash, state_locktime, signing_id, client_secret_nonce, \
            client_public_nonce, blinding_factor, server_public_nonce\
        ) SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13 \
        WHERE NOT EXISTS (\
            SELECT 1 FROM bip448_statechains \
            WHERE wallet_name = $1 AND statechain_id = $2\
        ) \
        ON CONFLICT(wallet_name, statechain_id) DO NOTHING";

    let _ = sqlx::query(query)
        .bind(&signing.wallet_name)
        .bind(&signing.statechain_id)
        .bind(&signing.funding_txid)
        .bind(i64::from(signing.funding_vout))
        .bind(i64::try_from(signing.funding_value_sats)?)
        .bind(&signing.update_template_hash)
        .bind(&signing.settlement_template_hash)
        .bind(i64::from(signing.state_locktime))
        .bind(&signing.signing_id)
        .bind(&signing.client_secret_nonce)
        .bind(&signing.client_public_nonce)
        .bind(&signing.blinding_factor)
        .bind(&signing.server_public_nonce)
        .execute(pool)
        .await?;

    if let Some(pending) =
        get_bip448_pending_deposit_signing(pool, &signing.wallet_name, &signing.statechain_id)
            .await?
    {
        return Ok(pending);
    }
    if get_bip448_statechain_optional(pool, &signing.wallet_name, &signing.statechain_id)
        .await?
        .is_some()
    {
        return Err(anyhow!(
            "BIP448 deposit state is already accepted; a new signing identity cannot be created"
        ));
    }

    Err(anyhow!(
        "BIP448 pending deposit signing row disappeared after insertion"
    ))
}

pub async fn get_bip448_pending_deposit_signing(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<Option<Bip448PendingDepositSigning>> {
    let query = "\
        SELECT wallet_name, statechain_id, funding_txid, funding_vout, funding_value_sats, \
               update_template_hash, settlement_template_hash, signing_id, client_secret_nonce, \
               client_public_nonce, blinding_factor, server_public_nonce, state_locktime \
        FROM bip448_pending_deposit_signings \
        WHERE wallet_name = $1 AND statechain_id = $2";

    let row = sqlx::query(query)
        .bind(wallet_name)
        .bind(statechain_id)
        .fetch_optional(pool)
        .await?;

    row.map(|row| {
        let state_locktime = row
            .try_get::<Option<i64>, _>(12)?
            .ok_or_else(|| {
                anyhow!(
                    "BIP448 pending deposit signing row predates randomized locktime support and cannot be resumed"
                )
            })?;
        let state_locktime = u32::try_from(state_locktime)
            .map_err(|_| anyhow!("BIP448 pending state locktime is outside the u32 range"))?;
        script::validate_initial_state_locktime(bitcoin::absolute::LockTime::from_consensus(
            state_locktime,
        ))?;
        let funding_txid = row.try_get::<Option<String>, _>(2)?.ok_or_else(|| {
            anyhow!(
                "BIP448 pending deposit signing row predates funding-outpoint journaling and cannot be resumed"
            )
        })?;
        let funding_vout = row.try_get::<Option<i64>, _>(3)?.ok_or_else(|| {
            anyhow!(
                "BIP448 pending deposit signing row predates funding-outpoint journaling and cannot be resumed"
            )
        })?;
        let funding_vout = u32::try_from(funding_vout)
            .map_err(|_| anyhow!("BIP448 pending funding vout is outside the u32 range"))?;
        let funding_value_sats = row.try_get::<Option<i64>, _>(4)?.ok_or_else(|| {
            anyhow!(
                "BIP448 pending deposit signing row predates funding-outpoint journaling and cannot be resumed"
            )
        })?;
        let funding_value_sats = u64::try_from(funding_value_sats)
            .map_err(|_| anyhow!("BIP448 pending funding value is negative"))?;
        let settlement_template_hash = row.try_get::<Option<String>, _>(6)?.ok_or_else(|| {
            anyhow!(
                "BIP448 pending deposit signing row predates settlement-template journaling and cannot be resumed"
            )
        })?;

        Ok(Bip448PendingDepositSigning {
            wallet_name: row.get(0),
            statechain_id: row.get(1),
            funding_txid,
            funding_vout,
            funding_value_sats,
            update_template_hash: row.get(5),
            settlement_template_hash,
            signing_id: row.get(7),
            client_secret_nonce: row.get(8),
            client_public_nonce: row.get(9),
            blinding_factor: row.get(10),
            server_public_nonce: row.get(11),
            state_locktime,
        })
    })
    .transpose()
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
    signing_id: &str,
) -> Result<()> {
    let query = "\
        DELETE FROM bip448_pending_deposit_signings \
        WHERE wallet_name = $1 AND statechain_id = $2 AND signing_id = $3";

    let _ = sqlx::query(query)
        .bind(wallet_name)
        .bind(statechain_id)
        .bind(signing_id)
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn insert_bip448_pending_transfer_signing_if_absent(
    pool: &Pool<Sqlite>,
    signing: &Bip448PendingDepositSigning,
) -> Result<Bip448PendingDepositSigning> {
    script::validate_state_locktime(bitcoin::absolute::LockTime::from_consensus(
        signing.state_locktime,
    ))?;
    let accepted =
        get_bip448_statechain_optional(pool, &signing.wallet_name, &signing.statechain_id).await?;
    if !accepted.as_ref().is_some_and(|record| {
        record.funding_outpoint.txid == signing.funding_txid
            && record.funding_outpoint.vout == signing.funding_vout
            && record.funding_outpoint.value_sats == signing.funding_value_sats
    }) {
        return Err(anyhow!(
            "BIP448 pending transfer signing requires a matching accepted record at the coin's latest state"
        ));
    }
    let latest_state_number = accepted.unwrap().latest_state_number;
    let query = "\
        INSERT INTO bip448_pending_transfer_signings (\
            wallet_name, statechain_id, funding_txid, funding_vout, funding_value_sats, \
            update_template_hash, settlement_template_hash, state_locktime, signing_id, client_secret_nonce, \
            client_public_nonce, blinding_factor, server_public_nonce\
        ) SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13 \
        WHERE EXISTS (\
            SELECT 1 FROM bip448_statechains \
            WHERE wallet_name = $1 AND statechain_id = $2 AND latest_state_number = $14 AND funding_txid = $3 AND funding_vout = $4 AND funding_value_sats = $5\
        ) \
        ON CONFLICT(wallet_name, statechain_id) DO NOTHING";

    sqlx::query(query)
        .bind(&signing.wallet_name)
        .bind(&signing.statechain_id)
        .bind(&signing.funding_txid)
        .bind(i64::from(signing.funding_vout))
        .bind(i64::try_from(signing.funding_value_sats)?)
        .bind(&signing.update_template_hash)
        .bind(&signing.settlement_template_hash)
        .bind(i64::from(signing.state_locktime))
        .bind(&signing.signing_id)
        .bind(&signing.client_secret_nonce)
        .bind(&signing.client_public_nonce)
        .bind(&signing.blinding_factor)
        .bind(&signing.server_public_nonce)
        .bind(i64::from(latest_state_number))
        .execute(pool)
        .await?;

    get_bip448_pending_transfer_signing(pool, &signing.wallet_name, &signing.statechain_id)
        .await?
        .ok_or_else(|| anyhow!("BIP448 pending transfer signing row disappeared after insertion"))
}

pub async fn get_bip448_pending_transfer_signing(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<Option<Bip448PendingDepositSigning>> {
    let query = "\
        SELECT wallet_name, statechain_id, funding_txid, funding_vout, funding_value_sats, \
               update_template_hash, settlement_template_hash, state_locktime, signing_id, \
               client_secret_nonce, client_public_nonce, blinding_factor, server_public_nonce \
        FROM bip448_pending_transfer_signings \
        WHERE wallet_name = $1 AND statechain_id = $2";

    let row = sqlx::query(query)
        .bind(wallet_name)
        .bind(statechain_id)
        .fetch_optional(pool)
        .await?;

    row.map(|row| {
        let state_locktime = u32::try_from(row.get::<i64, _>(7))
            .map_err(|_| anyhow!("BIP448 pending state locktime is outside the u32 range"))?;
        script::validate_state_locktime(bitcoin::absolute::LockTime::from_consensus(
            state_locktime,
        ))?;
        Ok(Bip448PendingDepositSigning {
            wallet_name: row.get(0),
            statechain_id: row.get(1),
            funding_txid: row.get(2),
            funding_vout: u32::try_from(row.get::<i64, _>(3))
                .map_err(|_| anyhow!("BIP448 pending funding vout is outside the u32 range"))?,
            funding_value_sats: u64::try_from(row.get::<i64, _>(4))
                .map_err(|_| anyhow!("BIP448 pending funding value is negative"))?,
            update_template_hash: row.get(5),
            settlement_template_hash: row.get(6),
            state_locktime,
            signing_id: row.get(8),
            client_secret_nonce: row.get(9),
            client_public_nonce: row.get(10),
            blinding_factor: row.get(11),
            server_public_nonce: row.get(12),
        })
    })
    .transpose()
}

pub async fn update_bip448_pending_transfer_server_public_nonce(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    signing_id: &str,
    server_public_nonce: &str,
) -> Result<()> {
    let result = sqlx::query(
        "UPDATE bip448_pending_transfer_signings \
         SET server_public_nonce = $1, updated_at = CURRENT_TIMESTAMP \
         WHERE wallet_name = $2 AND statechain_id = $3 AND signing_id = $4",
    )
    .bind(server_public_nonce)
    .bind(wallet_name)
    .bind(statechain_id)
    .bind(signing_id)
    .execute(pool)
    .await?;
    if result.rows_affected() != 1 {
        return Err(anyhow!(
            "BIP448 pending transfer signing row not found for statechain {}",
            statechain_id
        ));
    }
    Ok(())
}

pub async fn delete_bip448_pending_transfer_signing(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    signing_id: &str,
) -> Result<()> {
    sqlx::query(
        "DELETE FROM bip448_pending_transfer_signings \
         WHERE wallet_name = $1 AND statechain_id = $2 AND signing_id = $3",
    )
    .bind(wallet_name)
    .bind(statechain_id)
    .bind(signing_id)
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

    let result = sqlx::query(query)
        .bind(wallet_name)
        .bind(&transfer_msg.statechain_id)
        .bind(recipient_auth_pubkey)
        .bind(transfer_msg_json)
        .execute(pool)
        .await?;
    if result.rows_affected() != 1 {
        return Err(anyhow!(
            "BIP448 transfer-message upsert affected an unexpected row count"
        ));
    }

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

pub async fn get_bip448_transfer_msg_raw_optional(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    recipient_auth_pubkey: Option<&str>,
) -> Result<Option<(String, String)>> {
    let rows = match recipient_auth_pubkey {
        Some(recipient_auth_pubkey) => {
            sqlx::query(
                "SELECT recipient_auth_pubkey, transfer_msg_json \
                 FROM bip448_transfer_messages \
                 WHERE wallet_name = $1 AND statechain_id = $2 \
                 AND recipient_auth_pubkey = $3 ORDER BY recipient_auth_pubkey",
            )
            .bind(wallet_name)
            .bind(statechain_id)
            .bind(recipient_auth_pubkey)
            .fetch_all(pool)
            .await?
        }
        None => {
            sqlx::query(
                "SELECT recipient_auth_pubkey, transfer_msg_json \
                 FROM bip448_transfer_messages \
                 WHERE wallet_name = $1 AND statechain_id = $2 \
                 ORDER BY recipient_auth_pubkey",
            )
            .bind(wallet_name)
            .bind(statechain_id)
            .fetch_all(pool)
            .await?
        }
    };
    match rows.as_slice() {
        [] => Ok(None),
        [row] => Ok(Some((row.try_get(0)?, row.try_get(1)?))),
        _ => Err(anyhow!(
            "multiple BIP448 outgoing messages exist for one statechain"
        )),
    }
}

pub async fn has_bip448_transfer_msg_for_statechain(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM bip448_transfer_messages WHERE wallet_name = $1 AND statechain_id = $2").bind(wallet_name).bind(statechain_id).fetch_one(pool).await? != 0)
}

pub(crate) async fn list_bip448_transfer_msg_raw_rows(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<Vec<(String, String)>> {
    sqlx::query(
        "SELECT recipient_auth_pubkey,transfer_msg_json FROM bip448_transfer_messages \
         WHERE wallet_name=$1 AND statechain_id=$2 ORDER BY recipient_auth_pubkey",
    )
    .bind(wallet_name)
    .bind(statechain_id)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|row| Ok((row.try_get(0)?, row.try_get(1)?)))
    .collect()
}

pub async fn delete_bip448_transfer_msgs(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<()> {
    sqlx::query(
        "DELETE FROM bip448_transfer_messages WHERE wallet_name = $1 AND statechain_id = $2",
    )
    .bind(wallet_name)
    .bind(statechain_id)
    .execute(pool)
    .await?;
    Ok(())
}
