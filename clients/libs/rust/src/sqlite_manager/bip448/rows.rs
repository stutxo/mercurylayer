use anyhow::{anyhow, Context, Result};
use sqlx::{Pool, Row, Sqlite, SqliteConnection};

use crate::bip448_funding::{
    self, Bip448BindingRole, Bip448BroadcastStatus, Bip448CompletionStatus, Bip448FundingBinding,
    Bip448ObservationStatus, Bip448OwnershipStatus, Bip448TransferIntent,
    Bip448TransferIntentActivityStatus, Bip448TransferIntentKind, Bip448TransferIntentPhase,
    Bip448TransferStateSigningPhase, Bip448WithdrawalAttempt, Bip448WithdrawalAttemptKind,
    Bip448WithdrawalPhase,
};

pub(in crate::sqlite_manager) const BIP448_BINDING_COLUMNS: &str =
    "wallet_name, statechain_id, binding_index, txid, vout, \
    value_sats, script_pubkey, role, observation_status, funding_height, spend_txid, \
    spend_height, last_scanned_height, owner_user_pubkey, owner_state_number, \
    ownership_status, first_seen_at, last_seen_at";

pub(in crate::sqlite_manager) const BIP448_ATTEMPT_COLUMNS: &str =
    "wallet_name, statechain_id, binding_index, attempt_kind, \
    owner_user_pubkey, owner_state_number, source_txid, source_vout, source_value_sats, \
    source_script_pubkey, destination_address, destination_script_pubkey, \
    fee_rate_sat_per_vbyte, fee_sats, lock_time, unsigned_tx_hex, signing_id, \
    signed_statechain_id, sign_first_payload_json, client_secret_nonce, client_public_nonce, \
    blinding_factor, server_public_nonce, message_hex, output_pubkey, client_partial_sig, \
    encoded_session, sign_second_payload_json, server_partial_sig, aggregate_signature, \
    signed_tx_hex, txid, phase, broadcast_status, completion_status, closing_tip_height, \
    closing_tip_hash, closing_bindings_json, created_at, updated_at";

pub(in crate::sqlite_manager) const BIP448_INTENT_COLUMNS: &str =
    "wallet_name, statechain_id, intent_id, \
    predecessor_intent_id, activity_status, intent_kind, acknowledge_cooperative_duplicates, \
    recipient_address, receiver_user_pubkey, recipient_auth_pubkey, batch_id, \
    sender_signed_statechain_id, planned_state_number, expected_signature_count, \
    previous_locktime, prior_pending_signing_id, prior_transfer_recipient_auth_pubkey, \
    prior_transfer_msg_hash, reuse_pending, reuse_signed_state, clear_local_attempt, \
    generated_coin_user_pubkey, generated_coin_auth_pubkey, generated_coin_address, phase, \
    server_x1, current_pending_signing_id, state_signing_phase, server_partial_sig, \
    update_signature, created_at, updated_at";

pub(in crate::sqlite_manager) fn checked_u32(
    row: &sqlx::sqlite::SqliteRow,
    index: usize,
    description: &str,
) -> Result<u32> {
    u32::try_from(row.try_get::<i64, _>(index)?)
        .with_context(|| format!("{description} is outside the u32 range"))
}

fn checked_optional_u32(
    row: &sqlx::sqlite::SqliteRow,
    index: usize,
    description: &str,
) -> Result<Option<u32>> {
    row.try_get::<Option<i64>, _>(index)?
        .map(|value| {
            u32::try_from(value).with_context(|| format!("{description} is outside the u32 range"))
        })
        .transpose()
}

pub(in crate::sqlite_manager) fn checked_u64(
    row: &sqlx::sqlite::SqliteRow,
    index: usize,
    description: &str,
) -> Result<u64> {
    u64::try_from(row.try_get::<i64, _>(index)?)
        .with_context(|| format!("{description} is negative"))
}

fn checked_bool(row: &sqlx::sqlite::SqliteRow, index: usize, description: &str) -> Result<bool> {
    match row.try_get::<i64, _>(index)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(anyhow!("{description} is not a checked SQLite boolean")),
    }
}

pub(in crate::sqlite_manager) fn row_to_bip448_binding(
    row: sqlx::sqlite::SqliteRow,
) -> Result<Bip448FundingBinding> {
    let binding = Bip448FundingBinding {
        wallet_name: row.try_get(0)?,
        statechain_id: row.try_get(1)?,
        binding_index: checked_u32(&row, 2, "BIP448 binding index")?,
        txid: row.try_get(3)?,
        vout: checked_u32(&row, 4, "BIP448 binding vout")?,
        value_sats: checked_u64(&row, 5, "BIP448 binding value")?,
        script_pubkey: row.try_get(6)?,
        role: Bip448BindingRole::parse(row.try_get(7)?)?,
        observation_status: Bip448ObservationStatus::parse(row.try_get(8)?)?,
        funding_height: checked_optional_u32(&row, 9, "BIP448 funding height")?,
        spend_txid: row.try_get(10)?,
        spend_height: checked_optional_u32(&row, 11, "BIP448 spend height")?,
        last_scanned_height: checked_u32(&row, 12, "BIP448 last scanned height")?,
        owner_user_pubkey: row.try_get(13)?,
        owner_state_number: checked_u32(&row, 14, "BIP448 owner state number")?,
        ownership_status: Bip448OwnershipStatus::parse(row.try_get(15)?)?,
        first_seen_at: row.try_get(16)?,
        last_seen_at: row.try_get(17)?,
    };
    bip448_funding::validate_binding(&binding)?;
    Ok(binding)
}

pub(in crate::sqlite_manager) fn row_to_bip448_attempt(
    row: sqlx::sqlite::SqliteRow,
) -> Result<Bip448WithdrawalAttempt> {
    let attempt = Bip448WithdrawalAttempt {
        wallet_name: row.try_get(0)?,
        statechain_id: row.try_get(1)?,
        binding_index: checked_u32(&row, 2, "BIP448 attempt binding index")?,
        attempt_kind: Bip448WithdrawalAttemptKind::parse(row.try_get(3)?)?,
        owner_user_pubkey: row.try_get(4)?,
        owner_state_number: checked_u32(&row, 5, "BIP448 attempt owner state number")?,
        source_txid: row.try_get(6)?,
        source_vout: checked_u32(&row, 7, "BIP448 attempt source vout")?,
        source_value_sats: checked_u64(&row, 8, "BIP448 attempt source value")?,
        source_script_pubkey: row.try_get(9)?,
        destination_address: row.try_get(10)?,
        destination_script_pubkey: row.try_get(11)?,
        fee_rate_sat_per_vbyte: row.try_get(12)?,
        fee_sats: checked_u64(&row, 13, "BIP448 attempt fee")?,
        lock_time: checked_u32(&row, 14, "BIP448 attempt lock time")?,
        unsigned_tx_hex: row.try_get(15)?,
        signing_id: row.try_get(16)?,
        signed_statechain_id: row.try_get(17)?,
        sign_first_payload_json: row.try_get(18)?,
        client_secret_nonce: row.try_get(19)?,
        client_public_nonce: row.try_get(20)?,
        blinding_factor: row.try_get(21)?,
        server_public_nonce: row.try_get(22)?,
        message_hex: row.try_get(23)?,
        output_pubkey: row.try_get(24)?,
        client_partial_sig: row.try_get(25)?,
        encoded_session: row.try_get(26)?,
        sign_second_payload_json: row.try_get(27)?,
        server_partial_sig: row.try_get(28)?,
        aggregate_signature: row.try_get(29)?,
        signed_tx_hex: row.try_get(30)?,
        txid: row.try_get(31)?,
        phase: Bip448WithdrawalPhase::parse(row.try_get(32)?)?,
        broadcast_status: Bip448BroadcastStatus::parse(row.try_get(33)?)?,
        completion_status: Bip448CompletionStatus::parse(row.try_get(34)?)?,
        closing_tip_height: checked_optional_u32(&row, 35, "BIP448 closing tip height")?,
        closing_tip_hash: row.try_get(36)?,
        closing_bindings_json: row.try_get(37)?,
        created_at: row.try_get(38)?,
        updated_at: row.try_get(39)?,
    };
    bip448_funding::validate_withdrawal_attempt(&attempt)?;
    Ok(attempt)
}

pub(in crate::sqlite_manager) fn row_to_bip448_intent(
    row: sqlx::sqlite::SqliteRow,
) -> Result<Bip448TransferIntent> {
    let intent = Bip448TransferIntent {
        wallet_name: row.try_get(0)?,
        statechain_id: row.try_get(1)?,
        intent_id: row.try_get(2)?,
        predecessor_intent_id: row.try_get(3)?,
        activity_status: Bip448TransferIntentActivityStatus::parse(row.try_get(4)?)?,
        intent_kind: Bip448TransferIntentKind::parse(row.try_get(5)?)?,
        acknowledge_cooperative_duplicates: checked_bool(
            &row,
            6,
            "BIP448 cooperative-duplicate acknowledgement",
        )?,
        recipient_address: row.try_get(7)?,
        receiver_user_pubkey: row.try_get(8)?,
        recipient_auth_pubkey: row.try_get(9)?,
        batch_id: row.try_get(10)?,
        sender_signed_statechain_id: row.try_get(11)?,
        planned_state_number: checked_u32(&row, 12, "BIP448 planned state number")?,
        expected_signature_count: checked_u32(&row, 13, "BIP448 expected signature count")?,
        previous_locktime: checked_u32(&row, 14, "BIP448 previous locktime")?,
        prior_pending_signing_id: row.try_get(15)?,
        prior_transfer_recipient_auth_pubkey: row.try_get(16)?,
        prior_transfer_msg_hash: row.try_get(17)?,
        reuse_pending: checked_bool(&row, 18, "BIP448 reuse_pending")?,
        reuse_signed_state: checked_bool(&row, 19, "BIP448 reuse_signed_state")?,
        clear_local_attempt: checked_bool(&row, 20, "BIP448 clear_local_attempt")?,
        generated_coin_user_pubkey: row.try_get(21)?,
        generated_coin_auth_pubkey: row.try_get(22)?,
        generated_coin_address: row.try_get(23)?,
        phase: Bip448TransferIntentPhase::parse(row.try_get(24)?)?,
        server_x1: row.try_get(25)?,
        current_pending_signing_id: row.try_get(26)?,
        state_signing_phase: Bip448TransferStateSigningPhase::parse(row.try_get(27)?)?,
        server_partial_sig: row.try_get(28)?,
        update_signature: row.try_get(29)?,
        created_at: row.try_get(30)?,
        updated_at: row.try_get(31)?,
    };
    bip448_funding::validate_transfer_intent(&intent)?;
    Ok(intent)
}

pub(in crate::sqlite_manager) async fn list_bip448_funding_bindings_on(
    connection: &mut SqliteConnection,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<Vec<Bip448FundingBinding>> {
    let query = format!(
        "SELECT {BIP448_BINDING_COLUMNS} FROM bip448_funding_bindings \
         WHERE wallet_name = $1 AND statechain_id = $2 ORDER BY binding_index"
    );
    sqlx::query(&query)
        .bind(wallet_name)
        .bind(statechain_id)
        .fetch_all(connection)
        .await?
        .into_iter()
        .map(row_to_bip448_binding)
        .collect()
}

pub async fn list_bip448_funding_bindings(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<Vec<Bip448FundingBinding>> {
    let mut connection = pool.acquire().await?;
    list_bip448_funding_bindings_on(&mut connection, wallet_name, statechain_id).await
}

pub async fn get_bip448_funding_binding(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    binding_index: u32,
) -> Result<Option<Bip448FundingBinding>> {
    let query = format!(
        "SELECT {BIP448_BINDING_COLUMNS} FROM bip448_funding_bindings \
         WHERE wallet_name = $1 AND statechain_id = $2 AND binding_index = $3"
    );
    sqlx::query(&query)
        .bind(wallet_name)
        .bind(statechain_id)
        .bind(i64::from(binding_index))
        .fetch_optional(pool)
        .await?
        .map(row_to_bip448_binding)
        .transpose()
}

pub(in crate::sqlite_manager) async fn list_bip448_withdrawal_attempts_on(
    connection: &mut SqliteConnection,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<Vec<Bip448WithdrawalAttempt>> {
    let query = format!(
        "SELECT {BIP448_ATTEMPT_COLUMNS} FROM bip448_withdrawal_attempts \
         WHERE wallet_name = $1 AND statechain_id = $2 ORDER BY binding_index"
    );
    sqlx::query(&query)
        .bind(wallet_name)
        .bind(statechain_id)
        .fetch_all(connection)
        .await?
        .into_iter()
        .map(row_to_bip448_attempt)
        .collect()
}

pub async fn list_bip448_withdrawal_attempts(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<Vec<Bip448WithdrawalAttempt>> {
    let mut connection = pool.acquire().await?;
    list_bip448_withdrawal_attempts_on(&mut connection, wallet_name, statechain_id).await
}

pub async fn get_bip448_withdrawal_attempt(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    binding_index: u32,
) -> Result<Option<Bip448WithdrawalAttempt>> {
    let query = format!(
        "SELECT {BIP448_ATTEMPT_COLUMNS} FROM bip448_withdrawal_attempts \
         WHERE wallet_name = $1 AND statechain_id = $2 AND binding_index = $3"
    );
    sqlx::query(&query)
        .bind(wallet_name)
        .bind(statechain_id)
        .bind(i64::from(binding_index))
        .fetch_optional(pool)
        .await?
        .map(row_to_bip448_attempt)
        .transpose()
}

pub(in crate::sqlite_manager) async fn list_bip448_transfer_intents_on(
    connection: &mut SqliteConnection,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<Vec<Bip448TransferIntent>> {
    let query = format!(
        "SELECT {BIP448_INTENT_COLUMNS} FROM bip448_transfer_intents \
         WHERE wallet_name = $1 AND statechain_id = $2 ORDER BY intent_id"
    );
    sqlx::query(&query)
        .bind(wallet_name)
        .bind(statechain_id)
        .fetch_all(connection)
        .await?
        .into_iter()
        .map(row_to_bip448_intent)
        .collect()
}

pub async fn list_bip448_transfer_intents(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<Vec<Bip448TransferIntent>> {
    let mut connection = pool.acquire().await?;
    list_bip448_transfer_intents_on(&mut connection, wallet_name, statechain_id).await
}
