use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use bitcoin::{BlockHash, Txid};
use mercurylib::wallet::Wallet;
use sqlx::{Pool, Row, Sqlite};

mod bip448;

#[cfg(test)]
pub(crate) use self::bip448::insert_or_update_bip448_statechain;
pub use self::bip448::{
    arm_bip448_transfer_sender, arm_bip448_transfer_state_sign_second,
    arm_bip448_withdrawal_sign_first, arm_bip448_withdrawal_sign_second,
    begin_bip448_mutation_guard, begin_bip448_sync_base_guard, bip448_active_withdrawal_attempt,
    bip448_expected_signature_count, bip448_statechain_is_exit_only, capture_bip448_sync_base,
    classify_bip448_close_gate, cleanup_bip448_cancellation_after_acceptance,
    compare_and_set_wallet_after_bip448_scan, delete_bip448_cancellation_artifacts_after_sync,
    delete_bip448_pending_deposit_signing, delete_bip448_pending_transfer_signing,
    delete_bip448_transfer_msgs, delete_prepared_bip448_withdrawal_attempt_for_confirmed_spend,
    finish_bip448_cancellation_sender, finish_bip448_rotated_outgoing_transfer,
    finish_bip448_transfer_sender, finish_bip448_user_transfer_and_delete_intent,
    get_active_bip448_transfer_intent, get_bip448_funding_binding, get_bip448_package_attempt,
    get_bip448_pending_deposit_signing, get_bip448_pending_transfer_signing,
    get_bip448_state_history, get_bip448_statechain, get_bip448_statechain_optional,
    get_bip448_transfer_msg, get_bip448_transfer_msg_raw_optional, get_bip448_withdrawal_attempt,
    has_bip448_transfer_msg_for_statechain, insert_bip448_cancellation_intent_with_wallet,
    insert_bip448_pending_deposit_signing_if_absent,
    insert_bip448_pending_transfer_signing_if_absent, insert_bip448_state_history_entry,
    insert_bip448_transfer_intent_if_absent, insert_bip448_withdrawal_attempt_if_absent,
    insert_or_update_bip448_transfer_msg, install_bip448_transfer_target_pending,
    install_bip448_transfer_target_pending_signing, install_reused_signed_bip448_transfer_state,
    list_bip448_funding_bindings, list_bip448_transfer_intents, list_bip448_withdrawal_attempts,
    mark_bip448_cancellation_receiver_accepted, mark_bip448_funding_bindings_previous,
    materialize_bip448_signed_transfer_intent, persist_bip448_canonical_withdrawal_wallet,
    persist_bip448_initial_acceptance,
    reactivate_bip448_transfer_intent_predecessor_after_definitive_rejection,
    reassign_bip448_funding_bindings_owner, reconcile_bip448_accepted_local_outgoing_messages,
    reconcile_bip448_funding_bindings, reject_bip448_transfer_intent_and_reactivate_predecessor,
    set_bip448_package_attempt_status, store_bip448_transfer_intent_x1,
    store_bip448_transfer_server_x1, store_bip448_transfer_state_nonce,
    store_bip448_transfer_state_signed_artifacts, store_bip448_withdrawal_nonce_artifacts,
    store_bip448_withdrawal_nonce_session, store_bip448_withdrawal_signed_artifacts,
    store_signed_bip448_transfer_state, store_signed_bip448_withdrawal,
    supersede_bip448_transfer_intent, supersede_bip448_transfer_intent_with_cancellation_wallet,
    transition_bip448_transfer_intent_phase, transition_bip448_transfer_state_signing_phase,
    transition_bip448_withdrawal_broadcast_status, transition_bip448_withdrawal_completion_status,
    transition_bip448_withdrawal_phase, update_bip448_funding_binding_observation,
    update_bip448_pending_deposit_server_public_nonce,
    update_bip448_pending_transfer_server_public_nonce, update_bip448_withdrawal_broadcast_status,
    update_bip448_withdrawal_completion_status, validate_bip448_canonical_close_snapshot,
    Bip448FeeInputRecord, Bip448MutationGuard, Bip448PackageAttempt, Bip448PackageAttemptStatus,
    Bip448PendingDepositSigning, Bip448ScanCursor, BIP448_FEE_RESERVATION_TTL_SECONDS,
};
pub(crate) use self::bip448::{
    available_bip448_scanned_outpoints, bip448_reservation_id,
    ensure_no_orphaned_bip448_reservation, history_entry, insert_bip448_package_attempt,
    insert_or_update_bip448_statechain_from_transfer, list_bip448_transfer_msg_raw_rows,
    load_bip448_scan_state, persist_bip448_scan_state,
    reacquire_bip448_package_attempt_reservations, recover_bip448_initial_acceptance_wallet,
    upsert_bip448_scanned_outpoint, with_bip448_canonical_completion_fence,
    Bip448InitialAcceptanceRecovery,
};
use self::bip448::{
    pending_transfer_on, require_materialized_signed_transfer_intent_on,
    transfer_message_matches_history_prefix, validate_bip448_successor_plan_on,
    validate_bip448_transfer_intent_lineage,
};

pub(crate) fn canonical_txid(txid: &str) -> Result<String> {
    Ok(Txid::from_str(txid).context("invalid txid")?.to_string())
}

fn canonical_wallet_json(wallet: &Wallet) -> Result<String> {
    let mut wallet = wallet.clone();
    for coin in &mut wallet.coins {
        for txid in [&mut coin.utxo_txid, &mut coin.tx_withdraw] {
            if let Some(txid) = txid {
                *txid = canonical_txid(txid)?;
            }
        }
    }
    Ok(serde_json::to_string(&wallet)?)
}

fn canonical_block_hash(block_hash: &str) -> Result<String> {
    Ok(BlockHash::from_str(block_hash)
        .context("invalid block hash")?
        .to_string())
}

pub async fn insert_wallet(pool: &Pool<Sqlite>, wallet: &Wallet) -> Result<()> {
    let wallet_json = canonical_wallet_json(wallet)?;

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

pub(crate) async fn get_bip448_raw_wallet_json(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
) -> Result<String> {
    sqlx::query_scalar("SELECT wallet_json FROM wallet WHERE wallet_name = $1")
        .bind(wallet_name)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| anyhow!("BIP448 synchronization wallet is missing"))
}

pub async fn update_wallet(pool: &Pool<Sqlite>, wallet: &Wallet) -> Result<()> {
    let wallet_json = canonical_wallet_json(wallet)?;

    let query = "UPDATE wallet SET wallet_json = $1 WHERE wallet_name = $2";

    let _ = sqlx::query(query)
        .bind(wallet_json)
        .bind(wallet.name.clone())
        .execute(pool)
        .await?;

    Ok(())
}
