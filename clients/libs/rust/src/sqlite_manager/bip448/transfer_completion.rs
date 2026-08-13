use std::{collections::HashSet, str::FromStr};

use anyhow::{anyhow, Context, Result};
use mercurylib::{
    bip448_statechain::storage::Bip448StatechainRecord,
    transfer::bip448::{Bip448StateHistoryEntry, Bip448TransferMsg},
    wallet::Wallet,
};
use sqlx::{Pool, Row, Sqlite, SqliteConnection};

use crate::bip448_funding::{
    self, Bip448TransferIntent, Bip448TransferIntentActivityStatus, Bip448TransferIntentKind,
    Bip448TransferIntentPhase, Bip448TransferStateSigningPhase,
};

use super::super::canonical_wallet_json;
use super::transfer_intents::{
    exact_transfer_intent_on, require_materialized_signed_transfer_intent_on,
    transition_active_intent_on, validate_bip448_transfer_intent_lineage,
};
use super::transfer_signing::{pending_transfer_on, validate_bip448_transfer_pending_signing};
use super::{
    accepted_record_and_history_on, begin_bip448_mutation_guard,
    history_entry_matches_latest_state, list_bip448_transfer_intents_on,
    transfer_message_matches_record_and_history, Bip448PendingDepositSigning,
};

fn validate_bip448_sender_finish_wallet_transition(
    expected: &Bip448TransferIntent,
    expected_raw_wallet_json: &str,
    replacement_wallet: &Wallet,
) -> Result<String> {
    let old_wallet: Wallet = serde_json::from_str(expected_raw_wallet_json)?;
    if old_wallet.name != expected.wallet_name
        || replacement_wallet.name != expected.wallet_name
        || replacement_wallet.coins.len() != old_wallet.coins.len()
    {
        return Err(anyhow!("BIP448 sender-finish wallet identity changed"));
    }
    let matching = old_wallet
        .coins
        .iter()
        .enumerate()
        .filter(|(_, coin)| {
            coin.statechain_id.as_deref() == Some(expected.statechain_id.as_str())
                && coin.signed_statechain_id.as_deref()
                    == Some(expected.sender_signed_statechain_id.as_str())
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(anyhow!(
            "BIP448 sender-finish source Coin identity is not unique"
        ));
    }
    let index = matching[0];
    if replacement_wallet
        .coins
        .get(index)
        .is_none_or(|coin| coin.status != mercurylib::wallet::CoinStatus::IN_TRANSFER)
    {
        return Err(anyhow!(
            "BIP448 sender-finish replacement Coin is not IN_TRANSFER"
        ));
    }
    let mut normalized = replacement_wallet.clone();
    normalized
        .coins
        .get_mut(index)
        .ok_or_else(|| anyhow!("BIP448 sender-finish replacement Coin disappeared"))?
        .status = old_wallet.coins[index].status.clone();
    if serde_json::to_value(&normalized)? != serde_json::to_value(&old_wallet)? {
        return Err(anyhow!(
            "BIP448 sender finish changes fields other than the selected Coin status"
        ));
    }
    canonical_wallet_json(replacement_wallet)
}

pub async fn finish_bip448_transfer_sender(
    pool: &Pool<Sqlite>,
    expected: &Bip448TransferIntent,
    expected_raw_wallet_json: &str,
    replacement_wallet: &Wallet,
    transfer_msg_json: &str,
    validated_pending: &Bip448PendingDepositSigning,
) -> Result<Option<Bip448TransferIntent>> {
    bip448_funding::validate_transfer_intent(expected)?;
    validate_bip448_transfer_pending_signing(validated_pending)?;
    if expected.activity_status != Bip448TransferIntentActivityStatus::Active
        || expected.phase != Bip448TransferIntentPhase::X1Stored
        || expected.state_signing_phase != Bip448TransferStateSigningPhase::Signed
        || expected.wallet_name != validated_pending.wallet_name
        || expected.statechain_id != validated_pending.statechain_id
        || expected.current_pending_signing_id.as_deref()
            != Some(validated_pending.signing_id.as_str())
    {
        return Err(anyhow!(
            "BIP448 transfer intent is not ready for sender finish"
        ));
    }
    let message: Bip448TransferMsg = serde_json::from_str(transfer_msg_json)?;
    let cancellation_identity_matches = expected.intent_kind
        != Bip448TransferIntentKind::Cancellation
        || (expected.generated_coin_user_pubkey.as_deref()
            == Some(message.receiver_user_public_key.as_str())
            && expected.generated_coin_auth_pubkey.as_deref()
                == Some(expected.recipient_auth_pubkey.as_str()));
    if serde_json::to_string(&message)? != transfer_msg_json
        || message.statechain_id != expected.statechain_id
        || message.receiver_user_public_key != expected.receiver_user_pubkey
        || message.latest_state_number != expected.planned_state_number
        || !cancellation_identity_matches
    {
        return Err(anyhow!(
            "BIP448 sender-finish message does not match intent"
        ));
    }
    let replacement = validate_bip448_sender_finish_wallet_transition(
        expected,
        expected_raw_wallet_json,
        replacement_wallet,
    )?;
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    let live = exact_transfer_intent_on(
        guard.connection(),
        &expected.wallet_name,
        &expected.statechain_id,
        &expected.intent_id,
    )
    .await?
    .ok_or_else(|| anyhow!("BIP448 intent is missing"))?;
    if live != *expected {
        return Err(anyhow!("stale BIP448 sender worker lost activity CAS"));
    }
    let pending = pending_transfer_on(
        guard.connection(),
        &expected.wallet_name,
        &expected.statechain_id,
    )
    .await?
    .ok_or_else(|| anyhow!("BIP448 sender-finish pending signing is missing"))?;
    if pending != *validated_pending {
        return Err(anyhow!(
            "BIP448 sender-finish pending signing changed after complete validation"
        ));
    }
    require_materialized_signed_transfer_intent_on(guard.connection(), &live).await?;
    let stored_msg = sqlx::query_scalar::<_, String>(
        "SELECT transfer_msg_json FROM bip448_transfer_messages \
        WHERE wallet_name=$1 AND statechain_id=$2 AND recipient_auth_pubkey=$3",
    )
    .bind(&expected.wallet_name)
    .bind(&expected.statechain_id)
    .bind(&expected.recipient_auth_pubkey)
    .fetch_optional(guard.connection())
    .await?;
    if stored_msg.as_deref() != Some(transfer_msg_json) {
        return Err(anyhow!(
            "BIP448 sender-finish outgoing message is missing or changed"
        ));
    }
    let wallet =
        sqlx::query("UPDATE wallet SET wallet_json=$1 WHERE wallet_name=$2 AND wallet_json=$3")
            .bind(replacement)
            .bind(&expected.wallet_name)
            .bind(expected_raw_wallet_json)
            .execute(guard.connection())
            .await?;
    if wallet.rows_affected() != 1 {
        return Err(anyhow!("BIP448 sender-finish wallet CAS lost"));
    }
    let lineage = list_bip448_transfer_intents_on(
        guard.connection(),
        &expected.wallet_name,
        &expected.statechain_id,
    )
    .await?;
    validate_bip448_transfer_intent_lineage(&lineage)?;
    let result = match expected.intent_kind {
        Bip448TransferIntentKind::UserTransfer => {
            let deleted = sqlx::query(
                "DELETE FROM bip448_transfer_intents WHERE wallet_name=$1 AND statechain_id=$2",
            )
            .bind(&expected.wallet_name)
            .bind(&expected.statechain_id)
            .execute(guard.connection())
            .await?;
            if deleted.rows_affected() != u64::try_from(lineage.len())? {
                return Err(anyhow!(
                    "BIP448 user-transfer lineage cleanup affected an unexpected row count"
                ));
            }
            None
        }
        Bip448TransferIntentKind::Cancellation => {
            let updated = sqlx::query(
                "UPDATE bip448_transfer_intents SET phase='SenderFinished',\
                updated_at=CURRENT_TIMESTAMP WHERE wallet_name=$1 AND statechain_id=$2 \
                AND intent_id=$3 AND activity_status='Active' AND phase='X1Stored' \
                AND state_signing_phase='Signed'",
            )
            .bind(&expected.wallet_name)
            .bind(&expected.statechain_id)
            .bind(&expected.intent_id)
            .execute(guard.connection())
            .await?;
            if updated.rows_affected() != 1 {
                return Err(anyhow!("BIP448 cancellation sender-finish CAS lost"));
            }
            exact_transfer_intent_on(
                guard.connection(),
                &expected.wallet_name,
                &expected.statechain_id,
                &expected.intent_id,
            )
            .await?
        }
    };
    guard.commit().await?;
    Ok(result)
}

pub async fn finish_bip448_user_transfer_and_delete_intent(
    pool: &Pool<Sqlite>,
    expected: &Bip448TransferIntent,
    expected_raw_wallet_json: &str,
    replacement_wallet: &Wallet,
    transfer_msg_json: &str,
    validated_pending: &Bip448PendingDepositSigning,
) -> Result<()> {
    if expected.intent_kind != Bip448TransferIntentKind::UserTransfer {
        return Err(anyhow!("BIP448 sender finish is not a UserTransfer"));
    }
    if finish_bip448_transfer_sender(
        pool,
        expected,
        expected_raw_wallet_json,
        replacement_wallet,
        transfer_msg_json,
        validated_pending,
    )
    .await?
    .is_some()
    {
        return Err(anyhow!(
            "BIP448 user-transfer finish unexpectedly retained an intent"
        ));
    }
    Ok(())
}

pub async fn finish_bip448_cancellation_sender(
    pool: &Pool<Sqlite>,
    expected: &Bip448TransferIntent,
    expected_raw_wallet_json: &str,
    replacement_wallet: &Wallet,
    transfer_msg_json: &str,
    validated_pending: &Bip448PendingDepositSigning,
) -> Result<Bip448TransferIntent> {
    if expected.intent_kind != Bip448TransferIntentKind::Cancellation {
        return Err(anyhow!("BIP448 sender finish is not a Cancellation"));
    }
    finish_bip448_transfer_sender(
        pool,
        expected,
        expected_raw_wallet_json,
        replacement_wallet,
        transfer_msg_json,
        validated_pending,
    )
    .await?
    .ok_or_else(|| anyhow!("BIP448 cancellation finish deleted its recovery intent"))
}

async fn require_bip448_cancellation_accepted_owner_on(
    connection: &mut SqliteConnection,
    intent: &Bip448TransferIntent,
) -> Result<String> {
    if intent.intent_kind != Bip448TransferIntentKind::Cancellation
        || intent.activity_status != Bip448TransferIntentActivityStatus::Active
        || intent.state_signing_phase != Bip448TransferStateSigningPhase::Signed
    {
        return Err(anyhow!(
            "BIP448 cancellation accepted-owner journal is incoherent"
        ));
    }
    let (record, history) =
        accepted_record_and_history_on(connection, &intent.wallet_name, &intent.statechain_id)
            .await?;
    if record.latest_state_number != intent.planned_state_number
        || history.len() != usize::try_from(record.latest_state_number)?
    {
        return Err(anyhow!(
            "BIP448 cancellation is not the accepted latest state"
        ));
    }
    let transfer_msg_json = sqlx::query_scalar::<_, String>(
        "SELECT transfer_msg_json FROM bip448_transfer_messages WHERE wallet_name=$1 \
         AND statechain_id=$2 AND recipient_auth_pubkey=$3",
    )
    .bind(&intent.wallet_name)
    .bind(&intent.statechain_id)
    .bind(&intent.recipient_auth_pubkey)
    .fetch_optional(&mut *connection)
    .await?
    .ok_or_else(|| anyhow!("BIP448 cancellation outgoing message is missing"))?;
    let message: Bip448TransferMsg = serde_json::from_str(&transfer_msg_json)?;
    if serde_json::to_string(&message)? != transfer_msg_json
        || message.receiver_user_public_key != intent.receiver_user_pubkey
        || message.latest_state_number != intent.planned_state_number
        || !transfer_message_matches_record_and_history(&message, &record, &history)?
    {
        return Err(anyhow!(
            "BIP448 cancellation outgoing message is not the accepted state"
        ));
    }
    let raw_wallet =
        sqlx::query_scalar::<_, String>("SELECT wallet_json FROM wallet WHERE wallet_name=$1")
            .bind(&intent.wallet_name)
            .fetch_one(&mut *connection)
            .await?;
    let wallet: Wallet = serde_json::from_str(&raw_wallet)?;
    let matching = wallet
        .coins
        .iter()
        .filter(|coin| {
            coin.statechain_id.as_deref() == Some(intent.statechain_id.as_str())
                && Some(coin.user_pubkey.as_str()) == intent.generated_coin_user_pubkey.as_deref()
                && Some(coin.auth_pubkey.as_str()) == intent.generated_coin_auth_pubkey.as_deref()
                && Some(coin.address.as_str()) == intent.generated_coin_address.as_deref()
        })
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(anyhow!(
            "BIP448 cancellation accepted owner Coin is not unique"
        ));
    }
    let coin = matching[0];
    if coin.statechain_protocol.as_deref() != Some("bip448")
        || !matches!(
            coin.status,
            mercurylib::wallet::CoinStatus::IN_MEMPOOL
                | mercurylib::wallet::CoinStatus::UNCONFIRMED
                | mercurylib::wallet::CoinStatus::CONFIRMED
        )
    {
        return Err(anyhow!(
            "BIP448 cancellation generated Coin is not an accepted current owner"
        ));
    }
    let aggregate = secp256k1::PublicKey::from_str(&coin.user_pubkey)?.combine(
        &secp256k1::PublicKey::from_str(
            coin.server_pubkey
                .as_deref()
                .ok_or_else(|| anyhow!("BIP448 cancellation Coin has no server key"))?,
        )?,
    )?;
    if aggregate.to_string() != record.aggregate_pubkey
        || coin.aggregated_pubkey.as_deref() != Some(record.aggregate_pubkey.as_str())
    {
        return Err(anyhow!(
            "BIP448 cancellation Coin keys do not match the accepted aggregate key"
        ));
    }
    Ok(transfer_msg_json)
}

pub async fn mark_bip448_cancellation_receiver_accepted(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    intent_id: &str,
) -> Result<Bip448TransferIntent> {
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    let live = exact_transfer_intent_on(guard.connection(), wallet_name, statechain_id, intent_id)
        .await?
        .ok_or_else(|| anyhow!("BIP448 cancellation intent is missing"))?;
    if !matches!(
        live.phase,
        Bip448TransferIntentPhase::SenderFinished | Bip448TransferIntentPhase::ReceiverAccepted
    ) {
        return Err(anyhow!(
            "BIP448 cancellation is not ready for receiver acceptance"
        ));
    }
    require_bip448_cancellation_accepted_owner_on(guard.connection(), &live).await?;
    if live.phase == Bip448TransferIntentPhase::ReceiverAccepted {
        guard.commit().await?;
        return Ok(live);
    }
    transition_active_intent_on(
        &mut guard,
        wallet_name,
        statechain_id,
        intent_id,
        Bip448TransferIntentPhase::SenderFinished,
        Bip448TransferIntentPhase::ReceiverAccepted,
        Bip448TransferStateSigningPhase::Signed,
    )
    .await?;
    let row = exact_transfer_intent_on(guard.connection(), wallet_name, statechain_id, intent_id)
        .await?
        .ok_or_else(|| anyhow!("BIP448 cancellation intent disappeared"))?;
    guard.commit().await?;
    Ok(row)
}

pub(in crate::sqlite_manager) fn transfer_message_matches_history_prefix(
    message: &Bip448TransferMsg,
    accepted: &[Bip448StateHistoryEntry],
) -> Result<bool> {
    let message_len = usize::try_from(message.latest_state_number)?;
    if message_len == 0
        || message.state_history.len() != message_len
        || accepted.len() < message_len
        || message.state_history.as_slice() != &accepted[..message_len]
        || message.latest_state.state_number != message.latest_state_number
        || !message
            .state_history
            .last()
            .is_some_and(|entry| history_entry_matches_latest_state(entry, &message.latest_state))
        || message.server_signature_count != u64::from(message.latest_state_number)
        || message.latest_state.signing_metadata.server_signature_count
            != u64::from(message.latest_state_number)
    {
        return Ok(false);
    }
    Ok(true)
}

fn pending_transfer_matches_message_endpoint(
    pending: &Bip448PendingDepositSigning,
    record: &Bip448StatechainRecord,
    message: &Bip448TransferMsg,
) -> Result<bool> {
    let latest = message
        .state_history
        .last()
        .ok_or_else(|| anyhow!("BIP448 outgoing message history is empty"))?;
    let metadata = &message.latest_state.signing_metadata;
    Ok(pending.wallet_name == record.wallet_name
        && pending.statechain_id == record.statechain_id
        && pending.funding_txid == record.funding_outpoint.txid
        && pending.funding_vout == record.funding_outpoint.vout
        && pending.funding_value_sats == record.funding_outpoint.value_sats
        && pending.state_locktime == latest.state_locktime
        && pending.update_template_hash == latest.update_template_hash
        && pending.settlement_template_hash == latest.settlement_template_hash
        && pending.signing_id == metadata.signing_id
        && pending.client_public_nonce == latest.client_public_nonce
        && pending.server_public_nonce.as_deref() == Some(latest.server_public_nonce.as_str())
        && pending.blinding_factor == latest.blinding_factor)
}

pub async fn reconcile_bip448_accepted_local_outgoing_messages(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<usize> {
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    let (record, history) =
        accepted_record_and_history_on(guard.connection(), wallet_name, statechain_id).await?;
    let accepted_len = usize::try_from(record.latest_state_number)?;
    let accepted_history = history
        .get(..accepted_len)
        .ok_or_else(|| anyhow!("BIP448 accepted history prefix is missing"))?;
    let intents =
        list_bip448_transfer_intents_on(guard.connection(), wallet_name, statechain_id).await?;
    if !intents.is_empty() {
        validate_bip448_transfer_intent_lineage(&intents)?;
    }
    let referenced_recipients = intents
        .iter()
        .filter_map(|intent| intent.prior_transfer_recipient_auth_pubkey.as_deref())
        .chain(
            intents
                .iter()
                .map(|intent| intent.recipient_auth_pubkey.as_str()),
        )
        .collect::<HashSet<_>>();
    let referenced_pending_ids = intents
        .iter()
        .flat_map(|intent| {
            [
                intent.prior_pending_signing_id.as_deref(),
                intent.current_pending_signing_id.as_deref(),
            ]
        })
        .flatten()
        .collect::<HashSet<_>>();
    let pending = pending_transfer_on(guard.connection(), wallet_name, statechain_id).await?;
    let raw_wallet =
        sqlx::query_scalar::<_, String>("SELECT wallet_json FROM wallet WHERE wallet_name=$1")
            .bind(wallet_name)
            .fetch_one(guard.connection())
            .await?;
    let wallet: Wallet = serde_json::from_str(&raw_wallet)?;
    let rows = sqlx::query(
        "SELECT recipient_auth_pubkey,transfer_msg_json FROM bip448_transfer_messages \
        WHERE wallet_name=$1 AND statechain_id=$2 ORDER BY recipient_auth_pubkey",
    )
    .bind(wallet_name)
    .bind(statechain_id)
    .fetch_all(guard.connection())
    .await?;
    let mut deletions = Vec::new();
    for row in rows {
        let recipient_auth: String = row.try_get(0)?;
        bip448_funding::require_canonical_public_key(&recipient_auth)?;
        let stored_json: String = row.try_get(1)?;
        let message: Bip448TransferMsg = serde_json::from_str(&stored_json)
            .context("malformed BIP448 outgoing transfer-message journal")?;
        if serde_json::to_string(&message)? != stored_json || message.statechain_id != statechain_id
        {
            return Err(anyhow!(
                "noncanonical or conflicting BIP448 outgoing transfer message"
            ));
        }
        if referenced_recipients.contains(recipient_auth.as_str()) {
            continue;
        }
        let message_len = usize::try_from(message.latest_state_number)?;
        if message_len > accepted_len {
            if transfer_message_matches_record_and_history(&message, &record, &history)? {
                continue;
            }
            return Err(anyhow!("BIP448 current-sender suffix message is invalid"));
        }
        if !transfer_message_matches_record_and_history(&message, &record, accepted_history)? {
            return Err(anyhow!(
                "BIP448 outgoing message is not an exact accepted history prefix"
            ));
        }
        let owner = message
            .state_history
            .last()
            .ok_or_else(|| anyhow!("BIP448 message history is empty"))?;
        let receiver_owner = secp256k1::PublicKey::from_str(&message.receiver_user_public_key)
            .context("invalid BIP448 outgoing-message receiver user key")?
            .x_only_public_key()
            .0
            .to_string();
        if receiver_owner != owner.owner_public_key {
            return Err(anyhow!(
                "BIP448 outgoing message receiver does not own its prefix endpoint"
            ));
        }
        let local_matches = wallet
            .coins
            .iter()
            .filter(|coin| {
                coin.statechain_id.as_deref() == Some(statechain_id)
                    && coin.auth_pubkey == recipient_auth
                    && coin.user_pubkey == message.receiver_user_public_key
            })
            .count();
        if local_matches != 1 {
            return Err(anyhow!(
                "BIP448 accepted local outgoing message has no unique local Coin"
            ));
        }
        deletions.push((recipient_auth, stored_json, message));
    }
    if deletions.len() > 1 {
        return Err(anyhow!(
            "multiple BIP448 outgoing rows claim the accepted local history prefix"
        ));
    }
    let pending_signing_id = match (pending.as_ref(), deletions.first()) {
        (Some(pending), Some((_, _, message)))
            if !referenced_pending_ids.contains(pending.signing_id.as_str()) =>
        {
            if !pending_transfer_matches_message_endpoint(pending, &record, message)? {
                return Err(anyhow!(
                    "BIP448 accepted local outgoing pending/message fingerprint changed"
                ));
            }
            Some(pending.signing_id.clone())
        }
        _ => None,
    };
    for (recipient_auth, stored_json, _) in &deletions {
        let result = sqlx::query(
            "DELETE FROM bip448_transfer_messages WHERE wallet_name=$1 \
            AND statechain_id=$2 AND recipient_auth_pubkey=$3 AND transfer_msg_json=$4",
        )
        .bind(wallet_name)
        .bind(statechain_id)
        .bind(recipient_auth)
        .bind(stored_json)
        .execute(guard.connection())
        .await?;
        if result.rows_affected() != 1 {
            return Err(anyhow!("BIP448 accepted-message compare-delete lost"));
        }
    }
    if let Some(signing_id) = pending_signing_id {
        let result = sqlx::query(
            "DELETE FROM bip448_pending_transfer_signings WHERE wallet_name=$1 \
            AND statechain_id=$2 AND signing_id=$3",
        )
        .bind(wallet_name)
        .bind(statechain_id)
        .bind(signing_id)
        .execute(guard.connection())
        .await?;
        if result.rows_affected() != 1 {
            return Err(anyhow!(
                "BIP448 accepted pending-signing compare-delete lost"
            ));
        }
    }
    let count = deletions.len();
    guard.commit().await?;
    Ok(count)
}

pub async fn cleanup_bip448_cancellation_after_acceptance(
    pool: &Pool<Sqlite>,
    expected: &Bip448TransferIntent,
    transfer_msg_json: &str,
) -> Result<()> {
    if expected.intent_kind != Bip448TransferIntentKind::Cancellation
        || expected.activity_status != Bip448TransferIntentActivityStatus::Active
        || expected.phase != Bip448TransferIntentPhase::ReceiverAccepted
    {
        return Err(anyhow!("BIP448 cancellation is not ReceiverAccepted"));
    }
    let message: Bip448TransferMsg = serde_json::from_str(transfer_msg_json)?;
    if serde_json::to_string(&message)? != transfer_msg_json
        || message.statechain_id != expected.statechain_id
        || message.receiver_user_public_key != expected.receiver_user_pubkey
        || message.latest_state_number != expected.planned_state_number
        || expected.generated_coin_user_pubkey.as_deref()
            != Some(message.receiver_user_public_key.as_str())
        || expected.generated_coin_auth_pubkey.as_deref()
            != Some(expected.recipient_auth_pubkey.as_str())
    {
        return Err(anyhow!(
            "BIP448 cancellation message does not match its intent"
        ));
    }
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    let live = exact_transfer_intent_on(
        guard.connection(),
        &expected.wallet_name,
        &expected.statechain_id,
        &expected.intent_id,
    )
    .await?
    .ok_or_else(|| anyhow!("BIP448 cancellation intent is missing"))?;
    if live != *expected {
        return Err(anyhow!(
            "BIP448 cancellation intent changed before terminal cleanup"
        ));
    }
    let exact_message =
        require_bip448_cancellation_accepted_owner_on(guard.connection(), &live).await?;
    if exact_message != transfer_msg_json {
        return Err(anyhow!(
            "BIP448 cancellation terminal message bytes changed"
        ));
    }
    let (record, history) = accepted_record_and_history_on(
        guard.connection(),
        &expected.wallet_name,
        &expected.statechain_id,
    )
    .await?;
    let accepted_len = usize::try_from(record.latest_state_number)?;
    let accepted_history = history
        .get(..accepted_len)
        .ok_or_else(|| anyhow!("BIP448 accepted history prefix is missing"))?;
    if message.latest_state_number != record.latest_state_number
        || !transfer_message_matches_history_prefix(&message, accepted_history)?
    {
        return Err(anyhow!(
            "BIP448 cancellation message is not accepted history"
        ));
    }
    let pending = pending_transfer_on(
        guard.connection(),
        &expected.wallet_name,
        &expected.statechain_id,
    )
    .await?
    .ok_or_else(|| anyhow!("BIP448 cancellation pending signing is missing"))?;
    let latest = message
        .state_history
        .last()
        .ok_or_else(|| anyhow!("BIP448 cancellation message history is empty"))?;
    let metadata = &message.latest_state.signing_metadata;
    if expected.current_pending_signing_id.as_deref() != Some(pending.signing_id.as_str())
        || pending.wallet_name != expected.wallet_name
        || pending.statechain_id != expected.statechain_id
        || pending.funding_txid != record.funding_outpoint.txid
        || pending.funding_vout != record.funding_outpoint.vout
        || pending.funding_value_sats != record.funding_outpoint.value_sats
        || pending.state_locktime != latest.state_locktime
        || pending.update_template_hash != latest.update_template_hash
        || pending.settlement_template_hash != latest.settlement_template_hash
        || pending.signing_id != metadata.signing_id
        || pending.client_public_nonce != latest.client_public_nonce
        || pending.server_public_nonce.as_deref() != Some(latest.server_public_nonce.as_str())
        || pending.blinding_factor != latest.blinding_factor
    {
        return Err(anyhow!(
            "BIP448 cancellation pending/message fingerprint changed"
        ));
    }
    let raw_wallet =
        sqlx::query_scalar::<_, String>("SELECT wallet_json FROM wallet WHERE wallet_name=$1")
            .bind(&expected.wallet_name)
            .fetch_one(guard.connection())
            .await?;
    let wallet: Wallet = serde_json::from_str(&raw_wallet)?;
    let generated_matches = wallet
        .coins
        .iter()
        .filter(|coin| {
            coin.statechain_id.as_deref() == Some(expected.statechain_id.as_str())
                && Some(coin.user_pubkey.as_str()) == expected.generated_coin_user_pubkey.as_deref()
                && Some(coin.auth_pubkey.as_str()) == expected.generated_coin_auth_pubkey.as_deref()
                && Some(coin.address.as_str()) == expected.generated_coin_address.as_deref()
        })
        .count();
    if generated_matches != 1 {
        return Err(anyhow!(
            "BIP448 cancellation accepted owner Coin is not unique"
        ));
    }
    let outgoing_rows = sqlx::query(
        "SELECT recipient_auth_pubkey,transfer_msg_json FROM bip448_transfer_messages \
         WHERE wallet_name=$1 AND statechain_id=$2 ORDER BY recipient_auth_pubkey",
    )
    .bind(&expected.wallet_name)
    .bind(&expected.statechain_id)
    .fetch_all(guard.connection())
    .await?;
    if outgoing_rows.len() != 1
        || outgoing_rows[0].try_get::<String, _>(0)? != expected.recipient_auth_pubkey
        || outgoing_rows[0].try_get::<String, _>(1)? != transfer_msg_json
    {
        return Err(anyhow!(
            "BIP448 cancellation terminal cleanup requires one exact outgoing message"
        ));
    }
    let deleted_msg = sqlx::query(
        "DELETE FROM bip448_transfer_messages WHERE wallet_name=$1 \
        AND statechain_id=$2 AND recipient_auth_pubkey=$3 AND transfer_msg_json=$4",
    )
    .bind(&expected.wallet_name)
    .bind(&expected.statechain_id)
    .bind(&expected.recipient_auth_pubkey)
    .bind(transfer_msg_json)
    .execute(guard.connection())
    .await?;
    if deleted_msg.rows_affected() != 1 {
        return Err(anyhow!("BIP448 cancellation message compare-delete lost"));
    }
    let deleted_pending = sqlx::query(
        "DELETE FROM bip448_pending_transfer_signings WHERE wallet_name=$1 \
         AND statechain_id=$2 AND signing_id=$3",
    )
    .bind(&expected.wallet_name)
    .bind(&expected.statechain_id)
    .bind(&pending.signing_id)
    .execute(guard.connection())
    .await?;
    if deleted_pending.rows_affected() != 1 {
        return Err(anyhow!("BIP448 cancellation pending compare-delete lost"));
    }
    let lineage = list_bip448_transfer_intents_on(
        guard.connection(),
        &expected.wallet_name,
        &expected.statechain_id,
    )
    .await?;
    validate_bip448_transfer_intent_lineage(&lineage)?;
    let deleted_intents = sqlx::query(
        "DELETE FROM bip448_transfer_intents WHERE wallet_name=$1 AND statechain_id=$2",
    )
    .bind(&expected.wallet_name)
    .bind(&expected.statechain_id)
    .execute(guard.connection())
    .await?;
    if deleted_intents.rows_affected() != u64::try_from(lineage.len())? {
        return Err(anyhow!(
            "BIP448 cancellation lineage cleanup affected an unexpected row count"
        ));
    }
    guard.commit().await?;
    Ok(())
}

pub async fn delete_bip448_cancellation_artifacts_after_sync(
    pool: &Pool<Sqlite>,
    expected: &Bip448TransferIntent,
    transfer_msg_json: &str,
) -> Result<()> {
    cleanup_bip448_cancellation_after_acceptance(pool, expected, transfer_msg_json).await
}
