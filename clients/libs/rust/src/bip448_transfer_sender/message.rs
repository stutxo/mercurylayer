use super::{
    bip448_process_checkpoint, bip448_test_barrier,
    preflight::{
        ensure_local_eligibility, fresh_transfer_preflight, history_entry_matches_latest_state,
        require_duplicate_acknowledgement,
    },
    signing::{
        bip448_transfer_sign_second_artifacts, normalize_hex, sender_coin_for_intent,
        signing_metadata_from_history, transfer_artifacts, validate_pending,
        INCOMPLETE_HISTORY_ERROR, SIGNATURE_COUNT_ERROR,
    },
    Bip448TransferOptions,
};
use crate::{
    bip448_funding::{
        Bip448TransferIntent, Bip448TransferIntentKind, Bip448TransferIntentPhase,
        Bip448TransferStateSigningPhase,
    },
    bip448_owner::{
        classify_bip448_owner_relation, current_server_public_key, get_bip448_statechain_presence,
        validate_bip448_coin_local_auth, Bip448OwnerRelation, Bip448StatechainPresence,
    },
    client_config::ClientConfig,
    deposit::bip448_signature_count,
    sqlite_manager::{
        finish_bip448_cancellation_sender, finish_bip448_rotated_outgoing_transfer,
        finish_bip448_user_transfer_and_delete_intent, get_active_bip448_transfer_intent,
        get_bip448_pending_transfer_signing, get_bip448_raw_wallet_json, get_bip448_state_history,
        get_bip448_statechain, get_bip448_transfer_msg_raw_optional, get_wallet, history_entry,
        materialize_bip448_signed_transfer_intent, update_wallet, Bip448PendingDepositSigning,
    },
    transfer_receiver::bip448_transfer_receiver::expected_server_pubkey,
};
use anyhow::{anyhow, Context, Result};
use bitcoin::{
    hashes::{sha256, Hash},
    PrivateKey, Txid,
};
use mercurylib::{
    bip448_statechain::storage::*,
    transfer::{
        bip448::{
            verify_bip448_transfer_msg, Bip448StateHistoryEntry, Bip448TransferChainFacts,
            Bip448TransferMsg, BIP448_TRANSFER_MESSAGE_VERSION,
        },
        receiver::{StatechainInfo, StatechainInfoResponsePayload},
        sender::{
            bip448_transfer_update_msg_auth_digest, create_transfer_signature,
            TransferUpdateMsgRequestPayload,
        },
    },
    wallet::{Coin, CoinStatus, Wallet},
};
use secp256k1::{schnorr, KeyPair, PublicKey, Scalar, Secp256k1, SecretKey};
use std::{future::Future, str::FromStr};

pub(super) struct ValidatedPersistedTransfer {
    pub(super) wallet: Wallet,
    pub(super) record: Bip448StatechainRecord,
    pub(super) message: Bip448TransferMsg,
    pub(super) pending: Bip448PendingDepositSigning,
    pub(super) coin_index: usize,
    pub(super) x1_pub: String,
}
pub(super) async fn resume_unintended_persisted_transfer(
    client_config: &ClientConfig,
    wallet: Wallet,
    record: Bip448StatechainRecord,
    receiver_user_pubkey: PublicKey,
    recipient_auth_pubkey: PublicKey,
    transfer_msg_json: String,
    transfer_msg: Bip448TransferMsg,
) -> Result<()> {
    let statechain_id = transfer_msg.statechain_id.clone();
    let presence = get_bip448_statechain_presence(client_config, &statechain_id).await?;
    let Bip448StatechainPresence::Present(statechain_info) = &presence else {
        return Err(anyhow!(
            "BIP448 statechain is missing; persisted transfer ownership is closed or unknown"
        ));
    };
    let validated = validate_persisted_transfer_raw(
        client_config,
        &wallet.name,
        &statechain_id,
        &recipient_auth_pubkey.to_string(),
        &transfer_msg_json,
        &receiver_user_pubkey,
        None,
        statechain_info,
    )
    .await?;
    if serde_json::to_string(&validated.wallet)? != serde_json::to_string(&wallet)?
        || validated.record != record
        || validated.message != transfer_msg
    {
        return Err(anyhow!(
            "BIP448 persisted transfer storage changed during raw-first validation"
        ));
    }
    let mut wallet = validated.wallet;
    let record = validated.record;
    let transfer_msg = validated.message;
    let sender_coin_index = validated.coin_index;
    let relation = classify_bip448_owner_relation(
        &presence,
        &transfer_msg.sender_user_public_key,
        &transfer_msg.server_public_key,
        &record.aggregate_pubkey,
    )?;
    let coin_index = match relation {
        Bip448OwnerRelation::Current => {
            let preflight =
                fresh_transfer_preflight(client_config, &wallet.name, &statechain_id).await?;
            require_duplicate_acknowledgement(
                &preflight.unresolved_duplicates,
                Bip448TransferOptions {
                    acknowledge_cooperative_duplicates: false,
                    intent: Bip448TransferIntentKind::UserTransfer,
                },
            )?;
            wallet = preflight.wallet;
            if preflight.current_owner_coin_index != sender_coin_index {
                return Err(anyhow!(
                    "persisted BIP448 transfer sender does not match the current owner generation"
                ));
            }
            ensure_local_eligibility(
                record.latest_state_number,
                &wallet
                    .coins
                    .get(preflight.current_owner_coin_index)
                    .ok_or_else(|| {
                        anyhow!("selected BIP448 transfer owner index is absent from its wallet snapshot")
                    })?
                    .status,
            )?;
            preflight.current_owner_coin_index
        }
        Bip448OwnerRelation::Rotated => {
            let Bip448StatechainPresence::Present(statechain_info) = &presence else {
                unreachable!("Rotated requires a present statechain response")
            };
            let current_server = current_server_public_key(statechain_info)?;
            if current_server != expected_server_pubkey(&transfer_msg, &receiver_user_pubkey)? {
                return Err(anyhow!(
                    "BIP448 statechain rotated to an unrelated owner generation"
                ));
            }
            finish_bip448_rotated_outgoing_transfer(
                &client_config.pool,
                &wallet.name,
                &statechain_id,
                &recipient_auth_pubkey.to_string(),
                &transfer_msg_json,
                &validated.x1_pub,
                &validated.pending,
            )
            .await?;
            return Ok(());
        }
        Bip448OwnerRelation::Missing => {
            return Err(anyhow!(
                "BIP448 statechain is missing; persisted transfer ownership is closed or unknown"
            ));
        }
    };
    let coin = wallet
        .coins
        .get(coin_index)
        .ok_or_else(|| {
            anyhow!("selected BIP448 transfer owner index is absent from its wallet snapshot")
        })?
        .clone();
    let recipient_auth = recipient_auth_pubkey.to_string();
    resume_persisted_transfer(
        relation,
        || async {
            ensure_persisted_transfer_delivered(
                || {
                    verify_persisted_transfer_completed(
                        client_config,
                        &transfer_msg,
                        &receiver_user_pubkey,
                    )
                },
                || async {
                    let x1 = transfer_x1_from_message(&coin, &transfer_msg)?;
                    let encrypted = upload_transfer_msg(
                        client_config,
                        &coin,
                        &recipient_auth_pubkey,
                        &transfer_msg,
                        &x1,
                    )
                    .await?;
                    bip448_process_checkpoint("transfer_msg_uploaded");
                    Ok(encrypted)
                },
                |encrypted| async move {
                    transfer_message_is_stored(client_config, &recipient_auth, &encrypted).await
                },
            )
            .await
        },
        || finish_transfer(client_config, &mut wallet, coin_index),
    )
    .await
}

pub(super) async fn finish_if_bip448_active_message_rotated(
    client_config: &ClientConfig,
    intent: &Bip448TransferIntent,
) -> Result<bool> {
    if intent.intent_kind != Bip448TransferIntentKind::UserTransfer
        || intent.phase != Bip448TransferIntentPhase::X1Stored
        || intent.state_signing_phase != Bip448TransferStateSigningPhase::Signed
    {
        return Ok(false);
    }
    let Some((stored_recipient, raw)) = get_bip448_transfer_msg_raw_optional(
        &client_config.pool,
        &intent.wallet_name,
        &intent.statechain_id,
        Some(&intent.recipient_auth_pubkey),
    )
    .await?
    else {
        return Ok(false);
    };
    let message: Bip448TransferMsg = serde_json::from_str(&raw)?;
    if stored_recipient != intent.recipient_auth_pubkey
        || serde_json::to_string(&message)? != raw
        || message.statechain_id != intent.statechain_id
        || message.receiver_user_public_key != intent.receiver_user_pubkey
    {
        return Err(anyhow!(
            "BIP448 Active transfer message is noncanonical or changed identity"
        ));
    }
    let presence = get_bip448_statechain_presence(client_config, &intent.statechain_id).await?;
    match classify_bip448_owner_relation(
        &presence,
        &message.sender_user_public_key,
        &message.server_public_key,
        &message.aggregate_pubkey,
    )? {
        Bip448OwnerRelation::Current => Ok(false),
        Bip448OwnerRelation::Missing => Err(anyhow!(
            "BIP448 statechain is missing while finishing an Active transfer"
        )),
        Bip448OwnerRelation::Rotated => {
            let Bip448StatechainPresence::Present(statechain_info) = &presence else {
                unreachable!("Rotated requires a present statechain response")
            };
            let receiver = PublicKey::from_str(&message.receiver_user_public_key)?;
            if current_server_public_key(statechain_info)?
                != expected_server_pubkey(&message, &receiver)?
            {
                return Err(anyhow!(
                    "BIP448 Active transfer rotated to an unrelated owner generation"
                ));
            }
            let validated = validate_persisted_transfer_raw(
                client_config,
                &intent.wallet_name,
                &intent.statechain_id,
                &intent.recipient_auth_pubkey,
                &raw,
                &receiver,
                Some(intent),
                statechain_info,
            )
            .await?;
            finish_bip448_rotated_outgoing_transfer(
                &client_config.pool,
                &intent.wallet_name,
                &intent.statechain_id,
                &intent.recipient_auth_pubkey,
                &raw,
                &validated.x1_pub,
                &validated.pending,
            )
            .await?;
            Ok(true)
        }
    }
}

async fn build_materialized_bip448_transfer_message(
    client_config: &ClientConfig,
    intent: &Bip448TransferIntent,
) -> Result<(
    Wallet,
    usize,
    Coin,
    Bip448TransferMsg,
    Bip448PendingDepositSigning,
)> {
    let wallet = get_wallet(&client_config.pool, &intent.wallet_name).await?;
    let (coin_index, coin) = sender_coin_for_intent(&wallet, intent)?;
    let coin = coin.clone();
    let record = get_bip448_statechain(
        &client_config.pool,
        &intent.wallet_name,
        &intent.statechain_id,
    )
    .await?;
    let pending = get_bip448_pending_transfer_signing(
        &client_config.pool,
        &intent.wallet_name,
        &intent.statechain_id,
    )
    .await?
    .ok_or_else(|| anyhow!("BIP448 Signed transfer pending row is missing"))?;
    let receiver = PublicKey::from_str(&intent.receiver_user_pubkey)?;
    let artifacts = transfer_artifacts(
        &record,
        &receiver,
        intent.planned_state_number,
        pending.state_locktime,
    )?;
    let history = get_bip448_state_history(
        &client_config.pool,
        &intent.wallet_name,
        &intent.statechain_id,
    )
    .await?;
    let prefix_len = usize::try_from(intent.planned_state_number)?
        .checked_sub(1)
        .ok_or_else(|| anyhow!(INCOMPLETE_HISTORY_ERROR))?;
    let state_history = history
        .get(..prefix_len)
        .ok_or_else(|| anyhow!(INCOMPLETE_HISTORY_ERROR))?
        .to_vec();
    let signing_metadata = if intent.reuse_signed_state {
        let entry = history
            .get(prefix_len)
            .ok_or_else(|| anyhow!(INCOMPLETE_HISTORY_ERROR))?;
        signing_metadata_from_history(&pending, entry, intent.planned_state_number)?
    } else {
        Bip448SigningMetadata {
            role: Bip448RecoveryTemplateRole::FundingUpdate,
            signing_id: pending.signing_id.clone(),
            client_public_nonce: pending.client_public_nonce.clone(),
            server_public_nonce: pending
                .server_public_nonce
                .clone()
                .ok_or_else(|| anyhow!("BIP448 Signed transfer server nonce is missing"))?,
            blinding_factor: pending.blinding_factor.clone(),
            update_template_hash: pending.update_template_hash.clone(),
            update_signature: intent
                .update_signature
                .clone()
                .ok_or_else(|| anyhow!("BIP448 Signed transfer signature is missing"))?,
            server_signature_count: u64::from(intent.planned_state_number),
        }
    };
    let transfer_signature = create_transfer_signature(
        &intent.recipient_address,
        &record.funding_outpoint.txid,
        record.funding_outpoint.vout,
        &coin.user_privkey,
    )?;
    let x1 = intent
        .server_x1
        .as_deref()
        .ok_or_else(|| anyhow!("BIP448 transfer intent x1 is missing"))?;
    let message = build_transfer_msg(
        &record,
        &coin,
        receiver,
        x1,
        &transfer_signature,
        &artifacts,
        signing_metadata,
        state_history,
    )?;
    if intent.current_pending_signing_id.as_deref() != Some(pending.signing_id.as_str())
        || intent.update_signature.as_deref()
            != message
                .state_history
                .last()
                .map(|entry| entry.update_signature.as_str())
    {
        return Err(anyhow!(
            "BIP448 newly built Signed transfer intent/pending fingerprint changed"
        ));
    }
    validate_complete_signed_transfer_pending(&coin, &record, &receiver, &message, &pending)
        .context("BIP448 newly built Signed transfer pending row is invalid")?;
    Ok((wallet, coin_index, coin, message, pending))
}

pub(super) async fn load_or_materialize_signed_bip448_transfer_message(
    client_config: &ClientConfig,
    intent: &Bip448TransferIntent,
) -> Result<(
    Wallet,
    usize,
    Coin,
    Bip448TransferMsg,
    String,
    Bip448PendingDepositSigning,
)> {
    let stored = get_bip448_transfer_msg_raw_optional(
        &client_config.pool,
        &intent.wallet_name,
        &intent.statechain_id,
        None,
    )
    .await?;
    let signed_count = u64::from(intent.expected_signature_count)
        .checked_add(1)
        .ok_or_else(|| anyhow!(SIGNATURE_COUNT_ERROR))?;

    if let Some((stored_recipient, raw)) = stored {
        if stored_recipient != intent.recipient_auth_pubkey {
            return Err(anyhow!("BIP448 Signed transfer message recipient changed"));
        }
        let message: Bip448TransferMsg = serde_json::from_str(&raw)
            .context("failed to parse persisted BIP448 Signed transfer message")?;
        if serde_json::to_string(&message)? != raw {
            return Err(anyhow!(
                "BIP448 persisted Signed transfer message is noncanonical"
            ));
        }
        if message.statechain_id != intent.statechain_id
            || message.receiver_user_public_key != intent.receiver_user_pubkey
            || message.latest_state_number != intent.planned_state_number
        {
            return Err(anyhow!(
                "BIP448 persisted Signed transfer message changed intent identity"
            ));
        }

        let receiver = PublicKey::from_str(&intent.receiver_user_pubkey)?;
        let presence = get_bip448_statechain_presence(client_config, &intent.statechain_id).await?;
        let Bip448StatechainPresence::Present(statechain_info) = &presence else {
            return Err(anyhow!(
                "BIP448 statechain is missing while recovering a persisted Signed transfer"
            ));
        };
        let validated = validate_persisted_transfer_raw(
            client_config,
            &intent.wallet_name,
            &intent.statechain_id,
            &intent.recipient_auth_pubkey,
            &raw,
            &receiver,
            Some(intent),
            statechain_info,
        )
        .await?;
        if validated.message != message {
            return Err(anyhow!(
                "BIP448 persisted Signed transfer changed during raw-first validation"
            ));
        }
        let wallet = validated.wallet;
        let record = validated.record;
        let pending = validated.pending;
        let validated_coin_index = validated.coin_index;
        let (coin_index, coin) = sender_coin_for_intent(&wallet, intent)?;
        if coin_index != validated_coin_index {
            return Err(anyhow!(
                "BIP448 persisted Signed transfer sender Coin changed identity"
            ));
        }
        let coin = coin.clone();
        if intent.current_pending_signing_id.as_deref() != Some(pending.signing_id.as_str()) {
            return Err(anyhow!("BIP448 Signed transfer pending identity changed"));
        }
        let artifacts = transfer_artifacts(
            &record,
            &receiver,
            intent.planned_state_number,
            pending.state_locktime,
        )?;
        validate_pending(&pending, &record, &artifacts)?;
        let latest_entry = message
            .state_history
            .last()
            .ok_or_else(|| anyhow!("BIP448 persisted Signed transfer history is empty"))?;
        if latest_entry.state_locktime != pending.state_locktime
            || latest_entry.settlement_template_hash != pending.settlement_template_hash
            || intent.update_signature.as_deref() != Some(latest_entry.update_signature.as_str())
            || signing_metadata_from_history(&pending, latest_entry, intent.planned_state_number)?
                != message.latest_state.signing_metadata
        {
            return Err(anyhow!(
                "BIP448 persisted Signed transfer does not match its current signing journal"
            ));
        }
        let expected_x1 = intent
            .server_x1
            .as_deref()
            .ok_or_else(|| anyhow!("BIP448 transfer intent x1 is missing"))?;
        if transfer_x1_from_message(&coin, &message)? != expected_x1 {
            return Err(anyhow!(
                "BIP448 persisted Signed transfer x1 does not match its intent generation"
            ));
        }
        if bip448_signature_count(client_config, &intent.statechain_id).await? != signed_count {
            return Err(anyhow!(SIGNATURE_COUNT_ERROR));
        }
        bip448_test_barrier("transfer_pending_validated_before_materialization")?;
        let materialized = materialize_bip448_signed_transfer_intent(
            &client_config.pool,
            intent,
            &pending,
            &message,
        )
        .await?;
        if materialized != raw {
            return Err(anyhow!(
                "BIP448 persisted Signed transfer bytes changed during exact replay"
            ));
        }
        return Ok((wallet, coin_index, coin, message, raw, pending));
    }

    if bip448_signature_count(client_config, &intent.statechain_id).await? != signed_count {
        return Err(anyhow!(SIGNATURE_COUNT_ERROR));
    }
    let (wallet, coin_index, coin, message, pending) =
        build_materialized_bip448_transfer_message(client_config, intent).await?;
    bip448_test_barrier("transfer_pending_validated_before_materialization")?;
    let message_json =
        materialize_bip448_signed_transfer_intent(&client_config.pool, intent, &pending, &message)
            .await?;
    Ok((wallet, coin_index, coin, message, message_json, pending))
}

pub(super) async fn materialize_deliver_and_finish_bip448_intent(
    client_config: &ClientConfig,
    intent: &Bip448TransferIntent,
) -> Result<Option<Bip448TransferIntent>> {
    let (_, coin_index, coin, message, message_json, validated_pending) =
        load_or_materialize_signed_bip448_transfer_message(client_config, intent).await?;
    bip448_process_checkpoint("transfer_msg_persisted");
    let recipient_auth = PublicKey::from_str(&intent.recipient_auth_pubkey)?;
    let receiver_user = PublicKey::from_str(&intent.receiver_user_pubkey)?;
    let x1 = intent
        .server_x1
        .as_deref()
        .ok_or_else(|| anyhow!("BIP448 transfer intent x1 is missing"))?;
    ensure_persisted_transfer_delivered(
        || verify_persisted_transfer_completed(client_config, &message, &receiver_user),
        || async {
            let encrypted =
                upload_transfer_msg(client_config, &coin, &recipient_auth, &message, x1).await?;
            bip448_process_checkpoint("transfer_msg_uploaded");
            Ok(encrypted)
        },
        |encrypted| async move {
            transfer_message_is_stored(client_config, &intent.recipient_auth_pubkey, &encrypted)
                .await
        },
    )
    .await?;

    if finish_if_bip448_active_message_rotated(client_config, intent).await? {
        return Ok(None);
    }

    bip448_test_barrier("transfer_materialized_before_sender_finish")?;

    let raw_wallet = get_bip448_raw_wallet_json(&client_config.pool, &intent.wallet_name).await?;
    let mut wallet: Wallet = serde_json::from_str(&raw_wallet)?;
    let (live_coin_index, _) = sender_coin_for_intent(&wallet, intent)?;
    if live_coin_index != coin_index {
        return Err(anyhow!("BIP448 sender Coin index changed before finish"));
    }
    wallet
        .coins
        .get_mut(live_coin_index)
        .ok_or_else(|| anyhow!("BIP448 sender Coin disappeared before finish"))?
        .status = CoinStatus::IN_TRANSFER;
    let result = match intent.intent_kind {
        Bip448TransferIntentKind::UserTransfer => {
            finish_bip448_user_transfer_and_delete_intent(
                &client_config.pool,
                intent,
                &raw_wallet,
                &wallet,
                &message_json,
                &validated_pending,
            )
            .await?;
            None
        }
        Bip448TransferIntentKind::Cancellation => Some(
            finish_bip448_cancellation_sender(
                &client_config.pool,
                intent,
                &raw_wallet,
                &wallet,
                &message_json,
                &validated_pending,
            )
            .await?,
        ),
    };
    bip448_process_checkpoint("transfer_sender_finished");
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn validate_persisted_transfer_raw(
    client_config: &ClientConfig,
    wallet_name: &str,
    statechain_id: &str,
    recipient_auth_pubkey: &str,
    expected_raw: &str,
    receiver_user_pubkey: &PublicKey,
    expected_intent: Option<&Bip448TransferIntent>,
    authoritative: &StatechainInfoResponsePayload,
) -> Result<ValidatedPersistedTransfer> {
    let (stored_recipient, stored_raw) = get_bip448_transfer_msg_raw_optional(
        &client_config.pool,
        wallet_name,
        statechain_id,
        Some(recipient_auth_pubkey),
    )
    .await?
    .ok_or_else(|| anyhow!("BIP448 persisted outgoing transfer message is missing"))?;
    if stored_recipient != recipient_auth_pubkey || stored_raw != expected_raw {
        return Err(anyhow!(
            "BIP448 persisted outgoing transfer message bytes or recipient changed"
        ));
    }
    let message: Bip448TransferMsg = serde_json::from_str(&stored_raw)
        .context("failed to parse persisted BIP448 transfer message")?;
    if serde_json::to_string(&message)? != stored_raw
        || message.statechain_id != statechain_id
        || message.receiver_user_public_key != receiver_user_pubkey.to_string()
    {
        return Err(anyhow!(
            "BIP448 persisted outgoing transfer message is noncanonical or changed identity"
        ));
    }

    let raw_wallet = get_bip448_raw_wallet_json(&client_config.pool, wallet_name).await?;
    let wallet: Wallet = serde_json::from_str(&raw_wallet)
        .context("failed to parse wallet while validating persisted BIP448 transfer")?;
    if wallet.name != wallet_name || serde_json::to_string(&wallet)? != raw_wallet {
        return Err(anyhow!(
            "BIP448 persisted-transfer wallet bytes are noncanonical or changed identity"
        ));
    }
    let record = get_bip448_statechain(&client_config.pool, wallet_name, statechain_id).await?;
    let coin_index = validate_persisted_transfer_message_local(
        &client_config.pool,
        &wallet,
        &record,
        statechain_id,
        receiver_user_pubkey,
        &message,
    )
    .await?;

    let active =
        get_active_bip448_transfer_intent(&client_config.pool, wallet_name, statechain_id).await?;
    match (expected_intent, active.as_ref()) {
        (Some(expected), Some(stored)) if expected == stored => {}
        (None, None) => {}
        (Some(_), Some(_)) => {
            return Err(anyhow!(
                "BIP448 persisted transfer intent bytes changed during validation"
            ))
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err(anyhow!(
                "BIP448 persisted transfer intent presence changed during validation"
            ))
        }
    }
    if let Some(intent) = active.as_ref() {
        let message_hash = sha256::Hash::hash(stored_raw.as_bytes()).to_string();
        let direct = intent.intent_kind == Bip448TransferIntentKind::UserTransfer
            && intent.phase == Bip448TransferIntentPhase::X1Stored
            && intent.state_signing_phase == Bip448TransferStateSigningPhase::Signed
            && intent.recipient_auth_pubkey == recipient_auth_pubkey
            && intent.receiver_user_pubkey == message.receiver_user_public_key
            && intent.planned_state_number == message.latest_state_number;
        let predecessor = matches!(
            intent.phase,
            Bip448TransferIntentPhase::Prepared | Bip448TransferIntentPhase::SenderArmed
        ) && intent.state_signing_phase
            == Bip448TransferStateSigningPhase::NotStarted
            && intent.server_x1.is_none()
            && intent.prior_transfer_recipient_auth_pubkey.as_deref()
                == Some(recipient_auth_pubkey)
            && intent.prior_transfer_msg_hash.as_deref() == Some(message_hash.as_str());
        if !direct && !predecessor {
            return Err(anyhow!(
                "BIP448 persisted transfer message does not match its active journal fingerprint"
            ));
        }
    }

    let pending =
        get_bip448_pending_transfer_signing(&client_config.pool, wallet_name, statechain_id)
            .await?
            .ok_or_else(|| anyhow!("BIP448 persisted transfer pending signing is missing"))?;
    let coin = wallet
        .coins
        .get(coin_index)
        .ok_or_else(|| anyhow!("BIP448 persisted transfer sender Coin disappeared"))?;
    validate_complete_signed_transfer_pending(
        coin,
        &record,
        receiver_user_pubkey,
        &message,
        &pending,
    )
    .context("BIP448 persisted transfer pending row is invalid")?;
    if let Some(intent) = active.as_ref() {
        let message_is_direct = intent.phase == Bip448TransferIntentPhase::X1Stored
            && intent.state_signing_phase == Bip448TransferStateSigningPhase::Signed
            && intent.recipient_auth_pubkey == recipient_auth_pubkey;
        let expected_pending = if message_is_direct {
            intent.current_pending_signing_id.as_deref()
        } else {
            intent.prior_pending_signing_id.as_deref()
        };
        if expected_pending != Some(pending.signing_id.as_str()) {
            return Err(anyhow!(
                "BIP448 persisted transfer intent/pending fingerprint changed"
            ));
        }
    }
    let derived_x1 = transfer_x1_from_message(coin, &message)?;
    let derived_secret_bytes: [u8; 32] = hex::decode(&derived_x1)?
        .try_into()
        .map_err(|_| anyhow!("BIP448 persisted transfer x1 is not exactly 32 bytes"))?;
    let derived_x1_pub =
        SecretKey::from_secret_bytes(derived_secret_bytes)?.public_key(&Secp256k1::new());
    if let Some(intent) = active.as_ref().filter(|intent| {
        intent.recipient_auth_pubkey == recipient_auth_pubkey
            && intent.state_signing_phase == Bip448TransferStateSigningPhase::Signed
    }) {
        if intent.server_x1.as_deref() != Some(derived_x1.as_str()) {
            return Err(anyhow!(
                "BIP448 persisted transfer t1 does not match its active intent x1"
            ));
        }
    }
    let authoritative_x1_text = authoritative
        .x1_pub
        .as_deref()
        .ok_or_else(|| anyhow!("BIP448 persisted transfer has no authoritative x1 generation"))?;
    let authoritative_x1 = PublicKey::from_str(authoritative_x1_text)
        .context("invalid authoritative BIP448 x1 generation")?;
    if authoritative_x1.to_string() != authoritative_x1_text || authoritative_x1 != derived_x1_pub {
        return Err(anyhow!(
            "BIP448 persisted transfer t1 does not match the authoritative x1 generation"
        ));
    }

    let current_server = current_server_public_key(authoritative)?;
    let sender_server = PublicKey::from_str(&message.server_public_key)?;
    let receiver_server = expected_server_pubkey(&message, receiver_user_pubkey)?;
    if current_server != sender_server && current_server != receiver_server {
        return Err(anyhow!(
            "BIP448 persisted transfer has an unrelated authoritative owner generation"
        ));
    }
    if authoritative.num_sigs != message.latest_state_number {
        return Err(anyhow!(SIGNATURE_COUNT_ERROR));
    }
    let sender_generation_info = StatechainInfoResponsePayload {
        enclave_public_key: message.server_public_key.clone(),
        num_sigs: authoritative.num_sigs,
        statechain_info: authoritative
            .statechain_info
            .iter()
            .map(|row| StatechainInfo {
                statechain_id: row.statechain_id.clone(),
                server_pubnonce: row.server_pubnonce.clone(),
                challenge: row.challenge.clone(),
                tx_n: row.tx_n,
            })
            .collect(),
        x1_pub: Some(authoritative_x1_text.to_owned()),
    };
    let chain_facts: Bip448TransferChainFacts =
        crate::transfer_receiver::bip448_transfer_receiver::transfer_chain_facts(
            client_config,
            &message,
            *receiver_user_pubkey,
            &record.network,
        )
        .await?;
    verify_bip448_transfer_msg(&message, &sender_generation_info, &chain_facts)
        .context("persisted BIP448 transfer failed full cryptographic validation")?;

    Ok(ValidatedPersistedTransfer {
        wallet,
        record,
        message,
        pending,
        coin_index,
        x1_pub: authoritative_x1_text.to_owned(),
    })
}

async fn validate_persisted_transfer_message_local(
    pool: &sqlx::Pool<sqlx::Sqlite>,
    wallet: &Wallet,
    record: &Bip448StatechainRecord,
    statechain_id: &str,
    receiver_user_pubkey: &PublicKey,
    transfer_msg: &Bip448TransferMsg,
) -> Result<usize> {
    if transfer_msg.statechain_id != statechain_id
        || transfer_msg.receiver_user_public_key != receiver_user_pubkey.to_string()
    {
        return Err(anyhow!(
            "BIP448 persisted transfer message does not match the recipient address"
        ));
    }
    let sender_user_pubkey = PublicKey::from_str(&transfer_msg.sender_user_public_key)
        .map_err(|_| anyhow!("BIP448 persisted transfer message has an invalid sender key"))?;
    let server_pubkey = PublicKey::from_str(&transfer_msg.server_public_key)
        .map_err(|_| anyhow!("BIP448 persisted transfer message has an invalid server key"))?;
    let aggregate_pubkey = PublicKey::from_str(&transfer_msg.aggregate_pubkey)
        .map_err(|_| anyhow!("BIP448 persisted transfer message has an invalid aggregate key"))?;
    if sender_user_pubkey.to_string() != transfer_msg.sender_user_public_key
        || server_pubkey.to_string() != transfer_msg.server_public_key
        || aggregate_pubkey.to_string() != transfer_msg.aggregate_pubkey
    {
        return Err(anyhow!(
            "BIP448 persisted transfer message contains a non-canonical public key"
        ));
    }
    let max_message_state = record
        .latest_state_number
        .checked_add(2)
        .ok_or_else(|| anyhow!("BIP448 persisted transfer state number overflow"))?;
    if transfer_msg.msg_version != BIP448_TRANSFER_MESSAGE_VERSION
        || transfer_msg.aggregate_pubkey != record.aggregate_pubkey
        || transfer_msg.funding_outpoint != record.funding_outpoint
        || transfer_msg.challenge_delay != record.challenge_delay
        || transfer_msg.amount_sats != record.amount_sats
        || transfer_msg.network != record.network
        || transfer_msg.latest_state_number < record.latest_state_number
        || transfer_msg.latest_state_number > max_message_state
        || transfer_msg.latest_state_number < 2
        || transfer_msg.latest_state_number != transfer_msg.latest_state.state_number
        || transfer_msg.challenge_delay != transfer_msg.latest_state.challenge_delay
        || transfer_msg.value_schedule != transfer_msg.latest_state.value_schedule
        || transfer_msg.server_signature_count != u64::from(transfer_msg.latest_state_number)
        || transfer_msg
            .latest_state
            .signing_metadata
            .server_signature_count
            != u64::from(transfer_msg.latest_state_number)
        || !transfer_msg.latest_state.cpfp_child_templates.is_empty()
        || sender_user_pubkey.combine(&server_pubkey)? != aggregate_pubkey
    {
        return Err(anyhow!(
            "BIP448 persisted transfer message does not exactly match the accepted state and recipient"
        ));
    }
    if transfer_msg.latest_state.verify_recovery_against_keys(
        &Secp256k1::new(),
        &sender_user_pubkey,
        &server_pubkey,
    )? != aggregate_pubkey
    {
        return Err(anyhow!(
            "BIP448 persisted transfer message recovery key does not match its aggregate key"
        ));
    }

    let history = get_bip448_state_history(pool, &wallet.name, statechain_id).await?;
    if history != transfer_msg.state_history
        || history.len() != transfer_msg.latest_state_number as usize
        || history
            .iter()
            .enumerate()
            .any(|(index, entry)| entry.state_number != index as u32 + 1)
    {
        return Err(anyhow!(
            "BIP448 persisted transfer message does not exactly match local state history"
        ));
    }
    let accepted_history_index = record
        .latest_state_number
        .checked_sub(1)
        .ok_or_else(|| anyhow!("BIP448 accepted state number must be positive"))?
        as usize;
    let accepted_history = history
        .get(accepted_history_index)
        .ok_or_else(|| anyhow!("BIP448 persisted transfer history is incomplete"))?;
    let accepted_owner = if transfer_msg.latest_state_number == record.latest_state_number {
        receiver_user_pubkey.x_only_public_key().0.to_string()
    } else {
        sender_user_pubkey.x_only_public_key().0.to_string()
    };
    if accepted_history.owner_public_key != accepted_owner
        || !history_entry_matches_latest_state(accepted_history, &record.latest_state)
    {
        return Err(anyhow!(
            "BIP448 persisted transfer history does not contain the exact accepted state"
        ));
    }
    let latest_history = history
        .last()
        .ok_or_else(|| anyhow!("BIP448 persisted transfer history is empty"))?;
    if latest_history.owner_public_key != receiver_user_pubkey.x_only_public_key().0.to_string()
        || !history_entry_matches_latest_state(latest_history, &transfer_msg.latest_state)
    {
        return Err(anyhow!(
            "BIP448 persisted transfer latest state does not match its receiver history entry"
        ));
    }

    let transfer_signature = schnorr::Signature::from_str(&transfer_msg.transfer_signature)
        .map_err(|_| anyhow!("BIP448 persisted transfer signature is invalid"))?;
    let funding_txid = Txid::from_str(&transfer_msg.funding_outpoint.txid)?;
    let mut authorization = Vec::new();
    authorization.extend_from_slice(&funding_txid[..]);
    authorization.extend_from_slice(&transfer_msg.funding_outpoint.vout.to_le_bytes());
    authorization.extend_from_slice(&receiver_user_pubkey.serialize());
    let digest = sha256::Hash::hash(&authorization).to_byte_array();
    schnorr::verify(
        &transfer_signature,
        &digest,
        &sender_user_pubkey.x_only_public_key().0,
    )
    .map_err(|_| anyhow!("BIP448 persisted transfer signature is invalid"))?;

    let mut matching_coin = None;
    for (coin_index, coin) in wallet.coins.iter().enumerate().filter(|(_, coin)| {
        coin.statechain_id.as_deref() == Some(statechain_id)
            && mercurylib::bip448_statechain::deposit::is_bip448_coin(coin)
            && coin.user_pubkey == transfer_msg.sender_user_public_key
            && coin.server_pubkey.as_deref() == Some(transfer_msg.server_public_key.as_str())
    }) {
        if matching_coin.is_some() {
            return Err(anyhow!(
                "multiple wallet coins match the persisted BIP448 transfer sender generation"
            ));
        }
        if coin.aggregated_pubkey.as_deref() != Some(record.aggregate_pubkey.as_str())
            || coin.utxo_txid.as_deref() != Some(record.funding_outpoint.txid.as_str())
            || coin.utxo_vout != Some(record.funding_outpoint.vout)
            || coin.amount.map(u64::from) != Some(record.amount_sats)
        {
            return Err(anyhow!(
                "persisted BIP448 transfer sender coin does not match the accepted funding record"
            ));
        }
        let user_private = PrivateKey::from_wif(&coin.user_privkey)?;
        if user_private.inner.public_key(&Secp256k1::new()) != sender_user_pubkey {
            return Err(anyhow!(
                "persisted BIP448 transfer sender private key does not match its public key"
            ));
        }
        validate_bip448_coin_local_auth(coin, statechain_id)?;
        matching_coin = Some(coin_index);
    }
    matching_coin.ok_or_else(|| {
        anyhow!("no wallet coin exactly matches the persisted BIP448 transfer sender generation")
    })
}

async fn resume_persisted_transfer<D, DF, F, FF>(
    relation: Bip448OwnerRelation,
    deliver: D,
    finish_local: F,
) -> Result<()>
where
    D: FnOnce() -> DF,
    DF: Future<Output = Result<()>>,
    F: FnOnce() -> FF,
    FF: Future<Output = Result<()>>,
{
    match relation {
        Bip448OwnerRelation::Current => deliver().await?,
        Bip448OwnerRelation::Rotated => {}
        Bip448OwnerRelation::Missing => {
            return Err(anyhow!(
                "BIP448 statechain is missing; persisted transfer ownership is closed or unknown"
            ));
        }
    }
    finish_local().await
}

async fn ensure_persisted_transfer_delivered<C, CF, U, UF, S, SF>(
    mut verify_completed: C,
    upload: U,
    verify_stored: S,
) -> Result<()>
where
    C: FnMut() -> CF,
    CF: Future<Output = Result<bool>>,
    U: FnOnce() -> UF,
    UF: Future<Output = Result<String>>,
    S: FnOnce(String) -> SF,
    SF: Future<Output = Result<bool>>,
{
    if verify_completed().await? {
        return Ok(());
    }

    let upload_error = match upload().await {
        Ok(encrypted_transfer_msg) => {
            return if matches!(verify_stored(encrypted_transfer_msg).await, Ok(true)) {
                Ok(())
            } else {
                Err(anyhow!("transfer message was not stored"))
            }
        }
        Err(error) => error,
    };
    if verify_completed().await? {
        Ok(())
    } else {
        Err(upload_error)
    }
}
async fn transfer_message_is_stored(
    client_config: &ClientConfig,
    recipient_auth_pubkey: &str,
    encrypted_transfer_msg: &str,
) -> Result<bool> {
    let path = format!(
        "transfer/get_msg_addr/{}",
        recipient_auth_pubkey.to_string()
    );
    let client = client_config.get_reqwest_client()?;
    let request = client.get(&format!("{}/{}", client_config.statechain_entity, path));
    let value = request.send().await?.text().await?;
    let response: mercurylib::transfer::receiver::GetMsgAddrResponsePayload =
        serde_json::from_str(value.as_str())?;
    Ok(mailbox_contains_transfer_message(
        &response.list_enc_transfer_msg,
        encrypted_transfer_msg,
    ))
}
fn mailbox_contains_transfer_message(messages: &[String], encrypted_transfer_msg: &str) -> bool {
    messages
        .iter()
        .any(|message| message == encrypted_transfer_msg)
}
async fn verify_persisted_transfer_completed(
    client_config: &ClientConfig,
    transfer_msg: &Bip448TransferMsg,
    receiver_user_pubkey: &PublicKey,
) -> Result<bool> {
    let presence =
        get_bip448_statechain_presence(client_config, &transfer_msg.statechain_id).await?;
    let Bip448StatechainPresence::Present(statechain_info) = presence else {
        return Err(anyhow!(
            "BIP448 statechain is missing; persisted transfer ownership is closed or unknown"
        ));
    };
    let current_server = current_server_public_key(&statechain_info)?;
    let expected_receiver_server = expected_server_pubkey(transfer_msg, receiver_user_pubkey)?;
    if current_server == expected_receiver_server {
        return Ok(true);
    }
    let sender_server = PublicKey::from_str(&transfer_msg.server_public_key)?;
    if current_server == sender_server {
        Ok(false)
    } else {
        Err(anyhow!(
            "BIP448 statechain rotated to an unrelated owner generation"
        ))
    }
}
fn validate_complete_signed_transfer_pending(
    coin: &Coin,
    record: &Bip448StatechainRecord,
    receiver_user_pubkey: &PublicKey,
    message: &Bip448TransferMsg,
    pending: &Bip448PendingDepositSigning,
) -> Result<()> {
    crate::bip448_funding::require_canonical_txid(&pending.funding_txid)?;
    crate::bip448_funding::require_canonical_hex(&pending.update_template_hash, Some(32))?;
    crate::bip448_funding::require_canonical_hex(&pending.settlement_template_hash, Some(32))?;
    crate::bip448_funding::require_canonical_hex(&pending.signing_id, Some(32))?;
    crate::bip448_funding::require_canonical_hex(&pending.client_secret_nonce, Some(132))?;
    crate::bip448_funding::require_canonical_hex(&pending.client_public_nonce, Some(66))?;
    crate::bip448_funding::require_canonical_hex(&pending.blinding_factor, Some(32))?;
    let server_public_nonce = pending
        .server_public_nonce
        .as_deref()
        .ok_or_else(|| anyhow!("BIP448 Signed transfer server nonce is missing"))?;
    crate::bip448_funding::require_canonical_hex(server_public_nonce, Some(66))?;

    let latest = message
        .state_history
        .last()
        .ok_or_else(|| anyhow!("BIP448 Signed transfer history is empty"))?;
    let metadata = &message.latest_state.signing_metadata;
    if pending.wallet_name != record.wallet_name
        || pending.statechain_id != record.statechain_id
        || pending.funding_txid != record.funding_outpoint.txid
        || pending.funding_vout != record.funding_outpoint.vout
        || pending.funding_value_sats != record.funding_outpoint.value_sats
        || pending.state_locktime != latest.state_locktime
        || pending.update_template_hash != latest.update_template_hash
        || pending.settlement_template_hash != latest.settlement_template_hash
        || pending.signing_id != metadata.signing_id
        || pending.client_public_nonce != latest.client_public_nonce
        || server_public_nonce != latest.server_public_nonce
        || pending.blinding_factor != latest.blinding_factor
    {
        return Err(anyhow!(
            "BIP448 Signed transfer pending/message fingerprint changed"
        ));
    }
    let artifacts = transfer_artifacts(
        record,
        receiver_user_pubkey,
        message.latest_state_number,
        pending.state_locktime,
    )?;
    validate_pending(pending, record, &artifacts)?;
    bip448_transfer_sign_second_artifacts(coin, record, pending, &artifacts)
        .context("BIP448 Signed transfer pending nonce pair is invalid")?;
    if signing_metadata_from_history(pending, latest, message.latest_state_number)? != *metadata {
        return Err(anyhow!(
            "BIP448 Signed transfer metadata does not match its complete pending row"
        ));
    }
    Ok(())
}
fn build_transfer_msg(
    record: &Bip448StatechainRecord,
    coin: &Coin,
    receiver_user_pubkey: PublicKey,
    x1: &str,
    transfer_signature: &str,
    artifacts: &Bip448RecoveryArtifacts,
    signing_metadata: Bip448SigningMetadata,
    mut state_history: Vec<Bip448StateHistoryEntry>,
) -> Result<Bip448TransferMsg> {
    let secp = Secp256k1::new();
    let aggregate_pubkey = PublicKey::from_str(&record.aggregate_pubkey)?;
    let latest_state = build_funding_latest_state(
        &secp,
        &aggregate_pubkey,
        artifacts,
        signing_metadata,
        Vec::new(),
    )?;
    let x1_bytes: [u8; 32] = hex::decode(normalize_hex(x1))?
        .try_into()
        .map_err(|_| anyhow!("transfer x1 must be 32 bytes"))?;
    let t1 = PrivateKey::from_wif(&coin.user_privkey)?
        .inner
        .add_tweak(&Scalar::from_be_bytes(x1_bytes)?)?
        .to_secret_bytes();
    let server_public_key = coin
        .server_pubkey
        .clone()
        .ok_or_else(|| anyhow!("BIP448 transfer coin missing server_pubkey"))?;
    state_history.push(history_entry(
        &latest_state,
        receiver_user_pubkey.x_only_public_key().0,
    ));
    let receiver_user_public_key = receiver_user_pubkey.to_string();
    Ok(Bip448TransferMsg {
        msg_version: BIP448_TRANSFER_MESSAGE_VERSION,
        statechain_id: record.statechain_id.clone(),
        transfer_signature: transfer_signature.to_string(),
        sender_user_public_key: coin.user_pubkey.clone(),
        receiver_user_public_key,
        server_public_key,
        aggregate_pubkey: aggregate_pubkey.to_string(),
        funding_outpoint: record.funding_outpoint.clone(),
        latest_state_number: latest_state.state_number,
        challenge_delay: record.challenge_delay,
        amount_sats: record.amount_sats,
        network: record.network.clone(),
        value_schedule: latest_state.value_schedule.clone(),
        server_signature_count: latest_state.signing_metadata.server_signature_count,
        t1,
        state_history,
        latest_state,
    })
}
async fn upload_transfer_msg(
    client_config: &ClientConfig,
    coin: &Coin,
    recipient_auth_pubkey: &PublicKey,
    transfer_msg: &Bip448TransferMsg,
    x1: &str,
) -> Result<String> {
    let x1_bytes: [u8; 32] = hex::decode(normalize_hex(x1))?
        .try_into()
        .map_err(|_| anyhow!("transfer x1 must be 32 bytes"))?;
    let x1_generation = SecretKey::from_secret_bytes(x1_bytes)?.public_key(&Secp256k1::new());
    let enc_transfer_msg = transfer_msg.encrypt(recipient_auth_pubkey)?;
    let decoded_ciphertext = hex::decode(&enc_transfer_msg)?;
    let digest = bip448_transfer_update_msg_auth_digest(
        &transfer_msg.statechain_id,
        recipient_auth_pubkey,
        &x1_generation,
        &decoded_ciphertext,
    )?;
    let auth_secret = PrivateKey::from_wif(&coin.auth_privkey)?.inner;
    let auth_keypair = KeyPair::from_secret_key(&Secp256k1::new(), &auth_secret);
    let payload = TransferUpdateMsgRequestPayload {
        statechain_id: transfer_msg.statechain_id.clone(),
        auth_sig: schnorr::sign(&digest, &auth_keypair).to_string(),
        new_user_auth_key: recipient_auth_pubkey.to_string(),
        x1_pub: x1_generation.to_string(),
        enc_transfer_msg,
    };
    let response = client_config
        .get_reqwest_client()?
        .post(format!(
            "{}/transfer/update_msg",
            client_config.statechain_entity
        ))
        .json(&payload)
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(anyhow!("Failed to update transfer message"));
    }
    Ok(payload.enc_transfer_msg)
}

fn transfer_x1_from_message(coin: &Coin, transfer_msg: &Bip448TransferMsg) -> Result<String> {
    let t1 = SecretKey::from_secret_bytes(transfer_msg.t1)?;
    let sender_secret = PrivateKey::from_wif(&coin.user_privkey)?.inner;
    let x1 = t1.add_tweak(&Scalar::from(sender_secret.negate()))?;
    Ok(hex::encode(x1.to_secret_bytes()))
}

async fn finish_transfer(
    client_config: &ClientConfig,
    wallet: &mut Wallet,
    coin_index: usize,
) -> Result<()> {
    wallet
        .coins
        .get_mut(coin_index)
        .ok_or_else(|| {
            anyhow!("selected BIP448 transfer owner index is absent from its wallet snapshot")
        })?
        .status = CoinStatus::IN_TRANSFER;
    update_wallet(&client_config.pool, wallet).await
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    #[tokio::test]
    async fn verified_completion_skips_reupload() {
        let checks = Cell::new(0);
        let uploads = Cell::new(0);

        ensure_persisted_transfer_delivered(
            || {
                checks.set(checks.get() + 1);
                std::future::ready(Ok(true))
            },
            || {
                uploads.set(uploads.get() + 1);
                std::future::ready(Err(anyhow!("upload must be skipped")))
            },
            |_| std::future::ready(Err(anyhow!("storage check must be skipped"))),
        )
        .await
        .unwrap();

        assert_eq!(checks.get(), 1);
        assert_eq!(uploads.get(), 0);
    }

    #[tokio::test]
    async fn successful_upload_requires_retrievable_message() {
        ensure_persisted_transfer_delivered(
            || std::future::ready(Ok(false)),
            || std::future::ready(Ok("current ciphertext".to_string())),
            |encrypted_transfer_msg| {
                std::future::ready(Ok(encrypted_transfer_msg == "current ciphertext"))
            },
        )
        .await
        .unwrap();

        for stored in [Ok(false), Err(anyhow!("mailbox unavailable"))] {
            let error = ensure_persisted_transfer_delivered(
                || std::future::ready(Ok(false)),
                || std::future::ready(Ok("current ciphertext".to_string())),
                move |encrypted_transfer_msg| {
                    assert_eq!(encrypted_transfer_msg, "current ciphertext");
                    std::future::ready(stored)
                },
            )
            .await
            .unwrap_err();
            assert_eq!(error.to_string(), "transfer message was not stored");
        }
    }

    #[test]
    fn mailbox_must_contain_the_current_ciphertext() {
        let old_message = "old ciphertext".to_string();
        let current_message = "current ciphertext".to_string();

        assert!(!mailbox_contains_transfer_message(
            &[old_message.clone()],
            &current_message,
        ));
        assert!(mailbox_contains_transfer_message(
            &[old_message, current_message.clone()],
            &current_message,
        ));
    }

    #[tokio::test]
    async fn upload_failure_finishes_only_after_verified_completion() {
        let checks = Cell::new(0);
        ensure_persisted_transfer_delivered(
            || {
                let completed = checks.get() == 1;
                checks.set(checks.get() + 1);
                std::future::ready(Ok(completed))
            },
            || std::future::ready(Err(anyhow!("rotated authentication key"))),
            |_| std::future::ready(Err(anyhow!("storage check must be skipped"))),
        )
        .await
        .unwrap();
        assert_eq!(checks.get(), 2);

        let error = ensure_persisted_transfer_delivered(
            || std::future::ready(Ok(false)),
            || std::future::ready(Err(anyhow!("original upload error"))),
            |_| std::future::ready(Err(anyhow!("storage check must be skipped"))),
        )
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "original upload error");

        let error = ensure_persisted_transfer_delivered(
            || std::future::ready(Err(anyhow!("completion evidence unavailable"))),
            || std::future::ready(Err(anyhow!("original upload error"))),
            |_| std::future::ready(Err(anyhow!("storage check must be skipped"))),
        )
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "completion evidence unavailable");
    }

    #[tokio::test]
    async fn rotated_persisted_transfer_runs_only_local_cleanup() {
        let deliveries = Cell::new(0);
        let cleanups = Cell::new(0);
        resume_persisted_transfer(
            Bip448OwnerRelation::Rotated,
            || {
                deliveries.set(deliveries.get() + 1);
                std::future::ready(Err(anyhow!("delivery must not run")))
            },
            || {
                cleanups.set(cleanups.get() + 1);
                std::future::ready(Ok(()))
            },
        )
        .await
        .unwrap();
        assert_eq!(deliveries.get(), 0);
        assert_eq!(cleanups.get(), 1);
    }
}
