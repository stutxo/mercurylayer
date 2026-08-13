use super::{
    bip448_process_checkpoint, bip448_test_barrier,
    driver::{
        drive_bip448_transfer_intent, finish_if_bip448_predecessor_rotated,
        recover_bip448_intent_for_successor,
    },
    message::{finish_if_bip448_active_message_rotated, resume_unintended_persisted_transfer},
    preflight::{
        build_bip448_user_transfer_intent, eligibility_error, ensure_any_locally_eligible_coin,
        fresh_transfer_preflight, require_duplicate_acknowledgement,
        require_local_accepted_history_prefix,
    },
    signing::sender_coin_for_intent,
    Bip448TransferOptions,
};
use crate::{
    bip448_funding::{Bip448TransferIntentKind, Bip448TransferIntentPhase},
    client_config::ClientConfig,
    sqlite_manager::{
        get_active_bip448_transfer_intent, get_bip448_statechain_optional,
        get_bip448_transfer_msg_raw_optional, get_wallet, insert_bip448_transfer_intent_if_absent,
        supersede_bip448_transfer_intent,
    },
};
use anyhow::{anyhow, Result};
use mercurylib::{decode_transfer_address, transfer::bip448::Bip448TransferMsg, validate_address};

pub async fn transfer_bip448_sender(
    client_config: &ClientConfig,
    recipient_address: &str,
    wallet_name: &str,
    statechain_id: &str,
    batch_id: Option<String>,
) -> Result<()> {
    transfer_bip448_sender_with_options(
        client_config,
        recipient_address,
        wallet_name,
        statechain_id,
        batch_id,
        Bip448TransferOptions {
            acknowledge_cooperative_duplicates: false,
            intent: Bip448TransferIntentKind::UserTransfer,
        },
    )
    .await
}

pub async fn transfer_bip448_sender_with_options(
    client_config: &ClientConfig,
    recipient_address: &str,
    wallet_name: &str,
    statechain_id: &str,
    batch_id: Option<String>,
    options: Bip448TransferOptions,
) -> Result<()> {
    let wallet = get_wallet(&client_config.pool, wallet_name).await?;
    let record = get_bip448_statechain_optional(&client_config.pool, wallet_name, statechain_id)
        .await?
        .ok_or_else(eligibility_error)?;
    ensure_any_locally_eligible_coin(&wallet, statechain_id, record.latest_state_number)?;
    if !validate_address(recipient_address, &wallet.network)? {
        return Err(anyhow!("Invalid address"));
    }
    let (_, receiver_user_pubkey, recipient_auth_pubkey) =
        decode_transfer_address(recipient_address)?;
    let recipient_auth = recipient_auth_pubkey.to_string();

    let mut active =
        get_active_bip448_transfer_intent(&client_config.pool, wallet_name, statechain_id).await?;
    if let Some((stored_recipient, stored_json)) = get_bip448_transfer_msg_raw_optional(
        &client_config.pool,
        wallet_name,
        statechain_id,
        Some(&recipient_auth),
    )
    .await?
    {
        if stored_recipient != recipient_auth {
            return Err(anyhow!("BIP448 outgoing-message recipient changed"));
        }
        let transfer_msg: Bip448TransferMsg = serde_json::from_str(&stored_json)?;
        if serde_json::to_string(&transfer_msg)? != stored_json {
            return Err(anyhow!("BIP448 outgoing transfer message is noncanonical"));
        }
        if active.is_none() {
            return resume_unintended_persisted_transfer(
                client_config,
                wallet,
                record,
                receiver_user_pubkey,
                recipient_auth_pubkey,
                stored_json,
                transfer_msg,
            )
            .await;
        }
        if transfer_msg.receiver_user_public_key != receiver_user_pubkey.to_string() {
            return Err(anyhow!(
                "BIP448 persisted transfer message does not match the recipient address"
            ));
        }
    }

    if let Some(live) = active.as_ref() {
        if finish_if_bip448_active_message_rotated(client_config, live).await? {
            return Ok(());
        }
        if matches!(
            live.phase,
            Bip448TransferIntentPhase::Prepared | Bip448TransferIntentPhase::SenderArmed
        ) && finish_if_bip448_predecessor_rotated(client_config, live).await?
        {
            return Ok(());
        }
    }
    require_local_accepted_history_prefix(client_config, &record).await?;
    let preflight = fresh_transfer_preflight(client_config, wallet_name, statechain_id).await?;

    if let Some(existing) = active.clone() {
        let same_invocation_identity = existing.recipient_address == recipient_address
            && existing.receiver_user_pubkey == receiver_user_pubkey.to_string()
            && existing.recipient_auth_pubkey == recipient_auth
            && existing.batch_id == batch_id;
        if same_invocation_identity
            && (existing.intent_kind != options.intent
                || existing.acknowledge_cooperative_duplicates
                    != options.acknowledge_cooperative_duplicates)
        {
            return Err(anyhow!(
                "BIP448 transfer options do not match the immutable persisted intent"
            ));
        }
        require_duplicate_acknowledgement(&preflight.unresolved_duplicates, options)?;
        if same_invocation_identity {
            let (sender_coin_index, _) = sender_coin_for_intent(&preflight.wallet, &existing)?;
            if sender_coin_index != preflight.current_owner_coin_index {
                return Err(anyhow!(
                    "persisted BIP448 transfer sender is not the proven current owner generation"
                ));
            }
            drive_bip448_transfer_intent(client_config, existing).await?;
            return Ok(());
        }
        if options.intent != Bip448TransferIntentKind::UserTransfer
            || existing.intent_kind != Bip448TransferIntentKind::UserTransfer
        {
            return Err(anyhow!(
                "BIP448 cancellation must resume its exact atomically prepared intent"
            ));
        }
        recover_bip448_intent_for_successor(client_config, &existing).await?;
        active = get_active_bip448_transfer_intent(&client_config.pool, wallet_name, statechain_id)
            .await?;
    } else {
        require_duplicate_acknowledgement(&preflight.unresolved_duplicates, options)?;
        if options.intent != Bip448TransferIntentKind::UserTransfer {
            return Err(anyhow!(
                "BIP448 cancellation must be prepared with its generated Coin atomically"
            ));
        }
    }

    let intent = build_bip448_user_transfer_intent(
        client_config,
        &preflight.wallet,
        &preflight.record,
        preflight.current_owner_coin_index,
        recipient_address,
        &receiver_user_pubkey,
        &recipient_auth_pubkey,
        batch_id,
        options,
        active.as_ref(),
    )
    .await?;
    bip448_test_barrier("transfer_preflight_before_intent")?;
    let intent = match active {
        Some(predecessor) => {
            supersede_bip448_transfer_intent(&client_config.pool, &predecessor.intent_id, &intent)
                .await?
        }
        None => insert_bip448_transfer_intent_if_absent(&client_config.pool, &intent).await?,
    };
    bip448_process_checkpoint("transfer_intent_prepared");
    drive_bip448_transfer_intent(client_config, intent).await?;
    Ok(())
}
