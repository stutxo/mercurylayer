use super::{
    api::transfer_bip448_sender_with_options,
    bip448_process_checkpoint, bip448_test_barrier,
    driver::{finish_if_bip448_predecessor_rotated, recover_bip448_intent_for_successor},
    message::finish_if_bip448_active_message_rotated,
    preflight::{
        build_bip448_user_transfer_intent, fresh_transfer_preflight,
        require_duplicate_acknowledgement, BATCHED_PENDING_ERROR,
    },
    Bip448TransferOptions,
};
use crate::{
    bip448_funding::{Bip448TransferIntent, Bip448TransferIntentKind, Bip448TransferIntentPhase},
    client_config::ClientConfig,
    sqlite_manager::{
        get_active_bip448_transfer_intent, get_bip448_statechain,
        insert_bip448_cancellation_intent_with_wallet, mark_bip448_cancellation_receiver_accepted,
        supersede_bip448_transfer_intent_with_cancellation_wallet,
    },
};
use anyhow::{anyhow, Context, Result};
use mercurylib::decode_transfer_address;

async fn prepare_bip448_cancellation_intent(
    client_config: &ClientConfig,
    wallet_name: &str,
    statechain_id: &str,
    predecessor: Option<&Bip448TransferIntent>,
) -> Result<Bip448TransferIntent> {
    let options = Bip448TransferOptions {
        acknowledge_cooperative_duplicates: true,
        intent: Bip448TransferIntentKind::Cancellation,
    };
    let preflight = fresh_transfer_preflight(client_config, wallet_name, statechain_id).await?;
    require_duplicate_acknowledgement(&preflight.unresolved_duplicates, options)?;
    let generated_coin = preflight.wallet.get_new_coin()?;
    let recipient_address = generated_coin.address.clone();
    let (_, receiver_user_pubkey, recipient_auth_pubkey) =
        decode_transfer_address(&recipient_address)?;
    if receiver_user_pubkey.to_string() != generated_coin.user_pubkey
        || recipient_auth_pubkey.to_string() != generated_coin.auth_pubkey
    {
        return Err(anyhow!(
            "BIP448 cancellation generated Coin address does not match its keys"
        ));
    }
    let mut intent = build_bip448_user_transfer_intent(
        client_config,
        &preflight.wallet,
        &preflight.record,
        preflight.current_owner_coin_index,
        &recipient_address,
        &receiver_user_pubkey,
        &recipient_auth_pubkey,
        None,
        options,
        predecessor,
    )
    .await?;
    intent.generated_coin_user_pubkey = Some(generated_coin.user_pubkey.clone());
    intent.generated_coin_auth_pubkey = Some(generated_coin.auth_pubkey.clone());
    intent.generated_coin_address = Some(generated_coin.address.clone());
    let mut replacement_wallet = preflight.wallet;
    replacement_wallet.coins.push(generated_coin);
    bip448_test_barrier("cancellation_preflight_before_coin_intent")?;
    let stored = match predecessor {
        Some(predecessor) => {
            supersede_bip448_transfer_intent_with_cancellation_wallet(
                &client_config.pool,
                &predecessor.intent_id,
                &intent,
                &preflight.raw_wallet_json,
                &replacement_wallet,
            )
            .await?
        }
        None => {
            insert_bip448_cancellation_intent_with_wallet(
                &client_config.pool,
                &intent,
                &preflight.raw_wallet_json,
                &replacement_wallet,
            )
            .await?
        }
    };
    bip448_process_checkpoint("transfer_intent_prepared");
    Ok(stored)
}

pub async fn cancel_bip448_transfer(
    client_config: &ClientConfig,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<u32> {
    let mut active =
        get_active_bip448_transfer_intent(&client_config.pool, wallet_name, statechain_id).await?;
    if let Some(live) = active.as_ref() {
        let rotated = finish_if_bip448_active_message_rotated(client_config, live).await?
            || matches!(
                live.phase,
                Bip448TransferIntentPhase::Prepared | Bip448TransferIntentPhase::SenderArmed
            ) && finish_if_bip448_predecessor_rotated(client_config, live).await?;
        if rotated {
            return Ok(
                get_bip448_statechain(&client_config.pool, wallet_name, statechain_id)
                    .await?
                    .latest_state_number,
            );
        }
    }
    if active
        .as_ref()
        .is_some_and(|intent| intent.intent_kind != Bip448TransferIntentKind::Cancellation)
    {
        recover_bip448_intent_for_successor(
            client_config,
            active
                .as_ref()
                .ok_or_else(|| anyhow!("BIP448 cancellation predecessor disappeared"))?,
        )
        .await?;
        active = get_active_bip448_transfer_intent(&client_config.pool, wallet_name, statechain_id)
            .await?;
    }

    let mut cancellation = match active {
        Some(intent) if intent.intent_kind == Bip448TransferIntentKind::Cancellation => intent,
        predecessor => {
            prepare_bip448_cancellation_intent(
                client_config,
                wallet_name,
                statechain_id,
                predecessor.as_ref(),
            )
            .await?
        }
    };

    if !matches!(
        cancellation.phase,
        Bip448TransferIntentPhase::SenderFinished | Bip448TransferIntentPhase::ReceiverAccepted
    ) {
        transfer_bip448_sender_with_options(
            client_config,
            &cancellation.recipient_address,
            wallet_name,
            statechain_id,
            None,
            Bip448TransferOptions {
                acknowledge_cooperative_duplicates: true,
                intent: Bip448TransferIntentKind::Cancellation,
            },
        )
        .await?;
        let Some(live) =
            get_active_bip448_transfer_intent(&client_config.pool, wallet_name, statechain_id)
                .await?
        else {
            return Ok(
                get_bip448_statechain(&client_config.pool, wallet_name, statechain_id)
                    .await?
                    .latest_state_number,
            );
        };
        if live.intent_id != cancellation.intent_id {
            return Err(anyhow!(
                "BIP448 cancellation sender changed its active intent"
            ));
        }
        cancellation = live;
    }
    if cancellation.phase == Bip448TransferIntentPhase::SenderFinished {
        let received = match crate::transfer_receiver::execute(client_config, wallet_name).await {
            Ok(received) => received,
            Err(error)
                if error
                    .downcast_ref::<crate::transfer_receiver::Bip448PostAcceptanceSyncError>()
                    .is_some_and(|accepted| {
                        accepted
                            .accepted_statechain_ids()
                            .iter()
                            .any(|accepted_id| accepted_id == statechain_id)
                    }) =>
            {
                mark_bip448_cancellation_receiver_accepted(
                    &client_config.pool,
                    wallet_name,
                    statechain_id,
                    &cancellation.intent_id,
                )
                .await
                .context(
                    "BIP448 cancellation key update was accepted but its durable receiver proof failed",
                )?;
                return Err(error.context("BIP448 cancellation accepted; duplicate rescan pending"));
            }
            Err(error) => return Err(error),
        };
        if received.is_there_batch_locked {
            return Err(anyhow!(BATCHED_PENDING_ERROR));
        }
        match get_active_bip448_transfer_intent(&client_config.pool, wallet_name, statechain_id)
            .await?
        {
            None => {
                return Ok(
                    get_bip448_statechain(&client_config.pool, wallet_name, statechain_id)
                        .await?
                        .latest_state_number,
                );
            }
            Some(live) => {
                if live.intent_id != cancellation.intent_id {
                    return Err(anyhow!(
                        "BIP448 cancellation receiver changed its active intent"
                    ));
                }
                cancellation = mark_bip448_cancellation_receiver_accepted(
                    &client_config.pool,
                    wallet_name,
                    statechain_id,
                    &cancellation.intent_id,
                )
                .await
                .map_err(|error| {
                    if received
                        .received_statechain_ids
                        .iter()
                        .any(|id| id == statechain_id)
                    {
                        error
                            .context("BIP448 cancellation receiver accepted but local proof failed")
                    } else {
                        error.context(
                            "BIP448 transfer cancellation did not receive the replacement state",
                        )
                    }
                })?;
                bip448_process_checkpoint("transfer_receiver_accepted");
            }
        }
    }
    if cancellation.phase != Bip448TransferIntentPhase::ReceiverAccepted {
        return Err(anyhow!(
            "BIP448 cancellation did not reach ReceiverAccepted"
        ));
    }
    crate::coin_status::update_coins(client_config, wallet_name)
        .await
        .context("BIP448 cancellation accepted; duplicate rescan pending")?;
    Ok(
        get_bip448_statechain(&client_config.pool, wallet_name, statechain_id)
            .await?
            .latest_state_number,
    )
}
