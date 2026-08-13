use super::{
    bip448_process_checkpoint,
    message::{
        load_or_materialize_signed_bip448_transfer_message,
        materialize_deliver_and_finish_bip448_intent, validate_persisted_transfer_raw,
    },
    preflight::BATCHED_PENDING_ERROR,
    signing::{
        complete_bip448_transfer_sign_second, install_bip448_intent_pending, normalize_hex,
        request_and_store_bip448_transfer_nonce, SIGNATURE_COUNT_ERROR,
    },
};
use crate::{
    bip448_funding::{
        Bip448TransferIntent, Bip448TransferIntentKind, Bip448TransferIntentPhase,
        Bip448TransferStateSigningPhase,
    },
    bip448_owner::{
        classify_bip448_owner_relation, current_server_public_key, get_bip448_statechain_presence,
        Bip448OwnerRelation, Bip448StatechainPresence,
    },
    client_config::ClientConfig,
    deposit::bip448_signature_count,
    sqlite_manager::{
        finish_bip448_rotated_outgoing_transfer, get_active_bip448_transfer_intent,
        get_bip448_transfer_msg_raw_optional,
        reactivate_bip448_transfer_intent_predecessor_after_definitive_rejection,
        store_bip448_transfer_intent_x1, transition_bip448_transfer_intent_phase,
        transition_bip448_transfer_state_signing_phase,
    },
    transfer_receiver::bip448_transfer_receiver::expected_server_pubkey,
};
use anyhow::{anyhow, Result};
use bitcoin::hashes::{sha256, Hash};
use mercurylib::transfer::{bip448::Bip448TransferMsg, sender::*};
use secp256k1::{PublicKey, SecretKey};
use std::{fmt, str::FromStr};

#[derive(Debug)]
enum GetNewX1Error {
    DefinitiveBatch(String),
    Indeterminate(anyhow::Error),
}

impl fmt::Display for GetNewX1Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DefinitiveBatch(message) => formatter.write_str(message),
            Self::Indeterminate(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for GetNewX1Error {}

async fn get_new_x1(
    client_config: &ClientConfig,
    statechain_id: &str,
    signed_statechain_id: &str,
    recipient_auth_pubkey: &str,
    batch_id: Option<String>,
) -> std::result::Result<String, GetNewX1Error> {
    let endpoint = client_config.statechain_entity.clone();
    let path = "transfer/sender";

    let client = client_config
        .get_reqwest_client()
        .map_err(GetNewX1Error::Indeterminate)?;
    let request = client.post(&format!("{}/{}", endpoint, path));

    let transfer_sender_request_payload = TransferSenderRequestPayload {
        statechain_id: statechain_id.to_string(),
        auth_sig: signed_statechain_id.to_string(),
        new_user_auth_key: recipient_auth_pubkey.to_string(),
        batch_id,
    };

    let response = request
        .json(&transfer_sender_request_payload)
        .send()
        .await
        .map_err(|error| {
            GetNewX1Error::Indeterminate(anyhow!(
                "transfer sender request failed before a response: {error}"
            ))
        })?;
    let status = response.status();
    let value = response.text().await.map_err(|error| {
        GetNewX1Error::Indeterminate(anyhow!("failed to read transfer sender response: {error}"))
    })?;
    if !status.is_success() {
        let message = serde_json::from_str::<serde_json::Value>(&value)
            .ok()
            .and_then(|value| value.get("message")?.as_str().map(str::to_owned));
        if status == reqwest::StatusCode::BAD_REQUEST
            && message.as_deref().is_some_and(|message| {
                matches!(
                    message,
                    "Statecoin batch locked (the batch time has not expired)."
                        | "Batch time has expired. Try a new batch id."
                )
            })
        {
            return Err(GetNewX1Error::DefinitiveBatch(message.ok_or_else(
                || {
                    GetNewX1Error::Indeterminate(anyhow!(
                        "missing definitive transfer sender error body"
                    ))
                },
            )?));
        }
        return Err(GetNewX1Error::Indeterminate(anyhow!(
            "status: {status}, error: {value}"
        )));
    }

    let response: TransferSenderResponsePayload =
        serde_json::from_str(&value).map_err(|error| {
            GetNewX1Error::Indeterminate(anyhow!(
                "failed to parse transfer sender response: {error}"
            ))
        })?;
    let x1_bytes: [u8; 32] = hex::decode(normalize_hex(&response.x1))
        .map_err(|error| GetNewX1Error::Indeterminate(error.into()))?
        .try_into()
        .map_err(|_| {
            GetNewX1Error::Indeterminate(anyhow!(
                "transfer sender response x1 must be exactly 32 bytes"
            ))
        })?;
    SecretKey::from_secret_bytes(x1_bytes).map_err(|_| {
        GetNewX1Error::Indeterminate(anyhow!("transfer sender response x1 is not a valid scalar"))
    })?;
    Ok(hex::encode(x1_bytes))
}

pub(super) async fn exact_active_bip448_intent(
    client_config: &ClientConfig,
    expected: &Bip448TransferIntent,
) -> Result<Bip448TransferIntent> {
    let live = get_active_bip448_transfer_intent(
        &client_config.pool,
        &expected.wallet_name,
        &expected.statechain_id,
    )
    .await?
    .ok_or_else(|| anyhow!("stale BIP448 transfer worker has no Active intent"))?;
    if live.intent_id != expected.intent_id {
        return Err(anyhow!(
            "stale BIP448 transfer worker lost its activity CAS"
        ));
    }
    Ok(live)
}

pub(super) async fn drive_bip448_transfer_intent(
    client_config: &ClientConfig,
    intent: Bip448TransferIntent,
) -> Result<Option<Bip448TransferIntent>> {
    for _ in 0..12 {
        let live = exact_active_bip448_intent(client_config, &intent).await?;
        match (live.phase, live.state_signing_phase) {
            (Bip448TransferIntentPhase::Prepared, Bip448TransferStateSigningPhase::NotStarted) => {
                if finish_if_bip448_predecessor_rotated(client_config, &live).await? {
                    return Ok(None);
                }
                transition_bip448_transfer_intent_phase(
                    &client_config.pool,
                    &live.wallet_name,
                    &live.statechain_id,
                    &live.intent_id,
                    Bip448TransferIntentPhase::Prepared,
                    Bip448TransferIntentPhase::SenderArmed,
                )
                .await?;
                bip448_process_checkpoint("transfer_sender_armed");
            }
            (
                Bip448TransferIntentPhase::SenderArmed,
                Bip448TransferStateSigningPhase::NotStarted,
            ) => {
                if finish_if_bip448_predecessor_rotated(client_config, &live).await? {
                    return Ok(None);
                }
                let x1 = match get_new_x1(
                    client_config,
                    &live.statechain_id,
                    &live.sender_signed_statechain_id,
                    &live.recipient_auth_pubkey,
                    live.batch_id.clone(),
                )
                .await
                {
                    Ok(x1) => x1,
                    Err(GetNewX1Error::DefinitiveBatch(message)) => {
                        reactivate_bip448_transfer_intent_predecessor_after_definitive_rejection(
                            &client_config.pool,
                            &live,
                        )
                        .await?;
                        return Err(if message.starts_with("Statecoin batch locked") {
                            anyhow!(BATCHED_PENDING_ERROR)
                        } else {
                            anyhow!(message)
                        });
                    }
                    Err(GetNewX1Error::Indeterminate(error)) => return Err(error),
                };
                bip448_process_checkpoint("transfer_sender_response_returned");
                store_bip448_transfer_intent_x1(
                    &client_config.pool,
                    &live.wallet_name,
                    &live.statechain_id,
                    &live.intent_id,
                    &x1,
                )
                .await?;
                bip448_process_checkpoint("transfer_x1_persisted");
            }
            (Bip448TransferIntentPhase::X1Stored, Bip448TransferStateSigningPhase::NotStarted) => {
                install_bip448_intent_pending(client_config, &live).await?;
            }
            (Bip448TransferIntentPhase::X1Stored, Bip448TransferStateSigningPhase::FirstArmed) => {
                request_and_store_bip448_transfer_nonce(client_config, &live).await?;
            }
            (Bip448TransferIntentPhase::X1Stored, Bip448TransferStateSigningPhase::NonceStored) => {
                let count = bip448_signature_count(client_config, &live.statechain_id).await?;
                if count != u64::from(live.expected_signature_count) {
                    return Err(anyhow!(SIGNATURE_COUNT_ERROR));
                }
                let signing_id = live
                    .current_pending_signing_id
                    .as_deref()
                    .ok_or_else(|| anyhow!("BIP448 transfer intent has no pending signing id"))?;
                transition_bip448_transfer_state_signing_phase(
                    &client_config.pool,
                    &live.wallet_name,
                    &live.statechain_id,
                    &live.intent_id,
                    signing_id,
                    Bip448TransferStateSigningPhase::NonceStored,
                    Bip448TransferStateSigningPhase::SecondArmed,
                )
                .await?;
                bip448_process_checkpoint("transfer_state_sign_second_armed");
            }
            (Bip448TransferIntentPhase::X1Stored, Bip448TransferStateSigningPhase::SecondArmed) => {
                complete_bip448_transfer_sign_second(client_config, &live).await?;
            }
            (Bip448TransferIntentPhase::X1Stored, Bip448TransferStateSigningPhase::Signed) => {
                return materialize_deliver_and_finish_bip448_intent(client_config, &live).await;
            }
            (
                Bip448TransferIntentPhase::SenderFinished
                | Bip448TransferIntentPhase::ReceiverAccepted,
                Bip448TransferStateSigningPhase::Signed,
            ) if live.intent_kind == Bip448TransferIntentKind::Cancellation => {
                return Ok(Some(live));
            }
            _ => return Err(anyhow!("invalid BIP448 transfer intent phase combination")),
        }
    }
    Err(anyhow!(
        "BIP448 transfer intent exceeded its bounded phase driver"
    ))
}

pub(super) async fn finish_if_bip448_predecessor_rotated(
    client_config: &ClientConfig,
    intent: &Bip448TransferIntent,
) -> Result<bool> {
    let (Some(recipient_auth), Some(expected_hash)) = (
        intent.prior_transfer_recipient_auth_pubkey.as_deref(),
        intent.prior_transfer_msg_hash.as_deref(),
    ) else {
        return Ok(false);
    };
    let (_, raw) = get_bip448_transfer_msg_raw_optional(
        &client_config.pool,
        &intent.wallet_name,
        &intent.statechain_id,
        Some(recipient_auth),
    )
    .await?
    .ok_or_else(|| anyhow!("BIP448 predecessor outgoing message is missing"))?;
    if sha256::Hash::hash(raw.as_bytes()).to_string() != expected_hash {
        return Err(anyhow!("BIP448 predecessor outgoing message bytes changed"));
    }
    let message: Bip448TransferMsg = serde_json::from_str(&raw)?;
    if serde_json::to_string(&message)? != raw {
        return Err(anyhow!(
            "BIP448 predecessor outgoing message is noncanonical"
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
            "BIP448 statechain is missing while checking predecessor rotation"
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
                    "BIP448 predecessor rotated to an unrelated owner generation"
                ));
            }
            let validated = validate_persisted_transfer_raw(
                client_config,
                &intent.wallet_name,
                &intent.statechain_id,
                recipient_auth,
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
                recipient_auth,
                &raw,
                &validated.x1_pub,
                &validated.pending,
            )
            .await?;
            Ok(true)
        }
    }
}

pub(super) async fn recover_bip448_intent_for_successor(
    client_config: &ClientConfig,
    expected: &Bip448TransferIntent,
) -> Result<()> {
    for _ in 0..8 {
        let live = exact_active_bip448_intent(client_config, expected).await?;
        match (live.phase, live.state_signing_phase) {
            (Bip448TransferIntentPhase::Prepared, Bip448TransferStateSigningPhase::NotStarted)
            | (Bip448TransferIntentPhase::X1Stored, Bip448TransferStateSigningPhase::NotStarted) => {
                return Ok(())
            }
            (
                Bip448TransferIntentPhase::SenderArmed,
                Bip448TransferStateSigningPhase::NotStarted,
            ) => {
                if finish_if_bip448_predecessor_rotated(client_config, &live).await? {
                    return Ok(());
                }
                let x1 = match get_new_x1(
                    client_config,
                    &live.statechain_id,
                    &live.sender_signed_statechain_id,
                    &live.recipient_auth_pubkey,
                    live.batch_id.clone(),
                )
                .await
                {
                    Ok(x1) => x1,
                    Err(GetNewX1Error::DefinitiveBatch(message)) => {
                        reactivate_bip448_transfer_intent_predecessor_after_definitive_rejection(
                            &client_config.pool,
                            &live,
                        )
                        .await?;
                        return Err(if message.starts_with("Statecoin batch locked") {
                            anyhow!(BATCHED_PENDING_ERROR)
                        } else {
                            anyhow!(message)
                        });
                    }
                    Err(GetNewX1Error::Indeterminate(error)) => return Err(error),
                };
                bip448_process_checkpoint("transfer_sender_response_returned");
                store_bip448_transfer_intent_x1(
                    &client_config.pool,
                    &live.wallet_name,
                    &live.statechain_id,
                    &live.intent_id,
                    &x1,
                )
                .await?;
                bip448_process_checkpoint("transfer_x1_persisted");
                return Ok(());
            }
            (Bip448TransferIntentPhase::X1Stored, Bip448TransferStateSigningPhase::FirstArmed) => {
                request_and_store_bip448_transfer_nonce(client_config, &live).await?;
            }
            (Bip448TransferIntentPhase::X1Stored, Bip448TransferStateSigningPhase::NonceStored) => {
                let count = bip448_signature_count(client_config, &live.statechain_id).await?;
                if count != u64::from(live.expected_signature_count) {
                    return Err(anyhow!(SIGNATURE_COUNT_ERROR));
                }
                let signing_id = live
                    .current_pending_signing_id
                    .as_deref()
                    .ok_or_else(|| anyhow!("BIP448 transfer intent has no pending signing id"))?;
                transition_bip448_transfer_state_signing_phase(
                    &client_config.pool,
                    &live.wallet_name,
                    &live.statechain_id,
                    &live.intent_id,
                    signing_id,
                    Bip448TransferStateSigningPhase::NonceStored,
                    Bip448TransferStateSigningPhase::SecondArmed,
                )
                .await?;
                bip448_process_checkpoint("transfer_state_sign_second_armed");
            }
            (Bip448TransferIntentPhase::X1Stored, Bip448TransferStateSigningPhase::SecondArmed) => {
                complete_bip448_transfer_sign_second(client_config, &live).await?;
            }
            (Bip448TransferIntentPhase::X1Stored, Bip448TransferStateSigningPhase::Signed) => {
                load_or_materialize_signed_bip448_transfer_message(client_config, &live).await?;
                return Ok(());
            }
            _ => {
                return Err(anyhow!(
                    "BIP448 active transfer intent is not at a recoverable retarget boundary"
                ))
            }
        }
    }
    Err(anyhow!(
        "BIP448 predecessor recovery exceeded its bounded phase driver"
    ))
}
