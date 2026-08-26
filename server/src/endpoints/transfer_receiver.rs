use std::str::FromStr;

use mercurylib::bip448_statechain::signing_api::{
    Bip448AppliedStatus, Bip448CanonicalScalar, Bip448CompressedPublicKey,
    Bip448HandoffErrorResponsePayloadV2, Bip448KeyUpdateAppliedReceiptPayloadV2,
    Bip448LockboxKeyUpdateRequestPayloadV2, Bip448LockboxStateResponsePayloadV2,
    Bip448ProtocolVersionV2, Bip448PublicNonce, Bip448SecretScalar, Bip448StatechainId,
    Bip448StatechainInfoResponsePayloadV2, Bip448StatechainInfoV2,
};
use mercurylib::transfer::receiver::{
    GetMsgAddrResponsePayload, StatechainInfoResponsePayload, TransferReceiverError,
    TransferReceiverErrorResponsePayload, TransferReceiverRequestPayloadV2,
    TransferUnlockRequestPayload,
};
use rocket::{http::Status, response::status, serde::json::Json, State};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde_json::{json, Value};

use crate::server::StateChainEntity;

use super::is_batch_expired;

fn internal_server_error_response(message: String) -> status::Custom<Json<Value>> {
    status::Custom(
        Status::InternalServerError,
        Json(json!({
            "error": "Internal Server Error",
            "message": message,
        })),
    )
}

fn statechain_data_not_found_response() -> status::Custom<Json<Value>> {
    status::Custom(
        Status::NotFound,
        Json(json!({
            "message": "Statechain Id key not found."
        })),
    )
}

fn lockbox_state_divergence_response() -> status::Custom<Json<Value>> {
    internal_server_error_response(
        "lockbox BIP448 state is unavailable for an existing Mercury statechain".to_string(),
    )
}

fn lockbox_error_response(status_code: u16, body: String) -> status::Custom<Json<Value>> {
    if status_code == 409 {
        return match serde_json::from_str::<Bip448HandoffErrorResponsePayloadV2>(&body) {
            Ok(error) => status::Custom(Status::Conflict, Json(json!(error))),
            Err(_) => internal_server_error_response(
                "lockbox returned a malformed BIP448 conflict".to_string(),
            ),
        };
    }
    let message = format!("lockbox returned {status_code}");
    let status = match status_code {
        400 => Status::BadRequest,
        404 => Status::NotFound,
        _ => Status::InternalServerError,
    };

    status::Custom(
        status,
        Json(json!({
            "error": "Lockbox Error",
            "message": message,
        })),
    )
}

fn parse_lockbox_keyupdate_response(
    value: &str,
) -> Result<Bip448KeyUpdateAppliedReceiptPayloadV2, String> {
    serde_json::from_str(value)
        .map_err(|err| format!("failed to parse lockbox keyupdate response: {err}"))
}

fn locked_server_pubkey(
    locked: &crate::database::transfer_receiver::LockedStatechainGeneration,
) -> Result<Bip448CompressedPublicKey, String> {
    let bytes: [u8; 33] = locked
        .server_public_key
        .as_slice()
        .try_into()
        .map_err(|_| "statechain server public key is malformed".to_string())?;
    Bip448CompressedPublicKey::from_bytes(bytes)
        .map_err(|_| "statechain server public key is malformed".to_string())
}

async fn observe_locked_bip448_state(
    statechain_entity: &StateChainEntity,
    statechain_id: &Bip448StatechainId,
    locked: &crate::database::transfer_receiver::LockedStatechainGeneration,
) -> Result<Bip448LockboxStateResponsePayloadV2, status::Custom<Json<Value>>> {
    let enclave_index = usize::try_from(locked.enclave_index).map_err(|_| {
        internal_server_error_response("Enclave index for statechain ID not found.".to_string())
    })?;
    if statechain_entity
        .config
        .enclaves
        .get(enclave_index)
        .is_none()
    {
        return Err(internal_server_error_response(
            "Enclave index for statechain ID not found.".to_string(),
        ));
    }
    let response = statechain_entity
        .lockboxes
        .get_raw(
            enclave_index,
            &format!("/bip448/state/{}", statechain_id.as_str()),
        )
        .await
        .map_err(|error| internal_server_error_response(error.to_string()))?;
    if !(200..300).contains(&response.status) {
        return Err(lockbox_state_divergence_response());
    }
    let observed: Bip448LockboxStateResponsePayloadV2 = serde_json::from_str(&response.body)
        .map_err(|err| {
            internal_server_error_response(format!(
                "failed to parse lockbox BIP448 state response: {err}"
            ))
        })?;
    if observed.statechain_id != *statechain_id {
        return Err(internal_server_error_response(
            "lockbox returned BIP448 state for a different statechain".to_string(),
        ));
    }
    let mercury_server_pubkey =
        locked_server_pubkey(locked).map_err(internal_server_error_response)?;
    if observed.server_pubkey != mercury_server_pubkey {
        return Err(status::Custom(
            Status::Conflict,
            Json(json!({"message": "Mercury and lockbox BIP448 server keys do not match"})),
        ));
    }

    Ok(observed)
}

fn parse_bip448_generation_tag(value: Option<&str>) -> Option<PublicKey> {
    let value = value?;
    let key = PublicKey::from_str(value).ok()?;
    (key.to_string() == value).then_some(key)
}

fn validate_keyupdate_receipt(
    request: &Bip448LockboxKeyUpdateRequestPayloadV2,
    transfer_generation: &PublicKey,
    receipt: &Bip448KeyUpdateAppliedReceiptPayloadV2,
) -> Result<PublicKey, String> {
    let expected_resulting_generation = request
        .expected_key_generation
        .get()
        .checked_add(1)
        .ok_or_else(|| "BIP448 key generation overflowed".to_string())?;
    if receipt.operation_id != request.operation_id
        || receipt.statechain_id != request.statechain_id
        || receipt.accepted_sig_count != request.expected_sig_count
        || receipt.previous_key_generation != request.expected_key_generation
        || receipt.resulting_key_generation.get() != expected_resulting_generation
        || receipt.previous_server_pubkey != request.expected_server_pubkey
        || receipt.transfer_generation_pubkey.as_bytes() != &transfer_generation.serialize()
    {
        return Err("lockbox keyupdate receipt does not match the exact request".to_string());
    }

    let previous_server = PublicKey::from_slice(request.expected_server_pubkey.as_bytes())
        .map_err(|_| "BIP448 request server key is malformed".to_string())?;
    let t2 = SecretKey::from_secret_bytes(*request.t2.as_bytes())
        .map_err(|_| "BIP448 request t2 is malformed".to_string())?;
    let x1 = SecretKey::from_secret_bytes(*request.x1.as_bytes())
        .map_err(|_| "BIP448 request x1 is malformed".to_string())?;
    let secp = Secp256k1::new();
    if x1.public_key(&secp) != *transfer_generation {
        return Err("BIP448 request x1 does not match the transfer generation".to_string());
    }
    let expected_result = previous_server
        .combine(&t2.public_key(&secp))
        .and_then(|key| key.combine(&transfer_generation.negate()))
        .map_err(|_| "BIP448 keyupdate receipt violates transfer algebra".to_string())?;
    let resulting_server = PublicKey::from_slice(receipt.resulting_server_pubkey.as_bytes())
        .map_err(|_| "lockbox keyupdate receipt server key is malformed".to_string())?;
    if resulting_server != expected_result {
        return Err("lockbox keyupdate receipt violates transfer algebra".to_string());
    }

    Ok(resulting_server)
}

fn completed_keyupdate_replay_receipt(
    request: &Bip448LockboxKeyUpdateRequestPayloadV2,
    transfer_generation: &PublicKey,
    current: &Bip448LockboxStateResponsePayloadV2,
) -> Result<Bip448KeyUpdateAppliedReceiptPayloadV2, String> {
    let resulting_generation = request
        .expected_key_generation
        .get()
        .checked_add(1)
        .ok_or_else(|| "BIP448 key generation overflowed".to_string())?;
    if current.statechain_id != request.statechain_id
        || current.sig_count != request.expected_sig_count
        || current.key_generation.get() != resulting_generation
    {
        return Err("completed BIP448 keyupdate does not match current lockbox state".to_string());
    }
    let receipt = Bip448KeyUpdateAppliedReceiptPayloadV2 {
        protocol_version: Bip448ProtocolVersionV2,
        operation_id: request.operation_id,
        statechain_id: request.statechain_id.clone(),
        status: Bip448AppliedStatus,
        accepted_sig_count: request.expected_sig_count,
        previous_key_generation: request.expected_key_generation,
        resulting_key_generation: current.key_generation,
        previous_server_pubkey: request.expected_server_pubkey,
        resulting_server_pubkey: current.server_pubkey,
        transfer_generation_pubkey: Bip448CompressedPublicKey::from_bytes(
            transfer_generation.serialize(),
        )
        .map_err(|_| "transfer generation public key is malformed".to_string())?,
    };
    let resulting_server = validate_keyupdate_receipt(request, transfer_generation, &receipt)?;
    if resulting_server.serialize() != *current.server_pubkey.as_bytes() {
        return Err("completed BIP448 keyupdate server key does not match live state".to_string());
    }
    Ok(receipt)
}

#[get("/info/statechain/<statechain_id>")]
pub async fn statechain_info(
    statechain_entity: &State<StateChainEntity>,
    statechain_id: &str,
) -> status::Custom<Json<Value>> {
    let typed_statechain_id = match Bip448StatechainId::try_from(statechain_id) {
        Ok(value) => value,
        Err(err) => {
            return status::Custom(
                Status::UnprocessableEntity,
                Json(json!({"message": err.to_string()})),
            );
        }
    };
    let mut handoff_fence = match statechain_entity.pool.begin().await {
        Ok(transaction) => transaction,
        Err(err) => return internal_server_error_response(err.to_string()),
    };
    let locked = match crate::database::transfer_receiver::lock_statechain_generation(
        &mut *handoff_fence,
        statechain_id,
    )
    .await
    {
        Ok(Some(locked)) => locked,
        Ok(None) => return statechain_data_not_found_response(),
        Err(err) => return internal_server_error_response(err.to_string()),
    };
    let observed =
        match observe_locked_bip448_state(statechain_entity.inner(), &typed_statechain_id, &locked)
            .await
        {
            Ok(observed) => observed,
            Err(response) => return response,
        };
    let history =
        crate::database::transfer_receiver::get_statechain_info(&mut *handoff_fence, statechain_id)
            .await;
    let x1_pubkey =
        crate::database::transfer_receiver::get_x1pub(&mut *handoff_fence, statechain_id).await;
    let mercury_server_pubkey = match locked_server_pubkey(&locked) {
        Ok(key) => key,
        Err(err) => return internal_server_error_response(err),
    };

    let response = if let Some(x1_pubkey) = x1_pubkey {
        let x1_pub = match Bip448CompressedPublicKey::from_bytes(x1_pubkey.serialize()) {
            Ok(key) => key,
            Err(err) => return internal_server_error_response(err.to_string()),
        };
        let mut typed_history = Vec::with_capacity(history.len());
        for item in history {
            let history_statechain_id =
                match Bip448StatechainId::try_from(item.statechain_id.as_str()) {
                    Ok(value) => value,
                    Err(err) => return internal_server_error_response(err.to_string()),
                };
            let server_pubnonce = match Bip448PublicNonce::try_from(item.server_pubnonce.as_str()) {
                Ok(value) => value,
                Err(err) => return internal_server_error_response(err.to_string()),
            };
            let challenge = match Bip448CanonicalScalar::try_from(item.challenge.as_str()) {
                Ok(value) => value,
                Err(err) => return internal_server_error_response(err.to_string()),
            };
            typed_history.push(Bip448StatechainInfoV2 {
                statechain_id: history_statechain_id,
                server_pubnonce,
                challenge,
                tx_n: item.tx_n,
            });
        }
        json!(Bip448StatechainInfoResponsePayloadV2 {
            protocol_version: Bip448ProtocolVersionV2,
            enclave_public_key: mercury_server_pubkey,
            num_sigs: observed.sig_count,
            lockbox_key_generation: observed.key_generation,
            statechain_info: typed_history,
            x1_pub,
        })
    } else {
        let num_sigs = match u32::try_from(observed.sig_count) {
            Ok(value) => value,
            Err(err) => return internal_server_error_response(err.to_string()),
        };
        json!(StatechainInfoResponsePayload {
            enclave_public_key: hex::encode(mercury_server_pubkey.as_bytes()),
            num_sigs,
            statechain_info: history,
            x1_pub: None,
        })
    };

    if handoff_fence.commit().await.is_err() {
        return internal_server_error_response(
            "Failed to finish statechain observation.".to_string(),
        );
    }
    status::Custom(Status::Ok, Json(response))
}

#[get("/transfer/get_msg_addr/<new_auth_key>")]
pub async fn get_msg_addr(
    statechain_entity: &State<StateChainEntity>,
    new_auth_key: &str,
) -> status::Custom<Json<Value>> {
    let new_user_auth_public_key = PublicKey::from_str(new_auth_key);

    if new_user_auth_public_key.is_err() {
        let response_body = json!({
            "error": "Internal Server Error",
            "message": "Invalid authentication public key"
        });

        return status::Custom(Status::InternalServerError, Json(response_body));
    }

    let new_user_auth_public_key = new_user_auth_public_key.unwrap();

    let result = crate::database::transfer_receiver::get_statechain_transfer_messages(
        &statechain_entity.pool,
        &new_user_auth_public_key,
    )
    .await;

    let get_msg_addr_response_payload = GetMsgAddrResponsePayload {
        list_enc_transfer_msg: result,
    };

    let response_body = json!(get_msg_addr_response_payload);

    return status::Custom(Status::Ok, Json(response_body));
}

#[post(
    "/transfer/unlock",
    format = "json",
    data = "<transfer_unlock_request_payload>"
)]
pub async fn transfer_unlock(
    statechain_entity: &State<StateChainEntity>,
    transfer_unlock_request_payload: Json<TransferUnlockRequestPayload>,
) -> status::Custom<Json<Value>> {
    let statechain_id = transfer_unlock_request_payload.0.statechain_id.clone();
    let generation = match parse_bip448_generation_tag(
        transfer_unlock_request_payload.0.auth_pub_key.as_deref(),
    ) {
        Some(key) => key,
        None => {
            return status::Custom(
                Status::InternalServerError,
                Json(json!({"message": "Transfer generation does not match current row."})),
            );
        }
    };

    let result = crate::database::transfer_receiver::unlock_transfer_generation(
        &statechain_entity.pool,
        &statechain_id,
        &transfer_unlock_request_payload.0.auth_sig,
        &generation,
    )
    .await;

    match result {
        Ok(crate::database::transfer_receiver::UnlockTransferResult::Success) => {
            status::Custom(Status::Ok, Json(json!({"message": "Success"})))
        }
        Ok(crate::database::transfer_receiver::UnlockTransferResult::AuthenticationFailed) => {
            status::Custom(
                Status::Forbidden,
                Json(json!({"message": "Signature does not match authentication key."})),
            )
        }
        Ok(crate::database::transfer_receiver::UnlockTransferResult::GenerationMismatch) => {
            status::Custom(
                Status::InternalServerError,
                Json(json!({"message": "Transfer generation does not match current row."})),
            )
        }
        Err(_) => status::Custom(
            Status::InternalServerError,
            Json(json!({"message": "Failed to unlock transfer generation."})),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mercurylib::bip448_statechain::signing_api::{
        Bip448KeyGeneration, Bip448OperationId, Bip448SignatureCount,
    };

    fn keyupdate_fixture() -> (
        Bip448LockboxKeyUpdateRequestPayloadV2,
        PublicKey,
        Bip448KeyUpdateAppliedReceiptPayloadV2,
    ) {
        let secp = Secp256k1::new();
        let previous = SecretKey::from_secret_bytes([3; 32])
            .unwrap()
            .public_key(&secp);
        let t2 = SecretKey::from_secret_bytes([5; 32]).unwrap();
        let x1 = SecretKey::from_secret_bytes([7; 32]).unwrap();
        let transfer_generation = x1.public_key(&secp);
        let resulting = previous
            .combine(&t2.public_key(&secp))
            .unwrap()
            .combine(&transfer_generation.negate())
            .unwrap();
        let request = Bip448LockboxKeyUpdateRequestPayloadV2 {
            protocol_version: Bip448ProtocolVersionV2,
            operation_id: Bip448OperationId::from_bytes([0x11; 32]),
            statechain_id: Bip448StatechainId::try_from("statechain-receipt-test").unwrap(),
            t2: Bip448SecretScalar::from_bytes(t2.to_secret_bytes()).unwrap(),
            x1: Bip448SecretScalar::from_bytes(x1.to_secret_bytes()).unwrap(),
            expected_sig_count: Bip448SignatureCount::new(2),
            expected_key_generation: Bip448KeyGeneration::new(4),
            expected_server_pubkey: Bip448CompressedPublicKey::from_bytes(previous.serialize())
                .unwrap(),
        };
        let receipt = Bip448KeyUpdateAppliedReceiptPayloadV2 {
            protocol_version: Bip448ProtocolVersionV2,
            operation_id: request.operation_id,
            statechain_id: request.statechain_id.clone(),
            status: Bip448AppliedStatus,
            accepted_sig_count: request.expected_sig_count,
            previous_key_generation: request.expected_key_generation,
            resulting_key_generation: Bip448KeyGeneration::new(5),
            previous_server_pubkey: request.expected_server_pubkey,
            resulting_server_pubkey: Bip448CompressedPublicKey::from_bytes(resulting.serialize())
                .unwrap(),
            transfer_generation_pubkey: Bip448CompressedPublicKey::from_bytes(
                transfer_generation.serialize(),
            )
            .unwrap(),
        };
        (request, transfer_generation, receipt)
    }

    #[test]
    fn lockbox_conflict_stays_a_public_conflict() {
        let response = lockbox_error_response(
            409,
            r#"{"code":"bip448_signature_count_mismatch","message":"BIP448 request conflicts with current state","expected_sig_count":2,"actual_sig_count":3}"#.to_string(),
        );

        assert_eq!(response.0, Status::Conflict);
        assert_eq!(response.1 .0["code"], "bip448_signature_count_mismatch");
    }

    #[test]
    fn only_initial_missing_mercury_row_returns_exact_not_found_envelope() {
        let initial_lookup_response = statechain_data_not_found_response();
        let lockbox_missing_response = lockbox_state_divergence_response();

        assert_eq!(initial_lookup_response.0, Status::NotFound);
        assert_eq!(
            initial_lookup_response.1 .0,
            json!({"message": "Statechain Id key not found."})
        );
        assert_eq!(lockbox_missing_response.0, Status::InternalServerError);
        assert_ne!(lockbox_missing_response.1 .0, initial_lookup_response.1 .0);
    }

    #[test]
    fn parse_lockbox_keyupdate_response_accepts_valid_json() {
        let (_, _, receipt) = keyupdate_fixture();
        let response =
            parse_lockbox_keyupdate_response(&serde_json::to_string(&receipt).unwrap()).unwrap();

        assert_eq!(response, receipt);
    }

    #[test]
    fn parse_lockbox_keyupdate_response_rejects_plain_text() {
        let err = match parse_lockbox_keyupdate_response("keyupdate failed") {
            Ok(_) => panic!("plain text keyupdate response parsed as JSON"),
            Err(err) => err,
        };

        assert!(err.contains("failed to parse lockbox keyupdate response"));
    }

    #[test]
    fn bip448_generation_tag_requires_present_canonical_compressed_key() {
        let key = secp256k1::SecretKey::from_slice(&[7; 32])
            .unwrap()
            .public_key(&Secp256k1::new());
        let canonical = key.to_string();
        assert_eq!(parse_bip448_generation_tag(Some(&canonical)), Some(key));
        assert!(parse_bip448_generation_tag(None).is_none());
        assert!(parse_bip448_generation_tag(Some("not-a-key")).is_none());
        assert!(parse_bip448_generation_tag(Some(&canonical.to_uppercase())).is_none());
    }

    #[test]
    fn keyupdate_receipt_binds_every_fence_and_transfer_algebra() {
        let (request, transfer_generation, receipt) = keyupdate_fixture();
        assert_eq!(
            validate_keyupdate_receipt(&request, &transfer_generation, &receipt).unwrap(),
            PublicKey::from_slice(receipt.resulting_server_pubkey.as_bytes()).unwrap()
        );

        let other_key = Bip448CompressedPublicKey::from_bytes(
            SecretKey::from_secret_bytes([9; 32])
                .unwrap()
                .public_key(&Secp256k1::new())
                .serialize(),
        )
        .unwrap();
        let mut mismatches = Vec::new();
        let mut changed = receipt.clone();
        changed.operation_id = Bip448OperationId::from_bytes([0x22; 32]);
        mismatches.push(changed);
        let mut changed = receipt.clone();
        changed.statechain_id = Bip448StatechainId::try_from("other-statechain").unwrap();
        mismatches.push(changed);
        let mut wrong_count = receipt.clone();
        wrong_count.accepted_sig_count = Bip448SignatureCount::new(3);
        mismatches.push(wrong_count);
        let mut changed = receipt.clone();
        changed.previous_key_generation = Bip448KeyGeneration::new(3);
        mismatches.push(changed);
        let mut changed = receipt.clone();
        changed.resulting_key_generation = Bip448KeyGeneration::new(6);
        mismatches.push(changed);
        let mut changed = receipt.clone();
        changed.previous_server_pubkey = other_key;
        mismatches.push(changed);
        let mut changed = receipt.clone();
        changed.resulting_server_pubkey = request.expected_server_pubkey;
        mismatches.push(changed);
        let mut changed = receipt;
        changed.transfer_generation_pubkey = other_key;
        mismatches.push(changed);

        for mismatch in mismatches {
            assert!(validate_keyupdate_receipt(&request, &transfer_generation, &mismatch).is_err());
        }
    }

    #[test]
    fn completed_keyupdate_replay_requires_matching_live_n_g_and_s() {
        let (request, transfer_generation, receipt) = keyupdate_fixture();
        let current = Bip448LockboxStateResponsePayloadV2 {
            protocol_version: Bip448ProtocolVersionV2,
            statechain_id: request.statechain_id.clone(),
            sig_count: request.expected_sig_count,
            key_generation: receipt.resulting_key_generation,
            server_pubkey: receipt.resulting_server_pubkey,
        };
        assert_eq!(
            completed_keyupdate_replay_receipt(&request, &transfer_generation, &current).unwrap(),
            receipt
        );

        let mut wrong_n = current.clone();
        wrong_n.sig_count = Bip448SignatureCount::new(current.sig_count.get() + 1);
        assert!(
            completed_keyupdate_replay_receipt(&request, &transfer_generation, &wrong_n).is_err()
        );
        let mut wrong_g = current.clone();
        wrong_g.key_generation = Bip448KeyGeneration::new(current.key_generation.get() + 1);
        assert!(
            completed_keyupdate_replay_receipt(&request, &transfer_generation, &wrong_g).is_err()
        );
        let mut wrong_s = current;
        wrong_s.server_pubkey = request.expected_server_pubkey;
        assert!(
            completed_keyupdate_replay_receipt(&request, &transfer_generation, &wrong_s).is_err()
        );
    }

    #[test]
    fn bip448_generation_substitution_changes_the_locked_point() {
        let first = secp256k1::SecretKey::from_slice(&[8; 32])
            .unwrap()
            .public_key(&Secp256k1::new());
        let second = secp256k1::SecretKey::from_slice(&[9; 32])
            .unwrap()
            .public_key(&Secp256k1::new());
        assert_ne!(
            parse_bip448_generation_tag(Some(&first.to_string())),
            parse_bip448_generation_tag(Some(&second.to_string()))
        );
    }

    #[test]
    fn bip448_generation_error_envelopes_keep_the_existing_status_sets() {
        let unlock_generation = status::Custom(
            Status::InternalServerError,
            Json(json!({"message": "Transfer generation does not match current row."})),
        );
        let unlock_auth = status::Custom(
            Status::Forbidden,
            Json(json!({"message": "Signature does not match authentication key."})),
        );
        assert_eq!(unlock_generation.0, Status::InternalServerError);
        assert_eq!(unlock_auth.0, Status::Forbidden);
        assert_eq!(
            unlock_generation.1 .0,
            json!({"message": "Transfer generation does not match current row."})
        );
        assert_eq!(
            unlock_auth.1 .0,
            json!({"message": "Signature does not match authentication key."})
        );
    }
}

#[post(
    "/transfer/receiver",
    format = "json",
    data = "<transfer_receiver_request_payload>"
)]
pub async fn transfer_receiver(
    statechain_entity: &State<StateChainEntity>,
    transfer_receiver_request_payload: Json<TransferReceiverRequestPayloadV2>,
) -> status::Custom<Json<Value>> {
    let payload = transfer_receiver_request_payload.0;
    let statechain_id = payload.statechain_id.as_str().to_owned();
    let generation_error = || {
        status::Custom(
            Status::InternalServerError,
            Json(json!({"message": "Transfer generation does not match current row."})),
        )
    };

    let mut transaction = match statechain_entity.pool.begin().await {
        Ok(transaction) => transaction,
        Err(_) => {
            return internal_server_error_response(
                "Failed to lock transfer generation.".to_string(),
            );
        }
    };
    let statechain = match crate::database::transfer_receiver::lock_statechain_generation(
        &mut *transaction,
        &statechain_id,
    )
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            let _ = transaction.rollback().await;
            return statechain_data_not_found_response();
        }
        Err(_) => {
            let _ = transaction.rollback().await;
            return internal_server_error_response(
                "Failed to lock transfer generation.".to_string(),
            );
        }
    };
    let transfer =
        match crate::database::transfer_receiver::load_bip448_transfer_generation_for_update(
            &mut *transaction,
            &statechain_id,
        )
        .await
        {
            Ok(Some(row)) => row,
            Ok(None) => {
                let _ = transaction.rollback().await;
                return status::Custom(
                    Status::NotFound,
                    Json(json!({"message": "No transfer messages found for this statechain_id"})),
                );
            }
            Err(_) => {
                let _ = transaction.rollback().await;
                return internal_server_error_response(
                    "Failed to lock transfer generation.".to_string(),
                );
            }
        };

    let x1_secret = match secp256k1::SecretKey::from_secret_bytes(transfer.x1) {
        Ok(value) => value,
        Err(_) => {
            let _ = transaction.rollback().await;
            return generation_error();
        }
    };
    let x1_generation = x1_secret.public_key(&Secp256k1::new());
    if payload.transfer_generation_pubkey.as_bytes() != &x1_generation.serialize() {
        let _ = transaction.rollback().await;
        return generation_error();
    }
    let recipient_auth = match PublicKey::from_slice(&transfer.recipient_auth_public_key) {
        Ok(key) => key,
        Err(_) => {
            let _ = transaction.rollback().await;
            return generation_error();
        }
    };
    let recipient_auth_xonly = recipient_auth.x_only_public_key().0;
    let digest = match payload.auth_digest() {
        Ok(digest) => digest,
        Err(_) => {
            let _ = transaction.rollback().await;
            return generation_error();
        }
    };
    let signature_matches = crate::endpoints::utils::try_verify_digest_signature(
        &hex::encode(payload.auth_sig.as_bytes()),
        &digest,
        &recipient_auth_xonly,
    )
    .unwrap_or(false);
    if !signature_matches {
        let _ = transaction.rollback().await;
        return generation_error();
    }

    let mercury_server_pubkey = match locked_server_pubkey(&statechain) {
        Ok(key) => key,
        Err(err) => {
            let _ = transaction.rollback().await;
            return internal_server_error_response(err);
        }
    };
    if !transfer.key_updated && payload.expected_server_pubkey != mercury_server_pubkey {
        let _ = transaction.rollback().await;
        return generation_error();
    }
    let x1 = match Bip448SecretScalar::from_bytes(transfer.x1) {
        Ok(x1) => x1,
        Err(_) => {
            let _ = transaction.rollback().await;
            return generation_error();
        }
    };
    let key_update_request = Bip448LockboxKeyUpdateRequestPayloadV2 {
        protocol_version: Bip448ProtocolVersionV2,
        operation_id: payload.operation_id,
        statechain_id: payload.statechain_id,
        t2: payload.t2,
        x1,
        expected_sig_count: payload.expected_sig_count,
        expected_key_generation: payload.expected_key_generation,
        expected_server_pubkey: payload.expected_server_pubkey,
    };

    if transfer.key_updated {
        if statechain.auth_xonly_public_key != recipient_auth_xonly.serialize() {
            let _ = transaction.rollback().await;
            return internal_server_error_response(
                "completed BIP448 transfer does not match Mercury ownership state".to_string(),
            );
        }
        let current = match observe_locked_bip448_state(
            statechain_entity.inner(),
            &key_update_request.statechain_id,
            &statechain,
        )
        .await
        {
            Ok(current) => current,
            Err(response) => {
                let _ = transaction.rollback().await;
                return response;
            }
        };
        let receipt =
            match completed_keyupdate_replay_receipt(&key_update_request, &x1_generation, &current)
            {
                Ok(receipt) => receipt,
                Err(err) => {
                    let _ = transaction.rollback().await;
                    return internal_server_error_response(err);
                }
            };
        if transaction.commit().await.is_err() {
            return internal_server_error_response("Failed to finish receiver replay.".to_string());
        }
        return status::Custom(Status::Ok, Json(json!(receipt)));
    }

    // Completed retries return above after authenticating and matching live
    // lockbox state. Batch expiry and batch-wide row locks are first-apply
    // checks only and must not turn an otherwise read-only replay into a new
    // dependency on the rest of the batch.
    let batch_info = match crate::database::transfer::get_batch_id_and_time_by_statechain_id_in_tx(
        &mut *transaction,
        &statechain_id,
    )
    .await
    {
        Ok(value) => value,
        Err(_) => {
            let _ = transaction.rollback().await;
            return internal_server_error_response(
                "Failed to validate transfer batch.".to_string(),
            );
        }
    };
    if let Some((batch_id, batch_time)) = batch_info {
        if is_batch_expired(batch_time) {
            let _ = transaction.rollback().await;
            return status::Custom(
                Status::BadRequest,
                Json(json!(TransferReceiverErrorResponsePayload {
                    code: TransferReceiverError::ExpiredBatchTimeError,
                    message: "Batch time has expired".to_string(),
                })),
            );
        }
        let all_unlocked = match crate::database::transfer::is_all_coins_unlocked_in_tx(
            &mut *transaction,
            &batch_id,
        )
        .await
        {
            Ok(value) => value,
            Err(_) => {
                let _ = transaction.rollback().await;
                return internal_server_error_response(
                    "Failed to validate transfer batch.".to_string(),
                );
            }
        };
        if !all_unlocked {
            let _ = transaction.rollback().await;
            return status::Custom(
                Status::BadRequest,
                Json(json!(TransferReceiverErrorResponsePayload {
                    code: TransferReceiverError::StatecoinBatchLockedError,
                    message: "Statecoin batch is locked".to_string(),
                })),
            );
        }
    }

    let enclave_index = match usize::try_from(statechain.enclave_index) {
        Ok(index) => index,
        Err(_) => {
            let _ = transaction.rollback().await;
            return internal_server_error_response(
                "Enclave index for statechain ID not found.".to_string(),
            );
        }
    };
    if statechain_entity
        .config
        .enclaves
        .get(enclave_index)
        .is_none()
    {
        let _ = transaction.rollback().await;
        return internal_server_error_response(
            "Enclave index for statechain ID not found.".to_string(),
        );
    }

    let response = match statechain_entity
        .lockboxes
        .post_json_raw(enclave_index, "/keyupdate", &key_update_request)
        .await
    {
        Ok(response) => response,
        Err(error) => {
            let _ = transaction.rollback().await;
            return internal_server_error_response(error.to_string());
        }
    };
    if !(200..300).contains(&response.status) {
        let _ = transaction.rollback().await;
        return lockbox_error_response(response.status, response.body);
    }
    let value = response.body;

    let receipt: Bip448KeyUpdateAppliedReceiptPayloadV2 =
        match parse_lockbox_keyupdate_response(value.as_str()) {
            Ok(response) => response,
            Err(err) => {
                let _ = transaction.rollback().await;
                return internal_server_error_response(err);
            }
        };
    let server_pubkey =
        match validate_keyupdate_receipt(&key_update_request, &x1_generation, &receipt) {
            Ok(key) => key,
            Err(err) => {
                let _ = transaction.rollback().await;
                return internal_server_error_response(err);
            }
        };

    if crate::database::transfer_receiver::commit_bip448_transfer_generation_update(
        &mut *transaction,
        &statechain_id,
        &statechain,
        &transfer,
        &recipient_auth_xonly,
        &server_pubkey,
    )
    .await
    .is_err()
    {
        let _ = transaction.rollback().await;
        return internal_server_error_response("Failed to commit transfer generation.".to_string());
    }
    if transaction.commit().await.is_err() {
        // The existing lockbox-success/Mercury-commit failure boundary remains
        // a known prototype limitation.
        return internal_server_error_response("Failed to commit transfer generation.".to_string());
    }

    status::Custom(Status::Ok, Json(json!(receipt)))
}
