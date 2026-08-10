use std::str::FromStr;

use bitcoin::hashes::sha256;
use mercurylib::transfer::receiver::{
    GetMsgAddrResponsePayload, StatechainInfoResponsePayload, TransferReceiverError,
    TransferReceiverErrorResponsePayload, TransferReceiverPostResponsePayload,
    TransferReceiverRequestPayload, TransferUnlockRequestPayload,
};
use rocket::{http::Status, response::status, serde::json::Json, State};
use secp256k1::{schnorr::Signature, Message, PublicKey, Secp256k1};
use serde_json::{json, Value};

use crate::server::StateChainEntity;

use super::{is_batch_expired, outbound_request_timeout};

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

fn lockbox_signature_count_error_response(
    status_code: reqwest::StatusCode,
    body: String,
) -> status::Custom<Json<Value>> {
    let message = if body.is_empty() {
        format!("lockbox signature_count returned {}", status_code.as_u16())
    } else {
        format!(
            "lockbox signature_count returned {}: {}",
            status_code.as_u16(),
            body
        )
    };

    status::Custom(
        Status::InternalServerError,
        Json(json!({
            "error": "Lockbox Error",
            "message": message,
        })),
    )
}

fn parse_lockbox_signature_count(value: &str) -> Result<u64, String> {
    let response: Value = serde_json::from_str(value)
        .map_err(|err| format!("failed to parse lockbox signature_count response: {err}"))?;

    response["sig_count"]
        .as_u64()
        .ok_or_else(|| "lockbox signature_count response is missing sig_count".to_string())
}

fn parse_lockbox_keyupdate_response(
    value: &str,
) -> Result<TransferReceiverPostResponsePayload, String> {
    serde_json::from_str(value)
        .map_err(|err| format!("failed to parse lockbox keyupdate response: {err}"))
}

#[get("/info/statechain/<statechain_id>")]
pub async fn statechain_info(
    statechain_entity: &State<StateChainEntity>,
    statechain_id: &str,
) -> status::Custom<Json<Value>> {
    let enclave_public_key = crate::database::transfer_receiver::get_enclave_pubkey(
        &statechain_entity.pool,
        &statechain_id,
    )
    .await;

    if enclave_public_key.is_none() {
        return statechain_data_not_found_response();
    }

    let enclave_public_key = enclave_public_key.unwrap();

    let config = crate::server_config::ServerConfig::load();

    let enclave_index = crate::database::utils::get_enclave_index_from_database(
        &statechain_entity.pool,
        &statechain_id,
    )
    .await;

    let enclave_index = match enclave_index {
        Some(index) => index,
        None => {
            let response_body = json!({
                "message": format!("Enclave index for statechain {} ID not found.", statechain_id)
            });

            return status::Custom(Status::InternalServerError, Json(response_body));
        }
    };

    let enclave_index = enclave_index as usize;

    let lockbox_endpoint = config.enclaves.get(enclave_index).unwrap().url.clone();
    let path = "signature_count";

    let client = statechain_entity.inner().http_client.clone();
    let request = client
        .get(&format!("{}/{}/{}", lockbox_endpoint, path, statechain_id))
        .timeout(outbound_request_timeout());

    let value = match request.send().await {
        Ok(response) => {
            let response_status = response.status();
            let text = match response.text().await {
                Ok(text) => text,
                Err(err) => return internal_server_error_response(err.to_string()),
            };

            if !response_status.is_success() {
                return lockbox_signature_count_error_response(response_status, text);
            }

            text
        }
        Err(err) => {
            return internal_server_error_response(err.to_string());
        }
    };

    let num_sigs = match parse_lockbox_signature_count(value.as_str()) {
        Ok(num_sigs) => num_sigs,
        Err(message) => return internal_server_error_response(message),
    };

    let statechain_info = crate::database::transfer_receiver::get_statechain_info(
        &statechain_entity.pool,
        &statechain_id,
    )
    .await;

    let x1_pubkey =
        crate::database::transfer_receiver::get_x1pub(&statechain_entity.pool, &statechain_id)
            .await;

    let mut x1_pub: Option<String> = None;

    if x1_pubkey.is_some() {
        x1_pub = Some(x1_pubkey.unwrap().to_string());
    }

    let statechain_info_response_payload = StatechainInfoResponsePayload {
        enclave_public_key: enclave_public_key.to_string(),
        num_sigs: num_sigs as u32,
        statechain_info,
        x1_pub,
    };

    let response_body = json!(statechain_info_response_payload);

    return status::Custom(Status::Ok, Json(response_body));
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
    let signed_statechain_id = transfer_unlock_request_payload.0.auth_sig.clone();
    let auth_pub_key = transfer_unlock_request_payload.0.auth_pub_key.clone();

    let is_current_owner_signature = match crate::endpoints::utils::try_validate_signature(
        &statechain_entity.pool,
        &signed_statechain_id,
        &statechain_id,
    )
    .await
    {
        Ok(is_valid) => is_valid,
        Err(_) => {
            let response_body = json!({
                "message": "Signature does not match authentication key."
            });

            return status::Custom(Status::InternalServerError, Json(response_body));
        }
    };

    let durable_recipient_auth_key = if is_current_owner_signature {
        None
    } else {
        crate::database::transfer_receiver::get_auth_pubkey_and_x1(
            &statechain_entity.pool,
            &statechain_id,
        )
        .await
        .map(|(auth_key, _)| auth_key)
    };

    let is_authorized = match is_transfer_unlock_authorized(
        is_current_owner_signature,
        auth_pub_key.as_deref(),
        durable_recipient_auth_key.as_ref(),
        &signed_statechain_id,
        &statechain_id,
    )
    .await
    {
        Ok(is_authorized) => is_authorized,
        Err(_) => {
            let response_body = json!({
                "message": "Signature does not match authentication key."
            });

            return status::Custom(Status::InternalServerError, Json(response_body));
        }
    };

    if !is_authorized {
        let response_body = json!({
            "message": "Signature does not match authentication key."
        });

        return status::Custom(Status::Forbidden, Json(response_body));
    }

    crate::database::transfer_receiver::update_unlock_transfer(
        &statechain_entity.pool,
        is_current_owner_signature,
        &statechain_id,
    )
    .await;

    let response_body = json!({
        "message": "Success"
    });

    status::Custom(Status::Ok, Json(response_body))
}

async fn is_transfer_unlock_authorized(
    is_current_owner_signature: bool,
    _caller_auth_pub_key: Option<&str>,
    durable_recipient_auth_key: Option<&PublicKey>,
    auth_sig: &str,
    statechain_id: &str,
) -> Result<bool, crate::endpoints::utils::SignatureValidationError> {
    if is_current_owner_signature {
        return Ok(true);
    }

    let Some(durable_recipient_auth_key) = durable_recipient_auth_key else {
        return Ok(false);
    };

    crate::endpoints::utils::try_validate_signature_given_public_key(
        auth_sig,
        statechain_id,
        &durable_recipient_auth_key.to_string(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocket::tokio::runtime::Builder;
    use secp256k1::{KeyPair, SecretKey};

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future)
    }

    fn auth_material(secret_byte: u8, statechain_id: &str) -> (PublicKey, String) {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[secret_byte; 32]).unwrap();
        let keypair = KeyPair::from_seckey_slice(&secp, secret_key.as_ref()).unwrap();
        let public_key = secret_key.public_key(&secp);
        let message = Message::from_hashed_data::<sha256::Hash>(statechain_id.as_bytes());
        let signature = secp.sign_schnorr(message.as_ref(), &keypair);

        (public_key, signature.to_string())
    }

    #[test]
    fn transfer_unlock_rejects_no_key_and_invalid_signature() {
        let statechain_id = "statechain-1";
        let (durable_key, _) = auth_material(1, statechain_id);
        let (_, invalid_signature) = auth_material(2, statechain_id);

        assert!(!block_on(is_transfer_unlock_authorized(
            false,
            None,
            Some(&durable_key),
            &invalid_signature,
            statechain_id,
        ))
        .unwrap());
    }

    #[test]
    fn transfer_unlock_rejects_attacker_supplied_key() {
        let statechain_id = "statechain-1";
        let (durable_key, _) = auth_material(3, statechain_id);
        let (attacker_key, attacker_signature) = auth_material(4, statechain_id);
        let attacker_key = attacker_key.to_string();

        assert!(!block_on(is_transfer_unlock_authorized(
            false,
            Some(&attacker_key),
            Some(&durable_key),
            &attacker_signature,
            statechain_id,
        ))
        .unwrap());
    }

    #[test]
    fn transfer_unlock_authorizes_stored_recipient_key() {
        let statechain_id = "statechain-1";
        let (durable_key, recipient_signature) = auth_material(5, statechain_id);
        let supplied_key = durable_key.to_string();

        assert!(block_on(is_transfer_unlock_authorized(
            false,
            Some(&supplied_key),
            Some(&durable_key),
            &recipient_signature,
            statechain_id,
        ))
        .unwrap());
    }

    #[test]
    fn transfer_unlock_authorizes_current_owner() {
        assert!(block_on(is_transfer_unlock_authorized(
            true,
            None,
            None,
            "unused",
            "statechain-1",
        ))
        .unwrap());
    }

    #[test]
    fn parse_lockbox_signature_count_accepts_valid_json() {
        let sig_count = parse_lockbox_signature_count(r#"{"sig_count":7}"#).unwrap();

        assert_eq!(sig_count, 7);
    }

    #[test]
    fn parse_lockbox_signature_count_rejects_plain_text() {
        let err = parse_lockbox_signature_count("Signature count not found.").unwrap_err();

        assert!(err.contains("failed to parse lockbox signature_count response"));
    }

    #[test]
    fn parse_lockbox_signature_count_rejects_missing_sig_count() {
        let err = parse_lockbox_signature_count(r#"{"status":"ok"}"#).unwrap_err();

        assert_eq!(
            err,
            "lockbox signature_count response is missing sig_count".to_string()
        );
    }

    #[test]
    fn lockbox_signature_count_not_found_after_mercury_lookup_maps_to_internal_error() {
        let response = lockbox_signature_count_error_response(
            reqwest::StatusCode::NOT_FOUND,
            "Signature count not found.".to_string(),
        );

        assert_eq!(response.0, Status::InternalServerError);
        assert_eq!(response.1 .0["error"], "Lockbox Error");
        assert!(response.1 .0["message"].as_str().unwrap().contains("404"));
        assert!(response.1 .0["message"]
            .as_str()
            .unwrap()
            .contains("Signature count not found."));
    }

    #[test]
    fn only_initial_missing_mercury_row_returns_exact_not_found_envelope() {
        let initial_lookup_response = statechain_data_not_found_response();
        let lockbox_missing_response = lockbox_signature_count_error_response(
            reqwest::StatusCode::NOT_FOUND,
            "Signature count not found.".to_string(),
        );

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
        let response = parse_lockbox_keyupdate_response(r#"{"server_pubkey":"abc"}"#).unwrap();

        assert_eq!(response.server_pubkey, "abc");
    }

    #[test]
    fn parse_lockbox_keyupdate_response_rejects_plain_text() {
        let err = match parse_lockbox_keyupdate_response("keyupdate failed") {
            Ok(_) => panic!("plain text keyupdate response parsed as JSON"),
            Err(err) => err,
        };

        assert!(err.contains("failed to parse lockbox keyupdate response"));
    }
}

pub enum BatchTransferReceiveValidationResult {
    /// The statecoin batch is locked (not expired yet and not all coins are unlocked)
    StatecoinBatchLockedError(String),
    /// The batch_id sent by the user is expired
    ExpiredBatchTimeError(String),
    /// Success means there is no batch_id for the statecoin or all the coins of the batch are unlocked.
    Success,
}

pub async fn validate_batch(
    statechain_entity: &State<StateChainEntity>,
    statechain_id: &str,
) -> BatchTransferReceiveValidationResult {
    let batch_info = crate::database::transfer::get_batch_id_and_time_by_statechain_id(
        &statechain_entity.pool,
        statechain_id,
    )
    .await;

    // batch exists
    if batch_info.is_some() {
        let (batch_id, batch_time) = batch_info.unwrap();

        if is_batch_expired(batch_time) {
            // the batch time has not expired. It is possible to add a new coin to the batch.
            return BatchTransferReceiveValidationResult::ExpiredBatchTimeError(
                "Batch time has expired".to_string(),
            );
        } else {
            // batch not expired. Check if all coins are unlocked.
            let all_coins_unlocked = crate::database::transfer::is_all_coins_unlocked(
                &statechain_entity.pool,
                &batch_id,
            )
            .await;

            if all_coins_unlocked {
                return BatchTransferReceiveValidationResult::Success;
            } else {
                return BatchTransferReceiveValidationResult::StatecoinBatchLockedError(
                    "Statecoin batch is locked".to_string(),
                );
            }
        }
    }

    BatchTransferReceiveValidationResult::Success
}

#[post(
    "/transfer/receiver",
    format = "json",
    data = "<transfer_receiver_request_payload>"
)]
pub async fn transfer_receiver(
    statechain_entity: &State<StateChainEntity>,
    transfer_receiver_request_payload: Json<TransferReceiverRequestPayload>,
) -> status::Custom<Json<Value>> {
    // TODO: check if the statechain_id is within a batch and if it is, check if the batch is still open or expired.
    // If open, check all coins are unlocked. If not, return 400 error.
    // If expired, return 400 error.
    let batch_validation_result = validate_batch(
        &statechain_entity,
        &transfer_receiver_request_payload.statechain_id,
    )
    .await;

    match batch_validation_result {
        BatchTransferReceiveValidationResult::StatecoinBatchLockedError(msg) => {
            let response_body = json!(TransferReceiverErrorResponsePayload {
                code: TransferReceiverError::StatecoinBatchLockedError,
                message: msg
            });

            return status::Custom(Status::BadRequest, Json(response_body));
        }
        BatchTransferReceiveValidationResult::ExpiredBatchTimeError(msg) => {
            let response_body = json!(TransferReceiverErrorResponsePayload {
                code: TransferReceiverError::ExpiredBatchTimeError,
                message: msg
            });

            return status::Custom(Status::BadRequest, Json(response_body));
        }
        BatchTransferReceiveValidationResult::Success => {}
    }

    let auth_pubkey_x1 = crate::database::transfer_receiver::get_auth_pubkey_and_x1(
        &statechain_entity.pool,
        &transfer_receiver_request_payload.statechain_id,
    )
    .await;

    if auth_pubkey_x1.is_none() {
        let response_body = json!({
            "message": "No transfer messages found for this statechain_id"
        });

        return status::Custom(Status::NotFound, Json(response_body));
    }

    let auth_pubkey_x1 = auth_pubkey_x1.unwrap();
    let auth_pubkey = auth_pubkey_x1.0;
    let x1 = auth_pubkey_x1.1;

    let auth_pubkey = auth_pubkey.x_only_public_key().0;

    let statechain_id = transfer_receiver_request_payload.statechain_id.clone();
    let t2 = transfer_receiver_request_payload.t2.clone();
    let auth_sign = transfer_receiver_request_payload.auth_sig.clone();

    let signed_message = Signature::from_str(&auth_sign).unwrap();
    let msg = Message::from_hashed_data::<sha256::Hash>(t2.as_bytes());

    let secp = Secp256k1::new();

    if !secp
        .verify_schnorr(&signed_message, msg.as_ref(), &auth_pubkey)
        .is_ok()
    {
        let response_body = json!({
            "message": "Signature does not match authentication key."
        });

        return status::Custom(Status::InternalServerError, Json(response_body));
    }

    if crate::database::transfer_receiver::is_key_already_updated(
        &statechain_entity.pool,
        &statechain_id,
    )
    .await
    {
        let server_public_key = crate::database::transfer_receiver::get_server_public_key(
            &statechain_entity.pool,
            &statechain_id,
        )
        .await;

        if server_public_key.is_none() {
            let response_body = json!({
                "message": "Server public key not found."
            });

            return status::Custom(Status::InternalServerError, Json(response_body));
        }

        let server_public_key = server_public_key.unwrap();

        // Idempotent replay: the coin was already transferred to this owner and
        // the previous owner's signing guards were cleared transactionally
        // during that first key update (see `update_statechain`). Do NOT clear
        // guards here: a duplicate or re-synced transfer/receiver request must
        // not destroy the current owner's live signing round (their stored
        // BIP448 replay record and nonce lease).
        let response_body = json!({
            "server_pubkey": server_public_key.to_string(),
        });

        return status::Custom(Status::Ok, Json(response_body));
    }

    let x1_hex = hex::encode(x1);

    let key_update_response_payload = mercurylib::transfer::receiver::KeyUpdateResponsePayload {
        statechain_id: statechain_id.clone(),
        t2,
        x1: x1_hex,
    };

    let config = crate::server_config::ServerConfig::load();

    let enclave_index = crate::database::utils::get_enclave_index_from_database(
        &statechain_entity.pool,
        &statechain_id,
    )
    .await;

    let enclave_index = match enclave_index {
        Some(index) => index,
        None => {
            let response_body = json!({
                "message": format!("Enclave index for statechain {} ID not found.", statechain_id)
            });

            return status::Custom(Status::InternalServerError, Json(response_body));
        }
    };

    let enclave_index = enclave_index as usize;

    let lockbox_endpoint = config.enclaves.get(enclave_index).unwrap().url.clone();
    let path = "keyupdate";

    let client = statechain_entity.inner().http_client.clone();
    let request = client
        .post(&format!("{}/{}", lockbox_endpoint, path))
        .timeout(outbound_request_timeout());

    let value = match request.json(&key_update_response_payload).send().await {
        Ok(response) => {
            let response_status = response.status();
            let text = match response.text().await {
                Ok(text) => text,
                Err(err) => return internal_server_error_response(err.to_string()),
            };

            if !response_status.is_success() {
                return internal_server_error_response(format!(
                    "lockbox keyupdate returned {}: {}",
                    response_status.as_u16(),
                    text
                ));
            }

            text
        }
        Err(err) => {
            return internal_server_error_response(err.to_string());
        }
    };

    let response: TransferReceiverPostResponsePayload =
        match parse_lockbox_keyupdate_response(value.as_str()) {
            Ok(response) => response,
            Err(err) => return internal_server_error_response(err),
        };

    let mut server_pubkey_hex = response.server_pubkey.clone();

    if server_pubkey_hex.starts_with("0x") {
        server_pubkey_hex = server_pubkey_hex[2..].to_string();
    }

    let server_pubkey = PublicKey::from_str(&server_pubkey_hex).unwrap();

    crate::database::transfer_receiver::update_statechain(
        &statechain_entity.pool,
        &auth_pubkey,
        &server_pubkey,
        &statechain_id,
    )
    .await;

    let response_body = json!(TransferReceiverPostResponsePayload {
        server_pubkey: server_pubkey.to_string(),
    });

    status::Custom(Status::Ok, Json(response_body))
}
