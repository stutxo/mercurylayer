use std::str::FromStr;

use mercurylib::transfer::receiver::{
    GetMsgAddrResponsePayload, StatechainInfoResponsePayload, TransferReceiverError,
    TransferReceiverErrorResponsePayload, TransferReceiverPostResponsePayload,
    TransferReceiverRequestPayload, TransferUnlockRequestPayload,
};
use rocket::{http::Status, response::status, serde::json::Json, State};
use secp256k1::{PublicKey, Secp256k1};
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

fn parse_bip448_generation_tag(value: Option<&str>) -> Option<PublicKey> {
    let value = value?;
    let key = PublicKey::from_str(value).ok()?;
    (key.to_string() == value).then_some(key)
}

fn parse_bip448_receiver_t2(value: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(value).ok()?;
    if bytes.len() != 32 || hex::encode(&bytes) != value {
        return None;
    }
    let bytes: [u8; 32] = bytes.try_into().ok()?;
    secp256k1::SecretKey::from_slice(&bytes).ok()?;
    Some(bytes)
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
    fn bip448_receiver_t2_requires_lowercase_valid_scalar() {
        let canonical = "ab".repeat(32);
        assert_eq!(parse_bip448_receiver_t2(&canonical), Some([0xab; 32]));
        assert!(parse_bip448_receiver_t2(&canonical.to_uppercase()).is_none());
        assert!(parse_bip448_receiver_t2(&"07".repeat(31)).is_none());
        assert!(parse_bip448_receiver_t2(&"00".repeat(32)).is_none());
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
    transfer_receiver_request_payload: Json<TransferReceiverRequestPayload>,
) -> status::Custom<Json<Value>> {
    let statechain_id = transfer_receiver_request_payload.statechain_id.clone();
    let t2 = transfer_receiver_request_payload.t2.clone();
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

    let x1_secret = match secp256k1::SecretKey::from_slice(&transfer.x1) {
        Ok(value) => value,
        Err(_) => {
            let _ = transaction.rollback().await;
            return generation_error();
        }
    };
    let x1_generation = x1_secret.public_key(&Secp256k1::new());
    let supplied_generation = match parse_bip448_generation_tag(
        transfer_receiver_request_payload.batch_data.as_deref(),
    ) {
        Some(key) if key == x1_generation => key,
        _ => {
            let _ = transaction.rollback().await;
            return generation_error();
        }
    };
    let t2_bytes = match parse_bip448_receiver_t2(&t2) {
        Some(bytes) => bytes,
        None => {
            let _ = transaction.rollback().await;
            return generation_error();
        }
    };
    let recipient_auth = match PublicKey::from_slice(&transfer.recipient_auth_public_key) {
        Ok(key) => key,
        Err(_) => {
            let _ = transaction.rollback().await;
            return generation_error();
        }
    };
    let digest = match mercurylib::transfer::receiver::bip448_transfer_receiver_auth_digest(
        &statechain_id,
        &t2_bytes,
        &supplied_generation,
    ) {
        Ok(digest) => digest,
        Err(_) => {
            let _ = transaction.rollback().await;
            return generation_error();
        }
    };
    let signature_matches = crate::endpoints::utils::try_verify_digest_signature(
        &transfer_receiver_request_payload.auth_sig,
        &digest,
        &recipient_auth.x_only_public_key().0,
    )
    .unwrap_or(false);
    if !signature_matches {
        let _ = transaction.rollback().await;
        return generation_error();
    }

    if transfer.key_updated {
        let server_public_key = match PublicKey::from_slice(&statechain.server_public_key) {
            Ok(key) => key,
            Err(_) => {
                let _ = transaction.rollback().await;
                return internal_server_error_response("Server public key not found.".to_string());
            }
        };
        if transaction.commit().await.is_err() {
            return internal_server_error_response("Failed to finish receiver replay.".to_string());
        }
        return status::Custom(
            Status::Ok,
            Json(json!(TransferReceiverPostResponsePayload {
                server_pubkey: server_public_key.to_string(),
            })),
        );
    }

    let x1_hex = hex::encode(transfer.x1);

    let key_update_response_payload = mercurylib::transfer::receiver::KeyUpdateResponsePayload {
        statechain_id: statechain_id.clone(),
        t2,
        x1: x1_hex,
    };

    let config = crate::server_config::ServerConfig::load();

    let enclave_index = match usize::try_from(statechain.enclave_index) {
        Ok(index) => index,
        Err(_) => {
            let _ = transaction.rollback().await;
            return internal_server_error_response(
                "Enclave index for statechain ID not found.".to_string(),
            );
        }
    };
    let Some(enclave) = config.enclaves.get(enclave_index) else {
        let _ = transaction.rollback().await;
        return internal_server_error_response(
            "Enclave index for statechain ID not found.".to_string(),
        );
    };
    let lockbox_endpoint = enclave.url.clone();
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
                Err(err) => {
                    let _ = transaction.rollback().await;
                    return internal_server_error_response(err.to_string());
                }
            };

            if !response_status.is_success() {
                let _ = transaction.rollback().await;
                return internal_server_error_response(format!(
                    "lockbox keyupdate returned {}: {}",
                    response_status.as_u16(),
                    text
                ));
            }

            text
        }
        Err(err) => {
            let _ = transaction.rollback().await;
            return internal_server_error_response(err.to_string());
        }
    };

    let response: TransferReceiverPostResponsePayload =
        match parse_lockbox_keyupdate_response(value.as_str()) {
            Ok(response) => response,
            Err(err) => {
                let _ = transaction.rollback().await;
                return internal_server_error_response(err);
            }
        };

    let mut server_pubkey_hex = response.server_pubkey.clone();

    if server_pubkey_hex.starts_with("0x") {
        server_pubkey_hex = server_pubkey_hex[2..].to_string();
    }

    let server_pubkey = match PublicKey::from_str(&server_pubkey_hex) {
        Ok(key) => key,
        Err(_) => {
            let _ = transaction.rollback().await;
            return internal_server_error_response(
                "Lockbox returned an invalid server public key.".to_string(),
            );
        }
    };

    if crate::database::transfer_receiver::commit_bip448_transfer_generation_update(
        &mut *transaction,
        &statechain_id,
        &statechain,
        &transfer,
        &recipient_auth.x_only_public_key().0,
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

    let response_body = json!(TransferReceiverPostResponsePayload {
        server_pubkey: server_pubkey.to_string(),
    });

    status::Custom(Status::Ok, Json(response_body))
}
