use mercurylib::transaction::SignFirstRequestPayload;
use rocket::{http::Status, response::status, serde::json::Json, State};
use secp256k1::musig::Session as MusigSession;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::database::sign::{SigningProtocolClaim, LEGACY_SIGNING_PROTOCOL};
use crate::server::StateChainEntity;

fn error_response(status: Status, message: String) -> status::Custom<Json<Value>> {
    status::Custom(status, Json(json!({ "message": message })))
}

fn legacy_internal_server_error_response(message: String) -> status::Custom<Json<Value>> {
    status::Custom(
        Status::InternalServerError,
        Json(json!({
            "error": "Internal Server Error",
            "message": message,
        })),
    )
}

fn pending_nonce_response(protocol: &str) -> status::Custom<Json<Value>> {
    error_response(
        Status::Conflict,
        format!(
            "{} signing round is still incomplete for this statechain; complete sign/second before requesting another nonce",
            protocol
        ),
    )
}

fn protocol_mixing_response(
    existing_protocol: &str,
    requested_protocol: &str,
) -> status::Custom<Json<Value>> {
    error_response(
        Status::Conflict,
        format!(
            "statechain already uses {} signing; {} signing is disabled for this coin",
            existing_protocol, requested_protocol
        ),
    )
}

#[post("/sign/first", format = "json", data = "<sign_first_request_payload>")]
pub async fn sign_first(
    statechain_entity: &State<StateChainEntity>,
    sign_first_request_payload: Json<SignFirstRequestPayload>,
) -> status::Custom<Json<Value>> {
    let config = crate::server_config::ServerConfig::load();

    let statechain_id = sign_first_request_payload.0.statechain_id.clone();

    let statechain_entity = statechain_entity.inner();

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
    let path = "get_public_nonce";

    let client: reqwest::Client = reqwest::Client::new();
    let request = client.post(&format!("{}/{}", lockbox_endpoint, path));

    let signed_statechain_id = sign_first_request_payload.0.signed_statechain_id.clone();

    if !crate::endpoints::utils::validate_signature(
        &statechain_entity.pool,
        &signed_statechain_id,
        &statechain_id,
    )
    .await
    {
        let response_body = json!({
            "message": "Signature does not match authentication key."
        });

        return status::Custom(Status::Unauthorized, Json(response_body));
    }

    crate::database::sign::reclaim_stale_signing_nonce_lease(
        &statechain_entity.pool,
        &statechain_id,
    )
    .await;

    match crate::database::sign::claim_statechain_signing_protocol(
        &statechain_entity.pool,
        &statechain_id,
        LEGACY_SIGNING_PROTOCOL,
    )
    .await
    {
        SigningProtocolClaim::Claimed | SigningProtocolClaim::AlreadyMatches => {}
        SigningProtocolClaim::Conflict { existing_protocol } => {
            return protocol_mixing_response(&existing_protocol, LEGACY_SIGNING_PROTOCOL);
        }
    }

    // This situation should not happen, as this state is only possible if the client has called signFirst, but not signSecond
    // In this case, the server should have already stored server_pubnonce in the database and the challenge is still null because the client did not call signSecond
    let server_pubnonce_hex = crate::database::sign::get_server_pubnonce_from_null_challenge(
        &statechain_entity.pool,
        &statechain_id,
    )
    .await;

    if server_pubnonce_hex.is_some() {
        if let Some(protocol) =
            crate::database::sign::get_signing_nonce_lease(&statechain_entity.pool, &statechain_id)
                .await
        {
            if protocol != LEGACY_SIGNING_PROTOCOL {
                return pending_nonce_response(&protocol);
            }
        }

        let _ = crate::database::sign::insert_signing_nonce_lease(
            &statechain_entity.pool,
            &statechain_id,
            LEGACY_SIGNING_PROTOCOL,
        )
        .await;

        let response = mercurylib::transaction::SignFirstResponsePayload {
            server_pubnonce: server_pubnonce_hex.unwrap(),
        };

        let response_body = json!(response);

        return status::Custom(Status::Ok, Json(response_body));
    }

    if let Some(protocol) =
        crate::database::sign::get_signing_nonce_lease(&statechain_entity.pool, &statechain_id)
            .await
    {
        return pending_nonce_response(&protocol);
    }

    let lease_token = crate::database::sign::insert_signing_nonce_lease(
        &statechain_entity.pool,
        &statechain_id,
        LEGACY_SIGNING_PROTOCOL,
    )
    .await;

    let Some(lease_token) = lease_token else {
        let protocol =
            crate::database::sign::get_signing_nonce_lease(&statechain_entity.pool, &statechain_id)
                .await
                .unwrap_or_else(|| "unknown".to_string());

        return pending_nonce_response(&protocol);
    };

    let lease_lock = match crate::database::sign::lock_legacy_signing_nonce_lease_for_lockbox(
        &statechain_entity.pool,
        &statechain_id,
        &lease_token,
    )
    .await
    {
        Some(lease_lock) => lease_lock,
        None => return pending_nonce_response(LEGACY_SIGNING_PROTOCOL),
    };

    let value = match request.json(&sign_first_request_payload.0).send().await {
        Ok(response) => match response.text().await {
            Ok(text) => text,
            Err(err) => {
                lease_lock.rollback().await.unwrap();
                crate::database::sign::delete_signing_nonce_lease_by_token(
                    &statechain_entity.pool,
                    &statechain_id,
                    LEGACY_SIGNING_PROTOCOL,
                    &lease_token,
                )
                .await;
                return legacy_internal_server_error_response(err.to_string());
            }
        },
        Err(err) => {
            lease_lock.rollback().await.unwrap();
            crate::database::sign::delete_signing_nonce_lease_by_token(
                &statechain_entity.pool,
                &statechain_id,
                LEGACY_SIGNING_PROTOCOL,
                &lease_token,
            )
            .await;
            return legacy_internal_server_error_response(err.to_string());
        }
    };

    let response: mercurylib::transaction::SignFirstResponsePayload =
        match serde_json::from_str(value.as_str()) {
            Ok(response) => response,
            Err(err) => {
                lease_lock.rollback().await.unwrap();
                crate::database::sign::delete_signing_nonce_lease_by_token(
                    &statechain_entity.pool,
                    &statechain_id,
                    LEGACY_SIGNING_PROTOCOL,
                    &lease_token,
                )
                .await;
                return legacy_internal_server_error_response(err.to_string());
            }
        };

    let mut server_pubnonce_hex = response.server_pubnonce.clone();

    if server_pubnonce_hex.starts_with("0x") {
        server_pubnonce_hex = server_pubnonce_hex[2..].to_string();
    }

    crate::database::sign::insert_new_signature_data(
        &statechain_entity.pool,
        &server_pubnonce_hex,
        &statechain_id,
    )
    .await;

    lease_lock.commit().await.unwrap();

    let response_body = json!(response);

    return status::Custom(Status::Ok, Json(response_body));
}

#[post(
    "/sign/second",
    format = "json",
    data = "<partial_signature_request_payload>"
)]
pub async fn sign_second(
    statechain_entity: &State<StateChainEntity>,
    partial_signature_request_payload: Json<
        mercurylib::transaction::PartialSignatureRequestPayload,
    >,
) -> status::Custom<Json<Value>> {
    let statechain_id = partial_signature_request_payload.0.statechain_id.clone();

    let statechain_entity = statechain_entity.inner();

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
    let path = "get_partial_signature";

    let client: reqwest::Client = reqwest::Client::new();
    let request = client.post(&format!("{}/{}", lockbox_endpoint, path));

    let signed_statechain_id = partial_signature_request_payload
        .0
        .signed_statechain_id
        .clone();

    if !crate::endpoints::utils::validate_signature(
        &statechain_entity.pool,
        &signed_statechain_id,
        &statechain_id,
    )
    .await
    {
        let response_body = json!({
            "message": "Signature does not match authentication key."
        });

        return status::Custom(Status::Unauthorized, Json(response_body));
    }

    match crate::database::sign::claim_statechain_signing_protocol(
        &statechain_entity.pool,
        &statechain_id,
        LEGACY_SIGNING_PROTOCOL,
    )
    .await
    {
        SigningProtocolClaim::Claimed | SigningProtocolClaim::AlreadyMatches => {}
        SigningProtocolClaim::Conflict { existing_protocol } => {
            return protocol_mixing_response(&existing_protocol, LEGACY_SIGNING_PROTOCOL);
        }
    }

    if let Some(protocol) =
        crate::database::sign::get_signing_nonce_lease(&statechain_entity.pool, &statechain_id)
            .await
    {
        if protocol != LEGACY_SIGNING_PROTOCOL {
            return pending_nonce_response(&protocol);
        }
    }

    let partial_signature_request_payload = partial_signature_request_payload.0.clone();
    let session = partial_signature_request_payload.session.clone();
    let server_pub_nonce = partial_signature_request_payload.server_pub_nonce.clone();

    let session_bytes: [u8; 133] = hex::decode(&session).unwrap().try_into().unwrap();
    let session = MusigSession::from_slice(session_bytes);
    let challenge = session.get_challenge_from_session();
    let challenge_str = hex::encode(challenge);

    crate::database::sign::update_signature_data_challenge(
        &statechain_entity.pool,
        &server_pub_nonce,
        &challenge_str,
        &statechain_id,
    )
    .await;

    let value = match request
        .json(&partial_signature_request_payload)
        .send()
        .await
    {
        Ok(response) => match response.text().await {
            Ok(text) => text,
            Err(err) => return legacy_internal_server_error_response(err.to_string()),
        },
        Err(err) => {
            return legacy_internal_server_error_response(err.to_string());
        }
    };

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct PartialSignatureResponsePayload<'r> {
        partial_sig: &'r str,
    }

    let response: PartialSignatureResponsePayload = match serde_json::from_str(value.as_str()) {
        Ok(response) => response,
        Err(err) => return legacy_internal_server_error_response(err.to_string()),
    };

    crate::database::sign::delete_signing_nonce_lease(
        &statechain_entity.pool,
        &statechain_id,
        LEGACY_SIGNING_PROTOCOL,
    )
    .await;

    let response_body = json!(response);

    return status::Custom(Status::Ok, Json(response_body));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_mixing_response_rejects_legacy_after_bip448() {
        let response = protocol_mixing_response(
            crate::database::sign::BIP448_SIGNING_PROTOCOL,
            LEGACY_SIGNING_PROTOCOL,
        );

        assert_eq!(response.0, Status::Conflict);
        let message = response.1 .0["message"].as_str().unwrap();
        assert!(message.contains("statechain already uses bip448 signing"));
        assert!(message.contains("legacy signing is disabled"));
    }

    #[test]
    fn legacy_internal_server_error_response_keeps_error_key() {
        let response = legacy_internal_server_error_response("lockbox unavailable".to_string());

        assert_eq!(response.0, Status::InternalServerError);
        assert_eq!(response.1 .0["error"], "Internal Server Error");
        assert_eq!(response.1 .0["message"], "lockbox unavailable");
    }
}
