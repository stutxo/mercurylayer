use mercurylib::transaction::SignFirstRequestPayload;
use rocket::{http::Status, response::status, serde::json::Json, State};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{
    challenge_from_session_hex, error_response, outbound_request_timeout, protocol_mixing_response,
};
use crate::database::sign::{
    legacy_completed_replay_decision, LegacyChallengeClaim, SigningProtocolClaim,
    LEGACY_SIGNING_PROTOCOL,
};
use crate::server::StateChainEntity;

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

fn replay_legacy_partial_signature(server_partial_sig: String) -> status::Custom<Json<Value>> {
    status::Custom(
        Status::Ok,
        Json(json!({ "partial_sig": server_partial_sig })),
    )
}

#[post("/sign/first", format = "json", data = "<sign_first_request_payload>")]
pub async fn sign_first(
    statechain_entity: &State<StateChainEntity>,
    sign_first_request_payload: Json<SignFirstRequestPayload>,
) -> status::Custom<Json<Value>> {
    let statechain_id = sign_first_request_payload.0.statechain_id.clone();

    let statechain_entity = statechain_entity.inner();
    let config = &statechain_entity.config;

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

    let client = statechain_entity.http_client.clone();
    let request = client
        .post(&format!("{}/{}", lockbox_endpoint, path))
        .timeout(outbound_request_timeout());

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

    let incomplete_legacy_round = crate::database::sign::get_incomplete_legacy_signature_record(
        &statechain_entity.pool,
        &statechain_id,
    )
    .await;

    if let Some(incomplete_legacy_round) = incomplete_legacy_round {
        if let Some(protocol) =
            crate::database::sign::get_signing_nonce_lease(&statechain_entity.pool, &statechain_id)
                .await
        {
            if protocol != LEGACY_SIGNING_PROTOCOL {
                return pending_nonce_response(&protocol);
            }
        }

        if incomplete_legacy_round.challenge.is_some() {
            return pending_nonce_response(LEGACY_SIGNING_PROTOCOL);
        }

        // The in-flight round already owns its statechain-keyed lease (created
        // by the original sign/first and protected by reclaim while no partial
        // signature is stored). Replaying the SAME stored server nonce never
        // asks the lockbox for a new nonce, so it is safe regardless of the
        // lease. Do NOT gate the replay on inserting a second lease: that insert
        // always conflicts with the round's own lease and would wedge the coin
        // on a retried sign/first. Re-assert the lease defensively (in case it
        // was reclaimed) and ignore a conflict.
        let _ = crate::database::sign::insert_signing_nonce_lease(
            &statechain_entity.pool,
            &statechain_id,
            LEGACY_SIGNING_PROTOCOL,
        )
        .await;

        let response = mercurylib::transaction::SignFirstResponsePayload {
            server_pubnonce: incomplete_legacy_round.server_pubnonce,
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

    if !crate::database::sign::legacy_signing_nonce_lease_matches(
        &statechain_entity.pool,
        &statechain_id,
        &lease_token,
    )
    .await
    {
        return pending_nonce_response(LEGACY_SIGNING_PROTOCOL);
    }

    let value = match request.json(&sign_first_request_payload.0).send().await {
        Ok(response) => match response.text().await {
            Ok(text) => text,
            Err(err) => {
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

    let server_pubnonce_hex =
        crate::database::sign::normalize_hex_wire_value(&response.server_pubnonce);

    let inserted = crate::database::sign::insert_new_signature_data_if_lease_matches(
        &statechain_entity.pool,
        &server_pubnonce_hex,
        &statechain_id,
        &lease_token,
    )
    .await;

    if !inserted {
        crate::database::sign::delete_signing_nonce_lease_by_token(
            &statechain_entity.pool,
            &statechain_id,
            LEGACY_SIGNING_PROTOCOL,
            &lease_token,
        )
        .await;
        return error_response(
            Status::Conflict,
            "legacy signing nonce lease expired; retry sign/first".to_string(),
        );
    }

    // Return the same normalized (0x-stripped, lowercased) nonce that was
    // stored, so the fresh and replay sign/first paths hand the client an
    // identical textual form for the same nonce.
    let response = mercurylib::transaction::SignFirstResponsePayload {
        server_pubnonce: server_pubnonce_hex,
    };
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
    let config = &statechain_entity.config;

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

    let client = statechain_entity.http_client.clone();
    let request = client
        .post(&format!("{}/{}", lockbox_endpoint, path))
        .timeout(outbound_request_timeout());

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

    let mut partial_signature_request_payload = partial_signature_request_payload.0.clone();
    let session = partial_signature_request_payload.session.clone();
    let server_pub_nonce = crate::database::sign::normalize_hex_wire_value(
        &partial_signature_request_payload.server_pub_nonce,
    );
    partial_signature_request_payload.server_pub_nonce = server_pub_nonce.clone();

    let challenge_str = match challenge_from_session_hex(&session) {
        Some(challenge) => challenge,
        None => {
            return error_response(
                Status::UnprocessableEntity,
                "session is not a valid 133-byte hex MuSig session".to_string(),
            );
        }
    };

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

    if let Some(record) = crate::database::sign::get_legacy_signature_record(
        &statechain_entity.pool,
        &statechain_id,
        &server_pub_nonce,
    )
    .await
    {
        if let Some(decision) = legacy_completed_replay_decision(
            &record,
            &challenge_str,
            i32::from(partial_signature_request_payload.negate_seckey),
        ) {
            match decision {
                LegacyChallengeClaim::Replay { server_partial_sig } => {
                    return replay_legacy_partial_signature(server_partial_sig);
                }
                LegacyChallengeClaim::Conflict { reason } => {
                    return error_response(Status::Conflict, reason.to_string());
                }
                LegacyChallengeClaim::Claimed
                | LegacyChallengeClaim::RetryClaimed
                | LegacyChallengeClaim::NotFound => unreachable!(),
            }
        }
    }

    match crate::database::sign::get_signing_nonce_lease(&statechain_entity.pool, &statechain_id)
        .await
    {
        Some(protocol) if protocol == LEGACY_SIGNING_PROTOCOL => {}
        Some(protocol) => return pending_nonce_response(&protocol),
        None => {
            return error_response(
                Status::Conflict,
                "legacy signing nonce lease is not active; retry sign/first before sign/second"
                    .to_string(),
            );
        }
    }

    let legacy_claim = match crate::database::sign::claim_or_replay_legacy_signature_data_challenge(
        &statechain_entity.pool,
        &statechain_id,
        &server_pub_nonce,
        &challenge_str,
        partial_signature_request_payload.negate_seckey,
    )
    .await
    {
        Ok(claim) => claim,
        Err(err) => return legacy_internal_server_error_response(err.to_string()),
    };

    match legacy_claim {
        LegacyChallengeClaim::Claimed => {}
        LegacyChallengeClaim::RetryClaimed => {
            // Legacy lockbox signing is not idempotent: every call increments
            // sig_count. Re-driving an indeterminate claimed challenge could
            // keep nonce use safe but break receiver transfer-count checks.
            return error_response(
                Status::Conflict,
                "legacy signing challenge is already claimed and no partial signature is stored; retry cannot safely re-drive the legacy lockbox".to_string(),
            );
        }
        LegacyChallengeClaim::Replay { server_partial_sig } => {
            return replay_legacy_partial_signature(server_partial_sig);
        }
        LegacyChallengeClaim::NotFound => {
            return error_response(
                Status::NotFound,
                "no legacy signature nonce for server_pub_nonce; call sign/first first".to_string(),
            );
        }
        LegacyChallengeClaim::Conflict { reason } => {
            return error_response(Status::Conflict, reason.to_string());
        }
    }

    let value = match request
        .json(&partial_signature_request_payload)
        .send()
        .await
    {
        Ok(response) => match response.text().await {
            Ok(text) => text,
            Err(err) => {
                return legacy_internal_server_error_response(err.to_string());
            }
        },
        Err(err) => {
            return legacy_internal_server_error_response(err.to_string());
        }
    };

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct PartialSignatureResponsePayload {
        partial_sig: String,
    }

    let response: PartialSignatureResponsePayload = match serde_json::from_str(value.as_str()) {
        Ok(response) => response,
        Err(err) => {
            return legacy_internal_server_error_response(err.to_string());
        }
    };

    let updated = match crate::database::sign::update_legacy_signature_data_partial_sig(
        &statechain_entity.pool,
        &statechain_id,
        &server_pub_nonce,
        &challenge_str,
        partial_signature_request_payload.negate_seckey,
        &response.partial_sig,
    )
    .await
    {
        Ok(updated) => updated,
        Err(err) => return legacy_internal_server_error_response(err.to_string()),
    };

    if !updated {
        if let Some(record) = crate::database::sign::get_legacy_signature_record(
            &statechain_entity.pool,
            &statechain_id,
            &server_pub_nonce,
        )
        .await
        {
            if let Some(decision) = legacy_completed_replay_decision(
                &record,
                &challenge_str,
                i32::from(partial_signature_request_payload.negate_seckey),
            ) {
                match decision {
                    LegacyChallengeClaim::Replay { server_partial_sig } => {
                        return replay_legacy_partial_signature(server_partial_sig);
                    }
                    LegacyChallengeClaim::Conflict { reason } => {
                        return error_response(Status::Conflict, reason.to_string());
                    }
                    LegacyChallengeClaim::Claimed
                    | LegacyChallengeClaim::RetryClaimed
                    | LegacyChallengeClaim::NotFound => unreachable!(),
                }
            }
        }

        return error_response(
            Status::InternalServerError,
            "legacy partial signature was returned by the lockbox but Mercury could not persist it; retry is fail-closed until the active lease is resolved".to_string(),
        );
    }

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
    use crate::database::sign::LegacySignatureRecord;

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

    #[test]
    fn legacy_challenge_extraction_rejects_wrong_magic_session() {
        assert!(challenge_from_session_hex(&"00".repeat(133)).is_none());
    }

    fn legacy_record(
        challenge: Option<&str>,
        negate_seckey: Option<i32>,
        server_partial_sig: Option<&str>,
    ) -> LegacySignatureRecord {
        LegacySignatureRecord {
            server_pubnonce: "nonce-1".to_string(),
            challenge: challenge.map(str::to_string),
            negate_seckey,
            server_partial_sig: server_partial_sig.map(str::to_string),
        }
    }

    #[test]
    fn legacy_completed_replay_requires_exact_challenge_and_negation() {
        let record = legacy_record(Some("challenge-1"), Some(1), Some("partial-1"));

        assert_eq!(
            legacy_completed_replay_decision(&record, "challenge-1", 1),
            Some(LegacyChallengeClaim::Replay {
                server_partial_sig: "partial-1".to_string()
            })
        );

        assert!(matches!(
            legacy_completed_replay_decision(&record, "challenge-2", 1),
            Some(LegacyChallengeClaim::Conflict { .. })
        ));
        assert!(matches!(
            legacy_completed_replay_decision(&record, "challenge-1", 0),
            Some(LegacyChallengeClaim::Conflict { .. })
        ));
    }

    #[test]
    fn legacy_completed_replay_ignores_records_without_partial_signature() {
        let record = legacy_record(Some("challenge-1"), Some(1), None);

        assert_eq!(
            legacy_completed_replay_decision(&record, "challenge-1", 1),
            None
        );
    }
}
