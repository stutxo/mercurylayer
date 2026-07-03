//! Versioned BIP448 signing routes (Phase 5).
//!
//! `/bip448-statechain/sign/first` and `/bip448-statechain/sign/second` run
//! in parallel with the legacy `/sign/first` and `/sign/second`, which stay
//! unchanged. The lockbox enclave contract is also unchanged: the enclave
//! signs a blinded challenge and cannot distinguish a BIP448 `TemplateHash`
//! from a legacy `TapSighash`, so both routes forward the exact legacy
//! payload shape (via `to_enclave_payload`) to the same enclave endpoints.
//!
//! What is new is the opaque retry/idempotency identifier and the rules around
//! it:
//!
//! - Requests carry only an opaque client-generated `signing_id`; they do not
//!   carry transaction role, state number, template hash, locktime, output, or
//!   any other transaction-derived metadata.
//! - One signature record exists per (statechain, signing_id). An exact retry
//!   is replayed idempotently from the stored record without re-invoking the
//!   enclave. Reuse of the same signing_id with a different server nonce,
//!   blinded challenge, or negation flag is rejected as a conflict.
//! - The CSFS share-negation flag is recorded with the BIP448 record,
//!   distinct from any legacy Taproot tweak metadata.
//! - A statechain is single-protocol for its lifetime. BIP448 and legacy
//!   signing metadata cannot be mixed because the unchanged lockbox exposes one
//!   shared per-statechain signature counter for legacy transfer fraud checks.
//! - `/bip448-statechain/signature-count/<statechain_id>` exposes the shared
//!   lockbox signature counter so a receiver can verify it independently.

use mercurylib::bip448_statechain::signing_api::{
    validate_negate_seckey_flag, validate_signing_id, Bip448PartialSignatureRequestPayload,
    Bip448SignFirstRequestPayload, Bip448SignFirstResponsePayload,
    Bip448SignatureCountResponsePayload,
};
use rocket::{http::Status, response::status, serde::json::Json, State};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::database::bip448_sign::{Bip448IncompleteSignatureRecord, Bip448SignatureRecord};
use crate::database::sign::{SigningProtocolClaim, BIP448_SIGNING_PROTOCOL};
use crate::endpoints::utils::SignatureValidationError;
use crate::server::StateChainEntity;

/// Outcome of matching a `sign/first` request against the stored record.
#[derive(Debug, PartialEq, Eq)]
pub enum SignFirstDecision {
    /// No record for this opaque signing id: produce a fresh nonce.
    Fresh,
    /// Exact retry: replay the stored server public nonce.
    Replay { server_pubnonce: String },
    /// Matching reservation exists but the first request has not stored the
    /// lockbox nonce yet.
    Pending,
}

pub fn classify_sign_first(existing: Option<&Bip448SignatureRecord>) -> SignFirstDecision {
    match existing {
        None => SignFirstDecision::Fresh,
        Some(record) => match &record.server_pubnonce {
            Some(server_pubnonce) => SignFirstDecision::Replay {
                server_pubnonce: server_pubnonce.clone(),
            },
            None => SignFirstDecision::Pending,
        },
    }
}

/// Outcome of matching a `sign/second` request against the stored record.
#[derive(Debug, PartialEq, Eq)]
pub enum SignSecondDecision {
    /// First `sign/second` for this record: proceed to the enclave.
    Proceed,
    /// Exact retry after the challenge was claimed but before a partial
    /// signature was stored. Re-asking for the same challenge does not expose
    /// a second nonce equation; conflicting challenges are rejected above.
    RetryClaimed,
    /// Exact retry of an already-answered request: replay the stored partial
    /// signature without re-invoking the enclave.
    Replay { server_partial_sig: String },
    /// `sign/first` was never called for this opaque signing id.
    NotFound,
    /// Same signing_id reused with different material (server nonce, blinded
    /// challenge, or negation flag).
    Conflict { reason: &'static str },
}

pub fn classify_sign_second(
    existing: Option<&Bip448SignatureRecord>,
    server_pub_nonce: &str,
    challenge: &str,
    negate_seckey: bool,
) -> SignSecondDecision {
    let record = match existing {
        None => return SignSecondDecision::NotFound,
        Some(record) => record,
    };

    match &record.server_pubnonce {
        Some(stored_nonce) if stored_nonce == server_pub_nonce => {}
        _ => {
            return SignSecondDecision::Conflict {
                reason: "server public nonce does not match the stored signature record",
            }
        }
    }

    match (&record.challenge, record.negate_seckey) {
        (None, _) => SignSecondDecision::Proceed,
        (Some(stored_challenge), stored_negate) => {
            if stored_challenge != challenge {
                return SignSecondDecision::Conflict {
                    reason: "challenge does not match the stored signature record",
                };
            }
            if stored_negate != Some(negate_seckey) {
                return SignSecondDecision::Conflict {
                    reason: "negate_seckey flag does not match the stored signature record",
                };
            }
            match &record.server_partial_sig {
                Some(server_partial_sig) => SignSecondDecision::Replay {
                    server_partial_sig: server_partial_sig.clone(),
                },
                None => SignSecondDecision::RetryClaimed,
            }
        }
    }
}

const MUSIG_SESSION_MAGIC: [u8; 4] = [0x9d, 0xed, 0xe9, 0x17];
// rust-secp256k1 fork serialization: magic || parity || fin_nonce || noncecoef || challenge || s_part.
const MUSIG_SESSION_CHALLENGE_OFFSET: usize = 4 + 1 + 32 + 32;
const MUSIG_SESSION_CHALLENGE_END: usize = MUSIG_SESSION_CHALLENGE_OFFSET + 32;

/// Extracts the blinded challenge committed by the 133-byte hex session.
pub fn challenge_from_session_hex(session_hex: &str) -> Option<String> {
    let session_bytes: [u8; 133] = hex::decode(session_hex).ok()?.try_into().ok()?;

    if session_bytes[..4] != MUSIG_SESSION_MAGIC {
        return None;
    }

    Some(hex::encode(
        &session_bytes[MUSIG_SESSION_CHALLENGE_OFFSET..MUSIG_SESSION_CHALLENGE_END],
    ))
}

fn error_response(status: Status, message: String) -> status::Custom<Json<Value>> {
    status::Custom(status, Json(json!({ "message": message })))
}

fn incomplete_round_response(
    incomplete: Bip448IncompleteSignatureRecord,
) -> status::Custom<Json<Value>> {
    let action = if incomplete.has_server_pubnonce {
        "complete sign/second before requesting another nonce"
    } else {
        "retry sign/first after the current nonce request completes"
    };

    error_response(
        Status::Conflict,
        format!("BIP448 signing round is still incomplete; {}", action),
    )
}

fn pending_nonce_response() -> status::Custom<Json<Value>> {
    error_response(
        Status::Conflict,
        "BIP448 signing round is waiting for the server nonce; retry sign/first after the current request completes".to_string(),
    )
}

fn cross_protocol_nonce_response(protocol: &str) -> status::Custom<Json<Value>> {
    error_response(
        Status::Conflict,
        format!(
            "{} signing round is still incomplete for this statechain; complete sign/second before requesting another nonce",
            protocol
        ),
    )
}

async fn recover_bip448_sign_second_claim(
    pool: &sqlx::PgPool,
    statechain_id: &str,
    signing_id: &str,
    challenge: &str,
) {
    crate::database::bip448_sign::clear_bip448_signature_data_challenge(
        pool,
        statechain_id,
        signing_id,
        challenge,
    )
    .await;
    crate::database::sign::delete_bip448_signing_nonce_lease(pool, statechain_id, signing_id).await;
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

async fn validate_bip448_auth(
    pool: &sqlx::PgPool,
    signed_statechain_id: &str,
    statechain_id: &str,
) -> Result<(), status::Custom<Json<Value>>> {
    match crate::endpoints::utils::try_validate_signature(pool, signed_statechain_id, statechain_id)
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(error_response(
            Status::Unauthorized,
            "Signature does not match authentication key.".to_string(),
        )),
        Err(SignatureValidationError::StatechainNotFound) => Err(error_response(
            Status::NotFound,
            format!("statechain {statechain_id} not found"),
        )),
        Err(SignatureValidationError::InvalidSignature) => Err(error_response(
            Status::UnprocessableEntity,
            "signed_statechain_id is not a valid Schnorr signature".to_string(),
        )),
        Err(err @ SignatureValidationError::MissingAuthKey)
        | Err(err @ SignatureValidationError::InvalidAuthKey)
        | Err(err @ SignatureValidationError::Database(_)) => {
            Err(error_response(Status::InternalServerError, err.to_string()))
        }
    }
}

#[post(
    "/bip448-statechain/sign/first",
    format = "json",
    data = "<sign_first_request_payload>"
)]
pub async fn bip448_sign_first(
    statechain_entity: &State<StateChainEntity>,
    sign_first_request_payload: Json<Bip448SignFirstRequestPayload>,
) -> status::Custom<Json<Value>> {
    let payload = sign_first_request_payload.0;
    let statechain_entity = statechain_entity.inner();

    let signing_id = match validate_signing_id(&payload.signing_id) {
        Ok(signing_id) => signing_id,
        Err(err) => return error_response(Status::UnprocessableEntity, err.to_string()),
    };

    if let Err(response) = validate_bip448_auth(
        &statechain_entity.pool,
        &payload.signed_statechain_id,
        &payload.statechain_id,
    )
    .await
    {
        return response;
    }

    crate::database::sign::reclaim_stale_signing_nonce_lease(
        &statechain_entity.pool,
        &payload.statechain_id,
    )
    .await;

    match crate::database::sign::claim_statechain_signing_protocol(
        &statechain_entity.pool,
        &payload.statechain_id,
        BIP448_SIGNING_PROTOCOL,
    )
    .await
    {
        SigningProtocolClaim::Claimed | SigningProtocolClaim::AlreadyMatches => {}
        SigningProtocolClaim::Conflict { existing_protocol } => {
            return protocol_mixing_response(&existing_protocol, BIP448_SIGNING_PROTOCOL);
        }
    }

    let existing = crate::database::bip448_sign::get_bip448_signature_record(
        &statechain_entity.pool,
        &payload.statechain_id,
        &signing_id,
    )
    .await;
    let existing_bip448_round_is_incomplete = existing
        .as_ref()
        .map(|record| record.server_partial_sig.is_none())
        .unwrap_or(false);

    match classify_sign_first(existing.as_ref()) {
        SignFirstDecision::Replay { server_pubnonce } => {
            if existing_bip448_round_is_incomplete {
                let _ = crate::database::sign::insert_bip448_signing_nonce_lease(
                    &statechain_entity.pool,
                    &payload.statechain_id,
                    &signing_id,
                )
                .await;
            }
            let response = Bip448SignFirstResponsePayload { server_pubnonce };
            return status::Custom(Status::Ok, Json(json!(response)));
        }
        SignFirstDecision::Pending => {
            let _ = crate::database::sign::insert_bip448_signing_nonce_lease(
                &statechain_entity.pool,
                &payload.statechain_id,
                &signing_id,
            )
            .await;
            return pending_nonce_response();
        }
        SignFirstDecision::Fresh => {}
    }

    if let Some(incomplete) = crate::database::bip448_sign::get_incomplete_bip448_signature_record(
        &statechain_entity.pool,
        &payload.statechain_id,
    )
    .await
    {
        let _ = crate::database::sign::insert_bip448_signing_nonce_lease(
            &statechain_entity.pool,
            &payload.statechain_id,
            &incomplete.signing_id,
        )
        .await;
        return incomplete_round_response(incomplete);
    }

    if let Some(protocol) = crate::database::sign::get_signing_nonce_lease(
        &statechain_entity.pool,
        &payload.statechain_id,
    )
    .await
    {
        if protocol == BIP448_SIGNING_PROTOCOL {
            return pending_nonce_response();
        }

        return cross_protocol_nonce_response(&protocol);
    }

    let lease_token = crate::database::sign::insert_bip448_signing_nonce_lease(
        &statechain_entity.pool,
        &payload.statechain_id,
        &signing_id,
    )
    .await;

    let Some(lease_token) = lease_token else {
        let protocol = crate::database::sign::get_signing_nonce_lease(
            &statechain_entity.pool,
            &payload.statechain_id,
        )
        .await
        .unwrap_or_else(|| "unknown".to_string());

        if protocol == BIP448_SIGNING_PROTOCOL {
            return pending_nonce_response();
        }

        return cross_protocol_nonce_response(&protocol);
    };

    let reserved = crate::database::bip448_sign::insert_bip448_signature_reservation(
        &statechain_entity.pool,
        &payload.statechain_id,
        &signing_id,
    )
    .await;

    if !reserved {
        let existing = crate::database::bip448_sign::get_bip448_signature_record(
            &statechain_entity.pool,
            &payload.statechain_id,
            &signing_id,
        )
        .await;

        if let SignFirstDecision::Replay { server_pubnonce } =
            classify_sign_first(existing.as_ref())
        {
            crate::database::sign::delete_bip448_signing_nonce_lease_by_token(
                &statechain_entity.pool,
                &payload.statechain_id,
                &signing_id,
                &lease_token,
            )
            .await;
            let response = Bip448SignFirstResponsePayload { server_pubnonce };
            return status::Custom(Status::Ok, Json(json!(response)));
        }

        if let SignFirstDecision::Pending = classify_sign_first(existing.as_ref()) {
            crate::database::sign::delete_bip448_signing_nonce_lease_by_token(
                &statechain_entity.pool,
                &payload.statechain_id,
                &signing_id,
                &lease_token,
            )
            .await;
            return pending_nonce_response();
        }

        if let Some(incomplete) =
            crate::database::bip448_sign::get_incomplete_bip448_signature_record(
                &statechain_entity.pool,
                &payload.statechain_id,
            )
            .await
        {
            crate::database::sign::delete_bip448_signing_nonce_lease_by_token(
                &statechain_entity.pool,
                &payload.statechain_id,
                &signing_id,
                &lease_token,
            )
            .await;
            let _ = crate::database::sign::insert_bip448_signing_nonce_lease(
                &statechain_entity.pool,
                &payload.statechain_id,
                &incomplete.signing_id,
            )
            .await;
            return incomplete_round_response(incomplete);
        }

        crate::database::sign::delete_bip448_signing_nonce_lease_by_token(
            &statechain_entity.pool,
            &payload.statechain_id,
            &signing_id,
            &lease_token,
        )
        .await;

        return error_response(
            Status::Conflict,
            "BIP448 signing reservation was concurrently created; retry the request".to_string(),
        );
    }

    let config = crate::server_config::ServerConfig::load();
    let enclave_index = crate::database::utils::get_enclave_index_from_database(
        &statechain_entity.pool,
        &payload.statechain_id,
    )
    .await;

    let enclave_index = match enclave_index {
        Some(index) => index as usize,
        None => {
            crate::database::bip448_sign::delete_bip448_signature_reservation(
                &statechain_entity.pool,
                &payload.statechain_id,
                &signing_id,
            )
            .await;
            crate::database::sign::delete_bip448_signing_nonce_lease_by_token(
                &statechain_entity.pool,
                &payload.statechain_id,
                &signing_id,
                &lease_token,
            )
            .await;
            return error_response(
                Status::InternalServerError,
                format!(
                    "Enclave index for statechain {} ID not found.",
                    payload.statechain_id
                ),
            );
        }
    };

    let Some(enclave) = config.enclaves.get(enclave_index) else {
        crate::database::bip448_sign::delete_bip448_signature_reservation(
            &statechain_entity.pool,
            &payload.statechain_id,
            &signing_id,
        )
        .await;
        crate::database::sign::delete_bip448_signing_nonce_lease_by_token(
            &statechain_entity.pool,
            &payload.statechain_id,
            &signing_id,
            &lease_token,
        )
        .await;
        return error_response(
            Status::InternalServerError,
            format!("Enclave index {} is not configured.", enclave_index),
        );
    };

    let lockbox_endpoint = enclave.url.clone();
    let path = "get_public_nonce";

    let client: reqwest::Client = reqwest::Client::new();
    let request = client.post(&format!("{}/{}", lockbox_endpoint, path));

    let lease_lock = match crate::database::sign::lock_bip448_signing_nonce_lease_for_lockbox(
        &statechain_entity.pool,
        &payload.statechain_id,
        &signing_id,
        &lease_token,
    )
    .await
    {
        Some(lease_lock) => lease_lock,
        None => return pending_nonce_response(),
    };

    // The enclave contract is the unchanged legacy one; the enclave signs a
    // blinded challenge and never sees BIP448 metadata.
    let value = match request.json(&payload.to_enclave_payload()).send().await {
        Ok(response) => match response.text().await {
            Ok(text) => text,
            Err(err) => {
                lease_lock.rollback().await.unwrap();
                crate::database::bip448_sign::delete_bip448_signature_reservation(
                    &statechain_entity.pool,
                    &payload.statechain_id,
                    &signing_id,
                )
                .await;
                crate::database::sign::delete_bip448_signing_nonce_lease_by_token(
                    &statechain_entity.pool,
                    &payload.statechain_id,
                    &signing_id,
                    &lease_token,
                )
                .await;
                return error_response(Status::InternalServerError, err.to_string());
            }
        },
        Err(err) => {
            lease_lock.rollback().await.unwrap();
            crate::database::bip448_sign::delete_bip448_signature_reservation(
                &statechain_entity.pool,
                &payload.statechain_id,
                &signing_id,
            )
            .await;
            crate::database::sign::delete_bip448_signing_nonce_lease_by_token(
                &statechain_entity.pool,
                &payload.statechain_id,
                &signing_id,
                &lease_token,
            )
            .await;
            return error_response(Status::InternalServerError, err.to_string());
        }
    };

    let response: mercurylib::transaction::SignFirstResponsePayload =
        match serde_json::from_str(value.as_str()) {
            Ok(response) => response,
            Err(err) => {
                lease_lock.rollback().await.unwrap();
                crate::database::bip448_sign::delete_bip448_signature_reservation(
                    &statechain_entity.pool,
                    &payload.statechain_id,
                    &signing_id,
                )
                .await;
                crate::database::sign::delete_bip448_signing_nonce_lease_by_token(
                    &statechain_entity.pool,
                    &payload.statechain_id,
                    &signing_id,
                    &lease_token,
                )
                .await;
                return error_response(Status::InternalServerError, err.to_string());
            }
        };

    let mut server_pubnonce_hex = response.server_pubnonce.clone();
    if server_pubnonce_hex.starts_with("0x") {
        server_pubnonce_hex = server_pubnonce_hex[2..].to_string();
    }

    let updated = crate::database::bip448_sign::update_bip448_signature_data_server_pubnonce(
        &statechain_entity.pool,
        &payload.statechain_id,
        &signing_id,
        &server_pubnonce_hex,
    )
    .await;

    if !updated {
        lease_lock.rollback().await.unwrap();
        crate::database::bip448_sign::delete_bip448_signature_reservation(
            &statechain_entity.pool,
            &payload.statechain_id,
            &signing_id,
        )
        .await;
        crate::database::sign::delete_bip448_signing_nonce_lease_by_token(
            &statechain_entity.pool,
            &payload.statechain_id,
            &signing_id,
            &lease_token,
        )
        .await;
        return error_response(
            Status::InternalServerError,
            "reserved BIP448 signature record could not be updated with the server nonce"
                .to_string(),
        );
    }

    lease_lock.commit().await.unwrap();

    let response = Bip448SignFirstResponsePayload {
        server_pubnonce: server_pubnonce_hex,
    };

    status::Custom(Status::Ok, Json(json!(response)))
}

#[post(
    "/bip448-statechain/sign/second",
    format = "json",
    data = "<partial_signature_request_payload>"
)]
pub async fn bip448_sign_second(
    statechain_entity: &State<StateChainEntity>,
    partial_signature_request_payload: Json<Bip448PartialSignatureRequestPayload>,
) -> status::Custom<Json<Value>> {
    let payload = partial_signature_request_payload.0;
    let statechain_entity = statechain_entity.inner();

    let signing_id = match validate_signing_id(&payload.signing_id) {
        Ok(signing_id) => signing_id,
        Err(err) => return error_response(Status::UnprocessableEntity, err.to_string()),
    };

    let negate_seckey = match validate_negate_seckey_flag(payload.negate_seckey) {
        Ok(flag) => flag,
        Err(err) => return error_response(Status::UnprocessableEntity, err.to_string()),
    };

    if let Err(response) = validate_bip448_auth(
        &statechain_entity.pool,
        &payload.signed_statechain_id,
        &payload.statechain_id,
    )
    .await
    {
        return response;
    }

    let challenge = match challenge_from_session_hex(&payload.session) {
        Some(challenge) => challenge,
        None => {
            return error_response(
                Status::UnprocessableEntity,
                "session is not a valid 133-byte hex blinded MuSig session".to_string(),
            );
        }
    };

    let existing = crate::database::bip448_sign::get_bip448_signature_record(
        &statechain_entity.pool,
        &payload.statechain_id,
        &signing_id,
    )
    .await;

    let sign_second_decision = classify_sign_second(
        existing.as_ref(),
        &payload.server_pub_nonce,
        &challenge,
        negate_seckey,
    );

    match &sign_second_decision {
        SignSecondDecision::NotFound => {
            return error_response(
                Status::NotFound,
                "no BIP448 signature record for signing_id; call sign/first first".to_string(),
            );
        }
        SignSecondDecision::Conflict { reason } => {
            return error_response(Status::Conflict, (*reason).to_string());
        }
        SignSecondDecision::Proceed
        | SignSecondDecision::RetryClaimed
        | SignSecondDecision::Replay { .. } => {}
    }

    match crate::database::sign::claim_statechain_signing_protocol(
        &statechain_entity.pool,
        &payload.statechain_id,
        BIP448_SIGNING_PROTOCOL,
    )
    .await
    {
        SigningProtocolClaim::Claimed | SigningProtocolClaim::AlreadyMatches => {}
        SigningProtocolClaim::Conflict { existing_protocol } => {
            return protocol_mixing_response(&existing_protocol, BIP448_SIGNING_PROTOCOL);
        }
    }

    match sign_second_decision {
        SignSecondDecision::Replay { server_partial_sig } => {
            crate::database::sign::delete_bip448_signing_nonce_lease(
                &statechain_entity.pool,
                &payload.statechain_id,
                &signing_id,
            )
            .await;
            return status::Custom(
                Status::Ok,
                Json(json!({ "partial_sig": server_partial_sig })),
            );
        }
        SignSecondDecision::Proceed => {}
        SignSecondDecision::RetryClaimed => {
            return error_response(
                Status::Conflict,
                "BIP448 signing challenge is already claimed; retry after the partial signature is available".to_string(),
            );
        }
        SignSecondDecision::NotFound | SignSecondDecision::Conflict { .. } => unreachable!(),
    };

    if let Some(protocol) = crate::database::sign::get_signing_nonce_lease(
        &statechain_entity.pool,
        &payload.statechain_id,
    )
    .await
    {
        if protocol != BIP448_SIGNING_PROTOCOL {
            return cross_protocol_nonce_response(&protocol);
        }

        match crate::database::sign::get_bip448_signing_nonce_lease(
            &statechain_entity.pool,
            &payload.statechain_id,
        )
        .await
        {
            Some(lease_signing_id) if lease_signing_id == signing_id => {}
            _ => return pending_nonce_response(),
        }
    } else {
        let lease_token = crate::database::sign::insert_bip448_signing_nonce_lease(
            &statechain_entity.pool,
            &payload.statechain_id,
            &signing_id,
        )
        .await;

        if lease_token.is_none() {
            let protocol = crate::database::sign::get_signing_nonce_lease(
                &statechain_entity.pool,
                &payload.statechain_id,
            )
            .await
            .unwrap_or_else(|| "unknown".to_string());

            if protocol != BIP448_SIGNING_PROTOCOL {
                return cross_protocol_nonce_response(&protocol);
            }

            return pending_nonce_response();
        }
    }

    let claimed = crate::database::bip448_sign::try_claim_bip448_signature_data_challenge(
        &statechain_entity.pool,
        &payload.statechain_id,
        &signing_id,
        &payload.server_pub_nonce,
        &challenge,
        negate_seckey,
    )
    .await;

    if !claimed {
        let existing = crate::database::bip448_sign::get_bip448_signature_record(
            &statechain_entity.pool,
            &payload.statechain_id,
            &signing_id,
        )
        .await;

        return match classify_sign_second(
            existing.as_ref(),
            &payload.server_pub_nonce,
            &challenge,
            negate_seckey,
        ) {
            SignSecondDecision::Replay { server_partial_sig } => {
                crate::database::sign::delete_bip448_signing_nonce_lease(
                    &statechain_entity.pool,
                    &payload.statechain_id,
                    &signing_id,
                )
                .await;
                status::Custom(Status::Ok, Json(json!({ "partial_sig": server_partial_sig })))
            }
            SignSecondDecision::NotFound => error_response(
                Status::NotFound,
                "no BIP448 signature record for signing_id; call sign/first first".to_string(),
            ),
            SignSecondDecision::Conflict { reason } => {
                error_response(Status::Conflict, reason.to_string())
            }
            SignSecondDecision::Proceed | SignSecondDecision::RetryClaimed => error_response(
                Status::Conflict,
                "BIP448 signing challenge was concurrently claimed; retry after the partial signature is available".to_string(),
            ),
        };
    }
    let config = crate::server_config::ServerConfig::load();
    let enclave_index = crate::database::utils::get_enclave_index_from_database(
        &statechain_entity.pool,
        &payload.statechain_id,
    )
    .await;

    let enclave_index = match enclave_index {
        Some(index) => index as usize,
        None => {
            recover_bip448_sign_second_claim(
                &statechain_entity.pool,
                &payload.statechain_id,
                &signing_id,
                &challenge,
            )
            .await;
            return error_response(
                Status::InternalServerError,
                format!(
                    "Enclave index for statechain {} ID not found.",
                    payload.statechain_id
                ),
            );
        }
    };

    let Some(enclave) = config.enclaves.get(enclave_index) else {
        recover_bip448_sign_second_claim(
            &statechain_entity.pool,
            &payload.statechain_id,
            &signing_id,
            &challenge,
        )
        .await;
        return error_response(
            Status::InternalServerError,
            format!("Enclave index {} is not configured.", enclave_index),
        );
    };

    let lockbox_endpoint = enclave.url.clone();
    let path = "get_partial_signature";

    let client: reqwest::Client = reqwest::Client::new();
    let request = client.post(&format!("{}/{}", lockbox_endpoint, path));

    // Same unchanged enclave contract as the legacy route.
    let value = match request.json(&payload.to_enclave_payload()).send().await {
        Ok(response) => match response.text().await {
            Ok(text) => text,
            Err(err) => {
                recover_bip448_sign_second_claim(
                    &statechain_entity.pool,
                    &payload.statechain_id,
                    &signing_id,
                    &challenge,
                )
                .await;
                return error_response(Status::InternalServerError, err.to_string());
            }
        },
        Err(err) => {
            recover_bip448_sign_second_claim(
                &statechain_entity.pool,
                &payload.statechain_id,
                &signing_id,
                &challenge,
            )
            .await;
            return error_response(Status::InternalServerError, err.to_string());
        }
    };

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct PartialSignatureResponsePayload<'r> {
        partial_sig: &'r str,
    }

    let response: PartialSignatureResponsePayload = match serde_json::from_str(value.as_str()) {
        Ok(response) => response,
        Err(err) => {
            recover_bip448_sign_second_claim(
                &statechain_entity.pool,
                &payload.statechain_id,
                &signing_id,
                &challenge,
            )
            .await;
            return error_response(Status::InternalServerError, err.to_string());
        }
    };

    let updated = crate::database::bip448_sign::update_bip448_signature_data_partial_sig(
        &statechain_entity.pool,
        &payload.statechain_id,
        &signing_id,
        &challenge,
        response.partial_sig,
    )
    .await;

    if !updated {
        let existing = crate::database::bip448_sign::get_bip448_signature_record(
            &statechain_entity.pool,
            &payload.statechain_id,
            &signing_id,
        )
        .await;

        return match classify_sign_second(
            existing.as_ref(),
            &payload.server_pub_nonce,
            &challenge,
            negate_seckey,
        ) {
            SignSecondDecision::Replay { server_partial_sig } => {
                crate::database::sign::delete_bip448_signing_nonce_lease(
                    &statechain_entity.pool,
                    &payload.statechain_id,
                    &signing_id,
                )
                .await;
                status::Custom(
                    Status::Ok,
                    Json(json!({ "partial_sig": server_partial_sig })),
                )
            }
            SignSecondDecision::NotFound => error_response(
                Status::NotFound,
                "no BIP448 signature record for signing_id; call sign/first first".to_string(),
            ),
            SignSecondDecision::Conflict { reason } => {
                error_response(Status::Conflict, reason.to_string())
            }
            SignSecondDecision::Proceed | SignSecondDecision::RetryClaimed => {
                recover_bip448_sign_second_claim(
                    &statechain_entity.pool,
                    &payload.statechain_id,
                    &signing_id,
                    &challenge,
                )
                .await;
                error_response(
                    Status::Conflict,
                    "BIP448 partial signature was not recorded; retry the request".to_string(),
                )
            }
        };
    }

    crate::database::sign::delete_bip448_signing_nonce_lease(
        &statechain_entity.pool,
        &payload.statechain_id,
        &signing_id,
    )
    .await;

    status::Custom(Status::Ok, Json(json!(response)))
}

#[get("/bip448-statechain/signature-count/<statechain_id>")]
pub async fn bip448_signature_count(
    statechain_entity: &State<StateChainEntity>,
    statechain_id: &str,
) -> status::Custom<Json<Value>> {
    let statechain_entity = statechain_entity.inner();

    let enclave_index = crate::database::utils::get_enclave_index_from_database(
        &statechain_entity.pool,
        statechain_id,
    )
    .await;

    let enclave_index = match enclave_index {
        Some(index) => index as usize,
        None => {
            return error_response(
                Status::InternalServerError,
                format!("Enclave index for statechain {statechain_id} ID not found."),
            )
        }
    };

    let config = crate::server_config::ServerConfig::load();
    let Some(enclave) = config.enclaves.get(enclave_index) else {
        return error_response(
            Status::InternalServerError,
            format!("Enclave index {} is not configured.", enclave_index),
        );
    };

    let lockbox_endpoint = enclave.url.clone();
    let path = "signature_count";

    let client: reqwest::Client = reqwest::Client::new();
    let request = client.get(&format!("{}/{}/{}", lockbox_endpoint, path, statechain_id));

    let value = match request.send().await {
        Ok(response) => match response.text().await {
            Ok(text) => text,
            Err(err) => return error_response(Status::InternalServerError, err.to_string()),
        },
        Err(err) => {
            return error_response(Status::InternalServerError, err.to_string());
        }
    };

    let response: Value = match serde_json::from_str(value.as_str()) {
        Ok(response) => response,
        Err(err) => return error_response(Status::InternalServerError, err.to_string()),
    };

    let Some(sig_count) = response["sig_count"].as_u64() else {
        return error_response(
            Status::InternalServerError,
            "lockbox signature_count response is missing sig_count".to_string(),
        );
    };

    let response = Bip448SignatureCountResponsePayload { sig_count };

    status::Custom(Status::Ok, Json(json!(response)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNING_ID: &str = "aa11955b1327167cb7ae3dc39d52c277be39d75737b9cb80514ce6e825fd8eea";

    fn record(
        server_pubnonce: Option<&str>,
        challenge: Option<&str>,
        negate_seckey: Option<bool>,
        server_partial_sig: Option<&str>,
    ) -> Bip448SignatureRecord {
        Bip448SignatureRecord {
            server_pubnonce: server_pubnonce.map(str::to_string),
            challenge: challenge.map(str::to_string),
            negate_seckey,
            server_partial_sig: server_partial_sig.map(str::to_string),
        }
    }

    #[test]
    fn sign_first_is_fresh_without_a_record() {
        assert_eq!(classify_sign_first(None), SignFirstDecision::Fresh);
    }

    #[test]
    fn sign_first_replays_exact_retries() {
        let record = record(Some("nonce-1"), None, None, None);
        assert_eq!(
            classify_sign_first(Some(&record)),
            SignFirstDecision::Replay {
                server_pubnonce: "nonce-1".to_string()
            }
        );
        // Still an exact retry after sign/second completed.
        let completed = record_with_partial();
        assert_eq!(
            classify_sign_first(Some(&completed)),
            SignFirstDecision::Replay {
                server_pubnonce: "nonce-1".to_string()
            }
        );
    }

    #[test]
    fn sign_first_reports_matching_reservation_as_pending() {
        let pending = record(None, None, None, None);

        assert_eq!(
            classify_sign_first(Some(&pending)),
            SignFirstDecision::Pending
        );
    }

    fn record_with_partial() -> Bip448SignatureRecord {
        record(
            Some("nonce-1"),
            Some("challenge-1"),
            Some(true),
            Some("partial-1"),
        )
    }

    #[test]
    fn sign_second_requires_a_record() {
        assert_eq!(
            classify_sign_second(None, "nonce-1", "challenge-1", true),
            SignSecondDecision::NotFound
        );
    }

    #[test]
    fn sign_second_proceeds_once_then_replays_exact_retries() {
        let fresh = record(Some("nonce-1"), None, None, None);
        assert_eq!(
            classify_sign_second(Some(&fresh), "nonce-1", "challenge-1", true),
            SignSecondDecision::Proceed
        );

        let completed = record_with_partial();
        assert_eq!(
            classify_sign_second(Some(&completed), "nonce-1", "challenge-1", true),
            SignSecondDecision::Replay {
                server_partial_sig: "partial-1".to_string()
            }
        );
    }

    #[test]
    fn sign_second_retries_recorded_challenge_without_partial() {
        let interrupted = record(Some("nonce-1"), Some("challenge-1"), Some(true), None);
        assert_eq!(
            classify_sign_second(Some(&interrupted), "nonce-1", "challenge-1", true),
            SignSecondDecision::RetryClaimed
        );
    }

    #[test]
    fn sign_second_rejects_conflicting_reuse() {
        let completed = record_with_partial();

        assert!(matches!(
            classify_sign_second(Some(&completed), "nonce-2", "challenge-1", true),
            SignSecondDecision::Conflict { .. }
        ));
        assert!(matches!(
            classify_sign_second(Some(&completed), "nonce-1", "challenge-2", true),
            SignSecondDecision::Conflict { .. }
        ));
        // The recorded CSFS negation flag must replay identically.
        assert!(matches!(
            classify_sign_second(Some(&completed), "nonce-1", "challenge-1", false),
            SignSecondDecision::Conflict { .. }
        ));
    }

    #[test]
    fn challenge_extraction_rejects_malformed_sessions() {
        assert!(challenge_from_session_hex("zz").is_none());
        assert!(challenge_from_session_hex("aa").is_none());
        assert!(challenge_from_session_hex(&"aa".repeat(132)).is_none());
        assert!(challenge_from_session_hex(&"00".repeat(133)).is_none());
    }

    #[test]
    fn challenge_extraction_reads_serialized_session_challenge_field() {
        let mut session = [0u8; 133];
        session[..4].copy_from_slice(&MUSIG_SESSION_MAGIC);
        session[MUSIG_SESSION_CHALLENGE_OFFSET..MUSIG_SESSION_CHALLENGE_END].fill(0x42);

        assert_eq!(
            challenge_from_session_hex(&hex::encode(session)).unwrap(),
            "42".repeat(32)
        );
    }

    #[test]
    fn validated_signing_ids_canonicalize_hex_case() {
        let validated = validate_signing_id(&SIGNING_ID.to_uppercase()).unwrap();

        assert_eq!(validated, SIGNING_ID);
    }

    #[test]
    fn protocol_mixing_response_rejects_bip448_after_legacy() {
        let response = protocol_mixing_response(
            crate::database::sign::LEGACY_SIGNING_PROTOCOL,
            BIP448_SIGNING_PROTOCOL,
        );

        assert_eq!(response.0, Status::Conflict);
        let message = response.1 .0["message"].as_str().unwrap();
        assert!(message.contains("statechain already uses legacy signing"));
        assert!(message.contains("bip448 signing is disabled"));
    }
}
