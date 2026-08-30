//! BIP448 signing routes.
//!
//! `/bip448-statechain/sign/first` and `/bip448-statechain/sign/second` use
//! versioned lockbox endpoints that include the opaque signing id, letting the
//! lockbox make nonce idempotency authoritative without seeing transaction
//! metadata.
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
//! - The CSFS share-negation flag is recorded with the BIP448 record.
//! - `/bip448-statechain/signature-count/<statechain_id>` exposes the lockbox
//!   signature counter so a receiver can verify it independently.

use mercurylib::bip448_statechain::signing_api::{
    validate_negate_seckey_flag, validate_signing_id, Bip448BlindedSession,
    Bip448CompressedPublicKey, Bip448LockboxPartialSignatureRequestPayloadV1,
    Bip448LockboxSignFirstRequestPayloadV1, Bip448LockboxStateResponsePayloadV1,
    Bip448NegateSeckeyFlag, Bip448PartialSignatureRequestPayload, Bip448PublicNonce,
    Bip448SignFirstRequestPayload, Bip448SignFirstResponsePayload,
    Bip448SignatureCountResponsePayload, Bip448SigningId, Bip448StatechainId,
};
use rocket::{http::Status, response::status, serde::json::Json, State};
use secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{challenge_from_session_hex, error_response};
use crate::database::bip448_sign::{Bip448IncompleteSignatureRecord, Bip448SignatureRecord};
use crate::endpoints::utils::SignatureValidationError;
use crate::{lockbox_client::LockboxResponse, server::StateChainEntity};

fn normalize_hex_wire_value(value: &str) -> String {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value)
        .to_ascii_lowercase()
}

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

    let server_pub_nonce = normalize_hex_wire_value(server_pub_nonce);

    match &record.server_pubnonce {
        Some(stored_nonce) if normalize_hex_wire_value(stored_nonce) == server_pub_nonce => {}
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

fn lockbox_status_to_rocket(status: u16) -> Status {
    match status {
        400 => Status::BadRequest,
        404 => Status::NotFound,
        409 => Status::Conflict,
        _ => Status::InternalServerError,
    }
}

fn signing_enclave_failure() -> status::Custom<Json<Value>> {
    error_response(
        Status::BadGateway,
        "Signing enclave request failed.".to_string(),
    )
}

fn lockbox_response_text(response: LockboxResponse) -> Result<String, status::Custom<Json<Value>>> {
    if (200..300).contains(&response.status) {
        return Ok(response.body);
    }
    if matches!(response.status, 400 | 404 | 409) {
        return Err(error_response(
            lockbox_status_to_rocket(response.status),
            response.body,
        ));
    }
    log::error!(
        "Lockbox returned unexpected status {}: {}",
        response.status,
        response.body
    );
    Err(signing_enclave_failure())
}

fn parse_lockbox_signature_count(value: &str) -> Result<u64, String> {
    let response: Value = serde_json::from_str(value)
        .map_err(|err| format!("failed to parse lockbox signature_count response: {err}"))?;

    response["sig_count"]
        .as_u64()
        .ok_or_else(|| "lockbox signature_count response is missing sig_count".to_string())
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

async fn cleanup_bip448_sign_first_reservation(
    connection: &mut sqlx::PgConnection,
    statechain_id: &str,
    signing_id: &str,
    lease_token: &str,
) {
    crate::database::bip448_sign::delete_bip448_signature_reservation(
        &mut *connection,
        statechain_id,
        signing_id,
    )
    .await;
    crate::database::signing_nonce::delete_bip448_signing_nonce_lease_by_token(
        connection,
        statechain_id,
        signing_id,
        lease_token,
    )
    .await;
}

async fn replay_bip448_partial_signature(
    connection: &mut sqlx::PgConnection,
    statechain_id: &str,
    signing_id: &str,
    server_partial_sig: String,
) -> status::Custom<Json<Value>> {
    crate::database::signing_nonce::delete_bip448_signing_nonce_lease(
        connection,
        statechain_id,
        signing_id,
    )
    .await;

    status::Custom(
        Status::Ok,
        Json(json!({ "partial_sig": server_partial_sig })),
    )
}

fn validate_locked_bip448_auth(
    locked: &crate::database::transfer_receiver::LockedStatechainGeneration,
    signed_statechain_id: &str,
    statechain_id: &str,
) -> Result<(), status::Custom<Json<Value>>> {
    let auth_key = XOnlyPublicKey::from_slice(&locked.auth_xonly_public_key).map_err(|_| {
        error_response(
            Status::InternalServerError,
            "statechain auth key is invalid".to_string(),
        )
    })?;

    match crate::endpoints::utils::try_verify_statechain_signature(
        signed_statechain_id,
        statechain_id,
        &auth_key,
    ) {
        Ok(true) => Ok(()),
        Ok(false) => Err(error_response(
            Status::Unauthorized,
            "Signature does not match authentication key.".to_string(),
        )),
        Err(SignatureValidationError::InvalidSignature) => Err(error_response(
            Status::UnprocessableEntity,
            "signed_statechain_id is not a valid Schnorr signature".to_string(),
        )),
        Err(err @ SignatureValidationError::StatechainNotFound)
        | Err(err @ SignatureValidationError::MissingAuthKey)
        | Err(err @ SignatureValidationError::InvalidAuthKey)
        | Err(err @ SignatureValidationError::Database(_)) => {
            Err(error_response(Status::InternalServerError, err.to_string()))
        }
    }
}

fn locked_server_pubkey(
    locked: &crate::database::transfer_receiver::LockedStatechainGeneration,
) -> Result<Bip448CompressedPublicKey, status::Custom<Json<Value>>> {
    let bytes: [u8; 33] = locked
        .server_public_key
        .as_slice()
        .try_into()
        .map_err(|_| {
            error_response(
                Status::InternalServerError,
                "statechain server public key is malformed".to_string(),
            )
        })?;
    Bip448CompressedPublicKey::from_bytes(bytes).map_err(|_| {
        error_response(
            Status::InternalServerError,
            "statechain server public key is malformed".to_string(),
        )
    })
}

async fn observe_locked_bip448_state(
    statechain_entity: &StateChainEntity,
    statechain_id: &Bip448StatechainId,
    locked: &crate::database::transfer_receiver::LockedStatechainGeneration,
) -> Result<(usize, Bip448LockboxStateResponsePayloadV1), status::Custom<Json<Value>>> {
    let enclave_index = usize::try_from(locked.enclave_index).map_err(|_| {
        error_response(
            Status::InternalServerError,
            "Enclave index for statechain ID not found.".to_string(),
        )
    })?;
    if statechain_entity
        .config
        .enclaves
        .get(enclave_index)
        .is_none()
    {
        return Err(error_response(
            Status::InternalServerError,
            format!("Enclave index {enclave_index} is not configured."),
        ));
    }

    let response = statechain_entity
        .lockboxes
        .get_raw(
            enclave_index,
            &format!("/bip448/state/{}", statechain_id.as_str()),
        )
        .await
        .map_err(|error| {
            log::error!("failed to observe Lockbox BIP448 state: {error}");
            signing_enclave_failure()
        })?;
    let value = lockbox_response_text(response).map_err(|_| {
        error_response(
            Status::InternalServerError,
            "lockbox BIP448 state is unavailable for an existing Mercury statechain".to_string(),
        )
    })?;
    let observed: Bip448LockboxStateResponsePayloadV1 =
        serde_json::from_str(&value).map_err(|error| {
            log::error!("failed to parse Lockbox BIP448 state response: {error}");
            signing_enclave_failure()
        })?;
    if observed.statechain_id != *statechain_id {
        return Err(error_response(
            Status::InternalServerError,
            "lockbox returned BIP448 state for a different statechain".to_string(),
        ));
    }
    if observed.server_pubkey != locked_server_pubkey(locked)? {
        return Err(error_response(
            Status::Conflict,
            "Mercury and lockbox BIP448 server keys do not match".to_string(),
        ));
    }

    Ok((enclave_index, observed))
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
    let statechain_id = match Bip448StatechainId::try_from(payload.statechain_id.as_str()) {
        Ok(statechain_id) => statechain_id,
        Err(err) => return error_response(Status::UnprocessableEntity, err.to_string()),
    };
    let lockbox_signing_id = match Bip448SigningId::try_from(signing_id.as_str()) {
        Ok(signing_id) => signing_id,
        Err(err) => return error_response(Status::UnprocessableEntity, err.to_string()),
    };

    // The inner flow produces the response while this transaction remains the
    // handoff fence; its Mercury metadata is committed and the lock released
    // exactly once after any lockbox call has completed.
    let mut handoff_fence = match statechain_entity.pool.begin().await {
        Ok(transaction) => transaction,
        Err(err) => return error_response(Status::InternalServerError, err.to_string()),
    };
    let locked = match crate::database::transfer_receiver::lock_statechain_generation(
        &mut *handoff_fence,
        statechain_id.as_str(),
    )
    .await
    {
        Ok(Some(locked)) => locked,
        Ok(None) => {
            return error_response(
                Status::NotFound,
                format!("statechain {} not found", statechain_id.as_str()),
            );
        }
        Err(err) => return error_response(Status::InternalServerError, err.to_string()),
    };
    if let Err(response) = validate_locked_bip448_auth(
        &locked,
        &payload.signed_statechain_id,
        statechain_id.as_str(),
    ) {
        return response;
    }
    let (enclave_index, lockbox_state) =
        match observe_locked_bip448_state(statechain_entity, &statechain_id, &locked).await {
            Ok(observed) => observed,
            Err(response) => return response,
        };

    let response = async {
        crate::database::signing_nonce::reclaim_stale_signing_nonce_lease(
            &mut *handoff_fence,
            &payload.statechain_id,
        )
        .await;

        let existing = crate::database::bip448_sign::get_bip448_signature_record(
            &mut *handoff_fence,
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
                    let _ = crate::database::signing_nonce::insert_bip448_signing_nonce_lease(
                        &mut *handoff_fence,
                        &payload.statechain_id,
                        &signing_id,
                    )
                    .await;
                }
                let response = Bip448SignFirstResponsePayload { server_pubnonce };
                return status::Custom(Status::Ok, Json(json!(response)));
            }
            SignFirstDecision::Pending => {
                let _ = crate::database::signing_nonce::insert_bip448_signing_nonce_lease(
                    &mut *handoff_fence,
                    &payload.statechain_id,
                    &signing_id,
                )
                .await;
                return pending_nonce_response();
            }
            SignFirstDecision::Fresh => {}
        }

        if let Some(incomplete) =
            crate::database::bip448_sign::get_incomplete_bip448_signature_record(
                &mut *handoff_fence,
                &payload.statechain_id,
            )
            .await
        {
            let _ = crate::database::signing_nonce::insert_bip448_signing_nonce_lease(
                &mut *handoff_fence,
                &payload.statechain_id,
                &incomplete.signing_id,
            )
            .await;
            return incomplete_round_response(incomplete);
        }

        if crate::database::signing_nonce::get_bip448_signing_nonce_lease(
            &mut *handoff_fence,
            &payload.statechain_id,
        )
        .await
        .is_some()
        {
            return pending_nonce_response();
        }

        let lease_token = crate::database::signing_nonce::insert_bip448_signing_nonce_lease(
            &mut *handoff_fence,
            &payload.statechain_id,
            &signing_id,
        )
        .await;

        let Some(lease_token) = lease_token else {
            return pending_nonce_response();
        };

        let reserved = crate::database::bip448_sign::insert_bip448_signature_reservation(
            &mut *handoff_fence,
            &payload.statechain_id,
            &signing_id,
        )
        .await;

        if !reserved {
            let existing = crate::database::bip448_sign::get_bip448_signature_record(
                &mut *handoff_fence,
                &payload.statechain_id,
                &signing_id,
            )
            .await;

            if let SignFirstDecision::Replay { server_pubnonce } =
                classify_sign_first(existing.as_ref())
            {
                crate::database::signing_nonce::delete_bip448_signing_nonce_lease_by_token(
                    &mut *handoff_fence,
                    &payload.statechain_id,
                    &signing_id,
                    &lease_token,
                )
                .await;
                let response = Bip448SignFirstResponsePayload { server_pubnonce };
                return status::Custom(Status::Ok, Json(json!(response)));
            }

            if let SignFirstDecision::Pending = classify_sign_first(existing.as_ref()) {
                crate::database::signing_nonce::delete_bip448_signing_nonce_lease_by_token(
                    &mut *handoff_fence,
                    &payload.statechain_id,
                    &signing_id,
                    &lease_token,
                )
                .await;
                return pending_nonce_response();
            }

            if let Some(incomplete) =
                crate::database::bip448_sign::get_incomplete_bip448_signature_record(
                    &mut *handoff_fence,
                    &payload.statechain_id,
                )
                .await
            {
                crate::database::signing_nonce::delete_bip448_signing_nonce_lease_by_token(
                    &mut *handoff_fence,
                    &payload.statechain_id,
                    &signing_id,
                    &lease_token,
                )
                .await;
                let _ = crate::database::signing_nonce::insert_bip448_signing_nonce_lease(
                    &mut *handoff_fence,
                    &payload.statechain_id,
                    &incomplete.signing_id,
                )
                .await;
                return incomplete_round_response(incomplete);
            }

            crate::database::signing_nonce::delete_bip448_signing_nonce_lease_by_token(
                &mut *handoff_fence,
                &payload.statechain_id,
                &signing_id,
                &lease_token,
            )
            .await;

            return error_response(
                Status::Conflict,
                "BIP448 signing reservation was concurrently created; retry the request"
                    .to_string(),
            );
        }

        let path = "bip448/get_public_nonce";

        if !crate::database::signing_nonce::bip448_signing_nonce_lease_matches(
            &mut *handoff_fence,
            &payload.statechain_id,
            &signing_id,
            &lease_token,
        )
        .await
        {
            cleanup_bip448_sign_first_reservation(
                &mut *handoff_fence,
                &payload.statechain_id,
                &signing_id,
                &lease_token,
            )
            .await;
            return pending_nonce_response();
        }

        let lockbox_payload = Bip448LockboxSignFirstRequestPayloadV1 {
            statechain_id,
            signing_id: lockbox_signing_id,
            expected_key_generation: lockbox_state.key_generation,
            expected_server_pubkey: lockbox_state.server_pubkey,
        };
        let value = match statechain_entity
            .lockboxes
            .post_json_raw(enclave_index, path, &lockbox_payload)
            .await
        {
            Ok(response) => match lockbox_response_text(response) {
                Ok(text) => text,
                Err(response) => {
                    cleanup_bip448_sign_first_reservation(
                        &mut *handoff_fence,
                        &payload.statechain_id,
                        &signing_id,
                        &lease_token,
                    )
                    .await;
                    return response;
                }
            },
            Err(error) => {
                cleanup_bip448_sign_first_reservation(
                    &mut *handoff_fence,
                    &payload.statechain_id,
                    &signing_id,
                    &lease_token,
                )
                .await;
                log::error!("Lockbox sign-first request failed: {error}");
                return signing_enclave_failure();
            }
        };

        let response: Bip448SignFirstResponsePayload = match serde_json::from_str(value.as_str()) {
            Ok(response) => response,
            Err(error) => {
                cleanup_bip448_sign_first_reservation(
                    &mut *handoff_fence,
                    &payload.statechain_id,
                    &signing_id,
                    &lease_token,
                )
                .await;
                log::error!("failed to parse Lockbox sign-first response: {error}");
                return signing_enclave_failure();
            }
        };

        let server_pubnonce_hex = normalize_hex_wire_value(&response.server_pubnonce);

        let updated =
        crate::database::bip448_sign::update_bip448_signature_data_server_pubnonce_if_lease_matches(
            &mut *handoff_fence,
            &payload.statechain_id,
            &signing_id,
            &server_pubnonce_hex,
            &lease_token,
        )
        .await;

        if !updated {
            cleanup_bip448_sign_first_reservation(
                &mut *handoff_fence,
                &payload.statechain_id,
                &signing_id,
                &lease_token,
            )
            .await;
            return error_response(
                Status::Conflict,
                "BIP448 signing nonce lease expired; retry sign/first".to_string(),
            );
        }

        let response = Bip448SignFirstResponsePayload {
            server_pubnonce: server_pubnonce_hex,
        };

        status::Custom(Status::Ok, Json(json!(response)))
    }
    .await;

    if handoff_fence.commit().await.is_err() {
        return error_response(
            Status::InternalServerError,
            "Failed to commit BIP448 sign/first metadata.".to_string(),
        );
    }
    response
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
    let mut payload = partial_signature_request_payload.0;
    let statechain_entity = statechain_entity.inner();

    let signing_id = match validate_signing_id(&payload.signing_id) {
        Ok(signing_id) => signing_id,
        Err(err) => return error_response(Status::UnprocessableEntity, err.to_string()),
    };

    let negate_seckey = match validate_negate_seckey_flag(payload.negate_seckey) {
        Ok(flag) => flag,
        Err(err) => return error_response(Status::UnprocessableEntity, err.to_string()),
    };

    let challenge = match challenge_from_session_hex(&payload.session) {
        Some(challenge) => challenge,
        None => {
            return error_response(
                Status::UnprocessableEntity,
                "session is not a valid 133-byte hex blinded MuSig session".to_string(),
            );
        }
    };
    payload.session.make_ascii_lowercase();
    payload.server_pub_nonce = normalize_hex_wire_value(&payload.server_pub_nonce);
    let statechain_id = match Bip448StatechainId::try_from(payload.statechain_id.as_str()) {
        Ok(statechain_id) => statechain_id,
        Err(err) => return error_response(Status::UnprocessableEntity, err.to_string()),
    };
    let lockbox_signing_id = match Bip448SigningId::try_from(signing_id.as_str()) {
        Ok(signing_id) => signing_id,
        Err(err) => return error_response(Status::UnprocessableEntity, err.to_string()),
    };
    let lockbox_negate_seckey = match Bip448NegateSeckeyFlag::try_from(payload.negate_seckey) {
        Ok(flag) => flag,
        Err(err) => return error_response(Status::UnprocessableEntity, err.to_string()),
    };
    let lockbox_session = match Bip448BlindedSession::try_from(payload.session.as_str()) {
        Ok(session) => session,
        Err(err) => return error_response(Status::UnprocessableEntity, err.to_string()),
    };
    let lockbox_server_pub_nonce =
        match Bip448PublicNonce::try_from(payload.server_pub_nonce.as_str()) {
            Ok(nonce) => nonce,
            Err(err) => return error_response(Status::UnprocessableEntity, err.to_string()),
        };

    // The inner flow produces the response while this transaction remains the
    // handoff fence; its Mercury metadata is committed and the lock released
    // exactly once after any lockbox call has completed.
    let mut handoff_fence = match statechain_entity.pool.begin().await {
        Ok(transaction) => transaction,
        Err(err) => return error_response(Status::InternalServerError, err.to_string()),
    };
    let locked = match crate::database::transfer_receiver::lock_statechain_generation(
        &mut *handoff_fence,
        statechain_id.as_str(),
    )
    .await
    {
        Ok(Some(locked)) => locked,
        Ok(None) => {
            return error_response(
                Status::NotFound,
                format!("statechain {} not found", statechain_id.as_str()),
            );
        }
        Err(err) => return error_response(Status::InternalServerError, err.to_string()),
    };
    if let Err(response) = validate_locked_bip448_auth(
        &locked,
        &payload.signed_statechain_id,
        statechain_id.as_str(),
    ) {
        return response;
    }

    let existing = crate::database::bip448_sign::get_bip448_signature_record(
        &mut *handoff_fence,
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

    let response = async {
    let retry_claimed_challenge = matches!(&sign_second_decision, SignSecondDecision::RetryClaimed);

    match sign_second_decision {
        SignSecondDecision::Replay { server_partial_sig } => {
            if let Err(response) =
                observe_locked_bip448_state(statechain_entity, &statechain_id, &locked).await
            {
                return response;
            }
            return replay_bip448_partial_signature(
                &mut *handoff_fence,
                &payload.statechain_id,
                &signing_id,
                server_partial_sig,
            )
            .await;
        }
        SignSecondDecision::Proceed => {}
        SignSecondDecision::RetryClaimed => {}
        SignSecondDecision::NotFound | SignSecondDecision::Conflict { .. } => unreachable!(),
    };

    if let Some(lease_signing_id) = crate::database::signing_nonce::get_bip448_signing_nonce_lease(
        &mut *handoff_fence,
        &payload.statechain_id,
    )
    .await
    {
        if lease_signing_id != signing_id {
            return pending_nonce_response();
        }
    } else {
        let lease_token = crate::database::signing_nonce::insert_bip448_signing_nonce_lease(
            &mut *handoff_fence,
            &payload.statechain_id,
            &signing_id,
        )
        .await;

        if lease_token.is_none() {
            return pending_nonce_response();
        }
    }

    if !retry_claimed_challenge {
        let claimed = crate::database::bip448_sign::try_claim_bip448_signature_data_challenge(
            &mut *handoff_fence,
            &payload.statechain_id,
            &signing_id,
            &payload.server_pub_nonce,
            &challenge,
            negate_seckey,
        )
        .await;

        if !claimed {
            let existing = crate::database::bip448_sign::get_bip448_signature_record(
                &mut *handoff_fence,
                &payload.statechain_id,
                &signing_id,
            )
            .await;

            match classify_sign_second(
                existing.as_ref(),
                &payload.server_pub_nonce,
                &challenge,
                negate_seckey,
            ) {
                SignSecondDecision::Replay { server_partial_sig } => {
                    return replay_bip448_partial_signature(
                        &mut *handoff_fence,
                        &payload.statechain_id,
                        &signing_id,
                        server_partial_sig,
                    )
                    .await;
                }
                SignSecondDecision::NotFound => {
                    return error_response(
                        Status::NotFound,
                        "no BIP448 signature record for signing_id; call sign/first first"
                            .to_string(),
                    )
                }
                SignSecondDecision::Conflict { reason } => {
                    return error_response(Status::Conflict, reason.to_string())
                }
                SignSecondDecision::Proceed => {
                    return error_response(
                        Status::Conflict,
                        "BIP448 signing challenge was concurrently claimed; retry after the partial signature is available".to_string(),
                    )
                }
                SignSecondDecision::RetryClaimed => {
                    // The lockbox owns BIP448 nonce-use authority. Ask it for
                    // exact replay instead of clearing or reopening the claim.
                }
            };
        }
    }
    let (enclave_index, lockbox_state) =
        match observe_locked_bip448_state(statechain_entity, &statechain_id, &locked).await {
            Ok(observed) => observed,
            Err(response) => return response,
        };
    let path = "bip448/get_partial_signature";

    // Once this request is attempted, failures are indeterminate from
    // Mercury's point of view. The lockbox is authoritative for BIP448 exact
    // replay/conflict by opaque signing_id; Mercury must not clear/reopen the
    // challenge after this point.
    let lockbox_payload = Bip448LockboxPartialSignatureRequestPayloadV1 {
        statechain_id,
        signing_id: lockbox_signing_id,
        negate_seckey: lockbox_negate_seckey,
        session: lockbox_session,
        server_pub_nonce: lockbox_server_pub_nonce,
        expected_key_generation: lockbox_state.key_generation,
        expected_server_pubkey: lockbox_state.server_pubkey,
    };
    let value = match statechain_entity
        .lockboxes
        .post_json_raw(enclave_index, path, &lockbox_payload)
        .await
    {
        Ok(response) => match lockbox_response_text(response) {
            Ok(text) => text,
            Err(response) => return response,
        },
        Err(error) => {
            log::error!("Lockbox sign-second request failed: {error}");
            return signing_enclave_failure();
        }
    };

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct PartialSignatureResponsePayload<'r> {
        partial_sig: &'r str,
    }

    let response: PartialSignatureResponsePayload = match serde_json::from_str(value.as_str()) {
        Ok(response) => response,
        Err(error) => {
            log::error!("failed to parse Lockbox sign-second response: {error}");
            return signing_enclave_failure();
        }
    };

    let updated = crate::database::bip448_sign::update_bip448_signature_data_partial_sig(
        &mut *handoff_fence,
        &payload.statechain_id,
        &signing_id,
        &challenge,
        response.partial_sig,
    )
    .await;

    if !updated {
        let existing = crate::database::bip448_sign::get_bip448_signature_record(
            &mut *handoff_fence,
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
                replay_bip448_partial_signature(
                    &mut *handoff_fence,
                    &payload.statechain_id,
                    &signing_id,
                    server_partial_sig,
                )
                .await
            }
            SignSecondDecision::NotFound => error_response(
                Status::NotFound,
                "no BIP448 signature record for signing_id; call sign/first first".to_string(),
            ),
            SignSecondDecision::Conflict { reason } => {
                error_response(Status::Conflict, reason.to_string())
            }
            SignSecondDecision::Proceed | SignSecondDecision::RetryClaimed => error_response(
                Status::InternalServerError,
                "BIP448 partial signature was returned by the lockbox but Mercury could not persist it; exact retry can recover from the lockbox".to_string(),
            ),
        };
    }

    crate::database::signing_nonce::delete_bip448_signing_nonce_lease(
        &mut *handoff_fence,
        &payload.statechain_id,
        &signing_id,
    )
    .await;

        status::Custom(Status::Ok, Json(json!(response)))
    }
    .await;

    if handoff_fence.commit().await.is_err() {
        return error_response(
            Status::InternalServerError,
            "Failed to commit BIP448 sign/second metadata.".to_string(),
        );
    }
    response
}

#[get("/bip448-statechain/signature-count/<statechain_id>")]
pub async fn bip448_signature_count(
    statechain_entity: &State<StateChainEntity>,
    statechain_id: &str,
) -> status::Custom<Json<Value>> {
    let statechain_entity = statechain_entity.inner();
    let config = &statechain_entity.config;

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

    if config.enclaves.get(enclave_index).is_none() {
        return error_response(
            Status::InternalServerError,
            format!("Enclave index {} is not configured.", enclave_index),
        );
    }

    let value = match statechain_entity
        .lockboxes
        .get_raw(enclave_index, &format!("/signature_count/{statechain_id}"))
        .await
    {
        Ok(response) => match lockbox_response_text(response) {
            Ok(text) => text,
            Err(response) => return response,
        },
        Err(error) => {
            log::error!("Lockbox signature-count request failed: {error}");
            return signing_enclave_failure();
        }
    };

    let sig_count = match parse_lockbox_signature_count(value.as_str()) {
        Ok(sig_count) => sig_count,
        Err(error) => {
            log::error!("failed to parse Lockbox signature-count response: {error}");
            return signing_enclave_failure();
        }
    };

    let response = Bip448SignatureCountResponsePayload { sig_count };

    status::Custom(Status::Ok, Json(json!(response)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::{sha256, Hash};
    use secp256k1::{schnorr, KeyPair, Secp256k1, SecretKey};

    const SIGNING_ID: &str = "aa11955b1327167cb7ae3dc39d52c277be39d75737b9cb80514ce6e825fd8eea";

    #[test]
    fn signing_authentication_uses_the_locked_owner_key() {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_secret_bytes([0x41; 32]).unwrap();
        let keypair = KeyPair::from_secret_key(&secp, &secret);
        let statechain_id = "locked-owner-statechain";
        let digest = sha256::Hash::hash(statechain_id.as_bytes()).to_byte_array();
        let signature = schnorr::sign(&digest, &keypair).to_string();
        let locked = crate::database::transfer_receiver::LockedStatechainGeneration {
            auth_xonly_public_key: keypair.x_only_public_key().0.serialize().to_vec(),
            server_public_key: secret.public_key(&secp).serialize().to_vec(),
            enclave_index: 0,
        };

        assert!(validate_locked_bip448_auth(&locked, &signature, statechain_id).is_ok());
        assert_eq!(
            validate_locked_bip448_auth(&locked, &signature, "different-statechain")
                .unwrap_err()
                .0,
            Status::Unauthorized
        );
    }

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
    fn sign_second_normalizes_server_pubnonce_before_matching() {
        let fresh = record(Some("abcdef"), None, None, None);
        assert_eq!(
            classify_sign_second(Some(&fresh), "0xABCDEF", "challenge-1", true),
            SignSecondDecision::Proceed
        );

        let completed = record(
            Some("abcdef"),
            Some("challenge-1"),
            Some(true),
            Some("partial-1"),
        );
        assert_eq!(
            classify_sign_second(Some(&completed), "0XABCDEF", "challenge-1", true),
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
        let session = "9dede917000000000000000000000000000000000000000000000000000000000000000000b59faf7e0a44057b41d273e70cc0a59194347b286c8108fef3519bb52fe64b0729641b33afc4d71464ccde0ca4b0471ed2fda81a39056745ed7b1f4f90790dfd3ee2e8c6c5937a7f4dd30e9e78ec2096433ff32ea89ffca29a40b02b03b4e7eb";

        assert_eq!(
            challenge_from_session_hex(session).unwrap(),
            "29641b33afc4d71464ccde0ca4b0471ed2fda81a39056745ed7b1f4f90790dfd"
        );
    }

    #[test]
    fn validated_signing_ids_canonicalize_hex_case() {
        let validated = validate_signing_id(&SIGNING_ID.to_uppercase()).unwrap();

        assert_eq!(validated, SIGNING_ID);
    }

    #[test]
    fn parse_lockbox_signature_count_accepts_valid_json() {
        let sig_count = parse_lockbox_signature_count(r#"{"sig_count":3}"#).unwrap();

        assert_eq!(sig_count, 3);
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
    fn lockbox_status_maps_signature_count_not_found_to_not_found() {
        assert_eq!(lockbox_status_to_rocket(404), Status::NotFound);
    }
}
