use std::{
    str::FromStr,
    time::{Duration, Instant},
};

use crate::{server::StateChainEntity, server_config::Enclave};
use bitcoin::hashes::{sha256, Hash};
use rocket::{http::Status, response::status, serde::json::Json, State};
use secp256k1::{
    schnorr::{self, Signature},
    PublicKey, XOnlyPublicKey,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::outbound_request_timeout;

fn deposit_internal_error(message: String) -> status::Custom<Json<Value>> {
    status::Custom(
        Status::InternalServerError,
        Json(json!({
            "error": "Internal Server Error",
            "message": message,
        })),
    )
}

fn token_status_error(status: Status, message: String) -> TokenStatusResponse {
    TokenStatusResponse {
        confirmed: false,
        spent: false,
        err: true,
        status: Some(status),
        err_message: Some(message),
    }
}

fn token_verify_upstream_error(
    response_status: reqwest::StatusCode,
    text: String,
) -> TokenStatusResponse {
    token_status_error(
        Status::InternalServerError,
        format!(
            "token server token_verify returned {}: {}",
            response_status.as_u16(),
            text
        ),
    )
}

pub async fn get_token_no_server(
    statechain_entity: &State<StateChainEntity>,
    config: &crate::server_config::ServerConfig,
) -> status::Custom<Json<Value>> {
    if config.network == "mainnet" {
        let response_body = json!({
            "error": "Internal Server Error",
            "message": "Token generation not supported on mainnet."
        });

        return status::Custom(Status::InternalServerError, Json(response_body));
    }

    let token_id = uuid::Uuid::new_v4().to_string();

    crate::database::deposit::insert_new_token(&statechain_entity.pool, &token_id).await;

    let token = mercurylib::deposit::TokenResponse {
        token_id,
        payment_method: "free".to_string(),
        deposit_address: None,
        fee: 0,
        confirmation_target: 0,
    };

    let response_body = json!(token);

    status::Custom(Status::Ok, Json(response_body))
}

pub async fn get_token_from_server(
    config: &crate::server_config::ServerConfig,
    client: &reqwest::Client,
) -> status::Custom<Json<Value>> {
    let request = client
        .get(format!(
            "{}/token/token_gen",
            config.token_server_url.as_ref().unwrap()
        ))
        .timeout(outbound_request_timeout());

    let value = match request.send().await {
        Ok(response) => {
            let response_status = response.status();
            let text = match response.text().await {
                Ok(text) => text,
                Err(err) => return deposit_internal_error(err.to_string()),
            };

            if !response_status.is_success() {
                return deposit_internal_error(format!(
                    "token server token_gen returned {}: {}",
                    response_status.as_u16(),
                    text
                ));
            }

            text
        }
        Err(err) => {
            let response_body = json!({
                "message": err.to_string()
            });

            let status = err
                .status()
                .and_then(|status| Status::from_code(status.as_u16()))
                .unwrap_or(Status::InternalServerError);

            return status::Custom(status, Json(response_body));
        }
    };

    let response: serde_json::Value = match serde_json::from_str(value.as_str()) {
        Ok(response) => response,
        Err(err) => {
            return deposit_internal_error(format!(
                "failed to parse token server token_gen response: {err}"
            ))
        }
    };

    let (token_id, deposit_address, fee, confirmation_target) = match (
        response.get("token_id").and_then(|v| v.as_str()),
        response.get("deposit_address").and_then(|v| v.as_str()),
        response.get("fee").and_then(|v| v.as_u64()),
        response.get("confirmation_target").and_then(|v| v.as_u64()),
    ) {
        (Some(token_id), Some(deposit_address), Some(fee), Some(confirmation_target)) => (
            token_id.to_string(),
            deposit_address.to_string(),
            fee,
            confirmation_target,
        ),
        _ => {
            return deposit_internal_error(
                "token server token_gen response is missing expected fields".to_string(),
            )
        }
    };

    let token = mercurylib::deposit::TokenResponse {
        token_id,
        payment_method: "onchain".to_string(),
        deposit_address: Some(deposit_address),
        fee,
        confirmation_target,
    };

    let response_body = json!(token);

    status::Custom(Status::Ok, Json(response_body))
}

#[get("/deposit/get_token")]
pub async fn get_token(statechain_entity: &State<StateChainEntity>) -> status::Custom<Json<Value>> {
    let config = crate::server_config::ServerConfig::load();

    if config.token_server_url.is_none() {
        return get_token_no_server(statechain_entity, &config).await;
    } else {
        return get_token_from_server(&config, &statechain_entity.inner().http_client).await;
    }
}

fn select_deposit_enclave(statechain_id: &str, enclaves: &[Enclave]) -> Result<usize, String> {
    if enclaves.is_empty() {
        return Err("No Lockbox enclaves are configured".to_string());
    }

    let selected = get_enclave_index_from_statechain_id(statechain_id, enclaves.len() as u32);
    if enclaves[selected].allow_deposit {
        return Ok(selected);
    }

    enclaves
        .iter()
        .position(|enclave| enclave.allow_deposit)
        .ok_or_else(|| "No valid enclave found with allow_deposit set to true".to_string())
}

fn get_enclave_index_from_statechain_id(statechain_id: &str, enclave_array_len: u32) -> usize {
    let hash = sha256::Hash::hash(statechain_id.as_bytes());
    let hash_bytes = hash.as_byte_array();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash_bytes[..16]);
    let random_number = u128::from_be_bytes(bytes);

    (random_number % enclave_array_len as u128) as usize
}

struct TokenStatusResponse {
    confirmed: bool,
    spent: bool,
    err: bool,
    status: Option<Status>,
    err_message: Option<String>,
}

async fn check_token_status(
    token_server_url: Option<&str>,
    token_id: &str,
    client: &reqwest::Client,
) -> TokenStatusResponse {
    let Some(token_server_url) = token_server_url else {
        return TokenStatusResponse {
            confirmed: false,
            spent: false,
            err: false,
            status: None,
            err_message: None,
        };
    };

    let request = client
        .get(format!(
            "{}/token/token_verify/{}",
            token_server_url, token_id
        ))
        .timeout(outbound_request_timeout());

    let value = match request.send().await {
        Ok(response) => {
            let response_status = response.status();
            let text = match response.text().await {
                Ok(text) => text,
                Err(err) => {
                    return token_status_error(Status::InternalServerError, err.to_string())
                }
            };

            if !response_status.is_success() {
                return token_verify_upstream_error(response_status, text);
            }

            text
        }
        Err(err) => {
            let message = err.to_string();

            let status = err
                .status()
                .and_then(|status| Status::from_code(status.as_u16()))
                .unwrap_or(Status::InternalServerError);

            return token_status_error(status, message);
        }
    };

    let response: serde_json::Value = match serde_json::from_str(value.as_str()) {
        Ok(response) => response,
        Err(err) => {
            return token_status_error(
                Status::InternalServerError,
                format!("failed to parse token server token_verify response: {err}"),
            )
        }
    };

    let (confirmed, spent) = match (
        response.get("confirmed").and_then(|v| v.as_bool()),
        response.get("spent").and_then(|v| v.as_bool()),
    ) {
        (Some(confirmed), Some(spent)) => (confirmed, spent),
        _ => {
            return token_status_error(
                Status::InternalServerError,
                "token server token_verify response is missing confirmed/spent".to_string(),
            )
        }
    };

    TokenStatusResponse {
        confirmed,
        spent,
        err: false,
        status: None,
        err_message: None,
    }
}

#[derive(Debug, Serialize)]
struct GetPublicKeyRequestPayload {
    statechain_id: String,
}

#[derive(Debug, Deserialize)]
struct StorageTimingPayload {
    open: u64,
    transaction: u64,
    read: u64,
    insert: u64,
    commit: u64,
}

#[derive(Debug, Deserialize)]
struct GetPublicKeyResponsePayload {
    server_pubkey: String,
    #[serde(default)]
    storage_outcome: Option<String>,
    #[serde(default)]
    key_generation_us: Option<u64>,
    #[serde(default)]
    storage_timing_us: Option<StorageTimingPayload>,
}

#[derive(Debug, Deserialize)]
struct ObservedPublicKeyPayload {
    statechain_id: String,
    server_pubkey: String,
}

#[derive(Clone, Copy)]
struct DepositKeyRequestPolicy {
    request_timeout: Duration,
    recovery_timeout: Duration,
    retry_timeout: Duration,
    observation_window: Duration,
    observation_attempt_timeout: Duration,
    observation_delay: Duration,
    observation_max_delay: Duration,
}

// The deployed Lockbox can take about 33 seconds to durably finish a cold key
// request. This 53-second worst-case budget stays below the 60-second ingress
// and 65-second browser request ceilings.
const DEPOSIT_KEY_REQUEST_POLICY: DepositKeyRequestPolicy = DepositKeyRequestPolicy {
    request_timeout: Duration::from_secs(5),
    recovery_timeout: Duration::from_secs(3),
    retry_timeout: Duration::from_secs(5),
    observation_window: Duration::from_secs(40),
    observation_attempt_timeout: Duration::from_secs(3),
    observation_delay: Duration::from_millis(250),
    observation_max_delay: Duration::from_secs(2),
};

async fn observe_deposit_public_key(
    lockboxes: &crate::lockbox_client::LockboxClients,
    enclave_index: usize,
    statechain_id: &str,
    attempt_timeout: Duration,
) -> Result<Option<GetPublicKeyResponsePayload>, String> {
    let response = lockboxes
        .get_raw_once(
            enclave_index,
            &format!("/bip448/state/{statechain_id}"),
            attempt_timeout,
        )
        .await
        .map_err(|error| error.to_string())?;
    if response.status == 404 || response.status == 409 {
        return Ok(None);
    }
    if response.status != 200 {
        return Err(format!(
            "Lockbox state observation returned {}: {}",
            response.status, response.body
        ));
    }
    let observed: ObservedPublicKeyPayload =
        serde_json::from_str(&response.body).map_err(|error| error.to_string())?;
    if observed.statechain_id != statechain_id {
        return Err("Lockbox state observation returned a different statechain ID".to_string());
    }
    Ok(Some(GetPublicKeyResponsePayload {
        server_pubkey: observed.server_pubkey,
        storage_outcome: None,
        key_generation_us: None,
        storage_timing_us: None,
    }))
}

fn log_key_storage_diagnostics(
    enclave_index: usize,
    statechain_id: &str,
    response: &GetPublicKeyResponsePayload,
) {
    if let Some(timings) = &response.storage_timing_us {
        log::info!(
            "Lockbox generated key for statechain {statechain_id} on enclave {enclave_index}: \
             outcome={} key_generation_us={} storage_us={{open:{},transaction:{},read:{},\
             insert:{},commit:{}}}",
            response.storage_outcome.as_deref().unwrap_or("unreported"),
            response.key_generation_us.unwrap_or_default(),
            timings.open,
            timings.transaction,
            timings.read,
            timings.insert,
            timings.commit,
        );
    }
}

async fn request_deposit_public_key(
    lockboxes: &crate::lockbox_client::LockboxClients,
    enclave_index: usize,
    payload: &GetPublicKeyRequestPayload,
) -> Result<GetPublicKeyResponsePayload, String> {
    request_deposit_public_key_with_policy(
        lockboxes,
        enclave_index,
        payload,
        DEPOSIT_KEY_REQUEST_POLICY,
    )
    .await
}

async fn request_deposit_public_key_with_policy(
    lockboxes: &crate::lockbox_client::LockboxClients,
    enclave_index: usize,
    payload: &GetPublicKeyRequestPayload,
    policy: DepositKeyRequestPolicy,
) -> Result<GetPublicKeyResponsePayload, String> {
    let request = lockboxes
        .post_json_once(
            enclave_index,
            "/get_public_key",
            payload,
            policy.request_timeout,
        )
        .await;
    let request_error = match request {
        Ok(response) => {
            log_key_storage_diagnostics(enclave_index, &payload.statechain_id, &response);
            return Ok(response);
        }
        Err(error) => error.to_string(),
    };

    log::warn!(
        "Lockbox key request failed: {request_error}; recovering the attested channel before an \
         exact idempotent retry"
    );
    let recovery_error = match rocket::tokio::time::timeout(
        policy.recovery_timeout,
        lockboxes.recover_attested_session(enclave_index),
    )
    .await
    {
        Ok(Ok(())) => None,
        Ok(Err(error)) => {
            let error = error.to_string();
            log::warn!("Lockbox attested channel recovery failed before key retry: {error}");
            Some(error)
        }
        Err(_) => {
            let error = format!(
                "timed out after {:.3}s",
                policy.recovery_timeout.as_secs_f64()
            );
            log::warn!("Lockbox attested channel recovery {error} before key retry");
            Some(error)
        }
    };

    let retry = lockboxes
        .post_json_once(
            enclave_index,
            "/get_public_key",
            payload,
            policy.retry_timeout,
        )
        .await;
    let retry_error = match retry {
        Ok(response) => {
            log_key_storage_diagnostics(enclave_index, &payload.statechain_id, &response);
            return Ok(response);
        }
        Err(error) => error.to_string(),
    };
    log::warn!(
        "Exact Lockbox key retry failed: {retry_error}; observing durable state without another \
         mutation"
    );

    let deadline = Instant::now() + policy.observation_window;
    let mut last_observation_error = None;
    let mut observation_delay = policy.observation_delay.min(policy.observation_max_delay);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let attempt_timeout = policy.observation_attempt_timeout.min(remaining);
        match observe_deposit_public_key(
            lockboxes,
            enclave_index,
            &payload.statechain_id,
            attempt_timeout,
        )
        .await
        {
            Ok(Some(observed)) => return Ok(observed),
            Ok(None) => {}
            Err(error) => {
                log::warn!("Lockbox durable key observation failed: {error}");
                last_observation_error = Some(error);
            }
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        rocket::tokio::time::sleep(observation_delay.min(remaining)).await;
        observation_delay = observation_delay
            .saturating_mul(2)
            .min(policy.observation_max_delay);
    }

    let recovery_detail = recovery_error
        .map(|error| format!("; channel recovery failed: {error}"))
        .unwrap_or_default();
    let observation_detail = last_observation_error
        .map(|error| format!("; last durable state observation failed: {error}"))
        .unwrap_or_default();
    Err(format!(
        "Lockbox key request failed: {request_error}; exact retry failed: {retry_error}\
         {recovery_detail}; no durable key was observed{observation_detail}"
    ))
}

fn parse_deposit_authorization(
    auth_key: &str,
    signed_token_id: &str,
) -> Result<(XOnlyPublicKey, Signature), String> {
    let auth_key = XOnlyPublicKey::from_str(auth_key)
        .map_err(|_| "Authentication key is invalid.".to_string())?;
    let signed_token_id = Signature::from_str(signed_token_id)
        .map_err(|_| "Token signature is invalid.".to_string())?;
    Ok((auth_key, signed_token_id))
}

fn completed_deposit_response(
    server_public_key: &[u8],
    statechain_id: &str,
) -> status::Custom<Json<Value>> {
    let server_public_key = match PublicKey::from_slice(server_public_key) {
        Ok(key) => key,
        Err(error) => {
            log::error!("stored deposit server public key is malformed: {error}");
            return deposit_internal_error(
                "Stored deposit server public key is malformed.".to_string(),
            );
        }
    };
    status::Custom(
        Status::Ok,
        Json(json!(mercurylib::deposit::DepositMsg1Response {
            server_pubkey: server_public_key.to_string(),
            statechain_id: statechain_id.to_owned(),
        })),
    )
}

fn deposit_initialization_matches_auth(
    initialization: &crate::database::deposit::DepositInitialization,
    auth_key: &XOnlyPublicKey,
) -> bool {
    initialization.auth_xonly_public_key.as_slice() == auth_key.serialize().as_slice()
}

async fn completed_deposit_replay_response(
    statechain_entity: &StateChainEntity,
    initialization: &crate::database::deposit::DepositInitialization,
) -> status::Custom<Json<Value>> {
    let Some(server_public_key) = initialization.server_public_key.as_deref() else {
        return deposit_internal_error(
            "Completed deposit initialization has no server public key.".to_string(),
        );
    };
    match crate::database::deposit::completed_deposit_is_current(
        &statechain_entity.pool,
        initialization,
    )
    .await
    {
        Ok(true) => completed_deposit_response(server_public_key, &initialization.statechain_id),
        Ok(false) => status::Custom(
            Status::Conflict,
            Json(json!({
                "message": "The completed deposit no longer matches current statecoin ownership."
            })),
        ),
        Err(error) => {
            log::error!("failed to validate completed deposit replay: {error}");
            deposit_internal_error("Failed to validate completed deposit replay.".to_string())
        }
    }
}

#[post("/deposit/init/pod", format = "json", data = "<deposit_msg1>")]
pub async fn post_deposit(
    statechain_entity: &State<StateChainEntity>,
    deposit_msg1: Json<mercurylib::deposit::DepositMsg1>,
) -> status::Custom<Json<Value>> {
    let statechain_entity = statechain_entity.inner();
    let token_id = deposit_msg1.token_id.clone();

    let signed_token_id = deposit_msg1.signed_token_id.to_string();
    let (auth_key, signed_token_id) =
        match parse_deposit_authorization(&deposit_msg1.auth_key, &signed_token_id) {
            Ok(authorization) => authorization,
            Err(message) => {
                return status::Custom(Status::BadRequest, Json(json!({ "message": message })));
            }
        };

    let digest = sha256::Hash::hash(token_id.as_bytes()).to_byte_array();
    if schnorr::verify(&signed_token_id, &digest, &auth_key).is_err() {
        let response_body = json!({
            "message": "Signature does not match authentication key."
        });

        return status::Custom(Status::InternalServerError, Json(response_body));
    }

    let pending_deposit = match crate::database::deposit::get_deposit_initialization(
        &statechain_entity.pool,
        &token_id,
    )
    .await
    {
        Ok(Some(existing)) => {
            if !deposit_initialization_matches_auth(&existing, &auth_key) {
                return status::Custom(
                    Status::Conflict,
                    Json(json!({
                        "message": "The token is reserved for a different deposit authorization."
                    })),
                );
            }
            if existing.completed {
                return completed_deposit_replay_response(statechain_entity, &existing).await;
            }
            Some(existing)
        }
        Ok(None) => None,
        Err(error) => {
            log::error!("failed to load deposit initialization: {error}");
            return deposit_internal_error("Failed to load deposit initialization.".to_string());
        }
    };

    let token_info =
        crate::database::deposit::get_token_info(&statechain_entity.pool, &token_id).await;

    if token_info.is_none() {
        let response_body = json!({
            "error": "Deposit Error",
            "message": "Token ID not found."
        });

        return status::Custom(Status::NotFound, Json(response_body));
    }

    let token_info = token_info.unwrap();

    if token_info.spent {
        match crate::database::deposit::get_deposit_initialization(
            &statechain_entity.pool,
            &token_id,
        )
        .await
        {
            Ok(Some(existing))
                if deposit_initialization_matches_auth(&existing, &auth_key)
                    && existing.completed =>
            {
                return completed_deposit_replay_response(statechain_entity, &existing).await;
            }
            Ok(Some(existing)) if deposit_initialization_matches_auth(&existing, &auth_key) => {
                return deposit_internal_error(
                    "A spent token has an incomplete deposit initialization.".to_string(),
                );
            }
            Ok(_) => {}
            Err(error) => {
                log::error!("failed to recheck completed deposit: {error}");
                return deposit_internal_error("Failed to recheck completed deposit.".to_string());
            }
        }
        return status::Custom(
            Status::Gone,
            Json(json!({ "message": "Token already spent." })),
        );
    }

    if !token_info.confirmed {
        let token_status_response = check_token_status(
            statechain_entity.config.token_server_url.as_deref(),
            &token_id,
            &statechain_entity.http_client,
        )
        .await;

        if token_status_response.err {
            let response_body = json!({
                "message": token_status_response.err_message.unwrap()
            });

            return status::Custom(token_status_response.status.unwrap(), Json(response_body));
        }

        if token_status_response.spent {
            let response_body = json!({
                "message": "Token already spent."
            });

            return status::Custom(Status::Gone, Json(response_body));
        }

        if !token_status_response.confirmed {
            let response_body = json!({
                "message": "Token not confirmed."
            });

            return status::Custom(Status::Gone, Json(response_body));
        }
    }

    let reservation = match pending_deposit {
        Some(existing) => existing,
        None => {
            let candidate_statechain_id = uuid::Uuid::new_v4().as_simple().to_string();
            let candidate_enclave_index = match select_deposit_enclave(
                &candidate_statechain_id,
                &statechain_entity.config.enclaves,
            ) {
                Ok(index) => index,
                Err(error) => {
                    log::error!("no Lockbox accepts deposits: {error}");
                    return status::Custom(
                        Status::ServiceUnavailable,
                        Json(json!({
                            "message": "No signing enclave is available for deposits."
                        })),
                    );
                }
            };
            let candidate_enclave_index_i32 = match i32::try_from(candidate_enclave_index) {
                Ok(index) => index,
                Err(_) => {
                    log::error!("selected Lockbox index does not fit in the database");
                    return deposit_internal_error(
                        "Selected signing enclave index is invalid.".to_string(),
                    );
                }
            };
            match crate::database::deposit::reserve_deposit_initialization(
                &statechain_entity.pool,
                &token_id,
                &auth_key,
                &candidate_statechain_id,
                candidate_enclave_index_i32,
            )
            .await
            {
                Ok(existing) => existing,
                Err(error) => {
                    log::error!("failed to reserve deposit initialization: {error}");
                    return deposit_internal_error(
                        "Failed to reserve deposit initialization.".to_string(),
                    );
                }
            }
        }
    };

    if !deposit_initialization_matches_auth(&reservation, &auth_key) {
        return status::Custom(
            Status::Conflict,
            Json(json!({
                "message": "The token is reserved for a different deposit authorization."
            })),
        );
    }
    if reservation.completed {
        return completed_deposit_replay_response(statechain_entity, &reservation).await;
    }
    let enclave_index = match usize::try_from(reservation.enclave_index) {
        Ok(index) if index < statechain_entity.lockboxes.len() => index,
        _ => {
            log::error!(
                "deposit reservation references unavailable Lockbox index {}",
                reservation.enclave_index
            );
            return deposit_internal_error("Reserved signing enclave is unavailable.".to_string());
        }
    };
    let statechain_id = reservation.statechain_id;

    let payload = GetPublicKeyRequestPayload {
        statechain_id: statechain_id.clone(),
    };

    let response = match request_deposit_public_key(
        &statechain_entity.lockboxes,
        enclave_index,
        &payload,
    )
    .await
    {
        Ok(response) => response,
        Err(error) => {
            log::error!("get_public_key failed for Lockbox enclave {enclave_index}: {error}");
            return status::Custom(
                Status::BadGateway,
                Json(json!({
                    "message": "Signing enclave did not complete the deposit request. Retry the pending deposit."
                })),
            );
        }
    };

    let server_pubkey_hex = response
        .server_pubkey
        .strip_prefix("0x")
        .unwrap_or(&response.server_pubkey);
    let server_pubkey = match PublicKey::from_str(server_pubkey_hex) {
        Ok(server_pubkey) => server_pubkey,
        Err(error) => {
            log::error!(
                "get_public_key returned an invalid public key for Lockbox enclave \
                 {enclave_index}: {error}"
            );
            return status::Custom(
                Status::BadGateway,
                Json(json!({
                    "message": "Signing enclave returned an invalid public key."
                })),
            );
        }
    };

    if let Err(error) = crate::database::deposit::complete_deposit_initialization(
        &statechain_entity.pool,
        &token_id,
        &auth_key,
        &statechain_id,
        reservation.enclave_index,
        &server_pubkey,
    )
    .await
    {
        log::error!("failed to complete deposit initialization: {error}");
        return deposit_internal_error(
            "Failed to complete deposit initialization. Retry the pending deposit.".to_string(),
        );
    }

    let deposit_msg1_response = mercurylib::deposit::DepositMsg1Response {
        server_pubkey: server_pubkey.to_string(),
        statechain_id,
    };

    let response_body = json!(deposit_msg1_response);

    status::Custom(Status::Ok, Json(response_body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        },
        time::{Duration, Instant},
    };

    use rocket::tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    fn enclave(url: &str, allow_deposit: bool) -> Enclave {
        Enclave {
            url: url.to_string(),
            allow_deposit,
            pcr0: None,
            pcr1: None,
            pcr2: None,
            debug: false,
            allow_unattested: false,
        }
    }

    async fn read_http_request_line(stream: &mut TcpStream) -> String {
        let mut request = Vec::new();
        let mut expected_size = None;
        loop {
            let mut chunk = [0_u8; 1024];
            let read = stream.read(&mut chunk).await.unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            if expected_size.is_none() {
                if let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                    let headers = std::str::from_utf8(&request[..header_end]).unwrap();
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    expected_size = Some(header_end + 4 + content_length);
                }
            }
            if expected_size.is_some_and(|size| request.len() >= size) {
                break;
            }
        }
        String::from_utf8(request)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .to_string()
    }

    #[test]
    fn production_key_request_budget_covers_cold_lockbox_before_ingress_timeout() {
        const OBSERVED_COLD_COMPLETION: Duration = Duration::from_secs(34);
        const SAFETY_MARGIN: Duration = Duration::from_secs(10);
        const INGRESS_TIMEOUT: Duration = Duration::from_secs(60);

        let policy = DEPOSIT_KEY_REQUEST_POLICY;
        let total_budget = policy.request_timeout
            + policy.recovery_timeout
            + policy.retry_timeout
            + policy.observation_window;

        assert!(total_budget >= OBSERVED_COLD_COMPLETION + SAFETY_MARGIN);
        assert!(total_budget < INGRESS_TIMEOUT);
    }

    #[test]
    fn key_request_retries_exactly_then_observes_if_the_retry_is_ambiguous() {
        let runtime = rocket::tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let post_requests = Arc::new(AtomicUsize::new(0));
            let observation_requests = Arc::new(AtomicUsize::new(0));
            let stalled_key_committed = Arc::new(AtomicBool::new(false));
            let server_posts = Arc::clone(&post_requests);
            let server_observations = Arc::clone(&observation_requests);
            let server_committed = Arc::clone(&stalled_key_committed);
            let server = rocket::tokio::spawn(async move {
                loop {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let posts = Arc::clone(&server_posts);
                    let observations = Arc::clone(&server_observations);
                    let committed = Arc::clone(&server_committed);
                    rocket::tokio::spawn(async move {
                        let request_line = read_http_request_line(&mut stream).await;
                        let (status, body) =
                            if request_line.starts_with("POST /get_public_key ") {
                                let request_number = posts.fetch_add(1, Ordering::SeqCst) + 1;
                                let delay = match request_number {
                                    1 | 3 => Duration::from_millis(30),
                                    2 | 4 | 5 => Duration::from_millis(150),
                                    _ => panic!("unexpected get_public_key request"),
                                };
                                rocket::tokio::time::sleep(delay).await;
                                if request_number == 5 {
                                    committed.store(true, Ordering::SeqCst);
                                }
                                (
                                    "200 OK",
                                    r#"{"server_pubkey":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"}"#.to_string(),
                                )
                            } else if request_line.starts_with(
                                "GET /bip448/state/observed-statechain ",
                            ) {
                                observations.fetch_add(1, Ordering::SeqCst);
                                if committed.load(Ordering::SeqCst) {
                                    (
                                        "200 OK",
                                        r#"{"statechain_id":"observed-statechain","server_pubkey":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"}"#.to_string(),
                                    )
                                } else {
                                    ("404 Not Found", "{}".to_string())
                                }
                            } else {
                                panic!("unexpected mock Lockbox request: {request_line}");
                            };
                        let response = format!(
                            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = stream.write_all(response.as_bytes()).await;
                        let _ = stream.shutdown().await;
                    });
                }
            });

            let auth_token = "00".repeat(32);
            let clients = crate::lockbox_client::LockboxClients::connect(
                &[enclave(&format!("http://{address}"), true)],
                Some(&auth_token),
                "regtest",
            )
            .await
            .unwrap();
            let policy = DepositKeyRequestPolicy {
                request_timeout: Duration::from_millis(100),
                recovery_timeout: Duration::from_millis(25),
                retry_timeout: Duration::from_millis(100),
                observation_window: Duration::from_millis(500),
                observation_attempt_timeout: Duration::from_millis(75),
                observation_delay: Duration::from_millis(20),
                observation_max_delay: Duration::from_millis(80),
            };
            let payload = GetPublicKeyRequestPayload {
                statechain_id: "slow-statechain".to_string(),
            };

            let response =
                request_deposit_public_key_with_policy(&clients, 0, &payload, policy)
                    .await
                    .unwrap();
            assert_eq!(
                response.server_pubkey,
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            );
            assert_eq!(post_requests.load(Ordering::SeqCst), 1);
            assert_eq!(observation_requests.load(Ordering::SeqCst), 0);

            let retried_payload = GetPublicKeyRequestPayload {
                statechain_id: "retried-statechain".to_string(),
            };
            let retry_started = Instant::now();
            let retried_response =
                request_deposit_public_key_with_policy(&clients, 0, &retried_payload, policy)
                    .await
                    .unwrap();
            let retry_elapsed = retry_started.elapsed();
            assert_eq!(retried_response.server_pubkey, response.server_pubkey);
            assert!(retry_elapsed >= Duration::from_millis(120));
            assert!(retry_elapsed < Duration::from_millis(300));
            assert_eq!(post_requests.load(Ordering::SeqCst), 3);
            assert_eq!(observation_requests.load(Ordering::SeqCst), 0);

            stalled_key_committed.store(false, Ordering::SeqCst);
            let observed_payload = GetPublicKeyRequestPayload {
                statechain_id: "observed-statechain".to_string(),
            };
            let observation_started = Instant::now();
            let observed_response =
                request_deposit_public_key_with_policy(&clients, 0, &observed_payload, policy)
                    .await
                    .unwrap();
            let observation_elapsed = observation_started.elapsed();
            server.abort();

            assert_eq!(observed_response.server_pubkey, response.server_pubkey);
            assert!(observation_elapsed >= Duration::from_millis(240));
            assert!(observation_elapsed < Duration::from_millis(500));
            assert_eq!(post_requests.load(Ordering::SeqCst), 5);
            assert!(observation_requests.load(Ordering::SeqCst) >= 2);
        });
    }

    #[test]
    fn enclave_index_from_statechain_id_is_deterministic_and_bounded() {
        let first = get_enclave_index_from_statechain_id("statechain-a", 5);
        let second = get_enclave_index_from_statechain_id("statechain-a", 5);

        assert_eq!(first, second);
        assert!(first < 5);
    }

    #[test]
    fn random_enclave_index_returns_hashed_index_when_it_allows_deposits() {
        let enclaves = vec![
            enclave("http://one", true),
            enclave("http://two", true),
            enclave("http://three", true),
        ];
        let expected = get_enclave_index_from_statechain_id("statechain-b", enclaves.len() as u32);

        let index = select_deposit_enclave("statechain-b", &enclaves).unwrap();

        assert_eq!(index, expected);
    }

    #[test]
    fn random_enclave_index_falls_back_to_first_allowed_entry() {
        let selected = get_enclave_index_from_statechain_id("statechain-c", 3);
        let fallback = if selected == 0 { 1 } else { 0 };
        let mut enclaves = vec![
            enclave("http://one", false),
            enclave("http://two", false),
            enclave("http://three", false),
        ];
        enclaves[fallback].allow_deposit = true;
        enclaves[selected].allow_deposit = false;

        let index = select_deposit_enclave("statechain-c", &enclaves).unwrap();

        assert_eq!(index, fallback);
    }

    #[test]
    fn random_enclave_index_errors_when_no_enclave_allows_deposits() {
        let enclaves = vec![enclave("http://one", false), enclave("http://two", false)];

        let err = select_deposit_enclave("statechain-d", &enclaves).unwrap_err();

        assert_eq!(err, "No valid enclave found with allow_deposit set to true");
    }

    #[test]
    fn random_enclave_index_rejects_an_empty_configuration() {
        let err = select_deposit_enclave("statechain-e", &[]).unwrap_err();

        assert_eq!(err, "No Lockbox enclaves are configured");
    }

    #[test]
    fn deposit_authorization_rejects_malformed_values() {
        assert_eq!(
            parse_deposit_authorization("not-a-key", "not-a-signature").unwrap_err(),
            "Authentication key is invalid."
        );
        assert_eq!(
            parse_deposit_authorization(
                "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                "not-a-signature",
            )
            .unwrap_err(),
            "Token signature is invalid."
        );
    }

    #[test]
    fn token_status_without_server_remains_unconfirmed() {
        let runtime = rocket::tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let response = check_token_status(None, "local-token", &reqwest::Client::new()).await;

            assert!(!response.confirmed);
            assert!(!response.spent);
            assert!(!response.err);
            assert_eq!(response.status, None);
            assert_eq!(response.err_message, None);
        });
    }

    #[test]
    fn token_status_with_server_uses_configured_url() {
        let runtime = rocket::tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = rocket::tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request_line = read_http_request_line(&mut stream).await;
                let body = r#"{"confirmed":true,"spent":false}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
                request_line
            });
            let token_server_url = format!("http://{address}");

            let response = check_token_status(
                Some(&token_server_url),
                "paid-token",
                &reqwest::Client::new(),
            )
            .await;

            assert_eq!(
                server.await.unwrap(),
                "GET /token/token_verify/paid-token HTTP/1.1"
            );
            assert!(response.confirmed);
            assert!(!response.spent);
            assert!(!response.err);
        });
    }

    #[test]
    fn token_verify_upstream_error_does_not_forward_4xx_status() {
        let response = token_verify_upstream_error(
            reqwest::StatusCode::NOT_FOUND,
            r#"{"message":"Token not found in the database."}"#.to_string(),
        );

        assert!(response.err);
        assert_eq!(response.status, Some(Status::InternalServerError));
        assert!(response
            .err_message
            .unwrap()
            .contains("token server token_verify returned 404"));
    }
}
