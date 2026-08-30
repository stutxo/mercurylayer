use std::str::FromStr;

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

async fn check_token_status(token_id: &str, client: &reqwest::Client) -> TokenStatusResponse {
    let config = crate::server_config::ServerConfig::load();

    let request = client
        .get(format!(
            "{}/token/token_verify/{}",
            config.token_server_url.as_ref().unwrap(),
            token_id
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
struct GetPublicKeyResponsePayload {
    server_pubkey: String,
}

#[derive(Debug, Deserialize)]
struct ObservedPublicKeyPayload {
    statechain_id: String,
    server_pubkey: String,
}

async fn observe_deposit_public_key(
    lockboxes: &crate::lockbox_client::LockboxClients,
    enclave_index: usize,
    statechain_id: &str,
) -> Result<Option<GetPublicKeyResponsePayload>, String> {
    let response = match lockboxes
        .get_raw(enclave_index, &format!("/bip448/state/{statechain_id}"))
        .await
    {
        Ok(response) => response,
        Err(error) => {
            log::warn!("Lockbox state observation failed after key request: {error}");
            return Ok(None);
        }
    };
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
    }))
}

async fn request_deposit_public_key(
    lockboxes: &crate::lockbox_client::LockboxClients,
    enclave_index: usize,
    payload: &GetPublicKeyRequestPayload,
) -> Result<GetPublicKeyResponsePayload, String> {
    // A transient transport failure may replay this exact statechain ID. The
    // Lockbox's unique statechain key prevents duplicate durable keys; an
    // uncertain or duplicate response is resolved from durable state below.
    let request = lockboxes
        .post_json(enclave_index, "/get_public_key", payload)
        .await;
    let request_error = match request {
        Ok(response) => return Ok(response),
        Err(error) => error,
    };

    log::warn!(
        "Lockbox key request failed: {request_error}; checking durable state for a committed key"
    );
    match observe_deposit_public_key(lockboxes, enclave_index, &payload.statechain_id).await {
        Ok(Some(observed)) => Ok(observed),
        Ok(None) => Err(format!(
            "Lockbox key request failed: {request_error}; no durable key was observed"
        )),
        Err(observation_error) => Err(format!(
            "Lockbox key request failed: {request_error}; durable state observation failed: \
             {observation_error}"
        )),
    }
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

    match crate::database::deposit::get_existing_deposit(&statechain_entity.pool, &auth_key).await {
        Ok(Some(existing)) => {
            if existing.token_id != token_id {
                return status::Custom(
                    Status::BadRequest,
                    Json(json!({
                        "message": "The authentication key is already assigned to a statecoin."
                    })),
                );
            }
            let server_public_key = match PublicKey::from_slice(&existing.server_public_key) {
                Ok(key) => key,
                Err(error) => {
                    log::error!("stored deposit server public key is malformed: {error}");
                    return deposit_internal_error(
                        "Stored deposit server public key is malformed.".to_string(),
                    );
                }
            };
            return status::Custom(
                Status::Ok,
                Json(json!(mercurylib::deposit::DepositMsg1Response {
                    server_pubkey: server_public_key.to_string(),
                    statechain_id: existing.statechain_id,
                })),
            );
        }
        Ok(None) => {}
        Err(error) => {
            log::error!("failed to load existing deposit: {error}");
            return deposit_internal_error("Failed to load existing deposit.".to_string());
        }
    }

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
        let response_body = json!({
            "message": "Token already spent."
        });

        return status::Custom(Status::Gone, Json(response_body));
    }

    if !token_info.confirmed {
        let token_status_response =
            check_token_status(&token_id, &statechain_entity.http_client).await;

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

    let statechain_id = uuid::Uuid::new_v4().as_simple().to_string();

    let enclave_index =
        match select_deposit_enclave(&statechain_id, &statechain_entity.config.enclaves) {
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

    crate::database::deposit::insert_new_deposit(
        &statechain_entity.pool,
        &token_id,
        &auth_key,
        &server_pubkey,
        &statechain_id,
        enclave_index as i32,
    )
    .await;

    crate::database::deposit::set_token_spent(&statechain_entity.pool, &token_id).await;

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
            atomic::{AtomicUsize, Ordering},
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
    fn key_request_waits_for_slow_success_and_bounds_a_stalled_response() {
        let runtime = rocket::tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let post_requests = Arc::new(AtomicUsize::new(0));
            let observation_requests = Arc::new(AtomicUsize::new(0));
            let server_posts = Arc::clone(&post_requests);
            let server_observations = Arc::clone(&observation_requests);
            let server = rocket::tokio::spawn(async move {
                loop {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let posts = Arc::clone(&server_posts);
                    let observations = Arc::clone(&server_observations);
                    rocket::tokio::spawn(async move {
                        let request_line = read_http_request_line(&mut stream).await;
                        let body = if request_line.starts_with("POST /get_public_key ") {
                            let request_number = posts.fetch_add(1, Ordering::SeqCst) + 1;
                            let delay = if request_number == 1 {
                                Duration::from_millis(5_100)
                            } else {
                                Duration::from_secs(20)
                            };
                            rocket::tokio::time::sleep(delay).await;
                            r#"{"server_pubkey":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"}"#.to_string()
                        } else if request_line.starts_with(
                            "GET /bip448/state/stalled-statechain ",
                        ) {
                            observations.fetch_add(1, Ordering::SeqCst);
                            rocket::tokio::time::sleep(Duration::from_secs(3)).await;
                            r#"{"statechain_id":"stalled-statechain","server_pubkey":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"}"#.to_string()
                        } else {
                            panic!("unexpected mock Lockbox request: {request_line}");
                        };
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        stream.write_all(response.as_bytes()).await.unwrap();
                        stream.shutdown().await.unwrap();
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
            let payload = GetPublicKeyRequestPayload {
                statechain_id: "slow-statechain".to_string(),
            };

            let response = request_deposit_public_key(&clients, 0, &payload)
                .await
                .unwrap();
            assert_eq!(
                response.server_pubkey,
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            );
            assert_eq!(post_requests.load(Ordering::SeqCst), 1);
            assert_eq!(observation_requests.load(Ordering::SeqCst), 0);

            let stalled_payload = GetPublicKeyRequestPayload {
                statechain_id: "stalled-statechain".to_string(),
            };
            let started = Instant::now();
            let stalled_response =
                request_deposit_public_key(&clients, 0, &stalled_payload)
                    .await
                    .unwrap();
            let elapsed = started.elapsed();
            server.abort();

            assert_eq!(stalled_response.server_pubkey, response.server_pubkey);
            assert!(elapsed >= Duration::from_secs(10));
            assert!(elapsed < Duration::from_secs(15));
            assert_eq!(post_requests.load(Ordering::SeqCst), 2);
            assert_eq!(observation_requests.load(Ordering::SeqCst), 1);
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
