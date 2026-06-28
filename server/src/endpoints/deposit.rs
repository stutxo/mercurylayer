use std::str::FromStr;

use crate::{server::StateChainEntity, server_config::Enclave};
use bitcoin::hashes::{sha256, Hash};
use rocket::{http::Status, response::status, serde::json::Json, State};
use secp256k1::{schnorr::Signature, Message, PublicKey, Secp256k1, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

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

    return status::Custom(Status::Ok, Json(response_body));
}

pub async fn get_token_from_server(
    config: &crate::server_config::ServerConfig,
) -> status::Custom<Json<Value>> {
    let client: reqwest::Client = reqwest::Client::new();
    let request = client.get(&format!(
        "{}/token/token_gen",
        config.token_server_url.as_ref().unwrap()
    ));

    let value = match request.send().await {
        Ok(response) => {
            let text = response.text().await.unwrap();
            text
        }
        Err(err) => {
            let response_body = json!({
                "message": err.to_string()
            });

            let err = err.status();
            let status = if err.is_some() {
                Status::from_code(err.unwrap().as_u16()).unwrap_or(Status::InternalServerError)
            } else {
                Status::InternalServerError
            };

            return status::Custom(status, Json(response_body));
        }
    };

    let response: serde_json::Value = serde_json::from_str(value.as_str())
        .expect(&format!("failed to parse: {}", value.as_str()));

    let token_id = response
        .get("token_id")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let deposit_address = response
        .get("deposit_address")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let fee = response.get("fee").unwrap().as_u64().unwrap();
    let confirmation_target = response
        .get("confirmation_target")
        .unwrap()
        .as_u64()
        .unwrap();

    let token = mercurylib::deposit::TokenResponse {
        token_id,
        payment_method: "onchain".to_string(),
        deposit_address: Some(deposit_address),
        fee,
        confirmation_target,
    };

    let response_body = json!(token);

    return status::Custom(Status::Ok, Json(response_body));
}

#[get("/deposit/get_token")]
pub async fn get_token(statechain_entity: &State<StateChainEntity>) -> status::Custom<Json<Value>> {
    let config = crate::server_config::ServerConfig::load();

    if config.token_server_url.is_none() {
        return get_token_no_server(statechain_entity, &config).await;
    } else {
        return get_token_from_server(&config).await;
    }
}

fn get_random_enclave_index(statechain_id: &str, enclaves: &Vec<Enclave>) -> Result<usize, String> {
    let index_from_statechain_id =
        get_enclave_index_from_statechain_id(statechain_id, enclaves.len() as u32);

    let selected_enclave = enclaves.get(index_from_statechain_id).unwrap();
    if selected_enclave.allow_deposit {
        return Ok(index_from_statechain_id);
    } else {
        for (i, enclave) in enclaves.iter().enumerate() {
            if enclave.allow_deposit {
                return Ok(i);
            }
        }
    }

    Err("No valid enclave found with allow_deposit set to true".to_string())
}

fn get_enclave_index_from_statechain_id(statechain_id: &str, enclave_array_len: u32) -> usize {
    let hash = sha256::Hash::hash(statechain_id.as_bytes());
    let hash_bytes = hash.as_byte_array();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash_bytes[..16]);
    let random_number = u128::from_be_bytes(bytes);

    return (random_number % enclave_array_len as u128) as usize;
}

struct TokenStatusResponse {
    confirmed: bool,
    spent: bool,
    err: bool,
    status: Option<Status>,
    err_message: Option<String>,
}

async fn check_token_status(token_id: &str) -> TokenStatusResponse {
    let config = crate::server_config::ServerConfig::load();

    let client: reqwest::Client = reqwest::Client::new();
    let request = client.get(&format!(
        "{}/token/token_verify/{}",
        config.token_server_url.as_ref().unwrap(),
        token_id
    ));

    let value = match request.send().await {
        Ok(response) => {
            let text = response.text().await.unwrap();
            text
        }
        Err(err) => {
            let message = err.to_string();

            let err = err.status();
            let status = if err.is_some() {
                Status::from_code(err.unwrap().as_u16()).unwrap_or(Status::InternalServerError)
            } else {
                Status::InternalServerError
            };

            return TokenStatusResponse {
                confirmed: false,
                spent: false,
                err: true,
                status: Some(status),
                err_message: Some(message),
            };
        }
    };

    let response: serde_json::Value = serde_json::from_str(value.as_str())
        .expect(&format!("failed to parse: {}", value.as_str()));

    let confirmed = response.get("confirmed").unwrap().as_bool().unwrap();
    let spent = response.get("spent").unwrap().as_bool().unwrap();

    return TokenStatusResponse {
        confirmed,
        spent,
        err: false,
        status: None,
        err_message: None,
    };
}

#[post("/deposit/init/pod", format = "json", data = "<deposit_msg1>")]
pub async fn post_deposit(
    statechain_entity: &State<StateChainEntity>,
    deposit_msg1: Json<mercurylib::deposit::DepositMsg1>,
) -> status::Custom<Json<Value>> {
    let statechain_entity = statechain_entity.inner();

    let auth_key = XOnlyPublicKey::from_str(&deposit_msg1.auth_key).unwrap();
    let token_id = deposit_msg1.token_id.clone();
    let signed_token_id = Signature::from_str(&deposit_msg1.signed_token_id.to_string()).unwrap();

    let msg = Message::from_hashed_data::<sha256::Hash>(token_id.to_string().as_bytes());

    let secp = Secp256k1::new();
    if !secp
        .verify_schnorr(&signed_token_id, msg.as_ref(), &auth_key)
        .is_ok()
    {
        let response_body = json!({
            "message": "Signature does not match authentication key."
        });

        return status::Custom(Status::InternalServerError, Json(response_body));
    }

    let is_existing_key =
        crate::database::deposit::check_existing_key(&statechain_entity.pool, &auth_key).await;

    if is_existing_key {
        let response_body = json!({
            "message": "The authentication key is already assigned to a statecoin."
        });

        return status::Custom(Status::BadRequest, Json(response_body));
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
        let token_status_response = check_token_status(&token_id).await;

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

    #[derive(Debug, Serialize, Deserialize)]
    pub struct GetPublicKeyRequestPayload {
        statechain_id: String,
    }

    let statechain_id = uuid::Uuid::new_v4().as_simple().to_string();

    let config = crate::server_config::ServerConfig::load();

    let enclave_index = get_random_enclave_index(&statechain_id, &config.enclaves).unwrap();

    let lockbox_endpoint = config.enclaves.get(enclave_index).unwrap().url.clone();
    let path = "get_public_key";

    let client: reqwest::Client = reqwest::Client::new();
    let request = client.post(&format!("{}/{}", lockbox_endpoint, path));

    let payload = GetPublicKeyRequestPayload {
        statechain_id: statechain_id.clone(),
    };

    let value = match request.json(&payload).send().await {
        Ok(response) => {
            let text = response.text().await.unwrap();
            text
        }
        Err(err) => {
            let response_body = json!({
                "error": "Internal Server Error",
                "message": err.to_string()
            });

            return status::Custom(Status::InternalServerError, Json(response_body));
        }
    };

    #[derive(Serialize, Deserialize)]
    pub struct PublicNonceRequestPayload<'r> {
        server_pubkey: &'r str,
    }

    let response: PublicNonceRequestPayload = serde_json::from_str(value.as_str())
        .expect(&format!("failed to parse: {}", value.as_str()));

    let mut server_pubkey_hex = response.server_pubkey.to_string();

    if server_pubkey_hex.starts_with("0x") {
        server_pubkey_hex = server_pubkey_hex[2..].to_string();
    }

    let server_pubkey = PublicKey::from_str(&server_pubkey_hex).unwrap();

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

    fn enclave(url: &str, allow_deposit: bool) -> Enclave {
        Enclave {
            url: url.to_string(),
            allow_deposit,
        }
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

        let index = get_random_enclave_index("statechain-b", &enclaves).unwrap();

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

        let index = get_random_enclave_index("statechain-c", &enclaves).unwrap();

        assert_eq!(index, fallback);
    }

    #[test]
    fn random_enclave_index_errors_when_no_enclave_allows_deposits() {
        let enclaves = vec![enclave("http://one", false), enclave("http://two", false)];

        let err = get_random_enclave_index("statechain-d", &enclaves).unwrap_err();

        assert_eq!(err, "No valid enclave found with allow_deposit set to true");
    }
}
