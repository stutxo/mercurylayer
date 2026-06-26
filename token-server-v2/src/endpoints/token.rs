use std::str::FromStr;

use rocket::{http::Status, response::status, serde::json::Json, State};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;

use crate::server_state::TokenServerState;

pub async fn insert_new_token(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    token_id: &str,
    onchain_address: &str,
) {
    let query = "INSERT INTO tokens (token_id, onchain_address, confirmed, spent) \
                 VALUES ($1, $2, $3, $4)";
    sqlx::query(query)
        .bind(token_id)
        .bind(onchain_address)
        .bind(false)
        .bind(false)
        .execute(&mut **tx)
        .await
        .unwrap();
}

#[get("/token/token_gen")]
pub async fn token_gen(
    token_server_state: &State<TokenServerState>,
) -> status::Custom<Json<Value>> {
    let server_config = &token_server_state.server_config;

    // Start a transaction
    let mut tx = token_server_state.pool.begin().await.unwrap();

    let onchain_address = match token_server_state
        .core_rpc_client
        .get_new_address(&server_config.token_wallet.name)
        .await
    {
        Ok(address) => address,
        Err(error) => {
            let response_body = json!({
                "message": format!("Error generating token payment address: {}", error)
            });
            return status::Custom(Status::InternalServerError, Json(response_body));
        }
    };

    let token_id = uuid::Uuid::new_v4().to_string();

    // Insert within the same transaction
    insert_new_token(&mut tx, &token_id, &onchain_address).await;

    // Commit the transaction
    tx.commit().await.unwrap();

    let response_body = json!({
        "token_id": token_id,
        "deposit_address": onchain_address,
        "fee": server_config.fee,
        "confirmation_target": server_config.confirmation_target,
    });

    status::Custom(Status::Ok, Json(response_body))
}

#[derive(Serialize, Deserialize, Debug)]
struct TokenInfo {
    confirmed: bool,
    spent: bool,
    onchain_address: String,
}

async fn get_token_info(pool: &sqlx::PgPool, token_id: &str) -> Option<TokenInfo> {
    let row = sqlx::query(
        "SELECT confirmed, spent, onchain_address \
        FROM tokens \
        WHERE token_id = $1",
    )
    .bind(&token_id)
    .fetch_one(pool)
    .await;

    if row.is_err() {
        match row.err().unwrap() {
            sqlx::Error::RowNotFound => return None,
            _ => return None, // this case should be treated as unexpected error
        }
    }

    let row = row.unwrap();

    let confirmed: bool = row.get(0);
    let spent: bool = row.get(1);
    let onchain_address: String = row.get(2);

    Some(TokenInfo {
        confirmed,
        spent,
        onchain_address,
    })
}

pub async fn set_token_confirmed(pool: &sqlx::PgPool, token_id: &str) {
    let mut transaction = pool.begin().await.unwrap();

    let query = "UPDATE tokens \
        SET confirmed = true \
        WHERE token_id = $1";

    let _ = sqlx::query(query)
        .bind(token_id)
        .execute(&mut *transaction)
        .await
        .unwrap();

    transaction.commit().await.unwrap();
}

#[get("/token/token_verify/<token_id>")]
pub async fn token_verify(
    token_server_state: &State<TokenServerState>,
    token_id: String,
) -> status::Custom<Json<Value>> {
    let token_info = get_token_info(&token_server_state.pool, &token_id).await;

    if token_info.is_none() {
        let response_body = json!({
            "message": "Token not found in the database."
        });
        return status::Custom(Status::NotFound, Json(response_body));
    }

    let token_info = token_info.unwrap();

    if token_info.spent || token_info.confirmed {
        let response_body = json!({
            "confirmed": token_info.confirmed,
            "spent": token_info.spent,
        });
        return status::Custom(Status::Ok, Json(response_body));
    }

    let address = bitcoin::Address::from_str(&token_info.onchain_address);

    if address.is_err() {
        let response_body = json!({
            "message": "Invalid onchain address (network unchecked)."
        });
        return status::Custom(Status::InternalServerError, Json(response_body));
    }

    let unchecked_address = address.unwrap();

    let server_config = &token_server_state.server_config;

    let network = bitcoin::Network::from_str(server_config.network.as_str()).unwrap();

    let address = unchecked_address.require_network(network);

    if address.is_err() {
        let response_body = json!({
            "message": "Invalid onchain address (network checked)."
        });
        return status::Custom(Status::InternalServerError, Json(response_body));
    }

    let address = address.unwrap();

    let utxo_list = match token_server_state
        .core_rpc_client
        .list_unspent(&server_config.token_wallet.name, &address.to_string())
        .await
    {
        Ok(utxos) => utxos,
        Err(error) => {
            let response_body = json!({
                "message": format!("Error fetching UTXO list: {}", error)
            });
            return status::Custom(Status::InternalServerError, Json(response_body));
        }
    };

    let utxo = utxo_list
        .into_iter()
        .find(|unspent| unspent.amount_sats == server_config.fee);

    if utxo.is_none() {
        let response_body = json!({
            "confirmed": false,
            "spent": false,
        });
        return status::Custom(Status::Ok, Json(response_body));
    }

    let utxo = utxo.unwrap();

    if server_config.confirmation_target == 0 {
        set_token_confirmed(&token_server_state.pool, &token_id).await;

        let response_body = json!({
            "confirmed": true,
            "spent": false,
        });

        return status::Custom(Status::Ok, Json(response_body));
    }

    let confirmed = utxo.confirmations >= server_config.confirmation_target;

    if !confirmed {
        let response_body = json!({
            "confirmed": false,
            "spent": false,
        });
        return status::Custom(Status::Ok, Json(response_body));
    }

    set_token_confirmed(&token_server_state.pool, &token_id).await;

    let response_body = json!({
        "confirmed": true,
        "spent": false,
    });

    return status::Custom(Status::Ok, Json(response_body));
}
