use secp256k1::{PublicKey, XOnlyPublicKey};
use sqlx::Row;

pub async fn get_token_status(pool: &sqlx::PgPool, token_id: &str) -> Option<bool> {
    let row = sqlx::query(
        "SELECT confirmed, spent \
        FROM public.tokens \
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
    if confirmed && !spent {
        return Some(true);
    } else {
        return Some(false);
    }
}

pub struct TokenInfo {
    pub confirmed: bool,
    pub spent: bool,
}

pub async fn get_token_info(pool: &sqlx::PgPool, token_id: &str) -> Option<TokenInfo> {
    let row = sqlx::query(
        "SELECT confirmed, spent \
        FROM public.tokens \
        WHERE token_id = $1",
    )
    .bind(&token_id)
    .fetch_optional(pool)
    .await;

    let row = row.unwrap();

    if row.is_none() {
        return None;
    }

    let row = row.unwrap();

    let confirmed: bool = row.get(0);
    let spent: bool = row.get(1);

    Some(TokenInfo { confirmed, spent })
}

pub async fn set_token_spent(pool: &sqlx::PgPool, token_id: &str) {
    let mut transaction = pool.begin().await.unwrap();

    let query = "UPDATE tokens \
        SET spent = true \
        WHERE token_id = $1";

    let _ = sqlx::query(query)
        .bind(token_id)
        .execute(&mut *transaction)
        .await
        .unwrap();

    transaction.commit().await.unwrap();
}

pub async fn check_existing_key(pool: &sqlx::PgPool, auth_key: &XOnlyPublicKey) -> bool {
    let row = sqlx::query(
        "SELECT 1 \
        FROM statechain_data \
        WHERE auth_xonly_public_key = $1",
    )
    .bind(&auth_key.serialize())
    .fetch_one(pool)
    .await;

    match row {
        Ok(_) => true,
        Err(sqlx::Error::RowNotFound) => false,
        Err(_) => false,
    }
}

pub async fn insert_new_deposit(
    pool: &sqlx::PgPool,
    token_id: &str,
    auth_key: &XOnlyPublicKey,
    server_public_key: &PublicKey,
    statechain_id: &String,
    enclave_index: i32,
) {
    let query = "INSERT INTO statechain_data (token_id, auth_xonly_public_key, server_public_key, statechain_id, enclave_index) VALUES ($1, $2, $3, $4, $5)";

    let _ = sqlx::query(query)
        .bind(token_id)
        .bind(&auth_key.serialize())
        .bind(&server_public_key.serialize())
        .bind(statechain_id)
        .bind(enclave_index)
        .execute(pool)
        .await
        .unwrap();
}

pub async fn insert_new_token(pool: &sqlx::PgPool, token_id: &str) {
    let query = "INSERT INTO tokens (token_id, confirmed, spent) VALUES ($1, $2, $3)";

    let _ = sqlx::query(query)
        .bind(token_id)
        .bind(true)
        .bind(false)
        .execute(pool)
        .await
        .unwrap();
}
