use secp256k1::{PublicKey, XOnlyPublicKey};
use sqlx::{postgres::PgRow, Row};

pub struct TokenInfo {
    pub confirmed: bool,
    pub spent: bool,
}

pub struct DepositInitialization {
    pub token_id: String,
    pub auth_xonly_public_key: Vec<u8>,
    pub server_public_key: Option<Vec<u8>>,
    pub statechain_id: String,
    pub enclave_index: i32,
    pub completed: bool,
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

fn deposit_initialization_from_row(row: PgRow) -> Result<DepositInitialization, sqlx::Error> {
    let token_id = row.try_get::<String, _>(0)?;
    let auth_xonly_public_key = row.try_get::<Vec<u8>, _>(1)?;
    let server_public_key = row.try_get::<Option<Vec<u8>>, _>(2)?;
    let statechain_id = row.try_get::<String, _>(3)?;
    let enclave_index = row.try_get::<i32, _>(4)?;
    let status = row.try_get::<String, _>(5)?;
    let completed = match (status.as_str(), server_public_key.is_some()) {
        ("pending", false) => false,
        ("completed", true) => true,
        _ => {
            return Err(sqlx::Error::Protocol(
                "deposit initialization status does not match its server key".to_string(),
            ));
        }
    };
    Ok(DepositInitialization {
        token_id,
        auth_xonly_public_key,
        server_public_key,
        statechain_id,
        enclave_index,
        completed,
    })
}

pub async fn get_deposit_initialization(
    pool: &sqlx::PgPool,
    token_id: &str,
) -> Result<Option<DepositInitialization>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT token_id, auth_xonly_public_key, server_public_key, statechain_id, \
                enclave_index, status \
         FROM deposit_initialization \
         WHERE token_id = $1",
    )
    .bind(token_id)
    .fetch_optional(pool)
    .await?;
    row.map(deposit_initialization_from_row).transpose()
}

pub async fn completed_deposit_is_current(
    pool: &sqlx::PgPool,
    initialization: &DepositInitialization,
) -> Result<bool, sqlx::Error> {
    let server_public_key = initialization.server_public_key.as_ref().ok_or_else(|| {
        sqlx::Error::Protocol("completed deposit initialization has no server key".to_string())
    })?;
    sqlx::query_scalar(
        "SELECT EXISTS ( \
             SELECT 1 FROM statechain_data \
             WHERE token_id = $1 \
               AND auth_xonly_public_key = $2 \
               AND server_public_key = $3 \
               AND statechain_id = $4 \
               AND enclave_index = $5 \
         )",
    )
    .bind(&initialization.token_id)
    .bind(&initialization.auth_xonly_public_key)
    .bind(server_public_key)
    .bind(&initialization.statechain_id)
    .bind(initialization.enclave_index)
    .fetch_one(pool)
    .await
}

pub async fn reserve_deposit_initialization(
    pool: &sqlx::PgPool,
    token_id: &str,
    auth_key: &XOnlyPublicKey,
    candidate_statechain_id: &str,
    enclave_index: i32,
) -> Result<DepositInitialization, sqlx::Error> {
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "INSERT INTO deposit_initialization \
         (token_id, auth_xonly_public_key, statechain_id, enclave_index) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (token_id) DO NOTHING",
    )
    .bind(token_id)
    .bind(auth_key.serialize())
    .bind(candidate_statechain_id)
    .bind(enclave_index)
    .execute(&mut *transaction)
    .await?;

    let row = sqlx::query(
        "SELECT token_id, auth_xonly_public_key, server_public_key, statechain_id, \
                enclave_index, status \
         FROM deposit_initialization \
         WHERE token_id = $1 \
         FOR UPDATE",
    )
    .bind(token_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| {
        sqlx::Error::Protocol("deposit initialization reservation disappeared".to_string())
    })?;
    let initialization = deposit_initialization_from_row(row)?;
    transaction.commit().await?;
    Ok(initialization)
}

pub async fn complete_deposit_initialization(
    pool: &sqlx::PgPool,
    token_id: &str,
    auth_key: &XOnlyPublicKey,
    statechain_id: &str,
    enclave_index: i32,
    server_public_key: &PublicKey,
) -> Result<(), sqlx::Error> {
    let mut transaction = pool.begin().await?;
    let row = sqlx::query(
        "SELECT token_id, auth_xonly_public_key, server_public_key, statechain_id, \
                enclave_index, status \
         FROM deposit_initialization \
         WHERE token_id = $1 \
         FOR UPDATE",
    )
    .bind(token_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| {
        sqlx::Error::Protocol("deposit initialization reservation disappeared".to_string())
    })?;
    let initialization = deposit_initialization_from_row(row)?;
    let serialized_auth_key = auth_key.serialize();
    let serialized_server_key = server_public_key.serialize();
    if initialization.auth_xonly_public_key != serialized_auth_key
        || initialization.statechain_id != statechain_id
        || initialization.enclave_index != enclave_index
    {
        return Err(sqlx::Error::Protocol(
            "deposit initialization reservation changed before completion".to_string(),
        ));
    }
    if initialization.completed {
        if initialization.server_public_key.as_deref() != Some(serialized_server_key.as_slice()) {
            return Err(sqlx::Error::Protocol(
                "deposit initialization completed with a different server key".to_string(),
            ));
        }
        let remains_current: bool = sqlx::query_scalar(
            "SELECT EXISTS ( \
                 SELECT 1 FROM statechain_data \
                 WHERE token_id = $1 \
                   AND auth_xonly_public_key = $2 \
                   AND server_public_key = $3 \
                   AND statechain_id = $4 \
                   AND enclave_index = $5 \
             )",
        )
        .bind(token_id)
        .bind(serialized_auth_key)
        .bind(serialized_server_key)
        .bind(statechain_id)
        .bind(enclave_index)
        .fetch_one(&mut *transaction)
        .await?;
        if !remains_current {
            return Err(sqlx::Error::Protocol(
                "completed deposit no longer matches current statechain ownership".to_string(),
            ));
        }
        transaction.commit().await?;
        return Ok(());
    }

    let statechain_inserted = sqlx::query(
        "INSERT INTO statechain_data \
         (token_id, auth_xonly_public_key, server_public_key, statechain_id, enclave_index) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(token_id)
    .bind(serialized_auth_key)
    .bind(serialized_server_key)
    .bind(statechain_id)
    .bind(enclave_index)
    .execute(&mut *transaction)
    .await?;
    if statechain_inserted.rows_affected() != 1 {
        return Err(sqlx::Error::Protocol(
            "deposit initialization did not create one active statechain".to_string(),
        ));
    }

    let token_updated = sqlx::query(
        "UPDATE tokens \
         SET spent = true \
         WHERE token_id = $1 \
           AND confirmed = true \
           AND spent = false",
    )
    .bind(token_id)
    .execute(&mut *transaction)
    .await?;
    if token_updated.rows_affected() != 1 {
        return Err(sqlx::Error::Protocol(
            "deposit initialization token is not confirmed and unspent".to_string(),
        ));
    }

    let initialization_updated = sqlx::query(
        "UPDATE deposit_initialization \
         SET server_public_key = $2, status = 'completed', updated_at = NOW() \
         WHERE token_id = $1 AND status = 'pending'",
    )
    .bind(token_id)
    .bind(serialized_server_key)
    .execute(&mut *transaction)
    .await?;
    if initialization_updated.rows_affected() != 1 {
        return Err(sqlx::Error::Protocol(
            "deposit initialization did not complete one reservation".to_string(),
        ));
    }

    transaction.commit().await
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
