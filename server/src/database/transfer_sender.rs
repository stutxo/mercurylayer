use chrono::{DateTime, Utc};
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};

use sqlx::Row;

#[derive(Debug, Eq, PartialEq)]
pub enum InsertTransferResult {
    Success([u8; 32]),
    AuthenticationFailed,
    StatecoinBatchLocked(String),
    ExpiredBatchTime(String),
}

#[derive(Debug, Eq, PartialEq)]
pub enum UpdateTransferMessageResult {
    Success,
    AuthenticationFailed,
    GenerationMismatch,
}

fn integrity_error(message: &str) -> sqlx::Error {
    sqlx::Error::Protocol(message.to_string())
}

fn parse_x1(bytes: Vec<u8>) -> Result<[u8; 32], sqlx::Error> {
    bytes
        .try_into()
        .map_err(|_| integrity_error("statechain transfer x1 is not exactly 32 bytes"))
}

fn batch_is_expired(batch_time: DateTime<Utc>) -> bool {
    let timeout = crate::server_config::ServerConfig::load().batch_timeout;
    Utc::now() > batch_time + chrono::Duration::seconds(timeout as i64)
}

async fn get_locked_statechain_auth_key(
    connection: &mut sqlx::PgConnection,
    statechain_id: &str,
) -> Result<Option<XOnlyPublicKey>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT auth_xonly_public_key \
         FROM statechain_data \
         WHERE statechain_id = $1 \
         FOR UPDATE",
    )
    .bind(statechain_id)
    .fetch_optional(connection)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };
    let Some(bytes) = row.get::<Option<Vec<u8>>, _>(0) else {
        return Ok(None);
    };
    Ok(XOnlyPublicKey::from_slice(&bytes).ok())
}

/// Look up the exact active owner generation. This query is deliberately
/// NULL-safe for `batch_id` and locks the one-row transfer slot.
pub async fn get_exact_transfer_x1(
    connection: &mut sqlx::PgConnection,
    statechain_id: &str,
    new_user_auth_key: &PublicKey,
    batch_id: &Option<String>,
) -> Result<Option<[u8; 32]>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT x1 \
         FROM statechain_transfer \
         WHERE statechain_id = $1 \
           AND new_user_auth_public_key = $2 \
           AND batch_id IS NOT DISTINCT FROM $3 \
           AND key_updated = false \
         FOR UPDATE",
    )
    .bind(statechain_id)
    .bind(new_user_auth_key.serialize())
    .bind(batch_id)
    .fetch_optional(connection)
    .await?;

    row.map(|row| parse_x1(row.get(0))).transpose()
}

pub async fn get_batch_time_by_batch_id_in_tx(
    connection: &mut sqlx::PgConnection,
    batch_id: &str,
) -> Result<Option<DateTime<Utc>>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT batch_time \
         FROM statechain_transfer \
         WHERE batch_id = $1 AND locked = true \
         FOR UPDATE",
    )
    .bind(batch_id)
    .fetch_optional(connection)
    .await?;

    Ok(row.map(|row| row.get(0)))
}

async fn validate_batch_transfer_tx(
    connection: &mut sqlx::PgConnection,
    statechain_id: &str,
    new_batch_id: &Option<String>,
) -> Result<Option<InsertTransferResult>, sqlx::Error> {
    if let Some((batch_id, batch_time)) =
        crate::database::transfer::get_batch_id_and_time_by_statechain_id_in_tx(
            connection,
            statechain_id,
        )
        .await?
    {
        if !batch_is_expired(batch_time) {
            if crate::database::transfer::is_all_coins_unlocked_in_tx(connection, &batch_id).await?
            {
                return Ok(None);
            }
            return Ok(Some(InsertTransferResult::StatecoinBatchLocked(
                "Statecoin batch locked (the batch time has not expired).".to_string(),
            )));
        }

        if new_batch_id.as_ref() == Some(&batch_id) {
            return Ok(Some(InsertTransferResult::ExpiredBatchTime(
                "Batch time has expired. Try a new batch id.".to_string(),
            )));
        }
        return Ok(None);
    }

    if let Some(new_batch_id) = new_batch_id {
        if let Some(batch_time) = get_batch_time_by_batch_id_in_tx(connection, new_batch_id).await?
        {
            if batch_is_expired(batch_time) {
                return Ok(Some(InsertTransferResult::ExpiredBatchTime(
                    "Batch time has expired. Try a new batch id.".to_string(),
                )));
            }
        }
    }

    Ok(None)
}

/// Authenticate, exact-replay, validate a batch, and initialize a new
/// transfer generation in one PostgreSQL transaction.
pub async fn insert_new_transfer_or_replay_exact(
    pool: &sqlx::PgPool,
    signed_statechain_id: &str,
    statechain_id: &str,
    new_user_auth_key: &PublicKey,
    batch_id: &Option<String>,
) -> Result<InsertTransferResult, sqlx::Error> {
    let mut transaction = pool.begin().await?;
    let connection = &mut *transaction;

    let Some(owner_auth_key) = get_locked_statechain_auth_key(connection, statechain_id).await?
    else {
        transaction.rollback().await?;
        return Ok(InsertTransferResult::AuthenticationFailed);
    };
    let signature_valid = crate::endpoints::utils::try_verify_statechain_signature(
        signed_statechain_id,
        statechain_id,
        &owner_auth_key,
    )
    .unwrap_or(false);
    if !signature_valid {
        transaction.rollback().await?;
        return Ok(InsertTransferResult::AuthenticationFailed);
    }

    if let Some(x1) = get_exact_transfer_x1(
        &mut *transaction,
        statechain_id,
        new_user_auth_key,
        batch_id,
    )
    .await?
    {
        transaction.commit().await?;
        return Ok(InsertTransferResult::Success(x1));
    }

    if let Some(batch_error) =
        validate_batch_transfer_tx(&mut *transaction, statechain_id, batch_id).await?
    {
        transaction.rollback().await?;
        return Ok(batch_error);
    }

    let secret_x1 = SecretKey::new(&mut secp256k1::rand::rng());
    let x1 = Scalar::from(secret_x1).to_be_bytes();

    let (batch_time, locked, locked2) = if let Some(batch_id) = batch_id {
        let batch_time = get_batch_time_by_batch_id_in_tx(&mut *transaction, batch_id)
            .await?
            .unwrap_or_else(Utc::now);
        let locked2 = crate::database::lightning_latch::is_lightning_latch_in_tx(
            &mut *transaction,
            statechain_id,
            &owner_auth_key,
            batch_id,
        )
        .await?;
        (Some(batch_time), true, locked2)
    } else {
        (None, false, false)
    };

    sqlx::query("DELETE FROM statechain_transfer WHERE statechain_id = $1")
        .bind(statechain_id)
        .execute(&mut *transaction)
        .await?;
    let result = sqlx::query(
        "INSERT INTO statechain_transfer (\
             statechain_id, new_user_auth_public_key, x1, batch_id, batch_time, \
             locked, locked2, key_updated\
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, false)",
    )
    .bind(statechain_id)
    .bind(new_user_auth_key.serialize())
    .bind(x1)
    .bind(batch_id)
    .bind(batch_time)
    .bind(locked)
    .bind(locked2)
    .execute(&mut *transaction)
    .await?;
    if result.rows_affected() != 1 {
        return Err(integrity_error(
            "fresh transfer insert affected a non-unit row count",
        ));
    }

    transaction.commit().await?;
    Ok(InsertTransferResult::Success(x1))
}

pub async fn update_transfer_msg_for_generation_exact(
    pool: &sqlx::PgPool,
    statechain_id: &str,
    auth_sig: &str,
    new_user_auth_key: &PublicKey,
    x1_pub: &PublicKey,
    enc_transfer_msg: &[u8],
) -> Result<UpdateTransferMessageResult, sqlx::Error> {
    let mut transaction = pool.begin().await?;

    let Some(owner_auth_key) =
        get_locked_statechain_auth_key(&mut *transaction, statechain_id).await?
    else {
        transaction.rollback().await?;
        return Ok(UpdateTransferMessageResult::GenerationMismatch);
    };

    let digest = mercurylib::transfer::sender::bip448_transfer_update_msg_auth_digest(
        statechain_id,
        new_user_auth_key,
        x1_pub,
        enc_transfer_msg,
    )
    .map_err(|_| integrity_error("invalid BIP448 update-message digest input"))?;
    let signature_valid =
        crate::endpoints::utils::try_verify_digest_signature(auth_sig, &digest, &owner_auth_key)
            .unwrap_or(false);
    if !signature_valid {
        transaction.rollback().await?;
        return Ok(UpdateTransferMessageResult::AuthenticationFailed);
    }

    let row = sqlx::query(
        "SELECT new_user_auth_public_key, x1, key_updated \
         FROM statechain_transfer \
         WHERE statechain_id = $1 \
         FOR UPDATE",
    )
    .bind(statechain_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(row) = row else {
        transaction.rollback().await?;
        return Ok(UpdateTransferMessageResult::GenerationMismatch);
    };
    let recipient_bytes: Vec<u8> = row.get(0);
    let row_x1 = parse_x1(row.get(1))?;
    let key_updated: bool = row.get(2);
    let row_generation = SecretKey::from_slice(&row_x1)
        .map_err(|_| integrity_error("statechain transfer x1 is not a valid scalar"))?
        .public_key(&Secp256k1::new());
    if key_updated || recipient_bytes != new_user_auth_key.serialize() || row_generation != *x1_pub
    {
        transaction.rollback().await?;
        return Ok(UpdateTransferMessageResult::GenerationMismatch);
    }

    let result = sqlx::query(
        "UPDATE statechain_transfer \
         SET encrypted_transfer_msg = $1, updated_at = NOW() \
         WHERE statechain_id = $2 \
           AND new_user_auth_public_key = $3 \
           AND x1 = $4 \
           AND key_updated = false",
    )
    .bind(enc_transfer_msg)
    .bind(statechain_id)
    .bind(new_user_auth_key.serialize())
    .bind(row_x1)
    .execute(&mut *transaction)
    .await?;
    if result.rows_affected() != 1 {
        return Err(integrity_error(
            "generation-fenced transfer-message update affected a non-unit row count",
        ));
    }

    transaction.commit().await?;
    Ok(UpdateTransferMessageResult::Success)
}
