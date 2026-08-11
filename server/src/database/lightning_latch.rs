use chrono::{DateTime, Utc};
use secp256k1::XOnlyPublicKey;
use sqlx::Row;

pub async fn is_lightning_latch_in_tx(
    connection: &mut sqlx::PgConnection,
    statechain_id: &str,
    sender_auth_key: &XOnlyPublicKey,
    batch_id: &str,
) -> Result<bool, sqlx::Error> {
    let row = sqlx::query(
        "SELECT EXISTS (\
             SELECT 1 FROM lightning_latch \
             WHERE statechain_id = $1 \
               AND sender_auth_xonly_public_key = $2 \
               AND batch_id = $3\
         )",
    )
    .bind(statechain_id)
    .bind(sender_auth_key.serialize())
    .bind(batch_id)
    .fetch_one(connection)
    .await?;

    Ok(row.get(0))
}

pub async fn get_lightning_latch_tx(
    connection: &mut sqlx::PgConnection,
    statechain_id: &str,
    batch_id: &str,
) -> Result<Option<(Vec<u8>, bool)>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT sender_auth_xonly_public_key, locked \
         FROM lightning_latch \
         WHERE statechain_id = $1 AND batch_id = $2 \
         FOR UPDATE",
    )
    .bind(statechain_id)
    .bind(batch_id)
    .fetch_optional(connection)
    .await?;

    Ok(row.map(|row| (row.get(0), row.get(1))))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnlockBip448LightningLatchResult {
    Absent,
    ConflictingOwner,
    AlreadyUnlocked,
    Unlocked,
}

pub async fn unlock_bip448_lightning_latch_in_tx(
    connection: &mut sqlx::PgConnection,
    statechain_id: &str,
    batch_id: &str,
    sender_auth_key: &XOnlyPublicKey,
) -> Result<UnlockBip448LightningLatchResult, sqlx::Error> {
    let Some((owner, locked)) = get_lightning_latch_tx(connection, statechain_id, batch_id).await?
    else {
        return Ok(UnlockBip448LightningLatchResult::Absent);
    };
    if owner != sender_auth_key.serialize() {
        return Ok(UnlockBip448LightningLatchResult::ConflictingOwner);
    }
    if !locked {
        return Ok(UnlockBip448LightningLatchResult::AlreadyUnlocked);
    }

    let result = sqlx::query(
        "UPDATE lightning_latch \
         SET locked = false, updated_at = NOW() \
         WHERE statechain_id = $1 \
           AND batch_id = $2 \
           AND sender_auth_xonly_public_key = $3 \
           AND locked = true",
    )
    .bind(statechain_id)
    .bind(batch_id)
    .bind(sender_auth_key.serialize())
    .execute(connection)
    .await?;

    if result.rows_affected() != 1 {
        return Err(sqlx::Error::Protocol(
            "generation-fenced latch unlock affected a non-unit row count".to_string(),
        ));
    }
    Ok(UnlockBip448LightningLatchResult::Unlocked)
}

pub async fn insert_paymenthash(
    pool: &sqlx::PgPool,
    statechain_id: &str,
    sender_auth_key: &XOnlyPublicKey,
    batch_id: &str,
    pre_image: &str,
    expires_at: &DateTime<Utc>,
) {
    let query = "DELETE FROM lightning_latch WHERE expires_at < now()";

    let _ = sqlx::query(query).execute(pool).await.unwrap();

    let query = "INSERT INTO lightning_latch (statechain_id, sender_auth_xonly_public_key, batch_id, pre_image, expires_at) VALUES ($1, $2, $3, $4, $5)";

    let _ = sqlx::query(query)
        .bind(statechain_id)
        .bind(sender_auth_key.serialize())
        .bind(batch_id)
        .bind(pre_image)
        .bind(expires_at)
        .execute(pool)
        .await
        .unwrap();
}

pub async fn is_lightning_latch(
    pool: &sqlx::PgPool,
    statechain_id: &str,
    sender_auth_key: &XOnlyPublicKey,
    batch_id: &str,
) -> bool {
    let query = "SELECT EXISTS \
        (SELECT 1 FROM \
        lightning_latch \
        WHERE statechain_id = $1 \
        AND sender_auth_xonly_public_key = $2 \
        AND batch_id = $3)";

    let row = sqlx::query(query)
        .bind(statechain_id)
        .bind(sender_auth_key.serialize())
        .bind(batch_id)
        .fetch_one(pool)
        .await
        .unwrap();

    let exists: bool = row.get(0);

    exists
}

pub async fn get_preimage(
    pool: &sqlx::PgPool,
    statechain_id: &str,
    sender_auth_key: &XOnlyPublicKey,
    batch_id: &str,
) -> Option<String> {
    let query = "SELECT pre_image FROM \
        lightning_latch \
        WHERE statechain_id = $1 \
        AND sender_auth_xonly_public_key = $2 \
        AND batch_id = $3
        AND locked = false";

    let row = sqlx::query(query)
        .bind(statechain_id)
        .bind(sender_auth_key.serialize())
        .bind(batch_id)
        .fetch_optional(pool)
        .await
        .unwrap();

    if row.is_none() {
        return None;
    }

    let row = row.unwrap();

    let pre_image: String = row.get(0);

    Some(pre_image)
}

pub async fn get_preimage_by_batch_id(pool: &sqlx::PgPool, batch_id: &str) -> Option<String> {
    let query = "SELECT pre_image FROM \
        lightning_latch \
        WHERE batch_id = $1";

    let row = sqlx::query(query)
        .bind(batch_id)
        .fetch_optional(pool)
        .await
        .unwrap();

    if row.is_none() {
        return None;
    }

    let row = row.unwrap();

    let pre_image: String = row.get(0);

    Some(pre_image)
}
