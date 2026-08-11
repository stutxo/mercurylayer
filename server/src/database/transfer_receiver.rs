use chrono::{DateTime, Utc};
use mercurylib::transfer::receiver::StatechainInfo;
use mercurylib::transfer::receiver::{
    bip448_transfer_unlock_auth_digest, Bip448TransferUnlockRole,
};
use secp256k1::{PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};

use sqlx::Row;

const DELETE_SIGNING_GUARDS_AFTER_TRANSFER_QUERY: &str = "\
    WITH deleted_leases AS (\
        DELETE FROM signing_nonce_leases WHERE statechain_id = $1 RETURNING 1\
    ), \
    deleted_bip448_incomplete AS (\
        DELETE FROM bip448_signature_data WHERE statechain_id = $1 \
          AND server_partial_sig IS NULL RETURNING 1\
    ) \
    SELECT 1";

const GET_STATECHAIN_INFO_QUERY: &str = "\
        SELECT statechain_id, server_pubnonce, challenge, tx_n \
        FROM (\
            SELECT statechain_id, server_pubnonce, challenge, \
                   ROW_NUMBER() OVER (ORDER BY id ASC)::INTEGER AS tx_n \
            FROM bip448_signature_data \
            WHERE statechain_id = $1 \
              AND server_pubnonce IS NOT NULL \
              AND challenge IS NOT NULL \
              AND server_partial_sig IS NOT NULL\
        ) AS completed_signatures \
        ORDER BY tx_n ASC";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockedStatechainGeneration {
    pub auth_xonly_public_key: Vec<u8>,
    pub server_public_key: Vec<u8>,
    pub enclave_index: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockedTransferGeneration {
    pub recipient_auth_public_key: Vec<u8>,
    pub x1: [u8; 32],
    pub batch_id: Option<String>,
    pub batch_time: Option<DateTime<Utc>>,
    pub encrypted_transfer_msg: Option<Vec<u8>>,
    pub key_updated: bool,
    pub locked: bool,
    pub locked2: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnlockTransferResult {
    Success,
    AuthenticationFailed,
    GenerationMismatch,
}

fn integrity_error(message: &str) -> sqlx::Error {
    sqlx::Error::Protocol(message.to_string())
}

pub async fn lock_statechain_generation(
    connection: &mut sqlx::PgConnection,
    statechain_id: &str,
) -> Result<Option<LockedStatechainGeneration>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT auth_xonly_public_key, server_public_key, enclave_index \
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
    let Some(auth_xonly_public_key) = row.get::<Option<Vec<u8>>, _>(0) else {
        return Err(integrity_error(
            "statechain owner authentication key is null",
        ));
    };
    let Some(server_public_key) = row.get::<Option<Vec<u8>>, _>(1) else {
        return Err(integrity_error("statechain server public key is null"));
    };
    Ok(Some(LockedStatechainGeneration {
        auth_xonly_public_key,
        server_public_key,
        enclave_index: row.get(2),
    }))
}

pub async fn load_bip448_transfer_generation_for_update(
    connection: &mut sqlx::PgConnection,
    statechain_id: &str,
) -> Result<Option<LockedTransferGeneration>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT new_user_auth_public_key, x1, batch_id, batch_time, \
                encrypted_transfer_msg, key_updated, locked, locked2 \
         FROM statechain_transfer \
         WHERE statechain_id = $1 \
         FOR UPDATE",
    )
    .bind(statechain_id)
    .fetch_optional(connection)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };
    let Some(recipient_auth_public_key) = row.get::<Option<Vec<u8>>, _>(0) else {
        return Err(integrity_error(
            "transfer recipient authentication key is null",
        ));
    };
    let Some(x1_bytes) = row.get::<Option<Vec<u8>>, _>(1) else {
        return Err(integrity_error("transfer generation x1 is null"));
    };
    let x1 = x1_bytes
        .try_into()
        .map_err(|_| integrity_error("transfer generation x1 is not exactly 32 bytes"))?;

    Ok(Some(LockedTransferGeneration {
        recipient_auth_public_key,
        x1,
        batch_id: row.get(2),
        batch_time: row.get(3),
        encrypted_transfer_msg: row.get(4),
        key_updated: row.get(5),
        locked: row.get(6),
        locked2: row.get(7),
    }))
}

pub async fn unlock_transfer_generation(
    pool: &sqlx::PgPool,
    statechain_id: &str,
    auth_sig: &str,
    x1_generation_pubkey: &PublicKey,
) -> Result<UnlockTransferResult, sqlx::Error> {
    let mut transaction = pool.begin().await?;
    let Some(statechain) = lock_statechain_generation(&mut *transaction, statechain_id).await?
    else {
        transaction.rollback().await?;
        return Ok(UnlockTransferResult::GenerationMismatch);
    };
    let Some(mut transfer) =
        load_bip448_transfer_generation_for_update(&mut *transaction, statechain_id).await?
    else {
        transaction.rollback().await?;
        return Ok(UnlockTransferResult::GenerationMismatch);
    };

    let current_owner_auth = XOnlyPublicKey::from_slice(&statechain.auth_xonly_public_key)
        .map_err(|_| integrity_error("statechain owner authentication key is malformed"))?;
    let recipient_key = PublicKey::from_slice(&transfer.recipient_auth_public_key)
        .map_err(|_| integrity_error("transfer recipient authentication key is malformed"))?;
    let x1_secret = SecretKey::from_slice(&transfer.x1)
        .map_err(|_| integrity_error("transfer generation x1 is not a valid scalar"))?;
    let row_generation = x1_secret.public_key(&Secp256k1::new());
    if transfer.key_updated || row_generation != *x1_generation_pubkey {
        transaction.rollback().await?;
        return Ok(UnlockTransferResult::GenerationMismatch);
    }

    let current_digest = bip448_transfer_unlock_auth_digest(
        Bip448TransferUnlockRole::CurrentOwner,
        statechain_id,
        x1_generation_pubkey,
    )
    .map_err(|_| integrity_error("invalid current-owner unlock digest input"))?;
    let recipient_digest = bip448_transfer_unlock_auth_digest(
        Bip448TransferUnlockRole::Recipient,
        statechain_id,
        x1_generation_pubkey,
    )
    .map_err(|_| integrity_error("invalid recipient unlock digest input"))?;
    let current_matches = crate::endpoints::utils::try_verify_digest_signature(
        auth_sig,
        &current_digest,
        &current_owner_auth,
    )
    .unwrap_or(false);
    let recipient_matches = crate::endpoints::utils::try_verify_digest_signature(
        auth_sig,
        &recipient_digest,
        &recipient_key.x_only_public_key().0,
    )
    .unwrap_or(false);
    let role = match (current_matches, recipient_matches) {
        (true, false) => Bip448TransferUnlockRole::CurrentOwner,
        (false, true) => Bip448TransferUnlockRole::Recipient,
        (false, false) => {
            transaction.rollback().await?;
            return Ok(UnlockTransferResult::AuthenticationFailed);
        }
        (true, true) => {
            transaction.rollback().await?;
            return Ok(UnlockTransferResult::GenerationMismatch);
        }
    };

    (transfer.locked, transfer.locked2) =
        set_bip448_transfer_generation_unlocked(&mut *transaction, statechain_id, role, &transfer)
            .await?;

    if !transfer.locked && !transfer.locked2 {
        if let Some(batch_id) = &transfer.batch_id {
            use crate::database::lightning_latch::UnlockBip448LightningLatchResult;
            match crate::database::lightning_latch::unlock_bip448_lightning_latch_in_tx(
                &mut *transaction,
                statechain_id,
                batch_id,
                &current_owner_auth,
            )
            .await?
            {
                UnlockBip448LightningLatchResult::ConflictingOwner => {
                    return Err(integrity_error(
                        "lightning latch owner differs from locked statechain owner",
                    ));
                }
                UnlockBip448LightningLatchResult::Absent
                | UnlockBip448LightningLatchResult::AlreadyUnlocked
                | UnlockBip448LightningLatchResult::Unlocked => {}
            }
        }
    }

    transaction.commit().await?;
    Ok(UnlockTransferResult::Success)
}

pub async fn set_bip448_transfer_generation_unlocked(
    connection: &mut sqlx::PgConnection,
    statechain_id: &str,
    role: Bip448TransferUnlockRole,
    transfer: &LockedTransferGeneration,
) -> Result<(bool, bool), sqlx::Error> {
    let (assignment, target_predicate) = match role {
        Bip448TransferUnlockRole::CurrentOwner => ("locked2 = false", "locked2 = true"),
        Bip448TransferUnlockRole::Recipient => ("locked = false", "locked = true"),
    };
    let query = format!(
        "UPDATE statechain_transfer \
         SET {assignment}, updated_at = NOW() \
         WHERE statechain_id = $1 \
           AND x1 = $2 \
           AND new_user_auth_public_key = $3 \
           AND batch_id IS NOT DISTINCT FROM $4 \
           AND encrypted_transfer_msg IS NOT DISTINCT FROM $5 \
           AND key_updated = false \
           AND {target_predicate}"
    );
    let result = sqlx::query(&query)
        .bind(statechain_id)
        .bind(transfer.x1)
        .bind(&transfer.recipient_auth_public_key)
        .bind(&transfer.batch_id)
        .bind(&transfer.encrypted_transfer_msg)
        .execute(&mut *connection)
        .await?;
    if result.rows_affected() > 1 {
        return Err(integrity_error(
            "generation-fenced transfer unlock affected a non-unit row count",
        ));
    }

    let flags = sqlx::query(
        "SELECT locked, locked2 \
         FROM statechain_transfer \
         WHERE statechain_id = $1 \
           AND x1 = $2 \
           AND new_user_auth_public_key = $3 \
           AND batch_id IS NOT DISTINCT FROM $4 \
           AND encrypted_transfer_msg IS NOT DISTINCT FROM $5 \
           AND key_updated = false",
    )
    .bind(statechain_id)
    .bind(transfer.x1)
    .bind(&transfer.recipient_auth_public_key)
    .bind(&transfer.batch_id)
    .bind(&transfer.encrypted_transfer_msg)
    .fetch_optional(connection)
    .await?
    .ok_or_else(|| integrity_error("transfer generation disappeared while locked"))?;
    Ok((flags.get(0), flags.get(1)))
}

pub async fn commit_bip448_transfer_generation_update(
    connection: &mut sqlx::PgConnection,
    statechain_id: &str,
    statechain: &LockedStatechainGeneration,
    transfer: &LockedTransferGeneration,
    recipient_auth_key: &XOnlyPublicKey,
    new_server_public_key: &PublicKey,
) -> Result<(), sqlx::Error> {
    let statechain_result = sqlx::query(
        "UPDATE statechain_data \
         SET auth_xonly_public_key = $1, server_public_key = $2 \
         WHERE statechain_id = $3 AND auth_xonly_public_key = $4",
    )
    .bind(recipient_auth_key.serialize())
    .bind(new_server_public_key.serialize())
    .bind(statechain_id)
    .bind(&statechain.auth_xonly_public_key)
    .execute(&mut *connection)
    .await?;
    if statechain_result.rows_affected() != 1 {
        return Err(integrity_error(
            "receiver owner-key update affected a non-unit row count",
        ));
    }

    let transfer_result = sqlx::query(
        "UPDATE statechain_transfer \
         SET key_updated = true, updated_at = NOW() \
         WHERE statechain_id = $1 \
           AND new_user_auth_public_key = $2 \
           AND x1 = $3 \
           AND batch_id IS NOT DISTINCT FROM $4 \
           AND encrypted_transfer_msg IS NOT DISTINCT FROM $5 \
           AND key_updated = false",
    )
    .bind(statechain_id)
    .bind(&transfer.recipient_auth_public_key)
    .bind(transfer.x1)
    .bind(&transfer.batch_id)
    .bind(&transfer.encrypted_transfer_msg)
    .execute(&mut *connection)
    .await?;
    if transfer_result.rows_affected() != 1 {
        return Err(integrity_error(
            "receiver transfer-consume update affected a non-unit row count",
        ));
    }

    sqlx::query(DELETE_SIGNING_GUARDS_AFTER_TRANSFER_QUERY)
        .bind(statechain_id)
        .execute(connection)
        .await?;
    Ok(())
}

pub async fn get_statechain_info(pool: &sqlx::PgPool, statechain_id: &str) -> Vec<StatechainInfo> {
    let mut result = Vec::<StatechainInfo>::new();

    let rows = sqlx::query(GET_STATECHAIN_INFO_QUERY)
        .bind(statechain_id)
        .fetch_all(pool)
        .await
        .unwrap();

    for row in rows {
        let statechain_id: String = row.get(0);
        let server_pubnonce: Option<String> = row.get(1);
        let challenge: Option<String> = row.get(2);
        let tx_n: i32 = row.get(3);

        let (Some(server_pubnonce), Some(challenge)) = (server_pubnonce, challenge) else {
            continue;
        };

        let statechain_transfer = StatechainInfo {
            statechain_id,
            server_pubnonce,
            challenge,
            tx_n: tx_n as u32,
        };

        result.push(statechain_transfer);
    }

    result.sort_by(|a, b| a.tx_n.cmp(&b.tx_n));

    result
}

pub async fn get_enclave_pubkey(pool: &sqlx::PgPool, statechain_id: &str) -> Option<PublicKey> {
    let query = "SELECT server_public_key \
        FROM statechain_data \
        WHERE statechain_id = $1";

    let row = sqlx::query(query)
        .bind(statechain_id)
        .fetch_optional(pool)
        .await
        .unwrap();

    if row.is_none() {
        return None;
    }

    let row = row.unwrap();

    let enclave_public_key_bytes = row.get::<Vec<u8>, _>("server_public_key");
    let enclave_public_key = PublicKey::from_slice(&enclave_public_key_bytes).unwrap();

    Some(enclave_public_key)
}

pub async fn get_x1pub(pool: &sqlx::PgPool, statechain_id: &str) -> Option<PublicKey> {
    let query = "SELECT x1 \
        FROM statechain_transfer \
        WHERE statechain_id = $1";

    let row = sqlx::query(query)
        .bind(statechain_id)
        .fetch_optional(pool)
        .await
        .unwrap();

    if row.is_none() {
        return None;
    }

    let row = row.unwrap();

    let x1_secret_bytes = row.get::<Vec<u8>, _>("x1");
    let secret_x1 = SecretKey::from_slice(&x1_secret_bytes).unwrap();

    Some(secret_x1.public_key(&Secp256k1::new()))
}

pub async fn get_statechain_transfer_messages(
    pool: &sqlx::PgPool,
    new_user_auth_key: &PublicKey,
) -> Vec<String> {
    let query = "\
        SELECT encrypted_transfer_msg \
        FROM statechain_transfer \
        WHERE new_user_auth_public_key = $1
        AND encrypted_transfer_msg IS NOT NULL \
        ORDER BY updated_at ASC";

    let rows = sqlx::query(query)
        .bind(new_user_auth_key.serialize())
        .fetch_all(pool)
        .await
        .unwrap();

    let mut result = Vec::<String>::new();

    for row in rows {
        let encrypted_transfer_msg: Vec<u8> = row.get(0);
        result.push(hex::encode(encrypted_transfer_msg));
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completed_bip448_rows_survive_transfer_and_projection_stays_contiguous() {
        assert!(DELETE_SIGNING_GUARDS_AFTER_TRANSFER_QUERY.contains(
            "DELETE FROM bip448_signature_data WHERE statechain_id = $1 \
             AND server_partial_sig IS NULL RETURNING 1"
        ));
        assert!(GET_STATECHAIN_INFO_QUERY.contains(
            "FROM bip448_signature_data WHERE statechain_id = $1 \
             AND server_pubnonce IS NOT NULL AND challenge IS NOT NULL \
             AND server_partial_sig IS NOT NULL"
        ));

        let rows = [(1, Some("partial-1")), (2, None), (3, Some("partial-3"))];
        let projection = rows
            .into_iter()
            .filter(|(_, partial)| partial.is_some())
            .enumerate()
            .map(|(index, (id, _))| (id, index + 1))
            .collect::<Vec<_>>();
        assert_eq!(projection, [(1, 1), (3, 2)]);
    }
}
