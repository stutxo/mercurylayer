use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

pub const LEGACY_SIGNING_PROTOCOL: &str = "legacy";
pub const BIP448_SIGNING_PROTOCOL: &str = "bip448";
const STALE_PRE_NONCE_LEASE_INTERVAL: &str = "5 minutes";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningProtocolClaim {
    Claimed,
    AlreadyMatches,
    Conflict { existing_protocol: String },
}

pub async fn claim_statechain_signing_protocol(
    pool: &sqlx::PgPool,
    statechain_id: &str,
    protocol: &str,
) -> SigningProtocolClaim {
    let insert_query = "\
        INSERT INTO statechain_signing_protocol \
        (statechain_id, protocol) \
        VALUES ($1, $2) \
        ON CONFLICT DO NOTHING";

    let result = sqlx::query(insert_query)
        .bind(statechain_id)
        .bind(protocol)
        .execute(pool)
        .await
        .unwrap();

    if result.rows_affected() == 1 {
        return SigningProtocolClaim::Claimed;
    }

    let query = "\
        SELECT protocol \
        FROM statechain_signing_protocol \
        WHERE statechain_id = $1";

    let existing_protocol = sqlx::query(query)
        .bind(statechain_id)
        .fetch_optional(pool)
        .await
        .unwrap()
        .map(|row| row.get(0))
        .unwrap_or_else(|| "unknown".to_string());

    if existing_protocol == protocol {
        SigningProtocolClaim::AlreadyMatches
    } else {
        SigningProtocolClaim::Conflict { existing_protocol }
    }
}

pub async fn get_signing_nonce_lease(pool: &sqlx::PgPool, statechain_id: &str) -> Option<String> {
    let query = "\
        SELECT protocol \
        FROM signing_nonce_leases \
        WHERE statechain_id = $1";

    let row = sqlx::query(query)
        .bind(statechain_id)
        .fetch_optional(pool)
        .await
        .unwrap();

    row.map(|row| row.get(0))
}

pub async fn get_bip448_signing_nonce_lease(
    pool: &sqlx::PgPool,
    statechain_id: &str,
) -> Option<String> {
    let query = "\
        SELECT signing_id \
        FROM signing_nonce_leases \
        WHERE statechain_id = $1 AND protocol = $2";

    let row = sqlx::query(query)
        .bind(statechain_id)
        .bind(BIP448_SIGNING_PROTOCOL)
        .fetch_optional(pool)
        .await
        .unwrap();

    row.map(|row| row.get(0))
}

pub async fn insert_signing_nonce_lease(
    pool: &sqlx::PgPool,
    statechain_id: &str,
    protocol: &str,
) -> Option<String> {
    let lease_token = Uuid::new_v4().simple().to_string();
    let query = "\
        INSERT INTO signing_nonce_leases \
        (statechain_id, protocol, lease_token) \
        VALUES ($1, $2, $3) \
        ON CONFLICT DO NOTHING";

    let result = sqlx::query(query)
        .bind(statechain_id)
        .bind(protocol)
        .bind(&lease_token)
        .execute(pool)
        .await
        .unwrap();

    (result.rows_affected() == 1).then_some(lease_token)
}

pub async fn insert_bip448_signing_nonce_lease(
    pool: &sqlx::PgPool,
    statechain_id: &str,
    signing_id: &str,
) -> Option<String> {
    let lease_token = Uuid::new_v4().simple().to_string();
    let query = "\
        INSERT INTO signing_nonce_leases \
        (statechain_id, protocol, signing_id, lease_token) \
        VALUES ($1, $2, $3, $4) \
        ON CONFLICT DO NOTHING";

    let result = sqlx::query(query)
        .bind(statechain_id)
        .bind(BIP448_SIGNING_PROTOCOL)
        .bind(signing_id)
        .bind(&lease_token)
        .execute(pool)
        .await
        .unwrap();

    (result.rows_affected() == 1).then_some(lease_token)
}

pub async fn lock_legacy_signing_nonce_lease_for_lockbox<'a>(
    pool: &'a sqlx::PgPool,
    statechain_id: &str,
    lease_token: &str,
) -> Option<Transaction<'a, Postgres>> {
    let mut transaction = pool.begin().await.unwrap();
    let query = "\
        UPDATE signing_nonce_leases \
        SET updated_at = clock_timestamp() \
        WHERE statechain_id = $1 AND protocol = $2 \
          AND signing_id IS NULL AND lease_token = $3 \
        RETURNING 1";

    let row = sqlx::query(query)
        .bind(statechain_id)
        .bind(LEGACY_SIGNING_PROTOCOL)
        .bind(lease_token)
        .fetch_optional(&mut *transaction)
        .await
        .unwrap();

    if row.is_some() {
        Some(transaction)
    } else {
        transaction.rollback().await.unwrap();
        None
    }
}

pub async fn lock_bip448_signing_nonce_lease_for_lockbox<'a>(
    pool: &'a sqlx::PgPool,
    statechain_id: &str,
    signing_id: &str,
    lease_token: &str,
) -> Option<Transaction<'a, Postgres>> {
    let mut transaction = pool.begin().await.unwrap();
    let query = "\
        UPDATE signing_nonce_leases \
        SET updated_at = clock_timestamp() \
        WHERE statechain_id = $1 AND protocol = $2 \
          AND signing_id = $3 AND lease_token = $4 \
        RETURNING 1";

    let row = sqlx::query(query)
        .bind(statechain_id)
        .bind(BIP448_SIGNING_PROTOCOL)
        .bind(signing_id)
        .bind(lease_token)
        .fetch_optional(&mut *transaction)
        .await
        .unwrap();

    if row.is_some() {
        Some(transaction)
    } else {
        transaction.rollback().await.unwrap();
        None
    }
}

pub async fn delete_signing_nonce_lease(
    pool: &sqlx::PgPool,
    statechain_id: &str,
    protocol: &str,
) -> bool {
    let query = "\
        DELETE FROM signing_nonce_leases \
        WHERE statechain_id = $1 AND protocol = $2";

    let result = sqlx::query(query)
        .bind(statechain_id)
        .bind(protocol)
        .execute(pool)
        .await
        .unwrap();

    result.rows_affected() == 1
}

pub async fn delete_signing_nonce_lease_by_token(
    pool: &sqlx::PgPool,
    statechain_id: &str,
    protocol: &str,
    lease_token: &str,
) -> bool {
    let query = "\
        DELETE FROM signing_nonce_leases \
        WHERE statechain_id = $1 AND protocol = $2 AND lease_token = $3";

    let result = sqlx::query(query)
        .bind(statechain_id)
        .bind(protocol)
        .bind(lease_token)
        .execute(pool)
        .await
        .unwrap();

    result.rows_affected() == 1
}

pub async fn delete_bip448_signing_nonce_lease(
    pool: &sqlx::PgPool,
    statechain_id: &str,
    signing_id: &str,
) -> bool {
    let query = "\
        DELETE FROM signing_nonce_leases \
        WHERE statechain_id = $1 AND protocol = $2 \
          AND signing_id = $3";

    let result = sqlx::query(query)
        .bind(statechain_id)
        .bind(BIP448_SIGNING_PROTOCOL)
        .bind(signing_id)
        .execute(pool)
        .await
        .unwrap();

    result.rows_affected() == 1
}

pub async fn delete_bip448_signing_nonce_lease_by_token(
    pool: &sqlx::PgPool,
    statechain_id: &str,
    signing_id: &str,
    lease_token: &str,
) -> bool {
    let query = "\
        DELETE FROM signing_nonce_leases \
        WHERE statechain_id = $1 AND protocol = $2 \
          AND signing_id = $3 AND lease_token = $4";

    let result = sqlx::query(query)
        .bind(statechain_id)
        .bind(BIP448_SIGNING_PROTOCOL)
        .bind(signing_id)
        .bind(lease_token)
        .execute(pool)
        .await
        .unwrap();

    result.rows_affected() == 1
}

/// Reclaims expired leases only when no durable incomplete nonce round needs
/// protection. Fresh sign/first handlers hold a row lock on their exact
/// `lease_token` while asking the lockbox for a nonce, so this delete either
/// waits for that handler to finish or rechecks a refreshed `updated_at` before
/// reclaiming. Once a server nonce is stored without a partial signature, the
/// client may still be able to finish sign/second.
pub async fn reclaim_stale_signing_nonce_lease(pool: &sqlx::PgPool, statechain_id: &str) -> bool {
    let query = "\
        WITH deleted_lease AS (\
            DELETE FROM signing_nonce_leases AS lease \
            WHERE lease.statechain_id = $1 \
              AND lease.updated_at < NOW() - ($2::text)::interval \
              AND (\
                  (\
                      lease.protocol = $3 \
                      AND NOT EXISTS (\
                          SELECT 1 \
                          FROM statechain_signature_data AS signature \
                          WHERE signature.statechain_id = lease.statechain_id \
                            AND signature.server_pubnonce IS NOT NULL \
                            AND signature.created_at >= lease.created_at\
                      )\
                  )\
                   OR (\
                       lease.protocol = $4 \
                       AND NOT EXISTS (\
                           SELECT 1 \
                           FROM bip448_signature_data AS signature \
                           WHERE signature.statechain_id = lease.statechain_id \
                             AND signature.signing_id = lease.signing_id \
                             AND signature.server_pubnonce IS NOT NULL \
                             AND signature.server_partial_sig IS NULL\
                       )\
                   )\
               )\
            RETURNING lease.statechain_id, lease.protocol, lease.signing_id\
        ), \
        deleted_bip448_reservation AS (\
            DELETE FROM bip448_signature_data AS signature \
            USING deleted_lease AS lease \
            WHERE lease.protocol = $4 \
              AND signature.statechain_id = lease.statechain_id \
              AND signature.signing_id = lease.signing_id \
              AND signature.server_pubnonce IS NULL \
              AND signature.challenge IS NULL \
              AND signature.server_partial_sig IS NULL \
            RETURNING 1\
        ), \
        deleted_orphan_bip448_reservation AS (\
            DELETE FROM bip448_signature_data AS signature \
            WHERE signature.statechain_id = $1 \
              AND signature.created_at < NOW() - ($2::text)::interval \
              AND signature.server_pubnonce IS NULL \
              AND signature.challenge IS NULL \
              AND signature.server_partial_sig IS NULL \
              AND NOT EXISTS (\
                  SELECT 1 \
                  FROM signing_nonce_leases AS lease \
                  WHERE lease.statechain_id = signature.statechain_id \
                    AND lease.protocol = $4 \
                    AND lease.signing_id = signature.signing_id\
              ) \
            RETURNING 1\
        ) \
        SELECT (SELECT COUNT(*) FROM deleted_lease) \
             + (SELECT COUNT(*) FROM deleted_bip448_reservation) \
             + (SELECT COUNT(*) FROM deleted_orphan_bip448_reservation)";

    let row = sqlx::query(query)
        .bind(statechain_id)
        .bind(STALE_PRE_NONCE_LEASE_INTERVAL)
        .bind(LEGACY_SIGNING_PROTOCOL)
        .bind(BIP448_SIGNING_PROTOCOL)
        .fetch_one(pool)
        .await
        .unwrap();

    row.get::<i64, _>(0) > 0
}

pub async fn get_server_pubnonce_from_null_challenge(
    pool: &sqlx::PgPool,
    statechain_id: &str,
) -> Option<String> {
    let query = "SELECT server_pubnonce \
        FROM statechain_signature_data \
        WHERE statechain_id = $1 \
        AND server_pubnonce IS NOT NULL \
        AND challenge is NULL \
        ORDER BY created_at ASC \
        LIMIT 1";

    let row = sqlx::query(query)
        .bind(statechain_id)
        .fetch_optional(pool)
        .await
        .unwrap();

    if row.is_none() {
        return None;
    }

    let row = row.unwrap();

    let server_pubnonce: String = row.get(0);

    Some(server_pubnonce)
}

pub async fn insert_new_signature_data(
    pool: &sqlx::PgPool,
    server_pubnonce: &str,
    statechain_id: &str,
) {
    let mut transaction = pool.begin().await.unwrap();

    // FOR UPDATE is used to lock the row for the duration of the transaction
    // It is not allowed with aggregate functions (MAX in this case), so we need to wrap it in a subquery
    let max_tx_k_query = "\
        SELECT COALESCE(MAX(tx_n), 0) \
        FROM (\
            SELECT * \
            FROM statechain_signature_data \
            WHERE statechain_id = $1 FOR UPDATE) AS result";

    let row = sqlx::query(max_tx_k_query)
        .bind(statechain_id)
        .fetch_one(&mut *transaction)
        .await
        .unwrap();

    let mut new_tx_n = row.get::<i32, _>(0);
    new_tx_n = new_tx_n + 1;

    let query = "\
        INSERT INTO statechain_signature_data \
        (server_pubnonce, statechain_id, tx_n) \
        VALUES ($1, $2, $3)";

    let _ = sqlx::query(query)
        .bind(server_pubnonce)
        .bind(statechain_id)
        .bind(new_tx_n)
        .execute(&mut *transaction)
        .await
        .unwrap();

    transaction.commit().await.unwrap();
}

pub async fn update_signature_data_challenge(
    pool: &sqlx::PgPool,
    server_pub_nonce: &str,
    challenge: &str,
    statechain_id: &str,
) {
    let query = "\
        UPDATE statechain_signature_data \
        SET challenge = $1 \
        WHERE statechain_id = $2 AND server_pubnonce= $3";

    let _ = sqlx::query(query)
        .bind(challenge)
        .bind(statechain_id)
        .bind(server_pub_nonce)
        .execute(pool)
        .await
        .unwrap();
}
