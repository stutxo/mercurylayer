use sqlx::Row;
use uuid::Uuid;

const STALE_PRE_NONCE_LEASE_INTERVAL: &str = "5 minutes";

pub async fn get_bip448_signing_nonce_lease(
    connection: &mut sqlx::PgConnection,
    statechain_id: &str,
) -> Option<String> {
    let query = "\
        SELECT signing_id \
        FROM signing_nonce_leases \
        WHERE statechain_id = $1";

    let row = sqlx::query(query)
        .bind(statechain_id)
        .fetch_optional(connection)
        .await
        .unwrap();

    row.map(|row| row.get(0))
}

pub async fn insert_bip448_signing_nonce_lease(
    connection: &mut sqlx::PgConnection,
    statechain_id: &str,
    signing_id: &str,
) -> Option<String> {
    let lease_token = Uuid::new_v4().simple().to_string();
    let query = "\
        INSERT INTO signing_nonce_leases \
        (statechain_id, signing_id, lease_token) \
        VALUES ($1, $2, $3) \
        ON CONFLICT DO NOTHING";

    let result = sqlx::query(query)
        .bind(statechain_id)
        .bind(signing_id)
        .bind(&lease_token)
        .execute(connection)
        .await
        .unwrap();

    (result.rows_affected() == 1).then_some(lease_token)
}

pub async fn bip448_signing_nonce_lease_matches(
    connection: &mut sqlx::PgConnection,
    statechain_id: &str,
    signing_id: &str,
    lease_token: &str,
) -> bool {
    let query = "\
        UPDATE signing_nonce_leases \
        SET updated_at = clock_timestamp() \
        WHERE statechain_id = $1 AND signing_id = $2 \
          AND lease_token = $3 \
        RETURNING 1";

    sqlx::query(query)
        .bind(statechain_id)
        .bind(signing_id)
        .bind(lease_token)
        .fetch_optional(connection)
        .await
        .unwrap()
        .is_some()
}

pub async fn delete_bip448_signing_nonce_lease(
    connection: &mut sqlx::PgConnection,
    statechain_id: &str,
    signing_id: &str,
) -> bool {
    let query = "\
        DELETE FROM signing_nonce_leases \
        WHERE statechain_id = $1 AND signing_id = $2";

    let result = sqlx::query(query)
        .bind(statechain_id)
        .bind(signing_id)
        .execute(connection)
        .await
        .unwrap();

    result.rows_affected() == 1
}

pub async fn delete_bip448_signing_nonce_lease_by_token(
    connection: &mut sqlx::PgConnection,
    statechain_id: &str,
    signing_id: &str,
    lease_token: &str,
) -> bool {
    let query = "\
        DELETE FROM signing_nonce_leases \
        WHERE statechain_id = $1 AND signing_id = $2 \
          AND lease_token = $3";

    let result = sqlx::query(query)
        .bind(statechain_id)
        .bind(signing_id)
        .bind(lease_token)
        .execute(connection)
        .await
        .unwrap();

    result.rows_affected() == 1
}

/// Reclaims expired leases only when no durable incomplete nonce round needs
/// protection. Fresh sign/first handlers refresh their exact `lease_token`
/// before asking the lockbox for a nonce and then persist nonce state only if
/// the same token is still present. Incomplete BIP448 rounds are nonce rows
/// without a stored partial signature.
pub async fn reclaim_stale_signing_nonce_lease(
    connection: &mut sqlx::PgConnection,
    statechain_id: &str,
) -> bool {
    let query = "\
        WITH deleted_lease AS (\
            DELETE FROM signing_nonce_leases AS lease \
            WHERE lease.statechain_id = $1 \
              AND lease.updated_at < NOW() - ($2::text)::interval \
              AND NOT EXISTS (\
                  SELECT 1 \
                  FROM bip448_signature_data AS signature \
                  WHERE signature.statechain_id = lease.statechain_id \
                    AND signature.signing_id = lease.signing_id \
                    AND signature.server_pubnonce IS NOT NULL \
                    AND signature.server_partial_sig IS NULL\
              )\
            RETURNING lease.statechain_id, lease.signing_id\
        ), \
        deleted_bip448_reservation AS (\
            DELETE FROM bip448_signature_data AS signature \
            USING deleted_lease AS lease \
            WHERE signature.statechain_id = lease.statechain_id \
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
        .fetch_one(connection)
        .await
        .unwrap();

    row.get::<i64, _>(0) > 0
}
