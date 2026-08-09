//! Database access for BIP448 CSFS signing metadata.
//!
//! One record exists per opaque (statechain_id, signing_id); exact retries
//! replay the stored nonce/partial signature and conflicting blinded challenges
//! are rejected at the endpoint layer without storing transaction metadata.

use sqlx::Row;

/// The stored BIP448 signing state for one opaque signing id.
#[derive(Debug, Clone)]
pub struct Bip448SignatureRecord {
    pub server_pubnonce: Option<String>,
    pub challenge: Option<String>,
    /// CSFS share-negation flag derived from the untweaked aggregate key.
    /// Distinct from legacy Taproot key-path tweak metadata, which is never
    /// stored here.
    pub negate_seckey: Option<bool>,
    pub server_partial_sig: Option<String>,
}

/// One incomplete BIP448 signing round for a statechain. The lockbox has a
/// single sealed nonce slot per statechain_id, so a second incomplete round
/// would overwrite the nonce needed by the first round.
#[derive(Debug, Clone)]
pub struct Bip448IncompleteSignatureRecord {
    pub signing_id: String,
    pub has_server_pubnonce: bool,
}

pub async fn get_bip448_signature_record(
    pool: &sqlx::PgPool,
    statechain_id: &str,
    signing_id: &str,
) -> Option<Bip448SignatureRecord> {
    let query = "\
        SELECT server_pubnonce, challenge, negate_seckey, server_partial_sig \
        FROM bip448_signature_data \
        WHERE statechain_id = $1 AND signing_id = $2";

    let row = sqlx::query(query)
        .bind(statechain_id)
        .bind(signing_id)
        .fetch_optional(pool)
        .await
        .unwrap();

    row.map(|row| Bip448SignatureRecord {
        server_pubnonce: row.get(0),
        challenge: row.get(1),
        negate_seckey: row.get(2),
        server_partial_sig: row.get(3),
    })
}

pub async fn get_incomplete_bip448_signature_record(
    pool: &sqlx::PgPool,
    statechain_id: &str,
) -> Option<Bip448IncompleteSignatureRecord> {
    let query = "\
        SELECT signing_id, server_pubnonce IS NOT NULL \
        FROM bip448_signature_data \
        WHERE statechain_id = $1 AND server_partial_sig IS NULL \
        ORDER BY created_at ASC \
        LIMIT 1";

    let row = sqlx::query(query)
        .bind(statechain_id)
        .fetch_optional(pool)
        .await
        .unwrap();

    row.map(|row| Bip448IncompleteSignatureRecord {
        signing_id: row.get(0),
        has_server_pubnonce: row.get(1),
    })
}

/// Reserves a fresh signature record before the enclave creates its public
/// nonce. Returns `false` when a concurrent request already reserved this
/// opaque signing id; `signing_nonce_leases` enforces the one in-flight round
/// per statechain invariant.
pub async fn insert_bip448_signature_reservation(
    pool: &sqlx::PgPool,
    statechain_id: &str,
    signing_id: &str,
) -> bool {
    let query = "\
        INSERT INTO bip448_signature_data \
        (statechain_id, signing_id) \
        VALUES ($1, $2) \
        ON CONFLICT DO NOTHING";

    let result = sqlx::query(query)
        .bind(statechain_id)
        .bind(signing_id)
        .execute(pool)
        .await
        .unwrap();

    result.rows_affected() == 1
}

pub async fn update_bip448_signature_data_server_pubnonce_if_lease_matches(
    pool: &sqlx::PgPool,
    statechain_id: &str,
    signing_id: &str,
    server_pubnonce: &str,
    lease_token: &str,
) -> bool {
    let query = "\
        UPDATE bip448_signature_data AS signature \
        SET server_pubnonce = $1, updated_at = NOW() \
        WHERE signature.statechain_id = $2 AND signature.signing_id = $3 \
          AND signature.server_pubnonce IS NULL AND signature.challenge IS NULL \
          AND EXISTS (\
              SELECT 1 \
              FROM signing_nonce_leases AS lease \
              WHERE lease.statechain_id = signature.statechain_id \
                AND lease.signing_id = signature.signing_id \
                AND lease.lease_token = $4\
          )";

    let result = sqlx::query(query)
        .bind(server_pubnonce)
        .bind(statechain_id)
        .bind(signing_id)
        .bind(lease_token)
        .execute(pool)
        .await
        .unwrap();

    result.rows_affected() == 1
}

pub async fn delete_bip448_signature_reservation(
    pool: &sqlx::PgPool,
    statechain_id: &str,
    signing_id: &str,
) {
    let query = "\
        DELETE FROM bip448_signature_data \
        WHERE statechain_id = $1 AND signing_id = $2 \
          AND server_pubnonce IS NULL AND challenge IS NULL AND server_partial_sig IS NULL";

    let _ = sqlx::query(query)
        .bind(statechain_id)
        .bind(signing_id)
        .execute(pool)
        .await
        .unwrap();
}

pub async fn try_claim_bip448_signature_data_challenge(
    pool: &sqlx::PgPool,
    statechain_id: &str,
    signing_id: &str,
    server_pubnonce: &str,
    challenge: &str,
    negate_seckey: bool,
) -> bool {
    let query = "\
        UPDATE bip448_signature_data \
        SET challenge = $1, negate_seckey = $2, updated_at = NOW() \
        WHERE statechain_id = $3 AND signing_id = $4 \
          AND server_pubnonce = $5 AND challenge IS NULL";

    let result = sqlx::query(query)
        .bind(challenge)
        .bind(negate_seckey)
        .bind(statechain_id)
        .bind(signing_id)
        .bind(server_pubnonce)
        .execute(pool)
        .await
        .unwrap();

    result.rows_affected() == 1
}

pub async fn clear_bip448_signature_data_challenge(
    pool: &sqlx::PgPool,
    statechain_id: &str,
    signing_id: &str,
    challenge: &str,
) -> bool {
    let query = "\
        UPDATE bip448_signature_data \
        SET challenge = NULL, negate_seckey = NULL, updated_at = NOW() \
        WHERE statechain_id = $1 AND signing_id = $2 \
          AND challenge = $3 AND server_partial_sig IS NULL";

    let result = sqlx::query(query)
        .bind(statechain_id)
        .bind(signing_id)
        .bind(challenge)
        .execute(pool)
        .await
        .unwrap();

    result.rows_affected() == 1
}

pub async fn update_bip448_signature_data_partial_sig(
    pool: &sqlx::PgPool,
    statechain_id: &str,
    signing_id: &str,
    challenge: &str,
    server_partial_sig: &str,
) -> bool {
    let query = "\
        UPDATE bip448_signature_data \
        SET server_partial_sig = $1, updated_at = NOW() \
        WHERE statechain_id = $2 AND signing_id = $3 \
          AND challenge = $4 AND server_partial_sig IS NULL";

    let result = sqlx::query(query)
        .bind(server_partial_sig)
        .bind(statechain_id)
        .bind(signing_id)
        .bind(challenge)
        .execute(pool)
        .await
        .unwrap();

    result.rows_affected() == 1
}
