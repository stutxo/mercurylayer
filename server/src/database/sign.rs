use sqlx::Row;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacySignatureRecord {
    pub server_pubnonce: String,
    pub challenge: Option<String>,
    pub negate_seckey: Option<i32>,
    pub server_partial_sig: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegacyChallengeClaim {
    Claimed,
    RetryClaimed,
    Replay { server_partial_sig: String },
    NotFound,
    Conflict { reason: &'static str },
}

pub fn normalize_hex_wire_value(value: &str) -> String {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value)
        .to_ascii_lowercase()
}

fn legacy_record_from_row(row: &sqlx::postgres::PgRow) -> LegacySignatureRecord {
    LegacySignatureRecord {
        server_pubnonce: row.get("server_pubnonce"),
        challenge: row.get("challenge"),
        negate_seckey: row.get("negate_seckey"),
        server_partial_sig: row.get("server_partial_sig"),
    }
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

pub async fn legacy_signing_nonce_lease_matches(
    pool: &sqlx::PgPool,
    statechain_id: &str,
    lease_token: &str,
) -> bool {
    let query = "\
        UPDATE signing_nonce_leases \
        SET updated_at = clock_timestamp() \
        WHERE statechain_id = $1 AND protocol = $2 \
          AND signing_id IS NULL AND lease_token = $3 \
        RETURNING 1";

    sqlx::query(query)
        .bind(statechain_id)
        .bind(LEGACY_SIGNING_PROTOCOL)
        .bind(lease_token)
        .fetch_optional(pool)
        .await
        .unwrap()
        .is_some()
}

pub async fn bip448_signing_nonce_lease_matches(
    pool: &sqlx::PgPool,
    statechain_id: &str,
    signing_id: &str,
    lease_token: &str,
) -> bool {
    let query = "\
        UPDATE signing_nonce_leases \
        SET updated_at = clock_timestamp() \
        WHERE statechain_id = $1 AND protocol = $2 \
          AND signing_id = $3 AND lease_token = $4 \
        RETURNING 1";

    sqlx::query(query)
        .bind(statechain_id)
        .bind(BIP448_SIGNING_PROTOCOL)
        .bind(signing_id)
        .bind(lease_token)
        .fetch_optional(pool)
        .await
        .unwrap()
        .is_some()
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
/// protection. Fresh sign/first handlers refresh their exact `lease_token`
/// before asking the lockbox for a nonce and then persist nonce state only if
/// the same token is still present. Legacy and BIP448 incomplete rounds are
/// nonce rows without a stored partial signature.
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
                             AND signature.server_partial_sig IS NULL \
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

pub async fn get_incomplete_legacy_signature_record(
    pool: &sqlx::PgPool,
    statechain_id: &str,
) -> Option<LegacySignatureRecord> {
    let query = "\
        SELECT server_pubnonce, challenge, negate_seckey, server_partial_sig \
        FROM statechain_signature_data AS signature \
        WHERE signature.statechain_id = $1 \
          AND signature.server_pubnonce IS NOT NULL \
          AND signature.server_partial_sig IS NULL \
          AND (\
              signature.challenge IS NULL \
              OR signature.negate_seckey IS NOT NULL \
              OR EXISTS (\
                  SELECT 1 \
                  FROM signing_nonce_leases AS lease \
                  WHERE lease.statechain_id = signature.statechain_id \
                    AND lease.protocol = $2 \
                    AND signature.created_at >= lease.created_at\
              )\
          ) \
        ORDER BY signature.created_at ASC, signature.id ASC \
        LIMIT 1";

    sqlx::query(query)
        .bind(statechain_id)
        .bind(LEGACY_SIGNING_PROTOCOL)
        .fetch_optional(pool)
        .await
        .unwrap()
        .as_ref()
        .map(legacy_record_from_row)
}

pub async fn get_legacy_signature_record(
    pool: &sqlx::PgPool,
    statechain_id: &str,
    server_pubnonce: &str,
) -> Option<LegacySignatureRecord> {
    let server_pubnonce = normalize_hex_wire_value(server_pubnonce);
    let query = "\
        SELECT server_pubnonce, challenge, negate_seckey, server_partial_sig \
        FROM statechain_signature_data \
        WHERE statechain_id = $1 \
          AND server_pubnonce IS NOT NULL \
          AND LOWER(REGEXP_REPLACE(server_pubnonce, '^0[xX]', '')) = $2 \
        ORDER BY created_at DESC, id DESC \
        LIMIT 1";

    sqlx::query(query)
        .bind(statechain_id)
        .bind(server_pubnonce)
        .fetch_optional(pool)
        .await
        .unwrap()
        .as_ref()
        .map(legacy_record_from_row)
}

pub async fn insert_new_signature_data_if_lease_matches(
    pool: &sqlx::PgPool,
    server_pubnonce: &str,
    statechain_id: &str,
    lease_token: &str,
) -> bool {
    let mut transaction = pool.begin().await.unwrap();
    let server_pubnonce = normalize_hex_wire_value(server_pubnonce);

    let lease_query = "\
        SELECT 1 \
        FROM signing_nonce_leases \
        WHERE statechain_id = $1 AND protocol = $2 \
          AND signing_id IS NULL AND lease_token = $3";

    let lease = sqlx::query(lease_query)
        .bind(statechain_id)
        .bind(LEGACY_SIGNING_PROTOCOL)
        .bind(lease_token)
        .fetch_optional(&mut *transaction)
        .await
        .unwrap();

    if lease.is_none() {
        transaction.rollback().await.unwrap();
        return false;
    }

    let incomplete_query = "\
        SELECT 1 \
        FROM statechain_signature_data \
        WHERE statechain_id = $1 \
          AND server_pubnonce IS NOT NULL \
          AND server_partial_sig IS NULL \
          AND (challenge IS NULL OR negate_seckey IS NOT NULL) \
        LIMIT 1 \
        FOR UPDATE";

    let incomplete = sqlx::query(incomplete_query)
        .bind(statechain_id)
        .fetch_optional(&mut *transaction)
        .await
        .unwrap();

    if incomplete.is_some() {
        transaction.rollback().await.unwrap();
        return false;
    }

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
        .bind(&server_pubnonce)
        .bind(statechain_id)
        .bind(new_tx_n)
        .execute(&mut *transaction)
        .await
        .unwrap();

    transaction.commit().await.unwrap();

    true
}

/// Decides how a legacy sign/second maps against an already-completed signature
/// record (one with a stored `server_partial_sig`). Returns `None` when the
/// record has no stored partial signature yet. Shared by the endpoint's
/// pre-lockbox replay check and the exact-match branch of
/// [`claim_or_replay_legacy_signature_data_challenge`], so both layers agree on
/// exactly-once replay vs. conflict. `negate_seckey` is the DB-normalized i32.
pub fn legacy_completed_replay_decision(
    record: &LegacySignatureRecord,
    challenge: &str,
    negate_seckey: i32,
) -> Option<LegacyChallengeClaim> {
    record.server_partial_sig.as_ref()?;

    let decision = match (record.challenge.as_deref(), record.negate_seckey) {
        (Some(stored_challenge), Some(stored_negate))
            if stored_challenge == challenge && stored_negate == negate_seckey =>
        {
            LegacyChallengeClaim::Replay {
                server_partial_sig: record.server_partial_sig.clone().unwrap(),
            }
        }
        (Some(stored_challenge), _) if stored_challenge != challenge => {
            LegacyChallengeClaim::Conflict {
                reason: "challenge does not match the stored legacy signature record",
            }
        }
        (_, Some(stored_negate)) if stored_negate != negate_seckey => {
            LegacyChallengeClaim::Conflict {
                reason: "negate_seckey flag does not match the stored legacy signature record",
            }
        }
        _ => LegacyChallengeClaim::Conflict {
            reason: "stored legacy partial signature is missing replay metadata",
        },
    };

    Some(decision)
}

pub async fn claim_or_replay_legacy_signature_data_challenge(
    pool: &sqlx::PgPool,
    statechain_id: &str,
    server_pubnonce: &str,
    challenge: &str,
    negate_seckey: u8,
) -> Result<LegacyChallengeClaim, sqlx::Error> {
    let mut transaction = pool.begin().await?;
    let normalized_server_pubnonce = normalize_hex_wire_value(server_pubnonce);
    let negate_seckey = i32::from(negate_seckey);

    let exact_query = "\
        SELECT id, server_pubnonce, challenge, negate_seckey, server_partial_sig \
        FROM statechain_signature_data \
        WHERE statechain_id = $1 \
          AND server_pubnonce IS NOT NULL \
          AND LOWER(REGEXP_REPLACE(server_pubnonce, '^0[xX]', '')) = $2 \
        ORDER BY created_at DESC, id DESC \
        LIMIT 1 \
        FOR UPDATE";

    let exact = sqlx::query(exact_query)
        .bind(statechain_id)
        .bind(&normalized_server_pubnonce)
        .fetch_optional(&mut *transaction)
        .await?;

    if let Some(row) = exact.as_ref() {
        let record = legacy_record_from_row(row);
        if let Some(result) = legacy_completed_replay_decision(&record, challenge, negate_seckey) {
            transaction.commit().await?;
            return Ok(result);
        }
    }

    let current_query = "\
        SELECT id, server_pubnonce, challenge, negate_seckey, server_partial_sig \
        FROM statechain_signature_data AS signature \
        WHERE signature.statechain_id = $1 \
          AND signature.server_pubnonce IS NOT NULL \
          AND signature.server_partial_sig IS NULL \
          AND (\
              signature.challenge IS NULL \
              OR signature.negate_seckey IS NOT NULL \
              OR EXISTS (\
                  SELECT 1 \
                  FROM signing_nonce_leases AS lease \
                  WHERE lease.statechain_id = signature.statechain_id \
                    AND lease.protocol = $2 \
                    AND signature.created_at >= lease.created_at\
              )\
          ) \
        ORDER BY signature.created_at ASC, signature.id ASC \
        LIMIT 1 \
        FOR UPDATE";

    let current = sqlx::query(current_query)
        .bind(statechain_id)
        .bind(LEGACY_SIGNING_PROTOCOL)
        .fetch_optional(&mut *transaction)
        .await?;

    let Some(current) = current else {
        transaction.commit().await?;
        return Ok(if exact.is_some() {
            LegacyChallengeClaim::Conflict {
                reason:
                    "legacy signing nonce is no longer active and has no stored partial signature",
            }
        } else {
            LegacyChallengeClaim::NotFound
        });
    };

    let current_record = legacy_record_from_row(&current);
    if normalize_hex_wire_value(&current_record.server_pubnonce) != normalized_server_pubnonce {
        transaction.commit().await?;
        return Ok(LegacyChallengeClaim::Conflict {
            reason: "server public nonce does not match the current legacy signing round",
        });
    }

    if let Some(stored_challenge) = current_record.challenge.as_deref() {
        let result = if stored_challenge != challenge {
            LegacyChallengeClaim::Conflict {
                reason: "challenge does not match the stored legacy signature record",
            }
        } else if current_record.negate_seckey != Some(negate_seckey) {
            LegacyChallengeClaim::Conflict {
                reason: "negate_seckey flag does not match the stored legacy signature record",
            }
        } else {
            LegacyChallengeClaim::RetryClaimed
        };

        transaction.commit().await?;
        return Ok(result);
    }

    let id: i32 = current.get("id");
    let update_query = "\
        UPDATE statechain_signature_data \
        SET challenge = $1, negate_seckey = $2, updated_at = NOW() \
        WHERE id = $3 AND challenge IS NULL AND server_partial_sig IS NULL";

    let result = sqlx::query(update_query)
        .bind(challenge)
        .bind(negate_seckey)
        .bind(id)
        .execute(&mut *transaction)
        .await?;

    transaction.commit().await?;

    Ok(if result.rows_affected() == 1 {
        LegacyChallengeClaim::Claimed
    } else {
        LegacyChallengeClaim::Conflict {
            reason: "legacy signing challenge was concurrently claimed",
        }
    })
}

pub async fn update_legacy_signature_data_partial_sig(
    pool: &sqlx::PgPool,
    statechain_id: &str,
    server_pubnonce: &str,
    challenge: &str,
    negate_seckey: u8,
    server_partial_sig: &str,
) -> Result<bool, sqlx::Error> {
    let server_pubnonce = normalize_hex_wire_value(server_pubnonce);
    let query = "\
        WITH candidate AS (\
            SELECT ctid \
            FROM statechain_signature_data \
            WHERE statechain_id = $2 \
              AND server_pubnonce IS NOT NULL \
              AND LOWER(REGEXP_REPLACE(server_pubnonce, '^0[xX]', '')) = $3 \
              AND challenge = $4 \
              AND negate_seckey = $5 \
              AND server_partial_sig IS NULL \
            ORDER BY created_at ASC, id ASC \
            LIMIT 1 \
            FOR UPDATE\
        ) \
        UPDATE statechain_signature_data AS signature \
        SET server_partial_sig = $1, updated_at = NOW() \
        FROM candidate \
        WHERE signature.ctid = candidate.ctid";

    let result = sqlx::query(query)
        .bind(server_partial_sig)
        .bind(statechain_id)
        .bind(server_pubnonce)
        .bind(challenge)
        .bind(i32::from(negate_seckey))
        .execute(pool)
        .await?;

    Ok(result.rows_affected() == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_hex_wire_value_strips_prefix_and_case() {
        assert_eq!(normalize_hex_wire_value("0xABCDEF"), "abcdef");
        assert_eq!(normalize_hex_wire_value("0XABCDEF"), "abcdef");
        assert_eq!(normalize_hex_wire_value("abcdef"), "abcdef");
    }
}
