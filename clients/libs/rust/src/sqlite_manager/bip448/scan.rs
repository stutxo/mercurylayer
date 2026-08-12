use std::collections::{HashMap, HashSet};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Row, Sqlite, SqliteConnection};

use crate::{bip448_funding::Bip448AppliedScanRevision, chain::ChainUtxo};

use super::super::{canonical_block_hash, canonical_txid};
use super::rows::{checked_u32, checked_u64};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip448ScanCursor {
    pub coverage_start_height: u32,
    pub scan_revision: u64,
    pub last_scanned_height: u32,
    pub last_scanned_block_hash: String,
}

pub const BIP448_FEE_RESERVATION_TTL_SECONDS: i64 = 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bip448FeeInputRecord {
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bip448PackageAttemptStatus {
    Pending,
    Submitted,
    Confirmed,
    Abandoned,
}

impl Bip448PackageAttemptStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::Submitted => "Submitted",
            Self::Confirmed => "Confirmed",
            Self::Abandoned => "Abandoned",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "Pending" => Ok(Self::Pending),
            "Submitted" => Ok(Self::Submitted),
            "Confirmed" => Ok(Self::Confirmed),
            "Abandoned" => Ok(Self::Abandoned),
            _ => Err(anyhow!("invalid BIP448 package-attempt status")),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Bip448PackageAttempt {
    pub wallet_name: String,
    pub statechain_id: String,
    pub role: String,
    pub parent_txid: String,
    pub child_txid: String,
    pub child_tx_hex: String,
    pub fee_inputs: Vec<Bip448FeeInputRecord>,
    pub target_feerate_sat_per_vbyte: f64,
    pub status: Bip448PackageAttemptStatus,
}
pub(crate) async fn load_bip448_scan_state(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    script_pubkey: &str,
) -> Result<(Option<Bip448ScanCursor>, Vec<ChainUtxo>)> {
    let cursor = sqlx::query(
        "SELECT coverage_start_height, scan_revision, last_scanned_height, last_scanned_block_hash \
         FROM bip448_scan_cursors WHERE wallet_name = $1 AND script_pubkey = $2",
    )
    .bind(wallet_name)
    .bind(script_pubkey)
    .fetch_optional(pool)
    .await?
    .map(|row| -> Result<_> {
        Ok(Bip448ScanCursor {
            coverage_start_height: u32::try_from(row.try_get::<i64, _>(0)?)?,
            scan_revision: u64::try_from(row.try_get::<i64, _>(1)?)?,
            last_scanned_height: u32::try_from(row.try_get::<i64, _>(2)?)?,
            last_scanned_block_hash: canonical_block_hash(row.try_get(3)?)?,
        })
    })
    .transpose()?;
    let rows = sqlx::query(
        "SELECT txid, vout, value_sats, height FROM bip448_scanned_outpoints \
         WHERE wallet_name = $1 AND script_pubkey = $2",
    )
    .bind(wallet_name)
    .bind(script_pubkey)
    .fetch_all(pool)
    .await?;
    let outpoints = rows
        .into_iter()
        .map(|row| {
            Ok(ChainUtxo {
                txid: canonical_txid(row.try_get(0)?)?,
                vout: u32::try_from(row.try_get::<i64, _>(1)?)?,
                value: u64::try_from(row.try_get::<i64, _>(2)?)?,
                height: u32::try_from(row.try_get::<i64, _>(3)?)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((cursor, outpoints))
}

pub(in crate::sqlite_manager) async fn replace_bip448_scan_cache_on(
    connection: &mut SqliteConnection,
    wallet_name: &str,
    script_pubkey: &str,
    outpoints: &[(String, u32, u64, u32)],
) -> Result<()> {
    let mut desired = outpoints.to_vec();
    desired.sort_by(|left, right| (left.0.as_str(), left.1).cmp(&(right.0.as_str(), right.1)));
    if desired
        .windows(2)
        .any(|rows| rows[0].0 == rows[1].0 && rows[0].1 == rows[1].1)
    {
        return Err(anyhow!("duplicate BIP448 scan-cache outpoint"));
    }
    let desired_keys = desired
        .iter()
        .map(|(txid, vout, _, _)| (txid.clone(), *vout))
        .collect::<HashSet<_>>();
    let existing = sqlx::query(
        "SELECT txid,vout FROM bip448_scanned_outpoints \
         WHERE wallet_name=$1 AND script_pubkey=$2 ORDER BY txid,vout",
    )
    .bind(wallet_name)
    .bind(script_pubkey)
    .fetch_all(&mut *connection)
    .await?;
    for row in existing {
        let txid = canonical_txid(row.try_get(0)?)?;
        let vout = checked_u32(&row, 1, "BIP448 scan-cache vout")?;
        if !desired_keys.contains(&(txid.clone(), vout)) {
            let deleted = sqlx::query(
                "DELETE FROM bip448_scanned_outpoints WHERE wallet_name=$1 \
                 AND script_pubkey=$2 AND txid=$3 AND vout=$4",
            )
            .bind(wallet_name)
            .bind(script_pubkey)
            .bind(txid)
            .bind(i64::from(vout))
            .execute(&mut *connection)
            .await?;
            if deleted.rows_affected() != 1 {
                return Err(anyhow!("BIP448 stale scan-cache compare-delete lost"));
            }
        }
    }
    for (txid, vout, value, height) in &desired {
        let written = sqlx::query(
            "INSERT INTO bip448_scanned_outpoints \
                (wallet_name,txid,vout,script_pubkey,value_sats,height) \
             VALUES ($1,$2,$3,$4,$5,$6) \
             ON CONFLICT(wallet_name,txid,vout) DO UPDATE SET \
                script_pubkey=excluded.script_pubkey,value_sats=excluded.value_sats, \
                height=excluded.height",
        )
        .bind(wallet_name)
        .bind(txid)
        .bind(i64::from(*vout))
        .bind(script_pubkey)
        .bind(i64::try_from(*value)?)
        .bind(i64::from(*height))
        .execute(&mut *connection)
        .await?;
        if written.rows_affected() != 1 {
            return Err(anyhow!(
                "BIP448 scan-cache upsert affected an unexpected row count"
            ));
        }
    }

    let reservation_rows = sqlx::query(
        "SELECT json_extract(fee.value,'$.txid'), \
            CAST(json_extract(fee.value,'$.vout') AS INTEGER), \
            CAST(json_extract(fee.value,'$.value_sats') AS INTEGER), \
            statechain_id || ':' || role,unixepoch(updated_at) \
         FROM bip448_package_attempts,json_each(fee_inputs_json) AS fee \
         WHERE wallet_name=$1 AND status IN ('Pending','Submitted') \
         ORDER BY 1,2,5 DESC,4 DESC",
    )
    .bind(wallet_name)
    .fetch_all(&mut *connection)
    .await?;
    let mut reservations = HashMap::new();
    for row in reservation_rows {
        let txid = canonical_txid(row.try_get(0)?)?;
        let vout = checked_u32(&row, 1, "BIP448 reservation vout")?;
        let value = checked_u64(&row, 2, "BIP448 reservation value")?;
        let reservation_id: String = row.try_get(3)?;
        let reservation_time: i64 = row.try_get(4)?;
        if reservation_time < 0 {
            return Err(anyhow!("BIP448 reservation timestamp is negative"));
        }
        reservations
            .entry((txid, vout))
            .or_insert((value, reservation_id, reservation_time));
    }
    for (txid, vout, value, _) in &desired {
        let Some((reserved_value, reservation_id, reservation_time)) =
            reservations.get(&(txid.clone(), *vout))
        else {
            continue;
        };
        if reserved_value != value {
            continue;
        }
        let live = sqlx::query(
            "SELECT reserved_by,reserved_at FROM bip448_scanned_outpoints \
             WHERE wallet_name=$1 AND script_pubkey=$2 AND txid=$3 AND vout=$4 \
             AND value_sats=$5",
        )
        .bind(wallet_name)
        .bind(script_pubkey)
        .bind(txid)
        .bind(i64::from(*vout))
        .bind(i64::try_from(*value)?)
        .fetch_optional(&mut *connection)
        .await?
        .ok_or_else(|| anyhow!("BIP448 reservation target disappeared from scan cache"))?;
        let live_id: Option<String> = live.try_get(0)?;
        let live_time: Option<i64> = live.try_get(1)?;
        if live_id.as_deref() == Some(reservation_id.as_str()) && live_time.is_some() {
            continue;
        }
        let updated = sqlx::query(
            "UPDATE bip448_scanned_outpoints SET reserved_by=$1,reserved_at=$2 \
             WHERE wallet_name=$3 AND script_pubkey=$4 AND txid=$5 AND vout=$6 \
             AND value_sats=$7",
        )
        .bind(reservation_id)
        .bind(*reservation_time)
        .bind(wallet_name)
        .bind(script_pubkey)
        .bind(txid)
        .bind(i64::from(*vout))
        .bind(i64::try_from(*value)?)
        .execute(&mut *connection)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(anyhow!("BIP448 reservation restoration CAS lost"));
        }
    }
    Ok(())
}

pub(crate) async fn persist_bip448_scan_state(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    script_pubkey: &str,
    cursor: &Bip448ScanCursor,
    outpoints: &[ChainUtxo],
) -> Result<Bip448AppliedScanRevision> {
    let block_hash = canonical_block_hash(&cursor.last_scanned_block_hash)?;
    let outpoints = outpoints
        .iter()
        .map(|outpoint| {
            Ok((
                canonical_txid(&outpoint.txid)?,
                outpoint.vout,
                outpoint.value,
                outpoint.height,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut transaction = pool.begin_with("BEGIN IMMEDIATE").await?;
    let live_cursor = sqlx::query(
        "SELECT coverage_start_height, scan_revision FROM bip448_scan_cursors \
         WHERE wallet_name = $1 AND script_pubkey = $2",
    )
    .bind(wallet_name)
    .bind(script_pubkey)
    .fetch_optional(&mut *transaction)
    .await?;
    let (coverage_start_height, live_revision) = match live_cursor {
        Some(row) => {
            let coverage = u32::try_from(row.try_get::<i64, _>(0)?)?;
            let revision = u64::try_from(row.try_get::<i64, _>(1)?)?;
            (coverage.min(cursor.coverage_start_height), revision)
        }
        None => (cursor.coverage_start_height, 0),
    };
    if live_revision != cursor.scan_revision {
        return Err(anyhow!(
            "BIP448 scan cursor changed while the candidate scan was running"
        ));
    }
    let scan_revision = live_revision
        .checked_add(1)
        .ok_or_else(|| anyhow!("BIP448 scan revision overflow"))?;
    let scan_revision_i64 = i64::try_from(scan_revision)
        .map_err(|_| anyhow!("BIP448 scan revision exceeds the SQLite integer domain"))?;
    replace_bip448_scan_cache_on(&mut transaction, wallet_name, script_pubkey, &outpoints).await?;
    let cursor_write = if live_revision == 0
        && sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bip448_scan_cursors \
             WHERE wallet_name = $1 AND script_pubkey = $2",
        )
        .bind(wallet_name)
        .bind(script_pubkey)
        .fetch_one(&mut *transaction)
        .await?
            == 0
    {
        sqlx::query(
            "INSERT INTO bip448_scan_cursors \
                (wallet_name, script_pubkey, coverage_start_height, scan_revision, \
                 last_scanned_height, last_scanned_block_hash) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(wallet_name)
        .bind(script_pubkey)
        .bind(i64::from(coverage_start_height))
        .bind(scan_revision_i64)
        .bind(i64::from(cursor.last_scanned_height))
        .bind(block_hash)
        .execute(&mut *transaction)
        .await?
    } else {
        sqlx::query(
            "UPDATE bip448_scan_cursors SET \
                coverage_start_height = $1, scan_revision = $2, \
                last_scanned_height = $3, last_scanned_block_hash = $4, \
                updated_at = CURRENT_TIMESTAMP \
             WHERE wallet_name = $5 AND script_pubkey = $6 AND scan_revision = $7",
        )
        .bind(i64::from(coverage_start_height))
        .bind(scan_revision_i64)
        .bind(i64::from(cursor.last_scanned_height))
        .bind(block_hash)
        .bind(wallet_name)
        .bind(script_pubkey)
        .bind(i64::try_from(live_revision)?)
        .execute(&mut *transaction)
        .await?
    };
    if cursor_write.rows_affected() != 1 {
        return Err(anyhow!("BIP448 scan cursor compare-and-set lost"));
    }
    transaction.commit().await?;
    Ok(Bip448AppliedScanRevision {
        script_pubkey: script_pubkey.to_owned(),
        scan_revision,
    })
}

#[cfg(test)]
pub(in crate::sqlite_manager) async fn clear_bip448_scan_state(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    script_pubkey: &str,
) -> Result<()> {
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "DELETE FROM bip448_scanned_outpoints \
         WHERE wallet_name = $1 AND script_pubkey = $2",
    )
    .bind(wallet_name)
    .bind(script_pubkey)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

pub(crate) fn bip448_reservation_id(statechain_id: &str, role: &str) -> String {
    format!("{statechain_id}:{role}")
}

pub(crate) async fn upsert_bip448_scanned_outpoint(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    script_pubkey: &str,
    outpoint: &ChainUtxo,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO bip448_scanned_outpoints \
            (wallet_name, txid, vout, script_pubkey, value_sats, height) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT(wallet_name, txid, vout) DO UPDATE SET \
            script_pubkey = excluded.script_pubkey, value_sats = excluded.value_sats, \
            height = excluded.height",
    )
    .bind(wallet_name)
    .bind(canonical_txid(&outpoint.txid)?)
    .bind(i64::from(outpoint.vout))
    .bind(script_pubkey)
    .bind(i64::try_from(outpoint.value)?)
    .bind(i64::from(outpoint.height))
    .execute(pool)
    .await?;
    Ok(())
}

pub(crate) async fn available_bip448_scanned_outpoints(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    script_pubkey: &str,
    reservation_id: &str,
) -> Result<Vec<ChainUtxo>> {
    let rows = sqlx::query(
        "SELECT txid, vout, value_sats, height FROM bip448_scanned_outpoints \
         WHERE wallet_name = $1 AND script_pubkey = $2 AND \
            (reserved_by IS NULL OR \
             (reserved_by <> $3 AND reserved_at <= unixepoch() - $4))",
    )
    .bind(wallet_name)
    .bind(script_pubkey)
    .bind(reservation_id)
    .bind(BIP448_FEE_RESERVATION_TTL_SECONDS)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(ChainUtxo {
                txid: canonical_txid(row.try_get(0)?)?,
                vout: u32::try_from(row.try_get::<i64, _>(1)?)?,
                value: u64::try_from(row.try_get::<i64, _>(2)?)?,
                height: u32::try_from(row.try_get::<i64, _>(3)?)?,
            })
        })
        .collect()
}

pub(crate) async fn ensure_no_orphaned_bip448_reservation(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    role: &str,
) -> Result<()> {
    let reservation_id = bip448_reservation_id(statechain_id, role);
    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT EXISTS(\
            SELECT 1 FROM bip448_scanned_outpoints \
            WHERE wallet_name = $1 AND reserved_by = $2\
         )",
    )
    .bind(wallet_name)
    .bind(reservation_id)
    .fetch_one(pool)
    .await?;
    if exists != 0 {
        return Err(anyhow!(
            "BIP448 fee reservation exists without its package attempt"
        ));
    }
    Ok(())
}

pub async fn get_bip448_package_attempt(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    role: &str,
) -> Result<Option<Bip448PackageAttempt>> {
    let row = sqlx::query(
        "SELECT parent_txid, child_txid, child_tx_hex, fee_inputs_json, \
                target_feerate_sat_per_vbyte, status \
         FROM bip448_package_attempts \
         WHERE wallet_name = $1 AND statechain_id = $2 AND role = $3",
    )
    .bind(wallet_name)
    .bind(statechain_id)
    .bind(role)
    .fetch_optional(pool)
    .await?;
    row.map(|row| -> Result<_> {
        let parent_txid: String = row.try_get(0)?;
        let child_txid: String = row.try_get(1)?;
        let fee_inputs: Vec<Bip448FeeInputRecord> = serde_json::from_str(row.try_get(3)?)
            .map_err(|_| anyhow!("invalid BIP448 package-attempt fee inputs"))?;
        if canonical_txid(&parent_txid)? != parent_txid
            || canonical_txid(&child_txid)? != child_txid
            || fee_inputs
                .iter()
                .any(|input| canonical_txid(&input.txid).map_or(true, |txid| txid != input.txid))
        {
            return Err(anyhow!("non-canonical BIP448 package-attempt txid"));
        }
        Ok(Bip448PackageAttempt {
            wallet_name: wallet_name.to_owned(),
            statechain_id: statechain_id.to_owned(),
            role: role.to_owned(),
            parent_txid,
            child_txid,
            child_tx_hex: row.try_get(2)?,
            fee_inputs,
            target_feerate_sat_per_vbyte: row.try_get(4)?,
            status: Bip448PackageAttemptStatus::parse(row.try_get(5)?)?,
        })
    })
    .transpose()
}

pub(crate) async fn insert_bip448_package_attempt(
    pool: &Pool<Sqlite>,
    attempt: &Bip448PackageAttempt,
) -> Result<()> {
    if attempt.status != Bip448PackageAttemptStatus::Pending
        || !attempt.target_feerate_sat_per_vbyte.is_finite()
        || attempt.target_feerate_sat_per_vbyte <= 0.0
    {
        return Err(anyhow!("invalid BIP448 package attempt"));
    }
    let parent_txid = canonical_txid(&attempt.parent_txid)?;
    let child_txid = canonical_txid(&attempt.child_txid)?;
    let mut fee_inputs = attempt.fee_inputs.clone();
    for input in &mut fee_inputs {
        input.txid = canonical_txid(&input.txid)?;
    }
    let reservation_id = bip448_reservation_id(&attempt.statechain_id, &attempt.role);
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "INSERT INTO bip448_package_attempts \
            (wallet_name, statechain_id, role, parent_txid, child_txid, child_tx_hex, \
             fee_inputs_json, target_feerate_sat_per_vbyte, status) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(&attempt.wallet_name)
    .bind(&attempt.statechain_id)
    .bind(&attempt.role)
    .bind(parent_txid)
    .bind(child_txid)
    .bind(&attempt.child_tx_hex)
    .bind(serde_json::to_string(&fee_inputs)?)
    .bind(attempt.target_feerate_sat_per_vbyte)
    .bind(attempt.status.as_str())
    .execute(&mut *transaction)
    .await?;
    for input in &fee_inputs {
        let result = sqlx::query(
            "UPDATE bip448_scanned_outpoints SET reserved_by = $1, reserved_at = unixepoch() \
             WHERE wallet_name = $2 AND txid = $3 AND vout = $4 AND \
                (reserved_by IS NULL OR \
                 (reserved_by <> $1 AND reserved_at <= unixepoch() - $5))",
        )
        .bind(&reservation_id)
        .bind(&attempt.wallet_name)
        .bind(canonical_txid(&input.txid)?)
        .bind(i64::from(input.vout))
        .bind(BIP448_FEE_RESERVATION_TTL_SECONDS)
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() != 1 {
            return Err(anyhow!("BIP448 fee input is unavailable"));
        }
    }
    transaction.commit().await?;
    Ok(())
}

pub(crate) async fn reacquire_bip448_package_attempt_reservations(
    pool: &Pool<Sqlite>,
    attempt: &Bip448PackageAttempt,
) -> Result<()> {
    if !matches!(
        attempt.status,
        Bip448PackageAttemptStatus::Pending | Bip448PackageAttemptStatus::Submitted
    ) {
        return Err(anyhow!("BIP448 package attempt is not active"));
    }
    let fee_inputs_json = serde_json::to_string(&attempt.fee_inputs)?;
    let mut transaction = pool.begin().await?;
    let status = sqlx::query_scalar::<_, String>(
        "SELECT status FROM bip448_package_attempts \
         WHERE wallet_name = $1 AND statechain_id = $2 AND role = $3 AND \
            parent_txid = $4 AND child_txid = $5 AND child_tx_hex = $6 AND \
            fee_inputs_json = $7 AND target_feerate_sat_per_vbyte = $8",
    )
    .bind(&attempt.wallet_name)
    .bind(&attempt.statechain_id)
    .bind(&attempt.role)
    .bind(canonical_txid(&attempt.parent_txid)?)
    .bind(canonical_txid(&attempt.child_txid)?)
    .bind(&attempt.child_tx_hex)
    .bind(fee_inputs_json)
    .bind(attempt.target_feerate_sat_per_vbyte)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| anyhow!("stored BIP448 package attempt changed before replay"))?;
    if !matches!(
        Bip448PackageAttemptStatus::parse(&status)?,
        Bip448PackageAttemptStatus::Pending | Bip448PackageAttemptStatus::Submitted
    ) {
        return Err(anyhow!("BIP448 package attempt is not active"));
    }

    let reservation_id = bip448_reservation_id(&attempt.statechain_id, &attempt.role);
    for input in &attempt.fee_inputs {
        let result = sqlx::query(
            "UPDATE bip448_scanned_outpoints \
             SET reserved_by = $1, reserved_at = unixepoch() \
             WHERE wallet_name = $2 AND txid = $3 AND vout = $4 AND value_sats = $5 AND \
                (reserved_by IS NULL OR reserved_by = $1 OR \
                 reserved_at <= unixepoch() - $6)",
        )
        .bind(&reservation_id)
        .bind(&attempt.wallet_name)
        .bind(canonical_txid(&input.txid)?)
        .bind(i64::from(input.vout))
        .bind(i64::try_from(input.value_sats)?)
        .bind(BIP448_FEE_RESERVATION_TTL_SECONDS)
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() != 1 {
            return Err(anyhow!(
                "stored BIP448 package attempt cannot reacquire its fee inputs"
            ));
        }
    }
    transaction.commit().await?;
    Ok(())
}

pub async fn set_bip448_package_attempt_status(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    role: &str,
    status: Bip448PackageAttemptStatus,
) -> Result<()> {
    let mut transaction = pool.begin().await?;
    let result = sqlx::query(
        "UPDATE bip448_package_attempts SET status = $1, updated_at = CURRENT_TIMESTAMP \
         WHERE wallet_name = $2 AND statechain_id = $3 AND role = $4",
    )
    .bind(status.as_str())
    .bind(wallet_name)
    .bind(statechain_id)
    .bind(role)
    .execute(&mut *transaction)
    .await?;
    if result.rows_affected() != 1 {
        return Err(anyhow!("BIP448 package attempt is missing"));
    }
    if matches!(
        status,
        Bip448PackageAttemptStatus::Confirmed | Bip448PackageAttemptStatus::Abandoned
    ) {
        sqlx::query(
            "UPDATE bip448_scanned_outpoints SET reserved_by = NULL, reserved_at = NULL \
             WHERE wallet_name = $1 AND reserved_by = $2",
        )
        .bind(wallet_name)
        .bind(bip448_reservation_id(statechain_id, role))
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(())
}
