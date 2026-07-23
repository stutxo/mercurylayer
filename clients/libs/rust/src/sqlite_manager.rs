use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use bitcoin::{BlockHash, Txid};
use mercurylib::{
    bip448_statechain::{script, storage::Bip448StatechainRecord},
    transfer::bip448::Bip448TransferMsg,
    wallet::{BackupTx, Wallet},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{Pool, Row, Sqlite};

use crate::chain::ChainUtxo;
use crate::deposit::Bip448AcceptedDepositState;
use crate::transfer_receiver::bip448_transfer_receiver::Bip448AcceptedTransferState;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip448PendingDepositSigning {
    pub wallet_name: String,
    pub statechain_id: String,
    pub funding_txid: String,
    pub funding_vout: u32,
    pub funding_value_sats: u64,
    pub update_template_hash: String,
    pub settlement_template_hash: String,
    pub state_locktime: u32,
    pub signing_id: String,
    pub client_secret_nonce: String,
    pub client_public_nonce: String,
    pub blinding_factor: String,
    pub server_public_nonce: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Bip448ScanCursor {
    pub last_scanned_height: u32,
    pub last_scanned_block_hash: String,
}

pub const BIP448_FEE_RESERVATION_TTL_SECONDS: i64 = 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bip448FeeInputRecord { pub txid: String, pub vout: u32, pub value_sats: u64 }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bip448PackageAttemptStatus {
    Pending, Submitted, Confirmed, Abandoned,
}

impl Bip448PackageAttemptStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "Pending", Self::Submitted => "Submitted",
            Self::Confirmed => "Confirmed", Self::Abandoned => "Abandoned",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "Pending" => Ok(Self::Pending), "Submitted" => Ok(Self::Submitted),
            "Confirmed" => Ok(Self::Confirmed), "Abandoned" => Ok(Self::Abandoned),
            _ => Err(anyhow!("invalid BIP448 package-attempt status")),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Bip448PackageAttempt {
    pub wallet_name: String, pub statechain_id: String, pub role: String,
    pub parent_txid: String, pub child_txid: String, pub child_tx_hex: String,
    pub fee_inputs: Vec<Bip448FeeInputRecord>,
    pub target_feerate_sat_per_vbyte: f64, pub status: Bip448PackageAttemptStatus,
}

pub(crate) fn canonical_txid(txid: &str) -> Result<String> {
    Ok(Txid::from_str(txid).context("invalid txid")?.to_string())
}

fn canonical_wallet_json(wallet: &Wallet) -> Result<String> {
    let mut wallet = wallet.clone();
    for coin in &mut wallet.coins {
        for txid in [&mut coin.utxo_txid, &mut coin.tx_cpfp, &mut coin.tx_withdraw] {
            if let Some(txid) = txid {
                *txid = canonical_txid(txid)?;
            }
        }
    }
    Ok(serde_json::to_string(&wallet)?)
}

fn canonical_block_hash(block_hash: &str) -> Result<String> {
    Ok(BlockHash::from_str(block_hash)
        .context("invalid block hash")?.to_string())
}

pub(crate) async fn load_bip448_scan_state(
    pool: &Pool<Sqlite>, wallet_name: &str, script_pubkey: &str,
) -> Result<(Option<Bip448ScanCursor>, Vec<ChainUtxo>)> {
    let cursor = sqlx::query(
        "SELECT last_scanned_height, last_scanned_block_hash \
         FROM bip448_scan_cursors WHERE wallet_name = $1 AND script_pubkey = $2",
    )
    .bind(wallet_name).bind(script_pubkey).fetch_optional(pool).await?
    .map(|row| -> Result<_> {
        Ok(Bip448ScanCursor {
            last_scanned_height: u32::try_from(row.try_get::<i64, _>(0)?)?,
            last_scanned_block_hash: canonical_block_hash(row.try_get(1)?)?,
        })
    })
    .transpose()?;
    let rows = sqlx::query(
        "SELECT txid, vout, value_sats, height FROM bip448_scanned_outpoints \
         WHERE wallet_name = $1 AND script_pubkey = $2",
    )
    .bind(wallet_name).bind(script_pubkey).fetch_all(pool).await?;
    let outpoints = rows
        .into_iter()
        .map(|row| Ok(ChainUtxo {
            txid: canonical_txid(row.try_get(0)?)?,
            vout: u32::try_from(row.try_get::<i64, _>(1)?)?,
            value: u64::try_from(row.try_get::<i64, _>(2)?)?,
            height: u32::try_from(row.try_get::<i64, _>(3)?)?,
        }))
        .collect::<Result<Vec<_>>>()?;
    Ok((cursor, outpoints))
}

pub(crate) async fn persist_bip448_scan_state(
    pool: &Pool<Sqlite>, wallet_name: &str, script_pubkey: &str,
    cursor: &Bip448ScanCursor, outpoints: &[ChainUtxo],
) -> Result<()> {
    let block_hash = canonical_block_hash(&cursor.last_scanned_block_hash)?;
    let outpoints = outpoints
        .iter()
        .map(|outpoint| Ok((canonical_txid(&outpoint.txid)?, outpoint.vout,
            outpoint.value, outpoint.height)))
        .collect::<Result<Vec<_>>>()?;
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "UPDATE bip448_scanned_outpoints SET height = -1 \
         WHERE wallet_name = $1 AND script_pubkey = $2",
    )
    .bind(wallet_name).bind(script_pubkey).execute(&mut *transaction).await?;
    for (txid, vout, value, height) in outpoints {
        sqlx::query(
            "INSERT INTO bip448_scanned_outpoints \
                (wallet_name, txid, vout, script_pubkey, value_sats, height) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT(wallet_name, txid, vout) DO UPDATE SET \
                script_pubkey = excluded.script_pubkey, value_sats = excluded.value_sats, \
                height = excluded.height",
        )
        .bind(wallet_name).bind(txid).bind(i64::from(vout)).bind(script_pubkey)
        .bind(i64::try_from(value)?).bind(i64::from(height))
        .execute(&mut *transaction).await?;
    }
    sqlx::query(
        "DELETE FROM bip448_scanned_outpoints \
         WHERE wallet_name = $1 AND script_pubkey = $2 AND height = -1",
    )
    .bind(wallet_name).bind(script_pubkey).execute(&mut *transaction).await?;
    sqlx::query(
        "WITH active_reservations AS (\
            SELECT json_extract(fee.value, '$.txid') AS txid, \
                CAST(json_extract(fee.value, '$.vout') AS INTEGER) AS vout, \
                CAST(json_extract(fee.value, '$.value_sats') AS INTEGER) AS value_sats, \
                statechain_id || ':' || role AS reservation_id, \
                unixepoch(updated_at) AS reservation_time \
            FROM bip448_package_attempts, json_each(fee_inputs_json) AS fee \
            WHERE wallet_name = $1 AND status IN ('Pending', 'Submitted')\
         ) \
         UPDATE bip448_scanned_outpoints AS outpoint SET \
            reserved_at = CASE \
                WHEN reserved_by = (\
                    SELECT reservation_id FROM active_reservations \
                    WHERE txid = outpoint.txid AND vout = outpoint.vout AND \
                        value_sats = outpoint.value_sats \
                    ORDER BY reservation_time DESC, reservation_id DESC LIMIT 1\
                ) AND reserved_at IS NOT NULL THEN reserved_at \
                ELSE (\
                    SELECT reservation_time FROM active_reservations \
                    WHERE txid = outpoint.txid AND vout = outpoint.vout AND \
                        value_sats = outpoint.value_sats \
                    ORDER BY reservation_time DESC, reservation_id DESC LIMIT 1\
                ) \
            END, \
            reserved_by = (\
                SELECT reservation_id FROM active_reservations \
                WHERE txid = outpoint.txid AND vout = outpoint.vout AND \
                    value_sats = outpoint.value_sats \
                ORDER BY reservation_time DESC, reservation_id DESC LIMIT 1\
            ) \
         WHERE wallet_name = $1 AND script_pubkey = $2 AND EXISTS (\
            SELECT 1 FROM active_reservations \
            WHERE txid = outpoint.txid AND vout = outpoint.vout AND \
                value_sats = outpoint.value_sats\
         )",
    )
    .bind(wallet_name).bind(script_pubkey).execute(&mut *transaction).await?;
    sqlx::query(
        "INSERT INTO bip448_scan_cursors \
            (wallet_name, script_pubkey, last_scanned_height, last_scanned_block_hash) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT(wallet_name, script_pubkey) DO UPDATE SET \
            last_scanned_height = excluded.last_scanned_height, \
            last_scanned_block_hash = excluded.last_scanned_block_hash, \
            updated_at = CURRENT_TIMESTAMP",
    )
    .bind(wallet_name).bind(script_pubkey).bind(i64::from(cursor.last_scanned_height))
    .bind(block_hash).execute(&mut *transaction).await?;
    transaction.commit().await?;
    Ok(())
}

pub(crate) async fn clear_bip448_scan_state(
    pool: &Pool<Sqlite>, wallet_name: &str, script_pubkey: &str,
) -> Result<()> {
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "DELETE FROM bip448_scanned_outpoints \
         WHERE wallet_name = $1 AND script_pubkey = $2",
    )
    .bind(wallet_name).bind(script_pubkey).execute(&mut *transaction).await?;
    sqlx::query(
        "DELETE FROM bip448_scan_cursors WHERE wallet_name = $1 AND script_pubkey = $2",
    )
    .bind(wallet_name).bind(script_pubkey).execute(&mut *transaction).await?;
    transaction.commit().await?;
    Ok(())
}

pub(crate) fn bip448_reservation_id(statechain_id: &str, role: &str) -> String {
    format!("{statechain_id}:{role}")
}

pub(crate) async fn upsert_bip448_scanned_outpoint(
    pool: &Pool<Sqlite>, wallet_name: &str, script_pubkey: &str, outpoint: &ChainUtxo,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO bip448_scanned_outpoints \
            (wallet_name, txid, vout, script_pubkey, value_sats, height) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT(wallet_name, txid, vout) DO UPDATE SET \
            script_pubkey = excluded.script_pubkey, value_sats = excluded.value_sats, \
            height = excluded.height",
    )
    .bind(wallet_name).bind(canonical_txid(&outpoint.txid)?)
    .bind(i64::from(outpoint.vout)).bind(script_pubkey)
    .bind(i64::try_from(outpoint.value)?).bind(i64::from(outpoint.height))
    .execute(pool).await?;
    Ok(())
}

pub(crate) async fn available_bip448_scanned_outpoints(
    pool: &Pool<Sqlite>, wallet_name: &str, script_pubkey: &str, reservation_id: &str,
) -> Result<Vec<ChainUtxo>> {
    let rows = sqlx::query(
        "SELECT txid, vout, value_sats, height FROM bip448_scanned_outpoints \
         WHERE wallet_name = $1 AND script_pubkey = $2 AND \
            (reserved_by IS NULL OR \
             (reserved_by <> $3 AND reserved_at <= unixepoch() - $4))",
    )
    .bind(wallet_name).bind(script_pubkey).bind(reservation_id)
    .bind(BIP448_FEE_RESERVATION_TTL_SECONDS).fetch_all(pool).await?;
    rows.into_iter().map(|row| Ok(ChainUtxo {
        txid: canonical_txid(row.try_get(0)?)?,
        vout: u32::try_from(row.try_get::<i64, _>(1)?)?,
        value: u64::try_from(row.try_get::<i64, _>(2)?)?,
        height: u32::try_from(row.try_get::<i64, _>(3)?)?,
    })).collect()
}

pub(crate) async fn ensure_no_orphaned_bip448_reservation(
    pool: &Pool<Sqlite>, wallet_name: &str, statechain_id: &str, role: &str,
) -> Result<()> {
    let reservation_id = bip448_reservation_id(statechain_id, role);
    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT EXISTS(\
            SELECT 1 FROM bip448_scanned_outpoints \
            WHERE wallet_name = $1 AND reserved_by = $2\
         )",
    )
    .bind(wallet_name).bind(reservation_id).fetch_one(pool).await?;
    if exists != 0 {
        return Err(anyhow!(
            "BIP448 fee reservation exists without its package attempt"
        ));
    }
    Ok(())
}

pub async fn get_bip448_package_attempt(
    pool: &Pool<Sqlite>, wallet_name: &str, statechain_id: &str, role: &str,
) -> Result<Option<Bip448PackageAttempt>> {
    let row = sqlx::query(
        "SELECT parent_txid, child_txid, child_tx_hex, fee_inputs_json, \
                target_feerate_sat_per_vbyte, status \
         FROM bip448_package_attempts \
         WHERE wallet_name = $1 AND statechain_id = $2 AND role = $3",
    )
    .bind(wallet_name).bind(statechain_id).bind(role).fetch_optional(pool).await?;
    row.map(|row| -> Result<_> {
        let parent_txid: String = row.try_get(0)?;
        let child_txid: String = row.try_get(1)?;
        let fee_inputs: Vec<Bip448FeeInputRecord> = serde_json::from_str(row.try_get(3)?)
            .map_err(|_| anyhow!("invalid BIP448 package-attempt fee inputs"))?;
        if canonical_txid(&parent_txid)? != parent_txid
            || canonical_txid(&child_txid)? != child_txid
            || fee_inputs.iter().any(|input| {
                canonical_txid(&input.txid).map_or(true, |txid| txid != input.txid)
            })
        {
            return Err(anyhow!("non-canonical BIP448 package-attempt txid"));
        }
        Ok(Bip448PackageAttempt {
            wallet_name: wallet_name.to_owned(), statechain_id: statechain_id.to_owned(),
            role: role.to_owned(), parent_txid, child_txid, child_tx_hex: row.try_get(2)?,
            fee_inputs, target_feerate_sat_per_vbyte: row.try_get(4)?,
            status: Bip448PackageAttemptStatus::parse(row.try_get(5)?)?,
        })
    }).transpose()
}

pub(crate) async fn insert_bip448_package_attempt(
    pool: &Pool<Sqlite>, attempt: &Bip448PackageAttempt,
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
    .bind(&attempt.wallet_name).bind(&attempt.statechain_id).bind(&attempt.role)
    .bind(parent_txid).bind(child_txid).bind(&attempt.child_tx_hex)
    .bind(serde_json::to_string(&fee_inputs)?)
    .bind(attempt.target_feerate_sat_per_vbyte).bind(attempt.status.as_str())
    .execute(&mut *transaction).await?;
    for input in &fee_inputs {
        let result = sqlx::query(
            "UPDATE bip448_scanned_outpoints SET reserved_by = $1, reserved_at = unixepoch() \
             WHERE wallet_name = $2 AND txid = $3 AND vout = $4 AND \
                (reserved_by IS NULL OR \
                 (reserved_by <> $1 AND reserved_at <= unixepoch() - $5))",
        )
        .bind(&reservation_id).bind(&attempt.wallet_name).bind(canonical_txid(&input.txid)?)
        .bind(i64::from(input.vout)).bind(BIP448_FEE_RESERVATION_TTL_SECONDS)
        .execute(&mut *transaction).await?;
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
    pool: &Pool<Sqlite>, wallet_name: &str, statechain_id: &str, role: &str,
    status: Bip448PackageAttemptStatus,
) -> Result<()> {
    let mut transaction = pool.begin().await?;
    let result = sqlx::query(
        "UPDATE bip448_package_attempts SET status = $1, updated_at = CURRENT_TIMESTAMP \
         WHERE wallet_name = $2 AND statechain_id = $3 AND role = $4",
    )
    .bind(status.as_str()).bind(wallet_name).bind(statechain_id).bind(role)
    .execute(&mut *transaction).await?;
    if result.rows_affected() != 1 {
        return Err(anyhow!("BIP448 package attempt is missing"));
    }
    if matches!(status, Bip448PackageAttemptStatus::Confirmed | Bip448PackageAttemptStatus::Abandoned) {
        sqlx::query(
            "UPDATE bip448_scanned_outpoints SET reserved_by = NULL, reserved_at = NULL \
             WHERE wallet_name = $1 AND reserved_by = $2",
        )
        .bind(wallet_name).bind(bip448_reservation_id(statechain_id, role))
        .execute(&mut *transaction).await?;
    }
    transaction.commit().await?;
    Ok(())
}

pub async fn insert_wallet(pool: &Pool<Sqlite>, wallet: &Wallet) -> Result<()> {
    let wallet_json = canonical_wallet_json(wallet)?;

    let query = "INSERT INTO wallet (wallet_name, wallet_json) VALUES ($1, $2)";

    let _ = sqlx::query(query)
        .bind(wallet.name.clone())
        .bind(wallet_json)
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn get_wallet(pool: &Pool<Sqlite>, wallet_name: &str) -> Result<Wallet> {
    let query = "SELECT wallet_json FROM wallet WHERE wallet_name = $1";

    let row = sqlx::query(query).bind(wallet_name).fetch_one(pool).await?;

    if row.is_empty() {
        return Err(anyhow!("Wallet not found"));
    }

    let wallet_json: String = row.get(0);

    let wallet: Wallet = serde_json::from_str(&wallet_json)?;

    Ok(wallet)
}

pub async fn update_wallet(pool: &Pool<Sqlite>, wallet: &Wallet) -> Result<()> {
    let wallet_json = canonical_wallet_json(wallet)?;

    let query = "UPDATE wallet SET wallet_json = $1 WHERE wallet_name = $2";

    let _ = sqlx::query(query)
        .bind(wallet_json)
        .bind(wallet.name.clone())
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn insert_backup_txs(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    backup_txs: &Vec<BackupTx>,
) -> Result<()> {
    let backup_txs_json = json!(backup_txs).to_string();

    let query = "INSERT INTO backup_txs (wallet_name, statechain_id, txs) VALUES ($1, $2, $3)";

    let _ = sqlx::query(query)
        .bind(wallet_name)
        .bind(statechain_id)
        .bind(backup_txs_json)
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn update_backup_txs(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    backup_txs: &Vec<BackupTx>,
) -> Result<()> {
    let backup_txs_json = json!(backup_txs).to_string();

    let query = "UPDATE backup_txs SET txs = $1 WHERE statechain_id = $2 AND wallet_name = $3";

    let _ = sqlx::query(query)
        .bind(backup_txs_json)
        .bind(statechain_id)
        .bind(wallet_name)
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn get_backup_txs(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<Vec<BackupTx>> {
    let query = "SELECT txs FROM backup_txs WHERE statechain_id = $1 AND wallet_name = $2";

    let row = sqlx::query(query)
        .bind(statechain_id)
        .bind(wallet_name)
        .fetch_one(pool)
        .await?;

    if row.is_empty() {
        return Err(anyhow!("Statechain id not found"));
    }

    let backup_txs_json: String = row.get(0);

    let backup_txs: Vec<BackupTx> = serde_json::from_str(&backup_txs_json)?;

    Ok(backup_txs)
}

pub async fn insert_or_update_backup_txs(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    backup_txs: &Vec<BackupTx>,
) -> Result<()> {
    let mut transaction = pool.begin().await?;

    let backup_txs_json = json!(backup_txs).to_string();

    let query = "DELETE FROM backup_txs WHERE statechain_id = $1 AND wallet_name = $2";

    let _ = sqlx::query(query)
        .bind(statechain_id)
        .bind(wallet_name)
        .execute(&mut *transaction)
        .await?;

    let query = "INSERT INTO backup_txs (statechain_id, wallet_name, txs) VALUES ($1, $2, $3)";

    let _ = sqlx::query(query)
        .bind(statechain_id)
        .bind(wallet_name)
        .bind(backup_txs_json)
        .execute(&mut *transaction)
        .await?;

    transaction.commit().await?;

    Ok(())
}

/// Persists a BIP448 statechain record. `record_json` is the single source of
/// truth (and the only column read back by `get_bip448_statechain`); the
/// individual columns are denormalized copies derived from the same `record`
/// purely so the table can be queried/indexed without parsing JSON. Because
/// they are always written from `record` in this one place, they cannot diverge
/// from `record_json`.
pub(crate) async fn insert_or_update_bip448_statechain(
    pool: &Pool<Sqlite>,
    accepted: &Bip448AcceptedDepositState,
) -> Result<()> {
    upsert_bip448_statechain_record(pool, accepted.record()).await
}

pub(crate) async fn insert_or_update_bip448_statechain_from_transfer(
    pool: &Pool<Sqlite>,
    accepted: &Bip448AcceptedTransferState,
) -> Result<()> {
    upsert_bip448_statechain_record(pool, accepted.record()).await
}

fn validated_bip448_record_json(record: &Bip448StatechainRecord) -> Result<String> {
    if !record.latest_state.cpfp_child_templates.is_empty() {
        return Err(anyhow!(
            "BIP448 accepted state cannot contain unverified CPFP child templates"
        ));
    }
    if record.latest_state_number != record.latest_state.state_number {
        return Err(anyhow!(
            "BIP448 latest state number does not match the statechain record"
        ));
    }
    let state_locktime =
        bitcoin::absolute::LockTime::from_consensus(record.latest_state.state_locktime);
    if record.latest_state_number
        == mercurylib::bip448_statechain::deposit::INITIAL_BIP448_STATE_NUMBER
    {
        script::validate_initial_state_locktime(state_locktime)?;
    } else {
        script::validate_state_locktime(state_locktime)?;
    }

    Ok(serde_json::to_string(record)?)
}

async fn upsert_bip448_statechain_record(
    pool: &Pool<Sqlite>,
    record: &Bip448StatechainRecord,
) -> Result<()> {
    let mut record = record.clone();
    record.funding_outpoint.txid = canonical_txid(&record.funding_outpoint.txid)?;
    let record = &record;
    let record_json = validated_bip448_record_json(record)?;
    let mut transaction = pool.begin().await?;
    let existing = sqlx::query(
        "SELECT record_json FROM bip448_statechains \
         WHERE wallet_name = $1 AND statechain_id = $2",
    )
    .bind(&record.wallet_name)
    .bind(&record.statechain_id)
    .fetch_optional(&mut *transaction)
    .await?;

    if let Some(row) = existing {
        let stored_json: String = row.get(0);
        if stored_json == record_json {
            transaction.commit().await?;
            return Ok(());
        }

        let stored: Bip448StatechainRecord = serde_json::from_str(&stored_json)?;
        if stored.wallet_name != record.wallet_name
            || stored.statechain_id != record.statechain_id
            || stored.aggregate_pubkey != record.aggregate_pubkey
            || stored.funding_outpoint != record.funding_outpoint
            || stored.amount_sats != record.amount_sats
            || stored.network != record.network
            || stored.challenge_delay != record.challenge_delay
        {
            return Err(anyhow!("BIP448 accepted state immutable identity mismatch"));
        }
        if stored.latest_state_number != 1 || record.latest_state_number != 2 {
            return Err(anyhow!(
                "BIP448 accepted state must be an exact replay or a monotonic 1-to-2 transition"
            ));
        }

        sqlx::query(
            "UPDATE bip448_statechains SET \
                latest_state_number = $1, record_json = $2, updated_at = CURRENT_TIMESTAMP \
             WHERE wallet_name = $3 AND statechain_id = $4",
        )
        .bind(i64::from(record.latest_state_number))
        .bind(record_json)
        .bind(&record.wallet_name)
        .bind(&record.statechain_id)
        .execute(&mut *transaction)
        .await?;
    } else {
        sqlx::query(
            "INSERT INTO bip448_statechains (\
                wallet_name, statechain_id, aggregate_pubkey, funding_txid, funding_vout, \
                funding_value_sats, latest_state_number, challenge_delay, amount_sats, network, \
                record_json\
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(&record.wallet_name)
        .bind(&record.statechain_id)
        .bind(&record.aggregate_pubkey)
        .bind(&record.funding_outpoint.txid)
        .bind(i64::from(record.funding_outpoint.vout))
        .bind(record.funding_outpoint.value_sats as i64)
        .bind(i64::from(record.latest_state_number))
        .bind(i64::from(record.challenge_delay))
        .bind(record.amount_sats as i64)
        .bind(&record.network)
        .bind(record_json)
        .execute(&mut *transaction)
        .await?;
    }

    transaction.commit().await?;
    Ok(())
}

pub async fn get_bip448_statechain(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<Bip448StatechainRecord> {
    let query = "\
        SELECT record_json \
        FROM bip448_statechains \
        WHERE wallet_name = $1 AND statechain_id = $2";

    let row = sqlx::query(query)
        .bind(wallet_name)
        .bind(statechain_id)
        .fetch_one(pool)
        .await?;

    let record_json: String = row.get(0);
    let record = serde_json::from_str(&record_json)?;

    Ok(record)
}

pub async fn get_bip448_statechain_optional(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<Option<Bip448StatechainRecord>> {
    let query = "\
        SELECT record_json \
        FROM bip448_statechains \
        WHERE wallet_name = $1 AND statechain_id = $2";

    let row = sqlx::query(query)
        .bind(wallet_name)
        .bind(statechain_id)
        .fetch_optional(pool)
        .await?;

    row.map(|row| {
        let record_json: String = row.get(0);
        serde_json::from_str(&record_json).map_err(anyhow::Error::from)
    })
    .transpose()
}

pub async fn insert_bip448_pending_deposit_signing_if_absent(
    pool: &Pool<Sqlite>,
    signing: &Bip448PendingDepositSigning,
) -> Result<Bip448PendingDepositSigning> {
    script::validate_initial_state_locktime(bitcoin::absolute::LockTime::from_consensus(
        signing.state_locktime,
    ))?;
    let query = "\
        INSERT INTO bip448_pending_deposit_signings (\
            wallet_name, statechain_id, funding_txid, funding_vout, funding_value_sats, \
            update_template_hash, settlement_template_hash, state_locktime, signing_id, client_secret_nonce, \
            client_public_nonce, blinding_factor, server_public_nonce\
        ) SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13 \
        WHERE NOT EXISTS (\
            SELECT 1 FROM bip448_statechains \
            WHERE wallet_name = $1 AND statechain_id = $2\
        ) \
        ON CONFLICT(wallet_name, statechain_id) DO NOTHING";

    let _ = sqlx::query(query)
        .bind(&signing.wallet_name)
        .bind(&signing.statechain_id)
        .bind(&signing.funding_txid)
        .bind(i64::from(signing.funding_vout))
        .bind(signing.funding_value_sats as i64)
        .bind(&signing.update_template_hash)
        .bind(&signing.settlement_template_hash)
        .bind(i64::from(signing.state_locktime))
        .bind(&signing.signing_id)
        .bind(&signing.client_secret_nonce)
        .bind(&signing.client_public_nonce)
        .bind(&signing.blinding_factor)
        .bind(&signing.server_public_nonce)
        .execute(pool)
        .await?;

    if let Some(pending) =
        get_bip448_pending_deposit_signing(pool, &signing.wallet_name, &signing.statechain_id)
            .await?
    {
        return Ok(pending);
    }
    if get_bip448_statechain_optional(pool, &signing.wallet_name, &signing.statechain_id)
        .await?
        .is_some()
    {
        return Err(anyhow!(
            "BIP448 deposit state is already accepted; a new signing identity cannot be created"
        ));
    }

    Err(anyhow!(
        "BIP448 pending deposit signing row disappeared after insertion"
    ))
}

pub async fn get_bip448_pending_deposit_signing(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<Option<Bip448PendingDepositSigning>> {
    let query = "\
        SELECT wallet_name, statechain_id, funding_txid, funding_vout, funding_value_sats, \
               update_template_hash, settlement_template_hash, signing_id, client_secret_nonce, \
               client_public_nonce, blinding_factor, server_public_nonce, state_locktime \
        FROM bip448_pending_deposit_signings \
        WHERE wallet_name = $1 AND statechain_id = $2";

    let row = sqlx::query(query)
        .bind(wallet_name)
        .bind(statechain_id)
        .fetch_optional(pool)
        .await?;

    row.map(|row| {
        let state_locktime = row
            .try_get::<Option<i64>, _>(12)?
            .ok_or_else(|| {
                anyhow!(
                    "BIP448 pending deposit signing row predates randomized locktime support and cannot be resumed"
                )
            })?;
        let state_locktime = u32::try_from(state_locktime)
            .map_err(|_| anyhow!("BIP448 pending state locktime is outside the u32 range"))?;
        script::validate_initial_state_locktime(bitcoin::absolute::LockTime::from_consensus(
            state_locktime,
        ))?;
        let funding_txid = row.try_get::<Option<String>, _>(2)?.ok_or_else(|| {
            anyhow!(
                "BIP448 pending deposit signing row predates funding-outpoint journaling and cannot be resumed"
            )
        })?;
        let funding_vout = row.try_get::<Option<i64>, _>(3)?.ok_or_else(|| {
            anyhow!(
                "BIP448 pending deposit signing row predates funding-outpoint journaling and cannot be resumed"
            )
        })?;
        let funding_vout = u32::try_from(funding_vout)
            .map_err(|_| anyhow!("BIP448 pending funding vout is outside the u32 range"))?;
        let funding_value_sats = row.try_get::<Option<i64>, _>(4)?.ok_or_else(|| {
            anyhow!(
                "BIP448 pending deposit signing row predates funding-outpoint journaling and cannot be resumed"
            )
        })?;
        let funding_value_sats = u64::try_from(funding_value_sats)
            .map_err(|_| anyhow!("BIP448 pending funding value is negative"))?;
        let settlement_template_hash = row.try_get::<Option<String>, _>(6)?.ok_or_else(|| {
            anyhow!(
                "BIP448 pending deposit signing row predates settlement-template journaling and cannot be resumed"
            )
        })?;

        Ok(Bip448PendingDepositSigning {
            wallet_name: row.get(0),
            statechain_id: row.get(1),
            funding_txid,
            funding_vout,
            funding_value_sats,
            update_template_hash: row.get(5),
            settlement_template_hash,
            signing_id: row.get(7),
            client_secret_nonce: row.get(8),
            client_public_nonce: row.get(9),
            blinding_factor: row.get(10),
            server_public_nonce: row.get(11),
            state_locktime,
        })
    })
    .transpose()
}

pub async fn update_bip448_pending_deposit_server_public_nonce(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    signing_id: &str,
    server_public_nonce: &str,
) -> Result<()> {
    let query = "\
        UPDATE bip448_pending_deposit_signings \
        SET server_public_nonce = $1, updated_at = CURRENT_TIMESTAMP \
        WHERE wallet_name = $2 AND statechain_id = $3 AND signing_id = $4";

    let result = sqlx::query(query)
        .bind(server_public_nonce)
        .bind(wallet_name)
        .bind(statechain_id)
        .bind(signing_id)
        .execute(pool)
        .await?;

    if result.rows_affected() != 1 {
        return Err(anyhow!(
            "BIP448 pending deposit signing row not found for statechain {}",
            statechain_id
        ));
    }

    Ok(())
}

pub async fn delete_bip448_pending_deposit_signing(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    signing_id: &str,
) -> Result<()> {
    let query = "\
        DELETE FROM bip448_pending_deposit_signings \
        WHERE wallet_name = $1 AND statechain_id = $2 AND signing_id = $3";

    let _ = sqlx::query(query)
        .bind(wallet_name)
        .bind(statechain_id)
        .bind(signing_id)
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn insert_bip448_pending_transfer_signing_if_absent(
    pool: &Pool<Sqlite>,
    signing: &Bip448PendingDepositSigning,
) -> Result<Bip448PendingDepositSigning> {
    script::validate_state_locktime(bitcoin::absolute::LockTime::from_consensus(
        signing.state_locktime,
    ))?;
    let accepted =
        get_bip448_statechain_optional(pool, &signing.wallet_name, &signing.statechain_id).await?;
    if !accepted.as_ref().is_some_and(|record| record.latest_state_number == 1 && record.funding_outpoint.txid == signing.funding_txid && record.funding_outpoint.vout == signing.funding_vout && record.funding_outpoint.value_sats == signing.funding_value_sats) {
        return Err(anyhow!(
            "BIP448 pending transfer signing requires a matching accepted state-1 record"
        ));
    }
    let query = "\
        INSERT INTO bip448_pending_transfer_signings (\
            wallet_name, statechain_id, funding_txid, funding_vout, funding_value_sats, \
            update_template_hash, settlement_template_hash, state_locktime, signing_id, client_secret_nonce, \
            client_public_nonce, blinding_factor, server_public_nonce\
        ) SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13 \
        WHERE EXISTS (\
            SELECT 1 FROM bip448_statechains \
            WHERE wallet_name = $1 AND statechain_id = $2 AND latest_state_number = 1 AND funding_txid = $3 AND funding_vout = $4 AND funding_value_sats = $5\
        ) \
        ON CONFLICT(wallet_name, statechain_id) DO NOTHING";

    sqlx::query(query)
        .bind(&signing.wallet_name)
        .bind(&signing.statechain_id)
        .bind(&signing.funding_txid)
        .bind(i64::from(signing.funding_vout))
        .bind(signing.funding_value_sats as i64)
        .bind(&signing.update_template_hash)
        .bind(&signing.settlement_template_hash)
        .bind(i64::from(signing.state_locktime))
        .bind(&signing.signing_id)
        .bind(&signing.client_secret_nonce)
        .bind(&signing.client_public_nonce)
        .bind(&signing.blinding_factor)
        .bind(&signing.server_public_nonce)
        .execute(pool)
        .await?;

    get_bip448_pending_transfer_signing(pool, &signing.wallet_name, &signing.statechain_id)
        .await?
        .ok_or_else(|| anyhow!("BIP448 pending transfer signing row disappeared after insertion"))
}

pub async fn get_bip448_pending_transfer_signing(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<Option<Bip448PendingDepositSigning>> {
    let query = "\
        SELECT wallet_name, statechain_id, funding_txid, funding_vout, funding_value_sats, \
               update_template_hash, settlement_template_hash, state_locktime, signing_id, \
               client_secret_nonce, client_public_nonce, blinding_factor, server_public_nonce \
        FROM bip448_pending_transfer_signings \
        WHERE wallet_name = $1 AND statechain_id = $2";

    let row = sqlx::query(query)
        .bind(wallet_name)
        .bind(statechain_id)
        .fetch_optional(pool)
        .await?;

    row.map(|row| {
        let state_locktime = u32::try_from(row.get::<i64, _>(7))
            .map_err(|_| anyhow!("BIP448 pending state locktime is outside the u32 range"))?;
        script::validate_state_locktime(bitcoin::absolute::LockTime::from_consensus(
            state_locktime,
        ))?;
        Ok(Bip448PendingDepositSigning {
            wallet_name: row.get(0),
            statechain_id: row.get(1),
            funding_txid: row.get(2),
            funding_vout: u32::try_from(row.get::<i64, _>(3))
                .map_err(|_| anyhow!("BIP448 pending funding vout is outside the u32 range"))?,
            funding_value_sats: u64::try_from(row.get::<i64, _>(4))
                .map_err(|_| anyhow!("BIP448 pending funding value is negative"))?,
            update_template_hash: row.get(5),
            settlement_template_hash: row.get(6),
            state_locktime,
            signing_id: row.get(8),
            client_secret_nonce: row.get(9),
            client_public_nonce: row.get(10),
            blinding_factor: row.get(11),
            server_public_nonce: row.get(12),
        })
    })
    .transpose()
}

pub async fn update_bip448_pending_transfer_server_public_nonce(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    signing_id: &str,
    server_public_nonce: &str,
) -> Result<()> {
    let result = sqlx::query(
        "UPDATE bip448_pending_transfer_signings \
         SET server_public_nonce = $1, updated_at = CURRENT_TIMESTAMP \
         WHERE wallet_name = $2 AND statechain_id = $3 AND signing_id = $4",
    )
    .bind(server_public_nonce)
    .bind(wallet_name)
    .bind(statechain_id)
    .bind(signing_id)
    .execute(pool)
    .await?;
    if result.rows_affected() != 1 {
        return Err(anyhow!(
            "BIP448 pending transfer signing row not found for statechain {}",
            statechain_id
        ));
    }
    Ok(())
}

pub async fn delete_bip448_pending_transfer_signing(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    signing_id: &str,
) -> Result<()> {
    sqlx::query(
        "DELETE FROM bip448_pending_transfer_signings \
         WHERE wallet_name = $1 AND statechain_id = $2 AND signing_id = $3",
    )
    .bind(wallet_name)
    .bind(statechain_id)
    .bind(signing_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn insert_or_update_bip448_transfer_msg(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    recipient_auth_pubkey: &str,
    transfer_msg: &Bip448TransferMsg,
) -> Result<()> {
    let transfer_msg_json = serde_json::to_string(transfer_msg)?;
    let query = "\
        INSERT INTO bip448_transfer_messages (\
            wallet_name, statechain_id, recipient_auth_pubkey, transfer_msg_json\
        ) VALUES ($1, $2, $3, $4) \
        ON CONFLICT(wallet_name, statechain_id, recipient_auth_pubkey) DO UPDATE SET \
            transfer_msg_json = excluded.transfer_msg_json, \
            updated_at = CURRENT_TIMESTAMP";

    let _ = sqlx::query(query)
        .bind(wallet_name)
        .bind(&transfer_msg.statechain_id)
        .bind(recipient_auth_pubkey)
        .bind(transfer_msg_json)
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn get_bip448_transfer_msg(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    recipient_auth_pubkey: &str,
) -> Result<Bip448TransferMsg> {
    let query = "\
        SELECT transfer_msg_json \
        FROM bip448_transfer_messages \
        WHERE wallet_name = $1 AND statechain_id = $2 AND recipient_auth_pubkey = $3";

    let row = sqlx::query(query)
        .bind(wallet_name)
        .bind(statechain_id)
        .bind(recipient_auth_pubkey)
        .fetch_one(pool)
        .await?;

    let transfer_msg_json: String = row.get(0);
    let transfer_msg = serde_json::from_str(&transfer_msg_json)?;

    Ok(transfer_msg)
}

pub async fn has_bip448_transfer_msg_for_statechain(pool: &Pool<Sqlite>, wallet_name: &str, statechain_id: &str) -> Result<bool> { Ok(sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM bip448_transfer_messages WHERE wallet_name = $1 AND statechain_id = $2").bind(wallet_name).bind(statechain_id).fetch_one(pool).await? != 0) }
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{bip448_transfer_sender::transfer_bip448_sender,
        chain::{ChainClient, CoreRpcAuth, CoreRpcConfig}, client_config::ClientConfig};
    use bitcoin::Network;
    use mercurylib::bip448_statechain::storage::{
        Bip448AnchorOutput, Bip448CpfpChildTemplate, Bip448CsfsKeyMetadata, Bip448FeeBumpPolicy,
        Bip448FundingOutpoint, Bip448LatestState, Bip448RecoveryTemplateRole,
        Bip448SigningMetadata, Bip448ValueSchedule,
    };
    use mercurylib::transfer::bip448::Bip448TransferMsg;
    use mercurylib::wallet::{CoinStatus, Settings};
    use sqlx::sqlite::SqlitePoolOptions;

    async fn migrated_pool() -> Result<Pool<Sqlite>> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await?;

        sqlx::migrate!("./migrations").run(&pool).await?;

        Ok(pool)
    }

    async fn table_exists(pool: &Pool<Sqlite>, table_name: &str) -> Result<bool> {
        let row =
            sqlx::query("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = $1 LIMIT 1")
                .bind(table_name)
                .fetch_optional(pool)
                .await?;

        Ok(row.is_some())
    }

    fn sample_wallet() -> Wallet {
        Wallet {
            name: "wallet".to_string(),
            mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            version: "0.1.0".to_string(),
            state_entity_endpoint: "http://statechain".to_string(),
            chain_backend: "core".to_string(),
            chain_endpoint: "http://127.0.0.1:18443".to_string(),
            network: "regtest".to_string(),
            blockheight: 42,
            initlock: 1000,
            interval: 10,
            activities: Vec::new(),
            coins: Vec::new(),
            settings: Settings {
                network: "regtest".to_string(),
                block_explorerURL: None,
                torProxyHost: None,
                torProxyPort: None,
                torProxyControlPassword: None,
                torProxyControlPort: None,
                statechainEntityApi: "http://statechain".to_string(),
                torStatechainEntityApi: None,
                chainBackend: "core".to_string(),
                chainUrl: "http://127.0.0.1:18443".to_string(),
                chainType: None,
                notifications: false,
                tutorials: false,
            },
        }
    }

    fn sample_latest_state(state_number: u32) -> Bip448LatestState {
        Bip448LatestState {
            state_number,
            state_locktime: 700_000_042,
            challenge_delay: 144,
            update_tx: "02000000".to_string(),
            settlement_tx: "03000000".to_string(),
            update_template_hash: "11".repeat(32),
            settlement_template_hash: "22".repeat(32),
            state_output_script_pubkey: "5120".to_string() + &"33".repeat(32),
            funding_update_script: "51cecbcc".to_string(),
            funding_update_control_block: "c0".to_string() + &"44".repeat(32),
            state_update_script: "b175cecbcc".to_string(),
            state_update_control_block: "c0".to_string() + &"55".repeat(32),
            state_settlement_script: "20".to_string() + &"22".repeat(32) + "ce87",
            state_settlement_control_block: "c0".to_string() + &"66".repeat(32),
            csfs_key_metadata: Bip448CsfsKeyMetadata {
                aggregate_pubkey_parity_odd: true,
                negate_seckey: true,
            },
            signing_metadata: Bip448SigningMetadata {
                role: Bip448RecoveryTemplateRole::FundingUpdate,
                signing_id: "77".repeat(32),
                client_public_nonce: "88".repeat(66),
                server_public_nonce: "99".repeat(66),
                blinding_factor: "aa".repeat(32),
                update_template_hash: "11".repeat(32),
                update_signature: "bb".repeat(64),
                server_signature_count: u64::from(state_number),
            },
            fee_bump_policy: Bip448FeeBumpPolicy::ZeroFeeEphemeralAnchor,
            value_schedule: Bip448ValueSchedule {
                funding_value_sats: 100_000,
                update_input_value_sats: 100_000,
                update_state_output_value_sats: 100_000,
                settlement_input_value_sats: 100_000,
                settlement_recovery_output_value_sats: 100_000,
            },
            anchors: vec![Bip448AnchorOutput {
                tx_role: Bip448RecoveryTemplateRole::StateUpdate,
                output_index: 1,
                value_sats: 0,
                script_pubkey: "51024e73".to_string(),
            }],
            cpfp_child_templates: Vec::new(),
        }
    }

    fn sample_cpfp_child_template() -> Bip448CpfpChildTemplate {
        Bip448CpfpChildTemplate {
            parent_role: Bip448RecoveryTemplateRole::StateUpdate,
            anchor_output_index: 1,
            tx_hex: "03000000".to_string(),
            fee_sats: 1_000,
            target_feerate_sat_per_vbyte: Some(10),
        }
    }

    fn sample_bip448_record(state_number: u32) -> Bip448StatechainRecord {
        let latest_state = sample_latest_state(state_number);
        Bip448StatechainRecord {
            wallet_name: "wallet".to_string(),
            statechain_id: "statechain".to_string(),
            aggregate_pubkey: "02".to_string() + &"12".repeat(32),
            funding_outpoint: Bip448FundingOutpoint {
                txid: "34".repeat(32),
                vout: 0,
                value_sats: 100_000,
            },
            latest_state_number: latest_state.state_number,
            challenge_delay: latest_state.challenge_delay,
            amount_sats: 100_000,
            network: "regtest".to_string(),
            latest_state,
        }
    }

    fn sample_backup_txs() -> Vec<BackupTx> {
        vec![BackupTx {
            tx_n: 1,
            tx: "02000000".to_string(),
            client_public_nonce: "aa".to_string(),
            server_public_nonce: "bb".to_string(),
            client_public_key: "cc".to_string(),
            server_public_key: "dd".to_string(),
            blinding_factor: "ee".to_string(),
        }]
    }

    fn sample_bip448_transfer_msg() -> Bip448TransferMsg {
        let mut latest_state = sample_latest_state(2);
        latest_state
            .cpfp_child_templates
            .push(sample_cpfp_child_template());
        Bip448TransferMsg {
            msg_version: 1,
            statechain_id: "statechain".to_string(),
            transfer_signature: "ab".repeat(64),
            sender_user_public_key: "02".to_string() + &"12".repeat(32),
            receiver_user_public_key: "03".to_string() + &"13".repeat(32),
            server_public_key: "02".to_string() + &"14".repeat(32),
            aggregate_pubkey: "02".to_string() + &"15".repeat(32),
            funding_outpoint: Bip448FundingOutpoint {
                txid: "44".repeat(32),
                vout: 1,
                value_sats: 100_000,
            },
            latest_state_number: latest_state.state_number,
            challenge_delay: latest_state.challenge_delay,
            amount_sats: 100_000,
            network: "regtest".to_string(),
            value_schedule: latest_state.value_schedule.clone(),
            latest_state,
            server_signature_count: 2,
            t1: [9u8; 32],
            state_history: Vec::new(),
        }
    }

    fn sender_test_config(pool: Pool<Sqlite>) -> Result<ClientConfig> {
        let url = "http://127.0.0.1:1";
        Ok(ClientConfig { statechain_entity: url.into(), chain_backend: "core".into(),
            chain_client: ChainClient::new(CoreRpcConfig { url: url.into(), auth: CoreRpcAuth::None })?,
            core_rpc_url: Some(url.into()), core_rpc_auth: Some("none".into()), core_rpc_user: None,
            core_rpc_password: None, core_rpc_cookie_file: None, network: Network::Regtest,
            fee_rate_tolerance: 0.0, confirmation_target: 1,
            pool, tor_proxy: None, max_fee_rate: 10.0 })
    }
    async fn assert_sender_ineligible(config: &ClientConfig) {
        let error = transfer_bip448_sender(config, "unused", "wallet", "statechain")
            .await.unwrap_err();
        assert_eq!(error.to_string(), "only one-hop transfer of a fresh deposit is supported in the prototype");
    }
    #[tokio::test]
    async fn bip448_sender_exercises_record_coin_state_and_status_guards() -> Result<()> {
        let config = sender_test_config(migrated_pool().await?)?;
        let mut wallet = sample_wallet();
        insert_wallet(&config.pool, &wallet).await?; assert_sender_ineligible(&config).await;
        upsert_bip448_statechain_record(&config.pool, &sample_bip448_record(1)).await?; assert_sender_ineligible(&config).await;
        let mut coin = wallet.get_new_coin()?;
        coin.statechain_protocol = Some(mercurylib::bip448_statechain::deposit::BIP448_COIN_PROTOCOL.into());
        coin.statechain_id = Some("statechain".into()); coin.status = CoinStatus::IN_TRANSFER;
        wallet.coins.push(coin); update_wallet(&config.pool, &wallet).await?;
        assert_sender_ineligible(&config).await;
        wallet.coins[0].status = CoinStatus::CONFIRMED;
        let config = sender_test_config(migrated_pool().await?)?;
        insert_wallet(&config.pool, &wallet).await?; upsert_bip448_statechain_record(&config.pool, &sample_bip448_record(2)).await?;
        assert_sender_ineligible(&config).await;
        Ok(())
    }
    #[tokio::test]
    async fn migration_adds_bip448_tables_without_touching_legacy_wallet_data() -> Result<()> {
        let pool = migrated_pool().await?;

        assert!(table_exists(&pool, "wallet").await?);
        assert!(table_exists(&pool, "backup_txs").await?);
        assert!(table_exists(&pool, "bip448_statechains").await?);
        assert!(table_exists(&pool, "bip448_transfer_messages").await?);
        assert!(table_exists(&pool, "bip448_pending_deposit_signings").await?);
        assert!(table_exists(&pool, "bip448_pending_transfer_signings").await?);
        assert!(table_exists(&pool, "bip448_scan_cursors").await?);
        assert!(table_exists(&pool, "bip448_scanned_outpoints").await?);
        assert!(table_exists(&pool, "bip448_package_attempts").await?);

        let wallet = sample_wallet();
        insert_wallet(&pool, &wallet).await?;
        let backup_txs = sample_backup_txs();
        insert_backup_txs(&pool, &wallet.name, "legacy-statechain", &backup_txs).await?;

        let roundtrip_wallet = get_wallet(&pool, &wallet.name).await?;
        let roundtrip_backup_txs = get_backup_txs(&pool, &wallet.name, "legacy-statechain").await?;

        assert_eq!(roundtrip_wallet.name, wallet.name);
        assert_eq!(roundtrip_backup_txs.len(), 1);
        assert_eq!(roundtrip_backup_txs[0].tx_n, 1);

        Ok(())
    }

    #[tokio::test]
    async fn wallet_and_accepted_record_persistence_canonicalize_txids() -> Result<()> {
        let pool = migrated_pool().await?;
        let mut wallet = sample_wallet();
        let mut coin = wallet.get_new_coin()?;
        coin.utxo_txid = Some("AA".repeat(32));
        coin.utxo_vout = Some(1);
        coin.tx_cpfp = Some("BB".repeat(32));
        coin.tx_withdraw = Some("CC".repeat(32));
        wallet.coins.push(coin);
        insert_wallet(&pool, &wallet).await?;
        let stored_coin = get_wallet(&pool, &wallet.name).await?.coins.remove(0);
        assert_eq!(stored_coin.utxo_txid, Some("aa".repeat(32)));
        assert_eq!(stored_coin.tx_cpfp, Some("bb".repeat(32)));
        assert_eq!(stored_coin.tx_withdraw, Some("cc".repeat(32)));
        wallet.coins[0].utxo_txid = Some("not-a-txid".into());
        assert!(update_wallet(&pool, &wallet).await.is_err());
        wallet.coins[0].utxo_txid = Some("aa".repeat(32));
        wallet.coins[0].tx_cpfp = Some("not-a-txid".into());
        assert!(update_wallet(&pool, &wallet).await.is_err());
        wallet.coins[0].tx_cpfp = None;
        wallet.coins[0].tx_withdraw = Some("not-a-txid".into());
        assert!(update_wallet(&pool, &wallet).await.is_err());

        let mut record = sample_bip448_record(1);
        record.funding_outpoint.txid = "AA".repeat(32);
        upsert_bip448_statechain_record(&pool, &record).await?;
        assert_eq!(get_bip448_statechain(&pool, &record.wallet_name, &record.statechain_id)
            .await?.funding_outpoint.txid, "aa".repeat(32));
        Ok(())
    }

    #[tokio::test]
    async fn bip448_scan_state_round_trips_canonical_txids_and_clears() -> Result<()> {
        let pool = migrated_pool().await?;
        let cursor = Bip448ScanCursor {
            last_scanned_height: 42,
            last_scanned_block_hash: "22".repeat(32),
        };
        persist_bip448_scan_state(
            &pool,
            "wallet",
            "51",
            &cursor,
            &[ChainUtxo {
                txid: "AA".repeat(32),
                vout: 1,
                value: 50_000,
                height: 40,
            }],
        )
        .await?;

        let (stored_cursor, outpoints) =
            load_bip448_scan_state(&pool, "wallet", "51").await?;
        assert_eq!(stored_cursor, Some(cursor));
        assert_eq!(outpoints[0].txid, "aa".repeat(32));

        clear_bip448_scan_state(&pool, "wallet", "51").await?;
        assert_eq!(
            load_bip448_scan_state(&pool, "wallet", "51").await?,
            (None, Vec::new())
        );
        Ok(())
    }

    #[tokio::test]
    async fn package_attempt_reserves_expires_releases_and_fails_closed() -> Result<()> {
        let pool = migrated_pool().await?;
        let fee = ChainUtxo { txid: "aa".repeat(32), vout: 1, value: 50_000, height: 2 };
        upsert_bip448_scanned_outpoint(&pool, "wallet", "51", &fee).await?;
        let attempt = Bip448PackageAttempt {
            wallet_name: "wallet".into(), statechain_id: "statechain".into(),
            role: "funding_update".into(), parent_txid: "bb".repeat(32),
            child_txid: "cc".repeat(32), child_tx_hex: "deadbeef".into(),
            fee_inputs: vec![Bip448FeeInputRecord {
                txid: fee.txid.clone(), vout: fee.vout, value_sats: fee.value }],
            target_feerate_sat_per_vbyte: 2.0, status: Bip448PackageAttemptStatus::Pending,
        };
        insert_bip448_package_attempt(&pool, &attempt).await?;
        assert_eq!(get_bip448_package_attempt(&pool, "wallet", "statechain", "funding_update").await?.unwrap(), attempt);
        assert!(available_bip448_scanned_outpoints(&pool, "wallet", "51", "other").await?.is_empty());
        sqlx::query("UPDATE bip448_scanned_outpoints SET reserved_at = unixepoch() - $1").bind(BIP448_FEE_RESERVATION_TTL_SECONDS + 1).execute(&pool).await?;
        assert_eq!(available_bip448_scanned_outpoints(&pool, "wallet", "51", "other").await?.len(), 1);
        set_bip448_package_attempt_status(&pool, "wallet", "statechain", "funding_update", Bip448PackageAttemptStatus::Abandoned).await?;
        assert_eq!(sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bip448_scanned_outpoints WHERE reserved_by IS NOT NULL")
            .fetch_one(&pool).await?, 0);
        sqlx::query("UPDATE bip448_package_attempts SET fee_inputs_json = '{'").execute(&pool).await?;
        assert!(get_bip448_package_attempt(&pool, "wallet", "statechain", "funding_update").await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn scan_reset_clears_all_and_rediscovery_restores_only_active_valid_reservations(
    ) -> Result<()> {
        let pool = migrated_pool().await?;
        let fee = ChainUtxo {
            txid: "aa".repeat(32),
            vout: 1,
            value: 50_000,
            height: 2,
        };
        let cursor = Bip448ScanCursor {
            last_scanned_height: 3,
            last_scanned_block_hash: "11".repeat(32),
        };
        persist_bip448_scan_state(&pool, "wallet", "51", &cursor, &[fee.clone()]).await?;
        let attempt = Bip448PackageAttempt {
            wallet_name: "wallet".into(),
            statechain_id: "statechain".into(),
            role: "funding_update".into(),
            parent_txid: "bb".repeat(32),
            child_txid: "cc".repeat(32),
            child_tx_hex: "deadbeef".into(),
            fee_inputs: vec![Bip448FeeInputRecord {
                txid: fee.txid.clone(),
                vout: fee.vout,
                value_sats: fee.value,
            }],
            target_feerate_sat_per_vbyte: 2.0,
            status: Bip448PackageAttemptStatus::Pending,
        };
        insert_bip448_package_attempt(&pool, &attempt).await?;

        clear_bip448_scan_state(&pool, "wallet", "51").await?;
        assert_eq!(
            load_bip448_scan_state(&pool, "wallet", "51").await?,
            (None, Vec::new())
        );
        persist_bip448_scan_state(&pool, "wallet", "51", &cursor, &[fee.clone()]).await?;
        assert_eq!(
            load_bip448_scan_state(&pool, "wallet", "51").await?.1,
            vec![fee.clone()]
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT reserved_by FROM bip448_scanned_outpoints \
                 WHERE wallet_name = 'wallet' AND txid = $1 AND vout = 1",
            )
            .bind(&fee.txid)
            .fetch_one(&pool)
            .await?,
            bip448_reservation_id("statechain", "funding_update")
        );
        persist_bip448_scan_state(&pool, "wallet", "51", &cursor, &[]).await?;
        assert!(load_bip448_scan_state(&pool, "wallet", "51")
            .await?
            .1
            .is_empty());

        set_bip448_package_attempt_status(
            &pool,
            "wallet",
            "statechain",
            "funding_update",
            Bip448PackageAttemptStatus::Abandoned,
        )
        .await?;
        clear_bip448_scan_state(&pool, "wallet", "51").await?;
        assert!(load_bip448_scan_state(&pool, "wallet", "51")
            .await?
            .1
            .is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn orphaned_same_operation_reservation_rejects_a_rebuilt_attempt() -> Result<()> {
        let pool = migrated_pool().await?;
        let fee = ChainUtxo {
            txid: "aa".repeat(32),
            vout: 1,
            value: 50_000,
            height: 2,
        };
        upsert_bip448_scanned_outpoint(&pool, "wallet", "51", &fee).await?;
        let attempt = Bip448PackageAttempt {
            wallet_name: "wallet".into(),
            statechain_id: "statechain".into(),
            role: "funding_update".into(),
            parent_txid: "bb".repeat(32),
            child_txid: "cc".repeat(32),
            child_tx_hex: "deadbeef".into(),
            fee_inputs: vec![Bip448FeeInputRecord {
                txid: fee.txid,
                vout: fee.vout,
                value_sats: fee.value,
            }],
            target_feerate_sat_per_vbyte: 2.0,
            status: Bip448PackageAttemptStatus::Pending,
        };
        insert_bip448_package_attempt(&pool, &attempt).await?;
        sqlx::query(
            "DELETE FROM bip448_package_attempts \
             WHERE wallet_name = 'wallet' AND statechain_id = 'statechain'",
        )
        .execute(&pool)
        .await?;
        sqlx::query(
            "UPDATE bip448_scanned_outpoints SET reserved_at = unixepoch() - $1",
        )
        .bind(BIP448_FEE_RESERVATION_TTL_SECONDS + 1)
        .execute(&pool)
        .await?;

        assert!(ensure_no_orphaned_bip448_reservation(
            &pool,
            "wallet",
            "statechain",
            "funding_update",
        )
        .await
        .is_err());
        assert!(available_bip448_scanned_outpoints(
            &pool,
            "wallet",
            "51",
            &bip448_reservation_id("statechain", "funding_update"),
        )
        .await?
        .is_empty());
        assert!(insert_bip448_package_attempt(&pool, &attempt).await.is_err());
        assert!(get_bip448_package_attempt(
            &pool,
            "wallet",
            "statechain",
            "funding_update",
        )
        .await?
        .is_none());
        Ok(())
    }

    #[tokio::test]
    async fn replay_reacquires_expired_reservations_or_fails_after_reclaim() -> Result<()> {
        let pool = migrated_pool().await?;
        let fee = ChainUtxo {
            txid: "aa".repeat(32),
            vout: 1,
            value: 50_000,
            height: 2,
        };
        upsert_bip448_scanned_outpoint(&pool, "wallet", "51", &fee).await?;
        let attempt = Bip448PackageAttempt {
            wallet_name: "wallet".into(),
            statechain_id: "statechain-a".into(),
            role: "funding_update".into(),
            parent_txid: "bb".repeat(32),
            child_txid: "cc".repeat(32),
            child_tx_hex: "deadbeef".into(),
            fee_inputs: vec![Bip448FeeInputRecord {
                txid: fee.txid.clone(),
                vout: fee.vout,
                value_sats: fee.value,
            }],
            target_feerate_sat_per_vbyte: 2.0,
            status: Bip448PackageAttemptStatus::Pending,
        };
        insert_bip448_package_attempt(&pool, &attempt).await?;
        sqlx::query(
            "UPDATE bip448_scanned_outpoints SET reserved_at = unixepoch() - $1",
        )
        .bind(BIP448_FEE_RESERVATION_TTL_SECONDS + 1)
        .execute(&pool)
        .await?;
        reacquire_bip448_package_attempt_reservations(&pool, &attempt).await?;
        assert!(available_bip448_scanned_outpoints(&pool, "wallet", "51", "other")
            .await?
            .is_empty());

        sqlx::query(
            "UPDATE bip448_scanned_outpoints SET reserved_at = unixepoch() - $1",
        )
        .bind(BIP448_FEE_RESERVATION_TTL_SECONDS + 1)
        .execute(&pool)
        .await?;
        let mut reclaimed = attempt.clone();
        reclaimed.statechain_id = "statechain-b".into();
        reclaimed.parent_txid = "dd".repeat(32);
        reclaimed.child_txid = "ee".repeat(32);
        insert_bip448_package_attempt(&pool, &reclaimed).await?;
        assert!(reacquire_bip448_package_attempt_reservations(&pool, &attempt)
            .await
            .is_err());
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT reserved_by FROM bip448_scanned_outpoints \
                 WHERE wallet_name = 'wallet' AND txid = $1 AND vout = 1",
            )
            .bind(&fee.txid)
            .fetch_one(&pool)
            .await?,
            bip448_reservation_id(&reclaimed.statechain_id, &reclaimed.role)
        );
        Ok(())
    }

    #[tokio::test]
    async fn reapplying_bip448_migration_does_not_destroy_populated_legacy_data() -> Result<()> {
        let pool = migrated_pool().await?;
        let wallet = sample_wallet();
        insert_wallet(&pool, &wallet).await?;
        let backup_txs = sample_backup_txs();
        insert_backup_txs(&pool, &wallet.name, "legacy-statechain", &backup_txs).await?;

        // Re-run the additive 0002 migration statements against the ALREADY
        // POPULATED legacy database. A destructive DROP/ALTER in 0002 would wipe
        // the legacy rows asserted below; `CREATE TABLE IF NOT EXISTS` is a no-op.
        let migration_sql = include_str!("../migrations/0002_bip448_statechain_data.sql");
        for statement in migration_sql.split(';') {
            let statement = statement.trim();
            if !statement.is_empty() {
                sqlx::query(statement).execute(&pool).await?;
            }
        }

        let roundtrip_backup_txs = get_backup_txs(&pool, &wallet.name, "legacy-statechain").await?;
        assert_eq!(roundtrip_backup_txs.len(), 1);
        assert_eq!(roundtrip_backup_txs[0].tx_n, backup_txs[0].tx_n);
        assert_eq!(get_wallet(&pool, &wallet.name).await?.name, wallet.name);
        assert!(table_exists(&pool, "bip448_statechains").await?);

        Ok(())
    }

    #[tokio::test]
    async fn bip448_latest_state_allows_one_to_two_transition_and_exact_replay() -> Result<()> {
        let pool = migrated_pool().await?;
        let state_one = sample_bip448_record(1);
        let state_two = sample_bip448_record(2);

        upsert_bip448_statechain_record(&pool, &state_one).await?;
        let roundtrip =
            get_bip448_statechain(&pool, &state_one.wallet_name, &state_one.statechain_id).await?;
        assert_eq!(roundtrip, state_one);

        upsert_bip448_statechain_record(&pool, &state_two).await?;
        let roundtrip =
            get_bip448_statechain(&pool, &state_two.wallet_name, &state_two.statechain_id).await?;
        assert_eq!(roundtrip, state_two);

        upsert_bip448_statechain_record(&pool, &state_two).await?;
        let roundtrip =
            get_bip448_statechain(&pool, &state_two.wallet_name, &state_two.statechain_id).await?;
        assert_eq!(roundtrip, state_two);

        Ok(())
    }

    #[tokio::test]
    async fn bip448_latest_state_rejects_immutable_identity_changes() -> Result<()> {
        let pool = migrated_pool().await?;
        let state_one = sample_bip448_record(1);
        upsert_bip448_statechain_record(&pool, &state_one).await?;

        let mut aggregate_pubkey = sample_bip448_record(2);
        aggregate_pubkey.aggregate_pubkey = "03".to_string() + &"12".repeat(32);
        let mut funding_outpoint = sample_bip448_record(2);
        funding_outpoint.funding_outpoint.vout = 1;
        let mut amount_sats = sample_bip448_record(2);
        amount_sats.amount_sats += 1;
        let mut network = sample_bip448_record(2);
        network.network = "bitcoin".to_string();
        let mut challenge_delay = sample_bip448_record(2);
        challenge_delay.challenge_delay += 1;

        for conflicting in [
            aggregate_pubkey,
            funding_outpoint,
            amount_sats,
            network,
            challenge_delay,
        ] {
            let error = upsert_bip448_statechain_record(&pool, &conflicting)
                .await
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "BIP448 accepted state immutable identity mismatch"
            );
        }
        let persisted =
            get_bip448_statechain(&pool, &state_one.wallet_name, &state_one.statechain_id).await?;
        assert_eq!(persisted, state_one);

        Ok(())
    }

    #[tokio::test]
    async fn bip448_latest_state_rejects_rollback_and_divergent_same_state() -> Result<()> {
        let pool = migrated_pool().await?;
        let state_one = sample_bip448_record(1);
        let state_two = sample_bip448_record(2);
        upsert_bip448_statechain_record(&pool, &state_one).await?;
        upsert_bip448_statechain_record(&pool, &state_two).await?;

        let mut divergent_state_two = state_two.clone();
        divergent_state_two.latest_state.update_tx = "04000000".to_string();
        for rejected in [state_one, divergent_state_two] {
            let error = upsert_bip448_statechain_record(&pool, &rejected)
                .await
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "BIP448 accepted state must be an exact replay or a monotonic 1-to-2 transition"
            );
        }
        let persisted =
            get_bip448_statechain(&pool, &state_two.wallet_name, &state_two.statechain_id).await?;
        assert_eq!(persisted, state_two);

        Ok(())
    }

    #[tokio::test]
    async fn bip448_accepted_state_rejects_unverified_cpfp_children() -> Result<()> {
        let pool = migrated_pool().await?;
        let mut rejected_insert = sample_bip448_record(1);
        rejected_insert
            .latest_state
            .cpfp_child_templates
            .push(sample_cpfp_child_template());

        let error = upsert_bip448_statechain_record(&pool, &rejected_insert)
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("cannot contain unverified CPFP child templates"));
        assert!(get_bip448_statechain_optional(
            &pool,
            &rejected_insert.wallet_name,
            &rejected_insert.statechain_id,
        )
        .await?
        .is_none());

        let accepted = sample_bip448_record(1);
        upsert_bip448_statechain_record(&pool, &accepted).await?;
        let mut rejected_update = sample_bip448_record(2);
        rejected_update
            .latest_state
            .cpfp_child_templates
            .push(sample_cpfp_child_template());

        let error = upsert_bip448_statechain_record(&pool, &rejected_update)
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("cannot contain unverified CPFP child templates"));
        let persisted =
            get_bip448_statechain(&pool, &accepted.wallet_name, &accepted.statechain_id).await?;
        assert_eq!(persisted, accepted);

        Ok(())
    }

    #[tokio::test]
    async fn bip448_transfer_messages_round_trip_through_sqlite() -> Result<()> {
        let pool = migrated_pool().await?;
        let transfer_msg = sample_bip448_transfer_msg();
        let recipient_auth_pubkey = "02".to_string() + &"99".repeat(32);

        insert_or_update_bip448_transfer_msg(
            &pool,
            "wallet",
            &recipient_auth_pubkey,
            &transfer_msg,
        )
        .await?;
        let roundtrip = get_bip448_transfer_msg(
            &pool,
            "wallet",
            &transfer_msg.statechain_id,
            &recipient_auth_pubkey,
        )
        .await?;

        assert_eq!(roundtrip, transfer_msg);
        assert_eq!(roundtrip.latest_state.anchors[0].script_pubkey, "51024e73");
        assert_eq!(roundtrip.latest_state.cpfp_child_templates.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn bip448_pending_deposit_signing_round_trips_and_is_deleted() -> Result<()> {
        let pool = migrated_pool().await?;
        let mut pending = Bip448PendingDepositSigning {
            wallet_name: "wallet".to_string(),
            statechain_id: "statechain".to_string(),
            funding_txid: "aa".repeat(32),
            funding_vout: 1,
            funding_value_sats: 100_000,
            update_template_hash: "11".repeat(32),
            settlement_template_hash: "12".repeat(32),
            state_locktime: 700_000_042,
            signing_id: "22".repeat(32),
            client_secret_nonce: "33".repeat(132),
            client_public_nonce: "44".repeat(66),
            blinding_factor: "55".repeat(32),
            server_public_nonce: None,
        };

        let inserted = insert_bip448_pending_deposit_signing_if_absent(&pool, &pending).await?;
        assert_eq!(inserted, pending);
        let roundtrip =
            get_bip448_pending_deposit_signing(&pool, &pending.wallet_name, &pending.statechain_id)
                .await?
                .expect("pending signing exists");
        assert_eq!(roundtrip, pending);

        pending.server_public_nonce = Some("66".repeat(66));
        update_bip448_pending_deposit_server_public_nonce(
            &pool,
            &pending.wallet_name,
            &pending.statechain_id,
            &pending.signing_id,
            pending.server_public_nonce.as_ref().unwrap(),
        )
        .await?;
        let with_server_nonce =
            get_bip448_pending_deposit_signing(&pool, &pending.wallet_name, &pending.statechain_id)
                .await?
                .expect("pending signing exists");
        assert_eq!(with_server_nonce, pending);

        delete_bip448_pending_deposit_signing(
            &pool,
            &pending.wallet_name,
            &pending.statechain_id,
            &pending.signing_id,
        )
        .await?;
        assert!(get_bip448_pending_deposit_signing(
            &pool,
            &pending.wallet_name,
            &pending.statechain_id,
        )
        .await?
        .is_none());
        pending.state_locktime = 1_000_000_001;
        pending.server_public_nonce = None;
        let error = insert_bip448_pending_transfer_signing_if_absent(&pool, &pending)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("accepted state-1 record"));
        let accepted = sample_bip448_record(1); pending.funding_txid = accepted.funding_outpoint.txid.clone(); pending.funding_vout = accepted.funding_outpoint.vout; pending.funding_value_sats = accepted.funding_outpoint.value_sats; upsert_bip448_statechain_record(&pool, &accepted).await?;
        let persisted = insert_bip448_pending_transfer_signing_if_absent(&pool, &pending).await?;
        assert_eq!(persisted.state_locktime, 1_000_000_001);

        Ok(())
    }

    #[tokio::test]
    async fn pending_insert_if_absent_keeps_one_locktime_and_template_identity() -> Result<()> {
        let pool = migrated_pool().await?;
        let first = Bip448PendingDepositSigning {
            wallet_name: "wallet".to_string(),
            statechain_id: "statechain".to_string(),
            funding_txid: "aa".repeat(32),
            funding_vout: 1,
            funding_value_sats: 100_000,
            update_template_hash: "11".repeat(32),
            settlement_template_hash: "12".repeat(32),
            state_locktime: 600_000_001,
            signing_id: "22".repeat(32),
            client_secret_nonce: "33".repeat(132),
            client_public_nonce: "44".repeat(66),
            blinding_factor: "55".repeat(32),
            server_public_nonce: None,
        };
        let mut competing = first.clone();
        competing.update_template_hash = "aa".repeat(32);
        competing.settlement_template_hash = "ab".repeat(32);
        competing.state_locktime = 900_000_001;
        competing.signing_id = "bb".repeat(32);
        competing.client_secret_nonce = "cc".repeat(132);

        let (first_result, competing_result) = tokio::join!(
            insert_bip448_pending_deposit_signing_if_absent(&pool, &first),
            insert_bip448_pending_deposit_signing_if_absent(&pool, &competing),
        );
        let first_result = first_result?;
        let competing_result = competing_result?;

        assert_eq!(first_result, competing_result);
        assert!(first_result == first || first_result == competing);
        assert_eq!(
            get_bip448_pending_deposit_signing(&pool, "wallet", "statechain")
                .await?
                .unwrap(),
            first_result
        );

        Ok(())
    }

    #[tokio::test]
    async fn pending_row_without_randomized_locktime_fails_closed() -> Result<()> {
        let pool = migrated_pool().await?;
        sqlx::query(
            "INSERT INTO bip448_pending_deposit_signings (\
                wallet_name, statechain_id, update_template_hash, signing_id, \
                client_secret_nonce, client_public_nonce, blinding_factor\
             ) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind("wallet")
        .bind("pre-phase-7-1")
        .bind("11".repeat(32))
        .bind("22".repeat(32))
        .bind("33".repeat(132))
        .bind("44".repeat(66))
        .bind("55".repeat(32))
        .execute(&pool)
        .await?;

        let error = get_bip448_pending_deposit_signing(&pool, "wallet", "pre-phase-7-1")
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("predates randomized locktime support"));

        Ok(())
    }

    #[tokio::test]
    async fn accepted_record_without_explicit_locktime_is_not_silently_upgraded() -> Result<()> {
        let pool = migrated_pool().await?;
        let record = sample_bip448_record(1);
        upsert_bip448_statechain_record(&pool, &record).await?;

        let mut old_json = serde_json::to_value(&record)?;
        old_json["latest_state"]
            .as_object_mut()
            .unwrap()
            .remove("state_locktime");
        sqlx::query(
            "UPDATE bip448_statechains SET record_json = $1 \
             WHERE wallet_name = $2 AND statechain_id = $3",
        )
        .bind(serde_json::to_string(&old_json)?)
        .bind(&record.wallet_name)
        .bind(&record.statechain_id)
        .execute(&pool)
        .await?;

        let error = get_bip448_statechain(&pool, &record.wallet_name, &record.statechain_id)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("state_locktime"));

        Ok(())
    }

    #[test]
    fn legacy_coin_status_import_remains_available_for_existing_callers() {
        assert_eq!(CoinStatus::CONFIRMED.to_string(), "CONFIRMED");
    }
}
