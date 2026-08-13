use std::str::FromStr;

use anyhow::{anyhow, Result};
use mercurylib::wallet::Wallet;
use secp256k1::XOnlyPublicKey;
use sqlx::{Pool, Sqlite, SqliteConnection};

use crate::{
    bip448_funding::{self, Bip448AppliedScanRevision, Bip448OwnershipStatus, Bip448SyncBase},
    chain::ChainUtxo,
};

use super::super::{canonical_block_hash, canonical_txid, canonical_wallet_json};
use super::{
    accepted_record_and_history_on, begin_bip448_mutation_guard, checked_u32, checked_u64,
    list_bip448_funding_bindings_on, replace_bip448_scan_cache_on,
    require_selected_bip448_wallet_coin_on, Bip448MutationGuard, Bip448ScanCursor,
    Bip448WalletCoinRequirement,
};

async fn capture_bip448_sync_base_on(
    connection: &mut SqliteConnection,
    wallet_name: &str,
    script_pubkey: &str,
) -> Result<Bip448SyncBase> {
    let raw_wallet_json =
        sqlx::query_scalar::<_, String>("SELECT wallet_json FROM wallet WHERE wallet_name = $1")
            .bind(wallet_name)
            .fetch_optional(&mut *connection)
            .await?
            .ok_or_else(|| anyhow!("BIP448 synchronization wallet is missing"))?;
    let pending_deposit_rows = sqlx::query_scalar::<_, String>(
        "SELECT json_array(wallet_name,statechain_id,update_template_hash,signing_id,\
         client_secret_nonce,client_public_nonce,blinding_factor,server_public_nonce,\
         state_locktime,funding_txid,funding_vout,funding_value_sats,settlement_template_hash,\
         created_at,updated_at) FROM bip448_pending_deposit_signings \
         WHERE wallet_name = $1 ORDER BY statechain_id",
    )
    .bind(wallet_name)
    .fetch_all(&mut *connection)
    .await?;
    let accepted_record_rows = sqlx::query_scalar::<_, String>(
        "SELECT json_array(wallet_name,statechain_id,aggregate_pubkey,funding_txid,funding_vout,\
         funding_value_sats,latest_state_number,challenge_delay,amount_sats,network,record_json,\
         created_at,updated_at) FROM bip448_statechains WHERE wallet_name = $1 ORDER BY statechain_id",
    ).bind(wallet_name).fetch_all(&mut *connection).await?;
    let state_history_rows = sqlx::query_scalar::<_, String>(
        "SELECT json_array(wallet_name,statechain_id,state_number,entry_json) \
         FROM bip448_state_history WHERE wallet_name = $1 ORDER BY statechain_id,state_number",
    )
    .bind(wallet_name)
    .fetch_all(&mut *connection)
    .await?;
    let cursor_rows = sqlx::query_scalar::<_, String>(
        "SELECT json_array(wallet_name,script_pubkey,coverage_start_height,scan_revision,\
         last_scanned_height,last_scanned_block_hash,updated_at) FROM bip448_scan_cursors \
         WHERE wallet_name = $1 AND script_pubkey = $2",
    )
    .bind(wallet_name)
    .bind(script_pubkey)
    .fetch_all(&mut *connection)
    .await?;
    let scan_cache_rows = sqlx::query_scalar::<_, String>(
        "SELECT json_array(wallet_name,txid,vout,script_pubkey,value_sats,height,reserved_by,\
         reserved_at) FROM bip448_scanned_outpoints WHERE wallet_name = $1 \
         AND script_pubkey = $2 ORDER BY txid,vout",
    )
    .bind(wallet_name)
    .bind(script_pubkey)
    .fetch_all(&mut *connection)
    .await?;
    let funding_binding_rows = sqlx::query_scalar::<_, String>(
        "SELECT json_array(wallet_name,statechain_id,binding_index,txid,vout,value_sats,\
         script_pubkey,role,observation_status,funding_height,spend_txid,spend_height,\
         last_scanned_height,owner_user_pubkey,owner_state_number,ownership_status,\
         first_seen_at,last_seen_at) FROM bip448_funding_bindings WHERE wallet_name = $1 \
         ORDER BY statechain_id,binding_index",
    )
    .bind(wallet_name)
    .fetch_all(&mut *connection)
    .await?;
    let withdrawal_attempt_rows = sqlx::query_scalar::<_, String>(
        "SELECT json_array(wallet_name,statechain_id,binding_index,attempt_kind,owner_user_pubkey,\
         owner_state_number,source_txid,source_vout,source_value_sats,source_script_pubkey,\
         destination_address,destination_script_pubkey,quote(fee_rate_sat_per_vbyte),fee_sats,\
         lock_time,unsigned_tx_hex,signing_id,signed_statechain_id,sign_first_payload_json,\
         client_secret_nonce,client_public_nonce,blinding_factor,server_public_nonce,message_hex,\
         output_pubkey,client_partial_sig,encoded_session,sign_second_payload_json,\
         server_partial_sig,aggregate_signature,signed_tx_hex,txid,phase,broadcast_status,\
         completion_status,closing_tip_height,closing_tip_hash,closing_bindings_json,\
         created_at,updated_at) FROM bip448_withdrawal_attempts WHERE wallet_name = $1 \
         ORDER BY statechain_id,binding_index",
    )
    .bind(wallet_name)
    .fetch_all(&mut *connection)
    .await?;
    let transfer_intent_rows = sqlx::query_scalar::<_, String>(
        "SELECT json_array(wallet_name,statechain_id,intent_id,predecessor_intent_id,\
         activity_status,intent_kind,acknowledge_cooperative_duplicates,recipient_address,\
         receiver_user_pubkey,recipient_auth_pubkey,batch_id,sender_signed_statechain_id,\
         planned_state_number,expected_signature_count,previous_locktime,prior_pending_signing_id,\
         prior_transfer_recipient_auth_pubkey,prior_transfer_msg_hash,reuse_pending,\
         reuse_signed_state,clear_local_attempt,generated_coin_user_pubkey,generated_coin_auth_pubkey,\
         generated_coin_address,phase,server_x1,current_pending_signing_id,state_signing_phase,\
         server_partial_sig,update_signature,created_at,updated_at) FROM bip448_transfer_intents \
         WHERE wallet_name = $1 ORDER BY statechain_id,intent_id",
    ).bind(wallet_name).fetch_all(&mut *connection).await?;
    let pending_transfer_rows = sqlx::query_scalar::<_, String>(
        "SELECT json_array(wallet_name,statechain_id,funding_txid,funding_vout,funding_value_sats,\
         update_template_hash,settlement_template_hash,state_locktime,signing_id,client_secret_nonce,\
         client_public_nonce,blinding_factor,server_public_nonce,created_at,updated_at) \
         FROM bip448_pending_transfer_signings WHERE wallet_name = $1 ORDER BY statechain_id",
    ).bind(wallet_name).fetch_all(&mut *connection).await?;
    let outgoing_transfer_message_rows = sqlx::query_scalar::<_, String>(
        "SELECT json_array(wallet_name,statechain_id,recipient_auth_pubkey,transfer_msg_json,\
         created_at,updated_at) FROM bip448_transfer_messages WHERE wallet_name = $1 \
         ORDER BY statechain_id,recipient_auth_pubkey",
    )
    .bind(wallet_name)
    .fetch_all(&mut *connection)
    .await?;
    Ok(Bip448SyncBase {
        wallet_name: wallet_name.to_owned(),
        script_pubkey: script_pubkey.to_owned(),
        raw_wallet_json,
        pending_deposit_rows,
        accepted_record_rows,
        state_history_rows,
        cursor_rows,
        scan_cache_rows,
        funding_binding_rows,
        withdrawal_attempt_rows,
        transfer_intent_rows,
        pending_transfer_rows,
        outgoing_transfer_message_rows,
    })
}

pub async fn capture_bip448_sync_base(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    script_pubkey: &str,
) -> Result<Bip448SyncBase> {
    bip448_funding::require_canonical_script(script_pubkey)?;
    let mut connection = pool.acquire().await?;
    capture_bip448_sync_base_on(&mut connection, wallet_name, script_pubkey).await
}

pub async fn begin_bip448_sync_base_guard(
    pool: &Pool<Sqlite>,
    expected: &Bip448SyncBase,
) -> Result<Bip448MutationGuard> {
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    let live = capture_bip448_sync_base_on(
        guard.connection(),
        &expected.wallet_name,
        &expected.script_pubkey,
    )
    .await?;
    if live != *expected {
        return Err(anyhow!(
            "BIP448 synchronization base changed during RPC work"
        ));
    }
    Ok(guard)
}

pub async fn compare_and_set_wallet_after_bip448_scan(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    expected_raw_wallet_json: &str,
    replacement_wallet: &Wallet,
    applied_revisions: &[Bip448AppliedScanRevision],
) -> Result<bool> {
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    if !guard
        .update_wallet_if_unchanged_and_scan_current(
            wallet_name,
            expected_raw_wallet_json,
            replacement_wallet,
            applied_revisions,
        )
        .await?
    {
        return Ok(false);
    }
    guard.commit().await?;
    Ok(true)
}

impl Bip448MutationGuard {
    pub async fn apply_scan_cache_and_cursor(
        &mut self,
        wallet_name: &str,
        script_pubkey: &str,
        candidate: &Bip448ScanCursor,
        outpoints: &[ChainUtxo],
    ) -> Result<Bip448AppliedScanRevision> {
        bip448_funding::require_canonical_script(script_pubkey)?;
        let block_hash = canonical_block_hash(&candidate.last_scanned_block_hash)?;
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
        let live = sqlx::query(
            "SELECT coverage_start_height,scan_revision FROM bip448_scan_cursors \
            WHERE wallet_name = $1 AND script_pubkey = $2",
        )
        .bind(wallet_name)
        .bind(script_pubkey)
        .fetch_optional(self.connection())
        .await?;
        let (coverage, revision, existed) = match live {
            Some(row) => (
                checked_u32(&row, 0, "BIP448 coverage floor")?.min(candidate.coverage_start_height),
                checked_u64(&row, 1, "BIP448 scan revision")?,
                true,
            ),
            None => (candidate.coverage_start_height, 0, false),
        };
        if revision != candidate.scan_revision {
            return Err(anyhow!("BIP448 scan candidate lost its revision CAS"));
        }
        let next_revision = revision
            .checked_add(1)
            .ok_or_else(|| anyhow!("BIP448 scan revision overflow"))?;
        let next_revision_i64 = i64::try_from(next_revision)
            .map_err(|_| anyhow!("BIP448 scan revision exceeds SQLite integer domain"))?;
        replace_bip448_scan_cache_on(self.connection(), wallet_name, script_pubkey, &outpoints)
            .await?;
        let cursor_write = if existed {
            sqlx::query(
                "UPDATE bip448_scan_cursors SET coverage_start_height=$1,scan_revision=$2,\
                last_scanned_height=$3,last_scanned_block_hash=$4,updated_at=CURRENT_TIMESTAMP \
                WHERE wallet_name=$5 AND script_pubkey=$6 AND scan_revision=$7",
            )
            .bind(i64::from(coverage))
            .bind(next_revision_i64)
            .bind(i64::from(candidate.last_scanned_height))
            .bind(block_hash)
            .bind(wallet_name)
            .bind(script_pubkey)
            .bind(i64::try_from(revision)?)
            .execute(self.connection())
            .await?
        } else {
            sqlx::query(
                "INSERT INTO bip448_scan_cursors (wallet_name,script_pubkey,\
                coverage_start_height,scan_revision,last_scanned_height,last_scanned_block_hash) \
                VALUES ($1,$2,$3,$4,$5,$6)",
            )
            .bind(wallet_name)
            .bind(script_pubkey)
            .bind(i64::from(coverage))
            .bind(next_revision_i64)
            .bind(i64::from(candidate.last_scanned_height))
            .bind(block_hash)
            .execute(self.connection())
            .await?
        };
        if cursor_write.rows_affected() != 1 {
            return Err(anyhow!("BIP448 scan cursor CAS lost"));
        }
        Ok(Bip448AppliedScanRevision {
            script_pubkey: script_pubkey.to_owned(),
            scan_revision: next_revision,
        })
    }

    pub async fn update_wallet_if_unchanged_and_scan_current(
        &mut self,
        wallet_name: &str,
        expected_raw_wallet_json: &str,
        replacement_wallet: &Wallet,
        applied_revisions: &[Bip448AppliedScanRevision],
    ) -> Result<bool> {
        if replacement_wallet.name != wallet_name {
            return Err(anyhow!("BIP448 wallet CAS identity mismatch"));
        }
        let replacement = canonical_wallet_json(replacement_wallet)?;
        let mut tokens = applied_revisions.to_vec();
        tokens.sort_by(|left, right| left.script_pubkey.cmp(&right.script_pubkey));
        if tokens
            .windows(2)
            .any(|pair| pair[0].script_pubkey == pair[1].script_pubkey)
        {
            return Err(anyhow!("duplicate BIP448 applied scan revision token"));
        }
        let live_wallet = sqlx::query_scalar::<_, String>(
            "SELECT wallet_json FROM wallet WHERE wallet_name = $1",
        )
        .bind(wallet_name)
        .fetch_optional(self.connection())
        .await?;
        if live_wallet.as_deref() != Some(expected_raw_wallet_json) {
            return Ok(false);
        }
        for token in &tokens {
            bip448_funding::require_canonical_script(&token.script_pubkey)?;
            let live_revision = sqlx::query_scalar::<_, i64>(
                "SELECT scan_revision FROM bip448_scan_cursors \
                 WHERE wallet_name = $1 AND script_pubkey = $2",
            )
            .bind(wallet_name)
            .bind(&token.script_pubkey)
            .fetch_optional(self.connection())
            .await?;
            if live_revision.map(u64::try_from).transpose()? != Some(token.scan_revision) {
                return Ok(false);
            }
        }
        let expected_wallet: Wallet = serde_json::from_str(expected_raw_wallet_json)?;
        if expected_wallet.coins.len() != replacement_wallet.coins.len() {
            return Err(anyhow!("BIP448 scan wallet CAS cannot add or remove Coins"));
        }
        for (old_coin, new_coin) in expected_wallet.coins.iter().zip(&replacement_wallet.coins) {
            if new_coin.status != mercurylib::wallet::CoinStatus::TRANSFERRED
                || old_coin.status == mercurylib::wallet::CoinStatus::TRANSFERRED
            {
                continue;
            }
            if old_coin.status != mercurylib::wallet::CoinStatus::IN_TRANSFER {
                return Err(anyhow!(
                    "BIP448 TRANSFERRED status requires an IN_TRANSFER predecessor"
                ));
            }
            let mut normalized = new_coin.clone();
            normalized.status = old_coin.status.clone();
            if serde_json::to_value(&normalized)? != serde_json::to_value(old_coin)? {
                return Err(anyhow!(
                    "BIP448 positive rotation changes more than Coin status"
                ));
            }
            let statechain_id = old_coin
                .statechain_id
                .as_deref()
                .ok_or_else(|| anyhow!("rotated BIP448 Coin is missing statechain_id"))?;
            let owner = secp256k1::PublicKey::from_str(&old_coin.user_pubkey)?
                .x_only_public_key()
                .0
                .to_string();
            let bindings =
                list_bip448_funding_bindings_on(self.connection(), wallet_name, statechain_id)
                    .await?;
            if bindings.is_empty() {
                return Err(anyhow!(
                    "BIP448 positive rotation binding generation changed"
                ));
            }
            if bindings.iter().any(|binding| {
                binding.owner_user_pubkey != owner
                    || binding.ownership_status != Bip448OwnershipStatus::Current
            }) {
                let (record, history) =
                    accepted_record_and_history_on(self.connection(), wallet_name, statechain_id)
                        .await?;
                let accepted_owner_index = usize::try_from(record.latest_state_number)?
                    .checked_sub(1)
                    .ok_or_else(|| anyhow!("BIP448 accepted state number must be positive"))?;
                let accepted_owner = history
                    .get(accepted_owner_index)
                    .ok_or_else(|| anyhow!("BIP448 accepted owner history is incomplete"))?
                    .owner_public_key
                    .clone();
                let same_wallet_receiver_reassigned = accepted_owner != owner
                    && bindings.iter().all(|binding| {
                        binding.owner_user_pubkey == accepted_owner
                            && binding.owner_state_number == record.latest_state_number
                            && binding.ownership_status == Bip448OwnershipStatus::Current
                    });
                if !same_wallet_receiver_reassigned {
                    return Err(anyhow!(
                        "BIP448 positive rotation binding generation changed"
                    ));
                }
                require_selected_bip448_wallet_coin_on(
                    self.connection(),
                    &record,
                    XOnlyPublicKey::from_str(&accepted_owner)?,
                    Bip448WalletCoinRequirement::PassiveBindingSync,
                )
                .await?;
                continue;
            }
            for binding in &bindings {
                let result = sqlx::query(
                    "UPDATE bip448_funding_bindings SET ownership_status='Previous', \
                     last_seen_at=CURRENT_TIMESTAMP WHERE wallet_name=$1 AND statechain_id=$2 \
                     AND binding_index=$3 AND owner_user_pubkey=$4 AND owner_state_number=$5 \
                     AND ownership_status='Current'",
                )
                .bind(wallet_name)
                .bind(statechain_id)
                .bind(i64::from(binding.binding_index))
                .bind(&binding.owner_user_pubkey)
                .bind(i64::from(binding.owner_state_number))
                .execute(self.connection())
                .await?;
                if result.rows_affected() != 1 {
                    return Err(anyhow!("BIP448 positive rotation binding CAS lost"));
                }
            }
        }
        let result = sqlx::query(
            "UPDATE wallet SET wallet_json = $1 WHERE wallet_name = $2 AND wallet_json = $3",
        )
        .bind(replacement)
        .bind(wallet_name)
        .bind(expected_raw_wallet_json)
        .execute(self.connection())
        .await?;
        if result.rows_affected() != 1 {
            return Err(anyhow!(
                "BIP448 wallet CAS affected an unexpected row count"
            ));
        }
        Ok(true)
    }
}
