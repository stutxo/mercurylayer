use anyhow::{anyhow, Result};
use bitcoin::hashes::{sha256, Hash};
use mercurylib::{transfer::bip448::Bip448TransferMsg, wallet::Wallet};
use sqlx::{Pool, Row, Sqlite, SqliteConnection};

use crate::bip448_funding::{
    self, Bip448TransferIntent, Bip448TransferIntentActivityStatus, Bip448TransferIntentKind,
    Bip448TransferIntentPhase, Bip448TransferStateSigningPhase,
};

use super::super::{canonical_txid, canonical_wallet_json};
use super::transfer_intents::{
    exact_transfer_intent_on, require_materialized_signed_transfer_intent_on,
    validate_bip448_transfer_intent_lineage,
};
use super::{
    accepted_record_and_history_on, begin_bip448_mutation_guard, checked_u32, checked_u64,
    history_entry_matches_pending_intent, list_bip448_transfer_intents_on,
    transfer_message_matches_record_and_history, Bip448PendingDepositSigning,
};

fn pending_transfer_immutable_eq(
    left: &Bip448PendingDepositSigning,
    right: &Bip448PendingDepositSigning,
) -> bool {
    left.wallet_name == right.wallet_name
        && left.statechain_id == right.statechain_id
        && left.funding_txid == right.funding_txid
        && left.funding_vout == right.funding_vout
        && left.funding_value_sats == right.funding_value_sats
        && left.update_template_hash == right.update_template_hash
        && left.settlement_template_hash == right.settlement_template_hash
        && left.state_locktime == right.state_locktime
        && left.signing_id == right.signing_id
        && left.client_secret_nonce == right.client_secret_nonce
        && left.client_public_nonce == right.client_public_nonce
        && left.blinding_factor == right.blinding_factor
}

pub(super) fn validate_bip448_transfer_pending_signing(
    pending: &Bip448PendingDepositSigning,
) -> Result<()> {
    bip448_funding::require_canonical_txid(&pending.funding_txid)?;
    bip448_funding::require_canonical_hex(&pending.update_template_hash, Some(32))?;
    bip448_funding::require_canonical_hex(&pending.settlement_template_hash, Some(32))?;
    bip448_funding::require_canonical_hex(&pending.signing_id, Some(32))?;
    bip448_funding::require_canonical_hex(&pending.client_secret_nonce, Some(132))?;
    bip448_funding::require_canonical_hex(&pending.client_public_nonce, Some(66))?;
    bip448_funding::require_canonical_hex(&pending.blinding_factor, Some(32))?;
    if let Some(server_public_nonce) = &pending.server_public_nonce {
        bip448_funding::require_canonical_hex(server_public_nonce, Some(66))?;
    }
    if pending.funding_value_sats > bip448_funding::BIP448_MAX_MONEY_SATS
        || pending.state_locktime < 500_000_000
    {
        return Err(anyhow!(
            "invalid BIP448 transfer pending-signing integer domain"
        ));
    }
    Ok(())
}

pub(in crate::sqlite_manager) async fn pending_transfer_on(
    connection: &mut SqliteConnection,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<Option<Bip448PendingDepositSigning>> {
    let row = sqlx::query(
        "SELECT wallet_name, statechain_id, funding_txid, funding_vout, \
        funding_value_sats, update_template_hash, settlement_template_hash, state_locktime, \
        signing_id, client_secret_nonce, client_public_nonce, blinding_factor, server_public_nonce \
        FROM bip448_pending_transfer_signings WHERE wallet_name = $1 AND statechain_id = $2",
    )
    .bind(wallet_name)
    .bind(statechain_id)
    .fetch_optional(connection)
    .await?;
    row.map(|row| {
        let pending = Bip448PendingDepositSigning {
            wallet_name: row.try_get(0)?,
            statechain_id: row.try_get(1)?,
            funding_txid: canonical_txid(row.try_get(2)?)?,
            funding_vout: checked_u32(&row, 3, "BIP448 pending funding vout")?,
            funding_value_sats: checked_u64(&row, 4, "BIP448 pending funding value")?,
            update_template_hash: row.try_get(5)?,
            settlement_template_hash: row.try_get(6)?,
            state_locktime: checked_u32(&row, 7, "BIP448 pending locktime")?,
            signing_id: row.try_get(8)?,
            client_secret_nonce: row.try_get(9)?,
            client_public_nonce: row.try_get(10)?,
            blinding_factor: row.try_get(11)?,
            server_public_nonce: row.try_get(12)?,
        };
        validate_bip448_transfer_pending_signing(&pending)?;
        Ok(pending)
    })
    .transpose()
}

pub async fn install_bip448_transfer_target_pending_signing(
    pool: &Pool<Sqlite>,
    intent_id: &str,
    pending: &Bip448PendingDepositSigning,
) -> Result<Bip448TransferIntent> {
    validate_bip448_transfer_pending_signing(pending)?;
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    let intent = exact_transfer_intent_on(
        guard.connection(),
        &pending.wallet_name,
        &pending.statechain_id,
        intent_id,
    )
    .await?
    .ok_or_else(|| anyhow!("BIP448 transfer intent is missing"))?;
    if intent.activity_status != Bip448TransferIntentActivityStatus::Active
        || intent.phase != Bip448TransferIntentPhase::X1Stored
        || intent.state_signing_phase != Bip448TransferStateSigningPhase::NotStarted
        || intent.reuse_signed_state
    {
        return Err(anyhow!(
            "BIP448 transfer intent is not ready to install target pending signing"
        ));
    }
    if pending.funding_txid != canonical_txid(&pending.funding_txid)? {
        return Err(anyhow!("BIP448 pending transfer outpoint is not canonical"));
    }
    let (record, history) = accepted_record_and_history_on(
        guard.connection(),
        &pending.wallet_name,
        &pending.statechain_id,
    )
    .await?;
    if pending.funding_txid != record.funding_outpoint.txid
        || pending.funding_vout != record.funding_outpoint.vout
        || pending.funding_value_sats != record.funding_outpoint.value_sats
        || pending.state_locktime <= intent.previous_locktime
        || usize::try_from(intent.expected_signature_count)? != history.len()
    {
        return Err(anyhow!(
            "BIP448 target pending signing does not match its retained state plan"
        ));
    }
    let prior_pending = pending_transfer_on(
        guard.connection(),
        &pending.wallet_name,
        &pending.statechain_id,
    )
    .await?;
    match prior_pending {
        Some(prior) if intent.reuse_pending => {
            if intent.prior_pending_signing_id.as_deref() != Some(prior.signing_id.as_str())
                || !pending_transfer_immutable_eq(&prior, pending)
            {
                return Err(anyhow!("BIP448 reused predecessor pending signing changed"));
            }
        }
        Some(prior) => {
            if !intent.clear_local_attempt
                || intent.prior_pending_signing_id.as_deref() != Some(prior.signing_id.as_str())
                || prior.signing_id == pending.signing_id
                || pending.server_public_nonce.is_some()
            {
                return Err(anyhow!(
                    "BIP448 predecessor pending signing fingerprint changed"
                ));
            }
            let deleted = sqlx::query(
                "DELETE FROM bip448_pending_transfer_signings \
                WHERE wallet_name = $1 AND statechain_id = $2 AND signing_id = $3",
            )
            .bind(&pending.wallet_name)
            .bind(&pending.statechain_id)
            .bind(&prior.signing_id)
            .execute(guard.connection())
            .await?;
            if deleted.rows_affected() != 1 {
                return Err(anyhow!("BIP448 predecessor pending compare-delete lost"));
            }
        }
        None if intent.reuse_pending || intent.prior_pending_signing_id.is_some() => {
            return Err(anyhow!(
                "BIP448 predecessor pending signing is missing before replacement"
            ));
        }
        None if pending.server_public_nonce.is_some() => {
            return Err(anyhow!(
                "fresh BIP448 target pending signing already contains a server nonce"
            ));
        }
        None => {}
    }
    if intent.prior_transfer_msg_hash.is_none() {
        let unjournaled_messages = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bip448_transfer_messages WHERE wallet_name=$1 \
             AND statechain_id=$2",
        )
        .bind(&pending.wallet_name)
        .bind(&pending.statechain_id)
        .fetch_one(guard.connection())
        .await?;
        if unjournaled_messages != 0 {
            return Err(anyhow!(
                "BIP448 unjournaled predecessor transfer message blocks replacement"
            ));
        }
    }
    if let (Some(recipient), Some(expected_hash)) = (
        intent.prior_transfer_recipient_auth_pubkey.as_deref(),
        intent.prior_transfer_msg_hash.as_deref(),
    ) {
        if !intent.clear_local_attempt {
            return Err(anyhow!(
                "BIP448 predecessor message replacement is not authorized"
            ));
        }
        let prior_json = sqlx::query_scalar::<_, String>(
            "SELECT transfer_msg_json \
            FROM bip448_transfer_messages WHERE wallet_name=$1 AND statechain_id=$2 \
            AND recipient_auth_pubkey=$3",
        )
        .bind(&pending.wallet_name)
        .bind(&pending.statechain_id)
        .bind(recipient)
        .fetch_optional(guard.connection())
        .await?
        .ok_or_else(|| anyhow!("BIP448 predecessor transfer message is missing"))?;
        let actual_hash = sha256::Hash::hash(prior_json.as_bytes()).to_string();
        if actual_hash != expected_hash {
            return Err(anyhow!(
                "BIP448 predecessor transfer-message fingerprint changed"
            ));
        }
        let deleted = sqlx::query(
            "DELETE FROM bip448_transfer_messages WHERE wallet_name=$1 \
            AND statechain_id=$2 AND recipient_auth_pubkey=$3 AND transfer_msg_json=$4",
        )
        .bind(&pending.wallet_name)
        .bind(&pending.statechain_id)
        .bind(recipient)
        .bind(&prior_json)
        .execute(guard.connection())
        .await?;
        if deleted.rows_affected() != 1 {
            return Err(anyhow!("BIP448 predecessor message compare-delete lost"));
        }
    }
    if pending_transfer_on(
        guard.connection(),
        &pending.wallet_name,
        &pending.statechain_id,
    )
    .await?
    .is_none()
    {
        let inserted = sqlx::query(
            "INSERT INTO bip448_pending_transfer_signings \
            (wallet_name,statechain_id,funding_txid,funding_vout,funding_value_sats,\
             update_template_hash,settlement_template_hash,state_locktime,signing_id,\
             client_secret_nonce,client_public_nonce,blinding_factor,server_public_nonce) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
        )
        .bind(&pending.wallet_name)
        .bind(&pending.statechain_id)
        .bind(&pending.funding_txid)
        .bind(i64::from(pending.funding_vout))
        .bind(i64::try_from(pending.funding_value_sats)?)
        .bind(&pending.update_template_hash)
        .bind(&pending.settlement_template_hash)
        .bind(i64::from(pending.state_locktime))
        .bind(&pending.signing_id)
        .bind(&pending.client_secret_nonce)
        .bind(&pending.client_public_nonce)
        .bind(&pending.blinding_factor)
        .bind(&pending.server_public_nonce)
        .execute(guard.connection())
        .await?;
        if inserted.rows_affected() != 1 {
            return Err(anyhow!("BIP448 target pending signing insert failed"));
        }
    }
    let lineage = list_bip448_transfer_intents_on(
        guard.connection(),
        &pending.wallet_name,
        &pending.statechain_id,
    )
    .await?;
    validate_bip448_transfer_intent_lineage(&lineage)?;
    let generated = lineage
        .iter()
        .filter(|row| {
            row.activity_status == Bip448TransferIntentActivityStatus::Superseded
                && row.intent_kind == Bip448TransferIntentKind::Cancellation
        })
        .collect::<Vec<_>>();
    if !generated.is_empty() {
        let raw =
            sqlx::query_scalar::<_, String>("SELECT wallet_json FROM wallet WHERE wallet_name=$1")
                .bind(&pending.wallet_name)
                .fetch_one(guard.connection())
                .await?;
        let mut wallet: Wallet = serde_json::from_str(&raw)?;
        for old in generated {
            let matches = wallet
                .coins
                .iter()
                .enumerate()
                .filter(|(_, coin)| {
                    coin.status == mercurylib::wallet::CoinStatus::INITIALISED
                        && Some(coin.user_pubkey.as_str())
                            == old.generated_coin_user_pubkey.as_deref()
                        && Some(coin.auth_pubkey.as_str())
                            == old.generated_coin_auth_pubkey.as_deref()
                        && Some(coin.address.as_str()) == old.generated_coin_address.as_deref()
                        && coin.statechain_id.is_none()
                })
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            if matches.len() != 1 {
                return Err(anyhow!(
                    "superseded BIP448 cancellation Coin is not uniquely removable"
                ));
            }
            wallet.coins.remove(matches[0]);
        }
        let replacement = canonical_wallet_json(&wallet)?;
        let updated =
            sqlx::query("UPDATE wallet SET wallet_json=$1 WHERE wallet_name=$2 AND wallet_json=$3")
                .bind(replacement)
                .bind(&pending.wallet_name)
                .bind(&raw)
                .execute(guard.connection())
                .await?;
        if updated.rows_affected() != 1 {
            return Err(anyhow!("BIP448 superseded Coin cleanup CAS lost"));
        }
    }
    let result = sqlx::query(
        "UPDATE bip448_transfer_intents SET current_pending_signing_id = $1, \
        state_signing_phase = 'FirstArmed', updated_at = CURRENT_TIMESTAMP \
        WHERE wallet_name = $2 AND statechain_id = $3 AND intent_id = $4 \
        AND activity_status = 'Active' AND phase = 'X1Stored' \
        AND state_signing_phase = 'NotStarted' AND current_pending_signing_id IS NULL",
    )
    .bind(&pending.signing_id)
    .bind(&pending.wallet_name)
    .bind(&pending.statechain_id)
    .bind(intent_id)
    .execute(guard.connection())
    .await?;
    if result.rows_affected() != 1 {
        return Err(anyhow!(
            "stale BIP448 worker lost target-pending installation CAS"
        ));
    }
    let stored = exact_transfer_intent_on(
        guard.connection(),
        &pending.wallet_name,
        &pending.statechain_id,
        intent_id,
    )
    .await?
    .ok_or_else(|| anyhow!("BIP448 intent disappeared"))?;
    guard.commit().await?;
    Ok(stored)
}

pub async fn install_bip448_transfer_target_pending(
    pool: &Pool<Sqlite>,
    intent_id: &str,
    pending: &Bip448PendingDepositSigning,
) -> Result<Bip448TransferIntent> {
    install_bip448_transfer_target_pending_signing(pool, intent_id, pending).await
}

pub async fn store_bip448_transfer_state_nonce(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    intent_id: &str,
    signing_id: &str,
    server_public_nonce: &str,
) -> Result<Bip448TransferIntent> {
    bip448_funding::require_canonical_hex(server_public_nonce, Some(66))?;
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    let live_intent =
        exact_transfer_intent_on(guard.connection(), wallet_name, statechain_id, intent_id)
            .await?
            .ok_or_else(|| anyhow!("BIP448 transfer intent is missing before nonce storage"))?;
    if live_intent.activity_status != Bip448TransferIntentActivityStatus::Active
        || live_intent.phase != Bip448TransferIntentPhase::X1Stored
        || live_intent.state_signing_phase != Bip448TransferStateSigningPhase::FirstArmed
        || live_intent.current_pending_signing_id.as_deref() != Some(signing_id)
    {
        return Err(anyhow!("stale BIP448 transfer worker lost nonce identity"));
    }
    let live_pending = pending_transfer_on(guard.connection(), wallet_name, statechain_id)
        .await?
        .ok_or_else(|| anyhow!("BIP448 transfer nonce pending row is missing"))?;
    if live_pending.signing_id != signing_id {
        return Err(anyhow!("BIP448 transfer nonce pending identity changed"));
    }
    match live_pending.server_public_nonce.as_deref() {
        Some(stored) if stored == server_public_nonce => {}
        Some(_) => return Err(anyhow!("BIP448 transfer server nonce replay conflicts")),
        None => {
            let pending = sqlx::query(
                "UPDATE bip448_pending_transfer_signings SET server_public_nonce=$1, \
                updated_at=CURRENT_TIMESTAMP WHERE wallet_name=$2 AND statechain_id=$3 \
                AND signing_id=$4 AND server_public_nonce IS NULL",
            )
            .bind(server_public_nonce)
            .bind(wallet_name)
            .bind(statechain_id)
            .bind(signing_id)
            .execute(guard.connection())
            .await?;
            if pending.rows_affected() != 1 {
                return Err(anyhow!("BIP448 transfer nonce pending-row CAS lost"));
            }
        }
    }
    let intent = sqlx::query(
        "UPDATE bip448_transfer_intents SET state_signing_phase = 'NonceStored', \
        updated_at = CURRENT_TIMESTAMP WHERE wallet_name = $1 AND statechain_id = $2 \
        AND intent_id = $3 AND activity_status = 'Active' AND phase = 'X1Stored' \
        AND state_signing_phase = 'FirstArmed' AND current_pending_signing_id = $4",
    )
    .bind(wallet_name)
    .bind(statechain_id)
    .bind(intent_id)
    .bind(signing_id)
    .execute(guard.connection())
    .await?;
    if intent.rows_affected() != 1 {
        return Err(anyhow!("stale BIP448 transfer worker lost nonce CAS"));
    }
    let row = exact_transfer_intent_on(guard.connection(), wallet_name, statechain_id, intent_id)
        .await?
        .ok_or_else(|| anyhow!("BIP448 intent disappeared after nonce storage"))?;
    guard.commit().await?;
    Ok(row)
}

pub async fn arm_bip448_transfer_state_sign_second(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    intent_id: &str,
    signing_id: &str,
) -> Result<Bip448TransferIntent> {
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    let live = exact_transfer_intent_on(guard.connection(), wallet_name, statechain_id, intent_id)
        .await?
        .ok_or_else(|| anyhow!("BIP448 transfer intent is missing before sign/second"))?;
    let pending = pending_transfer_on(guard.connection(), wallet_name, statechain_id)
        .await?
        .ok_or_else(|| anyhow!("BIP448 transfer pending row is missing before sign/second"))?;
    if live.activity_status != Bip448TransferIntentActivityStatus::Active
        || live.phase != Bip448TransferIntentPhase::X1Stored
        || live.state_signing_phase != Bip448TransferStateSigningPhase::NonceStored
        || live.current_pending_signing_id.as_deref() != Some(signing_id)
        || pending.signing_id != signing_id
        || pending.server_public_nonce.is_none()
    {
        return Err(anyhow!(
            "BIP448 transfer sign/second journal identity is incoherent"
        ));
    }
    let result = sqlx::query(
        "UPDATE bip448_transfer_intents SET state_signing_phase = 'SecondArmed', \
        updated_at = CURRENT_TIMESTAMP WHERE wallet_name = $1 AND statechain_id = $2 \
        AND intent_id = $3 AND activity_status = 'Active' AND phase = 'X1Stored' \
        AND state_signing_phase = 'NonceStored' AND current_pending_signing_id = $4",
    )
    .bind(wallet_name)
    .bind(statechain_id)
    .bind(intent_id)
    .bind(signing_id)
    .execute(guard.connection())
    .await?;
    if result.rows_affected() != 1 {
        return Err(anyhow!("stale BIP448 transfer worker lost sign/second CAS"));
    }
    let row = exact_transfer_intent_on(guard.connection(), wallet_name, statechain_id, intent_id)
        .await?
        .ok_or_else(|| anyhow!("BIP448 intent disappeared after sign/second arm"))?;
    guard.commit().await?;
    Ok(row)
}

pub async fn transition_bip448_transfer_state_signing_phase(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    intent_id: &str,
    signing_id: &str,
    expected_phase: Bip448TransferStateSigningPhase,
    next_phase: Bip448TransferStateSigningPhase,
) -> Result<Bip448TransferIntent> {
    if (expected_phase, next_phase)
        != (
            Bip448TransferStateSigningPhase::NonceStored,
            Bip448TransferStateSigningPhase::SecondArmed,
        )
    {
        return Err(anyhow!(
            "BIP448 state-signing phase requires its artifact-specific transition helper"
        ));
    }
    arm_bip448_transfer_state_sign_second(pool, wallet_name, statechain_id, intent_id, signing_id)
        .await
}

pub async fn store_signed_bip448_transfer_state(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    intent_id: &str,
    signing_id: &str,
    server_partial_sig: &str,
    update_signature: &str,
) -> Result<Bip448TransferIntent> {
    bip448_funding::require_canonical_hex(server_partial_sig, Some(32))?;
    bip448_funding::require_canonical_hex(update_signature, Some(64))?;
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    let live = exact_transfer_intent_on(guard.connection(), wallet_name, statechain_id, intent_id)
        .await?
        .ok_or_else(|| anyhow!("BIP448 transfer intent is missing before Signed storage"))?;
    let pending = pending_transfer_on(guard.connection(), wallet_name, statechain_id)
        .await?
        .ok_or_else(|| anyhow!("BIP448 transfer pending row is missing before Signed storage"))?;
    if live.activity_status != Bip448TransferIntentActivityStatus::Active
        || live.phase != Bip448TransferIntentPhase::X1Stored
        || live.state_signing_phase != Bip448TransferStateSigningPhase::SecondArmed
        || live.current_pending_signing_id.as_deref() != Some(signing_id)
        || pending.signing_id != signing_id
        || pending.server_public_nonce.is_none()
    {
        return Err(anyhow!(
            "BIP448 transfer Signed journal identity is incoherent"
        ));
    }
    let result = sqlx::query(
        "UPDATE bip448_transfer_intents SET server_partial_sig = $1, \
        update_signature = $2, state_signing_phase = 'Signed', updated_at = CURRENT_TIMESTAMP \
        WHERE wallet_name = $3 AND statechain_id = $4 AND intent_id = $5 \
        AND activity_status = 'Active' AND phase = 'X1Stored' \
        AND state_signing_phase = 'SecondArmed' AND current_pending_signing_id = $6 \
        AND server_partial_sig IS NULL AND update_signature IS NULL",
    )
    .bind(server_partial_sig)
    .bind(update_signature)
    .bind(wallet_name)
    .bind(statechain_id)
    .bind(intent_id)
    .bind(signing_id)
    .execute(guard.connection())
    .await?;
    if result.rows_affected() != 1 {
        return Err(anyhow!("stale BIP448 worker lost signed-state CAS"));
    }
    let row = exact_transfer_intent_on(guard.connection(), wallet_name, statechain_id, intent_id)
        .await?
        .ok_or_else(|| anyhow!("BIP448 intent disappeared after signed-state storage"))?;
    guard.commit().await?;
    Ok(row)
}

pub async fn store_bip448_transfer_state_signed_artifacts(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    intent_id: &str,
    signing_id: &str,
    server_partial_sig: &str,
    update_signature: &str,
) -> Result<Bip448TransferIntent> {
    store_signed_bip448_transfer_state(
        pool,
        wallet_name,
        statechain_id,
        intent_id,
        signing_id,
        server_partial_sig,
        update_signature,
    )
    .await
}

pub async fn install_reused_signed_bip448_transfer_state(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    intent_id: &str,
    pending_signing_id: &str,
    update_signature: &str,
) -> Result<Bip448TransferIntent> {
    bip448_funding::require_canonical_hex(pending_signing_id, Some(32))?;
    bip448_funding::require_canonical_hex(update_signature, Some(64))?;
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    let intent =
        exact_transfer_intent_on(guard.connection(), wallet_name, statechain_id, intent_id)
            .await?
            .ok_or_else(|| anyhow!("BIP448 reused-state intent is missing"))?;
    if !intent.reuse_signed_state
        || !intent.reuse_pending
        || intent.activity_status != Bip448TransferIntentActivityStatus::Active
        || intent.phase != Bip448TransferIntentPhase::X1Stored
        || intent.state_signing_phase != Bip448TransferStateSigningPhase::NotStarted
        || intent.prior_pending_signing_id.as_deref() != Some(pending_signing_id)
    {
        return Err(anyhow!(
            "BIP448 intent does not authorize signed-state reuse"
        ));
    }
    let pending = pending_transfer_on(guard.connection(), wallet_name, statechain_id)
        .await?
        .ok_or_else(|| anyhow!("BIP448 reused pending signing is missing"))?;
    if pending.signing_id != pending_signing_id {
        return Err(anyhow!("BIP448 reused pending signing identity changed"));
    }
    let (record, history) =
        accepted_record_and_history_on(guard.connection(), wallet_name, statechain_id).await?;
    let history_index = usize::try_from(intent.planned_state_number)?
        .checked_sub(1)
        .ok_or_else(|| anyhow!("BIP448 planned state number must be positive"))?;
    let entry = history
        .get(history_index)
        .ok_or_else(|| anyhow!("BIP448 reused signed history entry is missing"))?;
    if history.len() != usize::try_from(intent.planned_state_number)?
        || pending.funding_txid != record.funding_outpoint.txid
        || pending.funding_vout != record.funding_outpoint.vout
        || pending.funding_value_sats != record.funding_outpoint.value_sats
        || entry.update_signature != update_signature
        || !history_entry_matches_pending_intent(entry, &pending, &intent)?
    {
        return Err(anyhow!(
            "BIP448 reused signed history does not match pending signing"
        ));
    }
    if let (Some(recipient), Some(expected_hash)) = (
        intent.prior_transfer_recipient_auth_pubkey.as_deref(),
        intent.prior_transfer_msg_hash.as_deref(),
    ) {
        let prior_json = sqlx::query_scalar::<_, String>(
            "SELECT transfer_msg_json FROM bip448_transfer_messages WHERE wallet_name=$1 \
             AND statechain_id=$2 AND recipient_auth_pubkey=$3",
        )
        .bind(wallet_name)
        .bind(statechain_id)
        .bind(recipient)
        .fetch_optional(guard.connection())
        .await?
        .ok_or_else(|| anyhow!("BIP448 reused-state predecessor message is missing"))?;
        if sha256::Hash::hash(prior_json.as_bytes()).to_string() != expected_hash {
            return Err(anyhow!(
                "BIP448 reused-state predecessor message fingerprint changed"
            ));
        }
    } else {
        let messages = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bip448_transfer_messages WHERE wallet_name=$1 \
             AND statechain_id=$2",
        )
        .bind(wallet_name)
        .bind(statechain_id)
        .fetch_one(guard.connection())
        .await?;
        if messages != 0 {
            return Err(anyhow!(
                "BIP448 reused-state replacement has an unjournaled predecessor message"
            ));
        }
    }
    let result = sqlx::query(
        "UPDATE bip448_transfer_intents SET current_pending_signing_id=$1,\
        update_signature=$2,state_signing_phase='Signed',updated_at=CURRENT_TIMESTAMP \
        WHERE wallet_name=$3 AND statechain_id=$4 AND intent_id=$5 AND activity_status='Active' \
        AND phase='X1Stored' AND state_signing_phase='NotStarted' \
        AND current_pending_signing_id IS NULL AND server_partial_sig IS NULL \
        AND update_signature IS NULL AND reuse_signed_state=1",
    )
    .bind(pending_signing_id)
    .bind(update_signature)
    .bind(wallet_name)
    .bind(statechain_id)
    .bind(intent_id)
    .execute(guard.connection())
    .await?;
    if result.rows_affected() != 1 {
        return Err(anyhow!("BIP448 reused-state CAS lost"));
    }
    let stored =
        exact_transfer_intent_on(guard.connection(), wallet_name, statechain_id, intent_id)
            .await?
            .ok_or_else(|| anyhow!("BIP448 reused-state intent disappeared"))?;
    guard.commit().await?;
    Ok(stored)
}

pub async fn materialize_bip448_signed_transfer_intent(
    pool: &Pool<Sqlite>,
    expected: &Bip448TransferIntent,
    validated_pending: &Bip448PendingDepositSigning,
    message: &Bip448TransferMsg,
) -> Result<String> {
    bip448_funding::validate_transfer_intent(expected)?;
    validate_bip448_transfer_pending_signing(validated_pending)?;
    if expected.activity_status != Bip448TransferIntentActivityStatus::Active
        || expected.phase != Bip448TransferIntentPhase::X1Stored
        || expected.state_signing_phase != Bip448TransferStateSigningPhase::Signed
        || expected.wallet_name != validated_pending.wallet_name
        || expected.statechain_id != validated_pending.statechain_id
        || expected.current_pending_signing_id.as_deref()
            != Some(validated_pending.signing_id.as_str())
    {
        return Err(anyhow!(
            "BIP448 transfer intent is not ready to materialize Signed state"
        ));
    }
    let message_json = serde_json::to_string(message)?;
    if message.statechain_id != expected.statechain_id
        || message.receiver_user_public_key != expected.receiver_user_pubkey
        || message.latest_state_number != expected.planned_state_number
    {
        return Err(anyhow!(
            "BIP448 Signed transfer message does not match its intent"
        ));
    }

    let mut guard = begin_bip448_mutation_guard(pool).await?;
    let live = exact_transfer_intent_on(
        guard.connection(),
        &expected.wallet_name,
        &expected.statechain_id,
        &expected.intent_id,
    )
    .await?
    .ok_or_else(|| anyhow!("BIP448 Signed transfer intent is missing"))?;
    if live != *expected {
        return Err(anyhow!(
            "stale BIP448 transfer worker lost materialization CAS"
        ));
    }
    let pending = pending_transfer_on(
        guard.connection(),
        &expected.wallet_name,
        &expected.statechain_id,
    )
    .await?
    .ok_or_else(|| anyhow!("BIP448 Signed transfer pending row is missing"))?;
    if pending != *validated_pending {
        return Err(anyhow!(
            "BIP448 Signed transfer pending signing changed after complete validation"
        ));
    }
    let (record, mut history) = accepted_record_and_history_on(
        guard.connection(),
        &expected.wallet_name,
        &expected.statechain_id,
    )
    .await?;

    let prior_rows = sqlx::query(
        "SELECT recipient_auth_pubkey,transfer_msg_json FROM bip448_transfer_messages \
         WHERE wallet_name=$1 AND statechain_id=$2 ORDER BY recipient_auth_pubkey",
    )
    .bind(&expected.wallet_name)
    .bind(&expected.statechain_id)
    .fetch_all(guard.connection())
    .await?;
    let exact_target_is_only_row = if prior_rows.len() == 1 {
        let stored_recipient: String = prior_rows[0].try_get(0)?;
        let stored_json: String = prior_rows[0].try_get(1)?;
        stored_recipient == expected.recipient_auth_pubkey && stored_json == message_json
    } else {
        false
    };
    let exact_target_history_matches_pending = match history.last() {
        Some(entry) => history_entry_matches_pending_intent(entry, &pending, expected)?,
        None => false,
    };
    if exact_target_is_only_row
        && history.len() == usize::try_from(expected.planned_state_number)?
        && exact_target_history_matches_pending
        && transfer_message_matches_record_and_history(message, &record, &history)?
    {
        guard.commit().await?;
        return Ok(message_json);
    }

    let latest_entry = message
        .state_history
        .last()
        .ok_or_else(|| anyhow!("BIP448 Signed transfer message history is empty"))?;
    if !history_entry_matches_pending_intent(latest_entry, &pending, expected)? {
        return Err(anyhow!(
            "BIP448 Signed transfer history entry does not match its journal"
        ));
    }
    if expected.reuse_signed_state {
        if history.len() != usize::try_from(expected.planned_state_number)?
            || message.state_history != history
        {
            return Err(anyhow!(
                "BIP448 reused Signed transfer history changed before materialization"
            ));
        }
    } else {
        if history.len() != usize::try_from(expected.expected_signature_count)?
            || message.state_history.len() != usize::try_from(expected.planned_state_number)?
            || message.state_history[..history.len()] != history
        {
            return Err(anyhow!(
                "BIP448 Signed transfer history prefix changed before materialization"
            ));
        }
        history.push(latest_entry.clone());
    }
    if !transfer_message_matches_record_and_history(message, &record, &history)? {
        return Err(anyhow!(
            "BIP448 Signed transfer message does not match exact record/history"
        ));
    }

    match (
        expected.prior_transfer_recipient_auth_pubkey.as_deref(),
        expected.prior_transfer_msg_hash.as_deref(),
    ) {
        (Some(recipient), Some(expected_hash)) if prior_rows.len() == 1 => {
            let stored_recipient: String = prior_rows[0].try_get(0)?;
            let stored_json: String = prior_rows[0].try_get(1)?;
            if stored_recipient != recipient
                || sha256::Hash::hash(stored_json.as_bytes()).to_string() != expected_hash
            {
                return Err(anyhow!(
                    "BIP448 predecessor transfer-message fingerprint changed"
                ));
            }
            let deleted = sqlx::query(
                "DELETE FROM bip448_transfer_messages WHERE wallet_name=$1 \
                 AND statechain_id=$2 AND recipient_auth_pubkey=$3 AND transfer_msg_json=$4",
            )
            .bind(&expected.wallet_name)
            .bind(&expected.statechain_id)
            .bind(recipient)
            .bind(stored_json)
            .execute(guard.connection())
            .await?;
            if deleted.rows_affected() != 1 {
                return Err(anyhow!(
                    "BIP448 predecessor transfer-message compare-delete lost"
                ));
            }
        }
        (Some(_), Some(_))
            if prior_rows.is_empty()
                && expected.clear_local_attempt
                && !expected.reuse_pending
                && !expected.reuse_signed_state
                && expected.current_pending_signing_id.as_deref()
                    == Some(pending.signing_id.as_str()) =>
        {
            // The target-pending transaction already compare-deleted the
            // fingerprinted predecessor message after x1 became durable.
        }
        (None, None) if prior_rows.is_empty() => {}
        _ => {
            return Err(anyhow!(
                "BIP448 Signed transfer has an unjournaled outgoing message"
            ));
        }
    }

    if !expected.reuse_signed_state {
        let entry_json = serde_json::to_string(latest_entry)?;
        let inserted = sqlx::query(
            "INSERT INTO bip448_state_history \
             (wallet_name,statechain_id,state_number,entry_json) VALUES ($1,$2,$3,$4) \
             ON CONFLICT(wallet_name,statechain_id,state_number) DO NOTHING",
        )
        .bind(&expected.wallet_name)
        .bind(&expected.statechain_id)
        .bind(i64::from(latest_entry.state_number))
        .bind(&entry_json)
        .execute(guard.connection())
        .await?;
        if inserted.rows_affected() != 1 {
            let stored = sqlx::query_scalar::<_, String>(
                "SELECT entry_json FROM bip448_state_history WHERE wallet_name=$1 \
                 AND statechain_id=$2 AND state_number=$3",
            )
            .bind(&expected.wallet_name)
            .bind(&expected.statechain_id)
            .bind(i64::from(latest_entry.state_number))
            .fetch_one(guard.connection())
            .await?;
            if stored != entry_json {
                return Err(anyhow!(
                    "BIP448 Signed transfer history materialization conflicts"
                ));
            }
        }
    }
    let inserted = sqlx::query(
        "INSERT INTO bip448_transfer_messages \
         (wallet_name,statechain_id,recipient_auth_pubkey,transfer_msg_json) \
         VALUES ($1,$2,$3,$4)",
    )
    .bind(&expected.wallet_name)
    .bind(&expected.statechain_id)
    .bind(&expected.recipient_auth_pubkey)
    .bind(&message_json)
    .execute(guard.connection())
    .await?;
    if inserted.rows_affected() != 1 {
        return Err(anyhow!(
            "BIP448 Signed transfer message materialization failed"
        ));
    }
    require_materialized_signed_transfer_intent_on(guard.connection(), expected).await?;
    guard.commit().await?;
    Ok(message_json)
}
