use std::{collections::HashMap, str::FromStr};

use anyhow::{anyhow, Result};
use bitcoin::{
    hashes::{sha256, Hash},
    PrivateKey,
};
use mercurylib::{
    bip448_statechain::{script, storage::Bip448StatechainRecord},
    transfer::bip448::Bip448TransferMsg,
    wallet::Wallet,
};
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};
use sqlx::{Pool, Sqlite};

use crate::bip448_funding::{
    self, Bip448BindingObservation, Bip448BindingRole, Bip448FundingBinding, Bip448OwnershipStatus,
    Bip448TransferIntentKind, Bip448TransferIntentPhase, Bip448TransferStateSigningPhase,
};

use super::super::{
    canonical_txid, canonical_wallet_json, pending_transfer_on,
    require_materialized_signed_transfer_intent_on, validate_bip448_successor_plan_on,
    validate_bip448_transfer_intent_lineage,
};
use super::{
    accepted_record_and_history_on, begin_bip448_mutation_guard, list_bip448_funding_bindings_on,
    list_bip448_transfer_intents_on, list_bip448_withdrawal_attempts_on,
    require_selected_bip448_wallet_coin_on, transfer_message_matches_record_and_history,
    Bip448MutationGuard, Bip448PendingDepositSigning, Bip448WalletCoinRequirement,
};

pub(in crate::sqlite_manager) fn accepted_funding_script(
    record: &Bip448StatechainRecord,
) -> Result<String> {
    let aggregate = secp256k1::PublicKey::from_str(&record.aggregate_pubkey)?;
    let spend_info = script::funding_spend_info(
        &secp256k1::Secp256k1::new(),
        aggregate.x_only_public_key().0,
    )?;
    Ok(hex::encode(
        script::output_script_pubkey(&spend_info).as_bytes(),
    ))
}

async fn reconcile_bip448_funding_bindings_in_guard(
    guard: &mut Bip448MutationGuard,
    wallet_name: &str,
    statechain_id: &str,
    owner_user_pubkey: &str,
    owner_state_number: u32,
    observations: &[Bip448BindingObservation],
) -> Result<Vec<Bip448FundingBinding>> {
    let owner_user_pubkey = bip448_funding::canonical_xonly_public_key(owner_user_pubkey)?;
    if owner_state_number == 0 {
        return Err(anyhow!(
            "BIP448 binding owner state number must be positive"
        ));
    }
    let (record, history) =
        accepted_record_and_history_on(guard.connection(), wallet_name, statechain_id).await?;
    if record.wallet_name != wallet_name
        || record.statechain_id != statechain_id
        || record.latest_state_number != owner_state_number
        || history
            .get(
                usize::try_from(record.latest_state_number)?
                    .checked_sub(1)
                    .ok_or_else(|| anyhow!("BIP448 accepted state number must be positive"))?,
            )
            .map(|entry| entry.owner_public_key.as_str())
            != Some(owner_user_pubkey.as_str())
    {
        return Err(anyhow!(
            "BIP448 accepted record/history does not match the selected owner generation"
        ));
    }
    require_selected_bip448_wallet_coin_on(
        guard.connection(),
        &record,
        XOnlyPublicKey::from_str(&owner_user_pubkey)?,
        Bip448WalletCoinRequirement::PassiveBindingSync,
    )
    .await?;
    let expected_script = accepted_funding_script(&record)?;
    let mut observations = observations.to_vec();
    for observation in &mut observations {
        observation.txid = canonical_txid(&observation.txid)?;
        if let Some(spend_txid) = &mut observation.spend_txid {
            *spend_txid = canonical_txid(spend_txid)?;
        }
        bip448_funding::validate_binding_observation(observation)?;
        if observation.script_pubkey != expected_script {
            return Err(anyhow!(
                "BIP448 binding script does not match the accepted aggregate key"
            ));
        }
    }
    observations.sort_by(|left, right| {
        (left.txid.as_str(), left.vout).cmp(&(right.txid.as_str(), right.vout))
    });
    if observations
        .windows(2)
        .any(|rows| rows[0].txid == rows[1].txid && rows[0].vout == rows[1].vout)
    {
        return Err(anyhow!("duplicate BIP448 binding observation"));
    }
    let canonical_position = observations.iter().position(|observation| {
        observation.txid == record.funding_outpoint.txid
            && observation.vout == record.funding_outpoint.vout
    });
    let canonical_position = canonical_position.ok_or_else(|| {
        anyhow!("BIP448 reconciliation is missing the accepted canonical outpoint")
    })?;
    if observations[canonical_position].value_sats != record.funding_outpoint.value_sats {
        return Err(anyhow!(
            "BIP448 canonical binding value conflicts with the accepted record"
        ));
    }

    let mut existing =
        list_bip448_funding_bindings_on(guard.connection(), wallet_name, statechain_id).await?;
    if let Some(prior) = existing
        .first()
        .filter(|binding| binding.owner_user_pubkey != owner_user_pubkey)
    {
        let prior_history_index = usize::try_from(prior.owner_state_number)?
            .checked_sub(1)
            .ok_or_else(|| anyhow!("BIP448 prior binding owner state must be positive"))?;
        let exact_prior_generation = prior.owner_state_number < owner_state_number
            && history
                .get(prior_history_index)
                .map(|entry| entry.owner_public_key.as_str())
                == Some(prior.owner_user_pubkey.as_str())
            && existing.iter().all(|binding| {
                binding.owner_user_pubkey == prior.owner_user_pubkey
                    && binding.owner_state_number == prior.owner_state_number
                    && binding.ownership_status == Bip448OwnershipStatus::Current
            });
        if !exact_prior_generation
            || !list_bip448_withdrawal_attempts_on(guard.connection(), wallet_name, statechain_id)
                .await?
                .is_empty()
        {
            return Err(anyhow!(
                "BIP448 binding owner reassignment is not one exact attempt-free generation"
            ));
        }
        for binding in &existing {
            let result = sqlx::query(
                "UPDATE bip448_funding_bindings SET owner_user_pubkey=$1, \
                    owner_state_number=$2, ownership_status='Current', \
                    last_seen_at=CURRENT_TIMESTAMP \
                 WHERE wallet_name=$3 AND statechain_id=$4 AND binding_index=$5 \
                   AND txid=$6 AND vout=$7 AND value_sats=$8 AND script_pubkey=$9 \
                   AND role=$10 AND owner_user_pubkey=$11 AND owner_state_number=$12 \
                   AND ownership_status='Current'",
            )
            .bind(&owner_user_pubkey)
            .bind(i64::from(owner_state_number))
            .bind(wallet_name)
            .bind(statechain_id)
            .bind(i64::from(binding.binding_index))
            .bind(&binding.txid)
            .bind(i64::from(binding.vout))
            .bind(i64::try_from(binding.value_sats)?)
            .bind(&binding.script_pubkey)
            .bind(binding.role.as_str())
            .bind(&binding.owner_user_pubkey)
            .bind(i64::from(binding.owner_state_number))
            .execute(guard.connection())
            .await?;
            if result.rows_affected() != 1 {
                return Err(anyhow!(
                    "BIP448 same-wallet binding owner reassignment CAS lost"
                ));
            }
        }
        existing =
            list_bip448_funding_bindings_on(guard.connection(), wallet_name, statechain_id).await?;
    }
    let mut by_outpoint = existing
        .iter()
        .map(|binding| ((binding.txid.clone(), binding.vout), binding.clone()))
        .collect::<HashMap<_, _>>();
    if let Some(canonical) = existing.iter().find(|binding| binding.binding_index == 0) {
        if canonical.txid != record.funding_outpoint.txid
            || canonical.vout != record.funding_outpoint.vout
            || canonical.value_sats != record.funding_outpoint.value_sats
            || canonical.script_pubkey != expected_script
            || canonical.role != Bip448BindingRole::Canonical
        {
            return Err(anyhow!(
                "BIP448 canonical binding immutable identity conflict"
            ));
        }
    }
    let mut highest_index = existing.iter().map(|binding| binding.binding_index).max();

    for observation in observations {
        let is_canonical = observation.txid == record.funding_outpoint.txid
            && observation.vout == record.funding_outpoint.vout;
        let key = (observation.txid.clone(), observation.vout);
        if let Some(binding) = by_outpoint.get(&key) {
            let expected_role = if is_canonical {
                Bip448BindingRole::Canonical
            } else {
                Bip448BindingRole::Duplicate
            };
            if binding.role != expected_role
                || (binding.binding_index == 0) != is_canonical
                || binding.value_sats != observation.value_sats
                || binding.script_pubkey != observation.script_pubkey
                || binding.owner_user_pubkey != owner_user_pubkey
                || binding.owner_state_number != owner_state_number
            {
                return Err(anyhow!("BIP448 binding immutable identity conflict"));
            }
            let result = sqlx::query(
                "UPDATE bip448_funding_bindings SET observation_status = $1, \
                    funding_height = $2, spend_txid = $3, spend_height = $4, \
                    last_scanned_height = $5, last_seen_at = CURRENT_TIMESTAMP \
                 WHERE wallet_name = $6 AND statechain_id = $7 AND binding_index = $8 \
                   AND txid = $9 AND vout = $10 AND value_sats = $11 AND script_pubkey = $12 \
                   AND role = $13 AND owner_user_pubkey = $14 AND owner_state_number = $15",
            )
            .bind(observation.observation_status.as_str())
            .bind(observation.funding_height.map(i64::from))
            .bind(&observation.spend_txid)
            .bind(observation.spend_height.map(i64::from))
            .bind(i64::from(observation.last_scanned_height))
            .bind(wallet_name)
            .bind(statechain_id)
            .bind(i64::from(binding.binding_index))
            .bind(&binding.txid)
            .bind(i64::from(binding.vout))
            .bind(i64::try_from(binding.value_sats)?)
            .bind(&binding.script_pubkey)
            .bind(binding.role.as_str())
            .bind(&binding.owner_user_pubkey)
            .bind(i64::from(binding.owner_state_number))
            .execute(guard.connection())
            .await?;
            if result.rows_affected() != 1 {
                return Err(anyhow!("BIP448 binding observation compare-and-set lost"));
            }
        } else {
            let binding_index = if is_canonical {
                0
            } else {
                let allocated = highest_index.map_or(Ok(1), |index| {
                    index
                        .checked_add(1)
                        .ok_or_else(|| anyhow!("BIP448 duplicate binding index overflow"))
                })?;
                highest_index = Some(allocated);
                allocated
            };
            let role = if is_canonical {
                Bip448BindingRole::Canonical
            } else {
                Bip448BindingRole::Duplicate
            };
            let result = sqlx::query(
                "INSERT INTO bip448_funding_bindings (\
                    wallet_name, statechain_id, binding_index, txid, vout, value_sats, \
                    script_pubkey, role, observation_status, funding_height, spend_txid, \
                    spend_height, last_scanned_height, owner_user_pubkey, owner_state_number, \
                    ownership_status\
                 ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
            )
            .bind(wallet_name)
            .bind(statechain_id)
            .bind(i64::from(binding_index))
            .bind(&observation.txid)
            .bind(i64::from(observation.vout))
            .bind(i64::try_from(observation.value_sats)?)
            .bind(&observation.script_pubkey)
            .bind(role.as_str())
            .bind(observation.observation_status.as_str())
            .bind(observation.funding_height.map(i64::from))
            .bind(&observation.spend_txid)
            .bind(observation.spend_height.map(i64::from))
            .bind(i64::from(observation.last_scanned_height))
            .bind(&owner_user_pubkey)
            .bind(i64::from(owner_state_number))
            .bind(Bip448OwnershipStatus::Current.as_str())
            .execute(guard.connection())
            .await?;
            if result.rows_affected() != 1 {
                return Err(anyhow!(
                    "BIP448 binding insert affected an unexpected row count"
                ));
            }
            let inserted = guard
                .exact_binding(wallet_name, statechain_id, binding_index)
                .await?
                .ok_or_else(|| anyhow!("BIP448 binding disappeared after insertion"))?;
            by_outpoint.insert(key, inserted);
        }
    }
    list_bip448_funding_bindings_on(guard.connection(), wallet_name, statechain_id).await
}

pub async fn reconcile_bip448_funding_bindings(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    owner_user_pubkey: &str,
    owner_state_number: u32,
    observations: &[Bip448BindingObservation],
) -> Result<Vec<Bip448FundingBinding>> {
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    let bindings = reconcile_bip448_funding_bindings_in_guard(
        &mut guard,
        wallet_name,
        statechain_id,
        owner_user_pubkey,
        owner_state_number,
        observations,
    )
    .await?;
    guard.commit().await?;
    Ok(bindings)
}

pub async fn update_bip448_funding_binding_observation(
    pool: &Pool<Sqlite>,
    expected: &Bip448FundingBinding,
    observation: &Bip448BindingObservation,
) -> Result<Bip448FundingBinding> {
    bip448_funding::validate_binding(expected)?;
    bip448_funding::validate_binding_observation(observation)?;
    if expected.txid != observation.txid
        || expected.vout != observation.vout
        || expected.value_sats != observation.value_sats
        || expected.script_pubkey != observation.script_pubkey
    {
        return Err(anyhow!("BIP448 observation cannot mutate binding identity"));
    }
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    let live = guard
        .exact_binding(
            &expected.wallet_name,
            &expected.statechain_id,
            expected.binding_index,
        )
        .await?
        .ok_or_else(|| anyhow!("BIP448 binding disappeared before observation update"))?;
    if live != *expected {
        return Err(anyhow!("BIP448 binding changed before observation update"));
    }
    let result = sqlx::query(
        "UPDATE bip448_funding_bindings SET observation_status = $1, funding_height = $2, \
            spend_txid = $3, spend_height = $4, last_scanned_height = $5, \
            last_seen_at = CURRENT_TIMESTAMP \
         WHERE wallet_name = $6 AND statechain_id = $7 AND binding_index = $8 \
           AND txid = $9 AND vout = $10 AND value_sats = $11 AND script_pubkey = $12 \
           AND role = $13 AND owner_user_pubkey = $14 AND owner_state_number = $15 \
           AND ownership_status = $16 AND observation_status = $17",
    )
    .bind(observation.observation_status.as_str())
    .bind(observation.funding_height.map(i64::from))
    .bind(&observation.spend_txid)
    .bind(observation.spend_height.map(i64::from))
    .bind(i64::from(observation.last_scanned_height))
    .bind(&expected.wallet_name)
    .bind(&expected.statechain_id)
    .bind(i64::from(expected.binding_index))
    .bind(&expected.txid)
    .bind(i64::from(expected.vout))
    .bind(i64::try_from(expected.value_sats)?)
    .bind(&expected.script_pubkey)
    .bind(expected.role.as_str())
    .bind(&expected.owner_user_pubkey)
    .bind(i64::from(expected.owner_state_number))
    .bind(expected.ownership_status.as_str())
    .bind(expected.observation_status.as_str())
    .execute(guard.connection())
    .await?;
    if result.rows_affected() != 1 {
        return Err(anyhow!("BIP448 binding observation compare-and-set lost"));
    }
    let updated = guard
        .exact_binding(
            &expected.wallet_name,
            &expected.statechain_id,
            expected.binding_index,
        )
        .await?
        .ok_or_else(|| anyhow!("BIP448 binding disappeared after observation update"))?;
    guard.commit().await?;
    Ok(updated)
}

pub async fn reassign_bip448_funding_bindings_owner(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    expected_owner_user_pubkey: &str,
    expected_owner_state_number: u32,
    new_owner_user_pubkey: &str,
    new_owner_state_number: u32,
) -> Result<Vec<Bip448FundingBinding>> {
    let expected_owner_user_pubkey =
        bip448_funding::canonical_xonly_public_key(expected_owner_user_pubkey)?;
    let new_owner_user_pubkey = bip448_funding::canonical_xonly_public_key(new_owner_user_pubkey)?;
    if expected_owner_state_number == 0 || new_owner_state_number == 0 {
        return Err(anyhow!("BIP448 owner state number must be positive"));
    }
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    let (record, history) =
        accepted_record_and_history_on(guard.connection(), wallet_name, statechain_id).await?;
    let new_index = usize::try_from(new_owner_state_number)?
        .checked_sub(1)
        .ok_or_else(|| anyhow!("BIP448 owner state number must be positive"))?;
    if record.latest_state_number != new_owner_state_number
        || history
            .get(new_index)
            .map(|entry| entry.owner_public_key.as_str())
            != Some(new_owner_user_pubkey.as_str())
    {
        return Err(anyhow!(
            "BIP448 accepted history does not prove the new owner"
        ));
    }
    let before =
        list_bip448_funding_bindings_on(guard.connection(), wallet_name, statechain_id).await?;
    if !list_bip448_withdrawal_attempts_on(guard.connection(), wallet_name, statechain_id)
        .await?
        .is_empty()
    {
        return Err(anyhow!(
            "BIP448 binding owner reassignment refuses a sender generation with a spend attempt"
        ));
    }
    if before.is_empty()
        || before.iter().any(|binding| {
            binding.owner_user_pubkey != expected_owner_user_pubkey
                || binding.owner_state_number != expected_owner_state_number
                || binding.ownership_status != Bip448OwnershipStatus::Current
        })
    {
        return Err(anyhow!(
            "BIP448 binding owner generation changed before reassignment"
        ));
    }
    for binding in &before {
        let result = sqlx::query(
            "UPDATE bip448_funding_bindings SET owner_user_pubkey=$1,owner_state_number=$2, \
                ownership_status='Current',last_seen_at=CURRENT_TIMESTAMP \
             WHERE wallet_name=$3 AND statechain_id=$4 AND binding_index=$5 \
               AND txid=$6 AND vout=$7 AND value_sats=$8 AND script_pubkey=$9 AND role=$10 \
               AND owner_user_pubkey=$11 AND owner_state_number=$12 \
               AND ownership_status='Current'",
        )
        .bind(&new_owner_user_pubkey)
        .bind(i64::from(new_owner_state_number))
        .bind(wallet_name)
        .bind(statechain_id)
        .bind(i64::from(binding.binding_index))
        .bind(&binding.txid)
        .bind(i64::from(binding.vout))
        .bind(i64::try_from(binding.value_sats)?)
        .bind(&binding.script_pubkey)
        .bind(binding.role.as_str())
        .bind(&expected_owner_user_pubkey)
        .bind(i64::from(expected_owner_state_number))
        .execute(guard.connection())
        .await?;
        if result.rows_affected() != 1 {
            return Err(anyhow!("BIP448 binding owner reassignment CAS lost"));
        }
    }
    let after =
        list_bip448_funding_bindings_on(guard.connection(), wallet_name, statechain_id).await?;
    if before.iter().zip(&after).any(|(old, new)| {
        old.binding_index != new.binding_index || old.txid != new.txid || old.vout != new.vout
    }) {
        return Err(anyhow!(
            "BIP448 owner reassignment changed stable binding identity"
        ));
    }
    guard.commit().await?;
    Ok(after)
}

pub async fn mark_bip448_funding_bindings_previous(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    owner_user_pubkey: &str,
    owner_state_number: u32,
) -> Result<Vec<Bip448FundingBinding>> {
    let owner_user_pubkey = bip448_funding::canonical_xonly_public_key(owner_user_pubkey)?;
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    let before =
        list_bip448_funding_bindings_on(guard.connection(), wallet_name, statechain_id).await?;
    let expected = before
        .iter()
        .filter(|binding| {
            binding.owner_user_pubkey == owner_user_pubkey
                && binding.owner_state_number == owner_state_number
                && binding.ownership_status == Bip448OwnershipStatus::Current
        })
        .count();
    if expected == 0 || expected != before.len() {
        return Err(anyhow!(
            "BIP448 current binding generation does not match rotation proof"
        ));
    }
    for binding in &before {
        let result = sqlx::query(
            "UPDATE bip448_funding_bindings SET ownership_status='Previous', \
                last_seen_at=CURRENT_TIMESTAMP WHERE wallet_name=$1 AND statechain_id=$2 \
                AND binding_index=$3 AND txid=$4 AND vout=$5 AND value_sats=$6 \
                AND script_pubkey=$7 AND role=$8 AND owner_user_pubkey=$9 \
                AND owner_state_number=$10 AND ownership_status='Current'",
        )
        .bind(wallet_name)
        .bind(statechain_id)
        .bind(i64::from(binding.binding_index))
        .bind(&binding.txid)
        .bind(i64::from(binding.vout))
        .bind(i64::try_from(binding.value_sats)?)
        .bind(&binding.script_pubkey)
        .bind(binding.role.as_str())
        .bind(&owner_user_pubkey)
        .bind(i64::from(owner_state_number))
        .execute(guard.connection())
        .await?;
        if result.rows_affected() != 1 {
            return Err(anyhow!("BIP448 ownership invalidation CAS lost"));
        }
    }
    let after =
        list_bip448_funding_bindings_on(guard.connection(), wallet_name, statechain_id).await?;
    guard.commit().await?;
    Ok(after)
}

pub async fn finish_bip448_rotated_outgoing_transfer(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    recipient_auth_pubkey: &str,
    expected_transfer_msg_json: &str,
    validated_x1_pub: &str,
    validated_pending: &Bip448PendingDepositSigning,
) -> Result<()> {
    let message: Bip448TransferMsg = serde_json::from_str(expected_transfer_msg_json)?;
    if serde_json::to_string(&message)? != expected_transfer_msg_json
        || message.statechain_id != statechain_id
        || message.receiver_user_public_key.is_empty()
    {
        return Err(anyhow!(
            "BIP448 rotated transfer message is noncanonical or has the wrong identity"
        ));
    }
    let sender_owner = secp256k1::PublicKey::from_str(&message.sender_user_public_key)?
        .x_only_public_key()
        .0
        .to_string();
    let validated_x1 = PublicKey::from_str(validated_x1_pub)?;
    if validated_x1.to_string() != validated_x1_pub {
        return Err(anyhow!("BIP448 rotated transfer x1 proof is not canonical"));
    }
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    let stored = sqlx::query_scalar::<_, String>(
        "SELECT transfer_msg_json FROM bip448_transfer_messages WHERE wallet_name=$1 \
         AND statechain_id=$2 AND recipient_auth_pubkey=$3",
    )
    .bind(wallet_name)
    .bind(statechain_id)
    .bind(recipient_auth_pubkey)
    .fetch_optional(guard.connection())
    .await?
    .ok_or_else(|| anyhow!("BIP448 rotated outgoing message is missing"))?;
    if stored != expected_transfer_msg_json {
        return Err(anyhow!("BIP448 rotated outgoing message bytes changed"));
    }
    let (record, history) =
        accepted_record_and_history_on(guard.connection(), wallet_name, statechain_id).await?;
    if !transfer_message_matches_record_and_history(&message, &record, &history)? {
        return Err(anyhow!(
            "BIP448 rotated outgoing message does not exactly match persisted accepted history"
        ));
    }
    let accepted_owner = history
        .get(
            usize::try_from(record.latest_state_number)?
                .checked_sub(1)
                .ok_or_else(|| anyhow!("BIP448 accepted state number must be positive"))?,
        )
        .ok_or_else(|| anyhow!("BIP448 accepted owner history is missing"))?
        .owner_public_key
        .parse::<XOnlyPublicKey>()?;
    if accepted_owner.to_string() != sender_owner {
        return Err(anyhow!(
            "BIP448 rotated outgoing message sender does not match the accepted owner"
        ));
    }
    require_selected_bip448_wallet_coin_on(
        guard.connection(),
        &record,
        accepted_owner,
        Bip448WalletCoinRequirement::PersistedTransferSender,
    )
    .await?;

    let pending = pending_transfer_on(guard.connection(), wallet_name, statechain_id)
        .await?
        .ok_or_else(|| anyhow!("BIP448 rotated transfer pending signing is missing"))?;
    if pending != *validated_pending {
        return Err(anyhow!(
            "BIP448 rotated transfer pending signing changed after raw-first validation"
        ));
    }
    let latest = message
        .state_history
        .last()
        .ok_or_else(|| anyhow!("BIP448 rotated transfer history is empty"))?;
    let metadata = &message.latest_state.signing_metadata;
    if pending.funding_txid != record.funding_outpoint.txid
        || pending.funding_vout != record.funding_outpoint.vout
        || pending.funding_value_sats != record.funding_outpoint.value_sats
        || pending.state_locktime != latest.state_locktime
        || pending.update_template_hash != latest.update_template_hash
        || pending.settlement_template_hash != latest.settlement_template_hash
        || pending.signing_id != metadata.signing_id
        || pending.client_public_nonce != latest.client_public_nonce
        || pending.server_public_nonce.as_deref() != Some(latest.server_public_nonce.as_str())
        || pending.blinding_factor != latest.blinding_factor
    {
        return Err(anyhow!(
            "BIP448 rotated transfer pending/message fingerprint changed"
        ));
    }
    let intents =
        list_bip448_transfer_intents_on(guard.connection(), wallet_name, statechain_id).await?;
    let mut materialized_active_owner = false;
    if !intents.is_empty() {
        let active_index = validate_bip448_transfer_intent_lineage(&intents)?
            .ok_or_else(|| anyhow!("BIP448 rotated transfer lineage has no Active row"))?;
        let active = &intents[active_index];
        let message_hash = sha256::Hash::hash(expected_transfer_msg_json.as_bytes()).to_string();
        let successor_matches = matches!(
            active.phase,
            Bip448TransferIntentPhase::Prepared | Bip448TransferIntentPhase::SenderArmed
        ) && active.server_x1.is_none()
            && active.state_signing_phase == Bip448TransferStateSigningPhase::NotStarted
            && active.prior_transfer_recipient_auth_pubkey.as_deref()
                == Some(recipient_auth_pubkey)
            && active.prior_transfer_msg_hash.as_deref() == Some(message_hash.as_str());
        materialized_active_owner = active.intent_kind == Bip448TransferIntentKind::UserTransfer
            && active.phase == Bip448TransferIntentPhase::X1Stored
            && active.server_x1.is_some()
            && active.state_signing_phase == Bip448TransferStateSigningPhase::Signed
            && active.recipient_auth_pubkey == recipient_auth_pubkey
            && active.receiver_user_pubkey == message.receiver_user_public_key;
        if !successor_matches && !materialized_active_owner {
            return Err(anyhow!(
                "BIP448 rotated predecessor does not match the Active successor lineage"
            ));
        }
        if materialized_active_owner {
            require_materialized_signed_transfer_intent_on(guard.connection(), active).await?;
        } else {
            let predecessor_id = active
                .predecessor_intent_id
                .as_deref()
                .ok_or_else(|| anyhow!("BIP448 rotated successor has no predecessor intent"))?;
            let predecessor = intents
                .iter()
                .find(|intent| intent.intent_id == predecessor_id)
                .ok_or_else(|| anyhow!("BIP448 rotated predecessor intent is missing"))?;
            validate_bip448_successor_plan_on(guard.connection(), predecessor, active).await?;
        }
        let expected_pending_id = if materialized_active_owner {
            active.current_pending_signing_id.as_deref()
        } else {
            active.prior_pending_signing_id.as_deref()
        };
        if expected_pending_id != Some(pending.signing_id.as_str()) {
            return Err(anyhow!(
                "BIP448 rotated transfer intent/pending fingerprint changed"
            ));
        }
    }

    let raw_wallet =
        sqlx::query_scalar::<_, String>("SELECT wallet_json FROM wallet WHERE wallet_name=$1")
            .bind(wallet_name)
            .fetch_one(guard.connection())
            .await?;
    let mut wallet: Wallet = serde_json::from_str(&raw_wallet)?;
    let sender_matches = wallet
        .coins
        .iter()
        .enumerate()
        .filter(|(_, coin)| {
            coin.statechain_id.as_deref() == Some(statechain_id)
                && coin.user_pubkey == message.sender_user_public_key
                && coin.server_pubkey.as_deref() == Some(message.server_public_key.as_str())
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let sender_status_matches = sender_matches.len() == 1
        && if materialized_active_owner {
            matches!(
                wallet.coins[sender_matches[0]].status,
                mercurylib::wallet::CoinStatus::CONFIRMED
                    | mercurylib::wallet::CoinStatus::IN_TRANSFER
            )
        } else {
            matches!(
                wallet.coins[sender_matches[0]].status,
                mercurylib::wallet::CoinStatus::CONFIRMED
                    | mercurylib::wallet::CoinStatus::IN_TRANSFER
            )
        };
    if !sender_status_matches {
        return Err(anyhow!(
            "BIP448 rotated sender Coin is not one exact IN_TRANSFER generation"
        ));
    }
    let sender_secret = PrivateKey::from_wif(&wallet.coins[sender_matches[0]].user_privkey)?.inner;
    let t1 = SecretKey::from_secret_bytes(message.t1)?;
    let derived_x1 = t1.add_tweak(&Scalar::from(sender_secret.negate()))?;
    if derived_x1.public_key(&Secp256k1::new()) != validated_x1 {
        return Err(anyhow!(
            "BIP448 rotated transfer message/Coin pair changed after x1 validation"
        ));
    }
    wallet.coins[sender_matches[0]].status = mercurylib::wallet::CoinStatus::TRANSFERRED;
    for intent in &intents {
        if intent.intent_kind != Bip448TransferIntentKind::Cancellation {
            continue;
        }
        let generated_matches = wallet
            .coins
            .iter()
            .enumerate()
            .filter(|(_, coin)| {
                coin.status == mercurylib::wallet::CoinStatus::INITIALISED
                    && coin.statechain_id.is_none()
                    && Some(coin.user_pubkey.as_str())
                        == intent.generated_coin_user_pubkey.as_deref()
                    && Some(coin.auth_pubkey.as_str())
                        == intent.generated_coin_auth_pubkey.as_deref()
                    && Some(coin.address.as_str()) == intent.generated_coin_address.as_deref()
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if generated_matches.len() != 1 {
            return Err(anyhow!(
                "BIP448 impossible successor cancellation Coin is not uniquely removable"
            ));
        }
        wallet.coins.remove(generated_matches[0]);
    }

    let bindings =
        list_bip448_funding_bindings_on(guard.connection(), wallet_name, statechain_id).await?;
    if bindings.is_empty()
        || bindings.iter().any(|binding| {
            binding.owner_user_pubkey != sender_owner
                || binding.ownership_status != Bip448OwnershipStatus::Current
        })
    {
        return Err(anyhow!(
            "BIP448 rotated sender binding generation changed before cleanup"
        ));
    }
    for binding in &bindings {
        let updated = sqlx::query(
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
        .execute(guard.connection())
        .await?;
        if updated.rows_affected() != 1 {
            return Err(anyhow!("BIP448 rotated binding cleanup CAS lost"));
        }
    }
    let deleted_message = sqlx::query(
        "DELETE FROM bip448_transfer_messages WHERE wallet_name=$1 AND statechain_id=$2 \
         AND recipient_auth_pubkey=$3 AND transfer_msg_json=$4",
    )
    .bind(wallet_name)
    .bind(statechain_id)
    .bind(recipient_auth_pubkey)
    .bind(expected_transfer_msg_json)
    .execute(guard.connection())
    .await?;
    if deleted_message.rows_affected() != 1 {
        return Err(anyhow!("BIP448 rotated message cleanup CAS lost"));
    }
    sqlx::query(
        "DELETE FROM bip448_pending_transfer_signings WHERE wallet_name=$1 AND statechain_id=$2",
    )
    .bind(wallet_name)
    .bind(statechain_id)
    .execute(guard.connection())
    .await?;
    let deleted_intents = sqlx::query(
        "DELETE FROM bip448_transfer_intents WHERE wallet_name=$1 AND statechain_id=$2",
    )
    .bind(wallet_name)
    .bind(statechain_id)
    .execute(guard.connection())
    .await?;
    if deleted_intents.rows_affected() != u64::try_from(intents.len())? {
        return Err(anyhow!(
            "BIP448 rotated intent cleanup affected an unexpected row count"
        ));
    }
    let replacement = canonical_wallet_json(&wallet)?;
    let updated_wallet =
        sqlx::query("UPDATE wallet SET wallet_json=$1 WHERE wallet_name=$2 AND wallet_json=$3")
            .bind(replacement)
            .bind(wallet_name)
            .bind(&raw_wallet)
            .execute(guard.connection())
            .await?;
    if updated_wallet.rows_affected() != 1 {
        return Err(anyhow!("BIP448 rotated wallet cleanup CAS lost"));
    }
    guard.commit().await?;
    Ok(())
}

impl Bip448MutationGuard {
    pub async fn reconcile_funding_bindings(
        &mut self,
        wallet_name: &str,
        statechain_id: &str,
        owner_user_pubkey: &str,
        owner_state_number: u32,
        observations: &[Bip448BindingObservation],
    ) -> Result<Vec<Bip448FundingBinding>> {
        reconcile_bip448_funding_bindings_in_guard(
            self,
            wallet_name,
            statechain_id,
            owner_user_pubkey,
            owner_state_number,
            observations,
        )
        .await
    }
}
