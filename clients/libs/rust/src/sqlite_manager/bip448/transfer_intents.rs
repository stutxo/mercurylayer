use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
};

use anyhow::{anyhow, Context, Result};
use bitcoin::hashes::{sha256, Hash};
use mercurylib::{transfer::bip448::Bip448TransferMsg, wallet::Wallet};
use sqlx::{Pool, Row, Sqlite, SqliteConnection};

use crate::bip448_funding::{
    self, Bip448BindingRole, Bip448ObservationStatus, Bip448OwnershipStatus, Bip448TransferIntent,
    Bip448TransferIntentActivityStatus, Bip448TransferIntentKind, Bip448TransferIntentPhase,
    Bip448TransferStateSigningPhase, Bip448WithdrawalPhase,
};

use super::super::canonical_wallet_json;
use super::transfer_signing::pending_transfer_on;
use super::{
    accepted_record_and_history_on, begin_bip448_mutation_guard,
    history_entry_matches_pending_intent, list_bip448_funding_bindings_on,
    list_bip448_transfer_intents, list_bip448_transfer_intents_on,
    list_bip448_withdrawal_attempts_on, row_to_bip448_intent,
    transfer_message_matches_record_and_history, Bip448MutationGuard, BIP448_INTENT_COLUMNS,
};

pub async fn get_active_bip448_transfer_intent(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<Option<Bip448TransferIntent>> {
    let intents = list_bip448_transfer_intents(pool, wallet_name, statechain_id).await?;
    validate_bip448_transfer_intent_lineage(&intents)?;
    Ok(intents
        .into_iter()
        .find(|intent| intent.activity_status == Bip448TransferIntentActivityStatus::Active))
}

pub(in crate::sqlite_manager) fn validate_bip448_transfer_intent_lineage(
    intents: &[Bip448TransferIntent],
) -> Result<Option<usize>> {
    if intents.is_empty() {
        return Ok(None);
    }
    let wallet_name = &intents[0].wallet_name;
    let statechain_id = &intents[0].statechain_id;
    if intents
        .iter()
        .any(|intent| &intent.wallet_name != wallet_name || &intent.statechain_id != statechain_id)
    {
        return Err(anyhow!(
            "BIP448 transfer intent lineage crosses wallet or statechain identity"
        ));
    }
    let by_id = intents
        .iter()
        .enumerate()
        .map(|(index, intent)| (intent.intent_id.as_str(), index))
        .collect::<HashMap<_, _>>();
    if by_id.len() != intents.len() {
        return Err(anyhow!("duplicate BIP448 transfer intent identity"));
    }
    let active = intents
        .iter()
        .enumerate()
        .filter(|(_, intent)| intent.activity_status == Bip448TransferIntentActivityStatus::Active)
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if active.len() != 1 {
        return Err(anyhow!(
            "BIP448 transfer intent lineage must contain exactly one Active row"
        ));
    }

    let active_index = active[0];
    let mut visited = HashSet::new();
    let mut current = Some(active_index);
    while let Some(index) = current {
        let intent = &intents[index];
        if !visited.insert(intent.intent_id.as_str()) {
            return Err(anyhow!("BIP448 transfer intent predecessor cycle"));
        }
        current = match intent.predecessor_intent_id.as_deref() {
            Some(predecessor) => {
                let predecessor_index = by_id
                    .get(predecessor)
                    .copied()
                    .ok_or_else(|| anyhow!("BIP448 transfer intent predecessor is missing"))?;
                if intents[predecessor_index].activity_status
                    != Bip448TransferIntentActivityStatus::Superseded
                {
                    return Err(anyhow!(
                        "BIP448 transfer intent predecessor is not Superseded"
                    ));
                }
                Some(predecessor_index)
            }
            None => None,
        };
    }
    if visited.len() != intents.len() {
        return Err(anyhow!("orphan Superseded BIP448 transfer intent row"));
    }
    Ok(Some(active_index))
}

impl Bip448MutationGuard {
    pub async fn prepare_or_supersede_transfer_intent(
        &mut self,
        expected_active_intent_id: Option<&str>,
        intent: &Bip448TransferIntent,
    ) -> Result<Bip448TransferIntent> {
        bip448_funding::validate_transfer_intent(intent)?;
        if intent.intent_kind != Bip448TransferIntentKind::UserTransfer
            || intent.activity_status != Bip448TransferIntentActivityStatus::Active
            || intent.phase != Bip448TransferIntentPhase::Prepared
            || intent.state_signing_phase != Bip448TransferStateSigningPhase::NotStarted
            || intent.batch_id.is_some() && expected_active_intent_id.is_some()
        {
            return Err(anyhow!("invalid BIP448 user-transfer intent plan"));
        }
        match expected_active_intent_id {
            None if intent.predecessor_intent_id.is_some() => {
                return Err(anyhow!("root BIP448 transfer intent has a predecessor"));
            }
            Some(expected) => {
                bip448_funding::require_canonical_hex(expected, Some(32))?;
                if intent.predecessor_intent_id.as_deref() != Some(expected) {
                    return Err(anyhow!("BIP448 successor names the wrong predecessor"));
                }
            }
            None => {}
        }

        let intents = list_bip448_transfer_intents_on(
            self.connection(),
            &intent.wallet_name,
            &intent.statechain_id,
        )
        .await?;
        if let Some(existing) = intents.iter().find(|row| row.intent_id == intent.intent_id) {
            validate_bip448_transfer_intent_lineage(&intents)?;
            if existing.activity_status != Bip448TransferIntentActivityStatus::Active
                || !bip448_funding::transfer_intent_immutable_eq(existing, intent)
            {
                return Err(anyhow!("BIP448 transfer intent immutable replay conflict"));
            }
            return Ok(existing.clone());
        }

        if let Some(expected) = expected_active_intent_id {
            let active_index = validate_bip448_transfer_intent_lineage(&intents)?
                .ok_or_else(|| anyhow!("BIP448 transfer intent successor has no predecessor"))?;
            let active = &intents[active_index];
            if active.intent_id != expected
                || !intent_is_directly_supersedable(active)
                || active.batch_id.is_some()
            {
                return Err(anyhow!(
                    "BIP448 active predecessor is not at a supersedable boundary"
                ));
            }
            require_materialized_signed_transfer_intent_on(self.connection(), active).await?;
            validate_bip448_successor_plan_on(self.connection(), active, intent).await?;
            ensure_transfer_insert_blockers_on(self.connection(), intent).await?;
            let superseded = sqlx::query(
                "UPDATE bip448_transfer_intents SET activity_status='Superseded', \
                 updated_at=CURRENT_TIMESTAMP WHERE wallet_name=$1 AND statechain_id=$2 \
                 AND intent_id=$3 AND activity_status='Active' AND phase=$4 \
                 AND state_signing_phase=$5",
            )
            .bind(&intent.wallet_name)
            .bind(&intent.statechain_id)
            .bind(expected)
            .bind(active.phase.as_str())
            .bind(active.state_signing_phase.as_str())
            .execute(self.connection())
            .await?;
            if superseded.rows_affected() != 1 {
                return Err(anyhow!(
                    "BIP448 predecessor supersession compare-and-set lost"
                ));
            }
        } else {
            if !intents.is_empty() {
                validate_bip448_transfer_intent_lineage(&intents)?;
                return Err(anyhow!(
                    "a different Active BIP448 transfer intent already exists"
                ));
            }
            ensure_transfer_insert_blockers_on(self.connection(), intent).await?;
        }

        insert_transfer_intent_on(self.connection(), intent).await?;
        let all = list_bip448_transfer_intents_on(
            self.connection(),
            &intent.wallet_name,
            &intent.statechain_id,
        )
        .await?;
        validate_bip448_transfer_intent_lineage(&all)?;
        all.into_iter()
            .find(|row| row.intent_id == intent.intent_id)
            .ok_or_else(|| anyhow!("BIP448 transfer intent disappeared after insertion"))
    }

    pub async fn persist_cancellation_wallet_and_intent(
        &mut self,
        expected_active_intent_id: Option<&str>,
        intent: &Bip448TransferIntent,
        expected_raw_wallet_json: &str,
        replacement_wallet: &Wallet,
    ) -> Result<Bip448TransferIntent> {
        bip448_funding::validate_transfer_intent(intent)?;
        if intent.intent_kind != Bip448TransferIntentKind::Cancellation
            || intent.activity_status != Bip448TransferIntentActivityStatus::Active
            || intent.phase != Bip448TransferIntentPhase::Prepared
            || intent.state_signing_phase != Bip448TransferStateSigningPhase::NotStarted
            || intent.batch_id.is_some()
        {
            return Err(anyhow!("invalid BIP448 cancellation intent plan"));
        }
        match expected_active_intent_id {
            None if intent.predecessor_intent_id.is_some() => {
                return Err(anyhow!("root BIP448 cancellation intent has a predecessor"));
            }
            Some(expected) => {
                bip448_funding::require_canonical_hex(expected, Some(32))?;
                if intent.predecessor_intent_id.as_deref() != Some(expected) {
                    return Err(anyhow!("BIP448 cancellation names the wrong predecessor"));
                }
            }
            None => {}
        }
        let replacement = validate_bip448_cancellation_wallet_append(
            intent,
            expected_raw_wallet_json,
            replacement_wallet,
        )?;
        let intents = list_bip448_transfer_intents_on(
            self.connection(),
            &intent.wallet_name,
            &intent.statechain_id,
        )
        .await?;
        if let Some(existing) = intents.iter().find(|row| row.intent_id == intent.intent_id) {
            validate_bip448_transfer_intent_lineage(&intents)?;
            if existing.activity_status != Bip448TransferIntentActivityStatus::Active
                || !bip448_funding::transfer_intent_immutable_eq(existing, intent)
            {
                return Err(anyhow!("BIP448 cancellation immutable replay conflict"));
            }
            let raw = sqlx::query_scalar::<_, String>(
                "SELECT wallet_json FROM wallet WHERE wallet_name=$1",
            )
            .bind(&intent.wallet_name)
            .fetch_one(self.connection())
            .await?;
            let wallet: Wallet = serde_json::from_str(&raw)?;
            let matches = wallet
                .coins
                .iter()
                .filter(|coin| {
                    Some(coin.user_pubkey.as_str()) == intent.generated_coin_user_pubkey.as_deref()
                        && Some(coin.auth_pubkey.as_str())
                            == intent.generated_coin_auth_pubkey.as_deref()
                        && Some(coin.address.as_str()) == intent.generated_coin_address.as_deref()
                        && coin
                            .statechain_id
                            .as_deref()
                            .is_none_or(|id| id == intent.statechain_id)
                })
                .count();
            if matches != 1 {
                return Err(anyhow!(
                    "BIP448 cancellation replay has no unique generated Coin"
                ));
            }
            return Ok(existing.clone());
        }

        let active = if let Some(expected) = expected_active_intent_id {
            let active_index = validate_bip448_transfer_intent_lineage(&intents)?
                .ok_or_else(|| anyhow!("BIP448 cancellation successor has no predecessor"))?;
            let active = intents[active_index].clone();
            if active.intent_id != expected
                || !intent_is_directly_supersedable(&active)
                || active.batch_id.is_some()
            {
                return Err(anyhow!(
                    "BIP448 active predecessor is not at a cancellation boundary"
                ));
            }
            require_materialized_signed_transfer_intent_on(self.connection(), &active).await?;
            validate_bip448_successor_plan_on(self.connection(), &active, intent).await?;
            Some(active)
        } else {
            if !intents.is_empty() {
                validate_bip448_transfer_intent_lineage(&intents)?;
                return Err(anyhow!(
                    "BIP448 cancellation conflicts with an active intent"
                ));
            }
            None
        };
        ensure_transfer_insert_blockers_on(self.connection(), intent).await?;
        let wallet =
            sqlx::query("UPDATE wallet SET wallet_json=$1 WHERE wallet_name=$2 AND wallet_json=$3")
                .bind(replacement)
                .bind(&intent.wallet_name)
                .bind(expected_raw_wallet_json)
                .execute(self.connection())
                .await?;
        if wallet.rows_affected() != 1 {
            return Err(anyhow!("BIP448 cancellation wallet CAS lost"));
        }
        if let Some(active) = active {
            let superseded = sqlx::query(
                "UPDATE bip448_transfer_intents SET activity_status='Superseded', \
                 updated_at=CURRENT_TIMESTAMP WHERE wallet_name=$1 AND statechain_id=$2 \
                 AND intent_id=$3 AND activity_status='Active' AND phase=$4 \
                 AND state_signing_phase=$5",
            )
            .bind(&intent.wallet_name)
            .bind(&intent.statechain_id)
            .bind(&active.intent_id)
            .bind(active.phase.as_str())
            .bind(active.state_signing_phase.as_str())
            .execute(self.connection())
            .await?;
            if superseded.rows_affected() != 1 {
                return Err(anyhow!("BIP448 cancellation predecessor CAS lost"));
            }
        }
        insert_transfer_intent_on(self.connection(), intent).await?;
        let all = list_bip448_transfer_intents_on(
            self.connection(),
            &intent.wallet_name,
            &intent.statechain_id,
        )
        .await?;
        validate_bip448_transfer_intent_lineage(&all)?;
        all.into_iter()
            .find(|row| row.intent_id == intent.intent_id)
            .ok_or_else(|| anyhow!("BIP448 cancellation intent disappeared after insertion"))
    }
}

pub(super) async fn insert_transfer_intent_on(
    connection: &mut SqliteConnection,
    intent: &Bip448TransferIntent,
) -> Result<()> {
    let result = sqlx::query(
        "INSERT INTO bip448_transfer_intents (wallet_name, statechain_id, intent_id, \
            predecessor_intent_id, activity_status, intent_kind, \
            acknowledge_cooperative_duplicates, recipient_address, receiver_user_pubkey, \
            recipient_auth_pubkey, batch_id, sender_signed_statechain_id, planned_state_number, \
            expected_signature_count, previous_locktime, prior_pending_signing_id, \
            prior_transfer_recipient_auth_pubkey, prior_transfer_msg_hash, reuse_pending, \
            reuse_signed_state, clear_local_attempt, generated_coin_user_pubkey, \
            generated_coin_auth_pubkey, generated_coin_address, phase, server_x1, \
            current_pending_signing_id, state_signing_phase, server_partial_sig, update_signature) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,\
                 $21,$22,$23,$24,$25,$26,$27,$28,$29,$30)",
    )
    .bind(&intent.wallet_name)
    .bind(&intent.statechain_id)
    .bind(&intent.intent_id)
    .bind(&intent.predecessor_intent_id)
    .bind(intent.activity_status.as_str())
    .bind(intent.intent_kind.as_str())
    .bind(i64::from(intent.acknowledge_cooperative_duplicates))
    .bind(&intent.recipient_address)
    .bind(&intent.receiver_user_pubkey)
    .bind(&intent.recipient_auth_pubkey)
    .bind(&intent.batch_id)
    .bind(&intent.sender_signed_statechain_id)
    .bind(i64::from(intent.planned_state_number))
    .bind(i64::from(intent.expected_signature_count))
    .bind(i64::from(intent.previous_locktime))
    .bind(&intent.prior_pending_signing_id)
    .bind(&intent.prior_transfer_recipient_auth_pubkey)
    .bind(&intent.prior_transfer_msg_hash)
    .bind(i64::from(intent.reuse_pending))
    .bind(i64::from(intent.reuse_signed_state))
    .bind(i64::from(intent.clear_local_attempt))
    .bind(&intent.generated_coin_user_pubkey)
    .bind(&intent.generated_coin_auth_pubkey)
    .bind(&intent.generated_coin_address)
    .bind(intent.phase.as_str())
    .bind(&intent.server_x1)
    .bind(&intent.current_pending_signing_id)
    .bind(intent.state_signing_phase.as_str())
    .bind(&intent.server_partial_sig)
    .bind(&intent.update_signature)
    .execute(connection)
    .await?;
    if result.rows_affected() != 1 {
        return Err(anyhow!(
            "BIP448 transfer intent insert affected an unexpected row count"
        ));
    }
    Ok(())
}

pub(super) async fn exact_transfer_intent_on(
    connection: &mut SqliteConnection,
    wallet_name: &str,
    statechain_id: &str,
    intent_id: &str,
) -> Result<Option<Bip448TransferIntent>> {
    let query = format!(
        "SELECT {BIP448_INTENT_COLUMNS} FROM bip448_transfer_intents \
        WHERE wallet_name = $1 AND statechain_id = $2 AND intent_id = $3"
    );
    sqlx::query(&query)
        .bind(wallet_name)
        .bind(statechain_id)
        .bind(intent_id)
        .fetch_optional(connection)
        .await?
        .map(row_to_bip448_intent)
        .transpose()
}

async fn ensure_transfer_insert_blockers_on(
    connection: &mut SqliteConnection,
    intent: &Bip448TransferIntent,
) -> Result<()> {
    let attempts =
        list_bip448_withdrawal_attempts_on(connection, &intent.wallet_name, &intent.statechain_id)
            .await?;
    if let Some(attempt) = attempts.iter().find(|attempt| {
        matches!(
            attempt.phase,
            Bip448WithdrawalPhase::SecondArmed | Bip448WithdrawalPhase::Signed
        )
    }) {
        return Err(anyhow!(
            "exit-only BIP448 withdrawal attempt {} blocks transfer",
            attempt.binding_index
        ));
    }
    if let Some(attempt) = attempts.first() {
        return Err(anyhow!(
            "active BIP448 withdrawal attempt {} blocks transfer",
            attempt.binding_index
        ));
    }
    let (record, history) =
        accepted_record_and_history_on(connection, &intent.wallet_name, &intent.statechain_id)
            .await?;
    if record.latest_state_number == 0
        || usize::try_from(intent.expected_signature_count)? != history.len()
    {
        return Err(anyhow!(
            "BIP448 transfer intent count/history plan is stale"
        ));
    }
    let expected_previous_locktime = if intent.planned_state_number
        == record
            .latest_state_number
            .checked_add(2)
            .ok_or_else(|| anyhow!("BIP448 transfer plan state number overflows"))?
    {
        history
            .last()
            .ok_or_else(|| anyhow!("BIP448 transfer plan history is empty"))?
            .state_locktime
    } else {
        record.latest_state.state_locktime
    };
    if intent.previous_locktime != expected_previous_locktime {
        return Err(anyhow!(
            "BIP448 transfer intent previous-locktime plan is stale"
        ));
    }
    let pending =
        pending_transfer_on(connection, &intent.wallet_name, &intent.statechain_id).await?;
    if intent.prior_pending_signing_id.as_deref()
        != pending.as_ref().map(|row| row.signing_id.as_str())
    {
        return Err(anyhow!(
            "BIP448 transfer intent pending-signing fingerprint is stale"
        ));
    }
    let messages = sqlx::query(
        "SELECT recipient_auth_pubkey,transfer_msg_json FROM bip448_transfer_messages \
         WHERE wallet_name=$1 AND statechain_id=$2 ORDER BY recipient_auth_pubkey",
    )
    .bind(&intent.wallet_name)
    .bind(&intent.statechain_id)
    .fetch_all(&mut *connection)
    .await?;
    match (
        intent.prior_transfer_recipient_auth_pubkey.as_deref(),
        intent.prior_transfer_msg_hash.as_deref(),
    ) {
        (Some(recipient), Some(expected_hash)) if messages.len() == 1 => {
            let stored_recipient: String = messages[0].try_get(0)?;
            let stored_json: String = messages[0].try_get(1)?;
            if stored_recipient != recipient
                || sha256::Hash::hash(stored_json.as_bytes()).to_string() != expected_hash
            {
                return Err(anyhow!(
                    "BIP448 transfer intent message fingerprint is stale"
                ));
            }
        }
        (None, None) if messages.is_empty() => {}
        _ => {
            return Err(anyhow!(
                "BIP448 transfer intent outgoing-message plan is stale"
            ));
        }
    }
    let has_local_attempt = pending.is_some() || !messages.is_empty();
    if intent.reuse_pending && pending.is_none()
        || intent.clear_local_attempt != (has_local_attempt && !intent.reuse_pending)
    {
        return Err(anyhow!(
            "BIP448 transfer intent retained-state flags are incoherent"
        ));
    }
    let unresolved_duplicates =
        list_bip448_funding_bindings_on(connection, &intent.wallet_name, &intent.statechain_id)
            .await?
            .into_iter()
            .any(|binding| {
                binding.role == Bip448BindingRole::Duplicate
                    && binding.ownership_status == Bip448OwnershipStatus::Current
                    && binding.observation_status != Bip448ObservationStatus::SpentConfirmed
            });
    if unresolved_duplicates && !intent.acknowledge_cooperative_duplicates {
        return Err(anyhow!(
            "BIP448 cooperative duplicate acknowledgement is required"
        ));
    }
    Ok(())
}

pub async fn insert_bip448_transfer_intent_if_absent(
    pool: &Pool<Sqlite>,
    intent: &Bip448TransferIntent,
) -> Result<Bip448TransferIntent> {
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    let stored = guard
        .prepare_or_supersede_transfer_intent(None, intent)
        .await?;
    guard.commit().await?;
    Ok(stored)
}

fn validate_bip448_cancellation_wallet_append(
    intent: &Bip448TransferIntent,
    expected_raw_wallet_json: &str,
    replacement_wallet: &Wallet,
) -> Result<String> {
    if intent.intent_kind != Bip448TransferIntentKind::Cancellation
        || replacement_wallet.name != intent.wallet_name
    {
        return Err(anyhow!("invalid BIP448 cancellation wallet identity"));
    }
    let old_wallet: Wallet = serde_json::from_str(expected_raw_wallet_json)?;
    if old_wallet.name != intent.wallet_name
        || replacement_wallet.coins.len()
            != old_wallet
                .coins
                .len()
                .checked_add(1)
                .ok_or_else(|| anyhow!("BIP448 cancellation Coin count overflow"))?
    {
        return Err(anyhow!(
            "BIP448 cancellation wallet does not append exactly one Coin"
        ));
    }
    let generated = replacement_wallet
        .coins
        .last()
        .ok_or_else(|| anyhow!("BIP448 cancellation generated Coin is missing"))?;
    if generated.status != mercurylib::wallet::CoinStatus::INITIALISED
        || generated.statechain_id.is_some()
        || Some(generated.user_pubkey.as_str()) != intent.generated_coin_user_pubkey.as_deref()
        || Some(generated.auth_pubkey.as_str()) != intent.generated_coin_auth_pubkey.as_deref()
        || Some(generated.address.as_str()) != intent.generated_coin_address.as_deref()
    {
        return Err(anyhow!(
            "BIP448 cancellation generated Coin does not match its intent"
        ));
    }
    let generated_matches = replacement_wallet
        .coins
        .iter()
        .filter(|coin| {
            Some(coin.user_pubkey.as_str()) == intent.generated_coin_user_pubkey.as_deref()
                && Some(coin.auth_pubkey.as_str()) == intent.generated_coin_auth_pubkey.as_deref()
                && Some(coin.address.as_str()) == intent.generated_coin_address.as_deref()
        })
        .count();
    if generated_matches != 1 {
        return Err(anyhow!(
            "BIP448 cancellation generated Coin identity is not unique"
        ));
    }
    let mut without_generated = replacement_wallet.clone();
    without_generated.coins.pop();
    if serde_json::to_value(&without_generated)? != serde_json::to_value(&old_wallet)? {
        return Err(anyhow!(
            "BIP448 cancellation wallet changes more than the appended generated Coin"
        ));
    }
    canonical_wallet_json(replacement_wallet)
}

pub async fn insert_bip448_cancellation_intent_with_wallet(
    pool: &Pool<Sqlite>,
    intent: &Bip448TransferIntent,
    expected_raw_wallet_json: &str,
    replacement_wallet: &Wallet,
) -> Result<Bip448TransferIntent> {
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    let stored = guard
        .persist_cancellation_wallet_and_intent(
            None,
            intent,
            expected_raw_wallet_json,
            replacement_wallet,
        )
        .await?;
    guard.commit().await?;
    Ok(stored)
}

pub(super) fn intent_is_directly_supersedable(intent: &Bip448TransferIntent) -> bool {
    intent.phase == Bip448TransferIntentPhase::Prepared
        || (intent.phase == Bip448TransferIntentPhase::X1Stored
            && matches!(
                intent.state_signing_phase,
                Bip448TransferStateSigningPhase::NotStarted
                    | Bip448TransferStateSigningPhase::Signed
            ))
}

pub(in crate::sqlite_manager) async fn require_materialized_signed_transfer_intent_on(
    connection: &mut SqliteConnection,
    intent: &Bip448TransferIntent,
) -> Result<()> {
    if intent.state_signing_phase != Bip448TransferStateSigningPhase::Signed {
        return Ok(());
    }
    let pending = pending_transfer_on(connection, &intent.wallet_name, &intent.statechain_id)
        .await?
        .ok_or_else(|| anyhow!("BIP448 Signed transfer intent pending row is missing"))?;
    if intent.current_pending_signing_id.as_deref() != Some(pending.signing_id.as_str()) {
        return Err(anyhow!(
            "BIP448 Signed transfer intent pending identity changed"
        ));
    }
    let (record, history) =
        accepted_record_and_history_on(connection, &intent.wallet_name, &intent.statechain_id)
            .await?;
    let planned_len = usize::try_from(intent.planned_state_number)?;
    let planned_entry = history
        .get(
            planned_len
                .checked_sub(1)
                .ok_or_else(|| anyhow!("BIP448 planned state number must be positive"))?,
        )
        .ok_or_else(|| anyhow!("BIP448 Signed transfer intent history is not materialized"))?;
    if history.len() != planned_len
        || pending.funding_txid != record.funding_outpoint.txid
        || pending.funding_vout != record.funding_outpoint.vout
        || pending.funding_value_sats != record.funding_outpoint.value_sats
        || !history_entry_matches_pending_intent(planned_entry, &pending, intent)?
    {
        return Err(anyhow!(
            "BIP448 Signed transfer intent history does not match its pending row"
        ));
    }
    let message_json = sqlx::query_scalar::<_, String>(
        "SELECT transfer_msg_json FROM bip448_transfer_messages WHERE wallet_name=$1 \
         AND statechain_id=$2 AND recipient_auth_pubkey=$3",
    )
    .bind(&intent.wallet_name)
    .bind(&intent.statechain_id)
    .bind(&intent.recipient_auth_pubkey)
    .fetch_optional(&mut *connection)
    .await?
    .ok_or_else(|| anyhow!("BIP448 Signed transfer intent message is not materialized"))?;
    let message: Bip448TransferMsg = serde_json::from_str(&message_json)?;
    if serde_json::to_string(&message)? != message_json
        || message.statechain_id != intent.statechain_id
        || message.receiver_user_public_key != intent.receiver_user_pubkey
        || message.latest_state_number != intent.planned_state_number
        || !transfer_message_matches_record_and_history(&message, &record, &history)?
    {
        return Err(anyhow!(
            "BIP448 Signed transfer intent message does not match its lineage"
        ));
    }
    Ok(())
}

pub(in crate::sqlite_manager) async fn validate_bip448_successor_plan_on(
    connection: &mut SqliteConnection,
    predecessor: &Bip448TransferIntent,
    successor: &Bip448TransferIntent,
) -> Result<()> {
    if successor.predecessor_intent_id.as_deref() != Some(predecessor.intent_id.as_str()) {
        return Err(anyhow!("BIP448 successor names the wrong predecessor"));
    }
    let pending =
        pending_transfer_on(connection, &successor.wallet_name, &successor.statechain_id).await?;
    if successor.prior_pending_signing_id.as_deref()
        != pending.as_ref().map(|row| row.signing_id.as_str())
    {
        return Err(anyhow!(
            "BIP448 successor pending-signing fingerprint is stale"
        ));
    }
    let expected_message_fingerprint =
        if predecessor.state_signing_phase == Bip448TransferStateSigningPhase::Signed {
            let json = sqlx::query_scalar::<_, String>(
                "SELECT transfer_msg_json FROM bip448_transfer_messages WHERE wallet_name=$1 \
                 AND statechain_id=$2 AND recipient_auth_pubkey=$3",
            )
            .bind(&successor.wallet_name)
            .bind(&successor.statechain_id)
            .bind(&predecessor.recipient_auth_pubkey)
            .fetch_optional(&mut *connection)
            .await?
            .ok_or_else(|| anyhow!("BIP448 Signed predecessor message is missing"))?;
            Some((
                predecessor.recipient_auth_pubkey.clone(),
                sha256::Hash::hash(json.as_bytes()).to_string(),
            ))
        } else {
            match (
                predecessor.prior_transfer_recipient_auth_pubkey.clone(),
                predecessor.prior_transfer_msg_hash.clone(),
            ) {
                (Some(recipient), Some(hash)) => Some((recipient, hash)),
                (None, None) => None,
                _ => {
                    return Err(anyhow!(
                        "BIP448 predecessor message fingerprint is incoherent"
                    ));
                }
            }
        };
    if let Some((recipient, expected_hash)) = &expected_message_fingerprint {
        let json = sqlx::query_scalar::<_, String>(
            "SELECT transfer_msg_json FROM bip448_transfer_messages WHERE wallet_name=$1 \
             AND statechain_id=$2 AND recipient_auth_pubkey=$3",
        )
        .bind(&successor.wallet_name)
        .bind(&successor.statechain_id)
        .bind(recipient)
        .fetch_optional(&mut *connection)
        .await?
        .ok_or_else(|| anyhow!("BIP448 successor predecessor message is missing"))?;
        if sha256::Hash::hash(json.as_bytes()).to_string() != *expected_hash {
            return Err(anyhow!(
                "BIP448 successor predecessor message bytes changed"
            ));
        }
    }
    if successor.prior_transfer_recipient_auth_pubkey.as_deref()
        != expected_message_fingerprint
            .as_ref()
            .map(|(recipient, _)| recipient.as_str())
        || successor.prior_transfer_msg_hash.as_deref()
            != expected_message_fingerprint
                .as_ref()
                .map(|(_, hash)| hash.as_str())
    {
        return Err(anyhow!(
            "BIP448 successor transfer-message fingerprint is stale"
        ));
    }
    let has_local_attempt = pending.is_some() || expected_message_fingerprint.is_some();
    if successor.reuse_pending && pending.is_none()
        || successor.clear_local_attempt != (has_local_attempt && !successor.reuse_pending)
    {
        return Err(anyhow!(
            "BIP448 successor retained-state plan is incoherent"
        ));
    }
    Ok(())
}

pub async fn supersede_bip448_transfer_intent(
    pool: &Pool<Sqlite>,
    expected_active_intent_id: &str,
    successor: &Bip448TransferIntent,
) -> Result<Bip448TransferIntent> {
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    let stored = guard
        .prepare_or_supersede_transfer_intent(Some(expected_active_intent_id), successor)
        .await?;
    guard.commit().await?;
    Ok(stored)
}

pub async fn supersede_bip448_transfer_intent_with_cancellation_wallet(
    pool: &Pool<Sqlite>,
    expected_active_intent_id: &str,
    successor: &Bip448TransferIntent,
    expected_raw_wallet_json: &str,
    replacement_wallet: &Wallet,
) -> Result<Bip448TransferIntent> {
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    let stored = guard
        .persist_cancellation_wallet_and_intent(
            Some(expected_active_intent_id),
            successor,
            expected_raw_wallet_json,
            replacement_wallet,
        )
        .await?;
    guard.commit().await?;
    Ok(stored)
}

pub(super) async fn transition_active_intent_on(
    guard: &mut Bip448MutationGuard,
    wallet_name: &str,
    statechain_id: &str,
    intent_id: &str,
    expected_phase: Bip448TransferIntentPhase,
    next_phase: Bip448TransferIntentPhase,
    expected_signing_phase: Bip448TransferStateSigningPhase,
) -> Result<()> {
    let result = sqlx::query(
        "UPDATE bip448_transfer_intents SET phase = $1, \
        updated_at = CURRENT_TIMESTAMP WHERE wallet_name = $2 AND statechain_id = $3 \
        AND intent_id = $4 AND activity_status = 'Active' AND phase = $5 \
        AND state_signing_phase = $6",
    )
    .bind(next_phase.as_str())
    .bind(wallet_name)
    .bind(statechain_id)
    .bind(intent_id)
    .bind(expected_phase.as_str())
    .bind(expected_signing_phase.as_str())
    .execute(guard.connection())
    .await?;
    if result.rows_affected() != 1 {
        return Err(anyhow!(
            "stale BIP448 transfer intent worker lost its activity CAS"
        ));
    }
    Ok(())
}

pub async fn arm_bip448_transfer_sender(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    intent_id: &str,
) -> Result<Bip448TransferIntent> {
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    transition_active_intent_on(
        &mut guard,
        wallet_name,
        statechain_id,
        intent_id,
        Bip448TransferIntentPhase::Prepared,
        Bip448TransferIntentPhase::SenderArmed,
        Bip448TransferStateSigningPhase::NotStarted,
    )
    .await?;
    let row = exact_transfer_intent_on(guard.connection(), wallet_name, statechain_id, intent_id)
        .await?
        .ok_or_else(|| anyhow!("BIP448 transfer intent disappeared after sender arm"))?;
    guard.commit().await?;
    Ok(row)
}

pub async fn transition_bip448_transfer_intent_phase(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    intent_id: &str,
    expected_phase: Bip448TransferIntentPhase,
    next_phase: Bip448TransferIntentPhase,
) -> Result<Bip448TransferIntent> {
    if (expected_phase, next_phase)
        != (
            Bip448TransferIntentPhase::Prepared,
            Bip448TransferIntentPhase::SenderArmed,
        )
    {
        return Err(anyhow!(
            "BIP448 transfer phase requires its artifact-specific transition helper"
        ));
    }
    arm_bip448_transfer_sender(pool, wallet_name, statechain_id, intent_id).await
}

pub async fn store_bip448_transfer_server_x1(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    intent_id: &str,
    server_x1: &str,
) -> Result<Bip448TransferIntent> {
    bip448_funding::require_canonical_hex(server_x1, Some(32))?;
    secp256k1::SecretKey::from_str(server_x1).context("invalid BIP448 transfer x1 scalar")?;
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    let result = sqlx::query(
        "UPDATE bip448_transfer_intents SET server_x1 = $1, phase = 'X1Stored', \
        updated_at = CURRENT_TIMESTAMP WHERE wallet_name = $2 AND statechain_id = $3 \
        AND intent_id = $4 AND activity_status = 'Active' AND phase = 'SenderArmed' \
        AND state_signing_phase = 'NotStarted' AND server_x1 IS NULL",
    )
    .bind(server_x1)
    .bind(wallet_name)
    .bind(statechain_id)
    .bind(intent_id)
    .execute(guard.connection())
    .await?;
    if result.rows_affected() != 1 {
        return Err(anyhow!("BIP448 transfer x1 compare-and-set lost"));
    }
    let row = exact_transfer_intent_on(guard.connection(), wallet_name, statechain_id, intent_id)
        .await?
        .ok_or_else(|| anyhow!("BIP448 intent disappeared after x1 storage"))?;
    guard.commit().await?;
    Ok(row)
}

pub async fn store_bip448_transfer_intent_x1(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    intent_id: &str,
    server_x1: &str,
) -> Result<Bip448TransferIntent> {
    store_bip448_transfer_server_x1(pool, wallet_name, statechain_id, intent_id, server_x1).await
}

pub async fn reject_bip448_transfer_intent_and_reactivate_predecessor(
    pool: &Pool<Sqlite>,
    expected: &Bip448TransferIntent,
) -> Result<Option<Bip448TransferIntent>> {
    bip448_funding::validate_transfer_intent(expected)?;
    if expected.activity_status != Bip448TransferIntentActivityStatus::Active
        || !matches!(
            expected.phase,
            Bip448TransferIntentPhase::Prepared | Bip448TransferIntentPhase::SenderArmed
        )
    {
        return Err(anyhow!(
            "BIP448 transfer rejection is not at a definitive pre-insert boundary"
        ));
    }
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    let intents = list_bip448_transfer_intents_on(
        guard.connection(),
        &expected.wallet_name,
        &expected.statechain_id,
    )
    .await?;
    let active_index = validate_bip448_transfer_intent_lineage(&intents)?
        .ok_or_else(|| anyhow!("BIP448 rejected intent lineage is missing"))?;
    if intents[active_index] != *expected {
        return Err(anyhow!(
            "stale BIP448 worker cannot reject a changed intent"
        ));
    }
    if expected.intent_kind == Bip448TransferIntentKind::Cancellation {
        let raw =
            sqlx::query_scalar::<_, String>("SELECT wallet_json FROM wallet WHERE wallet_name=$1")
                .bind(&expected.wallet_name)
                .fetch_one(guard.connection())
                .await?;
        let mut wallet: Wallet = serde_json::from_str(&raw)?;
        let matches = wallet
            .coins
            .iter()
            .enumerate()
            .filter(|(_, coin)| {
                coin.status == mercurylib::wallet::CoinStatus::INITIALISED
                    && Some(coin.user_pubkey.as_str())
                        == expected.generated_coin_user_pubkey.as_deref()
                    && Some(coin.auth_pubkey.as_str())
                        == expected.generated_coin_auth_pubkey.as_deref()
                    && Some(coin.address.as_str()) == expected.generated_coin_address.as_deref()
                    && coin.statechain_id.is_none()
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(anyhow!(
                "BIP448 cancellation generated Coin identity is not unique"
            ));
        }
        wallet.coins.remove(matches[0]);
        let replacement = canonical_wallet_json(&wallet)?;
        let updated =
            sqlx::query("UPDATE wallet SET wallet_json=$1 WHERE wallet_name=$2 AND wallet_json=$3")
                .bind(replacement)
                .bind(&expected.wallet_name)
                .bind(&raw)
                .execute(guard.connection())
                .await?;
        if updated.rows_affected() != 1 {
            return Err(anyhow!("BIP448 cancellation Coin compare-delete lost"));
        }
    }
    let deleted = sqlx::query(
        "DELETE FROM bip448_transfer_intents WHERE wallet_name=$1 \
        AND statechain_id=$2 AND intent_id=$3 AND activity_status='Active' AND phase=$4 \
        AND state_signing_phase=$5",
    )
    .bind(&expected.wallet_name)
    .bind(&expected.statechain_id)
    .bind(&expected.intent_id)
    .bind(expected.phase.as_str())
    .bind(expected.state_signing_phase.as_str())
    .execute(guard.connection())
    .await?;
    if deleted.rows_affected() != 1 {
        return Err(anyhow!("BIP448 rejected intent compare-delete lost"));
    }
    let predecessor = if let Some(predecessor_id) = &expected.predecessor_intent_id {
        let reactivated = sqlx::query("UPDATE bip448_transfer_intents SET activity_status='Active',\
            updated_at=CURRENT_TIMESTAMP WHERE wallet_name=$1 AND statechain_id=$2 AND intent_id=$3 \
            AND activity_status='Superseded'")
            .bind(&expected.wallet_name).bind(&expected.statechain_id).bind(predecessor_id)
            .execute(guard.connection()).await?;
        if reactivated.rows_affected() != 1 {
            return Err(anyhow!("BIP448 predecessor reactivation CAS lost"));
        }
        exact_transfer_intent_on(
            guard.connection(),
            &expected.wallet_name,
            &expected.statechain_id,
            predecessor_id,
        )
        .await?
    } else {
        None
    };
    let remaining = list_bip448_transfer_intents_on(
        guard.connection(),
        &expected.wallet_name,
        &expected.statechain_id,
    )
    .await?;
    if !remaining.is_empty() {
        validate_bip448_transfer_intent_lineage(&remaining)?;
    }
    guard.commit().await?;
    Ok(predecessor)
}

pub async fn reactivate_bip448_transfer_intent_predecessor_after_definitive_rejection(
    pool: &Pool<Sqlite>,
    expected: &Bip448TransferIntent,
) -> Result<Option<Bip448TransferIntent>> {
    reject_bip448_transfer_intent_and_reactivate_predecessor(pool, expected).await
}
