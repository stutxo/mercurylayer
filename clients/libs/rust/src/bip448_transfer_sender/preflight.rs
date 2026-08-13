use super::{
    signing::{
        transfer_artifacts, validate_pending, INCOMPLETE_HISTORY_ERROR, SIGNATURE_COUNT_ERROR,
    },
    Bip448TransferOptions,
};
use crate::{
    bip448_funding::{
        Bip448BindingRole, Bip448FundingBinding, Bip448ObservationStatus, Bip448OwnershipStatus,
        Bip448TransferIntent, Bip448TransferIntentActivityStatus, Bip448TransferIntentPhase,
        Bip448TransferStateSigningPhase, Bip448WithdrawalAttempt, Bip448WithdrawalPhase,
    },
    bip448_owner::get_current_bip448_owner,
    client_config::ClientConfig,
    coin_status::sync_bip448_funding_bindings,
    deposit::bip448_signature_count,
    sqlite_manager::{
        get_active_bip448_transfer_intent, get_bip448_pending_transfer_signing,
        get_bip448_raw_wallet_json, get_bip448_state_history, get_bip448_statechain,
        get_bip448_transfer_msg_raw_optional, Bip448PendingDepositSigning,
    },
};
use anyhow::{anyhow, Result};
use bitcoin::hashes::{sha256, Hash};
use mercurylib::{
    bip448_statechain::storage::{Bip448LatestState, Bip448StatechainRecord},
    transfer::bip448::Bip448StateHistoryEntry,
    wallet::{CoinStatus, Wallet},
};
use secp256k1::{rand, PublicKey, SecretKey};
use std::str::FromStr;

pub(super) const ELIGIBILITY_ERROR: &str =
    "only transfer of a CONFIRMED BIP448 coin at its accepted latest state is supported";
pub(super) const BATCHED_PENDING_ERROR: &str =
    "BIP448 batched pending transfers cannot be cancelled or retargeted";

pub(super) struct FreshTransferPreflight {
    pub(super) raw_wallet_json: String,
    pub(super) wallet: Wallet,
    pub(super) record: Bip448StatechainRecord,
    pub(super) current_owner_coin_index: usize,
    pub(super) unresolved_duplicates: Vec<Bip448FundingBinding>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TransferStatePlan {
    state_number: u32,
    reuse_pending: bool,
    reuse_signed_state: bool,
    clear_local_attempt: bool,
}

pub(super) async fn require_local_accepted_history_prefix(
    client_config: &ClientConfig,
    record: &Bip448StatechainRecord,
) -> Result<()> {
    let history = get_bip448_state_history(
        &client_config.pool,
        &record.wallet_name,
        &record.statechain_id,
    )
    .await?;
    let accepted_len = usize::try_from(record.latest_state_number)
        .map_err(|_| anyhow!(INCOMPLETE_HISTORY_ERROR))?;
    let maximum_len = accepted_len
        .checked_add(2)
        .ok_or_else(|| anyhow!(INCOMPLETE_HISTORY_ERROR))?;
    if history.len() < accepted_len
        || history.len() > maximum_len
        || history.iter().enumerate().any(|(index, entry)| {
            u32::try_from(index)
                .ok()
                .and_then(|index| index.checked_add(1))
                != Some(entry.state_number)
        })
        || accepted_len == 0
        || !history_entry_matches_latest_state(&history[accepted_len - 1], &record.latest_state)
    {
        return Err(anyhow!(INCOMPLETE_HISTORY_ERROR));
    }
    Ok(())
}

pub(super) async fn fresh_transfer_preflight(
    client_config: &ClientConfig,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<FreshTransferPreflight> {
    let report = sync_bip448_funding_bindings(client_config, wallet_name).await?;
    let raw_wallet_json = get_bip448_raw_wallet_json(&client_config.pool, wallet_name).await?;
    let wallet: Wallet = serde_json::from_str(&raw_wallet_json)?;
    let record = get_bip448_statechain(&client_config.pool, wallet_name, statechain_id).await?;
    require_local_accepted_history_prefix(client_config, &record).await?;
    ensure_any_locally_eligible_coin(&wallet, statechain_id, record.latest_state_number)?;
    let owner =
        get_current_bip448_owner(client_config, &wallet, wallet_name, statechain_id).await?;
    let coin = wallet
        .coins
        .get(owner.coin_index)
        .ok_or_else(|| anyhow!("proven current BIP448 owner Coin is missing"))?;
    ensure_local_eligibility(record.latest_state_number, &coin.status)?;
    let has_active_transfer_intent =
        get_active_bip448_transfer_intent(&client_config.pool, wallet_name, statechain_id)
            .await?
            .is_some();
    let statechain_attempts = report
        .attempts
        .iter()
        .filter(|attempt| attempt.statechain_id == statechain_id)
        .cloned()
        .collect::<Vec<_>>();
    let diagnose_canonical_signed_count_first = statechain_attempts.len() == 1
        && statechain_attempts[0].binding_index == 0
        && statechain_attempts[0].phase == Bip448WithdrawalPhase::Signed;
    if !has_active_transfer_intent && diagnose_canonical_signed_count_first {
        let pending =
            get_bip448_pending_transfer_signing(&client_config.pool, wallet_name, statechain_id)
                .await?;
        let prior_message = get_bip448_transfer_msg_raw_optional(
            &client_config.pool,
            wallet_name,
            statechain_id,
            None,
        )
        .await?;
        transfer_state_plan(
            u64::from(owner.statechain_info.num_sigs),
            record.latest_state_number,
            false,
            pending.is_some() || prior_message.is_some(),
            None,
        )?;
    }
    require_no_transfer_attempts(&statechain_attempts)?;
    let unresolved_duplicates = report
        .bindings
        .into_iter()
        .filter(|binding| {
            binding.statechain_id == statechain_id
                && binding.role == Bip448BindingRole::Duplicate
                && binding.ownership_status == Bip448OwnershipStatus::Current
                && binding.observation_status != Bip448ObservationStatus::SpentConfirmed
        })
        .collect();
    Ok(FreshTransferPreflight {
        raw_wallet_json,
        wallet,
        record,
        current_owner_coin_index: owner.coin_index,
        unresolved_duplicates,
    })
}

fn require_no_transfer_attempts(attempts: &[Bip448WithdrawalAttempt]) -> Result<()> {
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
    Ok(())
}

pub(super) fn require_duplicate_acknowledgement(
    unresolved_duplicates: &[Bip448FundingBinding],
    options: Bip448TransferOptions,
) -> Result<()> {
    if !unresolved_duplicates.is_empty() && !options.acknowledge_cooperative_duplicates {
        let details = unresolved_duplicates
            .iter()
            .map(|binding| {
                format!(
                    "{}={}:{}:{}sat",
                    binding.binding_index, binding.txid, binding.vout, binding.value_sats
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        return Err(anyhow!(
            "BIP448 cooperative duplicate acknowledgement is required ({details}). Duplicate values are not part of the verified canonical statechain amount, have no arbitrary-value unilateral backup under this solution, and remain server-dependent until the receiver chooses to sweep them. For an explicit user transfer, retry with --force-send-with-duplicates"
        ));
    }
    Ok(())
}

pub(super) async fn build_bip448_user_transfer_intent(
    client_config: &ClientConfig,
    wallet: &Wallet,
    record: &Bip448StatechainRecord,
    current_owner_coin_index: usize,
    recipient_address: &str,
    receiver_user_pubkey: &PublicKey,
    recipient_auth_pubkey: &PublicKey,
    batch_id: Option<String>,
    options: Bip448TransferOptions,
    predecessor: Option<&Bip448TransferIntent>,
) -> Result<Bip448TransferIntent> {
    if predecessor.is_some_and(|intent| intent.batch_id.is_some()) {
        return Err(anyhow!(BATCHED_PENDING_ERROR));
    }
    let coin = wallet
        .coins
        .get(current_owner_coin_index)
        .ok_or_else(|| anyhow!("selected BIP448 transfer owner Coin is missing"))?;
    ensure_local_eligibility(record.latest_state_number, &coin.status)?;
    let server = PublicKey::from_str(
        coin.server_pubkey
            .as_deref()
            .ok_or_else(|| anyhow!("BIP448 transfer coin missing server_pubkey"))?,
    )?;
    if PublicKey::from_str(&coin.user_pubkey)?.combine(&server)?
        != PublicKey::from_str(&record.aggregate_pubkey)?
    {
        return Err(anyhow!(
            "BIP448 transfer coin keys do not match the accepted aggregate public key"
        ));
    }
    let pending = get_bip448_pending_transfer_signing(
        &client_config.pool,
        &wallet.name,
        &record.statechain_id,
    )
    .await?;
    let prior_message = get_bip448_transfer_msg_raw_optional(
        &client_config.pool,
        &wallet.name,
        &record.statechain_id,
        None,
    )
    .await?;
    let current_count = bip448_signature_count(client_config, &record.statechain_id).await?;
    let pending_matches_recipient = prior_message.is_none()
        && pending.as_ref().is_some_and(|pending| {
            pending_matches_next_state(record, receiver_user_pubkey, pending)
        });
    let plan = transfer_state_plan(
        current_count,
        record.latest_state_number,
        pending_matches_recipient,
        pending.is_some() || prior_message.is_some(),
        predecessor.and_then(|intent| intent.batch_id.as_deref()),
    )?;
    let expected_signature_count =
        u32::try_from(current_count).map_err(|_| anyhow!(SIGNATURE_COUNT_ERROR))?;
    let state_history = outgoing_state_history(
        &client_config.pool,
        &wallet.name,
        &record.statechain_id,
        expected_signature_count,
    )
    .await?;
    let previous_locktime = if plan.state_number
        == record
            .latest_state_number
            .checked_add(2)
            .ok_or_else(|| anyhow!(SIGNATURE_COUNT_ERROR))?
    {
        state_history
            .last()
            .ok_or_else(|| anyhow!(INCOMPLETE_HISTORY_ERROR))?
            .state_locktime
    } else {
        record.latest_state.state_locktime
    };
    let (prior_transfer_recipient_auth_pubkey, prior_transfer_msg_hash) = match prior_message {
        Some((recipient, raw)) => (
            Some(recipient),
            Some(sha256::Hash::hash(raw.as_bytes()).to_string()),
        ),
        None => (None, None),
    };
    Ok(Bip448TransferIntent {
        wallet_name: wallet.name.clone(),
        statechain_id: record.statechain_id.clone(),
        intent_id: hex::encode(SecretKey::new(&mut rand::rng()).to_secret_bytes()),
        predecessor_intent_id: predecessor.map(|intent| intent.intent_id.clone()),
        activity_status: Bip448TransferIntentActivityStatus::Active,
        intent_kind: options.intent,
        acknowledge_cooperative_duplicates: options.acknowledge_cooperative_duplicates,
        recipient_address: recipient_address.to_owned(),
        receiver_user_pubkey: receiver_user_pubkey.to_string(),
        recipient_auth_pubkey: recipient_auth_pubkey.to_string(),
        batch_id,
        sender_signed_statechain_id: coin
            .signed_statechain_id
            .clone()
            .ok_or_else(|| anyhow!("BIP448 transfer coin missing signed_statechain_id"))?,
        planned_state_number: plan.state_number,
        expected_signature_count,
        previous_locktime,
        prior_pending_signing_id: pending.map(|pending| pending.signing_id),
        prior_transfer_recipient_auth_pubkey,
        prior_transfer_msg_hash,
        reuse_pending: plan.reuse_pending,
        reuse_signed_state: plan.reuse_signed_state,
        clear_local_attempt: plan.clear_local_attempt,
        generated_coin_user_pubkey: None,
        generated_coin_auth_pubkey: None,
        generated_coin_address: None,
        phase: Bip448TransferIntentPhase::Prepared,
        server_x1: None,
        current_pending_signing_id: None,
        state_signing_phase: Bip448TransferStateSigningPhase::NotStarted,
        server_partial_sig: None,
        update_signature: None,
        created_at: String::new(),
        updated_at: String::new(),
    })
}

pub(super) fn history_entry_matches_latest_state(
    entry: &Bip448StateHistoryEntry,
    latest_state: &Bip448LatestState,
) -> bool {
    entry.state_number == latest_state.state_number
        && entry.state_locktime == latest_state.state_locktime
        && entry.update_template_hash == latest_state.update_template_hash
        && entry.settlement_template_hash == latest_state.settlement_template_hash
        && entry.update_signature == latest_state.signing_metadata.update_signature
        && entry.client_public_nonce == latest_state.signing_metadata.client_public_nonce
        && entry.server_public_nonce == latest_state.signing_metadata.server_public_nonce
        && entry.blinding_factor == latest_state.signing_metadata.blinding_factor
}

pub(super) fn ensure_local_eligibility(
    latest_state_number: u32,
    status: &CoinStatus,
) -> Result<()> {
    if latest_state_number < 1 || !matches!(status, CoinStatus::CONFIRMED | CoinStatus::IN_TRANSFER)
    {
        return Err(eligibility_error());
    }
    Ok(())
}

pub(super) fn ensure_any_locally_eligible_coin(
    wallet: &Wallet,
    statechain_id: &str,
    latest_state_number: u32,
) -> Result<()> {
    if latest_state_number < 1
        || !wallet.coins.iter().any(|coin| {
            coin.statechain_id.as_deref() == Some(statechain_id)
                && mercurylib::bip448_statechain::deposit::is_bip448_coin(coin)
                && matches!(coin.status, CoinStatus::CONFIRMED | CoinStatus::IN_TRANSFER)
        })
    {
        return Err(eligibility_error());
    }
    Ok(())
}
fn transfer_state_plan(
    count: u64,
    latest: u32,
    pending_matches_recipient: bool,
    has_local_attempt: bool,
    pending_batch_id: Option<&str>,
) -> Result<TransferStatePlan> {
    if pending_batch_id.is_some() {
        return Err(anyhow!(BATCHED_PENDING_ERROR));
    }
    let next = latest
        .checked_add(1)
        .ok_or_else(|| anyhow!(SIGNATURE_COUNT_ERROR))?;
    if count == u64::from(latest) {
        return Ok(TransferStatePlan {
            state_number: next,
            reuse_pending: pending_matches_recipient,
            reuse_signed_state: false,
            clear_local_attempt: has_local_attempt && !pending_matches_recipient,
        });
    }
    if count == u64::from(next) {
        if !has_local_attempt {
            return Err(anyhow!(SIGNATURE_COUNT_ERROR));
        }
        return if pending_matches_recipient {
            Ok(TransferStatePlan {
                state_number: next,
                reuse_pending: true,
                reuse_signed_state: true,
                clear_local_attempt: false,
            })
        } else {
            Ok(TransferStatePlan {
                state_number: next
                    .checked_add(1)
                    .ok_or_else(|| anyhow!(SIGNATURE_COUNT_ERROR))?,
                reuse_pending: false,
                reuse_signed_state: false,
                clear_local_attempt: has_local_attempt,
            })
        };
    }
    Err(anyhow!(SIGNATURE_COUNT_ERROR))
}
pub(super) fn eligibility_error() -> anyhow::Error {
    anyhow!(ELIGIBILITY_ERROR)
}
fn pending_matches_next_state(
    record: &Bip448StatechainRecord,
    receiver_user_pubkey: &PublicKey,
    pending: &Bip448PendingDepositSigning,
) -> bool {
    transfer_artifacts(
        record,
        receiver_user_pubkey,
        record.latest_state_number + 1,
        pending.state_locktime,
    )
    .and_then(|artifacts| validate_pending(pending, record, &artifacts))
    .is_ok()
}
async fn outgoing_state_history(
    pool: &sqlx::Pool<sqlx::Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    history_tip: u32,
) -> Result<Vec<Bip448StateHistoryEntry>> {
    let history = get_bip448_state_history(pool, wallet_name, statechain_id)
        .await?
        .into_iter()
        .filter(|entry| (1..=history_tip).contains(&entry.state_number))
        .collect::<Vec<_>>();
    if history.len() != history_tip as usize
        || history
            .iter()
            .enumerate()
            .any(|(index, entry)| entry.state_number != index as u32 + 1)
    {
        return Err(anyhow!(INCOMPLETE_HISTORY_ERROR));
    }
    Ok(history)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    #[test]
    fn unknown_signature_count_fails_closed_before_mutation() {
        let mutated = Cell::new(false);
        let error = transfer_state_plan(5, 3, false, false, None)
            .map(|plan| {
                mutated.set(plan.clear_local_attempt);
                plan
            })
            .unwrap_err();
        assert_eq!(error.to_string(), SIGNATURE_COUNT_ERROR);
        assert!(!mutated.get());
        assert_eq!(
            transfer_state_plan(4, 3, false, false, None)
                .unwrap_err()
                .to_string(),
            SIGNATURE_COUNT_ERROR
        );
        assert_eq!(
            transfer_state_plan(3, 3, true, true, None).unwrap(),
            TransferStatePlan {
                state_number: 4,
                reuse_pending: true,
                reuse_signed_state: false,
                clear_local_attempt: false
            }
        );
        assert_eq!(
            transfer_state_plan(4, 3, false, true, None)
                .unwrap()
                .state_number,
            5
        );
        assert!(ensure_local_eligibility(2, &CoinStatus::CONFIRMED).is_ok());
        assert!(ensure_local_eligibility(2, &CoinStatus::IN_TRANSFER).is_ok());
    }

    #[test]
    fn selected_owner_status_gate_accepts_confirmed_and_in_transfer() {
        assert!(ensure_local_eligibility(2, &CoinStatus::CONFIRMED).is_ok());
        assert!(ensure_local_eligibility(2, &CoinStatus::IN_TRANSFER).is_ok());
        assert!(ensure_local_eligibility(2, &CoinStatus::INITIALISED).is_err());
    }

    #[test]
    fn batched_pending_attempt_stops_retargeting() {
        assert_eq!(
            transfer_state_plan(3, 3, false, true, Some("batch"))
                .unwrap_err()
                .to_string(),
            BATCHED_PENDING_ERROR
        );
    }
}
