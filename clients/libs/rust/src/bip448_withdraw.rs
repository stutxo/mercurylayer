use std::{str::FromStr, time::Duration};

use anyhow::{anyhow, Result};
use bitcoin::{OutPoint, ScriptBuf, Transaction, Txid};
use mercurylib::{
    bip448_statechain::{
        deposit::is_bip448_coin,
        script::{funding_spend_info, output_script_pubkey},
        signing_api::{Bip448PartialSignatureRequestPayload, Bip448SignFirstRequestPayload},
        storage::Bip448StatechainRecord,
        withdraw::{
            aggregate_bip448_keypath_signature, build_bip448_keypath_spend_signing_data,
            create_bip448_keypath_nonces, finalize_bip448_keypath_transaction,
            prepare_bip448_keypath_spend, sample_bip448_keypath_spend_lock_time,
            Bip448KeypathSpendSource, Bip448PreparedKeypathSpend,
        },
    },
    wallet::{Coin, CoinStatus, Wallet},
};
use secp256k1::{rand, PublicKey, Secp256k1, SecretKey};
use serde::Serialize;

use crate::{
    bip448_funding::{
        self, Bip448BindingRole, Bip448BroadcastStatus, Bip448CloseGate, Bip448ClosingResolution,
        Bip448CompletionStatus, Bip448FundingBinding, Bip448ObservationStatus,
        Bip448OwnershipStatus, Bip448WithdrawalAttempt, Bip448WithdrawalAttemptKind,
        Bip448WithdrawalPhase,
    },
    bip448_owner::{
        get_bip448_statechain_presence, get_current_bip448_owner, Bip448StatechainPresence,
    },
    chain::{broadcast_or_reconcile_transaction, BroadcastTxStatus},
    client_config::ClientConfig,
    coin_status::{sync_bip448_funding_bindings, sync_bip448_funding_bindings_from_height_zero},
    deposit::{bip448_sign_first, bip448_sign_second, bip448_signature_count},
    sqlite_manager::{
        arm_bip448_withdrawal_sign_first, arm_bip448_withdrawal_sign_second,
        begin_bip448_mutation_guard, bip448_expected_signature_count, classify_bip448_close_gate,
        delete_prepared_bip448_withdrawal_attempt_for_confirmed_spend,
        get_active_bip448_transfer_intent, get_bip448_funding_binding,
        get_bip448_pending_transfer_signing, get_bip448_state_history, get_bip448_statechain,
        get_bip448_withdrawal_attempt, get_wallet, has_bip448_transfer_msg_for_statechain,
        list_bip448_transfer_intents, list_bip448_transfer_msg_raw_rows,
        persist_bip448_canonical_withdrawal_wallet,
        reconcile_bip448_accepted_local_outgoing_messages, store_bip448_withdrawal_nonce_artifacts,
        store_bip448_withdrawal_signed_artifacts, transition_bip448_withdrawal_broadcast_status,
        transition_bip448_withdrawal_completion_status, validate_bip448_canonical_close_snapshot,
        with_bip448_canonical_completion_fence,
    },
    utils::estimate_fee_rate_sats_per_byte,
};

const UNEXPECTED_COMPLETION_RESPONSE: &str =
    "BIP448 withdraw completion returned an unexpected response";
const BIP448_CANONICAL_COMPLETION_TIMEOUT: Duration = Duration::from_secs(20);

#[cfg(feature = "test-hooks")]
fn bip448_process_checkpoint(checkpoint: &str) {
    if std::env::var("ML_BIP448_RESTART_CHILD").as_deref() == Ok("1")
        && std::env::var("ML_BIP448_TEST_CHECKPOINT").as_deref() == Ok(checkpoint)
    {
        std::process::exit(86);
    }
}

#[cfg(not(feature = "test-hooks"))]
fn bip448_process_checkpoint(_checkpoint: &str) {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Bip448DuplicateSweepResult {
    pub statechain_id: String,
    pub duplicate_index: u32,
    pub source_outpoint: String,
    pub amount_sats: u64,
    pub sweep_txid: String,
    pub broadcast_status: String,
    pub exit_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AttemptSourceState {
    ExactConfirmed,
    Wait(String),
    ConfirmedConflict(String),
}

fn binding_outpoint(binding: &Bip448FundingBinding) -> String {
    format!("{}:{}", binding.txid, binding.vout)
}

fn accepted_funding_script(record: &Bip448StatechainRecord) -> Result<ScriptBuf> {
    let aggregate = PublicKey::from_str(&record.aggregate_pubkey)?;
    let spend_info = funding_spend_info(&Secp256k1::new(), aggregate.x_only_public_key().0)?;
    Ok(output_script_pubkey(&spend_info))
}

fn require_attempt_binding(
    binding: &Bip448FundingBinding,
    binding_index: u32,
    attempt_kind: Bip448WithdrawalAttemptKind,
    owner_user_pubkey: Option<&str>,
    owner_state_number: Option<u32>,
) -> Result<()> {
    let outpoint = binding_outpoint(binding);
    let kind_matches = matches!(
        (binding.binding_index, binding.role, attempt_kind),
        (
            0,
            Bip448BindingRole::Canonical,
            Bip448WithdrawalAttemptKind::Canonical
        ) | (
            1..,
            Bip448BindingRole::Duplicate,
            Bip448WithdrawalAttemptKind::Duplicate
        )
    );
    if binding.binding_index != binding_index
        || !kind_matches
        || binding.ownership_status != Bip448OwnershipStatus::Current
        || owner_user_pubkey.is_some_and(|owner| owner != binding.owner_user_pubkey)
        || owner_state_number.is_some_and(|state| state != binding.owner_state_number)
    {
        return Err(anyhow!(
            "BIP448 {attempt_kind} binding index {binding_index} does not select the exact current-owner source ({outpoint})"
        ));
    }
    Ok(())
}

fn require_exact_confirmed_source(
    client_config: &ClientConfig,
    binding: &Bip448FundingBinding,
) -> Result<()> {
    let outpoint = binding_outpoint(binding);
    if binding.observation_status != Bip448ObservationStatus::Confirmed {
        return Err(anyhow!(
            "BIP448 source {outpoint} is {}, not Confirmed",
            binding.observation_status
        ));
    }
    let txid = Txid::from_str(&binding.txid)?;
    let Some(tx_out) = client_config
        .chain_client
        .get_tx_out(&txid, binding.vout, true)?
    else {
        return Err(anyhow!("BIP448 source {outpoint} is not currently unspent"));
    };
    if tx_out.value != binding.value_sats
        || hex::encode(tx_out.script_pubkey.as_bytes()) != binding.script_pubkey
        || tx_out.confirmations < client_config.confirmation_target
    {
        return Err(anyhow!(
            "BIP448 source {outpoint} does not match its target-confirmed chain fact"
        ));
    }
    Ok(())
}

fn attempt_coin(
    wallet: &Wallet,
    record: &Bip448StatechainRecord,
    attempt: &Bip448WithdrawalAttempt,
) -> Result<Coin> {
    let mut matches = wallet.coins.iter().filter_map(|coin| {
        if coin.statechain_id.as_deref() != Some(attempt.statechain_id.as_str())
            || !is_bip448_coin(coin)
        {
            return None;
        }
        let owner = PublicKey::from_str(&coin.user_pubkey)
            .ok()?
            .x_only_public_key()
            .0
            .to_string();
        (owner == attempt.owner_user_pubkey).then(|| coin.clone())
    });
    let coin = matches.next().ok_or_else(|| {
        anyhow!(
            "BIP448 attempt owner Coin is missing for {}:{}",
            attempt.source_txid,
            attempt.source_vout
        )
    })?;
    if matches.next().is_some()
        || coin.aggregated_pubkey.as_deref() != Some(record.aggregate_pubkey.as_str())
        || coin.signed_statechain_id.as_deref() != Some(attempt.signed_statechain_id.as_str())
    {
        return Err(anyhow!(
            "BIP448 attempt owner Coin identity changed for {}:{}",
            attempt.source_txid,
            attempt.source_vout
        ));
    }
    Ok(coin)
}

async fn validate_attempt_identity(
    client_config: &ClientConfig,
    wallet: &Wallet,
    record: &Bip448StatechainRecord,
    binding: &Bip448FundingBinding,
    attempt: &Bip448WithdrawalAttempt,
) -> Result<Coin> {
    let history = get_bip448_state_history(
        &client_config.pool,
        &attempt.wallet_name,
        &attempt.statechain_id,
    )
    .await?;
    let owner = history
        .get(
            usize::try_from(record.latest_state_number)?
                .checked_sub(1)
                .ok_or_else(|| anyhow!("BIP448 accepted state number must be positive"))?,
        )
        .ok_or_else(|| anyhow!("BIP448 accepted owner history is missing"))?;
    let accepted_script = accepted_funding_script(record)?;
    let kind_matches = matches!(
        (attempt.attempt_kind, binding.role, binding.binding_index),
        (
            Bip448WithdrawalAttemptKind::Canonical,
            Bip448BindingRole::Canonical,
            0
        ) | (
            Bip448WithdrawalAttemptKind::Duplicate,
            Bip448BindingRole::Duplicate,
            1..
        )
    );
    let canonical_source_matches = attempt.attempt_kind != Bip448WithdrawalAttemptKind::Canonical
        || (attempt.source_txid == record.funding_outpoint.txid
            && attempt.source_vout == record.funding_outpoint.vout
            && attempt.source_value_sats == record.funding_outpoint.value_sats);
    if attempt.wallet_name != wallet.name
        || attempt.statechain_id != record.statechain_id
        || attempt.binding_index != binding.binding_index
        || !kind_matches
        || !canonical_source_matches
        || attempt.owner_state_number != record.latest_state_number
        || attempt.owner_user_pubkey != owner.owner_public_key
        || attempt.owner_user_pubkey != binding.owner_user_pubkey
        || attempt.owner_state_number != binding.owner_state_number
        || attempt.source_txid != binding.txid
        || attempt.source_vout != binding.vout
        || attempt.source_value_sats != binding.value_sats
        || attempt.source_script_pubkey != binding.script_pubkey
        || attempt.source_script_pubkey != hex::encode(accepted_script.as_bytes())
        || binding.ownership_status != Bip448OwnershipStatus::Current
    {
        return Err(anyhow!(
            "BIP448 withdrawal attempt identity changed for {}:{}",
            attempt.source_txid,
            attempt.source_vout
        ));
    }
    attempt_coin(wallet, record, attempt)
}

fn validate_attempt_invocation(
    attempt: &Bip448WithdrawalAttempt,
    to_address: &str,
    fee_rate: Option<f64>,
) -> Result<()> {
    if attempt.destination_address != to_address {
        return Err(anyhow!(
            "BIP448 withdrawal {}:{} already has a different destination",
            attempt.source_txid,
            attempt.source_vout
        ));
    }
    if fee_rate.is_some_and(|fee| fee.to_bits() != attempt.fee_rate_sat_per_vbyte.to_bits()) {
        return Err(anyhow!(
            "BIP448 withdrawal {}:{} already has a different fee rate",
            attempt.source_txid,
            attempt.source_vout
        ));
    }
    Ok(())
}

async fn prove_attempt_owner(
    client_config: &ClientConfig,
    wallet: &Wallet,
    record: &Bip448StatechainRecord,
    binding: &Bip448FundingBinding,
    attempt_kind: Bip448WithdrawalAttemptKind,
    attempt: Option<&Bip448WithdrawalAttempt>,
) -> Result<Coin> {
    let current =
        get_current_bip448_owner(client_config, wallet, &wallet.name, &record.statechain_id)
            .await?;
    let coin = wallet.coins.get(current.coin_index).ok_or_else(|| {
        anyhow!("selected BIP448 duplicate owner disappeared from its wallet snapshot")
    })?;
    let owner = PublicKey::from_str(&coin.user_pubkey)?
        .x_only_public_key()
        .0
        .to_string();
    require_attempt_binding(
        binding,
        binding.binding_index,
        attempt_kind,
        Some(&owner),
        Some(record.latest_state_number),
    )?;
    if coin.status != CoinStatus::CONFIRMED
        || coin.aggregated_pubkey.as_deref() != Some(record.aggregate_pubkey.as_str())
        || record.network != wallet.network
    {
        return Err(anyhow!(
            "current owner cannot sign BIP448 {} source {}",
            attempt_kind,
            binding_outpoint(binding)
        ));
    }
    if let Some(attempt) = attempt {
        if owner != attempt.owner_user_pubkey
            || coin.signed_statechain_id.as_deref() != Some(attempt.signed_statechain_id.as_str())
        {
            return Err(anyhow!(
                "current owner no longer matches BIP448 withdrawal attempt {}",
                binding_outpoint(binding)
            ));
        }
    }
    Ok(coin.clone())
}

async fn require_no_local_transfer(
    client_config: &ClientConfig,
    wallet: &Wallet,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<()> {
    if get_active_bip448_transfer_intent(&client_config.pool, wallet_name, statechain_id)
        .await?
        .is_some()
    {
        return Err(anyhow!(
            "active BIP448 transfer intent blocks duplicate withdrawal"
        ));
    }
    if get_bip448_pending_transfer_signing(&client_config.pool, wallet_name, statechain_id)
        .await?
        .is_some()
    {
        return Err(anyhow!(
            "pending BIP448 transfer signing blocks duplicate withdrawal"
        ));
    }
    if has_bip448_transfer_msg_for_statechain(&client_config.pool, wallet_name, statechain_id)
        .await?
    {
        return Err(anyhow!(
            "outgoing BIP448 transfer message blocks duplicate withdrawal"
        ));
    }
    if wallet.coins.iter().any(|coin| {
        coin.statechain_id.as_deref() == Some(statechain_id)
            && coin.status == CoinStatus::IN_TRANSFER
    }) {
        return Err(anyhow!(
            "IN_TRANSFER BIP448 Coin blocks duplicate withdrawal"
        ));
    }
    Ok(())
}

fn require_prior_attempt_policy(attempts: &[Bip448WithdrawalAttempt]) -> Result<()> {
    if attempts.iter().any(|attempt| attempt.binding_index == 0) {
        return Err(anyhow!(
            "BIP448 address is retired by a canonical withdrawal attempt"
        ));
    }
    for attempt in attempts {
        if attempt.phase != Bip448WithdrawalPhase::Signed {
            return Err(anyhow!("another BIP448 withdrawal signing is active"));
        }
        if !matches!(
            attempt.broadcast_status,
            Bip448BroadcastStatus::Accepted
                | Bip448BroadcastStatus::Confirmed
                | Bip448BroadcastStatus::Conflicted
        ) {
            return Err(anyhow!(
                "prior BIP448 withdrawal bytes require reconciliation"
            ));
        }
    }
    Ok(())
}

fn attempt_source_state(
    binding: &Bip448FundingBinding,
    attempt: &Bip448WithdrawalAttempt,
) -> Result<AttemptSourceState> {
    let prospective = crate::bip448_funding::expected_withdrawal_txid(attempt)?;
    let outpoint = binding_outpoint(binding);
    match binding.observation_status {
        Bip448ObservationStatus::Confirmed => Ok(AttemptSourceState::ExactConfirmed),
        Bip448ObservationStatus::SpentConfirmed => {
            let spender = binding.spend_txid.clone().ok_or_else(|| {
                anyhow!("BIP448 duplicate {outpoint} has no confirmed spender identity")
            })?;
            if spender == prospective {
                return Err(anyhow!(
                    "pre-Signed BIP448 duplicate {outpoint} unexpectedly has its prospective sweep on chain"
                ));
            }
            Ok(AttemptSourceState::ConfirmedConflict(spender))
        }
        Bip448ObservationStatus::SpentMempool | Bip448ObservationStatus::SpentUnconfirmed => {
            let spender = binding.spend_txid.clone().ok_or_else(|| {
                anyhow!("BIP448 duplicate {outpoint} has no competing spender identity")
            })?;
            if spender == prospective {
                return Err(anyhow!(
                    "pre-Signed BIP448 duplicate {outpoint} unexpectedly has its prospective sweep in flight"
                ));
            }
            Ok(AttemptSourceState::Wait(format!(
                "BIP448 duplicate {outpoint} has transient competing spend {spender}"
            )))
        }
        status => Ok(AttemptSourceState::Wait(format!(
            "BIP448 duplicate {outpoint} is {status} and must wait"
        ))),
    }
}

fn source_and_prepared(
    attempt: &Bip448WithdrawalAttempt,
) -> Result<(Bip448KeypathSpendSource, Bip448PreparedKeypathSpend)> {
    let source = Bip448KeypathSpendSource {
        outpoint: OutPoint {
            txid: Txid::from_str(&attempt.source_txid)?,
            vout: attempt.source_vout,
        },
        value_sats: attempt.source_value_sats,
        script_pubkey: ScriptBuf::from_bytes(hex::decode(&attempt.source_script_pubkey)?),
    };
    let output_value_sats = attempt
        .source_value_sats
        .checked_sub(attempt.fee_sats)
        .ok_or_else(|| anyhow!("persisted BIP448 duplicate fee exceeds its input"))?;
    let prepared = Bip448PreparedKeypathSpend {
        unsigned_tx: hex::decode(&attempt.unsigned_tx_hex)?,
        fee_sats: attempt.fee_sats,
        destination_script_pubkey: ScriptBuf::from_bytes(hex::decode(
            &attempt.destination_script_pubkey,
        )?),
        output_value_sats,
        lock_time: attempt.lock_time,
    };
    Ok((source, prepared))
}

fn validated_sign_second_request(
    attempt: &Bip448WithdrawalAttempt,
) -> Result<Bip448PartialSignatureRequestPayload> {
    let request = bip448_funding::parse_canonical_sign_second_payload(
        attempt
            .sign_second_payload_json
            .as_deref()
            .ok_or_else(|| anyhow!("post-nonce BIP448 attempt has no sign/second payload"))?,
    )?;
    bip448_funding::require_bip448_session_relationship(
        attempt
            .encoded_session
            .as_deref()
            .ok_or_else(|| anyhow!("post-nonce BIP448 attempt has no full MuSig session"))?,
        &request.session,
    )?;
    if request.statechain_id != attempt.statechain_id
        || request.signed_statechain_id != attempt.signed_statechain_id
        || request.signing_id != attempt.signing_id
        || attempt.server_public_nonce.as_deref() != Some(request.server_pub_nonce.as_str())
        || !matches!(request.negate_seckey, 0 | 1)
    {
        return Err(anyhow!(
            "BIP448 sign/second payload does not match the persisted attempt"
        ));
    }
    Ok(request)
}

async fn require_count_before_signing(
    client_config: &ClientConfig,
    wallet_name: &str,
    statechain_id: &str,
    second_armed: bool,
) -> Result<()> {
    let expected =
        bip448_expected_signature_count(&client_config.pool, wallet_name, statechain_id).await?;
    let actual = bip448_signature_count(client_config, statechain_id).await?;
    let valid = actual == expected.settled_count
        || (second_armed && expected.second_armed_landed_count == Some(actual));
    if !valid {
        return Err(anyhow!(
            "BIP448 lockbox signature count is {}, expected {}{}",
            actual,
            expected.settled_count,
            expected
                .second_armed_landed_count
                .map_or(String::new(), |landed| format!(" or {landed}"))
        ));
    }
    Ok(())
}

async fn require_count_after_signing(
    client_config: &ClientConfig,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<()> {
    let expected =
        bip448_expected_signature_count(&client_config.pool, wallet_name, statechain_id).await?;
    let landed = expected
        .second_armed_landed_count
        .ok_or_else(|| anyhow!("BIP448 sign/second count check lost its SecondArmed row"))?;
    #[cfg(feature = "test-hooks")]
    if std::env::var("ML_BIP448_FAIL_POST_SIGN_COUNT").as_deref() == Ok("1") {
        return Err(anyhow!(
            "injected BIP448 post-sign lockbox count read failure"
        ));
    }
    let actual = bip448_signature_count(client_config, statechain_id).await?;
    if actual != landed {
        return Err(anyhow!(
            "BIP448 post-sign lockbox count is {actual}, expected {landed}"
        ));
    }
    Ok(())
}

fn require_statechain_deleted(body: &str) -> Result<()> {
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|_| anyhow!("{UNEXPECTED_COMPLETION_RESPONSE}"))?;
    if value.get("message").and_then(serde_json::Value::as_str) != Some("Statechain deleted.") {
        return Err(anyhow!("{UNEXPECTED_COMPLETION_RESPONSE}"));
    }
    Ok(())
}

pub async fn execute_duplicate_sweep(
    client_config: &ClientConfig,
    wallet_name: &str,
    statechain_id: &str,
    duplicate_index: u32,
    to_address: &str,
    fee_rate: Option<f64>,
) -> Result<Bip448DuplicateSweepResult> {
    // This is repeated by the CLI's pre-configuration handler. Keeping the
    // typed library boundary duplicate-only prevents an internal caller from
    // selecting the canonical outpoint accidentally.
    if duplicate_index == 0 {
        return Err(anyhow!(
            "duplicate_index 0 is canonical and cannot be swept as a duplicate"
        ));
    }

    // Journal lookup is intentionally first and precedes every estimator,
    // random sample, owner/count query, and signing request.
    let wallet = get_wallet(&client_config.pool, wallet_name).await?;
    let record = get_bip448_statechain(&client_config.pool, wallet_name, statechain_id).await?;
    let binding = get_bip448_funding_binding(
        &client_config.pool,
        wallet_name,
        statechain_id,
        duplicate_index,
    )
    .await?;
    let exact_attempt = get_bip448_withdrawal_attempt(
        &client_config.pool,
        wallet_name,
        statechain_id,
        duplicate_index,
    )
    .await?;
    let binding = binding.ok_or_else(|| {
        anyhow!("unknown BIP448 duplicate_index {duplicate_index} for statechain {statechain_id}")
    })?;

    if let Some(attempt) = exact_attempt {
        validate_attempt_invocation(&attempt, to_address, fee_rate)?;
        validate_attempt_identity(client_config, &wallet, &record, &binding, &attempt).await?;
        return drive_duplicate_attempt(client_config, to_address, fee_rate, attempt).await;
    }

    if !wallet
        .coins
        .iter()
        .any(|coin| coin.statechain_id.as_deref() == Some(statechain_id) && is_bip448_coin(coin))
    {
        return Err(anyhow!(
            "statechain {statechain_id} is not an accepted BIP448 coin"
        ));
    }

    let owner_coin = prove_attempt_owner(
        client_config,
        &wallet,
        &record,
        &binding,
        Bip448WithdrawalAttemptKind::Duplicate,
        None,
    )
    .await?;
    require_attempt_binding(
        &binding,
        duplicate_index,
        Bip448WithdrawalAttemptKind::Duplicate,
        Some(
            &PublicKey::from_str(&owner_coin.user_pubkey)?
                .x_only_public_key()
                .0
                .to_string(),
        ),
        Some(record.latest_state_number),
    )?;
    require_exact_confirmed_source(client_config, &binding)?;
    require_no_local_transfer(client_config, &wallet, wallet_name, statechain_id).await?;

    let report = sync_bip448_funding_bindings(client_config, wallet_name).await?;
    let wallet = get_wallet(&client_config.pool, wallet_name).await?;
    let record = get_bip448_statechain(&client_config.pool, wallet_name, statechain_id).await?;
    let binding = get_bip448_funding_binding(
        &client_config.pool,
        wallet_name,
        statechain_id,
        duplicate_index,
    )
    .await?
    .ok_or_else(|| anyhow!("BIP448 duplicate_index {duplicate_index} disappeared after rescan"))?;
    if let Some(attempt) = get_bip448_withdrawal_attempt(
        &client_config.pool,
        wallet_name,
        statechain_id,
        duplicate_index,
    )
    .await?
    {
        validate_attempt_invocation(&attempt, to_address, fee_rate)?;
        validate_attempt_identity(client_config, &wallet, &record, &binding, &attempt).await?;
        return drive_duplicate_attempt(client_config, to_address, fee_rate, attempt).await;
    }

    let owner_coin = prove_attempt_owner(
        client_config,
        &wallet,
        &record,
        &binding,
        Bip448WithdrawalAttemptKind::Duplicate,
        None,
    )
    .await?;
    require_attempt_binding(
        &binding,
        duplicate_index,
        Bip448WithdrawalAttemptKind::Duplicate,
        Some(
            &PublicKey::from_str(&owner_coin.user_pubkey)?
                .x_only_public_key()
                .0
                .to_string(),
        ),
        Some(record.latest_state_number),
    )?;
    require_exact_confirmed_source(client_config, &binding)?;
    require_prior_attempt_policy(
        &report
            .attempts
            .iter()
            .filter(|attempt| {
                attempt.wallet_name == wallet_name && attempt.statechain_id == statechain_id
            })
            .cloned()
            .collect::<Vec<_>>(),
    )?;

    let fee_rate_sat_per_vbyte = match fee_rate {
        Some(fee_rate) => fee_rate,
        None => estimate_fee_rate_sats_per_byte(client_config)?.min(client_config.max_fee_rate),
    };
    let source = Bip448KeypathSpendSource {
        outpoint: OutPoint {
            txid: Txid::from_str(&binding.txid)?,
            vout: binding.vout,
        },
        value_sats: binding.value_sats,
        script_pubkey: ScriptBuf::from_bytes(hex::decode(&binding.script_pubkey)?),
    };
    let lock_time = sample_bip448_keypath_spend_lock_time(report.tip_height);
    let prepared = prepare_bip448_keypath_spend(
        &record.aggregate_pubkey,
        &source,
        to_address,
        client_config.network,
        fee_rate_sat_per_vbyte,
        lock_time,
    )?;
    let nonce = create_bip448_keypath_nonces(&owner_coin)?;
    let signing_id = hex::encode(SecretKey::new(&mut rand::rng()).to_secret_bytes());
    let signed_statechain_id = owner_coin
        .signed_statechain_id
        .clone()
        .ok_or_else(|| anyhow!("BIP448 duplicate owner is missing signed_statechain_id"))?;
    let sign_first = Bip448SignFirstRequestPayload {
        statechain_id: statechain_id.to_owned(),
        signed_statechain_id: signed_statechain_id.clone(),
        signing_id: signing_id.clone(),
    };
    let owner_user_pubkey = PublicKey::from_str(&owner_coin.user_pubkey)?
        .x_only_public_key()
        .0
        .to_string();
    let attempt = Bip448WithdrawalAttempt {
        wallet_name: wallet_name.to_owned(),
        statechain_id: statechain_id.to_owned(),
        binding_index: duplicate_index,
        attempt_kind: Bip448WithdrawalAttemptKind::Duplicate,
        owner_user_pubkey,
        owner_state_number: record.latest_state_number,
        source_txid: binding.txid.clone(),
        source_vout: binding.vout,
        source_value_sats: binding.value_sats,
        source_script_pubkey: binding.script_pubkey.clone(),
        destination_address: to_address.to_owned(),
        destination_script_pubkey: hex::encode(prepared.destination_script_pubkey.as_bytes()),
        fee_rate_sat_per_vbyte,
        fee_sats: prepared.fee_sats,
        lock_time: prepared.lock_time,
        unsigned_tx_hex: hex::encode(&prepared.unsigned_tx),
        signing_id,
        signed_statechain_id,
        sign_first_payload_json: serde_json::to_string(&sign_first)?,
        client_secret_nonce: nonce.secret_nonce,
        client_public_nonce: nonce.public_nonce,
        blinding_factor: nonce.blinding_factor,
        server_public_nonce: None,
        message_hex: None,
        output_pubkey: None,
        client_partial_sig: None,
        encoded_session: None,
        sign_second_payload_json: None,
        server_partial_sig: None,
        aggregate_signature: None,
        signed_tx_hex: None,
        txid: None,
        phase: Bip448WithdrawalPhase::Prepared,
        broadcast_status: Bip448BroadcastStatus::NotBroadcast,
        completion_status: Bip448CompletionStatus::NotApplicable,
        closing_tip_height: None,
        closing_tip_hash: None,
        closing_bindings_json: None,
        created_at: String::new(),
        updated_at: String::new(),
    };

    let mut guard = begin_bip448_mutation_guard(&client_config.pool).await?;
    // The exact chain fact and count are repeated while the same BEGIN
    // IMMEDIATE transaction protects the local exclusion marker.
    require_exact_confirmed_source(client_config, &binding)?;
    let expected = guard
        .withdrawal_signature_count_expectation(wallet_name, statechain_id)
        .await?;
    let actual = bip448_signature_count(client_config, statechain_id).await?;
    if actual != expected.settled_count || expected.second_armed_landed_count.is_some() {
        return Err(anyhow!(
            "BIP448 lockbox signature count is {actual}, expected {} before creating duplicate {}",
            expected.settled_count,
            binding_outpoint(&binding)
        ));
    }
    let persisted = guard.insert_withdrawal_attempt_if_absent(&attempt).await?;
    guard.commit().await?;
    bip448_process_checkpoint("attempt_prepared");
    drive_duplicate_attempt(client_config, to_address, fee_rate, persisted).await
}

async fn refresh_withdrawal_attempt(
    client_config: &ClientConfig,
    to_address: &str,
    fee_rate: Option<f64>,
    expected: &Bip448WithdrawalAttempt,
) -> Result<(
    Wallet,
    Bip448StatechainRecord,
    Bip448FundingBinding,
    Bip448WithdrawalAttempt,
    u32,
    String,
)> {
    let report = sync_bip448_funding_bindings(client_config, &expected.wallet_name).await?;
    let wallet = get_wallet(&client_config.pool, &expected.wallet_name).await?;
    let record = get_bip448_statechain(
        &client_config.pool,
        &expected.wallet_name,
        &expected.statechain_id,
    )
    .await?;
    let binding = get_bip448_funding_binding(
        &client_config.pool,
        &expected.wallet_name,
        &expected.statechain_id,
        expected.binding_index,
    )
    .await?
    .ok_or_else(|| anyhow!("BIP448 withdrawal attempt lost its binding"))?;
    let attempt = get_bip448_withdrawal_attempt(
        &client_config.pool,
        &expected.wallet_name,
        &expected.statechain_id,
        expected.binding_index,
    )
    .await?
    .ok_or_else(|| anyhow!("BIP448 withdrawal attempt disappeared"))?;
    if attempt.signing_id != expected.signing_id {
        return Err(anyhow!(
            "BIP448 withdrawal attempt signing identity changed"
        ));
    }
    validate_attempt_invocation(&attempt, to_address, fee_rate)?;
    validate_attempt_identity(client_config, &wallet, &record, &binding, &attempt).await?;
    Ok((
        wallet,
        record,
        binding,
        attempt,
        report.tip_height,
        report.tip_hash,
    ))
}

async fn broadcast_signed_attempt(
    client_config: &ClientConfig,
    attempt: Bip448WithdrawalAttempt,
) -> Result<Bip448WithdrawalAttempt> {
    let txid = attempt
        .txid
        .clone()
        .ok_or_else(|| anyhow!("Signed BIP448 withdrawal attempt has no txid"))?;
    if attempt.broadcast_status == Bip448BroadcastStatus::Conflicted {
        return Ok(attempt);
    }
    let reconciliation = broadcast_or_reconcile_transaction(
        &client_config.chain_client,
        attempt
            .signed_tx_hex
            .as_deref()
            .ok_or_else(|| anyhow!("Signed BIP448 withdrawal has no transaction bytes"))?,
        &txid,
    );
    bip448_process_checkpoint("broadcast_returned");
    match reconciliation {
        Ok(BroadcastTxStatus::Accepted { confirmations }) => {
            let next = if confirmations >= client_config.confirmation_target && confirmations != 0 {
                Bip448BroadcastStatus::Confirmed
            } else {
                Bip448BroadcastStatus::Accepted
            };
            if attempt.broadcast_status == next {
                Ok(attempt)
            } else {
                transition_bip448_withdrawal_broadcast_status(
                    &client_config.pool,
                    &attempt.wallet_name,
                    &attempt.statechain_id,
                    attempt.binding_index,
                    &attempt.signing_id,
                    attempt.broadcast_status,
                    next,
                )
                .await
            }
        }
        Err(send_error) => {
            if attempt.broadcast_status == Bip448BroadcastStatus::Conflicting {
                return Err(send_error.context(format!(
                    "exact BIP448 bytes remain blocked by a different in-flight spender of {}:{}",
                    attempt.source_txid, attempt.source_vout
                )));
            }
            if attempt.broadcast_status != Bip448BroadcastStatus::NeedsRebroadcast {
                if let Err(status_error) = transition_bip448_withdrawal_broadcast_status(
                    &client_config.pool,
                    &attempt.wallet_name,
                    &attempt.statechain_id,
                    attempt.binding_index,
                    &attempt.signing_id,
                    attempt.broadcast_status,
                    Bip448BroadcastStatus::NeedsRebroadcast,
                )
                .await
                {
                    return Err(send_error.context(format!(
                        "failed to preserve NeedsRebroadcast: {status_error}"
                    )));
                }
            }
            Err(send_error)
        }
    }
}

async fn reconcile_and_validate_frozen_snapshot(
    client_config: &ClientConfig,
    canonical: &Bip448WithdrawalAttempt,
) -> Result<()> {
    if canonical.binding_index != 0
        || canonical.attempt_kind != Bip448WithdrawalAttemptKind::Canonical
    {
        return Err(anyhow!(
            "only the canonical BIP448 attempt owns a frozen close snapshot"
        ));
    }
    let frozen = bip448_funding::decode_bip448_closing_bindings(
        canonical
            .closing_bindings_json
            .as_deref()
            .ok_or_else(|| anyhow!("canonical BIP448 close snapshot is missing"))?,
    )?;
    for binding in frozen {
        let Bip448ClosingResolution::SignedAttempt {
            signing_id,
            sweep_txid,
            conflict_spend_txid,
        } = binding.resolution
        else {
            continue;
        };
        let sweep = get_bip448_withdrawal_attempt(
            &client_config.pool,
            &canonical.wallet_name,
            &canonical.statechain_id,
            binding.binding_index,
        )
        .await?
        .ok_or_else(|| anyhow!("frozen BIP448 sweep attempt disappeared"))?;
        if sweep.attempt_kind != Bip448WithdrawalAttemptKind::Duplicate
            || sweep.phase != Bip448WithdrawalPhase::Signed
            || sweep.signing_id != signing_id
            || sweep.txid.as_deref() != Some(sweep_txid.as_str())
            || sweep.source_txid != binding.txid
            || sweep.source_vout != binding.vout
            || sweep.source_value_sats != binding.value_sats
            || sweep.owner_user_pubkey != binding.owner_user_pubkey
            || sweep.owner_state_number != binding.owner_state_number
        {
            return Err(anyhow!(
                "frozen BIP448 sweep identity changed for binding {}",
                binding.binding_index
            ));
        }
        match (conflict_spend_txid.is_none(), sweep.broadcast_status) {
            (
                true,
                Bip448BroadcastStatus::NeedsRebroadcast | Bip448BroadcastStatus::Conflicting,
            ) => {
                let repaired = broadcast_signed_attempt(client_config, sweep).await?;
                if !matches!(
                    repaired.broadcast_status,
                    Bip448BroadcastStatus::Accepted | Bip448BroadcastStatus::Confirmed
                ) {
                    return Err(anyhow!(
                        "frozen BIP448 sweep {} was not restored to exact acceptance",
                        binding.binding_index
                    ));
                }
            }
            _ => {}
        }
    }
    validate_bip448_canonical_close_snapshot(
        &client_config.pool,
        &canonical.wallet_name,
        &canonical.statechain_id,
        &canonical.signing_id,
    )
    .await
}

async fn drive_duplicate_attempt(
    client_config: &ClientConfig,
    to_address: &str,
    fee_rate: Option<f64>,
    expected: Bip448WithdrawalAttempt,
) -> Result<Bip448DuplicateSweepResult> {
    if expected.attempt_kind != Bip448WithdrawalAttemptKind::Duplicate {
        return Err(anyhow!("canonical BIP448 attempt reached duplicate driver"));
    }
    let final_attempt =
        drive_withdrawal_attempt(client_config, to_address, fee_rate, expected).await?;
    let txid = final_attempt
        .txid
        .clone()
        .ok_or_else(|| anyhow!("Signed BIP448 duplicate has no txid"))?;
    Ok(duplicate_sweep_result(&final_attempt, &txid))
}

async fn drive_withdrawal_attempt(
    client_config: &ClientConfig,
    to_address: &str,
    fee_rate: Option<f64>,
    mut expected: Bip448WithdrawalAttempt,
) -> Result<Bip448WithdrawalAttempt> {
    loop {
        let (wallet, record, binding, attempt, tip_height, tip_hash) =
            refresh_withdrawal_attempt(client_config, to_address, fee_rate, &expected).await?;
        match attempt.phase {
            Bip448WithdrawalPhase::Prepared => {
                match attempt_source_state(&binding, &attempt)? {
                    AttemptSourceState::ExactConfirmed => {
                        require_exact_confirmed_source(client_config, &binding)?;
                    }
                    AttemptSourceState::Wait(reason) => return Err(anyhow!(reason)),
                    AttemptSourceState::ConfirmedConflict(spender) => {
                        if attempt.attempt_kind == Bip448WithdrawalAttemptKind::Canonical {
                            return Err(anyhow!(
                                "confirmed competing spend {spender} blocks canonical BIP448 source {} without deleting its retired-address journal",
                                binding_outpoint(&binding)
                            ));
                        }
                        delete_prepared_bip448_withdrawal_attempt_for_confirmed_spend(
                            &client_config.pool,
                            &attempt,
                            &spender,
                            tip_height,
                            &tip_hash,
                        )
                        .await?;
                        return Err(anyhow!(
                            "confirmed competing spend {spender} consumed duplicate {} without a signing count",
                            binding_outpoint(&binding)
                        ));
                    }
                }
                prove_attempt_owner(
                    client_config,
                    &wallet,
                    &record,
                    &binding,
                    attempt.attempt_kind,
                    Some(&attempt),
                )
                .await?;
                expected = arm_bip448_withdrawal_sign_first(
                    &client_config.pool,
                    &attempt.wallet_name,
                    &attempt.statechain_id,
                    attempt.binding_index,
                    &attempt.signing_id,
                )
                .await?;
                bip448_process_checkpoint("sign_first_armed");
            }
            Bip448WithdrawalPhase::FirstArmed => {
                match attempt_source_state(&binding, &attempt)? {
                    AttemptSourceState::Wait(reason) => return Err(anyhow!(reason)),
                    AttemptSourceState::ExactConfirmed
                    | AttemptSourceState::ConfirmedConflict(_) => {}
                }
                let mut coin = prove_attempt_owner(
                    client_config,
                    &wallet,
                    &record,
                    &binding,
                    attempt.attempt_kind,
                    Some(&attempt),
                )
                .await?;
                require_count_before_signing(
                    client_config,
                    &attempt.wallet_name,
                    &attempt.statechain_id,
                    false,
                )
                .await?;
                let sign_first: Bip448SignFirstRequestPayload =
                    serde_json::from_str(&attempt.sign_first_payload_json)?;
                let server_public_nonce = bip448_sign_first(client_config, &sign_first).await?;
                #[cfg(feature = "test-hooks")]
                {
                    use std::io::Write;

                    let mut stdout = std::io::stdout().lock();
                    writeln!(stdout, "BIP448_TEST_SERVER_NONCE={server_public_nonce}")?;
                    stdout.flush()?;
                }
                bip448_process_checkpoint("server_nonce_returned");

                coin.secret_nonce = Some(attempt.client_secret_nonce.clone());
                coin.public_nonce = Some(attempt.client_public_nonce.clone());
                coin.blinding_factor = Some(attempt.blinding_factor.clone());
                coin.server_public_nonce = Some(server_public_nonce.clone());
                let (source, prepared) = source_and_prepared(&attempt)?;
                let signing = build_bip448_keypath_spend_signing_data(
                    &coin,
                    &record.aggregate_pubkey,
                    &source,
                    &prepared,
                )?;
                if signing.encoded_unsigned_tx != attempt.unsigned_tx_hex {
                    return Err(anyhow!(
                        "BIP448 duplicate signing regenerated different unsigned bytes"
                    ));
                }
                let request = Bip448PartialSignatureRequestPayload {
                    statechain_id: signing
                        .partial_signature_request_payload
                        .statechain_id
                        .clone(),
                    signed_statechain_id: signing
                        .partial_signature_request_payload
                        .signed_statechain_id
                        .clone(),
                    signing_id: attempt.signing_id.clone(),
                    negate_seckey: signing.partial_signature_request_payload.negate_seckey,
                    session: signing.partial_signature_request_payload.session.clone(),
                    server_pub_nonce: signing
                        .partial_signature_request_payload
                        .server_pub_nonce
                        .clone(),
                };
                let derived_blinded_session =
                    bip448_funding::derive_bip448_blinded_session(&signing.encoded_session)?;
                if signing.partial_signature_request_payload.session != derived_blinded_session
                    || request.session != derived_blinded_session
                {
                    return Err(anyhow!(
                        "BIP448 sign/second DTO sessions do not derive from the full MuSig session"
                    ));
                }
                expected = store_bip448_withdrawal_nonce_artifacts(
                    &client_config.pool,
                    &attempt.wallet_name,
                    &attempt.statechain_id,
                    attempt.binding_index,
                    &attempt.signing_id,
                    &server_public_nonce,
                    &signing.msg,
                    &signing.output_pubkey,
                    &signing.client_partial_sig,
                    &signing.encoded_session,
                    &serde_json::to_string(&request)?,
                )
                .await?;
                bip448_process_checkpoint("server_nonce_persisted");
            }
            Bip448WithdrawalPhase::NonceStored => {
                validated_sign_second_request(&attempt)?;
                match attempt_source_state(&binding, &attempt)? {
                    AttemptSourceState::Wait(reason) => return Err(anyhow!(reason)),
                    AttemptSourceState::ExactConfirmed
                    | AttemptSourceState::ConfirmedConflict(_) => {}
                }
                prove_attempt_owner(
                    client_config,
                    &wallet,
                    &record,
                    &binding,
                    attempt.attempt_kind,
                    Some(&attempt),
                )
                .await?;
                if attempt.attempt_kind == Bip448WithdrawalAttemptKind::Canonical {
                    reconcile_and_validate_frozen_snapshot(client_config, &attempt).await?;
                }
                require_count_before_signing(
                    client_config,
                    &attempt.wallet_name,
                    &attempt.statechain_id,
                    false,
                )
                .await?;
                expected = arm_bip448_withdrawal_sign_second(
                    &client_config.pool,
                    &attempt.wallet_name,
                    &attempt.statechain_id,
                    attempt.binding_index,
                    &attempt.signing_id,
                )
                .await?;
                bip448_process_checkpoint("sign_second_armed");
            }
            Bip448WithdrawalPhase::SecondArmed => {
                let source_state = attempt_source_state(&binding, &attempt)?;
                let request = validated_sign_second_request(&attempt)?;
                require_count_before_signing(
                    client_config,
                    &attempt.wallet_name,
                    &attempt.statechain_id,
                    true,
                )
                .await?;
                let server_partial = bip448_sign_second(client_config, &request).await?;
                bip448_process_checkpoint("server_partial_returned");
                let server_partial_sig = hex::encode(server_partial.serialize());
                let aggregate_signature = aggregate_bip448_keypath_signature(
                    attempt
                        .message_hex
                        .clone()
                        .ok_or_else(|| anyhow!("SecondArmed BIP448 attempt has no message"))?,
                    attempt.client_partial_sig.clone().ok_or_else(|| {
                        anyhow!("SecondArmed BIP448 attempt has no client partial")
                    })?,
                    server_partial_sig.clone(),
                    attempt
                        .encoded_session
                        .clone()
                        .ok_or_else(|| anyhow!("SecondArmed BIP448 attempt has no session"))?,
                    attempt
                        .output_pubkey
                        .clone()
                        .ok_or_else(|| anyhow!("SecondArmed BIP448 attempt has no output key"))?,
                )?;
                let signed_tx_hex = finalize_bip448_keypath_transaction(
                    attempt.unsigned_tx_hex.clone(),
                    aggregate_signature.clone(),
                )?;
                let signed_bytes = hex::decode(&signed_tx_hex)?;
                let signed_transaction: Transaction =
                    bitcoin::consensus::deserialize(&signed_bytes)?;
                if bitcoin::consensus::serialize(&signed_transaction) != signed_bytes {
                    return Err(anyhow!(
                        "BIP448 duplicate finalizer returned noncanonical bytes"
                    ));
                }
                require_count_after_signing(
                    client_config,
                    &attempt.wallet_name,
                    &attempt.statechain_id,
                )
                .await?;
                let initial_status = match source_state {
                    AttemptSourceState::ConfirmedConflict(_) => Bip448BroadcastStatus::Conflicted,
                    AttemptSourceState::Wait(_)
                        if matches!(
                            binding.observation_status,
                            Bip448ObservationStatus::SpentMempool
                                | Bip448ObservationStatus::SpentUnconfirmed
                        ) =>
                    {
                        Bip448BroadcastStatus::Conflicting
                    }
                    _ => Bip448BroadcastStatus::NotBroadcast,
                };
                expected = store_bip448_withdrawal_signed_artifacts(
                    &client_config.pool,
                    &attempt.wallet_name,
                    &attempt.statechain_id,
                    attempt.binding_index,
                    &attempt.signing_id,
                    &server_partial_sig,
                    &aggregate_signature,
                    &signed_tx_hex,
                    &signed_transaction.txid().to_string(),
                    initial_status,
                )
                .await?;
                bip448_process_checkpoint("signed_tx_persisted");
                #[cfg(feature = "test-hooks")]
                if attempt.attempt_kind == Bip448WithdrawalAttemptKind::Canonical
                    && std::env::var("ML_BIP448_WITHDRAW_STOP_AFTER_SIGNATURE").as_deref()
                        == Ok("1")
                {
                    return Err(anyhow!("BIP448 withdraw stopped after signature for test"));
                }
            }
            Bip448WithdrawalPhase::Signed => {
                return broadcast_signed_attempt(client_config, attempt).await;
            }
        }
    }
}

fn duplicate_sweep_result(
    attempt: &Bip448WithdrawalAttempt,
    txid: &str,
) -> Bip448DuplicateSweepResult {
    Bip448DuplicateSweepResult {
        statechain_id: attempt.statechain_id.clone(),
        duplicate_index: attempt.binding_index,
        source_outpoint: format!("{}:{}", attempt.source_txid, attempt.source_vout),
        amount_sats: attempt.source_value_sats,
        sweep_txid: txid.to_owned(),
        broadcast_status: attempt.broadcast_status.to_string(),
        exit_only: true,
    }
}

fn require_canonical_coin_record_identity(
    wallet: &Wallet,
    coin: &Coin,
    record: &Bip448StatechainRecord,
) -> Result<()> {
    if record.wallet_name != wallet.name
        || record.network != wallet.network
        || record.amount_sats != record.funding_outpoint.value_sats
        || coin.statechain_id.as_deref() != Some(record.statechain_id.as_str())
        || coin.aggregated_pubkey.as_deref() != Some(record.aggregate_pubkey.as_str())
        || coin.utxo_txid.as_deref() != Some(record.funding_outpoint.txid.as_str())
        || coin.utxo_vout != Some(record.funding_outpoint.vout)
        || coin.amount.map(u64::from) != Some(record.amount_sats)
    {
        return Err(anyhow!(
            "BIP448 canonical Coin does not match its accepted funding record"
        ));
    }
    Ok(())
}

fn require_ready_close_gate(gate: Bip448CloseGate) -> Result<String> {
    match gate {
        Bip448CloseGate::Ready {
            closing_bindings_json,
            ..
        } => Ok(closing_bindings_json),
        Bip448CloseGate::Blocked { reasons } => Err(anyhow!(
            "BIP448 canonical withdrawal is blocked by unresolved close facts: {reasons:?}"
        )),
    }
}

async fn refresh_accepted_canonical_attempt(
    client_config: &ClientConfig,
    to_address: &str,
    fee_rate: Option<f64>,
    expected: &Bip448WithdrawalAttempt,
) -> Result<Bip448WithdrawalAttempt> {
    let (_, _, _, live, _, _) =
        refresh_withdrawal_attempt(client_config, to_address, fee_rate, expected).await?;
    if live.attempt_kind != Bip448WithdrawalAttemptKind::Canonical
        || live.binding_index != 0
        || live.phase != Bip448WithdrawalPhase::Signed
    {
        return Err(anyhow!(
            "canonical BIP448 close journal is not durably Signed"
        ));
    }
    let live = broadcast_signed_attempt(client_config, live).await?;
    if !matches!(
        live.broadcast_status,
        Bip448BroadcastStatus::Accepted | Bip448BroadcastStatus::Confirmed
    ) {
        return Err(anyhow!(
            "canonical BIP448 close bytes are {}, not accepted",
            live.broadcast_status
        ));
    }
    Ok(live)
}

async fn mark_canonical_closed(
    client_config: &ClientConfig,
    attempt: &Bip448WithdrawalAttempt,
) -> Result<()> {
    transition_bip448_withdrawal_completion_status(
        &client_config.pool,
        &attempt.wallet_name,
        &attempt.statechain_id,
        &attempt.signing_id,
        Bip448CompletionStatus::CloseArmed,
        Bip448CompletionStatus::Closed,
    )
    .await?;
    Ok(())
}

async fn reconcile_canonical_completion_result(
    client_config: &ClientConfig,
    attempt: &Bip448WithdrawalAttempt,
    completion: Result<String>,
) -> Result<()> {
    let completion_error = match completion {
        Ok(body) => {
            bip448_process_checkpoint("canonical_completion_returned");
            match require_statechain_deleted(&body) {
                Ok(()) => return mark_canonical_closed(client_config, attempt).await,
                Err(error) => error,
            }
        }
        Err(error) => error,
    };
    match get_bip448_statechain_presence(client_config, &attempt.statechain_id).await {
        Ok(Bip448StatechainPresence::Missing) => {
            mark_canonical_closed(client_config, attempt).await
        }
        Ok(Bip448StatechainPresence::Present(_)) => Err(completion_error.context(
            "BIP448 canonical completion is indeterminate while Mercury state remains present",
        )),
        Err(presence_error) => Err(completion_error.context(format!(
            "BIP448 canonical completion reconciliation was indeterminate: {presence_error}"
        ))),
    }
}

async fn complete_canonical_under_mutation_fence(
    client_config: &ClientConfig,
    expected: &Bip448WithdrawalAttempt,
) -> Result<(Bip448WithdrawalAttempt, Result<String>)> {
    // This short request is the irreversible boundary. Keep BEGIN IMMEDIATE
    // alive from the final frozen-snapshot reload until the response returns,
    // so no passive scan or other local mutation can commit in between.
    with_bip448_canonical_completion_fence(
        &client_config.pool,
        &expected.wallet_name,
        &expected.statechain_id,
        &expected.signing_id,
        BIP448_CANONICAL_COMPLETION_TIMEOUT,
        |canonical| async move {
            crate::utils::complete_withdraw(
                &canonical.statechain_id,
                &canonical.signed_statechain_id,
                client_config,
            )
            .await
        },
    )
    .await
}

async fn drive_canonical_attempt(
    client_config: &ClientConfig,
    to_address: &str,
    fee_rate: Option<f64>,
    attempt: Bip448WithdrawalAttempt,
) -> Result<()> {
    if attempt.attempt_kind != Bip448WithdrawalAttemptKind::Canonical || attempt.binding_index != 0
    {
        return Err(anyhow!("duplicate BIP448 attempt reached canonical driver"));
    }
    let signed = drive_withdrawal_attempt(client_config, to_address, fee_rate, attempt).await?;
    if !matches!(
        signed.broadcast_status,
        Bip448BroadcastStatus::Accepted | Bip448BroadcastStatus::Confirmed
    ) {
        return Err(anyhow!(
            "canonical BIP448 transaction is {}, so completion remains blocked",
            signed.broadcast_status
        ));
    }
    persist_bip448_canonical_withdrawal_wallet(
        &client_config.pool,
        &signed.wallet_name,
        &signed.statechain_id,
        &signed.signing_id,
    )
    .await?;
    bip448_process_checkpoint("canonical_wallet_persisted");

    let mut canonical =
        refresh_accepted_canonical_attempt(client_config, to_address, fee_rate, &signed).await?;
    if canonical.completion_status == Bip448CompletionStatus::Closed {
        return Ok(());
    }
    if canonical.completion_status == Bip448CompletionStatus::Open {
        reconcile_and_validate_frozen_snapshot(client_config, &canonical).await?;
        canonical = transition_bip448_withdrawal_completion_status(
            &client_config.pool,
            &canonical.wallet_name,
            &canonical.statechain_id,
            &canonical.signing_id,
            Bip448CompletionStatus::Open,
            Bip448CompletionStatus::CloseArmed,
        )
        .await?;
        bip448_process_checkpoint("canonical_close_armed");
    }
    if canonical.completion_status != Bip448CompletionStatus::CloseArmed {
        return Err(anyhow!("canonical BIP448 completion journal is invalid"));
    }

    // Journal identity and exact broadcast acceptance are established before
    // consulting Mercury. A definitive row-absent 404 is then terminal proof
    // of a previously completed request and must never return to signing.
    match get_bip448_statechain_presence(client_config, &canonical.statechain_id).await? {
        Bip448StatechainPresence::Missing => {
            return mark_canonical_closed(client_config, &canonical).await;
        }
        Bip448StatechainPresence::Present(_) => {}
    }

    // Refresh all exact chain facts after /info and immediately before the one
    // completion request permitted in this invocation.
    canonical =
        refresh_accepted_canonical_attempt(client_config, to_address, fee_rate, &canonical).await?;
    reconcile_and_validate_frozen_snapshot(client_config, &canonical).await?;
    let (canonical, completion) =
        complete_canonical_under_mutation_fence(client_config, &canonical).await?;
    reconcile_canonical_completion_result(client_config, &canonical, completion).await
}

pub async fn execute(
    client_config: &ClientConfig,
    wallet_name: &str,
    statechain_id: &str,
    to_address: &str,
    fee_rate: Option<f64>,
) -> Result<()> {
    // Canonical replay is journal-first. In particular, Signed/CloseArmed/Closed
    // rows remain actionable after valid Mercury deletion and never regenerate.
    let wallet = get_wallet(&client_config.pool, wallet_name).await?;
    let has_statechain_coin = wallet
        .coins
        .iter()
        .any(|coin| coin.statechain_id.as_deref() == Some(statechain_id));
    if !has_statechain_coin {
        return Err(anyhow!(
            "No coins associated with this statechain ID were found"
        ));
    }
    if !wallet
        .coins
        .iter()
        .any(|coin| coin.statechain_id.as_deref() == Some(statechain_id) && is_bip448_coin(coin))
    {
        return Err(anyhow!(
            "statechain {statechain_id} is not a BIP448 coin; BIP448 withdrawal requires an accepted BIP448 coin"
        ));
    }
    if let Some(attempt) =
        get_bip448_withdrawal_attempt(&client_config.pool, wallet_name, statechain_id, 0).await?
    {
        let record = get_bip448_statechain(&client_config.pool, wallet_name, statechain_id).await?;
        let binding =
            get_bip448_funding_binding(&client_config.pool, wallet_name, statechain_id, 0)
                .await?
                .ok_or_else(|| anyhow!("accepted BIP448 canonical funding binding is missing"))?;
        validate_attempt_invocation(&attempt, to_address, fee_rate)?;
        validate_attempt_identity(client_config, &wallet, &record, &binding, &attempt).await?;
        return drive_canonical_attempt(client_config, to_address, fee_rate, attempt).await;
    }

    // No-row preflight deliberately precedes every signing, wallet/activity,
    // broadcast, and completion side effect.
    let local_candidates = wallet
        .coins
        .iter()
        .filter(|coin| coin.statechain_id.as_deref() == Some(statechain_id) && is_bip448_coin(coin))
        .collect::<Vec<_>>();
    if let [only_candidate] = local_candidates.as_slice() {
        ensure_withdraw_status(&only_candidate.status)?;
    }

    let transfer_intents =
        list_bip448_transfer_intents(&client_config.pool, wallet_name, statechain_id).await?;
    if !transfer_intents.is_empty() {
        let gate =
            classify_bip448_close_gate(&client_config.pool, wallet_name, statechain_id).await?;
        return Err(anyhow!(
            "BIP448 canonical withdrawal is blocked by transfer intent state: {gate:?}"
        ));
    }
    if get_bip448_pending_transfer_signing(&client_config.pool, wallet_name, statechain_id)
        .await?
        .is_some()
    {
        return Err(anyhow!(
            "cancel or complete the in-flight transfer before withdrawing"
        ));
    }
    // Load before synchronization, but accepted-prefix cleanup is permitted
    // only after that synchronization succeeds.
    let _outgoing_messages =
        list_bip448_transfer_msg_raw_rows(&client_config.pool, wallet_name, statechain_id).await?;

    let sync = sync_bip448_funding_bindings_from_height_zero(client_config, wallet_name).await?;
    reconcile_bip448_accepted_local_outgoing_messages(
        &client_config.pool,
        wallet_name,
        statechain_id,
    )
    .await?;
    if has_bip448_transfer_msg_for_statechain(&client_config.pool, wallet_name, statechain_id)
        .await?
    {
        return Err(anyhow!(
            "outgoing BIP448 transfer message blocks canonical withdrawal"
        ));
    }

    let wallet = get_wallet(&client_config.pool, wallet_name).await?;
    let record = get_bip448_statechain(&client_config.pool, wallet_name, statechain_id).await?;
    let binding = get_bip448_funding_binding(&client_config.pool, wallet_name, statechain_id, 0)
        .await?
        .ok_or_else(|| anyhow!("accepted BIP448 canonical binding disappeared after rescan"))?;
    if let Some(attempt) =
        get_bip448_withdrawal_attempt(&client_config.pool, wallet_name, statechain_id, 0).await?
    {
        validate_attempt_invocation(&attempt, to_address, fee_rate)?;
        validate_attempt_identity(client_config, &wallet, &record, &binding, &attempt).await?;
        return drive_canonical_attempt(client_config, to_address, fee_rate, attempt).await;
    }
    let owner_coin = prove_attempt_owner(
        client_config,
        &wallet,
        &record,
        &binding,
        Bip448WithdrawalAttemptKind::Canonical,
        None,
    )
    .await?;
    ensure_withdraw_status(&owner_coin.status)?;
    require_canonical_coin_record_identity(&wallet, &owner_coin, &record)?;
    require_exact_confirmed_source(client_config, &binding)?;
    let closing_bindings_json = require_ready_close_gate(
        classify_bip448_close_gate(&client_config.pool, wallet_name, statechain_id).await?,
    )?;

    let fee_rate_sat_per_vbyte = match fee_rate {
        Some(fee_rate) => fee_rate,
        None => estimate_fee_rate_sats_per_byte(client_config)?.min(client_config.max_fee_rate),
    };
    let source = Bip448KeypathSpendSource {
        outpoint: OutPoint {
            txid: Txid::from_str(&binding.txid)?,
            vout: binding.vout,
        },
        value_sats: binding.value_sats,
        script_pubkey: ScriptBuf::from_bytes(hex::decode(&binding.script_pubkey)?),
    };
    let prepared = prepare_bip448_keypath_spend(
        &record.aggregate_pubkey,
        &source,
        to_address,
        client_config.network,
        fee_rate_sat_per_vbyte,
        sample_bip448_keypath_spend_lock_time(sync.tip_height),
    )?;
    let nonce = create_bip448_keypath_nonces(&owner_coin)?;
    let signing_id = hex::encode(SecretKey::new(&mut rand::rng()).to_secret_bytes());
    let signed_statechain_id = owner_coin
        .signed_statechain_id
        .clone()
        .ok_or_else(|| anyhow!("BIP448 canonical owner is missing signed_statechain_id"))?;
    let sign_first = Bip448SignFirstRequestPayload {
        statechain_id: statechain_id.to_owned(),
        signed_statechain_id: signed_statechain_id.clone(),
        signing_id: signing_id.clone(),
    };
    let owner_user_pubkey = PublicKey::from_str(&owner_coin.user_pubkey)?
        .x_only_public_key()
        .0
        .to_string();
    let attempt = Bip448WithdrawalAttempt {
        wallet_name: wallet_name.to_owned(),
        statechain_id: statechain_id.to_owned(),
        binding_index: 0,
        attempt_kind: Bip448WithdrawalAttemptKind::Canonical,
        owner_user_pubkey,
        owner_state_number: record.latest_state_number,
        source_txid: binding.txid.clone(),
        source_vout: binding.vout,
        source_value_sats: binding.value_sats,
        source_script_pubkey: binding.script_pubkey.clone(),
        destination_address: to_address.to_owned(),
        destination_script_pubkey: hex::encode(prepared.destination_script_pubkey.as_bytes()),
        fee_rate_sat_per_vbyte,
        fee_sats: prepared.fee_sats,
        lock_time: prepared.lock_time,
        unsigned_tx_hex: hex::encode(&prepared.unsigned_tx),
        signing_id,
        signed_statechain_id,
        sign_first_payload_json: serde_json::to_string(&sign_first)?,
        client_secret_nonce: nonce.secret_nonce,
        client_public_nonce: nonce.public_nonce,
        blinding_factor: nonce.blinding_factor,
        server_public_nonce: None,
        message_hex: None,
        output_pubkey: None,
        client_partial_sig: None,
        encoded_session: None,
        sign_second_payload_json: None,
        server_partial_sig: None,
        aggregate_signature: None,
        signed_tx_hex: None,
        txid: None,
        phase: Bip448WithdrawalPhase::Prepared,
        broadcast_status: Bip448BroadcastStatus::NotBroadcast,
        completion_status: Bip448CompletionStatus::Open,
        closing_tip_height: Some(sync.tip_height),
        closing_tip_hash: Some(sync.tip_hash.clone()),
        closing_bindings_json: Some(closing_bindings_json),
        created_at: String::new(),
        updated_at: String::new(),
    };

    let mut guard = begin_bip448_mutation_guard(&client_config.pool).await?;
    require_exact_confirmed_source(client_config, &binding)?;
    let live_tip_height = client_config.chain_client.tip_height()?;
    let live_tip_hash = client_config
        .chain_client
        .get_block_hash(live_tip_height)?
        .to_string();
    if live_tip_height != sync.tip_height || live_tip_hash != sync.tip_hash {
        return Err(anyhow!(
            "BIP448 canonical close chain tip changed before Prepared persistence"
        ));
    }
    let expected = guard
        .withdrawal_signature_count_expectation(wallet_name, statechain_id)
        .await?;
    let actual = bip448_signature_count(client_config, statechain_id).await?;
    if actual != expected.settled_count || expected.second_armed_landed_count.is_some() {
        return Err(anyhow!(
            "BIP448 lockbox signature count is {actual}, expected {} before canonical close",
            expected.settled_count
        ));
    }
    let persisted = guard.insert_withdrawal_attempt_if_absent(&attempt).await?;
    guard.commit().await?;
    bip448_process_checkpoint("attempt_prepared");
    drive_canonical_attempt(client_config, to_address, fee_rate, persisted).await
}

fn ensure_withdraw_status(status: &CoinStatus) -> Result<()> {
    if *status != CoinStatus::CONFIRMED {
        return Err(anyhow!(
            "Coin status must be CONFIRMED to begin canonical withdrawal. The current status is {}",
            status
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;
    use mercurylib::wallet::{Settings, Wallet};
    use sqlx::sqlite::SqlitePoolOptions;

    use crate::{
        chain::{ChainClient, CoreRpcAuth, CoreRpcConfig},
        sqlite_manager::{insert_wallet, update_wallet},
    };

    fn wallet(protocol: Option<&str>) -> Wallet {
        let mut wallet = Wallet {
            name: "wallet".into(), mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into(), version: "0.1.0".into(),
            state_entity_endpoint: "http://127.0.0.1:1".into(), chain_backend: "core".into(), chain_endpoint: "http://127.0.0.1:1".into(), network: "regtest".into(),
            blockheight: 0, activities: Vec::new(), coins: Vec::new(),
            settings: Settings { network: "regtest".into(), block_explorerURL: None, torProxyHost: None, torProxyPort: None, torProxyControlPassword: None, torProxyControlPort: None, statechainEntityApi: "http://127.0.0.1:1".into(), torStatechainEntityApi: None, chainBackend: "core".into(), chainUrl: "http://127.0.0.1:1".into(), chainType: None, notifications: false, tutorials: false },
        };
        let mut coin = wallet.get_new_coin().unwrap();
        coin.statechain_id = Some("statechain".into());
        coin.statechain_protocol = protocol.map(str::to_owned);
        coin.status = CoinStatus::CONFIRMED;
        wallet.coins.push(coin);
        wallet
    }

    async fn config() -> Result<ClientConfig> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        let url = "http://127.0.0.1:1";
        Ok(ClientConfig {
            statechain_entity: url.into(),
            chain_backend: "core".into(),
            chain_client: ChainClient::new(CoreRpcConfig {
                url: url.into(),
                auth: CoreRpcAuth::None,
            })?,
            core_rpc_url: Some(url.into()),
            core_rpc_auth: Some("none".into()),
            core_rpc_user: None,
            core_rpc_password: None,
            core_rpc_cookie_file: None,
            network: Network::Regtest,
            fee_rate_tolerance: 0.0,
            confirmation_target: 1,
            pool,
            tor_proxy: None,
            max_fee_rate: 10.0,
        })
    }

    #[test]
    fn require_statechain_deleted_accepts_exact_envelope() {
        assert!(require_statechain_deleted(r#"{"message":"Statechain deleted."}"#).is_ok());
    }

    #[test]
    fn require_statechain_deleted_rejects_plain_text_counterexample() {
        let error = require_statechain_deleted("Statechain deleted.").unwrap_err();
        assert_eq!(error.to_string(), UNEXPECTED_COMPLETION_RESPONSE);
    }

    #[test]
    fn require_statechain_deleted_rejects_json_without_string_message() {
        let error = require_statechain_deleted(r#"{"status":"deleted"}"#).unwrap_err();
        assert_eq!(error.to_string(), UNEXPECTED_COMPLETION_RESPONSE);
    }

    #[test]
    fn require_statechain_deleted_rejects_different_message() {
        let error =
            require_statechain_deleted(r#"{"message":"Statechain retained."}"#).unwrap_err();
        assert_eq!(error.to_string(), UNEXPECTED_COMPLETION_RESPONSE);
    }

    #[test]
    fn selected_owner_status_gate_remains_operation_specific() {
        assert!(ensure_withdraw_status(&CoinStatus::CONFIRMED).is_ok());
        assert!(ensure_withdraw_status(&CoinStatus::IN_TRANSFER).is_err());
        assert!(ensure_withdraw_status(&CoinStatus::INITIALISED).is_err());
    }

    #[tokio::test]
    async fn protocol_and_pending_transfer_guards_precede_signing() -> Result<()> {
        let config = config().await?;
        let mut wallet = wallet(None);
        insert_wallet(&config.pool, &wallet).await?;
        let error = execute(&config, "wallet", "statechain", "unused", None)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "statechain statechain is not a BIP448 coin; BIP448 withdrawal requires an accepted BIP448 coin");

        wallet.coins[0].statechain_protocol = Some("bip448".into());
        update_wallet(&config.pool, &wallet).await?;

        sqlx::query("INSERT INTO bip448_pending_transfer_signings (wallet_name,statechain_id,funding_txid,funding_vout,funding_value_sats,update_template_hash,settlement_template_hash,state_locktime,signing_id,client_secret_nonce,client_public_nonce,blinding_factor) VALUES ('wallet','statechain','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',0,50000,'aa','bb',700000000,'cc','dd','ee','ff')").execute(&config.pool).await?;
        let error = execute(&config, "wallet", "statechain", "unused", None)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "cancel or complete the in-flight transfer before withdrawing"
        );
        Ok(())
    }
}
