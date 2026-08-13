use std::str::FromStr;

use anyhow::{anyhow, Result};
use bitcoin::{OutPoint, ScriptBuf, Txid};
use mercurylib::bip448_statechain::{
    deposit::is_bip448_coin,
    signing_api::Bip448SignFirstRequestPayload,
    withdraw::{
        create_bip448_keypath_nonces, prepare_bip448_keypath_spend,
        sample_bip448_keypath_spend_lock_time, Bip448KeypathSpendSource,
    },
};
use secp256k1::{rand, PublicKey, SecretKey};
use serde::Serialize;

use crate::{
    bip448_funding::{
        Bip448BroadcastStatus, Bip448CompletionStatus, Bip448WithdrawalAttempt,
        Bip448WithdrawalAttemptKind, Bip448WithdrawalPhase,
    },
    client_config::ClientConfig,
    coin_status::sync_bip448_funding_bindings,
    deposit::bip448_signature_count,
    sqlite_manager::{
        begin_bip448_mutation_guard, get_bip448_funding_binding, get_bip448_statechain,
        get_bip448_withdrawal_attempt, get_wallet,
    },
    utils::estimate_fee_rate_sats_per_byte,
};

use super::{
    driver::{bip448_process_checkpoint, drive_duplicate_attempt},
    policy::{
        binding_outpoint, prove_attempt_owner, require_attempt_binding,
        require_exact_confirmed_source, require_no_local_transfer, require_prior_attempt_policy,
        validate_attempt_identity, validate_attempt_invocation,
    },
};

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

pub(super) fn duplicate_sweep_result(
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
