use std::str::FromStr;

use anyhow::{anyhow, Result};
use bitcoin::{OutPoint, ScriptBuf, Txid};
use mercurylib::{
    bip448_statechain::{
        deposit::is_bip448_coin,
        script::{funding_spend_info, output_script_pubkey},
        signing_api::Bip448PartialSignatureRequestPayload,
        storage::Bip448StatechainRecord,
        withdraw::{Bip448KeypathSpendSource, Bip448PreparedKeypathSpend},
    },
    wallet::{Coin, CoinStatus, Wallet},
};
use secp256k1::{PublicKey, Secp256k1};

use crate::{
    bip448_funding::{
        self, Bip448BindingRole, Bip448BroadcastStatus, Bip448FundingBinding,
        Bip448ObservationStatus, Bip448OwnershipStatus, Bip448WithdrawalAttempt,
        Bip448WithdrawalAttemptKind, Bip448WithdrawalPhase,
    },
    bip448_owner::get_current_bip448_owner,
    client_config::ClientConfig,
    deposit::bip448_signature_count,
    sqlite_manager::{
        bip448_expected_signature_count, get_active_bip448_transfer_intent,
        get_bip448_pending_transfer_signing, get_bip448_state_history,
        has_bip448_transfer_msg_for_statechain,
    },
};

const UNEXPECTED_COMPLETION_RESPONSE: &str =
    "BIP448 withdraw completion returned an unexpected response";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum AttemptSourceState {
    ExactConfirmed,
    Wait(String),
    ConfirmedConflict(String),
}

pub(super) fn binding_outpoint(binding: &Bip448FundingBinding) -> String {
    format!("{}:{}", binding.txid, binding.vout)
}

fn accepted_funding_script(record: &Bip448StatechainRecord) -> Result<ScriptBuf> {
    let aggregate = PublicKey::from_str(&record.aggregate_pubkey)?;
    let spend_info = funding_spend_info(&Secp256k1::new(), aggregate.x_only_public_key().0)?;
    Ok(output_script_pubkey(&spend_info))
}

pub(super) fn require_attempt_binding(
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

pub(super) fn require_exact_confirmed_source(
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

pub(super) async fn validate_attempt_identity(
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

pub(super) fn validate_attempt_invocation(
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

pub(super) async fn prove_attempt_owner(
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

pub(super) async fn require_no_local_transfer(
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

pub(super) fn require_prior_attempt_policy(attempts: &[Bip448WithdrawalAttempt]) -> Result<()> {
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

pub(super) fn attempt_source_state(
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

pub(super) fn source_and_prepared(
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

pub(super) fn validated_sign_second_request(
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

pub(super) async fn require_count_before_signing(
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

pub(super) async fn require_count_after_signing(
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

pub(super) fn require_statechain_deleted(body: &str) -> Result<()> {
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|_| anyhow!("{UNEXPECTED_COMPLETION_RESPONSE}"))?;
    if value.get("message").and_then(serde_json::Value::as_str) != Some("Statechain deleted.") {
        return Err(anyhow!("{UNEXPECTED_COMPLETION_RESPONSE}"));
    }
    Ok(())
}

pub(super) fn ensure_withdraw_status(status: &CoinStatus) -> Result<()> {
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
}
