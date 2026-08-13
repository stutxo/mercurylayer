use anyhow::{anyhow, Result};
use bitcoin::Transaction;
use mercurylib::{
    bip448_statechain::{
        signing_api::{Bip448PartialSignatureRequestPayload, Bip448SignFirstRequestPayload},
        storage::Bip448StatechainRecord,
        withdraw::{
            aggregate_bip448_keypath_signature, build_bip448_keypath_spend_signing_data,
            finalize_bip448_keypath_transaction,
        },
    },
    wallet::Wallet,
};

use crate::{
    bip448_funding::{
        self, Bip448BroadcastStatus, Bip448ClosingResolution, Bip448FundingBinding,
        Bip448ObservationStatus, Bip448WithdrawalAttempt, Bip448WithdrawalAttemptKind,
        Bip448WithdrawalPhase,
    },
    chain::{broadcast_or_reconcile_transaction, BroadcastTxStatus},
    client_config::ClientConfig,
    coin_status::sync_bip448_funding_bindings,
    deposit::{bip448_sign_first, bip448_sign_second},
    sqlite_manager::{
        arm_bip448_withdrawal_sign_first, arm_bip448_withdrawal_sign_second,
        delete_prepared_bip448_withdrawal_attempt_for_confirmed_spend, get_bip448_funding_binding,
        get_bip448_statechain, get_bip448_withdrawal_attempt, get_wallet,
        store_bip448_withdrawal_nonce_artifacts, store_bip448_withdrawal_signed_artifacts,
        transition_bip448_withdrawal_broadcast_status, validate_bip448_canonical_close_snapshot,
    },
};

use super::{
    duplicate::{duplicate_sweep_result, Bip448DuplicateSweepResult},
    policy::{
        attempt_source_state, binding_outpoint, prove_attempt_owner, require_count_after_signing,
        require_count_before_signing, require_exact_confirmed_source, source_and_prepared,
        validate_attempt_identity, validate_attempt_invocation, validated_sign_second_request,
        AttemptSourceState,
    },
};

#[cfg(feature = "test-hooks")]
pub(super) fn bip448_process_checkpoint(checkpoint: &str) {
    if std::env::var("ML_BIP448_RESTART_CHILD").as_deref() == Ok("1")
        && std::env::var("ML_BIP448_TEST_CHECKPOINT").as_deref() == Ok(checkpoint)
    {
        std::process::exit(86);
    }
}

#[cfg(not(feature = "test-hooks"))]
pub(super) fn bip448_process_checkpoint(_checkpoint: &str) {}

pub(super) async fn refresh_withdrawal_attempt(
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

pub(super) async fn broadcast_signed_attempt(
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

pub(super) async fn reconcile_and_validate_frozen_snapshot(
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

pub(super) async fn drive_duplicate_attempt(
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

pub(super) async fn drive_withdrawal_attempt(
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
