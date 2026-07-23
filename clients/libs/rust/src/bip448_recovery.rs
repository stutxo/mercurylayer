use std::{error::Error, fmt, str::FromStr};

use anyhow::{anyhow, Context, Result};
use bitcoin::{consensus::encode, Address, OutPoint, Txid};
use mercurylib::bip448_statechain::{
    package::{
        build_latest_state_recovery_package, fee_signing::sign_cpfp_fee_inputs, Bip448CpfpFeeInput,
        Bip448PackageError,
    },
    storage::Bip448RecoveryTemplateRole,
};
use serde::Serialize;
use serde_json::Value;

use crate::{
    chain::ChainUtxo,
    client_config::ClientConfig,
    coin_status::discover_unspent,
    sqlite_manager::{get_bip448_statechain, get_wallet},
};

const FEE_INPUT_SIZING_VALUE_SATS: u64 = 21_000_000u64 * 100_000_000;

#[derive(Debug, Clone, Serialize)]
pub struct Bip448RecoveryPackageSubmission {
    pub statechain_id: String,
    pub role: String,
    pub parent_txid: String,
    pub cpfp_child_txid: String,
    pub package_fee_sats: u64,
    pub package_vbytes: usize,
    pub package_feerate_sat_per_vbyte: f64,
    pub submitpackage_response: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip448InsufficientRecoveryFeeFunds {
    pub required_sats: u64,
    pub available_sats: u64,
}

impl fmt::Display for Bip448InsufficientRecoveryFeeFunds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "insufficient confirmed BIP448 recovery fee funds: required {} sats, available {} sats",
            self.required_sats, self.available_sats
        )
    }
}

impl Error for Bip448InsufficientRecoveryFeeFunds {}

fn select_confirmed_fee_inputs<T>(
    mut candidates: Vec<ChainUtxo>,
    minimum_required_sats: u64,
    change_dust_sats: u64,
    mut build: impl FnMut(&[Bip448CpfpFeeInput]) -> std::result::Result<T, Bip448PackageError>,
) -> Result<(Vec<Bip448CpfpFeeInput>, T)> {
    candidates.retain(|candidate| candidate.height > 0);
    candidates.sort_by(|a, b| {
        b.value
            .cmp(&a.value)
            .then_with(|| a.txid.cmp(&b.txid))
            .then_with(|| a.vout.cmp(&b.vout))
    });
    let available_sats = candidates.iter().map(|candidate| candidate.value).sum();
    let mut required_sats = minimum_required_sats;
    let mut selected_value_sats = 0u64;
    let mut selected = Vec::new();

    for candidate in candidates {
        let txid = Txid::from_str(&candidate.txid).with_context(|| {
            format!(
                "invalid discovered BIP448 fee input txid {}",
                candidate.txid
            )
        })?;
        selected_value_sats += candidate.value;
        selected.push(Bip448CpfpFeeInput::signed(
            OutPoint {
                txid,
                vout: candidate.vout,
            },
            candidate.value,
        ));

        match build(&selected) {
            Ok(package) => return Ok((selected, package)),
            Err(Bip448PackageError::FeeExceedsFeeInputs { fee_sats, .. }) => {
                required_sats = fee_sats.saturating_add(change_dust_sats);
            }
            Err(Bip448PackageError::ChangeWouldBeDust {
                value_sats,
                dust_sats,
            }) => {
                required_sats = selected_value_sats
                    .saturating_sub(value_sats)
                    .saturating_add(dust_sats)
                    .max(minimum_required_sats);
            }
            Err(error) => return Err(error.into()),
        }
    }

    Err(Bip448InsufficientRecoveryFeeFunds {
        required_sats,
        available_sats,
    }
    .into())
}

pub async fn submit_wallet_funded_latest_state_recovery_package(
    client_config: &ClientConfig,
    wallet_name: &str,
    statechain_id: &str,
    role: Bip448RecoveryTemplateRole,
    change_address: Option<&str>,
    fee_rate: Option<f64>,
) -> Result<Bip448RecoveryPackageSubmission> {
    let wallet = get_wallet(&client_config.pool, wallet_name).await?;
    let fee_key = wallet.bip448_recovery_fee_key()?;
    let change_address = change_address
        .map(str::to_owned)
        .unwrap_or_else(|| fee_key.address.to_string());
    let change_script_pubkey = Address::from_str(&change_address)
        .with_context(|| format!("invalid BIP448 CPFP change address {change_address}"))?
        .require_network(client_config.network)
        .with_context(|| {
            format!(
                "BIP448 CPFP change address {change_address} is not valid for {:?}",
                client_config.network
            )
        })?
        .script_pubkey();
    let fee_rate = match fee_rate {
        Some(fee_rate) => fee_rate,
        None => client_config.chain_client.estimate_fee_sat_per_vbyte(1)?,
    };
    let record = get_bip448_statechain(&client_config.pool, wallet_name, statechain_id).await?;

    let sizing_input = [Bip448CpfpFeeInput::signed(
        OutPoint::null(),
        FEE_INPUT_SIZING_VALUE_SATS,
    )];
    let sizing_package = build_latest_state_recovery_package(
        &record,
        role,
        &sizing_input,
        change_script_pubkey.clone(),
        fee_rate,
    )?;
    let change_dust_sats = change_script_pubkey.dust_value().to_sat();
    let minimum_required_sats = FEE_INPUT_SIZING_VALUE_SATS
        .saturating_sub(sizing_package.cpfp_child_tx.output[0].value)
        .saturating_add(change_dust_sats);

    let candidates =
        discover_unspent(client_config, wallet_name, &fee_key.address, wallet.blockheight).await?;
    let (mut fee_inputs, mut package) = select_confirmed_fee_inputs(
        candidates,
        minimum_required_sats,
        change_dust_sats,
        |fee_inputs| {
            build_latest_state_recovery_package(
                &record,
                role,
                fee_inputs,
                change_script_pubkey.clone(),
                fee_rate,
            )
        },
    )?;
    sign_cpfp_fee_inputs(
        &mut package,
        &fee_inputs,
        &fee_key.address.script_pubkey(),
        &fee_key.secret_key,
    )?;
    for (fee_input, child_input) in fee_inputs
        .iter_mut()
        .zip(package.cpfp_child_tx.input.iter().skip(1))
    {
        fee_input.witness = child_input.witness.clone();
    }

    submit_latest_state_recovery_package(
        client_config,
        wallet_name,
        statechain_id,
        role,
        &fee_inputs,
        &change_address,
        Some(fee_rate),
    )
    .await
}

pub async fn submit_latest_state_recovery_package(
    client_config: &ClientConfig,
    wallet_name: &str,
    statechain_id: &str,
    role: Bip448RecoveryTemplateRole,
    fee_inputs: &[Bip448CpfpFeeInput],
    change_address: &str,
    fee_rate: Option<f64>,
) -> Result<Bip448RecoveryPackageSubmission> {
    let record = get_bip448_statechain(&client_config.pool, wallet_name, statechain_id).await?;
    let change_script_pubkey = Address::from_str(change_address)
        .with_context(|| format!("invalid BIP448 CPFP change address {change_address}"))?
        .require_network(client_config.network)
        .with_context(|| {
            format!(
                "BIP448 CPFP change address {change_address} is not valid for {:?}",
                client_config.network
            )
        })?
        .script_pubkey();
    let fee_rate = match fee_rate {
        Some(fee_rate) => fee_rate,
        // Recovery is deadline-bound: the zero-fee U/S parent pays no fee itself
        // and relies entirely on its CPFP child, so the package must confirm
        // within `challenge_delay` blocks or a stale-state counterparty can win
        // the challenge window. Unlike a routine withdrawal, do NOT clamp the
        // estimate down to `max_fee_rate` — pay the estimated feerate so the
        // package confirms in time. Callers can pin an exact rate via `fee_rate`.
        None => client_config.chain_client.estimate_fee_sat_per_vbyte(1)?,
    };

    let package = build_latest_state_recovery_package(
        &record,
        role,
        fee_inputs,
        change_script_pubkey,
        fee_rate,
    )?;
    let txs = package
        .transactions()
        .into_iter()
        .map(encode::serialize)
        .collect::<Vec<_>>();
    let response = client_config.chain_client.submit_package(&txs)?;

    if !package_response_is_success(&response, txs.len()) {
        return Err(anyhow!(
            "Bitcoin Core submitpackage did not accept BIP448 {} package: {}",
            role.as_str(),
            response
        ));
    }

    Ok(Bip448RecoveryPackageSubmission {
        statechain_id: record.statechain_id,
        role: role.as_str().to_string(),
        parent_txid: package.parent_tx.txid().to_string(),
        cpfp_child_txid: package.cpfp_child_tx.txid().to_string(),
        package_fee_sats: package.package_fee_sats,
        package_vbytes: package.package_vbytes,
        package_feerate_sat_per_vbyte: package.package_feerate_sat_per_vbyte,
        submitpackage_response: response,
    })
}

pub fn parse_recovery_template_role(role: &str) -> Result<Bip448RecoveryTemplateRole> {
    let normalized = role.trim().to_ascii_lowercase();

    match normalized.as_str() {
        "funding_update" | "update" | "u" | "u1" => {
            Ok(Bip448RecoveryTemplateRole::FundingUpdate)
        }
        "settlement" | "s" | "s1" => Ok(Bip448RecoveryTemplateRole::Settlement),
        other => Err(anyhow!(
            "unsupported BIP448 recovery package role {other}; expected funding_update or settlement"
        )),
    }
}

pub fn parse_keyless_p2a_fee_input(input: &str) -> Result<Bip448CpfpFeeInput> {
    let parts = input.split(':').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(anyhow!(
            "invalid BIP448 fee input {input}; expected txid:vout:value_sats"
        ));
    }

    let txid = Txid::from_str(parts[0])
        .with_context(|| format!("invalid BIP448 fee input txid {}", parts[0]))?;
    let vout = parts[1]
        .parse::<u32>()
        .with_context(|| format!("invalid BIP448 fee input vout {}", parts[1]))?;
    let value_sats = parts[2]
        .parse::<u64>()
        .with_context(|| format!("invalid BIP448 fee input value_sats {}", parts[2]))?;

    Ok(Bip448CpfpFeeInput::keyless(
        OutPoint { txid, vout },
        value_sats,
    ))
}

fn package_response_is_success(response: &Value, expected_transaction_count: usize) -> bool {
    if response.get("package_msg").and_then(Value::as_str) == Some("success") {
        return true;
    }

    // An idempotent resubmission of an already-accepted package reports a
    // non-"success" package_msg while every transaction result indicates the tx
    // is already known / in the mempool or chain. Treat that as success so a
    // recovery retry does not fail on an already-broadcast package.
    response
        .get("tx-results")
        .and_then(Value::as_object)
        .map(|results| {
            results.len() == expected_transaction_count
                && results.values().all(|result| {
                    result
                        .get("error")
                        .and_then(Value::as_str)
                        .map_or(true, tx_error_is_already_known)
                })
        })
        .unwrap_or(false)
}

fn tx_error_is_already_known(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    error.contains("already in block chain")
        || error.contains("already-in-mempool")
        || error.contains("txn-already-known")
        || error.contains("txn-already-in-mempool")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn chain_utxo(txid_byte: &str, vout: u32, value: u64, height: u32) -> ChainUtxo {
        ChainUtxo {
            txid: txid_byte.repeat(32),
            vout,
            value,
            height,
        }
    }

    fn package_if_funded(
        fee_inputs: &[Bip448CpfpFeeInput],
    ) -> std::result::Result<(), Bip448PackageError> {
        const FEE_SATS: u64 = 11_500;
        const DUST_SATS: u64 = 500;
        let input_value_sats = fee_inputs.iter().map(|input| input.value_sats).sum();
        if input_value_sats < FEE_SATS {
            return Err(Bip448PackageError::FeeExceedsFeeInputs {
                fee_sats: FEE_SATS,
                input_value_sats,
            });
        }
        let value_sats = input_value_sats - FEE_SATS;
        if value_sats < DUST_SATS {
            return Err(Bip448PackageError::ChangeWouldBeDust {
                value_sats,
                dust_sats: DUST_SATS,
            });
        }
        Ok(())
    }

    #[test]
    fn confirmed_fee_inputs_are_selected_deterministically() {
        let candidates = vec![
            chain_utxo("22", 0, 7_000, 2),
            chain_utxo("11", 3, 7_000, 3),
            chain_utxo("00", 0, 9_000, 0),
            chain_utxo("44", 0, 5_000, 4),
            chain_utxo("11", 1, 7_000, 1),
        ];

        let (selected, ()) =
            select_confirmed_fee_inputs(candidates, 12_000, 500, package_if_funded).unwrap();

        assert_eq!(selected.len(), 2);
        assert_eq!(
            selected[0].previous_output.txid.to_string(),
            "11".repeat(32)
        );
        assert_eq!(selected[0].previous_output.vout, 1);
        assert_eq!(
            selected[1].previous_output.txid.to_string(),
            "11".repeat(32)
        );
        assert_eq!(selected[1].previous_output.vout, 3);
    }

    #[test]
    fn insufficient_fee_funds_report_required_and_confirmed_available() {
        let candidates = vec![
            chain_utxo("11", 0, 7_000, 1),
            chain_utxo("22", 0, 4_800, 2),
            chain_utxo("00", 0, 50_000, 0),
        ];

        let error =
            select_confirmed_fee_inputs(candidates, 12_000, 500, package_if_funded).unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<Bip448InsufficientRecoveryFeeFunds>()
                .unwrap(),
            &Bip448InsufficientRecoveryFeeFunds {
                required_sats: 12_000,
                available_sats: 11_800,
            }
        );
    }

    #[test]
    fn dust_only_insufficient_funds_preserve_package_minimum() {
        const MINIMUM_REQUIRED_SATS: u64 = 796;
        const P2PKH_DUST_SATS: u64 = 546;
        let candidates = vec![chain_utxo("11", 0, 330, 1)];

        let error = select_confirmed_fee_inputs(
            candidates,
            MINIMUM_REQUIRED_SATS,
            P2PKH_DUST_SATS,
            |fee_inputs| {
                Err::<(), _>(Bip448PackageError::ChangeWouldBeDust {
                    value_sats: fee_inputs.iter().map(|input| input.value_sats).sum(),
                    dust_sats: P2PKH_DUST_SATS,
                })
            },
        )
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<Bip448InsufficientRecoveryFeeFunds>(),
            Some(&Bip448InsufficientRecoveryFeeFunds {
                required_sats: MINIMUM_REQUIRED_SATS,
                available_sats: 330,
            })
        );
    }

    #[test]
    fn success_package_msg_is_accepted() {
        assert!(package_response_is_success(
            &json!({ "package_msg": "success" }),
            2,
        ));
    }

    #[test]
    fn already_known_resubmission_is_accepted() {
        // Idempotent resubmit: every tx is already in the mempool or chain.
        assert!(package_response_is_success(
            &json!({
                "package_msg": "transaction failed",
                "tx-results": {
                    "wtxid-a": { "txid": "a", "error": "txn-already-in-mempool" },
                    "wtxid-b": { "txid": "b", "error": "Transaction already in block chain" }
                }
            }),
            2,
        ));
    }

    #[test]
    fn genuine_failure_is_rejected() {
        assert!(!package_response_is_success(
            &json!({
                "package_msg": "transaction failed",
                "tx-results": {
                    "wtxid-a": { "txid": "a", "error": "txn-already-in-mempool" },
                    "wtxid-b": { "txid": "b", "error": "insufficient fee" }
                }
            }),
            2,
        ));
    }

    #[test]
    fn non_success_without_tx_results_is_rejected() {
        assert!(!package_response_is_success(
            &json!({ "package_msg": "transaction failed" }),
            2,
        ));
    }

    #[test]
    fn non_success_requires_a_complete_result_for_every_expected_transaction() {
        assert!(package_response_is_success(
            &json!({
                "package_msg": "transaction failed",
                "tx-results": {
                    "wtxid-a": { "txid": "a", "error": "txn-already-in-mempool" },
                    "wtxid-b": { "txid": "b" }
                }
            }),
            2,
        ));
        assert!(!package_response_is_success(
            &json!({
                "package_msg": "transaction failed",
                "tx-results": {
                    "wtxid-a": { "txid": "a", "error": "txn-already-in-mempool" }
                }
            }),
            2,
        ));
    }

    #[test]
    fn parses_supported_recovery_roles() {
        assert_eq!(
            parse_recovery_template_role("funding_update").unwrap(),
            Bip448RecoveryTemplateRole::FundingUpdate
        );
        assert_eq!(
            parse_recovery_template_role("update").unwrap(),
            Bip448RecoveryTemplateRole::FundingUpdate
        );
        assert_eq!(
            parse_recovery_template_role("settlement").unwrap(),
            Bip448RecoveryTemplateRole::Settlement
        );
        assert!(parse_recovery_template_role("state_update").is_err());
    }

    #[test]
    fn parses_keyless_p2a_fee_input_descriptor() {
        let fee_input =
            parse_keyless_p2a_fee_input(&format!("{}:2:3000", "11".repeat(32))).unwrap();

        assert_eq!(fee_input.previous_output.vout, 2);
        assert_eq!(fee_input.value_sats, 3_000);
        assert_eq!(fee_input.script_sig.len(), 0);
        assert_eq!(fee_input.witness.len(), 0);
    }

    #[test]
    fn rejects_malformed_fee_input_descriptor() {
        assert!(parse_keyless_p2a_fee_input("txid:0").is_err());
        assert!(
            parse_keyless_p2a_fee_input(&format!("{}:not-vout:3000", "11".repeat(32))).is_err()
        );
    }
}
