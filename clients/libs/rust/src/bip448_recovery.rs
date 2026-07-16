use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use bitcoin::{consensus::encode, Address, OutPoint, Txid};
use mercurylib::bip448_statechain::{
    package::{build_latest_state_recovery_package, Bip448CpfpFeeInput},
    storage::Bip448RecoveryTemplateRole,
};
use serde::Serialize;
use serde_json::Value;

use crate::{client_config::ClientConfig, sqlite_manager::get_bip448_statechain};

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
