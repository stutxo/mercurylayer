use std::str::FromStr;

use anyhow::Result;
use mercurylib::wallet::{Coin, Wallet};

use crate::{
    bip448_funding::{
        Bip448BindingRole, Bip448FundingBinding, Bip448ObservationStatus, Bip448OwnershipStatus,
        Bip448WithdrawalAttempt, Bip448WithdrawalPhase,
    },
    client_config::ClientConfig,
    sqlite_manager::list_bip448_funding_bindings,
};

pub fn statecoin_list_entry_json(
    wallet_name: &str,
    coin: &Coin,
    bindings: &[Bip448FundingBinding],
    attempts: &[Bip448WithdrawalAttempt],
) -> Result<serde_json::Value> {
    let owner = secp256k1::PublicKey::from_str(&coin.user_pubkey)?
        .x_only_public_key()
        .0
        .to_string();
    let statechain_id = coin.statechain_id.as_deref();
    let mut owned_attempts = attempts
        .iter()
        .filter(|attempt| {
            attempt.wallet_name == wallet_name
                && Some(attempt.statechain_id.as_str()) == statechain_id
                && attempt.owner_user_pubkey == owner
        })
        .collect::<Vec<_>>();
    owned_attempts.sort_by_key(|attempt| attempt.binding_index);
    let canonical_attempt = owned_attempts
        .iter()
        .copied()
        .find(|attempt| attempt.binding_index == 0);
    let address_retired = canonical_attempt.is_some();
    let exit_only = owned_attempts.iter().any(|attempt| {
        matches!(
            attempt.phase,
            Bip448WithdrawalPhase::SecondArmed | Bip448WithdrawalPhase::Signed
        )
    });
    let mut duplicates = bindings
        .iter()
        .filter(|binding| {
            binding.wallet_name == wallet_name
                && Some(binding.statechain_id.as_str()) == statechain_id
                && binding.owner_user_pubkey == owner
                && binding.role == Bip448BindingRole::Duplicate
        })
        .collect::<Vec<_>>();
    duplicates.sort_by_key(|binding| binding.binding_index);
    let duplicates = duplicates
        .into_iter()
        .map(|binding| {
            let attempt = owned_attempts
                .iter()
                .copied()
                .find(|attempt| attempt.binding_index == binding.binding_index);
            let durable_signed =
                attempt.is_some_and(|attempt| attempt.phase == Bip448WithdrawalPhase::Signed);
            let independently_confirmed =
                binding.observation_status == Bip448ObservationStatus::SpentConfirmed;
            let cooperative_only = !durable_signed && !independently_confirmed;
            let server_dependent = cooperative_only
                && binding.ownership_status == Bip448OwnershipStatus::Current
                && !address_retired;
            serde_json::json!({
                "duplicate_index": binding.binding_index,
                "txid": binding.txid,
                "vout": binding.vout,
                "amount_sats": binding.value_sats,
                "observation_status": binding.observation_status.to_string(),
                "sweep_phase": attempt.map(|attempt| attempt.phase.to_string()),
                "broadcast_status": attempt.map(|attempt| attempt.broadcast_status.to_string()),
                "ownership_status": binding.ownership_status.to_string(),
                "spend_txid": binding.spend_txid,
                "cooperative_only": cooperative_only,
                "server_dependent": server_dependent,
            })
        })
        .collect::<Vec<_>>();
    Ok(serde_json::json!({
        "coin.user_pubkey": coin.user_pubkey,
        "coin.aggregated_address": coin.aggregated_address.as_deref().unwrap_or(""),
        "coin.address": coin.address,
        "coin.statechain_id": coin.statechain_id.as_deref().unwrap_or(""),
        "coin.amount": coin.amount.unwrap_or(0),
        "coin.status": coin.status,
        "coin.locktime": coin.locktime.unwrap_or(0),
        "coin.statechain_protocol": coin.statechain_protocol,
        "coin.utxo_txid": coin.utxo_txid,
        "coin.utxo_vout": coin.utxo_vout,
        "coin.exit_only": exit_only,
        "coin.address_retired": address_retired,
        "coin.close_tip_height": canonical_attempt.and_then(|attempt| attempt.closing_tip_height),
        "coin.close_tip_hash": canonical_attempt.and_then(|attempt| attempt.closing_tip_hash.as_deref()),
        "coin.duplicates": duplicates,
    }))
}

pub async fn statecoin_list_json(
    client_config: &ClientConfig,
    wallet: &Wallet,
) -> Result<Vec<serde_json::Value>> {
    let mut result = Vec::with_capacity(wallet.coins.len());
    for coin in &wallet.coins {
        let (bindings, attempts) = match coin.statechain_id.as_deref() {
            Some(statechain_id) => (
                list_bip448_funding_bindings(&client_config.pool, &wallet.name, statechain_id)
                    .await?,
                crate::sqlite_manager::list_bip448_withdrawal_attempts(
                    &client_config.pool,
                    &wallet.name,
                    statechain_id,
                )
                .await?,
            ),
            None => (Vec::new(), Vec::new()),
        };
        result.push(statecoin_list_entry_json(
            &wallet.name,
            coin,
            &bindings,
            &attempts,
        )?);
    }
    Ok(result)
}
