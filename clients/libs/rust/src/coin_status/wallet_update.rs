use std::collections::HashMap;
use std::str::FromStr;

use anyhow::{anyhow, Result};
use bitcoin::{Address, ScriptBuf, Txid};
use mercurylib::{
    bip448_statechain::{
        deposit::{self as bip448_deposit, Bip448DepositError},
        storage::Bip448StatechainRecord,
    },
    wallet::{Activity, Coin, CoinStatus, Wallet},
};

use super::{
    discovery::sort_chain_utxos,
    sync::{
        accepted_bip448_statechain_ids, reconcile_bip448_post_sync_transfer_artifacts,
        sync_bip448_funding_bindings_with_candidates,
    },
};
use crate::{
    bip448_owner::{
        classify_bip448_owner_relation, get_bip448_statechain_presence, Bip448OwnerRelation,
        Bip448StatechainPresence,
    },
    chain::ChainUtxo,
    client_config::ClientConfig,
    deposit::create_bip448_deposit_state,
    sqlite_manager::{
        compare_and_set_wallet_after_bip448_scan, delete_bip448_pending_deposit_signing,
        get_bip448_pending_deposit_signing, get_bip448_raw_wallet_json,
        get_bip448_statechain_optional, recover_bip448_initial_acceptance_wallet,
        Bip448InitialAcceptanceRecovery,
    },
    utils::create_activity,
};

struct Bip448DepositResult {
    activity: Activity,
    accepted_state_materialized: bool,
}

struct DeferredBip448DepositError {
    statechain_id: String,
    error: anyhow::Error,
}

fn get_known_utxo(
    client_config: &ClientConfig,
    address: &Address,
    txid: &str,
    vout: u32,
    expected_value: Option<u64>,
) -> Result<Option<(ChainUtxo, u32)>> {
    let Some(tx_out) = client_config
        .chain_client
        .get_stored_tx_out(txid, vout, true)?
    else {
        return Ok(None);
    };
    if tx_out.script_pubkey != address.script_pubkey()
        || expected_value.map_or(false, |value| value != tx_out.value)
    {
        return Ok(None);
    }

    let confirmations = tx_out.confirmations;
    let blockheight = client_config.chain_client.tip_height()?;
    let height = if confirmations == 0 {
        0
    } else {
        blockheight.saturating_sub(confirmations).saturating_add(1)
    };
    Ok(Some((
        ChainUtxo {
            txid: txid.to_owned(),
            vout,
            value: tx_out.value,
            height,
        },
        confirmations,
    )))
}

fn deposit_setup_is_incomplete(coin: &Coin) -> bool {
    coin.status == CoinStatus::INITIALISED
        && coin.utxo_txid.is_none()
        && coin.utxo_vout.is_none()
        && coin.aggregated_address.is_none()
        && coin.amount.is_none()
}

fn funding_outpoint_is_partial(coin: &Coin) -> bool {
    coin.utxo_txid.is_some() != coin.utxo_vout.is_some()
}

fn defer_bip448_signature_count_error(
    coin: &Coin,
    error: anyhow::Error,
    deferred_errors: &mut Vec<DeferredBip448DepositError>,
) -> Result<()> {
    if !matches!(
        error.downcast_ref::<Bip448DepositError>(),
        Some(Bip448DepositError::InvalidServerSignatureCount { .. })
    ) {
        return Err(error);
    }

    deferred_errors.push(DeferredBip448DepositError {
        statechain_id: coin
            .statechain_id
            .clone()
            .unwrap_or_else(|| format!("coin-index-{}", coin.index)),
        error,
    });

    Ok(())
}

fn select_bip448_funding_utxo(
    mut utxo_list: Vec<ChainUtxo>,
    coin: &Coin,
    pending_signing: Option<&crate::sqlite_manager::Bip448PendingDepositSigning>,
    accepted_state: Option<&Bip448StatechainRecord>,
    expected_value: Option<u64>,
) -> Option<ChainUtxo> {
    sort_chain_utxos(&mut utxo_list);
    if let Some(pending) = pending_signing {
        return utxo_list.into_iter().find(|unspent| {
            unspent.txid == pending.funding_txid
                && unspent.vout == pending.funding_vout
                && unspent.value == pending.funding_value_sats
        });
    }

    if let (Some(txid), Some(vout)) = (coin.utxo_txid.as_ref(), coin.utxo_vout) {
        return utxo_list
            .into_iter()
            .find(|unspent| &unspent.txid == txid && unspent.vout == vout);
    }

    if let Some(record) = accepted_state {
        return utxo_list.into_iter().find(|unspent| {
            unspent.txid == record.funding_outpoint.txid
                && unspent.vout == record.funding_outpoint.vout
                && unspent.value == record.funding_outpoint.value_sats
        });
    }

    utxo_list
        .into_iter()
        .find(|unspent| Some(unspent.value) == expected_value)
}

fn validate_bip448_pending_matches_accepted(
    pending: &crate::sqlite_manager::Bip448PendingDepositSigning,
    accepted: &Bip448StatechainRecord,
) -> Result<()> {
    fn same_hex(left: &str, right: &str) -> bool {
        let left = left
            .strip_prefix("0x")
            .or_else(|| left.strip_prefix("0X"))
            .unwrap_or(left);
        let right = right
            .strip_prefix("0x")
            .or_else(|| right.strip_prefix("0X"))
            .unwrap_or(right);
        left.eq_ignore_ascii_case(right)
    }

    let signing = &accepted.latest_state.signing_metadata;
    let server_public_nonce = pending.server_public_nonce.as_deref().ok_or_else(|| {
        anyhow!("accepted BIP448 deposit has an incomplete pending signing journal")
    })?;
    let matches = pending.wallet_name == accepted.wallet_name
        && pending.statechain_id == accepted.statechain_id
        && pending.funding_txid == accepted.funding_outpoint.txid
        && pending.funding_vout == accepted.funding_outpoint.vout
        && pending.funding_value_sats == accepted.funding_outpoint.value_sats
        && pending.state_locktime == accepted.latest_state.state_locktime
        && same_hex(
            &pending.update_template_hash,
            &accepted.latest_state.update_template_hash,
        )
        && same_hex(
            &pending.settlement_template_hash,
            &accepted.latest_state.settlement_template_hash,
        )
        && same_hex(&pending.update_template_hash, &signing.update_template_hash)
        && same_hex(&pending.signing_id, &signing.signing_id)
        && same_hex(&pending.client_public_nonce, &signing.client_public_nonce)
        && same_hex(server_public_nonce, &signing.server_public_nonce)
        && same_hex(&pending.blinding_factor, &signing.blinding_factor);
    if !matches {
        return Err(anyhow!(
            "accepted BIP448 deposit does not match the pending signing journal"
        ));
    }

    Ok(())
}

async fn check_bip448_deposit(
    client_config: &ClientConfig,
    wallet_name: &str,
    coin: &mut Coin,
    wallet_network: &str,
    wallet_blockheight: u32,
    discovered: &HashMap<ScriptBuf, Vec<ChainUtxo>>,
) -> Result<Option<Bip448DepositResult>> {
    if funding_outpoint_is_partial(coin) {
        return Err(anyhow!("BIP448 coin has a partial funding outpoint"));
    }

    if deposit_setup_is_incomplete(coin) {
        return Ok(None);
    }

    if coin.statechain_id.is_none() && coin.utxo_txid.is_none() && coin.utxo_vout.is_none() {
        if coin.status != CoinStatus::INITIALISED {
            return Err(anyhow!(
                "BIP448 coin does not have a statechain ID, a UTXO and the status is not INITIALISED"
            ));
        }

        return Ok(None);
    }

    let pending_signing = if let Some(statechain_id) = coin.statechain_id.as_deref() {
        get_bip448_pending_deposit_signing(&client_config.pool, wallet_name, statechain_id).await?
    } else {
        None
    };
    let accepted_state = if let Some(statechain_id) = coin.statechain_id.as_deref() {
        get_bip448_statechain_optional(&client_config.pool, wallet_name, statechain_id).await?
    } else {
        None
    };
    if let (Some(pending), Some(accepted)) = (&pending_signing, &accepted_state) {
        validate_bip448_pending_matches_accepted(pending, accepted)?;
    }
    let known_outpoint = if let Some(pending) = &pending_signing {
        Some((
            pending.funding_txid.as_str(),
            pending.funding_vout,
            Some(pending.funding_value_sats),
        ))
    } else if let (Some(txid), Some(vout)) = (coin.utxo_txid.as_deref(), coin.utxo_vout) {
        Some((txid, vout, None))
    } else if let Some(record) = &accepted_state {
        Some((
            record.funding_outpoint.txid.as_str(),
            record.funding_outpoint.vout,
            Some(record.funding_outpoint.value_sats),
        ))
    } else {
        None
    };
    let expected_value = if known_outpoint.is_none() {
        Some(u64::from(coin.amount.ok_or_else(|| {
            anyhow!("BIP448 coin missing amount after deposit setup")
        })?))
    } else {
        None
    };
    let address =
        Address::from_str(coin.aggregated_address.as_ref().ok_or_else(|| {
            anyhow!("BIP448 coin missing aggregated_address after deposit setup")
        })?)?
        .require_network(client_config.network)?;
    if let Some(pending) = &pending_signing {
        if let (Some(txid), Some(vout)) = (coin.utxo_txid.as_ref(), coin.utxo_vout) {
            if txid != &pending.funding_txid || vout != pending.funding_vout {
                return Err(anyhow!(
                    "BIP448 wallet funding outpoint does not match the pending signing journal"
                ));
            }
        }
    }
    let (utxo, confirmations) = if let Some((txid, vout, value)) = known_outpoint {
        let Some(utxo) = get_known_utxo(client_config, &address, txid, vout, value)? else {
            return Ok(None);
        };
        utxo
    } else {
        let utxo_list = discovered
            .get(&address.script_pubkey())
            .into_iter()
            .flatten()
            .filter(|unspent| unspent.height == 0 || unspent.height >= wallet_blockheight)
            .cloned()
            .collect();
        let Some(utxo) = select_bip448_funding_utxo(
            utxo_list,
            coin,
            pending_signing.as_ref(),
            accepted_state.as_ref(),
            expected_value,
        ) else {
            return Ok(None);
        };
        let blockheight = client_config.chain_client.tip_height()?;
        let confirmations = if utxo.height == 0 {
            0
        } else {
            blockheight.saturating_sub(utxo.height).saturating_add(1)
        };
        (utxo, confirmations)
    };
    let mut deposit_result = None;

    if coin.utxo_txid.is_none() || coin.utxo_vout.is_none() {
        if coin.status != CoinStatus::INITIALISED {
            return Err(anyhow!(
                "The BIP448 coin with public key {} is not in the INITIALISED state",
                coin.user_pubkey
            ));
        }

        coin.utxo_txid = Some(utxo.txid.clone());
        coin.utxo_vout = Some(utxo.vout);
        coin.status = CoinStatus::IN_MEMPOOL;
    }

    if confirmations == 0 {
        return Ok(None);
    }

    coin.status = CoinStatus::UNCONFIRMED;

    if coin.public_nonce.is_none() {
        let statechain_id = coin
            .statechain_id
            .as_ref()
            .ok_or_else(|| anyhow!("BIP448 coin missing statechain_id"))?
            .clone();

        if let Some(record) = accepted_state.as_ref() {
            restore_bip448_deposit_state_from_record(
                coin, &record, &utxo.txid, utxo.vout, utxo.value,
            )?;
            if let Some(pending) = &pending_signing {
                delete_bip448_pending_deposit_signing(
                    &client_config.pool,
                    wallet_name,
                    &statechain_id,
                    &pending.signing_id,
                )
                .await?;
            }
        } else {
            create_bip448_deposit_state(
                client_config,
                wallet_name,
                coin,
                wallet_network,
                &utxo.txid,
                utxo.vout,
                utxo.value,
            )
            .await?;
        }

        let activity_utxo = format!("{}:{}", utxo.txid, utxo.vout);
        deposit_result = Some(Bip448DepositResult {
            activity: create_activity(&activity_utxo, utxo.value as u32, "bip448_deposit"),
            accepted_state_materialized: true,
        });
    }

    if confirmations as u32 >= client_config.confirmation_target {
        coin.status = CoinStatus::CONFIRMED;
    }

    Ok(deposit_result)
}

fn restore_bip448_deposit_state_from_record(
    coin: &mut Coin,
    record: &Bip448StatechainRecord,
    funding_txid: &str,
    funding_vout: u32,
    funding_value_sats: u64,
) -> Result<()> {
    let statechain_id = coin
        .statechain_id
        .as_ref()
        .ok_or_else(|| anyhow!("BIP448 coin missing statechain_id"))?;

    if record.statechain_id != *statechain_id {
        return Err(anyhow!(
            "persisted BIP448 deposit statechain_id does not match wallet coin"
        ));
    }

    if record.funding_outpoint.txid != funding_txid
        || record.funding_outpoint.vout != funding_vout
        || record.funding_outpoint.value_sats != funding_value_sats
    {
        return Err(anyhow!(
            "persisted BIP448 deposit funding outpoint does not match wallet coin"
        ));
    }

    let signing_metadata = &record.latest_state.signing_metadata;
    coin.public_nonce = Some(signing_metadata.client_public_nonce.clone());
    coin.server_public_nonce = Some(signing_metadata.server_public_nonce.clone());
    coin.blinding_factor = Some(signing_metadata.blinding_factor.clone());
    coin.locktime = Some(record.latest_state.state_locktime);

    Ok(())
}

async fn check_transfer(client_config: &ClientConfig, coin: &mut Coin) -> Result<()> {
    let statechain_id = coin
        .statechain_id
        .clone()
        .ok_or_else(|| anyhow!("Coin does not have a statechain ID"))?;
    let presence = get_bip448_statechain_presence(client_config, &statechain_id).await?;
    apply_bip448_transfer_presence(coin, &presence, &statechain_id)
}

fn apply_bip448_transfer_presence(
    coin: &mut Coin,
    presence: &Bip448StatechainPresence,
    statechain_id: &str,
) -> Result<()> {
    let aggregate_pubkey = coin
        .aggregated_pubkey
        .as_deref()
        .ok_or_else(|| anyhow!("BIP448 in-transfer coin is missing aggregated_pubkey"))?;
    let stored_server_pubkey = coin
        .server_pubkey
        .as_deref()
        .ok_or_else(|| anyhow!("BIP448 in-transfer coin is missing server_pubkey"))?;
    let relation = classify_bip448_owner_relation(
        presence,
        &coin.user_pubkey,
        stored_server_pubkey,
        aggregate_pubkey,
    )?;
    match relation {
        Bip448OwnerRelation::Current => Ok(()),
        Bip448OwnerRelation::Rotated => {
            coin.status = CoinStatus::TRANSFERRED;
            Ok(())
        }
        Bip448OwnerRelation::Missing => Err(anyhow!(
            "BIP448 statechain {statechain_id} is missing; transfer ownership is closed or unknown and the coin remains IN_TRANSFER"
        )),
    }
}

async fn check_withdrawal(client_config: &ClientConfig, coin: &mut Coin) -> Result<()> {
    let txid = coin
        .tx_withdraw
        .as_deref()
        .ok_or_else(|| anyhow!("Coin does not have tx_withdraw"))?;
    let txid = Txid::from_str(txid)?;

    if coin.withdrawal_address.is_none() {
        return Err(anyhow!("Coin does not have withdrawal_address"));
    }

    let address = Address::from_str(&coin.withdrawal_address.as_ref().unwrap())?
        .require_network(client_config.network)?;

    let tx_out = client_config.chain_client.get_tx_out(&txid, 0, true)?;

    let Some(tx_out) = tx_out else {
        // Sometimes the configured chain backend has not observed the transaction yet.
        // return Err(anyhow!("There is no UTXO with the address {} and the txid {}", coin.withdrawal_address.as_ref().unwrap(), txid));
        return Ok(());
    };

    if tx_out.script_pubkey != address.script_pubkey() {
        return Err(anyhow!(
            "withdrawal transaction vout 0 does not pay the stored address"
        ));
    }

    if tx_out.confirmations > 0 && tx_out.confirmations >= client_config.confirmation_target {
        coin.status = CoinStatus::WITHDRAWN;
    }

    Ok(())
}

fn deferred_bip448_deposit_error(deferred_errors: Vec<DeferredBip448DepositError>) -> Result<()> {
    if deferred_errors.is_empty() {
        return Ok(());
    }

    let details = deferred_errors
        .iter()
        .map(|failure| format!("{} ({})", failure.statechain_id, failure.error))
        .collect::<Vec<_>>()
        .join(", ");
    let first_error = deferred_errors.into_iter().next().unwrap().error;

    Err(first_error.context(format!(
        "BIP448 deposits could not enter accepted state: {details}; other wallet updates were persisted"
    )))
}

fn require_exact_adopted_initial_acceptance_wallet(
    raw_wallet_json: &str,
    expected_wallet: &Wallet,
) -> Result<()> {
    let adopted: Wallet = serde_json::from_str(raw_wallet_json)?;
    if serde_json::to_string(&adopted)? != raw_wallet_json
        || serde_json::to_value(&adopted)? != serde_json::to_value(expected_wallet)?
    {
        return Err(anyhow!(
            "BIP448 initial-acceptance wallet changed before post-acceptance synchronization"
        ));
    }
    Ok(())
}

#[cfg(test)]
async fn finalize_wallet_update(
    client_config: &ClientConfig,
    wallet: &mut Wallet,
    deferred_errors: Vec<DeferredBip448DepositError>,
) -> Result<()> {
    crate::sqlite_manager::update_wallet(&client_config.pool, wallet).await?;
    deferred_bip448_deposit_error(deferred_errors)
}

pub async fn update_coins(client_config: &ClientConfig, wallet_name: &str) -> Result<()> {
    for recovery_attempt in 1..=3 {
        let expected_raw_wallet_json =
            get_bip448_raw_wallet_json(&client_config.pool, wallet_name).await?;
        match recover_bip448_initial_acceptance_wallet(
            &client_config.pool,
            wallet_name,
            &expected_raw_wallet_json,
        )
        .await?
        {
            Bip448InitialAcceptanceRecovery::Unchanged
            | Bip448InitialAcceptanceRecovery::Recovered => break,
            Bip448InitialAcceptanceRecovery::WalletChanged if recovery_attempt < 3 => continue,
            Bip448InitialAcceptanceRecovery::WalletChanged => {
                return Err(anyhow!(
                    "BIP448 initial-acceptance recovery wallet changed during three consecutive cycles"
                ));
            }
        }
    }
    for update_attempt in 1..=3 {
        let live_raw_wallet_json =
            get_bip448_raw_wallet_json(&client_config.pool, wallet_name).await?;
        let mut wallet: Wallet = serde_json::from_str(&live_raw_wallet_json)?;
        let mut has_statechain = false;
        for coin in &wallet.coins {
            if let Some(statechain_id) = coin.statechain_id.as_deref() {
                if coin.statechain_protocol.as_deref() != Some(bip448_deposit::BIP448_COIN_PROTOCOL)
                {
                    return Err(anyhow!(
                        "statechain {statechain_id}: unsupported non-BIP448 coin"
                    ));
                }
                has_statechain = true;
            }
        }
        if !has_statechain {
            return Ok(());
        }
        let mut sync =
            sync_bip448_funding_bindings_with_candidates(client_config, wallet_name, false, None)
                .await?;
        if live_raw_wallet_json != sync.raw_wallet_json {
            if update_attempt == 3 {
                return Err(anyhow!(
                    "BIP448 wallet changed during three consecutive update cycles"
                ));
            }
            continue;
        }
        let network = wallet.network.clone();
        let wallet_blockheight = wallet.blockheight;
        let mut deferred_bip448_deposit_errors = Vec::new();
        let mut accepted_state_materialized = false;

        for coin in wallet.coins.iter_mut() {
            if coin.statechain_id.is_none() && deposit_setup_is_incomplete(coin) {
                continue;
            }
            if matches!(
                coin.status,
                CoinStatus::INITIALISED | CoinStatus::IN_MEMPOOL | CoinStatus::UNCONFIRMED
            ) {
                let deposit_result = match check_bip448_deposit(
                    client_config,
                    &wallet.name,
                    coin,
                    &network,
                    wallet_blockheight,
                    &sync.discovered,
                )
                .await
                {
                    std::result::Result::Ok(deposit_result) => deposit_result,
                    std::result::Result::Err(error) => {
                        defer_bip448_signature_count_error(
                            coin,
                            error,
                            &mut deferred_bip448_deposit_errors,
                        )?;
                        continue;
                    }
                };
                if let Some(deposit_result) = deposit_result {
                    accepted_state_materialized |= deposit_result.accepted_state_materialized;
                    wallet.activities.push(deposit_result.activity);
                }
            } else if coin.status == CoinStatus::IN_TRANSFER {
                check_transfer(client_config, coin).await?;
            } else if coin.status == CoinStatus::WITHDRAWING {
                check_withdrawal(client_config, coin).await?;
            }
        }

        let mut wallet_cas_base = live_raw_wallet_json.clone();
        if accepted_state_materialized {
            if !compare_and_set_wallet_after_bip448_scan(
                &client_config.pool,
                wallet_name,
                &wallet_cas_base,
                &wallet,
                &sync.report.applied_scan_revisions,
            )
            .await?
            {
                if update_attempt == 3 {
                    return Err(anyhow!(
                        "BIP448 initial-acceptance wallet/revision compare-and-set lost three consecutive update cycles"
                    ));
                }
                continue;
            }
            let adopted_raw_wallet_json =
                get_bip448_raw_wallet_json(&client_config.pool, wallet_name).await?;
            if let Err(error) =
                require_exact_adopted_initial_acceptance_wallet(&adopted_raw_wallet_json, &wallet)
            {
                if update_attempt == 3 {
                    return Err(error);
                }
                continue;
            }
            wallet_cas_base = adopted_raw_wallet_json;
            let post_acceptance = sync_bip448_funding_bindings_with_candidates(
                client_config,
                wallet_name,
                false,
                None,
            )
            .await?;
            if post_acceptance.raw_wallet_json != wallet_cas_base {
                if update_attempt == 3 {
                    return Err(anyhow!(
                        "BIP448 wallet changed during three consecutive post-acceptance cycles"
                    ));
                }
                continue;
            }
            sync = post_acceptance;
        }

        if !compare_and_set_wallet_after_bip448_scan(
            &client_config.pool,
            wallet_name,
            &wallet_cas_base,
            &wallet,
            &sync.report.applied_scan_revisions,
        )
        .await?
        {
            if update_attempt == 3 {
                return Err(anyhow!(
                    "BIP448 wallet/revision compare-and-set lost three consecutive update cycles"
                ));
            }
            continue;
        }
        let accepted_statechain_ids =
            accepted_bip448_statechain_ids(&client_config.pool, &wallet).await?;
        reconcile_bip448_post_sync_transfer_artifacts(
            &client_config.pool,
            wallet_name,
            &accepted_statechain_ids,
        )
        .await?;
        deferred_bip448_deposit_error(deferred_bip448_deposit_errors)?;
        return Ok(());
    }
    unreachable!("bounded BIP448 wallet update retry loop")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chain::{ChainClient, CoreRpcAuth, CoreRpcConfig},
        sqlite_manager::{
            get_bip448_pending_deposit_signing, get_bip448_statechain_optional, get_wallet,
            insert_bip448_pending_deposit_signing_if_absent, insert_wallet,
            Bip448PendingDepositSigning,
        },
    };
    use bitcoin::Network;
    use mercurylib::bip448_statechain::storage::{
        Bip448AnchorOutput, Bip448CpfpChildTemplate, Bip448CsfsKeyMetadata, Bip448FeeBumpPolicy,
        Bip448FundingOutpoint, Bip448LatestState, Bip448RecoveryTemplateRole,
        Bip448SigningMetadata, Bip448ValueSchedule,
    };
    use mercurylib::transfer::receiver::StatechainInfoResponsePayload;
    use mercurylib::wallet::{Settings, Wallet};
    use secp256k1::{PublicKey, Secp256k1, SecretKey};
    use sqlx::sqlite::SqlitePoolOptions;

    async fn test_client_config() -> Result<ClientConfig> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        let chain_client = ChainClient::new(CoreRpcConfig {
            url: "http://127.0.0.1:1".to_string(),
            auth: CoreRpcAuth::None,
        })?;

        Ok(ClientConfig {
            statechain_entity: "http://127.0.0.1:1".to_string(),
            chain_backend: "core".to_string(),
            chain_client,
            chain_endpoint: Some("http://127.0.0.1:1".to_string()),
            core_rpc_auth: Some("none".to_string()),
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

    fn sample_coin() -> Coin {
        let mut coin = sample_wallet(Vec::new()).get_new_coin().unwrap();
        coin.statechain_protocol = Some(bip448_deposit::BIP448_COIN_PROTOCOL.to_string());
        coin.utxo_txid = Some("aa".repeat(32));
        coin.utxo_vout = Some(1);
        coin.amount = Some(50_000);
        coin.statechain_id = Some("statechain".to_string());
        coin.status = CoinStatus::UNCONFIRMED;
        coin
    }

    fn incomplete_coin(index: u32, protocol: Option<&str>) -> Coin {
        let mut coin = sample_coin();
        coin.index = index;
        coin.statechain_protocol = protocol.map(str::to_owned);
        coin.utxo_txid = None;
        coin.utxo_vout = None;
        coin.amount = None;
        coin.status = CoinStatus::INITIALISED;
        coin
    }

    fn sample_wallet(coins: Vec<Coin>) -> Wallet {
        Wallet {
            name: "wallet".to_string(),
            mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            version: "0.1.0".to_string(),
            state_entity_endpoint: "http://127.0.0.1:1".to_string(),
            chain_backend: "core".to_string(),
            chain_endpoint: "http://127.0.0.1:1".to_string(),
            network: "regtest".to_string(),
            blockheight: 0,
            activities: Vec::new(),
            coins,
            settings: Settings {
                network: "regtest".to_string(),
                block_explorerURL: None,
                torProxyHost: None,
                torProxyPort: None,
                torProxyControlPassword: None,
                torProxyControlPort: None,
                statechainEntityApi: "http://127.0.0.1:1".to_string(),
                torStatechainEntityApi: None,
                chainBackend: "core".to_string(),
                chainUrl: "http://127.0.0.1:1".to_string(),
                chainType: None,
                notifications: false,
                tutorials: false,
            },
        }
    }

    fn sample_record(
        funding_txid: &str,
        funding_vout: u32,
        funding_value_sats: u64,
    ) -> Bip448StatechainRecord {
        let latest_state = Bip448LatestState {
            state_number: 1,
            state_locktime: 700_000_042,
            challenge_delay: 144,
            update_tx: "02000000".to_string(),
            settlement_tx: "03000000".to_string(),
            update_template_hash: "11".repeat(32),
            settlement_template_hash: "22".repeat(32),
            state_output_script_pubkey: "5120".to_string() + &"33".repeat(32),
            funding_update_script: "51cecbcc".to_string(),
            funding_update_control_block: "c0".to_string() + &"44".repeat(32),
            state_update_script: "b175cecbcc".to_string(),
            state_update_control_block: "c0".to_string() + &"55".repeat(32),
            state_settlement_script: "20".to_string() + &"22".repeat(32) + "ce87",
            state_settlement_control_block: "c0".to_string() + &"66".repeat(32),
            csfs_key_metadata: Bip448CsfsKeyMetadata {
                aggregate_pubkey_parity_odd: true,
                negate_seckey: true,
            },
            signing_metadata: Bip448SigningMetadata {
                role: Bip448RecoveryTemplateRole::FundingUpdate,
                signing_id: "77".repeat(32),
                client_public_nonce: "88".repeat(66),
                server_public_nonce: "99".repeat(66),
                blinding_factor: "aa".repeat(32),
                update_template_hash: "11".repeat(32),
                update_signature: "bb".repeat(64),
                server_signature_count: 1,
            },
            fee_bump_policy: Bip448FeeBumpPolicy::ZeroFeeEphemeralAnchor,
            value_schedule: Bip448ValueSchedule {
                funding_value_sats,
                update_input_value_sats: funding_value_sats,
                update_state_output_value_sats: funding_value_sats,
                settlement_input_value_sats: funding_value_sats,
                settlement_recovery_output_value_sats: funding_value_sats,
            },
            anchors: vec![Bip448AnchorOutput {
                tx_role: Bip448RecoveryTemplateRole::FundingUpdate,
                output_index: 1,
                value_sats: 0,
                script_pubkey: "51024e73".to_string(),
            }],
            cpfp_child_templates: vec![Bip448CpfpChildTemplate {
                parent_role: Bip448RecoveryTemplateRole::FundingUpdate,
                anchor_output_index: 1,
                tx_hex: "03000000".to_string(),
                fee_sats: 1_000,
                target_feerate_sat_per_vbyte: Some(10),
            }],
        };

        Bip448StatechainRecord {
            wallet_name: "wallet".to_string(),
            statechain_id: "statechain".to_string(),
            aggregate_pubkey: "02".to_string() + &"12".repeat(32),
            funding_outpoint: Bip448FundingOutpoint {
                txid: funding_txid.to_string(),
                vout: funding_vout,
                value_sats: funding_value_sats,
            },
            latest_state_number: latest_state.state_number,
            challenge_delay: latest_state.challenge_delay,
            amount_sats: funding_value_sats,
            network: "regtest".to_string(),
            latest_state,
        }
    }

    #[tokio::test]
    async fn incomplete_deposit_setup_is_ignored_only_while_unfunded_and_initialised() -> Result<()>
    {
        let client_config = test_client_config().await?;
        let mut bip448_coin = incomplete_coin(0, Some(bip448_deposit::BIP448_COIN_PROTOCOL));

        assert!(check_bip448_deposit(
            &client_config,
            "wallet",
            &mut bip448_coin,
            "regtest",
            0,
            &HashMap::new(),
        )
        .await?
        .is_none());

        bip448_coin.utxo_txid = Some("aa".repeat(32));
        let bip448_error = check_bip448_deposit(
            &client_config,
            "wallet",
            &mut bip448_coin,
            "regtest",
            0,
            &HashMap::new(),
        )
        .await
        .err()
        .expect("partial BIP448 outpoint must fail");
        assert_eq!(
            bip448_error.to_string(),
            "BIP448 coin has a partial funding outpoint"
        );

        Ok(())
    }

    #[tokio::test]
    async fn asymmetric_or_advanced_missing_setup_fields_fail_before_chain_access() -> Result<()> {
        let client_config = test_client_config().await?;
        let mut bip448_coin = incomplete_coin(0, Some(bip448_deposit::BIP448_COIN_PROTOCOL));

        bip448_coin.aggregated_address = Some("not-queried".to_string());
        let bip448_error = check_bip448_deposit(
            &client_config,
            "wallet",
            &mut bip448_coin,
            "regtest",
            0,
            &HashMap::new(),
        )
        .await
        .err()
        .expect("address-only BIP448 setup must fail");
        assert_eq!(
            bip448_error.to_string(),
            "BIP448 coin missing amount after deposit setup"
        );

        bip448_coin.aggregated_address = None;
        bip448_coin.amount = Some(50_000);
        let bip448_error = check_bip448_deposit(
            &client_config,
            "wallet",
            &mut bip448_coin,
            "regtest",
            0,
            &HashMap::new(),
        )
        .await
        .err()
        .expect("amount-only BIP448 setup must fail");
        assert!(bip448_error
            .to_string()
            .contains("missing aggregated_address"));

        bip448_coin.amount = None;
        bip448_coin.utxo_txid = None;
        bip448_coin.utxo_vout = None;
        bip448_coin.status = CoinStatus::IN_MEMPOOL;
        let bip448_error = check_bip448_deposit(
            &client_config,
            "wallet",
            &mut bip448_coin,
            "regtest",
            0,
            &HashMap::new(),
        )
        .await
        .err()
        .expect("advanced BIP448 setup must fail");
        assert!(bip448_error.to_string().contains("missing amount"));

        Ok(())
    }

    #[tokio::test]
    async fn known_bip448_outpoint_does_not_require_stored_amount_before_lookup() -> Result<()> {
        let client_config = test_client_config().await?;
        let mut coin = incomplete_coin(0, Some(bip448_deposit::BIP448_COIN_PROTOCOL));
        coin.utxo_txid = Some("aa".repeat(32));
        coin.utxo_vout = Some(0);

        let error = check_bip448_deposit(
            &client_config,
            "wallet",
            &mut coin,
            "regtest",
            0,
            &HashMap::new(),
        )
        .await
        .err()
        .expect("missing address must fail before chain access");
        assert!(error.to_string().contains("missing aggregated_address"));
        assert!(!error.to_string().contains("missing amount"));

        Ok(())
    }

    #[tokio::test]
    async fn malformed_or_noncanonical_known_txids_are_soft_misses_before_rpc() -> Result<()> {
        let client_config = test_client_config().await?;
        let address = Address::from_str("bcrt1qgwwa9fcrcvnme0jymg39zm38w6gzudcq3n90tl")?
            .require_network(Network::Regtest)?;
        for txid in ["not-a-txid".to_string(), "AA".repeat(32)] {
            assert!(get_known_utxo(&client_config, &address, &txid, 0, None)?.is_none());
        }
        Ok(())
    }

    #[tokio::test]
    async fn blank_initialized_transfer_address_coin_is_skipped() -> Result<()> {
        let client_config = test_client_config().await?;
        let mut coin = incomplete_coin(0, None);
        coin.statechain_id = None;
        let wallet = sample_wallet(vec![coin.clone()]);
        insert_wallet(&client_config.pool, &wallet).await?;

        update_coins(&client_config, &wallet.name).await?;

        let persisted = get_wallet(&client_config.pool, &wallet.name).await?;
        assert_eq!(persisted.coins.len(), 1);
        assert_eq!(
            serde_json::to_value(&persisted.coins[0])?,
            serde_json::to_value(coin)?
        );

        Ok(())
    }

    #[tokio::test]
    async fn statechain_without_bip448_marker_fails_closed_before_chain_access() -> Result<()> {
        let client_config = test_client_config().await?;
        let coin = incomplete_coin(0, None);
        let wallet = sample_wallet(vec![coin]);
        insert_wallet(&client_config.pool, &wallet).await?;

        let error = update_coins(&client_config, &wallet.name)
            .await
            .err()
            .expect("non-BIP448 marker must fail closed");

        assert_eq!(
            error.to_string(),
            "statechain statechain: unsupported non-BIP448 coin"
        );

        Ok(())
    }

    #[test]
    fn only_signature_count_mismatches_are_deferred() {
        let coin = sample_coin();
        let mut deferred_errors = Vec::new();

        let result = defer_bip448_signature_count_error(
            &coin,
            anyhow!("Bitcoin Core unavailable"),
            &mut deferred_errors,
        );

        assert!(result.is_err());
        assert!(deferred_errors.is_empty());
    }

    #[test]
    fn only_a_valid_positive_rotation_mutates_an_in_transfer_coin() {
        fn public_key(byte: u8) -> PublicKey {
            SecretKey::from_secret_bytes([byte; 32])
                .unwrap()
                .public_key(&Secp256k1::new())
        }

        fn present(server_pubkey: impl ToString) -> Bip448StatechainPresence {
            Bip448StatechainPresence::Present(StatechainInfoResponsePayload {
                enclave_public_key: server_pubkey.to_string(),
                num_sigs: 2,
                statechain_info: Vec::new(),
                x1_pub: None,
            })
        }

        let owner_user = public_key(3);
        let stored_server = public_key(5);
        let aggregate = owner_user.combine(&stored_server).unwrap();
        let rotated_server = public_key(7);
        let mut coin = sample_coin();
        coin.status = CoinStatus::IN_TRANSFER;
        coin.user_pubkey = owner_user.to_string();
        coin.server_pubkey = Some(stored_server.to_string());
        coin.aggregated_pubkey = Some(aggregate.to_string());

        apply_bip448_transfer_presence(&mut coin, &present(stored_server), "statechain").unwrap();
        assert_eq!(coin.status, CoinStatus::IN_TRANSFER);

        let mut rotated = coin.clone();
        apply_bip448_transfer_presence(&mut rotated, &present(rotated_server), "statechain")
            .unwrap();
        assert_eq!(rotated.status, CoinStatus::TRANSFERRED);

        let mut corrupt_aggregate = coin.clone();
        corrupt_aggregate.aggregated_pubkey = Some(public_key(11).to_string());
        let error = apply_bip448_transfer_presence(
            &mut corrupt_aggregate,
            &present(stored_server),
            "statechain",
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("stored BIP448 owner generation does not reproduce"));
        assert_eq!(corrupt_aggregate.status, CoinStatus::IN_TRANSFER);

        let mut corrupt_stored_tuple = coin.clone();
        corrupt_stored_tuple.server_pubkey = Some(public_key(9).to_string());
        let error = apply_bip448_transfer_presence(
            &mut corrupt_stored_tuple,
            &present(rotated_server),
            "statechain",
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("stored BIP448 owner generation does not reproduce"));
        assert_eq!(corrupt_stored_tuple.status, CoinStatus::IN_TRANSFER);

        let mut missing = coin.clone();
        let error = apply_bip448_transfer_presence(
            &mut missing,
            &Bip448StatechainPresence::Missing,
            "statechain",
        )
        .unwrap_err();
        assert!(error.to_string().contains("closed or unknown"));
        assert!(error.to_string().contains("remains IN_TRANSFER"));
        assert_eq!(missing.status, CoinStatus::IN_TRANSFER);

        let mut invalid_reported_key = coin;
        assert!(apply_bip448_transfer_presence(
            &mut invalid_reported_key,
            &present("invalid"),
            "statechain",
        )
        .is_err());
        assert_eq!(invalid_reported_key.status, CoinStatus::IN_TRANSFER);
    }

    #[tokio::test]
    async fn signature_count_mismatch_is_reported_after_other_wallet_updates_persist() -> Result<()>
    {
        let client_config = test_client_config().await?;
        let mut failed_coin = sample_coin();
        failed_coin.statechain_id = Some("failed-statechain".to_string());
        let mut successful_coin = sample_coin();
        successful_coin.index = 1;
        successful_coin.statechain_id = Some("successful-statechain".to_string());
        let wallet = sample_wallet(vec![failed_coin, successful_coin]);
        insert_wallet(&client_config.pool, &wallet).await?;

        let pending = Bip448PendingDepositSigning {
            wallet_name: wallet.name.clone(),
            statechain_id: "failed-statechain".to_string(),
            funding_txid: "aa".repeat(32),
            funding_vout: 1,
            funding_value_sats: 50_000,
            update_template_hash: "11".repeat(32),
            settlement_template_hash: "12".repeat(32),
            state_locktime: 700_000_042,
            signing_id: "22".repeat(32),
            client_secret_nonce: "33".repeat(132),
            client_public_nonce: "44".repeat(66),
            blinding_factor: "55".repeat(32),
            server_public_nonce: Some("66".repeat(66)),
        };
        insert_bip448_pending_deposit_signing_if_absent(&client_config.pool, &pending).await?;

        let mut wallet = get_wallet(&client_config.pool, &wallet.name).await?;
        wallet.coins[1].status = CoinStatus::CONFIRMED;
        wallet.activities.push(create_activity(
            "successful-funding:0",
            50_000,
            "bip448_deposit",
        ));
        let mut deferred_errors = Vec::new();
        defer_bip448_signature_count_error(
            &wallet.coins[0],
            anyhow::Error::new(Bip448DepositError::InvalidServerSignatureCount {
                expected: 1,
                actual: 2,
            }),
            &mut deferred_errors,
        )?;

        let error = finalize_wallet_update(&client_config, &mut wallet, deferred_errors)
            .await
            .err()
            .expect("signature-count mismatch must be reported after persistence");

        assert!(matches!(
            error.downcast_ref::<Bip448DepositError>(),
            Some(Bip448DepositError::InvalidServerSignatureCount {
                expected: 1,
                actual: 2
            })
        ));
        assert!(error.to_string().contains("failed-statechain"));
        assert!(error
            .to_string()
            .contains("other wallet updates were persisted"));

        let persisted = get_wallet(&client_config.pool, &wallet.name).await?;
        assert_eq!(persisted.coins[1].status, CoinStatus::CONFIRMED);
        assert_eq!(persisted.activities.len(), 1);
        assert_eq!(persisted.activities[0].action, "bip448_deposit");
        assert!(get_bip448_pending_deposit_signing(
            &client_config.pool,
            &wallet.name,
            "failed-statechain",
        )
        .await?
        .is_some());
        assert!(get_bip448_statechain_optional(
            &client_config.pool,
            &wallet.name,
            "failed-statechain",
        )
        .await?
        .is_none());

        Ok(())
    }

    #[test]
    fn bip448_deposit_recovery_restores_wallet_signing_metadata() -> Result<()> {
        let mut coin = sample_coin();
        let record = sample_record(&"aa".repeat(32), 1, 50_000);

        restore_bip448_deposit_state_from_record(&mut coin, &record, &"aa".repeat(32), 1, 50_000)?;

        assert_eq!(coin.public_nonce, Some("88".repeat(66)));
        assert_eq!(coin.server_public_nonce, Some("99".repeat(66)));
        assert_eq!(coin.blinding_factor, Some("aa".repeat(32)));
        assert_eq!(coin.locktime, Some(record.latest_state.state_locktime));

        Ok(())
    }

    #[test]
    fn bip448_deposit_recovery_rejects_mismatched_funding_outpoint() {
        let mut coin = sample_coin();
        let record = sample_record(&"bb".repeat(32), 1, 50_000);

        assert!(restore_bip448_deposit_state_from_record(
            &mut coin,
            &record,
            &"aa".repeat(32),
            1,
            50_000,
        )
        .is_err());
        assert_eq!(coin.public_nonce, None);
    }

    #[test]
    fn accepted_deposit_outpoint_wins_over_equal_value_utxo_order() {
        let mut coin = sample_coin();
        coin.utxo_txid = None;
        coin.utxo_vout = None;
        let accepted = sample_record(&"bb".repeat(32), 3, 50_000);
        let wrong_equal_value = ChainUtxo {
            txid: "aa".repeat(32),
            vout: 1,
            value: 50_000,
            height: 1,
        };
        let accepted_utxo = ChainUtxo {
            txid: accepted.funding_outpoint.txid.clone(),
            vout: accepted.funding_outpoint.vout,
            value: accepted.funding_outpoint.value_sats,
            height: 1,
        };

        let selected = select_bip448_funding_utxo(
            vec![wrong_equal_value, accepted_utxo.clone()],
            &coin,
            None,
            Some(&accepted),
            Some(50_000),
        );

        assert_eq!(selected, Some(accepted_utxo));
    }

    #[test]
    fn initial_acceptance_wallet_base_is_adopted_only_when_byte_exact() {
        let wallet = sample_wallet(vec![sample_coin()]);
        let raw = serde_json::to_string(&wallet).unwrap();
        require_exact_adopted_initial_acceptance_wallet(&raw, &wallet).unwrap();

        let mut changed = wallet.clone();
        changed.coins[0].status = CoinStatus::CONFIRMED;
        let changed_raw = serde_json::to_string(&changed).unwrap();
        assert!(require_exact_adopted_initial_acceptance_wallet(&changed_raw, &wallet).is_err());
        assert!(
            require_exact_adopted_initial_acceptance_wallet(&format!("{raw}\n"), &wallet,).is_err()
        );
        assert!(require_exact_adopted_initial_acceptance_wallet("{", &wallet).is_err());
    }

    #[test]
    fn accepted_and_pending_deposit_identities_must_match_before_cleanup() {
        let accepted = sample_record(&"bb".repeat(32), 3, 50_000);
        let signing = &accepted.latest_state.signing_metadata;
        let pending = Bip448PendingDepositSigning {
            wallet_name: accepted.wallet_name.clone(),
            statechain_id: accepted.statechain_id.clone(),
            funding_txid: accepted.funding_outpoint.txid.clone(),
            funding_vout: accepted.funding_outpoint.vout,
            funding_value_sats: accepted.funding_outpoint.value_sats,
            update_template_hash: accepted.latest_state.update_template_hash.clone(),
            settlement_template_hash: accepted.latest_state.settlement_template_hash.clone(),
            state_locktime: accepted.latest_state.state_locktime,
            signing_id: signing.signing_id.clone(),
            client_secret_nonce: "77".repeat(132),
            client_public_nonce: signing.client_public_nonce.clone(),
            blinding_factor: signing.blinding_factor.clone(),
            server_public_nonce: Some(format!(
                "0X{}",
                signing.server_public_nonce.to_ascii_uppercase()
            )),
        };
        assert!(validate_bip448_pending_matches_accepted(&pending, &accepted).is_ok());

        let mut conflicts = Vec::new();
        let mut conflict = pending.clone();
        conflict.funding_vout += 1;
        conflicts.push(conflict);
        let mut conflict = pending.clone();
        conflict.state_locktime += 1;
        conflicts.push(conflict);
        let mut conflict = pending.clone();
        conflict.update_template_hash = "01".repeat(32);
        conflicts.push(conflict);
        let mut conflict = pending.clone();
        conflict.settlement_template_hash = "02".repeat(32);
        conflicts.push(conflict);
        let mut conflict = pending.clone();
        conflict.signing_id = "03".repeat(32);
        conflicts.push(conflict);
        let mut conflict = pending.clone();
        conflict.client_public_nonce = "04".repeat(66);
        conflicts.push(conflict);
        let mut conflict = pending.clone();
        conflict.server_public_nonce = Some("05".repeat(66));
        conflicts.push(conflict);
        let mut conflict = pending.clone();
        conflict.blinding_factor = "06".repeat(32);
        conflicts.push(conflict);
        let mut conflict = pending;
        conflict.server_public_nonce = None;
        conflicts.push(conflict);

        for conflict in conflicts {
            assert!(validate_bip448_pending_matches_accepted(&conflict, &accepted).is_err());
        }
    }
}
