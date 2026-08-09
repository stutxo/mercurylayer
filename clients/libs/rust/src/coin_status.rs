use crate::utils::create_activity;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use anyhow::{anyhow, Ok, Result};
use bitcoin::{Address, ScriptBuf, Txid};
use mercurylib::{
    bip448_statechain::{
        deposit::{self as bip448_deposit, Bip448DepositError},
        storage::Bip448StatechainRecord,
    },
    utils::is_enclave_pubkey_part_of_coin,
    wallet::{Activity, Coin, CoinStatus, Wallet},
};

use crate::{
    chain::{ChainUtxo, DescriptorActivity},
    client_config::ClientConfig,
    deposit::create_bip448_deposit_state,
    sqlite_manager::{
        clear_bip448_scan_state, delete_bip448_pending_deposit_signing,
        get_bip448_pending_deposit_signing, get_bip448_statechain_optional, get_wallet,
        load_bip448_scan_state, persist_bip448_scan_state, update_wallet, Bip448ScanCursor,
    },
};

struct Bip448DepositResult {
    activity: Activity,
}

struct DeferredBip448DepositError {
    statechain_id: String,
    error: anyhow::Error,
}

pub fn unspent_from_descriptor_activity(activity: Vec<DescriptorActivity>) -> Vec<ChainUtxo> {
    let mut receives = HashMap::new();
    let mut spends = HashSet::new();
    for event in activity {
        match event {
            DescriptorActivity::Receive {
                amount,
                height,
                txid,
                vout,
                ..
            } => {
                receives.insert(
                    (txid, vout),
                    ChainUtxo {
                        txid: txid.to_string(),
                        vout,
                        value: amount,
                        height: height.unwrap_or(0),
                    },
                );
            }
            DescriptorActivity::Spend {
                prevout_txid,
                prevout_vout,
                ..
            } => {
                spends.insert((prevout_txid, prevout_vout));
            }
        }
    }
    receives.retain(|outpoint, _| !spends.contains(outpoint));

    receives.into_values().collect()
}

struct DescriptorScanState {
    descriptor: String,
    start_height: u32,
    result_start_height: u32,
    cursor: Option<Bip448ScanCursor>,
    outpoints: HashMap<(String, u32), ChainUtxo>,
}

#[derive(Clone)]
struct DescriptorDiscoveryRequest {
    address: Address,
    // This must be the lowest height this script can ever need. The cursor table
    // intentionally has no second lower-bound field.
    coverage_start_height: u32,
    result_start_height: u32,
}

async fn discover_unspent_batch(
    client_config: &ClientConfig,
    wallet_name: &str,
    requests: &[DescriptorDiscoveryRequest],
) -> Result<HashMap<ScriptBuf, Vec<ChainUtxo>>> {
    discover_unspent_batch_attempt(client_config, wallet_name, requests, true).await
}

async fn discover_unspent_batch_attempt(
    client_config: &ClientConfig,
    wallet_name: &str,
    requests: &[DescriptorDiscoveryRequest],
    retry_reorg: bool,
) -> Result<HashMap<ScriptBuf, Vec<ChainUtxo>>> {
    if requests.is_empty() {
        return Ok(HashMap::new());
    }
    let stop_height = client_config.chain_client.tip_height()?;
    let stop_block_hash = client_config
        .chain_client
        .get_block_hash(stop_height)?
        .to_string();
    let mut bounds = HashMap::<ScriptBuf, (String, u32, u32)>::new();
    for request in requests {
        let script = request.address.script_pubkey();
        let entry = bounds.entry(script).or_insert_with(|| {
            (
                format!("addr({})", request.address),
                request.coverage_start_height,
                request.result_start_height,
            )
        });
        entry.1 = entry.1.min(request.coverage_start_height);
        entry.2 = entry.2.min(request.result_start_height);
    }
    let mut states = HashMap::new();
    for (script, (descriptor, coverage_start_height, result_start_height)) in bounds {
        let script_hex = hex::encode(script.as_bytes());
        let (mut cursor, mut stored) = load_bip448_scan_state(&client_config.pool, wallet_name, &script_hex).await?;
        let cursor_matches = match &cursor {
            Some(cursor) if cursor.last_scanned_height > stop_height => false,
            Some(cursor) => client_config.chain_client.get_block_hash(cursor.last_scanned_height)?
                .to_string() == cursor.last_scanned_block_hash,
            None => true,
        };
        if !cursor_matches {
            clear_bip448_scan_state(&client_config.pool, wallet_name, &script_hex).await?;
            cursor = None;
            stored.clear();
        }
        let start_height = cursor.as_ref().map_or(coverage_start_height.min(stop_height),
            |cursor| cursor.last_scanned_height.saturating_add(1));
        let mut outpoints = HashMap::new();
        for mut outpoint in stored {
            if let Some(tx_out) = client_config.chain_client.get_stored_tx_out(&outpoint.txid, outpoint.vout, true)? {
                if tx_out.script_pubkey == script {
                    outpoint.value = tx_out.value;
                    outpoint.height = if tx_out.confirmations == 0 {
                        0
                    } else {
                        stop_height.saturating_sub(tx_out.confirmations).saturating_add(1)
                    };
                    outpoints.insert((outpoint.txid.clone(), outpoint.vout), outpoint);
                }
            }
        }
        states.insert(script, DescriptorScanState {
            descriptor,
            start_height,
            result_start_height,
            cursor,
            outpoints,
        });
    }
    if states.is_empty() {
        return Ok(HashMap::new());
    }
    let descriptors = states.values().map(|state| state.descriptor.clone()).collect::<Vec<_>>();
    let scan_start = states.values().map(|state| state.start_height).min().unwrap();
    let (scanned, activity) = retry_discovery_once(|| {
        let scan = (scan_start <= stop_height)
            .then(|| client_config.chain_client.scan_blocks(&descriptors, scan_start, stop_height))
            .transpose()?;
        if scan.as_ref().is_some_and(|scan| !scan.completed) {
            return Err(anyhow!("Bitcoin Core scanblocks did not complete"));
        }
        let blocks = scan.as_ref().map_or(&[][..], |scan| scan.relevant_blocks.as_slice());
        let activity = client_config.chain_client.descriptor_activity(blocks, &descriptors, true)?;
        Ok((scan.is_some(), activity))
    })?;
    let post_scan_tip = client_config.chain_client.tip_height()?;
    let stop_hash_matches = post_scan_tip >= stop_height
        && client_config
            .chain_client
            .get_block_hash(stop_height)?
            .to_string()
            == stop_block_hash;
    let mut unstable_scripts = Vec::new();
    for (script, state) in &states {
        let cursor_matches = match &state.cursor {
            Some(cursor) if cursor.last_scanned_height > post_scan_tip => false,
            Some(cursor) => {
                client_config
                    .chain_client
                    .get_block_hash(cursor.last_scanned_height)?
                    .to_string()
                    == cursor.last_scanned_block_hash
            }
            None => true,
        };
        if !stop_hash_matches || !cursor_matches {
            unstable_scripts.push(script.clone());
        }
    }
    if !unstable_scripts.is_empty() {
        for script in unstable_scripts {
            clear_bip448_scan_state(
                &client_config.pool,
                wallet_name,
                &hex::encode(script.as_bytes()),
            )
            .await?;
        }
        if !retry_reorg {
            return Err(anyhow!(
                "Bitcoin chain changed repeatedly during descriptor discovery"
            ));
        }
        return Box::pin(discover_unspent_batch_attempt(
            client_config,
            wallet_name,
            requests,
            false,
        ))
        .await;
    }
    for event in activity {
        let (script, height, key, received) = match event {
            DescriptorActivity::Receive {
                amount,
                height,
                txid,
                vout,
                output_spk,
            } => {
                let txid = txid.to_string();
                (output_spk, height, (txid.clone(), vout), Some(ChainUtxo {
                    txid, vout, value: amount, height: height.unwrap_or(0),
                }))
            }
            DescriptorActivity::Spend {
                height,
                prevout_txid,
                prevout_vout,
                prevout_spk,
                ..
            } => (prevout_spk, height, (prevout_txid.to_string(), prevout_vout), None),
        };
        if let Some(state) = states.get_mut(&script) {
            if height.map_or(true, |height| height >= state.start_height) {
                state.outpoints.remove(&key);
                if let Some(outpoint) = received {
                    state.outpoints.insert(key, outpoint);
                }
            }
        }
    }
    let scanned_cursor = if scanned {
        Some(Bip448ScanCursor {
                last_scanned_height: stop_height,
                last_scanned_block_hash: stop_block_hash,
        })
    } else {
        None
    };
    let mut result = HashMap::new();
    for (script, state) in states {
        let cursor = scanned_cursor.as_ref().or(state.cursor.as_ref()).unwrap();
        let outpoints = state.outpoints.into_values().collect::<Vec<_>>();
        persist_bip448_scan_state(&client_config.pool, wallet_name,
            &hex::encode(script.as_bytes()), cursor, &outpoints).await?;
        result.insert(
            script,
            outpoints
                .into_iter()
                .filter(|outpoint| {
                    outpoint.height == 0 || outpoint.height >= state.result_start_height
                })
                .collect(),
        );
    }
    Ok(result)
}

pub(crate) async fn discover_unspent(
    client_config: &ClientConfig,
    wallet_name: &str,
    address: &Address,
    start_height: u32,
) -> Result<Vec<ChainUtxo>> {
    let request = DescriptorDiscoveryRequest {
        address: address.clone(),
        coverage_start_height: start_height,
        result_start_height: start_height,
    };
    let mut discovered = discover_unspent_batch(client_config, wallet_name, &[request]).await?;
    Ok(discovered.remove(&address.script_pubkey()).unwrap_or_default())
}

fn retry_discovery_once<T>(mut operation: impl FnMut() -> Result<T>) -> Result<T> {
    operation().or_else(|_| operation())
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
    utxo_list: Vec<ChainUtxo>,
    coin: &Coin,
    pending_signing: Option<&crate::sqlite_manager::Bip448PendingDepositSigning>,
    accepted_state: Option<&Bip448StatechainRecord>,
    expected_value: Option<u64>,
) -> Option<ChainUtxo> {
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
            .filter(|unspent| {
                unspent.height == 0 || unspent.height >= wallet_blockheight
            })
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

async fn check_transfer(client_config: &ClientConfig, coin: &Coin) -> Result<bool> {
    if coin.statechain_id.is_none() {
        return Err(anyhow!("Coin does not have a statechain ID"));
    }

    let statechain_id = coin.statechain_id.as_ref().unwrap();

    let statechain_info = crate::utils::get_statechain_info(statechain_id, &client_config).await?;

    // if the statechain info is not found, we assume the coin has been transferred
    if statechain_info.is_none() {
        return Ok(true);
    }

    let statechain_info = statechain_info.unwrap();

    let enclave_public_key = statechain_info.enclave_public_key;

    // if the enclave's public key is no longer part of the coin, the coin has been transferred
    let is_transferred = !is_enclave_pubkey_part_of_coin(&coin, &enclave_public_key)?;

    return Ok(is_transferred);
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

async fn discover_wallet_unspent(
    client_config: &ClientConfig,
    wallet: &Wallet,
) -> Result<HashMap<ScriptBuf, Vec<ChainUtxo>>> {
    let mut requests = Vec::new();
    for coin in &wallet.coins {
        if !matches!(
            coin.status,
            CoinStatus::INITIALISED
                | CoinStatus::IN_MEMPOOL
                | CoinStatus::UNCONFIRMED
                | CoinStatus::CONFIRMED
        ) || funding_outpoint_is_partial(coin)
            || deposit_setup_is_incomplete(coin)
            || coin.statechain_id.is_none()
        {
            continue;
        }
        let Some(address) = coin.aggregated_address.as_deref() else {
            continue;
        };
        let address = Address::from_str(address)?.require_network(client_config.network)?;

        if coin.utxo_txid.is_some() {
            continue;
        }
        let statechain_id = coin.statechain_id.as_deref().unwrap();
        let has_persisted_outpoint =
            get_bip448_pending_deposit_signing(&client_config.pool, &wallet.name, statechain_id)
                .await?
                .is_some()
                || get_bip448_statechain_optional(
                    &client_config.pool,
                    &wallet.name,
                    statechain_id,
                )
                .await?
                .is_some();
        if !has_persisted_outpoint {
            requests.push(DescriptorDiscoveryRequest {
                address,
                coverage_start_height: wallet.blockheight,
                result_start_height: wallet.blockheight,
            });
        }
    }

    discover_unspent_batch(client_config, &wallet.name, &requests).await
}

async fn finalize_wallet_update(
    client_config: &ClientConfig,
    wallet: &mut Wallet,
    deferred_errors: Vec<DeferredBip448DepositError>,
) -> Result<()> {
    update_wallet(&client_config.pool, wallet).await?;

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

pub async fn update_coins(client_config: &ClientConfig, wallet_name: &str) -> Result<()> {
    let mut wallet = get_wallet(&client_config.pool, &wallet_name).await?;
    for coin in &wallet.coins {
        if let Some(statechain_id) = coin.statechain_id.as_deref() {
            if coin.statechain_protocol.as_deref()
                != Some(bip448_deposit::BIP448_COIN_PROTOCOL)
            {
                return Err(anyhow!(
                    "statechain {statechain_id}: unsupported non-BIP448 coin"
                ));
            }
        }
    }
    let discovered = discover_wallet_unspent(client_config, &wallet).await?;

    let network = wallet.network.clone();
    let wallet_blockheight = wallet.blockheight;
    let mut deferred_bip448_deposit_errors = Vec::new();

    for coin in wallet.coins.iter_mut() {
        if coin.statechain_id.is_none() && deposit_setup_is_incomplete(coin) {
            continue;
        }

        if coin.status == CoinStatus::INITIALISED
            || coin.status == CoinStatus::IN_MEMPOOL
            || coin.status == CoinStatus::UNCONFIRMED
        {
            let deposit_result = match check_bip448_deposit(
                client_config,
                &wallet.name,
                coin,
                &network,
                wallet_blockheight,
                &discovered,
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
                wallet.activities.push(deposit_result.activity);
            }
        } else if coin.status == CoinStatus::IN_TRANSFER {
            let is_transferred = check_transfer(client_config, coin).await?;

            if is_transferred {
                coin.status = CoinStatus::TRANSFERRED;
            }
        } else if coin.status == CoinStatus::WITHDRAWING {
            check_withdrawal(client_config, coin).await?;
        }
    }

    finalize_wallet_update(
        client_config,
        &mut wallet,
        deferred_bip448_deposit_errors,
    )
    .await
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
    use mercurylib::wallet::{Settings, Wallet};
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
            core_rpc_url: Some("http://127.0.0.1:1".to_string()),
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

        assert!(
            check_bip448_deposit(
                &client_config,
                "wallet",
                &mut bip448_coin,
                "regtest",
                0,
                &HashMap::new(),
            )
                .await?
                .is_none()
        );

        bip448_coin.utxo_txid = Some("aa".repeat(32));
        let bip448_error =
            check_bip448_deposit(
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
        let bip448_error =
            check_bip448_deposit(
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
        let bip448_error =
            check_bip448_deposit(
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
        let bip448_error =
            check_bip448_deposit(
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

        let error = finalize_wallet_update(
            &client_config,
            &mut wallet,
            deferred_errors,
        )
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
    fn descriptor_activity_assembles_receives_minus_later_spends() {
        let activity: Vec<DescriptorActivity> = serde_json::from_str(r#"[
            {"type":"receive","amount":0.00010000,"height":10,"txid":"1111111111111111111111111111111111111111111111111111111111111111","vout":0,"output_spk":{"hex":"51"}},
            {"type":"receive","amount":0.00020000,"height":11,"txid":"2222222222222222222222222222222222222222222222222222222222222222","vout":1,"output_spk":{"hex":"51"}},
            {"type":"spend","height":12,"spend_txid":"4444444444444444444444444444444444444444444444444444444444444444","prevout_txid":"1111111111111111111111111111111111111111111111111111111111111111","prevout_vout":0,"prevout_spk":{"hex":"51"}}
        ]"#).unwrap();
        let unspent = unspent_from_descriptor_activity(activity);
        assert_eq!(unspent.len(), 1);
        assert_eq!((unspent[0].value, unspent[0].height), (20_000, 11));
    }

    #[test]
    fn discovery_retries_the_whole_operation_once() {
        let mut results = [Err(anyhow!("reorg")), Ok(())].into_iter();
        retry_discovery_once(|| results.next().unwrap()).unwrap();
        assert!(results.next().is_none());
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
