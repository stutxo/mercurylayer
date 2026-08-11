use crate::utils::create_activity;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::str::FromStr;

use anyhow::{anyhow, Ok, Result};
use bitcoin::{Address, ScriptBuf, Txid};
use mercurylib::{
    bip448_statechain::{
        deposit::{self as bip448_deposit, Bip448DepositError},
        storage::Bip448StatechainRecord,
    },
    wallet::{Activity, Coin, CoinStatus, Wallet},
};

use crate::bip448_funding::{
    Bip448BindingObservation, Bip448BindingRole, Bip448FundingBinding, Bip448ObservationStatus,
    Bip448OwnershipStatus, Bip448SyncBase, Bip448SyncReport, Bip448WithdrawalAttempt,
    Bip448WithdrawalPhase,
};
use crate::{
    bip448_owner::{
        classify_bip448_owner_relation, get_bip448_statechain_presence, Bip448OwnerRelation,
        Bip448StatechainPresence,
    },
    chain::{ChainUtxo, DescriptorActivity},
    client_config::ClientConfig,
    deposit::create_bip448_deposit_state,
    sqlite_manager::{
        begin_bip448_sync_base_guard, capture_bip448_sync_base,
        compare_and_set_wallet_after_bip448_scan, delete_bip448_pending_deposit_signing,
        get_bip448_pending_deposit_signing, get_bip448_raw_wallet_json, get_bip448_state_history,
        get_bip448_statechain_optional, list_bip448_funding_bindings, load_bip448_scan_state,
        persist_bip448_scan_state, recover_bip448_initial_acceptance_wallet,
        Bip448InitialAcceptanceRecovery, Bip448ScanCursor,
    },
};

struct Bip448DepositResult {
    activity: Activity,
    accepted_state_materialized: bool,
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

    let mut unspent = receives.into_values().collect::<Vec<_>>();
    sort_chain_utxos(&mut unspent);
    unspent
}

fn sort_chain_utxos(outpoints: &mut [ChainUtxo]) {
    outpoints.sort_by(|left, right| {
        let left_mempool = left.height == 0;
        let right_mempool = right.height == 0;
        (left_mempool, left.height, left.txid.as_str(), left.vout).cmp(&(
            right_mempool,
            right.height,
            right.txid.as_str(),
            right.vout,
        ))
    });
}

struct DescriptorScanState {
    descriptor: String,
    coverage_start_height: u32,
    start_height: u32,
    result_start_height: u32,
    cursor: Option<Bip448ScanCursor>,
    cursor_logically_invalidated: bool,
    outpoints: HashMap<(String, u32), ChainUtxo>,
}

#[derive(Clone)]
struct DescriptorDiscoveryRequest {
    address: Address,
    // This is the durable, monotonic-nondecreasing-in-coverage scan floor.
    coverage_start_height: u32,
    result_start_height: u32,
}

fn prior_cursor_matches_post_scan(
    cursor: Option<&Bip448ScanCursor>,
    post_scan_tip: u32,
    cursor_logically_invalidated: bool,
    mut block_hash_at: impl FnMut(u32) -> Result<String>,
) -> Result<bool> {
    if cursor_logically_invalidated {
        return Ok(true);
    }
    let Some(cursor) = cursor else {
        return Ok(true);
    };
    if cursor.last_scanned_height > post_scan_tip {
        return Ok(false);
    }
    Ok(block_hash_at(cursor.last_scanned_height)? == cursor.last_scanned_block_hash)
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
        let (cursor, mut stored) =
            load_bip448_scan_state(&client_config.pool, wallet_name, &script_hex).await?;
        let cursor_matches = match &cursor {
            Some(cursor) if cursor.last_scanned_height > stop_height => false,
            Some(cursor) => {
                client_config
                    .chain_client
                    .get_block_hash(cursor.last_scanned_height)?
                    .to_string()
                    == cursor.last_scanned_block_hash
            }
            None => true,
        };
        let lower_floor_requested = cursor
            .as_ref()
            .is_some_and(|cursor| coverage_start_height < cursor.coverage_start_height);
        let cursor_logically_invalidated = !cursor_matches || lower_floor_requested;
        if cursor_logically_invalidated {
            stored.clear();
        }
        let start_height = if cursor_logically_invalidated {
            coverage_start_height.min(stop_height)
        } else {
            cursor
                .as_ref()
                .map_or(coverage_start_height.min(stop_height), |cursor| {
                    cursor.last_scanned_height.saturating_add(1)
                })
        };
        let mut outpoints = HashMap::new();
        for mut outpoint in stored {
            if let Some(tx_out) =
                client_config
                    .chain_client
                    .get_stored_tx_out(&outpoint.txid, outpoint.vout, true)?
            {
                if tx_out.script_pubkey == script {
                    outpoint.value = tx_out.value;
                    outpoint.height = if tx_out.confirmations == 0 {
                        0
                    } else {
                        stop_height
                            .saturating_sub(tx_out.confirmations)
                            .saturating_add(1)
                    };
                    outpoints.insert((outpoint.txid.clone(), outpoint.vout), outpoint);
                }
            }
        }
        states.insert(
            script,
            DescriptorScanState {
                descriptor,
                coverage_start_height,
                start_height,
                result_start_height,
                cursor,
                cursor_logically_invalidated,
                outpoints,
            },
        );
    }
    if states.is_empty() {
        return Ok(HashMap::new());
    }
    let descriptors = states
        .values()
        .map(|state| state.descriptor.clone())
        .collect::<Vec<_>>();
    let scan_start = states
        .values()
        .map(|state| state.start_height)
        .min()
        .unwrap();
    let (scanned, activity) = retry_discovery_once(|| {
        let scan = (scan_start <= stop_height)
            .then(|| {
                client_config
                    .chain_client
                    .scan_blocks(&descriptors, scan_start, stop_height)
            })
            .transpose()?;
        if scan.as_ref().is_some_and(|scan| !scan.completed) {
            return Err(anyhow!("Bitcoin Core scanblocks did not complete"));
        }
        let blocks = scan
            .as_ref()
            .map_or(&[][..], |scan| scan.relevant_blocks.as_slice());
        let activity =
            client_config
                .chain_client
                .descriptor_activity(blocks, &descriptors, true)?;
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
        let cursor_matches = prior_cursor_matches_post_scan(
            state.cursor.as_ref(),
            post_scan_tip,
            state.cursor_logically_invalidated,
            |height| {
                Ok(client_config
                    .chain_client
                    .get_block_hash(height)?
                    .to_string())
            },
        )?;
        if !stop_hash_matches || !cursor_matches {
            unstable_scripts.push(script.clone());
        }
    }
    if !unstable_scripts.is_empty() {
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
                (
                    output_spk,
                    height,
                    (txid.clone(), vout),
                    Some(ChainUtxo {
                        txid,
                        vout,
                        value: amount,
                        height: height.unwrap_or(0),
                    }),
                )
            }
            DescriptorActivity::Spend {
                height,
                prevout_txid,
                prevout_vout,
                prevout_spk,
                ..
            } => (
                prevout_spk,
                height,
                (prevout_txid.to_string(), prevout_vout),
                None,
            ),
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
    let mut result = HashMap::new();
    for (script, state) in states {
        let cursor = if scanned {
            Bip448ScanCursor {
                coverage_start_height: state.cursor.as_ref().map_or(
                    state.coverage_start_height,
                    |cursor| {
                        cursor
                            .coverage_start_height
                            .min(state.coverage_start_height)
                    },
                ),
                scan_revision: state
                    .cursor
                    .as_ref()
                    .map_or(0, |cursor| cursor.scan_revision),
                last_scanned_height: stop_height,
                last_scanned_block_hash: stop_block_hash.clone(),
            }
        } else {
            state
                .cursor
                .clone()
                .ok_or_else(|| anyhow!("BIP448 scan cursor is absent for an unscanned script"))?
        };
        let outpoints = state.outpoints.into_values().collect::<Vec<_>>();
        persist_bip448_scan_state(
            &client_config.pool,
            wallet_name,
            &hex::encode(script.as_bytes()),
            &cursor,
            &outpoints,
        )
        .await?;
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
    Ok(discovered
        .remove(&address.script_pubkey())
        .unwrap_or_default())
}

fn retry_discovery_once<T>(mut operation: impl FnMut() -> Result<T>) -> Result<T> {
    operation().or_else(|_| operation())
}

#[derive(Clone)]
struct Bip448ScriptSyncPlan {
    descriptor: String,
    script_pubkey: ScriptBuf,
    coverage_start_height: u32,
    result_start_height: u32,
    statechain_ids: Vec<String>,
}

#[derive(Clone)]
struct Bip448ReceiveFact {
    value_sats: u64,
    funding_height: Option<u32>,
}

#[derive(Clone)]
struct Bip448SpendFact {
    spend_txid: String,
    spend_height: Option<u32>,
}

struct Bip448AcceptedScanTarget {
    statechain_id: String,
    owner_user_pubkey: String,
    owner_state_number: u32,
    canonical_txid: String,
    canonical_vout: u32,
    existing_bindings: Vec<Bip448FundingBinding>,
}

struct Bip448ScriptScanCandidate {
    base: Bip448SyncBase,
    script_pubkey: String,
    cursor: Bip448ScanCursor,
    current_unspent: Vec<ChainUtxo>,
    discovered_unspent: Vec<ChainUtxo>,
    observations: Vec<Bip448BindingObservation>,
    accepted_targets: Vec<Bip448AcceptedScanTarget>,
    tip_height: u32,
    tip_hash: String,
    requires_authoritative_replay: bool,
}

struct Bip448SyncOutcome {
    report: Bip448SyncReport,
    discovered: HashMap<ScriptBuf, Vec<ChainUtxo>>,
    raw_wallet_json: String,
}

#[derive(Debug, PartialEq, Eq)]
struct Bip448ResolvedObservation {
    observation_status: Bip448ObservationStatus,
    funding_height: Option<u32>,
    spend_txid: Option<String>,
    spend_height: Option<u32>,
}

fn funding_status_at_tip(
    height: Option<u32>,
    tip_height: u32,
    confirmation_target: u32,
    spent: bool,
) -> Result<Bip448ObservationStatus> {
    let confirmations = match height {
        Some(height) => tip_height
            .checked_sub(height)
            .and_then(|distance| distance.checked_add(1))
            .ok_or_else(|| anyhow!("BIP448 observation height exceeds the stable scan tip"))?,
        None => 0,
    };
    Ok(
        match (spent, height, confirmations >= confirmation_target) {
            (false, None, _) => Bip448ObservationStatus::Mempool,
            (false, Some(_), true) => Bip448ObservationStatus::Confirmed,
            (false, Some(_), false) => Bip448ObservationStatus::Unconfirmed,
            (true, None, _) => Bip448ObservationStatus::SpentMempool,
            (true, Some(_), true) => Bip448ObservationStatus::SpentConfirmed,
            (true, Some(_), false) => Bip448ObservationStatus::SpentUnconfirmed,
        },
    )
}

fn height_from_confirmations(tip_height: u32, confirmations: u32) -> Result<Option<u32>> {
    if confirmations == 0 {
        return Ok(None);
    }
    tip_height
        .checked_sub(confirmations - 1)
        .map(Some)
        .ok_or_else(|| anyhow!("BIP448 gettxout confirmations exceed the stable scan tip"))
}

fn retained_observation_status_at_tip(
    status: Bip448ObservationStatus,
    spend_height: Option<u32>,
    tip_height: u32,
    confirmation_target: u32,
) -> Result<Bip448ObservationStatus> {
    if status != Bip448ObservationStatus::SpentUnconfirmed {
        return Ok(status);
    }
    let spend_height = spend_height
        .ok_or_else(|| anyhow!("SpentUnconfirmed BIP448 observation is missing spend height"))?;
    funding_status_at_tip(Some(spend_height), tip_height, confirmation_target, true)
}

fn resolve_bip448_observation_at_tip(
    current: Option<&ChainUtxo>,
    spend: Option<&Bip448SpendFact>,
    receive: Option<&Bip448ReceiveFact>,
    existing: Option<&Bip448FundingBinding>,
    authoritative_full_scan: bool,
    tip_height: u32,
    confirmation_target: u32,
) -> Result<Option<Bip448ResolvedObservation>> {
    if let Some(current) = current {
        let funding_height = (current.height != 0).then_some(current.height);
        return Ok(Some(Bip448ResolvedObservation {
            observation_status: funding_status_at_tip(
                funding_height,
                tip_height,
                confirmation_target,
                false,
            )?,
            funding_height,
            spend_txid: None,
            spend_height: None,
        }));
    }
    if let Some(spend) = spend {
        // A fresh receive fact, including an explicit mempool receive, is
        // authoritative for the funding height. Fall back to the durable
        // height only when this incremental interval contains no receive.
        let funding_height = receive.map_or_else(
            || existing.and_then(|binding| binding.funding_height),
            |receive| receive.funding_height,
        );
        return Ok(Some(Bip448ResolvedObservation {
            observation_status: funding_status_at_tip(
                spend.spend_height,
                tip_height,
                confirmation_target,
                true,
            )?,
            funding_height,
            spend_txid: Some(spend.spend_txid.clone()),
            spend_height: spend.spend_height,
        }));
    }
    if let Some(receive) = receive {
        return Ok(Some(Bip448ResolvedObservation {
            observation_status: funding_status_at_tip(
                receive.funding_height,
                tip_height,
                confirmation_target,
                false,
            )?,
            funding_height: receive.funding_height,
            spend_txid: None,
            spend_height: None,
        }));
    }
    if authoritative_full_scan {
        return Ok(Some(Bip448ResolvedObservation {
            observation_status: Bip448ObservationStatus::Absent,
            funding_height: None,
            spend_txid: None,
            spend_height: None,
        }));
    }
    let Some(existing) = existing else {
        return Ok(None);
    };
    Ok(Some(Bip448ResolvedObservation {
        observation_status: retained_observation_status_at_tip(
            existing.observation_status,
            existing.spend_height,
            tip_height,
            confirmation_target,
        )?,
        funding_height: existing.funding_height,
        spend_txid: existing.spend_txid.clone(),
        spend_height: existing.spend_height,
    }))
}

fn insert_receive_fact(
    receives: &mut BTreeMap<(String, u32), Bip448ReceiveFact>,
    key: (String, u32),
    fact: Bip448ReceiveFact,
) -> Result<()> {
    if let Some(existing) = receives.get(&key) {
        if existing.value_sats != fact.value_sats || existing.funding_height != fact.funding_height
        {
            return Err(anyhow!("conflicting BIP448 receive observations"));
        }
        return Ok(());
    }
    receives.insert(key, fact);
    Ok(())
}

fn spend_fact_order(fact: &Bip448SpendFact) -> (bool, u32, &str) {
    (
        fact.spend_height.is_none(),
        fact.spend_height.unwrap_or(u32::MAX),
        fact.spend_txid.as_str(),
    )
}

fn insert_spend_fact(
    spends: &mut BTreeMap<(String, u32), Bip448SpendFact>,
    key: (String, u32),
    fact: Bip448SpendFact,
) {
    match spends.get(&key) {
        Some(existing) if spend_fact_order(existing) <= spend_fact_order(&fact) => {}
        _ => {
            spends.insert(key, fact);
        }
    }
}

fn disappeared_mempool_receive_requires_authoritative_replay(
    authoritative: bool,
    existing_status: Bip448ObservationStatus,
    current: bool,
    receive: bool,
    spend: bool,
) -> bool {
    !authoritative
        && existing_status == Bip448ObservationStatus::Mempool
        && !current
        && !receive
        && !spend
}

fn require_stable_authoritative_replay_base(
    incremental: &Bip448SyncBase,
    replay: &Bip448SyncBase,
) -> Result<()> {
    if incremental != replay {
        return Err(anyhow!(
            "BIP448 synchronization base changed during authoritative mempool replay"
        ));
    }
    Ok(())
}

async fn build_bip448_script_sync_plans(
    client_config: &ClientConfig,
    wallet: &Wallet,
) -> Result<Vec<Bip448ScriptSyncPlan>> {
    let mut plans = BTreeMap::<String, Bip448ScriptSyncPlan>::new();
    for coin in &wallet.coins {
        if coin.statechain_protocol.as_deref() != Some(bip448_deposit::BIP448_COIN_PROTOCOL) {
            continue;
        }
        let (Some(statechain_id), Some(address)) = (
            coin.statechain_id.as_deref(),
            coin.aggregated_address.as_deref(),
        ) else {
            continue;
        };
        let address = Address::from_str(address)?.require_network(client_config.network)?;
        let script_pubkey = address.script_pubkey();
        let script_hex = hex::encode(script_pubkey.as_bytes());
        let accepted =
            get_bip448_statechain_optional(&client_config.pool, &wallet.name, statechain_id)
                .await?
                .is_some();
        let pending =
            get_bip448_pending_deposit_signing(&client_config.pool, &wallet.name, statechain_id)
                .await?
                .is_some();
        let pinned = accepted || pending || (coin.utxo_txid.is_some() && coin.utxo_vout.is_some());
        let requested_floor = if pinned { 0 } else { wallet.blockheight };
        let entry = plans
            .entry(script_hex)
            .or_insert_with(|| Bip448ScriptSyncPlan {
                descriptor: format!("addr({address})"),
                script_pubkey,
                coverage_start_height: requested_floor,
                result_start_height: wallet.blockheight,
                statechain_ids: Vec::new(),
            });
        entry.coverage_start_height = entry.coverage_start_height.min(requested_floor);
        entry.result_start_height = entry.result_start_height.min(wallet.blockheight);
        if !entry
            .statechain_ids
            .iter()
            .any(|existing| existing == statechain_id)
        {
            entry.statechain_ids.push(statechain_id.to_owned());
        }
    }
    let mut plans = plans.into_values().collect::<Vec<_>>();
    for plan in &mut plans {
        plan.statechain_ids.sort();
    }
    Ok(plans)
}

async fn scan_bip448_script_candidate(
    client_config: &ClientConfig,
    wallet_name: &str,
    expected_raw_wallet_json: &str,
    plan: &Bip448ScriptSyncPlan,
    force_authoritative: bool,
) -> Result<Bip448ScriptScanCandidate> {
    let script_hex = hex::encode(plan.script_pubkey.as_bytes());
    let base = capture_bip448_sync_base(&client_config.pool, wallet_name, &script_hex).await?;
    if base.raw_wallet_json != expected_raw_wallet_json {
        return Err(anyhow!(
            "BIP448 synchronization base changed before script capture"
        ));
    }

    let (cursor, mut cached_unspent) =
        load_bip448_scan_state(&client_config.pool, wallet_name, &script_hex).await?;
    sort_chain_utxos(&mut cached_unspent);
    let mut coverage_start_height = plan.coverage_start_height;
    let mut accepted_targets = Vec::new();
    for statechain_id in &plan.statechain_ids {
        let record =
            get_bip448_statechain_optional(&client_config.pool, wallet_name, statechain_id).await?;
        let history =
            get_bip448_state_history(&client_config.pool, wallet_name, statechain_id).await?;
        let pending =
            get_bip448_pending_deposit_signing(&client_config.pool, wallet_name, statechain_id)
                .await?;
        if record.is_none() && !history.is_empty() {
            return Err(anyhow!(
                "BIP448 state history exists without its accepted record"
            ));
        }
        if pending.is_some() || record.is_some() {
            coverage_start_height = 0;
        }
        let Some(record) = record else {
            continue;
        };
        let owner_index = usize::try_from(record.latest_state_number)?
            .checked_sub(1)
            .ok_or_else(|| anyhow!("BIP448 accepted state number must be positive"))?;
        let owner = history
            .get(owner_index)
            .ok_or_else(|| anyhow!("BIP448 accepted state history is incomplete"))?;
        if history.len() < usize::try_from(record.latest_state_number)? {
            return Err(anyhow!("BIP448 accepted state history is incomplete"));
        }
        accepted_targets.push(Bip448AcceptedScanTarget {
            statechain_id: statechain_id.clone(),
            owner_user_pubkey: owner.owner_public_key.clone(),
            owner_state_number: record.latest_state_number,
            canonical_txid: record.funding_outpoint.txid.clone(),
            canonical_vout: record.funding_outpoint.vout,
            existing_bindings: list_bip448_funding_bindings(
                &client_config.pool,
                wallet_name,
                statechain_id,
            )
            .await?,
        });
    }

    let tip_height = client_config.chain_client.tip_height()?;
    let tip_hash = client_config
        .chain_client
        .get_block_hash(tip_height)?
        .to_string();
    let cursor_matches = match &cursor {
        Some(cursor) if cursor.last_scanned_height > tip_height => false,
        Some(cursor) => {
            client_config
                .chain_client
                .get_block_hash(cursor.last_scanned_height)?
                .to_string()
                == cursor.last_scanned_block_hash
        }
        None => true,
    };
    let lower_floor_requested = cursor
        .as_ref()
        .is_some_and(|cursor| coverage_start_height < cursor.coverage_start_height);
    let cursor_invalidated = !cursor_matches || lower_floor_requested;
    let authoritative = force_authoritative || cursor_invalidated || cursor.is_none();
    if authoritative {
        cached_unspent.clear();
    }
    let start_height = if authoritative {
        coverage_start_height.min(tip_height)
    } else {
        cursor
            .as_ref()
            .map_or(coverage_start_height.min(tip_height), |cursor| {
                cursor.last_scanned_height.saturating_add(1)
            })
    };

    let descriptors = vec![plan.descriptor.clone()];
    let relevant_blocks = if start_height <= tip_height {
        let scan =
            client_config
                .chain_client
                .scan_blocks(&descriptors, start_height, tip_height)?;
        if !scan.completed {
            return Err(anyhow!("Bitcoin Core scanblocks did not complete"));
        }
        scan.relevant_blocks
    } else {
        Vec::new()
    };
    let mut activity =
        client_config
            .chain_client
            .descriptor_activity(&relevant_blocks, &descriptors, true)?;
    activity.sort_by(|left, right| {
        let key = |event: &DescriptorActivity| match event {
            DescriptorActivity::Receive {
                height, txid, vout, ..
            } => (0_u8, height.unwrap_or(u32::MAX), txid.to_string(), *vout),
            DescriptorActivity::Spend {
                height,
                spend_txid,
                prevout_vout,
                ..
            } => (
                1_u8,
                height.unwrap_or(u32::MAX),
                spend_txid.to_string(),
                *prevout_vout,
            ),
        };
        key(left).cmp(&key(right))
    });
    let mut receives = BTreeMap::new();
    let mut spends = BTreeMap::new();
    for event in activity {
        match event {
            DescriptorActivity::Receive {
                amount,
                height,
                txid,
                vout,
                output_spk,
            } if output_spk == plan.script_pubkey
                && height.map_or(true, |height| height >= start_height) =>
            {
                insert_receive_fact(
                    &mut receives,
                    (txid.to_string(), vout),
                    Bip448ReceiveFact {
                        value_sats: amount,
                        funding_height: height,
                    },
                )?;
            }
            DescriptorActivity::Spend {
                height,
                spend_txid,
                prevout_txid,
                prevout_vout,
                prevout_spk,
            } if prevout_spk == plan.script_pubkey
                && height.map_or(true, |height| height >= start_height) =>
            {
                insert_spend_fact(
                    &mut spends,
                    (prevout_txid.to_string(), prevout_vout),
                    Bip448SpendFact {
                        spend_txid: spend_txid.to_string(),
                        spend_height: height,
                    },
                );
            }
            _ => {}
        }
    }

    let mut known_keys = receives.keys().cloned().collect::<BTreeSet<_>>();
    known_keys.extend(spends.keys().cloned());
    known_keys.extend(
        cached_unspent
            .iter()
            .map(|outpoint| (outpoint.txid.clone(), outpoint.vout)),
    );
    for target in &accepted_targets {
        known_keys.extend(
            target
                .existing_bindings
                .iter()
                .map(|binding| (binding.txid.clone(), binding.vout)),
        );
        known_keys.insert((target.canonical_txid.clone(), target.canonical_vout));
    }
    let cached_by_key = cached_unspent
        .into_iter()
        .map(|outpoint| ((outpoint.txid.clone(), outpoint.vout), outpoint))
        .collect::<BTreeMap<_, _>>();
    let mut current_by_key = BTreeMap::new();
    for (txid, vout) in &known_keys {
        let Some(tx_out) = client_config
            .chain_client
            .get_stored_tx_out(txid, *vout, true)?
        else {
            continue;
        };
        if tx_out.script_pubkey != plan.script_pubkey {
            if accepted_targets.iter().any(|target| {
                target
                    .existing_bindings
                    .iter()
                    .any(|binding| binding.txid == *txid && binding.vout == *vout)
            }) {
                return Err(anyhow!("BIP448 known binding gettxout script changed"));
            }
            continue;
        }
        let funding_height = height_from_confirmations(tip_height, tx_out.confirmations)?;
        if let Some(receive) = receives.get(&(txid.clone(), *vout)) {
            if receive.value_sats != tx_out.value {
                return Err(anyhow!("BIP448 receive/gettxout value mismatch"));
            }
        }
        current_by_key.insert(
            (txid.clone(), *vout),
            ChainUtxo {
                txid: txid.clone(),
                vout: *vout,
                value: tx_out.value,
                height: funding_height.unwrap_or(0),
            },
        );
    }

    let post_tip_height = client_config.chain_client.tip_height()?;
    let post_tip_hash = client_config
        .chain_client
        .get_block_hash(post_tip_height)?
        .to_string();
    if post_tip_height != tip_height || post_tip_hash != tip_hash {
        return Err(anyhow!(
            "BIP448 synchronization chain changed during descriptor scan"
        ));
    }

    let existing_by_key = accepted_targets
        .iter()
        .flat_map(|target| target.existing_bindings.iter())
        .map(|binding| ((binding.txid.clone(), binding.vout), binding))
        .collect::<BTreeMap<_, _>>();
    let requires_authoritative_replay = !authoritative
        && existing_by_key.iter().any(|(key, binding)| {
            disappeared_mempool_receive_requires_authoritative_replay(
                authoritative,
                binding.observation_status,
                current_by_key.contains_key(key),
                receives.contains_key(key),
                spends.contains_key(key),
            )
        });
    let mut observations = Vec::new();
    for (txid, vout) in known_keys {
        let key = (txid.clone(), vout);
        let receive = receives.get(&key);
        let spend = spends.get(&key);
        let current = current_by_key.get(&key);
        let existing = existing_by_key.get(&key).copied();
        let value_sats = current
            .map(|outpoint| outpoint.value)
            .or_else(|| receive.map(|fact| fact.value_sats))
            .or_else(|| cached_by_key.get(&key).map(|outpoint| outpoint.value))
            .or_else(|| existing.map(|binding| binding.value_sats));
        let Some(value_sats) = value_sats else {
            continue;
        };
        if existing.is_some_and(|binding| binding.value_sats != value_sats) {
            return Err(anyhow!("BIP448 binding observation value changed"));
        }
        let Some(resolved) = resolve_bip448_observation_at_tip(
            current,
            spend,
            receive,
            existing,
            authoritative && coverage_start_height == 0,
            tip_height,
            client_config.confirmation_target,
        )?
        else {
            continue;
        };
        observations.push(Bip448BindingObservation {
            txid,
            vout,
            value_sats,
            script_pubkey: script_hex.clone(),
            observation_status: resolved.observation_status,
            funding_height: resolved.funding_height,
            spend_txid: resolved.spend_txid,
            spend_height: resolved.spend_height,
            last_scanned_height: tip_height,
        });
    }
    observations.sort_by(|left, right| {
        (left.txid.as_str(), left.vout).cmp(&(right.txid.as_str(), right.vout))
    });
    let mut current_unspent = current_by_key.into_values().collect::<Vec<_>>();
    sort_chain_utxos(&mut current_unspent);
    let discovered_unspent = current_unspent
        .iter()
        .filter(|outpoint| outpoint.height == 0 || outpoint.height >= plan.result_start_height)
        .cloned()
        .collect();
    let cursor = Bip448ScanCursor {
        coverage_start_height: cursor.as_ref().map_or(coverage_start_height, |cursor| {
            cursor.coverage_start_height.min(coverage_start_height)
        }),
        scan_revision: cursor.as_ref().map_or(0, |cursor| cursor.scan_revision),
        last_scanned_height: tip_height,
        last_scanned_block_hash: tip_hash.clone(),
    };
    Ok(Bip448ScriptScanCandidate {
        base,
        script_pubkey: script_hex,
        cursor,
        current_unspent,
        discovered_unspent,
        observations,
        accepted_targets,
        tip_height,
        tip_hash,
        requires_authoritative_replay,
    })
}

async fn apply_bip448_script_candidate(
    client_config: &ClientConfig,
    wallet_name: &str,
    candidate: Bip448ScriptScanCandidate,
) -> Result<(
    Vec<Bip448FundingBinding>,
    Vec<Bip448WithdrawalAttempt>,
    crate::bip448_funding::Bip448AppliedScanRevision,
)> {
    let mut guard = begin_bip448_sync_base_guard(&client_config.pool, &candidate.base).await?;
    let guarded_tip_height = client_config.chain_client.tip_height()?;
    let guarded_tip_hash = client_config
        .chain_client
        .get_block_hash(guarded_tip_height)?
        .to_string();
    if guarded_tip_height != candidate.tip_height || guarded_tip_hash != candidate.tip_hash {
        return Err(anyhow!(
            "BIP448 synchronization chain changed before atomic apply"
        ));
    }
    let mut bindings = Vec::new();
    let mut attempts = Vec::new();
    for target in &candidate.accepted_targets {
        let target_bindings = guard
            .reconcile_funding_bindings(
                wallet_name,
                &target.statechain_id,
                &target.owner_user_pubkey,
                target.owner_state_number,
                &candidate.observations,
            )
            .await?;
        let target_attempts = guard
            .reconcile_withdrawal_attempt_observations(
                wallet_name,
                &target.statechain_id,
                &target_bindings,
            )
            .await?;
        bindings.extend(target_bindings);
        attempts.extend(target_attempts);
    }
    let revision = guard
        .apply_scan_cache_and_cursor(
            wallet_name,
            &candidate.script_pubkey,
            &candidate.cursor,
            &candidate.current_unspent,
        )
        .await?;
    guard.commit().await?;
    Ok((bindings, attempts, revision))
}

fn bip448_sync_retryable(error: &anyhow::Error) -> bool {
    let message = error.to_string();
    message.contains("synchronization base changed")
        || message.contains("chain changed")
        || message.contains("scan candidate lost its revision CAS")
        || message.contains("database is locked")
        || message.contains("database is busy")
}

async fn sync_bip448_funding_bindings_with_candidates(
    client_config: &ClientConfig,
    wallet_name: &str,
    force_height_zero_replay: bool,
) -> Result<Bip448SyncOutcome> {
    for attempt in 1..=3 {
        let raw_wallet_json = get_bip448_raw_wallet_json(&client_config.pool, wallet_name).await?;
        let wallet: Wallet = serde_json::from_str(&raw_wallet_json)?;
        if wallet.name != wallet_name {
            return Err(anyhow!("BIP448 synchronization wallet identity mismatch"));
        }
        let plans = build_bip448_script_sync_plans(client_config, &wallet).await?;
        let mut bindings = Vec::new();
        let mut attempts = Vec::new();
        let mut applied_scan_revisions = Vec::new();
        let mut discovered = HashMap::new();
        let mut stable_tip = None;
        let mut retry_error = None;
        for plan in &plans {
            let mut candidate = match scan_bip448_script_candidate(
                client_config,
                wallet_name,
                &raw_wallet_json,
                plan,
                force_height_zero_replay,
            )
            .await
            {
                std::result::Result::Ok(candidate) => candidate,
                Err(error) if bip448_sync_retryable(&error) => {
                    retry_error = Some(error);
                    break;
                }
                Err(error) => return Err(error),
            };
            if candidate.requires_authoritative_replay {
                let incremental_base = candidate.base.clone();
                candidate = match scan_bip448_script_candidate(
                    client_config,
                    wallet_name,
                    &raw_wallet_json,
                    plan,
                    true,
                )
                .await
                {
                    std::result::Result::Ok(candidate) => candidate,
                    Err(error) if bip448_sync_retryable(&error) => {
                        retry_error = Some(error);
                        break;
                    }
                    Err(error) => return Err(error),
                };
                if let Err(error) =
                    require_stable_authoritative_replay_base(&incremental_base, &candidate.base)
                {
                    retry_error = Some(error);
                    break;
                }
                if candidate.requires_authoritative_replay {
                    return Err(anyhow!(
                        "BIP448 authoritative mempool replay requested another replay"
                    ));
                }
            }
            let script = plan.script_pubkey.clone();
            let candidates = candidate.discovered_unspent.clone();
            stable_tip = Some((candidate.tip_height, candidate.tip_hash.clone()));
            match apply_bip448_script_candidate(client_config, wallet_name, candidate).await {
                std::result::Result::Ok((mut script_bindings, mut script_attempts, revision)) => {
                    bindings.append(&mut script_bindings);
                    attempts.append(&mut script_attempts);
                    applied_scan_revisions.push(revision);
                    discovered.insert(script, candidates);
                }
                Err(error) if bip448_sync_retryable(&error) => {
                    retry_error = Some(error);
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        if let Some(error) = retry_error {
            if attempt == 3 {
                return Err(error.context(
                    "BIP448 synchronization lost three consecutive concurrent-update races",
                ));
            }
            continue;
        }
        let (tip_height, tip_hash) = match stable_tip {
            Some(tip) => tip,
            None => {
                let height = client_config.chain_client.tip_height()?;
                let hash = client_config
                    .chain_client
                    .get_block_hash(height)?
                    .to_string();
                (height, hash)
            }
        };
        bindings.sort_by(|left, right| {
            (
                left.statechain_id.as_str(),
                left.binding_index,
                left.txid.as_str(),
                left.vout,
            )
                .cmp(&(
                    right.statechain_id.as_str(),
                    right.binding_index,
                    right.txid.as_str(),
                    right.vout,
                ))
        });
        bindings.dedup_by(|left, right| {
            left.statechain_id == right.statechain_id && left.binding_index == right.binding_index
        });
        attempts.sort_by(|left, right| {
            (left.statechain_id.as_str(), left.binding_index)
                .cmp(&(right.statechain_id.as_str(), right.binding_index))
        });
        attempts.dedup_by(|left, right| {
            left.statechain_id == right.statechain_id && left.binding_index == right.binding_index
        });
        applied_scan_revisions.sort_by(|left, right| left.script_pubkey.cmp(&right.script_pubkey));
        return Ok(Bip448SyncOutcome {
            report: Bip448SyncReport {
                tip_height,
                tip_hash,
                bindings,
                attempts,
                applied_scan_revisions,
            },
            discovered,
            raw_wallet_json,
        });
    }
    unreachable!("bounded BIP448 synchronization retry loop")
}

pub async fn sync_bip448_funding_bindings(
    client_config: &ClientConfig,
    wallet_name: &str,
) -> Result<Bip448SyncReport> {
    Ok(
        sync_bip448_funding_bindings_with_candidates(client_config, wallet_name, false)
            .await?
            .report,
    )
}

pub async fn sync_bip448_funding_bindings_from_height_zero(
    client_config: &ClientConfig,
    wallet_name: &str,
) -> Result<Bip448SyncReport> {
    Ok(
        sync_bip448_funding_bindings_with_candidates(client_config, wallet_name, true)
            .await?
            .report,
    )
}

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
            sync_bip448_funding_bindings_with_candidates(client_config, wallet_name, false).await?;
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
            let post_acceptance =
                sync_bip448_funding_bindings_with_candidates(client_config, wallet_name, false)
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
    use anyhow::Context;
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
    fn incremental_positive_spend_reaches_the_confirmation_target() -> Result<()> {
        assert_eq!(
            retained_observation_status_at_tip(
                Bip448ObservationStatus::SpentUnconfirmed,
                Some(100),
                104,
                6,
            )?,
            Bip448ObservationStatus::SpentUnconfirmed
        );
        assert_eq!(
            retained_observation_status_at_tip(
                Bip448ObservationStatus::SpentUnconfirmed,
                Some(100),
                105,
                6,
            )?,
            Bip448ObservationStatus::SpentConfirmed
        );
        assert!(retained_observation_status_at_tip(
            Bip448ObservationStatus::SpentUnconfirmed,
            None,
            105,
            6,
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn reorged_and_reappeared_mempool_receives_clear_historical_heights() -> Result<()> {
        let mut existing = Bip448FundingBinding {
            wallet_name: "wallet".to_string(),
            statechain_id: "statechain".to_string(),
            binding_index: 1,
            txid: "11".repeat(32),
            vout: 0,
            value_sats: 70_000,
            script_pubkey: "51".to_string(),
            role: Bip448BindingRole::Duplicate,
            observation_status: Bip448ObservationStatus::Confirmed,
            funding_height: Some(100),
            spend_txid: None,
            spend_height: None,
            last_scanned_height: 110,
            owner_user_pubkey: "22".repeat(32),
            owner_state_number: 1,
            ownership_status: Bip448OwnershipStatus::Current,
            first_seen_at: "first".to_string(),
            last_seen_at: "last".to_string(),
        };
        let mempool_current = ChainUtxo {
            txid: existing.txid.clone(),
            vout: existing.vout,
            value: existing.value_sats,
            height: 0,
        };
        let mempool_receive = Bip448ReceiveFact {
            value_sats: existing.value_sats,
            funding_height: None,
        };
        let expected_mempool = Bip448ResolvedObservation {
            observation_status: Bip448ObservationStatus::Mempool,
            funding_height: None,
            spend_txid: None,
            spend_height: None,
        };

        assert_eq!(
            resolve_bip448_observation_at_tip(
                Some(&mempool_current),
                None,
                Some(&mempool_receive),
                Some(&existing),
                false,
                110,
                6,
            )?,
            Some(expected_mempool)
        );

        // A retained historical height is permitted for Absent storage, but a
        // positive mempool reappearance must still replace it with None.
        existing.observation_status = Bip448ObservationStatus::Absent;
        assert_eq!(
            resolve_bip448_observation_at_tip(
                Some(&mempool_current),
                None,
                None,
                Some(&existing),
                false,
                110,
                6,
            )?
            .context("mempool reappearance must resolve")?
            .funding_height,
            None
        );

        Ok(())
    }

    #[test]
    fn authoritative_absence_and_incremental_retention_are_status_height_coherent() -> Result<()> {
        let existing = Bip448FundingBinding {
            wallet_name: "wallet".to_string(),
            statechain_id: "statechain".to_string(),
            binding_index: 1,
            txid: "11".repeat(32),
            vout: 0,
            value_sats: 70_000,
            script_pubkey: "51".to_string(),
            role: Bip448BindingRole::Duplicate,
            observation_status: Bip448ObservationStatus::Mempool,
            funding_height: None,
            spend_txid: None,
            spend_height: None,
            last_scanned_height: 110,
            owner_user_pubkey: "22".repeat(32),
            owner_state_number: 1,
            ownership_status: Bip448OwnershipStatus::Current,
            first_seen_at: "first".to_string(),
            last_seen_at: "last".to_string(),
        };

        assert_eq!(
            resolve_bip448_observation_at_tip(None, None, None, Some(&existing), false, 110, 6,)?,
            Some(Bip448ResolvedObservation {
                observation_status: Bip448ObservationStatus::Mempool,
                funding_height: None,
                spend_txid: None,
                spend_height: None,
            })
        );
        assert_eq!(
            resolve_bip448_observation_at_tip(None, None, None, Some(&existing), true, 110, 6,)?,
            Some(Bip448ResolvedObservation {
                observation_status: Bip448ObservationStatus::Absent,
                funding_height: None,
                spend_txid: None,
                spend_height: None,
            })
        );

        Ok(())
    }

    #[test]
    fn fresh_receive_height_overrides_spend_fallback_but_incremental_spend_retains_it() -> Result<()>
    {
        let existing = Bip448FundingBinding {
            wallet_name: "wallet".to_string(),
            statechain_id: "statechain".to_string(),
            binding_index: 1,
            txid: "11".repeat(32),
            vout: 0,
            value_sats: 70_000,
            script_pubkey: "51".to_string(),
            role: Bip448BindingRole::Duplicate,
            observation_status: Bip448ObservationStatus::Confirmed,
            funding_height: Some(100),
            spend_txid: None,
            spend_height: None,
            last_scanned_height: 110,
            owner_user_pubkey: "22".repeat(32),
            owner_state_number: 1,
            ownership_status: Bip448OwnershipStatus::Current,
            first_seen_at: "first".to_string(),
            last_seen_at: "last".to_string(),
        };
        let spend = Bip448SpendFact {
            spend_txid: "33".repeat(32),
            spend_height: None,
        };
        let mempool_receive = Bip448ReceiveFact {
            value_sats: existing.value_sats,
            funding_height: None,
        };

        let fresh = resolve_bip448_observation_at_tip(
            None,
            Some(&spend),
            Some(&mempool_receive),
            Some(&existing),
            false,
            110,
            6,
        )?
        .context("fresh spend observation")?;
        assert_eq!(
            fresh.observation_status,
            Bip448ObservationStatus::SpentMempool
        );
        assert_eq!(fresh.funding_height, None);

        let incremental = resolve_bip448_observation_at_tip(
            None,
            Some(&spend),
            None,
            Some(&existing),
            false,
            110,
            6,
        )?
        .context("incremental spend observation")?;
        assert_eq!(
            incremental.observation_status,
            Bip448ObservationStatus::SpentMempool
        );
        assert_eq!(incremental.funding_height, Some(100));

        Ok(())
    }

    #[test]
    fn discovery_retries_the_whole_operation_once() {
        let mut results = [Err(anyhow!("reorg")), Ok(())].into_iter();
        retry_discovery_once(|| results.next().unwrap()).unwrap();
        assert!(results.next().is_none());
    }

    #[test]
    fn authoritative_replay_retains_cursor_for_cas_without_rechecking_its_bad_hash() -> Result<()> {
        let cursor = Bip448ScanCursor {
            coverage_start_height: 10,
            scan_revision: 7,
            last_scanned_height: 20,
            last_scanned_block_hash: "stale-hash".into(),
        };
        let invalidated_hash_calls = std::cell::Cell::new(0);
        assert!(prior_cursor_matches_post_scan(
            Some(&cursor),
            30,
            true,
            |_| {
                invalidated_hash_calls.set(invalidated_hash_calls.get() + 1);
                Ok("canonical-hash".into())
            },
        )?);
        assert_eq!(invalidated_hash_calls.get(), 0);

        let live_hash_calls = std::cell::Cell::new(0);
        assert!(!prior_cursor_matches_post_scan(
            Some(&cursor),
            30,
            false,
            |_| {
                live_hash_calls.set(live_hash_calls.get() + 1);
                Ok("canonical-hash".into())
            },
        )?);
        assert_eq!(live_hash_calls.get(), 1);
        assert!(!prior_cursor_matches_post_scan(
            Some(&cursor),
            19,
            false,
            |_| Err(anyhow!("a cursor above tip must not query its block hash")),
        )?);

        Ok(())
    }

    #[test]
    fn vanished_mempool_receive_requires_one_authoritative_replay_only() {
        assert!(disappeared_mempool_receive_requires_authoritative_replay(
            false,
            Bip448ObservationStatus::Mempool,
            false,
            false,
            false,
        ));
        for (authoritative, status, current, receive, spend) in [
            (true, Bip448ObservationStatus::Mempool, false, false, false),
            (
                false,
                Bip448ObservationStatus::Confirmed,
                false,
                false,
                false,
            ),
            (false, Bip448ObservationStatus::Mempool, true, false, false),
            (false, Bip448ObservationStatus::Mempool, false, true, false),
            (false, Bip448ObservationStatus::Mempool, false, false, true),
        ] {
            assert!(!disappeared_mempool_receive_requires_authoritative_replay(
                authoritative,
                status,
                current,
                receive,
                spend,
            ));
        }
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
    fn authoritative_mempool_replay_rejects_any_full_base_race() {
        let base = Bip448SyncBase {
            wallet_name: "wallet".to_string(),
            script_pubkey: "51".to_string(),
            raw_wallet_json: "wallet-bytes".to_string(),
            pending_deposit_rows: vec!["pending".to_string()],
            accepted_record_rows: vec!["record".to_string()],
            state_history_rows: vec!["history".to_string()],
            cursor_rows: vec!["cursor".to_string()],
            scan_cache_rows: vec!["cache".to_string()],
            funding_binding_rows: vec!["binding".to_string()],
            withdrawal_attempt_rows: vec!["attempt".to_string()],
            transfer_intent_rows: vec!["intent".to_string()],
            pending_transfer_rows: vec!["transfer-pending".to_string()],
            outgoing_transfer_message_rows: vec!["message".to_string()],
        };
        require_stable_authoritative_replay_base(&base, &base).unwrap();
        for mutate in 0..4 {
            let mut raced = base.clone();
            match mutate {
                0 => raced.raw_wallet_json.push_str("-changed"),
                1 => raced.cursor_rows.push("new-cursor".to_string()),
                2 => raced.funding_binding_rows.push("new-binding".to_string()),
                3 => raced.state_history_rows.push("new-history".to_string()),
                _ => unreachable!(),
            }
            assert!(require_stable_authoritative_replay_base(&base, &raced).is_err());
        }
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
