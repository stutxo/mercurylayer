use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::str::FromStr;

use anyhow::{anyhow, Ok, Result};
use bitcoin::{Address, ScriptBuf};
use mercurylib::{bip448_statechain::deposit as bip448_deposit, wallet::Wallet};

use super::{
    discovery::sort_chain_utxos,
    reducer::{
        disappeared_mempool_receive_requires_authoritative_replay, height_from_confirmations,
        insert_receive_fact, insert_spend_fact, require_stable_authoritative_replay_base,
        resolve_bip448_observation_at_tip, Bip448ReceiveFact, Bip448SpendFact,
    },
};
use crate::{
    bip448_funding::{
        Bip448BindingObservation, Bip448FundingBinding, Bip448SyncBase, Bip448SyncReport,
        Bip448TransferIntentKind, Bip448TransferIntentPhase, Bip448WithdrawalAttempt,
    },
    chain::{ChainUtxo, DescriptorActivity},
    client_config::ClientConfig,
    sqlite_manager::{
        begin_bip448_sync_base_guard, capture_bip448_sync_base,
        delete_bip448_cancellation_artifacts_after_sync, get_active_bip448_transfer_intent,
        get_bip448_pending_deposit_signing, get_bip448_raw_wallet_json, get_bip448_state_history,
        get_bip448_statechain_optional, get_bip448_transfer_msg_raw_optional,
        list_bip448_funding_bindings, load_bip448_scan_state,
        reconcile_bip448_accepted_local_outgoing_messages, Bip448ScanCursor,
    },
};

#[derive(Clone)]
struct Bip448ScriptSyncPlan {
    descriptor: String,
    script_pubkey: ScriptBuf,
    coverage_start_height: u32,
    result_start_height: u32,
    statechain_ids: Vec<String>,
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

pub(super) struct Bip448SyncOutcome {
    pub(super) report: Bip448SyncReport,
    pub(super) discovered: HashMap<ScriptBuf, Vec<ChainUtxo>>,
    pub(super) raw_wallet_json: String,
}

async fn build_bip448_script_sync_plans(
    client_config: &ClientConfig,
    wallet: &Wallet,
    statechain_filter: Option<&str>,
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
        if statechain_filter.is_some_and(|expected| expected != statechain_id) {
            continue;
        }
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

pub(super) async fn sync_bip448_funding_bindings_with_candidates(
    client_config: &ClientConfig,
    wallet_name: &str,
    force_height_zero_replay: bool,
    statechain_filter: Option<&str>,
) -> Result<Bip448SyncOutcome> {
    for attempt in 1..=3 {
        let raw_wallet_json = get_bip448_raw_wallet_json(&client_config.pool, wallet_name).await?;
        let wallet: Wallet = serde_json::from_str(&raw_wallet_json)?;
        if wallet.name != wallet_name {
            return Err(anyhow!("BIP448 synchronization wallet identity mismatch"));
        }
        let plans =
            build_bip448_script_sync_plans(client_config, &wallet, statechain_filter).await?;
        if statechain_filter.is_some() && plans.is_empty() {
            return Err(anyhow!(
                "BIP448 post-acceptance synchronization has no persisted receiver Coin"
            ));
        }
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
        sync_bip448_funding_bindings_with_candidates(client_config, wallet_name, false, None)
            .await?
            .report,
    )
}

pub(crate) async fn sync_bip448_funding_bindings_for_statechain_from_height_zero(
    client_config: &ClientConfig,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<Bip448SyncReport> {
    let report = sync_bip448_funding_bindings_with_candidates(
        client_config,
        wallet_name,
        true,
        Some(statechain_id),
    )
    .await?
    .report;
    if !report
        .bindings
        .iter()
        .any(|binding| binding.statechain_id == statechain_id)
    {
        return Err(anyhow!(
            "BIP448 post-acceptance synchronization did not reconcile the accepted statechain"
        ));
    }
    Ok(report)
}

pub(crate) async fn reconcile_bip448_post_sync_transfer_artifacts(
    pool: &sqlx::Pool<sqlx::Sqlite>,
    wallet_name: &str,
    statechain_ids: &[String],
) -> Result<()> {
    let mut statechain_ids = statechain_ids.to_vec();
    statechain_ids.sort();
    statechain_ids.dedup();

    for statechain_id in &statechain_ids {
        let Some(intent) =
            get_active_bip448_transfer_intent(pool, wallet_name, statechain_id).await?
        else {
            continue;
        };
        if intent.intent_kind != Bip448TransferIntentKind::Cancellation
            || intent.phase != Bip448TransferIntentPhase::ReceiverAccepted
        {
            continue;
        }
        let (_, message_json) = get_bip448_transfer_msg_raw_optional(
            pool,
            wallet_name,
            statechain_id,
            Some(&intent.recipient_auth_pubkey),
        )
        .await?
        .ok_or_else(|| anyhow!("BIP448 ReceiverAccepted cancellation message is missing"))?;
        delete_bip448_cancellation_artifacts_after_sync(pool, &intent, &message_json).await?;
    }

    for statechain_id in &statechain_ids {
        reconcile_bip448_accepted_local_outgoing_messages(pool, wallet_name, statechain_id).await?;
    }
    Ok(())
}

pub(super) async fn accepted_bip448_statechain_ids(
    pool: &sqlx::Pool<sqlx::Sqlite>,
    wallet: &Wallet,
) -> Result<Vec<String>> {
    let mut statechain_ids = wallet
        .coins
        .iter()
        .filter(|coin| {
            coin.statechain_protocol.as_deref() == Some(bip448_deposit::BIP448_COIN_PROTOCOL)
        })
        .filter_map(|coin| coin.statechain_id.clone())
        .collect::<Vec<_>>();
    statechain_ids.sort();
    statechain_ids.dedup();
    let mut accepted = Vec::new();
    for statechain_id in statechain_ids {
        if get_bip448_statechain_optional(pool, &wallet.name, &statechain_id)
            .await?
            .is_some()
        {
            accepted.push(statechain_id);
        }
    }
    Ok(accepted)
}

pub async fn sync_bip448_funding_bindings_from_height_zero(
    client_config: &ClientConfig,
    wallet_name: &str,
) -> Result<Bip448SyncReport> {
    Ok(
        sync_bip448_funding_bindings_with_candidates(client_config, wallet_name, true, None)
            .await?
            .report,
    )
}
