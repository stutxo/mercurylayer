use std::collections::{HashMap, HashSet};

use anyhow::{anyhow, Ok, Result};
use bitcoin::{Address, ScriptBuf};

use crate::{
    chain::{ChainUtxo, DescriptorActivity},
    client_config::ClientConfig,
    sqlite_manager::{load_bip448_scan_state, persist_bip448_scan_state, Bip448ScanCursor},
};

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

pub(super) fn sort_chain_utxos(outpoints: &mut [ChainUtxo]) {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
