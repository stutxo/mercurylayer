use std::str::FromStr;

use anyhow::{anyhow, Result};
use bitcoin::{
    absolute,
    blockdata::{
        block::{Block, Header, Version},
        opcodes::OP_TRUE,
    },
    consensus::encode::serialize,
    hash_types::TxMerkleNode,
    hashes::Hash,
    pow::CompactTarget,
    script::Builder,
    BlockHash, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness,
};
use serde_json::Value;

use super::bitcoin_core;

const BITCOIN_CLI: &str = "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury";
const BIP448_DEPLOYMENTS: [&str; 3] = ["checksigfromstack", "internalkey", "templatehash"];
const HERETICAL_PERIOD_BLOCKS: u32 = 144;
const HERETICAL_ACTIVATION_BLOCKS: u32 = HERETICAL_PERIOD_BLOCKS * 2;

pub fn ensure_bip448_deployments_active() -> Result<()> {
    if bip448_deployments_are_active()? {
        return Ok(());
    }

    if bip448_deployment_statuses()?
        .iter()
        .any(|(_, status)| status == "defined")
    {
        mine_blocks(HERETICAL_PERIOD_BLOCKS)?;
    }

    let deployments_before_signaling = deployment_info()?;
    for name in BIP448_DEPLOYMENTS {
        let deployment = deployment(&deployments_before_signaling, name)?;
        if deployment_is_active(deployment) {
            continue;
        }
        match deployment_status(deployment)? {
            "started" => submit_activation_signal_block(signal_activate_version(deployment)?)?,
            "locked_in" => continue,
            _ => {
                return Err(anyhow!(
                    "Inquisition deployment {name} is not ready for activation: {deployment}"
                ));
            }
        }
    }

    mine_blocks(HERETICAL_ACTIVATION_BLOCKS)?;

    let deployments_after_activation = deployment_info()?;
    for name in BIP448_DEPLOYMENTS {
        let deployment = deployment(&deployments_after_activation, name)?;
        if !deployment_is_active(deployment) {
            return Err(anyhow!(
                "Inquisition deployment {name} is not active after activation mining: {deployment}"
            ));
        }
    }

    Ok(())
}

fn deployment_info() -> Result<Value> {
    let deployment_info =
        bitcoin_core::execute_bitcoin_command(&format!("{BITCOIN_CLI} getdeploymentinfo"))?;

    Ok(serde_json::from_str(&deployment_info)?)
}

fn deployment_info_for_block(block_hash: &BlockHash) -> Result<Value> {
    let deployment_info = bitcoin_core::execute_bitcoin_command(&format!(
        "{BITCOIN_CLI} getdeploymentinfo {block_hash}"
    ))?;

    Ok(serde_json::from_str(&deployment_info)?)
}

fn deployment<'a>(deployment_info: &'a Value, name: &str) -> Result<&'a Value> {
    deployment_info
        .get("deployments")
        .and_then(|deployments| deployments.get(name))
        .ok_or_else(|| anyhow!("missing Inquisition deployment {name}"))
}

fn bip448_deployments_are_active() -> Result<bool> {
    let deployment_info = deployment_info()?;

    Ok(BIP448_DEPLOYMENTS
        .iter()
        .all(|name| deployment(&deployment_info, name).is_ok_and(deployment_is_active)))
}

fn bip448_deployment_statuses() -> Result<Vec<(String, String)>> {
    let deployment_info = deployment_info()?;

    BIP448_DEPLOYMENTS
        .iter()
        .map(|name| {
            Ok((
                name.to_string(),
                deployment_status(deployment(&deployment_info, name)?)?.to_string(),
            ))
        })
        .collect()
}

fn deployment_is_active(deployment: &Value) -> bool {
    deployment.get("active").and_then(Value::as_bool) == Some(true)
        || deployment
            .get("heretical")
            .and_then(|heretical| heretical.get("status"))
            .and_then(Value::as_str)
            == Some("active")
}

fn deployment_activation_is_in_progress(deployment: &Value) -> bool {
    deployment_is_active(deployment)
        || matches!(
            deployment_status(deployment).ok(),
            Some("started" | "locked_in")
        )
}

fn deployment_status(deployment: &Value) -> Result<&str> {
    deployment
        .get("heretical")
        .and_then(|heretical| heretical.get("status"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing heretical deployment status: {deployment}"))
}

fn signal_activate_version(deployment: &Value) -> Result<u32> {
    let signal_activate = deployment
        .get("heretical")
        .and_then(|heretical| heretical.get("signal_activate"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing heretical signal_activate version: {deployment}"))?;

    Ok(u32::from_str_radix(
        signal_activate.trim_start_matches("0x"),
        16,
    )?)
}

fn mine_blocks(num_blocks: u32) -> Result<()> {
    let address = bitcoin_core::getnewaddress()?;
    bitcoin_core::generatetoaddress(num_blocks, &address)?;

    Ok(())
}

fn submit_activation_signal_block(version: u32) -> Result<()> {
    let best_hash = best_block_hash()?;
    let header_info = block_header(&best_hash)?;
    let next_height = block_count()? + 1;
    let prev_time = header_info
        .get("time")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("best block header did not include time: {header_info}"))?
        as u32;
    let bits_hex = header_info
        .get("bits")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("best block header did not include bits: {header_info}"))?;
    let bits = CompactTarget::from_consensus(u32::from_str_radix(bits_hex, 16)?);

    let coinbase = coinbase_transaction(next_height as i64);
    let mut block = Block {
        header: Header {
            version: Version::from_consensus(version as i32),
            prev_blockhash: best_hash,
            merkle_root: TxMerkleNode::all_zeros(),
            time: prev_time + 1,
            bits,
            nonce: 0,
        },
        txdata: vec![coinbase],
    };
    block.header.merkle_root = block
        .compute_merkle_root()
        .ok_or_else(|| anyhow!("activation signal block is missing a merkle root"))?;
    solve_regtest_block(&mut block)?;

    let block_hex = hex::encode(serialize(&block));
    bitcoin_core::execute_bitcoin_command(&format!("{BITCOIN_CLI} submitblock {block_hex}"))?;

    let submitted_hash = block.block_hash();
    let deployment_info = deployment_info_for_block(&submitted_hash)?;
    if !BIP448_DEPLOYMENTS.iter().all(|name| {
        deployment(&deployment_info, name).is_ok_and(deployment_activation_is_in_progress)
    }) {
        return Err(anyhow!(
            "activation signal block did not leave BIP448 deployments in progress: {deployment_info}"
        ));
    }

    Ok(())
}

fn best_block_hash() -> Result<BlockHash> {
    Ok(BlockHash::from_str(
        &bitcoin_core::execute_bitcoin_command(&format!("{BITCOIN_CLI} getbestblockhash"))?,
    )?)
}

fn block_header(block_hash: &BlockHash) -> Result<Value> {
    let header = bitcoin_core::execute_bitcoin_command(&format!(
        "{BITCOIN_CLI} getblockheader {block_hash} true"
    ))?;

    Ok(serde_json::from_str(&header)?)
}

fn block_count() -> Result<u32> {
    Ok(bitcoin_core::execute_bitcoin_command(&format!("{BITCOIN_CLI} getblockcount"))?.parse()?)
}

fn coinbase_transaction(height: i64) -> Transaction {
    Transaction {
        version: 1,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Builder::new()
                .push_int(height)
                .push_slice(*b"bip448")
                .into_script(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: 0,
            script_pubkey: Builder::new().push_opcode(OP_TRUE).into_script(),
        }],
    }
}

fn solve_regtest_block(block: &mut Block) -> Result<()> {
    let target = block.header.target();
    loop {
        if target.is_met_by(block.block_hash()) {
            return Ok(());
        }

        block.header.nonce = block.header.nonce.wrapping_add(1);
        if block.header.nonce == 0 {
            block.header.time = block.header.time.saturating_add(1);
        }
    }
}
