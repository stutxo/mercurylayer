use anyhow::{anyhow, Result};
use bitcoin::{
    absolute, Address, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};

use super::bitcoin_core;

pub const FUNDING_AMOUNT_SATS: u32 = 50_000;
pub const SPEND_AMOUNT_SATS: u64 = 40_000;

pub struct FundingOutput {
    pub outpoint: OutPoint,
}

pub fn fund_bip448_output(address: &Address) -> Result<FundingOutput> {
    let txid: Txid =
        bitcoin_core::sendtoaddress(FUNDING_AMOUNT_SATS, &address.to_string())?.parse()?;
    let tx = bitcoin_core::wallet_transaction(&txid)?;
    let expected_script = address.script_pubkey();
    let vout = tx
        .output
        .iter()
        .position(|output| {
            output.value == FUNDING_AMOUNT_SATS as u64 && output.script_pubkey == expected_script
        })
        .ok_or_else(|| anyhow!("funding transaction did not pay the expected BIP448 output"))?
        as u32;

    Ok(FundingOutput {
        outpoint: OutPoint { txid, vout },
    })
}

pub fn unsigned_spend(
    previous_output: OutPoint,
    destination_script: ScriptBuf,
    value: u64,
) -> Transaction {
    Transaction {
        version: 3,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value,
            script_pubkey: destination_script,
        }],
    }
}
