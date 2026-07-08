use anyhow::{anyhow, Result};
use bitcoin::{
    absolute, Address, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use mercurylib::bip448_statechain::transaction::pay_to_anchor_script;

use super::bitcoin_core;

pub const FUNDING_AMOUNT_SATS: u32 = 50_000;
pub const FEE_INPUT_AMOUNT_SATS: u32 = 20_000;
pub const SPEND_AMOUNT_SATS: u64 = 40_000;

pub struct FundingOutput {
    pub outpoint: OutPoint,
    pub value_sats: u64,
}

pub fn fund_bip448_output(address: &Address) -> Result<FundingOutput> {
    fund_address_output(address, FUNDING_AMOUNT_SATS)
}

pub fn fund_p2a_fee_input() -> Result<FundingOutput> {
    fund_address_output(&p2a_address()?, FEE_INPUT_AMOUNT_SATS)
}

pub fn p2a_address() -> Result<Address> {
    Ok(Address::from_script(
        &pay_to_anchor_script(),
        bitcoin::Network::Regtest,
    )?)
}

pub fn fund_address_output(address: &Address, amount_sats: u32) -> Result<FundingOutput> {
    let txid: Txid = bitcoin_core::sendtoaddress(amount_sats, &address.to_string())?.parse()?;
    let tx = bitcoin_core::wallet_transaction(&txid)?;
    let expected_script = address.script_pubkey();
    let vout = tx
        .output
        .iter()
        .position(|output| {
            output.value == amount_sats as u64 && output.script_pubkey == expected_script
        })
        .ok_or_else(|| anyhow!("funding transaction did not pay the expected BIP448 output"))?
        as u32;

    Ok(FundingOutput {
        outpoint: OutPoint { txid, vout },
        value_sats: amount_sats as u64,
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
