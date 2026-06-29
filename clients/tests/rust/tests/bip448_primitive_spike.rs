mod common;

use std::str::FromStr;

use anyhow::{anyhow, Result};
use bitcoin::{
    absolute,
    consensus::encode::{deserialize, serialize},
    secp256k1::{KeyPair, Secp256k1, SecretKey},
    taproot::{ControlBlock, LeafVersion, TaprootBuilder},
    Address, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use mercurylib::bip448::{primitive_script, template_hash::template_hash_message};
use serde_json::Value;

const BITCOIN_CLI: &str = "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury";
const BITCOIN_WALLET_NAME: &str = "mercury_test";
const FUNDING_AMOUNT_SATS: u32 = 50_000;
const SPEND_AMOUNT_SATS: u64 = 40_000;

#[test]
#[ignore = "requires docker regtest stack with active BIP448 Inquisition deployments"]
fn bip448_template_signature_rebinds_prevout_on_inquisition() -> Result<()> {
    let _guard = common::test_guard();

    ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    ensure_wallet_ready()?;

    let taproot_output = Bip448TaprootOutput::new()?;
    let funding_a = fund_bip448_output(&taproot_output.address)?;
    let funding_b = fund_bip448_output(&taproot_output.address)?;

    let miner_address = common::bitcoin_core::getnewaddress()?;
    common::bitcoin_core::generatetoaddress(1, &miner_address)?;

    let destination_script =
        regtest_address(&common::bitcoin_core::getnewaddress()?)?.script_pubkey();
    let mut spend_a = unsigned_spend(funding_a.outpoint, destination_script, SPEND_AMOUNT_SATS);
    add_bip448_witness(
        &mut spend_a,
        &taproot_output.script,
        &taproot_output.control_block,
        &taproot_output.keypair,
    )?;

    let mut spend_b = spend_a.clone();
    spend_b.input[0].previous_output = funding_b.outpoint;

    assert_eq!(
        template_hash_message(&spend_a, 0, None)?,
        template_hash_message(&spend_b, 0, None)?
    );

    let mut committed_field_mutation = spend_b.clone();
    committed_field_mutation.output[0].value += 1;
    assert_ne!(
        template_hash_message(&spend_b, 0, None)?,
        template_hash_message(&committed_field_mutation, 0, None)?
    );
    assert_rejected_by_inquisition(&committed_field_mutation)?;

    let spend_a_txid = broadcast_raw_transaction(&spend_a)?;
    let spend_b_txid = broadcast_raw_transaction(&spend_b)?;

    let miner_address = common::bitcoin_core::getnewaddress()?;
    common::bitcoin_core::generatetoaddress(1, &miner_address)?;

    assert_confirmed(&spend_a_txid)?;
    assert_confirmed(&spend_b_txid)?;

    Ok(())
}

struct Bip448TaprootOutput {
    address: Address,
    control_block: ControlBlock,
    keypair: KeyPair,
    script: ScriptBuf,
}

impl Bip448TaprootOutput {
    fn new() -> Result<Self> {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_secret_bytes([7u8; 32])?;
        let keypair = KeyPair::from_secret_key(&secp, &secret_key);
        let (internal_key, _) = keypair.x_only_public_key();
        let script = primitive_script();
        let spend_info = TaprootBuilder::new()
            .add_leaf(0, script.clone())
            .map_err(|err| anyhow!("failed to add BIP448 taproot leaf: {err:?}"))?
            .finalize(&secp, internal_key)
            .map_err(|_| anyhow!("failed to finalize BIP448 taproot tree"))?;
        let control_block = spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .ok_or_else(|| anyhow!("BIP448 taproot leaf is missing a control block"))?;
        let address = Address::p2tr_tweaked(spend_info.output_key(), Network::Regtest);

        Ok(Self {
            address,
            control_block,
            keypair,
            script,
        })
    }
}

struct FundingOutput {
    outpoint: OutPoint,
}

fn ensure_wallet_loaded() -> Result<()> {
    common::bitcoin_core::execute_bitcoin_command(&format!(
        "{BITCOIN_CLI} createwallet {BITCOIN_WALLET_NAME} >/dev/null 2>&1 || \
         {BITCOIN_CLI} loadwallet {BITCOIN_WALLET_NAME} >/dev/null 2>&1 || true"
    ))?;

    Ok(())
}

fn ensure_wallet_ready() -> Result<()> {
    ensure_wallet_loaded()?;

    let address = common::bitcoin_core::getnewaddress()?;
    common::bitcoin_core::generatetoaddress(101, &address)?;

    Ok(())
}

fn fund_bip448_output(address: &Address) -> Result<FundingOutput> {
    let txid = Txid::from_str(&common::bitcoin_core::sendtoaddress(
        FUNDING_AMOUNT_SATS,
        &address.to_string(),
    )?)?;
    let tx = wallet_transaction(&txid)?;
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

fn wallet_transaction(txid: &Txid) -> Result<Transaction> {
    let tx_json = common::bitcoin_core::execute_bitcoin_command(&format!(
        "{BITCOIN_CLI} -rpcwallet={BITCOIN_WALLET_NAME} gettransaction {txid}"
    ))?;
    let tx_json: Value = serde_json::from_str(&tx_json)?;
    let tx_hex = tx_json
        .get("hex")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("wallet transaction {txid} did not include raw hex"))?;
    let tx_bytes = hex::decode(tx_hex)?;

    Ok(deserialize(&tx_bytes)?)
}

fn unsigned_spend(
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

fn add_bip448_witness(
    tx: &mut Transaction,
    script: &ScriptBuf,
    control_block: &ControlBlock,
    keypair: &KeyPair,
) -> Result<()> {
    let message = template_hash_message(tx, 0, None)?;
    let signature = keypair.sign_schnorr_no_aux_rand(&message);

    tx.input[0].witness.push(signature.as_byte_array());
    tx.input[0].witness.push(script.as_bytes());
    tx.input[0].witness.push(control_block.serialize());

    Ok(())
}

fn assert_rejected_by_inquisition(tx: &Transaction) -> Result<()> {
    let tx_hex = hex::encode(serialize(tx));
    let err = match common::bitcoin_core::execute_bitcoin_command(&format!(
        "{BITCOIN_CLI} sendrawtransaction {tx_hex}"
    )) {
        Ok(txid) => {
            return Err(anyhow!(
                "committed-field mutation unexpectedly broadcast successfully: {txid}"
            ));
        }
        Err(err) => err.to_string(),
    };

    let expected_rejection_reasons = [
        "mandatory-script-verify-flag-failed (Invalid Schnorr signature)",
        "mempool-script-verify-flag-failed (Invalid Schnorr signature)",
    ];

    if expected_rejection_reasons
        .iter()
        .any(|reason| err.contains(reason))
    {
        return Ok(());
    }

    Err(anyhow!(
        "committed-field mutation was rejected for an unexpected reason: {err}"
    ))
}

fn broadcast_raw_transaction(tx: &Transaction) -> Result<Txid> {
    let tx_hex = hex::encode(serialize(tx));
    let txid = common::bitcoin_core::execute_bitcoin_command(&format!(
        "{BITCOIN_CLI} sendrawtransaction {tx_hex}"
    ))?;

    Ok(Txid::from_str(&txid)?)
}

fn assert_confirmed(txid: &Txid) -> Result<()> {
    let tx_json = common::bitcoin_core::execute_bitcoin_command(&format!(
        "{BITCOIN_CLI} getrawtransaction {txid} true"
    ))?;
    let tx_json: Value = serde_json::from_str(&tx_json)?;
    let confirmations = tx_json
        .get("confirmations")
        .and_then(Value::as_u64)
        .unwrap_or(0);

    if confirmations == 0 {
        return Err(anyhow!("transaction {txid} was not mined"));
    }

    Ok(())
}

fn regtest_address(address: &str) -> Result<Address> {
    Ok(Address::from_str(address)?.require_network(Network::Regtest)?)
}
