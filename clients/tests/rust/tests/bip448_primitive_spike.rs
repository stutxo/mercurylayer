mod common;

use anyhow::{anyhow, Result};
use bitcoin::{
    secp256k1::{KeyPair, Secp256k1, SecretKey},
    taproot::{ControlBlock, LeafVersion, TaprootBuilder},
    Address, Network, ScriptBuf, Transaction,
};
use common::bip448_regtest::{fund_bip448_output, unsigned_spend, SPEND_AMOUNT_SATS};
use mercurylib::bip448::{primitive_script, template_hash::template_hash_message};

#[test]
#[ignore = "requires docker regtest stack with active BIP448 Inquisition deployments"]
fn bip448_template_signature_rebinds_prevout_on_inquisition() -> Result<()> {
    let _guard = common::test_guard();

    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;

    let taproot_output = Bip448TaprootOutput::new()?;
    let funding_a = fund_bip448_output(&taproot_output.address)?;
    let funding_b = fund_bip448_output(&taproot_output.address)?;

    common::bitcoin_core::mine_block()?;

    let destination_script =
        common::bitcoin_core::regtest_address(&common::bitcoin_core::getnewaddress()?)?
            .script_pubkey();
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

    let spend_a_txid = common::bitcoin_core::broadcast_raw_transaction(&spend_a)?;
    let spend_b_txid = common::bitcoin_core::broadcast_raw_transaction(&spend_b)?;

    common::bitcoin_core::mine_block()?;

    common::bitcoin_core::assert_confirmed(&spend_a_txid)?;
    common::bitcoin_core::assert_confirmed(&spend_b_txid)?;

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
    let err = match common::bitcoin_core::broadcast_raw_transaction(tx) {
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
