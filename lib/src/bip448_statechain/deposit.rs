use std::str::FromStr;

use bitcoin::{
    consensus::encode,
    hashes::Hash,
    secp256k1::{schnorr, PublicKey, Secp256k1},
    taproot::ControlBlock,
    Address, OutPoint, ScriptBuf, Transaction, Txid, Witness,
};
use serde::{Deserialize, Serialize};

use crate::{
    bip448_statechain::{
        script::{self, ScriptTemplateError},
        storage::{
            Bip448AnchorOutput, Bip448CpfpChildTemplate, Bip448CsfsKeyMetadata,
            Bip448FeeBumpPolicy, Bip448FundingOutpoint, Bip448LatestState,
            Bip448RecoveryTemplateRole, Bip448SigningMetadata, Bip448StatechainRecord,
            Bip448ValueSchedule,
        },
        transaction::{self, FeePolicy, StateTemplates, TransactionTemplateError},
    },
    error::MercuryError,
    utils::get_network,
    wallet::Coin,
};

pub const INITIAL_BIP448_STATE_NUMBER: u32 = 1;
pub const DEFAULT_BIP448_CHALLENGE_DELAY: u16 = 144;
pub const BIP448_COIN_PROTOCOL: &str = "bip448";

#[derive(Debug, thiserror::Error)]
pub enum Bip448DepositError {
    #[error("BIP448 deposit coin is missing server_pubkey")]
    MissingServerPubkey,
    #[error("BIP448 deposit coin is missing aggregate_pubkey")]
    MissingAggregatePubkey,
    #[error("BIP448 deposit transaction template error: {0}")]
    TransactionTemplate(#[from] TransactionTemplateError),
    #[error("BIP448 deposit script template error: {0}")]
    ScriptTemplate(#[from] ScriptTemplateError),
    #[error("BIP448 deposit wallet error: {0}")]
    Wallet(#[from] MercuryError),
    #[error("BIP448 deposit secp256k1 error: {0}")]
    Secp256k1(#[from] bitcoin::secp256k1::Error),
    #[error("BIP448 deposit address error: {0}")]
    Address(#[from] bitcoin::address::Error),
    #[error("BIP448 deposit txid hex error: {0}")]
    TxidHex(#[from] bitcoin::hashes::hex::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bip448DepositAddress {
    pub address: String,
    pub aggregate_pubkey: String,
    pub script_pubkey: String,
    pub funding_update_script: String,
    pub funding_update_control_block: String,
}

#[derive(Debug, Clone)]
pub struct Bip448DepositTemplates {
    pub state_number: u32,
    pub challenge_delay: u16,
    pub funding_outpoint: Bip448FundingOutpoint,
    pub aggregate_pubkey: String,
    pub funding_address: String,
    pub update_tx: Transaction,
    pub settlement_tx: Transaction,
    pub update_template_hash: bitcoin::sighash::TemplateHash,
    pub settlement_template_hash: bitcoin::sighash::TemplateHash,
    pub state_output_script_pubkey: ScriptBuf,
    pub funding_update_script: ScriptBuf,
    pub funding_update_control_block: ControlBlock,
    pub state_update_script: ScriptBuf,
    pub state_update_control_block: ControlBlock,
    pub state_settlement_script: ScriptBuf,
    pub state_settlement_control_block: ControlBlock,
    pub value_schedule: Bip448ValueSchedule,
    pub anchors: Vec<Bip448AnchorOutput>,
    pub cpfp_child_templates: Vec<Bip448CpfpChildTemplate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bip448DepositSigningData {
    pub signing_id: String,
    pub client_public_nonce: String,
    pub server_public_nonce: String,
    pub blinding_factor: String,
    pub update_signature: String,
    pub server_signature_count: u64,
}

pub fn create_deposit_address(
    coin: &Coin,
    network: &str,
) -> Result<Bip448DepositAddress, Bip448DepositError> {
    let network = get_network(network)?;
    let secp = Secp256k1::new();
    let aggregate_pubkey = aggregate_pubkey_from_coin(coin)?;
    let aggregate_xonly = aggregate_pubkey.x_only_public_key().0;
    let spend_info = script::funding_spend_info(&secp, aggregate_xonly)?;
    let script_pubkey = script::output_script_pubkey(&spend_info);
    let address = Address::from_script(&script_pubkey, network)?;
    let control_block = script::funding_update_control_block(&spend_info)?;

    Ok(Bip448DepositAddress {
        address: address.to_string(),
        aggregate_pubkey: aggregate_pubkey.to_string(),
        script_pubkey: script_hex(&script_pubkey),
        funding_update_script: script_hex(&script::funding_update_leaf()),
        funding_update_control_block: control_block_hex(control_block),
    })
}

pub fn build_deposit_templates(
    coin: &Coin,
    funding_outpoint: Bip448FundingOutpoint,
    challenge_delay: u16,
    network: &str,
) -> Result<Bip448DepositTemplates, Bip448DepositError> {
    let network = get_network(network)?;
    let secp = Secp256k1::new();
    let aggregate_pubkey = aggregate_pubkey_from_coin(coin)?;
    let aggregate_xonly = aggregate_pubkey.x_only_public_key().0;
    let recovery_script = recovery_script_from_coin(coin, network)?;
    let funding_outpoint_for_tx = OutPoint {
        txid: Txid::from_str(&funding_outpoint.txid)?,
        vout: funding_outpoint.vout,
    };

    let templates = transaction::build_state_templates(
        &secp,
        aggregate_xonly,
        transaction::placeholder_outpoint(),
        funding_outpoint.value_sats,
        recovery_script.clone(),
        INITIAL_BIP448_STATE_NUMBER,
        challenge_delay,
        FeePolicy::ZeroFeeEphemeralAnchor,
    )?;
    let update_tx = transaction::rebind_update_tx(
        &templates.update_tx,
        funding_outpoint_for_tx,
        funding_outpoint.value_sats,
        FeePolicy::ZeroFeeEphemeralAnchor,
    )?;
    let settlement_tx = transaction::rebind_settlement_tx(
        &templates.settlement_tx,
        OutPoint {
            txid: update_tx.txid(),
            vout: 0,
        },
        templates.settlement_input_amount,
        FeePolicy::ZeroFeeEphemeralAnchor,
    )?;
    let settlement_template_hash = transaction::validate_state_template_set(
        &secp,
        aggregate_xonly,
        INITIAL_BIP448_STATE_NUMBER,
        funding_outpoint.value_sats,
        &recovery_script,
        challenge_delay,
        FeePolicy::ZeroFeeEphemeralAnchor,
        &update_tx,
        &settlement_tx,
    )?;
    let update_template_hash = transaction::update_template_hash(&update_tx)?;
    let funding_spend_info = script::funding_spend_info(&secp, aggregate_xonly)?;
    let state_spend_info = script::state_spend_info(
        &secp,
        aggregate_xonly,
        INITIAL_BIP448_STATE_NUMBER,
        settlement_template_hash,
    )?;
    let funding_address =
        Address::from_script(&script::output_script_pubkey(&funding_spend_info), network)?;

    Ok(Bip448DepositTemplates {
        state_number: INITIAL_BIP448_STATE_NUMBER,
        challenge_delay,
        funding_outpoint,
        aggregate_pubkey: aggregate_pubkey.to_string(),
        funding_address: funding_address.to_string(),
        update_template_hash,
        settlement_template_hash,
        state_output_script_pubkey: templates.state_output_script_pubkey.clone(),
        funding_update_script: script::funding_update_leaf(),
        funding_update_control_block: script::funding_update_control_block(&funding_spend_info)?,
        state_update_script: script::state_update_leaf(INITIAL_BIP448_STATE_NUMBER)?,
        state_update_control_block: script::state_update_control_block(
            &state_spend_info,
            INITIAL_BIP448_STATE_NUMBER,
        )?,
        state_settlement_script: script::state_settlement_leaf(settlement_template_hash),
        state_settlement_control_block: script::state_settlement_control_block(
            &state_spend_info,
            settlement_template_hash,
        )?,
        value_schedule: value_schedule(&templates, &settlement_tx),
        anchors: committed_anchors(&update_tx, &settlement_tx),
        cpfp_child_templates: Vec::new(),
        update_tx,
        settlement_tx,
    })
}

pub fn build_deposit_record(
    wallet_name: &str,
    statechain_id: &str,
    network: &str,
    templates: &Bip448DepositTemplates,
    signing_data: Bip448DepositSigningData,
) -> Result<Bip448StatechainRecord, Bip448DepositError> {
    let signature = schnorr::Signature::from_str(&signing_data.update_signature)?;
    let mut update_tx = templates.update_tx.clone();
    update_tx.input[0].witness = crate::bip448_statechain::signing::csfs_script_witness(
        &signature,
        &templates.funding_update_script,
        &templates.funding_update_control_block,
    );
    let mut settlement_tx = templates.settlement_tx.clone();
    settlement_tx.input[0].witness = settlement_template_witness(
        &templates.state_settlement_script,
        &templates.state_settlement_control_block,
    );
    let update_template_hash = hex::encode(templates.update_template_hash.to_byte_array());

    let latest_state = Bip448LatestState {
        state_number: templates.state_number,
        challenge_delay: templates.challenge_delay,
        update_tx: tx_hex(&update_tx),
        settlement_tx: tx_hex(&settlement_tx),
        update_template_hash: update_template_hash.clone(),
        settlement_template_hash: hex::encode(templates.settlement_template_hash.to_byte_array()),
        state_output_script_pubkey: script_hex(&templates.state_output_script_pubkey),
        funding_update_script: script_hex(&templates.funding_update_script),
        funding_update_control_block: control_block_hex(
            templates.funding_update_control_block.clone(),
        ),
        state_update_script: script_hex(&templates.state_update_script),
        state_update_control_block: control_block_hex(templates.state_update_control_block.clone()),
        state_settlement_script: script_hex(&templates.state_settlement_script),
        state_settlement_control_block: control_block_hex(
            templates.state_settlement_control_block.clone(),
        ),
        csfs_key_metadata: Bip448CsfsKeyMetadata::from_aggregate_pubkey(
            &Secp256k1::new(),
            &PublicKey::from_str(&templates.aggregate_pubkey)?,
        ),
        signing_metadata: Bip448SigningMetadata {
            role: Bip448RecoveryTemplateRole::FundingUpdate,
            signing_id: signing_data.signing_id,
            client_public_nonce: signing_data.client_public_nonce,
            server_public_nonce: signing_data.server_public_nonce,
            blinding_factor: signing_data.blinding_factor,
            update_template_hash,
            update_signature: signing_data.update_signature,
            server_signature_count: signing_data.server_signature_count,
        },
        fee_bump_policy: Bip448FeeBumpPolicy::ZeroFeeEphemeralAnchor,
        value_schedule: templates.value_schedule.clone(),
        anchors: templates.anchors.clone(),
        cpfp_child_templates: templates.cpfp_child_templates.clone(),
    };

    Ok(Bip448StatechainRecord {
        wallet_name: wallet_name.to_string(),
        statechain_id: statechain_id.to_string(),
        aggregate_pubkey: templates.aggregate_pubkey.clone(),
        funding_outpoint: templates.funding_outpoint.clone(),
        latest_state_number: latest_state.state_number,
        challenge_delay: latest_state.challenge_delay,
        amount_sats: templates.funding_outpoint.value_sats,
        network: network.to_string(),
        latest_state,
    })
}

pub fn settlement_template_witness(script: &ScriptBuf, control_block: &ControlBlock) -> Witness {
    let mut witness = Witness::new();
    witness.push(script.as_bytes());
    witness.push(control_block.serialize());
    witness
}

pub fn is_bip448_coin(coin: &Coin) -> bool {
    coin.statechain_protocol.as_deref() == Some(BIP448_COIN_PROTOCOL)
}

fn aggregate_pubkey_from_coin(coin: &Coin) -> Result<PublicKey, Bip448DepositError> {
    if let Some(aggregate_pubkey) = &coin.aggregated_pubkey {
        return Ok(PublicKey::from_str(aggregate_pubkey)?);
    }

    let user_pubkey = PublicKey::from_str(&coin.user_pubkey)?;
    let server_pubkey = PublicKey::from_str(
        coin.server_pubkey
            .as_ref()
            .ok_or(Bip448DepositError::MissingServerPubkey)?,
    )?;

    Ok(user_pubkey.combine(&server_pubkey)?)
}

fn recovery_script_from_coin(
    coin: &Coin,
    network: bitcoin::Network,
) -> Result<ScriptBuf, Bip448DepositError> {
    Ok(Address::from_str(&coin.backup_address)?
        .require_network(network)?
        .script_pubkey())
}

fn value_schedule(templates: &StateTemplates, settlement_tx: &Transaction) -> Bip448ValueSchedule {
    Bip448ValueSchedule {
        funding_value_sats: templates.update_input_amount,
        update_input_value_sats: templates.update_input_amount,
        update_state_output_value_sats: templates.settlement_input_amount,
        settlement_input_value_sats: templates.settlement_input_amount,
        settlement_recovery_output_value_sats: settlement_tx.output[0].value,
    }
}

fn committed_anchors(
    update_tx: &Transaction,
    settlement_tx: &Transaction,
) -> Vec<Bip448AnchorOutput> {
    let mut anchors = Vec::new();

    if let Some(anchor) = anchor_output(Bip448RecoveryTemplateRole::FundingUpdate, update_tx, 1) {
        anchors.push(anchor);
    }
    if let Some(anchor) = anchor_output(Bip448RecoveryTemplateRole::Settlement, settlement_tx, 1) {
        anchors.push(anchor);
    }

    anchors
}

fn anchor_output(
    tx_role: Bip448RecoveryTemplateRole,
    tx: &Transaction,
    output_index: usize,
) -> Option<Bip448AnchorOutput> {
    tx.output
        .get(output_index)
        .map(|output| Bip448AnchorOutput {
            tx_role,
            output_index: output_index as u32,
            value_sats: output.value,
            script_pubkey: script_hex(&output.script_pubkey),
        })
}

fn tx_hex(tx: &Transaction) -> String {
    hex::encode(encode::serialize(tx))
}

fn script_hex(script: &ScriptBuf) -> String {
    hex::encode(script.as_bytes())
}

fn control_block_hex(control_block: ControlBlock) -> String {
    hex::encode(control_block.serialize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::{Settings, Wallet};
    use bitcoin::{consensus::encode, Network};
    use secp256k1::{KeyPair, SecretKey};

    const FUNDING_VALUE: u64 = 100_000;

    fn sample_wallet() -> Wallet {
        Wallet {
            name: "wallet".to_string(),
            mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            version: "0.1.0".to_string(),
            state_entity_endpoint: "http://statechain".to_string(),
            chain_backend: "core".to_string(),
            chain_endpoint: "http://127.0.0.1:18443".to_string(),
            network: "regtest".to_string(),
            blockheight: 42,
            initlock: 1000,
            interval: 10,
            activities: Vec::new(),
            coins: Vec::new(),
            settings: Settings {
                network: "regtest".to_string(),
                block_explorerURL: None,
                torProxyHost: None,
                torProxyPort: None,
                torProxyControlPassword: None,
                torProxyControlPort: None,
                statechainEntityApi: "http://statechain".to_string(),
                torStatechainEntityApi: None,
                chainBackend: "core".to_string(),
                chainUrl: "http://127.0.0.1:18443".to_string(),
                chainType: None,
                notifications: false,
                tutorials: false,
            },
        }
    }

    fn sample_coin() -> Coin {
        let secp = Secp256k1::new();
        let mut coin = sample_wallet().get_new_coin().unwrap();
        let server_secret_key = SecretKey::from_secret_bytes([7u8; 32]).unwrap();
        let server_pubkey = server_secret_key.public_key(&secp);
        let user_pubkey = PublicKey::from_str(&coin.user_pubkey).unwrap();
        coin.server_pubkey = Some(server_pubkey.to_string());
        coin.aggregated_pubkey = Some(user_pubkey.combine(&server_pubkey).unwrap().to_string());
        coin.statechain_protocol = Some(BIP448_COIN_PROTOCOL.to_string());
        coin.statechain_id = Some("statechain".to_string());
        coin.signed_statechain_id = Some("signed-statechain".to_string());
        coin.amount = Some(FUNDING_VALUE as u32);
        coin
    }

    fn funding_outpoint() -> Bip448FundingOutpoint {
        Bip448FundingOutpoint {
            txid: Txid::from_slice(&[0x11; 32]).unwrap().to_string(),
            vout: 0,
            value_sats: FUNDING_VALUE,
        }
    }

    fn tx_from_hex(tx_hex: &str) -> Transaction {
        encode::deserialize(&hex::decode(tx_hex).unwrap()).unwrap()
    }

    fn test_signature(hash: bitcoin::sighash::TemplateHash) -> schnorr::Signature {
        let secp = Secp256k1::new();
        let keypair =
            KeyPair::from_secret_key(&secp, &SecretKey::from_secret_bytes([42u8; 32]).unwrap());

        schnorr::sign(hash.as_byte_array(), &keypair)
    }

    #[test]
    fn deposit_address_uses_funding_leaf_not_legacy_key_path() {
        let secp = Secp256k1::new();
        let coin = sample_coin();
        let address = create_deposit_address(&coin, "regtest").unwrap();
        let aggregate_pubkey =
            PublicKey::from_str(&coin.aggregated_pubkey.clone().unwrap()).unwrap();
        let aggregate_xonly = aggregate_pubkey.x_only_public_key().0;
        let spend_info = script::funding_spend_info(&secp, aggregate_xonly).unwrap();
        let expected =
            Address::from_script(&script::output_script_pubkey(&spend_info), Network::Regtest)
                .unwrap();
        let legacy_key_path = Address::p2tr(&secp, aggregate_xonly, None, Network::Regtest);

        assert_eq!(address.address, expected.to_string());
        assert_ne!(address.address, legacy_key_path.to_string());
        assert_eq!(address.aggregate_pubkey, coin.aggregated_pubkey.unwrap());
        assert_eq!(
            address.funding_update_script,
            script_hex(&script::funding_update_leaf())
        );
    }

    #[test]
    fn deposit_templates_validate_state_one_and_reject_mutation() {
        let secp = Secp256k1::new();
        let coin = sample_coin();
        let templates = build_deposit_templates(
            &coin,
            funding_outpoint(),
            DEFAULT_BIP448_CHALLENGE_DELAY,
            "regtest",
        )
        .unwrap();
        let aggregate_pubkey = PublicKey::from_str(&templates.aggregate_pubkey).unwrap();
        let recovery_script = recovery_script_from_coin(&coin, Network::Regtest).unwrap();

        assert_eq!(templates.update_tx.version, transaction::TX_VERSION);
        assert_eq!(templates.settlement_tx.version, transaction::TX_VERSION);
        assert_eq!(templates.update_tx.input[0].previous_output.vout, 0);
        assert_eq!(
            templates.settlement_tx.input[0].previous_output.txid,
            templates.update_tx.txid()
        );
        assert_eq!(templates.anchors.len(), 2);
        assert_eq!(templates.anchors[0].script_pubkey, "51024e73");
        assert_eq!(templates.value_schedule.funding_value_sats, FUNDING_VALUE);
        assert!(transaction::validate_state_template_set(
            &secp,
            aggregate_pubkey.x_only_public_key().0,
            INITIAL_BIP448_STATE_NUMBER,
            FUNDING_VALUE,
            &recovery_script,
            DEFAULT_BIP448_CHALLENGE_DELAY,
            FeePolicy::ZeroFeeEphemeralAnchor,
            &templates.update_tx,
            &templates.settlement_tx,
        )
        .is_ok());

        let mut mutated = templates.update_tx.clone();
        mutated.output[0].value -= 1;
        assert!(transaction::validate_state_template_set(
            &secp,
            aggregate_pubkey.x_only_public_key().0,
            INITIAL_BIP448_STATE_NUMBER,
            FUNDING_VALUE,
            &recovery_script,
            DEFAULT_BIP448_CHALLENGE_DELAY,
            FeePolicy::ZeroFeeEphemeralAnchor,
            &mutated,
            &templates.settlement_tx,
        )
        .is_err());
    }

    #[test]
    fn signed_deposit_record_contains_recovery_witnesses_and_no_legacy_backups() {
        let templates = build_deposit_templates(
            &sample_coin(),
            funding_outpoint(),
            DEFAULT_BIP448_CHALLENGE_DELAY,
            "regtest",
        )
        .unwrap();
        let signature = test_signature(templates.update_template_hash);
        let record = build_deposit_record(
            "wallet",
            "statechain",
            "regtest",
            &templates,
            Bip448DepositSigningData {
                signing_id: "77".repeat(32),
                client_public_nonce: "88".repeat(66),
                server_public_nonce: "99".repeat(66),
                blinding_factor: "aa".repeat(32),
                update_signature: signature.to_string(),
                server_signature_count: 1,
            },
        )
        .unwrap();
        let update_tx = tx_from_hex(&record.latest_state.update_tx);
        let settlement_tx = tx_from_hex(&record.latest_state.settlement_tx);
        let json = serde_json::to_string(&record).unwrap();

        assert_eq!(record.latest_state_number, INITIAL_BIP448_STATE_NUMBER);
        assert_eq!(
            record.latest_state.signing_metadata.role,
            Bip448RecoveryTemplateRole::FundingUpdate
        );
        assert_eq!(
            record.latest_state.signing_metadata.server_signature_count,
            1
        );
        assert_eq!(update_tx.input[0].witness.len(), 3);
        assert_eq!(update_tx.input[0].witness.nth(0).unwrap().len(), 64);
        assert_eq!(settlement_tx.input[0].witness.len(), 2);
        assert!(record.latest_state.cpfp_child_templates.is_empty());
        assert!(!json.contains("backup_txs"));
        assert!(!json.contains("backup_transactions"));
    }
}
