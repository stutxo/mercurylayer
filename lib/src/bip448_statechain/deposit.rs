use std::str::FromStr;

use bitcoin::{
    absolute,
    hashes::Hash,
    secp256k1::{PublicKey, Secp256k1},
    Address, OutPoint, ScriptBuf, Txid,
};
use secp256k1::rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::{
    bip448_statechain::{
        script::{self, ScriptTemplateError},
        storage::{
            build_funding_latest_state, build_funding_recovery_artifacts, control_block_hex,
            script_hex, Bip448FeeBumpPolicy, Bip448FundingOutpoint, Bip448RecoveryArtifactError,
            Bip448RecoveryArtifacts, Bip448RecoveryTemplateRole, Bip448SigningMetadata,
            Bip448StatechainRecord,
        },
    },
    error::MercuryError,
    utils::get_network,
    wallet::Coin,
};

pub const INITIAL_BIP448_STATE_NUMBER: u32 = 1;
pub const DEFAULT_BIP448_CHALLENGE_DELAY: u16 = 144;
pub const BIP448_COIN_PROTOCOL: &str = "bip448";

pub fn sample_initial_state_locktime() -> absolute::LockTime {
    let mut rng = secp256k1::rand::rng();
    sample_initial_state_locktime_with_rng(&mut rng)
}

fn sample_initial_state_locktime_with_rng<R: RngCore + ?Sized>(rng: &mut R) -> absolute::LockTime {
    loop {
        if let Some(locktime) = map_initial_state_locktime_sample(rng.next_u32()) {
            return absolute::LockTime::from_consensus(locktime);
        }
    }
}

fn map_initial_state_locktime_sample(sample: u32) -> Option<u32> {
    let range_size = u64::from(script::INITIAL_STATE_LOCKTIME_MAX)
        - u64::from(script::INITIAL_STATE_LOCKTIME_MIN)
        + 1;
    let source_size = u64::from(u32::MAX) + 1;
    let unbiased_zone = source_size - (source_size % range_size);
    let sample = u64::from(sample);
    if sample >= unbiased_zone {
        return None;
    }

    Some(script::INITIAL_STATE_LOCKTIME_MIN + (sample % range_size) as u32)
}

#[derive(Debug, thiserror::Error)]
pub enum Bip448DepositError {
    #[error("BIP448 deposit coin is missing server_pubkey")]
    MissingServerPubkey,
    #[error("BIP448 deposit coin is missing aggregate_pubkey")]
    MissingAggregatePubkey,
    #[error("BIP448 deposit backup address does not match user_pubkey")]
    RecoveryAddressMismatch,
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
    #[error(
        "BIP448 deposit server signature count for the initial state must be {expected}, got {actual}"
    )]
    InvalidServerSignatureCount { expected: u64, actual: u64 },
    #[error("BIP448 deposit recovery artifact error: {0}")]
    RecoveryArtifacts(#[from] Bip448RecoveryArtifactError),
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
    pub funding_outpoint: Bip448FundingOutpoint,
    pub aggregate_pubkey: String,
    pub funding_address: String,
    pub artifacts: Bip448RecoveryArtifacts,
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
    recovery_script_from_coin(coin, network)?;
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
        funding_update_control_block: control_block_hex(&control_block),
    })
}

pub fn build_deposit_templates(
    coin: &Coin,
    funding_outpoint: Bip448FundingOutpoint,
    state_locktime: absolute::LockTime,
    challenge_delay: u16,
    network: &str,
) -> Result<Bip448DepositTemplates, Bip448DepositError> {
    script::validate_initial_state_locktime(state_locktime)?;
    let network = get_network(network)?;
    let secp = Secp256k1::new();
    let aggregate_pubkey = aggregate_pubkey_from_coin(coin)?;
    let recovery_script = recovery_script_from_coin(coin, network)?;
    let funding_outpoint_for_tx = OutPoint {
        txid: Txid::from_str(&funding_outpoint.txid)?,
        vout: funding_outpoint.vout,
    };

    let artifacts = build_funding_recovery_artifacts(
        &secp,
        &aggregate_pubkey,
        funding_outpoint_for_tx,
        funding_outpoint.value_sats,
        recovery_script.clone(),
        INITIAL_BIP448_STATE_NUMBER,
        state_locktime,
        challenge_delay,
        Bip448FeeBumpPolicy::ZeroFeeEphemeralAnchor,
    )?;
    let funding_address = Address::from_script(&artifacts.funding_output_script_pubkey, network)?;

    Ok(Bip448DepositTemplates {
        funding_outpoint,
        aggregate_pubkey: aggregate_pubkey.to_string(),
        funding_address: funding_address.to_string(),
        artifacts,
    })
}

pub fn build_deposit_record(
    wallet_name: &str,
    statechain_id: &str,
    network: &str,
    templates: &Bip448DepositTemplates,
    signing_data: Bip448DepositSigningData,
) -> Result<Bip448StatechainRecord, Bip448DepositError> {
    let expected_signature_count = u64::from(INITIAL_BIP448_STATE_NUMBER);
    if signing_data.server_signature_count != expected_signature_count {
        return Err(Bip448DepositError::InvalidServerSignatureCount {
            expected: expected_signature_count,
            actual: signing_data.server_signature_count,
        });
    }

    let secp = Secp256k1::new();
    let aggregate_pubkey = PublicKey::from_str(&templates.aggregate_pubkey)?;
    let update_template_hash =
        hex::encode(templates.artifacts.update_template_hash.to_byte_array());
    let latest_state = build_funding_latest_state(
        &secp,
        &aggregate_pubkey,
        &templates.artifacts,
        Bip448SigningMetadata {
            role: Bip448RecoveryTemplateRole::FundingUpdate,
            signing_id: signing_data.signing_id,
            client_public_nonce: signing_data.client_public_nonce,
            server_public_nonce: signing_data.server_public_nonce,
            blinding_factor: signing_data.blinding_factor,
            update_template_hash,
            update_signature: signing_data.update_signature,
            server_signature_count: signing_data.server_signature_count,
        },
        Vec::new(),
    )?;

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
    let recovery_address = Address::from_str(&coin.backup_address)?.require_network(network)?;
    let user_pubkey = PublicKey::from_str(&coin.user_pubkey)?;
    let expected = Address::p2tr(
        &Secp256k1::new(),
        user_pubkey.x_only_public_key().0,
        None,
        network,
    );
    if recovery_address != expected {
        return Err(Bip448DepositError::RecoveryAddressMismatch);
    }

    Ok(recovery_address.script_pubkey())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip448_statechain::storage::Bip448CpfpChildTemplate;
    use crate::bip448_statechain::transaction::{self, FeePolicy};
    use crate::wallet::{Settings, Wallet};
    use bitcoin::{consensus::encode, hashes::Hash, Network, PrivateKey, Transaction};
    use secp256k1::{schnorr, KeyPair, Scalar, SecretKey};

    const FUNDING_VALUE: u64 = 100_000;
    const STATE_LOCKTIME: u32 = 700_000_042;

    fn state_locktime() -> absolute::LockTime {
        absolute::LockTime::from_consensus(STATE_LOCKTIME)
    }

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

    fn test_signature(coin: &Coin, hash: bitcoin::sighash::TemplateHash) -> schnorr::Signature {
        let secp = Secp256k1::new();
        let user_secret = PrivateKey::from_wif(&coin.user_privkey).unwrap().inner;
        let server_secret = SecretKey::from_secret_bytes([7u8; 32]).unwrap();
        let server_tweak = Scalar::from_be_bytes(server_secret.to_secret_bytes()).unwrap();
        let aggregate_secret = user_secret.add_tweak(&server_tweak).unwrap();
        let keypair = KeyPair::from_secret_key(&secp, &aggregate_secret);

        schnorr::sign(hash.as_byte_array(), &keypair)
    }

    fn test_signing_data(signature: schnorr::Signature) -> Bip448DepositSigningData {
        Bip448DepositSigningData {
            signing_id: "77".repeat(32),
            client_public_nonce: "88".repeat(66),
            server_public_nonce: "99".repeat(66),
            blinding_factor: "aa".repeat(32),
            update_signature: signature.to_string(),
            server_signature_count: 1,
        }
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
    fn deposit_rejects_backup_address_not_derived_from_user_pubkey() {
        let secp = Secp256k1::new();
        let mut coin = sample_coin();
        let unrelated = SecretKey::from_secret_bytes([42u8; 32]).unwrap();
        coin.backup_address = Address::p2tr(
            &secp,
            unrelated.public_key(&secp).x_only_public_key().0,
            None,
            Network::Regtest,
        )
        .to_string();

        assert!(matches!(
            create_deposit_address(&coin, "regtest"),
            Err(Bip448DepositError::RecoveryAddressMismatch)
        ));
        assert!(matches!(
            build_deposit_templates(
                &coin,
                funding_outpoint(),
                state_locktime(),
                DEFAULT_BIP448_CHALLENGE_DELAY,
                "regtest",
            ),
            Err(Bip448DepositError::RecoveryAddressMismatch)
        ));
    }

    #[test]
    fn initial_locktime_sampler_includes_both_range_boundaries() {
        let range_size =
            script::INITIAL_STATE_LOCKTIME_MAX - script::INITIAL_STATE_LOCKTIME_MIN + 1;

        assert_eq!(
            map_initial_state_locktime_sample(0),
            Some(script::INITIAL_STATE_LOCKTIME_MIN)
        );
        assert_eq!(
            map_initial_state_locktime_sample(range_size - 1),
            Some(script::INITIAL_STATE_LOCKTIME_MAX)
        );
        assert_eq!(map_initial_state_locktime_sample(u32::MAX), None);
    }

    #[test]
    fn randomized_state_locktime_does_not_change_funding_address() {
        let coin = sample_coin();
        let minimum = build_deposit_templates(
            &coin,
            funding_outpoint(),
            absolute::LockTime::from_consensus(script::INITIAL_STATE_LOCKTIME_MIN),
            DEFAULT_BIP448_CHALLENGE_DELAY,
            "regtest",
        )
        .unwrap();
        let maximum = build_deposit_templates(
            &coin,
            funding_outpoint(),
            absolute::LockTime::from_consensus(script::INITIAL_STATE_LOCKTIME_MAX),
            DEFAULT_BIP448_CHALLENGE_DELAY,
            "regtest",
        )
        .unwrap();

        assert_eq!(minimum.funding_address, maximum.funding_address);
        assert_eq!(
            minimum.artifacts.funding_output_script_pubkey,
            maximum.artifacts.funding_output_script_pubkey
        );
        assert_ne!(minimum.artifacts.update_tx, maximum.artifacts.update_tx);
        assert_ne!(
            minimum.artifacts.settlement_tx,
            maximum.artifacts.settlement_tx
        );
    }

    #[test]
    fn deposit_templates_validate_state_one_and_reject_mutation() {
        let secp = Secp256k1::new();
        let coin = sample_coin();
        let templates = build_deposit_templates(
            &coin,
            funding_outpoint(),
            state_locktime(),
            DEFAULT_BIP448_CHALLENGE_DELAY,
            "regtest",
        )
        .unwrap();
        let aggregate_pubkey = PublicKey::from_str(&templates.aggregate_pubkey).unwrap();
        let recovery_script = recovery_script_from_coin(&coin, Network::Regtest).unwrap();

        assert_eq!(
            templates.artifacts.update_tx.version,
            transaction::TX_VERSION
        );
        assert_eq!(
            templates.artifacts.state_number,
            INITIAL_BIP448_STATE_NUMBER
        );
        assert_eq!(templates.artifacts.state_locktime, STATE_LOCKTIME);
        assert_eq!(templates.artifacts.update_tx.lock_time, state_locktime());
        assert_eq!(
            templates.artifacts.settlement_tx.lock_time,
            state_locktime()
        );
        assert_eq!(
            templates.artifacts.settlement_tx.version,
            transaction::TX_VERSION
        );
        assert_eq!(
            templates.artifacts.update_tx.input[0].previous_output.vout,
            0
        );
        assert_eq!(
            templates.artifacts.settlement_tx.input[0]
                .previous_output
                .txid,
            templates.artifacts.update_tx.txid()
        );
        assert_eq!(templates.artifacts.anchors.len(), 2);
        assert_eq!(templates.artifacts.anchors[0].script_pubkey, "51024e73");
        assert_eq!(
            templates.artifacts.value_schedule.funding_value_sats,
            FUNDING_VALUE
        );
        assert!(transaction::validate_state_template_set(
            &secp,
            aggregate_pubkey.x_only_public_key().0,
            INITIAL_BIP448_STATE_NUMBER,
            state_locktime(),
            FUNDING_VALUE,
            &recovery_script,
            DEFAULT_BIP448_CHALLENGE_DELAY,
            FeePolicy::ZeroFeeEphemeralAnchor,
            &templates.artifacts.update_tx,
            &templates.artifacts.settlement_tx,
        )
        .is_ok());

        let mut mutated = templates.artifacts.update_tx.clone();
        mutated.output[0].value -= 1;
        assert!(transaction::validate_state_template_set(
            &secp,
            aggregate_pubkey.x_only_public_key().0,
            INITIAL_BIP448_STATE_NUMBER,
            state_locktime(),
            FUNDING_VALUE,
            &recovery_script,
            DEFAULT_BIP448_CHALLENGE_DELAY,
            FeePolicy::ZeroFeeEphemeralAnchor,
            &mutated,
            &templates.artifacts.settlement_tx,
        )
        .is_err());
    }

    #[test]
    fn signed_deposit_record_contains_recovery_witnesses_and_no_legacy_backups() {
        let coin = sample_coin();
        let templates = build_deposit_templates(
            &coin,
            funding_outpoint(),
            state_locktime(),
            DEFAULT_BIP448_CHALLENGE_DELAY,
            "regtest",
        )
        .unwrap();
        let signature = test_signature(&coin, templates.artifacts.update_template_hash);
        let record = build_deposit_record(
            "wallet",
            "statechain",
            "regtest",
            &templates,
            test_signing_data(signature),
        )
        .unwrap();
        let update_tx = tx_from_hex(&record.latest_state.update_tx);
        let settlement_tx = tx_from_hex(&record.latest_state.settlement_tx);
        let json = serde_json::to_string(&record).unwrap();

        assert_eq!(record.latest_state_number, INITIAL_BIP448_STATE_NUMBER);
        assert_eq!(record.latest_state.state_locktime, STATE_LOCKTIME);
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

    #[test]
    fn deposit_record_rejects_wrong_aggregate_key_or_signature() {
        let secp = Secp256k1::new();
        let coin = sample_coin();
        let templates = build_deposit_templates(
            &coin,
            funding_outpoint(),
            state_locktime(),
            DEFAULT_BIP448_CHALLENGE_DELAY,
            "regtest",
        )
        .unwrap();
        let wrong_keypair =
            KeyPair::from_secret_key(&secp, &SecretKey::from_secret_bytes([42u8; 32]).unwrap());
        let wrong_signature = schnorr::sign(
            templates.artifacts.update_template_hash.as_byte_array(),
            &wrong_keypair,
        );
        let error = build_deposit_record(
            "wallet",
            "statechain",
            "regtest",
            &templates,
            test_signing_data(wrong_signature),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            Bip448DepositError::RecoveryArtifacts(
                Bip448RecoveryArtifactError::UpdateSignatureVerification
            )
        ));

        let mut mismatched_key = templates.clone();
        mismatched_key.aggregate_pubkey = wrong_keypair.public_key().to_string();
        let valid_signature = test_signature(&coin, templates.artifacts.update_template_hash);
        let error = build_deposit_record(
            "wallet",
            "statechain",
            "regtest",
            &mismatched_key,
            test_signing_data(valid_signature),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            Bip448DepositError::RecoveryArtifacts(
                Bip448RecoveryArtifactError::AggregateKeyMismatch
            )
        ));
    }

    #[test]
    fn deposit_record_rejects_non_initial_server_signature_count() {
        let coin = sample_coin();
        let templates = build_deposit_templates(
            &coin,
            funding_outpoint(),
            state_locktime(),
            DEFAULT_BIP448_CHALLENGE_DELAY,
            "regtest",
        )
        .unwrap();
        let signature = test_signature(&coin, templates.artifacts.update_template_hash);
        let mut signing_data = test_signing_data(signature);
        signing_data.server_signature_count = 2;

        let error =
            build_deposit_record("wallet", "statechain", "regtest", &templates, signing_data)
                .unwrap_err();

        assert!(matches!(
            error,
            Bip448DepositError::InvalidServerSignatureCount {
                expected: 1,
                actual: 2
            }
        ));
    }

    #[test]
    fn latest_state_builder_rejects_unverified_cpfp_children() {
        let secp = Secp256k1::new();
        let coin = sample_coin();
        let templates = build_deposit_templates(
            &coin,
            funding_outpoint(),
            state_locktime(),
            DEFAULT_BIP448_CHALLENGE_DELAY,
            "regtest",
        )
        .unwrap();
        let aggregate_pubkey = PublicKey::from_str(&templates.aggregate_pubkey).unwrap();
        let signature = test_signature(&coin, templates.artifacts.update_template_hash);
        let error = build_funding_latest_state(
            &secp,
            &aggregate_pubkey,
            &templates.artifacts,
            Bip448SigningMetadata {
                role: Bip448RecoveryTemplateRole::FundingUpdate,
                signing_id: "77".repeat(32),
                client_public_nonce: "88".repeat(66),
                server_public_nonce: "99".repeat(66),
                blinding_factor: "aa".repeat(32),
                update_template_hash: hex::encode(
                    templates.artifacts.update_template_hash.to_byte_array(),
                ),
                update_signature: signature.to_string(),
                server_signature_count: 1,
            },
            vec![Bip448CpfpChildTemplate {
                parent_role: Bip448RecoveryTemplateRole::FundingUpdate,
                anchor_output_index: 1,
                tx_hex: "03000000".to_string(),
                fee_sats: 1_000,
                target_feerate_sat_per_vbyte: Some(10),
            }],
        )
        .unwrap_err();

        assert!(matches!(
            error,
            Bip448RecoveryArtifactError::UnverifiedCpfpChildTemplates
        ));
    }
}
