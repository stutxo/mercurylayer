pub(super) use super::super::*;
pub(super) use crate::{
    bip448_funding,
    bip448_funding::*,
    bip448_transfer_sender::transfer_bip448_sender,
    chain::{ChainClient, ChainUtxo, CoreRpcAuth, CoreRpcConfig},
    client_config::ClientConfig,
    sqlite_manager::*,
};
pub(super) use anyhow::{anyhow, Context, Result};
pub(super) use bitcoin::{
    absolute,
    hashes::{sha256, Hash},
    Address, Network, OutPoint, PrivateKey, Txid,
};
pub(super) use mercurylib::{
    bip448_statechain::{
        deposit::{
            self as bip448_deposit, Bip448DepositSigningData, BIP448_COIN_PROTOCOL,
            DEFAULT_BIP448_CHALLENGE_DELAY,
        },
        storage::{
            build_funding_latest_state, build_funding_recovery_artifacts, Bip448AnchorOutput,
            Bip448CpfpChildTemplate, Bip448CsfsKeyMetadata, Bip448FeeBumpPolicy,
            Bip448FundingOutpoint, Bip448LatestState, Bip448RecoveryTemplateRole,
            Bip448SigningMetadata, Bip448StatechainRecord, Bip448ValueSchedule,
        },
        withdraw::{build_bip448_withdrawal_signing_data, create_bip448_keypath_nonces},
    },
    transfer::bip448::{Bip448StateHistoryEntry, Bip448TransferMsg},
    wallet::{Coin, CoinStatus, Settings, Wallet},
};
pub(super) use secp256k1::{
    musig::{new_musig_nonce_pair, BlindingFactor, MusigSessionId},
    schnorr, KeyPair, Message, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey,
};
pub(super) use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    Pool, Sqlite,
};
pub(super) use std::{path::PathBuf, str::FromStr, sync::Arc, time::Duration};

pub(super) use super::super::{
    bindings::accepted_funding_script,
    guard::{Bip448BeginImmediateTestHook, BIP448_BEGIN_IMMEDIATE_TEST_HOOK},
};

pub(super) async fn migrated_pool() -> Result<Pool<Sqlite>> {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await?;

    sqlx::migrate!("./migrations").run(&pool).await?;

    Ok(pool)
}

pub(super) struct IndependentTestPools {
    pub(super) first: Pool<Sqlite>,
    pub(super) second: Pool<Sqlite>,
    path: PathBuf,
}

impl Drop for IndependentTestPools {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        for suffix in ["-journal", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", self.path.display()));
        }
    }
}

pub(super) async fn independent_migrated_pools() -> Result<IndependentTestPools> {
    let path = std::env::temp_dir().join(format!(
        "mercurylayer-bip448-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    let options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true)
        .busy_timeout(Duration::from_secs(5));
    let first = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone())
        .await?;
    sqlx::migrate!("./migrations").run(&first).await?;
    let second = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await?;
    Ok(IndependentTestPools {
        first,
        second,
        path,
    })
}

pub(super) async fn assert_begin_is_contested(
    hook: &Arc<Bip448BeginImmediateTestHook>,
) -> Result<()> {
    hook.before_acquire.notified().await;
    if hook.after_emitted.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(anyhow!(
            "contested BEGIN IMMEDIATE acquired before the winner released"
        ));
    }
    Ok(())
}

pub(super) fn sample_wallet() -> Wallet {
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

pub(super) fn sample_latest_state(state_number: u32) -> Bip448LatestState {
    Bip448LatestState {
        state_number,
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
            server_signature_count: u64::from(state_number),
        },
        fee_bump_policy: Bip448FeeBumpPolicy::ZeroFeeEphemeralAnchor,
        value_schedule: Bip448ValueSchedule {
            funding_value_sats: 100_000,
            update_input_value_sats: 100_000,
            update_state_output_value_sats: 100_000,
            settlement_input_value_sats: 100_000,
            settlement_recovery_output_value_sats: 100_000,
        },
        anchors: vec![Bip448AnchorOutput {
            tx_role: Bip448RecoveryTemplateRole::StateUpdate,
            output_index: 1,
            value_sats: 0,
            script_pubkey: "51024e73".to_string(),
        }],
        cpfp_child_templates: Vec::new(),
    }
}

pub(super) fn sample_cpfp_child_template() -> Bip448CpfpChildTemplate {
    Bip448CpfpChildTemplate {
        parent_role: Bip448RecoveryTemplateRole::StateUpdate,
        anchor_output_index: 1,
        tx_hex: "03000000".to_string(),
        fee_sats: 1_000,
        target_feerate_sat_per_vbyte: Some(10),
    }
}

pub(super) fn sample_bip448_record(state_number: u32) -> Bip448StatechainRecord {
    let latest_state = sample_latest_state(state_number);
    Bip448StatechainRecord {
        wallet_name: "wallet".to_string(),
        statechain_id: "statechain".to_string(),
        aggregate_pubkey: "02".to_string() + &"12".repeat(32),
        funding_outpoint: Bip448FundingOutpoint {
            txid: "34".repeat(32),
            vout: 0,
            value_sats: 100_000,
        },
        latest_state_number: latest_state.state_number,
        challenge_delay: latest_state.challenge_delay,
        amount_sats: 100_000,
        network: "regtest".to_string(),
        latest_state,
    }
}

pub(super) fn sample_bip448_transfer_msg() -> Bip448TransferMsg {
    let mut latest_state = sample_latest_state(2);
    latest_state
        .cpfp_child_templates
        .push(sample_cpfp_child_template());
    Bip448TransferMsg {
        msg_version: 2,
        statechain_id: "statechain".to_string(),
        transfer_signature: "ab".repeat(64),
        sender_user_public_key: "02".to_string() + &"12".repeat(32),
        receiver_user_public_key: "03".to_string() + &"13".repeat(32),
        server_public_key: "02".to_string() + &"14".repeat(32),
        aggregate_pubkey: "02".to_string() + &"15".repeat(32),
        funding_outpoint: Bip448FundingOutpoint {
            txid: "44".repeat(32),
            vout: 1,
            value_sats: 100_000,
        },
        latest_state_number: latest_state.state_number,
        challenge_delay: latest_state.challenge_delay,
        amount_sats: 100_000,
        network: "regtest".to_string(),
        value_schedule: latest_state.value_schedule.clone(),
        latest_state,
        server_signature_count: 2,
        t1: [9u8; 32],
        state_history: Vec::new(),
    }
}

pub(super) fn sample_owner_key(byte: u8) -> (secp256k1::PublicKey, XOnlyPublicKey) {
    let secret = secp256k1::SecretKey::from_secret_bytes([byte; 32]).unwrap();
    let public = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &secret);
    (public, public.x_only_public_key().0)
}

pub(super) fn real_accepted_fixture_for(
    status: CoinStatus,
    statechain_id: &str,
    funding_txid: &str,
) -> Result<(
    Wallet,
    Bip448StatechainRecord,
    Bip448StateHistoryEntry,
    XOnlyPublicKey,
)> {
    let mut wallet = sample_wallet();
    let mut coin = wallet.get_new_coin()?;
    let secp = Secp256k1::new();
    let server_secret = SecretKey::from_secret_bytes([7u8; 32])?;
    let server_pubkey = server_secret.public_key(&secp);
    let user_pubkey = PublicKey::from_str(&coin.user_pubkey)?;
    let aggregate_pubkey = user_pubkey.combine(&server_pubkey)?;
    coin.server_pubkey = Some(server_pubkey.to_string());
    coin.aggregated_pubkey = Some(aggregate_pubkey.to_string());
    coin.statechain_protocol = Some(BIP448_COIN_PROTOCOL.to_string());
    coin.statechain_id = Some(statechain_id.to_owned());
    coin.signed_statechain_id = Some(mercurylib::transfer::receiver::sign_message(
        statechain_id,
        &coin,
    )?);
    coin.utxo_txid = Some(funding_txid.to_owned());
    coin.utxo_vout = Some(0);
    coin.amount = Some(100_000);
    coin.status = status;
    let deposit_address = bip448_deposit::create_deposit_address(&coin, "regtest")?;
    coin.aggregated_address = Some(deposit_address.address);

    let templates = bip448_deposit::build_deposit_templates(
        &coin,
        Bip448FundingOutpoint {
            txid: funding_txid.to_owned(),
            vout: 0,
            value_sats: 100_000,
        },
        absolute::LockTime::from_consensus(700_000_042),
        DEFAULT_BIP448_CHALLENGE_DELAY,
        "regtest",
    )?;
    let user_secret = PrivateKey::from_wif(&coin.user_privkey)?.inner;
    let server_scalar = Scalar::from_be_bytes(server_secret.to_secret_bytes())?;
    let aggregate_secret = user_secret.add_tweak(&server_scalar)?;
    let aggregate_keypair = KeyPair::from_secret_key(&secp, &aggregate_secret);
    let update_signature = schnorr::sign(
        templates.artifacts.update_template_hash.as_byte_array(),
        &aggregate_keypair,
    );
    let message: Message = templates.artifacts.update_template_hash.into();
    let client_nonce_key = SecretKey::from_secret_bytes([3u8; 32])?;
    let server_nonce_key = SecretKey::from_secret_bytes([4u8; 32])?;
    let (_, client_public_nonce) = new_musig_nonce_pair(
        &secp,
        MusigSessionId::assume_unique_per_nonce_gen([1u8; 32]),
        None,
        Some(client_nonce_key),
        client_nonce_key.public_key(&secp),
        Some(message),
        None,
    )?;
    let (_, server_public_nonce) = new_musig_nonce_pair(
        &secp,
        MusigSessionId::assume_unique_per_nonce_gen([2u8; 32]),
        None,
        Some(server_nonce_key),
        server_nonce_key.public_key(&secp),
        Some(message),
        None,
    )?;
    let blinding_factor = BlindingFactor::from_slice(&[21u8; 32])?;
    let signing_data = Bip448DepositSigningData {
        signing_id: "77".repeat(32),
        client_public_nonce: hex::encode(client_public_nonce.serialize()),
        server_public_nonce: hex::encode(server_public_nonce.serialize()),
        blinding_factor: hex::encode(blinding_factor.as_bytes()),
        update_signature: update_signature.to_string(),
        server_signature_count: 1,
    };
    let record = bip448_deposit::build_deposit_record(
        "wallet",
        statechain_id,
        "regtest",
        &templates,
        signing_data.clone(),
    )?;
    coin.locktime = Some(record.latest_state.state_locktime);
    coin.public_nonce = Some(signing_data.client_public_nonce);
    coin.server_public_nonce = Some(signing_data.server_public_nonce);
    coin.blinding_factor = Some(signing_data.blinding_factor);
    let owner = user_pubkey.x_only_public_key().0;
    let entry = history_entry(&record.latest_state, owner);
    wallet.coins.push(coin);
    Ok((wallet, record, entry, owner))
}

pub(super) fn real_accepted_fixture(
    status: CoinStatus,
) -> Result<(
    Wallet,
    Bip448StatechainRecord,
    Bip448StateHistoryEntry,
    XOnlyPublicKey,
)> {
    real_accepted_fixture_for(status, "statechain", &"34".repeat(32))
}

pub(super) fn real_keypath_session_pair(server_nonce_seed: u8) -> Result<(String, String)> {
    let (mut wallet, record, _, _) = real_accepted_fixture(CoinStatus::CONFIRMED)?;
    let coin = wallet
        .coins
        .first_mut()
        .ok_or_else(|| anyhow!("real keypath session fixture Coin is missing"))?;
    let nonce = create_bip448_keypath_nonces(coin)?;
    coin.secret_nonce = Some(nonce.secret_nonce);
    coin.public_nonce = Some(nonce.public_nonce);
    coin.blinding_factor = Some(nonce.blinding_factor);

    let secp = Secp256k1::new();
    let server_secret = SecretKey::from_secret_bytes([7u8; 32])?;
    let server_keypair = KeyPair::from_secret_key(&secp, &server_secret);
    let (_, server_public_nonce) = new_musig_nonce_pair(
        &secp,
        MusigSessionId::assume_unique_per_nonce_gen([server_nonce_seed; 32]),
        None,
        Some(server_secret),
        server_keypair.public_key(),
        None,
        None,
    )?;
    coin.server_public_nonce = Some(hex::encode(server_public_nonce.serialize()));
    let destination = coin.backup_address.clone();
    let signing = build_bip448_withdrawal_signing_data(
        coin,
        bitcoin::OutPoint {
            txid: bitcoin::Txid::from_str(&record.funding_outpoint.txid)?,
            vout: record.funding_outpoint.vout,
        },
        record.funding_outpoint.value_sats,
        101,
        1.0,
        &destination,
        Network::Regtest,
    )?;
    let blinded_session = signing.partial_signature_request_payload.session;
    if signing.encoded_session == blinded_session {
        return Err(anyhow!(
            "real keypath session fixture lost the full/blinded distinction"
        ));
    }
    Ok((signing.encoded_session, blinded_session))
}

pub(super) fn real_fixture_aggregate_secret(
    wallet: &Wallet,
    record: &Bip448StatechainRecord,
) -> Result<SecretKey> {
    let coin = wallet
        .coins
        .iter()
        .find(|coin| {
            coin.statechain_id.as_deref() == Some(record.statechain_id.as_str())
                && coin.aggregated_pubkey.as_deref() == Some(record.aggregate_pubkey.as_str())
        })
        .ok_or_else(|| anyhow!("real fixture aggregate Coin is missing"))?;
    let user_secret = PrivateKey::from_wif(&coin.user_privkey)?.inner;
    let server_secret = SecretKey::from_secret_bytes([7u8; 32])?;
    let aggregate_secret =
        user_secret.add_tweak(&Scalar::from_be_bytes(server_secret.to_secret_bytes())?)?;
    if aggregate_secret.public_key(&Secp256k1::new()).to_string() != record.aggregate_pubkey {
        return Err(anyhow!(
            "real fixture aggregate secret does not match record"
        ));
    }
    Ok(aggregate_secret)
}

pub(super) fn real_fixture_state_for_owner(
    wallet: &Wallet,
    record: &Bip448StatechainRecord,
    owner: XOnlyPublicKey,
    state_number: u32,
    state_locktime: u32,
) -> Result<Bip448LatestState> {
    let secp = Secp256k1::new();
    let aggregate_pubkey = PublicKey::from_str(&record.aggregate_pubkey)?;
    let recovery_script = Address::p2tr(
        &secp,
        owner,
        None,
        mercurylib::utils::get_network(&record.network)?,
    )
    .script_pubkey();
    let artifacts = build_funding_recovery_artifacts(
        &secp,
        &aggregate_pubkey,
        OutPoint {
            txid: Txid::from_str(&record.funding_outpoint.txid)?,
            vout: record.funding_outpoint.vout,
        },
        record.funding_outpoint.value_sats,
        recovery_script,
        state_number,
        absolute::LockTime::from_consensus(state_locktime),
        record.challenge_delay,
        Bip448FeeBumpPolicy::ZeroFeeEphemeralAnchor,
    )?;
    let aggregate_secret = real_fixture_aggregate_secret(wallet, record)?;
    let aggregate_keypair = KeyPair::from_secret_key(&secp, &aggregate_secret);
    let update_signature = schnorr::sign(
        artifacts.update_template_hash.as_byte_array(),
        &aggregate_keypair,
    );
    let message: Message = artifacts.update_template_hash.into();
    let state_seed = u8::try_from(state_number)?;
    let client_nonce_key = SecretKey::from_secret_bytes([state_seed + 30; 32])?;
    let server_nonce_key = SecretKey::from_secret_bytes([state_seed + 40; 32])?;
    let (_, client_public_nonce) = new_musig_nonce_pair(
        &secp,
        MusigSessionId::assume_unique_per_nonce_gen([state_seed + 50; 32]),
        None,
        Some(client_nonce_key),
        client_nonce_key.public_key(&secp),
        Some(message),
        None,
    )?;
    let (_, server_public_nonce) = new_musig_nonce_pair(
        &secp,
        MusigSessionId::assume_unique_per_nonce_gen([state_seed + 60; 32]),
        None,
        Some(server_nonce_key),
        server_nonce_key.public_key(&secp),
        Some(message),
        None,
    )?;
    let blinding_factor = BlindingFactor::from_slice(&[state_seed + 70; 32])?;
    let signing_metadata = Bip448SigningMetadata {
        role: Bip448RecoveryTemplateRole::FundingUpdate,
        signing_id: hex::encode([state_seed + 80; 32]),
        client_public_nonce: hex::encode(client_public_nonce.serialize()),
        server_public_nonce: hex::encode(server_public_nonce.serialize()),
        blinding_factor: hex::encode(blinding_factor.as_bytes()),
        update_template_hash: hex::encode(artifacts.update_template_hash.to_byte_array()),
        update_signature: update_signature.to_string(),
        server_signature_count: u64::from(state_number),
    };
    Ok(build_funding_latest_state(
        &secp,
        &aggregate_pubkey,
        &artifacts,
        signing_metadata,
        Vec::new(),
    )?)
}

pub(super) async fn accepted_binding_fixture(
    pool: &Pool<Sqlite>,
) -> Result<(Bip448StatechainRecord, XOnlyPublicKey, String)> {
    let (wallet, record, entry, owner) = real_accepted_fixture(CoinStatus::CONFIRMED)?;
    insert_wallet(pool, &wallet).await?;
    persist_bip448_initial_acceptance(pool, &record, &entry).await?;
    let script = accepted_funding_script(&record)?;
    Ok((record, owner, script))
}

pub(super) fn sample_binding_observation(
    txid_byte: &str,
    vout: u32,
    value_sats: u64,
    script_pubkey: &str,
) -> Bip448BindingObservation {
    Bip448BindingObservation {
        txid: txid_byte.repeat(32),
        vout,
        value_sats,
        script_pubkey: script_pubkey.to_owned(),
        observation_status: Bip448ObservationStatus::Confirmed,
        funding_height: Some(10),
        spend_txid: None,
        spend_height: None,
        last_scanned_height: 20,
    }
}

pub(super) fn sample_duplicate_attempt(binding: &Bip448FundingBinding) -> Bip448WithdrawalAttempt {
    let signing_id = "71".repeat(32);
    let signed_statechain_id = "75".repeat(64);
    let sign_first_payload_json = serde_json::to_string(
        &mercurylib::bip448_statechain::signing_api::Bip448SignFirstRequestPayload {
            statechain_id: binding.statechain_id.clone(),
            signed_statechain_id: signed_statechain_id.clone(),
            signing_id: signing_id.clone(),
        },
    )
    .unwrap();
    let unsigned_transaction = bitcoin::Transaction {
        version: 2,
        lock_time: bitcoin::absolute::LockTime::from_height(42).unwrap(),
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint {
                txid: bitcoin::Txid::from_str(&binding.txid).unwrap(),
                vout: binding.vout,
            },
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence(0),
            witness: bitcoin::Witness::default(),
        }],
        output: vec![bitcoin::TxOut {
            value: binding.value_sats - 140,
            script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    Bip448WithdrawalAttempt {
        wallet_name: binding.wallet_name.clone(),
        statechain_id: binding.statechain_id.clone(),
        binding_index: binding.binding_index,
        attempt_kind: Bip448WithdrawalAttemptKind::Duplicate,
        owner_user_pubkey: binding.owner_user_pubkey.clone(),
        owner_state_number: binding.owner_state_number,
        source_txid: binding.txid.clone(),
        source_vout: binding.vout,
        source_value_sats: binding.value_sats,
        source_script_pubkey: binding.script_pubkey.clone(),
        destination_address: "destination".into(),
        destination_script_pubkey: "51".into(),
        fee_rate_sat_per_vbyte: 1.25,
        fee_sats: 140,
        lock_time: 42,
        unsigned_tx_hex: hex::encode(bitcoin::consensus::serialize(&unsigned_transaction)),
        signing_id,
        signed_statechain_id,
        sign_first_payload_json,
        client_secret_nonce: "72".repeat(132),
        client_public_nonce: "73".repeat(66),
        blinding_factor: "74".repeat(32),
        server_public_nonce: None,
        message_hex: None,
        output_pubkey: None,
        client_partial_sig: None,
        encoded_session: None,
        sign_second_payload_json: None,
        server_partial_sig: None,
        aggregate_signature: None,
        signed_tx_hex: None,
        txid: None,
        phase: Bip448WithdrawalPhase::Prepared,
        broadcast_status: Bip448BroadcastStatus::NotBroadcast,
        completion_status: Bip448CompletionStatus::NotApplicable,
        closing_tip_height: None,
        closing_tip_hash: None,
        closing_bindings_json: None,
        created_at: String::new(),
        updated_at: String::new(),
    }
}

pub(super) fn refresh_attempt_sign_first_payload(attempt: &mut Bip448WithdrawalAttempt) {
    attempt.sign_first_payload_json = serde_json::to_string(
        &mercurylib::bip448_statechain::signing_api::Bip448SignFirstRequestPayload {
            statechain_id: attempt.statechain_id.clone(),
            signed_statechain_id: attempt.signed_statechain_id.clone(),
            signing_id: attempt.signing_id.clone(),
        },
    )
    .unwrap();
}

pub(super) fn sample_transfer_intent(intent_id_byte: &str) -> Bip448TransferIntent {
    let (receiver, _) = sample_owner_key(2);
    let (auth, _) = sample_owner_key(3);
    Bip448TransferIntent {
        wallet_name: "wallet".into(),
        statechain_id: "statechain".into(),
        intent_id: intent_id_byte.repeat(32),
        predecessor_intent_id: None,
        activity_status: Bip448TransferIntentActivityStatus::Active,
        intent_kind: Bip448TransferIntentKind::UserTransfer,
        acknowledge_cooperative_duplicates: false,
        recipient_address: "recipient".into(),
        receiver_user_pubkey: receiver.to_string(),
        recipient_auth_pubkey: auth.to_string(),
        batch_id: None,
        sender_signed_statechain_id: "b1".repeat(64),
        planned_state_number: 2,
        expected_signature_count: 1,
        previous_locktime: 700_000_042,
        prior_pending_signing_id: None,
        prior_transfer_recipient_auth_pubkey: None,
        prior_transfer_msg_hash: None,
        reuse_pending: false,
        reuse_signed_state: false,
        clear_local_attempt: false,
        generated_coin_user_pubkey: None,
        generated_coin_auth_pubkey: None,
        generated_coin_address: None,
        phase: Bip448TransferIntentPhase::Prepared,
        server_x1: None,
        current_pending_signing_id: None,
        state_signing_phase: Bip448TransferStateSigningPhase::NotStarted,
        server_partial_sig: None,
        update_signature: None,
        created_at: String::new(),
        updated_at: String::new(),
    }
}

pub(super) async fn second_arm_duplicate_attempt(
    pool: &Pool<Sqlite>,
    binding: &Bip448FundingBinding,
) -> Result<Bip448WithdrawalAttempt> {
    let attempt = sample_duplicate_attempt(binding);
    let attempt = insert_bip448_withdrawal_attempt_if_absent(pool, &attempt).await?;
    arm_bip448_withdrawal_sign_first(
        pool,
        &attempt.wallet_name,
        &attempt.statechain_id,
        attempt.binding_index,
        &attempt.signing_id,
    )
    .await?;
    let server_public_nonce = "81".repeat(66);
    let (encoded_session, blinded_session) = real_keypath_session_pair(90)?;
    let sign_second_payload_json = serde_json::to_string(
        &mercurylib::bip448_statechain::signing_api::Bip448PartialSignatureRequestPayload {
            statechain_id: attempt.statechain_id.clone(),
            signed_statechain_id: attempt.signed_statechain_id.clone(),
            signing_id: attempt.signing_id.clone(),
            negate_seckey: 0,
            session: blinded_session,
            server_pub_nonce: server_public_nonce.clone(),
        },
    )?;
    store_bip448_withdrawal_nonce_artifacts(
        pool,
        &attempt.wallet_name,
        &attempt.statechain_id,
        attempt.binding_index,
        &attempt.signing_id,
        &server_public_nonce,
        &"82".repeat(32),
        &sample_owner_key(4).0.to_string(),
        &"84".repeat(32),
        &encoded_session,
        &sign_second_payload_json,
    )
    .await?;
    arm_bip448_withdrawal_sign_second(
        pool,
        &attempt.wallet_name,
        &attempt.statechain_id,
        attempt.binding_index,
        &attempt.signing_id,
    )
    .await
}

pub(super) async fn sign_duplicate_attempt(
    pool: &Pool<Sqlite>,
    binding: &Bip448FundingBinding,
) -> Result<Bip448WithdrawalAttempt> {
    let attempt = second_arm_duplicate_attempt(pool, binding).await?;
    let aggregate_signature = "92".repeat(64);
    let mut signed_transaction: bitcoin::Transaction =
        bitcoin::consensus::deserialize(&hex::decode(&attempt.unsigned_tx_hex)?)?;
    let mut keypath_witness = hex::decode(&aggregate_signature)?;
    keypath_witness.push(0x01);
    signed_transaction
        .input
        .get_mut(0)
        .ok_or_else(|| anyhow!("sample BIP448 withdrawal has no input"))?
        .witness
        .push(keypath_witness);
    store_bip448_withdrawal_signed_artifacts(
        pool,
        &attempt.wallet_name,
        &attempt.statechain_id,
        attempt.binding_index,
        &attempt.signing_id,
        &"91".repeat(32),
        &aggregate_signature,
        &hex::encode(bitcoin::consensus::serialize(&signed_transaction)),
        &signed_transaction.txid().to_string(),
        Bip448BroadcastStatus::NotBroadcast,
    )
    .await
}
