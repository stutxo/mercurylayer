use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use bitcoin::{BlockHash, Txid};
use mercurylib::wallet::Wallet;
use sqlx::{Pool, Row, Sqlite};

#[cfg(test)]
use bitcoin::hashes::{sha256, Hash};
#[cfg(test)]
use mercurylib::{
    bip448_statechain::storage::Bip448StatechainRecord, transfer::bip448::Bip448StateHistoryEntry,
};

#[cfg(test)]
use mercurylib::wallet::Coin;
#[cfg(test)]
use secp256k1::{PublicKey, XOnlyPublicKey};

#[cfg(test)]
use crate::bip448_funding::{
    self, Bip448BroadcastStatus, Bip448CloseBlockReason, Bip448CloseGate, Bip448CompletionStatus,
    Bip448FundingBinding, Bip448ObservationStatus, Bip448OwnershipStatus, Bip448TransferIntent,
    Bip448TransferIntentActivityStatus, Bip448TransferIntentKind, Bip448TransferIntentPhase,
    Bip448TransferStateSigningPhase, Bip448WithdrawalAttempt, Bip448WithdrawalAttemptKind,
    Bip448WithdrawalPhase,
};

mod bip448;

#[cfg(test)]
use self::bip448::{
    accepted_funding_script, accepted_record_and_history_on, clear_bip448_scan_state,
    insert_transfer_intent_on, intent_is_directly_supersedable, legal_broadcast_transition,
    upsert_bip448_statechain_record, Bip448BeginImmediateTestHook,
    BIP448_BEGIN_IMMEDIATE_TEST_HOOK,
};
pub use self::bip448::{
    arm_bip448_transfer_sender, arm_bip448_transfer_state_sign_second,
    arm_bip448_withdrawal_sign_first, arm_bip448_withdrawal_sign_second,
    begin_bip448_mutation_guard, begin_bip448_sync_base_guard, bip448_active_withdrawal_attempt,
    bip448_expected_signature_count, bip448_statechain_is_exit_only, capture_bip448_sync_base,
    classify_bip448_close_gate, cleanup_bip448_cancellation_after_acceptance,
    compare_and_set_wallet_after_bip448_scan, delete_bip448_cancellation_artifacts_after_sync,
    delete_bip448_pending_deposit_signing, delete_bip448_pending_transfer_signing,
    delete_bip448_transfer_msgs, delete_prepared_bip448_withdrawal_attempt_for_confirmed_spend,
    finish_bip448_cancellation_sender, finish_bip448_rotated_outgoing_transfer,
    finish_bip448_transfer_sender, finish_bip448_user_transfer_and_delete_intent,
    get_active_bip448_transfer_intent, get_bip448_funding_binding, get_bip448_package_attempt,
    get_bip448_pending_deposit_signing, get_bip448_pending_transfer_signing,
    get_bip448_state_history, get_bip448_statechain, get_bip448_statechain_optional,
    get_bip448_transfer_msg, get_bip448_transfer_msg_raw_optional, get_bip448_withdrawal_attempt,
    has_bip448_transfer_msg_for_statechain, insert_bip448_cancellation_intent_with_wallet,
    insert_bip448_pending_deposit_signing_if_absent,
    insert_bip448_pending_transfer_signing_if_absent, insert_bip448_state_history_entry,
    insert_bip448_transfer_intent_if_absent, insert_bip448_withdrawal_attempt_if_absent,
    insert_or_update_bip448_transfer_msg, install_bip448_transfer_target_pending,
    install_bip448_transfer_target_pending_signing, install_reused_signed_bip448_transfer_state,
    list_bip448_funding_bindings, list_bip448_transfer_intents, list_bip448_withdrawal_attempts,
    mark_bip448_cancellation_receiver_accepted, mark_bip448_funding_bindings_previous,
    materialize_bip448_signed_transfer_intent, persist_bip448_canonical_withdrawal_wallet,
    persist_bip448_initial_acceptance,
    reactivate_bip448_transfer_intent_predecessor_after_definitive_rejection,
    reassign_bip448_funding_bindings_owner, reconcile_bip448_accepted_local_outgoing_messages,
    reconcile_bip448_funding_bindings, reject_bip448_transfer_intent_and_reactivate_predecessor,
    set_bip448_package_attempt_status, store_bip448_transfer_intent_x1,
    store_bip448_transfer_server_x1, store_bip448_transfer_state_nonce,
    store_bip448_transfer_state_signed_artifacts, store_bip448_withdrawal_nonce_artifacts,
    store_bip448_withdrawal_nonce_session, store_bip448_withdrawal_signed_artifacts,
    store_signed_bip448_transfer_state, store_signed_bip448_withdrawal,
    supersede_bip448_transfer_intent, supersede_bip448_transfer_intent_with_cancellation_wallet,
    transition_bip448_transfer_intent_phase, transition_bip448_transfer_state_signing_phase,
    transition_bip448_withdrawal_broadcast_status, transition_bip448_withdrawal_completion_status,
    transition_bip448_withdrawal_phase, update_bip448_funding_binding_observation,
    update_bip448_pending_deposit_server_public_nonce,
    update_bip448_pending_transfer_server_public_nonce, update_bip448_withdrawal_broadcast_status,
    update_bip448_withdrawal_completion_status, validate_bip448_canonical_close_snapshot,
    Bip448FeeInputRecord, Bip448MutationGuard, Bip448PackageAttempt, Bip448PackageAttemptStatus,
    Bip448PendingDepositSigning, Bip448ScanCursor, BIP448_FEE_RESERVATION_TTL_SECONDS,
};
pub(crate) use self::bip448::{
    available_bip448_scanned_outpoints, bip448_reservation_id,
    ensure_no_orphaned_bip448_reservation, history_entry, insert_bip448_package_attempt,
    insert_or_update_bip448_statechain, insert_or_update_bip448_statechain_from_transfer,
    list_bip448_transfer_msg_raw_rows, load_bip448_scan_state, persist_bip448_scan_state,
    reacquire_bip448_package_attempt_reservations, recover_bip448_initial_acceptance_wallet,
    upsert_bip448_scanned_outpoint, with_bip448_canonical_completion_fence,
    Bip448InitialAcceptanceRecovery,
};
use self::bip448::{
    pending_transfer_on, require_materialized_signed_transfer_intent_on,
    transfer_message_matches_history_prefix, validate_bip448_successor_plan_on,
    validate_bip448_transfer_intent_lineage,
};

pub(crate) fn canonical_txid(txid: &str) -> Result<String> {
    Ok(Txid::from_str(txid).context("invalid txid")?.to_string())
}

fn canonical_wallet_json(wallet: &Wallet) -> Result<String> {
    let mut wallet = wallet.clone();
    for coin in &mut wallet.coins {
        for txid in [&mut coin.utxo_txid, &mut coin.tx_withdraw] {
            if let Some(txid) = txid {
                *txid = canonical_txid(txid)?;
            }
        }
    }
    Ok(serde_json::to_string(&wallet)?)
}

fn canonical_block_hash(block_hash: &str) -> Result<String> {
    Ok(BlockHash::from_str(block_hash)
        .context("invalid block hash")?
        .to_string())
}

pub async fn insert_wallet(pool: &Pool<Sqlite>, wallet: &Wallet) -> Result<()> {
    let wallet_json = canonical_wallet_json(wallet)?;

    let query = "INSERT INTO wallet (wallet_name, wallet_json) VALUES ($1, $2)";

    let _ = sqlx::query(query)
        .bind(wallet.name.clone())
        .bind(wallet_json)
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn get_wallet(pool: &Pool<Sqlite>, wallet_name: &str) -> Result<Wallet> {
    let query = "SELECT wallet_json FROM wallet WHERE wallet_name = $1";

    let row = sqlx::query(query).bind(wallet_name).fetch_one(pool).await?;

    if row.is_empty() {
        return Err(anyhow!("Wallet not found"));
    }

    let wallet_json: String = row.get(0);

    let wallet: Wallet = serde_json::from_str(&wallet_json)?;

    Ok(wallet)
}

pub(crate) async fn get_bip448_raw_wallet_json(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
) -> Result<String> {
    sqlx::query_scalar("SELECT wallet_json FROM wallet WHERE wallet_name = $1")
        .bind(wallet_name)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| anyhow!("BIP448 synchronization wallet is missing"))
}

pub async fn update_wallet(pool: &Pool<Sqlite>, wallet: &Wallet) -> Result<()> {
    let wallet_json = canonical_wallet_json(wallet)?;

    let query = "UPDATE wallet SET wallet_json = $1 WHERE wallet_name = $2";

    let _ = sqlx::query(query)
        .bind(wallet_json)
        .bind(wallet.name.clone())
        .execute(pool)
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bip448_funding::{Bip448BindingObservation, Bip448SyncBase},
        bip448_transfer_sender::transfer_bip448_sender,
        chain::{ChainClient, ChainUtxo, CoreRpcAuth, CoreRpcConfig},
        client_config::ClientConfig,
    };
    use bitcoin::{absolute, Address, Network, OutPoint, PrivateKey};
    use mercurylib::bip448_statechain::{
        deposit::{
            self as bip448_deposit, Bip448DepositSigningData, BIP448_COIN_PROTOCOL,
            DEFAULT_BIP448_CHALLENGE_DELAY,
        },
        storage::{
            build_funding_latest_state, build_funding_recovery_artifacts, Bip448AnchorOutput,
            Bip448CpfpChildTemplate, Bip448CsfsKeyMetadata, Bip448FeeBumpPolicy,
            Bip448FundingOutpoint, Bip448LatestState, Bip448RecoveryTemplateRole,
            Bip448SigningMetadata, Bip448ValueSchedule,
        },
        withdraw::{build_bip448_withdrawal_signing_data, create_bip448_keypath_nonces},
    };
    use mercurylib::transfer::bip448::Bip448TransferMsg;
    use mercurylib::wallet::{CoinStatus, Settings};
    use secp256k1::{
        musig::{new_musig_nonce_pair, BlindingFactor, MusigSessionId},
        schnorr, KeyPair, Message, Scalar, Secp256k1, SecretKey,
    };
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::{path::PathBuf, sync::Arc, time::Duration};

    async fn migrated_pool() -> Result<Pool<Sqlite>> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await?;

        sqlx::migrate!("./migrations").run(&pool).await?;

        Ok(pool)
    }

    struct IndependentTestPools {
        first: Pool<Sqlite>,
        second: Pool<Sqlite>,
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

    async fn independent_migrated_pools() -> Result<IndependentTestPools> {
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

    async fn assert_begin_is_contested(hook: &Arc<Bip448BeginImmediateTestHook>) -> Result<()> {
        hook.before_acquire.notified().await;
        if hook.after_emitted.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(anyhow!(
                "contested BEGIN IMMEDIATE acquired before the winner released"
            ));
        }
        Ok(())
    }

    fn spawn_sync_base_loser(
        pool: Pool<Sqlite>,
        base: Bip448SyncBase,
    ) -> (
        Arc<Bip448BeginImmediateTestHook>,
        tokio::task::JoinHandle<Result<Bip448MutationGuard>>,
    ) {
        let hook = Arc::new(Bip448BeginImmediateTestHook::default());
        let task_hook = hook.clone();
        let task = tokio::spawn(
            BIP448_BEGIN_IMMEDIATE_TEST_HOOK.scope(task_hook, async move {
                begin_bip448_sync_base_guard(&pool, &base).await
            }),
        );
        (hook, task)
    }

    async fn commit_winner_and_assert_sync_loser_loses(
        hook: Arc<Bip448BeginImmediateTestHook>,
        winner: Bip448MutationGuard,
        loser: tokio::task::JoinHandle<Result<Bip448MutationGuard>>,
    ) -> Result<()> {
        assert_begin_is_contested(&hook).await?;
        winner.commit().await?;
        hook.after_acquire.notified().await;
        if loser.await?.is_ok() {
            return Err(anyhow!(
                "stale BIP448 synchronization base passed after deterministic serialization"
            ));
        }
        Ok(())
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

    fn sample_latest_state(state_number: u32) -> Bip448LatestState {
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

    fn sample_cpfp_child_template() -> Bip448CpfpChildTemplate {
        Bip448CpfpChildTemplate {
            parent_role: Bip448RecoveryTemplateRole::StateUpdate,
            anchor_output_index: 1,
            tx_hex: "03000000".to_string(),
            fee_sats: 1_000,
            target_feerate_sat_per_vbyte: Some(10),
        }
    }

    fn sample_bip448_record(state_number: u32) -> Bip448StatechainRecord {
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

    fn sample_bip448_transfer_msg() -> Bip448TransferMsg {
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

    fn exact_transfer_message(
        record: &Bip448StatechainRecord,
        latest_state: Bip448LatestState,
        receiver_user_public_key: &str,
        history: Vec<Bip448StateHistoryEntry>,
    ) -> Bip448TransferMsg {
        let mut message = sample_bip448_transfer_msg();
        message.statechain_id = record.statechain_id.clone();
        message.receiver_user_public_key = receiver_user_public_key.to_owned();
        message.aggregate_pubkey = record.aggregate_pubkey.clone();
        message.funding_outpoint = record.funding_outpoint.clone();
        message.latest_state_number = latest_state.state_number;
        message.challenge_delay = record.challenge_delay;
        message.amount_sats = record.amount_sats;
        message.network = record.network.clone();
        message.value_schedule = latest_state.value_schedule.clone();
        message.server_signature_count = u64::from(latest_state.state_number);
        message.latest_state = latest_state;
        message.state_history = history;
        message
    }

    fn sample_owner_key(byte: u8) -> (secp256k1::PublicKey, XOnlyPublicKey) {
        let secret = secp256k1::SecretKey::from_secret_bytes([byte; 32]).unwrap();
        let public = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &secret);
        (public, public.x_only_public_key().0)
    }

    fn real_accepted_fixture_for(
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

    fn real_accepted_fixture(
        status: CoinStatus,
    ) -> Result<(
        Wallet,
        Bip448StatechainRecord,
        Bip448StateHistoryEntry,
        XOnlyPublicKey,
    )> {
        real_accepted_fixture_for(status, "statechain", &"34".repeat(32))
    }

    fn real_keypath_session_pair(server_nonce_seed: u8) -> Result<(String, String)> {
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

    fn mutate_session_byte(session: &str, byte_index: usize) -> Result<String> {
        let mut bytes = hex::decode(session)?;
        let byte = bytes
            .get_mut(byte_index)
            .ok_or_else(|| anyhow!("session mutation index is out of bounds"))?;
        *byte ^= 1;
        Ok(hex::encode(bytes))
    }

    fn sign_second_payload_for_attempt(
        attempt: &Bip448WithdrawalAttempt,
        server_public_nonce: &str,
        blinded_session: &str,
    ) -> Result<String> {
        Ok(serde_json::to_string(
            &mercurylib::bip448_statechain::signing_api::Bip448PartialSignatureRequestPayload {
                statechain_id: attempt.statechain_id.clone(),
                signed_statechain_id: attempt.signed_statechain_id.clone(),
                signing_id: attempt.signing_id.clone(),
                negate_seckey: 0,
                session: blinded_session.to_owned(),
                server_pub_nonce: server_public_nonce.to_owned(),
            },
        )?)
    }

    async fn raw_withdrawal_attempt_snapshot(
        pool: &Pool<Sqlite>,
        wallet_name: &str,
        statechain_id: &str,
        binding_index: u32,
    ) -> Result<String> {
        Ok(sqlx::query_scalar(
            "SELECT json_array(wallet_name,statechain_id,binding_index,attempt_kind,\
                owner_user_pubkey,owner_state_number,source_txid,source_vout,source_value_sats,\
                source_script_pubkey,destination_address,destination_script_pubkey,\
                fee_rate_sat_per_vbyte,fee_sats,lock_time,unsigned_tx_hex,signing_id,\
                signed_statechain_id,sign_first_payload_json,client_secret_nonce,\
                client_public_nonce,blinding_factor,server_public_nonce,message_hex,\
                output_pubkey,client_partial_sig,encoded_session,sign_second_payload_json,\
                server_partial_sig,aggregate_signature,signed_tx_hex,txid,phase,broadcast_status,\
                completion_status,closing_tip_height,closing_tip_hash,closing_bindings_json,\
                created_at,updated_at) FROM bip448_withdrawal_attempts \
             WHERE wallet_name=$1 AND statechain_id=$2 AND binding_index=$3",
        )
        .bind(wallet_name)
        .bind(statechain_id)
        .bind(i64::from(binding_index))
        .fetch_one(pool)
        .await?)
    }

    fn pre_materialized_initial_acceptance_fixture(
        retain_observed_outpoint: bool,
    ) -> Result<(
        Wallet,
        Bip448StatechainRecord,
        Bip448StateHistoryEntry,
        Bip448PendingDepositSigning,
    )> {
        let (mut wallet, record, entry, _) = real_accepted_fixture(CoinStatus::UNCONFIRMED)?;
        let coin = wallet
            .coins
            .first_mut()
            .ok_or_else(|| anyhow!("initial-acceptance fixture Coin is missing"))?;
        if retain_observed_outpoint {
            coin.status = CoinStatus::IN_MEMPOOL;
        } else {
            coin.utxo_txid = None;
            coin.utxo_vout = None;
            coin.status = CoinStatus::INITIALISED;
        }
        coin.locktime = None;
        coin.public_nonce = None;
        coin.server_public_nonce = None;
        coin.blinding_factor = None;
        wallet.activities.clear();
        let pending = Bip448PendingDepositSigning {
            wallet_name: record.wallet_name.clone(),
            statechain_id: record.statechain_id.clone(),
            funding_txid: record.funding_outpoint.txid.clone(),
            funding_vout: record.funding_outpoint.vout,
            funding_value_sats: record.funding_outpoint.value_sats,
            update_template_hash: entry.update_template_hash.clone(),
            settlement_template_hash: entry.settlement_template_hash.clone(),
            state_locktime: entry.state_locktime,
            signing_id: record.latest_state.signing_metadata.signing_id.clone(),
            client_secret_nonce: "ab".repeat(132),
            client_public_nonce: entry.client_public_nonce.clone(),
            blinding_factor: entry.blinding_factor.clone(),
            server_public_nonce: Some(entry.server_public_nonce.clone()),
        };
        Ok((wallet, record, entry, pending))
    }

    async fn install_pre_materialized_initial_acceptance(
        pool: &Pool<Sqlite>,
        retain_observed_outpoint: bool,
        retain_pending: bool,
    ) -> Result<(
        Bip448StatechainRecord,
        Bip448StateHistoryEntry,
        Bip448PendingDepositSigning,
        String,
    )> {
        let (wallet, record, entry, pending) =
            pre_materialized_initial_acceptance_fixture(retain_observed_outpoint)?;
        insert_wallet(pool, &wallet).await?;
        insert_bip448_pending_deposit_signing_if_absent(pool, &pending).await?;
        persist_bip448_initial_acceptance(pool, &record, &entry).await?;
        if !retain_pending {
            delete_bip448_pending_deposit_signing(
                pool,
                &pending.wallet_name,
                &pending.statechain_id,
                &pending.signing_id,
            )
            .await?;
        }
        let raw_wallet = get_bip448_raw_wallet_json(pool, &wallet.name).await?;
        Ok((record, entry, pending, raw_wallet))
    }

    fn real_fixture_aggregate_secret(
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

    fn real_fixture_state_for_owner(
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

    async fn accepted_binding_fixture(
        pool: &Pool<Sqlite>,
    ) -> Result<(Bip448StatechainRecord, XOnlyPublicKey, String)> {
        let (wallet, record, entry, owner) = real_accepted_fixture(CoinStatus::CONFIRMED)?;
        insert_wallet(pool, &wallet).await?;
        persist_bip448_initial_acceptance(pool, &record, &entry).await?;
        let script = accepted_funding_script(&record)?;
        Ok((record, owner, script))
    }

    fn set_valid_withdrawal_lifecycle(coin: &mut Coin, status: CoinStatus) -> Result<()> {
        let nonce = create_bip448_keypath_nonces(coin)?;
        coin.secret_nonce = Some(nonce.secret_nonce);
        coin.public_nonce = Some(nonce.public_nonce);
        coin.blinding_factor = Some(nonce.blinding_factor);
        let secp = Secp256k1::new();
        let server_nonce_key = SecretKey::from_secret_bytes([99u8; 32])?;
        let (_, server_public_nonce) = new_musig_nonce_pair(
            &secp,
            MusigSessionId::assume_unique_per_nonce_gen([98u8; 32]),
            None,
            Some(server_nonce_key),
            server_nonce_key.public_key(&secp),
            None,
            None,
        )?;
        coin.server_public_nonce = Some(hex::encode(server_public_nonce.serialize()));
        coin.tx_withdraw = Some("62".repeat(32));
        coin.withdrawal_address = Some(coin.backup_address.clone());
        coin.status = status;
        Ok(())
    }

    fn sample_binding_observation(
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

    fn sample_duplicate_attempt(binding: &Bip448FundingBinding) -> Bip448WithdrawalAttempt {
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

    async fn current_duplicate_attempt_fixture(
        pool: &Pool<Sqlite>,
        duplicate_txid_byte: &str,
    ) -> Result<(Bip448WithdrawalAttempt, String, String)> {
        let (_, owner, script) = accepted_binding_fixture(pool).await?;
        let binding = reconcile_bip448_funding_bindings(
            pool,
            "wallet",
            "statechain",
            &owner.to_string(),
            1,
            &[
                sample_binding_observation("34", 0, 100_000, &script),
                sample_binding_observation(duplicate_txid_byte, 1, 70_000, &script),
            ],
        )
        .await?
        .into_iter()
        .find(|row| row.binding_index == 1)
        .ok_or_else(|| anyhow!("duplicate fixture binding is missing"))?;
        let wallet = get_wallet(pool, "wallet").await?;
        let signed_statechain_id = wallet
            .coins
            .iter()
            .find(|coin| coin.statechain_id.as_deref() == Some("statechain"))
            .and_then(|coin| coin.signed_statechain_id.clone())
            .ok_or_else(|| anyhow!("duplicate fixture signed statechain ID is missing"))?;
        Ok((
            sample_duplicate_attempt(&binding),
            owner.to_string(),
            signed_statechain_id,
        ))
    }

    fn refresh_attempt_sign_first_payload(attempt: &mut Bip448WithdrawalAttempt) {
        attempt.sign_first_payload_json = serde_json::to_string(
            &mercurylib::bip448_statechain::signing_api::Bip448SignFirstRequestPayload {
                statechain_id: attempt.statechain_id.clone(),
                signed_statechain_id: attempt.signed_statechain_id.clone(),
                signing_id: attempt.signing_id.clone(),
            },
        )
        .unwrap();
    }

    fn sample_transfer_intent(intent_id_byte: &str) -> Bip448TransferIntent {
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

    fn transfer_intent_for_phase_pair(
        intent_id_byte: &str,
        phase: Bip448TransferIntentPhase,
        signing_phase: Bip448TransferStateSigningPhase,
        reuse_signed_state: bool,
    ) -> Result<Bip448TransferIntent> {
        let mut intent = sample_transfer_intent(intent_id_byte);
        intent.activity_status = Bip448TransferIntentActivityStatus::Superseded;
        intent.phase = phase;
        intent.server_x1 = (!matches!(
            phase,
            Bip448TransferIntentPhase::Prepared | Bip448TransferIntentPhase::SenderArmed
        ))
        .then(|| "01".repeat(32));
        intent.state_signing_phase = signing_phase;
        if reuse_signed_state {
            intent.reuse_pending = true;
            intent.reuse_signed_state = true;
            intent.prior_pending_signing_id = Some("31".repeat(32));
            intent.planned_state_number = intent.expected_signature_count;
        }
        match signing_phase {
            Bip448TransferStateSigningPhase::NotStarted => {}
            Bip448TransferStateSigningPhase::FirstArmed
            | Bip448TransferStateSigningPhase::NonceStored
            | Bip448TransferStateSigningPhase::SecondArmed => {
                intent.current_pending_signing_id = Some("32".repeat(32));
            }
            Bip448TransferStateSigningPhase::Signed => {
                intent.current_pending_signing_id = Some("32".repeat(32));
                intent.server_partial_sig = (!reuse_signed_state).then(|| "33".repeat(32));
                intent.update_signature = Some("34".repeat(64));
            }
        }
        if matches!(
            phase,
            Bip448TransferIntentPhase::SenderFinished | Bip448TransferIntentPhase::ReceiverAccepted
        ) {
            let generated = sample_wallet().get_new_coin()?;
            intent.intent_kind = Bip448TransferIntentKind::Cancellation;
            intent.recipient_address = generated.address.clone();
            intent.receiver_user_pubkey = generated.user_pubkey.clone();
            intent.recipient_auth_pubkey = generated.auth_pubkey.clone();
            intent.generated_coin_user_pubkey = Some(generated.user_pubkey);
            intent.generated_coin_auth_pubkey = Some(generated.auth_pubkey);
            intent.generated_coin_address = Some(generated.address);
        }
        Ok(intent)
    }

    fn sender_test_config(pool: Pool<Sqlite>) -> Result<ClientConfig> {
        let url = "http://127.0.0.1:1";
        Ok(ClientConfig {
            statechain_entity: url.into(),
            chain_backend: "core".into(),
            chain_client: ChainClient::new(CoreRpcConfig {
                url: url.into(),
                auth: CoreRpcAuth::None,
            })?,
            core_rpc_url: Some(url.into()),
            core_rpc_auth: Some("none".into()),
            core_rpc_user: None,
            core_rpc_password: None,
            core_rpc_cookie_file: None,
            network: Network::Regtest,
            fee_rate_tolerance: 0.0,
            confirmation_target: 1,
            pool,
            tor_proxy: None,
            max_fee_rate: 10.0,
        })
    }

    async fn accepted_local_outgoing_fixture() -> Result<(
        Pool<Sqlite>,
        Bip448StatechainRecord,
        String,
        Bip448TransferMsg,
    )> {
        let pool = migrated_pool().await?;
        let (mut record, _, _) = accepted_binding_fixture(&pool).await?;
        let mut wallet = get_wallet(&pool, "wallet").await?;
        let mut local_coin = wallet.get_new_coin()?;
        local_coin.statechain_protocol = Some("bip448".into());
        local_coin.statechain_id = Some("statechain".into());
        local_coin.status = CoinStatus::CONFIRMED;
        let recipient_auth = local_coin.auth_pubkey.clone();
        let receiver_user = local_coin.user_pubkey.clone();
        let receiver = secp256k1::PublicKey::from_str(&receiver_user)?;
        let state_two = real_fixture_state_for_owner(
            &wallet,
            &record,
            receiver.x_only_public_key().0,
            2,
            record.latest_state.state_locktime + 1,
        )?;
        wallet.coins.push(local_coin);
        update_wallet(&pool, &wallet).await?;

        record.latest_state_number = 2;
        record.latest_state = state_two.clone();
        upsert_bip448_statechain_record(&pool, &record).await?;
        let entry_two = history_entry(&state_two, receiver.x_only_public_key().0);
        insert_bip448_state_history_entry(&pool, "wallet", "statechain", &entry_two).await?;
        let history = get_bip448_state_history(&pool, "wallet", "statechain").await?;
        let message = exact_transfer_message(&record, state_two, &receiver_user, history);
        insert_or_update_bip448_transfer_msg(&pool, "wallet", &recipient_auth, &message).await?;
        Ok((pool, record, recipient_auth, message))
    }

    async fn second_arm_duplicate_attempt(
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

    async fn sign_duplicate_attempt(
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

    async fn ready_canonical_attempt_fixture(
        pool: &Pool<Sqlite>,
    ) -> Result<Bip448WithdrawalAttempt> {
        let (_, owner, script) = accepted_binding_fixture(pool).await?;
        let canonical = reconcile_bip448_funding_bindings(
            pool,
            "wallet",
            "statechain",
            &owner.to_string(),
            1,
            &[sample_binding_observation("34", 0, 100_000, &script)],
        )
        .await?
        .into_iter()
        .find(|binding| binding.binding_index == 0)
        .ok_or_else(|| anyhow!("canonical test binding is missing"))?;
        let close_tip_hash = "61".repeat(32);
        persist_bip448_scan_state(
            pool,
            "wallet",
            &script,
            &Bip448ScanCursor {
                coverage_start_height: 0,
                scan_revision: 0,
                last_scanned_height: 20,
                last_scanned_block_hash: close_tip_hash.clone(),
            },
            &[],
        )
        .await?;
        let closing_bindings_json =
            match classify_bip448_close_gate(pool, "wallet", "statechain").await? {
                Bip448CloseGate::Ready {
                    closing_bindings_json,
                    ..
                } => closing_bindings_json,
                blocked => return Err(anyhow!("unexpected canonical close blocker: {blocked:?}")),
            };
        let mut attempt = sample_duplicate_attempt(&canonical);
        attempt.attempt_kind = Bip448WithdrawalAttemptKind::Canonical;
        attempt.completion_status = Bip448CompletionStatus::Open;
        attempt.destination_address = get_wallet(pool, "wallet")
            .await?
            .coins
            .first()
            .ok_or_else(|| anyhow!("canonical destination fixture Coin is missing"))?
            .backup_address
            .clone();
        attempt.closing_tip_height = Some(20);
        attempt.closing_tip_hash = Some(close_tip_hash);
        attempt.closing_bindings_json = Some(closing_bindings_json);
        Ok(attempt)
    }

    async fn assert_corrupt_transfer_lineage_blocks(
        intents: &[Bip448TransferIntent],
        remove_active_index: bool,
    ) -> Result<()> {
        let pool = migrated_pool().await?;
        let (_, owner, script) = accepted_binding_fixture(&pool).await?;
        let duplicate = reconcile_bip448_funding_bindings(
            &pool,
            "wallet",
            "statechain",
            &owner.to_string(),
            1,
            &[
                sample_binding_observation("34", 0, 100_000, &script),
                sample_binding_observation("11", 1, 70_000, &script),
            ],
        )
        .await?
        .into_iter()
        .find(|row| row.binding_index == 1)
        .ok_or_else(|| anyhow!("duplicate fixture binding is missing"))?;
        if remove_active_index {
            sqlx::query("DROP INDEX bip448_one_active_transfer_intent")
                .execute(&pool)
                .await?;
        }
        let mut connection = pool.acquire().await?;
        for intent in intents {
            insert_transfer_intent_on(&mut connection, intent).await?;
        }
        drop(connection);

        assert!(
            get_active_bip448_transfer_intent(&pool, "wallet", "statechain")
                .await
                .is_err(),
            "corrupt intent lineage must fail the active-intent query"
        );
        assert!(matches!(
            classify_bip448_close_gate(&pool, "wallet", "statechain").await?,
            Bip448CloseGate::Blocked { reasons }
                if matches!(reasons.as_slice(), [Bip448CloseBlockReason::InvalidTransferIntentLineage { .. }])
        ));
        assert!(
            insert_bip448_withdrawal_attempt_if_absent(
                &pool,
                &sample_duplicate_attempt(&duplicate)
            )
            .await
            .is_err(),
            "corrupt intent lineage must block attempt insertion"
        );
        assert!(
            list_bip448_withdrawal_attempts(&pool, "wallet", "statechain")
                .await?
                .is_empty()
        );
        Ok(())
    }

    async fn assert_sender_ineligible(config: &ClientConfig) {
        let error = transfer_bip448_sender(config, "unused", "wallet", "statechain", None)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "only transfer of a CONFIRMED BIP448 coin at its accepted latest state is supported"
        );
    }
    #[tokio::test]
    async fn bip448_sender_exercises_record_coin_state_and_status_guards() -> Result<()> {
        let config = sender_test_config(migrated_pool().await?)?;
        let mut wallet = sample_wallet();
        insert_wallet(&config.pool, &wallet).await?;
        assert_sender_ineligible(&config).await;
        upsert_bip448_statechain_record(&config.pool, &sample_bip448_record(1)).await?;
        assert_sender_ineligible(&config).await;
        let mut coin = wallet.get_new_coin()?;
        coin.statechain_protocol =
            Some(mercurylib::bip448_statechain::deposit::BIP448_COIN_PROTOCOL.into());
        coin.statechain_id = Some("statechain".into());
        coin.status = CoinStatus::TRANSFERRED;
        wallet.coins.push(coin);
        update_wallet(&config.pool, &wallet).await?;
        assert_sender_ineligible(&config).await;
        wallet.coins[0].status = CoinStatus::CONFIRMED;
        let config = sender_test_config(migrated_pool().await?)?;
        insert_wallet(&config.pool, &wallet).await?;
        upsert_bip448_statechain_record(&config.pool, &sample_bip448_record(0)).await?;
        assert_sender_ineligible(&config).await;
        Ok(())
    }
    #[tokio::test]
    async fn current_migrations_are_idempotent_and_preserve_bip448_wallet_state() -> Result<()> {
        let pool = migrated_pool().await?;
        let record = sample_bip448_record(1);
        let mut wallet = sample_wallet();
        let mut coin = wallet.get_new_coin()?;
        coin.statechain_protocol =
            Some(mercurylib::bip448_statechain::deposit::BIP448_COIN_PROTOCOL.into());
        coin.statechain_id = Some(record.statechain_id.clone());
        coin.aggregated_pubkey = Some(record.aggregate_pubkey.clone());
        coin.utxo_txid = Some(record.funding_outpoint.txid.clone());
        coin.utxo_vout = Some(record.funding_outpoint.vout);
        coin.amount = Some(u32::try_from(record.amount_sats)?);
        coin.locktime = Some(record.latest_state.state_locktime);
        coin.status = CoinStatus::CONFIRMED;
        wallet.coins.push(coin);
        insert_wallet(&pool, &wallet).await?;
        upsert_bip448_statechain_record(&pool, &record).await?;

        sqlx::migrate!("./migrations").run(&pool).await?;

        let roundtrip_wallet = get_wallet(&pool, &wallet.name).await?;
        let roundtrip_record =
            get_bip448_statechain(&pool, &wallet.name, &record.statechain_id).await?;
        assert_eq!(
            roundtrip_wallet.coins[0].statechain_protocol.as_deref(),
            Some(mercurylib::bip448_statechain::deposit::BIP448_COIN_PROTOCOL)
        );
        assert_eq!(
            roundtrip_wallet.coins[0].statechain_id,
            Some("statechain".into())
        );
        assert_eq!(roundtrip_record, record);

        Ok(())
    }

    #[tokio::test]
    async fn fresh_bip448_client_schema_has_exact_application_tables() -> Result<()> {
        let pool = migrated_pool().await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        let tables = sqlx::query_scalar::<_, String>(
            "SELECT name FROM sqlite_schema \
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%' \
               AND name <> '_sqlx_migrations' \
             ORDER BY name",
        )
        .fetch_all(&pool)
        .await?;
        assert_eq!(
            tables,
            vec![
                "bip448_funding_bindings",
                "bip448_package_attempts",
                "bip448_pending_deposit_signings",
                "bip448_pending_transfer_signings",
                "bip448_scan_cursors",
                "bip448_scanned_outpoints",
                "bip448_state_history",
                "bip448_statechains",
                "bip448_transfer_intents",
                "bip448_transfer_messages",
                "bip448_withdrawal_attempts",
                "wallet",
            ]
        );

        let expected_columns = [
            (
                "bip448_scan_cursors",
                vec![
                    "wallet_name",
                    "script_pubkey",
                    "coverage_start_height",
                    "scan_revision",
                    "last_scanned_height",
                    "last_scanned_block_hash",
                    "updated_at",
                ],
            ),
            (
                "bip448_funding_bindings",
                vec![
                    "wallet_name",
                    "statechain_id",
                    "binding_index",
                    "txid",
                    "vout",
                    "value_sats",
                    "script_pubkey",
                    "role",
                    "observation_status",
                    "funding_height",
                    "spend_txid",
                    "spend_height",
                    "last_scanned_height",
                    "owner_user_pubkey",
                    "owner_state_number",
                    "ownership_status",
                    "first_seen_at",
                    "last_seen_at",
                ],
            ),
            (
                "bip448_withdrawal_attempts",
                vec![
                    "wallet_name",
                    "statechain_id",
                    "binding_index",
                    "attempt_kind",
                    "owner_user_pubkey",
                    "owner_state_number",
                    "source_txid",
                    "source_vout",
                    "source_value_sats",
                    "source_script_pubkey",
                    "destination_address",
                    "destination_script_pubkey",
                    "fee_rate_sat_per_vbyte",
                    "fee_sats",
                    "lock_time",
                    "unsigned_tx_hex",
                    "signing_id",
                    "signed_statechain_id",
                    "sign_first_payload_json",
                    "client_secret_nonce",
                    "client_public_nonce",
                    "blinding_factor",
                    "server_public_nonce",
                    "message_hex",
                    "output_pubkey",
                    "client_partial_sig",
                    "encoded_session",
                    "sign_second_payload_json",
                    "server_partial_sig",
                    "aggregate_signature",
                    "signed_tx_hex",
                    "txid",
                    "phase",
                    "broadcast_status",
                    "completion_status",
                    "closing_tip_height",
                    "closing_tip_hash",
                    "closing_bindings_json",
                    "created_at",
                    "updated_at",
                ],
            ),
            (
                "bip448_transfer_intents",
                vec![
                    "wallet_name",
                    "statechain_id",
                    "intent_id",
                    "predecessor_intent_id",
                    "activity_status",
                    "intent_kind",
                    "acknowledge_cooperative_duplicates",
                    "recipient_address",
                    "receiver_user_pubkey",
                    "recipient_auth_pubkey",
                    "batch_id",
                    "sender_signed_statechain_id",
                    "planned_state_number",
                    "expected_signature_count",
                    "previous_locktime",
                    "prior_pending_signing_id",
                    "prior_transfer_recipient_auth_pubkey",
                    "prior_transfer_msg_hash",
                    "reuse_pending",
                    "reuse_signed_state",
                    "clear_local_attempt",
                    "generated_coin_user_pubkey",
                    "generated_coin_auth_pubkey",
                    "generated_coin_address",
                    "phase",
                    "server_x1",
                    "current_pending_signing_id",
                    "state_signing_phase",
                    "server_partial_sig",
                    "update_signature",
                    "created_at",
                    "updated_at",
                ],
            ),
        ];
        for (table, names) in expected_columns {
            let pragma = format!("PRAGMA table_info('{table}')");
            let metadata: Vec<(i64, String, String, i64, Option<String>, i64)> =
                sqlx::query_as(&pragma).fetch_all(&pool).await?;
            assert_eq!(metadata.len(), names.len(), "{table} column count");
            for (offset, (cid, name, ty, not_null, default_value, pk)) in
                metadata.iter().enumerate()
            {
                assert_eq!(*cid, i64::try_from(offset)?);
                assert_eq!(name, names[offset], "{table} column {offset}");
                let expected_type = if name == "fee_rate_sat_per_vbyte" {
                    "REAL"
                } else if [
                    "wallet_name",
                    "script_pubkey",
                    "last_scanned_block_hash",
                    "statechain_id",
                    "txid",
                    "role",
                    "observation_status",
                    "spend_txid",
                    "owner_user_pubkey",
                    "ownership_status",
                    "attempt_kind",
                    "source_txid",
                    "source_script_pubkey",
                    "destination_address",
                    "destination_script_pubkey",
                    "unsigned_tx_hex",
                    "signing_id",
                    "signed_statechain_id",
                    "sign_first_payload_json",
                    "client_secret_nonce",
                    "client_public_nonce",
                    "blinding_factor",
                    "server_public_nonce",
                    "message_hex",
                    "output_pubkey",
                    "client_partial_sig",
                    "encoded_session",
                    "sign_second_payload_json",
                    "server_partial_sig",
                    "aggregate_signature",
                    "signed_tx_hex",
                    "phase",
                    "broadcast_status",
                    "completion_status",
                    "closing_tip_hash",
                    "closing_bindings_json",
                    "intent_id",
                    "predecessor_intent_id",
                    "activity_status",
                    "intent_kind",
                    "recipient_address",
                    "receiver_user_pubkey",
                    "recipient_auth_pubkey",
                    "batch_id",
                    "sender_signed_statechain_id",
                    "prior_pending_signing_id",
                    "prior_transfer_recipient_auth_pubkey",
                    "prior_transfer_msg_hash",
                    "generated_coin_user_pubkey",
                    "generated_coin_auth_pubkey",
                    "generated_coin_address",
                    "server_x1",
                    "current_pending_signing_id",
                    "update_signature",
                    "state_signing_phase",
                    "created_at",
                    "updated_at",
                    "first_seen_at",
                    "last_seen_at",
                ]
                .contains(&name.as_str())
                {
                    "TEXT"
                } else {
                    "INTEGER"
                };
                assert_eq!(ty, expected_type, "{table}.{name} type");
                let nullable_columns: &[&str] = match table {
                    "bip448_scan_cursors" => &[],
                    "bip448_funding_bindings" => &["funding_height", "spend_txid", "spend_height"],
                    "bip448_withdrawal_attempts" => &[
                        "server_public_nonce",
                        "message_hex",
                        "output_pubkey",
                        "client_partial_sig",
                        "encoded_session",
                        "sign_second_payload_json",
                        "server_partial_sig",
                        "aggregate_signature",
                        "signed_tx_hex",
                        "txid",
                        "closing_tip_height",
                        "closing_tip_hash",
                        "closing_bindings_json",
                    ],
                    "bip448_transfer_intents" => &[
                        "predecessor_intent_id",
                        "batch_id",
                        "prior_pending_signing_id",
                        "prior_transfer_recipient_auth_pubkey",
                        "prior_transfer_msg_hash",
                        "generated_coin_user_pubkey",
                        "generated_coin_auth_pubkey",
                        "generated_coin_address",
                        "server_x1",
                        "current_pending_signing_id",
                        "server_partial_sig",
                        "update_signature",
                    ],
                    _ => unreachable!(),
                };
                let nullable = nullable_columns.contains(&name.as_str());
                assert_eq!(
                    *not_null,
                    i64::from(!nullable),
                    "{table}.{name} nullability"
                );
                let expected_default =
                    if ["created_at", "updated_at", "first_seen_at", "last_seen_at"]
                        .contains(&name.as_str())
                    {
                        Some("CURRENT_TIMESTAMP")
                    } else {
                        None
                    };
                assert_eq!(
                    default_value.as_deref(),
                    expected_default,
                    "{table}.{name} default"
                );
                let expected_pk = match (table, name.as_str()) {
                    ("bip448_scan_cursors", "wallet_name")
                    | ("bip448_funding_bindings", "wallet_name")
                    | ("bip448_withdrawal_attempts", "wallet_name")
                    | ("bip448_transfer_intents", "wallet_name") => 1,
                    ("bip448_scan_cursors", "script_pubkey")
                    | ("bip448_funding_bindings", "statechain_id")
                    | ("bip448_withdrawal_attempts", "statechain_id")
                    | ("bip448_transfer_intents", "statechain_id") => 2,
                    ("bip448_funding_bindings", "binding_index")
                    | ("bip448_withdrawal_attempts", "binding_index")
                    | ("bip448_transfer_intents", "intent_id") => 3,
                    _ => 0,
                };
                assert_eq!(*pk, expected_pk, "{table}.{name} PK ordinal");
            }
        }

        let indexes: Vec<(String,String)> = sqlx::query_as("SELECT name,sql FROM sqlite_schema \
            WHERE type='index' AND name IN ('bip448_one_canonical_binding',\
            'bip448_one_active_withdrawal_signing','bip448_one_active_transfer_intent') ORDER BY name")
            .fetch_all(&pool).await?;
        assert_eq!(indexes.len(), 3);
        assert_eq!(indexes[0].0, "bip448_one_active_transfer_intent");
        assert!(indexes[0].1.contains("WHERE activity_status = 'Active'"));
        assert_eq!(indexes[1].0, "bip448_one_active_withdrawal_signing");
        assert!(indexes[1].1.contains("WHERE phase <> 'Signed'"));
        assert_eq!(indexes[2].0, "bip448_one_canonical_binding");
        assert!(indexes[2].1.contains("WHERE role = 'Canonical'"));
        for table in &tables {
            let pragma = format!("PRAGMA foreign_key_list('{table}')");
            let foreign_keys = sqlx::query(&pragma).fetch_all(&pool).await?;
            assert!(foreign_keys.is_empty(), "{table} introduced a foreign key");
        }
        let migration_sql = include_str!("../migrations/0001_bip448_client_schema.sql");
        let normalized_migration = migration_sql
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        for fragment in [
            "binding_index BETWEEN 0 AND 4294967295",
            "length(txid) = 64",
            "vout BETWEEN 0 AND 4294967295",
            "value_sats BETWEEN 0 AND 2100000000000000",
            "role IN ('Canonical', 'Duplicate')",
            "'Mempool', 'Unconfirmed', 'Confirmed', 'SpentMempool', 'SpentUnconfirmed', 'SpentConfirmed', 'Absent'",
            "owner_state_number BETWEEN 1 AND 4294967295",
            "ownership_status IN ('Current', 'Previous')",
            "binding_index = 0 AND role = 'Canonical'",
            "observation_status = 'SpentMempool' AND spend_txid IS NOT NULL AND spend_height IS NULL",
            "observation_status = 'Mempool' AND funding_height IS NULL",
            "attempt_kind IN ('Duplicate', 'Canonical')",
            "fee_rate_sat_per_vbyte > 0",
            "lock_time BETWEEN 0 AND 499999999",
            "'Prepared', 'FirstArmed', 'NonceStored', 'SecondArmed', 'Signed'",
            "'NotBroadcast', 'Accepted', 'Confirmed', 'NeedsRebroadcast', 'Conflicting', 'Conflicted'",
            "'NotApplicable', 'Open', 'CloseArmed', 'Closed'",
            "binding_index = 0 AND attempt_kind = 'Canonical'",
            "phase IN ('Prepared', 'FirstArmed') OR",
            "phase <> 'Signed' OR",
            "phase = 'Signed' OR broadcast_status = 'NotBroadcast'",
            "completion_status <> 'CloseArmed' OR",
            "completion_status <> 'Closed' OR",
            "predecessor_intent_id <> intent_id",
            "activity_status IN ('Active', 'Superseded')",
            "intent_kind IN ('UserTransfer', 'Cancellation')",
            "acknowledge_cooperative_duplicates IN (0, 1)",
            "planned_state_number BETWEEN 1 AND 4294967295",
            "expected_signature_count BETWEEN 1 AND 4294967295",
            "previous_locktime BETWEEN 500000000 AND 4294967294",
            "reuse_pending IN (0, 1)",
            "reuse_signed_state IN (0, 1)",
            "clear_local_attempt IN (0, 1)",
            "'Prepared', 'SenderArmed', 'X1Stored', 'SenderFinished', 'ReceiverAccepted'",
            "'NotStarted', 'FirstArmed', 'NonceStored', 'SecondArmed', 'Signed'",
            "intent_kind = 'UserTransfer' AND generated_coin_user_pubkey IS NULL",
            "phase IN ('Prepared', 'SenderArmed') AND server_x1 IS NULL",
            "prior_transfer_recipient_auth_pubkey IS NULL AND prior_transfer_msg_hash IS NULL",
            "reuse_pending = 0 OR prior_pending_signing_id IS NOT NULL",
            "reuse_signed_state = 0 OR reuse_pending = 1",
            "planned_state_number = expected_signature_count + 1",
            "reuse_pending = 0 OR clear_local_attempt = 0",
            "intent_kind = 'UserTransfer' OR batch_id IS NULL",
            "intent_kind = 'Cancellation' OR phase IN ('Prepared', 'SenderArmed', 'X1Stored')",
            "state_signing_phase = 'NotStarted' AND current_pending_signing_id IS NULL",
        ] {
            assert!(
                normalized_migration.contains(fragment),
                "missing named CHECK fragment: {fragment}"
            );
        }
        let uppercase = normalized_migration.to_ascii_uppercase();
        for forbidden in [" ALTER ", " TRIGGER ", " CREATE VIEW ", " BACKUP "] {
            assert!(
                !uppercase.contains(forbidden),
                "forbidden schema object: {forbidden}"
            );
        }

        let pending_deposit_columns: Vec<(i64, String, String, i64, Option<String>, i64)> =
            sqlx::query_as("PRAGMA table_info('bip448_pending_deposit_signings')")
                .fetch_all(&pool)
                .await?;
        assert_eq!(
            pending_deposit_columns,
            vec![
                (0, "wallet_name".into(), "TEXT".into(), 1, None, 1),
                (1, "statechain_id".into(), "TEXT".into(), 1, None, 2),
                (2, "update_template_hash".into(), "TEXT".into(), 1, None, 0),
                (3, "signing_id".into(), "TEXT".into(), 1, None, 0),
                (4, "client_secret_nonce".into(), "TEXT".into(), 1, None, 0),
                (5, "client_public_nonce".into(), "TEXT".into(), 1, None, 0),
                (6, "blinding_factor".into(), "TEXT".into(), 1, None, 0),
                (7, "server_public_nonce".into(), "TEXT".into(), 0, None, 0),
                (8, "state_locktime".into(), "INTEGER".into(), 0, None, 0),
                (9, "funding_txid".into(), "TEXT".into(), 0, None, 0),
                (10, "funding_vout".into(), "INTEGER".into(), 0, None, 0),
                (
                    11,
                    "funding_value_sats".into(),
                    "INTEGER".into(),
                    0,
                    None,
                    0
                ),
                (
                    12,
                    "settlement_template_hash".into(),
                    "TEXT".into(),
                    0,
                    None,
                    0
                ),
                (
                    13,
                    "created_at".into(),
                    "TEXT".into(),
                    1,
                    Some("CURRENT_TIMESTAMP".into()),
                    0
                ),
                (
                    14,
                    "updated_at".into(),
                    "TEXT".into(),
                    1,
                    Some("CURRENT_TIMESTAMP".into()),
                    0
                ),
            ]
        );

        let backup_txs_exists = sqlx::query_scalar::<_, i64>(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema \
             WHERE type = 'table' AND name = 'backup_txs')",
        )
        .fetch_one(&pool)
        .await?;
        assert_eq!(backup_txs_exists, 0);

        Ok(())
    }

    #[tokio::test]
    async fn bip448_transfer_outer_and_signing_phase_cross_product_is_exact() -> Result<()> {
        let pool = migrated_pool().await?;
        let outer_phases = [
            Bip448TransferIntentPhase::Prepared,
            Bip448TransferIntentPhase::SenderArmed,
            Bip448TransferIntentPhase::X1Stored,
            Bip448TransferIntentPhase::SenderFinished,
            Bip448TransferIntentPhase::ReceiverAccepted,
        ];
        let signing_phases = [
            Bip448TransferStateSigningPhase::NotStarted,
            Bip448TransferStateSigningPhase::FirstArmed,
            Bip448TransferStateSigningPhase::NonceStored,
            Bip448TransferStateSigningPhase::SecondArmed,
            Bip448TransferStateSigningPhase::Signed,
        ];
        let mut case_number = 1u8;
        for outer in outer_phases {
            for signing in signing_phases {
                let legal = matches!(
                    (outer, signing),
                    (
                        Bip448TransferIntentPhase::Prepared
                            | Bip448TransferIntentPhase::SenderArmed,
                        Bip448TransferStateSigningPhase::NotStarted,
                    ) | (
                        Bip448TransferIntentPhase::X1Stored,
                        Bip448TransferStateSigningPhase::NotStarted
                            | Bip448TransferStateSigningPhase::FirstArmed
                            | Bip448TransferStateSigningPhase::NonceStored
                            | Bip448TransferStateSigningPhase::SecondArmed
                            | Bip448TransferStateSigningPhase::Signed,
                    ) | (
                        Bip448TransferIntentPhase::SenderFinished
                            | Bip448TransferIntentPhase::ReceiverAccepted,
                        Bip448TransferStateSigningPhase::Signed,
                    )
                );
                let id = format!("{case_number:02x}");
                case_number = case_number
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("BIP448 transfer matrix case number overflow"))?;
                let intent = transfer_intent_for_phase_pair(&id, outer, signing, false)?;
                assert_eq!(
                    bip448_funding::validate_transfer_intent(&intent).is_ok(),
                    legal,
                    "domain matrix mismatch for {outer:?} × {signing:?}"
                );
                let mut connection = pool.acquire().await?;
                let inserted = insert_transfer_intent_on(&mut connection, &intent).await;
                assert_eq!(
                    inserted.is_ok(),
                    legal,
                    "SQL matrix mismatch for {outer:?} × {signing:?}"
                );
            }
        }

        let mut invalid_reuse = transfer_intent_for_phase_pair(
            "e1",
            Bip448TransferIntentPhase::X1Stored,
            Bip448TransferStateSigningPhase::FirstArmed,
            true,
        )?;
        let mut signed_without_partial = transfer_intent_for_phase_pair(
            "e2",
            Bip448TransferIntentPhase::X1Stored,
            Bip448TransferStateSigningPhase::Signed,
            false,
        )?;
        signed_without_partial.server_partial_sig = None;
        let mut reused_with_partial = transfer_intent_for_phase_pair(
            "e3",
            Bip448TransferIntentPhase::X1Stored,
            Bip448TransferStateSigningPhase::Signed,
            true,
        )?;
        reused_with_partial.server_partial_sig = Some("35".repeat(32));
        let mut unstarted_with_artifact = transfer_intent_for_phase_pair(
            "e4",
            Bip448TransferIntentPhase::Prepared,
            Bip448TransferStateSigningPhase::NotStarted,
            false,
        )?;
        unstarted_with_artifact.current_pending_signing_id = Some("36".repeat(32));
        let mut active_with_result = transfer_intent_for_phase_pair(
            "e5",
            Bip448TransferIntentPhase::X1Stored,
            Bip448TransferStateSigningPhase::NonceStored,
            false,
        )?;
        active_with_result.update_signature = Some("37".repeat(64));
        for invalid in [
            &mut invalid_reuse,
            &mut signed_without_partial,
            &mut reused_with_partial,
            &mut unstarted_with_artifact,
            &mut active_with_result,
        ] {
            assert!(bip448_funding::validate_transfer_intent(invalid).is_err());
            let mut connection = pool.acquire().await?;
            assert!(insert_transfer_intent_on(&mut connection, invalid)
                .await
                .is_err());
        }

        let corrupt_pool = migrated_pool().await?;
        let corrupt = transfer_intent_for_phase_pair(
            "f1",
            Bip448TransferIntentPhase::Prepared,
            Bip448TransferStateSigningPhase::FirstArmed,
            false,
        )?;
        let mut connection = corrupt_pool.acquire().await?;
        sqlx::query("PRAGMA ignore_check_constraints = ON")
            .execute(&mut *connection)
            .await?;
        insert_transfer_intent_on(&mut connection, &corrupt).await?;
        sqlx::query("PRAGMA ignore_check_constraints = OFF")
            .execute(&mut *connection)
            .await?;
        drop(connection);
        assert!(
            list_bip448_transfer_intents(&corrupt_pool, "wallet", "statechain")
                .await
                .is_err()
        );
        assert!(
            reject_bip448_transfer_intent_and_reactivate_predecessor(&corrupt_pool, &corrupt,)
                .await
                .is_err()
        );
        assert!(
            reactivate_bip448_transfer_intent_predecessor_after_definitive_rejection(
                &corrupt_pool,
                &corrupt,
            )
            .await
            .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn bip448_sender_fails_before_signing_when_history_is_incomplete() -> Result<()> {
        let config = sender_test_config(migrated_pool().await?)?;
        let mut wallet = sample_wallet();
        let mut coin = wallet.get_new_coin()?;
        coin.statechain_protocol =
            Some(mercurylib::bip448_statechain::deposit::BIP448_COIN_PROTOCOL.into());
        coin.statechain_id = Some("statechain".into());
        coin.status = CoinStatus::CONFIRMED;
        wallet.coins.push(coin);
        let recipient_address = wallet.get_new_coin()?.address;
        insert_wallet(&config.pool, &wallet).await?;
        let record = sample_bip448_record(2);
        upsert_bip448_statechain_record(&config.pool, &record).await?;

        let error =
            transfer_bip448_sender(&config, &recipient_address, "wallet", "statechain", None)
                .await
                .unwrap_err();
        assert_eq!(
            error.to_string(),
            "BIP448 state history is incomplete for this coin"
        );
        assert!(
            get_bip448_pending_transfer_signing(&config.pool, "wallet", "statechain")
                .await?
                .is_none()
        );
        assert_eq!(
            get_bip448_statechain(&config.pool, "wallet", "statechain")
                .await?
                .latest_state
                .signing_metadata
                .server_signature_count,
            2
        );
        Ok(())
    }

    #[tokio::test]
    async fn wallet_and_accepted_record_persistence_canonicalize_txids() -> Result<()> {
        let pool = migrated_pool().await?;
        let mut wallet = sample_wallet();
        let mut coin = wallet.get_new_coin()?;
        coin.utxo_txid = Some("AA".repeat(32));
        coin.utxo_vout = Some(1);
        coin.tx_withdraw = Some("CC".repeat(32));
        wallet.coins.push(coin);
        insert_wallet(&pool, &wallet).await?;
        let stored_coin = get_wallet(&pool, &wallet.name).await?.coins.remove(0);
        assert_eq!(stored_coin.utxo_txid, Some("aa".repeat(32)));
        assert_eq!(stored_coin.tx_withdraw, Some("cc".repeat(32)));
        wallet.coins[0].utxo_txid = Some("not-a-txid".into());
        assert!(update_wallet(&pool, &wallet).await.is_err());
        wallet.coins[0].utxo_txid = Some("aa".repeat(32));
        wallet.coins[0].tx_withdraw = Some("not-a-txid".into());
        assert!(update_wallet(&pool, &wallet).await.is_err());

        let mut record = sample_bip448_record(1);
        record.funding_outpoint.txid = "AA".repeat(32);
        upsert_bip448_statechain_record(&pool, &record).await?;
        assert_eq!(
            get_bip448_statechain(&pool, &record.wallet_name, &record.statechain_id)
                .await?
                .funding_outpoint
                .txid,
            "aa".repeat(32)
        );
        Ok(())
    }

    #[tokio::test]
    async fn bip448_scan_state_round_trips_canonical_txids_and_clears_only_cache() -> Result<()> {
        let pool = migrated_pool().await?;
        let cursor = Bip448ScanCursor {
            coverage_start_height: 7,
            scan_revision: 0,
            last_scanned_height: 42,
            last_scanned_block_hash: "22".repeat(32),
        };
        persist_bip448_scan_state(
            &pool,
            "wallet",
            "51",
            &cursor,
            &[ChainUtxo {
                txid: "AA".repeat(32),
                vout: 1,
                value: 50_000,
                height: 40,
            }],
        )
        .await?;

        let (stored_cursor, outpoints) = load_bip448_scan_state(&pool, "wallet", "51").await?;
        assert_eq!(
            stored_cursor,
            Some(Bip448ScanCursor {
                scan_revision: 1,
                ..cursor.clone()
            })
        );
        assert_eq!(outpoints[0].txid, "aa".repeat(32));

        clear_bip448_scan_state(&pool, "wallet", "51").await?;
        assert_eq!(
            load_bip448_scan_state(&pool, "wallet", "51").await?,
            (
                Some(Bip448ScanCursor {
                    scan_revision: 1,
                    ..cursor
                }),
                Vec::new()
            )
        );
        Ok(())
    }

    #[tokio::test]
    async fn package_attempt_reserves_expires_releases_and_fails_closed() -> Result<()> {
        let pool = migrated_pool().await?;
        let fee = ChainUtxo {
            txid: "aa".repeat(32),
            vout: 1,
            value: 50_000,
            height: 2,
        };
        upsert_bip448_scanned_outpoint(&pool, "wallet", "51", &fee).await?;
        let attempt = Bip448PackageAttempt {
            wallet_name: "wallet".into(),
            statechain_id: "statechain".into(),
            role: "funding_update".into(),
            parent_txid: "bb".repeat(32),
            child_txid: "cc".repeat(32),
            child_tx_hex: "deadbeef".into(),
            fee_inputs: vec![Bip448FeeInputRecord {
                txid: fee.txid.clone(),
                vout: fee.vout,
                value_sats: fee.value,
            }],
            target_feerate_sat_per_vbyte: 2.0,
            status: Bip448PackageAttemptStatus::Pending,
        };
        insert_bip448_package_attempt(&pool, &attempt).await?;
        assert_eq!(
            get_bip448_package_attempt(&pool, "wallet", "statechain", "funding_update")
                .await?
                .unwrap(),
            attempt
        );
        assert!(
            available_bip448_scanned_outpoints(&pool, "wallet", "51", "other")
                .await?
                .is_empty()
        );
        sqlx::query("UPDATE bip448_scanned_outpoints SET reserved_at = unixepoch() - $1")
            .bind(BIP448_FEE_RESERVATION_TTL_SECONDS + 1)
            .execute(&pool)
            .await?;
        assert_eq!(
            available_bip448_scanned_outpoints(&pool, "wallet", "51", "other")
                .await?
                .len(),
            1
        );
        set_bip448_package_attempt_status(
            &pool,
            "wallet",
            "statechain",
            "funding_update",
            Bip448PackageAttemptStatus::Abandoned,
        )
        .await?;
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM bip448_scanned_outpoints WHERE reserved_by IS NOT NULL"
            )
            .fetch_one(&pool)
            .await?,
            0
        );
        sqlx::query("UPDATE bip448_package_attempts SET fee_inputs_json = '{'")
            .execute(&pool)
            .await?;
        assert!(
            get_bip448_package_attempt(&pool, "wallet", "statechain", "funding_update")
                .await
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn scan_reset_clears_all_and_rediscovery_restores_only_active_valid_reservations(
    ) -> Result<()> {
        let pool = migrated_pool().await?;
        let fee = ChainUtxo {
            txid: "aa".repeat(32),
            vout: 1,
            value: 50_000,
            height: 2,
        };
        let mut cursor = Bip448ScanCursor {
            coverage_start_height: 0,
            scan_revision: 0,
            last_scanned_height: 3,
            last_scanned_block_hash: "11".repeat(32),
        };
        persist_bip448_scan_state(&pool, "wallet", "51", &cursor, &[fee.clone()]).await?;
        cursor.scan_revision = 1;
        let attempt = Bip448PackageAttempt {
            wallet_name: "wallet".into(),
            statechain_id: "statechain".into(),
            role: "funding_update".into(),
            parent_txid: "bb".repeat(32),
            child_txid: "cc".repeat(32),
            child_tx_hex: "deadbeef".into(),
            fee_inputs: vec![Bip448FeeInputRecord {
                txid: fee.txid.clone(),
                vout: fee.vout,
                value_sats: fee.value,
            }],
            target_feerate_sat_per_vbyte: 2.0,
            status: Bip448PackageAttemptStatus::Pending,
        };
        insert_bip448_package_attempt(&pool, &attempt).await?;

        clear_bip448_scan_state(&pool, "wallet", "51").await?;
        assert_eq!(
            load_bip448_scan_state(&pool, "wallet", "51").await?,
            (Some(cursor.clone()), Vec::new())
        );
        persist_bip448_scan_state(&pool, "wallet", "51", &cursor, &[fee.clone()]).await?;
        cursor.scan_revision = 2;
        assert_eq!(
            load_bip448_scan_state(&pool, "wallet", "51").await?.1,
            vec![fee.clone()]
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT reserved_by FROM bip448_scanned_outpoints \
                 WHERE wallet_name = 'wallet' AND txid = $1 AND vout = 1",
            )
            .bind(&fee.txid)
            .fetch_one(&pool)
            .await?,
            bip448_reservation_id("statechain", "funding_update")
        );
        persist_bip448_scan_state(&pool, "wallet", "51", &cursor, &[]).await?;
        cursor.scan_revision = 3;
        assert!(load_bip448_scan_state(&pool, "wallet", "51")
            .await?
            .1
            .is_empty());

        set_bip448_package_attempt_status(
            &pool,
            "wallet",
            "statechain",
            "funding_update",
            Bip448PackageAttemptStatus::Abandoned,
        )
        .await?;
        clear_bip448_scan_state(&pool, "wallet", "51").await?;
        assert!(load_bip448_scan_state(&pool, "wallet", "51")
            .await?
            .1
            .is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn orphaned_same_operation_reservation_rejects_a_rebuilt_attempt() -> Result<()> {
        let pool = migrated_pool().await?;
        let fee = ChainUtxo {
            txid: "aa".repeat(32),
            vout: 1,
            value: 50_000,
            height: 2,
        };
        upsert_bip448_scanned_outpoint(&pool, "wallet", "51", &fee).await?;
        let attempt = Bip448PackageAttempt {
            wallet_name: "wallet".into(),
            statechain_id: "statechain".into(),
            role: "funding_update".into(),
            parent_txid: "bb".repeat(32),
            child_txid: "cc".repeat(32),
            child_tx_hex: "deadbeef".into(),
            fee_inputs: vec![Bip448FeeInputRecord {
                txid: fee.txid,
                vout: fee.vout,
                value_sats: fee.value,
            }],
            target_feerate_sat_per_vbyte: 2.0,
            status: Bip448PackageAttemptStatus::Pending,
        };
        insert_bip448_package_attempt(&pool, &attempt).await?;
        sqlx::query(
            "DELETE FROM bip448_package_attempts \
             WHERE wallet_name = 'wallet' AND statechain_id = 'statechain'",
        )
        .execute(&pool)
        .await?;
        sqlx::query("UPDATE bip448_scanned_outpoints SET reserved_at = unixepoch() - $1")
            .bind(BIP448_FEE_RESERVATION_TTL_SECONDS + 1)
            .execute(&pool)
            .await?;

        assert!(ensure_no_orphaned_bip448_reservation(
            &pool,
            "wallet",
            "statechain",
            "funding_update",
        )
        .await
        .is_err());
        assert!(available_bip448_scanned_outpoints(
            &pool,
            "wallet",
            "51",
            &bip448_reservation_id("statechain", "funding_update"),
        )
        .await?
        .is_empty());
        assert!(insert_bip448_package_attempt(&pool, &attempt)
            .await
            .is_err());
        assert!(
            get_bip448_package_attempt(&pool, "wallet", "statechain", "funding_update",)
                .await?
                .is_none()
        );
        Ok(())
    }

    #[tokio::test]
    async fn replay_reacquires_expired_reservations_or_fails_after_reclaim() -> Result<()> {
        let pool = migrated_pool().await?;
        let fee = ChainUtxo {
            txid: "aa".repeat(32),
            vout: 1,
            value: 50_000,
            height: 2,
        };
        upsert_bip448_scanned_outpoint(&pool, "wallet", "51", &fee).await?;
        let attempt = Bip448PackageAttempt {
            wallet_name: "wallet".into(),
            statechain_id: "statechain-a".into(),
            role: "funding_update".into(),
            parent_txid: "bb".repeat(32),
            child_txid: "cc".repeat(32),
            child_tx_hex: "deadbeef".into(),
            fee_inputs: vec![Bip448FeeInputRecord {
                txid: fee.txid.clone(),
                vout: fee.vout,
                value_sats: fee.value,
            }],
            target_feerate_sat_per_vbyte: 2.0,
            status: Bip448PackageAttemptStatus::Pending,
        };
        insert_bip448_package_attempt(&pool, &attempt).await?;
        sqlx::query("UPDATE bip448_scanned_outpoints SET reserved_at = unixepoch() - $1")
            .bind(BIP448_FEE_RESERVATION_TTL_SECONDS + 1)
            .execute(&pool)
            .await?;
        reacquire_bip448_package_attempt_reservations(&pool, &attempt).await?;
        assert!(
            available_bip448_scanned_outpoints(&pool, "wallet", "51", "other")
                .await?
                .is_empty()
        );

        sqlx::query("UPDATE bip448_scanned_outpoints SET reserved_at = unixepoch() - $1")
            .bind(BIP448_FEE_RESERVATION_TTL_SECONDS + 1)
            .execute(&pool)
            .await?;
        let mut reclaimed = attempt.clone();
        reclaimed.statechain_id = "statechain-b".into();
        reclaimed.parent_txid = "dd".repeat(32);
        reclaimed.child_txid = "ee".repeat(32);
        insert_bip448_package_attempt(&pool, &reclaimed).await?;
        assert!(
            reacquire_bip448_package_attempt_reservations(&pool, &attempt)
                .await
                .is_err()
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT reserved_by FROM bip448_scanned_outpoints \
                 WHERE wallet_name = 'wallet' AND txid = $1 AND vout = 1",
            )
            .bind(&fee.txid)
            .fetch_one(&pool)
            .await?,
            bip448_reservation_id(&reclaimed.statechain_id, &reclaimed.role)
        );
        Ok(())
    }

    #[tokio::test]
    async fn bip448_latest_state_allows_single_step_transitions_and_exact_replay() -> Result<()> {
        let pool = migrated_pool().await?;
        let state_one = sample_bip448_record(1);
        let state_two = sample_bip448_record(2);
        let state_three = sample_bip448_record(3);

        upsert_bip448_statechain_record(&pool, &state_one).await?;
        let roundtrip =
            get_bip448_statechain(&pool, &state_one.wallet_name, &state_one.statechain_id).await?;
        assert_eq!(roundtrip, state_one);

        upsert_bip448_statechain_record(&pool, &state_two).await?;
        let roundtrip =
            get_bip448_statechain(&pool, &state_two.wallet_name, &state_two.statechain_id).await?;
        assert_eq!(roundtrip, state_two);

        upsert_bip448_statechain_record(&pool, &state_three).await?;
        let roundtrip =
            get_bip448_statechain(&pool, &state_three.wallet_name, &state_three.statechain_id)
                .await?;
        assert_eq!(roundtrip, state_three);

        upsert_bip448_statechain_record(&pool, &state_three).await?;

        Ok(())
    }

    #[tokio::test]
    async fn bip448_latest_state_rejects_immutable_identity_changes() -> Result<()> {
        let pool = migrated_pool().await?;
        let state_one = sample_bip448_record(1);
        upsert_bip448_statechain_record(&pool, &state_one).await?;

        let mut aggregate_pubkey = sample_bip448_record(2);
        aggregate_pubkey.aggregate_pubkey = "03".to_string() + &"12".repeat(32);
        let mut funding_outpoint = sample_bip448_record(2);
        funding_outpoint.funding_outpoint.vout = 1;
        let mut amount_sats = sample_bip448_record(2);
        amount_sats.amount_sats += 1;
        let mut network = sample_bip448_record(2);
        network.network = "bitcoin".to_string();
        let mut challenge_delay = sample_bip448_record(2);
        challenge_delay.challenge_delay += 1;

        for conflicting in [
            aggregate_pubkey,
            funding_outpoint,
            amount_sats,
            network,
            challenge_delay,
        ] {
            let error = upsert_bip448_statechain_record(&pool, &conflicting)
                .await
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "BIP448 accepted state immutable identity mismatch"
            );
        }
        let persisted =
            get_bip448_statechain(&pool, &state_one.wallet_name, &state_one.statechain_id).await?;
        assert_eq!(persisted, state_one);

        Ok(())
    }

    #[tokio::test]
    async fn bip448_latest_state_rejects_rollback_skip_and_divergent_same_state() -> Result<()> {
        let pool = migrated_pool().await?;
        let state_one = sample_bip448_record(1);
        let state_two = sample_bip448_record(2);
        let state_three = sample_bip448_record(3);
        upsert_bip448_statechain_record(&pool, &state_one).await?;
        upsert_bip448_statechain_record(&pool, &state_two).await?;
        upsert_bip448_statechain_record(&pool, &state_three).await?;

        let mut divergent_state_three = state_three.clone();
        divergent_state_three.latest_state.update_tx = "04000000".to_string();
        for rejected in [state_two, divergent_state_three] {
            let error = upsert_bip448_statechain_record(&pool, &rejected)
                .await
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "BIP448 accepted state must be an exact replay or a monotonic single-step transition"
            );
        }
        let persisted =
            get_bip448_statechain(&pool, &state_three.wallet_name, &state_three.statechain_id)
                .await?;
        assert_eq!(persisted, state_three);

        let skip_pool = migrated_pool().await?;
        upsert_bip448_statechain_record(&skip_pool, &state_one).await?;
        let error = upsert_bip448_statechain_record(&skip_pool, &state_three)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "BIP448 accepted state must be an exact replay or a monotonic single-step transition"
        );

        Ok(())
    }

    #[tokio::test]
    async fn bip448_accepted_state_rejects_unverified_cpfp_children() -> Result<()> {
        let pool = migrated_pool().await?;
        let mut rejected_insert = sample_bip448_record(1);
        rejected_insert
            .latest_state
            .cpfp_child_templates
            .push(sample_cpfp_child_template());

        let error = upsert_bip448_statechain_record(&pool, &rejected_insert)
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("cannot contain unverified CPFP child templates"));
        assert!(get_bip448_statechain_optional(
            &pool,
            &rejected_insert.wallet_name,
            &rejected_insert.statechain_id,
        )
        .await?
        .is_none());

        let accepted = sample_bip448_record(1);
        upsert_bip448_statechain_record(&pool, &accepted).await?;
        let mut rejected_update = sample_bip448_record(2);
        rejected_update
            .latest_state
            .cpfp_child_templates
            .push(sample_cpfp_child_template());

        let error = upsert_bip448_statechain_record(&pool, &rejected_update)
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("cannot contain unverified CPFP child templates"));
        let persisted =
            get_bip448_statechain(&pool, &accepted.wallet_name, &accepted.statechain_id).await?;
        assert_eq!(persisted, accepted);

        Ok(())
    }

    #[tokio::test]
    async fn bip448_transfer_messages_round_trip_through_sqlite() -> Result<()> {
        let pool = migrated_pool().await?;
        let transfer_msg = sample_bip448_transfer_msg();
        let recipient_auth_pubkey = "02".to_string() + &"99".repeat(32);

        insert_or_update_bip448_transfer_msg(
            &pool,
            "wallet",
            &recipient_auth_pubkey,
            &transfer_msg,
        )
        .await?;
        let roundtrip = get_bip448_transfer_msg(
            &pool,
            "wallet",
            &transfer_msg.statechain_id,
            &recipient_auth_pubkey,
        )
        .await?;

        assert_eq!(roundtrip, transfer_msg);
        assert_eq!(roundtrip.latest_state.anchors[0].script_pubkey, "51024e73");
        assert_eq!(roundtrip.latest_state.cpfp_child_templates.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn bip448_pending_deposit_signing_round_trips_and_is_deleted() -> Result<()> {
        let pool = migrated_pool().await?;
        let mut pending = Bip448PendingDepositSigning {
            wallet_name: "wallet".to_string(),
            statechain_id: "statechain".to_string(),
            funding_txid: "aa".repeat(32),
            funding_vout: 1,
            funding_value_sats: 100_000,
            update_template_hash: "11".repeat(32),
            settlement_template_hash: "12".repeat(32),
            state_locktime: 700_000_042,
            signing_id: "22".repeat(32),
            client_secret_nonce: "33".repeat(132),
            client_public_nonce: "44".repeat(66),
            blinding_factor: "55".repeat(32),
            server_public_nonce: None,
        };

        let inserted = insert_bip448_pending_deposit_signing_if_absent(&pool, &pending).await?;
        assert_eq!(inserted, pending);
        let roundtrip =
            get_bip448_pending_deposit_signing(&pool, &pending.wallet_name, &pending.statechain_id)
                .await?
                .expect("pending signing exists");
        assert_eq!(roundtrip, pending);

        pending.server_public_nonce = Some("66".repeat(66));
        update_bip448_pending_deposit_server_public_nonce(
            &pool,
            &pending.wallet_name,
            &pending.statechain_id,
            &pending.signing_id,
            pending.server_public_nonce.as_ref().unwrap(),
        )
        .await?;
        let with_server_nonce =
            get_bip448_pending_deposit_signing(&pool, &pending.wallet_name, &pending.statechain_id)
                .await?
                .expect("pending signing exists");
        assert_eq!(with_server_nonce, pending);

        delete_bip448_pending_deposit_signing(
            &pool,
            &pending.wallet_name,
            &pending.statechain_id,
            &pending.signing_id,
        )
        .await?;
        assert!(get_bip448_pending_deposit_signing(
            &pool,
            &pending.wallet_name,
            &pending.statechain_id,
        )
        .await?
        .is_none());
        pending.state_locktime = 1_000_000_001;
        pending.server_public_nonce = None;
        let error = insert_bip448_pending_transfer_signing_if_absent(&pool, &pending)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("coin's latest state"));
        let accepted = sample_bip448_record(3);
        pending.funding_txid = accepted.funding_outpoint.txid.clone();
        pending.funding_vout = accepted.funding_outpoint.vout;
        pending.funding_value_sats = accepted.funding_outpoint.value_sats;
        upsert_bip448_statechain_record(&pool, &accepted).await?;
        let persisted = insert_bip448_pending_transfer_signing_if_absent(&pool, &pending).await?;
        assert_eq!(persisted.state_locktime, 1_000_000_001);

        Ok(())
    }

    #[tokio::test]
    async fn pending_insert_if_absent_keeps_one_locktime_and_template_identity() -> Result<()> {
        let pool = migrated_pool().await?;
        let first = Bip448PendingDepositSigning {
            wallet_name: "wallet".to_string(),
            statechain_id: "statechain".to_string(),
            funding_txid: "aa".repeat(32),
            funding_vout: 1,
            funding_value_sats: 100_000,
            update_template_hash: "11".repeat(32),
            settlement_template_hash: "12".repeat(32),
            state_locktime: 600_000_001,
            signing_id: "22".repeat(32),
            client_secret_nonce: "33".repeat(132),
            client_public_nonce: "44".repeat(66),
            blinding_factor: "55".repeat(32),
            server_public_nonce: None,
        };
        let mut competing = first.clone();
        competing.update_template_hash = "aa".repeat(32);
        competing.settlement_template_hash = "ab".repeat(32);
        competing.state_locktime = 900_000_001;
        competing.signing_id = "bb".repeat(32);
        competing.client_secret_nonce = "cc".repeat(132);

        let (first_result, competing_result) = tokio::join!(
            insert_bip448_pending_deposit_signing_if_absent(&pool, &first),
            insert_bip448_pending_deposit_signing_if_absent(&pool, &competing),
        );
        let first_result = first_result?;
        let competing_result = competing_result?;

        assert_eq!(first_result, competing_result);
        assert!(first_result == first || first_result == competing);
        assert_eq!(
            get_bip448_pending_deposit_signing(&pool, "wallet", "statechain")
                .await?
                .unwrap(),
            first_result
        );

        Ok(())
    }

    #[tokio::test]
    async fn pending_row_without_randomized_locktime_fails_closed() -> Result<()> {
        let pool = migrated_pool().await?;
        sqlx::query(
            "INSERT INTO bip448_pending_deposit_signings (\
                wallet_name, statechain_id, update_template_hash, signing_id, \
                client_secret_nonce, client_public_nonce, blinding_factor\
             ) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind("wallet")
        .bind("pre-phase-7-1")
        .bind("11".repeat(32))
        .bind("22".repeat(32))
        .bind("33".repeat(132))
        .bind("44".repeat(66))
        .bind("55".repeat(32))
        .execute(&pool)
        .await?;

        let error = get_bip448_pending_deposit_signing(&pool, "wallet", "pre-phase-7-1")
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("predates randomized locktime support"));

        Ok(())
    }

    #[tokio::test]
    async fn accepted_record_without_explicit_locktime_is_not_silently_upgraded() -> Result<()> {
        let pool = migrated_pool().await?;
        let record = sample_bip448_record(1);
        upsert_bip448_statechain_record(&pool, &record).await?;

        let mut old_json = serde_json::to_value(&record)?;
        old_json["latest_state"]
            .as_object_mut()
            .unwrap()
            .remove("state_locktime");
        sqlx::query(
            "UPDATE bip448_statechains SET record_json = $1 \
             WHERE wallet_name = $2 AND statechain_id = $3",
        )
        .bind(serde_json::to_string(&old_json)?)
        .bind(&record.wallet_name)
        .bind(&record.statechain_id)
        .execute(&pool)
        .await?;

        let error = get_bip448_statechain(&pool, &record.wallet_name, &record.statechain_id)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("state_locktime"));

        Ok(())
    }

    #[tokio::test]
    async fn bip448_initial_acceptance_is_atomic_exact_replay_or_full_rollback() -> Result<()> {
        let pool = migrated_pool().await?;
        let (wallet, record, entry, _) = real_accepted_fixture(CoinStatus::UNCONFIRMED)?;
        insert_wallet(&pool, &wallet).await?;
        persist_bip448_initial_acceptance(&pool, &record, &entry).await?;
        persist_bip448_initial_acceptance(&pool, &record, &entry).await?;
        assert_eq!(
            get_bip448_statechain(&pool, "wallet", "statechain").await?,
            record
        );
        assert_eq!(
            get_bip448_state_history(&pool, "wallet", "statechain").await?,
            vec![entry.clone()]
        );

        let fault_pool = migrated_pool().await?;
        insert_wallet(&fault_pool, &wallet).await?;
        let mut conflicting = entry.clone();
        conflicting.update_signature = "cc".repeat(64);
        sqlx::query("INSERT INTO bip448_state_history (wallet_name,statechain_id,state_number,entry_json) VALUES ($1,$2,1,$3)")
            .bind("wallet").bind("statechain").bind(serde_json::to_string(&conflicting)?)
            .execute(&fault_pool).await?;
        assert!(
            persist_bip448_initial_acceptance(&fault_pool, &record, &entry)
                .await
                .is_err()
        );
        assert!(
            get_bip448_statechain_optional(&fault_pool, "wallet", "statechain")
                .await?
                .is_none()
        );
        assert_eq!(
            get_bip448_state_history(&fault_pool, "wallet", "statechain").await?,
            vec![conflicting]
        );

        let record_only_pool = migrated_pool().await?;
        insert_wallet(&record_only_pool, &wallet).await?;
        upsert_bip448_statechain_record(&record_only_pool, &record).await?;
        assert!(
            persist_bip448_initial_acceptance(&record_only_pool, &record, &entry)
                .await
                .is_err()
        );
        assert_eq!(
            get_bip448_statechain(&record_only_pool, "wallet", "statechain").await?,
            record
        );
        assert!(
            get_bip448_state_history(&record_only_pool, "wallet", "statechain")
                .await?
                .is_empty()
        );

        let record_conflict_pool = migrated_pool().await?;
        insert_wallet(&record_conflict_pool, &wallet).await?;
        let mut other_record = record.clone();
        other_record.network = "signet".into();
        upsert_bip448_statechain_record(&record_conflict_pool, &other_record).await?;
        assert!(
            persist_bip448_initial_acceptance(&record_conflict_pool, &record, &entry)
                .await
                .is_err()
        );
        assert_eq!(
            get_bip448_statechain(&record_conflict_pool, "wallet", "statechain").await?,
            other_record
        );
        assert!(
            get_bip448_state_history(&record_conflict_pool, "wallet", "statechain")
                .await?
                .is_empty()
        );

        let write_fault_pool = migrated_pool().await?;
        insert_wallet(&write_fault_pool, &wallet).await?;
        sqlx::query(
            "INSERT INTO bip448_state_history \
             (wallet_name,statechain_id,state_number,entry_json) VALUES ('other','other',1,$1)",
        )
        .bind(serde_json::to_string(&entry)?)
        .execute(&write_fault_pool)
        .await?;
        sqlx::query(
            "CREATE UNIQUE INDEX test_bip448_history_fault ON bip448_state_history(entry_json)",
        )
        .execute(&write_fault_pool)
        .await?;
        assert!(
            persist_bip448_initial_acceptance(&write_fault_pool, &record, &entry)
                .await
                .is_err()
        );
        assert!(
            get_bip448_statechain_optional(&write_fault_pool, "wallet", "statechain")
                .await?
                .is_none()
        );
        assert!(
            get_bip448_state_history(&write_fault_pool, "wallet", "statechain")
                .await?
                .is_empty()
        );

        let pre_acceptance_pool = migrated_pool().await?;
        let mut pre_acceptance_wallet = wallet.clone();
        let pre_acceptance_coin = pre_acceptance_wallet
            .coins
            .first_mut()
            .ok_or_else(|| anyhow!("acceptance fixture Coin is missing"))?;
        pre_acceptance_coin.utxo_txid = None;
        pre_acceptance_coin.utxo_vout = None;
        pre_acceptance_coin.locktime = None;
        pre_acceptance_coin.public_nonce = None;
        pre_acceptance_coin.server_public_nonce = None;
        pre_acceptance_coin.blinding_factor = None;
        pre_acceptance_coin.status = CoinStatus::INITIALISED;
        insert_wallet(&pre_acceptance_pool, &pre_acceptance_wallet).await?;
        let pending = Bip448PendingDepositSigning {
            wallet_name: record.wallet_name.clone(),
            statechain_id: record.statechain_id.clone(),
            funding_txid: record.funding_outpoint.txid.clone(),
            funding_vout: record.funding_outpoint.vout,
            funding_value_sats: record.funding_outpoint.value_sats,
            update_template_hash: entry.update_template_hash.clone(),
            settlement_template_hash: entry.settlement_template_hash.clone(),
            state_locktime: entry.state_locktime,
            signing_id: record.latest_state.signing_metadata.signing_id.clone(),
            client_secret_nonce: "ab".repeat(132),
            client_public_nonce: entry.client_public_nonce.clone(),
            blinding_factor: entry.blinding_factor.clone(),
            server_public_nonce: Some(entry.server_public_nonce.clone()),
        };
        insert_bip448_pending_deposit_signing_if_absent(&pre_acceptance_pool, &pending).await?;
        persist_bip448_initial_acceptance(&pre_acceptance_pool, &record, &entry).await?;
        assert_eq!(
            get_bip448_statechain(&pre_acceptance_pool, "wallet", "statechain").await?,
            record
        );

        let missing_pending_pool = migrated_pool().await?;
        insert_wallet(&missing_pending_pool, &pre_acceptance_wallet).await?;
        assert!(
            persist_bip448_initial_acceptance(&missing_pending_pool, &record, &entry)
                .await
                .is_err()
        );
        assert!(
            get_bip448_statechain_optional(&missing_pending_pool, "wallet", "statechain")
                .await?
                .is_none()
        );
        Ok(())
    }

    async fn accepted_table_bytes(pool: &Pool<Sqlite>) -> Result<(Vec<String>, Vec<String>)> {
        let records = sqlx::query_scalar::<_, String>(
            "SELECT record_json FROM bip448_statechains ORDER BY wallet_name, statechain_id",
        )
        .fetch_all(pool)
        .await?;
        let history = sqlx::query_scalar::<_, String>(
            "SELECT entry_json FROM bip448_state_history \
             ORDER BY wallet_name, statechain_id, state_number",
        )
        .fetch_all(pool)
        .await?;
        Ok((records, history))
    }

    async fn initial_acceptance_recovery_storage(
        pool: &Pool<Sqlite>,
    ) -> Result<(String, Vec<String>, Vec<String>, Vec<String>)> {
        let wallet = get_bip448_raw_wallet_json(pool, "wallet").await?;
        let records = sqlx::query_scalar::<_, String>(
            "SELECT json_array(wallet_name,statechain_id,aggregate_pubkey,funding_txid,\
             funding_vout,funding_value_sats,latest_state_number,challenge_delay,amount_sats,\
             network,record_json,created_at,updated_at) FROM bip448_statechains \
             ORDER BY wallet_name,statechain_id",
        )
        .fetch_all(pool)
        .await?;
        let history = sqlx::query_scalar::<_, String>(
            "SELECT json_array(wallet_name,statechain_id,state_number,entry_json) \
             FROM bip448_state_history ORDER BY wallet_name,statechain_id,state_number",
        )
        .fetch_all(pool)
        .await?;
        let pending = sqlx::query_scalar::<_, String>(
            "SELECT json_array(wallet_name,statechain_id,update_template_hash,signing_id,\
             client_secret_nonce,client_public_nonce,blinding_factor,server_public_nonce,\
             state_locktime,funding_txid,funding_vout,funding_value_sats,\
             settlement_template_hash,created_at,updated_at) \
             FROM bip448_pending_deposit_signings ORDER BY wallet_name,statechain_id",
        )
        .fetch_all(pool)
        .await?;
        Ok((wallet, records, history, pending))
    }

    #[tokio::test]
    async fn initial_acceptance_restart_recovery_is_exact_atomic_and_fail_closed() -> Result<()> {
        for (retain_observed_outpoint, retain_pending) in [(false, true), (true, false)] {
            let pool = migrated_pool().await?;
            let (record, entry, pending, expected_raw_wallet) =
                install_pre_materialized_initial_acceptance(
                    &pool,
                    retain_observed_outpoint,
                    retain_pending,
                )
                .await?;
            let accepted_before = accepted_table_bytes(&pool).await?;
            assert_eq!(
                recover_bip448_initial_acceptance_wallet(&pool, "wallet", &expected_raw_wallet,)
                    .await?,
                Bip448InitialAcceptanceRecovery::Recovered
            );
            assert_eq!(accepted_table_bytes(&pool).await?, accepted_before);
            assert!(
                get_bip448_pending_deposit_signing(&pool, "wallet", "statechain")
                    .await?
                    .is_none()
            );
            let recovered_wallet = get_wallet(&pool, "wallet").await?;
            let recovered_coin = &recovered_wallet.coins[0];
            assert_eq!(
                recovered_coin.utxo_txid.as_deref(),
                Some(record.funding_outpoint.txid.as_str())
            );
            assert_eq!(recovered_coin.utxo_vout, Some(record.funding_outpoint.vout));
            assert_eq!(
                recovered_coin.locktime,
                Some(record.latest_state.state_locktime)
            );
            assert_eq!(
                recovered_coin.public_nonce.as_deref(),
                Some(entry.client_public_nonce.as_str())
            );
            assert_eq!(
                recovered_coin.server_public_nonce.as_deref(),
                Some(entry.server_public_nonce.as_str())
            );
            assert_eq!(
                recovered_coin.blinding_factor.as_deref(),
                Some(entry.blinding_factor.as_str())
            );
            assert_eq!(recovered_coin.status, CoinStatus::UNCONFIRMED);
            assert_eq!(recovered_wallet.activities.len(), 1);
            let activity = &recovered_wallet.activities[0];
            assert_eq!(
                activity.utxo,
                format!(
                    "{}:{}",
                    record.funding_outpoint.txid, record.funding_outpoint.vout
                )
            );
            assert_eq!(activity.amount, u32::try_from(record.amount_sats)?);
            assert_eq!(activity.action, "bip448_deposit");
            chrono::DateTime::parse_from_rfc3339(&activity.date)?;
            let recovered_raw_wallet = get_bip448_raw_wallet_json(&pool, "wallet").await?;
            assert_eq!(
                recover_bip448_initial_acceptance_wallet(&pool, "wallet", &recovered_raw_wallet,)
                    .await?,
                Bip448InitialAcceptanceRecovery::Unchanged
            );
            assert_eq!(
                get_bip448_pending_deposit_signing(&pool, "wallet", "statechain").await?,
                None,
                "replay recreated the cleaned {} pending journal",
                pending.signing_id
            );
        }

        let corrupt_pending_pool = migrated_pool().await?;
        let (_, _, _, corrupt_expected_raw) =
            install_pre_materialized_initial_acceptance(&corrupt_pending_pool, false, true).await?;
        sqlx::query(
            "UPDATE bip448_pending_deposit_signings SET settlement_template_hash=$1 \
             WHERE wallet_name='wallet' AND statechain_id='statechain'",
        )
        .bind("cd".repeat(32))
        .execute(&corrupt_pending_pool)
        .await?;
        let corrupt_before = initial_acceptance_recovery_storage(&corrupt_pending_pool).await?;
        assert!(recover_bip448_initial_acceptance_wallet(
            &corrupt_pending_pool,
            "wallet",
            &corrupt_expected_raw,
        )
        .await
        .is_err());
        assert_eq!(
            initial_acceptance_recovery_storage(&corrupt_pending_pool).await?,
            corrupt_before
        );

        let partial_coin_pool = migrated_pool().await?;
        let (partial_record, _, _, _) =
            install_pre_materialized_initial_acceptance(&partial_coin_pool, false, true).await?;
        let mut partial_wallet = get_wallet(&partial_coin_pool, "wallet").await?;
        partial_wallet.coins[0].public_nonce = Some(
            partial_record
                .latest_state
                .signing_metadata
                .client_public_nonce
                .clone(),
        );
        update_wallet(&partial_coin_pool, &partial_wallet).await?;
        let partial_before = initial_acceptance_recovery_storage(&partial_coin_pool).await?;
        assert!(recover_bip448_initial_acceptance_wallet(
            &partial_coin_pool,
            "wallet",
            &partial_before.0,
        )
        .await
        .is_err());
        assert_eq!(
            initial_acceptance_recovery_storage(&partial_coin_pool).await?,
            partial_before
        );

        let multiple_coin_pool = migrated_pool().await?;
        let (_, _, _, _) =
            install_pre_materialized_initial_acceptance(&multiple_coin_pool, false, true).await?;
        let mut multiple_wallet = get_wallet(&multiple_coin_pool, "wallet").await?;
        multiple_wallet.coins.push(multiple_wallet.coins[0].clone());
        update_wallet(&multiple_coin_pool, &multiple_wallet).await?;
        let multiple_before = initial_acceptance_recovery_storage(&multiple_coin_pool).await?;
        assert!(recover_bip448_initial_acceptance_wallet(
            &multiple_coin_pool,
            "wallet",
            &multiple_before.0,
        )
        .await
        .is_err());
        assert_eq!(
            initial_acceptance_recovery_storage(&multiple_coin_pool).await?,
            multiple_before
        );

        let stale_wallet_pool = migrated_pool().await?;
        let (_, _, _, stale_expected_raw) =
            install_pre_materialized_initial_acceptance(&stale_wallet_pool, false, true).await?;
        let mut raced_wallet = get_wallet(&stale_wallet_pool, "wallet").await?;
        raced_wallet.blockheight = raced_wallet.blockheight.saturating_add(1);
        update_wallet(&stale_wallet_pool, &raced_wallet).await?;
        let raced_before = initial_acceptance_recovery_storage(&stale_wallet_pool).await?;
        assert_eq!(
            recover_bip448_initial_acceptance_wallet(
                &stale_wallet_pool,
                "wallet",
                &stale_expected_raw,
            )
            .await?,
            Bip448InitialAcceptanceRecovery::WalletChanged
        );
        assert_eq!(
            initial_acceptance_recovery_storage(&stale_wallet_pool).await?,
            raced_before
        );

        let rollback_pool = migrated_pool().await?;
        let (_, _, _, rollback_expected_raw) =
            install_pre_materialized_initial_acceptance(&rollback_pool, false, true).await?;
        sqlx::query(
            "CREATE TRIGGER test_initial_acceptance_recovery_fault \
             BEFORE DELETE ON bip448_pending_deposit_signings \
             BEGIN SELECT RAISE(ABORT, 'injected recovery fault'); END",
        )
        .execute(&rollback_pool)
        .await?;
        let rollback_before = initial_acceptance_recovery_storage(&rollback_pool).await?;
        assert!(recover_bip448_initial_acceptance_wallet(
            &rollback_pool,
            "wallet",
            &rollback_expected_raw,
        )
        .await
        .is_err());
        assert_eq!(
            initial_acceptance_recovery_storage(&rollback_pool).await?,
            rollback_before
        );
        Ok(())
    }

    #[tokio::test]
    async fn bip448_initial_acceptance_requires_one_exact_real_wallet_coin() -> Result<()> {
        let (wallet, record, entry, _) = real_accepted_fixture(CoinStatus::UNCONFIRMED)?;

        let empty_pool = migrated_pool().await?;
        insert_wallet(&empty_pool, &sample_wallet()).await?;
        let before = accepted_table_bytes(&empty_pool).await?;
        assert!(
            persist_bip448_initial_acceptance(&empty_pool, &record, &entry)
                .await
                .is_err()
        );
        assert_eq!(accepted_table_bytes(&empty_pool).await?, before);

        let unrelated_pool = migrated_pool().await?;
        let mut unrelated_wallet = wallet.clone();
        unrelated_wallet.coins[0].statechain_id = Some("unrelated-statechain".into());
        insert_wallet(&unrelated_pool, &unrelated_wallet).await?;
        let before = accepted_table_bytes(&unrelated_pool).await?;
        assert!(
            persist_bip448_initial_acceptance(&unrelated_pool, &record, &entry)
                .await
                .is_err()
        );
        assert_eq!(accepted_table_bytes(&unrelated_pool).await?, before);

        let absent_wallet_pool = migrated_pool().await?;
        let before = accepted_table_bytes(&absent_wallet_pool).await?;
        assert!(
            persist_bip448_initial_acceptance(&absent_wallet_pool, &record, &entry)
                .await
                .is_err()
        );
        assert_eq!(accepted_table_bytes(&absent_wallet_pool).await?, before);

        let multiple_pool = migrated_pool().await?;
        let mut multiple_wallet = wallet.clone();
        multiple_wallet.coins.push(wallet.coins[0].clone());
        insert_wallet(&multiple_pool, &multiple_wallet).await?;
        let before = accepted_table_bytes(&multiple_pool).await?;
        assert!(
            persist_bip448_initial_acceptance(&multiple_pool, &record, &entry)
                .await
                .is_err()
        );
        assert_eq!(accepted_table_bytes(&multiple_pool).await?, before);

        for mutate in [
            |record: &mut Bip448StatechainRecord, entry: &mut Bip448StateHistoryEntry| {
                record.latest_state.update_tx.push_str("00");
                let _ = entry;
            },
            |record: &mut Bip448StatechainRecord, entry: &mut Bip448StateHistoryEntry| {
                let bad_signature = "00".repeat(64);
                record.latest_state.signing_metadata.update_signature = bad_signature.clone();
                entry.update_signature = bad_signature;
            },
            |record: &mut Bip448StatechainRecord, entry: &mut Bip448StateHistoryEntry| {
                let bad_nonce = "00".repeat(66);
                record.latest_state.signing_metadata.client_public_nonce = bad_nonce.clone();
                entry.client_public_nonce = bad_nonce;
            },
        ] {
            let malformed_pool = migrated_pool().await?;
            insert_wallet(&malformed_pool, &wallet).await?;
            let mut malformed_record = record.clone();
            let mut malformed_entry = entry.clone();
            mutate(&mut malformed_record, &mut malformed_entry);
            let before = accepted_table_bytes(&malformed_pool).await?;
            assert!(persist_bip448_initial_acceptance(
                &malformed_pool,
                &malformed_record,
                &malformed_entry,
            )
            .await
            .is_err());
            assert_eq!(accepted_table_bytes(&malformed_pool).await?, before);
        }
        Ok(())
    }

    #[tokio::test]
    async fn bip448_binding_indices_are_canonical_deterministic_stable_and_checked() -> Result<()> {
        let pool = migrated_pool().await?;
        let (record, owner, script) = accepted_binding_fixture(&pool).await?;
        let canonical = sample_binding_observation("34", 0, 100_000, &script);
        let one = sample_binding_observation("11", 1, 70_000, &script);
        let two = sample_binding_observation("22", 2, 80_000, &script);
        let bindings = reconcile_bip448_funding_bindings(
            &pool,
            "wallet",
            "statechain",
            &owner.to_string(),
            1,
            &[two.clone(), canonical.clone(), one.clone()],
        )
        .await?;
        assert_eq!(
            bindings
                .iter()
                .map(|row| (row.binding_index, row.txid.clone()))
                .collect::<Vec<_>>(),
            vec![
                (0, record.funding_outpoint.txid.clone()),
                (1, one.txid.clone()),
                (2, two.txid.clone())
            ]
        );
        let replay = reconcile_bip448_funding_bindings(
            &pool,
            "wallet",
            "statechain",
            &owner.to_string(),
            1,
            &[one.clone(), canonical.clone()],
        )
        .await?;
        assert_eq!(
            replay.len(),
            3,
            "an absent observation never deletes or renumbers a binding"
        );
        let three = sample_binding_observation("01", 3, 90_000, &script);
        let rows = reconcile_bip448_funding_bindings(
            &pool,
            "wallet",
            "statechain",
            &owner.to_string(),
            1,
            &[canonical.clone(), three.clone()],
        )
        .await?;
        assert_eq!(
            rows.iter()
                .find(|row| row.txid == three.txid)
                .unwrap()
                .binding_index,
            3
        );

        let before = rows.clone();
        let mut conflict = canonical.clone();
        conflict.value_sats += 1;
        assert!(reconcile_bip448_funding_bindings(
            &pool,
            "wallet",
            "statechain",
            &owner.to_string(),
            1,
            &[conflict]
        )
        .await
        .is_err());
        assert_eq!(
            list_bip448_funding_bindings(&pool, "wallet", "statechain").await?,
            before
        );
        for (status, spend_txid, spend_height) in [
            ("Unconfirmed", None, None),
            ("Confirmed", None, None),
            ("SpentUnconfirmed", Some("aa".repeat(32)), Some(11_i64)),
            ("SpentConfirmed", Some("aa".repeat(32)), Some(11_i64)),
        ] {
            let result = sqlx::query(
                "UPDATE bip448_funding_bindings SET observation_status=$1,\
                funding_height=NULL,spend_txid=$2,spend_height=$3 WHERE wallet_name='wallet' \
                AND statechain_id='statechain' AND binding_index=1",
            )
            .bind(status)
            .bind(spend_txid)
            .bind(spend_height)
            .execute(&pool)
            .await;
            assert!(result.is_err(), "{status} accepted a null funding height");
        }
        assert!(sqlx::query(
            "UPDATE bip448_funding_bindings SET role='DebugCanonical' WHERE wallet_name='wallet'"
        )
        .execute(&pool)
        .await
        .is_err());
        assert!(sqlx::query("UPDATE bip448_funding_bindings SET binding_index=4294967296 WHERE wallet_name='wallet' AND binding_index=3")
            .execute(&pool).await.is_err());
        let moved = sqlx::query(
            "UPDATE bip448_funding_bindings SET binding_index=4294967295 \
             WHERE wallet_name='wallet' AND statechain_id='statechain' AND binding_index=3",
        )
        .execute(&pool)
        .await?;
        assert_eq!(moved.rows_affected(), 1);
        let max_replay = reconcile_bip448_funding_bindings(
            &pool,
            "wallet",
            "statechain",
            &owner.to_string(),
            1,
            &[canonical.clone(), three.clone()],
        )
        .await?;
        assert_eq!(
            max_replay
                .iter()
                .find(|row| row.txid == three.txid)
                .unwrap()
                .binding_index,
            u32::MAX,
            "u32::MAX remains replayable when no allocation is required"
        );
        let four = sample_binding_observation("02", 4, 95_000, &script);
        let before_overflow = max_replay;
        assert!(reconcile_bip448_funding_bindings(
            &pool,
            "wallet",
            "statechain",
            &owner.to_string(),
            1,
            &[canonical, four]
        )
        .await
        .is_err());
        assert_eq!(
            list_bip448_funding_bindings(&pool, "wallet", "statechain").await?,
            before_overflow,
            "allocation overflow rolls back every earlier observation update"
        );
        Ok(())
    }

    #[tokio::test]
    async fn passive_binding_sync_requires_one_exact_current_generation_coin_before_writes(
    ) -> Result<()> {
        for status in [CoinStatus::WITHDRAWING, CoinStatus::WITHDRAWN] {
            let pool = migrated_pool().await?;
            let (record, owner, script) = accepted_binding_fixture(&pool).await?;
            let mut wallet = get_wallet(&pool, "wallet").await?;
            set_valid_withdrawal_lifecycle(&mut wallet.coins[0], status.clone())?;
            update_wallet(&pool, &wallet).await?;
            let raw_wallet = get_bip448_raw_wallet_json(&pool, "wallet").await?;
            assert_eq!(
                recover_bip448_initial_acceptance_wallet(&pool, "wallet", &raw_wallet).await?,
                Bip448InitialAcceptanceRecovery::Unchanged
            );
            assert_eq!(
                get_bip448_raw_wallet_json(&pool, "wallet").await?,
                raw_wallet
            );
            let bindings = reconcile_bip448_funding_bindings(
                &pool,
                "wallet",
                "statechain",
                &owner.to_string(),
                1,
                &[sample_binding_observation(
                    "34",
                    record.funding_outpoint.vout,
                    record.funding_outpoint.value_sats,
                    &script,
                )],
            )
            .await?;
            assert_eq!(bindings.len(), 1);
            assert_eq!(bindings[0].owner_user_pubkey, owner.to_string());
            assert_eq!(bindings[0].owner_state_number, 1);
        }

        for case in ["zero", "multiple", "malformed", "mismatched-owner"] {
            let pool = migrated_pool().await?;
            let (record, owner, script) = accepted_binding_fixture(&pool).await?;
            let cursor = Bip448ScanCursor {
                coverage_start_height: 0,
                scan_revision: 0,
                last_scanned_height: 20,
                last_scanned_block_hash: "61".repeat(32),
            };
            persist_bip448_scan_state(&pool, "wallet", &script, &cursor, &[]).await?;
            match case {
                "zero" => {
                    let mut wallet = get_wallet(&pool, "wallet").await?;
                    wallet.coins.clear();
                    update_wallet(&pool, &wallet).await?;
                }
                "multiple" => {
                    let mut wallet = get_wallet(&pool, "wallet").await?;
                    wallet.coins.push(wallet.coins[0].clone());
                    update_wallet(&pool, &wallet).await?;
                }
                "malformed" => {
                    let updated = sqlx::query(
                        "UPDATE wallet SET wallet_json='{not-json' WHERE wallet_name='wallet'",
                    )
                    .execute(&pool)
                    .await?;
                    assert_eq!(updated.rows_affected(), 1);
                }
                "mismatched-owner" => {
                    let mut wallet = get_wallet(&pool, "wallet").await?;
                    let mut unrelated = wallet.get_new_coin()?;
                    unrelated.statechain_protocol = Some(BIP448_COIN_PROTOCOL.to_string());
                    unrelated.statechain_id = Some("statechain".to_string());
                    wallet.coins = vec![unrelated];
                    update_wallet(&pool, &wallet).await?;
                }
                _ => unreachable!(),
            }
            let before = capture_bip448_sync_base(&pool, "wallet", &script).await?;
            let error = reconcile_bip448_funding_bindings(
                &pool,
                "wallet",
                "statechain",
                &owner.to_string(),
                1,
                &[sample_binding_observation(
                    "34",
                    record.funding_outpoint.vout,
                    record.funding_outpoint.value_sats,
                    &script,
                )],
            )
            .await
            .err()
            .ok_or_else(|| anyhow!("{case} passive wallet unexpectedly reconciled"))?;
            assert!(
                !error.to_string().is_empty(),
                "{case} returned an empty error"
            );
            let after = capture_bip448_sync_base(&pool, "wallet", &script).await?;
            assert_eq!(
                after, before,
                "{case} changed storage or advanced its cursor"
            );
        }

        for case in [
            "withdraw-missing-secret",
            "withdraw-malformed-client-nonce",
            "withdraw-unpaired-identifiers",
        ] {
            let pool = migrated_pool().await?;
            let (record, owner, script) = accepted_binding_fixture(&pool).await?;
            let cursor = Bip448ScanCursor {
                coverage_start_height: 0,
                scan_revision: 0,
                last_scanned_height: 20,
                last_scanned_block_hash: "61".repeat(32),
            };
            persist_bip448_scan_state(&pool, "wallet", &script, &cursor, &[]).await?;
            let mut wallet = get_wallet(&pool, "wallet").await?;
            set_valid_withdrawal_lifecycle(&mut wallet.coins[0], CoinStatus::WITHDRAWING)?;
            match case {
                "withdraw-missing-secret" => wallet.coins[0].secret_nonce = None,
                "withdraw-malformed-client-nonce" => {
                    wallet.coins[0].public_nonce = Some("00".repeat(66));
                }
                "withdraw-unpaired-identifiers" => {
                    wallet.coins[0].withdrawal_address = None;
                }
                _ => unreachable!(),
            }
            update_wallet(&pool, &wallet).await?;
            let before = capture_bip448_sync_base(&pool, "wallet", &script).await?;
            assert!(reconcile_bip448_funding_bindings(
                &pool,
                "wallet",
                "statechain",
                &owner.to_string(),
                1,
                &[sample_binding_observation(
                    "34",
                    record.funding_outpoint.vout,
                    record.funding_outpoint.value_sats,
                    &script,
                )],
            )
            .await
            .is_err());
            assert_eq!(
                capture_bip448_sync_base(&pool, "wallet", &script).await?,
                before,
                "{case} changed storage or advanced its cursor"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn bip448_binding_sql_domains_nullable_states_and_wallet_uniqueness() -> Result<()> {
        let pool = migrated_pool().await?;
        let (_record, owner, script) = accepted_binding_fixture(&pool).await?;
        reconcile_bip448_funding_bindings(
            &pool,
            "wallet",
            "statechain",
            &owner.to_string(),
            1,
            &[
                sample_binding_observation("34", 0, 100_000, &script),
                sample_binding_observation("11", 1, 70_000, &script),
            ],
        )
        .await?;

        for (status, funding_height, spend_txid, spend_height, accepted) in [
            ("Mempool", None, None, None, true),
            ("Mempool", Some(10_i64), None, None, false),
            ("Unconfirmed", None, None, None, false),
            ("Unconfirmed", Some(10), None, None, true),
            ("Confirmed", None, None, None, false),
            ("Confirmed", Some(10), None, None, true),
            ("SpentMempool", None, Some("aa".repeat(32)), None, true),
            ("SpentMempool", Some(10), Some("aa".repeat(32)), None, true),
            (
                "SpentUnconfirmed",
                None,
                Some("aa".repeat(32)),
                Some(11),
                false,
            ),
            (
                "SpentUnconfirmed",
                Some(10),
                Some("aa".repeat(32)),
                Some(11),
                true,
            ),
            (
                "SpentConfirmed",
                None,
                Some("aa".repeat(32)),
                Some(11),
                false,
            ),
            (
                "SpentConfirmed",
                Some(10),
                Some("aa".repeat(32)),
                Some(11),
                true,
            ),
            ("Absent", None, None, None, true),
            ("Absent", Some(10), None, None, true),
        ] {
            let result = sqlx::query(
                "UPDATE bip448_funding_bindings SET observation_status=$1, \
                 funding_height=$2,spend_txid=$3,spend_height=$4 \
                 WHERE wallet_name='wallet' AND statechain_id='statechain' AND binding_index=1",
            )
            .bind(status)
            .bind(funding_height)
            .bind(spend_txid)
            .bind(spend_height)
            .execute(&pool)
            .await;
            assert_eq!(result.is_ok(), accepted, "direct SQL status case {status}");
        }
        sqlx::query(
            "UPDATE bip448_funding_bindings SET observation_status='Confirmed',funding_height=10, \
             spend_txid=NULL,spend_height=NULL WHERE wallet_name='wallet' \
             AND statechain_id='statechain' AND binding_index=1",
        )
        .execute(&pool)
        .await?;
        for statement in [
            "UPDATE bip448_funding_bindings SET role='canonical' WHERE wallet_name='wallet' AND binding_index=1",
            "UPDATE bip448_funding_bindings SET observation_status='Unknown' WHERE wallet_name='wallet' AND binding_index=1",
            "UPDATE bip448_funding_bindings SET ownership_status='current' WHERE wallet_name='wallet' AND binding_index=1",
        ] {
            assert!(sqlx::query(statement).execute(&pool).await.is_err());
        }
        let max_value = i64::try_from(bip448_funding::BIP448_MAX_MONEY_SATS)?;
        assert_eq!(
            sqlx::query("UPDATE bip448_funding_bindings SET value_sats=$1 WHERE wallet_name='wallet' AND binding_index=1")
                .bind(max_value)
                .execute(&pool)
                .await?
                .rows_affected(),
            1
        );
        assert_eq!(
            get_bip448_funding_binding(&pool, "wallet", "statechain", 1)
                .await?
                .unwrap()
                .value_sats,
            bip448_funding::BIP448_MAX_MONEY_SATS
        );
        assert!(sqlx::query("UPDATE bip448_funding_bindings SET value_sats=$1 WHERE wallet_name='wallet' AND binding_index=1")
            .bind(max_value.checked_add(1).unwrap())
            .execute(&pool).await.is_err());
        assert!(sqlx::query("UPDATE bip448_funding_bindings SET value_sats=-1 WHERE wallet_name='wallet' AND binding_index=1")
            .execute(&pool).await.is_err());
        sqlx::query("UPDATE bip448_funding_bindings SET value_sats=70000 WHERE wallet_name='wallet' AND binding_index=1")
            .execute(&pool).await?;
        assert_eq!(
            sqlx::query("UPDATE bip448_funding_bindings SET vout=4294967295 WHERE wallet_name='wallet' AND binding_index=1")
                .execute(&pool).await?.rows_affected(),
            1
        );
        assert_eq!(
            get_bip448_funding_binding(&pool, "wallet", "statechain", 1)
                .await?
                .unwrap()
                .vout,
            u32::MAX
        );
        assert!(sqlx::query("UPDATE bip448_funding_bindings SET vout=4294967296 WHERE wallet_name='wallet' AND binding_index=1")
            .execute(&pool).await.is_err());
        sqlx::query("UPDATE bip448_funding_bindings SET vout=1 WHERE wallet_name='wallet' AND binding_index=1")
            .execute(&pool).await?;

        let (second_wallet, second_record, second_entry, second_owner) =
            real_accepted_fixture_for(CoinStatus::CONFIRMED, "statechain-two", &"35".repeat(32))?;
        let mut combined_wallet = get_wallet(&pool, "wallet").await?;
        combined_wallet.coins.extend(second_wallet.coins);
        update_wallet(&pool, &combined_wallet).await?;
        persist_bip448_initial_acceptance(&pool, &second_record, &second_entry).await?;
        let second_script = accepted_funding_script(&second_record)?;
        assert!(reconcile_bip448_funding_bindings(
            &pool,
            "wallet",
            "statechain-two",
            &second_owner.to_string(),
            1,
            &[
                sample_binding_observation("35", 0, 100_000, &second_script),
                sample_binding_observation("11", 1, 70_000, &second_script),
            ],
        )
        .await
        .is_err());
        assert!(
            list_bip448_funding_bindings(&pool, "wallet", "statechain-two")
                .await?
                .is_empty()
        );
        Ok(())
    }

    #[tokio::test]
    async fn bip448_signed_attempt_requires_exact_keypath_witness_and_rolls_back() -> Result<()> {
        let pool = migrated_pool().await?;
        let (_, owner, script) = accepted_binding_fixture(&pool).await?;
        let binding = reconcile_bip448_funding_bindings(
            &pool,
            "wallet",
            "statechain",
            &owner.to_string(),
            1,
            &[
                sample_binding_observation("34", 0, 100_000, &script),
                sample_binding_observation("11", 1, 70_000, &script),
            ],
        )
        .await?
        .into_iter()
        .find(|binding| binding.binding_index == 1)
        .ok_or_else(|| anyhow!("duplicate test binding is missing"))?;
        let armed = second_arm_duplicate_attempt(&pool, &binding).await?;
        let aggregate_signature = hex::decode("92".repeat(64))?;
        let mut with_sighash_byte = aggregate_signature.clone();
        with_sighash_byte.push(1);
        let invalid_witnesses = vec![
            Vec::<Vec<u8>>::new(),
            vec![Vec::new()],
            vec![hex::decode("93".repeat(64))?],
            vec![aggregate_signature.clone(), vec![1]],
            vec![aggregate_signature.clone()],
        ];
        for witness_items in invalid_witnesses {
            let mut transaction: bitcoin::Transaction =
                bitcoin::consensus::deserialize(&hex::decode(&armed.unsigned_tx_hex)?)?;
            for item in witness_items {
                transaction.input[0].witness.push(item);
            }
            let result = store_bip448_withdrawal_signed_artifacts(
                &pool,
                "wallet",
                "statechain",
                1,
                &armed.signing_id,
                &"91".repeat(32),
                &hex::encode(&aggregate_signature),
                &hex::encode(bitcoin::consensus::serialize(&transaction)),
                &transaction.txid().to_string(),
                Bip448BroadcastStatus::NotBroadcast,
            )
            .await;
            assert!(result.is_err());
            let unchanged = get_bip448_withdrawal_attempt(&pool, "wallet", "statechain", 1)
                .await?
                .ok_or_else(|| anyhow!("armed attempt disappeared"))?;
            assert_eq!(unchanged.phase, Bip448WithdrawalPhase::SecondArmed);
            assert!(unchanged.server_partial_sig.is_none());
            assert!(unchanged.aggregate_signature.is_none());
            assert!(unchanged.signed_tx_hex.is_none());
            assert!(unchanged.txid.is_none());
        }

        let mut transaction: bitcoin::Transaction =
            bitcoin::consensus::deserialize(&hex::decode(&armed.unsigned_tx_hex)?)?;
        transaction.input[0].witness.push(with_sighash_byte);
        let stored = store_bip448_withdrawal_signed_artifacts(
            &pool,
            "wallet",
            "statechain",
            1,
            &armed.signing_id,
            &"91".repeat(32),
            &hex::encode(&aggregate_signature),
            &hex::encode(bitcoin::consensus::serialize(&transaction)),
            &transaction.txid().to_string(),
            Bip448BroadcastStatus::NotBroadcast,
        )
        .await?;
        assert_eq!(stored.phase, Bip448WithdrawalPhase::Signed);
        Ok(())
    }

    #[tokio::test]
    async fn bip448_withdrawal_session_relationship_is_typed_and_mutation_resistant() -> Result<()>
    {
        let pool = migrated_pool().await?;
        let (_, owner, script) = accepted_binding_fixture(&pool).await?;
        let binding = reconcile_bip448_funding_bindings(
            &pool,
            "wallet",
            "statechain",
            &owner.to_string(),
            1,
            &[
                sample_binding_observation("34", 0, 100_000, &script),
                sample_binding_observation("11", 1, 70_000, &script),
            ],
        )
        .await?
        .into_iter()
        .find(|binding| binding.binding_index == 1)
        .ok_or_else(|| anyhow!("duplicate session test binding is missing"))?;
        let attempt = sample_duplicate_attempt(&binding);
        insert_bip448_withdrawal_attempt_if_absent(&pool, &attempt).await?;
        let first_armed =
            arm_bip448_withdrawal_sign_first(&pool, "wallet", "statechain", 1, &attempt.signing_id)
                .await?;

        let server_public_nonce = "81".repeat(66);
        let output_pubkey = sample_owner_key(4).0.to_string();
        let (full_session, blinded_session) = real_keypath_session_pair(94)?;
        let (_, other_blinded_session) = real_keypath_session_pair(95)?;
        assert_ne!(full_session, blinded_session);
        assert_ne!(blinded_session, other_blinded_session);
        assert_eq!(
            bip448_funding::derive_bip448_blinded_session(&full_session)?,
            blinded_session
        );

        let mutated_full_session = mutate_session_byte(&full_session, 70)?;
        let mutated_blinded_session = mutate_session_byte(&blinded_session, 70)?;
        let truncated_full_session = full_session[..full_session.len() - 2].to_owned();
        let extended_full_session = format!("{full_session}00");
        let malformed_full_session = format!("g0{}", &full_session[2..]);
        let noncanonical_full_session = full_session.to_uppercase();
        let invalid_storage_cases = [
            (
                "mutated full",
                mutated_full_session.clone(),
                blinded_session.clone(),
            ),
            (
                "mutated blinded",
                full_session.clone(),
                mutated_blinded_session.clone(),
            ),
            (
                "truncated full",
                truncated_full_session.clone(),
                blinded_session.clone(),
            ),
            (
                "extended full",
                extended_full_session.clone(),
                blinded_session.clone(),
            ),
            (
                "malformed full",
                malformed_full_session.clone(),
                blinded_session.clone(),
            ),
            (
                "noncanonical full",
                noncanonical_full_session.clone(),
                blinded_session.clone(),
            ),
            (
                "different valid blinded",
                full_session.clone(),
                other_blinded_session.clone(),
            ),
        ];
        let first_armed_snapshot =
            raw_withdrawal_attempt_snapshot(&pool, "wallet", "statechain", 1).await?;
        for (case, candidate_full, candidate_blinded) in invalid_storage_cases {
            let payload = sign_second_payload_for_attempt(
                &first_armed,
                &server_public_nonce,
                &candidate_blinded,
            )?;
            assert!(
                store_bip448_withdrawal_nonce_session(
                    &pool,
                    "wallet",
                    "statechain",
                    1,
                    &attempt.signing_id,
                    &server_public_nonce,
                    &"82".repeat(32),
                    &output_pubkey,
                    &"84".repeat(32),
                    &candidate_full,
                    &payload,
                )
                .await
                .is_err(),
                "invalid storage case {case} was accepted"
            );
            assert_eq!(
                raw_withdrawal_attempt_snapshot(&pool, "wallet", "statechain", 1).await?,
                first_armed_snapshot,
                "invalid storage case {case} changed the exact journal row"
            );
            let expectation =
                bip448_expected_signature_count(&pool, "wallet", "statechain").await?;
            assert_eq!(expectation.settled_count, 1);
            assert_eq!(expectation.second_armed_landed_count, None);
        }

        let valid_payload =
            sign_second_payload_for_attempt(&first_armed, &server_public_nonce, &blinded_session)?;
        let nonce_stored = store_bip448_withdrawal_nonce_session(
            &pool,
            "wallet",
            "statechain",
            1,
            &attempt.signing_id,
            &server_public_nonce,
            &"82".repeat(32),
            &output_pubkey,
            &"84".repeat(32),
            &full_session,
            &valid_payload,
        )
        .await?;
        assert_eq!(nonce_stored.phase, Bip448WithdrawalPhase::NonceStored);

        let invalid_load_cases = [
            (
                "mutated full",
                mutated_full_session,
                blinded_session.clone(),
            ),
            (
                "mutated blinded",
                full_session.clone(),
                mutated_blinded_session,
            ),
            (
                "truncated full",
                truncated_full_session,
                blinded_session.clone(),
            ),
            (
                "extended full",
                extended_full_session,
                blinded_session.clone(),
            ),
            (
                "malformed full",
                malformed_full_session,
                blinded_session.clone(),
            ),
            (
                "noncanonical full",
                noncanonical_full_session,
                blinded_session.clone(),
            ),
            (
                "different valid blinded",
                full_session.clone(),
                other_blinded_session,
            ),
        ];
        for (case, candidate_full, candidate_blinded) in invalid_load_cases {
            let payload = sign_second_payload_for_attempt(
                &nonce_stored,
                &server_public_nonce,
                &candidate_blinded,
            )?;
            sqlx::query(
                "UPDATE bip448_withdrawal_attempts SET encoded_session=$1,\
                    sign_second_payload_json=$2 WHERE wallet_name='wallet' \
                    AND statechain_id='statechain' AND binding_index=1",
            )
            .bind(candidate_full)
            .bind(payload)
            .execute(&pool)
            .await?;
            let corrupted_snapshot =
                raw_withdrawal_attempt_snapshot(&pool, "wallet", "statechain", 1).await?;
            assert!(
                get_bip448_withdrawal_attempt(&pool, "wallet", "statechain", 1)
                    .await
                    .is_err(),
                "invalid load case {case} passed typed validation"
            );
            assert!(
                arm_bip448_withdrawal_sign_second(
                    &pool,
                    "wallet",
                    "statechain",
                    1,
                    &attempt.signing_id,
                )
                .await
                .is_err(),
                "invalid load case {case} reached SecondArmed"
            );
            assert_eq!(
                raw_withdrawal_attempt_snapshot(&pool, "wallet", "statechain", 1).await?,
                corrupted_snapshot,
                "invalid load case {case} changed the exact journal row"
            );
            assert_eq!(
                sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM bip448_withdrawal_attempts \
                     WHERE wallet_name='wallet' AND statechain_id='statechain' \
                       AND phase='SecondArmed'",
                )
                .fetch_one(&pool)
                .await?,
                0,
                "invalid load case {case} armed sign/second"
            );
            sqlx::query(
                "UPDATE bip448_withdrawal_attempts SET encoded_session=$1,\
                    sign_second_payload_json=$2 WHERE wallet_name='wallet' \
                    AND statechain_id='statechain' AND binding_index=1",
            )
            .bind(&full_session)
            .bind(&valid_payload)
            .execute(&pool)
            .await?;
            assert_eq!(
                get_bip448_withdrawal_attempt(&pool, "wallet", "statechain", 1)
                    .await?
                    .ok_or_else(|| anyhow!("restored nonce row is missing"))?
                    .phase,
                Bip448WithdrawalPhase::NonceStored
            );
        }

        let second_armed = arm_bip448_withdrawal_sign_second(
            &pool,
            "wallet",
            "statechain",
            1,
            &attempt.signing_id,
        )
        .await?;
        assert_eq!(second_armed.phase, Bip448WithdrawalPhase::SecondArmed);
        Ok(())
    }

    #[tokio::test]
    async fn bip448_attempt_transitions_serialize_and_never_regress() -> Result<()> {
        let pool = migrated_pool().await?;
        let (record, owner, script) = accepted_binding_fixture(&pool).await?;
        let canonical = sample_binding_observation("34", 0, 100_000, &script);
        let duplicate = sample_binding_observation("11", 1, 70_000, &script);
        let bindings = reconcile_bip448_funding_bindings(
            &pool,
            "wallet",
            "statechain",
            &owner.to_string(),
            1,
            &[canonical, duplicate],
        )
        .await?;
        let binding = bindings
            .into_iter()
            .find(|row| row.binding_index == 1)
            .unwrap();
        let attempt = sample_duplicate_attempt(&binding);
        let inserted = insert_bip448_withdrawal_attempt_if_absent(&pool, &attempt).await?;
        assert_eq!(
            insert_bip448_withdrawal_attempt_if_absent(&pool, &attempt).await?,
            inserted
        );
        assert!(transition_bip448_withdrawal_phase(
            &pool,
            "wallet",
            "statechain",
            1,
            &attempt.signing_id,
            Bip448WithdrawalPhase::Prepared,
            Bip448WithdrawalPhase::SecondArmed,
        )
        .await
        .is_err());
        arm_bip448_withdrawal_sign_first(&pool, "wallet", "statechain", 1, &attempt.signing_id)
            .await?;
        assert!(arm_bip448_withdrawal_sign_first(
            &pool,
            "wallet",
            "statechain",
            1,
            &attempt.signing_id
        )
        .await
        .is_err());
        let output_pubkey = sample_owner_key(4).0.to_string();
        let server_public_nonce = "81".repeat(66);
        let (encoded_session, blinded_session) = real_keypath_session_pair(91)?;
        let sign_second_payload_json = serde_json::to_string(
            &mercurylib::bip448_statechain::signing_api::Bip448PartialSignatureRequestPayload {
                statechain_id: "statechain".into(),
                signed_statechain_id: attempt.signed_statechain_id.clone(),
                signing_id: attempt.signing_id.clone(),
                negate_seckey: 0,
                session: blinded_session,
                server_pub_nonce: server_public_nonce.clone(),
            },
        )?;
        store_bip448_withdrawal_nonce_session(
            &pool,
            "wallet",
            "statechain",
            1,
            &attempt.signing_id,
            &server_public_nonce,
            &"82".repeat(32),
            &output_pubkey,
            &"84".repeat(32),
            &encoded_session,
            &sign_second_payload_json,
        )
        .await?;
        assert!(store_bip448_withdrawal_nonce_session(
            &pool,
            "wallet",
            "statechain",
            1,
            &attempt.signing_id,
            &server_public_nonce,
            &"82".repeat(32),
            &output_pubkey,
            &"84".repeat(32),
            &encoded_session,
            &sign_second_payload_json,
        )
        .await
        .is_err());
        arm_bip448_withdrawal_sign_second(&pool, "wallet", "statechain", 1, &attempt.signing_id)
            .await?;
        assert!(arm_bip448_withdrawal_sign_second(
            &pool,
            "wallet",
            "statechain",
            1,
            &attempt.signing_id
        )
        .await
        .is_err());
        assert!(bip448_statechain_is_exit_only(&pool, "wallet", "statechain").await?);
        let expectation = bip448_expected_signature_count(&pool, "wallet", "statechain").await?;
        assert_eq!(expectation.settled_count, 1);
        assert_eq!(expectation.second_armed_landed_count, Some(2));
        let server_partial_sig = "91".repeat(32);
        let aggregate_signature = "92".repeat(64);
        let mut signed_transaction: bitcoin::Transaction =
            bitcoin::consensus::deserialize(&hex::decode(&attempt.unsigned_tx_hex)?)?;
        let mut keypath_witness = hex::decode(&aggregate_signature)?;
        keypath_witness.push(0x01);
        signed_transaction.input[0].witness.push(keypath_witness);
        let signed_tx_hex = hex::encode(bitcoin::consensus::serialize(&signed_transaction));
        let signed_txid = signed_transaction.txid().to_string();
        store_signed_bip448_withdrawal(
            &pool,
            "wallet",
            "statechain",
            1,
            &attempt.signing_id,
            &server_partial_sig,
            &aggregate_signature,
            &signed_tx_hex,
            &signed_txid,
            Bip448BroadcastStatus::NotBroadcast,
        )
        .await?;
        assert!(store_signed_bip448_withdrawal(
            &pool,
            "wallet",
            "statechain",
            1,
            &attempt.signing_id,
            &server_partial_sig,
            &aggregate_signature,
            &signed_tx_hex,
            &signed_txid,
            Bip448BroadcastStatus::NotBroadcast,
        )
        .await
        .is_err());
        for (from, to) in [
            (
                Bip448BroadcastStatus::NotBroadcast,
                Bip448BroadcastStatus::Accepted,
            ),
            (
                Bip448BroadcastStatus::Accepted,
                Bip448BroadcastStatus::NeedsRebroadcast,
            ),
            (
                Bip448BroadcastStatus::NeedsRebroadcast,
                Bip448BroadcastStatus::Conflicting,
            ),
            (
                Bip448BroadcastStatus::Conflicting,
                Bip448BroadcastStatus::Conflicted,
            ),
            (
                Bip448BroadcastStatus::Conflicted,
                Bip448BroadcastStatus::NeedsRebroadcast,
            ),
        ] {
            transition_bip448_withdrawal_broadcast_status(
                &pool,
                "wallet",
                "statechain",
                1,
                &attempt.signing_id,
                from,
                to,
            )
            .await?;
        }
        assert!(transition_bip448_withdrawal_broadcast_status(
            &pool,
            "wallet",
            "statechain",
            1,
            &attempt.signing_id,
            Bip448BroadcastStatus::NeedsRebroadcast,
            Bip448BroadcastStatus::NotBroadcast
        )
        .await
        .is_err());
        assert_eq!(
            bip448_expected_signature_count(&pool, "wallet", "statechain")
                .await?
                .settled_count,
            2
        );
        assert_eq!(
            get_bip448_statechain(&pool, "wallet", "statechain").await?,
            record
        );
        Ok(())
    }

    #[test]
    fn bip448_broadcast_transition_matrix_is_exact() {
        let statuses = [
            Bip448BroadcastStatus::NotBroadcast,
            Bip448BroadcastStatus::Accepted,
            Bip448BroadcastStatus::Confirmed,
            Bip448BroadcastStatus::NeedsRebroadcast,
            Bip448BroadcastStatus::Conflicting,
            Bip448BroadcastStatus::Conflicted,
        ];
        for from in statuses {
            for to in statuses {
                let expected = from == to
                    || from == Bip448BroadcastStatus::NotBroadcast
                    || to != Bip448BroadcastStatus::NotBroadcast;
                assert_eq!(
                    legal_broadcast_transition(from, to),
                    expected,
                    "unexpected broadcast edge {from:?} -> {to:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn bip448_sync_base_revision_pending_and_wallet_tokens_are_full_cas() -> Result<()> {
        let pool = migrated_pool().await?;
        let wallet = sample_wallet();
        insert_wallet(&pool, &wallet).await?;
        let base = capture_bip448_sync_base(&pool, "wallet", "51").await?;
        let pending = Bip448PendingDepositSigning {
            wallet_name: "wallet".into(),
            statechain_id: "statechain".into(),
            funding_txid: "11".repeat(32),
            funding_vout: 0,
            funding_value_sats: 1,
            update_template_hash: "21".repeat(32),
            settlement_template_hash: "22".repeat(32),
            state_locktime: 700_000_000,
            signing_id: "23".repeat(32),
            client_secret_nonce: "24".repeat(32),
            client_public_nonce: "25".repeat(33),
            blinding_factor: "26".repeat(32),
            server_public_nonce: None,
        };
        insert_bip448_pending_deposit_signing_if_absent(&pool, &pending).await?;
        assert!(begin_bip448_sync_base_guard(&pool, &base).await.is_err());
        let inserted_base = capture_bip448_sync_base(&pool, "wallet", "51").await?;
        update_bip448_pending_deposit_server_public_nonce(
            &pool,
            "wallet",
            "statechain",
            &pending.signing_id,
            &"27".repeat(33),
        )
        .await?;
        assert!(begin_bip448_sync_base_guard(&pool, &inserted_base)
            .await
            .is_err());
        let nonce_base = capture_bip448_sync_base(&pool, "wallet", "51").await?;
        delete_bip448_pending_deposit_signing(&pool, "wallet", "statechain", &pending.signing_id)
            .await?;
        assert!(begin_bip448_sync_base_guard(&pool, &nonce_base)
            .await
            .is_err());

        let base = capture_bip448_sync_base(&pool, "wallet", "51").await?;
        let candidate = Bip448ScanCursor {
            coverage_start_height: 10,
            scan_revision: 0,
            last_scanned_height: 20,
            last_scanned_block_hash: "31".repeat(32),
        };
        let mut guard = begin_bip448_sync_base_guard(&pool, &base).await?;
        let token1 = guard
            .apply_scan_cache_and_cursor("wallet", "51", &candidate, &[])
            .await?;
        guard.commit().await?;
        assert_eq!(token1.scan_revision, 1);
        assert!(begin_bip448_sync_base_guard(&pool, &base).await.is_err());
        let base2 = capture_bip448_sync_base(&pool, "wallet", "51").await?;
        let candidate2 = Bip448ScanCursor {
            scan_revision: 1,
            ..candidate.clone()
        };
        let mut guard = begin_bip448_sync_base_guard(&pool, &base2).await?;
        let token2 = guard
            .apply_scan_cache_and_cursor("wallet", "51", &candidate2, &[])
            .await?;
        guard.commit().await?;
        assert_eq!(
            token2.scan_revision, 2,
            "same-tip semantic no-op increments revision"
        );
        let mut replacement = wallet.clone();
        replacement.blockheight += 1;
        assert!(
            !compare_and_set_wallet_after_bip448_scan(
                &pool,
                "wallet",
                &base.raw_wallet_json,
                &replacement,
                &[token1]
            )
            .await?
        );
        let live_raw = sqlx::query_scalar::<_, String>(
            "SELECT wallet_json FROM wallet WHERE wallet_name='wallet'",
        )
        .fetch_one(&pool)
        .await?;
        assert!(
            compare_and_set_wallet_after_bip448_scan(
                &pool,
                "wallet",
                &live_raw,
                &replacement,
                &[token2]
            )
            .await?
        );
        let base3 = capture_bip448_sync_base(&pool, "wallet", "51").await?;
        let lower = Bip448ScanCursor {
            coverage_start_height: 0,
            scan_revision: 2,
            ..candidate
        };
        let mut guard = begin_bip448_sync_base_guard(&pool, &base3).await?;
        let token3 = guard
            .apply_scan_cache_and_cursor("wallet", "51", &lower, &[])
            .await?;
        guard.commit().await?;
        assert_eq!(token3.scan_revision, 3);
        assert_eq!(
            load_bip448_scan_state(&pool, "wallet", "51")
                .await?
                .0
                .unwrap()
                .coverage_start_height,
            0
        );
        let expected_after_lower = sqlx::query_scalar::<_, String>(
            "SELECT wallet_json FROM wallet WHERE wallet_name='wallet'",
        )
        .fetch_one(&pool)
        .await?;
        let mut winning_wallet: Wallet = serde_json::from_str(&expected_after_lower)?;
        winning_wallet.blockheight = winning_wallet
            .blockheight
            .checked_add(1)
            .ok_or_else(|| anyhow!("wallet height overflow"))?;
        update_wallet(&pool, &winning_wallet).await?;
        let winning_raw = sqlx::query_scalar::<_, String>(
            "SELECT wallet_json FROM wallet WHERE wallet_name='wallet'",
        )
        .fetch_one(&pool)
        .await?;
        let mut losing_wallet = winning_wallet.clone();
        losing_wallet.blockheight = losing_wallet
            .blockheight
            .checked_add(1)
            .ok_or_else(|| anyhow!("wallet height overflow"))?;
        assert!(
            !compare_and_set_wallet_after_bip448_scan(
                &pool,
                "wallet",
                &expected_after_lower,
                &losing_wallet,
                std::slice::from_ref(&token3),
            )
            .await?,
            "wallet-only CAS loss must report false"
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT wallet_json FROM wallet WHERE wallet_name='wallet'"
            )
            .fetch_one(&pool)
            .await?,
            winning_raw,
            "a losing wallet CAS must not overwrite the winner"
        );
        assert!(compare_and_set_wallet_after_bip448_scan(
            &pool,
            "wallet",
            &winning_raw,
            &losing_wallet,
            &[token3.clone(), token3.clone()],
        )
        .await
        .is_err());
        sqlx::query("UPDATE bip448_scan_cursors SET scan_revision=$1 WHERE wallet_name='wallet' AND script_pubkey='51'")
            .bind(i64::MAX).execute(&pool).await?;
        let overflow_base = capture_bip448_sync_base(&pool, "wallet", "51").await?;
        let overflow = Bip448ScanCursor {
            coverage_start_height: 0,
            scan_revision: u64::try_from(i64::MAX)?,
            last_scanned_height: 21,
            last_scanned_block_hash: "32".repeat(32),
        };
        let mut guard = begin_bip448_sync_base_guard(&pool, &overflow_base).await?;
        assert!(guard
            .apply_scan_cache_and_cursor(
                "wallet",
                "51",
                &overflow,
                &[ChainUtxo {
                    txid: "33".repeat(32),
                    vout: 0,
                    value: 1,
                    height: 21
                }]
            )
            .await
            .is_err());
        drop(guard);
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT scan_revision FROM bip448_scan_cursors WHERE wallet_name='wallet' AND script_pubkey='51'").fetch_one(&pool).await?,i64::MAX);
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT COUNT(*) FROM bip448_scanned_outpoints WHERE wallet_name='wallet' AND script_pubkey='51'").fetch_one(&pool).await?,0);
        Ok(())
    }

    #[tokio::test]
    async fn bip448_pending_aba_and_wallet_cas_have_deterministic_ordering() -> Result<()> {
        let pools = independent_migrated_pools().await?;
        let wallet = sample_wallet();
        insert_wallet(&pools.first, &wallet).await?;
        let pending = Bip448PendingDepositSigning {
            wallet_name: "wallet".into(),
            statechain_id: "statechain".into(),
            funding_txid: "11".repeat(32),
            funding_vout: 0,
            funding_value_sats: 1,
            update_template_hash: "21".repeat(32),
            settlement_template_hash: "22".repeat(32),
            state_locktime: 700_000_000,
            signing_id: "23".repeat(32),
            client_secret_nonce: "24".repeat(132),
            client_public_nonce: "25".repeat(66),
            blinding_factor: "26".repeat(32),
            server_public_nonce: None,
        };

        let insert_base = capture_bip448_sync_base(&pools.second, "wallet", "51").await?;
        let mut insert_winner = begin_bip448_mutation_guard(&pools.first).await?;
        sqlx::query(
            "INSERT INTO bip448_pending_deposit_signings (wallet_name,statechain_id,\
             funding_txid,funding_vout,funding_value_sats,update_template_hash,\
             settlement_template_hash,state_locktime,signing_id,client_secret_nonce,\
             client_public_nonce,blinding_factor,server_public_nonce) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NULL)",
        )
        .bind(&pending.wallet_name)
        .bind(&pending.statechain_id)
        .bind(&pending.funding_txid)
        .bind(i64::from(pending.funding_vout))
        .bind(i64::try_from(pending.funding_value_sats)?)
        .bind(&pending.update_template_hash)
        .bind(&pending.settlement_template_hash)
        .bind(i64::from(pending.state_locktime))
        .bind(&pending.signing_id)
        .bind(&pending.client_secret_nonce)
        .bind(&pending.client_public_nonce)
        .bind(&pending.blinding_factor)
        .execute(insert_winner.connection())
        .await?;
        let (hook, loser) = spawn_sync_base_loser(pools.second.clone(), insert_base);
        commit_winner_and_assert_sync_loser_loses(hook, insert_winner, loser).await?;

        let nonce_base = capture_bip448_sync_base(&pools.second, "wallet", "51").await?;
        let mut nonce_winner = begin_bip448_mutation_guard(&pools.first).await?;
        sqlx::query(
            "UPDATE bip448_pending_deposit_signings SET server_public_nonce=$1 \
             WHERE wallet_name='wallet' AND statechain_id='statechain' AND signing_id=$2",
        )
        .bind("27".repeat(66))
        .bind(&pending.signing_id)
        .execute(nonce_winner.connection())
        .await?;
        let (hook, loser) = spawn_sync_base_loser(pools.second.clone(), nonce_base);
        commit_winner_and_assert_sync_loser_loses(hook, nonce_winner, loser).await?;

        let delete_base = capture_bip448_sync_base(&pools.second, "wallet", "51").await?;
        let mut delete_winner = begin_bip448_mutation_guard(&pools.first).await?;
        sqlx::query(
            "DELETE FROM bip448_pending_deposit_signings \
             WHERE wallet_name='wallet' AND statechain_id='statechain' AND signing_id=$1",
        )
        .bind(&pending.signing_id)
        .execute(delete_winner.connection())
        .await?;
        let (hook, loser) = spawn_sync_base_loser(pools.second.clone(), delete_base);
        commit_winner_and_assert_sync_loser_loses(hook, delete_winner, loser).await?;

        persist_bip448_scan_state(
            &pools.first,
            "wallet",
            "51",
            &Bip448ScanCursor {
                coverage_start_height: 0,
                scan_revision: 0,
                last_scanned_height: 20,
                last_scanned_block_hash: "31".repeat(32),
            },
            &[],
        )
        .await?;
        let aba_base = capture_bip448_sync_base(&pools.second, "wallet", "51").await?;
        let mut aba_winner = begin_bip448_sync_base_guard(&pools.first, &aba_base).await?;
        let token_two = aba_winner
            .apply_scan_cache_and_cursor(
                "wallet",
                "51",
                &Bip448ScanCursor {
                    coverage_start_height: 0,
                    scan_revision: 1,
                    last_scanned_height: 20,
                    last_scanned_block_hash: "31".repeat(32),
                },
                &[],
            )
            .await?;
        let (hook, loser) = spawn_sync_base_loser(pools.second.clone(), aba_base);
        commit_winner_and_assert_sync_loser_loses(hook, aba_winner, loser).await?;
        assert_eq!(token_two.scan_revision, 2);

        let expected_raw = sqlx::query_scalar::<_, String>(
            "SELECT wallet_json FROM wallet WHERE wallet_name='wallet'",
        )
        .fetch_one(&pools.first)
        .await?;
        let mut replacement = wallet.clone();
        replacement.blockheight = replacement
            .blockheight
            .checked_add(1)
            .ok_or_else(|| anyhow!("wallet height overflow"))?;
        let token_winner_base = capture_bip448_sync_base(&pools.first, "wallet", "51").await?;
        let mut token_winner =
            begin_bip448_sync_base_guard(&pools.first, &token_winner_base).await?;
        let token_three = token_winner
            .apply_scan_cache_and_cursor(
                "wallet",
                "51",
                &Bip448ScanCursor {
                    coverage_start_height: 0,
                    scan_revision: 2,
                    last_scanned_height: 20,
                    last_scanned_block_hash: "31".repeat(32),
                },
                &[],
            )
            .await?;
        let hook = Arc::new(Bip448BeginImmediateTestHook::default());
        let task_hook = hook.clone();
        let second_pool = pools.second.clone();
        let stale_expected_raw = expected_raw.clone();
        let stale_replacement = replacement.clone();
        let stale_token = token_two.clone();
        let wallet_token_loser = tokio::spawn(BIP448_BEGIN_IMMEDIATE_TEST_HOOK.scope(
            task_hook,
            async move {
                compare_and_set_wallet_after_bip448_scan(
                    &second_pool,
                    "wallet",
                    &stale_expected_raw,
                    &stale_replacement,
                    &[stale_token],
                )
                .await
            },
        ));
        assert_begin_is_contested(&hook).await?;
        token_winner.commit().await?;
        hook.after_acquire.notified().await;
        assert!(!wallet_token_loser.await??);
        assert_eq!(token_three.scan_revision, 3);

        let raw_before_wallet_winner = sqlx::query_scalar::<_, String>(
            "SELECT wallet_json FROM wallet WHERE wallet_name='wallet'",
        )
        .fetch_one(&pools.first)
        .await?;
        let mut winning_wallet = wallet.clone();
        winning_wallet.blockheight = winning_wallet
            .blockheight
            .checked_add(2)
            .ok_or_else(|| anyhow!("wallet height overflow"))?;
        let winning_json = canonical_wallet_json(&winning_wallet)?;
        let mut wallet_winner = begin_bip448_mutation_guard(&pools.first).await?;
        sqlx::query(
            "UPDATE wallet SET wallet_json=$1 WHERE wallet_name='wallet' AND wallet_json=$2",
        )
        .bind(&winning_json)
        .bind(&raw_before_wallet_winner)
        .execute(wallet_winner.connection())
        .await?;
        let hook = Arc::new(Bip448BeginImmediateTestHook::default());
        let task_hook = hook.clone();
        let second_pool = pools.second.clone();
        let losing_expected = raw_before_wallet_winner.clone();
        let losing_replacement = replacement;
        let current_token = token_three;
        let wallet_bytes_loser = tokio::spawn(BIP448_BEGIN_IMMEDIATE_TEST_HOOK.scope(
            task_hook,
            async move {
                compare_and_set_wallet_after_bip448_scan(
                    &second_pool,
                    "wallet",
                    &losing_expected,
                    &losing_replacement,
                    &[current_token],
                )
                .await
            },
        ));
        assert_begin_is_contested(&hook).await?;
        wallet_winner.commit().await?;
        hook.after_acquire.notified().await;
        assert!(!wallet_bytes_loser.await??);
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT wallet_json FROM wallet WHERE wallet_name='wallet'",
            )
            .fetch_one(&pools.first)
            .await?,
            winning_json
        );
        Ok(())
    }

    #[tokio::test]
    async fn bip448_reverse_order_sync_base_cas_preserves_every_newer_fact_and_reruns() -> Result<()>
    {
        let pools = independent_migrated_pools().await?;
        let (_, owner, script) = accepted_binding_fixture(&pools.first).await?;
        let initial_observations = [
            sample_binding_observation("34", 0, 100_000, &script),
            sample_binding_observation("11", 1, 70_000, &script),
        ];
        let bindings = reconcile_bip448_funding_bindings(
            &pools.first,
            "wallet",
            "statechain",
            &owner.to_string(),
            1,
            &initial_observations,
        )
        .await?;
        let duplicate = bindings
            .iter()
            .find(|row| row.binding_index == 1)
            .ok_or_else(|| anyhow!("duplicate fixture binding is missing"))?;
        let signed = sign_duplicate_attempt(&pools.first, duplicate).await?;
        transition_bip448_withdrawal_broadcast_status(
            &pools.first,
            "wallet",
            "statechain",
            1,
            &signed.signing_id,
            Bip448BroadcastStatus::NotBroadcast,
            Bip448BroadcastStatus::Accepted,
        )
        .await?;
        persist_bip448_scan_state(
            &pools.first,
            "wallet",
            &script,
            &Bip448ScanCursor {
                coverage_start_height: 10,
                scan_revision: 0,
                last_scanned_height: 20,
                last_scanned_block_hash: "51".repeat(32),
            },
            &[],
        )
        .await?;
        let (older_base, newer_base) = tokio::try_join!(
            capture_bip448_sync_base(&pools.first, "wallet", &script),
            capture_bip448_sync_base(&pools.second, "wallet", &script),
        )?;
        assert_eq!(older_base, newer_base);

        let mut absent_duplicate = sample_binding_observation("11", 1, 70_000, &script);
        absent_duplicate.observation_status = Bip448ObservationStatus::Absent;
        absent_duplicate.funding_height = None;
        absent_duplicate.last_scanned_height = 21;
        let mut newer_canonical = sample_binding_observation("34", 0, 100_000, &script);
        newer_canonical.last_scanned_height = 21;
        let mut newer_guard = begin_bip448_sync_base_guard(&pools.first, &newer_base).await?;
        newer_guard
            .reconcile_funding_bindings(
                "wallet",
                "statechain",
                &owner.to_string(),
                1,
                &[newer_canonical, absent_duplicate],
            )
            .await?;
        newer_guard
            .update_withdrawal_broadcast_status(
                "wallet",
                "statechain",
                1,
                &signed.signing_id,
                Bip448BroadcastStatus::Accepted,
                Bip448BroadcastStatus::NeedsRebroadcast,
            )
            .await?;
        newer_guard
            .apply_scan_cache_and_cursor(
                "wallet",
                &script,
                &Bip448ScanCursor {
                    coverage_start_height: 10,
                    scan_revision: 1,
                    last_scanned_height: 21,
                    last_scanned_block_hash: "52".repeat(32),
                },
                &[],
            )
            .await?;
        let hook = Arc::new(Bip448BeginImmediateTestHook::default());
        let task_hook = hook.clone();
        let second_pool = pools.second.clone();
        let older_task = tokio::spawn(
            BIP448_BEGIN_IMMEDIATE_TEST_HOOK.scope(task_hook, async move {
                begin_bip448_sync_base_guard(&second_pool, &older_base).await
            }),
        );
        assert_begin_is_contested(&hook).await?;
        newer_guard.commit().await?;
        hook.after_acquire.notified().await;
        assert!(
            older_task.await?.is_err(),
            "the older observation candidate must lose its full SyncBase CAS"
        );
        let durable_binding = get_bip448_funding_binding(&pools.first, "wallet", "statechain", 1)
            .await?
            .ok_or_else(|| anyhow!("duplicate binding disappeared"))?;
        assert_eq!(
            durable_binding.observation_status,
            Bip448ObservationStatus::Absent
        );
        assert_eq!(
            get_bip448_withdrawal_attempt(&pools.first, "wallet", "statechain", 1)
                .await?
                .ok_or_else(|| anyhow!("signed attempt disappeared"))?
                .broadcast_status,
            Bip448BroadcastStatus::NeedsRebroadcast
        );
        assert_eq!(
            load_bip448_scan_state(&pools.first, "wallet", &script)
                .await?
                .0
                .ok_or_else(|| anyhow!("scan cursor disappeared"))?
                .scan_revision,
            2
        );

        let rerun_base = capture_bip448_sync_base(&pools.second, "wallet", &script).await?;
        let mut rerun_guard = begin_bip448_sync_base_guard(&pools.second, &rerun_base).await?;
        let mut rerun_canonical = sample_binding_observation("34", 0, 100_000, &script);
        rerun_canonical.last_scanned_height = 22;
        let mut rerun_duplicate = sample_binding_observation("11", 1, 70_000, &script);
        rerun_duplicate.last_scanned_height = 22;
        rerun_guard
            .reconcile_funding_bindings(
                "wallet",
                "statechain",
                &owner.to_string(),
                1,
                &[rerun_canonical, rerun_duplicate],
            )
            .await?;
        rerun_guard
            .update_withdrawal_broadcast_status(
                "wallet",
                "statechain",
                1,
                &signed.signing_id,
                Bip448BroadcastStatus::NeedsRebroadcast,
                Bip448BroadcastStatus::Accepted,
            )
            .await?;
        rerun_guard
            .apply_scan_cache_and_cursor(
                "wallet",
                &script,
                &Bip448ScanCursor {
                    coverage_start_height: 10,
                    scan_revision: 2,
                    last_scanned_height: 22,
                    last_scanned_block_hash: "53".repeat(32),
                },
                &[],
            )
            .await?;
        rerun_guard.commit().await?;
        assert_eq!(
            get_bip448_funding_binding(&pools.first, "wallet", "statechain", 1)
                .await?
                .ok_or_else(|| anyhow!("rerun binding disappeared"))?
                .observation_status,
            Bip448ObservationStatus::Confirmed
        );
        assert_eq!(
            get_bip448_withdrawal_attempt(&pools.first, "wallet", "statechain", 1)
                .await?
                .ok_or_else(|| anyhow!("rerun attempt disappeared"))?
                .broadcast_status,
            Bip448BroadcastStatus::Accepted
        );
        assert_eq!(
            load_bip448_scan_state(&pools.first, "wallet", &script)
                .await?
                .0
                .ok_or_else(|| anyhow!("rerun cursor disappeared"))?
                .scan_revision,
            3
        );
        Ok(())
    }

    #[tokio::test]
    async fn bip448_lower_coverage_floor_preserves_durable_bindings_and_attempts() -> Result<()> {
        let pool = migrated_pool().await?;
        let (_, owner, script) = accepted_binding_fixture(&pool).await?;
        let bindings = reconcile_bip448_funding_bindings(
            &pool,
            "wallet",
            "statechain",
            &owner.to_string(),
            1,
            &[
                sample_binding_observation("34", 0, 100_000, &script),
                sample_binding_observation("11", 1, 70_000, &script),
            ],
        )
        .await?;
        let duplicate = bindings
            .iter()
            .find(|row| row.binding_index == 1)
            .ok_or_else(|| anyhow!("duplicate fixture binding is missing"))?;
        insert_bip448_withdrawal_attempt_if_absent(&pool, &sample_duplicate_attempt(duplicate))
            .await?;
        persist_bip448_scan_state(
            &pool,
            "wallet",
            &script,
            &Bip448ScanCursor {
                coverage_start_height: 10,
                scan_revision: 0,
                last_scanned_height: 20,
                last_scanned_block_hash: "54".repeat(32),
            },
            &[ChainUtxo {
                txid: "55".repeat(32),
                vout: 0,
                value: 42,
                height: 20,
            }],
        )
        .await?;
        let bindings_before = list_bip448_funding_bindings(&pool, "wallet", "statechain").await?;
        let attempts_before =
            list_bip448_withdrawal_attempts(&pool, "wallet", "statechain").await?;
        let base = capture_bip448_sync_base(&pool, "wallet", &script).await?;
        let mut guard = begin_bip448_sync_base_guard(&pool, &base).await?;
        let token = guard
            .apply_scan_cache_and_cursor(
                "wallet",
                &script,
                &Bip448ScanCursor {
                    coverage_start_height: 0,
                    scan_revision: 1,
                    last_scanned_height: 21,
                    last_scanned_block_hash: "56".repeat(32),
                },
                &[],
            )
            .await?;
        guard.commit().await?;
        assert_eq!(token.scan_revision, 2);
        let (cursor, cache) = load_bip448_scan_state(&pool, "wallet", &script).await?;
        let cursor = cursor.ok_or_else(|| anyhow!("lower-floor cursor disappeared"))?;
        assert_eq!(cursor.coverage_start_height, 0);
        assert_eq!(cursor.scan_revision, 2);
        assert!(cache.is_empty(), "lower-floor apply replaces current cache");
        assert_eq!(
            list_bip448_funding_bindings(&pool, "wallet", "statechain").await?,
            bindings_before
        );
        assert_eq!(
            list_bip448_withdrawal_attempts(&pool, "wallet", "statechain").await?,
            attempts_before
        );
        Ok(())
    }

    #[tokio::test]
    async fn bip448_transfer_intent_successors_reactivation_and_stale_workers_are_guarded(
    ) -> Result<()> {
        let pool = migrated_pool().await?;
        let (record, _, _) = accepted_binding_fixture(&pool).await?;
        let root = sample_transfer_intent("a1");
        let mut boundary = root.clone();
        boundary.phase = Bip448TransferIntentPhase::X1Stored;
        boundary.state_signing_phase = Bip448TransferStateSigningPhase::NotStarted;
        assert!(intent_is_directly_supersedable(&boundary));
        boundary.state_signing_phase = Bip448TransferStateSigningPhase::FirstArmed;
        assert!(!intent_is_directly_supersedable(&boundary));
        boundary.state_signing_phase = Bip448TransferStateSigningPhase::NonceStored;
        assert!(!intent_is_directly_supersedable(&boundary));
        boundary.state_signing_phase = Bip448TransferStateSigningPhase::SecondArmed;
        assert!(!intent_is_directly_supersedable(&boundary));
        boundary.state_signing_phase = Bip448TransferStateSigningPhase::Signed;
        assert!(intent_is_directly_supersedable(&boundary));
        let persisted = insert_bip448_transfer_intent_if_absent(&pool, &root).await?;
        assert_eq!(
            insert_bip448_transfer_intent_if_absent(&pool, &root).await?,
            persisted
        );
        let mut immutable_conflict = root.clone();
        immutable_conflict.recipient_address = "different".into();
        assert!(
            insert_bip448_transfer_intent_if_absent(&pool, &immutable_conflict)
                .await
                .is_err()
        );
        arm_bip448_transfer_sender(&pool, "wallet", "statechain", &root.intent_id).await?;
        let mut premature = sample_transfer_intent("a2");
        premature.predecessor_intent_id = Some(root.intent_id.clone());
        assert!(
            supersede_bip448_transfer_intent(&pool, &root.intent_id, &premature)
                .await
                .is_err()
        );
        let x1 = "01".repeat(32);
        store_bip448_transfer_server_x1(&pool, "wallet", "statechain", &root.intent_id, &x1)
            .await?;
        let successor =
            supersede_bip448_transfer_intent(&pool, &root.intent_id, &premature).await?;
        assert_eq!(
            successor.predecessor_intent_id.as_deref(),
            Some(root.intent_id.as_str())
        );
        assert!(
            arm_bip448_transfer_sender(&pool, "wallet", "statechain", &root.intent_id)
                .await
                .is_err(),
            "a superseded predecessor worker must lose its activity CAS"
        );
        let reactivated =
            reject_bip448_transfer_intent_and_reactivate_predecessor(&pool, &successor)
                .await?
                .expect("direct predecessor reactivated");
        assert_eq!(reactivated.intent_id, root.intent_id);
        assert_eq!(reactivated.phase, Bip448TransferIntentPhase::X1Stored);
        assert_eq!(reactivated.server_x1.as_deref(), Some(x1.as_str()));

        let wallet = get_wallet(&pool, "wallet").await?;
        let receiver = secp256k1::PublicKey::from_str(&root.receiver_user_pubkey)?;
        let state_two = real_fixture_state_for_owner(
            &wallet,
            &record,
            receiver.x_only_public_key().0,
            2,
            record.latest_state.state_locktime + 1,
        )?;
        let pending = Bip448PendingDepositSigning {
            wallet_name: "wallet".into(),
            statechain_id: "statechain".into(),
            funding_txid: record.funding_outpoint.txid.clone(),
            funding_vout: record.funding_outpoint.vout,
            funding_value_sats: record.funding_outpoint.value_sats,
            update_template_hash: state_two.update_template_hash.clone(),
            settlement_template_hash: state_two.settlement_template_hash.clone(),
            state_locktime: state_two.state_locktime,
            signing_id: state_two.signing_metadata.signing_id.clone(),
            client_secret_nonce: "44".repeat(132),
            client_public_nonce: state_two.signing_metadata.client_public_nonce.clone(),
            blinding_factor: state_two.signing_metadata.blinding_factor.clone(),
            server_public_nonce: None,
        };
        install_bip448_transfer_target_pending_signing(&pool, &root.intent_id, &pending).await?;
        store_bip448_transfer_state_nonce(
            &pool,
            "wallet",
            "statechain",
            &root.intent_id,
            &pending.signing_id,
            &state_two.signing_metadata.server_public_nonce,
        )
        .await?;
        arm_bip448_transfer_state_sign_second(
            &pool,
            "wallet",
            "statechain",
            &root.intent_id,
            &pending.signing_id,
        )
        .await?;
        store_signed_bip448_transfer_state(
            &pool,
            "wallet",
            "statechain",
            &root.intent_id,
            &pending.signing_id,
            &"48".repeat(32),
            &state_two.signing_metadata.update_signature,
        )
        .await?;
        let active = get_active_bip448_transfer_intent(&pool, "wallet", "statechain")
            .await?
            .unwrap();
        assert_eq!(
            active.state_signing_phase,
            Bip448TransferStateSigningPhase::Signed
        );
        let mut post_sign_plan = sample_transfer_intent("a3");
        post_sign_plan.predecessor_intent_id = Some(root.intent_id.clone());
        post_sign_plan.expected_signature_count = 2;
        post_sign_plan.planned_state_number = 3;
        post_sign_plan.previous_locktime = pending.state_locktime;
        post_sign_plan.prior_pending_signing_id = Some(pending.signing_id.clone());
        post_sign_plan.clear_local_attempt = true;
        assert!(
            supersede_bip448_transfer_intent(&pool, &root.intent_id, &post_sign_plan)
                .await
                .is_err(),
            "Signed retarget must first materialize exact history and outgoing message"
        );
        let state_two_entry = history_entry(&state_two, receiver.x_only_public_key().0);
        insert_bip448_state_history_entry(&pool, "wallet", "statechain", &state_two_entry).await?;
        let complete_history = get_bip448_state_history(&pool, "wallet", "statechain").await?;
        let mut message = sample_bip448_transfer_msg();
        message.statechain_id = "statechain".into();
        message.receiver_user_public_key = root.receiver_user_pubkey.clone();
        message.aggregate_pubkey = record.aggregate_pubkey.clone();
        message.funding_outpoint = record.funding_outpoint.clone();
        message.latest_state = state_two;
        message.latest_state_number = 2;
        message.challenge_delay = record.challenge_delay;
        message.amount_sats = record.amount_sats;
        message.network = record.network.clone();
        message.value_schedule = message.latest_state.value_schedule.clone();
        message.server_signature_count = 2;
        message.state_history = complete_history;
        insert_or_update_bip448_transfer_msg(
            &pool,
            "wallet",
            &root.recipient_auth_pubkey,
            &message,
        )
        .await?;
        post_sign_plan.prior_transfer_recipient_auth_pubkey =
            Some(root.recipient_auth_pubkey.clone());
        post_sign_plan.prior_transfer_msg_hash =
            Some(sha256::Hash::hash(serde_json::to_string(&message)?.as_bytes()).to_string());
        let post_sign =
            supersede_bip448_transfer_intent(&pool, &root.intent_id, &post_sign_plan).await?;
        assert_eq!(
            list_bip448_transfer_intents(&pool, "wallet", "statechain")
                .await?
                .len(),
            2,
            "the predecessor chain remains durable through successor state signing"
        );
        arm_bip448_transfer_sender(&pool, "wallet", "statechain", &post_sign.intent_id).await?;
        store_bip448_transfer_server_x1(
            &pool,
            "wallet",
            "statechain",
            &post_sign.intent_id,
            &"02".repeat(32),
        )
        .await?;
        let successor_receiver = secp256k1::PublicKey::from_str(&post_sign.receiver_user_pubkey)?;
        let state_three = real_fixture_state_for_owner(
            &wallet,
            &record,
            successor_receiver.x_only_public_key().0,
            3,
            pending.state_locktime + 1,
        )?;
        let successor_pending = Bip448PendingDepositSigning {
            wallet_name: "wallet".into(),
            statechain_id: "statechain".into(),
            funding_txid: record.funding_outpoint.txid.clone(),
            funding_vout: record.funding_outpoint.vout,
            funding_value_sats: record.funding_outpoint.value_sats,
            update_template_hash: state_three.update_template_hash.clone(),
            settlement_template_hash: state_three.settlement_template_hash.clone(),
            state_locktime: state_three.state_locktime,
            signing_id: state_three.signing_metadata.signing_id.clone(),
            client_secret_nonce: "45".repeat(132),
            client_public_nonce: state_three.signing_metadata.client_public_nonce.clone(),
            blinding_factor: state_three.signing_metadata.blinding_factor.clone(),
            server_public_nonce: None,
        };
        install_bip448_transfer_target_pending_signing(
            &pool,
            &post_sign.intent_id,
            &successor_pending,
        )
        .await?;
        assert!(
            !has_bip448_transfer_msg_for_statechain(&pool, "wallet", "statechain").await?,
            "target-pending installation compare-deletes the fingerprinted predecessor message"
        );
        let mut accepted_connection = pool.acquire().await?;
        let (_, replacement_window_history) =
            accepted_record_and_history_on(&mut accepted_connection, "wallet", "statechain")
                .await?;
        assert_eq!(
            replacement_window_history.len(),
            2,
            "the N+1 suffix remains journal-proven while the N+2 target is FirstArmed"
        );
        drop(accepted_connection);
        store_bip448_transfer_state_nonce(
            &pool,
            "wallet",
            "statechain",
            &post_sign.intent_id,
            &successor_pending.signing_id,
            &state_three.signing_metadata.server_public_nonce,
        )
        .await?;
        arm_bip448_transfer_state_sign_second(
            &pool,
            "wallet",
            "statechain",
            &post_sign.intent_id,
            &successor_pending.signing_id,
        )
        .await?;
        store_signed_bip448_transfer_state(
            &pool,
            "wallet",
            "statechain",
            &post_sign.intent_id,
            &successor_pending.signing_id,
            &"49".repeat(32),
            &state_three.signing_metadata.update_signature,
        )
        .await?;
        let signed_successor = get_active_bip448_transfer_intent(&pool, "wallet", "statechain")
            .await?
            .ok_or_else(|| anyhow!("signed successor disappeared"))?;
        let mut state_three_history = replacement_window_history;
        state_three_history.push(history_entry(
            &state_three,
            successor_receiver.x_only_public_key().0,
        ));
        let mut state_three_message = sample_bip448_transfer_msg();
        state_three_message.statechain_id = "statechain".into();
        state_three_message.receiver_user_public_key = post_sign.receiver_user_pubkey.clone();
        state_three_message.aggregate_pubkey = record.aggregate_pubkey.clone();
        state_three_message.funding_outpoint = record.funding_outpoint.clone();
        state_three_message.latest_state = state_three;
        state_three_message.latest_state_number = 3;
        state_three_message.challenge_delay = record.challenge_delay;
        state_three_message.amount_sats = record.amount_sats;
        state_three_message.network = record.network.clone();
        state_three_message.value_schedule =
            state_three_message.latest_state.value_schedule.clone();
        state_three_message.server_signature_count = 3;
        state_three_message.state_history = state_three_history;
        let signed_successor_pending =
            get_bip448_pending_transfer_signing(&pool, "wallet", "statechain")
                .await?
                .ok_or_else(|| anyhow!("signed successor pending row disappeared"))?;
        let alternate_secret_nonce = "46".repeat(132);
        assert_ne!(
            alternate_secret_nonce,
            signed_successor_pending.client_secret_nonce
        );
        assert_eq!(
            sqlx::query(
                "UPDATE bip448_pending_transfer_signings SET client_secret_nonce=$1 \
                 WHERE wallet_name='wallet' AND statechain_id='statechain' \
                 AND client_secret_nonce=$2"
            )
            .bind(&alternate_secret_nonce)
            .bind(&signed_successor_pending.client_secret_nonce)
            .execute(&pool)
            .await?
            .rows_affected(),
            1
        );
        let materialization_error = materialize_bip448_signed_transfer_intent(
            &pool,
            &signed_successor,
            &signed_successor_pending,
            &state_three_message,
        )
        .await
        .unwrap_err();
        assert!(materialization_error
            .to_string()
            .contains("pending signing changed after complete validation"));
        assert_eq!(
            get_bip448_state_history(&pool, "wallet", "statechain")
                .await?
                .len(),
            2,
            "new-message materialization mismatch must not append history"
        );
        assert!(
            !has_bip448_transfer_msg_for_statechain(&pool, "wallet", "statechain").await?,
            "new-message materialization mismatch must not insert a message"
        );
        assert_eq!(
            get_active_bip448_transfer_intent(&pool, "wallet", "statechain").await?,
            Some(signed_successor.clone()),
            "new-message materialization mismatch must not change the intent"
        );
        assert_eq!(
            sqlx::query(
                "UPDATE bip448_pending_transfer_signings SET client_secret_nonce=$1 \
                 WHERE wallet_name='wallet' AND statechain_id='statechain' \
                 AND client_secret_nonce=$2"
            )
            .bind(&signed_successor_pending.client_secret_nonce)
            .bind(&alternate_secret_nonce)
            .execute(&pool)
            .await?
            .rows_affected(),
            1
        );
        let materialized_json = materialize_bip448_signed_transfer_intent(
            &pool,
            &signed_successor,
            &signed_successor_pending,
            &state_three_message,
        )
        .await?;
        let materialized_history = get_bip448_state_history(&pool, "wallet", "statechain").await?;
        assert_eq!(
            sqlx::query(
                "UPDATE bip448_pending_transfer_signings SET client_secret_nonce=$1 \
                 WHERE wallet_name='wallet' AND statechain_id='statechain' \
                 AND client_secret_nonce=$2"
            )
            .bind(&alternate_secret_nonce)
            .bind(&signed_successor_pending.client_secret_nonce)
            .execute(&pool)
            .await?
            .rows_affected(),
            1
        );
        let replay_error = materialize_bip448_signed_transfer_intent(
            &pool,
            &signed_successor,
            &signed_successor_pending,
            &state_three_message,
        )
        .await
        .unwrap_err();
        assert!(replay_error
            .to_string()
            .contains("pending signing changed after complete validation"));
        assert_eq!(
            get_bip448_state_history(&pool, "wallet", "statechain").await?,
            materialized_history,
            "stored-message replay mismatch must not change history"
        );
        assert_eq!(
            get_bip448_transfer_msg_raw_optional(&pool, "wallet", "statechain", None)
                .await?
                .map(|(_, raw)| raw),
            Some(materialized_json.clone()),
            "stored-message replay mismatch must not replace the message"
        );
        assert_eq!(
            sqlx::query(
                "UPDATE bip448_pending_transfer_signings SET client_secret_nonce=$1 \
                 WHERE wallet_name='wallet' AND statechain_id='statechain' \
                 AND client_secret_nonce=$2"
            )
            .bind(&signed_successor_pending.client_secret_nonce)
            .bind(&alternate_secret_nonce)
            .execute(&pool)
            .await?
            .rows_affected(),
            1
        );
        assert_eq!(
            materialize_bip448_signed_transfer_intent(
                &pool,
                &signed_successor,
                &signed_successor_pending,
                &state_three_message,
            )
            .await?,
            materialized_json,
            "restored complete pending row must permit exact stored-message replay"
        );
        assert_eq!(
            get_bip448_state_history(&pool, "wallet", "statechain")
                .await?
                .len(),
            3,
            "successor materialization consumes the already-recorded predecessor fingerprint once"
        );

        let mut orphan = sample_transfer_intent("a4");
        orphan.activity_status = Bip448TransferIntentActivityStatus::Superseded;
        let mut connection = pool.acquire().await?;
        insert_transfer_intent_on(&mut connection, &orphan).await?;
        drop(connection);
        assert!(
            get_active_bip448_transfer_intent(&pool, "wallet", "statechain")
                .await
                .is_err()
        );
        assert!(
            reject_bip448_transfer_intent_and_reactivate_predecessor(&pool, &post_sign)
                .await
                .is_err(),
            "corrupt lineage blocks even otherwise legal cleanup"
        );
        Ok(())
    }

    #[tokio::test]
    async fn bip448_every_corrupt_transfer_lineage_blocks_attempt_and_close() -> Result<()> {
        let active = sample_transfer_intent("b1");
        let mut orphan = sample_transfer_intent("b2");
        orphan.activity_status = Bip448TransferIntentActivityStatus::Superseded;
        assert_corrupt_transfer_lineage_blocks(&[active, orphan], false).await?;

        let mut missing = sample_transfer_intent("b3");
        missing.predecessor_intent_id = Some("b4".repeat(32));
        assert_corrupt_transfer_lineage_blocks(&[missing], false).await?;

        let mut cycle_active = sample_transfer_intent("b5");
        cycle_active.predecessor_intent_id = Some("b6".repeat(32));
        let mut cycle_predecessor = sample_transfer_intent("b6");
        cycle_predecessor.predecessor_intent_id = Some(cycle_active.intent_id.clone());
        cycle_predecessor.activity_status = Bip448TransferIntentActivityStatus::Superseded;
        assert_corrupt_transfer_lineage_blocks(&[cycle_active, cycle_predecessor], false).await?;

        assert_corrupt_transfer_lineage_blocks(
            &[sample_transfer_intent("b7"), sample_transfer_intent("b8")],
            true,
        )
        .await?;
        Ok(())
    }

    #[tokio::test]
    async fn bip448_accepted_local_outgoing_reconciliation_is_exact_and_conservative() -> Result<()>
    {
        let (pool, _, _recipient_auth, _message) = accepted_local_outgoing_fixture().await?;
        assert_eq!(
            reconcile_bip448_accepted_local_outgoing_messages(&pool, "wallet", "statechain")
                .await?,
            1
        );
        assert!(!has_bip448_transfer_msg_for_statechain(&pool, "wallet", "statechain").await?);

        let (pending_pool, pending_record, _, pending_message) =
            accepted_local_outgoing_fixture().await?;
        let pending_entry = pending_message
            .state_history
            .last()
            .ok_or_else(|| anyhow!("accepted-prefix fixture history is empty"))?;
        let pending = Bip448PendingDepositSigning {
            wallet_name: "wallet".into(),
            statechain_id: "statechain".into(),
            funding_txid: pending_record.funding_outpoint.txid.clone(),
            funding_vout: pending_record.funding_outpoint.vout,
            funding_value_sats: pending_record.funding_outpoint.value_sats,
            update_template_hash: pending_entry.update_template_hash.clone(),
            settlement_template_hash: pending_entry.settlement_template_hash.clone(),
            state_locktime: pending_entry.state_locktime,
            signing_id: pending_message
                .latest_state
                .signing_metadata
                .signing_id
                .clone(),
            client_secret_nonce: "ab".repeat(132),
            client_public_nonce: pending_entry.client_public_nonce.clone(),
            blinding_factor: pending_entry.blinding_factor.clone(),
            server_public_nonce: Some(pending_entry.server_public_nonce.clone()),
        };
        insert_bip448_pending_transfer_signing_if_absent(&pending_pool, &pending).await?;
        assert_eq!(
            reconcile_bip448_accepted_local_outgoing_messages(
                &pending_pool,
                "wallet",
                "statechain"
            )
            .await?,
            1
        );
        assert!(
            get_bip448_pending_transfer_signing(&pending_pool, "wallet", "statechain")
                .await?
                .is_none(),
            "the exact accepted-prefix pending signing must be deleted atomically"
        );

        let (conflicting_pending_pool, conflicting_record, _, conflicting_message) =
            accepted_local_outgoing_fixture().await?;
        let conflicting_entry = conflicting_message
            .state_history
            .last()
            .ok_or_else(|| anyhow!("accepted-prefix fixture history is empty"))?;
        let conflicting_pending = Bip448PendingDepositSigning {
            wallet_name: "wallet".into(),
            statechain_id: "statechain".into(),
            funding_txid: conflicting_record.funding_outpoint.txid.clone(),
            funding_vout: conflicting_record.funding_outpoint.vout,
            funding_value_sats: conflicting_record.funding_outpoint.value_sats,
            update_template_hash: conflicting_entry.update_template_hash.clone(),
            settlement_template_hash: conflicting_entry.settlement_template_hash.clone(),
            state_locktime: conflicting_entry.state_locktime,
            signing_id: conflicting_message
                .latest_state
                .signing_metadata
                .signing_id
                .clone(),
            client_secret_nonce: "ab".repeat(132),
            client_public_nonce: "55".repeat(66),
            blinding_factor: conflicting_entry.blinding_factor.clone(),
            server_public_nonce: Some(conflicting_entry.server_public_nonce.clone()),
        };
        insert_bip448_pending_transfer_signing_if_absent(
            &conflicting_pending_pool,
            &conflicting_pending,
        )
        .await?;
        assert!(reconcile_bip448_accepted_local_outgoing_messages(
            &conflicting_pending_pool,
            "wallet",
            "statechain"
        )
        .await
        .is_err());
        assert!(
            has_bip448_transfer_msg_for_statechain(
                &conflicting_pending_pool,
                "wallet",
                "statechain"
            )
            .await?
        );
        assert!(
            get_bip448_pending_transfer_signing(&conflicting_pending_pool, "wallet", "statechain")
                .await?
                .is_some(),
            "a conflicting pending signing must roll back accepted-prefix cleanup"
        );

        let (pool, record, recipient_auth, message) = accepted_local_outgoing_fixture().await?;
        let stored_json = serde_json::to_string(&message)?;
        let mut active = sample_transfer_intent("c1");
        active.expected_signature_count = 2;
        active.planned_state_number = 3;
        active.previous_locktime = record.latest_state.state_locktime;
        active.prior_transfer_recipient_auth_pubkey = Some(recipient_auth.clone());
        active.prior_transfer_msg_hash =
            Some(sha256::Hash::hash(stored_json.as_bytes()).to_string());
        active.clear_local_attempt = true;
        insert_bip448_transfer_intent_if_absent(&pool, &active).await?;
        assert_eq!(
            reconcile_bip448_accepted_local_outgoing_messages(&pool, "wallet", "statechain")
                .await?,
            0,
            "an intent-referenced message must be retained"
        );
        assert!(has_bip448_transfer_msg_for_statechain(&pool, "wallet", "statechain").await?);

        let suffix_pool = migrated_pool().await?;
        let (suffix_record, _, _) = accepted_binding_fixture(&suffix_pool).await?;
        let (receiver, _) = sample_owner_key(2);
        let (auth, _) = sample_owner_key(3);
        let suffix_wallet = get_wallet(&suffix_pool, "wallet").await?;
        let state_two = real_fixture_state_for_owner(
            &suffix_wallet,
            &suffix_record,
            receiver.x_only_public_key().0,
            2,
            suffix_record.latest_state.state_locktime + 1,
        )?;
        let entry_two = history_entry(&state_two, receiver.x_only_public_key().0);
        insert_bip448_state_history_entry(&suffix_pool, "wallet", "statechain", &entry_two).await?;
        let suffix_history = get_bip448_state_history(&suffix_pool, "wallet", "statechain").await?;
        let suffix_message = exact_transfer_message(
            &suffix_record,
            state_two,
            &receiver.to_string(),
            suffix_history,
        );
        insert_or_update_bip448_transfer_msg(
            &suffix_pool,
            "wallet",
            &auth.to_string(),
            &suffix_message,
        )
        .await?;
        assert_eq!(
            reconcile_bip448_accepted_local_outgoing_messages(&suffix_pool, "wallet", "statechain")
                .await?,
            0,
            "the journal-proven current sender suffix is not an accepted local prefix"
        );
        assert!(
            has_bip448_transfer_msg_for_statechain(&suffix_pool, "wallet", "statechain").await?
        );

        let (malformed_pool, _, malformed_recipient, malformed_message) =
            accepted_local_outgoing_fixture().await?;
        sqlx::query(
            "UPDATE bip448_transfer_messages SET transfer_msg_json='{' \
             WHERE wallet_name='wallet' AND statechain_id='statechain'",
        )
        .execute(&malformed_pool)
        .await?;
        assert!(reconcile_bip448_accepted_local_outgoing_messages(
            &malformed_pool,
            "wallet",
            "statechain"
        )
        .await
        .is_err());
        assert!(
            has_bip448_transfer_msg_for_statechain(&malformed_pool, "wallet", "statechain").await?
        );
        let mut wrong_statechain = malformed_message;
        wrong_statechain.statechain_id = "other-statechain".into();
        let wrong_json = serde_json::to_string(&wrong_statechain)?;
        sqlx::query(
            "UPDATE bip448_transfer_messages SET transfer_msg_json=$1 \
             WHERE wallet_name='wallet' AND statechain_id='statechain' \
             AND recipient_auth_pubkey=$2",
        )
        .bind(wrong_json)
        .bind(&malformed_recipient)
        .execute(&malformed_pool)
        .await?;
        assert!(reconcile_bip448_accepted_local_outgoing_messages(
            &malformed_pool,
            "wallet",
            "statechain"
        )
        .await
        .is_err());

        let (conflict_pool, _, first_recipient, conflict_message) =
            accepted_local_outgoing_fixture().await?;
        let mut wallet = get_wallet(&conflict_pool, "wallet").await?;
        let mut second_coin = wallet.get_new_coin()?;
        second_coin.user_pubkey = conflict_message.receiver_user_public_key.clone();
        second_coin.statechain_protocol = Some("bip448".into());
        second_coin.statechain_id = Some("statechain".into());
        second_coin.status = CoinStatus::CONFIRMED;
        let second_recipient = second_coin.auth_pubkey.clone();
        assert_ne!(second_recipient, first_recipient);
        wallet.coins.push(second_coin);
        update_wallet(&conflict_pool, &wallet).await?;
        insert_or_update_bip448_transfer_msg(
            &conflict_pool,
            "wallet",
            &second_recipient,
            &conflict_message,
        )
        .await?;
        assert!(reconcile_bip448_accepted_local_outgoing_messages(
            &conflict_pool,
            "wallet",
            "statechain"
        )
        .await
        .is_err());
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM bip448_transfer_messages \
                 WHERE wallet_name='wallet' AND statechain_id='statechain'",
            )
            .fetch_one(&conflict_pool)
            .await?,
            2,
            "conflicting rows must roll back without partial deletion"
        );
        Ok(())
    }

    #[tokio::test]
    async fn bip448_cross_wallet_receiver_without_local_outgoing_row_deletes_nothing() -> Result<()>
    {
        let (pool, _, recipient_auth, _) = accepted_local_outgoing_fixture().await?;
        let deleted = sqlx::query(
            "DELETE FROM bip448_transfer_messages WHERE wallet_name='wallet' \
             AND statechain_id='statechain' AND recipient_auth_pubkey=$1",
        )
        .bind(recipient_auth)
        .execute(&pool)
        .await?;
        assert_eq!(deleted.rows_affected(), 1);
        let wallet_before = get_bip448_raw_wallet_json(&pool, "wallet").await?;

        assert_eq!(
            reconcile_bip448_accepted_local_outgoing_messages(&pool, "wallet", "statechain")
                .await?,
            0
        );
        assert_eq!(
            get_bip448_raw_wallet_json(&pool, "wallet").await?,
            wallet_before
        );
        assert!(!has_bip448_transfer_msg_for_statechain(&pool, "wallet", "statechain").await?);
        Ok(())
    }

    #[tokio::test]
    async fn bip448_cancellation_wallet_signing_acceptance_and_cleanup_are_atomic() -> Result<()> {
        let pool = migrated_pool().await?;
        let (wallet, mut record, initial_entry, _) = real_accepted_fixture(CoinStatus::CONFIRMED)?;
        let generated_coin = wallet.get_new_coin()?;
        insert_wallet(&pool, &wallet).await?;
        let generated_user = secp256k1::PublicKey::from_str(&generated_coin.user_pubkey)?;
        persist_bip448_initial_acceptance(&pool, &record, &initial_entry).await?;

        let old_raw = sqlx::query_scalar::<_, String>(
            "SELECT wallet_json FROM wallet WHERE wallet_name='wallet'",
        )
        .fetch_one(&pool)
        .await?;
        let mut replacement_wallet = wallet.clone();
        replacement_wallet.coins.push(generated_coin.clone());
        let mut cancellation = sample_transfer_intent("d1");
        cancellation.intent_kind = Bip448TransferIntentKind::Cancellation;
        cancellation.sender_signed_statechain_id = wallet.coins[0]
            .signed_statechain_id
            .clone()
            .ok_or_else(|| anyhow!("real source Coin has no statechain authorization"))?;
        cancellation.recipient_address = generated_coin.address.clone();
        cancellation.receiver_user_pubkey = generated_coin.user_pubkey.clone();
        cancellation.recipient_auth_pubkey = generated_coin.auth_pubkey.clone();
        cancellation.generated_coin_user_pubkey = Some(generated_coin.user_pubkey.clone());
        cancellation.generated_coin_auth_pubkey = Some(generated_coin.auth_pubkey.clone());
        cancellation.generated_coin_address = Some(generated_coin.address.clone());

        let mut invalid_replacement = replacement_wallet.clone();
        invalid_replacement.blockheight += 1;
        assert!(insert_bip448_cancellation_intent_with_wallet(
            &pool,
            &cancellation,
            &old_raw,
            &invalid_replacement,
        )
        .await
        .is_err());
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT wallet_json FROM wallet WHERE wallet_name='wallet'"
            )
            .fetch_one(&pool)
            .await?,
            old_raw
        );

        let rejected = insert_bip448_cancellation_intent_with_wallet(
            &pool,
            &cancellation,
            &old_raw,
            &replacement_wallet,
        )
        .await?;
        assert_eq!(
            insert_bip448_cancellation_intent_with_wallet(
                &pool,
                &cancellation,
                &old_raw,
                &replacement_wallet,
            )
            .await?,
            rejected,
            "exact replay must not append a second generated Coin"
        );
        assert!(
            reactivate_bip448_transfer_intent_predecessor_after_definitive_rejection(
                &pool, &rejected
            )
            .await?
            .is_none()
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT wallet_json FROM wallet WHERE wallet_name='wallet'"
            )
            .fetch_one(&pool)
            .await?,
            old_raw,
            "definitive rejection removes only the generated Coin"
        );
        assert!(list_bip448_transfer_intents(&pool, "wallet", "statechain")
            .await?
            .is_empty());

        cancellation.intent_id = "d2".repeat(32);
        let stored = insert_bip448_cancellation_intent_with_wallet(
            &pool,
            &cancellation,
            &old_raw,
            &replacement_wallet,
        )
        .await?;
        transition_bip448_transfer_intent_phase(
            &pool,
            "wallet",
            "statechain",
            &stored.intent_id,
            Bip448TransferIntentPhase::Prepared,
            Bip448TransferIntentPhase::SenderArmed,
        )
        .await?;
        let x1_stored = store_bip448_transfer_intent_x1(
            &pool,
            "wallet",
            "statechain",
            &stored.intent_id,
            &"01".repeat(32),
        )
        .await?;
        assert_eq!(x1_stored.phase, Bip448TransferIntentPhase::X1Stored);
        assert!(transition_bip448_transfer_intent_phase(
            &pool,
            "wallet",
            "statechain",
            &stored.intent_id,
            Bip448TransferIntentPhase::SenderArmed,
            Bip448TransferIntentPhase::Prepared,
        )
        .await
        .is_err());

        let state_two = real_fixture_state_for_owner(
            &wallet,
            &record,
            generated_user.x_only_public_key().0,
            2,
            record.latest_state.state_locktime + 1,
        )?;
        let pending = Bip448PendingDepositSigning {
            wallet_name: "wallet".into(),
            statechain_id: "statechain".into(),
            funding_txid: record.funding_outpoint.txid.clone(),
            funding_vout: record.funding_outpoint.vout,
            funding_value_sats: record.funding_outpoint.value_sats,
            update_template_hash: state_two.update_template_hash.clone(),
            settlement_template_hash: state_two.settlement_template_hash.clone(),
            state_locktime: state_two.state_locktime,
            signing_id: state_two.signing_metadata.signing_id.clone(),
            client_secret_nonce: "44".repeat(132),
            client_public_nonce: state_two.signing_metadata.client_public_nonce.clone(),
            blinding_factor: state_two.signing_metadata.blinding_factor.clone(),
            server_public_nonce: None,
        };
        let first_armed =
            install_bip448_transfer_target_pending(&pool, &stored.intent_id, &pending).await?;
        assert_eq!(
            first_armed.state_signing_phase,
            Bip448TransferStateSigningPhase::FirstArmed
        );
        let nonce_stored = store_bip448_transfer_state_nonce(
            &pool,
            "wallet",
            "statechain",
            &stored.intent_id,
            &pending.signing_id,
            &state_two.signing_metadata.server_public_nonce,
        )
        .await?;
        assert_eq!(
            nonce_stored.state_signing_phase,
            Bip448TransferStateSigningPhase::NonceStored
        );
        assert!(store_bip448_transfer_state_nonce(
            &pool,
            "wallet",
            "statechain",
            &stored.intent_id,
            &pending.signing_id,
            &state_two.signing_metadata.server_public_nonce,
        )
        .await
        .is_err());
        transition_bip448_transfer_state_signing_phase(
            &pool,
            "wallet",
            "statechain",
            &stored.intent_id,
            &pending.signing_id,
            Bip448TransferStateSigningPhase::NonceStored,
            Bip448TransferStateSigningPhase::SecondArmed,
        )
        .await?;
        assert!(transition_bip448_transfer_state_signing_phase(
            &pool,
            "wallet",
            "statechain",
            &stored.intent_id,
            &pending.signing_id,
            Bip448TransferStateSigningPhase::NonceStored,
            Bip448TransferStateSigningPhase::SecondArmed,
        )
        .await
        .is_err());
        let signed = store_bip448_transfer_state_signed_artifacts(
            &pool,
            "wallet",
            "statechain",
            &stored.intent_id,
            &pending.signing_id,
            &"48".repeat(32),
            &state_two.signing_metadata.update_signature,
        )
        .await?;
        assert_eq!(
            signed.state_signing_phase,
            Bip448TransferStateSigningPhase::Signed
        );
        assert!(store_bip448_transfer_state_signed_artifacts(
            &pool,
            "wallet",
            "statechain",
            &stored.intent_id,
            &pending.signing_id,
            &"48".repeat(32),
            &state_two.signing_metadata.update_signature,
        )
        .await
        .is_err());

        let state_two_entry = history_entry(&state_two, generated_user.x_only_public_key().0);
        insert_bip448_state_history_entry(&pool, "wallet", "statechain", &state_two_entry).await?;
        let complete_history = get_bip448_state_history(&pool, "wallet", "statechain").await?;
        let message = exact_transfer_message(
            &record,
            state_two.clone(),
            &generated_coin.user_pubkey,
            complete_history,
        );
        let message_json = serde_json::to_string(&message)?;
        insert_or_update_bip448_transfer_msg(
            &pool,
            "wallet",
            &generated_coin.auth_pubkey,
            &message,
        )
        .await?;
        let signed = get_active_bip448_transfer_intent(&pool, "wallet", "statechain")
            .await?
            .unwrap();
        let signed_pending = get_bip448_pending_transfer_signing(&pool, "wallet", "statechain")
            .await?
            .context("signed cancellation pending row is missing")?;
        let sender_raw = sqlx::query_scalar::<_, String>(
            "SELECT wallet_json FROM wallet WHERE wallet_name='wallet'",
        )
        .fetch_one(&pool)
        .await?;
        let mut sender_finished_wallet: Wallet = serde_json::from_str(&sender_raw)?;
        sender_finished_wallet.coins[0].status = CoinStatus::IN_TRANSFER;
        let history_before_finish = get_bip448_state_history(&pool, "wallet", "statechain").await?;
        let alternate_secret_nonce = "47".repeat(132);
        assert_ne!(alternate_secret_nonce, signed_pending.client_secret_nonce);
        assert_eq!(
            sqlx::query(
                "UPDATE bip448_pending_transfer_signings SET client_secret_nonce=$1 \
                 WHERE wallet_name='wallet' AND statechain_id='statechain' \
                 AND client_secret_nonce=$2"
            )
            .bind(&alternate_secret_nonce)
            .bind(&signed_pending.client_secret_nonce)
            .execute(&pool)
            .await?
            .rows_affected(),
            1
        );
        let finish_error = finish_bip448_cancellation_sender(
            &pool,
            &signed,
            &sender_raw,
            &sender_finished_wallet,
            &message_json,
            &signed_pending,
        )
        .await
        .unwrap_err();
        assert!(finish_error
            .to_string()
            .contains("pending signing changed after complete validation"));
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT wallet_json FROM wallet WHERE wallet_name='wallet'"
            )
            .fetch_one(&pool)
            .await?,
            sender_raw,
            "pending-row mismatch must not change sender Coin status"
        );
        assert_eq!(
            get_active_bip448_transfer_intent(&pool, "wallet", "statechain").await?,
            Some(signed.clone()),
            "pending-row mismatch must not advance the cancellation intent"
        );
        assert_eq!(
            get_bip448_state_history(&pool, "wallet", "statechain").await?,
            history_before_finish,
            "pending-row mismatch must not change history"
        );
        assert_eq!(
            get_bip448_transfer_msg_raw_optional(&pool, "wallet", "statechain", None)
                .await?
                .map(|(_, raw)| raw),
            Some(message_json.clone()),
            "pending-row mismatch must not change the materialized message"
        );
        assert_eq!(
            sqlx::query(
                "UPDATE bip448_pending_transfer_signings SET client_secret_nonce=$1 \
                 WHERE wallet_name='wallet' AND statechain_id='statechain' \
                 AND client_secret_nonce=$2"
            )
            .bind(&signed_pending.client_secret_nonce)
            .bind(&alternate_secret_nonce)
            .execute(&pool)
            .await?
            .rows_affected(),
            1
        );
        let sender_finished = finish_bip448_cancellation_sender(
            &pool,
            &signed,
            &sender_raw,
            &sender_finished_wallet,
            &message_json,
            &signed_pending,
        )
        .await?;
        assert_eq!(
            sender_finished.phase,
            Bip448TransferIntentPhase::SenderFinished
        );
        assert_eq!(
            get_bip448_pending_transfer_signing(&pool, "wallet", "statechain").await?,
            Some(signed_pending),
            "sender finish must retain the signed journal until terminal cleanup"
        );
        assert_eq!(
            list_bip448_transfer_intents(&pool, "wallet", "statechain")
                .await?
                .len(),
            1
        );

        record.latest_state_number = 2;
        record.latest_state = state_two;
        upsert_bip448_statechain_record(&pool, &record).await?;
        let mut accepted_wallet = get_wallet(&pool, "wallet").await?;
        let accepted_coin = accepted_wallet
            .coins
            .iter_mut()
            .find(|coin| coin.auth_pubkey == generated_coin.auth_pubkey)
            .unwrap();
        accepted_coin.statechain_protocol = Some("bip448".into());
        accepted_coin.statechain_id = Some("statechain".into());
        accepted_coin.signed_statechain_id = Some(mercurylib::transfer::receiver::sign_message(
            "statechain",
            accepted_coin,
        )?);
        accepted_coin.status = CoinStatus::CONFIRMED;
        let aggregate_pubkey = PublicKey::from_str(&record.aggregate_pubkey)?;
        let receiver_server_key = aggregate_pubkey.combine(&generated_user.negate())?;
        accepted_coin.server_pubkey = Some(receiver_server_key.to_string());
        accepted_coin.aggregated_pubkey = Some(record.aggregate_pubkey.clone());
        accepted_coin.utxo_txid = Some(record.funding_outpoint.txid.clone());
        accepted_coin.utxo_vout = Some(record.funding_outpoint.vout);
        accepted_coin.amount = Some(u32::try_from(record.funding_outpoint.value_sats)?);
        accepted_coin.locktime = Some(record.latest_state.state_locktime);
        accepted_coin.public_nonce = Some(
            record
                .latest_state
                .signing_metadata
                .client_public_nonce
                .clone(),
        );
        accepted_coin.server_public_nonce = Some(
            record
                .latest_state
                .signing_metadata
                .server_public_nonce
                .clone(),
        );
        accepted_coin.blinding_factor =
            Some(record.latest_state.signing_metadata.blinding_factor.clone());
        accepted_coin.aggregated_address =
            Some(bip448_deposit::create_deposit_address(accepted_coin, "regtest")?.address);
        update_wallet(&pool, &accepted_wallet).await?;
        let receiver_accepted = mark_bip448_cancellation_receiver_accepted(
            &pool,
            "wallet",
            "statechain",
            &stored.intent_id,
        )
        .await?;
        assert_eq!(
            receiver_accepted.phase,
            Bip448TransferIntentPhase::ReceiverAccepted
        );
        assert_eq!(
            mark_bip448_cancellation_receiver_accepted(
                &pool,
                "wallet",
                "statechain",
                &stored.intent_id,
            )
            .await?,
            receiver_accepted,
            "ReceiverAccepted is exact-idempotent"
        );
        let (conflicting_recipient, _) = sample_owner_key(29);
        assert_ne!(
            conflicting_recipient.to_string(),
            receiver_accepted.recipient_auth_pubkey
        );
        insert_or_update_bip448_transfer_msg(
            &pool,
            "wallet",
            &conflicting_recipient.to_string(),
            &message,
        )
        .await?;
        assert!(delete_bip448_cancellation_artifacts_after_sync(
            &pool,
            &receiver_accepted,
            &message_json,
        )
        .await
        .is_err());
        assert_eq!(
            get_active_bip448_transfer_intent(&pool, "wallet", "statechain").await?,
            Some(receiver_accepted.clone()),
            "a conflicting outgoing row must preserve ReceiverAccepted lineage"
        );
        assert!(
            get_bip448_pending_transfer_signing(&pool, "wallet", "statechain")
                .await?
                .is_some()
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM bip448_transfer_messages \
                 WHERE wallet_name='wallet' AND statechain_id='statechain'",
            )
            .fetch_one(&pool)
            .await?,
            2,
            "conflicting cancellation cleanup must not delete either message"
        );
        let removed_conflict = sqlx::query(
            "DELETE FROM bip448_transfer_messages WHERE wallet_name='wallet' \
             AND statechain_id='statechain' AND recipient_auth_pubkey=$1",
        )
        .bind(conflicting_recipient.to_string())
        .execute(&pool)
        .await?;
        assert_eq!(removed_conflict.rows_affected(), 1);
        delete_bip448_cancellation_artifacts_after_sync(&pool, &receiver_accepted, &message_json)
            .await?;
        assert!(list_bip448_transfer_intents(&pool, "wallet", "statechain")
            .await?
            .is_empty());
        assert!(!has_bip448_transfer_msg_for_statechain(&pool, "wallet", "statechain").await?);
        assert!(
            get_bip448_pending_transfer_signing(&pool, "wallet", "statechain")
                .await?
                .is_none()
        );
        assert_eq!(
            get_wallet(&pool, "wallet")
                .await?
                .coins
                .iter()
                .filter(|coin| coin.auth_pubkey == generated_coin.auth_pubkey)
                .count(),
            1,
            "terminal cleanup preserves the accepted generated Coin"
        );
        Ok(())
    }

    #[tokio::test]
    async fn bip448_begin_immediate_excludes_two_real_pool_connections() -> Result<()> {
        let pools = independent_migrated_pools().await?;
        let (_, owner, script) = accepted_binding_fixture(&pools.first).await?;
        let canonical = sample_binding_observation("34", 0, 100_000, &script);
        let duplicate = sample_binding_observation("11", 1, 70_000, &script);
        let binding = reconcile_bip448_funding_bindings(
            &pools.first,
            "wallet",
            "statechain",
            &owner.to_string(),
            1,
            &[canonical, duplicate],
        )
        .await?
        .into_iter()
        .find(|row| row.binding_index == 1)
        .unwrap();
        let first = sample_duplicate_attempt(&binding);
        let mut second = first.clone();
        second.signing_id = "75".repeat(32);
        second.client_secret_nonce = "76".repeat(132);
        refresh_attempt_sign_first_payload(&mut second);

        let mut first_guard = begin_bip448_mutation_guard(&pools.first).await?;
        first_guard
            .insert_withdrawal_attempt_if_absent(&first)
            .await?;
        let hook = Arc::new(Bip448BeginImmediateTestHook::default());
        let task_hook = hook.clone();
        let second_pool = pools.second.clone();
        let task = tokio::spawn(
            BIP448_BEGIN_IMMEDIATE_TEST_HOOK.scope(task_hook, async move {
                insert_bip448_withdrawal_attempt_if_absent(&second_pool, &second).await
            }),
        );
        assert_begin_is_contested(&hook).await?;
        first_guard.commit().await?;
        hook.after_acquire.notified().await;
        assert!(
            task.await?.is_err(),
            "second competing immutable plan must lose after serialization"
        );
        assert_eq!(
            list_bip448_withdrawal_attempts(&pools.first, "wallet", "statechain")
                .await?
                .len(),
            1
        );
        Ok(())
    }

    #[tokio::test]
    async fn bip448_transfer_intent_and_duplicate_attempt_have_one_durable_winner() -> Result<()> {
        {
            let pools = independent_migrated_pools().await?;
            let (attempt, _, _) = current_duplicate_attempt_fixture(&pools.first, "11").await?;
            let mut intent = sample_transfer_intent("a9");
            intent.acknowledge_cooperative_duplicates = true;

            let mut attempt_guard = begin_bip448_mutation_guard(&pools.first).await?;
            attempt_guard
                .insert_withdrawal_attempt_if_absent(&attempt)
                .await?;
            let remote_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let task_remote_calls = remote_calls.clone();
            let hook = Arc::new(Bip448BeginImmediateTestHook::default());
            let task_hook = hook.clone();
            let second_pool = pools.second.clone();
            let task = tokio::spawn(BIP448_BEGIN_IMMEDIATE_TEST_HOOK.scope(
                task_hook,
                async move {
                    let mut guard = begin_bip448_mutation_guard(&second_pool).await?;
                    let stored = guard
                        .prepare_or_supersede_transfer_intent(None, &intent)
                        .await?;
                    guard.commit().await?;
                    task_remote_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok::<_, anyhow::Error>(stored)
                },
            ));
            assert_begin_is_contested(&hook).await?;
            attempt_guard.commit().await?;
            hook.after_acquire.notified().await;
            assert!(
                task.await?.is_err(),
                "attempt-first serialization must reject transfer intent creation"
            );
            assert_eq!(
                remote_calls.load(std::sync::atomic::Ordering::SeqCst),
                0,
                "losing transfer must make no remote call"
            );
            assert_eq!(
                list_bip448_withdrawal_attempts(&pools.first, "wallet", "statechain")
                    .await?
                    .len(),
                1
            );
            assert!(
                list_bip448_transfer_intents(&pools.first, "wallet", "statechain")
                    .await?
                    .is_empty()
            );
        }

        {
            let pools = independent_migrated_pools().await?;
            let (attempt, _, _) = current_duplicate_attempt_fixture(&pools.first, "12").await?;
            let mut intent = sample_transfer_intent("aa");
            intent.acknowledge_cooperative_duplicates = true;

            let mut transfer_guard = begin_bip448_mutation_guard(&pools.first).await?;
            transfer_guard
                .prepare_or_supersede_transfer_intent(None, &intent)
                .await?;
            let hook = Arc::new(Bip448BeginImmediateTestHook::default());
            let task_hook = hook.clone();
            let second_pool = pools.second.clone();
            let task = tokio::spawn(
                BIP448_BEGIN_IMMEDIATE_TEST_HOOK.scope(task_hook, async move {
                    insert_bip448_withdrawal_attempt_if_absent(&second_pool, &attempt).await
                }),
            );
            assert_begin_is_contested(&hook).await?;
            transfer_guard.commit().await?;
            hook.after_acquire.notified().await;
            assert!(
                task.await?.is_err(),
                "transfer-first serialization must reject attempt creation"
            );
            assert_eq!(
                list_bip448_transfer_intents(&pools.first, "wallet", "statechain")
                    .await?
                    .len(),
                1
            );
            assert!(
                list_bip448_withdrawal_attempts(&pools.first, "wallet", "statechain")
                    .await?
                    .is_empty()
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn bip448_latch_creation_and_duplicate_attempt_are_asymmetrically_linearized(
    ) -> Result<()> {
        {
            let pools = independent_migrated_pools().await?;
            let (attempt, owner, signed_statechain_id) =
                current_duplicate_attempt_fixture(&pools.first, "13").await?;
            let mut attempt_guard = begin_bip448_mutation_guard(&pools.first).await?;
            attempt_guard
                .insert_withdrawal_attempt_if_absent(&attempt)
                .await?;
            let remote_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let task_remote_calls = remote_calls.clone();
            let hook = Arc::new(Bip448BeginImmediateTestHook::default());
            let task_hook = hook.clone();
            let second_pool = pools.second.clone();
            let task = tokio::spawn(BIP448_BEGIN_IMMEDIATE_TEST_HOOK.scope(
                task_hook,
                async move {
                    let mut guard = begin_bip448_mutation_guard(&second_pool).await?;
                    let coin = guard
                        .latch_creation_coin("wallet", "statechain", &owner, &signed_statechain_id)
                        .await?;
                    task_remote_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    guard.commit().await?;
                    Ok::<_, anyhow::Error>(coin)
                },
            ));
            assert_begin_is_contested(&hook).await?;
            attempt_guard.commit().await?;
            hook.after_acquire.notified().await;
            assert!(
                task.await?.is_err(),
                "attempt-first serialization must reject latch creation"
            );
            assert_eq!(
                remote_calls.load(std::sync::atomic::Ordering::SeqCst),
                0,
                "attempt-first latch rejection must precede the remote call"
            );
        }

        {
            let pools = independent_migrated_pools().await?;
            let (attempt, owner, signed_statechain_id) =
                current_duplicate_attempt_fixture(&pools.first, "14").await?;
            let mut latch_guard = begin_bip448_mutation_guard(&pools.first).await?;
            let selected = latch_guard
                .latch_creation_coin("wallet", "statechain", &owner, &signed_statechain_id)
                .await?;
            let remote_calls = std::sync::atomic::AtomicUsize::new(0);
            remote_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

            let hook = Arc::new(Bip448BeginImmediateTestHook::default());
            let task_hook = hook.clone();
            let second_pool = pools.second.clone();
            let task = tokio::spawn(
                BIP448_BEGIN_IMMEDIATE_TEST_HOOK.scope(task_hook, async move {
                    insert_bip448_withdrawal_attempt_if_absent(&second_pool, &attempt).await
                }),
            );
            assert_begin_is_contested(&hook).await?;
            latch_guard.commit().await?;
            hook.after_acquire.notified().await;
            let stored_attempt = task.await??;
            assert_eq!(selected.statechain_id.as_deref(), Some("statechain"));
            assert_eq!(stored_attempt.binding_index, 1);
            assert_eq!(
                remote_calls.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "latch-first may finish its one remote call while retaining the guard"
            );
            assert_eq!(
                list_bip448_withdrawal_attempts(&pools.first, "wallet", "statechain")
                    .await?
                    .len(),
                1,
                "completed latch creation reserves no future transfer right"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn bip448_accepted_to_needs_rebroadcast_serializes_before_later_attempt() -> Result<()> {
        let pools = independent_migrated_pools().await?;
        let (_, owner, script) = accepted_binding_fixture(&pools.first).await?;
        let bindings = reconcile_bip448_funding_bindings(
            &pools.first,
            "wallet",
            "statechain",
            &owner.to_string(),
            1,
            &[
                sample_binding_observation("34", 0, 100_000, &script),
                sample_binding_observation("11", 1, 70_000, &script),
                sample_binding_observation("12", 2, 60_000, &script),
            ],
        )
        .await?;
        let first_binding = bindings
            .iter()
            .find(|row| row.binding_index == 1)
            .ok_or_else(|| anyhow!("first duplicate binding is missing"))?;
        let second_binding = bindings
            .iter()
            .find(|row| row.binding_index == 2)
            .ok_or_else(|| anyhow!("second duplicate binding is missing"))?;
        let first = sign_duplicate_attempt(&pools.first, first_binding).await?;
        transition_bip448_withdrawal_broadcast_status(
            &pools.first,
            "wallet",
            "statechain",
            1,
            &first.signing_id,
            Bip448BroadcastStatus::NotBroadcast,
            Bip448BroadcastStatus::Accepted,
        )
        .await?;
        let second = sample_duplicate_attempt(second_binding);

        let mut reconciliation = begin_bip448_mutation_guard(&pools.first).await?;
        reconciliation
            .update_withdrawal_broadcast_status(
                "wallet",
                "statechain",
                1,
                &first.signing_id,
                Bip448BroadcastStatus::Accepted,
                Bip448BroadcastStatus::NeedsRebroadcast,
            )
            .await?;
        let hook = Arc::new(Bip448BeginImmediateTestHook::default());
        let task_hook = hook.clone();
        let second_pool = pools.second.clone();
        let task = tokio::spawn(
            BIP448_BEGIN_IMMEDIATE_TEST_HOOK.scope(task_hook, async move {
                insert_bip448_withdrawal_attempt_if_absent(&second_pool, &second).await
            }),
        );
        assert_begin_is_contested(&hook).await?;
        reconciliation.commit().await?;
        hook.after_acquire.notified().await;
        assert!(
            task.await?.is_err(),
            "later attempt must observe NeedsRebroadcast and roll back"
        );
        let attempts =
            list_bip448_withdrawal_attempts(&pools.first, "wallet", "statechain").await?;
        assert_eq!(attempts.len(), 1);
        assert_eq!(
            attempts[0].broadcast_status,
            Bip448BroadcastStatus::NeedsRebroadcast
        );
        Ok(())
    }

    #[tokio::test]
    async fn bip448_owner_reassignment_preserves_every_binding_index_and_identity() -> Result<()> {
        let pool = migrated_pool().await?;
        let (record, owner_one, script) = accepted_binding_fixture(&pool).await?;
        let observations = [
            sample_binding_observation("34", 0, 100_000, &script),
            sample_binding_observation("11", 1, 70_000, &script),
        ];
        let rows = reconcile_bip448_funding_bindings(
            &pool,
            "wallet",
            "statechain",
            &owner_one.to_string(),
            1,
            &observations,
        )
        .await?;
        let attempt = sample_duplicate_attempt(&rows[1]);
        insert_bip448_withdrawal_attempt_if_absent(&pool, &attempt).await?;
        let mut wallet = get_wallet(&pool, "wallet").await?;
        let mut receiver_coin = wallet.get_new_coin()?;
        let receiver_user = PublicKey::from_str(&receiver_coin.user_pubkey)?;
        let owner_two = receiver_user.x_only_public_key().0;
        let mut state_two = record.clone();
        state_two.latest_state_number = 2;
        state_two.latest_state = real_fixture_state_for_owner(
            &wallet,
            &record,
            owner_two,
            2,
            record.latest_state.state_locktime + 1,
        )?;
        let receiver_server =
            PublicKey::from_str(&record.aggregate_pubkey)?.combine(&receiver_user.negate())?;
        receiver_coin.server_pubkey = Some(receiver_server.to_string());
        receiver_coin.aggregated_pubkey = Some(record.aggregate_pubkey.clone());
        receiver_coin.statechain_protocol = Some(BIP448_COIN_PROTOCOL.to_string());
        receiver_coin.statechain_id = Some("statechain".to_string());
        receiver_coin.signed_statechain_id = Some(mercurylib::transfer::receiver::sign_message(
            "statechain",
            &receiver_coin,
        )?);
        receiver_coin.utxo_txid = Some(record.funding_outpoint.txid.clone());
        receiver_coin.utxo_vout = Some(record.funding_outpoint.vout);
        receiver_coin.amount = Some(u32::try_from(record.amount_sats)?);
        receiver_coin.status = CoinStatus::CONFIRMED;
        receiver_coin.locktime = Some(state_two.latest_state.state_locktime);
        receiver_coin.public_nonce = Some(
            state_two
                .latest_state
                .signing_metadata
                .client_public_nonce
                .clone(),
        );
        receiver_coin.server_public_nonce = Some(
            state_two
                .latest_state
                .signing_metadata
                .server_public_nonce
                .clone(),
        );
        receiver_coin.blinding_factor = Some(
            state_two
                .latest_state
                .signing_metadata
                .blinding_factor
                .clone(),
        );
        receiver_coin.aggregated_address =
            Some(bip448_deposit::create_deposit_address(&receiver_coin, "regtest")?.address);
        wallet.coins.push(receiver_coin);
        update_wallet(&pool, &wallet).await?;
        upsert_bip448_statechain_record(&pool, &state_two).await?;
        insert_bip448_state_history_entry(
            &pool,
            "wallet",
            "statechain",
            &history_entry(&state_two.latest_state, owner_two),
        )
        .await?;
        let reassignment_error = reconcile_bip448_funding_bindings(
            &pool,
            "wallet",
            "statechain",
            &owner_two.to_string(),
            2,
            &observations,
        )
        .await
        .expect_err("a sender-generation spend attempt must stop owner reassignment");
        assert!(reassignment_error
            .to_string()
            .contains("attempt-free generation"));
        assert_eq!(
            list_bip448_funding_bindings(&pool, "wallet", "statechain").await?,
            rows
        );
        let deleted_attempt = sqlx::query(
            "DELETE FROM bip448_withdrawal_attempts WHERE wallet_name='wallet' \
             AND statechain_id='statechain' AND binding_index=$1 AND signing_id=$2",
        )
        .bind(i64::from(attempt.binding_index))
        .bind(&attempt.signing_id)
        .execute(&pool)
        .await?;
        assert_eq!(deleted_attempt.rows_affected(), 1);
        let reassigned = reconcile_bip448_funding_bindings(
            &pool,
            "wallet",
            "statechain",
            &owner_two.to_string(),
            2,
            &observations,
        )
        .await?;
        assert_eq!(
            rows.iter()
                .map(|row| (row.binding_index, row.txid.clone(), row.vout))
                .collect::<Vec<_>>(),
            reassigned
                .iter()
                .map(|row| (row.binding_index, row.txid.clone(), row.vout))
                .collect::<Vec<_>>()
        );
        for (before, after) in rows.iter().zip(&reassigned) {
            assert_eq!(after.binding_index, before.binding_index);
            assert_eq!(after.txid, before.txid);
            assert_eq!(after.vout, before.vout);
            assert_eq!(after.value_sats, before.value_sats);
            assert_eq!(after.script_pubkey, before.script_pubkey);
            assert_eq!(after.role, before.role);
            assert_eq!(after.observation_status, before.observation_status);
            assert_eq!(after.funding_height, before.funding_height);
            assert_eq!(after.spend_txid, before.spend_txid);
            assert_eq!(after.spend_height, before.spend_height);
            assert_eq!(after.last_scanned_height, before.last_scanned_height);
            assert_eq!(after.first_seen_at, before.first_seen_at);
        }
        assert!(
            list_bip448_withdrawal_attempts(&pool, "wallet", "statechain")
                .await?
                .is_empty()
        );
        assert!(reassigned
            .iter()
            .all(|row| row.owner_user_pubkey == owner_two.to_string()
                && row.owner_state_number == 2
                && row.ownership_status == Bip448OwnershipStatus::Current));
        let mut accepted_wallet = get_wallet(&pool, "wallet").await?;
        accepted_wallet.coins[0].status = CoinStatus::IN_TRANSFER;
        update_wallet(&pool, &accepted_wallet).await?;
        let accepted_raw = get_bip448_raw_wallet_json(&pool, "wallet").await?;
        let mut status_reconciled = accepted_wallet;
        status_reconciled.coins[0].status = CoinStatus::TRANSFERRED;
        let mut status_guard = begin_bip448_mutation_guard(&pool).await?;
        assert!(
            status_guard
                .update_wallet_if_unchanged_and_scan_current(
                    "wallet",
                    &accepted_raw,
                    &status_reconciled,
                    &[],
                )
                .await?
        );
        status_guard.commit().await?;
        assert!(list_bip448_funding_bindings(&pool, "wallet", "statechain")
            .await?
            .iter()
            .all(|row| row.owner_user_pubkey == owner_two.to_string()
                && row.ownership_status == Bip448OwnershipStatus::Current));
        let previous = mark_bip448_funding_bindings_previous(
            &pool,
            "wallet",
            "statechain",
            &owner_two.to_string(),
            2,
        )
        .await?;
        assert!(previous
            .iter()
            .all(|row| row.ownership_status == Bip448OwnershipStatus::Previous));
        Ok(())
    }

    #[tokio::test]
    async fn bip448_positive_coin_status_rotation_invalidates_bindings_with_wallet_cas(
    ) -> Result<()> {
        let pool = migrated_pool().await?;
        let (_, owner, script) = accepted_binding_fixture(&pool).await?;
        reconcile_bip448_funding_bindings(
            &pool,
            "wallet",
            "statechain",
            &owner.to_string(),
            1,
            &[
                sample_binding_observation("34", 0, 100_000, &script),
                sample_binding_observation("11", 1, 70_000, &script),
            ],
        )
        .await?;
        let mut wallet = get_wallet(&pool, "wallet").await?;
        wallet.coins[0].status = CoinStatus::IN_TRANSFER;
        update_wallet(&pool, &wallet).await?;
        let raw = get_bip448_raw_wallet_json(&pool, "wallet").await?;
        let mut transferred = wallet.clone();
        transferred.coins[0].status = CoinStatus::TRANSFERRED;

        let mut guard = begin_bip448_mutation_guard(&pool).await?;
        assert!(
            guard
                .update_wallet_if_unchanged_and_scan_current("wallet", &raw, &transferred, &[],)
                .await?
        );
        guard.commit().await?;
        assert_eq!(
            serde_json::to_value(get_wallet(&pool, "wallet").await?)?,
            serde_json::to_value(&transferred)?
        );
        assert!(list_bip448_funding_bindings(&pool, "wallet", "statechain")
            .await?
            .iter()
            .all(|binding| { binding.ownership_status == Bip448OwnershipStatus::Previous }));

        let stale_raw = raw;
        let mut stale_guard = begin_bip448_mutation_guard(&pool).await?;
        assert!(
            !stale_guard
                .update_wallet_if_unchanged_and_scan_current(
                    "wallet",
                    &stale_raw,
                    &transferred,
                    &[],
                )
                .await?
        );
        stale_guard.commit().await?;
        Ok(())
    }

    #[tokio::test]
    async fn bip448_prepared_compare_delete_is_duplicate_only_and_tip_bound() -> Result<()> {
        let pool = migrated_pool().await?;
        let (_, owner, script) = accepted_binding_fixture(&pool).await?;
        let binding = reconcile_bip448_funding_bindings(
            &pool,
            "wallet",
            "statechain",
            &owner.to_string(),
            1,
            &[
                sample_binding_observation("34", 0, 100_000, &script),
                sample_binding_observation("11", 1, 70_000, &script),
            ],
        )
        .await?
        .into_iter()
        .find(|row| row.binding_index == 1)
        .unwrap();
        let candidate = Bip448ScanCursor {
            coverage_start_height: 0,
            scan_revision: 0,
            last_scanned_height: 20,
            last_scanned_block_hash: "61".repeat(32),
        };
        persist_bip448_scan_state(&pool, "wallet", &script, &candidate, &[]).await?;
        let attempt = sample_duplicate_attempt(&binding);
        let attempt = insert_bip448_withdrawal_attempt_if_absent(&pool, &attempt).await?;
        let prospective_txid = bip448_funding::expected_withdrawal_txid(&attempt)?;
        let exact_sweep_spend = Bip448BindingObservation {
            observation_status: Bip448ObservationStatus::SpentConfirmed,
            spend_txid: Some(prospective_txid.clone()),
            spend_height: Some(19),
            ..sample_binding_observation("11", 1, 70_000, &script)
        };
        let exact_spent_binding =
            update_bip448_funding_binding_observation(&pool, &binding, &exact_sweep_spend).await?;
        assert!(
            delete_prepared_bip448_withdrawal_attempt_for_confirmed_spend(
                &pool,
                &attempt,
                &prospective_txid,
                20,
                &"61".repeat(32),
            )
            .await
            .is_err(),
            "the attempt's own prospective txid is not a competing spend"
        );
        let spent = Bip448BindingObservation {
            observation_status: Bip448ObservationStatus::SpentConfirmed,
            spend_txid: Some("62".repeat(32)),
            spend_height: Some(19),
            ..sample_binding_observation("11", 1, 70_000, &script)
        };
        update_bip448_funding_binding_observation(&pool, &exact_spent_binding, &spent).await?;
        assert!(
            delete_prepared_bip448_withdrawal_attempt_for_confirmed_spend(
                &pool,
                &attempt,
                &"62".repeat(32),
                20,
                &"63".repeat(32)
            )
            .await
            .is_err(),
            "wrong stable hash must retain row"
        );
        assert!(
            get_bip448_withdrawal_attempt(&pool, "wallet", "statechain", 1)
                .await?
                .is_some()
        );
        delete_prepared_bip448_withdrawal_attempt_for_confirmed_spend(
            &pool,
            &attempt,
            &"62".repeat(32),
            20,
            &"61".repeat(32),
        )
        .await?;
        assert!(
            get_bip448_withdrawal_attempt(&pool, "wallet", "statechain", 1)
                .await?
                .is_none()
        );

        let spent_binding = get_bip448_funding_binding(&pool, "wallet", "statechain", 1)
            .await?
            .unwrap();
        let confirmed = sample_binding_observation("11", 1, 70_000, &script);
        let confirmed_binding =
            update_bip448_funding_binding_observation(&pool, &spent_binding, &confirmed).await?;
        let mut armed = sample_duplicate_attempt(&confirmed_binding);
        armed.signing_id = "76".repeat(32);
        refresh_attempt_sign_first_payload(&mut armed);
        let armed = insert_bip448_withdrawal_attempt_if_absent(&pool, &armed).await?;
        arm_bip448_withdrawal_sign_first(&pool, "wallet", "statechain", 1, &armed.signing_id)
            .await?;
        let live = get_bip448_funding_binding(&pool, "wallet", "statechain", 1)
            .await?
            .unwrap();
        update_bip448_funding_binding_observation(&pool, &live, &spent).await?;
        let armed_live = get_bip448_withdrawal_attempt(&pool, "wallet", "statechain", 1)
            .await?
            .unwrap();
        assert!(
            delete_prepared_bip448_withdrawal_attempt_for_confirmed_spend(
                &pool,
                &armed_live,
                &"62".repeat(32),
                20,
                &"61".repeat(32)
            )
            .await
            .is_err()
        );
        assert_eq!(
            get_bip448_withdrawal_attempt(&pool, "wallet", "statechain", 1)
                .await?
                .unwrap()
                .phase,
            Bip448WithdrawalPhase::FirstArmed
        );
        let output_pubkey = sample_owner_key(4).0.to_string();
        let server_public_nonce = "81".repeat(66);
        let (encoded_session, blinded_session) = real_keypath_session_pair(92)?;
        let sign_second_payload_json = serde_json::to_string(
            &mercurylib::bip448_statechain::signing_api::Bip448PartialSignatureRequestPayload {
                statechain_id: "statechain".into(),
                signed_statechain_id: armed.signed_statechain_id.clone(),
                signing_id: armed.signing_id.clone(),
                negate_seckey: 0,
                session: blinded_session,
                server_pub_nonce: server_public_nonce.clone(),
            },
        )?;
        let nonce_stored = store_bip448_withdrawal_nonce_artifacts(
            &pool,
            "wallet",
            "statechain",
            1,
            &armed.signing_id,
            &server_public_nonce,
            &"82".repeat(32),
            &output_pubkey,
            &"84".repeat(32),
            &encoded_session,
            &sign_second_payload_json,
        )
        .await?;
        assert!(
            delete_prepared_bip448_withdrawal_attempt_for_confirmed_spend(
                &pool,
                &nonce_stored,
                &"62".repeat(32),
                20,
                &"61".repeat(32),
            )
            .await
            .is_err()
        );
        let second_armed =
            arm_bip448_withdrawal_sign_second(&pool, "wallet", "statechain", 1, &armed.signing_id)
                .await?;
        assert!(
            delete_prepared_bip448_withdrawal_attempt_for_confirmed_spend(
                &pool,
                &second_armed,
                &"62".repeat(32),
                20,
                &"61".repeat(32),
            )
            .await
            .is_err()
        );
        let aggregate_signature = "92".repeat(64);
        let mut signed_transaction: bitcoin::Transaction =
            bitcoin::consensus::deserialize(&hex::decode(&armed.unsigned_tx_hex)?)?;
        let mut keypath_witness = hex::decode(&aggregate_signature)?;
        keypath_witness.push(0x01);
        signed_transaction.input[0].witness.push(keypath_witness);
        let signed_tx_hex = hex::encode(bitcoin::consensus::serialize(&signed_transaction));
        let signed = store_bip448_withdrawal_signed_artifacts(
            &pool,
            "wallet",
            "statechain",
            1,
            &armed.signing_id,
            &"91".repeat(32),
            &aggregate_signature,
            &signed_tx_hex,
            &signed_transaction.txid().to_string(),
            Bip448BroadcastStatus::Conflicted,
        )
        .await?;
        assert!(
            delete_prepared_bip448_withdrawal_attempt_for_confirmed_spend(
                &pool,
                &signed,
                &"62".repeat(32),
                20,
                &"61".repeat(32),
            )
            .await
            .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn bip448_canonical_attempt_requires_one_exact_confirmed_coin() -> Result<()> {
        for status in [
            CoinStatus::INITIALISED,
            CoinStatus::IN_MEMPOOL,
            CoinStatus::UNCONFIRMED,
            CoinStatus::IN_TRANSFER,
            CoinStatus::TRANSFERRED,
            CoinStatus::WITHDRAWING,
            CoinStatus::WITHDRAWN,
        ] {
            let pool = migrated_pool().await?;
            let attempt = ready_canonical_attempt_fixture(&pool).await?;
            let mut wallet = get_wallet(&pool, "wallet").await?;
            wallet.coins[0].status = status;
            update_wallet(&pool, &wallet).await?;
            assert!(insert_bip448_withdrawal_attempt_if_absent(&pool, &attempt)
                .await
                .is_err());
            assert!(
                list_bip448_withdrawal_attempts(&pool, "wallet", "statechain")
                    .await?
                    .is_empty()
            );
        }

        let absent_pool = migrated_pool().await?;
        let absent_attempt = ready_canonical_attempt_fixture(&absent_pool).await?;
        sqlx::query("DELETE FROM wallet WHERE wallet_name = 'wallet'")
            .execute(&absent_pool)
            .await?;
        assert!(
            insert_bip448_withdrawal_attempt_if_absent(&absent_pool, &absent_attempt)
                .await
                .is_err()
        );

        let empty_pool = migrated_pool().await?;
        let empty_attempt = ready_canonical_attempt_fixture(&empty_pool).await?;
        update_wallet(&empty_pool, &sample_wallet()).await?;
        assert!(
            insert_bip448_withdrawal_attempt_if_absent(&empty_pool, &empty_attempt)
                .await
                .is_err()
        );

        let unrelated_pool = migrated_pool().await?;
        let unrelated_attempt = ready_canonical_attempt_fixture(&unrelated_pool).await?;
        let mut unrelated_wallet = get_wallet(&unrelated_pool, "wallet").await?;
        unrelated_wallet.coins[0].statechain_id = Some("unrelated".into());
        update_wallet(&unrelated_pool, &unrelated_wallet).await?;
        assert!(
            insert_bip448_withdrawal_attempt_if_absent(&unrelated_pool, &unrelated_attempt,)
                .await
                .is_err()
        );

        let multiple_pool = migrated_pool().await?;
        let multiple_attempt = ready_canonical_attempt_fixture(&multiple_pool).await?;
        let mut multiple_wallet = get_wallet(&multiple_pool, "wallet").await?;
        multiple_wallet.coins.push(multiple_wallet.coins[0].clone());
        update_wallet(&multiple_pool, &multiple_wallet).await?;
        assert!(
            insert_bip448_withdrawal_attempt_if_absent(&multiple_pool, &multiple_attempt,)
                .await
                .is_err()
        );

        let confirmed_pool = migrated_pool().await?;
        let confirmed_attempt = ready_canonical_attempt_fixture(&confirmed_pool).await?;
        assert!(
            insert_bip448_withdrawal_attempt_if_absent(&confirmed_pool, &confirmed_attempt,)
                .await
                .is_ok()
        );
        Ok(())
    }

    #[tokio::test]
    async fn bip448_canonical_attempt_requires_and_freezes_exact_close_snapshot() -> Result<()> {
        let pools = independent_migrated_pools().await?;
        let pool = pools.first.clone();
        let (_, owner, script) = accepted_binding_fixture(&pool).await?;
        let bindings = reconcile_bip448_funding_bindings(
            &pool,
            "wallet",
            "statechain",
            &owner.to_string(),
            1,
            &[
                sample_binding_observation("34", 0, 100_000, &script),
                sample_binding_observation("11", 1, 70_000, &script),
            ],
        )
        .await?;
        let canonical_binding = bindings
            .iter()
            .find(|binding| binding.binding_index == 0)
            .unwrap()
            .clone();
        let duplicate_binding = bindings
            .iter()
            .find(|binding| binding.binding_index == 1)
            .unwrap()
            .clone();
        let spent_duplicate = Bip448BindingObservation {
            observation_status: Bip448ObservationStatus::SpentConfirmed,
            spend_txid: Some("62".repeat(32)),
            spend_height: Some(19),
            ..sample_binding_observation("11", 1, 70_000, &script)
        };
        update_bip448_funding_binding_observation(&pool, &duplicate_binding, &spent_duplicate)
            .await?;
        let close_tip_hash = "61".repeat(32);
        persist_bip448_scan_state(
            &pool,
            "wallet",
            &script,
            &Bip448ScanCursor {
                coverage_start_height: 0,
                scan_revision: 0,
                last_scanned_height: 20,
                last_scanned_block_hash: close_tip_hash.clone(),
            },
            &[],
        )
        .await?;
        let snapshot = match classify_bip448_close_gate(&pool, "wallet", "statechain").await? {
            Bip448CloseGate::Ready {
                closing_bindings_json,
                ..
            } => closing_bindings_json,
            blocked => return Err(anyhow!("unexpected canonical close blocker: {blocked:?}")),
        };
        assert!(snapshot.contains("\"kind\":\"IndependentSpend\""));

        let mut canonical_attempt = sample_duplicate_attempt(&canonical_binding);
        canonical_attempt.attempt_kind = Bip448WithdrawalAttemptKind::Canonical;
        canonical_attempt.completion_status = Bip448CompletionStatus::Open;
        let wallet = get_wallet(&pool, "wallet").await?;
        let coin = wallet
            .coins
            .first()
            .ok_or_else(|| anyhow!("canonical destination fixture Coin is missing"))?;
        canonical_attempt.destination_address = coin.backup_address.clone();
        let nonce = create_bip448_keypath_nonces(coin)?;
        canonical_attempt.client_secret_nonce = nonce.secret_nonce;
        canonical_attempt.client_public_nonce = nonce.public_nonce;
        canonical_attempt.blinding_factor = nonce.blinding_factor;
        canonical_attempt.closing_tip_height = Some(20);
        canonical_attempt.closing_tip_hash = Some(close_tip_hash.clone());
        canonical_attempt.closing_bindings_json = Some(snapshot.clone());
        let mut malformed = canonical_attempt.clone();
        malformed.closing_bindings_json = Some(format!(" {snapshot}"));
        assert!(
            insert_bip448_withdrawal_attempt_if_absent(&pool, &malformed)
                .await
                .is_err()
        );

        let mut illegal_duplicate_snapshot = sample_duplicate_attempt(&duplicate_binding);
        illegal_duplicate_snapshot.closing_tip_height = Some(20);
        illegal_duplicate_snapshot.closing_tip_hash = Some(close_tip_hash.clone());
        illegal_duplicate_snapshot.closing_bindings_json = Some(snapshot.clone());
        assert!(bip448_funding::validate_withdrawal_attempt(&illegal_duplicate_snapshot).is_err());

        let stored = insert_bip448_withdrawal_attempt_if_absent(&pool, &canonical_attempt).await?;
        assert!(
            delete_prepared_bip448_withdrawal_attempt_for_confirmed_spend(
                &pool,
                &stored,
                &"62".repeat(32),
                20,
                &close_tip_hash,
            )
            .await
            .is_err(),
            "canonical index 0 is never compare-deletable"
        );
        assert_eq!(
            insert_bip448_withdrawal_attempt_if_absent(&pool, &canonical_attempt).await?,
            stored
        );
        let mut conflict = canonical_attempt.clone();
        conflict.destination_address = "different-destination".into();
        assert!(insert_bip448_withdrawal_attempt_if_absent(&pool, &conflict)
            .await
            .is_err());

        arm_bip448_withdrawal_sign_first(
            &pool,
            "wallet",
            "statechain",
            0,
            &canonical_attempt.signing_id,
        )
        .await?;
        let secp = Secp256k1::new();
        let server_nonce_key = SecretKey::from_secret_bytes([93u8; 32])?;
        let (_, server_public_nonce) = new_musig_nonce_pair(
            &secp,
            MusigSessionId::assume_unique_per_nonce_gen([94u8; 32]),
            None,
            Some(server_nonce_key),
            server_nonce_key.public_key(&secp),
            None,
            None,
        )?;
        let server_public_nonce = hex::encode(server_public_nonce.serialize());
        let (encoded_session, blinded_session) = real_keypath_session_pair(93)?;
        let sign_second_payload_json = serde_json::to_string(
            &mercurylib::bip448_statechain::signing_api::Bip448PartialSignatureRequestPayload {
                statechain_id: "statechain".into(),
                signed_statechain_id: canonical_attempt.signed_statechain_id.clone(),
                signing_id: canonical_attempt.signing_id.clone(),
                negate_seckey: 0,
                session: blinded_session,
                server_pub_nonce: server_public_nonce.clone(),
            },
        )?;
        store_bip448_withdrawal_nonce_artifacts(
            &pool,
            "wallet",
            "statechain",
            0,
            &canonical_attempt.signing_id,
            &server_public_nonce,
            &"82".repeat(32),
            &sample_owner_key(4).0.to_string(),
            &"84".repeat(32),
            &encoded_session,
            &sign_second_payload_json,
        )
        .await?;
        arm_bip448_withdrawal_sign_second(
            &pool,
            "wallet",
            "statechain",
            0,
            &canonical_attempt.signing_id,
        )
        .await?;
        let aggregate_signature = "92".repeat(64);
        let mut signed_transaction: bitcoin::Transaction =
            bitcoin::consensus::deserialize(&hex::decode(&canonical_attempt.unsigned_tx_hex)?)?;
        let mut keypath_witness = hex::decode(&aggregate_signature)?;
        keypath_witness.push(0x01);
        signed_transaction
            .input
            .get_mut(0)
            .ok_or_else(|| anyhow!("sample canonical withdrawal has no input"))?
            .witness
            .push(keypath_witness);
        store_bip448_withdrawal_signed_artifacts(
            &pool,
            "wallet",
            "statechain",
            0,
            &canonical_attempt.signing_id,
            &"91".repeat(32),
            &aggregate_signature,
            &hex::encode(bitcoin::consensus::serialize(&signed_transaction)),
            &signed_transaction.txid().to_string(),
            Bip448BroadcastStatus::NotBroadcast,
        )
        .await?;
        update_bip448_withdrawal_broadcast_status(
            &pool,
            "wallet",
            "statechain",
            0,
            &canonical_attempt.signing_id,
            Bip448BroadcastStatus::NotBroadcast,
            Bip448BroadcastStatus::Accepted,
        )
        .await?;
        let persisted_wallet = persist_bip448_canonical_withdrawal_wallet(
            &pool,
            "wallet",
            "statechain",
            &canonical_attempt.signing_id,
        )
        .await?;
        let persisted_coin = persisted_wallet
            .coins
            .iter()
            .find(|coin| coin.statechain_id.as_deref() == Some("statechain"))
            .ok_or_else(|| anyhow!("persisted canonical Coin is missing"))?;
        assert_eq!(persisted_coin.status, CoinStatus::WITHDRAWING);
        assert_eq!(
            persisted_coin.tx_withdraw.as_deref(),
            Some(signed_transaction.txid().to_string().as_str())
        );
        assert_eq!(
            persisted_wallet
                .activities
                .iter()
                .filter(|activity| activity.utxo == signed_transaction.txid().to_string())
                .count(),
            1
        );
        update_bip448_withdrawal_completion_status(
            &pool,
            "wallet",
            "statechain",
            &canonical_attempt.signing_id,
            Bip448CompletionStatus::Open,
            Bip448CompletionStatus::CloseArmed,
        )
        .await?;
        let mut current = Bip448BroadcastStatus::Accepted;
        for next in [
            Bip448BroadcastStatus::Confirmed,
            Bip448BroadcastStatus::NeedsRebroadcast,
            Bip448BroadcastStatus::Conflicting,
            Bip448BroadcastStatus::Conflicted,
            Bip448BroadcastStatus::Accepted,
        ] {
            let row = update_bip448_withdrawal_broadcast_status(
                &pool,
                "wallet",
                "statechain",
                0,
                &canonical_attempt.signing_id,
                current,
                next,
            )
            .await?;
            assert_eq!(row.completion_status, Bip448CompletionStatus::CloseArmed);
            if matches!(
                next,
                Bip448BroadcastStatus::NeedsRebroadcast
                    | Bip448BroadcastStatus::Conflicting
                    | Bip448BroadcastStatus::Conflicted
            ) {
                assert!(update_bip448_withdrawal_completion_status(
                    &pool,
                    "wallet",
                    "statechain",
                    &canonical_attempt.signing_id,
                    Bip448CompletionStatus::CloseArmed,
                    Bip448CompletionStatus::Closed,
                )
                .await
                .is_err());
                assert_eq!(
                    get_bip448_withdrawal_attempt(&pool, "wallet", "statechain", 0)
                        .await?
                        .unwrap()
                        .completion_status,
                    Bip448CompletionStatus::CloseArmed
                );
            }
            current = next;
        }

        let live_duplicate = get_bip448_funding_binding(&pool, "wallet", "statechain", 1)
            .await?
            .ok_or_else(|| anyhow!("frozen independent-spend binding is missing"))?;
        let conflict_observation = Bip448BindingObservation {
            txid: live_duplicate.txid.clone(),
            vout: live_duplicate.vout,
            value_sats: live_duplicate.value_sats,
            script_pubkey: live_duplicate.script_pubkey.clone(),
            observation_status: Bip448ObservationStatus::SpentUnconfirmed,
            funding_height: live_duplicate.funding_height,
            spend_txid: live_duplicate.spend_txid.clone(),
            spend_height: live_duplicate.spend_height,
            last_scanned_height: live_duplicate.last_scanned_height,
        };
        let confirmed_observation = Bip448BindingObservation {
            observation_status: Bip448ObservationStatus::SpentConfirmed,
            ..conflict_observation.clone()
        };
        let completion_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        // A passive conflict that linearizes before the final gate prevents
        // the irreversible callback entirely.
        let conflicted = update_bip448_funding_binding_observation(
            &pool,
            &live_duplicate,
            &conflict_observation,
        )
        .await?;
        let blocked_completion_calls = completion_calls.clone();
        let blocked = with_bip448_canonical_completion_fence(
            &pool,
            "wallet",
            "statechain",
            &canonical_attempt.signing_id,
            Duration::from_secs(5),
            move |_| async move {
                blocked_completion_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok::<_, anyhow::Error>(())
            },
        )
        .await;
        assert!(
            blocked.is_err(),
            "a committed frozen-binding conflict passed the final gate"
        );
        assert_eq!(
            completion_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a committed frozen-binding conflict permitted completion"
        );
        let restored =
            update_bip448_funding_binding_observation(&pool, &conflicted, &confirmed_observation)
                .await?;

        // At the exact post-validation/pre-completion interval, a second real
        // pool connection tries to commit the same passive conflict. It must
        // remain behind the retained mutation fence until the completion
        // boundary has linearized.
        let hook = Arc::new(Bip448BeginImmediateTestHook::default());
        let task_hook = hook.clone();
        let second_pool = pools.second.clone();
        let writer_commits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let task_writer_commits = writer_commits.clone();
        let fenced_hook = hook.clone();
        let fenced_writer_commits = writer_commits.clone();
        let fenced_completion_calls = completion_calls.clone();
        let (completion_attempt, writer) = with_bip448_canonical_completion_fence(
            &pool,
            "wallet",
            "statechain",
            &canonical_attempt.signing_id,
            Duration::from_secs(5),
            move |_| async move {
                let writer = tokio::spawn(BIP448_BEGIN_IMMEDIATE_TEST_HOOK.scope(
                    task_hook,
                    async move {
                        let updated = update_bip448_funding_binding_observation(
                            &second_pool,
                            &restored,
                            &conflict_observation,
                        )
                        .await?;
                        task_writer_commits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        Ok::<_, anyhow::Error>(updated)
                    },
                ));
                assert_begin_is_contested(&fenced_hook).await?;
                if fenced_writer_commits.load(std::sync::atomic::Ordering::SeqCst) != 0 {
                    return Err(anyhow!(
                        "passive conflict committed before the completion boundary"
                    ));
                }
                fenced_completion_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if fenced_hook
                    .after_emitted
                    .load(std::sync::atomic::Ordering::SeqCst)
                {
                    return Err(anyhow!(
                        "passive writer acquired during the completion request"
                    ));
                }
                Ok::<_, anyhow::Error>(writer)
            },
        )
        .await?;
        let writer = writer?;
        assert_eq!(
            completion_attempt.completion_status,
            Bip448CompletionStatus::CloseArmed
        );
        hook.after_acquire.notified().await;
        let conflicted_after_boundary = writer.await??;
        assert_eq!(
            writer_commits.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "passive writer did not commit after the completion boundary"
        );

        // Once that later conflict is durable, a retry cannot cross the same
        // gate or issue another completion request.
        let retry_completion_calls = completion_calls.clone();
        let retry = with_bip448_canonical_completion_fence(
            &pool,
            "wallet",
            "statechain",
            &canonical_attempt.signing_id,
            Duration::from_secs(5),
            move |_| async move {
                retry_completion_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok::<_, anyhow::Error>(())
            },
        )
        .await;
        assert!(
            retry.is_err(),
            "late frozen-binding conflict passed the retry gate"
        );
        assert_eq!(
            completion_calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "late frozen-binding conflict permitted another completion"
        );
        let restored_after_boundary = update_bip448_funding_binding_observation(
            &pool,
            &conflicted_after_boundary,
            &confirmed_observation,
        )
        .await?;

        // A callback that never resolves is bounded while holding the same
        // real BEGIN IMMEDIATE fence. The waiting writer cannot acquire until
        // timeout rolls the guard back, and its durable mutation must then
        // prevent a retry from invoking completion again.
        let timeout_hook = Arc::new(Bip448BeginImmediateTestHook::default());
        let timeout_task_hook = timeout_hook.clone();
        let timeout_callback_started = Arc::new(tokio::sync::Notify::new());
        let timeout_writer_started = timeout_callback_started.clone();
        let timeout_second_pool = pools.second.clone();
        let timeout_conflict_observation = Bip448BindingObservation {
            observation_status: Bip448ObservationStatus::SpentUnconfirmed,
            ..confirmed_observation.clone()
        };
        let timeout_restore_observation = confirmed_observation.clone();
        let timeout_writer = tokio::spawn(BIP448_BEGIN_IMMEDIATE_TEST_HOOK.scope(
            timeout_task_hook,
            async move {
                timeout_writer_started.notified().await;
                update_bip448_funding_binding_observation(
                    &timeout_second_pool,
                    &restored_after_boundary,
                    &timeout_conflict_observation,
                )
                .await
            },
        ));
        let timeout_callback_hook = timeout_hook.clone();
        let timeout_callback_signal = timeout_callback_started.clone();
        let timeout_writer_contested = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let timed_writer_contested = timeout_writer_contested.clone();
        let timeout_completion_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let timed_completion_calls = timeout_completion_calls.clone();
        let (timed_attempt, timed_result) = with_bip448_canonical_completion_fence(
            &pool,
            "wallet",
            "statechain",
            &canonical_attempt.signing_id,
            Duration::from_secs(1),
            move |_| async move {
                timed_completion_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                timeout_callback_signal.notify_one();
                assert_begin_is_contested(&timeout_callback_hook).await?;
                timed_writer_contested.store(true, std::sync::atomic::Ordering::SeqCst);
                std::future::pending::<Result<()>>().await
            },
        )
        .await?;
        assert_eq!(
            timed_attempt.completion_status,
            Bip448CompletionStatus::CloseArmed
        );
        let timeout_error = timed_result.expect_err("never-resolving completion did not time out");
        assert!(
            timeout_error
                .to_string()
                .contains("canonical completion timed out"),
            "unexpected completion-timeout error: {timeout_error:#}"
        );
        assert!(
            timeout_writer_contested.load(std::sync::atomic::Ordering::SeqCst),
            "writer did not contend while the never-resolving callback held the fence"
        );
        timeout_hook.after_acquire.notified().await;
        let conflicted_after_timeout = timeout_writer.await??;
        assert_eq!(
            conflicted_after_timeout.observation_status,
            Bip448ObservationStatus::SpentUnconfirmed,
            "waiting writer did not commit its durable mutation after timeout"
        );
        let armed_after_timeout = get_bip448_withdrawal_attempt(&pool, "wallet", "statechain", 0)
            .await?
            .ok_or_else(|| anyhow!("canonical attempt disappeared after completion timeout"))?;
        assert_eq!(
            armed_after_timeout.completion_status,
            Bip448CompletionStatus::CloseArmed,
            "completion timeout changed the indeterminate journal to Closed"
        );

        let retry_after_timeout_calls = timeout_completion_calls.clone();
        let retry_after_timeout = with_bip448_canonical_completion_fence(
            &pool,
            "wallet",
            "statechain",
            &canonical_attempt.signing_id,
            Duration::from_secs(5),
            move |_| async move {
                retry_after_timeout_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok::<_, anyhow::Error>(())
            },
        )
        .await;
        assert!(
            retry_after_timeout.is_err(),
            "durable mutation after timeout passed the retry snapshot gate"
        );
        assert_eq!(
            timeout_completion_calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "retry invoked completion after the timeout writer changed frozen facts"
        );
        let restored_after_timeout = update_bip448_funding_binding_observation(
            &pool,
            &conflicted_after_timeout,
            &timeout_restore_observation,
        )
        .await?;

        // Callback errors explicitly roll back, while cancellation and panic
        // exercise Transaction's rollback-on-drop path. Each case must release
        // the writer lock without changing the CloseArmed journal.
        let (error_attempt, callback_error) = with_bip448_canonical_completion_fence(
            &pool,
            "wallet",
            "statechain",
            &canonical_attempt.signing_id,
            Duration::from_secs(5),
            move |_| async move { Err::<(), _>(anyhow!("injected completion failure")) },
        )
        .await?;
        assert_eq!(
            error_attempt.completion_status,
            Bip448CompletionStatus::CloseArmed
        );
        assert!(callback_error
            .expect_err("completion callback error was discarded")
            .to_string()
            .contains("injected completion failure"));
        let error_release_guard = tokio::time::timeout(
            Duration::from_secs(2),
            begin_bip448_mutation_guard(&pools.second),
        )
        .await
        .context("callback error retained the BIP448 mutation fence")??;
        error_release_guard.commit().await?;

        let cancellation_started = Arc::new(tokio::sync::Notify::new());
        let cancellation_signal = cancellation_started.clone();
        let cancellation_pool = pool.clone();
        let cancellation_signing_id = canonical_attempt.signing_id.clone();
        let cancellation_task = tokio::spawn(async move {
            with_bip448_canonical_completion_fence(
                &cancellation_pool,
                "wallet",
                "statechain",
                &cancellation_signing_id,
                Duration::from_secs(5),
                move |_| async move {
                    cancellation_signal.notify_one();
                    std::future::pending::<Result<()>>().await
                },
            )
            .await
        });
        cancellation_started.notified().await;
        cancellation_task.abort();
        assert!(
            cancellation_task.await.unwrap_err().is_cancelled(),
            "completion-fence cancellation did not cancel its task"
        );
        let cancellation_release_guard = tokio::time::timeout(
            Duration::from_secs(2),
            begin_bip448_mutation_guard(&pools.second),
        )
        .await
        .context("cancelled completion retained the BIP448 mutation fence")??;
        cancellation_release_guard.commit().await?;

        let panic_pool = pool.clone();
        let panic_signing_id = canonical_attempt.signing_id.clone();
        let panic_task = tokio::spawn(async move {
            with_bip448_canonical_completion_fence(
                &panic_pool,
                "wallet",
                "statechain",
                &panic_signing_id,
                Duration::from_secs(5),
                move |_| async move {
                    panic!("injected completion panic");
                    #[allow(unreachable_code)]
                    Ok::<(), anyhow::Error>(())
                },
            )
            .await
        });
        assert!(
            panic_task.await.unwrap_err().is_panic(),
            "completion callback panic did not unwind its task"
        );
        let panic_release_guard = tokio::time::timeout(
            Duration::from_secs(2),
            begin_bip448_mutation_guard(&pools.second),
        )
        .await
        .context("panicked completion retained the BIP448 mutation fence")??;
        panic_release_guard.commit().await?;

        assert_eq!(
            get_bip448_funding_binding(&pool, "wallet", "statechain", 1)
                .await?
                .ok_or_else(|| anyhow!(
                    "frozen binding disappeared after fence lifecycle checks"
                ))?,
            restored_after_timeout
        );
        assert_eq!(
            get_bip448_withdrawal_attempt(&pool, "wallet", "statechain", 0)
                .await?
                .ok_or_else(|| anyhow!(
                    "canonical attempt disappeared after fence lifecycle checks"
                ))?
                .completion_status,
            Bip448CompletionStatus::CloseArmed
        );

        update_bip448_withdrawal_completion_status(
            &pool,
            "wallet",
            "statechain",
            &canonical_attempt.signing_id,
            Bip448CompletionStatus::CloseArmed,
            Bip448CompletionStatus::Closed,
        )
        .await?;
        assert!(update_bip448_withdrawal_completion_status(
            &pool,
            "wallet",
            "statechain",
            &canonical_attempt.signing_id,
            Bip448CompletionStatus::Closed,
            Bip448CompletionStatus::Open,
        )
        .await
        .is_err());

        let live_bindings = list_bip448_funding_bindings(&pool, "wallet", "statechain").await?;
        let mut guard = begin_bip448_mutation_guard(&pool).await?;
        let observed = guard
            .reconcile_withdrawal_attempt_observations("wallet", "statechain", &live_bindings)
            .await?;
        guard.commit().await?;
        let closed = observed
            .iter()
            .find(|attempt| attempt.binding_index == 0)
            .ok_or_else(|| anyhow!("closed canonical attempt is missing"))?;
        assert_eq!(
            closed.broadcast_status,
            Bip448BroadcastStatus::NeedsRebroadcast
        );
        assert_eq!(closed.completion_status, Bip448CompletionStatus::Closed);

        let late = sample_binding_observation("12", 2, 60_000, &script);
        let rows = reconcile_bip448_funding_bindings(
            &pool,
            "wallet",
            "statechain",
            &owner.to_string(),
            1,
            &[
                sample_binding_observation("34", 0, 100_000, &script),
                spent_duplicate,
                late,
            ],
        )
        .await?;
        let late_binding = rows
            .into_iter()
            .find(|binding| binding.txid == "12".repeat(32))
            .unwrap();
        assert!(insert_bip448_withdrawal_attempt_if_absent(
            &pool,
            &sample_duplicate_attempt(&late_binding)
        )
        .await
        .is_err());
        assert!(validate_bip448_canonical_close_snapshot(
            &pool,
            "wallet",
            "statechain",
            &canonical_attempt.signing_id
        )
        .await
        .is_err());
        assert_eq!(
            get_bip448_withdrawal_attempt(&pool, "wallet", "statechain", 0)
                .await?
                .unwrap()
                .closing_bindings_json,
            Some(snapshot),
            "late discovery never rewrites the frozen canonical snapshot"
        );
        Ok(())
    }

    #[tokio::test]
    async fn bip448_close_gate_classifies_every_observation_phase_and_broadcast_blocker(
    ) -> Result<()> {
        let pool = migrated_pool().await?;
        let (_, owner, script) = accepted_binding_fixture(&pool).await?;
        let duplicate = reconcile_bip448_funding_bindings(
            &pool,
            "wallet",
            "statechain",
            &owner.to_string(),
            1,
            &[
                sample_binding_observation("34", 0, 100_000, &script),
                sample_binding_observation("11", 1, 70_000, &script),
            ],
        )
        .await?
        .into_iter()
        .find(|row| row.binding_index == 1)
        .unwrap();
        for status in [
            Bip448ObservationStatus::Mempool,
            Bip448ObservationStatus::Unconfirmed,
            Bip448ObservationStatus::Confirmed,
            Bip448ObservationStatus::SpentMempool,
            Bip448ObservationStatus::SpentUnconfirmed,
            Bip448ObservationStatus::Absent,
        ] {
            let mut binding = duplicate.clone();
            binding.observation_status = status;
            binding.funding_height = match status {
                Bip448ObservationStatus::Mempool
                | Bip448ObservationStatus::SpentMempool
                | Bip448ObservationStatus::Absent => None,
                _ => Some(10),
            };
            binding.spend_txid = matches!(
                status,
                Bip448ObservationStatus::SpentMempool | Bip448ObservationStatus::SpentUnconfirmed
            )
            .then(|| "81".repeat(32));
            binding.spend_height =
                (status == Bip448ObservationStatus::SpentUnconfirmed).then_some(11);
            assert!(
                matches!(
                    bip448_funding::evaluate_bip448_close_gate(&[binding], &[])?,
                    Bip448CloseGate::Blocked { .. }
                ),
                "{status:?} did not block"
            );
        }
        let mut independently_spent = duplicate.clone();
        independently_spent.observation_status = Bip448ObservationStatus::SpentConfirmed;
        independently_spent.spend_txid = Some("82".repeat(32));
        independently_spent.spend_height = Some(11);
        assert!(matches!(
            bip448_funding::evaluate_bip448_close_gate(&[independently_spent.clone()], &[])?,
            Bip448CloseGate::Ready { .. }
        ));

        let mut attempt = sample_duplicate_attempt(&duplicate);
        for phase in [
            Bip448WithdrawalPhase::Prepared,
            Bip448WithdrawalPhase::FirstArmed,
            Bip448WithdrawalPhase::NonceStored,
            Bip448WithdrawalPhase::SecondArmed,
        ] {
            attempt.phase = phase;
            assert!(matches!(
                bip448_funding::evaluate_bip448_close_gate(
                    &[duplicate.clone()],
                    &[attempt.clone()]
                )?,
                Bip448CloseGate::Blocked { .. }
            ));
        }
        attempt.phase = Bip448WithdrawalPhase::Signed;
        attempt.txid = Some("83".repeat(32));
        for status in [
            Bip448BroadcastStatus::NotBroadcast,
            Bip448BroadcastStatus::NeedsRebroadcast,
            Bip448BroadcastStatus::Conflicting,
        ] {
            attempt.broadcast_status = status;
            assert!(matches!(
                bip448_funding::evaluate_bip448_close_gate(
                    &[duplicate.clone()],
                    &[attempt.clone()]
                )?,
                Bip448CloseGate::Blocked { .. }
            ));
        }
        for status in [
            Bip448BroadcastStatus::Accepted,
            Bip448BroadcastStatus::Confirmed,
        ] {
            attempt.broadcast_status = status;
            assert!(matches!(
                bip448_funding::evaluate_bip448_close_gate(
                    &[duplicate.clone()],
                    &[attempt.clone()]
                )?,
                Bip448CloseGate::Ready { .. }
            ));
        }
        attempt.broadcast_status = Bip448BroadcastStatus::Conflicted;
        assert!(matches!(
            bip448_funding::evaluate_bip448_close_gate(&[independently_spent], &[attempt])?,
            Bip448CloseGate::Ready { .. }
        ));
        Ok(())
    }

    #[tokio::test]
    async fn bip448_storage_close_gate_checks_transfer_pending_message_and_coin_blockers(
    ) -> Result<()> {
        let pool = migrated_pool().await?;
        let (record, owner, script) = accepted_binding_fixture(&pool).await?;
        reconcile_bip448_funding_bindings(
            &pool,
            "wallet",
            "statechain",
            &owner.to_string(),
            1,
            &[sample_binding_observation("34", 0, 100_000, &script)],
        )
        .await?;
        assert!(matches!(
            classify_bip448_close_gate(&pool, "wallet", "statechain").await?,
            Bip448CloseGate::Ready { .. }
        ));

        let pending = Bip448PendingDepositSigning {
            wallet_name: "wallet".into(),
            statechain_id: "statechain".into(),
            funding_txid: record.funding_outpoint.txid.clone(),
            funding_vout: record.funding_outpoint.vout,
            funding_value_sats: record.funding_outpoint.value_sats,
            update_template_hash: "41".repeat(32),
            settlement_template_hash: "42".repeat(32),
            state_locktime: 700_000_043,
            signing_id: "43".repeat(32),
            client_secret_nonce: "44".repeat(132),
            client_public_nonce: "45".repeat(66),
            blinding_factor: "46".repeat(32),
            server_public_nonce: None,
        };
        insert_bip448_pending_transfer_signing_if_absent(&pool, &pending).await?;
        assert!(matches!(
            classify_bip448_close_gate(&pool, "wallet", "statechain").await?,
            Bip448CloseGate::Blocked { reasons }
                if reasons == vec![Bip448CloseBlockReason::PendingTransferSigning]
        ));
        delete_bip448_pending_transfer_signing(&pool, "wallet", "statechain", &pending.signing_id)
            .await?;

        let recipient = sample_owner_key(3).0.to_string();
        insert_or_update_bip448_transfer_msg(
            &pool,
            "wallet",
            &recipient,
            &sample_bip448_transfer_msg(),
        )
        .await?;
        assert!(matches!(
            classify_bip448_close_gate(&pool, "wallet", "statechain").await?,
            Bip448CloseGate::Blocked { reasons }
                if reasons == vec![Bip448CloseBlockReason::OutgoingTransferMessage {
                    recipient_auth_pubkey: recipient.clone()
                }]
        ));
        delete_bip448_transfer_msgs(&pool, "wallet", "statechain").await?;

        let mut wallet = get_wallet(&pool, "wallet").await?;
        let mut in_transfer = wallet.get_new_coin()?;
        in_transfer.statechain_protocol = Some("bip448".into());
        in_transfer.statechain_id = Some("statechain".into());
        in_transfer.status = CoinStatus::IN_TRANSFER;
        wallet.coins.push(in_transfer);
        update_wallet(&pool, &wallet).await?;
        assert!(matches!(
            classify_bip448_close_gate(&pool, "wallet", "statechain").await?,
            Bip448CloseGate::Blocked { reasons }
                if reasons == vec![Bip448CloseBlockReason::CoinInTransfer]
        ));
        wallet.coins.clear();
        update_wallet(&pool, &wallet).await?;

        let intent = sample_transfer_intent("e1");
        insert_bip448_transfer_intent_if_absent(&pool, &intent).await?;
        assert!(matches!(
            classify_bip448_close_gate(&pool, "wallet", "statechain").await?,
            Bip448CloseGate::Blocked { reasons }
                if reasons == vec![Bip448CloseBlockReason::ActiveTransferIntent {
                    intent_id: intent.intent_id.clone()
                }]
        ));
        Ok(())
    }
}
