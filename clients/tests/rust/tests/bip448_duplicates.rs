#[path = "common/mod.rs"]
mod common;

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    str::FromStr,
    thread,
    time::Duration,
};

use anyhow::{Context, Result};
use bitcoin::{
    hashes::{sha256, Hash},
    Address, OutPoint, Txid,
};
use common::bip448_regtest::{
    fund_address_output, fund_p2a_fee_input, FundingOutput, FUNDING_AMOUNT_SATS,
};
use mercurylib::{
    bip448_statechain::{
        package::{
            build_anchor_cpfp_package, build_latest_state_recovery_package, Bip448CpfpFeeInput,
            Bip448RecoveryPackage,
        },
        signing_api::{Bip448PartialSignatureRequestPayload, Bip448SignFirstRequestPayload},
        storage::Bip448RecoveryTemplateRole,
        transaction::{self, FeePolicy},
        withdraw::{
            aggregate_bip448_keypath_signature, build_bip448_withdrawal_signing_data,
            create_bip448_keypath_nonces, finalize_bip448_keypath_transaction,
        },
    },
    transfer::bip448::Bip448TransferMsg,
    wallet::Coin,
};
use mercuryrustlib::{
    bip448_funding::{
        Bip448BindingObservation, Bip448BindingRole, Bip448BroadcastStatus, Bip448CompletionStatus,
        Bip448FundingBinding, Bip448ObservationStatus, Bip448OwnershipStatus, Bip448SyncReport,
        Bip448TransferIntentKind, Bip448WithdrawalAttempt, Bip448WithdrawalAttemptKind,
        Bip448WithdrawalPhase,
    },
    client_config::ClientConfig,
    sqlite_manager::Bip448ScanCursor,
    CoinStatus,
};
use reqwest::{Client, StatusCode};
use secp256k1::{PublicKey, Secp256k1};

const DUPLICATE_AMOUNT_SATS: u32 = 73_421;
const SMALL_DUPLICATE_AMOUNT_SATS: u32 = 12_345;
const DUST_DUPLICATE_AMOUNT_SATS: u32 = 400;
const MERCURY_DATABASE_URL: &str = "postgres://postgres:postgres@127.0.0.1:5432/mercury";

async fn run_commit10_child_if_requested() -> Result<bool> {
    let Ok(operation) = std::env::var("ML_BIP448_COMMIT10_CHILD") else {
        return Ok(false);
    };
    std::env::set_var("ML_NETWORK", "regtest");
    let config = mercuryrustlib::client_config::load().await;
    let wallet_name = std::env::var("ML_BIP448_RESTART_WALLET")?;
    let statechain_id = std::env::var("ML_BIP448_RESTART_STATECHAIN_ID")?;
    let result = match operation.as_str() {
        "force-transfer" => {
            mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender_with_options(
                &config,
                &std::env::var("ML_BIP448_RESTART_RECIPIENT")?,
                &wallet_name,
                &statechain_id,
                None,
                mercuryrustlib::bip448_transfer_sender::Bip448TransferOptions {
                    acknowledge_cooperative_duplicates: true,
                    intent: Bip448TransferIntentKind::UserTransfer,
                },
            )
            .await
        }
        "cancel" => mercuryrustlib::bip448_transfer_sender::cancel_bip448_transfer(
            &config,
            &wallet_name,
            &statechain_id,
        )
        .await
        .map(|_| ()),
        _ => anyhow::bail!("unknown Commit 10 child operation {operation}"),
    };
    config.pool.close().await;
    result?;
    Ok(true)
}

fn spawn_commit10_barrier_child(
    test_name: &str,
    operation: &str,
    wallet_name: &str,
    statechain_id: &str,
    recipient: Option<&str>,
    barrier: &str,
) -> Result<(Child, PathBuf, PathBuf)> {
    let id = uuid::Uuid::new_v4();
    let reached = std::env::temp_dir().join(format!("bip448-commit10-{id}-reached"));
    let release = std::env::temp_dir().join(format!("bip448-commit10-{id}-release"));
    if reached.try_exists()? || release.try_exists()? {
        anyhow::bail!("unique Commit 10 barrier path already exists");
    }
    let mut command = Command::new(std::env::current_exe()?);
    command
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "--ignored",
            "--exact",
            test_name,
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ML_BIP448_COMMIT10_CHILD", operation)
        .env("ML_BIP448_RESTART_CHILD", "1")
        .env("ML_BIP448_RESTART_WALLET", wallet_name)
        .env("ML_BIP448_RESTART_STATECHAIN_ID", statechain_id)
        .env("ML_BIP448_TEST_BARRIER", barrier)
        .env("ML_BIP448_TEST_BARRIER_REACHED", &reached)
        .env("ML_BIP448_TEST_BARRIER_RELEASE", &release)
        .env("ML_NETWORK", "regtest")
        .env_remove("ML_BIP448_TEST_CHECKPOINT")
        .env_remove("ML_BIP448_DUPLICATE_SWEEP_CHILD")
        .env_remove("ML_BIP448_CANONICAL_CLOSE_CHILD_MODE")
        .env_remove("ML_BIP448_RECEIVER_RESCAN_CHILD")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(recipient) = recipient {
        command.env("ML_BIP448_RESTART_RECIPIENT", recipient);
    } else {
        command.env_remove("ML_BIP448_RESTART_RECIPIENT");
    }
    Ok((command.spawn()?, reached, release))
}

fn wait_for_commit10_barrier(child: &mut Child, reached: &Path, barrier: &str) -> Result<()> {
    for _ in 0..6_000 {
        if reached.try_exists()? {
            let observed = std::fs::read_to_string(reached)?;
            if observed != barrier {
                anyhow::bail!("Commit 10 child reached {observed}, expected {barrier}");
            }
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            anyhow::bail!("Commit 10 barrier child exited with {status} before reaching {barrier}");
        }
        thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    let _ = child.wait();
    anyhow::bail!("timed out waiting for Commit 10 child barrier {barrier}")
}

fn release_commit10_barrier(child: Child, reached: &Path, release: &Path) -> Result<Output> {
    std::fs::write(release, b"release")?;
    let output = child.wait_with_output();
    for path in [reached, release] {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(output?)
}

async fn mercury_transfer_side_effect_counts(statechain_id: &str) -> Result<(i64, i64)> {
    let pool = sqlx::PgPool::connect(MERCURY_DATABASE_URL).await?;
    Ok(sqlx::query_as(
        "SELECT COUNT(*), COUNT(*) FILTER (WHERE encrypted_transfer_msg IS NOT NULL) \
         FROM statechain_transfer WHERE statechain_id=$1",
    )
    .bind(statechain_id)
    .fetch_one(&pool)
    .await?)
}

async fn assert_lockbox_state_absent(client: &Client, statechain_id: &str) -> Result<()> {
    let response =
        common::lockbox::get(client, &format!("signature_count/{statechain_id}")).await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(response.text().await?, "Signature count not found.");
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct PassiveInvariant {
    wallet_json: String,
    accepted: (String, Vec<(i64, String)>),
    canonical_amount: Option<u32>,
    canonical_outpoint: (Option<String>, Option<u32>),
    signature_count: u32,
}

async fn passive_invariant(
    config: &ClientConfig,
    lockbox_client: &Client,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<PassiveInvariant> {
    let wallet_json = sqlx::query_scalar("SELECT wallet_json FROM wallet WHERE wallet_name = $1")
        .bind(wallet_name)
        .fetch_one(&config.pool)
        .await?;
    let wallet = mercuryrustlib::sqlite_manager::get_wallet(&config.pool, wallet_name).await?;
    let coin = wallet
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some(statechain_id))
        .context("BIP448 passive invariant lost its logical Coin")?;
    Ok(PassiveInvariant {
        wallet_json,
        accepted: accepted_state_bytes(&config.pool, wallet_name, statechain_id).await?,
        canonical_amount: coin.amount,
        canonical_outpoint: (coin.utxo_txid.clone(), coin.utxo_vout),
        signature_count: common::lockbox::get_signature_count(lockbox_client, statechain_id)
            .await?,
    })
}

async fn passive_sync_preserving_state(
    config: &ClientConfig,
    lockbox_client: &Client,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<Bip448SyncReport> {
    let before = passive_invariant(config, lockbox_client, wallet_name, statechain_id).await?;
    let report =
        mercuryrustlib::coin_status::sync_bip448_funding_bindings(config, wallet_name).await?;
    let after = passive_invariant(config, lockbox_client, wallet_name, statechain_id).await?;
    assert_eq!(
        after, before,
        "passive synchronization mutated canonical state"
    );
    Ok(report)
}

fn observation(
    binding: &Bip448FundingBinding,
    status: Bip448ObservationStatus,
    last_scanned_height: u32,
    spend_txid: Option<Txid>,
    spend_height: Option<u32>,
) -> Bip448BindingObservation {
    let funding_height = match status {
        Bip448ObservationStatus::Mempool | Bip448ObservationStatus::Absent => None,
        _ => binding.funding_height.or(Some(1)),
    };
    Bip448BindingObservation {
        txid: binding.txid.clone(),
        vout: binding.vout,
        value_sats: binding.value_sats,
        script_pubkey: binding.script_pubkey.clone(),
        observation_status: status,
        funding_height,
        spend_txid: spend_txid.map(|txid| txid.to_string()),
        spend_height,
        last_scanned_height,
    }
}

fn fresh_observation(
    funding: &FundingOutput,
    script_pubkey: &str,
    status: Bip448ObservationStatus,
    last_scanned_height: u32,
) -> Bip448BindingObservation {
    Bip448BindingObservation {
        txid: funding.outpoint.txid.to_string(),
        vout: funding.outpoint.vout,
        value_sats: funding.value_sats,
        script_pubkey: script_pubkey.to_owned(),
        observation_status: status,
        funding_height: None,
        spend_txid: None,
        spend_height: None,
        last_scanned_height,
    }
}

fn attempt_for(
    binding: &Bip448FundingBinding,
    binding_index: u32,
    kind: Bip448WithdrawalAttemptKind,
    phase: Bip448WithdrawalPhase,
) -> Bip448WithdrawalAttempt {
    Bip448WithdrawalAttempt {
        wallet_name: binding.wallet_name.clone(),
        statechain_id: binding.statechain_id.clone(),
        binding_index,
        attempt_kind: kind,
        owner_user_pubkey: binding.owner_user_pubkey.clone(),
        owner_state_number: binding.owner_state_number,
        source_txid: binding.txid.clone(),
        source_vout: binding.vout,
        source_value_sats: binding.value_sats,
        source_script_pubkey: binding.script_pubkey.clone(),
        destination_address: "test-destination".into(),
        destination_script_pubkey: "51".into(),
        fee_rate_sat_per_vbyte: 1.0,
        fee_sats: 100,
        lock_time: 1,
        unsigned_tx_hex: "00".into(),
        signing_id: "11".repeat(32),
        signed_statechain_id: "12".repeat(64),
        sign_first_payload_json: "{}".into(),
        client_secret_nonce: "13".repeat(132),
        client_public_nonce: "14".repeat(66),
        blinding_factor: "15".repeat(32),
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
        phase,
        broadcast_status: Bip448BroadcastStatus::NotBroadcast,
        completion_status: Bip448CompletionStatus::NotApplicable,
        closing_tip_height: None,
        closing_tip_hash: None,
        closing_bindings_json: None,
        created_at: "test".into(),
        updated_at: "test".into(),
    }
}

async fn mercury_state_bytes(statechain_id: &str) -> Result<(String, String, String)> {
    let pool = sqlx::PgPool::connect(MERCURY_DATABASE_URL).await?;
    let statechain_data = sqlx::query_scalar(
        "SELECT COALESCE(jsonb_agg(to_jsonb(row_data)), '[]'::jsonb)::text FROM (\
         SELECT * FROM statechain_data WHERE statechain_id = $1 ORDER BY statechain_id\
         ) AS row_data",
    )
    .bind(statechain_id)
    .fetch_one(&pool)
    .await?;
    let signatures = sqlx::query_scalar(
        "SELECT COALESCE(jsonb_agg(to_jsonb(row_data)), '[]'::jsonb)::text FROM (\
         SELECT * FROM bip448_signature_data WHERE statechain_id = $1 ORDER BY signing_id\
         ) AS row_data",
    )
    .bind(statechain_id)
    .fetch_one(&pool)
    .await?;
    let transfer = sqlx::query_scalar(
        "SELECT COALESCE(jsonb_agg(to_jsonb(row_data)), '[]'::jsonb)::text FROM (\
         SELECT * FROM statechain_transfer WHERE statechain_id = $1 ORDER BY statechain_id\
         ) AS row_data",
    )
    .bind(statechain_id)
    .fetch_one(&pool)
    .await?;
    Ok((statechain_data, signatures, transfer))
}

async fn sign_and_broadcast_duplicate(
    config: &ClientConfig,
    canonical_coin: &Coin,
    duplicate: &Bip448FundingBinding,
) -> Result<Txid> {
    let mut signing_coin = canonical_coin.clone();
    signing_coin.utxo_txid = Some(duplicate.txid.clone());
    signing_coin.utxo_vout = Some(duplicate.vout);
    signing_coin.amount = Some(u32::try_from(duplicate.value_sats)?);
    let nonce = create_bip448_keypath_nonces(&signing_coin)?;
    signing_coin.secret_nonce = Some(nonce.secret_nonce);
    signing_coin.public_nonce = Some(nonce.public_nonce);
    signing_coin.blinding_factor = Some(nonce.blinding_factor);
    let signing_id = sha256::Hash::hash(uuid::Uuid::new_v4().as_bytes()).to_string();
    let statechain_id = signing_coin
        .statechain_id
        .clone()
        .context("duplicate signing Coin has no statechain ID")?;
    let signed_statechain_id = signing_coin
        .signed_statechain_id
        .clone()
        .context("duplicate signing Coin has no signed statechain ID")?;
    signing_coin.server_public_nonce = Some(
        mercuryrustlib::deposit::bip448_sign_first(
            config,
            &Bip448SignFirstRequestPayload {
                statechain_id: statechain_id.clone(),
                signed_statechain_id: signed_statechain_id.clone(),
                signing_id: signing_id.clone(),
            },
        )
        .await?,
    );
    let destination = common::bitcoin_core::getnewaddress()?;
    let signing = build_bip448_withdrawal_signing_data(
        &signing_coin,
        OutPoint {
            txid: Txid::from_str(&duplicate.txid)?,
            vout: duplicate.vout,
        },
        duplicate.value_sats,
        config.chain_client.tip_height()?,
        1.0,
        &destination,
        config.network,
    )?;
    let request = signing.partial_signature_request_payload;
    let server_partial = mercuryrustlib::deposit::bip448_sign_second(
        config,
        &Bip448PartialSignatureRequestPayload {
            statechain_id: request.statechain_id,
            signed_statechain_id: request.signed_statechain_id,
            signing_id,
            negate_seckey: request.negate_seckey,
            session: request.session,
            server_pub_nonce: request.server_pub_nonce,
        },
    )
    .await?;
    let signature = aggregate_bip448_keypath_signature(
        signing.msg,
        signing.client_partial_sig,
        hex::encode(server_partial.serialize()),
        signing.encoded_session,
        signing.output_pubkey,
    )?;
    let signed_tx = finalize_bip448_keypath_transaction(signing.encoded_unsigned_tx, signature)?;
    Ok(config.chain_client.broadcast_tx(&hex::decode(signed_tx)?)?)
}

async fn accepted_state_bytes(
    pool: &sqlx::SqlitePool,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<(String, Vec<(i64, String)>)> {
    let record_json = sqlx::query_scalar(
        "SELECT record_json FROM bip448_statechains \
         WHERE wallet_name = $1 AND statechain_id = $2",
    )
    .bind(wallet_name)
    .bind(statechain_id)
    .fetch_one(pool)
    .await?;
    let history_rows = sqlx::query_as(
        "SELECT state_number, entry_json FROM bip448_state_history \
         WHERE wallet_name = $1 AND statechain_id = $2 ORDER BY state_number",
    )
    .bind(wallet_name)
    .bind(statechain_id)
    .fetch_all(pool)
    .await?;

    Ok((record_json, history_rows))
}

fn restart_bitcoin_core_after_unclean_stop(container_id: &str) -> Result<()> {
    if container_id.is_empty() {
        anyhow::bail!("cannot restart an empty Bitcoin Core container ID");
    }
    for action in ["kill", "start"] {
        let output = Command::new("docker")
            .args([action, container_id])
            .output()
            .with_context(|| format!("failed to execute docker {action}"))?;
        if !output.status.success() {
            anyhow::bail!(
                "docker {action} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    for _ in 0..120 {
        if common::bitcoin_core::execute_bitcoin_command(
            "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury getblockchaininfo",
        )
        .is_ok()
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(250));
    }
    anyhow::bail!("Bitcoin Core did not become ready after its unclean restart")
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_repeated_funding_preserves_canonical_state_and_signature_count() -> Result<()> {
    let _guard = common::test_guard();

    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;
    let lockbox_client = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox_client).await?;

    let client_config = common::prepare_test_env().await?;
    let wallet_name = format!("bip448-duplicates-{}", uuid::Uuid::new_v4());
    let wallet = mercuryrustlib::wallet::create_wallet(&wallet_name, &client_config).await?;
    mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, &wallet).await?;

    let token = mercuryrustlib::deposit::get_token(&client_config).await?;
    let token_id = common::utils::handle_token_response(&client_config, &token).await?;
    let deposit = mercuryrustlib::deposit::get_bip448_deposit_bitcoin_address(
        &client_config,
        &wallet_name,
        &token_id,
        FUNDING_AMOUNT_SATS,
    )
    .await?;
    let aggregate_address =
        Address::from_str(&deposit.address)?.require_network(client_config.network)?;
    let expected_script = aggregate_address.script_pubkey();
    let canonical_funding = fund_address_output(&aggregate_address, FUNDING_AMOUNT_SATS)?;
    common::chain::wait_for_address_outpoint(
        &client_config,
        &deposit.address,
        canonical_funding.outpoint,
        canonical_funding.value_sats,
    )
    .await?;
    common::bitcoin_core::mine_blocks(client_config.confirmation_target)?;
    mercuryrustlib::coin_status::update_coins(&client_config, &wallet_name).await?;

    let wallet_before =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet_name).await?;
    let wallet_coin_count_before = wallet_before.coins.len();
    let statechain_coins_before = wallet_before
        .coins
        .iter()
        .filter(|coin| coin.statechain_id.as_deref() == Some(&deposit.statechain_id))
        .collect::<Vec<_>>();
    assert_eq!(statechain_coins_before.len(), 1);
    let canonical_coin = statechain_coins_before[0];
    assert_eq!(canonical_coin.status, CoinStatus::CONFIRMED);
    assert_eq!(canonical_coin.amount, Some(FUNDING_AMOUNT_SATS));
    let canonical_txid_string = canonical_coin
        .utxo_txid
        .as_deref()
        .context("confirmed BIP448 coin is missing its funding txid")?;
    let canonical_txid = Txid::from_str(canonical_txid_string)?;
    let canonical_vout = canonical_coin
        .utxo_vout
        .context("confirmed BIP448 coin is missing its funding vout")?;
    let canonical_outpoint = OutPoint {
        txid: canonical_txid,
        vout: canonical_vout,
    };
    assert_eq!(canonical_outpoint, canonical_funding.outpoint);

    let accepted_record_before = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &client_config.pool,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    assert_eq!(accepted_record_before.latest_state_number, 1);
    assert_eq!(accepted_record_before.latest_state.state_number, 1);
    assert_eq!(
        accepted_record_before.amount_sats,
        u64::from(FUNDING_AMOUNT_SATS)
    );
    assert_eq!(
        accepted_record_before.funding_outpoint.txid,
        canonical_outpoint.txid.to_string()
    );
    assert_eq!(
        accepted_record_before.funding_outpoint.vout,
        canonical_outpoint.vout
    );
    assert_eq!(
        accepted_record_before.funding_outpoint.value_sats,
        canonical_funding.value_sats
    );
    let (record_json_before, history_rows_before) =
        accepted_state_bytes(&client_config.pool, &wallet_name, &deposit.statechain_id).await?;
    assert_eq!(
        history_rows_before
            .iter()
            .map(|(state_number, _)| *state_number)
            .collect::<Vec<_>>(),
        vec![1]
    );
    let signature_count_before =
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?;
    assert_eq!(signature_count_before, 1);

    assert_ne!(DUPLICATE_AMOUNT_SATS, FUNDING_AMOUNT_SATS);
    let duplicate_funding = fund_address_output(&aggregate_address, DUPLICATE_AMOUNT_SATS)?;
    assert_ne!(duplicate_funding.outpoint, canonical_outpoint);
    common::bitcoin_core::mine_blocks(client_config.confirmation_target)?;

    let canonical_utxo = client_config
        .chain_client
        .get_tx_out(&canonical_outpoint.txid, canonical_outpoint.vout, true)?
        .context("canonical BIP448 funding output is no longer unspent")?;
    let duplicate_utxo = client_config
        .chain_client
        .get_tx_out(
            &duplicate_funding.outpoint.txid,
            duplicate_funding.outpoint.vout,
            true,
        )?
        .context("repeated BIP448 funding output is not unspent")?;
    assert!(canonical_utxo.confirmations >= client_config.confirmation_target);
    assert!(duplicate_utxo.confirmations >= client_config.confirmation_target);
    assert_eq!(canonical_utxo.script_pubkey, expected_script);
    assert_eq!(duplicate_utxo.script_pubkey, expected_script);
    assert_eq!(canonical_utxo.value, canonical_funding.value_sats);
    assert_eq!(duplicate_utxo.value, u64::from(DUPLICATE_AMOUNT_SATS));

    // This is the same update/load preparation used by the list-statecoins path.
    mercuryrustlib::coin_status::update_coins(&client_config, &wallet_name).await?;
    let wallet_after =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet_name).await?;
    assert_eq!(wallet_after.coins.len(), wallet_coin_count_before);
    let statechain_coins_after = wallet_after
        .coins
        .iter()
        .filter(|coin| coin.statechain_id.as_deref() == Some(&deposit.statechain_id))
        .collect::<Vec<_>>();
    assert_eq!(statechain_coins_after.len(), 1);
    let canonical_coin_after = statechain_coins_after[0];
    assert_eq!(
        canonical_coin_after.utxo_txid.as_deref(),
        Some(canonical_txid_string)
    );
    assert_eq!(
        canonical_coin_after.utxo_vout,
        Some(canonical_outpoint.vout)
    );
    assert_eq!(canonical_coin_after.amount, Some(FUNDING_AMOUNT_SATS));
    assert_eq!(canonical_coin_after.status, CoinStatus::CONFIRMED);

    let accepted_record_after = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &client_config.pool,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    assert_eq!(accepted_record_after.latest_state_number, 1);
    assert_eq!(
        accepted_record_after.funding_outpoint,
        accepted_record_before.funding_outpoint
    );
    assert_eq!(
        accepted_record_after.amount_sats,
        accepted_record_before.amount_sats
    );
    let (record_json_after, history_rows_after) =
        accepted_state_bytes(&client_config.pool, &wallet_name, &deposit.statechain_id).await?;
    assert_eq!(record_json_after, record_json_before);
    assert_eq!(history_rows_after, history_rows_before);
    let signature_count_after =
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?;
    assert_eq!(signature_count_after, signature_count_before);

    println!(
        "BIP448 repeated funding: canonical_outpoint={} duplicate_outpoint={} canonical_value_sats={} duplicate_value_sats={} signature_count_before={} signature_count_after={}",
        canonical_outpoint,
        duplicate_funding.outpoint,
        canonical_utxo.value,
        duplicate_utxo.value,
        signature_count_before,
        signature_count_after
    );

    Ok(())
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_duplicate_inventory_is_stable_across_restart_reorg_and_spend() -> Result<()> {
    let _guard = common::test_guard();

    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;
    let lockbox_client = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox_client).await?;

    let client_config = common::prepare_test_env().await?;
    assert!(
        client_config.confirmation_target > 1,
        "the inventory transition test requires an unconfirmed interval"
    );
    let wallet_name = format!("bip448-inventory-{}", uuid::Uuid::new_v4());
    let wallet = mercuryrustlib::wallet::create_wallet(&wallet_name, &client_config).await?;
    mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, &wallet).await?;
    let token = mercuryrustlib::deposit::get_token(&client_config).await?;
    let token_id = common::utils::handle_token_response(&client_config, &token).await?;
    let deposit = mercuryrustlib::deposit::get_bip448_deposit_bitcoin_address(
        &client_config,
        &wallet_name,
        &token_id,
        FUNDING_AMOUNT_SATS,
    )
    .await?;
    let aggregate_address =
        Address::from_str(&deposit.address)?.require_network(client_config.network)?;
    let script_pubkey = hex::encode(aggregate_address.script_pubkey().as_bytes());

    // A standard 400-sat P2TR output is relayable, but its eventual one-input
    // sweep output is dust after fees. It arrives before the canonical output.
    let dust = fund_address_output(&aggregate_address, DUST_DUPLICATE_AMOUNT_SATS)?;
    let pre_accept_report =
        mercuryrustlib::coin_status::sync_bip448_funding_bindings(&client_config, &wallet_name)
            .await?;
    assert!(pre_accept_report.bindings.is_empty());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bip448_funding_bindings WHERE wallet_name = $1",
        )
        .bind(&wallet_name)
        .fetch_one(&client_config.pool)
        .await?,
        0
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
        0
    );
    common::bitcoin_core::mine_blocks(1)?;

    // Pending-journal insert/update/delete and the raw-wallet birth-height
    // change each invalidate a pre-RPC full SyncBase snapshot.
    let pending_base = mercuryrustlib::sqlite_manager::capture_bip448_sync_base(
        &client_config.pool,
        &wallet_name,
        &script_pubkey,
    )
    .await?;
    let pending_statechain_id = format!("pending-race-{}", uuid::Uuid::new_v4());
    sqlx::query(
        "INSERT INTO bip448_pending_deposit_signings (wallet_name,statechain_id,\
         update_template_hash,signing_id,client_secret_nonce,client_public_nonce,\
         blinding_factor) VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(&wallet_name)
    .bind(&pending_statechain_id)
    .bind("21".repeat(32))
    .bind("22".repeat(32))
    .bind("23".repeat(132))
    .bind("24".repeat(66))
    .bind("25".repeat(32))
    .execute(&client_config.pool)
    .await?;
    assert!(
        mercuryrustlib::sqlite_manager::begin_bip448_sync_base_guard(
            &client_config.pool,
            &pending_base,
        )
        .await
        .is_err()
    );
    let inserted_base = mercuryrustlib::sqlite_manager::capture_bip448_sync_base(
        &client_config.pool,
        &wallet_name,
        &script_pubkey,
    )
    .await?;
    sqlx::query(
        "UPDATE bip448_pending_deposit_signings SET server_public_nonce=$1 \
         WHERE wallet_name=$2 AND statechain_id=$3",
    )
    .bind("26".repeat(66))
    .bind(&wallet_name)
    .bind(&pending_statechain_id)
    .execute(&client_config.pool)
    .await?;
    assert!(
        mercuryrustlib::sqlite_manager::begin_bip448_sync_base_guard(
            &client_config.pool,
            &inserted_base,
        )
        .await
        .is_err()
    );
    let updated_base = mercuryrustlib::sqlite_manager::capture_bip448_sync_base(
        &client_config.pool,
        &wallet_name,
        &script_pubkey,
    )
    .await?;
    sqlx::query(
        "DELETE FROM bip448_pending_deposit_signings \
         WHERE wallet_name=$1 AND statechain_id=$2",
    )
    .bind(&wallet_name)
    .bind(&pending_statechain_id)
    .execute(&client_config.pool)
    .await?;
    assert!(
        mercuryrustlib::sqlite_manager::begin_bip448_sync_base_guard(
            &client_config.pool,
            &updated_base,
        )
        .await
        .is_err()
    );

    let wallet_base = mercuryrustlib::sqlite_manager::capture_bip448_sync_base(
        &client_config.pool,
        &wallet_name,
        &script_pubkey,
    )
    .await?;
    let mut receiver_wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet_name).await?;
    let simulated_receiver_birth = client_config
        .chain_client
        .tip_height()?
        .checked_add(1)
        .context("simulated receiver birth height overflow")?;
    receiver_wallet.blockheight = simulated_receiver_birth;
    mercuryrustlib::sqlite_manager::update_wallet(&client_config.pool, &receiver_wallet).await?;
    assert!(
        mercuryrustlib::sqlite_manager::begin_bip448_sync_base_guard(
            &client_config.pool,
            &wallet_base,
        )
        .await
        .is_err()
    );

    let canonical = fund_address_output(&aggregate_address, FUNDING_AMOUNT_SATS)?;
    common::chain::wait_for_address_outpoint(
        &client_config,
        &deposit.address,
        canonical.outpoint,
        canonical.value_sats,
    )
    .await?;
    common::bitcoin_core::mine_blocks(client_config.confirmation_target)?;
    mercuryrustlib::coin_status::update_coins(&client_config, &wallet_name).await?;

    let accepted_before =
        accepted_state_bytes(&client_config.pool, &wallet_name, &deposit.statechain_id).await?;
    let accepted_record = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &client_config.pool,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    assert_eq!(
        accepted_record.funding_outpoint.txid,
        canonical.outpoint.txid.to_string()
    );
    assert_eq!(
        accepted_record.funding_outpoint.vout,
        canonical.outpoint.vout
    );
    assert_eq!(accepted_record.amount_sats, u64::from(FUNDING_AMOUNT_SATS));
    assert_eq!(accepted_before.1.len(), 1);
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
        1
    );

    let accepted_sync = passive_sync_preserving_state(
        &client_config,
        &lockbox_client,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    let mut bindings = accepted_sync
        .bindings
        .into_iter()
        .filter(|binding| binding.statechain_id == deposit.statechain_id)
        .collect::<Vec<_>>();
    bindings.sort_by_key(|binding| binding.binding_index);
    assert_eq!(bindings.len(), 2);
    assert_eq!(bindings[0].binding_index, 0);
    assert_eq!(bindings[0].role, Bip448BindingRole::Canonical);
    assert_eq!(bindings[0].txid, canonical.outpoint.txid.to_string());
    assert_eq!(bindings[1].binding_index, 1);
    assert_eq!(bindings[1].role, Bip448BindingRole::Duplicate);
    assert_eq!(bindings[1].txid, dust.outpoint.txid.to_string());
    assert_eq!(
        bindings[1].value_sats,
        u64::from(DUST_DUPLICATE_AMOUNT_SATS)
    );
    assert!(bindings[1].funding_height.context("dust funding height")? < simulated_receiver_birth);
    let owner_user_pubkey = bindings[0].owner_user_pubkey.clone();
    let owner_state_number = bindings[0].owner_state_number;

    // Two later values arrive together. Feed their real mempool observations
    // in reverse order through the public reconciliation helper; production's
    // internal sort, not callback order, determines their durable indices.
    let small = fund_address_output(&aggregate_address, SMALL_DUPLICATE_AMOUNT_SATS)?;
    let large = fund_address_output(&aggregate_address, DUPLICATE_AMOUNT_SATS)?;
    let tip_height = client_config.chain_client.tip_height()?;
    let mut reversed_observations = bindings
        .iter()
        .map(|binding| {
            observation(
                binding,
                binding.observation_status,
                tip_height,
                binding
                    .spend_txid
                    .as_deref()
                    .map(Txid::from_str)
                    .transpose()
                    .expect("stored spend txid must parse"),
                binding.spend_height,
            )
        })
        .collect::<Vec<_>>();
    reversed_observations.push(fresh_observation(
        &small,
        &script_pubkey,
        Bip448ObservationStatus::Mempool,
        tip_height,
    ));
    reversed_observations.push(fresh_observation(
        &large,
        &script_pubkey,
        Bip448ObservationStatus::Mempool,
        tip_height,
    ));
    reversed_observations.reverse();
    let count_before_order_injection =
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?;
    let reverse_rows = mercuryrustlib::sqlite_manager::reconcile_bip448_funding_bindings(
        &client_config.pool,
        &wallet_name,
        &deposit.statechain_id,
        &owner_user_pubkey,
        owner_state_number,
        &reversed_observations,
    )
    .await?;
    let mut forward_observations = reversed_observations;
    forward_observations.reverse();
    let forward_rows = mercuryrustlib::sqlite_manager::reconcile_bip448_funding_bindings(
        &client_config.pool,
        &wallet_name,
        &deposit.statechain_id,
        &owner_user_pubkey,
        owner_state_number,
        &forward_observations,
    )
    .await?;
    assert_eq!(
        reverse_rows
            .iter()
            .map(|binding| ((binding.txid.clone(), binding.vout), binding.binding_index))
            .collect::<std::collections::BTreeMap<_, _>>(),
        forward_rows
            .iter()
            .map(|binding| ((binding.txid.clone(), binding.vout), binding.binding_index))
            .collect::<std::collections::BTreeMap<_, _>>()
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
        count_before_order_injection
    );
    let post_funding_indices = forward_rows
        .iter()
        .map(|binding| ((binding.txid.clone(), binding.vout), binding.binding_index))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut new_outpoints = [small.outpoint, large.outpoint];
    new_outpoints.sort_by_key(|outpoint| (outpoint.txid.to_string(), outpoint.vout));
    assert_eq!(
        post_funding_indices[&(new_outpoints[0].txid.to_string(), new_outpoints[0].vout)],
        2
    );
    assert_eq!(
        post_funding_indices[&(new_outpoints[1].txid.to_string(), new_outpoints[1].vout)],
        3
    );

    let mempool = passive_sync_preserving_state(
        &client_config,
        &lockbox_client,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    for outpoint in [small.outpoint, large.outpoint] {
        assert_eq!(
            mempool
                .bindings
                .iter()
                .find(|binding| binding.txid == outpoint.txid.to_string()
                    && binding.vout == outpoint.vout)
                .context("mempool duplicate binding")?
                .observation_status,
            Bip448ObservationStatus::Mempool
        );
    }
    common::bitcoin_core::mine_blocks(1)?;
    let duplicate_funding_block_hash = client_config
        .chain_client
        .get_block_hash(client_config.chain_client.tip_height()?)?
        .to_string();
    let unconfirmed = passive_sync_preserving_state(
        &client_config,
        &lockbox_client,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    for outpoint in [small.outpoint, large.outpoint] {
        assert_eq!(
            unconfirmed
                .bindings
                .iter()
                .find(|binding| binding.txid == outpoint.txid.to_string()
                    && binding.vout == outpoint.vout)
                .context("unconfirmed duplicate binding")?
                .observation_status,
            Bip448ObservationStatus::Unconfirmed
        );
    }
    common::bitcoin_core::mine_blocks(client_config.confirmation_target - 1)?;
    let confirmed = passive_sync_preserving_state(
        &client_config,
        &lockbox_client,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    for outpoint in [small.outpoint, large.outpoint] {
        assert_eq!(
            confirmed
                .bindings
                .iter()
                .find(|binding| binding.txid == outpoint.txid.to_string()
                    && binding.vout == outpoint.vout)
                .context("confirmed duplicate binding")?
                .observation_status,
            Bip448ObservationStatus::Confirmed
        );
    }

    // Close and reopen every client connection: the next inventory is rebuilt
    // from Bitcoin and keeps the exact outpoint-to-index assignment.
    let durable_indices = confirmed
        .bindings
        .iter()
        .filter(|binding| binding.statechain_id == deposit.statechain_id)
        .map(|binding| ((binding.txid.clone(), binding.vout), binding.binding_index))
        .collect::<std::collections::BTreeMap<_, _>>();
    client_config.pool.close().await;
    drop(client_config);
    let client_config = ClientConfig::load().await;
    let restarted = passive_sync_preserving_state(
        &client_config,
        &lockbox_client,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    let restarted_indices = restarted
        .bindings
        .iter()
        .filter(|binding| binding.statechain_id == deposit.statechain_id)
        .map(|binding| ((binding.txid.clone(), binding.vout), binding.binding_index))
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(restarted_indices, durable_indices);

    let restarted_bindings = restarted
        .bindings
        .iter()
        .filter(|binding| binding.statechain_id == deposit.statechain_id)
        .cloned()
        .collect::<Vec<_>>();
    let current_tip = client_config.chain_client.tip_height()?;
    let current_observations = restarted_bindings
        .iter()
        .map(|binding| observation(binding, binding.observation_status, current_tip, None, None))
        .collect::<Vec<_>>();
    let fake_observation = Bip448BindingObservation {
        txid: "fe".repeat(32),
        vout: 7,
        value_sats: 9_999,
        script_pubkey: script_pubkey.clone(),
        observation_status: Bip448ObservationStatus::Confirmed,
        funding_height: Some(1),
        spend_txid: None,
        spend_height: None,
        last_scanned_height: current_tip,
    };
    let binding_count_before_integrity = restarted_bindings.len() as i64;
    let count_before_integrity =
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?;

    // Record-only storage is not acceptance: without its exact history, a
    // novel observation cannot create a binding.
    let saved_history = sqlx::query_as::<_, (i64, String)>(
        "SELECT state_number,entry_json FROM bip448_state_history \
         WHERE wallet_name=$1 AND statechain_id=$2 ORDER BY state_number",
    )
    .bind(&wallet_name)
    .bind(&deposit.statechain_id)
    .fetch_all(&client_config.pool)
    .await?;
    sqlx::query("DELETE FROM bip448_state_history WHERE wallet_name=$1 AND statechain_id=$2")
        .bind(&wallet_name)
        .bind(&deposit.statechain_id)
        .execute(&client_config.pool)
        .await?;
    let mut observations_with_fake = current_observations.clone();
    observations_with_fake.push(fake_observation.clone());
    assert!(
        mercuryrustlib::sqlite_manager::reconcile_bip448_funding_bindings(
            &client_config.pool,
            &wallet_name,
            &deposit.statechain_id,
            &owner_user_pubkey,
            owner_state_number,
            &observations_with_fake,
        )
        .await
        .is_err()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bip448_funding_bindings \
             WHERE wallet_name=$1 AND statechain_id=$2",
        )
        .bind(&wallet_name)
        .bind(&deposit.statechain_id)
        .fetch_one(&client_config.pool)
        .await?,
        binding_count_before_integrity
    );
    for (state_number, entry_json) in &saved_history {
        sqlx::query(
            "INSERT INTO bip448_state_history \
             (wallet_name,statechain_id,state_number,entry_json) VALUES ($1,$2,$3,$4)",
        )
        .bind(&wallet_name)
        .bind(&deposit.statechain_id)
        .bind(*state_number)
        .bind(entry_json)
        .execute(&client_config.pool)
        .await?;
    }

    // History-only storage is equally insufficient. Preserve and restore the
    // accepted row byte-for-byte around the deliberately failed reconcile.
    type StoredRecord = (
        String,
        String,
        String,
        String,
        i64,
        i64,
        i64,
        i64,
        i64,
        String,
        String,
        String,
        String,
    );
    let saved_record = sqlx::query_as::<_, StoredRecord>(
        "SELECT wallet_name,statechain_id,aggregate_pubkey,funding_txid,funding_vout,\
         funding_value_sats,latest_state_number,challenge_delay,amount_sats,network,\
         record_json,created_at,updated_at FROM bip448_statechains \
         WHERE wallet_name=$1 AND statechain_id=$2",
    )
    .bind(&wallet_name)
    .bind(&deposit.statechain_id)
    .fetch_one(&client_config.pool)
    .await?;
    sqlx::query("DELETE FROM bip448_statechains WHERE wallet_name=$1 AND statechain_id=$2")
        .bind(&wallet_name)
        .bind(&deposit.statechain_id)
        .execute(&client_config.pool)
        .await?;
    assert!(
        mercuryrustlib::sqlite_manager::reconcile_bip448_funding_bindings(
            &client_config.pool,
            &wallet_name,
            &deposit.statechain_id,
            &owner_user_pubkey,
            owner_state_number,
            &observations_with_fake,
        )
        .await
        .is_err()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bip448_funding_bindings \
             WHERE wallet_name=$1 AND statechain_id=$2",
        )
        .bind(&wallet_name)
        .bind(&deposit.statechain_id)
        .fetch_one(&client_config.pool)
        .await?,
        binding_count_before_integrity
    );
    sqlx::query(
        "INSERT INTO bip448_statechains (wallet_name,statechain_id,aggregate_pubkey,\
         funding_txid,funding_vout,funding_value_sats,latest_state_number,challenge_delay,\
         amount_sats,network,record_json,created_at,updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
    )
    .bind(&saved_record.0)
    .bind(&saved_record.1)
    .bind(&saved_record.2)
    .bind(&saved_record.3)
    .bind(saved_record.4)
    .bind(saved_record.5)
    .bind(saved_record.6)
    .bind(saved_record.7)
    .bind(saved_record.8)
    .bind(&saved_record.9)
    .bind(&saved_record.10)
    .bind(&saved_record.11)
    .bind(&saved_record.12)
    .execute(&client_config.pool)
    .await?;
    assert_eq!(
        accepted_state_bytes(&client_config.pool, &wallet_name, &deposit.statechain_id).await?,
        accepted_before
    );
    let idempotent_rows = mercuryrustlib::sqlite_manager::reconcile_bip448_funding_bindings(
        &client_config.pool,
        &wallet_name,
        &deposit.statechain_id,
        &owner_user_pubkey,
        owner_state_number,
        &current_observations,
    )
    .await?;
    assert_eq!(idempotent_rows.len() as i64, binding_count_before_integrity);
    assert_eq!(
        idempotent_rows
            .iter()
            .map(|binding| ((binding.txid.clone(), binding.vout), binding.binding_index))
            .collect::<std::collections::BTreeMap<_, _>>(),
        durable_indices
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
        count_before_integrity
    );

    // Stage both a new observation and a cursor/cache revision under one
    // guard, then simulate a process crash by dropping it before commit.
    let cursor_before = sqlx::query_as::<_, (i64, i64, i64, String)>(
        "SELECT coverage_start_height,scan_revision,last_scanned_height,last_scanned_block_hash \
         FROM bip448_scan_cursors WHERE wallet_name=$1 AND script_pubkey=$2",
    )
    .bind(&wallet_name)
    .bind(&script_pubkey)
    .fetch_one(&client_config.pool)
    .await?;
    let bindings_before_crash = mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
        &client_config.pool,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    let crash_base = mercuryrustlib::sqlite_manager::capture_bip448_sync_base(
        &client_config.pool,
        &wallet_name,
        &script_pubkey,
    )
    .await?;
    let mut crash_guard = mercuryrustlib::sqlite_manager::begin_bip448_sync_base_guard(
        &client_config.pool,
        &crash_base,
    )
    .await?;
    crash_guard
        .reconcile_funding_bindings(
            &wallet_name,
            &deposit.statechain_id,
            &owner_user_pubkey,
            owner_state_number,
            &observations_with_fake,
        )
        .await?;
    crash_guard
        .apply_scan_cache_and_cursor(
            &wallet_name,
            &script_pubkey,
            &Bip448ScanCursor {
                coverage_start_height: u32::try_from(cursor_before.0)?,
                scan_revision: u64::try_from(cursor_before.1)?,
                last_scanned_height: u32::try_from(cursor_before.2)?
                    .checked_add(1)
                    .context("test cursor height overflow")?,
                last_scanned_block_hash: client_config
                    .chain_client
                    .get_block_hash(client_config.chain_client.tip_height()?)?
                    .to_string(),
            },
            &[],
        )
        .await?;
    drop(crash_guard);
    tokio::task::yield_now().await;
    assert_eq!(
        sqlx::query_as::<_, (i64, i64, i64, String)>(
            "SELECT coverage_start_height,scan_revision,last_scanned_height,last_scanned_block_hash \
             FROM bip448_scan_cursors WHERE wallet_name=$1 AND script_pubkey=$2",
        )
        .bind(&wallet_name)
        .bind(&script_pubkey)
        .fetch_one(&client_config.pool)
        .await?,
        cursor_before
    );
    assert_eq!(
        mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
            &client_config.pool,
            &wallet_name,
            &deposit.statechain_id,
        )
        .await?,
        bindings_before_crash
    );

    // A newer scan commits first. The older pre-RPC snapshot cannot follow it,
    // even though both began from the same accepted wallet and chain tip.
    let reversed_commit_base = mercuryrustlib::sqlite_manager::capture_bip448_sync_base(
        &client_config.pool,
        &wallet_name,
        &script_pubkey,
    )
    .await?;
    let newer_scan = passive_sync_preserving_state(
        &client_config,
        &lockbox_client,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    assert!(
        mercuryrustlib::sqlite_manager::begin_bip448_sync_base_guard(
            &client_config.pool,
            &reversed_commit_base,
        )
        .await
        .is_err(),
        "an older candidate committed after the newer full SyncBase winner"
    );

    // A second same-tip no-op scan advances only the durable revision. A final
    // wallet CAS holding the first scan's token must still lose.
    let stale_wallet_json: String =
        sqlx::query_scalar("SELECT wallet_json FROM wallet WHERE wallet_name=$1")
            .bind(&wallet_name)
            .fetch_one(&client_config.pool)
            .await?;
    let stale_tokens = newer_scan.applied_scan_revisions.clone();
    assert!(!stale_tokens.is_empty());
    let same_tip_winner = passive_sync_preserving_state(
        &client_config,
        &lockbox_client,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    for stale in &stale_tokens {
        let winner = same_tip_winner
            .applied_scan_revisions
            .iter()
            .find(|token| token.script_pubkey == stale.script_pubkey)
            .context("same-tip winner omitted a script revision")?;
        assert!(winner.scan_revision > stale.scan_revision);
    }
    let mut stale_replacement =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet_name).await?;
    stale_replacement.blockheight = stale_replacement
        .blockheight
        .checked_add(1)
        .context("stale replacement height overflow")?;
    assert!(
        !mercuryrustlib::sqlite_manager::compare_and_set_wallet_after_bip448_scan(
            &client_config.pool,
            &wallet_name,
            &stale_wallet_json,
            &stale_replacement,
            &stale_tokens,
        )
        .await?
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT wallet_json FROM wallet WHERE wallet_name=$1",)
            .bind(&wallet_name)
            .fetch_one(&client_config.pool)
            .await?,
        stale_wallet_json
    );

    // The interim old canonical withdrawal gate must fail before any signing,
    // broadcast, completion, activity, or server mutation.
    let withdrawal_wallet_before = stale_wallet_json.clone();
    let withdrawal_accepted_before =
        accepted_state_bytes(&client_config.pool, &wallet_name, &deposit.statechain_id).await?;
    let withdrawal_mercury_before = mercury_state_bytes(&deposit.statechain_id).await?;
    let withdrawal_count_before =
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?;
    let withdrawal_rows_before = sqlx::query_as::<_, (i64, i64, i64)>(
        "SELECT \
         (SELECT COUNT(*) FROM bip448_withdrawal_attempts WHERE wallet_name=$1 AND statechain_id=$2),\
         (SELECT COUNT(*) FROM bip448_pending_transfer_signings WHERE wallet_name=$1 AND statechain_id=$2),\
         (SELECT COUNT(*) FROM bip448_transfer_messages WHERE wallet_name=$1 AND statechain_id=$2)",
    )
    .bind(&wallet_name)
    .bind(&deposit.statechain_id)
    .fetch_one(&client_config.pool)
    .await?;
    let withdrawal_destination = common::bitcoin_core::getnewaddress()?;
    let withdrawal_error = mercuryrustlib::bip448_withdraw::execute(
        &client_config,
        &wallet_name,
        &deposit.statechain_id,
        &withdrawal_destination,
        Some(1.0),
    )
    .await
    .expect_err("old canonical withdrawal must reject every duplicate binding");
    let withdrawal_error = withdrawal_error.to_string();
    assert!(
        withdrawal_error
            .contains("BIP448 canonical withdrawal is blocked by unresolved close facts"),
        "unexpected canonical close-gate error: {withdrawal_error}"
    );
    assert!(
        withdrawal_error.contains("BindingObservation"),
        "canonical close did not report its unresolved duplicate binding: {withdrawal_error}"
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT wallet_json FROM wallet WHERE wallet_name=$1",)
            .bind(&wallet_name)
            .fetch_one(&client_config.pool)
            .await?,
        withdrawal_wallet_before
    );
    assert_eq!(
        accepted_state_bytes(&client_config.pool, &wallet_name, &deposit.statechain_id).await?,
        withdrawal_accepted_before
    );
    assert_eq!(
        mercury_state_bytes(&deposit.statechain_id).await?,
        withdrawal_mercury_before
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
        withdrawal_count_before
    );
    assert_eq!(
        sqlx::query_as::<_, (i64, i64, i64)>(
            "SELECT \
             (SELECT COUNT(*) FROM bip448_withdrawal_attempts WHERE wallet_name=$1 AND statechain_id=$2),\
             (SELECT COUNT(*) FROM bip448_pending_transfer_signings WHERE wallet_name=$1 AND statechain_id=$2),\
             (SELECT COUNT(*) FROM bip448_transfer_messages WHERE wallet_name=$1 AND statechain_id=$2)",
        )
        .bind(&wallet_name)
        .bind(&deposit.statechain_id)
        .fetch_one(&client_config.pool)
        .await?,
        withdrawal_rows_before
    );

    // A real mempool eviction must force one authoritative height-zero replay.
    // The public sync path observes Absent, then the exact transactions
    // reappear with their original stable indices and no canonical mutation.
    let inventory = mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
        &client_config.pool,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    let canonical_binding = inventory
        .iter()
        .find(|binding| binding.binding_index == 0)
        .context("canonical inventory binding")?
        .clone();
    let small_binding = inventory
        .iter()
        .find(|binding| binding.txid == small.outpoint.txid.to_string())
        .context("small duplicate inventory binding")?
        .clone();
    let stable_small_index = small_binding.binding_index;
    let large_binding_before_eviction = inventory
        .iter()
        .find(|binding| binding.txid == large.outpoint.txid.to_string())
        .context("large duplicate inventory binding before eviction")?
        .clone();
    let stable_large_index = large_binding_before_eviction.binding_index;
    let small_transaction = common::bitcoin_core::wallet_transaction(&small.outpoint.txid)?;
    let large_transaction = common::bitcoin_core::wallet_transaction(&large.outpoint.txid)?;
    assert!(
        common::bitcoin_core::raw_mempool()?.is_empty(),
        "the eviction fixture requires an empty persisted mempool baseline"
    );
    common::bitcoin_core::execute_bitcoin_command(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury savemempool",
    )?;
    common::bitcoin_core::execute_bitcoin_command(&format!(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury invalidateblock {duplicate_funding_block_hash}"
    ))?;
    let reorged_receives = passive_sync_preserving_state(
        &client_config,
        &lockbox_client,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    for (outpoint, stable_index) in [
        (small.outpoint, stable_small_index),
        (large.outpoint, stable_large_index),
    ] {
        let row = reorged_receives
            .bindings
            .iter()
            .find(|binding| binding.txid == outpoint.txid.to_string())
            .context("reorged mempool receive binding")?;
        assert_eq!(row.binding_index, stable_index);
        assert_eq!(row.observation_status, Bip448ObservationStatus::Mempool);
    }

    let eviction_tip_height = client_config.chain_client.tip_height()?;
    let flushed_chainstate: serde_json::Value =
        serde_json::from_str(&common::bitcoin_core::execute_bitcoin_command(
            "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury gettxoutsetinfo none",
        )?)?;
    assert_eq!(
        flushed_chainstate
            .get("height")
            .and_then(serde_json::Value::as_u64),
        Some(u64::from(eviction_tip_height)),
        "the eviction fixture must flush the exact post-invalidation chain tip"
    );
    common::bitcoin_core::execute_bitcoin_command(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury unloadwallet mercury_test",
    )?;
    common::bitcoin_core::execute_bitcoin_command(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury unloadwallet mercury_tokens",
    )?;
    let bitcoin_container = common::bitcoin_core::get_container_id()?;
    restart_bitcoin_core_after_unclean_stop(&bitcoin_container)?;
    assert_eq!(
        client_config.chain_client.tip_height()?,
        eviction_tip_height,
        "the force-flushed post-invalidation tip must survive the unclean restart"
    );
    common::bitcoin_core::assert_not_in_mempool(&small.outpoint.txid)?;
    common::bitcoin_core::assert_not_in_mempool(&large.outpoint.txid)?;
    let absent_receives = passive_sync_preserving_state(
        &client_config,
        &lockbox_client,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    for (outpoint, stable_index) in [
        (small.outpoint, stable_small_index),
        (large.outpoint, stable_large_index),
    ] {
        let row = absent_receives
            .bindings
            .iter()
            .find(|binding| binding.txid == outpoint.txid.to_string())
            .context("authoritatively absent receive binding")?;
        assert_eq!(row.binding_index, stable_index);
        assert_eq!(row.observation_status, Bip448ObservationStatus::Absent);
    }
    assert_eq!(absent_receives.bindings.len(), inventory.len());

    assert_eq!(
        common::bitcoin_core::broadcast_raw_transaction(&small_transaction)?,
        small.outpoint.txid
    );
    assert_eq!(
        common::bitcoin_core::broadcast_raw_transaction(&large_transaction)?,
        large.outpoint.txid
    );
    let reappeared_receives = passive_sync_preserving_state(
        &client_config,
        &lockbox_client,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    for (outpoint, stable_index) in [
        (small.outpoint, stable_small_index),
        (large.outpoint, stable_large_index),
    ] {
        let row = reappeared_receives
            .bindings
            .iter()
            .find(|binding| binding.txid == outpoint.txid.to_string())
            .context("reappeared mempool receive binding")?;
        assert_eq!(row.binding_index, stable_index);
        assert_eq!(row.observation_status, Bip448ObservationStatus::Mempool);
    }
    assert_eq!(reappeared_receives.bindings.len(), inventory.len());

    common::bitcoin_core::execute_bitcoin_command(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury loadwallet mercury_test",
    )?;
    common::bitcoin_core::execute_bitcoin_command(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury loadwallet mercury_tokens",
    )?;
    common::bitcoin_core::execute_bitcoin_command(&format!(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury reconsiderblock {duplicate_funding_block_hash}"
    ))?;
    common::bitcoin_core::ensure_wallet_loaded()?;
    let restored_receive = passive_sync_preserving_state(
        &client_config,
        &lockbox_client,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    assert_eq!(
        restored_receive
            .bindings
            .iter()
            .find(|binding| binding.txid == small_binding.txid)
            .context("restored receive binding")?
            .observation_status,
        Bip448ObservationStatus::Confirmed
    );
    assert_eq!(
        restored_receive
            .bindings
            .iter()
            .find(|binding| binding.txid == large_binding_before_eviction.txid)
            .context("restored large receive binding")?
            .binding_index,
        stable_large_index
    );

    // Use the retained key-path primitive only to manufacture a real external
    // spend. Every subsequent observation is passive and must leave the new
    // signature count fixed.
    let wallet_for_spend =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet_name).await?;
    let canonical_coin = wallet_for_spend
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some(deposit.statechain_id.as_str()))
        .context("canonical Coin for duplicate test spend")?
        .clone();
    let large_binding = restored_receive
        .bindings
        .iter()
        .find(|binding| binding.txid == large.outpoint.txid.to_string())
        .context("large duplicate inventory binding")?
        .clone();
    assert_eq!(large_binding.binding_index, stable_large_index);
    let spend_txid =
        sign_and_broadcast_duplicate(&client_config, &canonical_coin, &large_binding).await?;
    let signed_count =
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?;
    assert_eq!(signed_count, withdrawal_count_before + 1);
    let spent_mempool = passive_sync_preserving_state(
        &client_config,
        &lockbox_client,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    let spent_row = spent_mempool
        .bindings
        .iter()
        .find(|binding| binding.binding_index == stable_large_index)
        .context("mempool-spent duplicate")?;
    assert_eq!(
        spent_row.observation_status,
        Bip448ObservationStatus::SpentMempool
    );
    assert_eq!(
        spent_row.spend_txid.as_deref(),
        Some(spend_txid.to_string().as_str())
    );

    common::bitcoin_core::mine_block_with_transactions(&[spend_txid])?;
    let spend_block_height = client_config.chain_client.tip_height()?;
    let spend_block_hash = client_config
        .chain_client
        .get_block_hash(spend_block_height)?
        .to_string();
    let spent_unconfirmed = passive_sync_preserving_state(
        &client_config,
        &lockbox_client,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    assert_eq!(
        spent_unconfirmed
            .bindings
            .iter()
            .find(|binding| binding.binding_index == stable_large_index)
            .context("unconfirmed-spent duplicate")?
            .observation_status,
        Bip448ObservationStatus::SpentUnconfirmed
    );
    common::bitcoin_core::mine_blocks(client_config.confirmation_target - 1)?;
    let spent_confirmed = passive_sync_preserving_state(
        &client_config,
        &lockbox_client,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    assert_eq!(
        spent_confirmed
            .bindings
            .iter()
            .find(|binding| binding.binding_index == stable_large_index)
            .context("confirmed-spent duplicate")?
            .observation_status,
        Bip448ObservationStatus::SpentConfirmed
    );

    common::bitcoin_core::execute_bitcoin_command(&format!(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury invalidateblock {spend_block_hash}"
    ))?;
    let reorged = passive_sync_preserving_state(
        &client_config,
        &lockbox_client,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    let reorged_spend = reorged
        .bindings
        .iter()
        .find(|binding| binding.binding_index == stable_large_index)
        .context("reorged duplicate spend")?;
    assert_eq!(reorged_spend.binding_index, stable_large_index);
    assert_eq!(
        reorged_spend.observation_status,
        Bip448ObservationStatus::SpentMempool
    );
    assert!(reorged.bindings.iter().all(|binding| {
        binding.txid == large_binding.txid
            || binding.observation_status != Bip448ObservationStatus::Absent
    }));
    let cursor_coverage: i64 = sqlx::query_scalar(
        "SELECT coverage_start_height FROM bip448_scan_cursors \
         WHERE wallet_name=$1 AND script_pubkey=$2",
    )
    .bind(&wallet_name)
    .bind(&script_pubkey)
    .fetch_one(&client_config.pool)
    .await?;
    assert_eq!(cursor_coverage, 0);

    // Inject the authoritative result of mempool-spend eviction, then restore
    // the original block. Neither transition removes or renumbers the row.
    let reorg_tip = client_config.chain_client.tip_height()?;
    let eviction_rows = mercuryrustlib::sqlite_manager::reconcile_bip448_funding_bindings(
        &client_config.pool,
        &wallet_name,
        &deposit.statechain_id,
        &owner_user_pubkey,
        owner_state_number,
        &[
            observation(
                &canonical_binding,
                canonical_binding.observation_status,
                reorg_tip,
                None,
                None,
            ),
            observation(
                &large_binding,
                Bip448ObservationStatus::Confirmed,
                reorg_tip,
                None,
                None,
            ),
        ],
    )
    .await?;
    assert_eq!(
        eviction_rows
            .iter()
            .find(|binding| binding.binding_index == stable_large_index)
            .context("mempool-spend eviction row")?
            .observation_status,
        Bip448ObservationStatus::Confirmed
    );
    assert_eq!(eviction_rows.len(), inventory.len());
    common::bitcoin_core::execute_bitcoin_command(&format!(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury reconsiderblock {spend_block_hash}"
    ))?;
    let reconsidered = passive_sync_preserving_state(
        &client_config,
        &lockbox_client,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    assert_eq!(
        reconsidered
            .bindings
            .iter()
            .find(|binding| binding.binding_index == stable_large_index)
            .context("reconsidered duplicate spend")?
            .observation_status,
        Bip448ObservationStatus::SpentConfirmed
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
        signed_count
    );

    // The real list path keeps one logical Coin, preserves the seven legacy
    // fields, and nests all duplicate inventory in stable-index order.
    let final_wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet_name).await?;
    let logical_coins = final_wallet
        .coins
        .iter()
        .filter(|coin| coin.statechain_id.as_deref() == Some(deposit.statechain_id.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(logical_coins.len(), 1, "duplicate discovery cloned a Coin");
    let list =
        mercuryrustlib::coin_status::statecoin_list_json(&client_config, &final_wallet).await?;
    let listed = list
        .iter()
        .find(|entry| {
            entry
                .get("coin.statechain_id")
                .and_then(serde_json::Value::as_str)
                == Some(deposit.statechain_id.as_str())
        })
        .context("nested duplicate list entry")?;
    let expected_outer_keys = [
        "coin.address",
        "coin.address_retired",
        "coin.aggregated_address",
        "coin.amount",
        "coin.close_tip_hash",
        "coin.close_tip_height",
        "coin.duplicates",
        "coin.exit_only",
        "coin.locktime",
        "coin.statechain_id",
        "coin.statechain_protocol",
        "coin.status",
        "coin.user_pubkey",
        "coin.utxo_txid",
        "coin.utxo_vout",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    assert_eq!(
        listed
            .as_object()
            .context("statecoin list entry object")?
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        expected_outer_keys
    );
    assert_eq!(
        listed["coin.amount"].as_u64(),
        Some(u64::from(FUNDING_AMOUNT_SATS))
    );
    assert!(listed["coin.close_tip_height"].is_null());
    assert!(listed["coin.close_tip_hash"].is_null());
    let duplicate_json = listed["coin.duplicates"]
        .as_array()
        .context("nested duplicate array")?;
    assert_eq!(duplicate_json.len(), 3);
    assert_eq!(
        duplicate_json
            .iter()
            .map(|row| row["duplicate_index"].as_u64())
            .collect::<Vec<_>>(),
        vec![Some(1), Some(2), Some(3)]
    );
    let expected_duplicate_keys = [
        "amount_sats",
        "broadcast_status",
        "cooperative_only",
        "duplicate_index",
        "observation_status",
        "ownership_status",
        "server_dependent",
        "spend_txid",
        "sweep_phase",
        "txid",
        "vout",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    for row in duplicate_json {
        assert_eq!(
            row.as_object()
                .context("nested duplicate object")?
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>(),
            expected_duplicate_keys
        );
        assert!(row["amount_sats"].as_u64().is_some());
        assert!(row["vout"].as_u64().is_some());
    }
    assert_eq!(
        duplicate_json
            .iter()
            .map(|row| row["amount_sats"].as_u64().expect("u64 duplicate amount"))
            .collect::<BTreeSet<_>>(),
        [
            u64::from(DUST_DUPLICATE_AMOUNT_SATS),
            u64::from(SMALL_DUPLICATE_AMOUNT_SATS),
            u64::from(DUPLICATE_AMOUNT_SATS),
        ]
        .into_iter()
        .collect()
    );

    // Full attachment identity prevents rows from another statechain, wallet,
    // or owner generation on a reused aggregate script from leaking in.
    let truth_binding = reconsidered
        .bindings
        .iter()
        .find(|binding| binding.txid == small_binding.txid)
        .context("truth-table duplicate")?
        .clone();
    let mut foreign_statechain = truth_binding.clone();
    foreign_statechain.statechain_id = format!("foreign-{}", uuid::Uuid::new_v4());
    let mut foreign_wallet = truth_binding.clone();
    foreign_wallet.wallet_name = format!("foreign-{}", uuid::Uuid::new_v4());
    let mut foreign_owner = truth_binding.clone();
    foreign_owner.owner_user_pubkey = "02".repeat(32);
    let isolated = mercuryrustlib::coin_status::statecoin_list_entry_json(
        &wallet_name,
        logical_coins[0],
        &[
            truth_binding.clone(),
            foreign_statechain,
            foreign_wallet,
            foreign_owner,
        ],
        &[],
    )?;
    assert_eq!(
        isolated["coin.duplicates"]
            .as_array()
            .context("isolated duplicates")?
            .len(),
        1
    );

    let flags = |entry: &serde_json::Value| -> Result<(bool, bool)> {
        let row = entry["coin.duplicates"]
            .as_array()
            .and_then(|rows| rows.first())
            .context("truth-table duplicate row")?;
        Ok((
            row["cooperative_only"]
                .as_bool()
                .context("cooperative_only bool")?,
            row["server_dependent"]
                .as_bool()
                .context("server_dependent bool")?,
        ))
    };
    let mut current_live = truth_binding.clone();
    current_live.observation_status = Bip448ObservationStatus::Confirmed;
    current_live.spend_txid = None;
    current_live.spend_height = None;
    current_live.ownership_status = Bip448OwnershipStatus::Current;
    assert_eq!(
        flags(&mercuryrustlib::coin_status::statecoin_list_entry_json(
            &wallet_name,
            logical_coins[0],
            &[current_live.clone()],
            &[],
        )?)?,
        (true, true)
    );
    for phase in [
        Bip448WithdrawalPhase::Prepared,
        Bip448WithdrawalPhase::FirstArmed,
        Bip448WithdrawalPhase::NonceStored,
        Bip448WithdrawalPhase::SecondArmed,
    ] {
        let attempt = attempt_for(
            &current_live,
            current_live.binding_index,
            Bip448WithdrawalAttemptKind::Duplicate,
            phase,
        );
        assert_eq!(
            flags(&mercuryrustlib::coin_status::statecoin_list_entry_json(
                &wallet_name,
                logical_coins[0],
                &[current_live.clone()],
                &[attempt],
            )?)?,
            (true, true),
            "non-durable phase {phase} changed cooperative truth"
        );
    }
    let signed_attempt = attempt_for(
        &current_live,
        current_live.binding_index,
        Bip448WithdrawalAttemptKind::Duplicate,
        Bip448WithdrawalPhase::Signed,
    );
    assert_eq!(
        flags(&mercuryrustlib::coin_status::statecoin_list_entry_json(
            &wallet_name,
            logical_coins[0],
            &[current_live.clone()],
            &[signed_attempt],
        )?)?,
        (false, false)
    );
    let mut independently_spent = current_live.clone();
    independently_spent.observation_status = Bip448ObservationStatus::SpentConfirmed;
    independently_spent.spend_txid = Some("ab".repeat(32));
    independently_spent.spend_height = Some(1);
    assert_eq!(
        flags(&mercuryrustlib::coin_status::statecoin_list_entry_json(
            &wallet_name,
            logical_coins[0],
            &[independently_spent],
            &[],
        )?)?,
        (false, false)
    );
    let mut previous_unresolved = current_live.clone();
    previous_unresolved.ownership_status = Bip448OwnershipStatus::Previous;
    assert_eq!(
        flags(&mercuryrustlib::coin_status::statecoin_list_entry_json(
            &wallet_name,
            logical_coins[0],
            &[previous_unresolved],
            &[],
        )?)?,
        (true, false)
    );
    let canonical_attempt = attempt_for(
        &canonical_binding,
        0,
        Bip448WithdrawalAttemptKind::Canonical,
        Bip448WithdrawalPhase::Prepared,
    );
    let retired = mercuryrustlib::coin_status::statecoin_list_entry_json(
        &wallet_name,
        logical_coins[0],
        &[current_live],
        &[canonical_attempt],
    )?;
    assert_eq!(flags(&retired)?, (true, false));
    assert_eq!(retired["coin.address_retired"].as_bool(), Some(true));

    let final_indices = mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
        &client_config.pool,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?
    .into_iter()
    .map(|binding| ((binding.txid, binding.vout), binding.binding_index))
    .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(final_indices, durable_indices);
    assert_eq!(
        accepted_state_bytes(&client_config.pool, &wallet_name, &deposit.statechain_id).await?,
        accepted_before
    );
    assert_eq!(logical_coins[0].amount, Some(FUNDING_AMOUNT_SATS));
    assert_eq!(
        logical_coins[0].utxo_txid.as_deref(),
        Some(canonical.outpoint.txid.to_string().as_str())
    );
    assert_eq!(logical_coins[0].utxo_vout, Some(canonical.outpoint.vout));
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
        signed_count
    );

    println!(
        "BIP448 duplicate inventory stable: statechain_id={} canonical={} dust={} small={} large={} spend={} indices={:?}",
        deposit.statechain_id,
        canonical.outpoint,
        dust.outpoint,
        small.outpoint,
        large.outpoint,
        spend_txid,
        final_indices,
    );

    Ok(())
}

struct DuplicateSweepFixture {
    config: ClientConfig,
    wallet_name: String,
    statechain_id: String,
    bindings: Vec<Bip448FundingBinding>,
}

async fn duplicate_sweep_fixture(duplicate_amounts: &[u32]) -> Result<DuplicateSweepFixture> {
    let config = common::prepare_test_env().await?;
    let wallet_name = format!("bip448-sweep-{}", uuid::Uuid::new_v4());
    let wallet = mercuryrustlib::wallet::create_wallet(&wallet_name, &config).await?;
    mercuryrustlib::sqlite_manager::insert_wallet(&config.pool, &wallet).await?;
    let token = mercuryrustlib::deposit::get_token(&config).await?;
    let token_id = common::utils::handle_token_response(&config, &token).await?;
    let deposit = mercuryrustlib::deposit::get_bip448_deposit_bitcoin_address(
        &config,
        &wallet_name,
        &token_id,
        FUNDING_AMOUNT_SATS,
    )
    .await?;
    let aggregate_address = Address::from_str(&deposit.address)?.require_network(config.network)?;
    let canonical = fund_address_output(&aggregate_address, FUNDING_AMOUNT_SATS)?;
    common::chain::wait_for_address_outpoint(
        &config,
        &deposit.address,
        canonical.outpoint,
        canonical.value_sats,
    )
    .await?;
    common::bitcoin_core::mine_blocks(config.confirmation_target)?;
    mercuryrustlib::coin_status::update_coins(&config, &wallet_name).await?;
    for amount in duplicate_amounts {
        fund_address_output(&aggregate_address, *amount)?;
    }
    common::bitcoin_core::mine_blocks(config.confirmation_target)?;
    let report =
        mercuryrustlib::coin_status::sync_bip448_funding_bindings(&config, &wallet_name).await?;
    let mut bindings = report
        .bindings
        .into_iter()
        .filter(|binding| binding.statechain_id == deposit.statechain_id)
        .collect::<Vec<_>>();
    bindings.sort_by_key(|binding| binding.binding_index);
    assert_eq!(bindings.len(), duplicate_amounts.len() + 1);
    assert_eq!(bindings[0].role, Bip448BindingRole::Canonical);
    for binding in bindings.iter().skip(1) {
        assert_eq!(binding.role, Bip448BindingRole::Duplicate);
        assert_eq!(
            binding.observation_status,
            Bip448ObservationStatus::Confirmed
        );
        assert_eq!(binding.ownership_status, Bip448OwnershipStatus::Current);
    }
    Ok(DuplicateSweepFixture {
        config,
        wallet_name,
        statechain_id: deposit.statechain_id,
        bindings,
    })
}

async fn retained_update_conflict_package(
    fixture: &DuplicateSweepFixture,
    duplicate: &Bip448FundingBinding,
) -> Result<Bip448RecoveryPackage> {
    let record = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?;
    assert_eq!(
        duplicate.value_sats, record.funding_outpoint.value_sats,
        "retained U may only be rebound to an exact-value duplicate"
    );
    assert_eq!(
        duplicate.script_pubkey, fixture.bindings[0].script_pubkey,
        "competing-spend target is not the accepted aggregate script"
    );
    let retained_update_bytes = hex::decode(&record.latest_state.update_tx)?;
    let retained_update: bitcoin::Transaction =
        bitcoin::consensus::deserialize(&retained_update_bytes)?;
    assert_eq!(
        bitcoin::consensus::serialize(&retained_update),
        retained_update_bytes
    );
    let retained_hash = transaction::update_template_hash(&retained_update)?;
    let retained_witness = retained_update.input[0].witness.clone();
    let rebound = transaction::rebind_update_tx(
        &retained_update,
        OutPoint {
            txid: Txid::from_str(&duplicate.txid)?,
            vout: duplicate.vout,
        },
        duplicate.value_sats,
        FeePolicy::ZeroFeeEphemeralAnchor,
    )?;
    assert_eq!(
        transaction::update_template_hash(&rebound)?,
        retained_hash,
        "retained U template hash changed during exact rebinding"
    );
    assert_eq!(
        rebound.input[0].witness, retained_witness,
        "retained U signature witness changed during rebinding"
    );
    let anchor = record
        .latest_state
        .anchors
        .iter()
        .find(|anchor| anchor.tx_role == Bip448RecoveryTemplateRole::FundingUpdate)
        .context("retained U has no FundingUpdate anchor metadata")?;
    let fee_funding = fund_p2a_fee_input()?;
    common::bitcoin_core::mine_block()?;
    let fee_input = Bip448CpfpFeeInput::keyless(fee_funding.outpoint, fee_funding.value_sats);
    let change_script =
        common::bitcoin_core::regtest_address(&common::bitcoin_core::getnewaddress()?)?
            .script_pubkey();
    Ok(build_anchor_cpfp_package(
        &rebound,
        duplicate.value_sats,
        anchor.output_index,
        &[fee_input],
        change_script,
        2.0,
    )?)
}

fn save_empty_mempool_baseline() -> Result<()> {
    assert!(
        common::bitcoin_core::raw_mempool()?.is_empty(),
        "mempool baseline must be empty before the unclean-restart eviction"
    );
    common::bitcoin_core::execute_bitcoin_command(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury savemempool",
    )?;
    Ok(())
}

fn restart_core_dropping_unpersisted_mempool(
    config: &ClientConfig,
    expected_tip_height: u32,
    reload_wallets: bool,
) -> Result<()> {
    let flushed: serde_json::Value =
        serde_json::from_str(&common::bitcoin_core::execute_bitcoin_command(
            "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury gettxoutsetinfo none",
        )?)?;
    assert_eq!(
        flushed.get("height").and_then(serde_json::Value::as_u64),
        Some(u64::from(expected_tip_height))
    );
    let loaded_wallets: Vec<String> =
        serde_json::from_str(&common::bitcoin_core::execute_bitcoin_command(
            "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury listwallets",
        )?)?;
    for wallet_name in ["mercury_test", "mercury_tokens"] {
        if loaded_wallets.iter().any(|loaded| loaded == wallet_name) {
            common::bitcoin_core::execute_bitcoin_command(&format!(
                "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury unloadwallet {wallet_name}"
            ))?;
        }
    }
    let container = common::bitcoin_core::get_container_id()?;
    restart_bitcoin_core_after_unclean_stop(&container)?;
    assert_eq!(config.chain_client.tip_height()?, expected_tip_height);
    if reload_wallets {
        common::bitcoin_core::execute_bitcoin_command(
            "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury loadwallet mercury_test",
        )?;
        common::bitcoin_core::execute_bitcoin_command(
            "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury loadwallet mercury_tokens",
        )?;
    }
    Ok(())
}

fn submit_conflict_package(package: &Bip448RecoveryPackage) -> Result<()> {
    common::bitcoin_core::submit_package(&[
        package.parent_tx.clone(),
        package.cpfp_child_tx.clone(),
    ])?;
    common::bitcoin_core::assert_in_mempool(&package.parent_tx.txid())?;
    common::bitcoin_core::assert_in_mempool(&package.cpfp_child_tx.txid())?;
    Ok(())
}

fn confirm_conflict_package(
    config: &ClientConfig,
    package: &Bip448RecoveryPackage,
) -> Result<String> {
    submit_conflict_package(package)?;
    common::bitcoin_core::mine_block_with_transactions(&[
        package.parent_tx.txid(),
        package.cpfp_child_tx.txid(),
    ])?;
    let conflict_block_height = config.chain_client.tip_height()?;
    let conflict_block_hash = config
        .chain_client
        .get_block_hash(conflict_block_height)?
        .to_string();
    common::bitcoin_core::mine_blocks(config.confirmation_target.saturating_sub(1))?;
    Ok(conflict_block_hash)
}

fn invalidate_conflict_and_evict(
    config: &ClientConfig,
    conflict_block_hash: &str,
    conflict_txid: Txid,
    reload_wallets: bool,
) -> Result<()> {
    save_empty_mempool_baseline()?;
    common::bitcoin_core::execute_bitcoin_command(&format!(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury invalidateblock {conflict_block_hash}"
    ))?;
    common::bitcoin_core::assert_in_mempool(&conflict_txid)?;
    let reorg_tip = config.chain_client.tip_height()?;
    restart_core_dropping_unpersisted_mempool(config, reorg_tip, reload_wallets)?;
    common::bitcoin_core::assert_not_in_mempool(&conflict_txid)?;
    Ok(())
}

fn duplicate_attempt_immutable_json(attempt: &Bip448WithdrawalAttempt) -> serde_json::Value {
    serde_json::json!({
        "wallet_name": attempt.wallet_name,
        "statechain_id": attempt.statechain_id,
        "binding_index": attempt.binding_index,
        "attempt_kind": attempt.attempt_kind.to_string(),
        "owner_user_pubkey": attempt.owner_user_pubkey,
        "owner_state_number": attempt.owner_state_number,
        "source_txid": attempt.source_txid,
        "source_vout": attempt.source_vout,
        "source_value_sats": attempt.source_value_sats,
        "source_script_pubkey": attempt.source_script_pubkey,
        "destination_address": attempt.destination_address,
        "destination_script_pubkey": attempt.destination_script_pubkey,
        "fee_rate_bits": attempt.fee_rate_sat_per_vbyte.to_bits(),
        "fee_sats": attempt.fee_sats,
        "lock_time": attempt.lock_time,
        "unsigned_tx_hex": attempt.unsigned_tx_hex,
        "signing_id": attempt.signing_id,
        "signed_statechain_id": attempt.signed_statechain_id,
        "sign_first_payload_json": attempt.sign_first_payload_json,
        "client_secret_nonce": attempt.client_secret_nonce,
        "client_public_nonce": attempt.client_public_nonce,
        "blinding_factor": attempt.blinding_factor,
    })
}

async fn raw_withdrawal_attempt_journal_snapshot(
    config: &ClientConfig,
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
            client_public_nonce,blinding_factor,server_public_nonce,message_hex,output_pubkey,\
            client_partial_sig,encoded_session,sign_second_payload_json,server_partial_sig,\
            aggregate_signature,signed_tx_hex,txid,phase,broadcast_status,completion_status,\
            closing_tip_height,closing_tip_hash,closing_bindings_json,created_at,updated_at) \
         FROM bip448_withdrawal_attempts WHERE wallet_name=$1 AND statechain_id=$2 \
           AND binding_index=$3",
    )
    .bind(wallet_name)
    .bind(statechain_id)
    .bind(i64::from(binding_index))
    .fetch_one(&config.pool)
    .await?)
}

fn run_duplicate_sweep_child(
    wallet_name: &str,
    statechain_id: &str,
    duplicate_index: u32,
    destination: &str,
    checkpoint: Option<&str>,
    fail_post_sign_count: bool,
) -> Result<Output> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "--ignored",
            "--exact",
            "bip448_duplicate_sweep_replays_every_signing_and_broadcast_boundary",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ML_BIP448_RESTART_CHILD", "1")
        .env("ML_BIP448_DUPLICATE_SWEEP_CHILD", "1")
        .env("ML_BIP448_RESTART_WALLET", wallet_name)
        .env("ML_BIP448_RESTART_STATECHAIN_ID", statechain_id)
        .env(
            "ML_BIP448_RESTART_DUPLICATE_INDEX",
            duplicate_index.to_string(),
        )
        .env("ML_BIP448_RESTART_DESTINATION", destination)
        .env("ML_NETWORK", "regtest")
        .env_remove("ML_BIP448_TEST_CHECKPOINT")
        .env_remove("ML_BIP448_FAIL_POST_SIGN_COUNT");
    if let Some(checkpoint) = checkpoint {
        command.env("ML_BIP448_TEST_CHECKPOINT", checkpoint);
    }
    if fail_post_sign_count {
        command.env("ML_BIP448_FAIL_POST_SIGN_COUNT", "1");
    }
    Ok(command.output()?)
}

fn run_canonical_close_child(
    wallet_name: &str,
    statechain_id: &str,
    destination: &str,
    mode: &str,
    checkpoint: Option<&str>,
) -> Result<Output> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "--ignored",
            "--exact",
            "bip448_duplicate_sweeps_are_one_input_and_canonical_closes_last",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ML_BIP448_RESTART_CHILD", "1")
        .env("ML_BIP448_CANONICAL_CLOSE_CHILD_MODE", mode)
        .env("ML_BIP448_RESTART_WALLET", wallet_name)
        .env("ML_BIP448_RESTART_STATECHAIN_ID", statechain_id)
        .env("ML_BIP448_RESTART_DESTINATION", destination)
        .env("ML_NETWORK", "regtest")
        .env_remove("ML_BIP448_TEST_CHECKPOINT");
    if let Some(checkpoint) = checkpoint {
        command.env("ML_BIP448_TEST_CHECKPOINT", checkpoint);
    }
    Ok(command.output()?)
}

#[derive(Debug, PartialEq, Eq)]
struct CanonicalSideEffectInvariant {
    wallet_json: String,
    accepted: (String, Vec<(i64, String)>),
    attempt_count: i64,
    signature_count: u32,
    mercury: (String, String, String),
}

async fn canonical_side_effect_invariant(
    fixture: &DuplicateSweepFixture,
    lockbox_client: &Client,
) -> Result<CanonicalSideEffectInvariant> {
    Ok(CanonicalSideEffectInvariant {
        wallet_json: sqlx::query_scalar("SELECT wallet_json FROM wallet WHERE wallet_name=$1")
            .bind(&fixture.wallet_name)
            .fetch_one(&fixture.config.pool)
            .await?,
        accepted: accepted_state_bytes(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?,
        attempt_count: sqlx::query_scalar(
            "SELECT COUNT(*) FROM bip448_withdrawal_attempts WHERE wallet_name=$1 AND statechain_id=$2",
        )
        .bind(&fixture.wallet_name)
        .bind(&fixture.statechain_id)
        .fetch_one(&fixture.config.pool)
        .await?,
        signature_count: common::lockbox::get_signature_count(
            lockbox_client,
            &fixture.statechain_id,
        )
        .await?,
        mercury: mercury_state_bytes(&fixture.statechain_id).await?,
    })
}

async fn accepted_prefix_message(
    fixture: &DuplicateSweepFixture,
) -> Result<(String, Bip448TransferMsg)> {
    let wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&fixture.config.pool, &fixture.wallet_name)
            .await?;
    let coin = wallet
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some(fixture.statechain_id.as_str()))
        .context("accepted-prefix fixture Coin is missing")?;
    let record = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?;
    let history = mercuryrustlib::sqlite_manager::get_bip448_state_history(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?;
    Ok((
        coin.auth_pubkey.clone(),
        Bip448TransferMsg {
            msg_version: 2,
            statechain_id: fixture.statechain_id.clone(),
            transfer_signature: "11".repeat(64),
            sender_user_public_key: coin.user_pubkey.clone(),
            receiver_user_public_key: coin.user_pubkey.clone(),
            server_public_key: coin
                .server_pubkey
                .clone()
                .context("accepted-prefix Coin has no server key")?,
            aggregate_pubkey: record.aggregate_pubkey.clone(),
            funding_outpoint: record.funding_outpoint.clone(),
            latest_state_number: record.latest_state_number,
            challenge_delay: record.challenge_delay,
            amount_sats: record.amount_sats,
            network: record.network.clone(),
            value_schedule: record.latest_state.value_schedule.clone(),
            latest_state: record.latest_state,
            server_signature_count: u64::from(record.latest_state_number),
            t1: [7; 32],
            state_history: history,
        },
    ))
}

async fn delete_exact_outgoing_message(
    fixture: &DuplicateSweepFixture,
    recipient_auth_pubkey: &str,
) -> Result<()> {
    let deleted = sqlx::query(
        "DELETE FROM bip448_transfer_messages WHERE wallet_name=$1 AND statechain_id=$2 AND recipient_auth_pubkey=$3",
    )
    .bind(&fixture.wallet_name)
    .bind(&fixture.statechain_id)
    .bind(recipient_auth_pubkey)
    .execute(&fixture.config.pool)
    .await?;
    assert_eq!(
        deleted.rows_affected(),
        1,
        "exact outgoing cleanup missed its row"
    );
    Ok(())
}

fn child_server_nonce(output: &Output) -> Result<String> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| {
            line.split_once("BIP448_TEST_SERVER_NONCE=")
                .map(|(_, nonce)| nonce)
        })
        .map(str::to_owned)
        .context("duplicate sweep child did not report its decoded server nonce")
}

fn require_child_exit(output: &Output, expected: i32, checkpoint: &str) -> Result<()> {
    if output.status.code() == Some(expected) {
        return Ok(());
    }
    anyhow::bail!(
        "duplicate sweep child at {checkpoint} exited {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn run_receiver_rescan_cancel_child(wallet_name: &str, statechain_id: &str) -> Result<Output> {
    Ok(Command::new(std::env::current_exe()?)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "--ignored",
            "--exact",
            "bip448_receiver_post_acceptance_duplicate_rescan_is_retryable",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ML_BIP448_RECEIVER_RESCAN_CHILD", "1")
        .env("ML_BIP448_RESTART_CHILD", "1")
        .env("ML_BIP448_RESTART_WALLET", wallet_name)
        .env("ML_BIP448_RESTART_STATECHAIN_ID", statechain_id)
        .env("ML_BIP448_TEST_CHECKPOINT", "transfer_sender_finished")
        .env("ML_NETWORK", "regtest")
        .env_remove("ML_BIP448_DUPLICATE_SWEEP_CHILD")
        .env_remove("ML_BIP448_CANONICAL_CLOSE_CHILD_MODE")
        .env_remove("ML_BIP448_TEST_BARRIER")
        .env_remove("ML_BIP448_TEST_BARRIER_REACHED")
        .env_remove("ML_BIP448_TEST_BARRIER_RELEASE")
        .output()?)
}

fn json_has_duplicate_key(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(fields) => fields.iter().any(|(key, value)| {
            key.to_ascii_lowercase().contains("duplicate") || json_has_duplicate_key(value)
        }),
        serde_json::Value::Array(values) => values.iter().any(json_has_duplicate_key),
        _ => false,
    }
}

fn require_v2_message_without_duplicate_field(raw: &str) -> Result<Bip448TransferMsg> {
    let json: serde_json::Value = serde_json::from_str(raw)?;
    assert!(
        !json_has_duplicate_key(&json),
        "BIP448 transfer wire message unexpectedly contains duplicate metadata"
    );
    let message: Bip448TransferMsg = serde_json::from_value(json)?;
    assert_eq!(message.msg_version, 2);
    assert_eq!(serde_json::to_string(&message)?, raw);
    Ok(message)
}

async fn bip448_transfer_artifact_counts(
    config: &ClientConfig,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<(i64, i64, i64)> {
    Ok(sqlx::query_as(
        "SELECT \
         (SELECT COUNT(*) FROM bip448_transfer_messages WHERE wallet_name=$1 AND statechain_id=$2),\
         (SELECT COUNT(*) FROM bip448_transfer_intents WHERE wallet_name=$1 AND statechain_id=$2),\
         (SELECT COUNT(*) FROM bip448_pending_transfer_signings WHERE wallet_name=$1 AND statechain_id=$2)",
    )
    .bind(wallet_name)
    .bind(statechain_id)
    .fetch_one(&config.pool)
    .await?)
}

async fn exercise_late_binding_after_canonical_wallet_persisted(
    lockbox_client: &Client,
) -> Result<()> {
    let fixture = duplicate_sweep_fixture(&[]).await?;
    let destination = common::bitcoin_core::getnewaddress()?;
    let checkpoint = run_canonical_close_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        "execute",
        Some("canonical_wallet_persisted"),
    )?;
    require_child_exit(
        &checkpoint,
        86,
        "late binding after canonical_wallet_persisted",
    )?;
    let frozen = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        0,
    )
    .await?
    .context("late-binding canonical journal is missing")?;
    assert_eq!(frozen.phase, Bip448WithdrawalPhase::Signed);
    assert_eq!(frozen.broadcast_status, Bip448BroadcastStatus::Accepted);
    assert_eq!(frozen.closing_bindings_json.as_deref(), Some("[]"));
    let frozen_signing_id = frozen.signing_id.clone();
    let frozen_signed_tx = frozen
        .signed_tx_hex
        .clone()
        .context("late-binding canonical bytes are missing")?;
    assert_eq!(
        common::lockbox::get_signature_count(lockbox_client, &fixture.statechain_id).await?,
        2
    );

    let wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&fixture.config.pool, &fixture.wallet_name)
            .await?;
    let aggregate_address = wallet
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some(fixture.statechain_id.as_str()))
        .and_then(|coin| coin.aggregated_address.as_deref())
        .context("late-binding canonical Coin has no aggregate address")?;
    let aggregate_address =
        Address::from_str(aggregate_address)?.require_network(fixture.config.network)?;
    let late_funding = fund_address_output(&aggregate_address, DUPLICATE_AMOUNT_SATS)?;
    common::chain::wait_for_address_outpoint(
        &fixture.config,
        &aggregate_address.to_string(),
        late_funding.outpoint,
        late_funding.value_sats,
    )
    .await?;
    common::bitcoin_core::mine_blocks(fixture.config.confirmation_target)?;
    let report = mercuryrustlib::coin_status::sync_bip448_funding_bindings(
        &fixture.config,
        &fixture.wallet_name,
    )
    .await?;
    let late = report
        .bindings
        .iter()
        .find(|binding| {
            binding.statechain_id == fixture.statechain_id
                && binding.txid == late_funding.outpoint.txid.to_string()
                && binding.vout == late_funding.outpoint.vout
        })
        .context("late canonical-freeze duplicate was not discovered")?;
    assert_eq!(late.role, Bip448BindingRole::Duplicate);
    assert_eq!(late.ownership_status, Bip448OwnershipStatus::Current);
    assert_eq!(late.observation_status, Bip448ObservationStatus::Confirmed);
    assert!(
        mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
            late.binding_index,
        )
        .await?
        .is_none()
    );

    let before_rejections = canonical_side_effect_invariant(&fixture, lockbox_client).await?;
    assert!(mercuryrustlib::bip448_withdraw::execute_duplicate_sweep(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        late.binding_index,
        &destination,
        Some(1.0),
    )
    .await
    .is_err());
    assert!(
        mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
            late.binding_index,
        )
        .await?
        .is_none(),
        "late duplicate acquired an attempt after canonical freeze"
    );
    assert!(mercuryrustlib::bip448_withdraw::execute(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        Some(1.0),
    )
    .await
    .is_err());
    assert_eq!(
        canonical_side_effect_invariant(&fixture, lockbox_client).await?,
        before_rejections,
        "late binding changed wallet, signing count, or Mercury state"
    );
    let retained = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        0,
    )
    .await?
    .context("late binding removed the canonical journal")?;
    assert_eq!(retained.signing_id, frozen_signing_id);
    assert_eq!(
        retained.signed_tx_hex.as_deref(),
        Some(frozen_signed_tx.as_str())
    );
    assert_eq!(retained.closing_bindings_json.as_deref(), Some("[]"));
    assert!(
        mercuryrustlib::utils::get_statechain_info(&fixture.statechain_id, &fixture.config)
            .await?
            .is_some()
    );
    Ok(())
}

async fn exercise_frozen_signed_duplicate_mutations(lockbox_client: &Client) -> Result<()> {
    let fixture = duplicate_sweep_fixture(&[FUNDING_AMOUNT_SATS]).await?;
    let duplicate = fixture.bindings[1].clone();
    let destination = common::bitcoin_core::getnewaddress()?;
    let conflict = retained_update_conflict_package(&fixture, &duplicate).await?;
    save_empty_mempool_baseline()?;

    mercuryrustlib::bip448_withdraw::execute_duplicate_sweep(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        duplicate.binding_index,
        &destination,
        Some(1.0),
    )
    .await?;
    let frozen_sweep = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        duplicate.binding_index,
    )
    .await?
    .context("frozen duplicate sweep is missing")?;
    let frozen_sweep_signing_id = frozen_sweep.signing_id.clone();
    let frozen_sweep_bytes = frozen_sweep
        .signed_tx_hex
        .clone()
        .context("frozen duplicate sweep bytes are missing")?;
    assert_eq!(
        common::lockbox::get_signature_count(lockbox_client, &fixture.statechain_id).await?,
        2
    );

    let prepared_output = run_canonical_close_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        "execute",
        Some("attempt_prepared"),
    )?;
    require_child_exit(&prepared_output, 86, "frozen duplicate canonical Prepared")?;
    let prepared = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        0,
    )
    .await?
    .context("frozen duplicate canonical Prepared row is missing")?;
    assert_eq!(prepared.phase, Bip448WithdrawalPhase::Prepared);
    let canonical_signing_id = prepared.signing_id.clone();
    let frozen_snapshot = prepared
        .closing_bindings_json
        .clone()
        .context("frozen duplicate canonical snapshot is missing")?;

    let tip = fixture.config.chain_client.tip_height()?;
    restart_core_dropping_unpersisted_mempool(&fixture.config, tip, true)?;
    mercuryrustlib::coin_status::sync_bip448_funding_bindings(
        &fixture.config,
        &fixture.wallet_name,
    )
    .await?;
    submit_conflict_package(&conflict)?;
    mercuryrustlib::coin_status::sync_bip448_funding_bindings(
        &fixture.config,
        &fixture.wallet_name,
    )
    .await?;
    let conflicting_sweep = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        duplicate.binding_index,
    )
    .await?
    .context("conflicting frozen duplicate sweep is missing")?;
    assert_eq!(
        conflicting_sweep.broadcast_status,
        Bip448BroadcastStatus::Conflicting
    );

    let blocked_second_arm = run_canonical_close_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        "execute",
        None,
    )?;
    require_child_exit(
        &blocked_second_arm,
        101,
        "frozen duplicate mutation before SecondArmed",
    )?;
    let before_second_arm = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        0,
    )
    .await?
    .context("blocked canonical journal is missing")?;
    assert_eq!(before_second_arm.phase, Bip448WithdrawalPhase::NonceStored);
    assert_eq!(before_second_arm.signing_id, canonical_signing_id);
    assert_eq!(
        before_second_arm.closing_bindings_json.as_deref(),
        Some(frozen_snapshot.as_str())
    );
    assert_eq!(
        common::lockbox::get_signature_count(lockbox_client, &fixture.statechain_id).await?,
        2,
        "frozen mutation reached canonical sign/second"
    );
    assert!(
        mercuryrustlib::utils::get_statechain_info(&fixture.statechain_id, &fixture.config)
            .await?
            .is_some()
    );

    common::bitcoin_core::mine_block_with_transactions(&[
        conflict.parent_tx.txid(),
        conflict.cpfp_child_tx.txid(),
    ])?;
    let conflict_block_height = fixture.config.chain_client.tip_height()?;
    let conflict_block_hash = fixture
        .config
        .chain_client
        .get_block_hash(conflict_block_height)?
        .to_string();
    invalidate_conflict_and_evict(
        &fixture.config,
        &conflict_block_hash,
        conflict.parent_tx.txid(),
        false,
    )?;
    mercuryrustlib::coin_status::sync_bip448_funding_bindings(
        &fixture.config,
        &fixture.wallet_name,
    )
    .await?;
    let close_armed_output = run_canonical_close_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        "execute",
        Some("canonical_close_armed"),
    )?;
    require_child_exit(
        &close_armed_output,
        86,
        "exact frozen sweep reconciliation before CloseArmed",
    )?;
    let close_armed = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        0,
    )
    .await?
    .context("canonical CloseArmed journal is missing")?;
    assert_eq!(close_armed.phase, Bip448WithdrawalPhase::Signed);
    assert_eq!(
        close_armed.completion_status,
        Bip448CompletionStatus::CloseArmed
    );
    let canonical_signed_bytes = close_armed
        .signed_tx_hex
        .clone()
        .context("canonical CloseArmed bytes are missing")?;
    assert_eq!(
        common::lockbox::get_signature_count(lockbox_client, &fixture.statechain_id).await?,
        3
    );
    let mercury_before_blocked_completion = mercury_state_bytes(&fixture.statechain_id).await?;

    restart_core_dropping_unpersisted_mempool(&fixture.config, tip, false)?;
    mercuryrustlib::coin_status::sync_bip448_funding_bindings(
        &fixture.config,
        &fixture.wallet_name,
    )
    .await?;
    submit_conflict_package(&conflict)?;
    mercuryrustlib::coin_status::sync_bip448_funding_bindings(
        &fixture.config,
        &fixture.wallet_name,
    )
    .await?;
    let reorged_canonical = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        0,
    )
    .await?
    .context("reorged canonical CloseArmed journal is missing")?;
    assert_eq!(
        reorged_canonical.broadcast_status,
        Bip448BroadcastStatus::NeedsRebroadcast
    );
    assert_eq!(
        reorged_canonical.completion_status,
        Bip448CompletionStatus::CloseArmed
    );
    let blocked_completion = mercuryrustlib::bip448_withdraw::execute(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        Some(1.0),
    )
    .await;
    assert!(blocked_completion.is_err());
    let still_armed = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        0,
    )
    .await?
    .context("blocked completion lost canonical journal")?;
    assert_eq!(
        still_armed.completion_status,
        Bip448CompletionStatus::CloseArmed
    );
    assert_eq!(still_armed.signing_id, canonical_signing_id);
    assert_eq!(
        still_armed.signed_tx_hex.as_deref(),
        Some(canonical_signed_bytes.as_str())
    );
    assert_eq!(
        common::lockbox::get_signature_count(lockbox_client, &fixture.statechain_id).await?,
        3
    );
    assert_eq!(
        mercury_state_bytes(&fixture.statechain_id).await?,
        mercury_before_blocked_completion,
        "frozen conflict reached completion or mutated Mercury signing state"
    );

    restart_core_dropping_unpersisted_mempool(&fixture.config, tip, true)?;
    mercuryrustlib::coin_status::sync_bip448_funding_bindings(
        &fixture.config,
        &fixture.wallet_name,
    )
    .await?;
    mercuryrustlib::bip448_withdraw::execute(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        Some(1.0),
    )
    .await?;
    let closed = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        0,
    )
    .await?
    .context("reconciled canonical journal is missing")?;
    assert_eq!(closed.completion_status, Bip448CompletionStatus::Closed);
    assert_eq!(closed.signing_id, canonical_signing_id);
    assert_eq!(
        closed.signed_tx_hex.as_deref(),
        Some(canonical_signed_bytes.as_str())
    );
    let restored_sweep = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        duplicate.binding_index,
    )
    .await?
    .context("reconciled frozen sweep is missing")?;
    assert_eq!(restored_sweep.signing_id, frozen_sweep_signing_id);
    assert_eq!(
        restored_sweep.signed_tx_hex.as_deref(),
        Some(frozen_sweep_bytes.as_str())
    );
    assert_lockbox_state_absent(lockbox_client, &fixture.statechain_id).await?;
    assert!(
        mercuryrustlib::utils::get_statechain_info(&fixture.statechain_id, &fixture.config)
            .await?
            .is_none()
    );
    Ok(())
}

async fn exercise_frozen_independent_spend_reorg(lockbox_client: &Client) -> Result<()> {
    let fixture = duplicate_sweep_fixture(&[FUNDING_AMOUNT_SATS]).await?;
    let duplicate = fixture.bindings[1].clone();
    let destination = common::bitcoin_core::getnewaddress()?;
    let conflict = retained_update_conflict_package(&fixture, &duplicate).await?;
    let conflict_block_hash = confirm_conflict_package(&fixture.config, &conflict)?;
    let report = mercuryrustlib::coin_status::sync_bip448_funding_bindings(
        &fixture.config,
        &fixture.wallet_name,
    )
    .await?;
    let spent = report
        .bindings
        .iter()
        .find(|binding| {
            binding.statechain_id == fixture.statechain_id
                && binding.binding_index == duplicate.binding_index
        })
        .context("independently spent frozen duplicate is missing")?;
    assert_eq!(
        spent.observation_status,
        Bip448ObservationStatus::SpentConfirmed
    );
    assert_eq!(
        spent.spend_txid.as_deref(),
        Some(conflict.parent_tx.txid().to_string().as_str())
    );
    assert!(
        mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
            duplicate.binding_index,
        )
        .await?
        .is_none()
    );

    let prepared_output = run_canonical_close_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        "execute",
        Some("attempt_prepared"),
    )?;
    require_child_exit(&prepared_output, 86, "independent-spend canonical Prepared")?;
    let prepared = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        0,
    )
    .await?
    .context("independent-spend canonical journal is missing")?;
    let frozen_snapshot = prepared
        .closing_bindings_json
        .clone()
        .context("independent-spend snapshot is missing")?;
    assert!(frozen_snapshot.contains("\"kind\":\"IndependentSpend\""));
    let canonical_signing_id = prepared.signing_id.clone();
    assert_eq!(
        common::lockbox::get_signature_count(lockbox_client, &fixture.statechain_id).await?,
        1
    );

    invalidate_conflict_and_evict(
        &fixture.config,
        &conflict_block_hash,
        conflict.parent_tx.txid(),
        true,
    )?;
    mercuryrustlib::coin_status::sync_bip448_funding_bindings(
        &fixture.config,
        &fixture.wallet_name,
    )
    .await?;
    let blocked = run_canonical_close_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        "execute",
        None,
    )?;
    require_child_exit(&blocked, 101, "reorged independent frozen spend")?;
    let blocked_attempt = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        0,
    )
    .await?
    .context("independent-spend reorg lost canonical journal")?;
    assert_eq!(blocked_attempt.phase, Bip448WithdrawalPhase::NonceStored);
    assert_eq!(blocked_attempt.signing_id, canonical_signing_id);
    assert_eq!(
        blocked_attempt.closing_bindings_json.as_deref(),
        Some(frozen_snapshot.as_str())
    );
    assert_eq!(
        common::lockbox::get_signature_count(lockbox_client, &fixture.statechain_id).await?,
        1,
        "reorged independent spend consumed a new signature"
    );
    assert!(
        mercuryrustlib::utils::get_statechain_info(&fixture.statechain_id, &fixture.config)
            .await?
            .is_some()
    );

    common::bitcoin_core::execute_bitcoin_command(&format!(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury reconsiderblock {conflict_block_hash}"
    ))?;
    let restored = mercuryrustlib::coin_status::sync_bip448_funding_bindings(
        &fixture.config,
        &fixture.wallet_name,
    )
    .await?;
    let restored_binding = restored
        .bindings
        .iter()
        .find(|binding| {
            binding.statechain_id == fixture.statechain_id
                && binding.binding_index == duplicate.binding_index
        })
        .context("reconsidered independent frozen duplicate is missing")?;
    assert_eq!(
        restored_binding.observation_status,
        Bip448ObservationStatus::SpentConfirmed
    );
    assert_eq!(
        restored_binding.spend_txid.as_deref(),
        Some(conflict.parent_tx.txid().to_string().as_str())
    );
    mercuryrustlib::bip448_withdraw::execute(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        Some(1.0),
    )
    .await?;
    let closed = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        0,
    )
    .await?
    .context("reconciled independent-spend canonical journal is missing")?;
    assert_eq!(closed.completion_status, Bip448CompletionStatus::Closed);
    assert_eq!(closed.signing_id, canonical_signing_id);
    assert_lockbox_state_absent(lockbox_client, &fixture.statechain_id).await?;
    Ok(())
}

async fn exercise_canonical_prepared_confirmed_conflict(lockbox_client: &Client) -> Result<()> {
    let fixture = duplicate_sweep_fixture(&[]).await?;
    let canonical_binding = fixture.bindings[0].clone();
    let destination = common::bitcoin_core::getnewaddress()?;
    let conflict = retained_update_conflict_package(&fixture, &canonical_binding).await?;
    let prepared_output = run_canonical_close_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        "execute",
        Some("attempt_prepared"),
    )?;
    require_child_exit(&prepared_output, 86, "canonical Prepared conflict fixture")?;
    let prepared = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        0,
    )
    .await?
    .context("canonical conflict Prepared row is missing")?;
    assert_eq!(prepared.phase, Bip448WithdrawalPhase::Prepared);
    let exact_prepared_journal = raw_withdrawal_attempt_journal_snapshot(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        0,
    )
    .await?;
    let frozen_snapshot = prepared
        .closing_bindings_json
        .clone()
        .context("canonical conflict snapshot is missing")?;
    assert_eq!(frozen_snapshot, "[]");
    let canonical_signing_id = prepared.signing_id.clone();

    let conflict_block_hash = confirm_conflict_package(&fixture.config, &conflict)?;
    let report = mercuryrustlib::coin_status::sync_bip448_funding_bindings(
        &fixture.config,
        &fixture.wallet_name,
    )
    .await?;
    let spent = report
        .bindings
        .iter()
        .find(|binding| {
            binding.statechain_id == fixture.statechain_id && binding.binding_index == 0
        })
        .context("confirmed canonical conflict binding is missing")?;
    assert_eq!(
        spent.observation_status,
        Bip448ObservationStatus::SpentConfirmed
    );
    assert_eq!(
        spent.spend_txid.as_deref(),
        Some(conflict.parent_tx.txid().to_string().as_str())
    );
    assert!(mercuryrustlib::bip448_withdraw::execute(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        Some(1.0),
    )
    .await
    .is_err());
    let retained = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        0,
    )
    .await?
    .context("confirmed conflict compare-deleted canonical Prepared")?;
    assert_eq!(retained.phase, Bip448WithdrawalPhase::Prepared);
    assert_eq!(retained.signing_id, canonical_signing_id);
    assert_eq!(
        retained.closing_bindings_json.as_deref(),
        Some(frozen_snapshot.as_str())
    );
    assert_eq!(
        raw_withdrawal_attempt_journal_snapshot(
            &fixture.config,
            &fixture.wallet_name,
            &fixture.statechain_id,
            0,
        )
        .await?,
        exact_prepared_journal,
        "confirmed canonical conflict mutated the Prepared journal"
    );
    let conflict_tip = fixture.config.chain_client.tip_height()?;
    let conflict_tip_hash = fixture
        .config
        .chain_client
        .get_block_hash(conflict_tip)?
        .to_string();
    assert!(
        mercuryrustlib::sqlite_manager::delete_prepared_bip448_withdrawal_attempt_for_confirmed_spend(
            &fixture.config.pool,
            &retained,
            &conflict.parent_tx.txid().to_string(),
            conflict_tip,
            &conflict_tip_hash,
        )
        .await
        .is_err(),
        "canonical Prepared unexpectedly entered duplicate compare-delete"
    );
    assert!(
        mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
            0,
        )
        .await?
        .is_some()
    );
    assert_eq!(
        common::lockbox::get_signature_count(lockbox_client, &fixture.statechain_id).await?,
        1
    );
    assert!(
        mercuryrustlib::utils::get_statechain_info(&fixture.statechain_id, &fixture.config)
            .await?
            .is_some()
    );

    invalidate_conflict_and_evict(
        &fixture.config,
        &conflict_block_hash,
        conflict.parent_tx.txid(),
        true,
    )?;
    mercuryrustlib::coin_status::sync_bip448_funding_bindings(
        &fixture.config,
        &fixture.wallet_name,
    )
    .await?;
    mercuryrustlib::bip448_withdraw::execute(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        Some(1.0),
    )
    .await?;
    let closed = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        0,
    )
    .await?
    .context("restored canonical conflict journal is missing")?;
    assert_eq!(closed.completion_status, Bip448CompletionStatus::Closed);
    assert_eq!(closed.signing_id, canonical_signing_id);
    assert_lockbox_state_absent(lockbox_client, &fixture.statechain_id).await?;
    Ok(())
}

async fn exercise_target_confirmed_duplicate_conflict(
    checkpoint: &str,
    phase: Bip448WithdrawalPhase,
) -> Result<()> {
    let fixture = duplicate_sweep_fixture(&[FUNDING_AMOUNT_SATS]).await?;
    let selected = fixture.bindings[1].clone();
    assert_eq!(selected.value_sats, fixture.bindings[0].value_sats);
    assert_eq!(selected.script_pubkey, fixture.bindings[0].script_pubkey);
    let destination = common::bitcoin_core::getnewaddress()?;
    let accepted_before = accepted_state_bytes(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?;
    let raw_wallet_before =
        sqlx::query_scalar::<_, String>("SELECT wallet_json FROM wallet WHERE wallet_name=$1")
            .bind(&fixture.wallet_name)
            .fetch_one(&fixture.config.pool)
            .await?;
    let mercury_before = mercury_state_bytes(&fixture.statechain_id).await?;
    let lockbox_client = common::lockbox::http_client();
    let initial_count =
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?;
    assert_eq!(initial_count, 1);

    let checkpoint_output = run_duplicate_sweep_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
        &destination,
        Some(checkpoint),
        false,
    )?;
    require_child_exit(&checkpoint_output, 86, checkpoint)?;
    let before_conflict = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
    )
    .await?
    .context("conflict checkpoint did not persist its attempt")?;
    assert_eq!(before_conflict.phase, phase);
    assert_eq!(
        before_conflict.broadcast_status,
        Bip448BroadcastStatus::NotBroadcast
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
        initial_count
    );
    let immutable_before = duplicate_attempt_immutable_json(&before_conflict);
    let package = retained_update_conflict_package(&fixture, &selected).await?;
    assert_eq!(
        package.parent_tx.input[0].previous_output,
        OutPoint {
            txid: Txid::from_str(&selected.txid)?,
            vout: selected.vout,
        }
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
        initial_count,
        "constructing the retained-U conflict consumed a lockbox signature"
    );
    let conflict_block_hash = confirm_conflict_package(&fixture.config, &package)?;
    let resolve_output = run_duplicate_sweep_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
        &destination,
        None,
        false,
    )?;

    if phase == Bip448WithdrawalPhase::Prepared {
        require_child_exit(&resolve_output, 101, "Prepared target-confirmed conflict")?;
        assert!(
            mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
                &fixture.config.pool,
                &fixture.wallet_name,
                &fixture.statechain_id,
                selected.binding_index,
            )
            .await?
            .is_none(),
            "duplicate Prepared conflict was not compare-deleted"
        );
        assert_eq!(
            common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
            initial_count,
            "duplicate Prepared conflict consumed a signature count"
        );
    } else {
        require_child_exit(&resolve_output, 0, "armed target-confirmed conflict")?;
        let conflicted = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
            selected.binding_index,
        )
        .await?
        .context("armed target-confirmed conflict lost its attempt")?;
        assert_eq!(conflicted.phase, Bip448WithdrawalPhase::Signed);
        assert_eq!(
            conflicted.broadcast_status,
            Bip448BroadcastStatus::Conflicted
        );
        assert_eq!(
            duplicate_attempt_immutable_json(&conflicted),
            immutable_before
        );
        assert!(conflicted.signed_tx_hex.is_some());
        assert_eq!(
            common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
            initial_count + 1,
            "armed target-confirmed conflict did not resolve with exactly one count"
        );
    }
    assert_eq!(
        accepted_state_bytes(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?,
        accepted_before
    );

    invalidate_conflict_and_evict(
        &fixture.config,
        &conflict_block_hash,
        package.parent_tx.txid(),
        true,
    )?;
    let reopened = mercuryrustlib::coin_status::sync_bip448_funding_bindings(
        &fixture.config,
        &fixture.wallet_name,
    )
    .await?;
    let reopened_binding = reopened
        .bindings
        .iter()
        .find(|binding| {
            binding.statechain_id == fixture.statechain_id
                && binding.binding_index == selected.binding_index
        })
        .context("reorged conflict lost the duplicate binding")?;
    assert_eq!(
        reopened_binding.observation_status,
        Bip448ObservationStatus::Confirmed
    );

    if phase == Bip448WithdrawalPhase::Prepared {
        assert!(
            mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
                &fixture.config.pool,
                &fixture.wallet_name,
                &fixture.statechain_id,
                selected.binding_index,
            )
            .await?
            .is_none(),
            "reorg recreated a compare-deleted Prepared row"
        );
        let reopened_output = run_duplicate_sweep_child(
            &fixture.wallet_name,
            &fixture.statechain_id,
            selected.binding_index,
            &destination,
            Some("attempt_prepared"),
            false,
        )?;
        require_child_exit(&reopened_output, 86, "reopened Prepared duplicate")?;
        assert_eq!(
            common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
            initial_count
        );
    } else {
        let needs_rebroadcast = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
            selected.binding_index,
        )
        .await?
        .context("reorg deleted the retained Signed conflict")?;
        assert_eq!(needs_rebroadcast.phase, Bip448WithdrawalPhase::Signed);
        assert_eq!(
            needs_rebroadcast.broadcast_status,
            Bip448BroadcastStatus::NeedsRebroadcast
        );
        assert_eq!(
            duplicate_attempt_immutable_json(&needs_rebroadcast),
            immutable_before
        );
    }

    let rebroadcast = run_duplicate_sweep_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
        &destination,
        None,
        false,
    )?;
    require_child_exit(&rebroadcast, 0, "reopened exact duplicate sweep")?;
    let accepted = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
    )
    .await?
    .context("reopened exact sweep did not persist")?;
    assert_eq!(accepted.phase, Bip448WithdrawalPhase::Signed);
    assert_eq!(accepted.broadcast_status, Bip448BroadcastStatus::Accepted);
    assert_eq!(
        accepted.completion_status,
        Bip448CompletionStatus::NotApplicable
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
        initial_count + 1
    );
    common::bitcoin_core::mine_block()?;
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT wallet_json FROM wallet WHERE wallet_name=$1")
            .bind(&fixture.wallet_name)
            .fetch_one(&fixture.config.pool)
            .await?,
        raw_wallet_before
    );
    assert_eq!(
        accepted_state_bytes(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?,
        accepted_before
    );
    let mercury_after = mercury_state_bytes(&fixture.statechain_id).await?;
    assert_eq!(mercury_after.0, mercury_before.0);
    assert_eq!(mercury_after.2, mercury_before.2);
    Ok(())
}

async fn exercise_prepared_mempool_conflict_and_eviction() -> Result<()> {
    let fixture = duplicate_sweep_fixture(&[FUNDING_AMOUNT_SATS]).await?;
    let selected = fixture.bindings[1].clone();
    let destination = common::bitcoin_core::getnewaddress()?;
    let lockbox_client = common::lockbox::http_client();
    let server_before = mercury_state_bytes(&fixture.statechain_id).await?;
    let checkpoint = run_duplicate_sweep_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
        &destination,
        Some("attempt_prepared"),
        false,
    )?;
    require_child_exit(&checkpoint, 86, "Prepared mempool-conflict fixture")?;
    let prepared = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
    )
    .await?
    .context("Prepared mempool-conflict row is missing")?;
    let immutable = duplicate_attempt_immutable_json(&prepared);
    let package = retained_update_conflict_package(&fixture, &selected).await?;
    save_empty_mempool_baseline()?;
    submit_conflict_package(&package)?;
    let transient = run_duplicate_sweep_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
        &destination,
        None,
        false,
    )?;
    require_child_exit(&transient, 101, "Prepared mempool conflict")?;
    let waiting = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
    )
    .await?
    .context("mempool conflict deleted the Prepared row")?;
    assert_eq!(waiting.phase, Bip448WithdrawalPhase::Prepared);
    assert_eq!(
        waiting.broadcast_status,
        Bip448BroadcastStatus::NotBroadcast
    );
    assert_eq!(duplicate_attempt_immutable_json(&waiting), immutable);
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
        1
    );
    assert_eq!(
        mercury_state_bytes(&fixture.statechain_id).await?.1,
        server_before.1,
        "Prepared mempool conflict reached sign/first"
    );

    let unchanged_tip = fixture.config.chain_client.tip_height()?;
    restart_core_dropping_unpersisted_mempool(&fixture.config, unchanged_tip, true)?;
    common::bitcoin_core::assert_not_in_mempool(&package.parent_tx.txid())?;
    let resumed = run_duplicate_sweep_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
        &destination,
        Some("sign_first_armed"),
        false,
    )?;
    require_child_exit(&resumed, 86, "Prepared conflict eviction resume")?;
    let armed = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
    )
    .await?
    .context("evicted Prepared conflict did not resume")?;
    assert_eq!(armed.phase, Bip448WithdrawalPhase::FirstArmed);
    assert_eq!(duplicate_attempt_immutable_json(&armed), immutable);
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
        1
    );
    let finish = run_duplicate_sweep_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
        &destination,
        None,
        false,
    )?;
    require_child_exit(&finish, 0, "post-eviction exact sweep")?;
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
        2
    );
    common::bitcoin_core::mine_block()?;
    Ok(())
}

async fn exercise_signed_sweep_with_missing_funding_parent() -> Result<()> {
    let fixture = duplicate_sweep_fixture(&[DUPLICATE_AMOUNT_SATS]).await?;
    let selected = fixture.bindings[1].clone();
    let destination = common::bitcoin_core::getnewaddress()?;
    let recovery_mining_address = common::bitcoin_core::getnewaddress()?;
    let funding_transaction =
        common::bitcoin_core::wallet_transaction(&Txid::from_str(&selected.txid)?)?;
    let funding_block_height = selected
        .funding_height
        .context("signed-parent fixture funding height is missing")?;
    let funding_block_hash = fixture
        .config
        .chain_client
        .get_block_hash(funding_block_height)?
        .to_string();
    let signed_checkpoint = run_duplicate_sweep_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
        &destination,
        Some("signed_tx_persisted"),
        false,
    )?;
    require_child_exit(&signed_checkpoint, 86, "signed missing-parent fixture")?;
    let signed = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
    )
    .await?
    .context("signed missing-parent attempt is missing")?;
    let signed_bytes = signed
        .signed_tx_hex
        .clone()
        .context("signed missing-parent bytes are missing")?;
    let sweep_txid = Txid::from_str(signed.txid.as_deref().context("signed sweep txid")?)?;
    save_empty_mempool_baseline()?;
    common::bitcoin_core::execute_bitcoin_command(&format!(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury invalidateblock {funding_block_hash}"
    ))?;
    common::bitcoin_core::assert_in_mempool(&funding_transaction.txid())?;
    let reorg_tip = fixture.config.chain_client.tip_height()?;
    restart_core_dropping_unpersisted_mempool(&fixture.config, reorg_tip, false)?;
    common::bitcoin_core::assert_not_in_mempool(&funding_transaction.txid())?;

    let unavailable = run_duplicate_sweep_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
        &destination,
        None,
        false,
    )?;
    require_child_exit(&unavailable, 101, "signed sweep with unavailable parent")?;
    let needs = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
    )
    .await?
    .context("missing-parent broadcast deleted signed bytes")?;
    assert_eq!(
        needs.broadcast_status,
        Bip448BroadcastStatus::NeedsRebroadcast
    );
    assert_eq!(needs.signed_tx_hex.as_deref(), Some(signed_bytes.as_str()));
    common::bitcoin_core::assert_not_in_mempool(&sweep_txid)?;

    assert_eq!(
        common::bitcoin_core::broadcast_raw_transaction(&funding_transaction)?,
        funding_transaction.txid()
    );
    common::bitcoin_core::assert_in_mempool(&funding_transaction.txid())?;
    let current_tip = fixture.config.chain_client.tip_height()?;
    let blocks_until_sweep_final = signed.lock_time.saturating_sub(current_tip).max(1);
    common::bitcoin_core::generatetoaddress(blocks_until_sweep_final, &recovery_mining_address)?;
    common::bitcoin_core::assert_confirmed(&funding_transaction.txid())?;
    common::bitcoin_core::execute_bitcoin_command(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury loadwallet mercury_test",
    )?;
    common::bitcoin_core::execute_bitcoin_command(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury loadwallet mercury_tokens",
    )?;
    let recovered = run_duplicate_sweep_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
        &destination,
        None,
        false,
    )?;
    require_child_exit(&recovered, 0, "signed sweep after parent resubmission")?;
    common::bitcoin_core::assert_in_mempool(&sweep_txid)?;
    let accepted = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
    )
    .await?
    .context("resubmitted-parent sweep attempt is missing")?;
    assert_eq!(accepted.broadcast_status, Bip448BroadcastStatus::Accepted);
    assert_eq!(
        accepted.signed_tx_hex.as_deref(),
        Some(signed_bytes.as_str())
    );
    assert_eq!(
        common::lockbox::get_signature_count(
            &common::lockbox::http_client(),
            &fixture.statechain_id,
        )
        .await?,
        2
    );
    common::bitcoin_core::mine_block_with_transactions(&[sweep_txid])?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_duplicate_sweep_replays_every_signing_and_broadcast_boundary() -> Result<()> {
    if std::env::var("ML_BIP448_DUPLICATE_SWEEP_CHILD").as_deref() == Ok("1") {
        std::env::set_var("ML_NETWORK", "regtest");
        let config = mercuryrustlib::client_config::load().await;
        let result = mercuryrustlib::bip448_withdraw::execute_duplicate_sweep(
            &config,
            &std::env::var("ML_BIP448_RESTART_WALLET")?,
            &std::env::var("ML_BIP448_RESTART_STATECHAIN_ID")?,
            std::env::var("ML_BIP448_RESTART_DUPLICATE_INDEX")?.parse()?,
            &std::env::var("ML_BIP448_RESTART_DESTINATION")?,
            Some(1.0),
        )
        .await
        .map(|_| ());
        config.pool.close().await;
        return result;
    }

    let _guard = common::test_guard();
    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;
    let lockbox_client = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox_client).await?;

    exercise_prepared_mempool_conflict_and_eviction().await?;
    for (checkpoint, phase) in [
        ("attempt_prepared", Bip448WithdrawalPhase::Prepared),
        ("sign_first_armed", Bip448WithdrawalPhase::FirstArmed),
        ("server_nonce_persisted", Bip448WithdrawalPhase::NonceStored),
    ] {
        exercise_target_confirmed_duplicate_conflict(checkpoint, phase).await?;
    }
    exercise_signed_sweep_with_missing_funding_parent().await?;

    let fixture =
        duplicate_sweep_fixture(&[DUPLICATE_AMOUNT_SATS, SMALL_DUPLICATE_AMOUNT_SATS]).await?;
    let selected = fixture.bindings[1].clone();
    let other = fixture.bindings[2].clone();
    let destination = common::bitcoin_core::getnewaddress()?;
    let raw_wallet_before =
        sqlx::query_scalar::<_, String>("SELECT wallet_json FROM wallet WHERE wallet_name=$1")
            .bind(&fixture.wallet_name)
            .fetch_one(&fixture.config.pool)
            .await?;
    let accepted_before = accepted_state_bytes(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?;
    let mercury_before = mercury_state_bytes(&fixture.statechain_id).await?;
    let initial_count =
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?;
    assert_eq!(initial_count, 1);

    let checkpoints = [
        ("attempt_prepared", Bip448WithdrawalPhase::Prepared, 1),
        ("sign_first_armed", Bip448WithdrawalPhase::FirstArmed, 1),
        (
            "server_nonce_returned",
            Bip448WithdrawalPhase::FirstArmed,
            1,
        ),
        (
            "server_nonce_persisted",
            Bip448WithdrawalPhase::NonceStored,
            1,
        ),
        ("sign_second_armed", Bip448WithdrawalPhase::SecondArmed, 1),
        (
            "server_partial_returned",
            Bip448WithdrawalPhase::SecondArmed,
            2,
        ),
        ("signed_tx_persisted", Bip448WithdrawalPhase::Signed, 2),
        ("broadcast_returned", Bip448WithdrawalPhase::Signed, 2),
    ];
    let mut immutable = None;
    let mut nonce_artifacts = None;
    let mut signed_artifacts = None;
    let mut returned_server_nonce = None;
    for (checkpoint, phase, count) in checkpoints {
        let output = run_duplicate_sweep_child(
            &fixture.wallet_name,
            &fixture.statechain_id,
            selected.binding_index,
            &destination,
            Some(checkpoint),
            false,
        )?;
        require_child_exit(&output, 86, checkpoint)?;
        let attempts = mercuryrustlib::sqlite_manager::list_bip448_withdrawal_attempts(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?;
        assert_eq!(attempts.len(), 1, "{checkpoint} created a second row");
        let attempt = &attempts[0];
        assert_eq!(attempt.binding_index, selected.binding_index);
        assert_eq!(attempt.phase, phase, "wrong phase at {checkpoint}");
        assert_eq!(
            attempt.completion_status,
            mercuryrustlib::bip448_funding::Bip448CompletionStatus::NotApplicable,
            "duplicate attempt entered canonical completion at {checkpoint}"
        );
        let current_immutable = duplicate_attempt_immutable_json(attempt);
        if let Some(expected) = &immutable {
            assert_eq!(
                &current_immutable, expected,
                "immutable drift at {checkpoint}"
            );
        } else {
            immutable = Some(current_immutable);
        }
        if attempt.server_public_nonce.is_some() {
            let current = serde_json::json!({
                "server_public_nonce": attempt.server_public_nonce,
                "message_hex": attempt.message_hex,
                "output_pubkey": attempt.output_pubkey,
                "client_partial_sig": attempt.client_partial_sig,
                "encoded_session": attempt.encoded_session,
                "sign_second_payload_json": attempt.sign_second_payload_json,
            });
            if let Some(expected) = &nonce_artifacts {
                assert_eq!(&current, expected, "nonce/session drift at {checkpoint}");
            } else {
                nonce_artifacts = Some(current);
            }
        }
        if attempt.signed_tx_hex.is_some() {
            let current = serde_json::json!({
                "server_partial_sig": attempt.server_partial_sig,
                "aggregate_signature": attempt.aggregate_signature,
                "signed_tx_hex": attempt.signed_tx_hex,
                "txid": attempt.txid,
            });
            if let Some(expected) = &signed_artifacts {
                assert_eq!(&current, expected, "signed-artifact drift at {checkpoint}");
            } else {
                signed_artifacts = Some(current);
            }
        }
        assert_eq!(
            common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
            count,
            "wrong lockbox count at {checkpoint}"
        );

        if checkpoint == "server_nonce_returned" {
            assert!(
                attempt.server_public_nonce.is_none(),
                "returned nonce was persisted before its checkpoint"
            );
            returned_server_nonce = Some(child_server_nonce(&output)?);
        }
        if checkpoint == "server_nonce_persisted" {
            let replayed = child_server_nonce(&output)?;
            assert_eq!(
                Some(replayed.as_str()),
                returned_server_nonce.as_deref(),
                "exact sign/first replay returned a different server nonce"
            );
            assert_eq!(
                attempt.server_public_nonce.as_deref(),
                Some(replayed.as_str()),
                "persisted nonce differs from the replayed response"
            );

            let exact_payload_json = attempt
                .sign_second_payload_json
                .clone()
                .context("NonceStored attempt has no exact sign/second payload")?;
            let mut corrupted_payload: Bip448PartialSignatureRequestPayload =
                serde_json::from_str(&exact_payload_json)?;
            let full_session = attempt
                .encoded_session
                .as_deref()
                .context("NonceStored attempt has no full MuSig session")?;
            assert_ne!(
                full_session, corrupted_payload.session,
                "full and blinded MuSig sessions were falsely persisted as equal"
            );
            let mut different_blinded_session = hex::decode(&corrupted_payload.session)?;
            *different_blinded_session
                .get_mut(70)
                .context("blinded MuSig session is shorter than its typed encoding")? ^= 1;
            corrupted_payload.session = hex::encode(different_blinded_session);
            let corrupted_payload_json = serde_json::to_string(&corrupted_payload)?;
            sqlx::query(
                "UPDATE bip448_withdrawal_attempts SET sign_second_payload_json=$1 \
                 WHERE wallet_name=$2 AND statechain_id=$3 AND binding_index=$4",
            )
            .bind(&corrupted_payload_json)
            .bind(&fixture.wallet_name)
            .bind(&fixture.statechain_id)
            .bind(i64::from(selected.binding_index))
            .execute(&fixture.config.pool)
            .await?;
            let corrupted_journal = raw_withdrawal_attempt_journal_snapshot(
                &fixture.config,
                &fixture.wallet_name,
                &fixture.statechain_id,
                selected.binding_index,
            )
            .await?;
            let mercury_before_rejected_resume =
                mercury_state_bytes(&fixture.statechain_id).await?;
            let count_before_rejected_resume =
                common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id)
                    .await?;
            let rejected_resume = run_duplicate_sweep_child(
                &fixture.wallet_name,
                &fixture.statechain_id,
                selected.binding_index,
                &destination,
                None,
                false,
            )?;
            require_child_exit(&rejected_resume, 101, "mutated blinded session resume")?;
            let rejected_output = format!(
                "{}{}",
                String::from_utf8_lossy(&rejected_resume.stdout),
                String::from_utf8_lossy(&rejected_resume.stderr)
            );
            assert!(
                rejected_output.contains(
                    "BIP448 blinded MuSig session does not derive from the persisted full session"
                ),
                "mutated blinded session returned an unrelated error: {rejected_output}"
            );
            assert_eq!(
                raw_withdrawal_attempt_journal_snapshot(
                    &fixture.config,
                    &fixture.wallet_name,
                    &fixture.statechain_id,
                    selected.binding_index,
                )
                .await?,
                corrupted_journal,
                "rejected mutated-session resume changed the exact journal"
            );
            assert_eq!(
                sqlx::query_scalar::<_, String>(
                    "SELECT phase FROM bip448_withdrawal_attempts WHERE wallet_name=$1 \
                     AND statechain_id=$2 AND binding_index=$3",
                )
                .bind(&fixture.wallet_name)
                .bind(&fixture.statechain_id)
                .bind(i64::from(selected.binding_index))
                .fetch_one(&fixture.config.pool)
                .await?,
                "NonceStored",
                "mutated blinded session reached SecondArmed"
            );
            assert_eq!(
                mercury_state_bytes(&fixture.statechain_id).await?,
                mercury_before_rejected_resume,
                "mutated-session resume reached a Mercury signing side effect"
            );
            assert_eq!(
                common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id)
                    .await?,
                count_before_rejected_resume,
                "mutated-session resume consumed a lockbox count"
            );

            sqlx::query(
                "UPDATE bip448_withdrawal_attempts SET sign_second_payload_json=$1 \
                 WHERE wallet_name=$2 AND statechain_id=$3 AND binding_index=$4",
            )
            .bind(&exact_payload_json)
            .bind(&fixture.wallet_name)
            .bind(&fixture.statechain_id)
            .bind(i64::from(selected.binding_index))
            .execute(&fixture.config.pool)
            .await?;
            let restored = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
                &fixture.config.pool,
                &fixture.wallet_name,
                &fixture.statechain_id,
                selected.binding_index,
            )
            .await?
            .context("restored exact session journal disappeared")?;
            assert_eq!(restored.phase, Bip448WithdrawalPhase::NonceStored);
            assert_eq!(
                restored.sign_second_payload_json.as_deref(),
                Some(exact_payload_json.as_str())
            );
        }
        if checkpoint == "server_partial_returned" {
            let failed_count_read = run_duplicate_sweep_child(
                &fixture.wallet_name,
                &fixture.statechain_id,
                selected.binding_index,
                &destination,
                None,
                true,
            )?;
            require_child_exit(&failed_count_read, 101, "post-sign count-read failure")?;
            assert!(String::from_utf8_lossy(&failed_count_read.stderr)
                .contains("injected BIP448 post-sign lockbox count read failure"));
            let after_failure = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
                &fixture.config.pool,
                &fixture.wallet_name,
                &fixture.statechain_id,
                selected.binding_index,
            )
            .await?
            .context("count-read failure deleted the attempt")?;
            assert_eq!(after_failure.phase, Bip448WithdrawalPhase::SecondArmed);
            assert_eq!(
                duplicate_attempt_immutable_json(&after_failure),
                immutable.clone().unwrap(),
                "count-read failure changed immutable attempt artifacts"
            );
            assert!(after_failure.signed_tx_hex.is_none());
            assert_eq!(
                common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id)
                    .await?,
                2,
                "exact sign/second replay incremented the count twice"
            );
        }

        if checkpoint == "signed_tx_persisted" {
            let different = mercuryrustlib::bip448_withdraw::execute_duplicate_sweep(
                &fixture.config,
                &fixture.wallet_name,
                &fixture.statechain_id,
                other.binding_index,
                &destination,
                Some(1.0),
            )
            .await;
            assert!(different.is_err());
            assert!(
                mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
                    &fixture.config.pool,
                    &fixture.wallet_name,
                    &fixture.statechain_id,
                    other.binding_index,
                )
                .await?
                .is_none()
            );
            assert_eq!(
                common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id)
                    .await?,
                2
            );
        }
    }

    let final_output = run_duplicate_sweep_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
        &destination,
        None,
        false,
    )?;
    require_child_exit(&final_output, 0, "final reconciliation")?;
    let attempt = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
    )
    .await?
    .context("final duplicate attempt is missing")?;
    assert_eq!(attempt.phase, Bip448WithdrawalPhase::Signed);
    assert_eq!(attempt.broadcast_status, Bip448BroadcastStatus::Accepted);
    assert_eq!(
        duplicate_attempt_immutable_json(&attempt),
        immutable.unwrap()
    );
    let txid = Txid::from_str(attempt.txid.as_deref().context("signed txid")?)?;
    let transaction: bitcoin::Transaction =
        bitcoin::consensus::deserialize(&fixture.config.chain_client.get_raw_tx(&txid)?)?;
    assert_eq!(transaction.input.len(), 1);
    assert_eq!(transaction.output.len(), 1);
    assert_eq!(transaction.input[0].witness.len(), 1);
    let keypath_signature = transaction.input[0]
        .witness
        .iter()
        .next()
        .context("duplicate sweep keypath witness is missing")?;
    assert_eq!(keypath_signature.len(), 65);
    assert_eq!(
        keypath_signature[64], 0x01,
        "duplicate sweep lost SIGHASH_ALL"
    );
    assert_eq!(
        transaction.input[0].previous_output,
        OutPoint {
            txid: Txid::from_str(&selected.txid)?,
            vout: selected.vout,
        }
    );
    assert_ne!(
        transaction.input[0].previous_output,
        OutPoint {
            txid: Txid::from_str(&fixture.bindings[0].txid)?,
            vout: fixture.bindings[0].vout,
        }
    );
    assert_eq!(
        transaction.output[0].value,
        selected.value_sats.checked_sub(attempt.fee_sats).unwrap()
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT wallet_json FROM wallet WHERE wallet_name=$1")
            .bind(&fixture.wallet_name)
            .fetch_one(&fixture.config.pool)
            .await?,
        raw_wallet_before
    );
    assert_eq!(
        accepted_state_bytes(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?,
        accepted_before
    );
    let mercury_after = mercury_state_bytes(&fixture.statechain_id).await?;
    assert_eq!(
        mercury_after.0, mercury_before.0,
        "duplicate sweep deleted/changed Mercury state"
    );
    assert_eq!(
        mercury_after.2, mercury_before.2,
        "duplicate sweep changed transfer state"
    );
    let wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&fixture.config.pool, &fixture.wallet_name)
            .await?;
    let coin = wallet
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some(&fixture.statechain_id))
        .context("canonical Coin disappeared")?;
    let record = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?;
    let user = PublicKey::from_str(&coin.user_pubkey)?;
    let server = PublicKey::from_str(coin.server_pubkey.as_deref().context("server key")?)?;
    assert_eq!(
        record
            .latest_state
            .verify_recovery_against_keys(&Secp256k1::new(), &user, &server)?,
        PublicKey::from_str(&record.aggregate_pubkey)?
    );
    let funded_fee_inputs = [fund_p2a_fee_input()?, fund_p2a_fee_input()?];
    common::bitcoin_core::mine_block()?;
    let fee_inputs = funded_fee_inputs
        .into_iter()
        .map(|funding| Bip448CpfpFeeInput::keyless(funding.outpoint, funding.value_sats))
        .collect::<Vec<_>>();
    let change_script =
        common::bitcoin_core::regtest_address(&common::bitcoin_core::getnewaddress()?)?
            .script_pubkey();
    let update_package = build_latest_state_recovery_package(
        &record,
        Bip448RecoveryTemplateRole::FundingUpdate,
        &fee_inputs[..1],
        change_script.clone(),
        2.0,
    )?;
    let settlement_package = build_latest_state_recovery_package(
        &record,
        Bip448RecoveryTemplateRole::Settlement,
        &fee_inputs[1..],
        change_script,
        2.0,
    )?;
    assert_eq!(
        hex::encode(bitcoin::consensus::serialize(&update_package.parent_tx)),
        record.latest_state.update_tx,
        "duplicate sweep changed canonical U recovery bytes"
    );
    assert_eq!(
        hex::encode(bitcoin::consensus::serialize(&settlement_package.parent_tx)),
        record.latest_state.settlement_tx,
        "duplicate sweep changed canonical S recovery bytes"
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
        2
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_duplicate_sweeps_are_one_input_and_canonical_closes_last() -> Result<()> {
    if let Ok(mode) = std::env::var("ML_BIP448_CANONICAL_CLOSE_CHILD_MODE") {
        std::env::set_var("ML_NETWORK", "regtest");
        let config = mercuryrustlib::client_config::load().await;
        let wallet_name = std::env::var("ML_BIP448_RESTART_WALLET")?;
        let statechain_id = std::env::var("ML_BIP448_RESTART_STATECHAIN_ID")?;
        let result = match mode.as_str() {
            "execute" => {
                mercuryrustlib::bip448_withdraw::execute(
                    &config,
                    &wallet_name,
                    &statechain_id,
                    &std::env::var("ML_BIP448_RESTART_DESTINATION")?,
                    Some(1.0),
                )
                .await
            }
            "assert-outgoing" => {
                let count: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM bip448_transfer_messages WHERE wallet_name=$1 AND statechain_id=$2",
                )
                .bind(&wallet_name)
                .bind(&statechain_id)
                .fetch_one(&config.pool)
                .await?;
                if count != 1 {
                    anyhow::bail!("accepted-prefix outgoing row did not survive restart");
                }
                Ok(())
            }
            _ => anyhow::bail!("unknown canonical-close child mode {mode}"),
        };
        config.pool.close().await;
        return result;
    }

    let _guard = common::test_guard();
    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;
    let lockbox_client = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox_client).await?;

    exercise_canonical_prepared_confirmed_conflict(&lockbox_client).await?;
    exercise_frozen_independent_spend_reorg(&lockbox_client).await?;
    exercise_frozen_signed_duplicate_mutations(&lockbox_client).await?;
    exercise_late_binding_after_canonical_wallet_persisted(&lockbox_client).await?;

    let fixture =
        duplicate_sweep_fixture(&[DUPLICATE_AMOUNT_SATS, SMALL_DUPLICATE_AMOUNT_SATS]).await?;
    assert_ne!(
        fixture.bindings[1].value_sats,
        fixture.bindings[2].value_sats
    );
    let destination = common::bitcoin_core::getnewaddress()?;
    let initial = canonical_side_effect_invariant(&fixture, &lockbox_client).await?;
    assert_eq!(initial.signature_count, 1);
    assert!(mercuryrustlib::bip448_withdraw::execute(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        Some(1.0),
    )
    .await
    .is_err());
    assert_eq!(
        canonical_side_effect_invariant(&fixture, &lockbox_client).await?,
        initial,
        "pre-sweep canonical rejection caused a signing/wallet/completion side effect"
    );
    assert!(
        mercuryrustlib::utils::get_statechain_info(&fixture.statechain_id, &fixture.config)
            .await?
            .is_some()
    );

    let original_wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&fixture.config.pool, &fixture.wallet_name)
            .await?;
    let mut in_transfer_wallet = original_wallet.clone();
    let owner_coin = in_transfer_wallet
        .coins
        .iter_mut()
        .find(|coin| coin.statechain_id.as_deref() == Some(fixture.statechain_id.as_str()))
        .context("canonical guard Coin is missing")?;
    owner_coin.status = CoinStatus::IN_TRANSFER;
    mercuryrustlib::sqlite_manager::update_wallet(&fixture.config.pool, &in_transfer_wallet)
        .await?;
    let in_transfer_before = canonical_side_effect_invariant(&fixture, &lockbox_client).await?;
    assert!(mercuryrustlib::bip448_withdraw::execute(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        Some(1.0),
    )
    .await
    .is_err());
    assert_eq!(
        canonical_side_effect_invariant(&fixture, &lockbox_client).await?,
        in_transfer_before,
        "IN_TRANSFER rejection changed durable state"
    );
    mercuryrustlib::sqlite_manager::update_wallet(&fixture.config.pool, &original_wallet).await?;

    let record = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?;
    let guard_coin = original_wallet
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some(fixture.statechain_id.as_str()))
        .context("active-intent guard Coin is missing")?;
    let intent_id = "a1".repeat(32);
    sqlx::query(
        "INSERT INTO bip448_transfer_intents (wallet_name,statechain_id,intent_id, \
         predecessor_intent_id,activity_status,intent_kind,acknowledge_cooperative_duplicates, \
         recipient_address,receiver_user_pubkey,recipient_auth_pubkey,batch_id, \
         sender_signed_statechain_id,planned_state_number,expected_signature_count, \
         previous_locktime,prior_pending_signing_id,prior_transfer_recipient_auth_pubkey, \
         prior_transfer_msg_hash,reuse_pending,reuse_signed_state,clear_local_attempt, \
         generated_coin_user_pubkey,generated_coin_auth_pubkey,generated_coin_address,phase, \
         server_x1,current_pending_signing_id,state_signing_phase,server_partial_sig, \
         update_signature) VALUES ($1,$2,$3,NULL,'Active','UserTransfer',1,$4,$5,$6,NULL, \
         $7,$8,$9,$10,NULL,NULL,NULL,0,0,0,NULL,NULL,NULL,'Prepared',NULL,NULL,'NotStarted',NULL,NULL)",
    )
    .bind(&fixture.wallet_name)
    .bind(&fixture.statechain_id)
    .bind(&intent_id)
    .bind(&guard_coin.address)
    .bind(&guard_coin.user_pubkey)
    .bind(&guard_coin.auth_pubkey)
    .bind(
        guard_coin
            .signed_statechain_id
            .as_deref()
            .context("active-intent guard Coin has no signature")?,
    )
    .bind(i64::from(record.latest_state_number + 1))
    .bind(i64::from(record.latest_state_number))
    .bind(i64::from(record.latest_state.state_locktime))
    .execute(&fixture.config.pool)
    .await?;
    let intent_before = canonical_side_effect_invariant(&fixture, &lockbox_client).await?;
    assert!(mercuryrustlib::bip448_withdraw::execute(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        Some(1.0),
    )
    .await
    .is_err());
    assert_eq!(
        canonical_side_effect_invariant(&fixture, &lockbox_client).await?,
        intent_before,
        "active transfer intent did not reject before canonical side effects"
    );
    let deleted = sqlx::query(
        "DELETE FROM bip448_transfer_intents WHERE wallet_name=$1 AND statechain_id=$2 AND intent_id=$3",
    )
    .bind(&fixture.wallet_name)
    .bind(&fixture.statechain_id)
    .bind(&intent_id)
    .execute(&fixture.config.pool)
    .await?;
    assert_eq!(deleted.rows_affected(), 1);

    let (accepted_recipient, accepted_message) = accepted_prefix_message(&fixture).await?;
    mercuryrustlib::sqlite_manager::insert_or_update_bip448_transfer_msg(
        &fixture.config.pool,
        &fixture.wallet_name,
        &accepted_recipient,
        &accepted_message,
    )
    .await?;
    let restart = run_canonical_close_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        "assert-outgoing",
        None,
    )?;
    require_child_exit(&restart, 0, "accepted-prefix restart persistence")?;
    let accepted_prefix_before = canonical_side_effect_invariant(&fixture, &lockbox_client).await?;
    assert!(mercuryrustlib::bip448_withdraw::execute(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        Some(1.0),
    )
    .await
    .is_err());
    assert_eq!(
        canonical_side_effect_invariant(&fixture, &lockbox_client).await?,
        accepted_prefix_before,
        "accepted-prefix cleanup changed anything except its exact outgoing row"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bip448_transfer_messages WHERE wallet_name=$1 AND statechain_id=$2",
        )
        .bind(&fixture.wallet_name)
        .bind(&fixture.statechain_id)
        .fetch_one(&fixture.config.pool)
        .await?,
        0
    );

    let mut beyond_accepted = accepted_message.clone();
    beyond_accepted.latest_state_number = beyond_accepted
        .latest_state_number
        .checked_add(1)
        .context("beyond-accepted state number overflow")?;
    for (case, recipient, message) in [
        (
            "beyond accepted",
            accepted_recipient.clone(),
            beyond_accepted,
        ),
        (
            "one field",
            accepted_recipient.clone(),
            Bip448TransferMsg {
                amount_sats: accepted_message.amount_sats + 1,
                ..accepted_message.clone()
            },
        ),
        ("history", accepted_recipient.clone(), {
            let mut message = accepted_message.clone();
            message.state_history[0].update_template_hash = "a2".repeat(32);
            message
        }),
        (
            "recipient",
            PublicKey::from_secret_key(
                &Secp256k1::new(),
                &secp256k1::SecretKey::from_secret_bytes([99; 32])?,
            )
            .to_string(),
            accepted_message.clone(),
        ),
    ] {
        mercuryrustlib::sqlite_manager::insert_or_update_bip448_transfer_msg(
            &fixture.config.pool,
            &fixture.wallet_name,
            &recipient,
            &message,
        )
        .await?;
        let mismatch_before = canonical_side_effect_invariant(&fixture, &lockbox_client).await?;
        assert!(
            mercuryrustlib::bip448_withdraw::execute(
                &fixture.config,
                &fixture.wallet_name,
                &fixture.statechain_id,
                &destination,
                Some(1.0),
            )
            .await
            .is_err(),
            "{case} outgoing mismatch did not block canonical close"
        );
        assert_eq!(
            canonical_side_effect_invariant(&fixture, &lockbox_client).await?,
            mismatch_before,
            "{case} outgoing mismatch changed signing/wallet/completion state"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM bip448_transfer_messages WHERE wallet_name=$1 AND statechain_id=$2 AND recipient_auth_pubkey=$3",
            )
            .bind(&fixture.wallet_name)
            .bind(&fixture.statechain_id)
            .bind(&recipient)
            .fetch_one(&fixture.config.pool)
            .await?,
            1,
            "{case} outgoing mismatch was incorrectly deleted"
        );
        delete_exact_outgoing_message(&fixture, &recipient).await?;
    }

    common::bitcoin_core::mine_block()?;
    save_empty_mempool_baseline()?;
    let accepted_before = accepted_state_bytes(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?;
    let sweep_one = mercuryrustlib::bip448_withdraw::execute_duplicate_sweep(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        fixture.bindings[1].binding_index,
        &destination,
        Some(1.0),
    )
    .await?;
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
        2
    );
    assert!(
        mercuryrustlib::utils::get_statechain_info(&fixture.statechain_id, &fixture.config)
            .await?
            .is_some()
    );
    assert!(mercuryrustlib::bip448_withdraw::execute(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        Some(1.0),
    )
    .await
    .is_err());
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
        2
    );
    assert!(
        mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
            0,
        )
        .await?
        .is_none()
    );

    let sweep_two = mercuryrustlib::bip448_withdraw::execute_duplicate_sweep(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        fixture.bindings[2].binding_index,
        &destination,
        Some(1.0),
    )
    .await?;
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
        3
    );
    assert!(
        mercuryrustlib::utils::get_statechain_info(&fixture.statechain_id, &fixture.config)
            .await?
            .is_some()
    );
    assert_eq!(
        accepted_state_bytes(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?,
        accepted_before
    );

    let canonical_checkpoints = [
        (
            "attempt_prepared",
            Bip448WithdrawalPhase::Prepared,
            Bip448BroadcastStatus::NotBroadcast,
            Bip448CompletionStatus::Open,
            3,
        ),
        (
            "sign_first_armed",
            Bip448WithdrawalPhase::FirstArmed,
            Bip448BroadcastStatus::NotBroadcast,
            Bip448CompletionStatus::Open,
            3,
        ),
        (
            "server_nonce_returned",
            Bip448WithdrawalPhase::FirstArmed,
            Bip448BroadcastStatus::NotBroadcast,
            Bip448CompletionStatus::Open,
            3,
        ),
        (
            "server_nonce_persisted",
            Bip448WithdrawalPhase::NonceStored,
            Bip448BroadcastStatus::NotBroadcast,
            Bip448CompletionStatus::Open,
            3,
        ),
        (
            "sign_second_armed",
            Bip448WithdrawalPhase::SecondArmed,
            Bip448BroadcastStatus::NotBroadcast,
            Bip448CompletionStatus::Open,
            3,
        ),
        (
            "server_partial_returned",
            Bip448WithdrawalPhase::SecondArmed,
            Bip448BroadcastStatus::NotBroadcast,
            Bip448CompletionStatus::Open,
            4,
        ),
        (
            "signed_tx_persisted",
            Bip448WithdrawalPhase::Signed,
            Bip448BroadcastStatus::NotBroadcast,
            Bip448CompletionStatus::Open,
            4,
        ),
        (
            "broadcast_returned",
            Bip448WithdrawalPhase::Signed,
            Bip448BroadcastStatus::NeedsRebroadcast,
            Bip448CompletionStatus::Open,
            4,
        ),
        (
            "canonical_wallet_persisted",
            Bip448WithdrawalPhase::Signed,
            Bip448BroadcastStatus::Accepted,
            Bip448CompletionStatus::Open,
            4,
        ),
        (
            "canonical_close_armed",
            Bip448WithdrawalPhase::Signed,
            Bip448BroadcastStatus::Accepted,
            Bip448CompletionStatus::CloseArmed,
            4,
        ),
        (
            "canonical_completion_returned",
            Bip448WithdrawalPhase::Signed,
            Bip448BroadcastStatus::Accepted,
            Bip448CompletionStatus::CloseArmed,
            4,
        ),
    ];
    let raw_wallet_before_canonical: String =
        sqlx::query_scalar("SELECT wallet_json FROM wallet WHERE wallet_name=$1")
            .bind(&fixture.wallet_name)
            .fetch_one(&fixture.config.pool)
            .await?;
    let mut canonical_immutable = None;
    for (checkpoint, phase, broadcast, completion, count) in canonical_checkpoints {
        let output = run_canonical_close_child(
            &fixture.wallet_name,
            &fixture.statechain_id,
            &destination,
            "execute",
            Some(checkpoint),
        )?;
        require_child_exit(&output, 86, checkpoint)?;
        let attempts = mercuryrustlib::sqlite_manager::list_bip448_withdrawal_attempts(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?;
        assert_eq!(
            attempts.len(),
            3,
            "{checkpoint} changed attempt cardinality"
        );
        let canonical = attempts
            .iter()
            .find(|attempt| attempt.binding_index == 0)
            .context("canonical journal is missing")?;
        assert_eq!(
            canonical.attempt_kind,
            Bip448WithdrawalAttemptKind::Canonical
        );
        assert_eq!(
            canonical.phase, phase,
            "wrong canonical phase at {checkpoint}"
        );
        assert_eq!(
            canonical.broadcast_status, broadcast,
            "wrong canonical broadcast status at {checkpoint}"
        );
        assert_eq!(
            canonical.completion_status, completion,
            "wrong canonical completion status at {checkpoint}"
        );
        let immutable = duplicate_attempt_immutable_json(canonical);
        if let Some(expected) = &canonical_immutable {
            assert_eq!(
                &immutable, expected,
                "canonical immutable drift at {checkpoint}"
            );
        } else {
            canonical_immutable = Some(immutable);
        }
        if checkpoint == "canonical_completion_returned" {
            assert_lockbox_state_absent(&lockbox_client, &fixture.statechain_id).await?;
        } else {
            assert_eq!(
                common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id)
                    .await?,
                count,
                "wrong canonical lockbox count at {checkpoint}"
            );
        }
        assert_eq!(
            accepted_state_bytes(
                &fixture.config.pool,
                &fixture.wallet_name,
                &fixture.statechain_id,
            )
            .await?,
            accepted_before,
            "canonical checkpoint {checkpoint} changed accepted history"
        );
        if checkpoint == "attempt_prepared" {
            let wallet = mercuryrustlib::sqlite_manager::get_wallet(
                &fixture.config.pool,
                &fixture.wallet_name,
            )
            .await?;
            let listed = mercuryrustlib::coin_status::statecoin_list_entry_json(
                &fixture.wallet_name,
                wallet
                    .coins
                    .iter()
                    .find(|coin| {
                        coin.statechain_id.as_deref() == Some(fixture.statechain_id.as_str())
                    })
                    .context("canonical listed Coin is missing")?,
                &mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
                    &fixture.config.pool,
                    &fixture.wallet_name,
                    &fixture.statechain_id,
                )
                .await?,
                &attempts,
            )?;
            assert_eq!(listed["coin.address_retired"].as_bool(), Some(true));
            assert_eq!(
                listed["coin.close_tip_height"].as_u64(),
                canonical.closing_tip_height.map(u64::from)
            );
            assert_eq!(
                listed["coin.close_tip_hash"].as_str(),
                canonical.closing_tip_hash.as_deref()
            );
            let close_height = canonical.closing_tip_height.context("close height")?;
            assert_eq!(
                canonical.closing_tip_hash.as_deref(),
                Some(
                    fixture
                        .config
                        .chain_client
                        .get_block_hash(close_height)?
                        .to_string()
                        .as_str()
                )
            );
        }
        if matches!(
            checkpoint,
            "attempt_prepared"
                | "sign_first_armed"
                | "server_nonce_returned"
                | "server_nonce_persisted"
                | "sign_second_armed"
                | "server_partial_returned"
                | "signed_tx_persisted"
                | "broadcast_returned"
        ) {
            assert_eq!(
                sqlx::query_scalar::<_, String>(
                    "SELECT wallet_json FROM wallet WHERE wallet_name=$1",
                )
                .bind(&fixture.wallet_name)
                .fetch_one(&fixture.config.pool)
                .await?,
                raw_wallet_before_canonical,
                "wallet changed before canonical acceptance at {checkpoint}"
            );
        }
        let server_present =
            mercuryrustlib::utils::get_statechain_info(&fixture.statechain_id, &fixture.config)
                .await?
                .is_some();
        assert_eq!(
            server_present,
            checkpoint != "canonical_completion_returned",
            "server deletion occurred at the wrong canonical checkpoint"
        );
    }

    let final_resume = run_canonical_close_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        "execute",
        None,
    )?;
    require_child_exit(&final_resume, 0, "canonical lost-response reconciliation")?;
    let attempts = mercuryrustlib::sqlite_manager::list_bip448_withdrawal_attempts(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?;
    assert_eq!(attempts.len(), 3);
    let canonical = attempts
        .iter()
        .find(|attempt| attempt.binding_index == 0)
        .context("closed canonical journal is missing")?;
    assert_eq!(canonical.completion_status, Bip448CompletionStatus::Closed);
    let canonical_txid = Txid::from_str(canonical.txid.as_deref().context("canonical txid")?)?;
    let signed_bytes = canonical
        .signed_tx_hex
        .clone()
        .context("canonical signed bytes are missing")?;
    let all_txids = [
        Txid::from_str(&sweep_one.sweep_txid)?,
        Txid::from_str(&sweep_two.sweep_txid)?,
        canonical_txid,
    ];
    let mut sources = BTreeSet::new();
    for txid in all_txids {
        let transaction: bitcoin::Transaction =
            bitcoin::consensus::deserialize(&fixture.config.chain_client.get_raw_tx(&txid)?)?;
        assert_eq!(transaction.input.len(), 1);
        assert_eq!(transaction.output.len(), 1);
        sources.insert(transaction.input[0].previous_output);
    }
    assert_eq!(sources.len(), 3);
    let wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&fixture.config.pool, &fixture.wallet_name)
            .await?;
    assert_eq!(
        wallet
            .activities
            .iter()
            .filter(|activity| activity.utxo == canonical_txid.to_string())
            .count(),
        1
    );
    assert_lockbox_state_absent(&lockbox_client, &fixture.statechain_id).await?;
    assert_eq!(
        accepted_state_bytes(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?,
        accepted_before
    );

    let tip = fixture.config.chain_client.tip_height()?;
    restart_core_dropping_unpersisted_mempool(&fixture.config, tip, false)?;
    mercuryrustlib::coin_status::sync_bip448_funding_bindings(
        &fixture.config,
        &fixture.wallet_name,
    )
    .await?;
    let disappeared = mercuryrustlib::sqlite_manager::list_bip448_withdrawal_attempts(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?;
    assert!(disappeared
        .iter()
        .all(|attempt| attempt.broadcast_status == Bip448BroadcastStatus::NeedsRebroadcast));
    assert_eq!(
        disappeared
            .iter()
            .find(|attempt| attempt.binding_index == 0)
            .context("disappeared canonical journal is missing")?
            .completion_status,
        Bip448CompletionStatus::Closed
    );
    for (index, expected_txid) in [
        (
            fixture.bindings[1].binding_index,
            sweep_one.sweep_txid.as_str(),
        ),
        (
            fixture.bindings[2].binding_index,
            sweep_two.sweep_txid.as_str(),
        ),
    ] {
        let replayed = mercuryrustlib::bip448_withdraw::execute_duplicate_sweep(
            &fixture.config,
            &fixture.wallet_name,
            &fixture.statechain_id,
            index,
            &destination,
            Some(1.0),
        )
        .await?;
        assert_eq!(replayed.sweep_txid, expected_txid);
    }
    mercuryrustlib::bip448_withdraw::execute(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        Some(1.0),
    )
    .await?;
    let rebroadcast = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        0,
    )
    .await?
    .context("rebroadcast canonical journal is missing")?;
    assert_eq!(
        rebroadcast.completion_status,
        Bip448CompletionStatus::Closed
    );
    assert_eq!(
        rebroadcast.signed_tx_hex.as_deref(),
        Some(signed_bytes.as_str())
    );
    assert_lockbox_state_absent(&lockbox_client, &fixture.statechain_id).await?;
    assert!(
        mercuryrustlib::utils::get_statechain_info(&fixture.statechain_id, &fixture.config)
            .await?
            .is_none()
    );
    let wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&fixture.config.pool, &fixture.wallet_name)
            .await?;
    assert_eq!(
        wallet
            .activities
            .iter()
            .filter(|activity| activity.utxo == canonical_txid.to_string())
            .count(),
        1
    );
    common::bitcoin_core::execute_bitcoin_command(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury loadwallet mercury_test",
    )?;
    common::bitcoin_core::execute_bitcoin_command(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury loadwallet mercury_tokens",
    )?;
    common::bitcoin_core::mine_block_with_transactions(&all_txids)?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_receiver_post_acceptance_duplicate_rescan_is_retryable() -> Result<()> {
    if std::env::var("ML_BIP448_RECEIVER_RESCAN_CHILD").as_deref() == Ok("1") {
        std::env::set_var("ML_NETWORK", "regtest");
        let config = mercuryrustlib::client_config::load().await;
        let result = mercuryrustlib::bip448_transfer_sender::cancel_bip448_transfer(
            &config,
            &std::env::var("ML_BIP448_RESTART_WALLET")?,
            &std::env::var("ML_BIP448_RESTART_STATECHAIN_ID")?,
        )
        .await
        .map(|_| ());
        config.pool.close().await;
        return result;
    }

    let _guard = common::test_guard();
    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;
    let lockbox_client = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox_client).await?;

    // Cancellation first: stop after sender preflight/finish, introduce a new
    // output, then fail only after the real outer receiver has persisted the
    // accepted record, complete history, and final wallet.
    let cancellation_fixture = duplicate_sweep_fixture(&[]).await?;
    let cancellation_wallet = mercuryrustlib::sqlite_manager::get_wallet(
        &cancellation_fixture.config.pool,
        &cancellation_fixture.wallet_name,
    )
    .await?;
    let cancellation_sender_coin = cancellation_wallet
        .coins
        .iter()
        .find(|coin| {
            coin.statechain_id.as_deref() == Some(cancellation_fixture.statechain_id.as_str())
        })
        .context("cancellation fixture sender Coin is missing")?;
    let cancellation_aggregate = Address::from_str(
        cancellation_sender_coin
            .aggregated_address
            .as_deref()
            .context("cancellation fixture aggregate address is missing")?,
    )?
    .require_network(cancellation_fixture.config.network)?;
    cancellation_fixture.config.pool.close().await;

    let sender_finished = run_receiver_rescan_cancel_child(
        &cancellation_fixture.wallet_name,
        &cancellation_fixture.statechain_id,
    )?;
    require_child_exit(
        &sender_finished,
        86,
        "cancellation after transfer_sender_finished",
    )?;
    let cancellation_config = mercuryrustlib::client_config::load().await;
    let sender_finished_intent = mercuryrustlib::sqlite_manager::get_active_bip448_transfer_intent(
        &cancellation_config.pool,
        &cancellation_fixture.wallet_name,
        &cancellation_fixture.statechain_id,
    )
    .await?
    .context("cancellation SenderFinished intent is missing")?;
    assert_eq!(sender_finished_intent.intent_kind.as_str(), "Cancellation");
    assert_eq!(sender_finished_intent.phase.as_str(), "SenderFinished");
    let generated_user = sender_finished_intent
        .generated_coin_user_pubkey
        .clone()
        .context("cancellation intent has no generated user key")?;
    let generated_auth = sender_finished_intent
        .generated_coin_auth_pubkey
        .clone()
        .context("cancellation intent has no generated auth key")?;
    let (cancellation_recipient, cancellation_message_raw) =
        mercuryrustlib::sqlite_manager::get_bip448_transfer_msg_raw_optional(
            &cancellation_config.pool,
            &cancellation_fixture.wallet_name,
            &cancellation_fixture.statechain_id,
            None,
        )
        .await?
        .context("cancellation outgoing message is missing")?;
    assert_eq!(cancellation_recipient, generated_auth);
    let cancellation_message =
        require_v2_message_without_duplicate_field(&cancellation_message_raw)?;
    assert_eq!(
        cancellation_message.receiver_user_public_key,
        generated_user
    );
    let sender_finished_bindings = mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
        &cancellation_config.pool,
        &cancellation_fixture.wallet_name,
        &cancellation_fixture.statechain_id,
    )
    .await?;
    assert_eq!(sender_finished_bindings.len(), 1);
    let sender_finished_canonical = sender_finished_bindings[0].clone();
    let sender_finished_wallet = mercuryrustlib::sqlite_manager::get_wallet(
        &cancellation_config.pool,
        &cancellation_fixture.wallet_name,
    )
    .await?;
    let generated_before_acceptance = sender_finished_wallet
        .coins
        .iter()
        .filter(|coin| coin.user_pubkey == generated_user && coin.auth_pubkey == generated_auth)
        .collect::<Vec<_>>();
    assert_eq!(generated_before_acceptance.len(), 1);
    assert_eq!(
        generated_before_acceptance[0].status,
        CoinStatus::INITIALISED
    );
    assert!(generated_before_acceptance[0].statechain_id.is_none());

    let late_duplicate = fund_address_output(&cancellation_aggregate, DUPLICATE_AMOUNT_SATS)?;
    common::bitcoin_core::mine_blocks(cancellation_config.confirmation_target)?;
    let duplicate_tx_out = cancellation_config
        .chain_client
        .get_tx_out(
            &late_duplicate.outpoint.txid,
            late_duplicate.outpoint.vout,
            true,
        )?
        .context("late cancellation duplicate is not unspent")?;
    let duplicate_funding_height = cancellation_config
        .chain_client
        .tip_height()?
        .checked_sub(duplicate_tx_out.confirmations.saturating_sub(1))
        .context("late cancellation duplicate confirmations exceed the tip")?;
    let mut simulated_receiver_wallet = mercuryrustlib::sqlite_manager::get_wallet(
        &cancellation_config.pool,
        &cancellation_fixture.wallet_name,
    )
    .await?;
    let simulated_receiver_birth = cancellation_config
        .chain_client
        .tip_height()?
        .checked_add(1)
        .context("simulated cancellation receiver birth height overflow")?;
    assert!(duplicate_funding_height < simulated_receiver_birth);
    simulated_receiver_wallet.blockheight = simulated_receiver_birth;
    mercuryrustlib::sqlite_manager::update_wallet(
        &cancellation_config.pool,
        &simulated_receiver_wallet,
    )
    .await?;
    assert_eq!(
        bip448_transfer_artifact_counts(
            &cancellation_config,
            &cancellation_fixture.wallet_name,
            &cancellation_fixture.statechain_id,
        )
        .await?,
        (1, 1, 1)
    );

    mercuryrustlib::transfer_receiver::inject_bip448_post_acceptance_sync_failures_for_test(1);
    let cancellation_error = match mercuryrustlib::transfer_receiver::execute(
        &cancellation_config,
        &cancellation_fixture.wallet_name,
    )
    .await
    {
        Ok(_) => anyhow::bail!("injected cancellation post-acceptance rescan did not fail"),
        Err(error) => error,
    };
    let typed_cancellation = cancellation_error
        .downcast_ref::<mercuryrustlib::transfer_receiver::Bip448PostAcceptanceSyncError>()
        .context("cancellation rescan error is not the typed post-acceptance error")?;
    assert_eq!(
        typed_cancellation.accepted_statechain_ids(),
        &[cancellation_fixture.statechain_id.clone()]
    );
    assert!(cancellation_error.to_string().contains("already accepted"));
    assert!(cancellation_error
        .to_string()
        .contains("next update/list will retry"));

    let receiver_accepted_intent =
        mercuryrustlib::sqlite_manager::get_active_bip448_transfer_intent(
            &cancellation_config.pool,
            &cancellation_fixture.wallet_name,
            &cancellation_fixture.statechain_id,
        )
        .await?
        .context("accepted cancellation intent was rolled back")?;
    assert_eq!(
        receiver_accepted_intent.intent_id,
        sender_finished_intent.intent_id
    );
    assert_eq!(receiver_accepted_intent.phase.as_str(), "ReceiverAccepted");
    assert_eq!(
        receiver_accepted_intent.intent_kind.as_str(),
        "Cancellation"
    );
    let accepted_cancellation_wallet = mercuryrustlib::sqlite_manager::get_wallet(
        &cancellation_config.pool,
        &cancellation_fixture.wallet_name,
    )
    .await?;
    let accepted_generated = accepted_cancellation_wallet
        .coins
        .iter()
        .filter(|coin| {
            coin.user_pubkey == generated_user
                && coin.auth_pubkey == generated_auth
                && coin.statechain_id.as_deref()
                    == Some(cancellation_fixture.statechain_id.as_str())
        })
        .collect::<Vec<_>>();
    assert_eq!(accepted_generated.len(), 1);
    assert!(matches!(
        accepted_generated[0].status,
        CoinStatus::UNCONFIRMED | CoinStatus::CONFIRMED
    ));
    let accepted_cancellation_record = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &cancellation_config.pool,
        &cancellation_fixture.wallet_name,
        &cancellation_fixture.statechain_id,
    )
    .await?;
    assert_eq!(accepted_cancellation_record.latest_state_number, 2);
    let accepted_cancellation_bytes = accepted_state_bytes(
        &cancellation_config.pool,
        &cancellation_fixture.wallet_name,
        &cancellation_fixture.statechain_id,
    )
    .await?;
    assert_eq!(accepted_cancellation_bytes.1.len(), 2);
    assert_eq!(
        mercuryrustlib::sqlite_manager::get_bip448_transfer_msg_raw_optional(
            &cancellation_config.pool,
            &cancellation_fixture.wallet_name,
            &cancellation_fixture.statechain_id,
            Some(&cancellation_recipient),
        )
        .await?,
        Some((
            cancellation_recipient.clone(),
            cancellation_message_raw.clone()
        ))
    );
    assert_eq!(
        mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
            &cancellation_config.pool,
            &cancellation_fixture.wallet_name,
            &cancellation_fixture.statechain_id,
        )
        .await?,
        sender_finished_bindings,
        "post-acceptance failure must precede binding reassignment/discovery"
    );
    assert!(
        mercuryrustlib::sqlite_manager::list_bip448_withdrawal_attempts(
            &cancellation_config.pool,
            &cancellation_fixture.wallet_name,
            &cancellation_fixture.statechain_id,
        )
        .await?
        .is_empty()
    );
    assert_eq!(
        bip448_transfer_artifact_counts(
            &cancellation_config,
            &cancellation_fixture.wallet_name,
            &cancellation_fixture.statechain_id,
        )
        .await?,
        (1, 1, 1),
        "post-acceptance failure lost cancellation message, intent, or pending lineage"
    );
    let cancellation_mercury_after_acceptance =
        mercury_state_bytes(&cancellation_fixture.statechain_id).await?;
    let cancellation_count_after_acceptance =
        common::lockbox::get_signature_count(&lockbox_client, &cancellation_fixture.statechain_id)
            .await?;
    cancellation_config.pool.close().await;

    let cancellation_retry = mercuryrustlib::client_config::load().await;
    assert_eq!(
        accepted_state_bytes(
            &cancellation_retry.pool,
            &cancellation_fixture.wallet_name,
            &cancellation_fixture.statechain_id,
        )
        .await?,
        accepted_cancellation_bytes,
        "accepted cancellation record/history did not survive restart"
    );
    assert_eq!(
        mercuryrustlib::sqlite_manager::get_bip448_transfer_msg_raw_optional(
            &cancellation_retry.pool,
            &cancellation_fixture.wallet_name,
            &cancellation_fixture.statechain_id,
            Some(&cancellation_recipient),
        )
        .await?,
        Some((
            cancellation_recipient.clone(),
            cancellation_message_raw.clone()
        ))
    );
    mercuryrustlib::coin_status::update_coins(
        &cancellation_retry,
        &cancellation_fixture.wallet_name,
    )
    .await?;
    assert_eq!(
        accepted_state_bytes(
            &cancellation_retry.pool,
            &cancellation_fixture.wallet_name,
            &cancellation_fixture.statechain_id,
        )
        .await?,
        accepted_cancellation_bytes
    );
    assert_eq!(
        bip448_transfer_artifact_counts(
            &cancellation_retry,
            &cancellation_fixture.wallet_name,
            &cancellation_fixture.statechain_id,
        )
        .await?,
        (0, 0, 0),
        "successful cancellation retry must atomically remove its exact terminal artifacts"
    );
    let cancellation_bindings = mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
        &cancellation_retry.pool,
        &cancellation_fixture.wallet_name,
        &cancellation_fixture.statechain_id,
    )
    .await?;
    assert_eq!(cancellation_bindings.len(), 2);
    let cancellation_canonical = cancellation_bindings
        .iter()
        .find(|binding| binding.role == Bip448BindingRole::Canonical)
        .context("reassigned cancellation canonical binding is missing")?;
    assert_eq!(
        cancellation_canonical.binding_index,
        sender_finished_canonical.binding_index
    );
    assert_eq!(cancellation_canonical.txid, sender_finished_canonical.txid);
    assert_eq!(cancellation_canonical.vout, sender_finished_canonical.vout);
    assert_eq!(
        cancellation_canonical.first_seen_at,
        sender_finished_canonical.first_seen_at
    );
    let cancellation_duplicate = cancellation_bindings
        .iter()
        .find(|binding| {
            binding.txid == late_duplicate.outpoint.txid.to_string()
                && binding.vout == late_duplicate.outpoint.vout
        })
        .context("height-0 retry did not discover the late cancellation duplicate")?;
    assert_eq!(cancellation_duplicate.role, Bip448BindingRole::Duplicate);
    assert!(
        cancellation_duplicate
            .funding_height
            .context("late cancellation duplicate has no funding height")?
            < simulated_receiver_birth
    );
    let cancellation_owner = accepted_cancellation_bytes
        .1
        .last()
        .map(|(_, entry)| serde_json::from_str::<serde_json::Value>(entry))
        .transpose()?
        .and_then(|entry| {
            entry
                .get("owner_public_key")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .context("accepted cancellation history has no owner")?;
    assert!(cancellation_bindings.iter().all(|binding| {
        binding.owner_user_pubkey == cancellation_owner
            && binding.owner_state_number == 2
            && binding.ownership_status == Bip448OwnershipStatus::Current
    }));
    assert!(
        mercuryrustlib::sqlite_manager::list_bip448_withdrawal_attempts(
            &cancellation_retry.pool,
            &cancellation_fixture.wallet_name,
            &cancellation_fixture.statechain_id,
        )
        .await?
        .is_empty()
    );
    assert_eq!(
        mercury_state_bytes(&cancellation_fixture.statechain_id).await?,
        cancellation_mercury_after_acceptance,
        "passive cancellation retry performed a second server key update"
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &cancellation_fixture.statechain_id,)
            .await?,
        cancellation_count_after_acceptance,
        "passive cancellation retry changed the signature count"
    );
    let rejection_recipient = mercuryrustlib::transfer_receiver::new_transfer_address(
        &cancellation_retry,
        &cancellation_fixture.wallet_name,
    )
    .await?;
    let duplicate_rejection = mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender(
        &cancellation_retry,
        &rejection_recipient,
        &cancellation_fixture.wallet_name,
        &cancellation_fixture.statechain_id,
        None,
    )
    .await
    .expect_err("normal sender accepted a known cooperative duplicate");
    assert!(duplicate_rejection
        .to_string()
        .to_ascii_lowercase()
        .contains("duplicate"));
    assert_eq!(
        bip448_transfer_artifact_counts(
            &cancellation_retry,
            &cancellation_fixture.wallet_name,
            &cancellation_fixture.statechain_id,
        )
        .await?,
        (0, 0, 0)
    );
    assert_eq!(
        mercury_state_bytes(&cancellation_fixture.statechain_id).await?,
        cancellation_mercury_after_acceptance
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &cancellation_fixture.statechain_id,)
            .await?,
        cancellation_count_after_acceptance
    );
    cancellation_retry.pool.close().await;

    // Ordinary same-wallet UserTransfer has no durable intent after sender
    // finish. Its exact local outgoing row must therefore be the restart
    // trigger for accepted-prefix cleanup in the normal update/list path.
    let ordinary_fixture = duplicate_sweep_fixture(&[]).await?;
    let ordinary_initial_binding = ordinary_fixture.bindings[0].clone();
    let ordinary_recipient = mercuryrustlib::transfer_receiver::new_transfer_address(
        &ordinary_fixture.config,
        &ordinary_fixture.wallet_name,
    )
    .await?;
    let (_, ordinary_receiver_user, ordinary_receiver_auth) =
        mercurylib::decode_transfer_address(&ordinary_recipient)?;
    mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender(
        &ordinary_fixture.config,
        &ordinary_recipient,
        &ordinary_fixture.wallet_name,
        &ordinary_fixture.statechain_id,
        None,
    )
    .await?;
    assert!(
        mercuryrustlib::sqlite_manager::get_active_bip448_transfer_intent(
            &ordinary_fixture.config.pool,
            &ordinary_fixture.wallet_name,
            &ordinary_fixture.statechain_id,
        )
        .await?
        .is_none(),
        "finished ordinary UserTransfer retained an active intent"
    );
    let (ordinary_recipient_auth, ordinary_message_raw) =
        mercuryrustlib::sqlite_manager::get_bip448_transfer_msg_raw_optional(
            &ordinary_fixture.config.pool,
            &ordinary_fixture.wallet_name,
            &ordinary_fixture.statechain_id,
            None,
        )
        .await?
        .context("ordinary same-wallet outgoing message is missing")?;
    assert_eq!(ordinary_recipient_auth, ordinary_receiver_auth.to_string());
    let ordinary_message = require_v2_message_without_duplicate_field(&ordinary_message_raw)?;
    assert_eq!(
        ordinary_message.receiver_user_public_key,
        ordinary_receiver_user.to_string()
    );
    let ordinary_sender_finished_bindings =
        mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
            &ordinary_fixture.config.pool,
            &ordinary_fixture.wallet_name,
            &ordinary_fixture.statechain_id,
        )
        .await?;
    assert_eq!(ordinary_sender_finished_bindings.len(), 1);

    mercuryrustlib::transfer_receiver::inject_bip448_post_acceptance_sync_failures_for_test(1);
    let ordinary_error = match mercuryrustlib::transfer_receiver::execute(
        &ordinary_fixture.config,
        &ordinary_fixture.wallet_name,
    )
    .await
    {
        Ok(_) => anyhow::bail!("injected ordinary post-acceptance rescan did not fail"),
        Err(error) => error,
    };
    let typed_ordinary = ordinary_error
        .downcast_ref::<mercuryrustlib::transfer_receiver::Bip448PostAcceptanceSyncError>()
        .context("ordinary rescan error is not the typed post-acceptance error")?;
    assert_eq!(
        typed_ordinary.accepted_statechain_ids(),
        &[ordinary_fixture.statechain_id.clone()]
    );
    assert!(ordinary_error.to_string().contains("already accepted"));
    let ordinary_accepted_bytes = accepted_state_bytes(
        &ordinary_fixture.config.pool,
        &ordinary_fixture.wallet_name,
        &ordinary_fixture.statechain_id,
    )
    .await?;
    assert_eq!(ordinary_accepted_bytes.1.len(), 2);
    assert_eq!(
        mercuryrustlib::sqlite_manager::get_bip448_transfer_msg_raw_optional(
            &ordinary_fixture.config.pool,
            &ordinary_fixture.wallet_name,
            &ordinary_fixture.statechain_id,
            Some(&ordinary_recipient_auth),
        )
        .await?,
        Some((
            ordinary_recipient_auth.clone(),
            ordinary_message_raw.clone()
        )),
        "ordinary accepted-prefix row was deleted before passive sync succeeded"
    );
    assert!(
        mercuryrustlib::sqlite_manager::get_active_bip448_transfer_intent(
            &ordinary_fixture.config.pool,
            &ordinary_fixture.wallet_name,
            &ordinary_fixture.statechain_id,
        )
        .await?
        .is_none()
    );
    assert_eq!(
        mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
            &ordinary_fixture.config.pool,
            &ordinary_fixture.wallet_name,
            &ordinary_fixture.statechain_id,
        )
        .await?,
        ordinary_sender_finished_bindings
    );
    let ordinary_wallet_after_acceptance = mercuryrustlib::sqlite_manager::get_wallet(
        &ordinary_fixture.config.pool,
        &ordinary_fixture.wallet_name,
    )
    .await?;
    assert_eq!(
        ordinary_wallet_after_acceptance
            .coins
            .iter()
            .filter(|coin| {
                coin.statechain_id.as_deref() == Some(ordinary_fixture.statechain_id.as_str())
                    && coin.user_pubkey == ordinary_receiver_user.to_string()
                    && coin.auth_pubkey == ordinary_receiver_auth.to_string()
            })
            .count(),
        1
    );
    assert_eq!(
        bip448_transfer_artifact_counts(
            &ordinary_fixture.config,
            &ordinary_fixture.wallet_name,
            &ordinary_fixture.statechain_id,
        )
        .await?,
        (1, 0, 1)
    );
    let ordinary_mercury_after_acceptance =
        mercury_state_bytes(&ordinary_fixture.statechain_id).await?;
    let ordinary_count_after_acceptance =
        common::lockbox::get_signature_count(&lockbox_client, &ordinary_fixture.statechain_id)
            .await?;
    ordinary_fixture.config.pool.close().await;

    let ordinary_retry = mercuryrustlib::client_config::load().await;
    assert_eq!(
        accepted_state_bytes(
            &ordinary_retry.pool,
            &ordinary_fixture.wallet_name,
            &ordinary_fixture.statechain_id,
        )
        .await?,
        ordinary_accepted_bytes
    );
    assert_eq!(
        mercuryrustlib::sqlite_manager::get_bip448_transfer_msg_raw_optional(
            &ordinary_retry.pool,
            &ordinary_fixture.wallet_name,
            &ordinary_fixture.statechain_id,
            Some(&ordinary_recipient_auth),
        )
        .await?,
        Some((
            ordinary_recipient_auth.clone(),
            ordinary_message_raw.clone()
        ))
    );
    mercuryrustlib::coin_status::update_coins(&ordinary_retry, &ordinary_fixture.wallet_name)
        .await?;
    assert_eq!(
        accepted_state_bytes(
            &ordinary_retry.pool,
            &ordinary_fixture.wallet_name,
            &ordinary_fixture.statechain_id,
        )
        .await?,
        ordinary_accepted_bytes
    );
    assert_eq!(
        bip448_transfer_artifact_counts(
            &ordinary_retry,
            &ordinary_fixture.wallet_name,
            &ordinary_fixture.statechain_id,
        )
        .await?,
        (0, 0, 0),
        "plain update did not reconcile the exact ordinary accepted-prefix row"
    );
    let ordinary_bindings = mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
        &ordinary_retry.pool,
        &ordinary_fixture.wallet_name,
        &ordinary_fixture.statechain_id,
    )
    .await?;
    assert_eq!(ordinary_bindings.len(), 1);
    assert_eq!(
        ordinary_bindings[0].binding_index,
        ordinary_initial_binding.binding_index
    );
    assert_eq!(ordinary_bindings[0].txid, ordinary_initial_binding.txid);
    assert_eq!(ordinary_bindings[0].vout, ordinary_initial_binding.vout);
    assert_eq!(
        ordinary_bindings[0].first_seen_at,
        ordinary_initial_binding.first_seen_at
    );
    assert_eq!(
        ordinary_bindings[0].owner_user_pubkey,
        ordinary_receiver_user.x_only_public_key().0.to_string()
    );
    assert_eq!(ordinary_bindings[0].owner_state_number, 2);
    assert_eq!(
        ordinary_bindings[0].ownership_status,
        Bip448OwnershipStatus::Current
    );
    assert_eq!(
        mercury_state_bytes(&ordinary_fixture.statechain_id).await?,
        ordinary_mercury_after_acceptance,
        "ordinary passive retry performed a second server key update"
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &ordinary_fixture.statechain_id)
            .await?,
        ordinary_count_after_acceptance,
        "ordinary passive retry changed the signature count"
    );

    let close_destination = common::bitcoin_core::getnewaddress()?;
    mercuryrustlib::bip448_withdraw::execute(
        &ordinary_retry,
        &ordinary_fixture.wallet_name,
        &ordinary_fixture.statechain_id,
        &close_destination,
        Some(1.0),
    )
    .await
    .context("no-duplicate canonical preflight remained blocked by an accepted local message")?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bip448_withdrawal_attempts \
             WHERE wallet_name=$1 AND statechain_id=$2 AND binding_index=0",
        )
        .bind(&ordinary_fixture.wallet_name)
        .bind(&ordinary_fixture.statechain_id)
        .fetch_one(&ordinary_retry.pool)
        .await?,
        1
    );
    assert!(
        !mercuryrustlib::sqlite_manager::has_bip448_transfer_msg_for_statechain(
            &ordinary_retry.pool,
            &ordinary_fixture.wallet_name,
            &ordinary_fixture.statechain_id,
        )
        .await?
    );

    println!(
        "BIP448 receiver rescan retry: cancellation_statechain={} late_duplicate={} birth_height={} duplicate_height={} ordinary_statechain={} cancellation_bindings={} ordinary_bindings={}",
        cancellation_fixture.statechain_id,
        late_duplicate.outpoint,
        simulated_receiver_birth,
        duplicate_funding_height,
        ordinary_fixture.statechain_id,
        cancellation_bindings.len(),
        ordinary_bindings.len(),
    );
    ordinary_retry.pool.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_duplicate_transfer_requires_ack_and_receiver_rediscovers() -> Result<()> {
    if run_commit10_child_if_requested().await? {
        return Ok(());
    }

    let _guard = common::test_guard();
    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;
    let lockbox_client = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox_client).await?;

    // Retained-path race: the transfer completes its passive/current-owner
    // preflight, then a real duplicate attempt wins the storage guard. The
    // losing forced transfer must not reach /transfer/sender.
    let race = duplicate_sweep_fixture(&[SMALL_DUPLICATE_AMOUNT_SATS]).await?;
    let race_receiver_name = format!("bip448-transfer-race-r-{}", uuid::Uuid::new_v4());
    let race_receiver =
        mercuryrustlib::wallet::create_wallet(&race_receiver_name, &race.config).await?;
    mercuryrustlib::sqlite_manager::insert_wallet(&race.config.pool, &race_receiver).await?;
    let race_recipient =
        mercuryrustlib::transfer_receiver::new_transfer_address(&race.config, &race_receiver_name)
            .await?;
    let (mut transfer_child, reached, release) = spawn_commit10_barrier_child(
        "bip448_duplicate_transfer_requires_ack_and_receiver_rediscovers",
        "force-transfer",
        &race.wallet_name,
        &race.statechain_id,
        Some(&race_recipient),
        "transfer_preflight_before_intent",
    )?;
    wait_for_commit10_barrier(
        &mut transfer_child,
        &reached,
        "transfer_preflight_before_intent",
    )?;
    let race_destination = common::bitcoin_core::getnewaddress()?;
    let attempt_winner = run_duplicate_sweep_child(
        &race.wallet_name,
        &race.statechain_id,
        race.bindings[1].binding_index,
        &race_destination,
        Some("attempt_prepared"),
        false,
    )?;
    require_child_exit(&attempt_winner, 86, "transfer-versus-attempt winner")?;
    let transfer_loser = release_commit10_barrier(transfer_child, &reached, &release)?;
    assert!(
        !transfer_loser.status.success(),
        "forced transfer won after the competing attempt was durable"
    );
    assert!(String::from_utf8_lossy(&transfer_loser.stderr)
        .to_ascii_lowercase()
        .contains("attempt"));
    assert_eq!(
        mercury_transfer_side_effect_counts(&race.statechain_id).await?,
        (0, 0),
        "losing transfer created a Mercury row or mailbox message"
    );
    assert_eq!(
        bip448_transfer_artifact_counts(&race.config, &race.wallet_name, &race.statechain_id)
            .await?,
        (0, 0, 0),
        "losing transfer created a local message, intent, or pending journal"
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &race.statechain_id).await?,
        1,
        "losing transfer consumed a lockbox signature"
    );

    let fixture =
        duplicate_sweep_fixture(&[DUPLICATE_AMOUNT_SATS, SMALL_DUPLICATE_AMOUNT_SATS]).await?;
    assert_ne!(
        fixture.bindings[1].value_sats,
        fixture.bindings[2].value_sats
    );
    common::bitcoin_core::mine_block()?;
    let sender_record = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?;
    let sender_wallet_before =
        mercuryrustlib::sqlite_manager::get_wallet(&fixture.config.pool, &fixture.wallet_name)
            .await?;
    let sender_coin_before = sender_wallet_before
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some(fixture.statechain_id.as_str()))
        .context("cross-wallet sender Coin is missing")?;
    let sender_user_xonly = PublicKey::from_str(&sender_coin_before.user_pubkey)?
        .x_only_public_key()
        .0
        .to_string();

    // Create the receiver only after all three funding outputs are confirmed;
    // its ordinary birth height therefore cannot account for their discovery.
    let receiver_name = format!("bip448-duplicate-receiver-{}", uuid::Uuid::new_v4());
    let receiver_wallet =
        mercuryrustlib::wallet::create_wallet(&receiver_name, &fixture.config).await?;
    let receiver_birth_height = receiver_wallet.blockheight;
    assert!(fixture.bindings.iter().all(|binding| {
        binding
            .funding_height
            .is_some_and(|height| height < receiver_birth_height)
    }));
    mercuryrustlib::sqlite_manager::insert_wallet(&fixture.config.pool, &receiver_wallet).await?;
    let recipient =
        mercuryrustlib::transfer_receiver::new_transfer_address(&fixture.config, &receiver_name)
            .await?;
    let (_, receiver_user, receiver_auth) = mercurylib::decode_transfer_address(&recipient)?;

    let accepted_before = accepted_state_bytes(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?;
    let sender_status_before = sender_coin_before.status.clone();
    let lockbox_before =
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?;
    assert_eq!(lockbox_before, 1);
    assert_eq!(
        mercury_transfer_side_effect_counts(&fixture.statechain_id).await?,
        (0, 0)
    );

    let warning = mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender(
        &fixture.config,
        &recipient,
        &fixture.wallet_name,
        &fixture.statechain_id,
        None,
    )
    .await
    .expect_err("unacknowledged duplicate transfer unexpectedly succeeded");
    let warning_text = warning.to_string();
    assert!(warning_text.contains("--force-send-with-duplicates"));
    assert!(warning_text.contains("not part of the verified canonical statechain amount"));
    assert!(warning_text.contains("server-dependent"));
    assert_eq!(
        accepted_state_bytes(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?,
        accepted_before,
        "warning path changed accepted record/history"
    );
    assert_eq!(
        bip448_transfer_artifact_counts(
            &fixture.config,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?,
        (0, 0, 0),
        "warning path created client transfer artifacts"
    );
    assert_eq!(
        mercury_transfer_side_effect_counts(&fixture.statechain_id).await?,
        (0, 0)
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
        lockbox_before
    );
    assert_eq!(
        mercuryrustlib::sqlite_manager::get_wallet(&fixture.config.pool, &fixture.wallet_name)
            .await?
            .coins
            .iter()
            .find(|coin| coin.statechain_id.as_deref() == Some(fixture.statechain_id.as_str()))
            .context("warning path lost sender Coin")?
            .status,
        sender_status_before,
        "warning path changed sender wallet status"
    );

    mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender_with_options(
        &fixture.config,
        &recipient,
        &fixture.wallet_name,
        &fixture.statechain_id,
        None,
        mercuryrustlib::bip448_transfer_sender::Bip448TransferOptions {
            acknowledge_cooperative_duplicates: true,
            intent: Bip448TransferIntentKind::UserTransfer,
        },
    )
    .await?;
    assert_eq!(
        mercury_transfer_side_effect_counts(&fixture.statechain_id).await?,
        (1, 1)
    );
    assert_eq!(
        bip448_transfer_artifact_counts(
            &fixture.config,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?,
        (1, 0, 1)
    );
    let (_, message_raw) = mercuryrustlib::sqlite_manager::get_bip448_transfer_msg_raw_optional(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        Some(&receiver_auth.to_string()),
    )
    .await?
    .context("forced transfer did not retain its exact outgoing message")?;
    let message = require_v2_message_without_duplicate_field(&message_raw)?;
    assert_eq!(message.amount_sats, sender_record.amount_sats);
    assert_eq!(message.funding_outpoint, sender_record.funding_outpoint);
    assert_eq!(
        message.funding_outpoint.txid, fixture.bindings[0].txid,
        "transfer message selected a duplicate outpoint"
    );
    assert_eq!(message.funding_outpoint.vout, fixture.bindings[0].vout);
    assert_eq!(message.receiver_user_public_key, receiver_user.to_string());

    let sender_after_send =
        mercuryrustlib::sqlite_manager::get_wallet(&fixture.config.pool, &fixture.wallet_name)
            .await?;
    assert_eq!(
        sender_after_send
            .coins
            .iter()
            .find(|coin| coin.statechain_id.as_deref() == Some(fixture.statechain_id.as_str()))
            .context("forced transfer lost sender Coin")?
            .status,
        CoinStatus::IN_TRANSFER
    );
    assert!(
        mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?
        .iter()
        .all(
            |binding| binding.ownership_status == Bip448OwnershipStatus::Current
                && binding.owner_user_pubkey == sender_user_xonly
        ),
        "sender bindings rotated before positive server rotation"
    );

    let received =
        mercuryrustlib::transfer_receiver::execute(&fixture.config, &receiver_name).await?;
    assert_eq!(
        received.received_statechain_ids,
        vec![fixture.statechain_id.clone()]
    );

    // There is deliberately no sender notification or sweep guarantee. Until
    // the sender performs its own positive-rotation sync, its local Coin and
    // bindings remain IN_TRANSFER/Current even though the receiver accepted.
    assert_eq!(
        mercuryrustlib::sqlite_manager::get_wallet(&fixture.config.pool, &fixture.wallet_name)
            .await?
            .coins
            .iter()
            .find(|coin| coin.statechain_id.as_deref() == Some(fixture.statechain_id.as_str()))
            .context("post-acceptance sender Coin is missing")?
            .status,
        CoinStatus::IN_TRANSFER
    );
    assert!(
        mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?
        .iter()
        .all(|binding| binding.ownership_status == Bip448OwnershipStatus::Current)
    );

    let receiver_bindings = mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
        &fixture.config.pool,
        &receiver_name,
        &fixture.statechain_id,
    )
    .await?;
    assert_eq!(receiver_bindings.len(), 3);
    let expected_outpoints = fixture
        .bindings
        .iter()
        .map(|binding| (binding.txid.clone(), binding.vout, binding.value_sats))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        receiver_bindings
            .iter()
            .map(|binding| (binding.txid.clone(), binding.vout, binding.value_sats))
            .collect::<BTreeSet<_>>(),
        expected_outpoints,
        "height-0 receiver rescan did not rediscover the exact funding set"
    );
    let receiver_owner_xonly = receiver_user.x_only_public_key().0.to_string();
    assert!(receiver_bindings.iter().all(|binding| {
        binding.ownership_status == Bip448OwnershipStatus::Current
            && binding.owner_user_pubkey == receiver_owner_xonly
            && binding.owner_state_number == 2
    }));
    let receiver_wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&fixture.config.pool, &receiver_name).await?;
    let receiver_coin = receiver_wallet
        .coins
        .iter()
        .find(|coin| {
            coin.statechain_id.as_deref() == Some(fixture.statechain_id.as_str())
                && coin.user_pubkey == receiver_user.to_string()
        })
        .context("receiver current owner Coin is missing")?;
    let listed = mercuryrustlib::coin_status::statecoin_list_entry_json(
        &receiver_name,
        receiver_coin,
        &receiver_bindings,
        &[],
    )?;
    let listed_duplicates = listed["coin.duplicates"]
        .as_array()
        .context("receiver duplicate list is not an array")?;
    assert_eq!(listed_duplicates.len(), 2);
    assert!(listed_duplicates.iter().all(|duplicate| {
        duplicate["cooperative_only"].as_bool() == Some(true)
            && duplicate["server_dependent"].as_bool() == Some(true)
    }));

    mercuryrustlib::coin_status::update_coins(&fixture.config, &fixture.wallet_name).await?;
    assert!(
        mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?
        .iter()
        .all(|binding| binding.ownership_status == Bip448OwnershipStatus::Previous),
        "positive rotation did not retire every sender binding"
    );

    // The receiver independently chooses its locally assigned indices and
    // timing. Sweep in reverse local-index order to avoid implying that sender
    // indices or notifications coordinate the action.
    let mut receiver_duplicate_indices = receiver_bindings
        .iter()
        .filter(|binding| binding.role == Bip448BindingRole::Duplicate)
        .map(|binding| binding.binding_index)
        .collect::<Vec<_>>();
    receiver_duplicate_indices.sort_unstable_by(|left, right| right.cmp(left));
    let destination = common::bitcoin_core::getnewaddress()?;
    for duplicate_index in &receiver_duplicate_indices {
        mercuryrustlib::bip448_withdraw::execute_duplicate_sweep(
            &fixture.config,
            &receiver_name,
            &fixture.statechain_id,
            *duplicate_index,
            &destination,
            Some(1.0),
        )
        .await?;
        assert!(
            mercuryrustlib::utils::get_statechain_info(&fixture.statechain_id, &fixture.config)
                .await?
                .is_some(),
            "duplicate sweep deleted the canonical statechain"
        );
    }
    mercuryrustlib::bip448_withdraw::execute(
        &fixture.config,
        &receiver_name,
        &fixture.statechain_id,
        &destination,
        Some(1.0),
    )
    .await?;
    assert!(
        mercuryrustlib::utils::get_statechain_info(&fixture.statechain_id, &fixture.config)
            .await?
            .is_none(),
        "receiver did not close canonical after independently sweeping duplicates"
    );
    println!(
        "BIP448 forced cross-wallet transfer: statechain={} receiver_birth={} receiver_indices={:?}; sender received no notification or sweep guarantee",
        fixture.statechain_id, receiver_birth_height, receiver_duplicate_indices
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_duplicate_same_wallet_cancel_reassigns_current_owner() -> Result<()> {
    if run_commit10_child_if_requested().await? {
        return Ok(());
    }

    let _guard = common::test_guard();
    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;
    let lockbox_client = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox_client).await?;

    // Cancellation Coin creation and its intent insertion are one guarded
    // write. Let an attempt win after cancellation preflight and prove that the
    // losing cancellation appended neither a Coin nor any remote/local row.
    let race = duplicate_sweep_fixture(&[SMALL_DUPLICATE_AMOUNT_SATS]).await?;
    let race_wallet_before =
        mercuryrustlib::sqlite_manager::get_wallet(&race.config.pool, &race.wallet_name).await?;
    let (mut cancellation_child, reached, release) = spawn_commit10_barrier_child(
        "bip448_duplicate_same_wallet_cancel_reassigns_current_owner",
        "cancel",
        &race.wallet_name,
        &race.statechain_id,
        None,
        "cancellation_preflight_before_coin_intent",
    )?;
    wait_for_commit10_barrier(
        &mut cancellation_child,
        &reached,
        "cancellation_preflight_before_coin_intent",
    )?;
    let race_destination = common::bitcoin_core::getnewaddress()?;
    let attempt_winner = run_duplicate_sweep_child(
        &race.wallet_name,
        &race.statechain_id,
        race.bindings[1].binding_index,
        &race_destination,
        Some("attempt_prepared"),
        false,
    )?;
    require_child_exit(&attempt_winner, 86, "cancellation-versus-attempt winner")?;
    let cancellation_loser = release_commit10_barrier(cancellation_child, &reached, &release)?;
    assert!(
        !cancellation_loser.status.success(),
        "cancellation won after the competing attempt was durable"
    );
    assert!(String::from_utf8_lossy(&cancellation_loser.stderr)
        .to_ascii_lowercase()
        .contains("attempt"));
    assert_eq!(
        mercuryrustlib::sqlite_manager::get_wallet(&race.config.pool, &race.wallet_name)
            .await?
            .coins
            .len(),
        race_wallet_before.coins.len(),
        "losing cancellation appended its generated Coin"
    );
    assert_eq!(
        bip448_transfer_artifact_counts(&race.config, &race.wallet_name, &race.statechain_id)
            .await?,
        (0, 0, 0)
    );
    assert_eq!(
        mercury_transfer_side_effect_counts(&race.statechain_id).await?,
        (0, 0)
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &race.statechain_id).await?,
        1
    );

    // Force bypasses only the duplicate warning. Durable exit-only attempts
    // still block both user transfer and cancellation before any side effect.
    for (checkpoint, expected_phase) in [
        ("sign_second_armed", Bip448WithdrawalPhase::SecondArmed),
        ("signed_tx_persisted", Bip448WithdrawalPhase::Signed),
    ] {
        let blocked = duplicate_sweep_fixture(&[SMALL_DUPLICATE_AMOUNT_SATS]).await?;
        let destination = common::bitcoin_core::getnewaddress()?;
        let attempt_child = run_duplicate_sweep_child(
            &blocked.wallet_name,
            &blocked.statechain_id,
            blocked.bindings[1].binding_index,
            &destination,
            Some(checkpoint),
            false,
        )?;
        require_child_exit(&attempt_child, 86, checkpoint)?;
        let attempt = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
            &blocked.config.pool,
            &blocked.wallet_name,
            &blocked.statechain_id,
            blocked.bindings[1].binding_index,
        )
        .await?
        .context("exit-only blocker attempt is missing")?;
        assert_eq!(attempt.phase, expected_phase);

        let recipient_wallet_name = format!("bip448-exit-only-r-{}", uuid::Uuid::new_v4());
        let recipient_wallet =
            mercuryrustlib::wallet::create_wallet(&recipient_wallet_name, &blocked.config).await?;
        mercuryrustlib::sqlite_manager::insert_wallet(&blocked.config.pool, &recipient_wallet)
            .await?;
        let recipient = mercuryrustlib::transfer_receiver::new_transfer_address(
            &blocked.config,
            &recipient_wallet_name,
        )
        .await?;
        let wallet_before =
            mercuryrustlib::sqlite_manager::get_wallet(&blocked.config.pool, &blocked.wallet_name)
                .await?;
        let wallet_before = serde_json::to_string(&wallet_before)?;
        let accepted_before = accepted_state_bytes(
            &blocked.config.pool,
            &blocked.wallet_name,
            &blocked.statechain_id,
        )
        .await?;
        let mercury_before = mercury_state_bytes(&blocked.statechain_id).await?;
        let count_before =
            common::lockbox::get_signature_count(&lockbox_client, &blocked.statechain_id).await?;

        let transfer_error =
            mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender_with_options(
                &blocked.config,
                &recipient,
                &blocked.wallet_name,
                &blocked.statechain_id,
                None,
                mercuryrustlib::bip448_transfer_sender::Bip448TransferOptions {
                    acknowledge_cooperative_duplicates: true,
                    intent: Bip448TransferIntentKind::UserTransfer,
                },
            )
            .await
            .expect_err("force bypassed an exit-only withdrawal attempt");
        assert!(
            transfer_error.to_string().contains("exit-only"),
            "{checkpoint} transfer gate returned: {transfer_error}"
        );
        let cancellation_error = mercuryrustlib::bip448_transfer_sender::cancel_bip448_transfer(
            &blocked.config,
            &blocked.wallet_name,
            &blocked.statechain_id,
        )
        .await
        .expect_err("cancellation bypassed an exit-only withdrawal attempt");
        assert!(
            cancellation_error.to_string().contains("exit-only"),
            "{checkpoint} cancellation gate returned: {cancellation_error}"
        );
        assert_eq!(
            serde_json::to_string(
                &mercuryrustlib::sqlite_manager::get_wallet(
                    &blocked.config.pool,
                    &blocked.wallet_name,
                )
                .await?
            )?,
            wallet_before,
            "exit-only rejection changed or appended a wallet Coin at {checkpoint}"
        );
        assert_eq!(
            accepted_state_bytes(
                &blocked.config.pool,
                &blocked.wallet_name,
                &blocked.statechain_id,
            )
            .await?,
            accepted_before
        );
        assert_eq!(
            bip448_transfer_artifact_counts(
                &blocked.config,
                &blocked.wallet_name,
                &blocked.statechain_id,
            )
            .await?,
            (0, 0, 0)
        );
        assert_eq!(
            mercury_state_bytes(&blocked.statechain_id).await?,
            mercury_before
        );
        assert_eq!(
            common::lockbox::get_signature_count(&lockbox_client, &blocked.statechain_id).await?,
            count_before
        );
    }

    let fixture =
        duplicate_sweep_fixture(&[DUPLICATE_AMOUNT_SATS, SMALL_DUPLICATE_AMOUNT_SATS]).await?;
    let initial_bindings = fixture.bindings.clone();
    let initial_wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&fixture.config.pool, &fixture.wallet_name)
            .await?;
    let initial_coin = initial_wallet
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some(fixture.statechain_id.as_str()))
        .context("same-wallet initial owner Coin is missing")?;
    let old_user = initial_coin.user_pubkey.clone();
    let old_server = initial_coin
        .server_pubkey
        .clone()
        .context("same-wallet initial owner server key is missing")?;
    let old_owner_xonly = PublicKey::from_str(&old_user)?
        .x_only_public_key()
        .0
        .to_string();

    let first_recipient = mercuryrustlib::transfer_receiver::new_transfer_address(
        &fixture.config,
        &fixture.wallet_name,
    )
    .await?;
    mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender_with_options(
        &fixture.config,
        &first_recipient,
        &fixture.wallet_name,
        &fixture.statechain_id,
        None,
        mercuryrustlib::bip448_transfer_sender::Bip448TransferOptions {
            acknowledge_cooperative_duplicates: true,
            intent: Bip448TransferIntentKind::UserTransfer,
        },
    )
    .await?;
    assert!(
        mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?
        .iter()
        .all(
            |binding| binding.ownership_status == Bip448OwnershipStatus::Current
                && binding.owner_user_pubkey == old_owner_xonly
        )
    );
    let wallet_after_forced_send =
        mercuryrustlib::sqlite_manager::get_wallet(&fixture.config.pool, &fixture.wallet_name)
            .await?;
    assert_eq!(
        wallet_after_forced_send
            .coins
            .iter()
            .find(|coin| coin.user_pubkey == old_user)
            .context("forced same-wallet send lost old Coin")?
            .status,
        CoinStatus::IN_TRANSFER
    );

    let coin_count_before_cancellation = wallet_after_forced_send.coins.len();
    mercuryrustlib::transfer_receiver::inject_bip448_post_acceptance_sync_failures_for_test(1);
    let first_cancellation_error = mercuryrustlib::bip448_transfer_sender::cancel_bip448_transfer(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await
    .expect_err("injected post-acceptance cancellation rescan unexpectedly succeeded");
    let typed = first_cancellation_error
        .downcast_ref::<mercuryrustlib::transfer_receiver::Bip448PostAcceptanceSyncError>()
        .context("cancellation did not preserve the typed accepted/rescan-pending error")?;
    assert_eq!(
        typed.accepted_statechain_ids(),
        &[fixture.statechain_id.clone()]
    );
    assert!(first_cancellation_error
        .to_string()
        .contains("cancellation accepted; duplicate rescan pending"));

    let receiver_accepted = mercuryrustlib::sqlite_manager::get_active_bip448_transfer_intent(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?
    .context("accepted cancellation intent is missing")?;
    assert_eq!(
        receiver_accepted.intent_kind,
        Bip448TransferIntentKind::Cancellation
    );
    assert!(receiver_accepted.acknowledge_cooperative_duplicates);
    assert_eq!(receiver_accepted.phase.as_str(), "ReceiverAccepted");
    let generated_user = receiver_accepted
        .generated_coin_user_pubkey
        .clone()
        .context("cancellation generated user key is missing")?;
    let generated_auth = receiver_accepted
        .generated_coin_auth_pubkey
        .clone()
        .context("cancellation generated auth key is missing")?;
    let generated_address = receiver_accepted
        .generated_coin_address
        .clone()
        .context("cancellation generated address is missing")?;
    let accepted_wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&fixture.config.pool, &fixture.wallet_name)
            .await?;
    assert_eq!(
        accepted_wallet.coins.len(),
        coin_count_before_cancellation + 1
    );
    assert_eq!(
        accepted_wallet
            .coins
            .iter()
            .filter(|coin| {
                coin.user_pubkey == generated_user
                    && coin.auth_pubkey == generated_auth
                    && coin.address == generated_address
                    && coin.statechain_id.as_deref() == Some(fixture.statechain_id.as_str())
            })
            .count(),
        1,
        "accepted cancellation did not retain exactly one generated Coin"
    );
    let accepted_bytes = accepted_state_bytes(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?;
    assert_eq!(accepted_bytes.1.len(), 3);
    let accepted_record = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?;
    assert_eq!(accepted_record.latest_state_number, 3);
    let (retained_recipient, retained_message) =
        mercuryrustlib::sqlite_manager::get_bip448_transfer_msg_raw_optional(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
            Some(&generated_auth),
        )
        .await?
        .context("ReceiverAccepted cancellation lost its exact outgoing message")?;
    assert_eq!(retained_recipient, generated_auth);
    require_v2_message_without_duplicate_field(&retained_message)?;
    assert_eq!(
        bip448_transfer_artifact_counts(
            &fixture.config,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?,
        (1, 1, 1)
    );
    let mercury_after_acceptance = mercury_state_bytes(&fixture.statechain_id).await?;
    let count_after_acceptance =
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?;

    let blocked_destination = common::bitcoin_core::getnewaddress()?;
    assert!(
        mercuryrustlib::bip448_withdraw::execute(
            &fixture.config,
            &fixture.wallet_name,
            &fixture.statechain_id,
            &blocked_destination,
            Some(1.0),
        )
        .await
        .is_err(),
        "retained cancellation message/intent did not block canonical preflight"
    );
    assert!(
        mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
            0,
        )
        .await?
        .is_none()
    );
    assert_eq!(
        mercuryrustlib::sqlite_manager::get_bip448_transfer_msg_raw_optional(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
            Some(&generated_auth),
        )
        .await?,
        Some((generated_auth.clone(), retained_message.clone())),
        "blocked preflight changed retained cancellation message bytes"
    );

    let retry_state = mercuryrustlib::bip448_transfer_sender::cancel_bip448_transfer(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?;
    assert_eq!(retry_state, 3);
    assert_eq!(
        bip448_transfer_artifact_counts(
            &fixture.config,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?,
        (0, 0, 0),
        "passive cancellation retry retained message/intent/pending artifacts"
    );
    assert_eq!(
        accepted_state_bytes(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?,
        accepted_bytes,
        "passive cancellation retry inserted a second history state"
    );
    assert_eq!(
        mercury_state_bytes(&fixture.statechain_id).await?,
        mercury_after_acceptance
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
        count_after_acceptance,
        "passive cancellation retry consumed another signature"
    );
    let final_wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&fixture.config.pool, &fixture.wallet_name)
            .await?;
    assert_eq!(final_wallet.coins.len(), coin_count_before_cancellation + 1);
    let generated_coin_index = final_wallet
        .coins
        .iter()
        .position(|coin| {
            coin.user_pubkey == generated_user
                && coin.auth_pubkey == generated_auth
                && coin.address == generated_address
                && coin.statechain_id.as_deref() == Some(fixture.statechain_id.as_str())
        })
        .context("passive retry lost the accepted generated Coin")?;
    assert_eq!(
        final_wallet
            .coins
            .iter()
            .filter(|coin| {
                coin.user_pubkey == generated_user
                    && coin.auth_pubkey == generated_auth
                    && coin.address == generated_address
            })
            .count(),
        1,
        "passive retry appended a second generated Coin"
    );
    let current_owner = mercuryrustlib::bip448_owner::get_current_bip448_owner(
        &fixture.config,
        &final_wallet,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?;
    assert_eq!(current_owner.coin_index, generated_coin_index);
    assert_eq!(
        final_wallet.coins[generated_coin_index].user_pubkey,
        generated_user
    );
    assert_ne!(
        final_wallet.coins[generated_coin_index]
            .server_pubkey
            .as_deref(),
        Some(old_server.as_str())
    );

    let reassigned = mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?;
    assert_eq!(reassigned.len(), initial_bindings.len());
    let immutable_binding_set = |bindings: &[Bip448FundingBinding]| {
        bindings
            .iter()
            .map(|binding| {
                (
                    binding.binding_index,
                    binding.txid.clone(),
                    binding.vout,
                    binding.value_sats,
                )
            })
            .collect::<BTreeSet<_>>()
    };
    assert_eq!(
        immutable_binding_set(&reassigned),
        immutable_binding_set(&initial_bindings),
        "cancellation changed stable binding indices/outpoints/amounts"
    );
    let generated_owner_xonly = PublicKey::from_str(&generated_user)?
        .x_only_public_key()
        .0
        .to_string();
    assert!(reassigned.iter().all(|binding| {
        binding.owner_user_pubkey == generated_owner_xonly
            && binding.owner_state_number == 3
            && binding.ownership_status == Bip448OwnershipStatus::Current
    }));
    assert!(!reassigned.iter().any(|binding| {
        binding.owner_user_pubkey == old_owner_xonly
            && binding.ownership_status == Bip448OwnershipStatus::Current
    }));

    // Separately prove ordinary same-wallet UserTransfer cleanup: an exact
    // accepted outgoing row survives a failed post-acceptance sync, blocks
    // canonical preflight byte-for-byte, and is deleted only by successful
    // passive sync. With no duplicates, canonical preflight then succeeds.
    let ordinary = duplicate_sweep_fixture(&[]).await?;
    let ordinary_recipient = mercuryrustlib::transfer_receiver::new_transfer_address(
        &ordinary.config,
        &ordinary.wallet_name,
    )
    .await?;
    let (_, _, ordinary_auth) = mercurylib::decode_transfer_address(&ordinary_recipient)?;
    mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender(
        &ordinary.config,
        &ordinary_recipient,
        &ordinary.wallet_name,
        &ordinary.statechain_id,
        None,
    )
    .await?;
    let (_, ordinary_message) =
        mercuryrustlib::sqlite_manager::get_bip448_transfer_msg_raw_optional(
            &ordinary.config.pool,
            &ordinary.wallet_name,
            &ordinary.statechain_id,
            Some(&ordinary_auth.to_string()),
        )
        .await?
        .context("ordinary same-wallet message is missing")?;
    mercuryrustlib::transfer_receiver::inject_bip448_post_acceptance_sync_failures_for_test(1);
    let ordinary_error =
        match mercuryrustlib::transfer_receiver::execute(&ordinary.config, &ordinary.wallet_name)
            .await
        {
            Ok(_) => anyhow::bail!("ordinary injected post-acceptance sync unexpectedly succeeded"),
            Err(error) => error,
        };
    assert!(ordinary_error
        .downcast_ref::<mercuryrustlib::transfer_receiver::Bip448PostAcceptanceSyncError>()
        .is_some());
    assert_eq!(
        mercuryrustlib::sqlite_manager::get_bip448_transfer_msg_raw_optional(
            &ordinary.config.pool,
            &ordinary.wallet_name,
            &ordinary.statechain_id,
            Some(&ordinary_auth.to_string()),
        )
        .await?,
        Some((ordinary_auth.to_string(), ordinary_message.clone()))
    );
    let ordinary_destination = common::bitcoin_core::getnewaddress()?;
    assert!(mercuryrustlib::bip448_withdraw::execute(
        &ordinary.config,
        &ordinary.wallet_name,
        &ordinary.statechain_id,
        &ordinary_destination,
        Some(1.0),
    )
    .await
    .is_err());
    assert!(
        mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
            &ordinary.config.pool,
            &ordinary.wallet_name,
            &ordinary.statechain_id,
            0,
        )
        .await?
        .is_none()
    );
    assert_eq!(
        mercuryrustlib::sqlite_manager::get_bip448_transfer_msg_raw_optional(
            &ordinary.config.pool,
            &ordinary.wallet_name,
            &ordinary.statechain_id,
            Some(&ordinary_auth.to_string()),
        )
        .await?,
        Some((ordinary_auth.to_string(), ordinary_message))
    );
    mercuryrustlib::coin_status::update_coins(&ordinary.config, &ordinary.wallet_name).await?;
    assert_eq!(
        bip448_transfer_artifact_counts(
            &ordinary.config,
            &ordinary.wallet_name,
            &ordinary.statechain_id,
        )
        .await?,
        (0, 0, 0)
    );
    mercuryrustlib::bip448_withdraw::execute(
        &ordinary.config,
        &ordinary.wallet_name,
        &ordinary.statechain_id,
        &ordinary_destination,
        Some(1.0),
    )
    .await
    .context("ordinary accepted message still blocked no-duplicate canonical preflight")?;

    println!(
        "BIP448 forced same-wallet cancellation: statechain={} old_owner={} new_owner={} stable_bindings={}",
        fixture.statechain_id,
        old_owner_xonly,
        generated_owner_xonly,
        reassigned.len()
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_duplicate_dust_remains_visible_and_blocks_close() -> Result<()> {
    let _guard = common::test_guard();
    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;
    let lockbox_client = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox_client).await?;

    let fixture = duplicate_sweep_fixture(&[DUST_DUPLICATE_AMOUNT_SATS]).await?;
    let dust = fixture.bindings[1].clone();
    let destination = common::bitcoin_core::getnewaddress()?;
    let destination_script = Address::from_str(&destination)?
        .require_network(fixture.config.network)?
        .script_pubkey();
    let output_value = dust.value_sats.checked_sub(112).context("dust fee")?;
    assert!(output_value < destination_script.dust_value().to_sat());
    let before_count =
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?;
    let wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&fixture.config.pool, &fixture.wallet_name)
            .await?;
    let entry = mercuryrustlib::coin_status::statecoin_list_entry_json(
        &fixture.wallet_name,
        wallet
            .coins
            .iter()
            .find(|coin| coin.statechain_id.as_deref() == Some(&fixture.statechain_id))
            .context("dust fixture Coin missing")?,
        &fixture.bindings,
        &[],
    )?;
    assert!(entry["coin.duplicates"]
        .as_array()
        .context("duplicate list is not an array")?
        .iter()
        .any(|duplicate| {
            duplicate["duplicate_index"].as_u64() == Some(u64::from(dust.binding_index))
                && duplicate["amount_sats"].as_u64() == Some(dust.value_sats)
        }));

    let error = mercuryrustlib::bip448_withdraw::execute_duplicate_sweep(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        dust.binding_index,
        &destination,
        Some(1.0),
    )
    .await
    .unwrap_err();
    assert!(
        error.to_string().contains("TransactionReconstructionError")
            || error.to_string().contains("dust")
    );
    assert!(
        mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
            dust.binding_index,
        )
        .await?
        .is_none()
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
        before_count
    );
    assert!(
        mercuryrustlib::bip448_withdraw::execute(
            &fixture.config,
            &fixture.wallet_name,
            &fixture.statechain_id,
            &destination,
            Some(1.0),
        )
        .await
        .is_err(),
        "canonical close ignored the visible dust duplicate"
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
        before_count
    );
    assert_eq!(
        mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?
        .into_iter()
        .find(|binding| binding.binding_index == dust.binding_index)
        .context("dust duplicate disappeared")?
        .value_sats,
        dust.value_sats
    );
    Ok(())
}
