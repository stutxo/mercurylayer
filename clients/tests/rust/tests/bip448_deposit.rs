mod common;

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    process::{Command, Output},
    str::FromStr,
};

use anyhow::{anyhow, Context, Result};
use bitcoin::{
    blockdata::opcodes::all::OP_CLTV, consensus::encode, script::Builder, OutPoint, ScriptBuf,
    Transaction, TxOut, Txid,
};
use common::bip448_regtest::{
    fund_address_output, fund_p2a_fee_input, FEE_INPUT_AMOUNT_SATS, FUNDING_AMOUNT_SATS,
};
use mercurylib::bip448_statechain::{
    package::{
        build_anchor_cpfp_package, build_latest_state_recovery_package, Bip448CpfpFeeInput,
        Bip448RecoveryPackage,
    },
    storage::{Bip448RecoveryTemplateRole, Bip448StatechainRecord},
    transaction::pay_to_anchor_script,
};
use mercuryrustlib::{client_config::ClientConfig, CoinStatus, Wallet};
use serde_json::Value;
use sqlx::{postgres::PgPoolOptions, Row};

const PACKAGE_FEERATE_SAT_PER_VBYTE: f64 = 2.0;
const FEE_INPUT_COUNT: usize = 8;
const RESTART_CHECKPOINT_EXIT_CODE: i32 = 86;

#[tokio::test]
#[ignore = "internal child entry point for the BIP448 process-restart test"]
async fn bip448_client_restart_child() -> Result<()> {
    if std::env::var("ML_BIP448_RESTART_CHILD").as_deref() != Ok("1") {
        return Ok(());
    }

    let wallet_name = std::env::var("ML_BIP448_RESTART_WALLET")?;
    std::env::set_var("ML_NETWORK", "regtest");
    let client_config = mercuryrustlib::client_config::load().await;
    if let Ok(statechain_id) = std::env::var("ML_BIP448_RECOVERY_STATECHAIN") {
        let fee_input = mercuryrustlib::bip448_recovery::parse_keyless_p2a_fee_input(
            &std::env::var("ML_BIP448_RECOVERY_FEE_INPUT")?,
        )?;
        let change_address = std::env::var("ML_BIP448_RECOVERY_CHANGE_ADDRESS")?;
        let result =
            mercuryrustlib::bip448_recovery::submit_latest_state_recovery_package(
                &client_config,
                &wallet_name,
                &statechain_id,
                Bip448RecoveryTemplateRole::FundingUpdate,
                &[fee_input],
                &change_address,
                Some(PACKAGE_FEERATE_SAT_PER_VBYTE),
            )
            .await
            .map(|_| ());
        client_config.pool.close().await;
        return result;
    }
    let result = mercuryrustlib::coin_status::update_coins(&client_config, &wallet_name).await;
    client_config.pool.close().await;
    result
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_deposit_survives_client_process_restarts() -> Result<()> {
    let _guard = common::test_guard();

    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;
    let lockbox_client = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox_client).await?;

    let initial_config = common::prepare_test_env().await?;
    initial_config.pool.close().await;
    let boundaries = [
        ("pending_persisted", false, false, 0),
        ("server_nonce_persisted", true, false, 0),
        ("final_signature_completed", true, false, 1),
        ("accepted_persisted", true, true, 1),
    ];

    for (index, (checkpoint, expect_server_nonce, expect_accepted, expected_count)) in
        boundaries.into_iter().enumerate()
    {
        let client_config = mercuryrustlib::client_config::load().await;
        let wallet_name = format!("bip448-restart-{index}-{}", uuid::Uuid::new_v4());
        let wallet = mercuryrustlib::wallet::create_wallet(&wallet_name, &client_config).await?;
        mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, &wallet).await?;
        let deposit = fund_confirmed_bip448_deposit(&client_config, &wallet).await?;
        client_config.pool.close().await;

        let interrupted = run_restart_child(&wallet_name, Some(checkpoint))?;
        assert_child_status(&interrupted, Some(RESTART_CHECKPOINT_EXIT_CODE), checkpoint)?;

        let interrupted_config = mercuryrustlib::client_config::load().await;
        let pending = mercuryrustlib::sqlite_manager::get_bip448_pending_deposit_signing(
            &interrupted_config.pool,
            &wallet_name,
            &deposit.statechain_id,
        )
        .await?
        .context("restart checkpoint did not leave a pending signing journal")?;
        assert_eq!(pending.server_public_nonce.is_some(), expect_server_nonce);
        let interrupted_accepted = mercuryrustlib::sqlite_manager::get_bip448_statechain_optional(
            &interrupted_config.pool,
            &wallet_name,
            &deposit.statechain_id,
        )
        .await?;
        assert_eq!(interrupted_accepted.is_some(), expect_accepted);
        if let Some(record) = &interrupted_accepted {
            assert_pending_matches_record(&pending, record);
        }
        assert_eq!(
            common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
            expected_count
        );
        interrupted_config.pool.close().await;

        let resumed = run_restart_child(&wallet_name, None)?;
        assert_child_status(&resumed, Some(0), &format!("resume after {checkpoint}"))?;

        let recovered_config = mercuryrustlib::client_config::load().await;
        assert!(
            mercuryrustlib::sqlite_manager::get_bip448_pending_deposit_signing(
                &recovered_config.pool,
                &wallet_name,
                &deposit.statechain_id,
            )
            .await?
            .is_none(),
            "resume after {checkpoint} did not clean up the pending journal"
        );
        let record = mercuryrustlib::sqlite_manager::get_bip448_statechain(
            &recovered_config.pool,
            &wallet_name,
            &deposit.statechain_id,
        )
        .await?;
        assert_pending_matches_record(&pending, &record);
        if let Some(interrupted_record) = interrupted_accepted {
            assert_eq!(record, interrupted_record);
        }

        let recovered_wallet =
            mercuryrustlib::sqlite_manager::get_wallet(&recovered_config.pool, &wallet_name)
                .await?;
        let recovered_coin = recovered_wallet
            .coins
            .iter()
            .find(|coin| coin.statechain_id.as_deref() == Some(&deposit.statechain_id))
            .context("resumed wallet does not contain the BIP448 deposit coin")?;
        assert_eq!(
            recovered_coin.public_nonce.as_deref(),
            Some(
                record
                    .latest_state
                    .signing_metadata
                    .client_public_nonce
                    .as_str()
            )
        );
        assert_eq!(
            recovered_coin.server_public_nonce.as_deref(),
            Some(
                record
                    .latest_state
                    .signing_metadata
                    .server_public_nonce
                    .as_str()
            )
        );
        assert_eq!(
            recovered_coin.blinding_factor.as_deref(),
            Some(
                record
                    .latest_state
                    .signing_metadata
                    .blinding_factor
                    .as_str()
            )
        );
        let update_tx = tx_from_hex(&record.latest_state.update_tx)?;
        let settlement_tx = tx_from_hex(&record.latest_state.settlement_tx)?;
        assert_eq!(update_tx.lock_time, settlement_tx.lock_time);
        assert_eq!(
            update_tx.lock_time.to_consensus_u32(),
            pending.state_locktime
        );
        assert_eq!(
            common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
            1,
            "resume after {checkpoint} consumed another blind signature"
        );
        recovered_config.pool.close().await;
    }

    Ok(())
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_deposit_recovers_through_update_and_settlement_packages() -> Result<()> {
    let _guard = common::test_guard();

    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;
    let lockbox_client = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox_client).await?;

    let client_config = common::prepare_test_env().await?;
    let wallet = mercuryrustlib::wallet::create_wallet("bip448-wallet", &client_config).await?;
    mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, &wallet).await?;

    let deposit = create_confirmed_bip448_deposit(&client_config, &wallet).await?;
    let record = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &client_config.pool,
        &wallet.name,
        &deposit.statechain_id,
    )
    .await?;
    assert_server_persistence_excludes_locktime(&record).await?;
    let wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet.name).await?;
    let coin = wallet
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some(&deposit.statechain_id))
        .context("BIP448 deposit coin not found after status update")?;
    assert_eq!(coin.statechain_protocol.as_deref(), Some("bip448"));
    assert!(matches!(
        coin.status,
        CoinStatus::UNCONFIRMED | CoinStatus::CONFIRMED
    ));

    let fee_inputs = confirmed_p2a_fee_inputs(FEE_INPUT_COUNT)?;
    let change_script = wallet_change_script()?;
    let update_tx = tx_from_hex(&record.latest_state.update_tx)?;
    let settlement_tx = tx_from_hex(&record.latest_state.settlement_tx)?;

    assert_eq!(update_tx.lock_time, settlement_tx.lock_time);
    assert_eq!(
        update_tx.lock_time.to_consensus_u32(),
        record.latest_state.state_locktime
    );
    assert!((500_000_000..=1_000_000_000).contains(&record.latest_state.state_locktime));
    let state_update_leaf = hex::decode(&record.latest_state.state_update_script)?;
    let expected_gate_prefix = Builder::new()
        .push_int(i64::from(record.latest_state.state_locktime) + 1)
        .push_opcode(OP_CLTV)
        .into_script();
    assert!(state_update_leaf.starts_with(expected_gate_prefix.as_bytes()));

    assert_eq!(update_tx.output[1].script_pubkey, pay_to_anchor_script());
    assert_eq!(
        settlement_tx.output[1].script_pubkey,
        pay_to_anchor_script()
    );
    assert_eq!(settlement_tx.input[0].witness.len(), 2);
    assert_ne!(settlement_tx.input[0].witness.nth(0).unwrap().len(), 64);

    assert_parent_only_rejected(&update_tx, "zero-fee BIP448 update parent")?;
    assert_committed_update_mutation_rejected(&record, &fee_inputs[0], change_script.clone())?;
    assert_anchor_mutation_rejected(
        &update_tx,
        record.funding_outpoint.value_sats,
        &fee_inputs[1],
        change_script.clone(),
    )?;

    let update_package = build_latest_state_recovery_package(
        &record,
        Bip448RecoveryTemplateRole::FundingUpdate,
        &[fee_inputs[2].clone()],
        change_script.clone(),
        PACKAGE_FEERATE_SAT_PER_VBYTE,
    )?;
    submit_package_success(&update_package)?;
    common::bitcoin_core::assert_in_mempool(&update_package.parent_tx.txid())?;
    common::bitcoin_core::assert_in_mempool(&update_package.cpfp_child_tx.txid())?;
    common::bitcoin_core::mine_block()?;
    common::bitcoin_core::assert_confirmed(&update_package.parent_tx.txid())?;

    let early_settlement_package = build_latest_state_recovery_package(
        &record,
        Bip448RecoveryTemplateRole::Settlement,
        &[fee_inputs[3].clone()],
        change_script.clone(),
        PACKAGE_FEERATE_SAT_PER_VBYTE,
    )?;
    assert_package_rejected(&early_settlement_package, "early BIP68 settlement package")?;

    common::bitcoin_core::mine_blocks(record.challenge_delay as u32)?;

    assert_committed_settlement_mutation_rejected(&record, &fee_inputs[4], change_script.clone())?;
    assert_anchor_mutation_rejected(
        &settlement_tx,
        record
            .latest_state
            .value_schedule
            .settlement_input_value_sats,
        &fee_inputs[5],
        change_script.clone(),
    )?;

    let settlement_package = build_latest_state_recovery_package(
        &record,
        Bip448RecoveryTemplateRole::Settlement,
        &[fee_inputs[6].clone()],
        change_script,
        PACKAGE_FEERATE_SAT_PER_VBYTE,
    )?;
    submit_package_success(&settlement_package)?;
    common::bitcoin_core::assert_in_mempool(&settlement_package.parent_tx.txid())?;
    common::bitcoin_core::assert_in_mempool(&settlement_package.cpfp_child_tx.txid())?;
    common::bitcoin_core::mine_block()?;
    common::bitcoin_core::assert_confirmed(&settlement_package.parent_tx.txid())?;

    common::chain::wait_for_address_outpoint(
        &client_config,
        &coin.backup_address,
        OutPoint {
            txid: settlement_package.parent_tx.txid(),
            vout: 0,
        },
        u64::from(FUNDING_AMOUNT_SATS),
    )
    .await?;

    Ok(())
}

async fn transfer_and_accept_bip448(
    client_config: &ClientConfig,
    sender_wallet: &str,
    receiver_wallet: &str,
    statechain_id: &str,
) -> Result<Bip448StatechainRecord> {
    let recipient_address =
        mercuryrustlib::transfer_receiver::new_transfer_address(client_config, receiver_wallet)
            .await?;
    mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender(
        client_config,
        &recipient_address,
        sender_wallet,
        statechain_id,
        None,
    )
    .await?;
    let receive_result =
        mercuryrustlib::transfer_receiver::execute(client_config, receiver_wallet).await?;
    assert!(!receive_result.is_there_batch_locked);
    assert_eq!(
        receive_result.received_statechain_ids,
        vec![statechain_id.to_string()]
    );
    mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &client_config.pool,
        receiver_wallet,
        statechain_id,
    )
    .await
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_one_hop_transfer_accepts_and_recovers_state_two() -> Result<()> {
    let _guard = common::test_guard();

    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;
    let lockbox_client = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox_client).await?;

    let client_config = common::prepare_test_env().await?;
    let sender =
        mercuryrustlib::wallet::create_wallet("bip448-one-hop-sender", &client_config).await?;
    let receiver =
        mercuryrustlib::wallet::create_wallet("bip448-one-hop-receiver", &client_config).await?;
    for wallet in [&sender, &receiver] {
        mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, wallet).await?;
    }

    let deposit = create_confirmed_bip448_deposit(&client_config, &sender).await?;
    common::bitcoin_core::mine_blocks(client_config.confirmation_target)?;
    mercuryrustlib::coin_status::update_coins(&client_config, &sender.name).await?;
    let state_one = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &client_config.pool,
        &sender.name,
        &deposit.statechain_id,
    )
    .await?;
    assert_eq!(state_one.latest_state_number, 1);
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
        1
    );

    let recipient_address =
        mercuryrustlib::transfer_receiver::new_transfer_address(&client_config, &receiver.name)
            .await?;
    mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender(
        &client_config,
        &recipient_address,
        &sender.name,
        &deposit.statechain_id,
        None,
    )
    .await?;
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
        2
    );

    let receive_result =
        mercuryrustlib::transfer_receiver::execute(&client_config, &receiver.name).await?;
    assert!(!receive_result.is_there_batch_locked);
    assert_eq!(
        receive_result.received_statechain_ids,
        vec![deposit.statechain_id.clone()]
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
        2
    );

    let state_two = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &client_config.pool,
        &receiver.name,
        &deposit.statechain_id,
    )
    .await?;
    assert_eq!(state_two.latest_state_number, 2);
    assert_eq!(state_two.latest_state.state_number, 2);
    assert_eq!(
        state_two
            .latest_state
            .signing_metadata
            .server_signature_count,
        2
    );
    let receiver_wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &receiver.name).await?;
    let received_coin = receiver_wallet
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some(&deposit.statechain_id))
        .context("receiver wallet does not contain the accepted BIP448 coin")?;
    assert_eq!(received_coin.status, CoinStatus::CONFIRMED);
    assert_eq!(received_coin.statechain_protocol.as_deref(), Some("bip448"));
    let receiver_backup_address = received_coin.backup_address.clone();

    let fee_inputs = confirmed_p2a_fee_inputs(2)?;
    let change_address = common::bitcoin_core::getnewaddress()?;
    let update = mercuryrustlib::bip448_recovery::submit_latest_state_recovery_package(
        &client_config,
        &receiver.name,
        &deposit.statechain_id,
        Bip448RecoveryTemplateRole::FundingUpdate,
        &fee_inputs[..1],
        &change_address,
        Some(PACKAGE_FEERATE_SAT_PER_VBYTE),
    )
    .await?;
    assert_eq!(update.role, "funding_update");
    let update_txid = Txid::from_str(&update.parent_txid)?;
    let update_child_txid = Txid::from_str(&update.cpfp_child_txid)?;
    common::bitcoin_core::assert_in_mempool(&update_txid)?;
    common::bitcoin_core::assert_in_mempool(&update_child_txid)?;
    common::bitcoin_core::mine_block()?;
    common::bitcoin_core::assert_confirmed(&update_txid)?;
    common::bitcoin_core::assert_confirmed(&update_child_txid)?;

    common::bitcoin_core::mine_blocks(state_two.challenge_delay as u32)?;

    let settlement = mercuryrustlib::bip448_recovery::submit_latest_state_recovery_package(
        &client_config,
        &receiver.name,
        &deposit.statechain_id,
        Bip448RecoveryTemplateRole::Settlement,
        &fee_inputs[1..],
        &change_address,
        Some(PACKAGE_FEERATE_SAT_PER_VBYTE),
    )
    .await?;
    assert_eq!(settlement.role, "settlement");
    let settlement_txid = Txid::from_str(&settlement.parent_txid)?;
    let settlement_child_txid = Txid::from_str(&settlement.cpfp_child_txid)?;
    common::bitcoin_core::assert_in_mempool(&settlement_txid)?;
    common::bitcoin_core::assert_in_mempool(&settlement_child_txid)?;
    common::bitcoin_core::mine_block()?;
    common::bitcoin_core::assert_confirmed(&settlement_txid)?;
    common::bitcoin_core::assert_confirmed(&settlement_child_txid)?;

    common::chain::wait_for_address_outpoint(
        &client_config,
        &receiver_backup_address,
        OutPoint {
            txid: settlement_txid,
            vout: 0,
        },
        u64::from(FUNDING_AMOUNT_SATS),
    )
    .await?;

    Ok(())
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_two_hop_transfer_accepts_and_recovers_state_three() -> Result<()> {
    let _guard = common::test_guard();

    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;
    let lockbox_client = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox_client).await?;

    let client_config = common::prepare_test_env().await?;
    let sender =
        mercuryrustlib::wallet::create_wallet("bip448-two-hop-sender", &client_config).await?;
    let middle =
        mercuryrustlib::wallet::create_wallet("bip448-two-hop-middle", &client_config).await?;
    let receiver =
        mercuryrustlib::wallet::create_wallet("bip448-two-hop-receiver", &client_config).await?;
    for wallet in [&sender, &middle, &receiver] {
        mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, wallet).await?;
    }

    let deposit = create_confirmed_bip448_deposit(&client_config, &sender).await?;
    common::bitcoin_core::mine_blocks(client_config.confirmation_target)?;
    mercuryrustlib::coin_status::update_coins(&client_config, &sender.name).await?;
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
        1
    );

    let state_two = transfer_and_accept_bip448(
        &client_config,
        &sender.name,
        &middle.name,
        &deposit.statechain_id,
    )
    .await?;
    assert_eq!(state_two.latest_state_number, 2);
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
        2
    );

    let state_three = transfer_and_accept_bip448(
        &client_config,
        &middle.name,
        &receiver.name,
        &deposit.statechain_id,
    )
    .await?;
    assert_eq!(state_three.latest_state_number, 3);
    assert_eq!(state_three.latest_state.state_number, 3);
    assert_eq!(
        state_three
            .latest_state
            .signing_metadata
            .server_signature_count,
        3
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
        3
    );

    let receiver_wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &receiver.name).await?;
    let received_coin = receiver_wallet
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some(&deposit.statechain_id))
        .context("final receiver does not contain the accepted state-3 BIP448 coin")?;
    assert_eq!(received_coin.status, CoinStatus::CONFIRMED);
    let receiver_backup_address = received_coin.backup_address.clone();

    let fee_inputs = confirmed_p2a_fee_inputs(2)?;
    let change_address = common::bitcoin_core::getnewaddress()?;
    let update = mercuryrustlib::bip448_recovery::submit_latest_state_recovery_package(
        &client_config,
        &receiver.name,
        &deposit.statechain_id,
        Bip448RecoveryTemplateRole::FundingUpdate,
        &fee_inputs[..1],
        &change_address,
        Some(PACKAGE_FEERATE_SAT_PER_VBYTE),
    )
    .await?;
    let update_txid = Txid::from_str(&update.parent_txid)?;
    let update_child_txid = Txid::from_str(&update.cpfp_child_txid)?;
    common::bitcoin_core::assert_in_mempool(&update_txid)?;
    common::bitcoin_core::assert_in_mempool(&update_child_txid)?;
    common::bitcoin_core::mine_block()?;
    common::bitcoin_core::assert_confirmed(&update_txid)?;
    common::bitcoin_core::assert_confirmed(&update_child_txid)?;

    common::bitcoin_core::mine_blocks(state_three.challenge_delay as u32)?;

    let settlement = mercuryrustlib::bip448_recovery::submit_latest_state_recovery_package(
        &client_config,
        &receiver.name,
        &deposit.statechain_id,
        Bip448RecoveryTemplateRole::Settlement,
        &fee_inputs[1..],
        &change_address,
        Some(PACKAGE_FEERATE_SAT_PER_VBYTE),
    )
    .await?;
    let settlement_txid = Txid::from_str(&settlement.parent_txid)?;
    let settlement_child_txid = Txid::from_str(&settlement.cpfp_child_txid)?;
    common::bitcoin_core::assert_in_mempool(&settlement_txid)?;
    common::bitcoin_core::assert_in_mempool(&settlement_child_txid)?;
    common::bitcoin_core::mine_block()?;
    common::bitcoin_core::assert_confirmed(&settlement_txid)?;
    common::bitcoin_core::assert_confirmed(&settlement_child_txid)?;

    common::chain::wait_for_address_outpoint(
        &client_config,
        &receiver_backup_address,
        OutPoint {
            txid: settlement_txid,
            vout: 0,
        },
        u64::from(FUNDING_AMOUNT_SATS),
    )
    .await?;

    Ok(())
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_same_wallet_second_hop_advances_to_state_three() -> Result<()> {
    let _guard = common::test_guard();

    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;
    let lockbox_client = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox_client).await?;

    let client_config = common::prepare_test_env().await?;
    let sender =
        mercuryrustlib::wallet::create_wallet("bip448-state-three-sender", &client_config).await?;
    let holder =
        mercuryrustlib::wallet::create_wallet("bip448-state-three-same-wallet", &client_config)
            .await?;
    for wallet in [&sender, &holder] {
        mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, wallet).await?;
    }

    let deposit = create_confirmed_bip448_deposit(&client_config, &sender).await?;
    common::bitcoin_core::mine_blocks(client_config.confirmation_target)?;
    mercuryrustlib::coin_status::update_coins(&client_config, &sender.name).await?;
    let state_two = transfer_and_accept_bip448(
        &client_config,
        &sender.name,
        &holder.name,
        &deposit.statechain_id,
    )
    .await?;
    assert_eq!(state_two.latest_state_number, 2);

    let state_three = transfer_and_accept_bip448(
        &client_config,
        &holder.name,
        &holder.name,
        &deposit.statechain_id,
    )
    .await?;
    assert_eq!(state_three.latest_state_number, 3);
    assert_eq!(state_three.latest_state.state_number, 3);
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
        3
    );

    let wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &holder.name).await?;
    assert!(wallet.coins.iter().any(|coin| {
        coin.statechain_id.as_deref() == Some(deposit.statechain_id.as_str())
            && coin.status == CoinStatus::CONFIRMED
    }));
    assert!(wallet.coins.iter().any(|coin| {
        coin.statechain_id.as_deref() == Some(deposit.statechain_id.as_str())
            && coin.status == CoinStatus::IN_TRANSFER
    }));

    Ok(())
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_same_wallet_transfer_advances_the_accepted_record_to_state_two() -> Result<()> {
    let _guard = common::test_guard();

    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;
    let lockbox_client = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox_client).await?;

    let client_config = common::prepare_test_env().await?;
    let wallet =
        mercuryrustlib::wallet::create_wallet("bip448-same-wallet", &client_config).await?;
    mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, &wallet).await?;

    let deposit = create_confirmed_bip448_deposit(&client_config, &wallet).await?;
    common::bitcoin_core::mine_blocks(client_config.confirmation_target)?;
    mercuryrustlib::coin_status::update_coins(&client_config, &wallet.name).await?;
    let recipient_address =
        mercuryrustlib::transfer_receiver::new_transfer_address(&client_config, &wallet.name)
            .await?;
    let (_, recipient_user_pubkey, recipient_auth_pubkey) =
        mercurylib::decode_transfer_address(&recipient_address)?;

    mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender(
        &client_config,
        &recipient_address,
        &wallet.name,
        &deposit.statechain_id,
        None,
    )
    .await?;
    let receive_result =
        mercuryrustlib::transfer_receiver::execute(&client_config, &wallet.name).await?;

    assert_eq!(
        receive_result.received_statechain_ids,
        vec![deposit.statechain_id.clone()]
    );
    let state_two = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &client_config.pool,
        &wallet.name,
        &deposit.statechain_id,
    )
    .await?;
    assert_eq!(state_two.latest_state_number, 2);
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
        2
    );

    let wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet.name).await?;
    let received = wallet
        .coins
        .iter()
        .find(|coin| {
            coin.statechain_id.as_deref() == Some(deposit.statechain_id.as_str())
                && coin.user_pubkey == recipient_user_pubkey.to_string()
                && coin.auth_pubkey == recipient_auth_pubkey.to_string()
        })
        .context("same-wallet recipient coin was not accepted")?;
    assert_eq!(received.status, CoinStatus::CONFIRMED);
    assert_eq!(received.statechain_protocol.as_deref(), Some("bip448"));
    assert!(wallet.coins.iter().any(|coin| {
        coin.statechain_id.as_deref() == Some(deposit.statechain_id.as_str())
            && coin.status == CoinStatus::IN_TRANSFER
    }));

    Ok(())
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Bitcoin Core descriptor activity RPCs"]
async fn bip448_discovery_cursor_reorg_and_restart_state() -> Result<()> {
    let _guard = common::test_guard();

    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;

    let client_config = common::prepare_test_env().await?;
    let scan_address =
        common::bitcoin_core::regtest_address(&common::bitcoin_core::getnewaddress()?)?;
    let first = fund_address_output(&scan_address, FUNDING_AMOUNT_SATS)?;
    common::bitcoin_core::mine_block()?;
    common::bitcoin_core::set_wallet_outpoint_locked(first.outpoint, true)?;

    let wallet_name = format!("bip448-scan-state-{}", uuid::Uuid::new_v4());
    let mut wallet = mercuryrustlib::wallet::create_wallet(&wallet_name, &client_config).await?;
    let mut coin = wallet.get_new_coin()?;
    coin.aggregated_address = Some(scan_address.to_string());
    coin.utxo_txid = Some(first.outpoint.txid.to_string());
    coin.utxo_vout = Some(first.outpoint.vout);
    coin.amount = Some(u32::try_from(first.value_sats)?);
    coin.statechain_id = Some(format!("legacy-scan-{}", uuid::Uuid::new_v4()));
    coin.status = CoinStatus::CONFIRMED;
    wallet.coins.push(coin);
    mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, &wallet).await?;

    let script_hex = hex::encode(scan_address.script_pubkey().as_bytes());
    mercuryrustlib::chain::take_scan_blocks_calls();
    mercuryrustlib::coin_status::update_coins(&client_config, &wallet_name).await?;
    let first_calls = mercuryrustlib::chain::take_scan_blocks_calls();
    assert_eq!(first_calls.len(), 1);
    assert_eq!(first_calls[0].0, 0);
    let (first_cursor_height, _): (i64, String) = sqlx::query_as(
        "SELECT last_scanned_height, last_scanned_block_hash \
         FROM bip448_scan_cursors WHERE wallet_name = $1 AND script_pubkey = $2",
    )
    .bind(&wallet_name)
    .bind(&script_hex)
    .fetch_one(&client_config.pool)
    .await?;

    common::bitcoin_core::mine_block()?;
    let next_tip = client_config.chain_client.tip_height()?;
    mercuryrustlib::chain::take_scan_blocks_calls();
    mercuryrustlib::coin_status::update_coins(&client_config, &wallet_name).await?;
    assert_eq!(
        mercuryrustlib::chain::take_scan_blocks_calls(),
        vec![(u32::try_from(first_cursor_height)? + 1, next_tip)]
    );

    let second = fund_address_output(&scan_address, FUNDING_AMOUNT_SATS)?;
    common::bitcoin_core::mine_block()?;
    mercuryrustlib::coin_status::update_coins(&client_config, &wallet_name).await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bip448_scanned_outpoints \
             WHERE wallet_name = $1 AND txid = $2 AND vout = $3",
        )
        .bind(&wallet_name)
        .bind(second.outpoint.txid.to_string())
        .bind(i64::from(second.outpoint.vout))
        .fetch_one(&client_config.pool)
        .await?,
        1
    );

    client_config.pool.close().await;
    common::bitcoin_core::spend_wallet_outpoint(second.outpoint, second.value_sats)?;
    let restarted_config = mercuryrustlib::client_config::load().await;
    mercuryrustlib::coin_status::update_coins(&restarted_config, &wallet_name).await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bip448_scanned_outpoints \
             WHERE wallet_name = $1 AND txid = $2 AND vout = $3",
        )
        .bind(&wallet_name)
        .bind(second.outpoint.txid.to_string())
        .bind(i64::from(second.outpoint.vout))
        .fetch_one(&restarted_config.pool)
        .await?,
        0
    );

    let reservation_statechain = format!("scan-reservation-{}", uuid::Uuid::new_v4());
    let reservation_id = format!("{reservation_statechain}:funding_update");
    let fake_txid = "f0".repeat(32);
    let fee_inputs = serde_json::json!([
        {
            "txid": first.outpoint.txid.to_string(),
            "vout": first.outpoint.vout,
            "value_sats": first.value_sats,
        },
        {
            "txid": fake_txid,
            "vout": 7,
            "value_sats": 12345,
        }
    ]);
    sqlx::query(
        "INSERT INTO bip448_package_attempts \
            (wallet_name, statechain_id, role, parent_txid, child_txid, child_tx_hex, \
             fee_inputs_json, target_feerate_sat_per_vbyte, status) \
         VALUES ($1, $2, 'funding_update', $3, $4, '00', $5, 2.0, 'Pending')",
    )
    .bind(&wallet_name)
    .bind(&reservation_statechain)
    .bind("a1".repeat(32))
    .bind("b2".repeat(32))
    .bind(fee_inputs.to_string())
    .execute(&restarted_config.pool)
    .await?;
    sqlx::query(
        "UPDATE bip448_scanned_outpoints SET reserved_by = $1, reserved_at = unixepoch() \
         WHERE wallet_name = $2 AND txid = $3 AND vout = $4",
    )
    .bind(&reservation_id)
    .bind(&wallet_name)
    .bind(first.outpoint.txid.to_string())
    .bind(i64::from(first.outpoint.vout))
    .execute(&restarted_config.pool)
    .await?;
    sqlx::query(
        "INSERT INTO bip448_scanned_outpoints \
            (wallet_name, txid, vout, script_pubkey, value_sats, height, \
             reserved_by, reserved_at) \
         VALUES ($1, $2, 7, $3, 12345, 1, $4, unixepoch())",
    )
    .bind(&wallet_name)
    .bind(&fake_txid)
    .bind(&script_hex)
    .bind(&reservation_id)
    .execute(&restarted_config.pool)
    .await?;
    let genesis_hash = restarted_config.chain_client.get_block_hash(0)?.to_string();
    sqlx::query(
        "UPDATE bip448_scan_cursors SET last_scanned_block_hash = $1 \
         WHERE wallet_name = $2 AND script_pubkey = $3",
    )
    .bind(genesis_hash)
    .bind(&wallet_name)
    .bind(&script_hex)
    .execute(&restarted_config.pool)
    .await?;

    let rescan_tip = restarted_config.chain_client.tip_height()?;
    mercuryrustlib::chain::take_scan_blocks_calls();
    mercuryrustlib::coin_status::update_coins(&restarted_config, &wallet_name).await?;
    assert_eq!(
        mercuryrustlib::chain::take_scan_blocks_calls(),
        vec![(0, rescan_tip)]
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bip448_scanned_outpoints \
             WHERE wallet_name = $1 AND txid = $2",
        )
        .bind(&wallet_name)
        .bind(&fake_txid)
        .fetch_one(&restarted_config.pool)
        .await?,
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT reserved_by FROM bip448_scanned_outpoints \
             WHERE wallet_name = $1 AND txid = $2 AND vout = $3",
        )
        .bind(&wallet_name)
        .bind(first.outpoint.txid.to_string())
        .bind(i64::from(first.outpoint.vout))
        .fetch_one(&restarted_config.pool)
        .await?,
        reservation_id
    );
    let (cursor_height, cursor_hash): (i64, String) = sqlx::query_as(
        "SELECT last_scanned_height, last_scanned_block_hash \
         FROM bip448_scan_cursors WHERE wallet_name = $1 AND script_pubkey = $2",
    )
    .bind(&wallet_name)
    .bind(&script_hex)
    .fetch_one(&restarted_config.pool)
    .await?;
    assert_eq!(u32::try_from(cursor_height)?, rescan_tip);
    assert_eq!(
        cursor_hash,
        restarted_config
            .chain_client
            .get_block_hash(rescan_tip)?
            .to_string()
    );

    common::bitcoin_core::set_wallet_outpoint_locked(first.outpoint, false)?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_client_submitter_broadcasts_recovery_package() -> Result<()> {
    let _guard = common::test_guard();

    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;
    let lockbox_client = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox_client).await?;

    let client_config = common::prepare_test_env().await?;
    let wallet =
        mercuryrustlib::wallet::create_wallet("bip448-submitter-wallet", &client_config).await?;
    mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, &wallet).await?;

    let deposit = create_confirmed_bip448_deposit(&client_config, &wallet).await?;
    let fee_inputs = confirmed_p2a_fee_inputs(1)?;
    let change_address = common::bitcoin_core::getnewaddress()?;

    // Exercise the client submitter end-to-end, including both mempool deduplication
    // and Bitcoin Core's response when the parent is already confirmed.
    let submit_funding_update = || {
        mercuryrustlib::bip448_recovery::submit_latest_state_recovery_package(
            &client_config,
            &wallet.name,
            &deposit.statechain_id,
            Bip448RecoveryTemplateRole::FundingUpdate,
            &fee_inputs,
            &change_address,
            Some(PACKAGE_FEERATE_SAT_PER_VBYTE),
        )
    };
    let submission = submit_funding_update().await?;
    let mempool_replay = submit_funding_update().await?;

    assert_eq!(submission.role, "funding_update");
    assert_eq!(mempool_replay.parent_txid, submission.parent_txid);
    assert_eq!(mempool_replay.cpfp_child_txid, submission.cpfp_child_txid);
    let parent_txid = Txid::from_str(&submission.parent_txid)?;
    let child_txid = Txid::from_str(&submission.cpfp_child_txid)?;
    common::bitcoin_core::assert_in_mempool(&parent_txid)?;
    common::bitcoin_core::assert_in_mempool(&child_txid)?;

    // Mine only the parent so Core can evaluate every transaction in the
    // replayed package.
    common::bitcoin_core::mine_block_with_transactions(&[parent_txid])?;
    common::bitcoin_core::assert_confirmed(&parent_txid)?;
    common::bitcoin_core::assert_not_in_mempool(&parent_txid)?;
    common::bitcoin_core::assert_in_mempool(&child_txid)?;

    let confirmed_parent_replay = submit_funding_update().await?;
    assert_eq!(confirmed_parent_replay.parent_txid, submission.parent_txid);
    assert_eq!(
        confirmed_parent_replay.cpfp_child_txid,
        submission.cpfp_child_txid
    );
    assert_ne!(
        confirmed_parent_replay
            .submitpackage_response
            .get("package_msg")
            .and_then(Value::as_str),
        Some("success")
    );
    let tx_results = confirmed_parent_replay
        .submitpackage_response
        .get("tx-results")
        .and_then(Value::as_object)
        .context("confirmed-parent replay did not include transaction results")?;
    assert_eq!(tx_results.len(), 2);
    let parent_result = tx_results
        .values()
        .find(|result| result.get("txid").and_then(Value::as_str) == Some(&submission.parent_txid))
        .context("confirmed-parent replay did not include the parent result")?;
    assert_eq!(
        parent_result.get("error").and_then(Value::as_str),
        Some("txn-already-known")
    );
    let child_result = tx_results
        .values()
        .find(|result| {
            result.get("txid").and_then(Value::as_str) == Some(&submission.cpfp_child_txid)
        })
        .context("confirmed-parent replay did not include the CPFP child result")?;
    assert!(child_result.get("error").is_none());

    let stored_attempt = mercuryrustlib::sqlite_manager::get_bip448_package_attempt(
        &client_config.pool,
        &wallet.name,
        &deposit.statechain_id,
        Bip448RecoveryTemplateRole::FundingUpdate.as_str(),
    )
    .await?
    .context("submitted recovery attempt disappeared")?;
    let mempool_before_corruption = common::bitcoin_core::raw_mempool()?
        .into_iter()
        .collect::<HashSet<_>>();
    sqlx::query(
        "UPDATE bip448_package_attempts \
         SET target_feerate_sat_per_vbyte = $1 \
         WHERE wallet_name = $2 AND statechain_id = $3 AND role = 'funding_update'",
    )
    .bind(stored_attempt.target_feerate_sat_per_vbyte + 100.0)
    .bind(&wallet.name)
    .bind(&deposit.statechain_id)
    .execute(&client_config.pool)
    .await?;
    let target_error = submit_funding_update()
        .await
        .expect_err("corrupt persisted target feerate did not fail closed");
    assert!(target_error.to_string().contains("inconsistent"));
    assert_eq!(
        common::bitcoin_core::raw_mempool()?
            .into_iter()
            .collect::<HashSet<_>>(),
        mempool_before_corruption
    );
    sqlx::query(
        "UPDATE bip448_package_attempts \
         SET target_feerate_sat_per_vbyte = $1 \
         WHERE wallet_name = $2 AND statechain_id = $3 AND role = 'funding_update'",
    )
    .bind(stored_attempt.target_feerate_sat_per_vbyte)
    .bind(&wallet.name)
    .bind(&deposit.statechain_id)
    .execute(&client_config.pool)
    .await?;

    common::bitcoin_core::mine_block()?;
    common::bitcoin_core::assert_confirmed(&child_txid)?;
    sqlx::query(
        "UPDATE bip448_package_attempts SET child_tx_hex = '00' \
         WHERE wallet_name = $1 AND statechain_id = $2 AND role = 'funding_update'",
    )
    .bind(&wallet.name)
    .bind(&deposit.statechain_id)
    .execute(&client_config.pool)
    .await?;
    let corrupt_child_error =
        mercuryrustlib::bip448_recovery::confirm_latest_state_recovery_package(
            &client_config,
            &wallet.name,
            &deposit.statechain_id,
            Bip448RecoveryTemplateRole::FundingUpdate,
        )
        .await
        .expect_err("unparseable persisted child was marked confirmed");
    assert!(corrupt_child_error
        .to_string()
        .contains("invalid stored BIP448 recovery child"));
    assert_eq!(
        mercuryrustlib::sqlite_manager::get_bip448_package_attempt(
            &client_config.pool,
            &wallet.name,
            &deposit.statechain_id,
            Bip448RecoveryTemplateRole::FundingUpdate.as_str(),
        )
        .await?
        .context("corrupt recovery attempt disappeared")?
        .status,
        mercuryrustlib::sqlite_manager::Bip448PackageAttemptStatus::Submitted
    );
    assert!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bip448_scanned_outpoints \
             WHERE wallet_name = $1 AND reserved_by IS NOT NULL",
        )
        .bind(&wallet.name)
        .fetch_one(&client_config.pool)
        .await?
            > 0
    );
    sqlx::query(
        "UPDATE bip448_package_attempts SET child_tx_hex = $1 \
         WHERE wallet_name = $2 AND statechain_id = $3 AND role = 'funding_update'",
    )
    .bind(&stored_attempt.child_tx_hex)
    .bind(&wallet.name)
    .bind(&deposit.statechain_id)
    .execute(&client_config.pool)
    .await?;

    let child: Transaction = encode::deserialize(&hex::decode(&stored_attempt.child_tx_hex)?)?;
    let descendant_txid = common::bitcoin_core::spend_wallet_outpoint(
        OutPoint {
            txid: child_txid,
            vout: 0,
        },
        child.output[0].value,
    )?;
    common::bitcoin_core::assert_in_mempool(&descendant_txid)?;
    assert!(client_config
        .chain_client
        .get_tx_out(&child_txid, 0, true)?
        .is_none());
    let confirmed_replay = submit_funding_update().await?;
    assert_eq!(
        confirmed_replay
            .submitpackage_response
            .get("package_msg")
            .and_then(Value::as_str),
        Some("already-in-chain")
    );
    assert_eq!(
        mercuryrustlib::sqlite_manager::get_bip448_package_attempt(
            &client_config.pool,
            &wallet.name,
            &deposit.statechain_id,
            Bip448RecoveryTemplateRole::FundingUpdate.as_str(),
        )
        .await?
        .context("confirmed recovery attempt disappeared")?
        .status,
        mercuryrustlib::sqlite_manager::Bip448PackageAttemptStatus::Confirmed
    );

    Ok(())
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_owner_recovery_survives_restart_mid_broadcast() -> Result<()> {
    let _guard = common::test_guard();

    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;
    let lockbox_client = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox_client).await?;

    let initial_config = common::prepare_test_env().await?;
    initial_config.pool.close().await;
    for (index, checkpoint) in ["recovery_pending", "recovery_submitted"]
        .into_iter()
        .enumerate()
    {
        let client_config = mercuryrustlib::client_config::load().await;
        let wallet_name = format!("bip448-recovery-restart-{index}-{}", uuid::Uuid::new_v4());
        let wallet = mercuryrustlib::wallet::create_wallet(&wallet_name, &client_config).await?;
        mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, &wallet).await?;
        let deposit = create_confirmed_bip448_deposit(&client_config, &wallet).await?;
        let fee_input = confirmed_p2a_fee_inputs(1)?
            .into_iter()
            .next()
            .context("fee input funding returned no input")?;
        let fee_input_descriptor = format!(
            "{}:{}:{}",
            fee_input.previous_output.txid,
            fee_input.previous_output.vout,
            fee_input.value_sats
        );
        let change_address = common::bitcoin_core::getnewaddress()?;
        let missing = mercuryrustlib::bip448_recovery::resume_latest_state_recovery_package(
            &client_config,
            &wallet_name,
            &deposit.statechain_id,
            Bip448RecoveryTemplateRole::FundingUpdate,
        )
        .await
        .expect_err("recovery without a persisted attempt did not fail closed");
        assert!(missing.to_string().contains("attempt is missing"));
        client_config.pool.close().await;

        let interrupted = run_recovery_restart_child(
            &wallet_name,
            &deposit.statechain_id,
            &fee_input_descriptor,
            &change_address,
            Some(checkpoint),
        )?;
        assert_child_status(
            &interrupted,
            Some(RESTART_CHECKPOINT_EXIT_CODE),
            checkpoint,
        )?;

        let interrupted_config = mercuryrustlib::client_config::load().await;
        let attempt = mercuryrustlib::sqlite_manager::get_bip448_package_attempt(
            &interrupted_config.pool,
            &wallet_name,
            &deposit.statechain_id,
            Bip448RecoveryTemplateRole::FundingUpdate.as_str(),
        )
        .await?
        .context("recovery checkpoint did not persist an attempt")?;
        assert_eq!(
            attempt.status,
            mercuryrustlib::sqlite_manager::Bip448PackageAttemptStatus::Pending
        );
        let parent_txid = Txid::from_str(&attempt.parent_txid)?;
        let child_txid = Txid::from_str(&attempt.child_txid)?;
        let stored_child_hex = attempt.child_tx_hex.clone();
        let mempool_before_resume = common::bitcoin_core::raw_mempool()?
            .into_iter()
            .collect::<HashSet<_>>();
        if checkpoint == "recovery_pending" {
            assert!(!mempool_before_resume.contains(&parent_txid));
            assert!(!mempool_before_resume.contains(&child_txid));
        } else {
            assert!(mempool_before_resume.contains(&parent_txid));
            assert!(mempool_before_resume.contains(&child_txid));
        }
        interrupted_config.pool.close().await;

        let resumed = run_recovery_restart_child(
            &wallet_name,
            &deposit.statechain_id,
            &fee_input_descriptor,
            &change_address,
            None,
        )?;
        assert_child_status(&resumed, Some(0), &format!("resume after {checkpoint}"))?;

        let resumed_config = mercuryrustlib::client_config::load().await;
        let resumed_attempt = mercuryrustlib::sqlite_manager::get_bip448_package_attempt(
            &resumed_config.pool,
            &wallet_name,
            &deposit.statechain_id,
            Bip448RecoveryTemplateRole::FundingUpdate.as_str(),
        )
        .await?
        .context("resumed recovery attempt disappeared")?;
        assert_eq!(resumed_attempt.child_tx_hex, stored_child_hex);
        assert_eq!(resumed_attempt.child_txid, child_txid.to_string());
        assert_eq!(
            resumed_attempt.status,
            mercuryrustlib::sqlite_manager::Bip448PackageAttemptStatus::Submitted
        );
        common::bitcoin_core::assert_in_mempool(&parent_txid)?;
        common::bitcoin_core::assert_in_mempool(&child_txid)?;
        if checkpoint == "recovery_submitted" {
            assert_eq!(
                common::bitcoin_core::raw_mempool()?
                    .into_iter()
                    .collect::<HashSet<_>>(),
                mempool_before_resume
            );
        }
        resumed_config.pool.close().await;

        common::bitcoin_core::mine_block()?;
        common::bitcoin_core::assert_confirmed(&parent_txid)?;
        common::bitcoin_core::assert_confirmed(&child_txid)?;
        let confirmed = run_recovery_restart_child(
            &wallet_name,
            &deposit.statechain_id,
            &fee_input_descriptor,
            &change_address,
            None,
        )?;
        assert_child_status(
            &confirmed,
            Some(0),
            &format!("confirmed replay after {checkpoint}"),
        )?;
        let confirmed_config = mercuryrustlib::client_config::load().await;
        let confirmed_attempt = mercuryrustlib::sqlite_manager::get_bip448_package_attempt(
            &confirmed_config.pool,
            &wallet_name,
            &deposit.statechain_id,
            Bip448RecoveryTemplateRole::FundingUpdate.as_str(),
        )
        .await?
        .context("confirmed recovery attempt disappeared")?;
        assert_eq!(confirmed_attempt.child_tx_hex, stored_child_hex);
        assert_eq!(
            confirmed_attempt.status,
            mercuryrustlib::sqlite_manager::Bip448PackageAttemptStatus::Confirmed
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM bip448_scanned_outpoints \
                 WHERE wallet_name = $1 AND reserved_by IS NOT NULL",
            )
            .bind(&wallet_name)
            .fetch_one(&confirmed_config.pool)
            .await?,
            0
        );
        confirmed_config.pool.close().await;
    }

    Ok(())
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_cli_wallet_funded_and_keyless_recovery_packages() -> Result<()> {
    let _guard = common::test_guard();
    let client_cli = build_client_cli()?;

    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;
    let lockbox_client = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox_client).await?;

    let client_config = common::prepare_test_env().await?;
    let wallet =
        mercuryrustlib::wallet::create_wallet("bip448-wallet-funded-cli", &client_config).await?;
    mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, &wallet).await?;
    let deposit = create_confirmed_bip448_deposit(&client_config, &wallet).await?;

    let fee_address = run_client_cli(
        &client_cli,
        &[
            "bip448-recovery-fee-address".to_string(),
            wallet.name.clone(),
        ],
    )?;
    let fee_address = fee_address
        .get("address")
        .and_then(Value::as_str)
        .context("fee-address command omitted address")?;
    let fee_address = common::bitcoin_core::regtest_address(fee_address)?;
    fund_address_output(&fee_address, FEE_INPUT_AMOUNT_SATS)?;
    common::bitcoin_core::mine_block()?;

    let wallet_funded = run_client_cli(
        &client_cli,
        &[
            "broadcast-bip448-recovery-package".to_string(),
            wallet.name.clone(),
            deposit.statechain_id,
            "funding_update".to_string(),
            "--fund-from-wallet".to_string(),
            "--fee-rate".to_string(),
            PACKAGE_FEERATE_SAT_PER_VBYTE.to_string(),
        ],
    )?;
    confirm_cli_recovery_package(&wallet_funded)?;

    let keyless_wallet =
        mercuryrustlib::wallet::create_wallet("bip448-keyless-cli", &client_config).await?;
    mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, &keyless_wallet).await?;
    let keyless_deposit = create_confirmed_bip448_deposit(&client_config, &keyless_wallet).await?;
    let fee_input = fund_p2a_fee_input()?;
    common::bitcoin_core::mine_block()?;
    let fee_input = format!(
        "{}:{}:{}",
        fee_input.outpoint.txid, fee_input.outpoint.vout, fee_input.value_sats
    );

    let keyless = run_client_cli(
        &client_cli,
        &[
            "broadcast-bip448-recovery-package".to_string(),
            keyless_wallet.name,
            keyless_deposit.statechain_id,
            "funding_update".to_string(),
            common::bitcoin_core::getnewaddress()?,
            "--fee-input".to_string(),
            fee_input,
            "--fee-rate".to_string(),
            PACKAGE_FEERATE_SAT_PER_VBYTE.to_string(),
        ],
    )?;
    confirm_cli_recovery_package(&keyless)?;

    Ok(())
}

struct Bip448DepositFixture {
    statechain_id: String,
}

fn build_client_cli() -> Result<PathBuf> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "build",
            "--locked",
            "--package",
            "client-rust",
            "--bin",
            "client-rust",
            "--message-format=json-render-diagnostics",
        ])
        .output()
        .context("failed to build client-rust for the CLI recovery test")?;
    if !output.status.success() {
        return Err(anyhow!(
            "client-rust build failed with {:?}\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ));
    }

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find_map(|message| {
            (message.get("reason").and_then(Value::as_str) == Some("compiler-artifact")
                && message
                    .get("target")
                    .and_then(|target| target.get("name"))
                    .and_then(Value::as_str)
                    == Some("client-rust"))
            .then(|| {
                message
                    .get("executable")
                    .and_then(Value::as_str)
                    .map(PathBuf::from)
            })
            .flatten()
        })
        .context("client-rust build did not report its executable")
}

fn run_client_cli(binary: &Path, args: &[String]) -> Result<Value> {
    let output = Command::new(binary)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("ML_NETWORK", "regtest")
        .args(args)
        .output()
        .with_context(|| format!("failed to execute {}", binary.display()))?;
    if !output.status.success() {
        return Err(anyhow!(
            "client command failed with {:?}\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ));
    }

    Ok(serde_json::from_slice(&output.stdout)?)
}

fn confirm_cli_recovery_package(submission: &Value) -> Result<()> {
    let parent_txid = submission
        .get("parent_txid")
        .and_then(Value::as_str)
        .context("CLI recovery omitted parent_txid")?
        .parse::<Txid>()?;
    let child_txid = submission
        .get("cpfp_child_txid")
        .and_then(Value::as_str)
        .context("CLI recovery omitted cpfp_child_txid")?
        .parse::<Txid>()?;
    common::bitcoin_core::assert_in_mempool(&parent_txid)?;
    common::bitcoin_core::assert_in_mempool(&child_txid)?;
    common::bitcoin_core::mine_block()?;
    common::bitcoin_core::assert_confirmed(&parent_txid)?;
    common::bitcoin_core::assert_confirmed(&child_txid)?;

    Ok(())
}

fn run_restart_child(wallet_name: &str, checkpoint: Option<&str>) -> Result<Output> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "--ignored",
            "--exact",
            "bip448_client_restart_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ML_BIP448_RESTART_CHILD", "1")
        .env("ML_BIP448_RESTART_WALLET", wallet_name)
        .env("ML_NETWORK", "regtest")
        .env_remove("ML_BIP448_TEST_CHECKPOINT");
    if let Some(checkpoint) = checkpoint {
        command.env("ML_BIP448_TEST_CHECKPOINT", checkpoint);
    }

    Ok(command.output()?)
}

fn run_recovery_restart_child(
    wallet_name: &str,
    statechain_id: &str,
    fee_input: &str,
    change_address: &str,
    checkpoint: Option<&str>,
) -> Result<Output> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "--ignored",
            "--exact",
            "bip448_client_restart_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ML_BIP448_RESTART_CHILD", "1")
        .env("ML_BIP448_RESTART_WALLET", wallet_name)
        .env("ML_BIP448_RECOVERY_STATECHAIN", statechain_id)
        .env("ML_BIP448_RECOVERY_FEE_INPUT", fee_input)
        .env("ML_BIP448_RECOVERY_CHANGE_ADDRESS", change_address)
        .env("ML_NETWORK", "regtest")
        .env_remove("ML_BIP448_TEST_CHECKPOINT");
    if let Some(checkpoint) = checkpoint {
        command.env("ML_BIP448_TEST_CHECKPOINT", checkpoint);
    }
    Ok(command.output()?)
}

fn assert_child_status(output: &Output, expected: Option<i32>, context: &str) -> Result<()> {
    if output.status.code() == expected {
        return Ok(());
    }

    Err(anyhow!(
        "client process at {context} exited with {:?}, expected {expected:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    ))
}

fn assert_pending_matches_record(
    pending: &mercuryrustlib::sqlite_manager::Bip448PendingDepositSigning,
    record: &Bip448StatechainRecord,
) {
    assert_eq!(record.latest_state_number, 1);
    assert_eq!(record.latest_state.state_number, 1);
    assert_eq!(
        record.latest_state.signing_metadata.server_signature_count,
        1
    );
    assert_eq!(pending.wallet_name, record.wallet_name);
    assert_eq!(pending.statechain_id, record.statechain_id);
    assert_eq!(pending.funding_txid, record.funding_outpoint.txid);
    assert_eq!(pending.funding_vout, record.funding_outpoint.vout);
    assert_eq!(
        pending.funding_value_sats,
        record.funding_outpoint.value_sats
    );
    assert_eq!(pending.state_locktime, record.latest_state.state_locktime);
    assert_eq!(
        pending.update_template_hash,
        record.latest_state.update_template_hash
    );
    assert_eq!(
        pending.settlement_template_hash,
        record.latest_state.settlement_template_hash
    );
    assert_eq!(
        pending.signing_id,
        record.latest_state.signing_metadata.signing_id
    );
    assert_eq!(
        pending.client_public_nonce,
        record.latest_state.signing_metadata.client_public_nonce
    );
    assert_eq!(
        pending.blinding_factor,
        record.latest_state.signing_metadata.blinding_factor
    );
    if let Some(server_public_nonce) = &pending.server_public_nonce {
        assert_eq!(
            server_public_nonce,
            &record.latest_state.signing_metadata.server_public_nonce
        );
    }
}

async fn create_confirmed_bip448_deposit(
    client_config: &ClientConfig,
    wallet: &Wallet,
) -> Result<Bip448DepositFixture> {
    let deposit = fund_confirmed_bip448_deposit(client_config, wallet).await?;
    mercuryrustlib::coin_status::update_coins(client_config, &wallet.name).await?;

    Ok(deposit)
}

async fn fund_confirmed_bip448_deposit(
    client_config: &ClientConfig,
    wallet: &Wallet,
) -> Result<Bip448DepositFixture> {
    let token_response = mercuryrustlib::deposit::get_token(client_config).await?;
    let token_id = common::utils::handle_token_response(client_config, &token_response).await?;
    let deposit_address = mercuryrustlib::deposit::get_bip448_deposit_bitcoin_address(
        client_config,
        &wallet.name,
        &token_id,
        FUNDING_AMOUNT_SATS,
    )
    .await?;

    let _ = common::bitcoin_core::sendtoaddress(FUNDING_AMOUNT_SATS, &deposit_address.address)?;
    common::chain::wait_for_address_utxo(
        client_config,
        &deposit_address.address,
        FUNDING_AMOUNT_SATS,
    )
    .await?;
    common::bitcoin_core::mine_block()?;

    Ok(Bip448DepositFixture {
        statechain_id: deposit_address.statechain_id,
    })
}

fn confirmed_p2a_fee_inputs(count: usize) -> Result<Vec<Bip448CpfpFeeInput>> {
    let funded = (0..count)
        .map(|_| fund_p2a_fee_input())
        .collect::<Result<Vec<_>>>()?;
    common::bitcoin_core::mine_block()?;

    Ok(funded
        .into_iter()
        .map(|funding| Bip448CpfpFeeInput::keyless(funding.outpoint, funding.value_sats))
        .collect())
}

fn wallet_change_script() -> Result<ScriptBuf> {
    Ok(
        common::bitcoin_core::regtest_address(&common::bitcoin_core::getnewaddress()?)?
            .script_pubkey(),
    )
}

fn tx_from_hex(tx_hex: &str) -> Result<Transaction> {
    Ok(encode::deserialize(&hex::decode(tx_hex)?)?)
}

async fn assert_server_persistence_excludes_locktime(
    record: &Bip448StatechainRecord,
) -> Result<()> {
    let databases = [
        (
            std::env::var("MERCURY_TEST_DATABASE_URL").unwrap_or_else(|_| {
                "postgres://postgres:postgres@127.0.0.1:5432/mercury".to_string()
            }),
            &[
                "bip448_signature_data",
                "signing_nonce_leases",
                "statechain_signing_protocol",
            ][..],
        ),
        (
            std::env::var("LOCKBOX_TEST_DATABASE_URL").unwrap_or_else(|_| {
                "postgres://postgres:postgres@127.0.0.1:5433/enclave".to_string()
            }),
            &["bip448_nonce_state", "generated_public_key"][..],
        ),
    ];
    let forbidden = [
        "state_locktime",
        "locktime",
        "state_number",
        "template_hash",
        "random_offset",
        "stride",
    ];
    let forbidden_values = [
        record.latest_state.state_locktime.to_string(),
        record
            .latest_state
            .update_template_hash
            .to_ascii_lowercase(),
        record
            .latest_state
            .settlement_template_hash
            .to_ascii_lowercase(),
        record.latest_state.update_tx.to_ascii_lowercase(),
        record.latest_state.settlement_tx.to_ascii_lowercase(),
        record
            .latest_state
            .state_output_script_pubkey
            .to_ascii_lowercase(),
        record
            .latest_state
            .funding_update_script
            .to_ascii_lowercase(),
        record
            .latest_state
            .funding_update_control_block
            .to_ascii_lowercase(),
        record.latest_state.state_update_script.to_ascii_lowercase(),
        record
            .latest_state
            .state_update_control_block
            .to_ascii_lowercase(),
        record
            .latest_state
            .state_settlement_script
            .to_ascii_lowercase(),
        record
            .latest_state
            .state_settlement_control_block
            .to_ascii_lowercase(),
    ];

    for (database_url, tables) in databases {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await?;
        let columns = sqlx::query(
            "SELECT table_name, column_name FROM information_schema.columns \
             WHERE table_schema = 'public'",
        )
        .fetch_all(&pool)
        .await?;
        let mut audited_tables = HashSet::new();
        for row in columns {
            let table_name: String = row.get("table_name");
            if !tables.contains(&table_name.as_str()) {
                continue;
            }
            audited_tables.insert(table_name.clone());
            let column_name: String = row.get("column_name");
            assert!(
                !forbidden.iter().any(|name| column_name.contains(name)),
                "server-side table {table_name} exposes forbidden column {column_name}"
            );
        }
        assert_eq!(
            audited_tables.len(),
            tables.len(),
            "server-side audit did not find every expected table: {tables:?}"
        );

        let mut populated_rows = 0;
        for table_name in tables {
            let query = format!(
                "SELECT row_to_json(row_data)::text FROM {table_name} AS row_data \
                 WHERE statechain_id = $1"
            );
            let rows = sqlx::query_scalar::<_, String>(&query)
                .bind(&record.statechain_id)
                .fetch_all(&pool)
                .await?;
            populated_rows += rows.len();
            for row_json in rows {
                let row_json = row_json.to_ascii_lowercase();
                assert!(
                    !forbidden.iter().any(|name| row_json.contains(name)),
                    "server-side row in {table_name} exposed consensus metadata: {row_json}"
                );
                for forbidden_value in &forbidden_values {
                    assert!(
                        !row_json.contains(forbidden_value),
                        "server-side row in {table_name} exposed template value {forbidden_value}"
                    );
                }
            }
        }
        assert!(
            populated_rows > 0,
            "server-side audit queried no populated rows"
        );
        pool.close().await;
    }

    Ok(())
}

fn submit_package_success(package: &Bip448RecoveryPackage) -> Result<Value> {
    let response = common::bitcoin_core::submit_package(&[
        package.parent_tx.clone(),
        package.cpfp_child_tx.clone(),
    ])?;

    if !package_response_is_success(&response) {
        return Err(anyhow!("submitpackage did not accept package: {response}"));
    }

    Ok(response)
}

fn assert_package_rejected(package: &Bip448RecoveryPackage, context: &str) -> Result<()> {
    let response = common::bitcoin_core::submit_package(&[
        package.parent_tx.clone(),
        package.cpfp_child_tx.clone(),
    ])
    .with_context(|| format!("{context}: submitpackage invocation failed"))?;
    let package_msg = response
        .get("package_msg")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{context}: submitpackage omitted package_msg: {response}"))?;
    if package_msg == "success" {
        return Err(anyhow!(
            "{context} unexpectedly accepted by submitpackage: {response}"
        ));
    }

    common::bitcoin_core::assert_not_in_mempool(&package.parent_tx.txid())?;
    common::bitcoin_core::assert_not_in_mempool(&package.cpfp_child_tx.txid())?;

    Ok(())
}

fn assert_parent_only_rejected(parent_tx: &Transaction, context: &str) -> Result<()> {
    match common::bitcoin_core::broadcast_raw_transaction(parent_tx) {
        Ok(txid) => Err(anyhow!("{context} unexpectedly broadcast alone: {txid}")),
        Err(error) => {
            let error = error.to_string();
            if !error.contains("error code: -26") || !error.contains("min relay fee not met") {
                return Err(anyhow!(
                    "{context} broadcast failed for an unexpected reason: {error}"
                ));
            }
            common::bitcoin_core::assert_not_in_mempool(&parent_tx.txid())?;
            Ok(())
        }
    }
}

fn assert_committed_update_mutation_rejected(
    record: &Bip448StatechainRecord,
    fee_input: &Bip448CpfpFeeInput,
    change_script: ScriptBuf,
) -> Result<()> {
    let mut mutated = tx_from_hex(&record.latest_state.update_tx)?;
    mutated.output[0].value -= 1;
    let package = build_anchor_cpfp_package(
        &mutated,
        record.funding_outpoint.value_sats,
        1,
        &[fee_input.clone()],
        change_script,
        PACKAGE_FEERATE_SAT_PER_VBYTE,
    )?;

    assert_package_rejected(&package, "mutated BIP448 update package")
}

fn assert_committed_settlement_mutation_rejected(
    record: &Bip448StatechainRecord,
    fee_input: &Bip448CpfpFeeInput,
    change_script: ScriptBuf,
) -> Result<()> {
    let mut mutated = tx_from_hex(&record.latest_state.settlement_tx)?;
    mutated.output[0].value -= 1;
    let package = build_anchor_cpfp_package(
        &mutated,
        record
            .latest_state
            .value_schedule
            .settlement_input_value_sats,
        1,
        &[fee_input.clone()],
        change_script,
        PACKAGE_FEERATE_SAT_PER_VBYTE,
    )?;

    assert_package_rejected(&package, "mutated BIP448 settlement package")
}

fn assert_anchor_mutation_rejected(
    parent_tx: &Transaction,
    parent_input_value_sats: u64,
    fee_input: &Bip448CpfpFeeInput,
    change_script: ScriptBuf,
) -> Result<()> {
    let mut missing_anchor = parent_tx.clone();
    missing_anchor.output.pop();
    assert!(build_anchor_cpfp_package(
        &missing_anchor,
        parent_input_value_sats,
        1,
        &[fee_input.clone()],
        change_script.clone(),
        PACKAGE_FEERATE_SAT_PER_VBYTE,
    )
    .is_err());

    let mut mutated_anchor = parent_tx.clone();
    mutated_anchor.output[1].script_pubkey = change_script.clone();
    assert!(build_anchor_cpfp_package(
        &mutated_anchor,
        parent_input_value_sats,
        1,
        &[fee_input.clone()],
        change_script.clone(),
        PACKAGE_FEERATE_SAT_PER_VBYTE,
    )
    .is_err());

    let mut moved_anchor = parent_tx.clone();
    let replacement_anchor = moved_anchor.output[1].clone();
    moved_anchor.output[1] = TxOut {
        value: 0,
        script_pubkey: ScriptBuf::from_bytes(vec![0x6a]),
    };
    moved_anchor.output.push(replacement_anchor);
    let replacement_anchor_package = build_anchor_cpfp_package(
        &moved_anchor,
        parent_input_value_sats,
        2,
        &[fee_input.clone()],
        change_script,
        PACKAGE_FEERATE_SAT_PER_VBYTE,
    )?;
    assert_package_rejected(
        &replacement_anchor_package,
        "BIP448 parent with its committed anchor replaced and moved",
    )?;

    Ok(())
}

fn package_response_is_success(response: &Value) -> bool {
    response.get("package_msg").and_then(Value::as_str) == Some("success")
}
