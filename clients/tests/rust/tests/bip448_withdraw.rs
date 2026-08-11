mod common;

use std::str::FromStr;

use anyhow::{Context, Result};
use bitcoin::{Address, Txid};
use common::bip448_regtest::FUNDING_AMOUNT_SATS;
use mercuryrustlib::{client_config::ClientConfig, CoinStatus, Wallet};
use reqwest::StatusCode;

async fn assert_lockbox_state_absent(statechain_id: &str) -> Result<()> {
    let client = common::lockbox::http_client();
    let response =
        common::lockbox::get(&client, &format!("signature_count/{statechain_id}")).await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(response.text().await?, "Signature count not found.");
    Ok(())
}

async fn wallet(config: &ClientConfig, name: &str) -> Result<Wallet> {
    let wallet = mercuryrustlib::wallet::create_wallet(name, config).await?;
    mercuryrustlib::sqlite_manager::insert_wallet(&config.pool, &wallet).await?;
    Ok(wallet)
}

async fn deposit(config: &ClientConfig, wallet: &Wallet) -> Result<String> {
    let token = mercuryrustlib::deposit::get_token(config).await?;
    let token_id = common::utils::handle_token_response(config, &token).await?;
    let deposit = mercuryrustlib::deposit::get_bip448_deposit_bitcoin_address(
        config,
        &wallet.name,
        &token_id,
        FUNDING_AMOUNT_SATS,
    )
    .await?;
    common::bitcoin_core::sendtoaddress(FUNDING_AMOUNT_SATS, &deposit.address)?;
    common::chain::wait_for_address_utxo(config, &deposit.address, FUNDING_AMOUNT_SATS).await?;
    common::bitcoin_core::mine_blocks(config.confirmation_target)?;
    mercuryrustlib::coin_status::update_coins(config, &wallet.name).await?;
    Ok(deposit.statechain_id)
}

async fn transfer(
    config: &ClientConfig,
    sender: &Wallet,
    receiver: &Wallet,
    id: &str,
) -> Result<()> {
    let address =
        mercuryrustlib::transfer_receiver::new_transfer_address(config, &receiver.name).await?;
    mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender(
        config,
        &address,
        &sender.name,
        id,
        None,
    )
    .await?;
    let received = mercuryrustlib::transfer_receiver::execute(config, &receiver.name).await?;
    assert_eq!(received.received_statechain_ids, vec![id.to_string()]);
    Ok(())
}

async fn withdraw_and_confirm(config: &ClientConfig, wallet: &Wallet, id: &str) -> Result<()> {
    let destination = common::bitcoin_core::getnewaddress()?;
    let accepted_state_number =
        mercuryrustlib::sqlite_manager::get_bip448_statechain(&config.pool, &wallet.name, id)
            .await?
            .latest_state_number;
    let expected_count = accepted_state_number
        .checked_add(1)
        .context("canonical signature count overflow")?;
    std::env::set_var("ML_BIP448_WITHDRAW_STOP_AFTER_SIGNATURE", "1");
    let stopped =
        mercuryrustlib::bip448_withdraw::execute(config, &wallet.name, id, &destination, None)
            .await;
    std::env::remove_var("ML_BIP448_WITHDRAW_STOP_AFTER_SIGNATURE");
    assert_eq!(
        stopped.unwrap_err().to_string(),
        "BIP448 withdraw stopped after signature for test"
    );
    let signed_attempts = mercuryrustlib::sqlite_manager::list_bip448_withdrawal_attempts(
        &config.pool,
        &wallet.name,
        id,
    )
    .await?;
    assert_eq!(signed_attempts.len(), 1);
    assert_eq!(
        common::lockbox::get_signature_count(&common::lockbox::http_client(), id).await?,
        expected_count
    );
    mercuryrustlib::bip448_withdraw::execute(config, &wallet.name, id, &destination, None).await?;
    let stored = mercuryrustlib::sqlite_manager::get_wallet(&config.pool, &wallet.name).await?;
    let coin = stored
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some(id))
        .context("withdrawn coin is missing")?;
    assert_eq!(coin.status, CoinStatus::WITHDRAWING);
    let txid = Txid::from_str(
        coin.tx_withdraw
            .as_deref()
            .context("withdraw txid is missing")?,
    )?;
    let txid_text = txid.to_string();
    let attempts = mercuryrustlib::sqlite_manager::list_bip448_withdrawal_attempts(
        &config.pool,
        &wallet.name,
        id,
    )
    .await?;
    assert_eq!(attempts.len(), 1);
    let attempt = &attempts[0];
    assert_eq!(attempt.binding_index, 0);
    assert_eq!(
        attempt.attempt_kind,
        mercuryrustlib::bip448_funding::Bip448WithdrawalAttemptKind::Canonical
    );
    assert_eq!(
        attempt.phase,
        mercuryrustlib::bip448_funding::Bip448WithdrawalPhase::Signed
    );
    assert_eq!(
        attempt.completion_status,
        mercuryrustlib::bip448_funding::Bip448CompletionStatus::Closed
    );
    assert_eq!(attempt.txid.as_deref(), Some(txid_text.as_str()));
    let signing_id = attempt.signing_id.clone();
    let signed_tx_hex = attempt
        .signed_tx_hex
        .clone()
        .context("canonical signed bytes are missing")?;
    assert_eq!(
        stored
            .activities
            .iter()
            .filter(|activity| activity.utxo == txid_text)
            .count(),
        1
    );
    assert_lockbox_state_absent(id).await?;
    let output = config
        .chain_client
        .get_tx_out(&txid, 0, true)?
        .context("withdraw output is missing")?;
    assert_eq!(
        output.script_pubkey,
        Address::from_str(&destination)?
            .require_network(config.network)?
            .script_pubkey()
    );
    assert!(mercuryrustlib::utils::get_statechain_info(id, config)
        .await?
        .is_none());

    mercuryrustlib::bip448_withdraw::execute(config, &wallet.name, id, &destination, None).await?;
    let replayed_attempts = mercuryrustlib::sqlite_manager::list_bip448_withdrawal_attempts(
        &config.pool,
        &wallet.name,
        id,
    )
    .await?;
    assert_eq!(replayed_attempts.len(), 1);
    assert_eq!(replayed_attempts[0].signing_id, signing_id);
    assert_eq!(
        replayed_attempts[0].signed_tx_hex.as_deref(),
        Some(signed_tx_hex.as_str())
    );
    assert_eq!(
        replayed_attempts[0].completion_status,
        mercuryrustlib::bip448_funding::Bip448CompletionStatus::Closed
    );
    let replayed_wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&config.pool, &wallet.name).await?;
    assert_eq!(
        replayed_wallet
            .activities
            .iter()
            .filter(|activity| activity.utxo == txid_text)
            .count(),
        1
    );
    assert_lockbox_state_absent(id).await?;
    common::bitcoin_core::mine_blocks(config.confirmation_target)?;
    mercuryrustlib::coin_status::update_coins(config, &wallet.name).await?;
    let stored = mercuryrustlib::sqlite_manager::get_wallet(&config.pool, &wallet.name).await?;
    assert_eq!(
        stored
            .coins
            .iter()
            .find(|coin| coin.statechain_id.as_deref() == Some(id))
            .unwrap()
            .status,
        CoinStatus::WITHDRAWN
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_cooperative_withdrawal_closed_list() -> Result<()> {
    let _guard = common::test_guard();
    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury).await?;
    let lockbox = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox).await?;
    let config = common::prepare_test_env().await?;

    let state_one_owner = wallet(&config, "bip448-withdraw-state-one").await?;
    let state_one = deposit(&config, &state_one_owner).await?;
    withdraw_and_confirm(&config, &state_one_owner, &state_one).await?;

    let sender = wallet(&config, "bip448-withdraw-sender").await?;
    let receiver = wallet(&config, "bip448-withdraw-receiver").await?;
    let state_two = deposit(&config, &sender).await?;
    transfer(&config, &sender, &receiver, &state_two).await?;
    assert_eq!(
        mercuryrustlib::sqlite_manager::get_bip448_statechain(
            &config.pool,
            &receiver.name,
            &state_two
        )
        .await?
        .latest_state_number,
        2
    );
    withdraw_and_confirm(&config, &receiver, &state_two).await?;

    let committed = wallet(&config, "bip448-withdraw-committed").await?;
    let recipient = wallet(&config, "bip448-withdraw-commit-recipient").await?;
    let committed_id = deposit(&config, &committed).await?;
    let destination = common::bitcoin_core::getnewaddress()?;
    std::env::set_var("ML_BIP448_WITHDRAW_STOP_AFTER_SIGNATURE", "1");
    let stopped = mercuryrustlib::bip448_withdraw::execute(
        &config,
        &committed.name,
        &committed_id,
        &destination,
        None,
    )
    .await;
    std::env::remove_var("ML_BIP448_WITHDRAW_STOP_AFTER_SIGNATURE");
    assert_eq!(
        stopped.unwrap_err().to_string(),
        "BIP448 withdraw stopped after signature for test"
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox, &committed_id).await?,
        2
    );
    let recipient_address =
        mercuryrustlib::transfer_receiver::new_transfer_address(&config, &recipient.name).await?;
    let error = mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender(
        &config,
        &recipient_address,
        &committed.name,
        &committed_id,
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "BIP448 signature count does not match any supported transfer state"
    );
    Ok(())
}
