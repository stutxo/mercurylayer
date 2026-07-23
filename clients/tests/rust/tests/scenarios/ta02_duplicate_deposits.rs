use anyhow::{Ok, Result};
use bitcoin::Txid;
use mercuryrustlib::{client_config::ClientConfig, CoinStatus, Wallet};
use std::str::FromStr;

use crate::common::{bitcoin_core, chain, utils};

async fn withdraw_flow(
    client_config: &ClientConfig,
    wallet1: &Wallet,
    wallet2: &Wallet,
) -> Result<()> {
    let amount = 1000;

    let token_response = mercuryrustlib::deposit::get_token(client_config).await?;

    let token_id = utils::handle_token_response(client_config, &token_response).await?;

    let deposit_address = mercuryrustlib::deposit::get_deposit_bitcoin_address(
        &client_config,
        &wallet1.name,
        &token_id,
        amount,
    )
    .await?;

    let _ = bitcoin_core::sendtoaddress(amount, &deposit_address)?;

    let core_wallet_address = bitcoin_core::getnewaddress()?;
    let remaining_blocks = client_config.confirmation_target;
    let _ = bitcoin_core::generatetoaddress(remaining_blocks, &core_wallet_address)?;

    chain::wait_for_address_utxo(client_config, &deposit_address, amount).await?;

    mercuryrustlib::coin_status::update_coins(&client_config, &wallet1.name).await?;
    let wallet: mercuryrustlib::Wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet1.name).await?;
    let new_coin = wallet
        .coins
        .iter()
        .find(|&coin| coin.aggregated_address == Some(deposit_address.clone()))
        .unwrap();

    assert!(new_coin.status == CoinStatus::CONFIRMED);

    let amount = 2000;

    let _ = bitcoin_core::sendtoaddress(amount, &deposit_address)?;

    let _ = bitcoin_core::generatetoaddress(remaining_blocks, &core_wallet_address)?;

    chain::wait_for_address_utxo(client_config, &deposit_address, amount).await?;

    mercuryrustlib::coin_status::update_coins(&client_config, &wallet1.name).await?;
    let wallet1: mercuryrustlib::Wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet1.name).await?;

    let new_coin = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.status == CoinStatus::CONFIRMED
    });
    let duplicated_coin = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.status == CoinStatus::DUPLICATED
    });

    assert!(new_coin.is_some());
    assert!(duplicated_coin.is_some());

    let new_coin = new_coin.unwrap();
    let duplicated_coin = duplicated_coin.unwrap();

    assert!(new_coin.duplicate_index == 0);
    assert!(duplicated_coin.duplicate_index == 1);

    let statechain_id = new_coin.statechain_id.as_ref().unwrap();

    let wallet2_transfer_adress =
        mercuryrustlib::transfer_receiver::new_transfer_address(&client_config, &wallet2.name)
            .await?;

    let batch_id = None;

    let force_send = false;

    let result = mercuryrustlib::transfer_sender::execute(
        &client_config,
        &wallet2_transfer_adress,
        &wallet1.name,
        statechain_id,
        None,
        force_send,
        batch_id.clone(),
    )
    .await;

    assert!(result.is_err());

    let error_msg = result.err().unwrap().to_string();

    assert!(error_msg == "Coin is duplicated. If you want to proceed, use the command '--force, -f' option. \
        You will no longer be able to move other duplicate coins with the same statechain_id and this will cause PERMANENT LOSS of these duplicate coin funds.");

    let fee_rate = None;

    let result = mercuryrustlib::withdraw::execute(
        &client_config,
        &wallet1.name,
        statechain_id,
        &core_wallet_address,
        fee_rate,
        Some(1),
    )
    .await;

    assert!(result.is_ok());

    mercuryrustlib::coin_status::update_coins(&client_config, &wallet1.name).await?;

    let result = mercuryrustlib::transfer_sender::execute(
        &client_config,
        &wallet2_transfer_adress,
        &wallet1.name,
        statechain_id,
        None,
        force_send,
        batch_id,
    )
    .await;

    assert!(result.is_err());

    let error_msg = result.err().unwrap().to_string();

    assert!(error_msg == "There have been withdrawals of other coins with this same statechain_id (possibly duplicates).\
        This transfer cannot be performed because the recipient would reject it due to the difference in signature count.\
        This coin can be withdrawn, however.");

    let result = mercuryrustlib::withdraw::execute(
        &client_config,
        &wallet1.name,
        statechain_id,
        &core_wallet_address,
        fee_rate,
        None,
    )
    .await;

    assert!(result.is_ok());

    Ok(())
}

async fn transfer_flow(
    client_config: &ClientConfig,
    wallet1: &Wallet,
    wallet2: &Wallet,
) -> Result<()> {
    let amount = 1000;

    let token_response = mercuryrustlib::deposit::get_token(client_config).await?;

    let token_id = utils::handle_token_response(client_config, &token_response).await?;

    let deposit_address = mercuryrustlib::deposit::get_deposit_bitcoin_address(
        &client_config,
        &wallet1.name,
        &token_id,
        amount,
    )
    .await?;

    let _ = bitcoin_core::sendtoaddress(amount, &deposit_address)?;

    let core_wallet_address = bitcoin_core::getnewaddress()?;
    let remaining_blocks = client_config.confirmation_target;
    let _ = bitcoin_core::generatetoaddress(remaining_blocks, &core_wallet_address)?;

    chain::wait_for_address_utxo(client_config, &deposit_address, amount).await?;

    mercuryrustlib::coin_status::update_coins(&client_config, &wallet1.name).await?;
    let wallet: mercuryrustlib::Wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet1.name).await?;
    let new_coin = wallet
        .coins
        .iter()
        .find(|&coin| coin.aggregated_address == Some(deposit_address.clone()))
        .unwrap();

    assert!(new_coin.status == CoinStatus::CONFIRMED);

    let amount = 2000;

    let _ = bitcoin_core::sendtoaddress(amount, &deposit_address)?;

    let _ = bitcoin_core::generatetoaddress(remaining_blocks, &core_wallet_address)?;

    chain::wait_for_address_utxo(client_config, &deposit_address, amount).await?;

    mercuryrustlib::coin_status::update_coins(&client_config, &wallet1.name).await?;
    let wallet1: mercuryrustlib::Wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet1.name).await?;

    let new_coin = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.status == CoinStatus::CONFIRMED
    });
    let duplicated_coin = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.status == CoinStatus::DUPLICATED
    });

    assert!(new_coin.is_some());
    assert!(duplicated_coin.is_some());

    let new_coin = new_coin.unwrap();
    let duplicated_coin = duplicated_coin.unwrap();

    assert!(new_coin.duplicate_index == 0);
    assert!(duplicated_coin.duplicate_index == 1);

    let statechain_id = new_coin.statechain_id.as_ref().unwrap();

    let wallet2_transfer_adress =
        mercuryrustlib::transfer_receiver::new_transfer_address(&client_config, &wallet2.name)
            .await?;

    let batch_id = None;

    let force_send = true;

    let duplicated_index = duplicated_coin.duplicate_index;
    let noncanonical_txid = duplicated_coin.utxo_txid.as_ref().unwrap().to_uppercase();
    let mut stored_wallet = wallet1.clone();
    stored_wallet
        .coins
        .iter_mut()
        .find(|coin| coin.duplicate_index == duplicated_index)
        .unwrap()
        .utxo_txid = Some(noncanonical_txid);
    mercuryrustlib::sqlite_manager::update_wallet(&client_config.pool, &stored_wallet).await?;

    let result = mercuryrustlib::transfer_sender::execute(
        &client_config,
        &wallet2_transfer_adress,
        &wallet1.name,
        statechain_id,
        None,
        force_send,
        batch_id.clone(),
    )
    .await;

    assert!(result.is_ok());

    let transfer_receive_result =
        mercuryrustlib::transfer_receiver::execute(&client_config, &wallet2.name).await?;
    let received_statechain_ids = transfer_receive_result.received_statechain_ids;

    assert!(received_statechain_ids.contains(&statechain_id.to_string()));
    assert!(received_statechain_ids.len() == 1);

    mercuryrustlib::coin_status::update_coins(&client_config, &wallet1.name).await?;
    let wallet1: mercuryrustlib::Wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet1.name).await?;

    let transferred_coin = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.status == CoinStatus::TRANSFERRED
    });
    let duplicated_coin = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.status == CoinStatus::INVALIDATED
    });

    assert!(transferred_coin.is_some());
    assert!(duplicated_coin.is_some());

    let transferred_coin = transferred_coin.unwrap();
    let duplicated_coin = duplicated_coin.unwrap();

    assert!(transferred_coin.duplicate_index == 0);
    assert!(duplicated_coin.duplicate_index == 1);

    let fee_rate = None;

    let result = mercuryrustlib::withdraw::execute(
        &client_config,
        &wallet1.name,
        statechain_id,
        &core_wallet_address,
        fee_rate,
        Some(1),
    )
    .await;

    assert!(result.is_err());

    let error_msg = result.err().unwrap().to_string();

    // assert!(error_msg == "Signature does not match authentication key.");

    assert!(
        error_msg
            == "No duplicated coins associated with this statechain ID and index 1 were found"
    );

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires docker regtest stack"]
async fn ta02_duplicate_deposits() -> Result<()> {
    let _guard = crate::common::test_guard();
    let client_config = crate::common::prepare_test_env().await?;

    let wallet1 = mercuryrustlib::wallet::create_wallet("wallet1", &client_config).await?;

    mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, &wallet1).await?;

    let wallet2 = mercuryrustlib::wallet::create_wallet("wallet2", &client_config).await?;

    mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, &wallet2).await?;

    withdraw_flow(&client_config, &wallet1, &wallet2).await?;
    transfer_flow(&client_config, &wallet1, &wallet2).await?;

    println!("TA02 - Test \"Duplicate Deposits in the Same Adress\" completed successfully");

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires docker regtest stack"]
async fn ta02_mempool_primary_discovers_confirmed_duplicate() -> Result<()> {
    let _guard = crate::common::test_guard();
    let client_config = crate::common::prepare_test_env().await?;

    let wallet = mercuryrustlib::wallet::create_wallet("wallet1", &client_config).await?;
    mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, &wallet).await?;

    let amount = 1000;
    let token_response = mercuryrustlib::deposit::get_token(&client_config).await?;
    let token_id = utils::handle_token_response(&client_config, &token_response).await?;
    let deposit_address = mercuryrustlib::deposit::get_deposit_bitcoin_address(
        &client_config,
        &wallet.name,
        &token_id,
        amount,
    )
    .await?;
    let primary_txid = bitcoin_core::sendtoaddress(amount, &deposit_address)?;
    chain::wait_for_address_utxo(&client_config, &deposit_address, amount).await?;
    mercuryrustlib::coin_status::update_coins(&client_config, &wallet.name).await?;

    let wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet.name).await?;
    let primary_coin = wallet
        .coins
        .iter()
        .find(|coin| coin.utxo_txid.as_deref() == Some(primary_txid.as_str()))
        .unwrap();
    assert_eq!(primary_coin.status, CoinStatus::IN_MEMPOOL);
    let statechain_id = primary_coin.statechain_id.clone().unwrap();
    let primary_vout = primary_coin.utxo_vout.unwrap();

    let duplicate_amount = 2000;
    let duplicate_txid = bitcoin_core::sendtoaddress(duplicate_amount, &deposit_address)?;
    let duplicate_txid = Txid::from_str(&duplicate_txid)?;
    bitcoin_core::mine_block_with_transactions(&[duplicate_txid])?;
    bitcoin_core::mine_block_with_transactions(&[])?;
    bitcoin_core::mine_block_with_transactions(&[])?;

    let primary_txid = Txid::from_str(&primary_txid)?;
    let primary_output = client_config
        .chain_client
        .get_tx_out(&primary_txid, primary_vout, true)?
        .unwrap();
    assert_eq!(primary_output.confirmations, 0);

    mercuryrustlib::coin_status::update_coins(&client_config, &wallet.name).await?;
    let wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet.name).await?;
    let duplicate_txid_string = duplicate_txid.to_string();
    let duplicated_coin = wallet
        .coins
        .iter()
        .find(|coin| coin.utxo_txid.as_deref() == Some(duplicate_txid_string.as_str()))
        .unwrap();
    assert_eq!(duplicated_coin.status, CoinStatus::DUPLICATED);
    assert_eq!(duplicated_coin.duplicate_index, 1);
    let duplicate_vout = duplicated_coin.utxo_vout.unwrap();

    let withdrawal_address = bitcoin_core::getnewaddress()?;
    mercuryrustlib::withdraw::execute(
        &client_config,
        &wallet.name,
        &statechain_id,
        &withdrawal_address,
        None,
        Some(1),
    )
    .await?;
    assert!(client_config
        .chain_client
        .get_tx_out(&duplicate_txid, duplicate_vout, true)?
        .is_none());

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires docker regtest stack"]
async fn ta02_received_coin_preserves_pre_wallet_history() -> Result<()> {
    let _guard = crate::common::test_guard();
    let mut client_config = crate::common::prepare_test_env().await?;

    let wallet1 = mercuryrustlib::wallet::create_wallet("wallet1", &client_config).await?;
    mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, &wallet1).await?;

    let amount = 1000;
    let token_response = mercuryrustlib::deposit::get_token(&client_config).await?;
    let token_id = utils::handle_token_response(&client_config, &token_response).await?;
    let deposit_address = mercuryrustlib::deposit::get_deposit_bitcoin_address(
        &client_config,
        &wallet1.name,
        &token_id,
        amount,
    )
    .await?;
    let funding_txid = bitcoin_core::sendtoaddress(amount, &deposit_address)?;
    chain::wait_for_address_utxo(&client_config, &deposit_address, amount).await?;
    mercuryrustlib::coin_status::update_coins(&client_config, &wallet1.name).await?;

    let mining_address = bitcoin_core::getnewaddress()?;
    bitcoin_core::generatetoaddress(client_config.confirmation_target, &mining_address)?;
    mercuryrustlib::coin_status::update_coins(&client_config, &wallet1.name).await?;
    let wallet1 =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet1.name).await?;
    let funded_coin = wallet1
        .coins
        .iter()
        .find(|coin| coin.utxo_txid.as_deref() == Some(funding_txid.as_str()))
        .unwrap();
    assert_eq!(funded_coin.status, CoinStatus::CONFIRMED);
    let funding_vout = funded_coin.utxo_vout.unwrap();
    let statechain_id = funded_coin.statechain_id.clone().unwrap();

    let duplicate_amount = 2000;
    let duplicate_txid = bitcoin_core::sendtoaddress(duplicate_amount, &deposit_address)?;
    chain::wait_for_address_utxo(&client_config, &deposit_address, duplicate_amount).await?;
    bitcoin_core::generatetoaddress(2, &mining_address)?;

    let wallet2 = mercuryrustlib::wallet::create_wallet("wallet2", &client_config).await?;
    let wallet2_birth_height = wallet2.blockheight;
    mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, &wallet2).await?;
    let transfer_address =
        mercuryrustlib::transfer_receiver::new_transfer_address(&client_config, &wallet2.name)
            .await?;
    mercuryrustlib::transfer_sender::execute(
        &client_config,
        &transfer_address,
        &wallet1.name,
        &statechain_id,
        None,
        false,
        None,
    )
    .await?;

    let funding_txid = Txid::from_str(&funding_txid)?;
    let blockheight = client_config.chain_client.tip_height()?;
    let funding_output = client_config
        .chain_client
        .get_tx_out(&funding_txid, funding_vout, true)?
        .unwrap();
    let funding_height = blockheight - funding_output.confirmations + 1;
    assert!(funding_height < wallet2_birth_height);
    client_config.confirmation_target = funding_output.confirmations + 1;

    let transfer_result =
        mercuryrustlib::transfer_receiver::execute(&client_config, &wallet2.name).await?;
    assert!(transfer_result
        .received_statechain_ids
        .contains(&statechain_id));
    let wallet2 =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet2.name).await?;
    let received_coin = wallet2
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some(statechain_id.as_str()))
        .unwrap();
    assert_eq!(received_coin.status, CoinStatus::UNCONFIRMED);

    mercuryrustlib::coin_status::update_coins(&client_config, &wallet2.name).await?;
    let wallet2 =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet2.name).await?;
    let duplicated_coin = wallet2
        .coins
        .iter()
        .find(|coin| coin.utxo_txid.as_deref() == Some(duplicate_txid.as_str()))
        .unwrap();
    assert_eq!(duplicated_coin.status, CoinStatus::DUPLICATED);
    assert_eq!(duplicated_coin.duplicate_index, 1);
    let duplicate_vout = duplicated_coin.utxo_vout.unwrap();
    let duplicate_txid = Txid::from_str(&duplicate_txid)?;
    let duplicate_output = client_config
        .chain_client
        .get_tx_out(&duplicate_txid, duplicate_vout, true)?
        .unwrap();
    let blockheight = client_config.chain_client.tip_height()?;
    let duplicate_height = blockheight - duplicate_output.confirmations + 1;
    assert!(duplicate_height < wallet2_birth_height);

    bitcoin_core::generatetoaddress(1, &mining_address)?;
    mercuryrustlib::coin_status::update_coins(&client_config, &wallet2.name).await?;
    let wallet2 =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet2.name).await?;
    let received_coin = wallet2
        .coins
        .iter()
        .find(|coin| coin.duplicate_index == 0)
        .unwrap();
    assert_eq!(received_coin.status, CoinStatus::CONFIRMED);

    let second_duplicate_amount = 3000;
    let second_duplicate_txid =
        bitcoin_core::sendtoaddress(second_duplicate_amount, &deposit_address)?;
    chain::wait_for_address_utxo(&client_config, &deposit_address, second_duplicate_amount).await?;

    // Simulate losing the local wallet update after the primary withdrawal was broadcast.
    // Duplicate discovery must still run while the stale primary remains CONFIRMED locally.
    let stale_wallet = wallet2.clone();
    let primary_withdrawal_address = bitcoin_core::getnewaddress()?;
    mercuryrustlib::withdraw::execute(
        &client_config,
        &wallet2.name,
        &statechain_id,
        &primary_withdrawal_address,
        None,
        None,
    )
    .await?;
    assert!(client_config
        .chain_client
        .get_tx_out(&funding_txid, funding_vout, true)?
        .is_none());
    mercuryrustlib::sqlite_manager::update_wallet(&client_config.pool, &stale_wallet).await?;

    mercuryrustlib::coin_status::update_coins(&client_config, &wallet2.name).await?;
    let wallet2 =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet2.name).await?;
    let second_duplicated_coin = wallet2
        .coins
        .iter()
        .find(|coin| coin.utxo_txid.as_deref() == Some(second_duplicate_txid.as_str()))
        .unwrap();
    assert_eq!(second_duplicated_coin.status, CoinStatus::DUPLICATED);
    assert_eq!(second_duplicated_coin.duplicate_index, 2);
    let second_duplicate_vout = second_duplicated_coin.utxo_vout.unwrap();
    let second_duplicate_txid = Txid::from_str(&second_duplicate_txid)?;

    let withdrawal_address = bitcoin_core::getnewaddress()?;
    mercuryrustlib::withdraw::execute(
        &client_config,
        &wallet2.name,
        &statechain_id,
        &withdrawal_address,
        None,
        Some(1),
    )
    .await?;
    assert!(client_config
        .chain_client
        .get_tx_out(&duplicate_txid, duplicate_vout, true)?
        .is_none());
    mercuryrustlib::withdraw::execute(
        &client_config,
        &wallet2.name,
        &statechain_id,
        &withdrawal_address,
        None,
        Some(2),
    )
    .await?;
    assert!(client_config
        .chain_client
        .get_tx_out(&second_duplicate_txid, second_duplicate_vout, true)?
        .is_none());

    bitcoin_core::generatetoaddress(client_config.confirmation_target, &mining_address)?;
    mercuryrustlib::coin_status::update_coins(&client_config, &wallet2.name).await?;
    let wallet2 =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet2.name).await?;
    let duplicated_coin = wallet2
        .coins
        .iter()
        .find(|coin| coin.duplicate_index == 1)
        .unwrap();
    assert_eq!(duplicated_coin.status, CoinStatus::WITHDRAWN);
    let second_duplicated_coin = wallet2
        .coins
        .iter()
        .find(|coin| coin.duplicate_index == 2)
        .unwrap();
    assert_eq!(second_duplicated_coin.status, CoinStatus::WITHDRAWN);

    let third_duplicate_amount = 4000;
    let third_duplicate_txid =
        bitcoin_core::sendtoaddress(third_duplicate_amount, &deposit_address)?;
    chain::wait_for_address_utxo(&client_config, &deposit_address, third_duplicate_amount).await?;
    mercuryrustlib::coin_status::update_coins(&client_config, &wallet2.name).await?;
    let wallet2 =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet2.name).await?;
    let third_duplicated_coin = wallet2
        .coins
        .iter()
        .find(|coin| coin.utxo_txid.as_deref() == Some(third_duplicate_txid.as_str()))
        .unwrap();
    assert_eq!(third_duplicated_coin.status, CoinStatus::DUPLICATED);
    assert_eq!(third_duplicated_coin.duplicate_index, 3);

    Ok(())
}
