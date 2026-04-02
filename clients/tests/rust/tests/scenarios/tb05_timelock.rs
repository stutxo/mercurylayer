use std::{thread, time::Duration};

use anyhow::{Ok, Result};
use electrum_client::ElectrumApi;
use mercuryrustlib::{client_config::ClientConfig, CoinStatus, Wallet};

use crate::common::{bitcoin_core, electrs, utils};

pub async fn old_state_broadcasted(
    client_config: &ClientConfig,
    wallet1: &Wallet,
    wallet2: &Wallet,
) -> Result<()> {
    let amount = 1000;

    // Create first deposit address

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

    // It appears that Electrs takes a few seconds to index the transaction
    let mut is_tx_indexed = false;

    while !is_tx_indexed {
        is_tx_indexed = electrs::check_address(client_config, &deposit_address, amount).await?;
        thread::sleep(Duration::from_secs(1));
    }

    let wallet1_transfer_adress =
        mercuryrustlib::transfer_receiver::new_transfer_address(&client_config, &wallet1.name)
            .await?;

    mercuryrustlib::coin_status::update_coins(&client_config, &wallet1.name).await?;
    let wallet1: mercuryrustlib::Wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet1.name).await?;
    let new_coin = wallet1
        .coins
        .iter()
        .find(|&coin| {
            coin.aggregated_address == Some(deposit_address.clone())
                && coin.status == CoinStatus::CONFIRMED
        })
        .unwrap();
    let statechain_id_1 = new_coin.statechain_id.as_ref().unwrap();

    let force_send = false;

    let result = mercuryrustlib::transfer_sender::execute(
        &client_config,
        &wallet1_transfer_adress,
        &wallet1.name,
        &statechain_id_1.clone(),
        None,
        force_send,
        None,
    )
    .await;

    assert!(result.is_ok());

    let wallet2_transfer_adress =
        mercuryrustlib::transfer_receiver::new_transfer_address(&client_config, &wallet2.name)
            .await?;

    mercuryrustlib::coin_status::update_coins(&client_config, &wallet1.name).await?;
    let wallet1: mercuryrustlib::Wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet1.name).await?;

    let result = mercuryrustlib::transfer_sender::execute(
        &client_config,
        &wallet2_transfer_adress,
        &wallet1.name,
        &statechain_id_1.clone(),
        None,
        force_send,
        None,
    )
    .await;

    assert!(result.is_ok());

    let backup_transactions = mercuryrustlib::sqlite_manager::get_backup_txs(
        &client_config.pool,
        &wallet1.name,
        &statechain_id_1,
    )
    .await?;

    assert!(backup_transactions.len() == 3);

    let bkp_tx = backup_transactions.get(1).unwrap();

    assert!(bkp_tx.tx_n == 2);

    let tx_bytes = hex::decode(&bkp_tx.tx)?;
    let txid = client_config
        .electrum_client
        .transaction_broadcast_raw(&tx_bytes);

    assert!(txid.is_err());

    let tx_lock_time = mercuryrustlib::get_blockheight(&bkp_tx)?;

    let current_blockheight = electrs::get_blockheight(&client_config).await? as u32;

    let height_diff = tx_lock_time - current_blockheight;

    let _ = bitcoin_core::generatetoaddress(height_diff, &core_wallet_address)?;

    let txid = client_config
        .electrum_client
        .transaction_broadcast_raw(&tx_bytes);

    assert!(txid.is_ok());

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires docker regtest stack"]
async fn tb05_timelock() -> Result<()> {
    let _guard = crate::common::test_guard();
    let client_config = crate::common::prepare_test_env().await?;

    let wallet1 = mercuryrustlib::wallet::create_wallet("wallet1", &client_config).await?;

    mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, &wallet1).await?;

    let wallet2 = mercuryrustlib::wallet::create_wallet("wallet2", &client_config).await?;

    mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, &wallet2).await?;

    old_state_broadcasted(&client_config, &wallet1, &wallet2).await?;

    println!("TB05 - Timelock tests completed successfully");

    Ok(())
}
