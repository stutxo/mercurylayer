use std::{thread, time::Duration};

use anyhow::{Ok, Result};
use mercuryrustlib::{client_config::ClientConfig, BackupTx, CoinStatus, Wallet};

use crate::common::{bitcoin_core, electrs, utils};

async fn deposit(
    amount_in_sats: u32,
    client_config: &ClientConfig,
    deposit_address: &str,
) -> Result<()> {
    let _ = bitcoin_core::sendtoaddress(amount_in_sats, &deposit_address)?;

    let core_wallet_address = bitcoin_core::getnewaddress()?;
    let remaining_blocks = client_config.confirmation_target;
    let _ = bitcoin_core::generatetoaddress(remaining_blocks, &core_wallet_address)?;

    // It appears that Electrs takes a few seconds to index the transaction
    let mut is_tx_indexed = false;

    while !is_tx_indexed {
        is_tx_indexed =
            electrs::check_address(client_config, &deposit_address, amount_in_sats).await?;
        thread::sleep(Duration::from_secs(1));
    }

    Ok(())
}

fn validate_backup_transactions(backup_transactions: &Vec<BackupTx>, interval: u32) -> Result<()> {
    let mut current_txid: Option<String> = None;
    let mut current_vout: Option<u32> = None;
    let mut current_tx_n = 0u32;
    let mut previous_lock_time = 0u32;

    for backup_tx in backup_transactions {
        let outpoint = mercuryrustlib::get_previous_outpoint(&backup_tx)?;

        let current_lock_time = mercuryrustlib::get_blockheight(&backup_tx)?;

        if current_txid.is_some() && current_vout.is_some() {
            assert!(
                current_txid.unwrap() == outpoint.txid && current_vout.unwrap() == outpoint.vout
            );
            assert!(current_lock_time == previous_lock_time - interval);
            assert!(backup_tx.tx_n > current_tx_n);
        }

        current_txid = Some(outpoint.txid);
        current_vout = Some(outpoint.vout);
        current_tx_n = backup_tx.tx_n;
        previous_lock_time = current_lock_time;
    }

    Ok(())
}

async fn basic_workflow(
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

    deposit(amount, &client_config, &deposit_address).await?;

    let amount = 2000;

    deposit(amount, &client_config, &deposit_address).await?;

    deposit(amount, &client_config, &deposit_address).await?;

    let amount = 1000;

    deposit(amount, &client_config, &deposit_address).await?;

    mercuryrustlib::coin_status::update_coins(&client_config, &wallet1.name).await?;
    let wallet1: mercuryrustlib::Wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet1.name).await?;

    let new_coin = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 0
            && coin.status == CoinStatus::CONFIRMED
    });
    let duplicated_coin_1 = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 1
            && coin.status == CoinStatus::DUPLICATED
    });
    let duplicated_coin_2 = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 2
            && coin.status == CoinStatus::DUPLICATED
    });
    let duplicated_coin_3 = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 3
            && coin.status == CoinStatus::DUPLICATED
    });

    assert!(new_coin.is_some());
    assert!(duplicated_coin_1.is_some());
    assert!(duplicated_coin_2.is_some());
    assert!(duplicated_coin_3.is_some());

    let new_coin = new_coin.unwrap();

    let statechain_id = new_coin.statechain_id.as_ref().unwrap();

    let wallet2_transfer_adress =
        mercuryrustlib::transfer_receiver::new_transfer_address(&client_config, &wallet2.name)
            .await?;

    let batch_id = None;

    let force_send = true;

    let duplicated_indexes = vec![1, 3];

    let result = mercuryrustlib::transfer_sender::execute(
        &client_config,
        &wallet2_transfer_adress,
        &wallet1.name,
        &statechain_id,
        Some(duplicated_indexes),
        force_send,
        batch_id,
    )
    .await;

    assert!(result.is_ok());

    let wallet1 =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet1.name).await?;

    let new_coin = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 0
            && coin.status == CoinStatus::IN_TRANSFER
    });
    let duplicated_coin_1 = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 1
            && coin.status == CoinStatus::IN_TRANSFER
    });
    let duplicated_coin_2 = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 2
            && coin.status == CoinStatus::DUPLICATED
    });
    let duplicated_coin_3 = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 3
            && coin.status == CoinStatus::IN_TRANSFER
    });

    assert!(new_coin.is_some());
    assert!(duplicated_coin_1.is_some());
    assert!(duplicated_coin_2.is_some());
    assert!(duplicated_coin_3.is_some());

    let new_coin = new_coin.unwrap();

    let backup_transactions = mercuryrustlib::sqlite_manager::get_backup_txs(
        &client_config.pool,
        &wallet1.name,
        &statechain_id,
    )
    .await?;

    /* for backup_tx in backup_transactions.iter() {
        let tx_outpoint = mercuryrustlib::get_previous_outpoint(&backup_tx)?;
        println!("statechain_id: {}", statechain_id);
        println!("txid: {} vout: {}", tx_outpoint.txid, tx_outpoint.vout);
        println!("tx_n: {}", backup_tx.tx_n);
        // println!("client_public_nonce: {}", backup_tx.client_public_nonce);
        // println!("server_public_nonce: {}", backup_tx.server_public_nonce);
        // println!("client_public_key: {}", backup_tx.client_public_key);
        // println!("server_public_key: {}", backup_tx.server_public_key);
        // println!("blinding_factor: {}", backup_tx.blinding_factor);
        println!("----------------------");
    } */

    let info_config = mercuryrustlib::utils::info_config(&client_config).await?;

    let split_backup_transactions =
        mercuryrustlib::transfer_receiver::split_backup_transactions(&backup_transactions);

    for (index, bk_txs) in split_backup_transactions.iter().enumerate() {
        if index == 0 {
            let first_bkp_tx = bk_txs.first().unwrap();
            let first_backup_outpoint = mercuryrustlib::get_previous_outpoint(&first_bkp_tx)?;
            assert!(
                first_backup_outpoint.txid == new_coin.utxo_txid.clone().unwrap()
                    && first_backup_outpoint.vout == new_coin.utxo_vout.unwrap()
            );
        }
        validate_backup_transactions(&bk_txs, info_config.interval)?;
    }

    let transfer_receive_result =
        mercuryrustlib::transfer_receiver::execute(&client_config, &wallet2.name).await?;

    let received_statechain_ids = transfer_receive_result.received_statechain_ids;

    assert!(received_statechain_ids.contains(&statechain_id.to_string()));
    assert!(received_statechain_ids.len() == 1);

    let wallet2: mercuryrustlib::Wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet2.name).await?;

    let w2_new_coin = wallet2.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 0
            && coin.status == CoinStatus::CONFIRMED
    });
    let w2_duplicated_coin_1 = wallet2.coins.iter().find(|&coin| {
        coin.statechain_id == Some(statechain_id.to_string())
            && coin.duplicate_index == 1
            && coin.status == CoinStatus::DUPLICATED
    });
    let w2_duplicated_coin_2 = wallet2.coins.iter().find(|&coin| {
        coin.statechain_id == Some(statechain_id.to_string())
            && coin.duplicate_index == 2
            && coin.status == CoinStatus::DUPLICATED
    });

    assert!(w2_new_coin.is_some());
    assert!(w2_duplicated_coin_1.is_some());
    assert!(w2_duplicated_coin_2.is_some());

    /* let mut coins_json = Vec::new();

    for coin in wallet2.coins.iter() {
        let obj = json!({
            "coin.user_pubkey": coin.user_pubkey,
            "coin.aggregated_address": coin.aggregated_address.as_ref().unwrap_or(&"".to_string()),
            "coin.address": coin.address,
            "coin.statechain_id": coin.statechain_id.as_ref().unwrap_or(&"".to_string()),
            "coin.amount": coin.amount.unwrap_or(0),
            "coin.status": coin.status,
            "coin.locktime": coin.locktime.unwrap_or(0),
            "coin.duplicate_index": coin.duplicate_index,
        });

        coins_json.push(obj);
    }

    let coins_json_string = serde_json::to_string_pretty(&coins_json).unwrap();
    println!("{}", coins_json_string); */

    mercuryrustlib::coin_status::update_coins(&client_config, &wallet1.name).await?;
    let wallet1: mercuryrustlib::Wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet1.name).await?;

    let new_coin = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 0
            && coin.status == CoinStatus::TRANSFERRED
    });
    let duplicated_coin_1 = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 1
            && coin.status == CoinStatus::TRANSFERRED
    });
    let duplicated_coin_2 = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 2
            && coin.status == CoinStatus::INVALIDATED
    });
    let duplicated_coin_3 = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 3
            && coin.status == CoinStatus::TRANSFERRED
    });

    assert!(new_coin.is_some());
    assert!(duplicated_coin_1.is_some());
    assert!(duplicated_coin_2.is_some());
    assert!(duplicated_coin_3.is_some());

    let core_wallet_address = bitcoin_core::getnewaddress()?;

    let fee_rate = None;

    let result = mercuryrustlib::withdraw::execute(
        &client_config,
        &wallet2.name,
        statechain_id,
        &core_wallet_address,
        fee_rate,
        Some(1),
    )
    .await;
    assert!(result.is_ok());

    let result = mercuryrustlib::withdraw::execute(
        &client_config,
        &wallet2.name,
        statechain_id,
        &core_wallet_address,
        fee_rate,
        Some(2),
    )
    .await;
    assert!(result.is_ok());

    let result = mercuryrustlib::withdraw::execute(
        &client_config,
        &wallet2.name,
        statechain_id,
        &core_wallet_address,
        fee_rate,
        None,
    )
    .await;
    assert!(result.is_ok());

    Ok(())
}

async fn resend_workflow(
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

    deposit(amount, &client_config, &deposit_address).await?;

    let amount = 2000;

    deposit(amount, &client_config, &deposit_address).await?;

    deposit(amount, &client_config, &deposit_address).await?;

    let amount = 1000;

    deposit(amount, &client_config, &deposit_address).await?;

    mercuryrustlib::coin_status::update_coins(&client_config, &wallet1.name).await?;
    let wallet1: mercuryrustlib::Wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet1.name).await?;

    let new_coin = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 0
            && coin.status == CoinStatus::CONFIRMED
    });
    let duplicated_coin_1 = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 1
            && coin.status == CoinStatus::DUPLICATED
    });
    let duplicated_coin_2 = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 2
            && coin.status == CoinStatus::DUPLICATED
    });
    let duplicated_coin_3 = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 3
            && coin.status == CoinStatus::DUPLICATED
    });

    assert!(new_coin.is_some());
    assert!(duplicated_coin_1.is_some());
    assert!(duplicated_coin_2.is_some());
    assert!(duplicated_coin_3.is_some());

    let new_coin = new_coin.unwrap();

    let statechain_id = new_coin.statechain_id.as_ref().unwrap();

    let wallet2_transfer_adress =
        mercuryrustlib::transfer_receiver::new_transfer_address(&client_config, &wallet2.name)
            .await?;

    let batch_id = None;

    let force_send = true;

    let duplicated_indexes = vec![1, 3];

    let result = mercuryrustlib::transfer_sender::execute(
        &client_config,
        &wallet2_transfer_adress,
        &wallet1.name,
        &statechain_id,
        Some(duplicated_indexes),
        force_send,
        batch_id,
    )
    .await;

    assert!(result.is_ok());

    let wallet1 =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet1.name).await?;

    let new_coin = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 0
            && coin.status == CoinStatus::IN_TRANSFER
    });
    let duplicated_coin_1 = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 1
            && coin.status == CoinStatus::IN_TRANSFER
    });
    let duplicated_coin_2 = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 2
            && coin.status == CoinStatus::DUPLICATED
    });
    let duplicated_coin_3 = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 3
            && coin.status == CoinStatus::IN_TRANSFER
    });

    assert!(new_coin.is_some());
    assert!(duplicated_coin_1.is_some());
    assert!(duplicated_coin_2.is_some());
    assert!(duplicated_coin_3.is_some());

    let batch_id = None;

    let duplicated_indexes = vec![2];

    let result = mercuryrustlib::transfer_sender::execute(
        &client_config,
        &wallet2_transfer_adress,
        &wallet1.name,
        &statechain_id,
        Some(duplicated_indexes),
        force_send,
        batch_id,
    )
    .await;

    assert!(result.is_ok());

    let wallet1 =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet1.name).await?;

    let new_coin = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 0
            && coin.status == CoinStatus::IN_TRANSFER
    });
    let duplicated_coin_1 = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 1
            && coin.status == CoinStatus::IN_TRANSFER
    });
    let duplicated_coin_2 = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 2
            && coin.status == CoinStatus::IN_TRANSFER
    });
    let duplicated_coin_3 = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 3
            && coin.status == CoinStatus::IN_TRANSFER
    });

    assert!(new_coin.is_some());
    assert!(duplicated_coin_1.is_some());
    assert!(duplicated_coin_2.is_some());
    assert!(duplicated_coin_3.is_some());

    let transfer_receive_result =
        mercuryrustlib::transfer_receiver::execute(&client_config, &wallet2.name).await?;

    let received_statechain_ids = transfer_receive_result.received_statechain_ids;

    assert!(received_statechain_ids.contains(&statechain_id.to_string()));
    assert!(received_statechain_ids.len() == 1);

    let wallet2: mercuryrustlib::Wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet2.name).await?;

    let w2_new_coin = wallet2.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 0
            && coin.status == CoinStatus::CONFIRMED
    });
    let w2_duplicated_coin_1 = wallet2.coins.iter().find(|&coin| {
        coin.statechain_id == Some(statechain_id.to_string())
            && coin.duplicate_index == 1
            && coin.status == CoinStatus::DUPLICATED
    });
    let w2_duplicated_coin_2 = wallet2.coins.iter().find(|&coin| {
        coin.statechain_id == Some(statechain_id.to_string())
            && coin.duplicate_index == 2
            && coin.status == CoinStatus::DUPLICATED
    });
    let w2_duplicated_coin_3 = wallet2.coins.iter().find(|&coin| {
        coin.statechain_id == Some(statechain_id.to_string())
            && coin.duplicate_index == 3
            && coin.status == CoinStatus::DUPLICATED
    });

    assert!(w2_new_coin.is_some());
    assert!(w2_duplicated_coin_1.is_some());
    assert!(w2_duplicated_coin_2.is_some());
    assert!(w2_duplicated_coin_3.is_some());

    let core_wallet_address = bitcoin_core::getnewaddress()?;

    let fee_rate = None;

    let result = mercuryrustlib::withdraw::execute(
        &client_config,
        &wallet2.name,
        statechain_id,
        &core_wallet_address,
        fee_rate,
        Some(1),
    )
    .await;
    assert!(result.is_ok());

    let result = mercuryrustlib::withdraw::execute(
        &client_config,
        &wallet2.name,
        statechain_id,
        &core_wallet_address,
        fee_rate,
        Some(2),
    )
    .await;
    assert!(result.is_ok());

    let result = mercuryrustlib::withdraw::execute(
        &client_config,
        &wallet2.name,
        statechain_id,
        &core_wallet_address,
        fee_rate,
        Some(3),
    )
    .await;
    assert!(result.is_ok());

    let result = mercuryrustlib::withdraw::execute(
        &client_config,
        &wallet2.name,
        statechain_id,
        &core_wallet_address,
        fee_rate,
        None,
    )
    .await;
    assert!(result.is_ok());

    Ok(())
}

async fn multiple_sends_workflow(
    client_config: &ClientConfig,
    wallet1: &Wallet,
    wallet2: &Wallet,
    wallet3: &Wallet,
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

    deposit(amount, &client_config, &deposit_address).await?;

    let amount = 2000;

    deposit(amount, &client_config, &deposit_address).await?;

    deposit(amount, &client_config, &deposit_address).await?;

    let amount = 1000;

    deposit(amount, &client_config, &deposit_address).await?;

    mercuryrustlib::coin_status::update_coins(&client_config, &wallet1.name).await?;
    let wallet1: mercuryrustlib::Wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet1.name).await?;

    let new_coin = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 0
            && coin.status == CoinStatus::CONFIRMED
    });
    let duplicated_coin_1 = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 1
            && coin.status == CoinStatus::DUPLICATED
    });
    let duplicated_coin_2 = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 2
            && coin.status == CoinStatus::DUPLICATED
    });
    let duplicated_coin_3 = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 3
            && coin.status == CoinStatus::DUPLICATED
    });

    assert!(new_coin.is_some());
    assert!(duplicated_coin_1.is_some());
    assert!(duplicated_coin_2.is_some());
    assert!(duplicated_coin_3.is_some());

    let new_coin = new_coin.unwrap();

    let statechain_id = new_coin.statechain_id.as_ref().unwrap();

    let wallet2_transfer_adress =
        mercuryrustlib::transfer_receiver::new_transfer_address(&client_config, &wallet2.name)
            .await?;

    let batch_id = None;

    let force_send = true;

    let duplicated_indexes = vec![1, 2, 3];

    let result = mercuryrustlib::transfer_sender::execute(
        &client_config,
        &wallet2_transfer_adress,
        &wallet1.name,
        &statechain_id,
        Some(duplicated_indexes),
        force_send,
        batch_id,
    )
    .await;

    assert!(result.is_ok());

    let wallet1 =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet1.name).await?;

    let new_coin = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 0
            && coin.status == CoinStatus::IN_TRANSFER
    });
    let duplicated_coin_1 = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 1
            && coin.status == CoinStatus::IN_TRANSFER
    });
    let duplicated_coin_2 = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 2
            && coin.status == CoinStatus::IN_TRANSFER
    });
    let duplicated_coin_3 = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 3
            && coin.status == CoinStatus::IN_TRANSFER
    });

    assert!(new_coin.is_some());
    assert!(duplicated_coin_1.is_some());
    assert!(duplicated_coin_2.is_some());
    assert!(duplicated_coin_3.is_some());

    let transfer_receive_result =
        mercuryrustlib::transfer_receiver::execute(&client_config, &wallet2.name).await?;

    let received_statechain_ids = transfer_receive_result.received_statechain_ids;

    assert!(received_statechain_ids.contains(&statechain_id.to_string()));
    assert!(received_statechain_ids.len() == 1);

    let wallet2: mercuryrustlib::Wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet2.name).await?;

    let w2_new_coin = wallet2.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 0
            && coin.status == CoinStatus::CONFIRMED
    });
    let w2_duplicated_coin_1 = wallet2.coins.iter().find(|&coin| {
        coin.statechain_id == Some(statechain_id.to_string())
            && coin.duplicate_index == 1
            && coin.status == CoinStatus::DUPLICATED
    });
    let w2_duplicated_coin_2 = wallet2.coins.iter().find(|&coin| {
        coin.statechain_id == Some(statechain_id.to_string())
            && coin.duplicate_index == 2
            && coin.status == CoinStatus::DUPLICATED
    });
    let w2_duplicated_coin_3 = wallet2.coins.iter().find(|&coin| {
        coin.statechain_id == Some(statechain_id.to_string())
            && coin.duplicate_index == 3
            && coin.status == CoinStatus::DUPLICATED
    });

    assert!(w2_new_coin.is_some());
    assert!(w2_duplicated_coin_1.is_some());
    assert!(w2_duplicated_coin_2.is_some());
    assert!(w2_duplicated_coin_3.is_some());

    let wallet3_transfer_adress =
        mercuryrustlib::transfer_receiver::new_transfer_address(&client_config, &wallet3.name)
            .await?;

    let batch_id = None;

    let force_send = true;

    let duplicated_indexes = vec![1, 2, 3];

    let result = mercuryrustlib::transfer_sender::execute(
        &client_config,
        &wallet3_transfer_adress,
        &wallet2.name,
        &statechain_id,
        Some(duplicated_indexes),
        force_send,
        batch_id,
    )
    .await;

    assert!(result.is_ok());

    let transfer_receive_result =
        mercuryrustlib::transfer_receiver::execute(&client_config, &wallet3.name).await?;

    let received_statechain_ids = transfer_receive_result.received_statechain_ids;

    assert!(received_statechain_ids.contains(&statechain_id.to_string()));
    assert!(received_statechain_ids.len() == 1);

    let wallet3: mercuryrustlib::Wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet3.name).await?;

    let w3_new_coin = wallet3.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 0
            && coin.status == CoinStatus::CONFIRMED
    });
    let w3_duplicated_coin_1 = wallet3.coins.iter().find(|&coin| {
        coin.statechain_id == Some(statechain_id.to_string())
            && coin.duplicate_index == 1
            && coin.status == CoinStatus::DUPLICATED
    });
    let w3_duplicated_coin_2 = wallet3.coins.iter().find(|&coin| {
        coin.statechain_id == Some(statechain_id.to_string())
            && coin.duplicate_index == 2
            && coin.status == CoinStatus::DUPLICATED
    });
    let w3_duplicated_coin_3 = wallet3.coins.iter().find(|&coin| {
        coin.statechain_id == Some(statechain_id.to_string())
            && coin.duplicate_index == 3
            && coin.status == CoinStatus::DUPLICATED
    });

    assert!(w3_new_coin.is_some());
    assert!(w3_duplicated_coin_1.is_some());
    assert!(w3_duplicated_coin_2.is_some());
    assert!(w3_duplicated_coin_3.is_some());

    let core_wallet_address = bitcoin_core::getnewaddress()?;

    let fee_rate = None;

    let result = mercuryrustlib::withdraw::execute(
        &client_config,
        &wallet3.name,
        statechain_id,
        &core_wallet_address,
        fee_rate,
        Some(3),
    )
    .await;
    assert!(result.is_ok());

    let wallet1_transfer_adress =
        mercuryrustlib::transfer_receiver::new_transfer_address(&client_config, &wallet1.name)
            .await?;

    let batch_id = None;

    let force_send = true;

    let duplicated_indexes = vec![1, 2, 3];

    let result = mercuryrustlib::transfer_sender::execute(
        &client_config,
        &wallet1_transfer_adress,
        &wallet3.name,
        &statechain_id,
        Some(duplicated_indexes),
        force_send,
        batch_id,
    )
    .await;

    assert!(result.is_err());

    assert!(result.err().unwrap().to_string().contains("There have been withdrawals of other coins with this same statechain_id (possibly duplicates).This transfer cannot be performed because the recipient would reject it due to the difference in signature count.This coin can be withdrawn, however."));

    Ok(())
}

async fn send_to_itself_workflow(
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

    deposit(amount, &client_config, &deposit_address).await?;

    let amount = 2000;

    deposit(amount, &client_config, &deposit_address).await?;

    deposit(amount, &client_config, &deposit_address).await?;

    let amount = 1000;

    deposit(amount, &client_config, &deposit_address).await?;

    mercuryrustlib::coin_status::update_coins(&client_config, &wallet1.name).await?;
    let wallet1: mercuryrustlib::Wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet1.name).await?;

    let new_coin = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 0
            && coin.status == CoinStatus::CONFIRMED
    });
    let duplicated_coin_1 = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 1
            && coin.status == CoinStatus::DUPLICATED
    });
    let duplicated_coin_2 = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 2
            && coin.status == CoinStatus::DUPLICATED
    });
    let duplicated_coin_3 = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 3
            && coin.status == CoinStatus::DUPLICATED
    });

    assert!(new_coin.is_some());
    assert!(duplicated_coin_1.is_some());
    assert!(duplicated_coin_2.is_some());
    assert!(duplicated_coin_3.is_some());

    let new_coin = new_coin.unwrap();

    let statechain_id = new_coin.statechain_id.as_ref().unwrap();

    let wallet1_transfer_adress =
        mercuryrustlib::transfer_receiver::new_transfer_address(&client_config, &wallet1.name)
            .await?;

    let batch_id = None;

    let force_send = true;

    let duplicated_indexes = vec![1, 3];

    let result = mercuryrustlib::transfer_sender::execute(
        &client_config,
        &wallet1_transfer_adress,
        &wallet1.name,
        &statechain_id,
        Some(duplicated_indexes),
        force_send,
        batch_id,
    )
    .await;

    assert!(result.is_ok());

    let transfer_receive_result =
        mercuryrustlib::transfer_receiver::execute(&client_config, &wallet1.name).await?;

    let received_statechain_ids = transfer_receive_result.received_statechain_ids;

    assert!(received_statechain_ids.contains(&statechain_id.to_string()));
    assert!(received_statechain_ids.len() == 1);

    mercuryrustlib::coin_status::update_coins(&client_config, &wallet1.name).await?;
    let wallet1: mercuryrustlib::Wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet1.name).await?;

    let transferred_coin_0 = wallet1.coins.iter().filter(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 0
            && coin.status == CoinStatus::TRANSFERRED
    });
    let transferred_coin_1 = wallet1.coins.iter().filter(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 1
            && coin.status == CoinStatus::TRANSFERRED
    });
    let invalidated_coin_2 = wallet1.coins.iter().filter(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 2
            && coin.status == CoinStatus::INVALIDATED
    });
    let transferred_coin_3 = wallet1.coins.iter().filter(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 3
            && coin.status == CoinStatus::TRANSFERRED
    });

    assert!(transferred_coin_0.count() == 1);
    assert!(transferred_coin_1.count() == 1);
    assert!(invalidated_coin_2.count() == 1);
    assert!(transferred_coin_3.count() == 1);

    let confirmed_coin_0 = wallet1.coins.iter().filter(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 0
            && coin.status == CoinStatus::CONFIRMED
    });
    let duplicated_coin_1 = wallet1.coins.iter().filter(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 1
            && coin.status == CoinStatus::DUPLICATED
    });
    let duplicated_coin_2 = wallet1.coins.iter().filter(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 2
            && coin.status == CoinStatus::DUPLICATED
    });

    assert!(confirmed_coin_0.count() == 1);
    assert!(duplicated_coin_1.count() == 1);
    assert!(duplicated_coin_2.count() == 1);

    // now send the coins to another wallet.

    let wallet2_transfer_adress =
        mercuryrustlib::transfer_receiver::new_transfer_address(&client_config, &wallet2.name)
            .await?;

    let batch_id = None;

    let force_send = true;

    let duplicated_indexes = vec![1, 2];

    let result = mercuryrustlib::transfer_sender::execute(
        &client_config,
        &wallet2_transfer_adress,
        &wallet1.name,
        &statechain_id,
        Some(duplicated_indexes),
        force_send,
        batch_id,
    )
    .await;

    assert!(result.is_ok());

    let wallet1: mercuryrustlib::Wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet1.name).await?;

    let new_coin = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 0
            && coin.status == CoinStatus::IN_TRANSFER
    });
    let duplicated_coin_1 = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 1
            && coin.status == CoinStatus::IN_TRANSFER
    });
    let duplicated_coin_2 = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 2
            && coin.status == CoinStatus::IN_TRANSFER
    });

    /* let mut coins_json = Vec::new();

    for coin in wallet1.coins.iter() {
        let obj = json!({
            "coin.user_pubkey": coin.user_pubkey,
            "coin.aggregated_address": coin.aggregated_address.as_ref().unwrap_or(&"".to_string()),
            "coin.address": coin.address,
            "coin.statechain_id": coin.statechain_id.as_ref().unwrap_or(&"".to_string()),
            "coin.amount": coin.amount.unwrap_or(0),
            "coin.status": coin.status,
            "coin.locktime": coin.locktime.unwrap_or(0),
            "coin.duplicate_index": coin.duplicate_index,
        });

        coins_json.push(obj);
    }

    let coins_json_string = serde_json::to_string_pretty(&coins_json).unwrap();
    println!("{}", coins_json_string); */

    assert!(new_coin.is_some());
    assert!(duplicated_coin_1.is_some());
    assert!(duplicated_coin_2.is_some());

    let transfer_receive_result =
        mercuryrustlib::transfer_receiver::execute(&client_config, &wallet2.name).await?;

    let received_statechain_ids = transfer_receive_result.received_statechain_ids;

    assert!(received_statechain_ids.contains(&statechain_id.to_string()));
    assert!(received_statechain_ids.len() == 1);

    let wallet2: mercuryrustlib::Wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet2.name).await?;

    let w2_new_coin = wallet2.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 0
            && coin.status == CoinStatus::CONFIRMED
    });
    let w2_duplicated_coin_1 = wallet2.coins.iter().find(|&coin| {
        coin.statechain_id == Some(statechain_id.to_string())
            && coin.duplicate_index == 1
            && coin.status == CoinStatus::DUPLICATED
    });
    let w2_duplicated_coin_2 = wallet2.coins.iter().find(|&coin| {
        coin.statechain_id == Some(statechain_id.to_string())
            && coin.duplicate_index == 2
            && coin.status == CoinStatus::DUPLICATED
    });

    assert!(w2_new_coin.is_some());
    assert!(w2_duplicated_coin_1.is_some());
    assert!(w2_duplicated_coin_2.is_some());

    let core_wallet_address = bitcoin_core::getnewaddress()?;

    let fee_rate = None;

    let result = mercuryrustlib::withdraw::execute(
        &client_config,
        &wallet2.name,
        statechain_id,
        &core_wallet_address,
        fee_rate,
        Some(1),
    )
    .await;
    assert!(result.is_ok());

    let result = mercuryrustlib::withdraw::execute(
        &client_config,
        &wallet2.name,
        statechain_id,
        &core_wallet_address,
        fee_rate,
        Some(2),
    )
    .await;
    assert!(result.is_ok());

    let result = mercuryrustlib::withdraw::execute(
        &client_config,
        &wallet2.name,
        statechain_id,
        &core_wallet_address,
        fee_rate,
        None,
    )
    .await;
    assert!(result.is_ok());

    Ok(())
}

async fn send_unconfirmed_duplicated_workflow(
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

    deposit(amount, &client_config, &deposit_address).await?;

    let amount = 1000;

    deposit(amount, &client_config, &deposit_address).await?;

    let amount = 2000;

    let _ = bitcoin_core::sendtoaddress(amount, &deposit_address)?;

    let mut is_tx_indexed = false;

    while !is_tx_indexed {
        is_tx_indexed = electrs::check_address(client_config, &deposit_address, amount).await?;
        thread::sleep(Duration::from_secs(1));
    }

    mercuryrustlib::coin_status::update_coins(&client_config, &wallet1.name).await?;
    let wallet1: mercuryrustlib::Wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet1.name).await?;

    let new_coin = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.duplicate_index == 0
            && coin.status == CoinStatus::CONFIRMED
    });
    let confirmed_duplicated_coin = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.status == CoinStatus::DUPLICATED
            && coin.amount == Some(1000)
    });
    let unconfirmed_duplicated_coin = wallet1.coins.iter().find(|&coin| {
        coin.aggregated_address == Some(deposit_address.clone())
            && coin.status == CoinStatus::DUPLICATED
            && coin.amount == Some(2000)
    });

    assert!(new_coin.is_some());
    assert!(confirmed_duplicated_coin.is_some());
    assert!(unconfirmed_duplicated_coin.is_some());

    let unconfirmed_duplicated_coin = unconfirmed_duplicated_coin.unwrap();

    let new_coin = new_coin.unwrap();

    let statechain_id = new_coin.statechain_id.as_ref().unwrap();

    let wallet2_transfer_adress =
        mercuryrustlib::transfer_receiver::new_transfer_address(&client_config, &wallet2.name)
            .await?;

    let batch_id = None;

    let force_send = true;

    let duplicated_indexes = vec![1, 2];

    // try to send the unconfirmed duplicated coin
    let result = mercuryrustlib::transfer_sender::execute(
        &client_config,
        &wallet2_transfer_adress,
        &wallet1.name,
        &statechain_id,
        Some(duplicated_indexes),
        force_send,
        batch_id,
    )
    .await;

    assert!(result.is_err());

    let error_message = result.err().unwrap().to_string();

    let expected_error_message = format!("The coin with duplicated index {} has not yet been confirmed. This transfer cannot be performed.", unconfirmed_duplicated_coin.duplicate_index);

    assert!(error_message.contains(expected_error_message.as_str()));

    let core_wallet_address = bitcoin_core::getnewaddress()?;
    let remaining_blocks = client_config.confirmation_target;
    let _ = bitcoin_core::generatetoaddress(remaining_blocks, &core_wallet_address)?;

    let batch_id = None;

    let duplicated_indexes = vec![1, 2];

    let result = mercuryrustlib::transfer_sender::execute(
        &client_config,
        &wallet2_transfer_adress,
        &wallet1.name,
        &statechain_id,
        Some(duplicated_indexes),
        force_send,
        batch_id,
    )
    .await;

    assert!(result.is_ok());

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires docker regtest stack"]
async fn ta03_multiple_deposits() -> Result<()> {
    let _guard = crate::common::test_guard();
    let client_config = crate::common::prepare_test_env().await?;

    let wallet1 = mercuryrustlib::wallet::create_wallet("wallet1", &client_config).await?;

    mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, &wallet1).await?;

    let wallet2 = mercuryrustlib::wallet::create_wallet("wallet2", &client_config).await?;

    mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, &wallet2).await?;

    basic_workflow(&client_config, &wallet1, &wallet2).await?;

    resend_workflow(&client_config, &wallet1, &wallet2).await?;

    let wallet3 = mercuryrustlib::wallet::create_wallet("wallet3", &client_config).await?;

    mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, &wallet3).await?;

    multiple_sends_workflow(&client_config, &wallet1, &wallet2, &wallet3).await?;

    send_to_itself_workflow(&client_config, &wallet1, &wallet2).await?;

    send_unconfirmed_duplicated_workflow(&client_config, &wallet1, &wallet2).await?;

    println!("TA03 - Test \"Multiple Deposits in the Same Adress\" completed successfully");

    Ok(())
}
