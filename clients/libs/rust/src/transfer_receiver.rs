use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
};

use crate::{
    chain::ChainClient,
    client_config::ClientConfig,
    sqlite_manager::{get_wallet, insert_or_update_backup_txs, update_wallet},
    utils,
};
use anyhow::{anyhow, Ok, Result};
use bitcoin::{Address, Txid};
use chrono::Utc;
use mercurylib::{
    utils::{get_network, InfoConfig},
    wallet::{get_previous_outpoint, Activity, BackupTx, Coin, CoinStatus},
};
use reqwest::StatusCode;

#[path = "bip448_transfer_receiver.rs"]
pub(crate) mod bip448_transfer_receiver;

pub async fn new_transfer_address(
    client_config: &ClientConfig,
    wallet_name: &str,
) -> Result<String> {
    let wallet = get_wallet(&client_config.pool, &wallet_name).await?;

    let mut wallet = wallet.clone();

    let coin = wallet.get_new_coin()?;

    wallet.coins.push(coin.clone());

    update_wallet(&client_config.pool, &wallet).await?;

    Ok(coin.address)
}

pub struct TransferReceiveResult {
    pub is_there_batch_locked: bool,
    pub received_statechain_ids: Vec<String>,
}

pub struct DuplicatedCoinData {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub index: u32,
}

pub struct MessageResult {
    pub is_batch_locked: bool,
    pub statechain_id: Option<String>,
    pub duplicated_coins: Vec<DuplicatedCoinData>,
}

enum Bip448ReceiveOutcome {
    Legacy,
    Processed(MessageResult),
    AlreadyProcessed,
}

enum Bip448MessageDisposition {
    Legacy,
    Processed,
    AlreadyProcessed,
    Rejected,
}

fn handle_bip448_message_result(
    result: Result<Bip448ReceiveOutcome>,
    received_statechain_ids: &mut Vec<String>,
) -> Bip448MessageDisposition {
    match result {
        std::result::Result::Ok(Bip448ReceiveOutcome::Legacy) => Bip448MessageDisposition::Legacy,
        std::result::Result::Ok(Bip448ReceiveOutcome::Processed(message_result)) => {
            if let Some(statechain_id) = message_result.statechain_id {
                received_statechain_ids.push(statechain_id);
            }
            Bip448MessageDisposition::Processed
        }
        std::result::Result::Ok(Bip448ReceiveOutcome::AlreadyProcessed) => {
            Bip448MessageDisposition::AlreadyProcessed
        }
        std::result::Result::Err(error) => {
            println!("BIP448 processing error: {error}");
            Bip448MessageDisposition::Rejected
        }
    }
}

pub fn sort_coins_by_statechain(coins: &mut Vec<Coin>) {
    // Create a map to store the position of first occurrence of each statechain_id
    let mut first_positions: HashMap<String, usize> = HashMap::new();

    // Record the position of the first occurrence of each statechain_id
    for (idx, coin) in coins.iter().enumerate() {
        if let Some(id) = &coin.statechain_id {
            first_positions.entry(id.clone()).or_insert(idx);
        }
    }

    // Sort the vector maintaining original order of different statechain_ids
    coins.sort_by(|a, b| {
        match (&a.statechain_id, &b.statechain_id) {
            (None, None) => a.duplicate_index.cmp(&b.duplicate_index),
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (Some(_), None) => std::cmp::Ordering::Less,
            (Some(id_a), Some(id_b)) => {
                if id_a == id_b {
                    // Same statechain_id: sort by duplicate_index
                    a.duplicate_index.cmp(&b.duplicate_index)
                } else {
                    // Different statechain_ids: compare their first positions
                    first_positions[id_a].cmp(&first_positions[id_b])
                }
            }
        }
    });
}

pub async fn execute(
    client_config: &ClientConfig,
    wallet_name: &str,
) -> Result<TransferReceiveResult> {
    let mut wallet = get_wallet(&client_config.pool, &wallet_name).await?;

    let info_config = utils::info_config(&client_config).await.unwrap();

    let mut unique_auth_pubkeys: HashSet<String> = HashSet::new();

    for coin in wallet.coins.iter() {
        unique_auth_pubkeys.insert(coin.auth_pubkey.clone());
    }

    let mut enc_msgs_per_auth_pubkey: HashMap<String, Vec<String>> = HashMap::new();

    for auth_pubkey in unique_auth_pubkeys {
        let enc_messages = get_msg_addr(&auth_pubkey, &client_config).await?;
        if enc_messages.len() == 0 {
            continue;
        }

        enc_msgs_per_auth_pubkey.insert(auth_pubkey.clone(), enc_messages);
    }

    let mut is_there_batch_locked = false;

    let mut received_statechain_ids = Vec::<String>::new();

    let mut temp_coins = wallet.coins.clone();
    let mut temp_activities = wallet.activities.clone();

    let mut duplicated_coins: Vec<Coin> = Vec::new();

    let blockheight = client_config.chain_client.tip_height()?;

    for (key, values) in &enc_msgs_per_auth_pubkey {
        let auth_pubkey = key.clone();

        for enc_message in values {
            let coin: Option<&mut Coin> = temp_coins.iter_mut().find(|coin| {
                coin.auth_pubkey == auth_pubkey && coin.status == CoinStatus::INITIALISED
            });

            if coin.is_some() {
                let mut coin = coin.unwrap();

                let bip448_result = bip448_transfer_receiver::try_transfer_bip448_receiver(
                    client_config,
                    coin,
                    enc_message,
                    &wallet.network,
                    &wallet.name,
                    &mut temp_activities,
                )
                .await;
                match handle_bip448_message_result(
                    bip448_result,
                    &mut received_statechain_ids,
                ) {
                    Bip448MessageDisposition::Legacy => {}
                    Bip448MessageDisposition::Processed
                    | Bip448MessageDisposition::AlreadyProcessed
                    | Bip448MessageDisposition::Rejected => {
                        continue;
                    }
                }

                let is_msg_valid = validate_encrypted_message(
                    client_config,
                    &coin,
                    enc_message,
                    &wallet.network,
                    &info_config,
                    blockheight,
                )
                .await;

                if is_msg_valid.is_err() {
                    println!(
                        "Validation error: {}",
                        is_msg_valid.err().unwrap().to_string()
                    );
                    continue;
                }

                let message_result = process_encrypted_message(
                    client_config,
                    &mut coin,
                    enc_message,
                    &wallet.network,
                    &wallet.name,
                    &mut temp_activities,
                )
                .await;

                if message_result.is_err() {
                    println!(
                        "Processing error: {}",
                        message_result.err().unwrap().to_string()
                    );
                    continue;
                }

                let message_result = message_result.unwrap();

                if message_result.is_batch_locked {
                    is_there_batch_locked = true;
                }

                if message_result.statechain_id.is_some() {
                    received_statechain_ids.push(message_result.statechain_id.unwrap());
                }

                if message_result.duplicated_coins.len() > 0 {
                    assert!(!message_result.is_batch_locked);

                    for duplicated_coin_data in message_result.duplicated_coins {
                        let mut duplicated_coin = coin.clone();
                        duplicated_coin.status = CoinStatus::DUPLICATED;
                        duplicated_coin.utxo_txid = Some(duplicated_coin_data.txid);
                        duplicated_coin.utxo_vout = Some(duplicated_coin_data.vout);
                        duplicated_coin.amount = Some(duplicated_coin_data.amount as u32);
                        duplicated_coin.duplicate_index = duplicated_coin_data.index;
                        duplicated_coins.push(duplicated_coin);
                    }
                }
            } else {
                let new_coin = mercurylib::transfer::receiver::duplicate_coin_to_initialized_state(
                    &wallet,
                    &auth_pubkey,
                );

                if new_coin.is_err() {
                    println!("Error: {}", new_coin.err().unwrap().to_string());
                    continue;
                }

                let mut new_coin = new_coin.unwrap();

                let bip448_result = bip448_transfer_receiver::try_transfer_bip448_receiver(
                    client_config,
                    &mut new_coin,
                    enc_message,
                    &wallet.network,
                    &wallet.name,
                    &mut temp_activities,
                )
                .await;
                match handle_bip448_message_result(
                    bip448_result,
                    &mut received_statechain_ids,
                ) {
                    Bip448MessageDisposition::Legacy => {}
                    Bip448MessageDisposition::Processed => {
                        temp_coins.push(new_coin.clone());
                        continue;
                    }
                    Bip448MessageDisposition::AlreadyProcessed
                    | Bip448MessageDisposition::Rejected => continue,
                }

                let is_msg_valid = validate_encrypted_message(
                    client_config,
                    &new_coin,
                    enc_message,
                    &wallet.network,
                    &info_config,
                    blockheight,
                )
                .await;

                if is_msg_valid.is_err() {
                    println!(
                        "Validation error: {}",
                        is_msg_valid.err().unwrap().to_string()
                    );
                    continue;
                }

                let message_result = process_encrypted_message(
                    client_config,
                    &mut new_coin,
                    enc_message,
                    &wallet.network,
                    &wallet.name,
                    &mut temp_activities,
                )
                .await;

                if message_result.is_err() {
                    println!(
                        "Processing error: {}",
                        message_result.err().unwrap().to_string()
                    );
                    continue;
                }

                temp_coins.push(new_coin.clone());

                let message_result = message_result.unwrap();

                if message_result.is_batch_locked {
                    is_there_batch_locked = true;
                }

                if message_result.statechain_id.is_some() {
                    received_statechain_ids.push(message_result.statechain_id.unwrap());
                }

                if message_result.duplicated_coins.len() > 0 {
                    assert!(!message_result.is_batch_locked);

                    for duplicated_coin_data in message_result.duplicated_coins {
                        let mut duplicated_coin = new_coin.clone();
                        duplicated_coin.status = CoinStatus::DUPLICATED;
                        duplicated_coin.utxo_txid = Some(duplicated_coin_data.txid);
                        duplicated_coin.utxo_vout = Some(duplicated_coin_data.vout);
                        duplicated_coin.amount = Some(duplicated_coin_data.amount as u32);
                        duplicated_coin.duplicate_index = duplicated_coin_data.index;
                        // temp_coins.push(duplicated_coin);
                        duplicated_coins.push(duplicated_coin);
                    }
                }
            }
        }
    }

    temp_coins.extend(duplicated_coins);
    sort_coins_by_statechain(&mut temp_coins);
    wallet.coins = temp_coins.clone();
    wallet.activities = temp_activities.clone();

    update_wallet(&client_config.pool, &wallet).await?;

    Ok(TransferReceiveResult {
        is_there_batch_locked,
        received_statechain_ids,
    })
}

async fn get_msg_addr(auth_pubkey: &str, client_config: &ClientConfig) -> Result<Vec<String>> {
    let path = format!("transfer/get_msg_addr/{}", auth_pubkey.to_string());

    let client = client_config.get_reqwest_client()?;
    let request = client.get(&format!("{}/{}", client_config.statechain_entity, path));

    let value = request.send().await?.text().await?;

    let response: mercurylib::transfer::receiver::GetMsgAddrResponsePayload =
        serde_json::from_str(value.as_str())?;

    Ok(response.list_enc_transfer_msg)
}

pub fn split_backup_transactions(backup_transactions: &Vec<BackupTx>) -> Vec<Vec<BackupTx>> {
    // HashMap to store grouped transactions
    let mut grouped_txs: HashMap<(String, u32), Vec<BackupTx>> = HashMap::new();

    // Vector to keep track of order of appearance of outpoints
    let mut order_of_appearance: Vec<(String, u32)> = Vec::new();
    // HashSet to track which outpoints we've seen
    let mut seen_outpoints: HashSet<(String, u32)> = HashSet::new();

    // Process each transaction
    for tx in backup_transactions {
        // Get the outpoint for this transaction
        let outpoint = get_previous_outpoint(&tx).expect("Valid outpoint");

        // Create a key tuple from txid and vout
        let key = (outpoint.txid, outpoint.vout);

        // If we haven't seen this outpoint before, record its order
        if seen_outpoints.insert(key.clone()) {
            order_of_appearance.push(key.clone());
        }

        // Add the transaction to its group
        grouped_txs
            .entry(key)
            .or_insert_with(Vec::new)
            .push(tx.clone());
    }

    // Create result vector maintaining order of first appearance
    let mut result: Vec<Vec<BackupTx>> = Vec::with_capacity(order_of_appearance.len());

    // Add vectors to result in order of first appearance
    for key in order_of_appearance {
        if let Some(mut transactions) = grouped_txs.remove(&key) {
            // Sort each group by tx_n
            transactions.sort_by_key(|tx| tx.tx_n);
            result.push(transactions);
        }
    }

    result
}

async fn validate_encrypted_message(
    client_config: &ClientConfig,
    coin: &Coin,
    enc_message: &str,
    network: &str,
    info_config: &InfoConfig,
    blockheight: u32,
) -> Result<()> {
    let client_auth_key = coin.auth_privkey.clone();
    let new_user_pubkey = coin.user_pubkey.clone();

    let transfer_msg =
        mercurylib::transfer::receiver::decrypt_transfer_msg(enc_message, &client_auth_key)?;

    let grouped_backup_transactions = split_backup_transactions(&transfer_msg.backup_transactions);

    for (index, backup_transactions) in grouped_backup_transactions.iter().enumerate() {
        let tx0_outpoint = mercurylib::transfer::receiver::get_tx0_outpoint(backup_transactions)?;

        let tx0_hex = get_tx0(&client_config.chain_client, &tx0_outpoint.txid).await?;

        if index == 0 {
            let is_transfer_signature_valid =
                mercurylib::transfer::receiver::verify_transfer_signature(
                    &new_user_pubkey,
                    &tx0_outpoint,
                    &transfer_msg,
                )?;

            if !is_transfer_signature_valid {
                return Err(anyhow::anyhow!("Invalid transfer signature".to_string()));
            }
        }

        let statechain_info =
            utils::get_statechain_info(&transfer_msg.statechain_id, &client_config).await?;

        if statechain_info.is_none() {
            return Err(anyhow::anyhow!("Statechain info not found".to_string()));
        }

        let statechain_info = statechain_info.unwrap();

        let is_tx0_output_pubkey_valid =
            mercurylib::transfer::receiver::validate_tx0_output_pubkey(
                &statechain_info.enclave_public_key,
                &transfer_msg,
                &tx0_outpoint,
                &tx0_hex,
                network,
            )?;

        if !is_tx0_output_pubkey_valid {
            return Err(anyhow::anyhow!("Invalid tx0 output pubkey".to_string()));
        }

        let latest_backup_tx_pays_to_user_pubkey =
            mercurylib::transfer::receiver::verify_latest_backup_tx_pays_to_user_pubkey(
                &transfer_msg,
                &new_user_pubkey,
                network,
            )?;

        if !latest_backup_tx_pays_to_user_pubkey {
            return Err(anyhow::anyhow!(
                "Latest Backup Tx does not pay to the expected public key".to_string()
            ));
        }

        if statechain_info.num_sigs != transfer_msg.backup_transactions.len() as u32 {
            return Err(anyhow::anyhow!("num_sigs is not correct".to_string()));
        }

        let (is_tx0_output_unspent, _) = verify_tx0_output_is_unspent_and_confirmed(
            &client_config.chain_client,
            &tx0_outpoint,
            &tx0_hex,
            &network,
            client_config.confirmation_target,
        )
        .await?;

        if !is_tx0_output_unspent {
            return Err(anyhow::anyhow!(
                "tx0 output is spent or not confirmed".to_string()
            ));
        }

        let current_fee_rate_sats_per_byte =
            if info_config.fee_rate_sats_per_byte > client_config.max_fee_rate {
                client_config.max_fee_rate
            } else {
                info_config.fee_rate_sats_per_byte
            };

        let previous_lock_time = mercurylib::transfer::receiver::validate_signature_scheme(
            backup_transactions,
            &statechain_info,
            &tx0_hex,
            blockheight,
            client_config.fee_rate_tolerance,
            current_fee_rate_sats_per_byte,
            info_config.initlock,
            info_config.interval,
        );

        if previous_lock_time.is_err() {
            let error = previous_lock_time.err().unwrap();
            return Err(anyhow!(
                "Signature scheme validation failed. Error {}",
                error.to_string()
            ));
        }
    }

    Ok(())
}

async fn process_encrypted_message(
    client_config: &ClientConfig,
    coin: &mut Coin,
    enc_message: &str,
    network: &str,
    wallet_name: &str,
    activities: &mut Vec<Activity>,
) -> Result<MessageResult> {
    let mut transfer_receive_result = MessageResult {
        is_batch_locked: false,
        statechain_id: None,
        duplicated_coins: Vec::new(),
    };

    let client_auth_key = coin.auth_privkey.clone();

    let transfer_msg =
        mercurylib::transfer::receiver::decrypt_transfer_msg(enc_message, &client_auth_key)?;

    let grouped_backup_transactions = split_backup_transactions(&transfer_msg.backup_transactions);

    for (index, backup_transactions) in grouped_backup_transactions.iter().enumerate() {
        if index == 0 {
            let tx0_outpoint =
                mercurylib::transfer::receiver::get_tx0_outpoint(backup_transactions)?;
            let tx0_hex = get_tx0(&client_config.chain_client, &tx0_outpoint.txid).await?;

            let statechain_info =
                utils::get_statechain_info(&transfer_msg.statechain_id, &client_config).await?;
            let statechain_info = statechain_info.unwrap();

            let (_, tx0_status) = verify_tx0_output_is_unspent_and_confirmed(
                &client_config.chain_client,
                &tx0_outpoint,
                &tx0_hex,
                &network,
                client_config.confirmation_target,
            )
            .await?;

            let backup_tx = backup_transactions.last().unwrap();

            let last_tx_lock_time = mercurylib::utils::get_blockheight(&backup_tx)?;

            let transfer_receiver_request_payload =
                mercurylib::transfer::receiver::create_transfer_receiver_request_payload(
                    &statechain_info,
                    &transfer_msg,
                    &coin,
                )?;

            // unlock the statecoin - it might be part of a batch

            // the pub_auth_key has not been updated yet in the server (it will be updated after the transfer/receive call)
            // So we need to manually sign the statechain_id with the client_auth_key
            let signed_statechain_id_for_unlock =
                mercurylib::transfer::receiver::sign_message(&transfer_msg.statechain_id, &coin)?;

            unlock_statecoin(
                &client_config,
                &transfer_msg.statechain_id,
                &signed_statechain_id_for_unlock,
                &coin.auth_pubkey,
            )
            .await?;

            let transfer_receiver_result = send_transfer_receiver_request_payload(
                &client_config,
                &transfer_receiver_request_payload,
            )
            .await;

            let server_public_key_hex = match transfer_receiver_result {
                std::result::Result::Ok(server_public_key_hex) => {
                    if server_public_key_hex.is_batch_locked {
                        return Ok(MessageResult {
                            is_batch_locked: true,
                            statechain_id: None,
                            duplicated_coins: Vec::new(),
                        });
                    }

                    server_public_key_hex.server_pubkey.unwrap()
                }
                Err(err) => {
                    return Err(anyhow::anyhow!("Error: {}", err.to_string()));
                }
            };

            let new_key_info = mercurylib::transfer::receiver::get_new_key_info(
                &server_public_key_hex,
                &coin,
                &transfer_msg.statechain_id,
                &tx0_outpoint,
                &tx0_hex,
                network,
            )?;

            coin.server_pubkey = Some(server_public_key_hex);
            coin.aggregated_pubkey = Some(new_key_info.aggregate_pubkey);
            coin.aggregated_address = Some(new_key_info.aggregate_address);
            coin.statechain_id = Some(transfer_msg.statechain_id.clone());
            coin.signed_statechain_id = Some(new_key_info.signed_statechain_id.clone());
            coin.amount = Some(new_key_info.amount);
            coin.utxo_txid = Some(tx0_outpoint.txid.clone());
            coin.utxo_vout = Some(tx0_outpoint.vout);
            coin.locktime = Some(last_tx_lock_time);
            coin.status = tx0_status;

            let date = Utc::now(); // This will get the current date and time in UTC
            let iso_string = date.to_rfc3339(); // Converts the date to an ISO 8601 string

            let activity = Activity {
                utxo: tx0_outpoint.txid.clone(),
                amount: new_key_info.amount,
                action: "Receive".to_string(),
                date: iso_string,
            };

            activities.push(activity);

            insert_or_update_backup_txs(
                &client_config.pool,
                wallet_name,
                &transfer_msg.statechain_id,
                &transfer_msg.backup_transactions,
            )
            .await?;

            transfer_receive_result.is_batch_locked = false;
            transfer_receive_result.statechain_id = Some(transfer_msg.statechain_id.clone());
        } else {
            let tx0_outpoint =
                mercurylib::transfer::receiver::get_tx0_outpoint(backup_transactions)?;
            let tx0_hex = get_tx0(&client_config.chain_client, &tx0_outpoint.txid).await?;

            let first_backup_tx = backup_transactions.first().unwrap();

            let tx_outpoint = get_previous_outpoint(&first_backup_tx)?;

            let amount =
                mercurylib::transfer::receiver::get_amount_from_tx0(&tx0_hex, &tx_outpoint)?;

            transfer_receive_result
                .duplicated_coins
                .push(DuplicatedCoinData {
                    txid: tx_outpoint.txid,
                    vout: tx_outpoint.vout,
                    amount,
                    index: index as u32,
                });
        }
    }

    Ok(transfer_receive_result)
}

async fn get_tx0(chain_client: &ChainClient, tx0_txid: &str) -> Result<String> {
    let tx0_txid = Txid::from_str(tx0_txid)?;
    let tx_bytes = chain_client.get_raw_tx(&tx0_txid)?;
    let tx0_hex = hex::encode(&tx_bytes);

    Ok(tx0_hex)
}

async fn verify_tx0_output_is_unspent_and_confirmed(
    chain_client: &ChainClient,
    tx0_outpoint: &mercurylib::transfer::TxOutpoint,
    tx0_hex: &str,
    network: &str,
    confirmation_target: u32,
) -> Result<(bool, CoinStatus)> {
    let output_address = mercurylib::transfer::receiver::get_output_address_from_tx0(
        &tx0_outpoint,
        &tx0_hex,
        &network,
    )?;

    let network = get_network(&network)?;
    let address = Address::from_str(&output_address)?.require_network(network)?;
    let script = address.script_pubkey();
    let script = script.as_script();

    let res = chain_client.list_unspent(script)?;
    let blockheight = chain_client.tip_height()?;

    let mut status = CoinStatus::UNCONFIRMED;

    for unspent in res {
        if unspent.txid == tx0_outpoint.txid && unspent.vout == tx0_outpoint.vout {
            status = tx0_status_for_utxo_height(unspent.height, blockheight, confirmation_target);

            return Ok((true, status));
        }
    }

    Ok((false, status))
}

fn tx0_status_for_utxo_height(
    utxo_height: u32,
    blockheight: u32,
    confirmation_target: u32,
) -> CoinStatus {
    if utxo_height == 0 {
        return CoinStatus::UNCONFIRMED;
    }

    let confirmations = blockheight.saturating_sub(utxo_height).saturating_add(1);
    if confirmations >= confirmation_target {
        CoinStatus::CONFIRMED
    } else {
        CoinStatus::UNCONFIRMED
    }
}

async fn unlock_statecoin(
    client_config: &ClientConfig,
    statechain_id: &str,
    signed_statechain_id: &str,
    auth_pubkey: &str,
) -> Result<()> {
    let path = "transfer/unlock";

    let client = client_config.get_reqwest_client()?;
    let request = client.post(&format!("{}/{}", client_config.statechain_entity, path));

    let transfer_unlock_request_payload =
        mercurylib::transfer::receiver::TransferUnlockRequestPayload {
            statechain_id: statechain_id.to_string(),
            auth_sig: signed_statechain_id.to_string(),
            auth_pub_key: Some(auth_pubkey.to_string()),
        };

    let status = request
        .json(&transfer_unlock_request_payload)
        .send()
        .await?
        .status();

    if !status.is_success() {
        return Err(anyhow::anyhow!(
            "Failed to update transfer message".to_string()
        ));
    }

    Ok(())
}

pub struct TransferReceiveRequestResult {
    pub is_batch_locked: bool,
    pub server_pubkey: Option<String>,
}

async fn send_transfer_receiver_request_payload(
    client_config: &ClientConfig,
    transfer_receiver_request_payload: &mercurylib::transfer::receiver::TransferReceiverRequestPayload,
) -> Result<TransferReceiveRequestResult> {
    let path = "transfer/receiver";

    let client = client_config.get_reqwest_client()?;

    let request: reqwest::RequestBuilder =
        client.post(&format!("{}/{}", client_config.statechain_entity, path));

    let response = request
        .json(&transfer_receiver_request_payload)
        .send()
        .await?;

    let status = response.status();

    let value = response.text().await?;

    if status == StatusCode::BAD_REQUEST {
        let error: mercurylib::transfer::receiver::TransferReceiverErrorResponsePayload =
            serde_json::from_str(value.as_str())?;

        match error.code {
            mercurylib::transfer::receiver::TransferReceiverError::ExpiredBatchTimeError => {
                return Err(anyhow::anyhow!(error.message));
            }
            mercurylib::transfer::receiver::TransferReceiverError::StatecoinBatchLockedError => {
                return Ok(TransferReceiveRequestResult {
                    is_batch_locked: true,
                    server_pubkey: None,
                });
            }
        }
    }

    if status == StatusCode::OK {
        let response: mercurylib::transfer::receiver::TransferReceiverPostResponsePayload =
            serde_json::from_str(value.as_str())?;
        return Ok(TransferReceiveRequestResult {
            is_batch_locked: false,
            server_pubkey: Some(response.server_pubkey),
        });
    } else {
        return Err(anyhow::anyhow!(
            "{}: {}",
            "Failed to update transfer message".to_string(),
            value
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::{
        absolute, Address, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    };
    use mercurylib::wallet::Coin;

    #[test]
    fn bip448_message_error_does_not_discard_prior_success() {
        let mut received_statechain_ids = Vec::new();

        let success = handle_bip448_message_result(
            Ok(Bip448ReceiveOutcome::Processed(MessageResult {
                is_batch_locked: false,
                statechain_id: Some("accepted-statechain".to_string()),
                duplicated_coins: Vec::new(),
            })),
            &mut received_statechain_ids,
        );
        let failure = handle_bip448_message_result(
            Err(anyhow!("invalid later message")),
            &mut received_statechain_ids,
        );

        assert!(matches!(success, Bip448MessageDisposition::Processed));
        assert!(matches!(failure, Bip448MessageDisposition::Rejected));
        assert_eq!(received_statechain_ids, vec!["accepted-statechain"]);
    }

    #[test]
    fn completed_bip448_replay_does_not_report_or_mutate_a_new_result() {
        let mut received_statechain_ids = vec!["previously-accepted".to_string()];

        let disposition = handle_bip448_message_result(
            Ok(Bip448ReceiveOutcome::AlreadyProcessed),
            &mut received_statechain_ids,
        );

        assert!(matches!(
            disposition,
            Bip448MessageDisposition::AlreadyProcessed
        ));
        assert_eq!(received_statechain_ids, vec!["previously-accepted"]);
    }

    #[test]
    fn non_bip448_message_still_falls_through_to_legacy_processing() {
        let mut received_statechain_ids = Vec::new();

        let disposition = handle_bip448_message_result(
            Ok(Bip448ReceiveOutcome::Legacy),
            &mut received_statechain_ids,
        );

        assert!(matches!(disposition, Bip448MessageDisposition::Legacy));
        assert!(received_statechain_ids.is_empty());
    }

    fn sample_coin(statechain_id: Option<&str>, duplicate_index: u32) -> Coin {
        Coin {
            index: 0,
            user_privkey: "user-privkey".to_string(),
            user_pubkey: "0286c2d3c05e7f5a4fd8f7e7ba9b2a8df0b2c4d6db1f4dbd6c8d1f5b3eb8b9f7f2"
                .to_string(),
            auth_privkey: "auth-privkey".to_string(),
            auth_pubkey: "0294e1c5ec6ef6b1f4c24ad0c5f13f0a7f56d8796f1f8c6cb8e3c4b22a5d1d6f0b"
                .to_string(),
            derivation_path: "m/86h/0h/0h/0/0".to_string(),
            fingerprint: "deadbeef".to_string(),
            address: "address".to_string(),
            backup_address: "backup".to_string(),
            server_pubkey: None,
            aggregated_pubkey: None,
            aggregated_address: None,
            statechain_protocol: None,
            utxo_txid: None,
            utxo_vout: None,
            amount: None,
            statechain_id: statechain_id.map(|value| value.to_string()),
            signed_statechain_id: None,
            locktime: None,
            secret_nonce: None,
            public_nonce: None,
            blinding_factor: None,
            server_public_nonce: None,
            tx_cpfp: None,
            tx_withdraw: None,
            withdrawal_address: None,
            status: CoinStatus::INITIALISED,
            duplicate_index,
        }
    }

    fn sample_backup_tx(tx_n: u32, txid_byte: u8, vout: u32) -> BackupTx {
        let txid = Txid::from_str(&hex::encode([txid_byte; 32])).unwrap();
        let secp = Secp256k1::new();
        let backup_secret_key = SecretKey::from_slice(&[5u8; 32]).unwrap();
        let backup_address = Address::p2tr(
            &secp,
            backup_secret_key.public_key(&secp).x_only_public_key().0,
            None,
            bitcoin::Network::Regtest,
        );
        let tx = Transaction {
            version: 2,
            lock_time: absolute::LockTime::from_height(1_000 + tx_n).unwrap(),
            input: vec![TxIn {
                previous_output: OutPoint { txid, vout },
                script_sig: ScriptBuf::new(),
                sequence: Sequence(0),
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: 10_000,
                script_pubkey: backup_address.script_pubkey(),
            }],
        };

        BackupTx {
            tx_n,
            tx: hex::encode(bitcoin::consensus::encode::serialize(&tx)),
            client_public_nonce: String::new(),
            server_public_nonce: String::new(),
            client_public_key: String::new(),
            server_public_key: String::new(),
            blinding_factor: String::new(),
        }
    }

    #[test]
    fn sort_coins_by_statechain_preserves_group_order_and_sorts_duplicates() {
        let mut coins = vec![
            sample_coin(Some("b"), 2),
            sample_coin(None, 1),
            sample_coin(Some("a"), 3),
            sample_coin(Some("b"), 0),
            sample_coin(Some("a"), 1),
            sample_coin(None, 0),
        ];

        sort_coins_by_statechain(&mut coins);

        let statechain_and_duplicates = coins
            .iter()
            .map(|coin| (coin.statechain_id.clone(), coin.duplicate_index))
            .collect::<Vec<_>>();

        assert_eq!(
            statechain_and_duplicates,
            vec![
                (Some("b".to_string()), 0),
                (Some("b".to_string()), 2),
                (Some("a".to_string()), 1),
                (Some("a".to_string()), 3),
                (None, 0),
                (None, 1),
            ]
        );
    }

    #[test]
    fn split_backup_transactions_groups_by_outpoint_and_preserves_first_seen_order() {
        let backup_transactions = vec![
            sample_backup_tx(3, 0xaa, 1),
            sample_backup_tx(1, 0xbb, 2),
            sample_backup_tx(1, 0xaa, 1),
            sample_backup_tx(2, 0xbb, 2),
            sample_backup_tx(2, 0xaa, 1),
        ];

        let grouped = split_backup_transactions(&backup_transactions);
        let first_group_outpoint = get_previous_outpoint(&grouped[0][0]).unwrap();
        let second_group_outpoint = get_previous_outpoint(&grouped[1][0]).unwrap();

        assert_eq!(grouped.len(), 2);
        assert_eq!(
            grouped[0].iter().map(|tx| tx.tx_n).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(
            grouped[1].iter().map(|tx| tx.tx_n).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(first_group_outpoint.txid, hex::encode([0xaau8; 32]));
        assert_eq!(first_group_outpoint.vout, 1);
        assert_eq!(second_group_outpoint.txid, hex::encode([0xbbu8; 32]));
        assert_eq!(second_group_outpoint.vout, 2);
    }

    #[test]
    fn tx0_confirmation_status_never_treats_mempool_height_as_confirmed() {
        assert_eq!(
            tx0_status_for_utxo_height(0, 800_000, 2),
            CoinStatus::UNCONFIRMED
        );
        assert_eq!(
            tx0_status_for_utxo_height(0, 800_000, 0),
            CoinStatus::UNCONFIRMED
        );
    }

    #[test]
    fn tx0_confirmation_status_uses_confirmed_heights_only() {
        assert_eq!(
            tx0_status_for_utxo_height(800_000, 800_000, 2),
            CoinStatus::UNCONFIRMED
        );
        assert_eq!(
            tx0_status_for_utxo_height(799_999, 800_000, 2),
            CoinStatus::CONFIRMED
        );
    }
}
