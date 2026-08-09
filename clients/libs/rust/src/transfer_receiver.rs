use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
};

use crate::{
    chain::ChainClient,
    client_config::ClientConfig,
    sqlite_manager::{get_wallet, update_wallet},
};
use anyhow::Result;
use bitcoin::{Address, Transaction, Txid};
use mercurylib::{
    error::MercuryError,
    utils::get_network,
    wallet::{Coin, CoinStatus},
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

enum Bip448ReceiveOutcome {
    Processed(String),
    BatchLocked,
    AlreadyProcessed,
}

enum Bip448MessageDisposition {
    Processed,
    BatchLocked,
    AlreadyProcessed,
    Rejected,
}

const EXPIRED_BATCH_TIME_ERROR: &str = "Batch time has expired";

fn handle_bip448_message_result(
    result: Result<Bip448ReceiveOutcome>,
    received_statechain_ids: &mut Vec<String>,
) -> Result<Bip448MessageDisposition> {
    match result {
        std::result::Result::Ok(Bip448ReceiveOutcome::Processed(statechain_id)) => {
            received_statechain_ids.push(statechain_id);
            Ok(Bip448MessageDisposition::Processed)
        }
        std::result::Result::Ok(Bip448ReceiveOutcome::BatchLocked) => {
            Ok(Bip448MessageDisposition::BatchLocked)
        }
        std::result::Result::Ok(Bip448ReceiveOutcome::AlreadyProcessed) => {
            Ok(Bip448MessageDisposition::AlreadyProcessed)
        }
        std::result::Result::Err(error) if error.to_string() == EXPIRED_BATCH_TIME_ERROR => {
            Err(error)
        }
        std::result::Result::Err(error) => {
            println!("BIP448 processing error: {error}");
            Ok(Bip448MessageDisposition::Rejected)
        }
    }
}

pub async fn execute(
    client_config: &ClientConfig,
    wallet_name: &str,
) -> Result<TransferReceiveResult> {
    let mut wallet = get_wallet(&client_config.pool, &wallet_name).await?;

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

    for (key, values) in &enc_msgs_per_auth_pubkey {
        let auth_pubkey = key.clone();

        for enc_message in values {
            let coin: Option<&mut Coin> = temp_coins.iter_mut().find(|coin| {
                coin.auth_pubkey == auth_pubkey && coin.status == CoinStatus::INITIALISED
            });

            if coin.is_some() {
                let coin = coin.unwrap();

                let bip448_result = bip448_transfer_receiver::try_transfer_bip448_receiver(
                    client_config,
                    coin,
                    enc_message,
                    &wallet.network,
                    &wallet.name,
                    &mut temp_activities,
                )
                .await;
                match handle_bip448_message_result(bip448_result, &mut received_statechain_ids)? {
                    Bip448MessageDisposition::BatchLocked => {
                        is_there_batch_locked = true;
                        continue;
                    }
                    Bip448MessageDisposition::Processed
                    | Bip448MessageDisposition::AlreadyProcessed
                    | Bip448MessageDisposition::Rejected => {
                        continue;
                    }
                }
            } else {
                let new_coin =
                    mercurylib::transfer::receiver::clone_transfer_address_coin_to_initialized_state(
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
                match handle_bip448_message_result(bip448_result, &mut received_statechain_ids)? {
                    Bip448MessageDisposition::BatchLocked => {
                        is_there_batch_locked = true;
                        continue;
                    }
                    Bip448MessageDisposition::Processed => {
                        temp_coins.push(new_coin.clone());
                        continue;
                    }
                    Bip448MessageDisposition::AlreadyProcessed
                    | Bip448MessageDisposition::Rejected => continue,
                }
            }
        }
    }

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
    let output_address = get_output_address_from_tx0(&tx0_outpoint, &tx0_hex, &network)?;

    let network = get_network(&network)?;
    let address = Address::from_str(&output_address)?.require_network(network)?;
    let script = address.script_pubkey();
    let script = script.as_script();

    let txid = Txid::from_str(&tx0_outpoint.txid)?;
    let Some(tx_out) = chain_client.get_tx_out(&txid, tx0_outpoint.vout, true)? else {
        return Ok((false, CoinStatus::UNCONFIRMED));
    };

    if tx_out.script_pubkey.as_script() != script {
        return Ok((false, CoinStatus::UNCONFIRMED));
    }

    Ok((
        true,
        tx0_status_for_confirmations(tx_out.confirmations, confirmation_target),
    ))
}

fn get_output_address_from_tx0(
    tx0_outpoint: &mercurylib::transfer::TxOutpoint,
    tx0_hex: &str,
    network: &str,
) -> std::result::Result<String, MercuryError> {
    let network = get_network(&network)?;

    let tx0: Transaction = bitcoin::consensus::encode::deserialize(&hex::decode(&tx0_hex)?)?;

    let tx0_output = tx0.output[tx0_outpoint.vout as usize].clone();

    let output_script_pubkey = tx0_output.script_pubkey;

    let address = Address::from_script(&output_script_pubkey.as_script(), network)?;

    Ok(address.to_string())
}

pub(crate) fn tx0_status_for_confirmations(
    confirmations: u32,
    confirmation_target: u32,
) -> CoinStatus {
    if confirmations == 0 {
        return CoinStatus::UNCONFIRMED;
    }

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
    use anyhow::anyhow;

    #[test]
    fn bip448_message_error_does_not_discard_prior_success() {
        let mut received_statechain_ids = Vec::new();

        let success = handle_bip448_message_result(
            Ok(Bip448ReceiveOutcome::Processed(
                "accepted-statechain".to_string(),
            )),
            &mut received_statechain_ids,
        )
        .unwrap();
        let failure = handle_bip448_message_result(
            Err(anyhow!("invalid later message")),
            &mut received_statechain_ids,
        )
        .unwrap();

        assert!(matches!(success, Bip448MessageDisposition::Processed));
        assert!(matches!(failure, Bip448MessageDisposition::Rejected));
        assert_eq!(received_statechain_ids, vec!["accepted-statechain"]);
    }

    #[test]
    fn bip448_expired_batch_error_propagates_exactly() {
        let mut received_statechain_ids = Vec::new();

        let result = handle_bip448_message_result(
            Err(anyhow!(EXPIRED_BATCH_TIME_ERROR)),
            &mut received_statechain_ids,
        );

        assert_eq!(result.err().unwrap().to_string(), EXPIRED_BATCH_TIME_ERROR);
        assert!(received_statechain_ids.is_empty());
    }

    #[test]
    fn completed_bip448_replay_does_not_report_or_mutate_a_new_result() {
        let mut received_statechain_ids = vec!["previously-accepted".to_string()];

        let disposition = handle_bip448_message_result(
            Ok(Bip448ReceiveOutcome::AlreadyProcessed),
            &mut received_statechain_ids,
        )
        .unwrap();

        assert!(matches!(
            disposition,
            Bip448MessageDisposition::AlreadyProcessed
        ));
        assert_eq!(received_statechain_ids, vec!["previously-accepted"]);
    }

    #[test]
    fn invalid_non_bip448_ciphertext_is_rejected_without_panic_or_id_mutation() {
        let mut received_statechain_ids = vec!["previously-accepted".to_string()];

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            handle_bip448_message_result(
                Err(anyhow!("invalid/non-BIP448 ciphertext")),
                &mut received_statechain_ids,
            )
        }));

        let disposition = result.expect("invalid ciphertext must not panic").unwrap();
        assert!(matches!(disposition, Bip448MessageDisposition::Rejected));
        assert_eq!(received_statechain_ids, vec!["previously-accepted"]);
    }

    #[test]
    fn tx0_confirmation_status_never_treats_mempool_as_confirmed() {
        assert_eq!(tx0_status_for_confirmations(0, 2), CoinStatus::UNCONFIRMED);
        assert_eq!(tx0_status_for_confirmations(0, 0), CoinStatus::UNCONFIRMED);
    }

    #[test]
    fn tx0_confirmation_status_uses_confirmation_count() {
        assert_eq!(tx0_status_for_confirmations(1, 2), CoinStatus::UNCONFIRMED);
        assert_eq!(tx0_status_for_confirmations(2, 2), CoinStatus::CONFIRMED);
    }

    #[test]
    fn tx0_output_address_maps_invalid_hex_to_mercury_error() {
        let tx0_outpoint = mercurylib::transfer::TxOutpoint {
            txid: "00".repeat(32),
            vout: 0,
        };

        let error = get_output_address_from_tx0(&tx0_outpoint, "not-hex", "regtest").unwrap_err();

        assert!(matches!(error, MercuryError::HexError));
    }

    #[test]
    fn tx0_output_address_maps_undecodable_transaction_to_mercury_error() {
        let tx0_outpoint = mercurylib::transfer::TxOutpoint {
            txid: "00".repeat(32),
            vout: 0,
        };

        let error = get_output_address_from_tx0(&tx0_outpoint, "00", "regtest").unwrap_err();

        assert!(matches!(error, MercuryError::BitcoinConsensusEncodeError));
    }

    #[test]
    fn tx0_output_address_maps_unrecognized_script_to_mercury_error() {
        let tx0 = Transaction {
            version: 2,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: vec![bitcoin::TxOut {
                value: 100_000,
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        let tx0_outpoint = mercurylib::transfer::TxOutpoint {
            txid: tx0.txid().to_string(),
            vout: 0,
        };
        let tx0_hex = hex::encode(bitcoin::consensus::encode::serialize(&tx0));

        let error = get_output_address_from_tx0(&tx0_outpoint, &tx0_hex, "regtest").unwrap_err();

        assert!(matches!(error, MercuryError::BitcoinAddressError));
    }

    #[tokio::test]
    async fn tx0_output_error_preserves_mercury_error_through_anyhow_boundary() {
        let chain_client = ChainClient::new(crate::chain::CoreRpcConfig {
            url: "http://127.0.0.1:1".to_string(),
            auth: crate::chain::CoreRpcAuth::None,
        })
        .unwrap();
        let tx0_outpoint = mercurylib::transfer::TxOutpoint {
            txid: "00".repeat(32),
            vout: 0,
        };

        let error = verify_tx0_output_is_unspent_and_confirmed(
            &chain_client,
            &tx0_outpoint,
            "not-hex",
            "regtest",
            1,
        )
        .await
        .unwrap_err();

        assert_eq!(error.to_string(), "HexError");
        assert!(matches!(
            error.downcast_ref::<MercuryError>(),
            Some(MercuryError::HexError)
        ));
    }

    #[test]
    fn tx0_output_address_is_derived_from_selected_output() -> Result<()> {
        let expected_address =
            Address::from_str("bcrt1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wq5jq7et")?
                .require_network(bitcoin::Network::Regtest)?;
        let tx0 = Transaction {
            version: 2,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: vec![
                bitcoin::TxOut {
                    value: 0,
                    script_pubkey: bitcoin::ScriptBuf::new(),
                },
                bitcoin::TxOut {
                    value: 100_000,
                    script_pubkey: expected_address.script_pubkey(),
                },
            ],
        };
        let tx0_outpoint = mercurylib::transfer::TxOutpoint {
            txid: tx0.txid().to_string(),
            vout: 1,
        };
        let tx0_hex = hex::encode(bitcoin::consensus::encode::serialize(&tx0));

        assert_eq!(
            get_output_address_from_tx0(&tx0_outpoint, &tx0_hex, "regtest")?,
            expected_address.to_string()
        );
        Ok(())
    }
}
