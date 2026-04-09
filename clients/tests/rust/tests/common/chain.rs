use std::str::FromStr;

use anyhow::{anyhow, Ok, Result};
use bitcoin::{Address, Txid};
use mercuryrustlib::client_config::ClientConfig;
use tokio::time::{sleep, Duration};

const CHAIN_SYNC_TIMEOUT_SECONDS: u64 = 60;

pub async fn check_address(
    client_config: &ClientConfig,
    address: &str,
    amount: u32,
) -> Result<bool> {
    let address = Address::from_str(address)?.require_network(client_config.network)?;

    let utxo_list = client_config
        .chain_client
        .list_unspent(address.script_pubkey().as_script())?;

    Ok(utxo_list
        .into_iter()
        .any(|unspent| unspent.value == amount as u64))
}

pub async fn wait_for_address_utxo(
    client_config: &ClientConfig,
    address: &str,
    amount: u32,
) -> Result<()> {
    for _ in 0..CHAIN_SYNC_TIMEOUT_SECONDS {
        if check_address(client_config, address, amount).await? {
            return Ok(());
        }

        sleep(Duration::from_secs(1)).await;
    }

    Err(anyhow!(
        "address {} with amount {} was not indexed by the configured chain backend within {} seconds",
        address,
        amount,
        CHAIN_SYNC_TIMEOUT_SECONDS
    ))
}

pub async fn get_blockheight(client_config: &ClientConfig) -> Result<u32> {
    client_config.chain_client.tip_height()
}

pub fn broadcast_raw_tx(client_config: &ClientConfig, tx_bytes: &[u8]) -> Result<Txid> {
    client_config.chain_client.broadcast_tx(tx_bytes)
}
