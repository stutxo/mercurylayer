use std::str::FromStr;

use anyhow::{Ok, Result};
use bitcoin::Address;
use mercuryrustlib::client_config::ClientConfig;

pub async fn check_address(
    client_config: &ClientConfig,
    address: &str,
    amount: u32,
) -> Result<bool> {
    let address = Address::from_str(address)?.require_network(client_config.network)?;

    let utxo_list = client_config
        .chain_client
        .list_unspent(address.script_pubkey().as_script())?;

    Ok(utxo_list.into_iter().any(|unspent| unspent.value == amount as u64))
}

pub async fn get_blockheight(client_config: &ClientConfig) -> Result<u32> {
    client_config.chain_client.tip_height()
}
