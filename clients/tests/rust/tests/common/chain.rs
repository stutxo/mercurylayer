use std::str::FromStr;

use anyhow::{anyhow, Result};
use bitcoin::{Address, OutPoint, Txid};
use mercuryrustlib::{chain::ChainUtxo, client_config::ClientConfig};
use tokio::time::{sleep, Duration};

const CHAIN_SYNC_TIMEOUT_SECONDS: u64 = 60;

pub async fn wait_for_address_utxo(
    client_config: &ClientConfig,
    address: &str,
    amount: u32,
) -> Result<()> {
    let amount = u64::from(amount);
    wait_for_address_utxo_matching(
        client_config,
        address,
        format!("address {address} with amount {amount}"),
        move |unspent| unspent.value == amount,
    )
    .await
}

pub async fn wait_for_address_outpoint(
    client_config: &ClientConfig,
    address: &str,
    outpoint: OutPoint,
    amount: u64,
) -> Result<()> {
    let expected_txid = outpoint.txid.to_string();
    let expected_vout = outpoint.vout;
    wait_for_address_utxo_matching(
        client_config,
        address,
        format!("address {address} with outpoint {outpoint} and amount {amount}"),
        move |unspent| {
            unspent.txid == expected_txid
                && unspent.vout == expected_vout
                && unspent.value == amount
        },
    )
    .await
}

async fn wait_for_address_utxo_matching(
    client_config: &ClientConfig,
    address: &str,
    expected_utxo: String,
    matches: impl Fn(&ChainUtxo) -> bool,
) -> Result<()> {
    let address = Address::from_str(address)?.require_network(client_config.network)?;
    let descriptor = format!("addr({address})");

    for _ in 0..CHAIN_SYNC_TIMEOUT_SECONDS {
        let stop_height = client_config.chain_client.tip_height()?;
        let scan = client_config
            .chain_client
            .scan_blocks(&descriptor, 0, stop_height)?;
        let activity = client_config.chain_client.descriptor_activity(
            &scan.relevant_blocks,
            &descriptor,
            true,
        )?;
        let utxo_list = mercuryrustlib::coin_status::unspent_from_descriptor_activity(activity);
        if utxo_list.iter().any(|unspent| matches(unspent)) {
            return Ok(());
        }

        sleep(Duration::from_secs(1)).await;
    }

    Err(anyhow!(
        "{} was not indexed by the configured chain backend within {} seconds",
        expected_utxo,
        CHAIN_SYNC_TIMEOUT_SECONDS
    ))
}

pub async fn get_blockheight(client_config: &ClientConfig) -> Result<u32> {
    client_config.chain_client.tip_height()
}

pub fn broadcast_raw_tx(client_config: &ClientConfig, tx_bytes: &[u8]) -> Result<Txid> {
    client_config.chain_client.broadcast_tx(tx_bytes)
}
