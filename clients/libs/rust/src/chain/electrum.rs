use anyhow::{anyhow, Result};
use bitcoin::{Script, Txid};
use electrum_client::ElectrumApi;

use super::ChainUtxo;

pub struct ElectrumChainClient {
    client: electrum_client::Client,
}

impl ElectrumChainClient {
    pub fn new(server: &str) -> Result<Self> {
        Ok(Self {
            client: electrum_client::Client::new(server)?,
        })
    }

    pub fn tip_height(&self) -> Result<u32> {
        Ok(self.client.block_headers_subscribe_raw()?.height as u32)
    }

    pub fn estimate_fee_btc_per_kb(&self, number_blocks: usize) -> Result<f64> {
        Ok(self.client.estimate_fee(number_blocks)?)
    }

    pub fn list_unspent(&self, script: &Script) -> Result<Vec<ChainUtxo>> {
        let utxos = self.client.script_list_unspent(script)?;

        Ok(utxos
            .into_iter()
            .map(|unspent| ChainUtxo {
                txid: unspent.tx_hash.to_string(),
                vout: unspent.tx_pos as u32,
                value: unspent.value,
                height: unspent.height as u32,
            })
            .collect())
    }

    pub fn get_raw_tx(&self, txid: &Txid) -> Result<Vec<u8>> {
        let txs = self
            .client
            .batch_transaction_get_raw(std::slice::from_ref(txid))?;

        txs.into_iter()
            .next()
            .ok_or_else(|| anyhow!("Transaction not found: {}", txid))
    }

    pub fn broadcast_tx(&self, tx_bytes: &[u8]) -> Result<Txid> {
        Ok(self.client.transaction_broadcast_raw(tx_bytes)?)
    }
}
