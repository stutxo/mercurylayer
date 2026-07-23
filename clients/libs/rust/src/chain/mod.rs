mod core;

use std::str::FromStr;

use anyhow::Result;
use bitcoin::{BlockHash, Txid};
use serde_json::Value;

use self::core::CoreChainClient;
pub use self::core::{ChainTxOut, DescriptorActivity, ScanBlocksResult};
pub(crate) use self::core::{CoreRpcAuth, CoreRpcConfig};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainUtxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub height: u32,
}

pub struct ChainClient {
    core: CoreChainClient,
}

impl ChainClient {
    pub fn new(core_rpc_config: CoreRpcConfig) -> Result<Self> {
        Ok(Self {
            core: CoreChainClient::new(core_rpc_config)?,
        })
    }

    pub fn tip_height(&self) -> Result<u32> {
        self.core.tip_height()
    }

    pub fn median_time_past(&self) -> Result<u32> {
        self.core.median_time_past()
    }

    pub fn estimate_fee_sat_per_vbyte(&self, number_blocks: usize) -> Result<f64> {
        let fee_rate_btc_per_kb = self.core.estimate_fee_btc_per_kb(number_blocks)?;

        Ok(normalize_fee_rate_sats_per_byte(fee_rate_btc_per_kb))
    }

    pub fn get_tx_out(
        &self,
        txid: &Txid,
        vout: u32,
        include_mempool: bool,
    ) -> Result<Option<ChainTxOut>> {
        self.core.get_tx_out(txid, vout, include_mempool)
    }

    pub fn get_block_hash(&self, height: u32) -> Result<BlockHash> {
        self.core.get_block_hash(height)
    }

    pub(crate) fn get_stored_tx_out(
        &self,
        txid: &str,
        vout: u32,
        include_mempool: bool,
    ) -> Result<Option<ChainTxOut>> {
        let Ok(parsed) = Txid::from_str(txid) else {
            return Ok(None);
        };
        if parsed.to_string() != txid {
            return Ok(None);
        }

        self.get_tx_out(&parsed, vout, include_mempool)
    }

    pub fn scan_blocks(
        &self,
        descriptors: &[String],
        start_height: u32,
        stop_height: u32,
    ) -> Result<ScanBlocksResult> {
        self.core
            .scan_blocks(descriptors, start_height, stop_height)
    }

    pub fn descriptor_activity(
        &self,
        block_hashes: &[BlockHash],
        descriptors: &[String],
        include_mempool: bool,
    ) -> Result<Vec<DescriptorActivity>> {
        self.core
            .descriptor_activity(block_hashes, descriptors, include_mempool)
    }

    pub fn get_raw_tx(&self, txid: &Txid) -> Result<Vec<u8>> {
        self.core.get_raw_tx(txid)
    }

    pub fn broadcast_tx(&self, tx_bytes: &[u8]) -> Result<Txid> {
        self.core.broadcast_tx(tx_bytes)
    }

    pub fn submit_package(&self, txs: &[Vec<u8>]) -> Result<Value> {
        self.core.submit_package(txs)
    }
}

pub fn normalize_fee_rate_sats_per_byte(mut fee_rate_btc_per_kb: f64) -> f64 {
    if fee_rate_btc_per_kb <= 0.0 {
        fee_rate_btc_per_kb = 0.00001;
    }

    fee_rate_btc_per_kb * 100000.0
}

#[cfg(test)]
mod tests {
    use super::{normalize_fee_rate_sats_per_byte, ChainClient, CoreRpcAuth, CoreRpcConfig};

    #[test]
    fn normalize_fee_rate_uses_current_fallback_for_non_positive_estimates() {
        assert_eq!(normalize_fee_rate_sats_per_byte(0.0), 1.0);
        assert_eq!(normalize_fee_rate_sats_per_byte(-1.0), 1.0);
        assert_eq!(normalize_fee_rate_sats_per_byte(0.00002), 2.0);
    }

    #[test]
    fn malformed_and_noncanonical_stored_txids_are_soft_misses_before_rpc() {
        let client = ChainClient::new(CoreRpcConfig {
            url: "http://127.0.0.1:1".to_string(),
            auth: CoreRpcAuth::None,
        })
        .unwrap();

        for txid in ["not-a-txid".to_string(), "AA".repeat(32)] {
            assert_eq!(client.get_stored_tx_out(&txid, 0, true).unwrap(), None);
        }
    }
}
