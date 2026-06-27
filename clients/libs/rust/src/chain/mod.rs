mod core;

use anyhow::{anyhow, Result};
use bitcoin::{Script, Txid};

use self::core::CoreChainClient;
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
    pub fn new(chain_backend: &str, core_rpc_config: CoreRpcConfig) -> Result<Self> {
        match chain_backend {
            "core" => Ok(Self {
                core: CoreChainClient::new(core_rpc_config)?,
            }),
            "electrum" => Err(anyhow!(
                "Electrum backend is no longer supported; use chain_backend = \"core\""
            )),
            other => Err(anyhow!("Unsupported chain backend: {}", other)),
        }
    }

    pub fn tip_height(&self) -> Result<u32> {
        self.core.tip_height()
    }

    pub fn estimate_fee_sat_per_vbyte(&self, number_blocks: usize) -> Result<f64> {
        let fee_rate_btc_per_kb = self.core.estimate_fee_btc_per_kb(number_blocks)?;

        Ok(normalize_fee_rate_sats_per_byte(fee_rate_btc_per_kb))
    }

    pub fn list_unspent(&self, script: &Script) -> Result<Vec<ChainUtxo>> {
        self.core.list_unspent(script)
    }

    pub fn get_raw_tx(&self, txid: &Txid) -> Result<Vec<u8>> {
        self.core.get_raw_tx(txid)
    }

    pub fn broadcast_tx(&self, tx_bytes: &[u8]) -> Result<Txid> {
        self.core.broadcast_tx(tx_bytes)
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
    use super::normalize_fee_rate_sats_per_byte;

    #[test]
    fn normalize_fee_rate_uses_current_fallback_for_non_positive_estimates() {
        assert_eq!(normalize_fee_rate_sats_per_byte(0.0), 1.0);
        assert_eq!(normalize_fee_rate_sats_per_byte(-1.0), 1.0);
        assert_eq!(normalize_fee_rate_sats_per_byte(0.00002), 2.0);
    }
}
