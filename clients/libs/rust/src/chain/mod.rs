mod core;
mod explorer;

#[cfg(feature = "test-hooks")]
use parking_lot::Mutex;
use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use bitcoin::{BlockHash, Transaction, Txid};
use serde_json::Value;

pub use self::core::{ChainTransaction, ChainTxOut, DescriptorActivity, ScanBlocksResult};
pub(crate) use self::core::{CoreRpcAuth, CoreRpcConfig};
use self::{core::CoreChainClient, explorer::ExplorerChainClient};

#[cfg(feature = "test-hooks")]
static SCAN_BLOCKS_CALLS: Mutex<Vec<(u32, u32)>> = Mutex::new(Vec::new());

#[cfg(feature = "test-hooks")]
pub fn take_scan_blocks_calls() -> Vec<(u32, u32)> {
    std::mem::take(&mut *SCAN_BLOCKS_CALLS.lock())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainUtxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub height: u32,
}

enum ChainBackend {
    Core(CoreChainClient),
    Explorer(ExplorerChainClient),
}

pub struct ChainClient {
    backend: ChainBackend,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BroadcastTxStatus {
    Accepted { confirmations: u32 },
}

impl ChainClient {
    pub fn new(core_rpc_config: CoreRpcConfig) -> Result<Self> {
        Ok(Self {
            backend: ChainBackend::Core(CoreChainClient::new(core_rpc_config)?),
        })
    }

    pub fn new_explorer(url: String) -> Result<Self> {
        Ok(Self {
            backend: ChainBackend::Explorer(ExplorerChainClient::new(url)?),
        })
    }

    pub fn tip_height(&self) -> Result<u32> {
        match &self.backend {
            ChainBackend::Core(client) => client.tip_height(),
            ChainBackend::Explorer(client) => client.tip_height(),
        }
    }

    pub fn median_time_past(&self) -> Result<u32> {
        match &self.backend {
            ChainBackend::Core(client) => client.median_time_past(),
            ChainBackend::Explorer(client) => client.median_time_past(),
        }
    }

    pub fn estimate_fee_sat_per_vbyte(&self, number_blocks: usize) -> Result<f64> {
        match &self.backend {
            ChainBackend::Core(client) => Ok(normalize_fee_rate_sats_per_byte(
                client.estimate_fee_btc_per_kb(number_blocks)?,
            )),
            ChainBackend::Explorer(client) => client.estimate_fee_sat_per_vbyte(number_blocks),
        }
    }

    pub fn get_tx_out(
        &self,
        txid: &Txid,
        vout: u32,
        include_mempool: bool,
    ) -> Result<Option<ChainTxOut>> {
        match &self.backend {
            ChainBackend::Core(client) => client.get_tx_out(txid, vout, include_mempool),
            ChainBackend::Explorer(client) => client.get_tx_out(txid, vout, include_mempool),
        }
    }

    pub fn get_block_hash(&self, height: u32) -> Result<BlockHash> {
        match &self.backend {
            ChainBackend::Core(client) => client.get_block_hash(height),
            ChainBackend::Explorer(client) => client.get_block_hash(height),
        }
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
        #[cfg(feature = "test-hooks")]
        SCAN_BLOCKS_CALLS.lock().push((start_height, stop_height));
        match &self.backend {
            ChainBackend::Core(client) => {
                client.scan_blocks(descriptors, start_height, stop_height)
            }
            ChainBackend::Explorer(client) => {
                client.scan_blocks(descriptors, start_height, stop_height)
            }
        }
    }

    pub fn descriptor_activity(
        &self,
        block_hashes: &[BlockHash],
        descriptors: &[String],
        include_mempool: bool,
    ) -> Result<Vec<DescriptorActivity>> {
        match &self.backend {
            ChainBackend::Core(client) => {
                client.descriptor_activity(block_hashes, descriptors, include_mempool)
            }
            ChainBackend::Explorer(client) => {
                client.descriptor_activity(block_hashes, descriptors, include_mempool)
            }
        }
    }

    pub fn get_raw_tx(&self, txid: &Txid) -> Result<Vec<u8>> {
        match &self.backend {
            ChainBackend::Core(client) => client.get_raw_tx(txid),
            ChainBackend::Explorer(client) => client.get_raw_tx(txid),
        }
    }

    pub fn transaction_confirmations(&self, txid: &Txid) -> Result<Option<u32>> {
        match &self.backend {
            ChainBackend::Core(client) => client.transaction_confirmations(txid),
            ChainBackend::Explorer(client) => client.transaction_confirmations(txid),
        }
    }

    pub fn exact_transaction(&self, txid: &Txid) -> Result<Option<ChainTransaction>> {
        match &self.backend {
            ChainBackend::Core(client) => client.exact_transaction(txid),
            ChainBackend::Explorer(client) => client.exact_transaction(txid),
        }
    }

    pub fn broadcast_tx(&self, tx_bytes: &[u8]) -> Result<Txid> {
        match &self.backend {
            ChainBackend::Core(client) => client.broadcast_tx(tx_bytes),
            ChainBackend::Explorer(client) => client.broadcast_tx(tx_bytes),
        }
    }

    pub fn submit_package(&self, txs: &[Vec<u8>]) -> Result<Value> {
        match &self.backend {
            ChainBackend::Core(client) => client.submit_package(txs),
            ChainBackend::Explorer(client) => client.submit_package(txs),
        }
    }
}

/// Reconciles one immutable signed transaction without interpreting Bitcoin
/// Core's English error messages. A successful lookup is accepted only when
/// Core returns the exact persisted consensus bytes.
pub fn broadcast_or_reconcile_transaction(
    chain_client: &ChainClient,
    signed_tx_hex: &str,
    stored_txid: &str,
) -> Result<BroadcastTxStatus> {
    let bytes = hex::decode(signed_tx_hex).context("invalid persisted signed transaction hex")?;
    let transaction: Transaction = bitcoin::consensus::deserialize(&bytes)
        .context("invalid persisted signed transaction bytes")?;
    if bitcoin::consensus::serialize(&transaction) != bytes {
        return Err(anyhow!(
            "persisted signed transaction is not canonical consensus encoding"
        ));
    }
    let txid = Txid::from_str(stored_txid).context("invalid persisted signed transaction txid")?;
    if txid.to_string() != stored_txid || transaction.txid() != txid {
        return Err(anyhow!(
            "persisted signed transaction does not match its stored txid"
        ));
    }

    if let Some(known) = chain_client.exact_transaction(&txid)? {
        if known.bytes != bytes {
            return Err(anyhow!(
                "the stored txid resolves to different transaction bytes"
            ));
        }
        return Ok(BroadcastTxStatus::Accepted {
            confirmations: known.confirmations,
        });
    }

    match chain_client.broadcast_tx(&bytes) {
        Ok(returned_txid) if returned_txid == txid => {
            Ok(BroadcastTxStatus::Accepted { confirmations: 0 })
        }
        Ok(returned_txid) => Err(anyhow!(
            "Bitcoin Core accepted the persisted bytes as unexpected txid {} instead of {}",
            returned_txid,
            txid
        )),
        Err(send_error) => match chain_client.exact_transaction(&txid) {
            Ok(Some(known)) if known.bytes == bytes => Ok(BroadcastTxStatus::Accepted {
                confirmations: known.confirmations,
            }),
            Ok(Some(_)) => Err(send_error
                .context("post-broadcast lookup resolved the stored txid to different bytes")),
            Ok(None) | Err(_) => Err(send_error),
        },
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
    use bitcoin::{absolute, hashes::Hash, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    use serde_json::{json, Value};
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    fn sample_transaction(tag: u8) -> Transaction {
        Transaction {
            version: 2,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_byte_array([tag; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ZERO,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: 1_000,
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    }

    fn rpc_sequence(responses: Vec<String>) -> (ChainClient, thread::JoinHandle<Vec<Value>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let mut requests = Vec::new();
            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0; 32_768];
                let size = stream.read(&mut request).unwrap();
                let body = String::from_utf8_lossy(&request[..size]);
                let body = body.split_once("\r\n\r\n").unwrap().1;
                requests.push(serde_json::from_str(body).unwrap());
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response.len(),
                    response
                );
                stream.write_all(reply.as_bytes()).unwrap();
            }
            requests
        });
        (
            ChainClient::new(CoreRpcConfig {
                url,
                auth: CoreRpcAuth::None,
            })
            .unwrap(),
            server,
        )
    }

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

    #[test]
    fn exact_broadcast_reconciles_known_success_and_lost_response_without_text_matching() {
        let transaction = sample_transaction(7);
        let bytes = bitcoin::consensus::serialize(&transaction);
        let encoded = hex::encode(&bytes);
        let txid = transaction.txid().to_string();

        let (known_client, known_server) = rpc_sequence(vec![json!({
            "result": {"hex": encoded.clone(), "confirmations": 3}, "error": null
        })
        .to_string()]);
        let known =
            super::broadcast_or_reconcile_transaction(&known_client, &encoded, &txid).unwrap();
        assert_eq!(
            known,
            super::BroadcastTxStatus::Accepted { confirmations: 3 }
        );
        let requests = known_server.join().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["method"], "getrawtransaction");

        let (lost_client, lost_server) = rpc_sequence(vec![
            json!({"result": null, "error": {"code": -5, "message": "arbitrary missing text"}})
                .to_string(),
            json!({"result": null, "error": {"code": -26, "message": "arbitrary send text"}})
                .to_string(),
            json!({"result": {"hex": encoded.clone(), "confirmations": 0}, "error": null})
                .to_string(),
        ]);
        let reconciled =
            super::broadcast_or_reconcile_transaction(&lost_client, &encoded, &txid).unwrap();
        assert_eq!(
            reconciled,
            super::BroadcastTxStatus::Accepted { confirmations: 0 }
        );
        assert_eq!(
            lost_server
                .join()
                .unwrap()
                .iter()
                .map(|request| request["method"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec![
                "getrawtransaction",
                "sendrawtransaction",
                "getrawtransaction"
            ]
        );
    }

    #[test]
    fn exact_broadcast_preserves_send_error_and_rejects_different_bytes() {
        let transaction = sample_transaction(8);
        let different = sample_transaction(9);
        let encoded = hex::encode(bitcoin::consensus::serialize(&transaction));
        let txid = transaction.txid().to_string();

        let (failure_client, failure_server) = rpc_sequence(vec![
            json!({"result": null, "error": {"code": -5, "message": "first lookup"}})
                .to_string(),
            json!({"result": null, "error": {"code": -26, "message": "original contextual send failure"}})
                .to_string(),
            json!({"result": null, "error": {"code": -5, "message": "second lookup"}})
                .to_string(),
        ]);
        let error = super::broadcast_or_reconcile_transaction(&failure_client, &encoded, &txid)
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("original contextual send failure"));
        failure_server.join().unwrap();

        let (collision_client, collision_server) = rpc_sequence(vec![json!({
            "result": {"hex": hex::encode(bitcoin::consensus::serialize(&different))},
            "error": null
        })
        .to_string()]);
        assert!(
            super::broadcast_or_reconcile_transaction(&collision_client, &encoded, &txid).is_err()
        );
        collision_server.join().unwrap();
    }
}
