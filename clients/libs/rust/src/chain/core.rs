use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::path::PathBuf;
use std::thread;

use anyhow::{anyhow, Context, Result};
use bitcoin::{consensus::deserialize, Amount, Denomination, OutPoint, Script, Transaction, Txid};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::runtime::Builder;

use super::ChainUtxo;

#[derive(Clone, Debug)]
pub struct CoreRpcConfig {
    pub url: String,
    pub auth: CoreRpcAuth,
}

#[derive(Clone, Debug)]
pub enum CoreRpcAuth {
    None,
    UserPass { username: String, password: String },
    CookieFile(PathBuf),
}

pub struct CoreChainClient {
    client: reqwest::Client,
    config: CoreRpcConfig,
}

impl CoreChainClient {
    pub fn new(config: CoreRpcConfig) -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .build()
                .context("failed to build Bitcoin Core RPC client")?,
            config,
        })
    }

    pub fn tip_height(&self) -> Result<u32> {
        self.call("getblockcount", &[])
    }

    pub fn estimate_fee_btc_per_kb(&self, number_blocks: usize) -> Result<f64> {
        let response: EstimateSmartFeeResponse =
            self.call("estimatesmartfee", &[json!(number_blocks)])?;

        Ok(response.feerate.unwrap_or(0.0))
    }

    pub fn list_unspent(&self, script: &Script) -> Result<Vec<ChainUtxo>> {
        let descriptor = format!("raw({})", hex::encode(script.as_bytes()));
        let scan_response: ScanTxOutSetResponse =
            self.call("scantxoutset", &[json!("start"), json!([descriptor])])?;

        if !scan_response.success {
            return Err(anyhow!("Bitcoin Core scantxoutset returned success=false"));
        }

        let mut utxos = scan_response
            .unspents
            .into_iter()
            .map(|unspent| {
                (
                    OutPoint {
                        txid: unspent.txid,
                        vout: unspent.vout,
                    },
                    ChainUtxo {
                        txid: unspent.txid.to_string(),
                        vout: unspent.vout,
                        value: unspent.amount_sats,
                        height: unspent.height,
                    },
                )
            })
            .collect::<HashMap<_, _>>();

        let mempool_txids: Vec<Txid> = self.call("getrawmempool", &[])?;
        let mut mempool_spent_outpoints = HashSet::new();

        for txid in mempool_txids {
            let tx = self.get_transaction(&txid)?;

            for input in &tx.input {
                mempool_spent_outpoints.insert(input.previous_output);
            }

            for (vout, output) in tx.output.iter().enumerate() {
                if output.script_pubkey.as_script() == script {
                    utxos.insert(
                        OutPoint {
                            txid,
                            vout: vout as u32,
                        },
                        ChainUtxo {
                            txid: txid.to_string(),
                            vout: vout as u32,
                            value: output.value,
                            height: 0,
                        },
                    );
                }
            }
        }

        for spent_outpoint in mempool_spent_outpoints {
            utxos.remove(&spent_outpoint);
        }

        Ok(utxos.into_values().collect())
    }

    pub fn get_raw_tx(&self, txid: &Txid) -> Result<Vec<u8>> {
        let tx_hex: String = self.call("getrawtransaction", &[json!(txid), json!(false)])?;

        hex::decode(tx_hex).with_context(|| format!("failed to decode raw tx {}", txid))
    }

    pub fn broadcast_tx(&self, tx_bytes: &[u8]) -> Result<Txid> {
        let tx_hex = hex::encode(tx_bytes);
        let txid: Txid = self.call("sendrawtransaction", &[json!(tx_hex)])?;

        Ok(txid)
    }

    fn get_transaction(&self, txid: &Txid) -> Result<Transaction> {
        let raw_tx = self.get_raw_tx(txid)?;
        deserialize(&raw_tx).with_context(|| format!("failed to deserialize raw tx {}", txid))
    }

    fn call<T>(&self, method: &str, params: &[Value]) -> Result<T>
    where
        T: DeserializeOwned + Send,
    {
        self.run_async(async {
            let response = self
                .apply_auth(self.client.post(&self.config.url).json(&json!({
                    "jsonrpc": "1.0",
                    "id": "mercury-client",
                    "method": method,
                    "params": params,
                })))?
                .send()
                .await
                .with_context(|| format!("Bitcoin Core RPC {} request failed", method))?;

            let status = response.status();
            let body = response.text().await.with_context(|| {
                format!("Bitcoin Core RPC {} failed to read response body", method)
            })?;

            if !status.is_success() {
                return Err(anyhow!(
                    "Bitcoin Core RPC {} failed with status {} and body {}",
                    method,
                    status,
                    body
                ));
            }

            let rpc_response: RpcResponse<T> = serde_json::from_str(&body).with_context(|| {
                format!(
                    "Bitcoin Core RPC {} returned invalid JSON response {}",
                    method, body
                )
            })?;

            if let Some(error) = rpc_response.error {
                return Err(anyhow!(
                    "Bitcoin Core RPC {} failed with code {}: {}",
                    method,
                    error.code,
                    error.message
                ));
            }

            rpc_response
                .result
                .ok_or_else(|| anyhow!("Bitcoin Core RPC {} returned no result", method))
        })
    }

    fn apply_auth(&self, request: reqwest::RequestBuilder) -> Result<reqwest::RequestBuilder> {
        match &self.config.auth {
            CoreRpcAuth::None => Ok(request),
            CoreRpcAuth::UserPass { username, password } => {
                Ok(request.basic_auth(username, Some(password)))
            }
            CoreRpcAuth::CookieFile(path) => {
                let cookie = std::fs::read_to_string(path).with_context(|| {
                    format!(
                        "failed to read Bitcoin Core RPC cookie file {}",
                        path.display()
                    )
                })?;
                let (username, password) = cookie
                    .trim()
                    .split_once(':')
                    .ok_or_else(|| anyhow!("invalid Bitcoin Core RPC cookie format"))?;

                Ok(request.basic_auth(username, Some(password)))
            }
        }
    }

    fn run_async<F, T>(&self, future: F) -> Result<T>
    where
        F: Future<Output = Result<T>> + Send,
        T: Send,
    {
        thread::scope(|scope| {
            let task = scope.spawn(|| {
                Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context("failed to create temporary Tokio runtime for Bitcoin Core RPC")?
                    .block_on(future)
            });

            match task.join() {
                Ok(result) => result,
                Err(payload) => std::panic::resume_unwind(payload),
            }
        })
    }
}

#[derive(Debug, Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

#[derive(Debug, Deserialize)]
struct EstimateSmartFeeResponse {
    feerate: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct ScanTxOutSetResponse {
    success: bool,
    #[serde(default)]
    unspents: Vec<ScanTxOutSetUnspent>,
}

#[derive(Debug, Deserialize)]
struct ScanTxOutSetUnspent {
    txid: Txid,
    vout: u32,
    #[serde(rename = "amount")]
    #[serde(deserialize_with = "deserialize_btc_amount_to_sats")]
    amount_sats: u64,
    height: u32,
}

fn deserialize_btc_amount_to_sats<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;

    match value {
        Value::Number(number) => {
            let amount_btc = number.as_f64().ok_or_else(|| {
                serde::de::Error::custom(format!("unexpected BTC amount value {}", number))
            })?;

            Amount::from_btc(amount_btc)
                .map(|amount| amount.to_sat())
                .map_err(serde::de::Error::custom)
        }
        Value::String(string) => Amount::from_str_in(&string, Denomination::Bitcoin)
            .map(|amount| amount.to_sat())
            .map_err(serde::de::Error::custom),
        other => Err(serde::de::Error::custom(format!(
            "unexpected BTC amount value {}",
            other
        ))),
    }
}
