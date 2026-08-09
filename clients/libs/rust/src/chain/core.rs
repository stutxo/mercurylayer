use std::error::Error;
use std::fmt;
use std::future::Future;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use bitcoin::{Amount, BlockHash, Denomination, ScriptBuf, Txid};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::runtime::Builder;

const FILTER_INDEX_POLL_INTERVAL: Duration = Duration::from_millis(100);
const FILTER_INDEX_WAIT_TIMEOUT: Duration = Duration::from_secs(10);

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

    pub fn median_time_past(&self) -> Result<u32> {
        let response: BlockchainInfoResponse = self.call("getblockchaininfo", &[])?;
        Ok(response.median_time)
    }

    pub fn estimate_fee_btc_per_kb(&self, number_blocks: usize) -> Result<f64> {
        let response: EstimateSmartFeeResponse =
            self.call("estimatesmartfee", &[json!(number_blocks)])?;

        Ok(response.feerate.unwrap_or(0.0))
    }

    pub fn get_tx_out(
        &self,
        txid: &Txid,
        vout: u32,
        include_mempool: bool,
    ) -> Result<Option<ChainTxOut>> {
        self.call(
            "gettxout",
            &[json!(txid), json!(vout), json!(include_mempool)],
        )
    }

    pub fn get_block_hash(&self, height: u32) -> Result<BlockHash> {
        self.call("getblockhash", &[json!(height)])
    }

    pub fn scan_blocks(
        &self,
        descriptors: &[String],
        start_height: u32,
        stop_height: u32,
    ) -> Result<ScanBlocksResult> {
        wait_for_filter_index(
            stop_height,
            FILTER_INDEX_WAIT_TIMEOUT,
            FILTER_INDEX_POLL_INTERVAL,
            |remaining| self.filter_index_height(remaining),
        )?;
        self.call(
            "scanblocks",
            &[
                json!("start"),
                json!(descriptors),
                json!(start_height),
                json!(stop_height),
                json!("basic"),
            ],
        )
    }

    fn filter_index_height(&self, timeout: Duration) -> Result<u64> {
        self.call_with_timeout::<Value>("getindexinfo", &[], timeout)?["basic block filter index"]
            ["best_block_height"]
            .as_u64()
            .ok_or_else(|| anyhow!("Bitcoin Core basic block filter index is unavailable"))
    }

    pub fn descriptor_activity(
        &self,
        block_hashes: &[BlockHash],
        descriptors: &[String],
        include_mempool: bool,
    ) -> Result<Vec<DescriptorActivity>> {
        let response: DescriptorActivityResponse = self.call(
            "getdescriptoractivity",
            &[
                json!(block_hashes),
                json!(descriptors),
                json!(include_mempool),
            ],
        )?;

        Ok(response.activity)
    }

    pub fn get_raw_tx(&self, txid: &Txid) -> Result<Vec<u8>> {
        let tx_hex: String = self.call("getrawtransaction", &[json!(txid), json!(false)])?;

        hex::decode(tx_hex).with_context(|| format!("failed to decode raw tx {}", txid))
    }

    pub fn transaction_confirmations(&self, txid: &Txid) -> Result<Option<u32>> {
        match self.call::<RawTransactionStatus>("getrawtransaction", &[json!(txid), json!(true)]) {
            Ok(status) => status
                .confirmations
                .map(u32::try_from)
                .transpose()
                .context("Bitcoin Core returned negative transaction confirmations"),
            Err(error)
                if error
                    .downcast_ref::<CoreRpcError>()
                    .is_some_and(|error| error.code == -5) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    pub fn broadcast_tx(&self, tx_bytes: &[u8]) -> Result<Txid> {
        let tx_hex = hex::encode(tx_bytes);
        let txid: Txid = self.call("sendrawtransaction", &[json!(tx_hex)])?;

        Ok(txid)
    }

    pub fn submit_package(&self, txs: &[Vec<u8>]) -> Result<Value> {
        let tx_hexes = txs.iter().map(hex::encode).collect::<Vec<_>>();

        self.call("submitpackage", &[json!(tx_hexes)])
    }

    fn call<T>(&self, method: &str, params: &[Value]) -> Result<T>
    where
        T: DeserializeOwned + Send,
    {
        self.call_inner(method, params, None)
    }

    fn call_with_timeout<T>(&self, method: &str, params: &[Value], timeout: Duration) -> Result<T>
    where
        T: DeserializeOwned + Send,
    {
        self.call_inner(method, params, Some(timeout))
    }

    fn call_inner<T>(&self, method: &str, params: &[Value], timeout: Option<Duration>) -> Result<T>
    where
        T: DeserializeOwned + Send,
    {
        self.run_async(async {
            let request = self.apply_auth(self.client.post(&self.config.url).json(&json!({
                "jsonrpc": "1.0",
                "id": "mercury-client",
                "method": method,
                "params": params,
            })))?;
            let request = match timeout {
                Some(timeout) => request.timeout(timeout),
                None => request,
            };
            let response = request
                .send()
                .await
                .with_context(|| format!("Bitcoin Core RPC {} request failed", method))?;

            let status = response.status();
            let body = response.text().await.with_context(|| {
                format!("Bitcoin Core RPC {} failed to read response body", method)
            })?;

            let rpc_response = serde_json::from_str::<Value>(&body);
            if let Ok(rpc_response) = &rpc_response {
                if let Some(error) = rpc_response.get("error").filter(|error| !error.is_null()) {
                    let error: RpcError = serde_json::from_value(error.clone())?;
                    return Err(CoreRpcError {
                        method: method.to_owned(),
                        code: error.code,
                        message: error.message,
                    }
                    .into());
                }
            }
            if !status.is_success() {
                return Err(anyhow!(
                    "Bitcoin Core RPC {} failed with status {} and body {}",
                    method,
                    status,
                    body
                ));
            }

            let rpc_response = rpc_response.with_context(|| {
                format!(
                    "Bitcoin Core RPC {} returned invalid JSON response {}",
                    method, body
                )
            })?;

            let result = rpc_response
                .get("result")
                .cloned()
                .ok_or_else(|| anyhow!("Bitcoin Core RPC {} returned no result", method))?;
            serde_json::from_value(result)
                .with_context(|| format!("Bitcoin Core RPC {} returned an invalid result", method))
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

fn wait_for_filter_index(
    stop_height: u32,
    timeout: Duration,
    poll_interval: Duration,
    mut best_height: impl FnMut(Duration) -> Result<u64>,
) -> Result<()> {
    let started = Instant::now();
    loop {
        let elapsed = started.elapsed();
        if elapsed >= timeout {
            return Err(anyhow!("Bitcoin Core scanblocks did not complete"));
        }
        let height = match best_height(timeout - elapsed) {
            Ok(height) => height,
            Err(_) if started.elapsed() >= timeout => {
                return Err(anyhow!("Bitcoin Core scanblocks did not complete"))
            }
            Err(error) => return Err(error),
        };
        if height >= u64::from(stop_height) {
            return Ok(());
        }
        let elapsed = started.elapsed();
        if elapsed >= timeout {
            return Err(anyhow!("Bitcoin Core scanblocks did not complete"));
        }
        thread::sleep(poll_interval.min(timeout - elapsed));
    }
}

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

#[derive(Debug)]
struct CoreRpcError {
    method: String,
    code: i64,
    message: String,
}

impl fmt::Display for CoreRpcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Bitcoin Core RPC {} failed with code {}: {}",
            self.method, self.code, self.message
        )
    }
}

impl Error for CoreRpcError {}

#[derive(Debug, Deserialize)]
struct EstimateSmartFeeResponse {
    feerate: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct BlockchainInfoResponse {
    #[serde(rename = "mediantime")]
    median_time: u32,
}

#[derive(Debug, Deserialize)]
struct RawTransactionStatus {
    confirmations: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct ChainTxOut {
    #[serde(deserialize_with = "deserialize_btc_amount_to_sats")]
    pub value: u64,
    pub confirmations: u32,
    #[serde(
        rename = "scriptPubKey",
        deserialize_with = "deserialize_script_pubkey"
    )]
    pub script_pubkey: ScriptBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct ScanBlocksResult {
    pub from_height: u32,
    pub to_height: u32,
    pub relevant_blocks: Vec<BlockHash>,
    pub completed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum DescriptorActivity {
    Receive {
        #[serde(deserialize_with = "deserialize_btc_amount_to_sats")]
        amount: u64,
        height: Option<u32>,
        txid: Txid,
        vout: u32,
        #[serde(deserialize_with = "deserialize_script_pubkey")]
        output_spk: ScriptBuf,
    },
    Spend {
        height: Option<u32>,
        spend_txid: Txid,
        prevout_txid: Txid,
        prevout_vout: u32,
        #[serde(deserialize_with = "deserialize_script_pubkey")]
        prevout_spk: ScriptBuf,
    },
}

#[derive(Debug, Deserialize)]
struct DescriptorActivityResponse {
    activity: Vec<DescriptorActivity>,
}

fn deserialize_script_pubkey<'de, D>(deserializer: D) -> Result<ScriptBuf, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct ScriptPubKey {
        hex: String,
    }

    let script_pubkey = ScriptPubKey::deserialize(deserializer)?;
    hex::decode(script_pubkey.hex)
        .map(ScriptBuf::from_bytes)
        .map_err(serde::de::Error::custom)
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

#[cfg(test)]
mod tests {
    use super::*;
    use mercurylib::wallet::CoinStatus;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::str::FromStr;

    fn rpc_client(response: &str) -> (CoreChainClient, thread::JoinHandle<Value>) {
        rpc_client_with_status(response, "200 OK")
    }

    fn rpc_client_with_status(
        response: &str,
        status: &str,
    ) -> (CoreChainClient, thread::JoinHandle<Value>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let response = response.to_owned();
        let status = status.to_owned();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 8192];
            let size = stream.read(&mut request).unwrap();
            let body = String::from_utf8_lossy(&request[..size]);
            let body = body.split_once("\r\n\r\n").unwrap().1;
            let reply = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                response.len()
            );
            stream.write_all(reply.as_bytes()).unwrap();
            serde_json::from_str(body).unwrap()
        });
        let config = CoreRpcConfig {
            url,
            auth: CoreRpcAuth::None,
        };
        (CoreChainClient::new(config).unwrap(), server)
    }

    fn stalled_rpc_client(delay: Duration) -> (CoreChainClient, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            thread::sleep(delay);
        });
        let config = CoreRpcConfig {
            url,
            auth: CoreRpcAuth::None,
        };
        (CoreChainClient::new(config).unwrap(), server)
    }

    #[test]
    fn blockchain_info_uses_core_median_time_past_field() {
        let response: BlockchainInfoResponse =
            serde_json::from_str(r#"{"mediantime":1700000000}"#).unwrap();

        assert_eq!(response.median_time, 1_700_000_000);
    }

    #[test]
    fn get_tx_out_maps_unspent_spent_and_mempool_results() {
        let txid = Txid::from_str(&"11".repeat(32)).unwrap();
        let responses = [
            r#"{"result":{"value":0.00050000,"confirmations":2,"scriptPubKey":{"hex":"51"}},"error":null}"#,
            r#"{"result":null,"error":null}"#,
            r#"{"result":{"value":0.00025000,"confirmations":0,"scriptPubKey":{"hex":"0014"}},"error":null}"#,
        ];
        let mut results = Vec::new();
        for response in responses {
            let (client, server) = rpc_client(response);
            results.push(client.get_tx_out(&txid, 7, true).unwrap());
            let request = server.join().unwrap();
            assert_eq!(request["method"], "gettxout");
            assert_eq!(request["params"], json!([txid, 7, true]));
        }
        let unspent = results[0].as_ref().unwrap();
        let spent = results[1].as_ref();
        let mempool = results[2].as_ref().unwrap();
        assert_eq!(unspent.value, 50_000);
        assert_eq!(unspent.confirmations, 2);
        assert_eq!(unspent.script_pubkey.as_bytes(), &[0x51]);
        assert!(spent.is_none());
        assert_eq!(mempool.value, 25_000);
        assert_eq!(mempool.confirmations, 0);
        let status = crate::transfer_receiver::tx0_status_for_confirmations;
        assert_eq!(status(unspent.confirmations, 2), CoinStatus::CONFIRMED);
        let spent_status =
            spent.map_or(CoinStatus::UNCONFIRMED, |out| status(out.confirmations, 2));
        assert_eq!(spent_status, CoinStatus::UNCONFIRMED);
        assert_eq!(status(mempool.confirmations, 2), CoinStatus::UNCONFIRMED);

        let (client, server) = rpc_client(r#"{"error":{"code":-5,"message":"not found"}}"#);
        let error = client.get_tx_out(&txid, 0, true).unwrap_err();
        server.join().unwrap();
        assert_eq!(
            error.to_string(),
            "Bitcoin Core RPC gettxout failed with code -5: not found"
        );
    }

    #[test]
    fn transaction_confirmations_do_not_depend_on_an_unspent_output() {
        let txid = Txid::from_str(&"11".repeat(32)).unwrap();
        let cases = [
            (
                r#"{"result":{"txid":"11","confirmations":3,"blockhash":"22"},"error":null}"#,
                "200 OK",
                Some(3),
            ),
            (r#"{"result":{"txid":"11"},"error":null}"#, "200 OK", None),
            (
                r#"{"result":null,"error":{"code":-5,"message":"No such mempool or blockchain transaction"}}"#,
                "500 Internal Server Error",
                None,
            ),
        ];
        for (response, status, expected) in cases {
            let (client, server) = rpc_client_with_status(response, status);
            assert_eq!(client.transaction_confirmations(&txid).unwrap(), expected);
            let request = server.join().unwrap();
            assert_eq!(request["method"], "getrawtransaction");
            assert_eq!(request["params"], json!([txid, true]));
        }
    }

    #[test]
    fn filter_index_wait_is_bounded_and_allows_catch_up() {
        let mut calls = 0;
        let error = wait_for_filter_index(
            10,
            Duration::from_millis(10),
            Duration::from_millis(1),
            |_| {
                calls += 1;
                Ok(9)
            },
        )
        .unwrap_err();
        assert!(calls > 0);
        assert_eq!(
            error.to_string(),
            "Bitcoin Core scanblocks did not complete"
        );

        let mut heights = [9, 10].into_iter();
        wait_for_filter_index(10, Duration::from_secs(1), Duration::ZERO, |remaining| {
            assert!(!remaining.is_zero());
            Ok(heights.next().unwrap())
        })
        .unwrap();
        assert!(heights.next().is_none());

        let (client, server) = stalled_rpc_client(Duration::from_millis(100));
        let error =
            wait_for_filter_index(10, Duration::from_millis(20), Duration::ZERO, |remaining| {
                client.filter_index_height(remaining)
            })
            .unwrap_err();
        server.join().unwrap();
        assert_eq!(
            error.to_string(),
            "Bitcoin Core scanblocks did not complete"
        );
    }
}
