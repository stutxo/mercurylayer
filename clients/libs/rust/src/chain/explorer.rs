use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use bitcoin::{Address, BlockHash, ScriptBuf, Transaction, Txid};
use reqwest::{
    blocking::{Client, Response},
    Url,
};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::Value;

use super::core::{ChainTransaction, ChainTxOut, DescriptorActivity, ScanBlocksResult};

#[derive(Debug)]
pub struct ExplorerChainClient {
    client: Client,
    base_url: String,
}

#[derive(Debug, Deserialize)]
struct TxStatus {
    confirmed: bool,
    block_height: Option<u32>,
    block_hash: Option<BlockHash>,
}

#[derive(Debug, Deserialize)]
struct Block {
    mediantime: u32,
}

#[derive(Debug, Deserialize)]
struct Outspend {
    spent: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct TxOutput {
    scriptpubkey: String,
    value: u64,
}

#[derive(Debug, Deserialize)]
struct TxInput {
    txid: Txid,
    vout: u32,
    prevout: Option<TxOutput>,
}

#[derive(Debug, Deserialize)]
struct ExplorerTransaction {
    txid: Txid,
    vin: Vec<TxInput>,
    vout: Vec<TxOutput>,
    status: TxStatus,
}

impl ExplorerChainClient {
    pub fn new(base_url: String) -> Result<Self> {
        let parsed = Url::parse(&base_url).context("explorer URL is invalid")?;
        let loopback_http =
            parsed.scheme() == "http" && matches!(parsed.host_str(), Some("127.0.0.1" | "::1"));
        if parsed.scheme() != "https" && !loopback_http {
            return Err(anyhow!("explorer backend must use HTTPS or loopback HTTP"));
        }
        Ok(Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .context("failed to build explorer HTTP client")?,
            base_url: parsed.as_str().trim_end_matches('/').to_string(),
        })
    }

    pub fn tip_height(&self) -> Result<u32> {
        self.get_text("blocks/tip/height")?
            .trim()
            .parse()
            .context("explorer returned an invalid tip height")
    }

    pub fn median_time_past(&self) -> Result<u32> {
        let hash = self.get_text("blocks/tip/hash")?;
        Ok(self
            .get_json::<Block>(&format!("block/{}", hash.trim()))?
            .mediantime)
    }

    pub fn estimate_fee_sat_per_vbyte(&self, number_blocks: usize) -> Result<f64> {
        select_fee_estimate(&self.get_json("fee-estimates")?, number_blocks)
    }

    pub fn get_tx_out(
        &self,
        txid: &Txid,
        vout: u32,
        _include_mempool: bool,
    ) -> Result<Option<ChainTxOut>> {
        let Some(transaction) =
            self.get_optional_json::<ExplorerTransaction>(&format!("tx/{txid}"))?
        else {
            return Ok(None);
        };
        let output = match transaction.vout.get(vout as usize) {
            Some(output) => output,
            None => return Ok(None),
        };
        let outspend: Outspend = self.get_json(&format!("tx/{txid}/outspend/{vout}"))?;
        if outspend.spent {
            return Ok(None);
        }
        Ok(Some(ChainTxOut {
            value: output.value,
            confirmations: self.confirmations(&transaction.status)?,
            script_pubkey: ScriptBuf::from_bytes(
                hex::decode(&output.scriptpubkey)
                    .context("explorer output script is invalid hex")?,
            ),
        }))
    }

    pub fn get_block_hash(&self, height: u32) -> Result<BlockHash> {
        self.get_text(&format!("block-height/{height}"))?
            .trim()
            .parse()
            .context("explorer returned an invalid block hash")
    }

    pub fn scan_blocks(
        &self,
        descriptors: &[String],
        start_height: u32,
        stop_height: u32,
    ) -> Result<ScanBlocksResult> {
        let mut relevant = BTreeMap::<u32, BlockHash>::new();
        for address in descriptor_addresses(descriptors)? {
            for transaction in self.address_transactions(&address)? {
                if let (Some(height), Some(hash)) = (
                    transaction.status.block_height,
                    transaction.status.block_hash,
                ) {
                    if (start_height..=stop_height).contains(&height) {
                        relevant.insert(height, hash);
                    }
                }
            }
        }
        Ok(ScanBlocksResult {
            from_height: start_height,
            to_height: stop_height,
            relevant_blocks: relevant.into_values().collect(),
            completed: true,
        })
    }

    pub fn descriptor_activity(
        &self,
        block_hashes: &[BlockHash],
        descriptors: &[String],
        include_mempool: bool,
    ) -> Result<Vec<DescriptorActivity>> {
        let selected_blocks = block_hashes.iter().copied().collect::<BTreeSet<_>>();
        let addresses = descriptor_addresses(descriptors)?;
        let mut events = BTreeMap::<String, DescriptorActivity>::new();
        for address in addresses {
            let script = address.script_pubkey();
            for transaction in self.address_transactions(&address)? {
                let selected = transaction
                    .status
                    .block_hash
                    .is_some_and(|hash| selected_blocks.contains(&hash))
                    || (include_mempool && !transaction.status.confirmed);
                if !selected {
                    continue;
                }
                let height = transaction.status.block_height;
                for (vout, output) in transaction.vout.iter().enumerate() {
                    let output_script = ScriptBuf::from_bytes(
                        hex::decode(&output.scriptpubkey)
                            .context("explorer output script is invalid hex")?,
                    );
                    if output_script == script {
                        events.insert(
                            format!("receive:{}:{vout}", transaction.txid),
                            DescriptorActivity::Receive {
                                amount: output.value,
                                height,
                                txid: transaction.txid,
                                vout: vout as u32,
                                output_spk: output_script,
                            },
                        );
                    }
                }
                for input in &transaction.vin {
                    let Some(prevout) = &input.prevout else {
                        continue;
                    };
                    let prevout_script = ScriptBuf::from_bytes(
                        hex::decode(&prevout.scriptpubkey)
                            .context("explorer prevout script is invalid hex")?,
                    );
                    if prevout_script == script {
                        events.insert(
                            format!("spend:{}:{}:{}", transaction.txid, input.txid, input.vout),
                            DescriptorActivity::Spend {
                                height,
                                spend_txid: transaction.txid,
                                prevout_txid: input.txid,
                                prevout_vout: input.vout,
                                prevout_spk: prevout_script,
                            },
                        );
                    }
                }
            }
        }
        Ok(events.into_values().collect())
    }

    pub fn get_raw_tx(&self, txid: &Txid) -> Result<Vec<u8>> {
        hex::decode(self.get_text(&format!("tx/{txid}/hex"))?.trim())
            .context("explorer returned invalid transaction hex")
    }

    pub fn transaction_confirmations(&self, txid: &Txid) -> Result<Option<u32>> {
        let Some(status) = self.get_optional_json::<TxStatus>(&format!("tx/{txid}/status"))? else {
            return Ok(None);
        };
        if !status.confirmed {
            return Ok(None);
        }
        Ok(Some(self.confirmations(&status)?))
    }

    pub fn exact_transaction(&self, txid: &Txid) -> Result<Option<ChainTransaction>> {
        let Some(status) = self.get_optional_json::<TxStatus>(&format!("tx/{txid}/status"))? else {
            return Ok(None);
        };
        let bytes = self.get_raw_tx(txid)?;
        let transaction: Transaction = bitcoin::consensus::deserialize(&bytes)
            .context("explorer returned invalid transaction bytes")?;
        if bitcoin::consensus::serialize(&transaction) != bytes || transaction.txid() != *txid {
            return Err(anyhow!(
                "explorer returned different transaction bytes for {txid}"
            ));
        }
        Ok(Some(ChainTransaction {
            bytes,
            confirmations: self.confirmations(&status)?,
        }))
    }

    pub fn broadcast_tx(&self, tx_bytes: &[u8]) -> Result<Txid> {
        let response = self
            .client
            .post(self.url("tx"))
            .header("Content-Type", "text/plain")
            .body(hex::encode(tx_bytes))
            .send()
            .context("explorer transaction broadcast failed")?;
        let body = response_text(response, "explorer transaction broadcast")?;
        body.trim()
            .parse()
            .context("explorer returned an invalid transaction id")
    }

    pub fn submit_package(&self, txs: &[Vec<u8>]) -> Result<Value> {
        let response = self
            .client
            .post(self.url("txs/package"))
            .json(&txs.iter().map(hex::encode).collect::<Vec<_>>())
            .send()
            .context("explorer package submission failed")?;
        let body = response_text(response, "explorer package submission")?;
        serde_json::from_str(&body).context("explorer returned invalid package JSON")
    }

    fn confirmations(&self, status: &TxStatus) -> Result<u32> {
        if !status.confirmed {
            return Ok(0);
        }
        let height = status
            .block_height
            .ok_or_else(|| anyhow!("confirmed explorer transaction omitted block height"))?;
        Ok(self.tip_height()?.saturating_sub(height).saturating_add(1))
    }

    fn address_transactions(&self, address: &Address) -> Result<Vec<ExplorerTransaction>> {
        let mut transactions =
            self.get_json::<Vec<ExplorerTransaction>>(&format!("address/{address}/txs"))?;
        let mut cursor = transactions
            .iter()
            .rev()
            .find(|transaction| transaction.status.confirmed)
            .map(|transaction| transaction.txid);

        while let Some(last_seen_txid) = cursor {
            let page = self.get_json::<Vec<ExplorerTransaction>>(&format!(
                "address/{address}/txs/chain/{last_seen_txid}"
            ))?;
            if page.is_empty() {
                break;
            }
            let next_cursor = page
                .last()
                .map(|transaction| transaction.txid)
                .expect("nonempty explorer transaction page");
            if next_cursor == last_seen_txid {
                return Err(anyhow!(
                    "explorer transaction pagination did not advance for {address}"
                ));
            }
            let complete = page.len() < 25;
            transactions.extend(page);
            if complete {
                break;
            }
            cursor = Some(next_cursor);
        }
        Ok(transactions)
    }

    fn url(&self, path: &str) -> String {
        format!("{}/{}", self.base_url, path.trim_start_matches('/'))
    }

    fn get_text(&self, path: &str) -> Result<String> {
        response_text(
            self.client
                .get(self.url(path))
                .send()
                .with_context(|| format!("explorer GET {path} failed"))?,
            &format!("explorer GET {path}"),
        )
    }

    fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        serde_json::from_str(&self.get_text(path)?)
            .with_context(|| format!("explorer GET {path} returned invalid JSON"))
    }

    fn get_optional_json<T: DeserializeOwned>(&self, path: &str) -> Result<Option<T>> {
        let response = self
            .client
            .get(self.url(path))
            .send()
            .with_context(|| format!("explorer GET {path} failed"))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let body = response_text(response, &format!("explorer GET {path}"))?;
        serde_json::from_str(&body)
            .map(Some)
            .with_context(|| format!("explorer GET {path} returned invalid JSON"))
    }
}

fn response_text(response: Response, context: &str) -> Result<String> {
    let status = response.status();
    let body = response
        .text()
        .with_context(|| format!("{context} body read failed"))?;
    if !status.is_success() {
        return Err(anyhow!("{context} returned {status}: {body}"));
    }
    Ok(body)
}

fn select_fee_estimate(estimates: &BTreeMap<String, f64>, number_blocks: usize) -> Result<f64> {
    let target = number_blocks.max(1);
    estimates
        .iter()
        .filter_map(|(blocks, rate)| blocks.parse::<usize>().ok().map(|blocks| (blocks, *rate)))
        .filter(|(blocks, _)| *blocks >= target)
        .min_by_key(|(blocks, _)| *blocks)
        .or_else(|| {
            estimates
                .iter()
                .filter_map(|(blocks, rate)| {
                    blocks.parse::<usize>().ok().map(|blocks| (blocks, *rate))
                })
                .max_by_key(|(blocks, _)| *blocks)
        })
        .map(|(_, rate)| rate)
        .ok_or_else(|| anyhow!("explorer returned no fee estimates"))
}
fn descriptor_addresses(descriptors: &[String]) -> Result<Vec<Address>> {
    descriptors
        .iter()
        .map(|descriptor| {
            let value = descriptor
                .strip_prefix("addr(")
                .and_then(|value| value.strip_suffix(')'))
                .ok_or_else(|| anyhow!("explorer backend supports only addr() descriptors"))?;
            Address::from_str(value)
                .map(|address| address.assume_checked())
                .context("descriptor contains an invalid address")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    fn mock_explorer(response: &str) -> (ExplorerChainClient, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let response = response.to_string();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 8_192];
            let size = stream.read(&mut request).unwrap();
            let request = String::from_utf8(request[..size].to_vec()).unwrap();
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.len(),
                response
            );
            stream.write_all(reply.as_bytes()).unwrap();
            request
        });
        (ExplorerChainClient::new(endpoint).unwrap(), server)
    }

    #[test]
    fn fee_estimate_uses_nearest_available_target() {
        let estimates = BTreeMap::from([
            ("1".to_string(), 5.0),
            ("2".to_string(), 3.0),
            ("6".to_string(), 1.5),
        ]);

        assert_eq!(select_fee_estimate(&estimates, 0).unwrap(), 5.0);
        assert_eq!(select_fee_estimate(&estimates, 2).unwrap(), 3.0);
        assert_eq!(select_fee_estimate(&estimates, 4).unwrap(), 1.5);
        assert_eq!(select_fee_estimate(&estimates, 10).unwrap(), 1.5);
        assert!(select_fee_estimate(&BTreeMap::new(), 2).is_err());
    }

    #[test]
    fn descriptor_parser_accepts_only_address_descriptors() {
        let address = "tb1pzf09qspcp5txe98lvfj3cevvru5t78pn4s04645npq5eqj5vun0smf2dv8";
        let parsed = descriptor_addresses(&[format!("addr({address})")]).unwrap();

        assert_eq!(parsed[0].to_string(), address);
        assert!(descriptor_addresses(&[format!("raw({address})")]).is_err());
        assert!(descriptor_addresses(&["addr(not-an-address)".to_string()]).is_err());
    }

    #[test]
    fn explorer_transport_requires_https_or_loopback_http() {
        assert!(ExplorerChainClient::new("https://mutinynet.com/api".to_string()).is_ok());
        assert!(ExplorerChainClient::new("http://127.0.0.1:3000".to_string()).is_ok());
        assert!(ExplorerChainClient::new("http://mutinynet.com/api".to_string()).is_err());
    }
    #[test]
    fn package_submission_uses_esplora_package_endpoint_and_hex_body() {
        let (client, server) = mock_explorer(r#"{"package_msg":"success"}"#);
        let result = client
            .submit_package(&[vec![0x00, 0x01], vec![0xfe]])
            .unwrap();
        let request = server.join().unwrap();
        let (head, body) = request.split_once("\r\n\r\n").unwrap();

        assert!(head.starts_with("POST /txs/package HTTP/1.1\r\n"));
        assert_eq!(
            serde_json::from_str::<Value>(body).unwrap(),
            serde_json::json!(["0001", "fe"])
        );
        assert_eq!(result["package_msg"], "success");
    }
}
