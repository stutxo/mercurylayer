use std::fmt::Write as _;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use bitcoin::{Amount, Denomination};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};

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

#[derive(Clone, Debug)]
pub struct TokenWalletConfig {
    pub name: String,
    pub create: bool,
}

pub struct CoreRpcClient {
    client: reqwest::Client,
    config: CoreRpcConfig,
}

impl CoreRpcClient {
    pub fn new(config: CoreRpcConfig) -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .build()
                .context("failed to build Bitcoin Core RPC client")?,
            config,
        })
    }

    pub async fn ensure_wallet(
        &self,
        wallet_config: &TokenWalletConfig,
        public_key_descriptor: &str,
    ) -> Result<()> {
        self.ensure_wallet_loaded(wallet_config).await?;
        self.ensure_wallet_is_watch_only_descriptor(&wallet_config.name)
            .await?;

        self.import_receive_descriptor(wallet_config, public_key_descriptor)
            .await?;

        Ok(())
    }

    pub async fn get_new_address(&self, wallet_name: &str) -> Result<String> {
        self.call_wallet(wallet_name, "getnewaddress", &[]).await
    }

    pub async fn list_unspent(
        &self,
        wallet_name: &str,
        address: &str,
    ) -> Result<Vec<WalletUnspent>> {
        self.call_wallet(
            wallet_name,
            "listunspent",
            &[json!(0), json!(9999999), json!([address]), json!(true)],
        )
        .await
    }

    async fn ensure_wallet_loaded(&self, wallet_config: &TokenWalletConfig) -> Result<()> {
        let loaded_wallets: Vec<String> = self.call_node("listwallets", &[]).await?;

        if loaded_wallets
            .iter()
            .any(|wallet| wallet == &wallet_config.name)
        {
            return Ok(());
        }

        if self
            .call_node::<Value>("loadwallet", &[json!(wallet_config.name)])
            .await
            .is_ok()
        {
            return Ok(());
        }

        if !wallet_config.create {
            return Err(anyhow!(
                "Bitcoin Core token wallet '{}' is not loaded and wallet creation is disabled",
                wallet_config.name
            ));
        }

        let params = vec![
            json!(wallet_config.name),
            json!(true),
            json!(true),
            json!(""),
            json!(false),
            json!(true),
        ];

        match self.call_node::<Value>("createwallet", &params).await {
            Ok(_) => Ok(()),
            Err(create_error) => {
                self.call_node::<Value>("loadwallet", &[json!(wallet_config.name)])
                    .await
                    .with_context(|| {
                        format!(
                            "failed to create token wallet '{}' ({}) and then failed to load it",
                            wallet_config.name, create_error
                        )
                    })?;
                Ok(())
            }
        }
    }

    async fn ensure_wallet_is_watch_only_descriptor(&self, wallet_name: &str) -> Result<()> {
        let wallet_info: WalletInfo = self.call_wallet(wallet_name, "getwalletinfo", &[]).await?;

        if wallet_info.private_keys_enabled {
            return Err(anyhow!(
                "Bitcoin Core token wallet '{}' must have private keys disabled",
                wallet_name
            ));
        }

        if !wallet_info.descriptors {
            return Err(anyhow!(
                "Bitcoin Core token wallet '{}' must be a descriptor wallet",
                wallet_name
            ));
        }

        Ok(())
    }

    async fn import_receive_descriptor(
        &self,
        wallet_config: &TokenWalletConfig,
        public_key_descriptor: &str,
    ) -> Result<()> {
        if public_key_descriptor.trim().is_empty() {
            return Err(anyhow!(
                "public_key_descriptor is required for token wallet descriptor import"
            ));
        }

        let request = json!({
            "desc": public_key_descriptor,
            "timestamp": "now",
            "active": true,
            "internal": false,
        });

        let results: Vec<ImportDescriptorResult> = self
            .call_wallet(
                &wallet_config.name,
                "importdescriptors",
                &[json!([request])],
            )
            .await?;

        for result in results {
            if result.success {
                continue;
            }

            let message = result
                .error
                .map(|error| error.message)
                .unwrap_or_else(|| "unknown descriptor import error".to_string());

            if !message.to_ascii_lowercase().contains("already exists") {
                return Err(anyhow!(
                    "Bitcoin Core token wallet descriptor import failed: {}",
                    message
                ));
            }
        }

        Ok(())
    }

    async fn call_node<T>(&self, method: &str, params: &[Value]) -> Result<T>
    where
        T: DeserializeOwned,
    {
        self.call(&self.config.url, method, params).await
    }

    async fn call_wallet<T>(&self, wallet_name: &str, method: &str, params: &[Value]) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let url = format!(
            "{}/wallet/{}",
            self.config.url.trim_end_matches('/'),
            percent_encode_wallet_name(wallet_name)
        );
        self.call(&url, method, params).await
    }

    async fn call<T>(&self, url: &str, method: &str, params: &[Value]) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let response = self
            .apply_auth(self.client.post(url).json(&json!({
                "jsonrpc": "1.0",
                "id": "mercury-token-server",
                "method": method,
                "params": params,
            })))?
            .send()
            .await
            .with_context(|| format!("Bitcoin Core RPC {} request failed", method))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .with_context(|| format!("Bitcoin Core RPC {} failed to read response body", method))?;

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
}

#[derive(Debug, Deserialize)]
pub struct WalletUnspent {
    #[allow(dead_code)]
    pub txid: String,
    #[allow(dead_code)]
    pub vout: u32,
    #[serde(rename = "amount")]
    #[serde(deserialize_with = "deserialize_btc_amount_to_sats")]
    pub amount_sats: u64,
    #[serde(default)]
    pub confirmations: u32,
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
struct WalletInfo {
    private_keys_enabled: bool,
    descriptors: bool,
}

#[derive(Debug, Deserialize)]
struct ImportDescriptorResult {
    success: bool,
    error: Option<ImportDescriptorError>,
}

#[derive(Debug, Deserialize)]
struct ImportDescriptorError {
    message: String,
}

fn percent_encode_wallet_name(wallet_name: &str) -> String {
    let mut encoded = String::new();

    for byte in wallet_name.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char)
            }
            _ => {
                let _ = write!(&mut encoded, "%{:02X}", byte);
            }
        }
    }

    encoded
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
