pub mod cpfp_tx;
pub mod key_derivation;

use std::{fmt, str::FromStr};

use bip39::{Language, Mnemonic};
use bitcoin::Transaction;
use secp256k1::rand::{self, Rng};
use serde::{Deserialize, Serialize};

use crate::{transfer::TxOutpoint, utils::ServerConfig, MercuryError};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(try_from = "WalletCompat")]
pub struct Wallet {
    pub name: String,
    pub mnemonic: String,
    pub version: String,
    pub state_entity_endpoint: String,
    pub chain_backend: String,
    pub chain_endpoint: String,
    pub network: String,
    pub blockheight: u32,
    pub initlock: u32,
    pub interval: u32,
    pub tokens: Vec<Token>,
    pub activities: Vec<Activity>,
    pub coins: Vec<Coin>,
    pub settings: Settings,
}

#[allow(non_snake_case)]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(try_from = "SettingsCompat")]
pub struct Settings {
    pub network: String,
    pub block_explorerURL: Option<String>,
    pub torProxyHost: Option<String>,
    pub torProxyPort: Option<String>,
    pub torProxyControlPassword: Option<String>,
    pub torProxyControlPort: Option<String>,
    pub statechainEntityApi: String,
    pub torStatechainEntityApi: Option<String>,
    pub chainBackend: String,
    pub chainUrl: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chainType: Option<String>,
    pub notifications: bool,
    pub tutorials: bool,
}

#[derive(Debug, Deserialize)]
struct WalletCompat {
    pub name: String,
    pub mnemonic: String,
    pub version: String,
    pub state_entity_endpoint: String,
    #[serde(default)]
    pub chain_backend: Option<String>,
    #[serde(default)]
    pub chain_endpoint: Option<String>,
    #[serde(default)]
    pub electrum_endpoint: Option<String>,
    pub network: String,
    pub blockheight: u32,
    pub initlock: u32,
    pub interval: u32,
    pub tokens: Vec<Token>,
    pub activities: Vec<Activity>,
    pub coins: Vec<Coin>,
    pub settings: Settings,
}

#[allow(non_snake_case)]
#[derive(Debug, Deserialize)]
struct SettingsCompat {
    pub network: String,
    pub block_explorerURL: Option<String>,
    pub torProxyHost: Option<String>,
    pub torProxyPort: Option<String>,
    pub torProxyControlPassword: Option<String>,
    pub torProxyControlPort: Option<String>,
    pub statechainEntityApi: String,
    pub torStatechainEntityApi: Option<String>,
    #[serde(default)]
    pub chainBackend: Option<String>,
    #[serde(default)]
    pub chainUrl: Option<String>,
    #[serde(default)]
    pub chainType: Option<String>,
    #[serde(default)]
    pub electrumProtocol: Option<String>,
    #[serde(default)]
    pub electrumHost: Option<String>,
    #[serde(default)]
    pub electrumPort: Option<String>,
    #[serde(default)]
    pub electrumType: Option<String>,
    pub notifications: bool,
    pub tutorials: bool,
}

impl TryFrom<WalletCompat> for Wallet {
    type Error = String;

    fn try_from(value: WalletCompat) -> Result<Self, Self::Error> {
        let settings = value.settings;
        let chain_backend = value
            .chain_backend
            .unwrap_or_else(|| settings.chainBackend.clone());
        let chain_endpoint = value
            .chain_endpoint
            .or(value.electrum_endpoint)
            .unwrap_or_else(|| settings.chainUrl.clone());

        if chain_endpoint.is_empty() {
            return Err("wallet missing chain_endpoint".to_string());
        }

        Ok(Self {
            name: value.name,
            mnemonic: value.mnemonic,
            version: value.version,
            state_entity_endpoint: value.state_entity_endpoint,
            chain_backend,
            chain_endpoint,
            network: value.network,
            blockheight: value.blockheight,
            initlock: value.initlock,
            interval: value.interval,
            tokens: value.tokens,
            activities: value.activities,
            coins: value.coins,
            settings,
        })
    }
}

impl TryFrom<SettingsCompat> for Settings {
    type Error = String;

    fn try_from(value: SettingsCompat) -> Result<Self, Self::Error> {
        let chain_backend = value.chainBackend.unwrap_or_else(default_chain_backend);
        let chain_url = match value.chainUrl {
            Some(chain_url) => chain_url,
            None => build_legacy_electrum_url(
                value.electrumProtocol.as_deref(),
                value.electrumHost.as_deref(),
                value.electrumPort.as_deref(),
            )?,
        };

        Ok(Self {
            network: value.network,
            block_explorerURL: value.block_explorerURL,
            torProxyHost: value.torProxyHost,
            torProxyPort: value.torProxyPort,
            torProxyControlPassword: value.torProxyControlPassword,
            torProxyControlPort: value.torProxyControlPort,
            statechainEntityApi: value.statechainEntityApi,
            torStatechainEntityApi: value.torStatechainEntityApi,
            chainBackend: chain_backend,
            chainUrl: chain_url,
            chainType: value.chainType.or(value.electrumType),
            notifications: value.notifications,
            tutorials: value.tutorials,
        })
    }
}

fn default_chain_backend() -> String {
    "electrum".to_string()
}

fn build_legacy_electrum_url(
    protocol: Option<&str>,
    host: Option<&str>,
    port: Option<&str>,
) -> Result<String, String> {
    match (protocol, host, port) {
        (Some(protocol), Some(host), Some(port)) => Ok(format!("{}://{}:{}", protocol, host, port)),
        (None, None, None) => Err("wallet settings missing chainUrl".to_string()),
        _ => Err("wallet settings contain incomplete legacy electrum configuration".to_string()),
    }
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Token {
    pub btc_payment_address: String,
    pub fee: String,
    pub lightning_invoice: String,
    pub processor_id: String,
    pub token_id: String,
    pub confirmed: bool,
    pub spent: bool,
    pub expiry: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Activity {
    pub utxo: String,
    pub amount: u32,
    pub action: String,
    pub date: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Coin {
    pub index: u32,
    pub user_privkey: String,
    pub user_pubkey: String,
    pub auth_privkey: String,
    pub auth_pubkey: String,
    pub derivation_path: String,
    pub fingerprint: String,
    /// The coin address is the user_pubkey || auth_pubkey
    /// Used to transfer the coin to another wallet
    pub address: String,
    /// The backup address is the address used in backup transactions
    /// The backup address is the p2tr address of the user_pubkey
    pub backup_address: String,
    pub server_pubkey: Option<String>,
    // The aggregated_pubkey is the user_pubkey + server_pubkey
    pub aggregated_pubkey: Option<String>,
    /// The aggregated address is the P2TR address from aggregated_pubkey
    pub aggregated_address: Option<String>,
    pub utxo_txid: Option<String>,
    pub utxo_vout: Option<u32>,
    pub amount: Option<u32>,
    pub statechain_id: Option<String>,
    pub signed_statechain_id: Option<String>,
    pub locktime: Option<u32>,
    pub secret_nonce: Option<String>,
    pub public_nonce: Option<String>,
    pub blinding_factor: Option<String>,
    pub server_public_nonce: Option<String>,
    pub tx_cpfp: Option<String>,
    pub tx_withdraw: Option<String>,
    pub withdrawal_address: Option<String>,
    pub status: CoinStatus,
    pub duplicate_index: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[allow(non_camel_case_types)]
pub enum CoinStatus {
    INITIALISED, //  address generated but no Tx0 yet
    IN_MEMPOOL,  // Tx0 in mempool
    UNCONFIRMED, // Tx0 is awaiting more confirmations before coin is available to be sent
    CONFIRMED,   // Tx0 confirmed and coin available to be sent
    IN_TRANSFER, // transfer-sender performed, but receiver hasn't completed transfer-receiver
    WITHDRAWING, // withdrawal tx signed and broadcast but not yet confirmed
    TRANSFERRED, // the coin was transferred
    WITHDRAWN,   // the coin was withdrawn
    DUPLICATED,  // the coin was duplicated
    INVALIDATED, // the coin was invalidated (duplicated but not transferred)
}

impl fmt::Display for CoinStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Match the enum variants
        write!(
            f,
            "{}",
            match self {
                Self::INITIALISED => "INITIALISED",
                Self::IN_MEMPOOL => "IN_MEMPOOL",
                Self::UNCONFIRMED => "UNCONFIRMED",
                Self::CONFIRMED => "CONFIRMED",
                Self::IN_TRANSFER => "IN_TRANSFER",
                Self::WITHDRAWING => "WITHDRAWING",
                Self::TRANSFERRED => "TRANSFERRED",
                Self::WITHDRAWN => "WITHDRAWN",
                Self::DUPLICATED => "DUPLICATED",
                Self::INVALIDATED => "INVALIDATED",
            }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoinStatusParseError;

impl fmt::Display for CoinStatusParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "provided string was not a valid CoinStatus")
    }
}

impl std::error::Error for CoinStatusParseError {}

impl FromStr for CoinStatus {
    type Err = CoinStatusParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "INITIALISED" => Ok(CoinStatus::INITIALISED),
            "IN_MEMPOOL" => Ok(CoinStatus::IN_MEMPOOL),
            "UNCONFIRMED" => Ok(CoinStatus::UNCONFIRMED),
            "CONFIRMED" => Ok(CoinStatus::CONFIRMED),
            "IN_TRANSFER" => Ok(CoinStatus::IN_TRANSFER),
            "WITHDRAWING" => Ok(CoinStatus::WITHDRAWING),
            "TRANSFERRED" => Ok(CoinStatus::TRANSFERRED),
            "WITHDRAWN" => Ok(CoinStatus::WITHDRAWN),
            "DUPLICATED" => Ok(CoinStatus::DUPLICATED),
            "INVALIDATED" => Ok(CoinStatus::INVALIDATED),
            _ => Err(CoinStatusParseError {}),
        }
    }
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StatechainBackupTxs {
    pub statechain_id: String,
    pub backup_txs: Vec<BackupTx>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BackupTx {
    pub tx_n: u32,
    pub tx: String,
    pub client_public_nonce: String,
    pub server_public_nonce: String,
    pub client_public_key: String,
    pub server_public_key: String,
    pub blinding_factor: String,
}

pub fn get_previous_outpoint(backup_tx: &BackupTx) -> Result<TxOutpoint, MercuryError> {
    let tx1: Transaction =
        bitcoin::consensus::encode::deserialize(&hex::decode(backup_tx.tx.clone())?)?;

    if tx1.input.len() > 1 {
        return Err(MercuryError::Tx1HasMoreThanOneInput);
    }

    if tx1.output.len() > 1 {
        return Err(MercuryError::Tx1HasMoreThanOneInput);
    }

    let tx0_txid = tx1.input[0].previous_output.txid;
    let tx0_vout = tx1.input[0].previous_output.vout as u32;

    Ok(TxOutpoint {
        txid: tx0_txid.to_string(),
        vout: tx0_vout,
    })
}

pub fn set_config(wallet: &mut Wallet, config: &ServerConfig) {
    wallet.initlock = config.initlock;
    wallet.interval = config.interval;
}

pub fn generate_mnemonic() -> core::result::Result<String, MercuryError> {
    let mut rng = rand::thread_rng();
    let entropy = (0..16).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>(); // 16 bytes of entropy for 12 words
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)?;
    Ok(mnemonic.to_string())
}

#[cfg(test)]
mod tests {
    use super::{Settings, Wallet};
    use serde_json::Value;

    #[test]
    fn wallet_deserializes_legacy_electrum_metadata() {
        let wallet_json = r#"
        {
          "name": "wallet",
          "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
          "version": "0.1.0",
          "state_entity_endpoint": "http://statechain",
          "electrum_endpoint": "tcp://electrum:50001",
          "network": "regtest",
          "blockheight": 42,
          "initlock": 1000,
          "interval": 10,
          "tokens": [],
          "activities": [],
          "coins": [],
          "settings": {
            "network": "regtest",
            "block_explorerURL": null,
            "torProxyHost": null,
            "torProxyPort": null,
            "torProxyControlPassword": null,
            "torProxyControlPort": null,
            "statechainEntityApi": "http://statechain",
            "torStatechainEntityApi": null,
            "electrumProtocol": "tcp",
            "electrumHost": "electrum",
            "electrumPort": "50001",
            "electrumType": "electrs",
            "notifications": false,
            "tutorials": false
          }
        }
        "#;

        let wallet: Wallet = serde_json::from_str(wallet_json).unwrap();

        assert_eq!(wallet.chain_backend, "electrum");
        assert_eq!(wallet.chain_endpoint, "tcp://electrum:50001");
        assert_eq!(wallet.settings.chainBackend, "electrum");
        assert_eq!(wallet.settings.chainUrl, "tcp://electrum:50001");
        assert_eq!(wallet.settings.chainType.as_deref(), Some("electrs"));
    }

    #[test]
    fn wallet_serialization_rewrites_legacy_metadata_to_neutral_fields() {
        let wallet_json = r#"
        {
          "name": "wallet",
          "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
          "version": "0.1.0",
          "state_entity_endpoint": "http://statechain",
          "electrum_endpoint": "tcp://electrum:50001",
          "network": "regtest",
          "blockheight": 42,
          "initlock": 1000,
          "interval": 10,
          "tokens": [],
          "activities": [],
          "coins": [],
          "settings": {
            "network": "regtest",
            "block_explorerURL": null,
            "torProxyHost": null,
            "torProxyPort": null,
            "torProxyControlPassword": null,
            "torProxyControlPort": null,
            "statechainEntityApi": "http://statechain",
            "torStatechainEntityApi": null,
            "electrumProtocol": "tcp",
            "electrumHost": "electrum",
            "electrumPort": "50001",
            "electrumType": "electrs",
            "notifications": false,
            "tutorials": false
          }
        }
        "#;

        let wallet: Wallet = serde_json::from_str(wallet_json).unwrap();
        let rewritten = serde_json::to_value(&wallet).unwrap();

        assert_eq!(rewritten["chain_backend"], "electrum");
        assert_eq!(rewritten["chain_endpoint"], "tcp://electrum:50001");
        assert!(rewritten.get("electrum_endpoint").is_none());

        let settings = rewritten
            .get("settings")
            .and_then(Value::as_object)
            .unwrap();
        assert_eq!(
            settings.get("chainBackend").and_then(Value::as_str),
            Some("electrum")
        );
        assert_eq!(
            settings.get("chainUrl").and_then(Value::as_str),
            Some("tcp://electrum:50001")
        );
        assert_eq!(
            settings.get("chainType").and_then(Value::as_str),
            Some("electrs")
        );
        assert!(!settings.contains_key("electrumProtocol"));
        assert!(!settings.contains_key("electrumHost"));
        assert!(!settings.contains_key("electrumPort"));
        assert!(!settings.contains_key("electrumType"));
    }

    #[test]
    fn wallet_deserializes_neutral_chain_metadata() {
        let wallet = Wallet {
            name: "wallet".to_string(),
            mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            version: "0.1.0".to_string(),
            state_entity_endpoint: "http://statechain".to_string(),
            chain_backend: "core".to_string(),
            chain_endpoint: "http://127.0.0.1:18443".to_string(),
            network: "regtest".to_string(),
            blockheight: 42,
            initlock: 1000,
            interval: 10,
            tokens: Vec::new(),
            activities: Vec::new(),
            coins: Vec::new(),
            settings: Settings {
                network: "regtest".to_string(),
                block_explorerURL: None,
                torProxyHost: None,
                torProxyPort: None,
                torProxyControlPassword: None,
                torProxyControlPort: None,
                statechainEntityApi: "http://statechain".to_string(),
                torStatechainEntityApi: None,
                chainBackend: "core".to_string(),
                chainUrl: "http://127.0.0.1:18443".to_string(),
                chainType: None,
                notifications: false,
                tutorials: false,
            },
        };

        let roundtrip: Wallet =
            serde_json::from_value(serde_json::to_value(wallet).unwrap()).unwrap();

        assert_eq!(roundtrip.chain_backend, "core");
        assert_eq!(roundtrip.chain_endpoint, "http://127.0.0.1:18443");
        assert_eq!(roundtrip.settings.chainBackend, "core");
        assert_eq!(roundtrip.settings.chainUrl, "http://127.0.0.1:18443");
        assert_eq!(roundtrip.settings.chainType, None);
    }
}
