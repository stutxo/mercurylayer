pub mod key_derivation;

use std::{fmt, str::FromStr};

use bip39::{Language, Mnemonic};
use secp256k1::rand::{self, Rng};
use serde::{Deserialize, Serialize};

use crate::MercuryError;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Wallet {
    pub name: String,
    pub mnemonic: String,
    pub version: String,
    pub state_entity_endpoint: String,
    pub chain_backend: String,
    pub chain_endpoint: String,
    pub network: String,
    pub blockheight: u32,
    pub activities: Vec<Activity>,
    pub coins: Vec<Coin>,
    pub settings: Settings,
}

#[allow(non_snake_case)]
#[derive(Debug, Serialize, Deserialize, Clone)]
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
    /// The BIP448 recovery address derived from the user public key.
    /// The serialized field name remains `backup_address` for code stability.
    pub backup_address: String,
    pub server_pubkey: Option<String>,
    // The aggregated_pubkey is the user_pubkey + server_pubkey
    pub aggregated_pubkey: Option<String>,
    /// The aggregated address is the P2TR address from aggregated_pubkey
    pub aggregated_address: Option<String>,
    /// `None` marks a new transfer-address coin before a statechain is assigned.
    /// An initialized deposit or accepted transfer sets this to `Some("bip448")`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statechain_protocol: Option<String>,
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
    pub tx_withdraw: Option<String>,
    pub withdrawal_address: Option<String>,
    pub status: CoinStatus,
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
            _ => Err(CoinStatusParseError {}),
        }
    }
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

        let mut wallet_json = serde_json::to_value(wallet).unwrap();
        wallet_json["tokens"] = serde_json::json!([]);

        let roundtrip: Wallet = serde_json::from_value(wallet_json).unwrap();

        assert_eq!(roundtrip.chain_backend, "core");
        assert_eq!(roundtrip.chain_endpoint, "http://127.0.0.1:18443");
        assert_eq!(roundtrip.settings.chainBackend, "core");
        assert_eq!(roundtrip.settings.chainUrl, "http://127.0.0.1:18443");
        assert_eq!(roundtrip.settings.chainType, None);
    }

    #[test]
    fn fresh_coin_has_no_statechain_id_or_protocol_marker() {
        let wallet = Wallet {
            name: "wallet".to_string(),
            mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            version: "0.1.0".to_string(),
            state_entity_endpoint: "http://statechain".to_string(),
            chain_backend: "core".to_string(),
            chain_endpoint: "http://127.0.0.1:18443".to_string(),
            network: "regtest".to_string(),
            blockheight: 42,
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
        let coin = wallet.get_new_coin().unwrap();

        assert_eq!(coin.statechain_id, None);
        assert_eq!(coin.statechain_protocol, None);
    }
}
