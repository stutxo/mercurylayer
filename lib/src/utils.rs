use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{wallet::Coin, MercuryError};

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub initlock: u32,
    pub interval: u32,
    pub batchtimeout: u32,
    pub version: String,
}

pub fn get_network(network: &str) -> Result<bitcoin::Network, MercuryError> {
    match network {
        "signet" => Ok(bitcoin::Network::Signet),
        "testnet" => Ok(bitcoin::Network::Testnet),
        "regtest" => Ok(bitcoin::Network::Regtest),
        "bitcoin" => Ok(bitcoin::Network::Bitcoin),
        _ => Err(MercuryError::NetworkConversionError),
    }
}

pub fn is_enclave_pubkey_part_of_coin(
    coin: &Coin,
    enclave_pubkey: &str,
) -> Result<bool, MercuryError> {
    if coin.aggregated_pubkey.is_none() {
        return Err(MercuryError::NoAggregatedPubkeyError);
    }

    let enclave_pubkey = secp256k1::PublicKey::from_str(enclave_pubkey)?;

    let user_public_key = secp256k1::PublicKey::from_str(&coin.user_pubkey)?;

    let aggregate_enclave_pubkey = user_public_key.combine(&enclave_pubkey)?;

    let coin_aggregated_pubkey = coin.aggregated_pubkey.as_ref().unwrap();

    let coin_aggregated_pubkey = secp256k1::PublicKey::from_str(coin_aggregated_pubkey)?;

    return Ok(aggregate_enclave_pubkey == coin_aggregated_pubkey);
}
