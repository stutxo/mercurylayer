use std::str::FromStr;

use crate::{error::MercuryError, wallet::Coin};
use bitcoin::{hashes::sha256, secp256k1, PrivateKey};
use secp256k1::{Message, PublicKey, Secp256k1};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenID {
    pub token_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub token_id: String,
    pub payment_method: String,
    pub deposit_address: Option<String>,
    pub fee: u64,
    pub confirmation_target: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DepositMsg1 {
    pub auth_key: String,
    pub token_id: String,
    pub signed_token_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DepositMsg1Response {
    pub server_pubkey: String,
    pub statechain_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DepositInitResult {
    pub server_pubkey: String,
    pub statechain_id: String,
    pub signed_statechain_id: String,
}

pub fn create_deposit_msg1(coin: &Coin, token_id: &str) -> Result<DepositMsg1, MercuryError> {
    let msg = Message::from_hashed_data::<sha256::Hash>(token_id.to_string().as_bytes());

    let secp = Secp256k1::new();
    let auth_secret_key = PrivateKey::from_wif(&coin.auth_privkey)?.inner;
    let keypair = secp256k1::KeyPair::from_seckey_slice(&secp, auth_secret_key.as_ref())?;
    let signed_token_id = secp.sign_schnorr(msg.as_ref(), &keypair);

    let auth_xonly_pubkey = PublicKey::from_str(&coin.auth_pubkey)?
        .x_only_public_key()
        .0;

    let deposit_msg_1 = DepositMsg1 {
        auth_key: auth_xonly_pubkey.to_string(),
        token_id: token_id.to_string(),
        signed_token_id: signed_token_id.to_string(),
    };

    Ok(deposit_msg_1)
}

pub fn handle_deposit_msg_1_response(
    coin: &Coin,
    deposit_msg_1_response: &DepositMsg1Response,
) -> Result<DepositInitResult, MercuryError> {
    let secp = Secp256k1::new();

    let server_pubkey_share = PublicKey::from_str(&deposit_msg_1_response.server_pubkey).unwrap();

    let statechain_id = deposit_msg_1_response.statechain_id.to_string();

    let auth_secret_key = PrivateKey::from_wif(&coin.auth_privkey)?.inner;
    let keypair = secp256k1::KeyPair::from_seckey_slice(&secp, auth_secret_key.as_ref()).unwrap();

    let msg = Message::from_hashed_data::<sha256::Hash>(statechain_id.to_string().as_bytes());
    let signed_statechain_id = secp.sign_schnorr(msg.as_ref(), &keypair);

    Ok(DepositInitResult {
        server_pubkey: server_pubkey_share.to_string(),
        statechain_id,
        signed_statechain_id: signed_statechain_id.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::{Settings, Wallet};
    use secp256k1::{schnorr::Signature, XOnlyPublicKey};

    fn sample_wallet() -> Wallet {
        Wallet {
            name: "wallet".to_string(),
            mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            version: "0.1.0".to_string(),
            state_entity_endpoint: "http://statechain".to_string(),
            chain_backend: "core".to_string(),
            chain_endpoint: "http://127.0.0.1:18443".to_string(),
            network: "regtest".to_string(),
            blockheight: 0,
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
        }
    }

    #[test]
    fn create_deposit_msg1_signs_token_with_coin_auth_key() {
        let coin = sample_wallet().get_new_coin().unwrap();
        let token_id = "token-123";

        let deposit_msg = create_deposit_msg1(&coin, token_id).unwrap();
        let auth_key = XOnlyPublicKey::from_str(&deposit_msg.auth_key).unwrap();
        let signature = Signature::from_str(&deposit_msg.signed_token_id).unwrap();
        let message = Message::from_hashed_data::<sha256::Hash>(token_id.as_bytes());

        assert_eq!(
            deposit_msg.auth_key,
            PublicKey::from_str(&coin.auth_pubkey)
                .unwrap()
                .x_only_public_key()
                .0
                .to_string()
        );
        assert!(Secp256k1::new()
            .verify_schnorr(&signature, message.as_ref(), &auth_key)
            .is_ok());
    }
}
