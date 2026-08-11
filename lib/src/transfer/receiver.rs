use bitcoin::{
    hashes::{sha256, Hash},
    PrivateKey, Txid,
};
use secp256k1::{
    schnorr::Signature, KeyPair, Message, PublicKey, Secp256k1, SecretKey, Verification,
};
use serde::{Deserialize, Serialize};

use crate::{
    error::MercuryError,
    wallet::{Coin, CoinStatus, Wallet},
};

#[derive(Debug, Serialize, Deserialize)]
pub struct TransferUnlockRequestPayload {
    pub statechain_id: String,
    pub auth_sig: String,
    /// For BIP448 this is the canonical compressed public key derived from
    /// the locked transfer row's `x1`. It is a generation tag, not an
    /// authentication identity.
    pub auth_pub_key: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransferReceiverRequestPayload {
    pub statechain_id: String,
    pub batch_data: Option<String>,
    pub t2: String,
    pub auth_sig: String,
}

#[derive(Serialize, Deserialize)]
pub enum TransferReceiverError {
    StatecoinBatchLockedError,
    ExpiredBatchTimeError,
}

#[derive(Serialize, Deserialize)]
pub struct TransferReceiverErrorResponsePayload {
    pub code: TransferReceiverError,
    pub message: String,
}

#[derive(Serialize, Deserialize)]
pub struct TransferReceiverPostResponsePayload {
    pub server_pubkey: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyUpdateResponsePayload {
    pub statechain_id: String,
    pub t2: String,
    pub x1: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetMsgAddrResponsePayload {
    pub list_enc_transfer_msg: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatechainInfo {
    pub statechain_id: String,
    pub server_pubnonce: String,
    pub challenge: String,
    pub tx_n: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatechainInfoResponsePayload {
    pub enclave_public_key: String,
    pub num_sigs: u32,
    pub statechain_info: Vec<StatechainInfo>,
    pub x1_pub: Option<String>,
}

const BIP448_TRANSFER_UNLOCK_DOMAIN: &[u8] = b"BIP448/transfer-unlock/v1\0";
const BIP448_TRANSFER_RECEIVER_DOMAIN: &[u8] = b"BIP448/transfer-receiver/v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Bip448TransferUnlockRole {
    CurrentOwner,
    Recipient,
}

impl Bip448TransferUnlockRole {
    fn as_byte(self) -> u8 {
        match self {
            Self::CurrentOwner => 0x00,
            Self::Recipient => 0x01,
        }
    }
}

fn append_statechain_id(preimage: &mut Vec<u8>, statechain_id: &str) -> Result<(), MercuryError> {
    let statechain_id_len = u32::try_from(statechain_id.len())
        .map_err(|_| MercuryError::InvalidStatechainAddressError)?;
    preimage.extend_from_slice(&statechain_id_len.to_be_bytes());
    preimage.extend_from_slice(statechain_id.as_bytes());
    Ok(())
}

pub fn bip448_transfer_unlock_auth_digest(
    role: Bip448TransferUnlockRole,
    statechain_id: &str,
    x1_generation_pubkey: &PublicKey,
) -> Result<[u8; 32], MercuryError> {
    let mut preimage =
        Vec::with_capacity(BIP448_TRANSFER_UNLOCK_DOMAIN.len() + 1 + 4 + statechain_id.len() + 33);
    preimage.extend_from_slice(BIP448_TRANSFER_UNLOCK_DOMAIN);
    preimage.push(role.as_byte());
    append_statechain_id(&mut preimage, statechain_id)?;
    preimage.extend_from_slice(&x1_generation_pubkey.serialize());
    Ok(sha256::Hash::hash(&preimage).to_byte_array())
}

pub fn bip448_transfer_receiver_auth_digest(
    statechain_id: &str,
    t2: &[u8; 32],
    x1_generation_pubkey: &PublicKey,
) -> Result<[u8; 32], MercuryError> {
    let mut preimage = Vec::with_capacity(
        BIP448_TRANSFER_RECEIVER_DOMAIN.len() + 4 + statechain_id.len() + 32 + 33,
    );
    preimage.extend_from_slice(BIP448_TRANSFER_RECEIVER_DOMAIN);
    append_statechain_id(&mut preimage, statechain_id)?;
    preimage.extend_from_slice(t2);
    preimage.extend_from_slice(&x1_generation_pubkey.serialize());
    Ok(sha256::Hash::hash(&preimage).to_byte_array())
}

pub fn clone_transfer_address_coin_to_initialized_state(
    wallet: &Wallet,
    auth_pubkey: &str,
) -> Result<Coin, MercuryError> {
    let coin = wallet
        .coins
        .iter()
        .find(|coin| coin.auth_pubkey == auth_pubkey.to_string());

    if coin.is_none() {
        return Err(MercuryError::CoinNotFound);
    }

    let coin = coin.unwrap();

    Ok(Coin {
        index: coin.index,
        user_privkey: coin.user_privkey.clone(),
        user_pubkey: coin.user_pubkey.clone(),
        auth_privkey: coin.auth_privkey.clone(),
        auth_pubkey: coin.auth_pubkey.clone(),
        derivation_path: coin.derivation_path.clone(),
        fingerprint: coin.fingerprint.clone(),
        address: coin.address.clone(),
        backup_address: coin.backup_address.clone(),
        server_pubkey: None,
        aggregated_pubkey: None,
        aggregated_address: None,
        statechain_protocol: None,
        utxo_txid: None,
        utxo_vout: None,
        amount: None,
        statechain_id: None,
        signed_statechain_id: None,
        locktime: None,
        secret_nonce: None,
        public_nonce: None,
        blinding_factor: None,
        server_public_nonce: None,
        tx_withdraw: None,
        withdrawal_address: None,
        status: CoinStatus::INITIALISED,
    })
}

pub(crate) fn verify_transfer_signature_with_keys<C: Verification>(
    secp: &Secp256k1<C>,
    new_user_pubkey: &PublicKey,
    input_txid: &Txid,
    input_vout: u32,
    sender_public_key: &PublicKey,
    signature: &Signature,
) -> bool {
    let mut data_to_verify = Vec::<u8>::new();
    data_to_verify.extend_from_slice(&input_txid[..]);
    data_to_verify.extend_from_slice(&input_vout.to_le_bytes());
    data_to_verify.extend_from_slice(&new_user_pubkey.serialize()[..]);
    let msg = Message::from_hashed_data::<sha256::Hash>(&data_to_verify);

    secp.verify_schnorr(
        signature,
        msg.as_ref(),
        &sender_public_key.x_only_public_key().0,
    )
    .is_ok()
}

pub(crate) fn validate_t1pub(
    t1: &[u8; 32],
    x1_pub: &PublicKey,
    sender_public_key: &PublicKey,
) -> Result<bool, MercuryError> {
    let secret_t1 = SecretKey::from_slice(t1)?;
    let public_t1 = secret_t1.public_key(&Secp256k1::new());

    let result_pubkey = sender_public_key.combine(&x1_pub)?;

    Ok(result_pubkey == public_t1)
}

pub fn sign_message(message: &str, coin: &Coin) -> Result<String, MercuryError> {
    let client_auth_key = PrivateKey::from_wif(&coin.auth_privkey)?.inner;

    let secp = Secp256k1::new();

    let client_auth_keypair = KeyPair::from_seckey_slice(&secp, client_auth_key.as_ref())?;
    let hashed_msg = Message::from_hashed_data::<sha256::Hash>(message.to_string().as_bytes());
    let signed_message = secp.sign_schnorr(hashed_msg.as_ref(), &client_auth_keypair);

    Ok(signed_message.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::Settings;
    use std::str::FromStr;

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
    fn clone_transfer_address_coin_copies_identity_and_resets_state() {
        let mut wallet = sample_wallet();
        let mut coin = wallet.get_new_coin().unwrap();
        coin.server_pubkey = Some("server-pubkey".to_string());
        coin.aggregated_pubkey = Some("aggregated-pubkey".to_string());
        coin.aggregated_address = Some("aggregated-address".to_string());
        coin.statechain_protocol = Some("bip448".to_string());
        coin.utxo_txid = Some("utxo-txid".to_string());
        coin.utxo_vout = Some(1);
        coin.amount = Some(10_000);
        coin.statechain_id = Some("statechain-1".to_string());
        coin.signed_statechain_id = Some("signed-statechain-1".to_string());
        coin.locktime = Some(1_234);
        coin.secret_nonce = Some("secret-nonce".to_string());
        coin.public_nonce = Some("public-nonce".to_string());
        coin.blinding_factor = Some("blinding-factor".to_string());
        coin.server_public_nonce = Some("server-public-nonce".to_string());
        coin.tx_withdraw = Some("withdraw".to_string());
        coin.withdrawal_address = Some("withdrawal-address".to_string());
        coin.status = CoinStatus::CONFIRMED;
        wallet.coins.push(coin.clone());

        let cloned =
            clone_transfer_address_coin_to_initialized_state(&wallet, &coin.auth_pubkey).unwrap();

        assert_eq!(cloned.index, coin.index);
        assert_eq!(cloned.user_privkey, coin.user_privkey);
        assert_eq!(cloned.user_pubkey, coin.user_pubkey);
        assert_eq!(cloned.auth_privkey, coin.auth_privkey);
        assert_eq!(cloned.auth_pubkey, coin.auth_pubkey);
        assert_eq!(cloned.derivation_path, coin.derivation_path);
        assert_eq!(cloned.fingerprint, coin.fingerprint);
        assert_eq!(cloned.address, coin.address);
        assert_eq!(cloned.backup_address, coin.backup_address);
        assert!(cloned.server_pubkey.is_none());
        assert!(cloned.aggregated_pubkey.is_none());
        assert!(cloned.aggregated_address.is_none());
        assert!(cloned.statechain_protocol.is_none());
        assert!(cloned.utxo_txid.is_none());
        assert!(cloned.utxo_vout.is_none());
        assert!(cloned.amount.is_none());
        assert!(cloned.statechain_id.is_none());
        assert!(cloned.signed_statechain_id.is_none());
        assert!(cloned.locktime.is_none());
        assert!(cloned.secret_nonce.is_none());
        assert!(cloned.public_nonce.is_none());
        assert!(cloned.blinding_factor.is_none());
        assert!(cloned.server_public_nonce.is_none());
        assert!(cloned.tx_withdraw.is_none());
        assert!(cloned.withdrawal_address.is_none());
        assert_eq!(cloned.status, CoinStatus::INITIALISED);
    }

    #[test]
    fn bip448_unlock_digest_is_domain_role_and_generation_bound() {
        let generation = PublicKey::from_str(
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        )
        .unwrap();
        let other_generation = PublicKey::from_str(
            "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        )
        .unwrap();
        let digest = bip448_transfer_unlock_auth_digest(
            Bip448TransferUnlockRole::CurrentOwner,
            "statechain-vector",
            &generation,
        )
        .unwrap();

        assert_eq!(
            hex::encode(digest),
            "d3fdde0c6e031931fd5cac33e5f8070fd19f07a41fce544a776117aa10516b97"
        );
        assert_ne!(
            digest,
            bip448_transfer_unlock_auth_digest(
                Bip448TransferUnlockRole::Recipient,
                "statechain-vector",
                &generation
            )
            .unwrap()
        );
        assert_ne!(
            digest,
            bip448_transfer_unlock_auth_digest(
                Bip448TransferUnlockRole::CurrentOwner,
                "statechain-vector-2",
                &generation
            )
            .unwrap()
        );
        assert_ne!(
            digest,
            bip448_transfer_unlock_auth_digest(
                Bip448TransferUnlockRole::CurrentOwner,
                "statechain-vector",
                &other_generation
            )
            .unwrap()
        );
    }

    #[test]
    fn bip448_receiver_digest_is_domain_state_t2_and_generation_bound() {
        let generation = PublicKey::from_str(
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        )
        .unwrap();
        let other_generation = PublicKey::from_str(
            "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        )
        .unwrap();
        let t2 = [0x42; 32];
        let digest =
            bip448_transfer_receiver_auth_digest("statechain-vector", &t2, &generation).unwrap();

        assert_eq!(
            hex::encode(digest),
            "e8185081251d8a4b31f3e4d90eb4eb063bf19a6bda669fb8380beefefa87d81b"
        );
        assert_ne!(
            digest,
            bip448_transfer_receiver_auth_digest("statechain-vector-2", &t2, &generation).unwrap()
        );
        let mut other_t2 = t2;
        other_t2[0] ^= 1;
        assert_ne!(
            digest,
            bip448_transfer_receiver_auth_digest("statechain-vector", &other_t2, &generation)
                .unwrap()
        );
        assert_ne!(
            digest,
            bip448_transfer_receiver_auth_digest("statechain-vector", &t2, &other_generation)
                .unwrap()
        );
    }
}
