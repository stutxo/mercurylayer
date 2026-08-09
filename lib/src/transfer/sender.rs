use std::str::FromStr;

use bitcoin::{hashes::sha256, secp256k1, PrivateKey, Txid};
use secp256k1::{Message, Secp256k1};
use serde::{Deserialize, Serialize};

use crate::{decode_transfer_address, error::MercuryError};

#[derive(Serialize, Deserialize)]
pub struct PaymentHashRequestPayload {
    pub statechain_id: String,
    pub auth_sig: String, // signed_statechain_id
    pub batch_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct PaymentHashResponsePayload {
    pub hash: String,
}

#[derive(Serialize, Deserialize)]
pub struct TransferSenderRequestPayload {
    pub statechain_id: String,
    pub auth_sig: String, // signed_statechain_id
    pub new_user_auth_key: String,
    pub batch_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct TransferSenderResponsePayload {
    pub x1: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TransferUpdateMsgRequestPayload {
    pub statechain_id: String,
    pub auth_sig: String, // signed_statechain_id
    pub new_user_auth_key: String,
    pub enc_transfer_msg: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TransferPreimageRequestPayload {
    pub statechain_id: String,
    pub auth_sig: String, // signed_statechain_id
    pub previous_user_auth_key: String,
    pub batch_id: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TransferPreimageResponsePayload {
    pub preimage: String, // signed_statechain_id
}

// Step 7. Owner 1 then concatinates the Tx0 outpoint with the Owner 2 public key (O2) and signs it with their key o1 to generate SC_sig_1.
pub fn create_transfer_signature(
    recipient_address: &str,
    input_txid: &str,
    input_vout: u32,
    client_seckey: &str,
) -> Result<String, MercuryError> {
    // new_user_pubkey: PublicKey, input_txid: &Txid, input_vout: u32, client_seckey: &SecretKey

    let (_, recipient_user_pubkey, _) = decode_transfer_address(recipient_address)?;

    let input_txid = Txid::from_str(&input_txid)?;
    let client_seckey = PrivateKey::from_wif(client_seckey)?.inner;

    let secp = Secp256k1::new();
    let keypair = secp256k1::KeyPair::from_seckey_slice(&secp, client_seckey.as_ref()).unwrap();

    let mut data_to_sign = Vec::<u8>::new();
    data_to_sign.extend_from_slice(&input_txid[..]);
    data_to_sign.extend_from_slice(&input_vout.to_le_bytes());
    data_to_sign.extend_from_slice(&recipient_user_pubkey.serialize()[..]);

    let msg = Message::from_hashed_data::<sha256::Hash>(&data_to_sign);
    let signature = secp.sign_schnorr(msg.as_ref(), &keypair);

    Ok(signature.to_string())
}
