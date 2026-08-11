use std::str::FromStr;

use bitcoin::{
    hashes::{sha256, Hash},
    secp256k1, PrivateKey, Txid,
};
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
    pub auth_sig: String,
    pub new_user_auth_key: String,
    pub x1_pub: String,
    pub enc_transfer_msg: String,
}

const BIP448_TRANSFER_UPDATE_MSG_DOMAIN: &[u8] = b"BIP448/transfer-update-msg/v1\0";

/// Return the exact BIP448 transfer-message generation authentication digest.
///
/// `encrypted_transfer_msg` is the decoded ciphertext, rather than its hex
/// serialization. Public keys are serialized in canonical compressed form.
pub fn bip448_transfer_update_msg_auth_digest(
    statechain_id: &str,
    recipient_auth_pubkey: &secp256k1::PublicKey,
    x1_pub: &secp256k1::PublicKey,
    encrypted_transfer_msg: &[u8],
) -> Result<[u8; 32], MercuryError> {
    let statechain_id_len = u32::try_from(statechain_id.len())
        .map_err(|_| MercuryError::InvalidStatechainAddressError)?;
    let ciphertext_hash = sha256::Hash::hash(encrypted_transfer_msg);

    let mut preimage = Vec::with_capacity(
        BIP448_TRANSFER_UPDATE_MSG_DOMAIN.len() + 4 + statechain_id.len() + 33 + 33 + 32,
    );
    preimage.extend_from_slice(BIP448_TRANSFER_UPDATE_MSG_DOMAIN);
    preimage.extend_from_slice(&statechain_id_len.to_be_bytes());
    preimage.extend_from_slice(statechain_id.as_bytes());
    preimage.extend_from_slice(&recipient_auth_pubkey.serialize());
    preimage.extend_from_slice(&x1_pub.serialize());
    preimage.extend_from_slice(ciphertext_hash.as_ref());

    Ok(sha256::Hash::hash(&preimage).to_byte_array())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn bip448_update_message_digest_is_domain_and_generation_bound() {
        let recipient = secp256k1::PublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();
        let generation = secp256k1::PublicKey::from_str(
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        )
        .unwrap();
        let digest = bip448_transfer_update_msg_auth_digest(
            "statechain-vector",
            &recipient,
            &generation,
            &[0x00, 0x01, 0xfe, 0xff],
        )
        .unwrap();

        assert_eq!(
            hex::encode(digest),
            "de2781961d35196a3ca1db8627f34be0272444bc507c8b57eb47af03ce6053b1"
        );
        assert_ne!(
            digest,
            bip448_transfer_update_msg_auth_digest(
                "statechain-vector-2",
                &recipient,
                &generation,
                &[0x00, 0x01, 0xfe, 0xff]
            )
            .unwrap()
        );
        assert_ne!(
            digest,
            bip448_transfer_update_msg_auth_digest(
                "statechain-vector",
                &generation,
                &generation,
                &[0x00, 0x01, 0xfe, 0xff]
            )
            .unwrap()
        );
        assert_ne!(
            digest,
            bip448_transfer_update_msg_auth_digest(
                "statechain-vector",
                &recipient,
                &recipient,
                &[0x00, 0x01, 0xfe, 0xff]
            )
            .unwrap()
        );
        assert_ne!(
            digest,
            bip448_transfer_update_msg_auth_digest(
                "statechain-vector",
                &recipient,
                &generation,
                &[0x00, 0x01, 0xfe, 0x00]
            )
            .unwrap()
        );
    }
}
