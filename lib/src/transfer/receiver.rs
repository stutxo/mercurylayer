use bitcoin::{
    hashes::{sha256, Hash},
    PrivateKey, Txid,
};
use secp256k1::{
    schnorr::Signature, KeyPair, Message, PublicKey, Secp256k1, SecretKey, Verification,
};
use serde::{Deserialize, Serialize};

use crate::{
    bip448_statechain::signing_api::{
        Bip448CompressedPublicKey, Bip448KeyGeneration, Bip448OperationId, Bip448ProtocolVersionV2,
        Bip448SchnorrSignature, Bip448SecretScalar, Bip448SignatureCount, Bip448StatechainId,
        Bip448WireError,
    },
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
const BIP448_TRANSFER_RECEIVER_V2_DOMAIN: &[u8] = b"BIP448/transfer-receiver/v2\0";

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TransferReceiverRequestPayloadV2 {
    pub protocol_version: Bip448ProtocolVersionV2,
    pub operation_id: Bip448OperationId,
    pub statechain_id: Bip448StatechainId,
    pub t2: Bip448SecretScalar,
    pub transfer_generation_pubkey: Bip448CompressedPublicKey,
    pub expected_sig_count: Bip448SignatureCount,
    pub expected_key_generation: Bip448KeyGeneration,
    pub expected_server_pubkey: Bip448CompressedPublicKey,
    pub recipient_unlock_auth_sig: Bip448SchnorrSignature,
    pub auth_sig: Bip448SchnorrSignature,
}

impl TransferReceiverRequestPayloadV2 {
    pub fn canonical_auth_preimage(&self) -> Result<Vec<u8>, Bip448WireError> {
        let statechain_id = self.statechain_id.as_str().as_bytes();
        let statechain_id_len = u32::try_from(statechain_id.len())
            .map_err(|_| Bip448WireError::StatechainIdLengthOverflow)?;
        let mut preimage = Vec::with_capacity(
            BIP448_TRANSFER_RECEIVER_V2_DOMAIN.len()
                + 32
                + 4
                + statechain_id.len()
                + 32
                + 33
                + 8
                + 8
                + 33
                + 64,
        );
        preimage.extend_from_slice(BIP448_TRANSFER_RECEIVER_V2_DOMAIN);
        preimage.extend_from_slice(self.operation_id.as_bytes());
        preimage.extend_from_slice(&statechain_id_len.to_be_bytes());
        preimage.extend_from_slice(statechain_id);
        preimage.extend_from_slice(self.t2.as_bytes());
        preimage.extend_from_slice(self.transfer_generation_pubkey.as_bytes());
        preimage.extend_from_slice(&self.expected_sig_count.get().to_be_bytes());
        preimage.extend_from_slice(&self.expected_key_generation.get().to_be_bytes());
        preimage.extend_from_slice(self.expected_server_pubkey.as_bytes());
        preimage.extend_from_slice(self.recipient_unlock_auth_sig.as_bytes());
        Ok(preimage)
    }

    pub fn auth_digest(&self) -> Result<[u8; 32], Bip448WireError> {
        Ok(sha256::Hash::hash(&self.canonical_auth_preimage()?).to_byte_array())
    }
}

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

    const V2_OPERATION_ID: &str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const V2_TRANSFER_KEY: &str =
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const V2_SERVER_KEY: &str =
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    const V2_RECIPIENT_SIGNATURE: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";

    fn v2_signature(byte: u8) -> Bip448SchnorrSignature {
        Bip448SchnorrSignature::try_from(hex::encode([byte; 64]).as_str()).unwrap()
    }

    fn v2_request() -> TransferReceiverRequestPayloadV2 {
        TransferReceiverRequestPayloadV2 {
            protocol_version: Bip448ProtocolVersionV2,
            operation_id: Bip448OperationId::try_from(V2_OPERATION_ID).unwrap(),
            statechain_id: Bip448StatechainId::try_from("statechain-vector-v2").unwrap(),
            t2: Bip448SecretScalar::from_bytes([0x11; 32]).unwrap(),
            transfer_generation_pubkey: Bip448CompressedPublicKey::try_from(V2_TRANSFER_KEY)
                .unwrap(),
            expected_sig_count: Bip448SignatureCount::new(0x0102_0304_0506_0708),
            expected_key_generation: Bip448KeyGeneration::new(0x1112_1314_1516_1718),
            expected_server_pubkey: Bip448CompressedPublicKey::try_from(V2_SERVER_KEY).unwrap(),
            recipient_unlock_auth_sig: Bip448SchnorrSignature::try_from(V2_RECIPIENT_SIGNATURE)
                .unwrap(),
            auth_sig: v2_signature(0x11),
        }
    }

    fn v2_json_keys(
        request: &TransferReceiverRequestPayloadV2,
    ) -> std::collections::BTreeSet<String> {
        serde_json::to_value(request)
            .unwrap()
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect()
    }

    #[test]
    fn bip448_receiver_v2_digest_matches_independent_literal_vector() {
        const PREIMAGE_HEX: &str = "4249503434382f7472616e736665722d72656365697665722f763200000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000000147374617465636861696e2d766563746f722d763211111111111111111111111111111111111111111111111111111111111111110279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817980102030405060708111213141516171802c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
        const DIGEST_HEX: &str = "16ede35157adf3b73226f6af70c94ba28fcb50792648fb3debfe7da966fae813";

        let request = v2_request();
        assert_eq!(
            hex::encode(request.canonical_auth_preimage().unwrap()),
            PREIMAGE_HEX
        );
        assert_eq!(hex::encode(request.auth_digest().unwrap()), DIGEST_HEX);
    }

    #[test]
    fn bip448_receiver_v2_digest_binds_every_preimage_field_only() {
        let request = v2_request();
        let digest = request.auth_digest().unwrap();
        let mut mutations = Vec::new();

        let mut changed = request.clone();
        changed.operation_id = Bip448OperationId::from_bytes([0x44; 32]);
        mutations.push(changed);
        let mut changed = request.clone();
        changed.statechain_id = Bip448StatechainId::try_from("statechain-vector-v3").unwrap();
        mutations.push(changed);
        let mut changed = request.clone();
        changed.t2 = Bip448SecretScalar::from_bytes([0x12; 32]).unwrap();
        mutations.push(changed);
        let mut changed = request.clone();
        changed.transfer_generation_pubkey =
            Bip448CompressedPublicKey::try_from(V2_SERVER_KEY).unwrap();
        mutations.push(changed);
        let mut changed = request.clone();
        changed.expected_sig_count =
            Bip448SignatureCount::new(request.expected_sig_count.get().checked_add(1).unwrap());
        mutations.push(changed);
        let mut changed = request.clone();
        changed.expected_key_generation = Bip448KeyGeneration::new(
            request
                .expected_key_generation
                .get()
                .checked_add(1)
                .unwrap(),
        );
        mutations.push(changed);
        let mut changed = request.clone();
        changed.expected_server_pubkey =
            Bip448CompressedPublicKey::try_from(V2_TRANSFER_KEY).unwrap();
        mutations.push(changed);
        let mut changed = request.clone();
        changed.recipient_unlock_auth_sig = v2_signature(0x12);
        mutations.push(changed);

        for changed in mutations {
            assert_ne!(changed.auth_digest().unwrap(), digest);
        }

        let mut changed_auth_sig = request.clone();
        changed_auth_sig.auth_sig = v2_signature(0x22);
        assert_eq!(changed_auth_sig.auth_digest().unwrap(), digest);
    }

    #[test]
    fn bip448_receiver_v2_json_has_exact_key_set_and_no_forbidden_metadata() {
        let request = v2_request();
        assert_eq!(
            v2_json_keys(&request),
            [
                "auth_sig",
                "expected_key_generation",
                "expected_server_pubkey",
                "expected_sig_count",
                "operation_id",
                "protocol_version",
                "recipient_unlock_auth_sig",
                "statechain_id",
                "t2",
                "transfer_generation_pubkey",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        );

        let json = serde_json::to_string(&request).unwrap();
        for forbidden in [
            "batch_data",
            "transaction",
            "txid",
            "outpoint",
            "amount",
            "script",
            "destination",
            "state_number",
            "signing_role",
            "template_hash",
            "recovery_address",
            "fee_policy",
            "sender",
        ] {
            assert!(
                !json.contains(forbidden),
                "v2 receiver request exposed forbidden sentinel {forbidden}: {json}"
            );
        }
        for forbidden_value in [
            "02000000deadbeef",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:7",
            "5120bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ] {
            assert!(!json.contains(forbidden_value));
        }
    }

    #[test]
    fn bip448_receiver_v2_rejects_unknown_missing_null_and_normalized_hex() {
        let request = v2_request();
        let value = serde_json::to_value(&request).unwrap();
        let fields: Vec<String> = value.as_object().unwrap().keys().cloned().collect();

        let mut unknown = value.clone();
        unknown["batch_data"] = serde_json::json!("forbidden");
        assert!(serde_json::from_value::<TransferReceiverRequestPayloadV2>(unknown).is_err());

        for field in &fields {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<TransferReceiverRequestPayloadV2>(missing).is_err(),
                "missing field {field} was accepted"
            );

            let mut null = value.clone();
            null[field] = serde_json::Value::Null;
            assert!(
                serde_json::from_value::<TransferReceiverRequestPayloadV2>(null).is_err(),
                "explicit null for {field} was accepted"
            );
        }

        let mut wrong_version = value.clone();
        wrong_version["protocol_version"] = serde_json::json!(1);
        assert!(serde_json::from_value::<TransferReceiverRequestPayloadV2>(wrong_version).is_err());

        for field in [
            "operation_id",
            "t2",
            "transfer_generation_pubkey",
            "expected_server_pubkey",
            "recipient_unlock_auth_sig",
            "auth_sig",
        ] {
            let mut uppercase = value.clone();
            let uppercase_value = match field {
                "t2" => "AA".repeat(32),
                "auth_sig" => "AA".repeat(64),
                _ => value[field].as_str().unwrap().to_ascii_uppercase(),
            };
            uppercase[field] = serde_json::json!(uppercase_value);
            assert!(
                serde_json::from_value::<TransferReceiverRequestPayloadV2>(uppercase).is_err(),
                "uppercase field {field} was normalized"
            );
        }
    }
}
