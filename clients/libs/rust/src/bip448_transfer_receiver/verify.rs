use std::str::FromStr;

use anyhow::{anyhow, Result};
use bitcoin::{consensus::deserialize, Network, OutPoint, PrivateKey, Transaction, Txid};
use mercurylib::{
    bip448_statechain::signing_api::{
        Bip448CompressedPublicKey, Bip448KeyUpdateAppliedReceiptPayloadV1, Bip448OperationId,
        Bip448ProtocolVersionV1, Bip448SchnorrSignature, Bip448SecretScalar, Bip448StatechainId,
        Bip448StatechainInfoResponsePayloadV1,
    },
    transfer::{
        bip448::{
            decrypt_bip448_transfer_msg, verify_bip448_transfer_msg, Bip448TransferChainFacts,
            Bip448TransferMsg,
        },
        receiver::{
            StatechainInfo, StatechainInfoResponsePayload, TransferReceiverRequestPayloadV1,
        },
        TxOutpoint,
    },
};
use secp256k1::{schnorr, KeyPair, PublicKey, Scalar, Secp256k1, SecretKey};

use crate::client_config::ClientConfig;

use super::Bip448VerifiedTransfer;

impl Bip448VerifiedTransfer {
    pub(super) fn new(
        msg: Bip448TransferMsg,
        statechain_info: &StatechainInfoResponsePayload,
        chain_facts: Bip448TransferChainFacts,
    ) -> Result<Self> {
        verify_bip448_transfer_msg(&msg, statechain_info, &chain_facts)?;
        let x1_generation_text = statechain_info
            .x1_pub
            .as_deref()
            .ok_or_else(|| anyhow!("BIP448 transfer statechain response has no x1 generation"))?;
        let x1_generation = PublicKey::from_str(x1_generation_text)?;
        if x1_generation.to_string() != x1_generation_text {
            return Err(anyhow!(
                "BIP448 transfer statechain response has a noncanonical x1 generation"
            ));
        }
        Ok(Self {
            msg,
            chain_facts,
            x1_generation,
        })
    }
}

pub(super) fn decrypt_transfer_message(
    enc_message: &str,
    auth_privkey: &str,
) -> Result<Bip448TransferMsg> {
    Ok(decrypt_bip448_transfer_msg(enc_message, auth_privkey)?)
}

pub(crate) async fn transfer_chain_facts(
    client_config: &ClientConfig,
    msg: &Bip448TransferMsg,
    receiver_user_pubkey: PublicKey,
    wallet_network: &str,
) -> Result<Bip448TransferChainFacts> {
    let funding_outpoint = OutPoint {
        txid: Txid::from_str(&msg.funding_outpoint.txid)?,
        vout: msg.funding_outpoint.vout,
    };
    let tx0_hex =
        super::super::get_tx0(&client_config.chain_client, &msg.funding_outpoint.txid).await?;
    let tx0: Transaction = deserialize(&hex::decode(&tx0_hex)?)?;
    let funding_output = tx0
        .output
        .get(funding_outpoint.vout as usize)
        .cloned()
        .ok_or_else(|| anyhow!("BIP448 funding output is missing from Tx0"))?;
    let (tx0_unspent, status) = super::super::verify_tx0_output_is_unspent_and_confirmed(
        &client_config.chain_client,
        &TxOutpoint {
            txid: funding_outpoint.txid.to_string(),
            vout: funding_outpoint.vout,
        },
        &tx0_hex,
        wallet_network,
        client_config.confirmation_target,
    )
    .await?;

    Ok(Bip448TransferChainFacts {
        expected_network: Network::from_str(wallet_network)?,
        median_time_past: client_config.chain_client.median_time_past()?,
        funding_outpoint,
        funding_output,
        tx0_confirmed: status == mercurylib::wallet::CoinStatus::CONFIRMED,
        tx0_unspent,
        receiver_user_pubkey,
    })
}

pub(crate) fn expected_server_pubkey(
    msg: &Bip448TransferMsg,
    receiver: &PublicKey,
) -> Result<PublicKey> {
    Ok(PublicKey::from_str(&msg.aggregate_pubkey)?.combine(&receiver.negate())?)
}

pub(super) fn statechain_info_for_verification(
    observed: &Bip448StatechainInfoResponsePayloadV1,
) -> Result<StatechainInfoResponsePayload> {
    Ok(StatechainInfoResponsePayload {
        enclave_public_key: hex::encode(observed.enclave_public_key.as_bytes()),
        num_sigs: observed.num_sigs.try_into()?,
        statechain_info: observed
            .statechain_info
            .iter()
            .map(|item| StatechainInfo {
                statechain_id: item.statechain_id.as_str().to_owned(),
                server_pubnonce: hex::encode(item.server_pubnonce.as_bytes()),
                challenge: hex::encode(item.challenge.as_bytes()),
                tx_n: item.tx_n,
            })
            .collect(),
        x1_pub: Some(hex::encode(observed.x1_pub.as_bytes())),
    })
}

pub(super) fn create_receiver_request(
    verified: &Bip448VerifiedTransfer,
    coin: &mercurylib::wallet::Coin,
    observed: &Bip448StatechainInfoResponsePayloadV1,
    operation_id: Bip448OperationId,
    recipient_unlock_auth_sig: Bip448SchnorrSignature,
) -> Result<TransferReceiverRequestPayloadV1> {
    let receiver_secret = PrivateKey::from_wif(&coin.user_privkey)?.inner;
    let t1 = Scalar::from_be_bytes(verified.msg.t1)?;
    let t2 = receiver_secret.negate().add_tweak(&t1)?;
    let t2_bytes = t2.to_secret_bytes();
    let auth_secret = PrivateKey::from_wif(&coin.auth_privkey)?.inner;
    let secp = Secp256k1::new();
    let auth_keypair = KeyPair::from_secret_key(&secp, &auth_secret);
    let transfer_generation_pubkey =
        Bip448CompressedPublicKey::from_bytes(verified.x1_generation.serialize())?;
    if transfer_generation_pubkey != observed.x1_pub {
        return Err(anyhow!(
            "BIP448 verified transfer generation does not match live state"
        ));
    }
    let mut request = TransferReceiverRequestPayloadV1 {
        protocol_version: Bip448ProtocolVersionV1,
        operation_id,
        statechain_id: Bip448StatechainId::try_from(verified.msg.statechain_id.as_str())?,
        t2: Bip448SecretScalar::from_bytes(t2_bytes)?,
        transfer_generation_pubkey,
        expected_sig_count: observed.num_sigs,
        expected_key_generation: observed.lockbox_key_generation,
        expected_server_pubkey: observed.enclave_public_key,
        recipient_unlock_auth_sig,
        auth_sig: recipient_unlock_auth_sig,
    };
    let auth_sig = schnorr::sign(&request.auth_digest()?, &auth_keypair);
    request.auth_sig = Bip448SchnorrSignature::try_from(auth_sig.to_string().as_str())?;
    Ok(request)
}

pub(super) fn verify_keyupdate_receipt(
    request: &TransferReceiverRequestPayloadV1,
    receipt: &Bip448KeyUpdateAppliedReceiptPayloadV1,
    live_after: &Bip448StatechainInfoResponsePayloadV1,
) -> Result<PublicKey> {
    let resulting_generation = request
        .expected_key_generation
        .get()
        .checked_add(1)
        .ok_or_else(|| anyhow!("BIP448 key generation overflowed"))?;
    if receipt.operation_id != request.operation_id
        || receipt.statechain_id != request.statechain_id
        || receipt.accepted_sig_count != request.expected_sig_count
        || receipt.previous_key_generation != request.expected_key_generation
        || receipt.resulting_key_generation.get() != resulting_generation
        || receipt.previous_server_pubkey != request.expected_server_pubkey
        || receipt.transfer_generation_pubkey != request.transfer_generation_pubkey
    {
        return Err(anyhow!(
            "BIP448 keyupdate receipt does not match the exact request"
        ));
    }

    let previous_server = PublicKey::from_slice(request.expected_server_pubkey.as_bytes())?;
    let t2 = SecretKey::from_secret_bytes(*request.t2.as_bytes())?;
    let transfer_generation = PublicKey::from_slice(request.transfer_generation_pubkey.as_bytes())?;
    let expected_server = previous_server
        .combine(&t2.public_key(&Secp256k1::new()))?
        .combine(&transfer_generation.negate())?;
    let resulting_server = PublicKey::from_slice(receipt.resulting_server_pubkey.as_bytes())?;
    if resulting_server != expected_server {
        return Err(anyhow!(
            "BIP448 keyupdate receipt violates transfer algebra"
        ));
    }

    if live_after.num_sigs != receipt.accepted_sig_count
        || live_after.lockbox_key_generation != receipt.resulting_key_generation
        || live_after.enclave_public_key != receipt.resulting_server_pubkey
        || live_after.x1_pub != receipt.transfer_generation_pubkey
        || live_after
            .statechain_info
            .iter()
            .any(|item| item.statechain_id != request.statechain_id)
    {
        return Err(anyhow!(
            "BIP448 keyupdate receipt does not match freshly observed live state"
        ));
    }

    Ok(resulting_server)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::transfer_receiver::bip448_transfer_receiver::test_support::{
        applied_receipt, fixture, observed_info, test_coin, MISSING_SIGNATURE,
    };
    use mercurylib::bip448_statechain::signing_api::{Bip448KeyGeneration, Bip448SignatureCount};
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    fn receiver_request_fixture() -> (
        TransferReceiverRequestPayloadV1,
        Bip448KeyUpdateAppliedReceiptPayloadV1,
        Bip448StatechainInfoResponsePayloadV1,
    ) {
        let fixture = fixture();
        let observed = observed_info();
        let verification_info = statechain_info_for_verification(&observed).unwrap();
        let verified =
            Bip448VerifiedTransfer::new(fixture.msg, &verification_info, fixture.facts).unwrap();
        let auth_secret = PrivateKey::from_wif(&fixture.coin.auth_privkey)
            .unwrap()
            .inner;
        let auth_keypair = KeyPair::from_secret_key(&Secp256k1::new(), &auth_secret);
        let unlock_digest = mercurylib::transfer::receiver::bip448_transfer_unlock_auth_digest(
            mercurylib::transfer::receiver::Bip448TransferUnlockRole::Recipient,
            &verified.msg.statechain_id,
            &verified.x1_generation,
        )
        .unwrap();
        let unlock_signature = schnorr::sign(&unlock_digest, &auth_keypair);
        let request = create_receiver_request(
            &verified,
            &fixture.coin,
            &observed,
            Bip448OperationId::from_bytes([0x77; 32]),
            Bip448SchnorrSignature::try_from(unlock_signature.to_string().as_str()).unwrap(),
        )
        .unwrap();
        let receipt = applied_receipt(&request);
        let mut live_after = observed;
        live_after.enclave_public_key = receipt.resulting_server_pubkey;
        live_after.lockbox_key_generation = receipt.resulting_key_generation;
        (request, receipt, live_after)
    }

    #[test]
    fn mirrored_t2_satisfies_continuity_equation() {
        let secp = Secp256k1::new();
        let fixture = fixture();
        let (request, _, _) = receiver_request_fixture();
        let t2_g = SecretKey::from_secret_bytes(*request.t2.as_bytes())
            .unwrap()
            .public_key(&secp);
        let t1_g = SecretKey::from_secret_bytes(fixture.msg.t1)
            .unwrap()
            .public_key(&secp);
        let receiver = PublicKey::from_str(&fixture.coin.user_pubkey).unwrap();

        assert_eq!(t2_g, t1_g.combine(&receiver.negate()).unwrap());
        assert_eq!(request.expected_sig_count, observed_info().num_sigs);
        assert_eq!(
            request.expected_key_generation,
            observed_info().lockbox_key_generation
        );
        assert_eq!(
            request.expected_server_pubkey,
            observed_info().enclave_public_key
        );
        let auth = PrivateKey::from_wif(&fixture.coin.auth_privkey)
            .unwrap()
            .inner
            .public_key(&secp)
            .x_only_public_key()
            .0;
        schnorr::verify(
            &schnorr::Signature::from_byte_array(*request.auth_sig.as_bytes()),
            &request.auth_digest().unwrap(),
            &auth,
        )
        .unwrap();
    }

    #[test]
    fn live_signature_count_remains_authoritative_for_history_verification() {
        let fixture = fixture();
        let mut observed = observed_info();
        observed.num_sigs = Bip448SignatureCount::new(observed.num_sigs.get() + 1);
        let verification_info = statechain_info_for_verification(&observed).unwrap();

        assert!(
            Bip448VerifiedTransfer::new(fixture.msg, &verification_info, fixture.facts).is_err()
        );
    }

    #[test]
    fn receipt_and_fresh_live_state_bind_every_handoff_field() {
        let (request, receipt, live_after) = receiver_request_fixture();
        assert!(verify_keyupdate_receipt(&request, &receipt, &live_after).is_ok());

        let other_key = Bip448CompressedPublicKey::from_bytes(
            SecretKey::from_secret_bytes([0x33; 32])
                .unwrap()
                .public_key(&Secp256k1::new())
                .serialize(),
        )
        .unwrap();
        let mut mismatches = Vec::new();
        let mut changed = receipt.clone();
        changed.operation_id = Bip448OperationId::from_bytes([0x44; 32]);
        mismatches.push(changed);
        let mut changed = receipt.clone();
        changed.statechain_id = Bip448StatechainId::try_from("other-statechain").unwrap();
        mismatches.push(changed);
        let mut changed = receipt.clone();
        changed.accepted_sig_count =
            Bip448SignatureCount::new(receipt.accepted_sig_count.get() + 1);
        mismatches.push(changed);
        let mut changed = receipt.clone();
        changed.previous_key_generation =
            Bip448KeyGeneration::new(receipt.previous_key_generation.get() + 1);
        mismatches.push(changed);
        let mut changed = receipt.clone();
        changed.resulting_key_generation =
            Bip448KeyGeneration::new(receipt.resulting_key_generation.get() + 1);
        mismatches.push(changed);
        let mut changed = receipt.clone();
        changed.previous_server_pubkey = other_key;
        mismatches.push(changed);
        let mut changed = receipt.clone();
        changed.resulting_server_pubkey = other_key;
        mismatches.push(changed);
        let mut changed = receipt.clone();
        changed.transfer_generation_pubkey = other_key;
        mismatches.push(changed);
        for mismatch in mismatches {
            assert!(verify_keyupdate_receipt(&request, &mismatch, &live_after).is_err());
        }

        let mut wrong_n = live_after.clone();
        wrong_n.num_sigs = Bip448SignatureCount::new(wrong_n.num_sigs.get() + 1);
        assert!(verify_keyupdate_receipt(&request, &receipt, &wrong_n).is_err());
        let mut wrong_g = live_after.clone();
        wrong_g.lockbox_key_generation =
            Bip448KeyGeneration::new(wrong_g.lockbox_key_generation.get() + 1);
        assert!(verify_keyupdate_receipt(&request, &receipt, &wrong_g).is_err());
        let mut wrong_s = live_after.clone();
        wrong_s.enclave_public_key = request.expected_server_pubkey;
        assert!(verify_keyupdate_receipt(&request, &receipt, &wrong_s).is_err());
        let mut wrong_x1 = live_after;
        wrong_x1.x1_pub = other_key;
        assert!(verify_keyupdate_receipt(&request, &receipt, &wrong_x1).is_err());
    }

    #[test]
    #[rustfmt::skip]
    fn version_one_plaintext_missing_transfer_signature_is_rejected_without_panic() {
        let coin = test_coin(5, 8);
        let result = std::panic::catch_unwind(|| decrypt_transfer_message(MISSING_SIGNATURE, &coin.auth_privkey));
        assert!(result.is_ok());
        assert!(result.unwrap().is_err());
    }
}
