use std::str::FromStr;

use anyhow::{anyhow, Result};
use bitcoin::{consensus::deserialize, Network, OutPoint, PrivateKey, Transaction, Txid};
use mercurylib::transfer::{
    bip448::{
        decrypt_bip448_transfer_msg, verify_bip448_transfer_msg, Bip448TransferChainFacts,
        Bip448TransferMsg,
    },
    receiver::{StatechainInfoResponsePayload, TransferReceiverRequestPayload},
    TxOutpoint,
};
use secp256k1::{schnorr, KeyPair, PublicKey, Scalar, Secp256k1};

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

pub(super) fn create_receiver_request(
    msg: &Bip448TransferMsg,
    coin: &mercurylib::wallet::Coin,
    x1_generation: &PublicKey,
) -> Result<TransferReceiverRequestPayload> {
    let receiver_secret = PrivateKey::from_wif(&coin.user_privkey)?.inner;
    let t1 = Scalar::from_be_bytes(msg.t1)?;
    let t2 = receiver_secret.negate().add_tweak(&t1)?;
    let t2_bytes = t2.to_secret_bytes();
    let t2 = hex::encode(t2_bytes);
    let auth_secret = PrivateKey::from_wif(&coin.auth_privkey)?.inner;
    let secp = Secp256k1::new();
    let auth_keypair = KeyPair::from_secret_key(&secp, &auth_secret);
    let auth_message = mercurylib::transfer::receiver::bip448_transfer_receiver_auth_digest(
        &msg.statechain_id,
        &t2_bytes,
        x1_generation,
    )?;
    let auth_sig = schnorr::sign(&auth_message, &auth_keypair);

    Ok(TransferReceiverRequestPayload {
        statechain_id: msg.statechain_id.clone(),
        batch_data: Some(x1_generation.to_string()),
        t2,
        auth_sig: auth_sig.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::transfer_receiver::bip448_transfer_receiver::test_support::{
        test_coin, INFO, MISSING_SIGNATURE, MSG,
    };
    use mercurylib::transfer::receiver::StatechainInfoResponsePayload;
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    #[test]
    fn mirrored_t2_satisfies_continuity_equation() {
        let secp = Secp256k1::new();
        let msg: Bip448TransferMsg = serde_json::from_str(MSG).unwrap();
        let info: StatechainInfoResponsePayload = serde_json::from_str(INFO).unwrap();
        let generation = PublicKey::from_str(info.x1_pub.as_deref().unwrap()).unwrap();
        let coin = test_coin(5, 8);
        let request = create_receiver_request(&msg, &coin, &generation).unwrap();
        let t2_bytes: [u8; 32] = hex::decode(request.t2).unwrap().try_into().unwrap();
        let t2_g = SecretKey::from_secret_bytes(t2_bytes)
            .unwrap()
            .public_key(&secp);
        let t1_g = SecretKey::from_secret_bytes(msg.t1)
            .unwrap()
            .public_key(&secp);
        let receiver = PublicKey::from_str(&coin.user_pubkey).unwrap();

        assert_eq!(t2_g, t1_g.combine(&receiver.negate()).unwrap());
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
