use std::{collections::BTreeMap, str::FromStr};

use bitcoin::{
    absolute,
    hashes::Hash,
    psbt::Psbt,
    sighash::{self, SighashCache, TapSighash, TapSighashType},
    taproot::{self, TapTweakHash, TaprootSpendInfo},
    Address, Network, OutPoint, PrivateKey, ScriptBuf, Transaction, TxIn, TxOut, Witness,
};
use secp256k1::{
    musig::{
        blinded_musig_negate_seckey, blinded_musig_pubkey_xonly_tweak_add, new_musig_nonce_pair,
        AggregatedNonce as MusigAggNonce, BlindingFactor, MusigSessionId,
        PartialSignature as MusigPartialSignature, PublicNonce as MusigPubNonce,
        SecretNonce as MusigSecNonce, Session as MusigSession,
    },
    rand::{self, Rng},
    schnorr::Signature,
    KeyPair, Message, PublicKey, Secp256k1, SecretKey,
};
use serde::{Deserialize, Serialize};

use crate::{decode_transfer_address, error::MercuryError, wallet::Coin};

#[derive(Serialize, Deserialize)]
pub struct Bip448KeypathNonce {
    pub secret_nonce: String,
    pub public_nonce: String,
    pub blinding_factor: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Bip448KeypathPartialSignatureRequest {
    pub statechain_id: String,
    pub negate_seckey: u8,
    pub session: String,
    pub signed_statechain_id: String,
    pub server_pub_nonce: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Bip448WithdrawalSigningData {
    pub msg: String,
    pub output_pubkey: String, // the tweaked pubkey
    pub client_partial_sig: String,
    pub encoded_session: String,
    pub encoded_unsigned_tx: String,
    pub partial_signature_request_payload: Bip448KeypathPartialSignatureRequest,
}

pub fn create_bip448_keypath_nonces(
    coin: &Coin,
) -> core::result::Result<Bip448KeypathNonce, MercuryError> {
    let secp = Secp256k1::new();

    let client_session_id = MusigSessionId::new(&mut rand::thread_rng());

    let client_seckey = PrivateKey::from_wif(&coin.user_privkey)?.inner;
    let client_pubkey = PublicKey::from_str(&coin.user_pubkey)?;

    let (client_sec_nonce, client_pub_nonce) = new_musig_nonce_pair(
        &secp,
        client_session_id,
        None,
        Some(client_seckey),
        client_pubkey,
        None,
        None,
    )?;

    let blinding_factor = BlindingFactor::new(&mut rand::thread_rng());

    Ok(Bip448KeypathNonce {
        secret_nonce: hex::encode(client_sec_nonce.serialize()),
        public_nonce: hex::encode(client_pub_nonce.serialize()),
        blinding_factor: hex::encode(blinding_factor.as_bytes()),
    })
}

/// The purpose of this function is to get a random locktime for the withdrawal transaction.
/// This is done to improve privacy and discourage fee sniping.
/// This function assumes that the block_height is the current block height.
fn get_locktime_for_withdrawal_transaction(block_height: u32) -> u32 {
    let mut locktime = block_height as i32;

    let mut rng = rand::thread_rng();
    let number = rng.gen_range(0..=10);

    // sometimes locktime is set a bit further back, for privacy reasons
    if number == 0 {
        locktime = locktime - rng.gen_range(0..=99);
    }

    std::cmp::max(0, locktime) as u32
}

fn create_tx_out(
    coin: &Coin,
    fee_rate_sats_per_byte: f64,
    to_address: &str,
    network: Network,
) -> core::result::Result<TxOut, MercuryError> {
    const BACKUP_TX_SIZE: u64 = 112; // virtual size one input P2TR and one output P2TR
                                     // 163 is the real size one input P2TR and one output P2TR

    let input_amount = coin.amount.unwrap() as u64;
    let absolute_fee = (BACKUP_TX_SIZE as f64 * fee_rate_sats_per_byte).ceil() as u64;
    let amount_out = input_amount - absolute_fee;

    let recipient_address = if to_address.starts_with(crate::MAINNET_HRP)
        || to_address.starts_with(crate::TESTNET_HRP)
    {
        let (_, recipient_user_pubkey, _) = decode_transfer_address(to_address)?;
        let new_address = Address::p2tr(
            &Secp256k1::new(),
            recipient_user_pubkey.x_only_public_key().0,
            None,
            network,
        );
        new_address
    } else {
        let new_address = Address::from_str(&to_address)
            .unwrap()
            .require_network(network)?;
        new_address
    };

    let tx_out = TxOut {
        value: amount_out,
        script_pubkey: recipient_address.script_pubkey(),
    };

    Ok(tx_out)
}

pub fn build_bip448_withdrawal_signing_data(
    coin: &Coin,
    funding_outpoint: OutPoint,
    funding_value_sats: u64,
    block_height: u32,
    fee_rate_sats_per_byte: f64,
    to_address: &str,
    network: Network,
) -> core::result::Result<Bip448WithdrawalSigningData, MercuryError> {
    let secp = Secp256k1::new();
    let aggregate_pubkey = PublicKey::from_str(
        coin.aggregated_pubkey
            .as_deref()
            .ok_or(MercuryError::TransactionReconstructionError)?,
    )?;
    let funding_spend_info = crate::bip448_statechain::script::funding_spend_info(
        &secp,
        aggregate_pubkey.x_only_public_key().0,
    )
    .map_err(|_| MercuryError::TransactionReconstructionError)?;
    let funding_script =
        crate::bip448_statechain::script::output_script_pubkey(&funding_spend_info);
    let recorded_script = Address::from_str(
        coin.aggregated_address
            .as_deref()
            .ok_or(MercuryError::TransactionReconstructionError)?,
    )?
    .require_network(network)?
    .script_pubkey();
    if recorded_script != funding_script
        || coin.utxo_txid.as_deref() != Some(&funding_outpoint.txid.to_string())
        || coin.utxo_vout != Some(funding_outpoint.vout)
        || coin.amount.map(u64::from) != Some(funding_value_sats)
    {
        return Err(MercuryError::TransactionReconstructionError);
    }

    let unsigned_tx = Transaction {
        version: 2,
        lock_time: absolute::LockTime::from_height(get_locktime_for_withdrawal_transaction(
            block_height,
        ))?,
        input: vec![TxIn {
            previous_output: funding_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence(0),
            witness: Witness::default(),
        }],
        output: vec![create_tx_out(
            coin,
            fee_rate_sats_per_byte,
            to_address,
            network,
        )?],
    };
    let funding_output = TxOut {
        value: funding_value_sats,
        script_pubkey: funding_script,
    };
    let hash = SighashCache::new(&unsigned_tx).taproot_key_spend_signature_hash(
        0,
        &sighash::Prevouts::All(&[funding_output]),
        TapSighashType::All,
    )?;
    let encoded_unsigned_tx = hex::encode(bitcoin::consensus::encode::serialize(&unsigned_tx));

    calculate_bip448_keypath_musig_session(coin, hash, encoded_unsigned_tx, &funding_spend_info)
}

fn calculate_bip448_keypath_musig_session(
    coin: &Coin,
    hash: TapSighash,
    encoded_unsigned_tx: String,
    funding_spend_info: &TaprootSpendInfo,
) -> core::result::Result<Bip448WithdrawalSigningData, MercuryError> {
    let secp = Secp256k1::new();

    let aggregate_pubkey = PublicKey::from_str(&coin.aggregated_pubkey.as_ref().unwrap())?;

    let tap_tweak = TapTweakHash::from_key_and_tweak(
        aggregate_pubkey.x_only_public_key().0,
        funding_spend_info.merkle_root(),
    );
    let tap_tweak_bytes = tap_tweak.as_byte_array();

    // tranform tweak: Scalar to SecretKey
    let tweak = SecretKey::from_slice(tap_tweak_bytes)?;

    let (parity_acc, output_pubkey, out_tweak32) =
        blinded_musig_pubkey_xonly_tweak_add(&secp, &aggregate_pubkey, tweak);

    let client_pub_nonce_bytes = hex::decode(coin.public_nonce.as_ref().unwrap())?;
    let client_pub_nonce = MusigPubNonce::from_slice(client_pub_nonce_bytes.as_slice())?;

    let server_pubnonce_hex = coin.server_public_nonce.as_ref().unwrap().to_string();
    let server_pub_nonce_bytes = hex::decode(&server_pubnonce_hex)?;
    let server_pub_nonce = MusigPubNonce::from_slice(server_pub_nonce_bytes.as_slice())?;

    let aggnonce = MusigAggNonce::new(&[&client_pub_nonce, &server_pub_nonce]);

    let blinding_factor_bytes = hex::decode(coin.blinding_factor.as_ref().unwrap())?;
    let blinding_factor = BlindingFactor::from_slice(blinding_factor_bytes.as_slice())?;

    let msg: Message = hash.into();

    let session = MusigSession::new_blinded_without_key_agg_cache(
        &secp,
        &output_pubkey,
        aggnonce,
        msg,
        None,
        &blinding_factor,
        out_tweak32,
    );

    let negate_seckey = blinded_musig_negate_seckey(&secp, &output_pubkey, parity_acc);

    let client_seckey = PrivateKey::from_wif(&coin.user_privkey)?.inner;

    let client_pubkey = PublicKey::from_str(&coin.user_pubkey)?;

    let client_keypair = KeyPair::from_secret_key(&secp, &client_seckey);

    let client_sec_nonce_bytes = hex::decode(coin.secret_nonce.as_ref().unwrap())?;
    let client_sec_nonce_bytes: [u8; 132] = client_sec_nonce_bytes.try_into().unwrap();
    let client_sec_nonce = MusigSecNonce::from_slice(client_sec_nonce_bytes);

    let client_partial_sig = session.blinded_partial_sign_without_keyaggcoeff(
        &secp,
        client_sec_nonce,
        &client_keypair,
        negate_seckey,
    )?;

    assert!(session.blinded_musig_partial_sig_verify(
        &secp,
        &client_partial_sig,
        &client_pub_nonce,
        &client_pubkey,
        &output_pubkey,
        parity_acc
    ));

    let encoded_session = hex::encode(session.serialize());

    session.remove_fin_nonce_from_session();

    let negate_seckey = match negate_seckey {
        true => 1,
        false => 0,
    };

    let blinded_session = session.remove_fin_nonce_from_session();

    let statechain_id = coin.statechain_id.as_ref().unwrap();
    let signed_statechain_id = coin.signed_statechain_id.as_ref().unwrap();

    let payload = Bip448KeypathPartialSignatureRequest {
        statechain_id: statechain_id.to_string(),
        negate_seckey,
        session: hex::encode(blinded_session.serialize()),
        signed_statechain_id: signed_statechain_id.to_string(),
        server_pub_nonce: server_pubnonce_hex,
    };

    let client_partial_sig_hex = hex::encode(client_partial_sig.serialize());

    Ok(Bip448WithdrawalSigningData {
        msg: hex::encode(hash.as_byte_array()),
        output_pubkey: output_pubkey.to_string(),
        client_partial_sig: client_partial_sig_hex,
        encoded_session,
        encoded_unsigned_tx,
        partial_signature_request_payload: payload,
    })
}

pub fn aggregate_bip448_keypath_signature(
    msg: String,
    client_partial_sig_hex: String,
    server_partial_sig_hex: String,
    session_hex: String,
    output_pubkey_hex: String,
) -> core::result::Result<String, MercuryError> {
    let msg = Message::from_slice(hex::decode(msg)?.as_slice())?;

    let server_partial_sig_bytes = hex::decode(server_partial_sig_hex)?;
    let server_partial_sig =
        MusigPartialSignature::from_slice(server_partial_sig_bytes.as_slice())?;

    let client_partial_sig_bytes = hex::decode(client_partial_sig_hex)?;
    let client_partial_sig =
        MusigPartialSignature::from_slice(client_partial_sig_bytes.as_slice())?;

    let session_bytes: [u8; 133] = hex::decode(&session_hex)?.try_into().unwrap();
    let session = MusigSession::from_slice(session_bytes);

    let aggregated_sig = session.partial_sig_agg(&[&client_partial_sig, &server_partial_sig]);

    let output_pubkey = PublicKey::from_str(&output_pubkey_hex)?;

    let x_only_key_tweaked = output_pubkey.x_only_public_key().0;

    let sig = aggregated_sig
        .verify(&x_only_key_tweaked, msg.as_ref())
        .map_err(|_| MercuryError::SchnorrSignatureValidationError)?;

    Ok(sig.to_string())
}

pub fn finalize_bip448_keypath_transaction(
    encoded_unsigned_tx: String,
    signature_hex: String,
) -> core::result::Result<String, MercuryError> {
    let tx_bytes = hex::decode(encoded_unsigned_tx)?;
    let tx: Transaction = bitcoin::consensus::encode::deserialize(&tx_bytes)?;

    let mut psbt = Psbt::from_unsigned_tx(tx)?;

    if psbt.inputs.len() != 1 {
        return Err(MercuryError::MoreThanOneInputError);
    }

    let vout = 0;
    let input = psbt.inputs.iter_mut().nth(vout).unwrap();

    let hash_ty = input
        .sighash_type
        .and_then(|psbt_sighash_type| psbt_sighash_type.taproot_hash_ty().ok())
        .unwrap_or(TapSighashType::All);

    let sig = Signature::from_str(signature_hex.as_str())?;

    let final_signature = taproot::Signature { sig, hash_ty };

    input.tap_key_sig = Some(final_signature);

    psbt.inputs.iter_mut().for_each(|input| {
        let mut script_witness: Witness = Witness::new();
        script_witness.push(input.tap_key_sig.unwrap().to_vec());
        input.final_script_witness = Some(script_witness);

        // Clear all the data fields as per the spec.
        input.partial_sigs = BTreeMap::new();
        input.sighash_type = None;
        input.redeem_script = None;
        input.witness_script = None;
        input.bip32_derivation = BTreeMap::new();
    });

    let signed_tx = psbt.extract_tx();

    let tx_bytes = bitcoin::consensus::encode::serialize(&signed_tx);
    let encoded_signed_tx = hex::encode(tx_bytes);

    Ok(encoded_signed_tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        decode_transfer_address,
        wallet::{CoinStatus, Settings, Wallet},
    };
    use bitcoin::{Network, Txid};
    use secp256k1::musig::new_musig_nonce_pair;

    fn sample_wallet(name: &str, mnemonic: &str) -> Wallet {
        Wallet {
            name: name.to_string(),
            mnemonic: mnemonic.to_string(),
            version: "0.1.0".to_string(),
            state_entity_endpoint: "http://statechain".to_string(),
            chain_backend: "core".to_string(),
            chain_endpoint: "http://127.0.0.1:18443".to_string(),
            network: "regtest".to_string(),
            blockheight: 0,
            initlock: 1_000,
            interval: 10,
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

    fn sample_coin() -> crate::wallet::Coin {
        let mut coin = sample_wallet(
            "sender",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .get_new_coin()
        .unwrap();
        coin.amount = Some(50_000);
        coin.statechain_id = Some("statechain-1".to_string());
        coin.signed_statechain_id = Some("signed-statechain-1".to_string());
        coin.status = CoinStatus::CONFIRMED;
        coin
    }

    #[test]
    fn create_tx_out_uses_transfer_address_recipient_pubkey() {
        let coin = sample_coin();
        let recipient_coin = sample_wallet(
            "recipient",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        )
        .get_new_coin()
        .unwrap();

        let tx_out = create_tx_out(&coin, 1.25, &recipient_coin.address, Network::Regtest).unwrap();
        let (_, recipient_user_pubkey, _) =
            decode_transfer_address(&recipient_coin.address).unwrap();
        let expected_address = bitcoin::Address::p2tr(
            &Secp256k1::new(),
            recipient_user_pubkey.x_only_public_key().0,
            None,
            Network::Regtest,
        );

        assert_eq!(tx_out.script_pubkey, expected_address.script_pubkey());
        assert_eq!(tx_out.value, 49_860);
    }

    #[test]
    fn create_bip448_keypath_nonces_returns_hex_payloads() {
        let coin = sample_coin();

        let nonce = create_bip448_keypath_nonces(&coin).unwrap();

        assert!(!hex::decode(&nonce.secret_nonce).unwrap().is_empty());
        assert!(!hex::decode(&nonce.public_nonce).unwrap().is_empty());
        assert_eq!(hex::decode(&nonce.blinding_factor).unwrap().len(), 32);
    }

    #[test]
    fn bip448_withdrawal_signature_verifies_against_funding_output_key() {
        let secp = Secp256k1::new();
        let mut coin = sample_coin();
        let client_seckey = PrivateKey::from_wif(&coin.user_privkey).unwrap().inner;
        let server_seckey = SecretKey::from_slice(&[7; 32]).unwrap();
        let server_keypair = KeyPair::from_secret_key(&secp, &server_seckey);
        let server_pubkey = server_keypair.public_key();
        let aggregate_pubkey = PublicKey::from_str(&coin.user_pubkey)
            .unwrap()
            .combine(&server_pubkey)
            .unwrap();
        let spend_info = crate::bip448_statechain::script::funding_spend_info(
            &secp,
            aggregate_pubkey.x_only_public_key().0,
        )
        .unwrap();
        let funding_outpoint = OutPoint {
            txid: Txid::from_slice(&[42; 32]).unwrap(),
            vout: 1,
        };
        coin.server_pubkey = Some(server_pubkey.to_string());
        coin.aggregated_pubkey = Some(aggregate_pubkey.to_string());
        coin.aggregated_address = Some(
            Address::from_script(
                &crate::bip448_statechain::script::output_script_pubkey(&spend_info),
                Network::Regtest,
            )
            .unwrap()
            .to_string(),
        );
        coin.utxo_txid = Some(funding_outpoint.txid.to_string());
        coin.utxo_vout = Some(funding_outpoint.vout);
        let client_nonce = create_bip448_keypath_nonces(&coin).unwrap();
        coin.secret_nonce = Some(client_nonce.secret_nonce);
        coin.public_nonce = Some(client_nonce.public_nonce);
        coin.blinding_factor = Some(client_nonce.blinding_factor);
        let (server_sec_nonce, server_pub_nonce) = new_musig_nonce_pair(
            &secp,
            MusigSessionId::assume_unique_per_nonce_gen([9; 32]),
            None,
            Some(server_seckey),
            server_pubkey,
            None,
            None,
        )
        .unwrap();
        coin.server_public_nonce = Some(hex::encode(server_pub_nonce.serialize()));

        let msg1 = build_bip448_withdrawal_signing_data(
            &coin,
            funding_outpoint,
            50_000,
            101,
            1.0,
            &coin.backup_address,
            Network::Regtest,
        )
        .unwrap();
        let blinded_session: [u8; 133] =
            hex::decode(&msg1.partial_signature_request_payload.session)
                .unwrap()
                .try_into()
                .unwrap();
        let server_partial = MusigSession::from_slice(blinded_session)
            .blinded_partial_sign_without_keyaggcoeff(
                &secp,
                server_sec_nonce,
                &server_keypair,
                msg1.partial_signature_request_payload.negate_seckey == 1,
            )
            .unwrap();
        let signature = aggregate_bip448_keypath_signature(
            msg1.msg.clone(),
            msg1.client_partial_sig,
            hex::encode(server_partial.serialize()),
            msg1.encoded_session,
            msg1.output_pubkey,
        )
        .unwrap();
        let unsigned_tx: Transaction =
            bitcoin::consensus::deserialize(&hex::decode(&msg1.encoded_unsigned_tx).unwrap())
                .unwrap();
        let sighash = SighashCache::new(&unsigned_tx)
            .taproot_key_spend_signature_hash(
                0,
                &sighash::Prevouts::All(&[TxOut {
                    value: 50_000,
                    script_pubkey: crate::bip448_statechain::script::output_script_pubkey(
                        &spend_info,
                    ),
                }]),
                TapSighashType::All,
            )
            .unwrap();
        assert_eq!(msg1.msg, hex::encode(sighash.as_byte_array()));
        secp.verify_schnorr(
            &Signature::from_str(&signature).unwrap(),
            Message::from(sighash).as_ref(),
            &spend_info.output_key().to_inner(),
        )
        .unwrap();
        assert_eq!(unsigned_tx.input[0].previous_output, funding_outpoint);
        assert_ne!(client_seckey, server_seckey);
    }
}
