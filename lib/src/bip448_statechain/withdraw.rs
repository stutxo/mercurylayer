use std::{collections::BTreeMap, str::FromStr};

use bech32::FromBase32;
use bitcoin::{
    absolute,
    hashes::Hash,
    psbt::Psbt,
    sighash::{self, SighashCache, TapSighash, TapSighashType},
    taproot::{self, TapTweakHash, TaprootSpendInfo},
    Address, Amount, Network, OutPoint, PrivateKey, ScriptBuf, Transaction, TxIn, TxOut, Witness,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip448KeypathSpendSource {
    pub outpoint: OutPoint,
    pub value_sats: u64,
    pub script_pubkey: ScriptBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip448PreparedKeypathSpend {
    pub unsigned_tx: Vec<u8>,
    pub fee_sats: u64,
    pub destination_script_pubkey: ScriptBuf,
    pub output_value_sats: u64,
    pub lock_time: u32,
}

const BIP448_KEYPATH_SPEND_VBYTES: f64 = 112.0;

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
pub fn sample_bip448_keypath_spend_lock_time(block_height: u32) -> u32 {
    let mut locktime = block_height as i32;

    let mut rng = rand::thread_rng();
    let number = rng.gen_range(0..=10);

    // sometimes locktime is set a bit further back, for privacy reasons
    if number == 0 {
        locktime = locktime - rng.gen_range(0..=99);
    }

    std::cmp::max(0, locktime) as u32
}

fn destination_script_pubkey(
    to_address: &str,
    network: Network,
) -> core::result::Result<ScriptBuf, MercuryError> {
    let recipient_address = if to_address.starts_with(crate::MAINNET_HRP)
        || to_address.starts_with(crate::TESTNET_HRP)
    {
        if (to_address.starts_with(crate::MAINNET_HRP) && network != Network::Bitcoin)
            || (to_address.starts_with(crate::TESTNET_HRP) && network == Network::Bitcoin)
        {
            return Err(MercuryError::StatechainAddressMismatchNetworkError);
        }
        let (_, encoded_data, _) = bech32::decode(to_address)?;
        if Vec::<u8>::from_base32(&encoded_data)?.len() != 67 {
            return Err(MercuryError::InvalidStatechainAddressError);
        }
        let (_, recipient_user_pubkey, _) = decode_transfer_address(to_address)?;
        Address::p2tr(
            &Secp256k1::new(),
            recipient_user_pubkey.x_only_public_key().0,
            None,
            network,
        )
    } else {
        Address::from_str(to_address)?.require_network(network)?
    };

    Ok(recipient_address.script_pubkey())
}

fn accepted_funding_spend_info(
    accepted_aggregate_pubkey: &str,
) -> core::result::Result<TaprootSpendInfo, MercuryError> {
    let secp = Secp256k1::new();
    let aggregate_pubkey = PublicKey::from_str(accepted_aggregate_pubkey)?;
    crate::bip448_statechain::script::funding_spend_info(
        &secp,
        aggregate_pubkey.x_only_public_key().0,
    )
    .map_err(|_| MercuryError::TransactionReconstructionError)
}

fn validate_bip448_keypath_spend_source(
    accepted_aggregate_pubkey: &str,
    source: &Bip448KeypathSpendSource,
) -> core::result::Result<TaprootSpendInfo, MercuryError> {
    i64::try_from(source.value_sats).map_err(|_| MercuryError::TransactionReconstructionError)?;
    if source.value_sats > Amount::MAX_MONEY.to_sat() {
        return Err(MercuryError::TransactionReconstructionError);
    }

    let funding_spend_info = accepted_funding_spend_info(accepted_aggregate_pubkey)?;
    let accepted_script =
        crate::bip448_statechain::script::output_script_pubkey(&funding_spend_info);
    if source.script_pubkey != accepted_script {
        return Err(MercuryError::TransactionReconstructionError);
    }

    Ok(funding_spend_info)
}

fn checked_bip448_keypath_spend_fee(
    source_value_sats: u64,
    fee_rate_sat_per_vbyte: f64,
    destination_dust_sats: u64,
) -> core::result::Result<(u64, u64), MercuryError> {
    if !fee_rate_sat_per_vbyte.is_finite() || fee_rate_sat_per_vbyte <= 0.0 {
        return Err(MercuryError::TransactionReconstructionError);
    }

    let fee = BIP448_KEYPATH_SPEND_VBYTES * fee_rate_sat_per_vbyte;
    if !fee.is_finite() || fee >= 18_446_744_073_709_551_616.0_f64 {
        return Err(MercuryError::TransactionReconstructionError);
    }
    let fee_sats = fee
        .ceil()
        .to_string()
        .parse::<u64>()
        .map_err(|_| MercuryError::TransactionReconstructionError)?;
    let output_value_sats = source_value_sats
        .checked_sub(fee_sats)
        .ok_or(MercuryError::TransactionReconstructionError)?;
    if output_value_sats < destination_dust_sats {
        return Err(MercuryError::TransactionReconstructionError);
    }

    Ok((fee_sats, output_value_sats))
}

pub fn prepare_bip448_keypath_spend(
    accepted_aggregate_pubkey: &str,
    source: &Bip448KeypathSpendSource,
    to_address: &str,
    network: Network,
    fee_rate_sat_per_vbyte: f64,
    lock_time: u32,
) -> core::result::Result<Bip448PreparedKeypathSpend, MercuryError> {
    validate_bip448_keypath_spend_source(accepted_aggregate_pubkey, source)?;
    let destination_script_pubkey = destination_script_pubkey(to_address, network)?;
    let (fee_sats, output_value_sats) = checked_bip448_keypath_spend_fee(
        source.value_sats,
        fee_rate_sat_per_vbyte,
        destination_script_pubkey.dust_value().to_sat(),
    )?;

    let unsigned_tx = Transaction {
        version: 2,
        lock_time: absolute::LockTime::from_height(lock_time)?,
        input: vec![TxIn {
            previous_output: source.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence(0),
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: output_value_sats,
            script_pubkey: destination_script_pubkey.clone(),
        }],
    };

    Ok(Bip448PreparedKeypathSpend {
        unsigned_tx: bitcoin::consensus::encode::serialize(&unsigned_tx),
        fee_sats,
        destination_script_pubkey,
        output_value_sats,
        lock_time,
    })
}

fn validate_prepared_bip448_keypath_spend(
    source: &Bip448KeypathSpendSource,
    prepared: &Bip448PreparedKeypathSpend,
) -> core::result::Result<Transaction, MercuryError> {
    let unsigned_tx: Transaction = bitcoin::consensus::encode::deserialize(&prepared.unsigned_tx)?;
    if bitcoin::consensus::encode::serialize(&unsigned_tx) != prepared.unsigned_tx
        || unsigned_tx.version != 2
        || unsigned_tx.lock_time != absolute::LockTime::from_height(prepared.lock_time)?
        || unsigned_tx.input.len() != 1
        || unsigned_tx.output.len() != 1
    {
        return Err(MercuryError::TransactionReconstructionError);
    }

    let input = unsigned_tx
        .input
        .first()
        .ok_or(MercuryError::TransactionReconstructionError)?;
    let output = unsigned_tx
        .output
        .first()
        .ok_or(MercuryError::TransactionReconstructionError)?;
    if input.previous_output != source.outpoint
        || !input.script_sig.is_empty()
        || input.sequence != bitcoin::Sequence(0)
        || !input.witness.is_empty()
        || output.value != prepared.output_value_sats
        || output.script_pubkey != prepared.destination_script_pubkey
        || prepared.fee_sats == 0
        || source.value_sats.checked_sub(prepared.fee_sats) != Some(prepared.output_value_sats)
        || prepared.output_value_sats < prepared.destination_script_pubkey.dust_value().to_sat()
    {
        return Err(MercuryError::TransactionReconstructionError);
    }

    Ok(unsigned_tx)
}

pub fn build_bip448_keypath_spend_signing_data(
    coin: &Coin,
    accepted_aggregate_pubkey: &str,
    source: &Bip448KeypathSpendSource,
    prepared: &Bip448PreparedKeypathSpend,
) -> core::result::Result<Bip448WithdrawalSigningData, MercuryError> {
    if coin.aggregated_pubkey.as_deref() != Some(accepted_aggregate_pubkey) {
        return Err(MercuryError::TransactionReconstructionError);
    }

    let funding_spend_info =
        validate_bip448_keypath_spend_source(accepted_aggregate_pubkey, source)?;
    let unsigned_tx = validate_prepared_bip448_keypath_spend(source, prepared)?;
    let funding_output = TxOut {
        value: source.value_sats,
        script_pubkey: source.script_pubkey.clone(),
    };
    let hash = SighashCache::new(&unsigned_tx).taproot_key_spend_signature_hash(
        0,
        &sighash::Prevouts::All(&[funding_output]),
        TapSighashType::All,
    )?;
    let encoded_unsigned_tx = hex::encode(&prepared.unsigned_tx);

    calculate_bip448_keypath_musig_session(coin, hash, encoded_unsigned_tx, &funding_spend_info)
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
    let accepted_aggregate_pubkey = coin
        .aggregated_pubkey
        .as_deref()
        .ok_or(MercuryError::TransactionReconstructionError)?;
    let funding_spend_info = accepted_funding_spend_info(accepted_aggregate_pubkey)?;
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

    let source = Bip448KeypathSpendSource {
        outpoint: funding_outpoint,
        value_sats: funding_value_sats,
        script_pubkey: funding_script,
    };
    let prepared = prepare_bip448_keypath_spend(
        accepted_aggregate_pubkey,
        &source,
        to_address,
        network,
        fee_rate_sats_per_byte,
        sample_bip448_keypath_spend_lock_time(block_height),
    )?;

    build_bip448_keypath_spend_signing_data(coin, accepted_aggregate_pubkey, &source, &prepared)
}

fn calculate_bip448_keypath_musig_session(
    coin: &Coin,
    hash: TapSighash,
    encoded_unsigned_tx: String,
    funding_spend_info: &TaprootSpendInfo,
) -> core::result::Result<Bip448WithdrawalSigningData, MercuryError> {
    let secp = Secp256k1::new();

    let aggregate_pubkey = PublicKey::from_str(
        coin.aggregated_pubkey
            .as_deref()
            .ok_or(MercuryError::TransactionReconstructionError)?,
    )?;

    let tap_tweak = TapTweakHash::from_key_and_tweak(
        aggregate_pubkey.x_only_public_key().0,
        funding_spend_info.merkle_root(),
    );
    let tap_tweak_bytes = tap_tweak.as_byte_array();

    // tranform tweak: Scalar to SecretKey
    let tweak = SecretKey::from_slice(tap_tweak_bytes)?;

    let (parity_acc, output_pubkey, out_tweak32) =
        blinded_musig_pubkey_xonly_tweak_add(&secp, &aggregate_pubkey, tweak);

    let client_pub_nonce_bytes = hex::decode(
        coin.public_nonce
            .as_deref()
            .ok_or(MercuryError::TransactionReconstructionError)?,
    )?;
    let client_pub_nonce = MusigPubNonce::from_slice(client_pub_nonce_bytes.as_slice())?;

    let server_pubnonce_hex = coin
        .server_public_nonce
        .as_deref()
        .ok_or(MercuryError::TransactionReconstructionError)?
        .to_string();
    let server_pub_nonce_bytes = hex::decode(&server_pubnonce_hex)?;
    let server_pub_nonce = MusigPubNonce::from_slice(server_pub_nonce_bytes.as_slice())?;

    let aggnonce = MusigAggNonce::new(&[&client_pub_nonce, &server_pub_nonce]);

    let blinding_factor_bytes = hex::decode(
        coin.blinding_factor
            .as_deref()
            .ok_or(MercuryError::TransactionReconstructionError)?,
    )?;
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

    let client_sec_nonce_bytes = hex::decode(
        coin.secret_nonce
            .as_deref()
            .ok_or(MercuryError::TransactionReconstructionError)?,
    )?;
    let client_sec_nonce_bytes: [u8; 132] = client_sec_nonce_bytes
        .try_into()
        .map_err(|_| MercuryError::TransactionReconstructionError)?;
    let client_sec_nonce = MusigSecNonce::from_slice(client_sec_nonce_bytes);

    let client_partial_sig = session.blinded_partial_sign_without_keyaggcoeff(
        &secp,
        client_sec_nonce,
        &client_keypair,
        negate_seckey,
    )?;

    if !session.blinded_musig_partial_sig_verify(
        &secp,
        &client_partial_sig,
        &client_pub_nonce,
        &client_pubkey,
        &output_pubkey,
        parity_acc,
    ) {
        return Err(MercuryError::SchnorrSignatureValidationError);
    }

    let encoded_session = hex::encode(session.serialize());

    session.remove_fin_nonce_from_session();

    let negate_seckey = match negate_seckey {
        true => 1,
        false => 0,
    };

    let blinded_session = session.remove_fin_nonce_from_session();

    let statechain_id = coin
        .statechain_id
        .as_deref()
        .ok_or(MercuryError::TransactionReconstructionError)?;
    let signed_statechain_id = coin
        .signed_statechain_id
        .as_deref()
        .ok_or(MercuryError::TransactionReconstructionError)?;

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

    let session_bytes: [u8; 133] = hex::decode(&session_hex)?
        .try_into()
        .map_err(|_| MercuryError::TransactionReconstructionError)?;
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

    if psbt.inputs.len() > 1 {
        return Err(MercuryError::MoreThanOneInputError);
    }
    if psbt.inputs.len() != 1 || psbt.unsigned_tx.output.len() != 1 {
        return Err(MercuryError::TransactionReconstructionError);
    }

    let input = psbt
        .inputs
        .first_mut()
        .ok_or(MercuryError::TransactionReconstructionError)?;

    let hash_ty = input
        .sighash_type
        .and_then(|psbt_sighash_type| psbt_sighash_type.taproot_hash_ty().ok())
        .unwrap_or(TapSighashType::All);

    let sig = Signature::from_str(signature_hex.as_str())?;

    let final_signature = taproot::Signature { sig, hash_ty };
    let final_signature_bytes = final_signature.to_vec();

    input.tap_key_sig = Some(final_signature);

    let mut script_witness: Witness = Witness::new();
    script_witness.push(final_signature_bytes);
    input.final_script_witness = Some(script_witness);

    // Clear all the data fields as per the spec.
    input.partial_sigs = BTreeMap::new();
    input.sighash_type = None;
    input.redeem_script = None;
    input.witness_script = None;
    input.bip32_derivation = BTreeMap::new();

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
    use bech32::ToBase32;
    use bitcoin::{consensus, Network, Txid};
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

    fn configured_keypath_coin() -> (
        crate::wallet::Coin,
        PublicKey,
        TaprootSpendInfo,
        Bip448KeypathSpendSource,
    ) {
        let secp = Secp256k1::new();
        let mut coin = sample_coin();
        let server_seckey = SecretKey::from_slice(&[7; 32]).unwrap();
        let server_pubkey = server_seckey.public_key(&secp);
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
        let funding_script = crate::bip448_statechain::script::output_script_pubkey(&spend_info);
        coin.server_pubkey = Some(server_pubkey.to_string());
        coin.aggregated_pubkey = Some(aggregate_pubkey.to_string());
        coin.aggregated_address = Some(
            Address::from_script(&funding_script, Network::Regtest)
                .unwrap()
                .to_string(),
        );
        coin.utxo_txid = Some(funding_outpoint.txid.to_string());
        coin.utxo_vout = Some(funding_outpoint.vout);
        let client_nonce = create_bip448_keypath_nonces(&coin).unwrap();
        coin.secret_nonce = Some(client_nonce.secret_nonce);
        coin.public_nonce = Some(client_nonce.public_nonce);
        coin.blinding_factor = Some(client_nonce.blinding_factor);
        let (_, server_public_nonce) = new_musig_nonce_pair(
            &secp,
            MusigSessionId::assume_unique_per_nonce_gen([9; 32]),
            None,
            Some(server_seckey),
            server_pubkey,
            None,
            None,
        )
        .unwrap();
        coin.server_public_nonce = Some(hex::encode(server_public_nonce.serialize()));

        let source = Bip448KeypathSpendSource {
            outpoint: funding_outpoint,
            value_sats: 50_000,
            script_pubkey: funding_script,
        };
        (coin, aggregate_pubkey, spend_info, source)
    }

    fn prepare_fixture(
        aggregate_pubkey: &PublicKey,
        source: &Bip448KeypathSpendSource,
        destination: &str,
        fee_rate: f64,
        lock_time: u32,
    ) -> Bip448PreparedKeypathSpend {
        prepare_bip448_keypath_spend(
            &aggregate_pubkey.to_string(),
            source,
            destination,
            Network::Regtest,
            fee_rate,
            lock_time,
        )
        .unwrap()
    }

    #[test]
    fn prepared_output_uses_transfer_address_recipient_pubkey() {
        let (_, aggregate_pubkey, _, source) = configured_keypath_coin();
        let recipient_coin = sample_wallet(
            "recipient",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        )
        .get_new_coin()
        .unwrap();

        let prepared = prepare_fixture(
            &aggregate_pubkey,
            &source,
            &recipient_coin.address,
            1.25,
            101,
        );
        let (_, recipient_user_pubkey, _) =
            decode_transfer_address(&recipient_coin.address).unwrap();
        let expected_address = bitcoin::Address::p2tr(
            &Secp256k1::new(),
            recipient_user_pubkey.x_only_public_key().0,
            None,
            Network::Regtest,
        );

        assert_eq!(
            prepared.destination_script_pubkey,
            expected_address.script_pubkey()
        );
        assert_eq!(prepared.output_value_sats, 49_860);
        assert_eq!(prepared.fee_sats, 140);
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
    fn supplied_lock_time_makes_unsigned_transaction_replayable() {
        let (coin, aggregate_pubkey, _, source) = configured_keypath_coin();
        let first = prepare_fixture(&aggregate_pubkey, &source, &coin.backup_address, 1.001, 101);
        let replay = prepare_fixture(&aggregate_pubkey, &source, &coin.backup_address, 1.001, 101);
        let transaction: Transaction = consensus::deserialize(&first.unsigned_tx).unwrap();

        assert_eq!(first, replay);
        assert_eq!(first.fee_sats, 113);
        assert_eq!(first.output_value_sats, 49_887);
        assert_eq!(
            transaction.lock_time,
            absolute::LockTime::from_height(101).unwrap()
        );
        assert_eq!(transaction.input.len(), 1);
        assert_eq!(transaction.output.len(), 1);
        assert_eq!(transaction.input[0].previous_output, source.outpoint);
        assert_eq!(transaction.output[0].value, first.output_value_sats);
        assert_eq!(
            transaction.output[0].script_pubkey,
            first.destination_script_pubkey
        );
    }

    #[test]
    fn persisted_inputs_reproduce_identical_sighash_and_session_artifacts() {
        let (coin, aggregate_pubkey, _, source) = configured_keypath_coin();
        let prepared = prepare_fixture(&aggregate_pubkey, &source, &coin.backup_address, 1.0, 101);

        let first = build_bip448_keypath_spend_signing_data(
            &coin,
            &aggregate_pubkey.to_string(),
            &source,
            &prepared,
        )
        .unwrap();
        let replay = build_bip448_keypath_spend_signing_data(
            &coin,
            &aggregate_pubkey.to_string(),
            &source,
            &prepared,
        )
        .unwrap();

        assert_eq!(first.msg, replay.msg);
        assert_eq!(first.output_pubkey, replay.output_pubkey);
        assert_eq!(first.client_partial_sig, replay.client_partial_sig);
        assert_eq!(first.encoded_session, replay.encoded_session);
        assert_eq!(first.encoded_unsigned_tx, replay.encoded_unsigned_tx);
        assert_eq!(
            serde_json::to_string(&first.partial_signature_request_payload).unwrap(),
            serde_json::to_string(&replay.partial_signature_request_payload).unwrap()
        );
    }

    #[test]
    fn every_valid_transaction_plan_change_changes_unsigned_bytes() {
        let (coin, aggregate_pubkey, _, source) = configured_keypath_coin();
        let recipient = sample_wallet(
            "recipient",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        )
        .get_new_coin()
        .unwrap();
        let base = prepare_fixture(&aggregate_pubkey, &source, &coin.backup_address, 1.0, 101);

        let mut changed_outpoint = source.clone();
        changed_outpoint.outpoint.vout += 1;
        let outpoint_plan = prepare_fixture(
            &aggregate_pubkey,
            &changed_outpoint,
            &coin.backup_address,
            1.0,
            101,
        );
        let mut changed_value = source.clone();
        changed_value.value_sats += 1;
        let value_plan = prepare_fixture(
            &aggregate_pubkey,
            &changed_value,
            &coin.backup_address,
            1.0,
            101,
        );
        let destination_plan = prepare_fixture(
            &aggregate_pubkey,
            &source,
            &recipient.backup_address,
            1.0,
            101,
        );
        let fee_plan = prepare_fixture(&aggregate_pubkey, &source, &coin.backup_address, 2.0, 101);
        let lock_time_plan =
            prepare_fixture(&aggregate_pubkey, &source, &coin.backup_address, 1.0, 102);

        for changed in [
            outpoint_plan,
            value_plan,
            destination_plan,
            fee_plan,
            lock_time_plan,
        ] {
            assert_ne!(changed.unsigned_tx, base.unsigned_tx);
        }
    }

    #[test]
    fn wrong_source_script_rejects_before_destination_or_construction() {
        let (_, aggregate_pubkey, _, mut source) = configured_keypath_coin();
        source.script_pubkey = ScriptBuf::from_bytes(vec![0x51]);

        let error = prepare_bip448_keypath_spend(
            &aggregate_pubkey.to_string(),
            &source,
            "not-a-destination",
            Network::Regtest,
            1.0,
            101,
        )
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            MercuryError::TransactionReconstructionError.to_string()
        );
    }

    #[test]
    fn economic_values_above_u32_are_preserved_without_truncation() {
        let (coin, aggregate_pubkey, _, mut source) = configured_keypath_coin();
        source.value_sats = u64::from(u32::MAX) + 50_000;

        let prepared = prepare_fixture(&aggregate_pubkey, &source, &coin.backup_address, 1.0, 101);
        let transaction: Transaction = consensus::deserialize(&prepared.unsigned_tx).unwrap();

        assert_eq!(prepared.output_value_sats, source.value_sats - 112);
        assert_eq!(transaction.output[0].value, source.value_sats - 112);
        assert!(transaction.output[0].value > u64::from(u32::MAX));
    }

    #[test]
    fn values_outside_bitcoin_or_sqlite_domain_are_rejected() {
        let (coin, aggregate_pubkey, _, mut source) = configured_keypath_coin();
        source.value_sats = Amount::MAX_MONEY.to_sat() + 1;
        assert!(prepare_bip448_keypath_spend(
            &aggregate_pubkey.to_string(),
            &source,
            &coin.backup_address,
            Network::Regtest,
            1.0,
            101,
        )
        .is_err());

        source.value_sats = u64::MAX;
        assert!(prepare_bip448_keypath_spend(
            &aggregate_pubkey.to_string(),
            &source,
            &coin.backup_address,
            Network::Regtest,
            1.0,
            101,
        )
        .is_err());
    }

    #[test]
    fn fee_rate_subtraction_and_dust_are_checked() {
        let (coin, aggregate_pubkey, _, source) = configured_keypath_coin();
        let explicit_high_rate =
            prepare_fixture(&aggregate_pubkey, &source, &coin.backup_address, 100.0, 101);
        assert_eq!(explicit_high_rate.fee_sats, 11_200);
        for invalid_rate in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, 0.0, -1.0] {
            assert!(prepare_bip448_keypath_spend(
                &aggregate_pubkey.to_string(),
                &source,
                &coin.backup_address,
                Network::Regtest,
                invalid_rate,
                101,
            )
            .is_err());
        }
        for overflow_rate in [f64::MAX, 18_446_744_073_709_551_616.0_f64 / 112.0] {
            assert!(prepare_bip448_keypath_spend(
                &aggregate_pubkey.to_string(),
                &source,
                &coin.backup_address,
                Network::Regtest,
                overflow_rate,
                101,
            )
            .is_err());
        }

        let mut fee_exceeds_source = source.clone();
        fee_exceeds_source.value_sats = 1_000;
        assert!(prepare_bip448_keypath_spend(
            &aggregate_pubkey.to_string(),
            &fee_exceeds_source,
            &coin.backup_address,
            Network::Regtest,
            10.0,
            101,
        )
        .is_err());

        let mut dust_source = source;
        dust_source.value_sats = 400;
        assert!(prepare_bip448_keypath_spend(
            &aggregate_pubkey.to_string(),
            &dust_source,
            &coin.backup_address,
            Network::Regtest,
            1.0,
            101,
        )
        .is_err());
    }

    #[test]
    fn destination_must_be_a_supported_class_on_the_configured_network() {
        let (coin, aggregate_pubkey, _, source) = configured_keypath_coin();
        let user_pubkey = PublicKey::from_str(&coin.user_pubkey).unwrap();
        let auth_pubkey = PublicKey::from_str(&coin.auth_pubkey).unwrap();
        let wrong_network_transfer =
            crate::encode_sc_address(&user_pubkey, &auth_pubkey, Network::Bitcoin).unwrap();

        assert!(prepare_bip448_keypath_spend(
            &aggregate_pubkey.to_string(),
            &source,
            &wrong_network_transfer,
            Network::Regtest,
            1.0,
            101,
        )
        .is_err());
        assert!(prepare_bip448_keypath_spend(
            &aggregate_pubkey.to_string(),
            &source,
            "not-an-address",
            Network::Regtest,
            1.0,
            101,
        )
        .is_err());
        let short_transfer_address = bech32::encode(
            crate::TESTNET_HRP,
            vec![0u8].to_base32(),
            bech32::Variant::Bech32m,
        )
        .unwrap();
        assert!(prepare_bip448_keypath_spend(
            &aggregate_pubkey.to_string(),
            &source,
            &short_transfer_address,
            Network::Regtest,
            1.0,
            101,
        )
        .is_err());
    }

    #[test]
    fn canonical_compatibility_wrapper_requires_wallet_source_facts() {
        let (mut coin, _, _, source) = configured_keypath_coin();

        let mut wrong_outpoint = source.outpoint;
        wrong_outpoint.vout += 1;
        assert!(build_bip448_withdrawal_signing_data(
            &coin,
            wrong_outpoint,
            source.value_sats,
            101,
            1.0,
            &coin.backup_address,
            Network::Regtest,
        )
        .is_err());
        assert!(build_bip448_withdrawal_signing_data(
            &coin,
            source.outpoint,
            source.value_sats + 1,
            101,
            1.0,
            &coin.backup_address,
            Network::Regtest,
        )
        .is_err());

        coin.aggregated_address = Some(coin.backup_address.clone());
        assert!(build_bip448_withdrawal_signing_data(
            &coin,
            source.outpoint,
            source.value_sats,
            101,
            1.0,
            &coin.backup_address,
            Network::Regtest,
        )
        .is_err());
    }

    #[test]
    fn signing_rejects_unsigned_transaction_shape_and_plan_mismatches() {
        let (coin, aggregate_pubkey, _, source) = configured_keypath_coin();
        let prepared = prepare_fixture(&aggregate_pubkey, &source, &coin.backup_address, 1.0, 101);
        let rejected = |candidate: &Bip448PreparedKeypathSpend,
                        candidate_source: &Bip448KeypathSpendSource| {
            build_bip448_keypath_spend_signing_data(
                &coin,
                &aggregate_pubkey.to_string(),
                candidate_source,
                candidate,
            )
            .is_err()
        };

        let mut transaction: Transaction = consensus::deserialize(&prepared.unsigned_tx).unwrap();
        transaction.input.push(transaction.input[0].clone());
        let mut two_inputs = prepared.clone();
        two_inputs.unsigned_tx = consensus::serialize(&transaction);
        assert!(rejected(&two_inputs, &source));

        let mut transaction: Transaction = consensus::deserialize(&prepared.unsigned_tx).unwrap();
        transaction.output.push(transaction.output[0].clone());
        let mut two_outputs = prepared.clone();
        two_outputs.unsigned_tx = consensus::serialize(&transaction);
        assert!(rejected(&two_outputs, &source));

        let mut transaction: Transaction = consensus::deserialize(&prepared.unsigned_tx).unwrap();
        transaction.input[0].previous_output.vout += 1;
        let mut wrong_outpoint = prepared.clone();
        wrong_outpoint.unsigned_tx = consensus::serialize(&transaction);
        assert!(rejected(&wrong_outpoint, &source));

        let mut wrong_value = prepared.clone();
        wrong_value.output_value_sats += 1;
        assert!(rejected(&wrong_value, &source));

        let mut wrong_fee = prepared.clone();
        wrong_fee.fee_sats += 1;
        assert!(rejected(&wrong_fee, &source));

        let mut wrong_script = prepared.clone();
        wrong_script.destination_script_pubkey = ScriptBuf::from_bytes(vec![0x51]);
        assert!(rejected(&wrong_script, &source));

        let mut wrong_lock_time = prepared.clone();
        wrong_lock_time.lock_time += 1;
        assert!(rejected(&wrong_lock_time, &source));

        let mut wrong_source_value = source.clone();
        wrong_source_value.value_sats += 1;
        assert!(rejected(&prepared, &wrong_source_value));

        let mut wrong_source_script = source.clone();
        wrong_source_script.script_pubkey = ScriptBuf::from_bytes(vec![0x51]);
        assert!(rejected(&prepared, &wrong_source_script));
    }

    #[test]
    fn finalization_requires_exactly_one_input_and_one_output() {
        let (coin, aggregate_pubkey, _, source) = configured_keypath_coin();
        let prepared = prepare_fixture(&aggregate_pubkey, &source, &coin.backup_address, 1.0, 101);
        let mut transaction: Transaction = consensus::deserialize(&prepared.unsigned_tx).unwrap();
        transaction.input.push(transaction.input[0].clone());
        assert!(matches!(
            finalize_bip448_keypath_transaction(
                hex::encode(consensus::serialize(&transaction)),
                "00".to_string(),
            ),
            Err(MercuryError::MoreThanOneInputError)
        ));

        let mut transaction: Transaction = consensus::deserialize(&prepared.unsigned_tx).unwrap();
        transaction.output.clear();
        assert!(matches!(
            finalize_bip448_keypath_transaction(
                hex::encode(consensus::serialize(&transaction)),
                "00".to_string(),
            ),
            Err(MercuryError::TransactionReconstructionError)
        ));

        let mut transaction: Transaction = consensus::deserialize(&prepared.unsigned_tx).unwrap();
        transaction.input.clear();
        assert!(matches!(
            finalize_bip448_keypath_transaction(
                hex::encode(consensus::serialize(&transaction)),
                "00".to_string(),
            ),
            Err(MercuryError::TransactionReconstructionError)
        ));
    }

    #[test]
    fn bip448_withdrawal_signature_verifies_against_funding_output_key() {
        let secp = Secp256k1::new();
        let (coin, _, spend_info, source) = configured_keypath_coin();
        let client_seckey = PrivateKey::from_wif(&coin.user_privkey).unwrap().inner;
        let server_seckey = SecretKey::from_slice(&[7; 32]).unwrap();
        let server_keypair = KeyPair::from_secret_key(&secp, &server_seckey);
        let (server_sec_nonce, _) = new_musig_nonce_pair(
            &secp,
            MusigSessionId::assume_unique_per_nonce_gen([9; 32]),
            None,
            Some(server_seckey),
            server_keypair.public_key(),
            None,
            None,
        )
        .unwrap();

        let msg1 = build_bip448_withdrawal_signing_data(
            &coin,
            source.outpoint,
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
        let signed_tx_hex =
            finalize_bip448_keypath_transaction(msg1.encoded_unsigned_tx.clone(), signature)
                .unwrap();
        let signed_bytes = hex::decode(&signed_tx_hex).unwrap();
        let signed_tx: Transaction = consensus::deserialize(&signed_bytes).unwrap();
        assert_eq!(consensus::serialize(&signed_tx), signed_bytes);
        assert_eq!(signed_tx.input.len(), 1);
        assert_eq!(signed_tx.output.len(), 1);
        assert_eq!(signed_tx.input[0].witness.len(), 1);
        assert_eq!(signed_tx.txid(), unsigned_tx.txid());
        assert_eq!(unsigned_tx.input[0].previous_output, source.outpoint);
        assert_ne!(client_seckey, server_seckey);
    }
}
