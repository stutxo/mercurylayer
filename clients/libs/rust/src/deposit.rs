use anyhow::{anyhow, Ok, Result};
use bitcoin::{hashes::Hash, PrivateKey};
use mercurylib::{
    bip448_statechain::{
        deposit as bip448_deposit,
        deposit::{Bip448DepositSigningData, BIP448_COIN_PROTOCOL},
        signing::{CsfsSigningParticipant, CsfsSigningRole, CsfsSigningSession},
        signing_api::{
            Bip448PartialSignatureRequestPayload, Bip448PartialSignatureResponsePayload,
            Bip448SignFirstRequestPayload, Bip448SignFirstResponsePayload,
            Bip448SignatureCountResponsePayload,
        },
        storage::{Bip448FundingOutpoint, Bip448StatechainRecord},
    },
    deposit::{create_aggregated_address, create_deposit_msg1},
    transaction::get_user_backup_address,
    utils::get_blockheight,
    wallet::{BackupTx, Coin, Wallet},
};
use reqwest::StatusCode;
use secp256k1::{
    musig::{
        new_musig_nonce_pair, BlindingFactor, MusigSessionId, PartialSignature, PublicNonce,
        SecretNonce as MusigSecNonce,
    },
    rand, KeyPair, Message, PublicKey, Secp256k1, SecretKey,
};
use serde::Serialize;
use serde_json::Value;
use std::str::FromStr;

use crate::{
    client_config::ClientConfig,
    sqlite_manager::{
        delete_bip448_pending_deposit_signing, get_bip448_pending_deposit_signing, get_wallet,
        insert_or_update_bip448_pending_deposit_signing, insert_or_update_bip448_statechain,
        update_bip448_pending_deposit_server_public_nonce, update_wallet,
        Bip448PendingDepositSigning,
    },
    transaction::new_transaction,
    utils::info_config,
};

#[derive(Debug, Clone, Serialize)]
pub struct Bip448DepositAddressResult {
    pub address: String,
    pub statechain_id: String,
    pub aggregate_pubkey: String,
}

pub async fn get_deposit_bitcoin_address(
    client_config: &ClientConfig,
    wallet_name: &str,
    token_id: &str,
    amount: u32,
) -> Result<String> {
    let token_id = uuid::Uuid::parse_str(&token_id)?;
    // println!("Deposit: {} {} {}", wallet_name, token_id, amount);
    let wallet = get_wallet(&client_config.pool, &wallet_name).await?;
    let mut wallet = init(&client_config, &wallet, token_id).await?;

    let coin = wallet.coins.last_mut().unwrap();

    let aggregated_public_key = create_aggregated_address(&coin, wallet.network.clone())?;

    coin.amount = Some(amount);
    coin.aggregated_address = Some(aggregated_public_key.aggregate_address.clone());
    coin.aggregated_pubkey = Some(aggregated_public_key.aggregate_pubkey);

    update_wallet(&client_config.pool, &wallet).await?;

    Ok(aggregated_public_key.aggregate_address)
}

pub async fn get_bip448_deposit_bitcoin_address(
    client_config: &ClientConfig,
    wallet_name: &str,
    token_id: &str,
    amount: u32,
) -> Result<Bip448DepositAddressResult> {
    let token_id = uuid::Uuid::parse_str(&token_id)?;
    let wallet = get_wallet(&client_config.pool, &wallet_name).await?;
    let mut wallet = init(&client_config, &wallet, token_id).await?;

    let coin = wallet.coins.last_mut().unwrap();
    coin.statechain_protocol = Some(BIP448_COIN_PROTOCOL.to_string());

    let deposit_address = bip448_deposit::create_deposit_address(coin, &wallet.network)?;

    coin.amount = Some(amount);
    coin.aggregated_address = Some(deposit_address.address.clone());
    coin.aggregated_pubkey = Some(deposit_address.aggregate_pubkey.clone());

    let statechain_id = coin
        .statechain_id
        .clone()
        .ok_or_else(|| anyhow!("BIP448 deposit coin missing statechain_id"))?;

    update_wallet(&client_config.pool, &wallet).await?;

    Ok(Bip448DepositAddressResult {
        address: deposit_address.address,
        statechain_id,
        aggregate_pubkey: deposit_address.aggregate_pubkey,
    })
}

// When sending duplicated coins, the tx_n of the backup_tx must be different
pub async fn create_tx1(
    client_config: &ClientConfig,
    coin: &mut Coin,
    wallet_netwotk: &str,
    tx_n: u32,
) -> Result<BackupTx> {
    let to_address = get_user_backup_address(&coin, wallet_netwotk.to_string())?;

    let server_info = info_config(&client_config).await?;

    let fee_rate_sats_per_byte = if server_info.fee_rate_sats_per_byte > client_config.max_fee_rate
    {
        client_config.max_fee_rate
    } else {
        server_info.fee_rate_sats_per_byte
    };

    let signed_tx = new_transaction(
        &client_config,
        coin,
        &to_address,
        0,
        false,
        None,
        wallet_netwotk,
        fee_rate_sats_per_byte,
        server_info.initlock,
        server_info.interval,
    )
    .await?;

    if coin.public_nonce.is_none() {
        return Err(anyhow::anyhow!("coin.public_nonce is None"));
    }

    if coin.blinding_factor.is_none() {
        return Err(anyhow::anyhow!("coin.blinding_factor is None"));
    }

    if coin.statechain_id.is_none() {
        return Err(anyhow::anyhow!("coin.statechain_id is None"));
    }

    let backup_tx = BackupTx {
        tx_n,
        tx: signed_tx,
        client_public_nonce: coin.public_nonce.as_ref().unwrap().to_string(),
        server_public_nonce: coin.server_public_nonce.as_ref().unwrap().to_string(),
        client_public_key: coin.user_pubkey.clone(),
        server_public_key: coin.server_pubkey.as_ref().unwrap().to_string(),
        blinding_factor: coin.blinding_factor.as_ref().unwrap().to_string(),
    };

    let block_height = Some(get_blockheight(&backup_tx)?);
    coin.locktime = block_height;

    Ok(backup_tx)
}

pub async fn create_bip448_deposit_state(
    client_config: &ClientConfig,
    wallet_name: &str,
    coin: &mut Coin,
    wallet_network: &str,
    funding_txid: &str,
    funding_vout: u32,
    funding_value_sats: u64,
) -> Result<Bip448StatechainRecord> {
    let funding_outpoint = Bip448FundingOutpoint {
        txid: funding_txid.to_string(),
        vout: funding_vout,
        value_sats: funding_value_sats,
    };
    let templates = bip448_deposit::build_deposit_templates(
        coin,
        funding_outpoint,
        bip448_deposit::DEFAULT_BIP448_CHALLENGE_DELAY,
        wallet_network,
    )?;
    let signing_data = sign_bip448_update(client_config, wallet_name, coin, &templates).await?;
    let statechain_id = coin
        .statechain_id
        .as_ref()
        .ok_or_else(|| anyhow!("BIP448 deposit coin missing statechain_id"))?;
    let record = bip448_deposit::build_deposit_record(
        wallet_name,
        statechain_id,
        wallet_network,
        &templates,
        signing_data.clone(),
    )?;

    coin.public_nonce = Some(signing_data.client_public_nonce);
    coin.server_public_nonce = Some(signing_data.server_public_nonce);
    coin.blinding_factor = Some(signing_data.blinding_factor);

    insert_or_update_bip448_statechain(&client_config.pool, &record).await?;
    delete_bip448_pending_deposit_signing(&client_config.pool, wallet_name, statechain_id).await?;

    Ok(record)
}

async fn sign_bip448_update(
    client_config: &ClientConfig,
    wallet_name: &str,
    coin: &Coin,
    templates: &bip448_deposit::Bip448DepositTemplates,
) -> Result<Bip448DepositSigningData> {
    let secp = Secp256k1::new();
    let client_seckey = PrivateKey::from_wif(&coin.user_privkey)?.inner;
    let client_keypair = KeyPair::from_secret_key(&secp, &client_seckey);
    let client_pubkey = PublicKey::from_str(&coin.user_pubkey)?;
    let server_pubkey = PublicKey::from_str(
        coin.server_pubkey
            .as_ref()
            .ok_or_else(|| anyhow!("BIP448 deposit coin missing server_pubkey"))?,
    )?;
    let aggregate_pubkey = client_pubkey.combine(&server_pubkey)?;
    let statechain_id = coin
        .statechain_id
        .as_ref()
        .ok_or_else(|| anyhow!("BIP448 deposit coin missing statechain_id"))?
        .clone();
    let signed_statechain_id = coin
        .signed_statechain_id
        .as_ref()
        .ok_or_else(|| anyhow!("BIP448 deposit coin missing signed_statechain_id"))?
        .clone();
    let update_template_hash = hex::encode(templates.update_template_hash.to_byte_array());
    let pending_signing = pending_or_new_bip448_deposit_signing(
        client_config,
        wallet_name,
        &statechain_id,
        &update_template_hash,
        client_seckey,
        client_pubkey,
        templates,
    )
    .await?;

    let client_sec_nonce = musig_secret_nonce_from_hex(&pending_signing.client_secret_nonce)?;
    let client_pub_nonce =
        PublicNonce::from_slice(&hex::decode(&pending_signing.client_public_nonce)?)?;
    let blinding_factor =
        BlindingFactor::from_slice(&hex::decode(&pending_signing.blinding_factor)?)?;
    let server_pubnonce = replay_or_request_bip448_server_pubnonce(
        client_config,
        wallet_name,
        &statechain_id,
        &signed_statechain_id,
        &pending_signing,
    )
    .await?;
    let server_pub_nonce = PublicNonce::from_slice(&hex::decode(&server_pubnonce)?)?;
    let session = CsfsSigningSession::new(
        &secp,
        CsfsSigningRole::FundingUpdate,
        aggregate_pubkey,
        &client_pub_nonce,
        &server_pub_nonce,
        templates.update_template_hash,
        &blinding_factor,
    )?;
    let client_partial = session.partial_sign_verified(
        &secp,
        CsfsSigningParticipant::Client,
        client_sec_nonce,
        &client_pub_nonce,
        &client_keypair,
    )?;
    let server_partial = bip448_sign_second(
        client_config,
        &Bip448PartialSignatureRequestPayload {
            statechain_id: statechain_id.clone(),
            signed_statechain_id,
            signing_id: pending_signing.signing_id.clone(),
            negate_seckey: u8::from(session.negate_seckey()),
            session: hex::encode(session.blinded_server_session().serialize()),
            server_pub_nonce: server_pubnonce.clone(),
        },
    )
    .await?;
    session.verify_partial(
        &secp,
        CsfsSigningParticipant::Server,
        &server_partial,
        &server_pub_nonce,
        &server_pubkey,
    )?;
    let signature = session.aggregate_and_verify(&[&client_partial, &server_partial])?;
    // This is the owner's OWN deposit, so the lockbox-reported count is
    // authoritative to store here. A future transfer RECEIVER must not trust a
    // sender-supplied count and must re-query /signature-count independently
    // before accepting it as latest-state metadata.
    let server_signature_count = bip448_signature_count(client_config, &statechain_id).await?;

    Ok(Bip448DepositSigningData {
        signing_id: pending_signing.signing_id,
        client_public_nonce: pending_signing.client_public_nonce,
        server_public_nonce: server_pubnonce,
        blinding_factor: pending_signing.blinding_factor,
        update_signature: signature.to_string(),
        server_signature_count,
    })
}

async fn pending_or_new_bip448_deposit_signing(
    client_config: &ClientConfig,
    wallet_name: &str,
    statechain_id: &str,
    update_template_hash: &str,
    client_seckey: SecretKey,
    client_pubkey: PublicKey,
    templates: &bip448_deposit::Bip448DepositTemplates,
) -> Result<Bip448PendingDepositSigning> {
    if let Some(pending) =
        get_bip448_pending_deposit_signing(&client_config.pool, wallet_name, statechain_id).await?
    {
        if pending.update_template_hash != update_template_hash {
            return Err(anyhow!(
                "BIP448 pending deposit signing template hash does not match the current deposit template"
            ));
        }

        return Ok(pending);
    }

    let secp = Secp256k1::new();
    let mut rng = rand::rng();
    let signing_message: Message = templates.update_template_hash.into();
    let (client_sec_nonce, client_pub_nonce) = new_musig_nonce_pair(
        &secp,
        MusigSessionId::new(&mut rng),
        None,
        Some(client_seckey),
        client_pubkey,
        Some(signing_message),
        None,
    )?;
    let blinding_secret = SecretKey::new(&mut rng);
    let blinding_factor = BlindingFactor::from_slice(&blinding_secret.to_secret_bytes())?;

    let pending = Bip448PendingDepositSigning {
        wallet_name: wallet_name.to_string(),
        statechain_id: statechain_id.to_string(),
        update_template_hash: update_template_hash.to_string(),
        signing_id: hex::encode(SecretKey::new(&mut rng).to_secret_bytes()),
        client_secret_nonce: hex::encode(client_sec_nonce.serialize()),
        client_public_nonce: hex::encode(client_pub_nonce.serialize()),
        blinding_factor: hex::encode(blinding_factor.as_bytes()),
        server_public_nonce: None,
    };

    insert_or_update_bip448_pending_deposit_signing(&client_config.pool, &pending).await?;

    Ok(pending)
}

async fn replay_or_request_bip448_server_pubnonce(
    client_config: &ClientConfig,
    wallet_name: &str,
    statechain_id: &str,
    signed_statechain_id: &str,
    pending_signing: &Bip448PendingDepositSigning,
) -> Result<String> {
    if let Some(stored_server_pubnonce) = &pending_signing.server_public_nonce {
        return Ok(normalize_hex(stored_server_pubnonce.clone()));
    }

    let server_pubnonce = bip448_sign_first(
        client_config,
        &Bip448SignFirstRequestPayload {
            statechain_id: statechain_id.to_string(),
            signed_statechain_id: signed_statechain_id.to_string(),
            signing_id: pending_signing.signing_id.clone(),
        },
    )
    .await?;

    update_bip448_pending_deposit_server_public_nonce(
        &client_config.pool,
        wallet_name,
        statechain_id,
        &pending_signing.signing_id,
        &server_pubnonce,
    )
    .await?;

    Ok(server_pubnonce)
}

fn musig_secret_nonce_from_hex(value: &str) -> Result<MusigSecNonce> {
    let bytes = hex::decode(value)?;
    let bytes: [u8; 132] = bytes
        .try_into()
        .map_err(|_| anyhow!("BIP448 pending client secret nonce must be 132 bytes"))?;

    Ok(MusigSecNonce::from_slice(bytes))
}

pub async fn bip448_sign_first(
    client_config: &ClientConfig,
    payload: &Bip448SignFirstRequestPayload,
) -> Result<String> {
    let endpoint = client_config.statechain_entity.clone();
    let client = client_config.get_reqwest_client()?;
    let response = client
        .post(&format!("{}/bip448-statechain/sign/first", endpoint))
        .json(payload)
        .send()
        .await?;
    let status = response.status();
    let value = response.text().await?;

    if status != StatusCode::OK {
        return Err(response_error("BIP448 sign/first", &value));
    }

    let payload: Bip448SignFirstResponsePayload = serde_json::from_str(value.as_str())?;
    Ok(normalize_hex(payload.server_pubnonce))
}

pub async fn bip448_sign_second(
    client_config: &ClientConfig,
    payload: &Bip448PartialSignatureRequestPayload,
) -> Result<PartialSignature> {
    let endpoint = client_config.statechain_entity.clone();
    let client = client_config.get_reqwest_client()?;
    let response = client
        .post(&format!("{}/bip448-statechain/sign/second", endpoint))
        .json(payload)
        .send()
        .await?;
    let status = response.status();
    let value = response.text().await?;

    if status != StatusCode::OK {
        return Err(response_error("BIP448 sign/second", &value));
    }

    let payload: Bip448PartialSignatureResponsePayload = serde_json::from_str(value.as_str())?;
    let partial_sig = hex::decode(normalize_hex(payload.partial_sig))?;

    Ok(PartialSignature::from_slice(partial_sig.as_slice())?)
}

pub async fn bip448_signature_count(
    client_config: &ClientConfig,
    statechain_id: &str,
) -> Result<u64> {
    let endpoint = client_config.statechain_entity.clone();
    let client = client_config.get_reqwest_client()?;
    let response = client
        .get(&format!(
            "{}/bip448-statechain/signature-count/{}",
            endpoint, statechain_id
        ))
        .send()
        .await?;
    let status = response.status();
    let value = response.text().await?;

    if status != StatusCode::OK {
        return Err(response_error("BIP448 signature-count", &value));
    }

    let payload: Bip448SignatureCountResponsePayload = serde_json::from_str(value.as_str())?;

    Ok(payload.sig_count)
}

fn normalize_hex(value: String) -> String {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(&value)
        .to_string()
}

fn response_error(context: &str, body: &str) -> anyhow::Error {
    if let std::result::Result::Ok(error_message) = serde_json::from_str::<Value>(body) {
        if let Some(message) = error_message["message"].as_str() {
            return anyhow!("{}: {}", context, message);
        }
    }

    anyhow!("{}: {}", context, body)
}

pub async fn init(
    client_config: &ClientConfig,
    wallet: &Wallet,
    token_id: uuid::Uuid,
) -> Result<Wallet> {
    let mut wallet = wallet.clone();

    let coin = wallet.get_new_coin()?;

    wallet.coins.push(coin.clone());

    update_wallet(&client_config.pool, &wallet).await?;

    let deposit_msg_1 = create_deposit_msg1(&coin, &token_id.to_string())?;

    // println!("deposit_msg_1: {:?}", deposit_msg_1);

    let endpoint = client_config.statechain_entity.clone();
    let path = "deposit/init/pod";

    let client = client_config.get_reqwest_client()?;
    let request = client.post(&format!("{}/{}", endpoint, path));

    let response = request.json(&deposit_msg_1).send().await?;

    if response.status() != 200 {
        let response_body = response.text().await?;
        return Err(anyhow!(response_body));
    }

    let value = response.text().await?;

    let deposit_msg_1_response: mercurylib::deposit::DepositMsg1Response =
        serde_json::from_str(value.as_str())?;

    let deposit_init_result =
        mercurylib::deposit::handle_deposit_msg_1_response(&coin, &deposit_msg_1_response)?;

    let coin = wallet.coins.last_mut().unwrap();

    coin.statechain_id = Some(deposit_init_result.statechain_id);
    coin.signed_statechain_id = Some(deposit_init_result.signed_statechain_id);
    coin.server_pubkey = Some(deposit_init_result.server_pubkey);

    update_wallet(&client_config.pool, &wallet).await?;

    Ok(wallet)
}

pub async fn get_token(client_config: &ClientConfig) -> Result<mercurylib::deposit::TokenResponse> {
    let endpoint = client_config.statechain_entity.clone();
    let path = "deposit/get_token";

    let client = client_config.get_reqwest_client()?;
    let request = client.get(&format!("{}/{}", endpoint, path));

    let response = request.send().await?;

    if response.status() != 200 {
        let response_body = response.text().await?;
        return Err(anyhow!(response_body));
    }

    let value = response.text().await?;

    let token: mercurylib::deposit::TokenResponse = serde_json::from_str(value.as_str())?;

    return Ok(token);
}
