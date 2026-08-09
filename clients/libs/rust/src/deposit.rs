use anyhow::{anyhow, Ok, Result};
use bitcoin::{absolute, hashes::Hash, OutPoint, PrivateKey, TxOut, Txid};
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
    deposit::create_deposit_msg1,
    wallet::{Coin, Wallet},
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
        history_entry, insert_bip448_pending_deposit_signing_if_absent,
        insert_bip448_state_history_entry, insert_or_update_bip448_statechain,
        update_bip448_pending_deposit_server_public_nonce, update_wallet,
        Bip448PendingDepositSigning,
    },
};

#[cfg(feature = "test-hooks")]
fn bip448_process_checkpoint(checkpoint: &str) {
    let is_restart_child =
        std::env::var("ML_BIP448_RESTART_CHILD").as_deref() == std::result::Result::Ok("1");
    if is_restart_child
        && matches!(
            std::env::var("ML_BIP448_TEST_CHECKPOINT").as_deref(),
            std::result::Result::Ok(configured) if configured == checkpoint
        )
    {
        std::process::exit(86);
    }
}

#[cfg(not(feature = "test-hooks"))]
fn bip448_process_checkpoint(_checkpoint: &str) {}

#[derive(Debug, Clone, Serialize)]
pub struct Bip448DepositAddressResult {
    pub address: String,
    pub statechain_id: String,
    pub aggregate_pubkey: String,
}

pub(crate) struct Bip448AcceptedDepositState {
    record: Bip448StatechainRecord,
}

impl Bip448AcceptedDepositState {
    fn new(
        record: Bip448StatechainRecord,
        templates: &bip448_deposit::Bip448DepositTemplates,
        median_time_past: u32,
    ) -> Result<Self> {
        if record.latest_state_number != bip448_deposit::INITIAL_BIP448_STATE_NUMBER
            || record.latest_state.state_number != bip448_deposit::INITIAL_BIP448_STATE_NUMBER
            || record.latest_state.signing_metadata.server_signature_count
                != u64::from(bip448_deposit::INITIAL_BIP448_STATE_NUMBER)
        {
            return Err(anyhow!(
                "accepted BIP448 deposit must be the initial logical state"
            ));
        }
        if record.aggregate_pubkey != templates.aggregate_pubkey
            || record.funding_outpoint != templates.funding_outpoint
            || record.amount_sats != templates.funding_outpoint.value_sats
            || record.latest_state.state_locktime != templates.artifacts.state_locktime
        {
            return Err(anyhow!(
                "accepted BIP448 deposit record does not match its canonical construction inputs"
            ));
        }

        let aggregate_pubkey = PublicKey::from_str(&record.aggregate_pubkey)?;
        let funding_outpoint = OutPoint {
            txid: Txid::from_str(&record.funding_outpoint.txid)?,
            vout: record.funding_outpoint.vout,
        };
        let funding_output = TxOut {
            value: record.funding_outpoint.value_sats,
            script_pubkey: templates.artifacts.funding_output_script_pubkey.clone(),
        };
        let recovery_script = templates
            .artifacts
            .settlement_tx
            .output
            .first()
            .ok_or_else(|| anyhow!("BIP448 settlement template has no recovery output"))?
            .script_pubkey
            .clone();
        let canonical = record.latest_state.verify_reconstructed_templates(
            &Secp256k1::new(),
            &aggregate_pubkey,
            funding_outpoint,
            &funding_output,
            &recovery_script,
        )?;
        if canonical != record.latest_state {
            return Err(anyhow!(
                "accepted BIP448 deposit record is not the canonical reconstructed state"
            ));
        }
        mercurylib::bip448_statechain::transaction::validate_immediately_final(
            absolute::LockTime::from_consensus(record.latest_state.state_locktime),
            median_time_past,
        )?;

        Ok(Self { record })
    }

    pub(crate) fn record(&self) -> &Bip448StatechainRecord {
        &self.record
    }

    fn into_record(self) -> Bip448StatechainRecord {
        self.record
    }
}

fn populate_bip448_deposit_locktime(coin: &mut Coin, accepted: &Bip448AcceptedDepositState) {
    coin.locktime = Some(accepted.record().latest_state.state_locktime);
}

pub async fn get_bip448_deposit_bitcoin_address(
    client_config: &ClientConfig,
    wallet_name: &str,
    token_id: &str,
    amount: u32,
) -> Result<Bip448DepositAddressResult> {
    let token_id = uuid::Uuid::parse_str(&token_id)?;
    let wallet = get_wallet(&client_config.pool, &wallet_name).await?;
    let mut wallet = init_bip448(&client_config, &wallet, token_id).await?;

    let coin = wallet.coins.last_mut().unwrap();

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
    let statechain_id = coin
        .statechain_id
        .clone()
        .ok_or_else(|| anyhow!("BIP448 deposit coin missing statechain_id"))?;
    let (templates, pending_signing) = pending_or_new_bip448_deposit_signing(
        client_config,
        wallet_name,
        &statechain_id,
        coin,
        funding_outpoint,
        wallet_network,
    )
    .await?;
    bip448_process_checkpoint("pending_persisted");
    let signing_data = sign_bip448_update(
        client_config,
        wallet_name,
        coin,
        &templates,
        pending_signing,
    )
    .await?;
    let median_time_past = client_config.chain_client.median_time_past()?;
    let record = bip448_deposit::build_deposit_record(
        wallet_name,
        &statechain_id,
        wallet_network,
        &templates,
        signing_data.clone(),
    )?;
    let accepted = Bip448AcceptedDepositState::new(record, &templates, median_time_past)?;

    coin.public_nonce = Some(signing_data.client_public_nonce);
    coin.server_public_nonce = Some(signing_data.server_public_nonce);
    coin.blinding_factor = Some(signing_data.blinding_factor);
    populate_bip448_deposit_locktime(coin, &accepted);

    insert_or_update_bip448_statechain(&client_config.pool, &accepted).await?;
    insert_bip448_state_history_entry(
        &client_config.pool,
        wallet_name,
        &statechain_id,
        &history_entry(
            &accepted.record().latest_state,
            PublicKey::from_str(&coin.user_pubkey)?.x_only_public_key().0,
        ),
    )
    .await?;
    bip448_process_checkpoint("accepted_persisted");
    delete_bip448_pending_deposit_signing(
        &client_config.pool,
        wallet_name,
        &statechain_id,
        &signing_data.signing_id,
    )
    .await?;

    Ok(accepted.into_record())
}

async fn sign_bip448_update(
    client_config: &ClientConfig,
    wallet_name: &str,
    coin: &Coin,
    templates: &bip448_deposit::Bip448DepositTemplates,
    pending_signing: Bip448PendingDepositSigning,
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
    bip448_process_checkpoint("server_nonce_persisted");
    let server_pub_nonce = PublicNonce::from_slice(&hex::decode(&server_pubnonce)?)?;
    let session = CsfsSigningSession::new(
        &secp,
        CsfsSigningRole::FundingUpdate,
        aggregate_pubkey,
        &client_pub_nonce,
        &server_pub_nonce,
        templates.artifacts.update_template_hash,
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
    bip448_process_checkpoint("final_signature_completed");
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
    coin: &Coin,
    funding_outpoint: Bip448FundingOutpoint,
    wallet_network: &str,
) -> Result<(
    bip448_deposit::Bip448DepositTemplates,
    Bip448PendingDepositSigning,
)> {
    if let Some(pending) =
        get_bip448_pending_deposit_signing(&client_config.pool, wallet_name, statechain_id).await?
    {
        let templates = build_pending_bip448_deposit_templates(
            coin,
            funding_outpoint,
            wallet_network,
            &pending,
        )?;
        return Ok((templates, pending));
    }

    let state_locktime = bip448_deposit::sample_initial_state_locktime().to_consensus_u32();
    let templates = bip448_deposit::build_deposit_templates(
        coin,
        funding_outpoint.clone(),
        absolute::LockTime::from_consensus(state_locktime),
        bip448_deposit::DEFAULT_BIP448_CHALLENGE_DELAY,
        wallet_network,
    )?;
    let update_template_hash =
        hex::encode(templates.artifacts.update_template_hash.to_byte_array());
    let settlement_template_hash =
        hex::encode(templates.artifacts.settlement_template_hash.to_byte_array());
    let client_seckey = PrivateKey::from_wif(&coin.user_privkey)?.inner;
    let client_pubkey = PublicKey::from_str(&coin.user_pubkey)?;
    let secp = Secp256k1::new();
    let mut rng = rand::rng();
    let signing_message: Message = templates.artifacts.update_template_hash.into();
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
        funding_txid: funding_outpoint.txid.clone(),
        funding_vout: funding_outpoint.vout,
        funding_value_sats: funding_outpoint.value_sats,
        update_template_hash,
        settlement_template_hash,
        state_locktime,
        signing_id: hex::encode(SecretKey::new(&mut rng).to_secret_bytes()),
        client_secret_nonce: hex::encode(client_sec_nonce.serialize()),
        client_public_nonce: hex::encode(client_pub_nonce.serialize()),
        blinding_factor: hex::encode(blinding_factor.as_bytes()),
        server_public_nonce: None,
    };

    let persisted =
        insert_bip448_pending_deposit_signing_if_absent(&client_config.pool, &pending).await?;
    if persisted == pending {
        return Ok((templates, persisted));
    }

    let templates =
        build_pending_bip448_deposit_templates(coin, funding_outpoint, wallet_network, &persisted)?;
    Ok((templates, persisted))
}

fn build_pending_bip448_deposit_templates(
    coin: &Coin,
    funding_outpoint: Bip448FundingOutpoint,
    wallet_network: &str,
    pending: &Bip448PendingDepositSigning,
) -> Result<bip448_deposit::Bip448DepositTemplates> {
    if pending.funding_txid != funding_outpoint.txid
        || pending.funding_vout != funding_outpoint.vout
        || pending.funding_value_sats != funding_outpoint.value_sats
    {
        return Err(anyhow!(
            "BIP448 pending deposit signing funding outpoint does not match the detected funding output"
        ));
    }
    let templates = bip448_deposit::build_deposit_templates(
        coin,
        funding_outpoint,
        absolute::LockTime::from_consensus(pending.state_locktime),
        bip448_deposit::DEFAULT_BIP448_CHALLENGE_DELAY,
        wallet_network,
    )?;
    let update_template_hash =
        hex::encode(templates.artifacts.update_template_hash.to_byte_array());
    let settlement_template_hash =
        hex::encode(templates.artifacts.settlement_template_hash.to_byte_array());
    if pending.update_template_hash != update_template_hash
        || pending.settlement_template_hash != settlement_template_hash
    {
        return Err(anyhow!(
            "BIP448 pending deposit signing template hashes do not match the persisted-locktime deposit template"
        ));
    }

    Ok(templates)
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

async fn init_bip448(
    client_config: &ClientConfig,
    wallet: &Wallet,
    token_id: uuid::Uuid,
) -> Result<Wallet> {
    let mut wallet = wallet.clone();

    let mut coin = wallet.get_new_coin()?;
    coin.statechain_protocol = Some(BIP448_COIN_PROTOCOL.to_string());

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chain::{ChainClient, CoreRpcAuth, CoreRpcConfig},
        sqlite_manager::get_bip448_pending_deposit_signing,
    };
    use bitcoin::Network;
    use mercurylib::wallet::Settings;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn test_client_config() -> Result<ClientConfig> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;

        Ok(ClientConfig {
            statechain_entity: "http://127.0.0.1:1".to_string(),
            chain_backend: "core".to_string(),
            chain_client: ChainClient::new(CoreRpcConfig {
                url: "http://127.0.0.1:1".to_string(),
                auth: CoreRpcAuth::None,
            })?,
            core_rpc_url: Some("http://127.0.0.1:1".to_string()),
            core_rpc_auth: Some("none".to_string()),
            core_rpc_user: None,
            core_rpc_password: None,
            core_rpc_cookie_file: None,
            network: Network::Regtest,
            fee_rate_tolerance: 0.0,
            confirmation_target: 1,
            pool,
            tor_proxy: None,
            max_fee_rate: 10.0,
        })
    }

    fn sample_coin() -> Coin {
        let wallet = Wallet {
            name: "wallet".to_string(),
            mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            version: "0.1.0".to_string(),
            state_entity_endpoint: "http://127.0.0.1:1".to_string(),
            chain_backend: "core".to_string(),
            chain_endpoint: "http://127.0.0.1:1".to_string(),
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
                statechainEntityApi: "http://127.0.0.1:1".to_string(),
                torStatechainEntityApi: None,
                chainBackend: "core".to_string(),
                chainUrl: "http://127.0.0.1:1".to_string(),
                chainType: None,
                notifications: false,
                tutorials: false,
            },
        };
        let mut coin = wallet.get_new_coin().unwrap();
        let secp = Secp256k1::new();
        let server_secret = SecretKey::from_secret_bytes([7u8; 32]).unwrap();
        let server_pubkey = server_secret.public_key(&secp);
        let user_pubkey = PublicKey::from_str(&coin.user_pubkey).unwrap();
        coin.server_pubkey = Some(server_pubkey.to_string());
        coin.aggregated_pubkey = Some(user_pubkey.combine(&server_pubkey).unwrap().to_string());
        coin.statechain_protocol = Some(BIP448_COIN_PROTOCOL.to_string());
        coin.statechain_id = Some("statechain".to_string());
        coin.signed_statechain_id = Some("signed-statechain".to_string());
        coin.amount = Some(50_000);
        coin
    }

    fn assert_payload_excludes_template_values(
        payload_json: &str,
        templates: &bip448_deposit::Bip448DepositTemplates,
    ) {
        let artifacts = &templates.artifacts;
        let forbidden_values = [
            artifacts.state_locktime.to_string(),
            hex::encode(artifacts.update_template_hash.to_byte_array()),
            hex::encode(artifacts.settlement_template_hash.to_byte_array()),
            hex::encode(bitcoin::consensus::encode::serialize(&artifacts.update_tx)),
            hex::encode(bitcoin::consensus::encode::serialize(
                &artifacts.settlement_tx,
            )),
            hex::encode(artifacts.state_output_script_pubkey.as_bytes()),
            hex::encode(artifacts.funding_update_script.as_bytes()),
            hex::encode(artifacts.funding_update_control_block.serialize()),
            hex::encode(artifacts.state_update_script.as_bytes()),
            hex::encode(artifacts.state_update_control_block.serialize()),
            hex::encode(artifacts.state_settlement_script.as_bytes()),
            hex::encode(artifacts.state_settlement_control_block.serialize()),
        ];
        let payload_json = payload_json.to_ascii_lowercase();
        for forbidden in forbidden_values {
            assert!(
                !payload_json.contains(&forbidden),
                "signing payload exposed template value {forbidden}"
            );
        }
    }

    #[tokio::test]
    async fn pending_identity_is_committed_before_signing_and_reused_exactly() -> Result<()> {
        let client_config = test_client_config().await?;
        let coin = sample_coin();
        let funding_outpoint = Bip448FundingOutpoint {
            txid: Txid::from_slice(&[0x11; 32])?.to_string(),
            vout: 2,
            value_sats: 50_000,
        };

        let (first_templates, first_pending) = pending_or_new_bip448_deposit_signing(
            &client_config,
            "wallet",
            "statechain",
            &coin,
            funding_outpoint.clone(),
            "regtest",
        )
        .await?;
        let persisted =
            get_bip448_pending_deposit_signing(&client_config.pool, "wallet", "statechain")
                .await?
                .expect("pending identity must be committed before signing starts");
        assert_eq!(persisted, first_pending);

        let first_payload = Bip448SignFirstRequestPayload {
            statechain_id: "statechain".to_string(),
            signed_statechain_id: "signed-statechain".to_string(),
            signing_id: first_pending.signing_id.clone(),
        };
        assert_payload_excludes_template_values(
            &serde_json::to_string(&first_payload)?,
            &first_templates,
        );

        let secp = Secp256k1::new();
        let server_secret = SecretKey::from_secret_bytes([7u8; 32])?;
        let server_keypair = KeyPair::from_secret_key(&secp, &server_secret);
        let mut rng = rand::rng();
        let (_, server_public_nonce) = new_musig_nonce_pair(
            &secp,
            MusigSessionId::new(&mut rng),
            None,
            Some(server_secret),
            server_keypair.public_key(),
            Some(first_templates.artifacts.update_template_hash.into()),
            None,
        )?;
        let client_public_nonce =
            PublicNonce::from_slice(&hex::decode(&first_pending.client_public_nonce)?)?;
        let blinding_factor =
            BlindingFactor::from_slice(&hex::decode(&first_pending.blinding_factor)?)?;
        let session = CsfsSigningSession::new(
            &secp,
            CsfsSigningRole::FundingUpdate,
            PublicKey::from_str(&first_templates.aggregate_pubkey)?,
            &client_public_nonce,
            &server_public_nonce,
            first_templates.artifacts.update_template_hash,
            &blinding_factor,
        )?;
        let second_payload = Bip448PartialSignatureRequestPayload {
            statechain_id: "statechain".to_string(),
            signed_statechain_id: "signed-statechain".to_string(),
            signing_id: first_pending.signing_id.clone(),
            negate_seckey: u8::from(session.negate_seckey()),
            session: hex::encode(session.blinded_server_session().serialize()),
            server_pub_nonce: hex::encode(server_public_nonce.serialize()),
        };
        assert_payload_excludes_template_values(
            &serde_json::to_string(&second_payload)?,
            &first_templates,
        );

        let (retry_templates, retry_pending) = pending_or_new_bip448_deposit_signing(
            &client_config,
            "wallet",
            "statechain",
            &coin,
            funding_outpoint,
            "regtest",
        )
        .await?;
        assert_eq!(retry_pending, first_pending);
        assert_eq!(retry_templates.artifacts, first_templates.artifacts);

        update_bip448_pending_deposit_server_public_nonce(
            &client_config.pool,
            "wallet",
            "statechain",
            &first_pending.signing_id,
            &format!("0X{}", "AB".repeat(66)),
        )
        .await?;
        let after_sign_first =
            get_bip448_pending_deposit_signing(&client_config.pool, "wallet", "statechain")
                .await?
                .expect("server nonce must survive a restart boundary");
        let replayed_nonce = replay_or_request_bip448_server_pubnonce(
            &client_config,
            "wallet",
            "statechain",
            "signed-statechain",
            &after_sign_first,
        )
        .await?;
        assert_eq!(replayed_nonce, "AB".repeat(66));

        let user_secret = PrivateKey::from_wif(&coin.user_privkey)?.inner;
        let server_secret = SecretKey::from_secret_bytes([7u8; 32])?;
        let server_scalar = secp256k1::Scalar::from_be_bytes(server_secret.to_secret_bytes())?;
        let aggregate_secret = user_secret.add_tweak(&server_scalar)?;
        let aggregate_keypair = KeyPair::from_secret_key(&secp, &aggregate_secret);
        let update_signature = secp256k1::schnorr::sign(
            first_templates
                .artifacts
                .update_template_hash
                .as_byte_array(),
            &aggregate_keypair,
        );
        let signing_data = Bip448DepositSigningData {
            signing_id: first_pending.signing_id.clone(),
            client_public_nonce: first_pending.client_public_nonce.clone(),
            server_public_nonce: replayed_nonce,
            blinding_factor: first_pending.blinding_factor.clone(),
            update_signature: update_signature.to_string(),
            server_signature_count: 1,
        };
        let record = bip448_deposit::build_deposit_record(
            "wallet",
            "statechain",
            "regtest",
            &first_templates,
            signing_data.clone(),
        )?;
        let rebuilt_after_final_signature = bip448_deposit::build_deposit_record(
            "wallet",
            "statechain",
            "regtest",
            &first_templates,
            signing_data,
        )?;
        assert_eq!(rebuilt_after_final_signature, record);

        let accepted =
            Bip448AcceptedDepositState::new(record.clone(), &first_templates, 1_900_000_000)?;
        let mut accepted_coin = coin.clone();
        populate_bip448_deposit_locktime(&mut accepted_coin, &accepted);
        assert_eq!(
            accepted_coin.locktime,
            Some(accepted.record().latest_state.state_locktime)
        );
        insert_or_update_bip448_statechain(&client_config.pool, &accepted).await?;
        let persisted_accepted = crate::sqlite_manager::get_bip448_statechain_optional(
            &client_config.pool,
            "wallet",
            "statechain",
        )
        .await?
        .expect("accepted state must survive before pending cleanup");
        assert_eq!(persisted_accepted, record);
        assert!(
            get_bip448_pending_deposit_signing(&client_config.pool, "wallet", "statechain")
                .await?
                .is_some()
        );
        let (post_acceptance_templates, post_acceptance_pending) =
            pending_or_new_bip448_deposit_signing(
                &client_config,
                "wallet",
                "statechain",
                &coin,
                first_templates.funding_outpoint.clone(),
                "regtest",
            )
            .await?;
        assert_eq!(post_acceptance_pending, after_sign_first);
        assert_eq!(
            post_acceptance_templates.artifacts,
            first_templates.artifacts
        );

        sqlx::query(
            "UPDATE bip448_pending_deposit_signings SET update_template_hash = ?1 \
             WHERE wallet_name = ?2 AND statechain_id = ?3",
        )
        .bind("00".repeat(32))
        .bind("wallet")
        .bind("statechain")
        .execute(&client_config.pool)
        .await?;
        let error = pending_or_new_bip448_deposit_signing(
            &client_config,
            "wallet",
            "statechain",
            &coin,
            first_templates.funding_outpoint.clone(),
            "regtest",
        )
        .await
        .expect_err("corrupted persisted identity must fail before signing");
        assert!(error
            .to_string()
            .contains("persisted-locktime deposit template"));

        sqlx::query(
            "UPDATE bip448_pending_deposit_signings \
             SET update_template_hash = ?1, settlement_template_hash = ?2 \
             WHERE wallet_name = ?3 AND statechain_id = ?4",
        )
        .bind(&first_pending.update_template_hash)
        .bind("00".repeat(32))
        .bind("wallet")
        .bind("statechain")
        .execute(&client_config.pool)
        .await?;
        let error = pending_or_new_bip448_deposit_signing(
            &client_config,
            "wallet",
            "statechain",
            &coin,
            first_templates.funding_outpoint,
            "regtest",
        )
        .await
        .expect_err("corrupted settlement template identity must fail before signing");
        assert!(error
            .to_string()
            .contains("persisted-locktime deposit template"));

        Ok(())
    }
}
