use std::{path::PathBuf, process::Command, str::FromStr, time::Duration};

use anyhow::{anyhow, Context, Result};
use bitcoin::Transaction;
use mercurylib::{
    deposit::{self, DepositMsg1Response},
    transaction::{self, PartialSignatureMsg1},
    wallet::{Settings, Wallet},
};
use reqwest::{Client, Response, StatusCode};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::time::sleep;
use uuid::Uuid;

pub const LOCKBOX_URL: &str = "http://127.0.0.1:18080";
const READY_TIMEOUT_SECONDS: u64 = 180;

#[derive(Debug, Deserialize)]
pub struct ServerPubkeyResponse {
    pub server_pubkey: String,
}

#[derive(Debug, Deserialize)]
pub struct ServerPubnonceResponse {
    pub server_pubnonce: String,
}

#[derive(Debug, Deserialize)]
pub struct PartialSignatureResponse {
    pub partial_sig: String,
}

#[derive(Debug, Deserialize)]
pub struct SignatureCountResponse {
    pub sig_count: u32,
}

pub fn http_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .expect("reqwest client should build")
}

pub fn new_statechain_id(prefix: &str) -> String {
    let short_prefix = &prefix[..prefix.len().min(12)];
    format!("{}-{}", short_prefix, Uuid::new_v4().simple())
}

pub fn normalize_hex(value: &str) -> String {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value)
        .to_string()
}

pub async fn wait_until_ready(client: &Client) -> Result<()> {
    for _ in 0..READY_TIMEOUT_SECONDS {
        if let Ok(response) = client.get(format!("{}/", LOCKBOX_URL)).send().await {
            if response.status() == StatusCode::OK {
                let body = response.text().await.unwrap_or_default();
                if body.contains("Hello, Crow!") {
                    return Ok(());
                }
            }
        }

        sleep(Duration::from_secs(1)).await;
    }

    Err(anyhow!("lockbox did not become ready within 180 seconds"))
}

pub async fn post_json(client: &Client, path: &str, body: Value) -> Result<Response> {
    client
        .post(format!("{}/{}", LOCKBOX_URL, path))
        .json(&body)
        .send()
        .await
        .with_context(|| format!("failed POST {} with body {}", path, body))
}

pub async fn get(client: &Client, path: &str) -> Result<Response> {
    client
        .get(format!("{}/{}", LOCKBOX_URL, path))
        .send()
        .await
        .with_context(|| format!("failed GET {}", path))
}

pub async fn delete(client: &Client, path: &str) -> Result<Response> {
    client
        .delete(format!("{}/{}", LOCKBOX_URL, path))
        .send()
        .await
        .with_context(|| format!("failed DELETE {}", path))
}

pub async fn create_statechain(
    client: &Client,
    statechain_id: &str,
) -> Result<ServerPubkeyResponse> {
    let response = post_json(
        client,
        "get_public_key",
        json!({ "statechain_id": statechain_id }),
    )
    .await?;

    let mut result: ServerPubkeyResponse = ensure_success(response, "get_public_key").await?;
    result.server_pubkey = normalize_hex(&result.server_pubkey);
    Ok(result)
}

pub async fn get_public_nonce(
    client: &Client,
    statechain_id: &str,
) -> Result<ServerPubnonceResponse> {
    let response = post_json(
        client,
        "get_public_nonce",
        json!({ "statechain_id": statechain_id }),
    )
    .await?;

    let mut result: ServerPubnonceResponse = ensure_success(response, "get_public_nonce").await?;
    result.server_pubnonce = normalize_hex(&result.server_pubnonce);
    Ok(result)
}

pub async fn delete_statechain(client: &Client, statechain_id: &str) -> Result<()> {
    let response = delete(client, &format!("delete_statechain/{}", statechain_id)).await?;
    let status = response.status();
    let body = response
        .text()
        .await
        .context("failed to read delete_statechain body")?;

    if status == StatusCode::OK {
        return Ok(());
    }

    Err(anyhow!(
        "delete_statechain failed with status {} and body {}",
        status,
        body
    ))
}

pub async fn restart_lockbox_service(client: &Client) -> Result<()> {
    let output = Command::new("docker")
        .args([
            "compose",
            "-f",
            "docker-compose-lockbox.yml",
            "restart",
            "lockbox",
        ])
        .current_dir(repo_root())
        .output()
        .context("failed to restart lockbox service")?;

    if !output.status.success() {
        return Err(anyhow!(
            "failed to restart lockbox service: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    wait_until_ready(client).await
}

pub async fn stop_token_stack_lockbox_service() -> Result<()> {
    let output = Command::new("docker")
        .args([
            "compose",
            "-f",
            "docker-compose-token-servers.yml",
            "stop",
            "lockbox",
        ])
        .current_dir(repo_root())
        .output()
        .context("failed to stop token-stack lockbox service")?;

    if !output.status.success() {
        return Err(anyhow!(
            "failed to stop token-stack lockbox service: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(())
}

pub async fn start_token_stack_lockbox_service(client: &Client) -> Result<()> {
    let output = Command::new("docker")
        .args([
            "compose",
            "-f",
            "docker-compose-token-servers.yml",
            "up",
            "-d",
            "--no-deps",
            "lockbox",
        ])
        .current_dir(repo_root())
        .output()
        .context("failed to start token-stack lockbox service")?;

    if !output.status.success() {
        return Err(anyhow!(
            "failed to start token-stack lockbox service: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    wait_until_ready(client).await
}

pub async fn recreate_lockbox_service_with_rng_seed(
    client: &Client,
    rng_seed_hex: Option<&str>,
) -> Result<()> {
    let mut command = Command::new("docker");
    command
        .args([
            "compose",
            "-f",
            "docker-compose-lockbox.yml",
            "up",
            "-d",
            "--build",
            "--force-recreate",
            "lockbox",
        ])
        .current_dir(repo_root());

    match rng_seed_hex {
        Some(seed) => {
            command.env("LOCKBOX_ENABLE_TEST_RNG", "ON");
            command.env("LOCKBOX_TEST_RNG_SEED", seed);
        }
        None => {
            command.env_remove("LOCKBOX_ENABLE_TEST_RNG");
            command.env_remove("LOCKBOX_TEST_RNG_SEED");
        }
    }

    let output = command
        .output()
        .context("failed to recreate lockbox service")?;

    if !output.status.success() {
        return Err(anyhow!(
            "failed to recreate lockbox service: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    wait_until_ready(client).await
}

pub async fn keyupdate(
    client: &Client,
    statechain_id: &str,
    t2_bytes: [u8; 32],
    x1_bytes: [u8; 32],
) -> Result<ServerPubkeyResponse> {
    let response = post_json(
        client,
        "keyupdate",
        json!({
            "statechain_id": statechain_id,
            "t2": hex::encode(t2_bytes),
            "x1": hex::encode(x1_bytes),
        }),
    )
    .await?;

    let mut result: ServerPubkeyResponse = ensure_success(response, "keyupdate").await?;
    result.server_pubkey = normalize_hex(&result.server_pubkey);
    Ok(result)
}

pub async fn request_partial_signature(
    client: &Client,
    payload: &transaction::PartialSignatureRequestPayload,
) -> Result<String> {
    let response = post_json(
        client,
        "get_partial_signature",
        serde_json::to_value(payload)?,
    )
    .await?;
    let mut result: PartialSignatureResponse =
        ensure_success(response, "get_partial_signature").await?;
    result.partial_sig = normalize_hex(&result.partial_sig);

    Ok(result.partial_sig)
}

pub async fn get_signature_count(client: &Client, statechain_id: &str) -> Result<u32> {
    let response = get(client, &format!("signature_count/{}", statechain_id)).await?;
    let result: SignatureCountResponse = ensure_success(response, "signature_count").await?;

    Ok(result.sig_count)
}

pub async fn complete_signing_roundtrip(
    client: &Client,
    statechain_id: &str,
    server_pubkey: &str,
    server_pubnonce: &str,
) -> Result<Transaction> {
    let msg1 = build_partial_signature_fixture(statechain_id, server_pubkey, server_pubnonce)?;
    let server_partial_signature =
        request_partial_signature(client, &msg1.partial_signature_request_payload).await?;

    let aggregated_signature = transaction::create_signature(
        msg1.msg,
        msg1.client_partial_sig,
        server_partial_signature,
        msg1.encoded_session,
        msg1.output_pubkey,
    )?;
    let signed_tx_hex =
        transaction::new_backup_transaction(msg1.encoded_unsigned_tx, aggregated_signature)?;
    let signed_tx = bitcoin::consensus::deserialize(&hex::decode(&signed_tx_hex)?)
        .context("failed to decode signed tx")?;

    Ok(signed_tx)
}

pub fn build_partial_signature_fixture(
    statechain_id: &str,
    server_pubkey: &str,
    server_pubnonce: &str,
) -> Result<PartialSignatureMsg1> {
    let wallet = sample_wallet();
    let mut coin = wallet.get_new_coin()?;

    let deposit_init = deposit::handle_deposit_msg_1_response(
        &coin,
        &DepositMsg1Response {
            server_pubkey: normalize_hex(server_pubkey),
            statechain_id: statechain_id.to_string(),
        },
    )?;

    coin.server_pubkey = Some(deposit_init.server_pubkey);
    coin.statechain_id = Some(deposit_init.statechain_id);
    coin.signed_statechain_id = Some(deposit_init.signed_statechain_id);

    let aggregated = deposit::create_aggregated_address(&coin, wallet.network.clone())?;
    coin.aggregated_pubkey = Some(aggregated.aggregate_pubkey);
    coin.aggregated_address = Some(aggregated.aggregate_address);
    coin.utxo_txid = Some(hex::encode([0x11u8; 32]));
    coin.utxo_vout = Some(0);
    coin.amount = Some(100_000);

    let nonce = transaction::create_and_commit_nonces(&coin)?;
    coin.secret_nonce = Some(nonce.secret_nonce);
    coin.public_nonce = Some(nonce.public_nonce);
    coin.blinding_factor = Some(nonce.blinding_factor);
    coin.server_public_nonce = Some(normalize_hex(server_pubnonce));

    Ok(transaction::get_partial_sig_request(
        &coin,
        1_500,
        wallet.initlock,
        wallet.interval,
        1.5,
        0,
        coin.backup_address.clone(),
        wallet.network,
        false,
    )?)
}

pub fn expected_keyupdate_server_pubkey(
    old_server_pubkey: &str,
    t2_bytes: [u8; 32],
    x1_bytes: [u8; 32],
) -> Result<String> {
    let secp = Secp256k1::new();
    let old_server_pubkey = PublicKey::from_str(&normalize_hex(old_server_pubkey))?;
    let t2_secret = SecretKey::from_secret_bytes(t2_bytes)?;
    let x1_secret = SecretKey::from_secret_bytes(x1_bytes)?;
    let t2_pubkey = t2_secret.public_key(&secp);
    let negated_x1_secret = x1_secret.negate();
    let negated_x1_pubkey = negated_x1_secret.public_key(&secp);

    let expected = old_server_pubkey
        .combine(&t2_pubkey)?
        .combine(&negated_x1_pubkey)?;

    Ok(expected.to_string())
}

async fn ensure_success<T: DeserializeOwned>(response: Response, context: &str) -> Result<T> {
    let status = response.status();
    let body = response
        .text()
        .await
        .with_context(|| format!("failed to read {} response body", context))?;

    if !status.is_success() {
        return Err(anyhow!(
            "{} failed with status {} and body {}",
            context,
            status,
            body
        ));
    }

    serde_json::from_str(&body)
        .with_context(|| format!("failed to decode {} response body {}", context, body))
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

pub fn sample_wallet() -> Wallet {
    Wallet {
        name: "lockbox-compat".to_string(),
        mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
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
