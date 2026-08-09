use std::{path::PathBuf, process::Command, str::FromStr, time::Duration};

use anyhow::{anyhow, Context, Result};
use bitcoin::{hashes::Hash, sighash::TemplateHash};
use mercurylib::{
    bip448_statechain::{
        signing::{CsfsSigningParticipant, CsfsSigningRole, CsfsSigningSession},
        signing_api::{
            Bip448LockboxPartialSignatureRequestPayload, Bip448LockboxSignFirstRequestPayload,
        },
    },
    wallet::{Settings, Wallet},
};
use reqwest::{Client, Response, StatusCode};
use secp256k1::{
    musig::{new_musig_nonce_pair, BlindingFactor, MusigSessionId, PartialSignature, PublicNonce},
    rand, Message, PublicKey, Secp256k1, SecretKey,
};
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

pub struct Bip448PartialSignatureFixture {
    pub payload: Bip448LockboxPartialSignatureRequestPayload,
    session: CsfsSigningSession,
    server_public_nonce: PublicNonce,
    server_public_key: PublicKey,
}

impl Bip448PartialSignatureFixture {
    pub fn verify_server_partial_signature(&self, partial_sig: &str) -> Result<()> {
        let secp = Secp256k1::new();
        let partial_sig = PartialSignature::from_slice(&hex::decode(partial_sig)?)?;
        self.session.verify_partial(
            &secp,
            CsfsSigningParticipant::Server,
            &partial_sig,
            &self.server_public_nonce,
            &self.server_public_key,
        )?;

        Ok(())
    }
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
    // Mirror the production `normalize_hex_wire_value`: strip an 0x/0X prefix
    // and lowercase, so test-side comparisons match the server's stored form.
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value)
        .to_ascii_lowercase()
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

pub async fn bip448_get_public_nonce(
    client: &Client,
    payload: &Bip448LockboxSignFirstRequestPayload,
) -> Result<ServerPubnonceResponse> {
    let response = post_json(
        client,
        "bip448/get_public_nonce",
        serde_json::to_value(payload)?,
    )
    .await?;

    let mut result: ServerPubnonceResponse =
        ensure_success(response, "bip448/get_public_nonce").await?;
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
    run_docker_compose(
        "docker-compose-lockbox.yml",
        &["restart", "lockbox"],
        "restart lockbox service",
    )?;

    wait_until_ready(client).await
}

pub async fn stop_token_stack_lockbox_service() -> Result<()> {
    run_docker_compose(
        "docker-compose-token-servers.yml",
        &["stop", "lockbox"],
        "stop token-stack lockbox service",
    )
}

pub async fn start_token_stack_lockbox_service(client: &Client) -> Result<()> {
    run_docker_compose(
        "docker-compose-token-servers.yml",
        &["up", "-d", "--no-deps", "lockbox"],
        "start token-stack lockbox service",
    )?;

    wait_until_ready(client).await
}

fn run_docker_compose(compose_file: &str, args: &[&str], context: &str) -> Result<()> {
    let command = docker_compose_command(compose_file, args);
    run_docker_command(command, context)
}

fn docker_compose_command(compose_file: &str, args: &[&str]) -> Command {
    let mut command = Command::new("docker");
    command
        .arg("compose")
        .arg("-f")
        .arg(compose_file)
        .args(args)
        .current_dir(repo_root());
    command
}

fn run_docker_command(mut command: Command, context: &str) -> Result<()> {
    let output = command
        .output()
        .with_context(|| format!("failed to {context}"))?;

    if !output.status.success() {
        return Err(anyhow!(
            "failed to {}: stdout={} stderr={}",
            context,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(())
}

pub async fn recreate_lockbox_service_with_rng_seed(
    client: &Client,
    rng_seed_hex: Option<&str>,
) -> Result<()> {
    run_recreate_lockbox_service_with_rng_seed(rng_seed_hex)?;

    wait_until_ready(client).await
}

pub fn recreate_lockbox_service_with_production_rng() -> Result<()> {
    run_recreate_lockbox_service_with_rng_seed(None)
}

fn run_recreate_lockbox_service_with_rng_seed(rng_seed_hex: Option<&str>) -> Result<()> {
    let mut command = docker_compose_command(
        "docker-compose-lockbox.yml",
        &["up", "-d", "--build", "--force-recreate", "lockbox"],
    );

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

    run_docker_command(command, "recreate lockbox service")
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

pub async fn bip448_request_partial_signature(
    client: &Client,
    payload: &Bip448LockboxPartialSignatureRequestPayload,
) -> Result<String> {
    let response = post_json(
        client,
        "bip448/get_partial_signature",
        serde_json::to_value(payload)?,
    )
    .await?;
    let mut result: PartialSignatureResponse =
        ensure_success(response, "bip448/get_partial_signature").await?;
    result.partial_sig = normalize_hex(&result.partial_sig);

    Ok(result.partial_sig)
}

pub async fn complete_bip448_signing_roundtrip(
    client: &Client,
    statechain_id: &str,
    signing_id: &str,
    server_pubkey: &str,
    server_pubnonce: &str,
) -> Result<String> {
    let fixture = build_bip448_partial_signature_fixture(
        statechain_id,
        signing_id,
        server_pubkey,
        server_pubnonce,
    )?;
    let partial_sig = bip448_request_partial_signature(client, &fixture.payload).await?;
    fixture.verify_server_partial_signature(&partial_sig)?;

    Ok(partial_sig)
}

pub async fn get_signature_count(client: &Client, statechain_id: &str) -> Result<u32> {
    let response = get(client, &format!("signature_count/{}", statechain_id)).await?;
    let result: SignatureCountResponse = ensure_success(response, "signature_count").await?;

    Ok(result.sig_count)
}

pub fn build_bip448_partial_signature_fixture(
    statechain_id: &str,
    signing_id: &str,
    server_pubkey: &str,
    server_pubnonce: &str,
) -> Result<Bip448PartialSignatureFixture> {
    let secp = Secp256k1::new();
    let client_secret_key = SecretKey::from_secret_bytes([0x21u8; 32])?;
    let client_public_key = client_secret_key.public_key(&secp);
    let server_public_key = PublicKey::from_str(&normalize_hex(server_pubkey))?;
    let aggregate_public_key = client_public_key.combine(&server_public_key)?;
    let template_hash = TemplateHash::from_slice(&[0x51u8; 32])?;
    let signing_message: Message = template_hash.into();
    let mut rng = rand::rng();
    let (_client_secret_nonce, client_public_nonce) = new_musig_nonce_pair(
        &secp,
        MusigSessionId::new(&mut rng),
        None,
        Some(client_secret_key),
        client_public_key,
        Some(signing_message),
        None,
    )?;
    let server_public_nonce = PublicNonce::from_slice(&hex::decode(server_pubnonce)?)?;
    let blinding_factor = BlindingFactor::from_slice(&[0x22u8; 32])?;
    let session = CsfsSigningSession::new(
        &secp,
        CsfsSigningRole::FundingUpdate,
        aggregate_public_key,
        &client_public_nonce,
        &server_public_nonce,
        template_hash,
        &blinding_factor,
    )?;
    let serialized_session = session.blinded_server_session().serialize();
    assert_eq!(serialized_session.len(), 133);

    Ok(Bip448PartialSignatureFixture {
        payload: Bip448LockboxPartialSignatureRequestPayload {
            statechain_id: statechain_id.to_string(),
            signing_id: signing_id.to_string(),
            negate_seckey: u8::from(session.negate_seckey()),
            session: hex::encode(serialized_session),
            server_pub_nonce: normalize_hex(server_pubnonce),
        },
        session,
        server_public_nonce,
        server_public_key,
    })
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
