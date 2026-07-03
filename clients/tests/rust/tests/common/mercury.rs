use std::{
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use mercurylib::{
    bip448_statechain::signing_api::{
        Bip448PartialSignatureRequestPayload, Bip448PartialSignatureResponsePayload,
        Bip448SignFirstRequestPayload, Bip448SignFirstResponsePayload,
    },
    deposit::{self, DepositMsg1, DepositMsg1Response, TokenResponse},
    transaction::{
        PartialSignatureRequestPayload, PartialSignatureResponsePayload, SignFirstRequestPayload,
        SignFirstResponsePayload,
    },
    transfer::receiver::{
        StatechainInfoResponsePayload, TransferReceiverPostResponsePayload,
        TransferReceiverRequestPayload,
    },
    wallet::{Coin, Wallet},
};
use reqwest::{Client, Response, StatusCode};
use secp256k1::{hashes::sha256, KeyPair, Message, PublicKey, Secp256k1, SecretKey};
use serde::de::DeserializeOwned;
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use tokio::time::sleep;

use crate::common::{bitcoin_core, lockbox};

pub const MERCURY_URL: &str = "http://127.0.0.1:8000";
const MERCURY_DATABASE_URL: &str = "postgres://postgres:postgres@127.0.0.1:5432/mercury";
const READY_TIMEOUT_SECONDS: u64 = 180;
static NEXT_MERCURY_COIN_INDEX: AtomicU32 = AtomicU32::new(0);

pub fn http_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .expect("reqwest client should build")
}

pub async fn wait_until_ready(client: &Client) -> Result<()> {
    for _ in 0..READY_TIMEOUT_SECONDS {
        if let Ok(response) = client
            .get(format!("{}/info/config", MERCURY_URL))
            .send()
            .await
        {
            if response.status() == StatusCode::OK {
                return Ok(());
            }
        }

        sleep(Duration::from_secs(1)).await;
    }

    Err(anyhow!(
        "mercury server did not become ready within 180 seconds"
    ))
}

pub async fn get_token(client: &Client) -> Result<TokenResponse> {
    let response = client
        .get(format!("{}/deposit/get_token", MERCURY_URL))
        .send()
        .await
        .context("failed to call mercury deposit/get_token")?;

    ensure_success(response, "deposit/get_token").await
}

pub async fn deposit_init(client: &Client, payload: &DepositMsg1) -> Result<DepositMsg1Response> {
    let response = client
        .post(format!("{}/deposit/init/pod", MERCURY_URL))
        .json(payload)
        .send()
        .await
        .context("failed to call mercury deposit/init/pod")?;

    ensure_success(response, "deposit/init/pod").await
}

pub async fn sign_first(
    client: &Client,
    payload: &SignFirstRequestPayload,
) -> Result<SignFirstResponsePayload> {
    let response = client
        .post(format!("{}/sign/first", MERCURY_URL))
        .json(payload)
        .send()
        .await
        .context("failed to call mercury sign/first")?;

    let mut result: SignFirstResponsePayload = ensure_success(response, "sign/first").await?;
    result.server_pubnonce = lockbox::normalize_hex(&result.server_pubnonce);

    Ok(result)
}

pub async fn sign_second(
    client: &Client,
    payload: &PartialSignatureRequestPayload,
) -> Result<PartialSignatureResponsePayload> {
    let response = client
        .post(format!("{}/sign/second", MERCURY_URL))
        .json(payload)
        .send()
        .await
        .context("failed to call mercury sign/second")?;

    let mut result: PartialSignatureResponsePayload =
        ensure_success(response, "sign/second").await?;
    result.partial_sig = lockbox::normalize_hex(&result.partial_sig);

    Ok(result)
}

pub async fn bip448_sign_first(
    client: &Client,
    payload: &Bip448SignFirstRequestPayload,
) -> Result<Bip448SignFirstResponsePayload> {
    let response = client
        .post(format!("{}/bip448-statechain/sign/first", MERCURY_URL))
        .json(payload)
        .send()
        .await
        .context("failed to call mercury bip448 sign/first")?;

    let mut result: Bip448SignFirstResponsePayload =
        ensure_success(response, "bip448 sign/first").await?;
    result.server_pubnonce = lockbox::normalize_hex(&result.server_pubnonce);

    Ok(result)
}

pub async fn bip448_sign_second(
    client: &Client,
    payload: &Bip448PartialSignatureRequestPayload,
) -> Result<Bip448PartialSignatureResponsePayload> {
    let response = client
        .post(format!("{}/bip448-statechain/sign/second", MERCURY_URL))
        .json(payload)
        .send()
        .await
        .context("failed to call mercury bip448 sign/second")?;

    let mut result: Bip448PartialSignatureResponsePayload =
        ensure_success(response, "bip448 sign/second").await?;
    result.partial_sig = lockbox::normalize_hex(&result.partial_sig);

    Ok(result)
}

pub async fn statechain_info(
    client: &Client,
    statechain_id: &str,
) -> Result<StatechainInfoResponsePayload> {
    let response = client
        .get(format!("{}/info/statechain/{}", MERCURY_URL, statechain_id))
        .send()
        .await
        .with_context(|| format!("failed to call mercury info/statechain/{}", statechain_id))?;

    ensure_success(response, "info/statechain").await
}

pub async fn transfer_receiver(
    client: &Client,
    payload: &TransferReceiverRequestPayload,
) -> Result<TransferReceiverPostResponsePayload> {
    let response = client
        .post(format!("{}/transfer/receiver", MERCURY_URL))
        .json(payload)
        .send()
        .await
        .context("failed to call mercury transfer/receiver")?;

    ensure_success(response, "transfer/receiver").await
}

pub async fn create_deposited_coin(client: &Client) -> Result<(Wallet, Coin)> {
    for _ in 0..32 {
        let mut wallet = lockbox::sample_wallet();
        let derivation_index = NEXT_MERCURY_COIN_INDEX.fetch_add(1, Ordering::SeqCst);

        for _ in 0..derivation_index {
            let previous_coin = wallet.get_new_coin()?;
            wallet.coins.push(previous_coin);
        }

        let mut coin = wallet.get_new_coin()?;
        let token = get_token(client).await?;
        pay_token_if_required(&token)?;
        let deposit_msg1 = deposit::create_deposit_msg1(&coin, &token.token_id)?;

        match deposit_init(client, &deposit_msg1).await {
            Ok(response) => {
                let init = deposit::handle_deposit_msg_1_response(&coin, &response)?;

                coin.statechain_id = Some(init.statechain_id);
                coin.signed_statechain_id = Some(init.signed_statechain_id);
                coin.server_pubkey = Some(init.server_pubkey);

                return Ok((wallet, coin));
            }
            Err(err) if err.to_string().contains("already assigned to a statecoin") => continue,
            Err(err) => return Err(err),
        }
    }

    Err(anyhow!(
        "failed to create a deposited coin with a unique auth key after 32 attempts"
    ))
}

fn pay_token_if_required(token: &TokenResponse) -> Result<()> {
    if token.payment_method != "onchain" {
        return Ok(());
    }

    let deposit_address = token
        .deposit_address
        .as_ref()
        .context("onchain token response missing deposit_address")?;
    let amount = u32::try_from(token.fee).context("token fee does not fit in u32")?;

    bitcoin_core::sendtoaddress(amount, deposit_address)?;

    let mining_address = bitcoin_core::getnewaddress()?;
    bitcoin_core::generatetoaddress(token.confirmation_target as u32, &mining_address)?;

    Ok(())
}

pub async fn insert_statechain_transfer_row(
    statechain_id: &str,
    new_user_auth_public_key: &PublicKey,
    x1_secret_key: [u8; 32],
) -> Result<()> {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(MERCURY_DATABASE_URL)
        .await
        .context("failed to connect to mercury postgres")?;

    sqlx::query(
        "INSERT INTO statechain_transfer \
        (statechain_id, new_user_auth_public_key, x1, key_updated, locked, locked2) \
        VALUES ($1, $2, $3, false, false, false) \
        ON CONFLICT (statechain_id) DO UPDATE SET \
            new_user_auth_public_key = EXCLUDED.new_user_auth_public_key, \
            x1 = EXCLUDED.x1, \
            key_updated = false, \
            locked = false, \
            locked2 = false, \
            updated_at = NOW()",
    )
    .bind(statechain_id)
    .bind(new_user_auth_public_key.serialize().to_vec())
    .bind(x1_secret_key.to_vec())
    .execute(&pool)
    .await
    .with_context(|| format!("failed to insert transfer row for {}", statechain_id))?;

    Ok(())
}

pub fn sign_t2_hex(auth_secret_key: &SecretKey, t2_hex: &str) -> Result<String> {
    let secp = Secp256k1::new();
    let keypair = KeyPair::from_seckey_slice(&secp, auth_secret_key.as_ref())?;
    let msg = Message::from_hashed_data::<sha256::Hash>(t2_hex.as_bytes());
    let signature = secp.sign_schnorr(msg.as_ref(), &keypair);

    Ok(signature.to_string())
}

async fn ensure_success<T: DeserializeOwned>(response: Response, context: &str) -> Result<T> {
    let status = response.status();
    let body = response
        .text()
        .await
        .with_context(|| format!("failed to read {} response body", context))?;

    if !status.is_success() {
        let parsed_json: Result<Value, _> = serde_json::from_str(&body);
        let message = parsed_json
            .ok()
            .and_then(|value| {
                value
                    .get("message")
                    .and_then(|message| message.as_str().map(ToOwned::to_owned))
            })
            .unwrap_or(body);

        return Err(anyhow!(
            "{} failed with status {} and body {}",
            context,
            status,
            message
        ));
    }

    serde_json::from_str(&body)
        .with_context(|| format!("failed to decode {} response body {}", context, body))
}
