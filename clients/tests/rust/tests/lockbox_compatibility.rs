mod common;

use std::{str::FromStr, sync::Arc, time::Duration};

use anyhow::{ensure, Context, Result};
use bitcoin::{hashes::Hash, sighash::TemplateHash, PrivateKey};
use mercurylib::{
    bip448_statechain::{
        signing::{CsfsSigningRole, CsfsSigningSession},
        signing_api::{
            Bip448LockboxPartialSignatureRequestPayload, Bip448LockboxSignFirstRequestPayload,
            Bip448PartialSignatureRequestPayload, Bip448SignFirstRequestPayload,
        },
    },
    transfer::receiver::{
        bip448_transfer_receiver_auth_digest, bip448_transfer_unlock_auth_digest,
        Bip448TransferUnlockRole, TransferReceiverRequestPayload, TransferUnlockRequestPayload,
    },
    transfer::sender::{
        bip448_transfer_update_msg_auth_digest, TransferSenderResponsePayload,
        TransferUpdateMsgRequestPayload,
    },
    withdraw::WithdrawCompletePayload,
};
use reqwest::StatusCode;
use secp256k1::{
    musig::{new_musig_nonce_pair, BlindingFactor, MusigSessionId, PublicNonce},
    rand, schnorr, KeyPair, PublicKey, Secp256k1, SecretKey,
};
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Transaction};
use tokio::{
    sync::Barrier,
    task::{JoinHandle, JoinSet},
    time::{sleep, timeout},
};

use crate::common::{lockbox, mercury};

const DETERMINISTIC_RNG_SEED: &str =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const DETERMINISTIC_STATECHAIN_ID: &str = "deterministic-vector";
const DETERMINISTIC_SIGNING_ID: &str =
    "d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1";
const MERCURY_DATABASE_URL: &str = "postgres://postgres:postgres@127.0.0.1:5432/mercury";
const LOCKBOX_DATABASE_URL: &str = "postgres://postgres:postgres@127.0.0.1:5433/enclave";

fn generation_bound_receiver_request(
    statechain_id: &str,
    recipient_secret: &SecretKey,
    x1: [u8; 32],
    t2: [u8; 32],
) -> Result<TransferReceiverRequestPayload> {
    let secp = Secp256k1::new();
    let generation = SecretKey::from_secret_bytes(x1)?.public_key(&secp);
    let digest = bip448_transfer_receiver_auth_digest(statechain_id, &t2, &generation)?;
    let keypair = KeyPair::from_secret_key(&secp, recipient_secret);
    Ok(TransferReceiverRequestPayload {
        statechain_id: statechain_id.to_owned(),
        batch_data: Some(generation.to_string()),
        t2: hex::encode(t2),
        auth_sig: schnorr::sign(&digest, &keypair).to_string(),
    })
}

async fn unlock_recipient_transfer_generation(
    client: &reqwest::Client,
    statechain_id: &str,
    recipient_secret: &SecretKey,
    x1: [u8; 32],
) -> Result<()> {
    let secp = Secp256k1::new();
    let generation = SecretKey::from_secret_bytes(x1)?.public_key(&secp);
    let digest = bip448_transfer_unlock_auth_digest(
        Bip448TransferUnlockRole::Recipient,
        statechain_id,
        &generation,
    )?;
    let keypair = KeyPair::from_secret_key(&secp, recipient_secret);
    let response = client
        .post(format!("{}/transfer/unlock", mercury::MERCURY_URL))
        .json(&TransferUnlockRequestPayload {
            statechain_id: statechain_id.to_owned(),
            auth_sig: schnorr::sign(&digest, &keypair).to_string(),
            auth_pub_key: Some(generation.to_string()),
        })
        .send()
        .await?;
    let status = response.status();
    let body = response.text().await?;
    ensure!(
        status == StatusCode::OK && body == r#"{"message":"Success"}"#,
        "generation-bound recipient unlock returned {status}: {body}"
    );
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TransferGenerationSnapshot {
    recipient_auth_key: Option<Vec<u8>>,
    x1: Option<Vec<u8>>,
    encrypted_transfer_msg: Option<Vec<u8>>,
    key_updated: Option<bool>,
    batch_id: Option<String>,
    batch_time: Option<String>,
    locked: bool,
    locked2: bool,
    updated_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StatechainGenerationSnapshot {
    auth_key: Option<Vec<u8>>,
    server_key: Option<Vec<u8>>,
    enclave_index: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LatchSnapshot {
    sender_auth_key: Option<Vec<u8>>,
    locked: bool,
    updated_at: String,
}

async fn post_mercury_json(
    client: &reqwest::Client,
    path: &str,
    payload: &Value,
) -> Result<(StatusCode, String)> {
    let response = client
        .post(format!("{}/{path}", mercury::MERCURY_URL))
        .json(payload)
        .send()
        .await
        .with_context(|| format!("failed to post Mercury {path}"))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .with_context(|| format!("failed to read Mercury {path} response"))?;
    Ok((status, body))
}

fn assert_json_response(
    response: &(StatusCode, String),
    expected_status: StatusCode,
    expected_body: Value,
) -> Result<()> {
    ensure!(
        response.0 == expected_status,
        "unexpected status: expected {expected_status}, got {} with {}",
        response.0,
        response.1
    );
    let actual: Value = serde_json::from_str(&response.1)
        .with_context(|| format!("response body was not JSON: {}", response.1))?;
    ensure!(
        actual == expected_body,
        "unexpected response body: expected {expected_body}, got {actual}"
    );
    Ok(())
}

fn coin_auth_secret(coin: &mercurylib::wallet::Coin) -> Result<SecretKey> {
    Ok(PrivateKey::from_wif(&coin.auth_privkey)?.inner)
}

fn sign_statechain_id(auth_secret: &SecretKey, statechain_id: &str) -> String {
    let digest = bitcoin::hashes::sha256::Hash::hash(statechain_id.as_bytes()).to_byte_array();
    let keypair = KeyPair::from_secret_key(&Secp256k1::new(), auth_secret);
    schnorr::sign(&digest, &keypair).to_string()
}

fn sign_digest(auth_secret: &SecretKey, digest: &[u8; 32]) -> String {
    let keypair = KeyPair::from_secret_key(&Secp256k1::new(), auth_secret);
    schnorr::sign(digest, &keypair).to_string()
}

fn sender_request_value(
    statechain_id: &str,
    auth_sig: &str,
    recipient: &PublicKey,
    batch_id: Option<&str>,
) -> Value {
    json!({
        "statechain_id": statechain_id,
        "auth_sig": auth_sig,
        "new_user_auth_key": recipient.to_string(),
        "batch_id": batch_id,
    })
}

fn sender_x1(response: &(StatusCode, String)) -> Result<[u8; 32]> {
    ensure!(
        response.0 == StatusCode::OK,
        "transfer sender returned {}: {}",
        response.0,
        response.1
    );
    let payload: TransferSenderResponsePayload = serde_json::from_str(&response.1)?;
    let bytes: [u8; 32] = hex::decode(payload.x1)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("sender x1 was not 32 bytes"))?;
    SecretKey::from_secret_bytes(bytes)?;
    Ok(bytes)
}

fn update_message_request_value(
    statechain_id: &str,
    owner_auth_secret: &SecretKey,
    recipient: &PublicKey,
    generation: &PublicKey,
    ciphertext: &[u8],
) -> Result<Value> {
    let digest =
        bip448_transfer_update_msg_auth_digest(statechain_id, recipient, generation, ciphertext)?;
    Ok(serde_json::to_value(TransferUpdateMsgRequestPayload {
        statechain_id: statechain_id.to_owned(),
        auth_sig: sign_digest(owner_auth_secret, &digest),
        new_user_auth_key: recipient.to_string(),
        x1_pub: generation.to_string(),
        enc_transfer_msg: hex::encode(ciphertext),
    })?)
}

fn unlock_request_value(
    role: Bip448TransferUnlockRole,
    statechain_id: &str,
    signer: &SecretKey,
    generation: &PublicKey,
) -> Result<Value> {
    let digest = bip448_transfer_unlock_auth_digest(role, statechain_id, generation)?;
    Ok(serde_json::to_value(TransferUnlockRequestPayload {
        statechain_id: statechain_id.to_owned(),
        auth_sig: sign_digest(signer, &digest),
        auth_pub_key: Some(generation.to_string()),
    })?)
}

async fn load_transfer_generation(
    pool: &PgPool,
    statechain_id: &str,
) -> Result<TransferGenerationSnapshot> {
    let row: (
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<bool>,
        Option<String>,
        Option<String>,
        bool,
        bool,
        String,
    ) = sqlx::query_as(
        "SELECT new_user_auth_public_key,x1,encrypted_transfer_msg,key_updated,batch_id,\
         batch_time::text,locked,locked2,updated_at::text FROM statechain_transfer \
         WHERE statechain_id=$1",
    )
    .bind(statechain_id)
    .fetch_one(pool)
    .await?;
    Ok(TransferGenerationSnapshot {
        recipient_auth_key: row.0,
        x1: row.1,
        encrypted_transfer_msg: row.2,
        key_updated: row.3,
        batch_id: row.4,
        batch_time: row.5,
        locked: row.6,
        locked2: row.7,
        updated_at: row.8,
    })
}

async fn load_statechain_generation(
    pool: &PgPool,
    statechain_id: &str,
) -> Result<StatechainGenerationSnapshot> {
    let row: (Option<Vec<u8>>, Option<Vec<u8>>, i32) = sqlx::query_as(
        "SELECT auth_xonly_public_key,server_public_key,enclave_index FROM statechain_data \
         WHERE statechain_id=$1",
    )
    .bind(statechain_id)
    .fetch_one(pool)
    .await?;
    Ok(StatechainGenerationSnapshot {
        auth_key: row.0,
        server_key: row.1,
        enclave_index: row.2,
    })
}

async fn load_latch(
    pool: &PgPool,
    statechain_id: &str,
    batch_id: &str,
) -> Result<Option<LatchSnapshot>> {
    let row: Option<(Option<Vec<u8>>, bool, String)> = sqlx::query_as(
        "SELECT sender_auth_xonly_public_key,locked,updated_at::text FROM lightning_latch \
         WHERE statechain_id=$1 AND batch_id=$2",
    )
    .bind(statechain_id)
    .bind(batch_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| LatchSnapshot {
        sender_auth_key: row.0,
        locked: row.1,
        updated_at: row.2,
    }))
}

async fn load_lockbox_generation(
    pool: &PgPool,
    statechain_id: &str,
) -> Result<(Option<Vec<u8>>, Option<i32>)> {
    Ok(sqlx::query_as(
        "SELECT public_key,sig_count FROM generated_public_key WHERE statechain_id=$1",
    )
    .bind(statechain_id)
    .fetch_one(pool)
    .await?)
}

async fn lock_transfer_row<'a>(
    pool: &'a PgPool,
    statechain_id: &str,
) -> Result<Transaction<'a, Postgres>> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT statechain_id FROM statechain_transfer WHERE statechain_id=$1 FOR UPDATE")
        .bind(statechain_id)
        .fetch_one(&mut *transaction)
        .await?;
    Ok(transaction)
}

async fn wait_for_blocked_mercury_query(pool: &PgPool, needle: &str) -> Result<()> {
    for _ in 0..200 {
        let blocked: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pg_stat_activity WHERE datname=current_database() \
             AND pid <> pg_backend_pid() AND wait_event_type='Lock' AND query LIKE $1",
        )
        .bind(format!("%{needle}%"))
        .fetch_one(pool)
        .await?;
        if blocked > 0 {
            return Ok(());
        }
        sleep(Duration::from_millis(10)).await;
    }
    Err(anyhow::anyhow!(
        "Mercury endpoint did not reach the expected PostgreSQL lock barrier: {needle}"
    ))
}

async fn join_http_task(
    task: JoinHandle<Result<(StatusCode, String)>>,
) -> Result<(StatusCode, String)> {
    task.await.context("Mercury HTTP barrier task panicked")?
}

async fn assert_sender_and_update_generation_fences(
    mercury_client: &reqwest::Client,
    mercury_pool: &PgPool,
) -> Result<()> {
    let secp = Secp256k1::new();
    let (_wallet, coin) = mercury::create_deposited_coin(mercury_client).await?;
    let statechain_id = coin
        .statechain_id
        .as_deref()
        .context("sender replay Coin has no statechain ID")?
        .to_owned();
    let signed_statechain_id = coin
        .signed_statechain_id
        .as_deref()
        .context("sender replay Coin has no owner signature")?
        .to_owned();
    let owner_secret = coin_auth_secret(&coin)?;
    let recipient_secret = SecretKey::from_secret_bytes([0x31; 32])?;
    let recipient = recipient_secret.public_key(&secp);
    let batch_id = format!("generation-replay-{}", uuid::Uuid::new_v4());
    let request = sender_request_value(
        &statechain_id,
        &signed_statechain_id,
        &recipient,
        Some(&batch_id),
    );
    let barrier = Arc::new(Barrier::new(3));
    let mut tasks = Vec::new();
    for _ in 0..2 {
        let client = mercury_client.clone();
        let payload = request.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            post_mercury_json(&client, "transfer/sender", &payload).await
        }));
    }
    barrier.wait().await;
    let first = join_http_task(tasks.remove(0)).await?;
    let second = join_http_task(tasks.remove(0)).await?;
    let first_x1 = sender_x1(&first)?;
    let second_x1 = sender_x1(&second)?;
    ensure!(
        first_x1 == second_x1,
        "concurrent exact sender replay changed x1"
    );
    let replay_row = load_transfer_generation(mercury_pool, &statechain_id).await?;
    ensure!(
        replay_row.recipient_auth_key == Some(recipient.serialize().to_vec())
            && replay_row.x1.as_deref() == Some(first_x1.as_slice())
            && replay_row.batch_id.as_deref() == Some(batch_id.as_str())
            && replay_row.key_updated == Some(false),
        "concurrent sender replay stored the wrong generation: {replay_row:?}"
    );
    let replay_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM statechain_transfer WHERE statechain_id=$1")
            .bind(&statechain_id)
            .fetch_one(mercury_pool)
            .await?;
    ensure!(
        replay_count == 1,
        "concurrent sender replay stored {replay_count} rows"
    );

    let mut malformed_sender = request.clone();
    malformed_sender["new_user_auth_key"] = json!("not-a-public-key");
    let malformed_response =
        post_mercury_json(mercury_client, "transfer/sender", &malformed_sender).await?;
    assert_json_response(
        &malformed_response,
        StatusCode::BAD_REQUEST,
        json!({"message":"Invalid new_user_auth_key."}),
    )?;
    ensure!(
        load_transfer_generation(mercury_pool, &statechain_id).await? == replay_row,
        "malformed sender request mutated the replay row"
    );
    let mut unauthenticated_sender = request.clone();
    unauthenticated_sender["auth_sig"] = json!("not-a-signature");
    let unauthenticated_response =
        post_mercury_json(mercury_client, "transfer/sender", &unauthenticated_sender).await?;
    assert_json_response(
        &unauthenticated_response,
        StatusCode::INTERNAL_SERVER_ERROR,
        json!({"message":"Signature does not match authentication key."}),
    )?;
    ensure!(
        load_transfer_generation(mercury_pool, &statechain_id).await? == replay_row,
        "unauthenticated sender request mutated the replay row"
    );

    let (_wallet, competing_coin) = mercury::create_deposited_coin(mercury_client).await?;
    let competing_statechain_id = competing_coin
        .statechain_id
        .as_deref()
        .context("competing sender Coin has no statechain ID")?
        .to_owned();
    let competing_signature = competing_coin
        .signed_statechain_id
        .as_deref()
        .context("competing sender Coin has no owner signature")?
        .to_owned();
    let competing_batch = format!("recipient-race-{}", uuid::Uuid::new_v4());
    let competing_recipients = [
        SecretKey::from_secret_bytes([0x32; 32])?.public_key(&secp),
        SecretKey::from_secret_bytes([0x33; 32])?.public_key(&secp),
    ];
    let barrier = Arc::new(Barrier::new(3));
    let mut competing_tasks = Vec::new();
    for recipient in competing_recipients {
        let client = mercury_client.clone();
        let barrier = barrier.clone();
        let payload = sender_request_value(
            &competing_statechain_id,
            &competing_signature,
            &recipient,
            Some(&competing_batch),
        );
        competing_tasks.push((
            recipient,
            tokio::spawn(async move {
                barrier.wait().await;
                post_mercury_json(&client, "transfer/sender", &payload).await
            }),
        ));
    }
    barrier.wait().await;
    let first_competing = (
        competing_tasks[0].0,
        join_http_task(competing_tasks.remove(0).1).await?,
    );
    let second_competing = (
        competing_tasks[0].0,
        join_http_task(competing_tasks.remove(0).1).await?,
    );
    let results = [first_competing, second_competing];
    ensure!(
        results
            .iter()
            .filter(|(_, response)| response.0 == StatusCode::OK)
            .count()
            == 1,
        "different-recipient batch race did not have one winner: {results:?}"
    );
    let loser = results
        .iter()
        .find(|(_, response)| response.0 != StatusCode::OK)
        .context("different-recipient batch race had no loser")?;
    assert_json_response(
        &loser.1,
        StatusCode::BAD_REQUEST,
        json!({"message":"Statecoin batch locked (the batch time has not expired)."}),
    )?;
    let winner = results
        .iter()
        .find(|(_, response)| response.0 == StatusCode::OK)
        .context("different-recipient batch race had no winner")?;
    sender_x1(&winner.1)?;
    let competing_row = load_transfer_generation(mercury_pool, &competing_statechain_id).await?;
    ensure!(
        competing_row.recipient_auth_key == Some(winner.0.serialize().to_vec())
            && competing_row.batch_id.as_deref() == Some(competing_batch.as_str()),
        "different-recipient batch loser replaced the winner"
    );

    let generation = SecretKey::from_secret_bytes(first_x1)?.public_key(&secp);
    let first_ciphertext = [0x00, 0x01, 0xfe, 0xff];
    let first_update = update_message_request_value(
        &statechain_id,
        &owner_secret,
        &recipient,
        &generation,
        &first_ciphertext,
    )?;
    let first_update_response =
        post_mercury_json(mercury_client, "transfer/update_msg", &first_update).await?;
    assert_json_response(
        &first_update_response,
        StatusCode::OK,
        json!({"updated":true}),
    )?;
    let first_update_replay =
        post_mercury_json(mercury_client, "transfer/update_msg", &first_update).await?;
    assert_json_response(
        &first_update_replay,
        StatusCode::OK,
        json!({"updated":true}),
    )?;
    let randomized_ciphertext = [0x05, 0x04, 0x03, 0x02, 0x01];
    let randomized_update = update_message_request_value(
        &statechain_id,
        &owner_secret,
        &recipient,
        &generation,
        &randomized_ciphertext,
    )?;
    let randomized_response =
        post_mercury_json(mercury_client, "transfer/update_msg", &randomized_update).await?;
    assert_json_response(
        &randomized_response,
        StatusCode::OK,
        json!({"updated":true}),
    )?;
    let updated_row = load_transfer_generation(mercury_pool, &statechain_id).await?;
    ensure!(
        updated_row.x1.as_deref() == Some(first_x1.as_slice())
            && updated_row.encrypted_transfer_msg.as_deref()
                == Some(randomized_ciphertext.as_slice()),
        "legal update replay changed generation or stored the wrong ciphertext"
    );

    let generation_error = json!({
        "error":"Internal Server Error",
        "message":"Transfer message generation does not match current state."
    });
    let authentication_error = json!({
        "error":"Internal Server Error",
        "message":"Signature does not match authentication key."
    });
    let mut missing_x1 = randomized_update.clone();
    missing_x1
        .as_object_mut()
        .context("update request is not an object")?
        .remove("x1_pub");
    let missing_x1_response =
        post_mercury_json(mercury_client, "transfer/update_msg", &missing_x1).await?;
    ensure!(
        missing_x1_response.0 == StatusCode::UNPROCESSABLE_ENTITY,
        "missing update x1_pub did not use Rocket's deserialization status: {missing_x1_response:?}"
    );
    ensure!(
        load_transfer_generation(mercury_pool, &statechain_id).await? == updated_row,
        "missing update x1_pub mutated its row"
    );

    let mut noncanonical_x1 = randomized_update.clone();
    noncanonical_x1["x1_pub"] = json!(generation.to_string().to_uppercase());
    let noncanonical_x1_response =
        post_mercury_json(mercury_client, "transfer/update_msg", &noncanonical_x1).await?;
    assert_json_response(
        &noncanonical_x1_response,
        StatusCode::INTERNAL_SERVER_ERROR,
        generation_error.clone(),
    )?;
    let wrong_generation = SecretKey::from_secret_bytes([0x34; 32])?.public_key(&secp);
    let wrong_generation_request = update_message_request_value(
        &statechain_id,
        &owner_secret,
        &recipient,
        &wrong_generation,
        &randomized_ciphertext,
    )?;
    let wrong_generation_response = post_mercury_json(
        mercury_client,
        "transfer/update_msg",
        &wrong_generation_request,
    )
    .await?;
    assert_json_response(
        &wrong_generation_response,
        StatusCode::INTERNAL_SERVER_ERROR,
        generation_error.clone(),
    )?;
    let substituted_recipient = SecretKey::from_secret_bytes([0x35; 32])?.public_key(&secp);
    let recipient_substitution = update_message_request_value(
        &statechain_id,
        &owner_secret,
        &substituted_recipient,
        &generation,
        &randomized_ciphertext,
    )?;
    let recipient_substitution_response = post_mercury_json(
        mercury_client,
        "transfer/update_msg",
        &recipient_substitution,
    )
    .await?;
    assert_json_response(
        &recipient_substitution_response,
        StatusCode::INTERNAL_SERVER_ERROR,
        generation_error.clone(),
    )?;
    let wrong_statechain = format!("wrong-{}", uuid::Uuid::new_v4());
    let statechain_substitution = update_message_request_value(
        &wrong_statechain,
        &owner_secret,
        &recipient,
        &generation,
        &randomized_ciphertext,
    )?;
    let statechain_substitution_response = post_mercury_json(
        mercury_client,
        "transfer/update_msg",
        &statechain_substitution,
    )
    .await?;
    assert_json_response(
        &statechain_substitution_response,
        StatusCode::INTERNAL_SERVER_ERROR,
        generation_error.clone(),
    )?;
    let mut ciphertext_substitution = randomized_update.clone();
    ciphertext_substitution["enc_transfer_msg"] = json!(hex::encode([0xaa, 0xbb]));
    let ciphertext_substitution_response = post_mercury_json(
        mercury_client,
        "transfer/update_msg",
        &ciphertext_substitution,
    )
    .await?;
    assert_json_response(
        &ciphertext_substitution_response,
        StatusCode::INTERNAL_SERVER_ERROR,
        authentication_error,
    )?;
    ensure!(
        load_transfer_generation(mercury_pool, &statechain_id).await? == updated_row,
        "update-message substitution changed the authenticated generation"
    );

    let (_wallet, stale_coin) = mercury::create_deposited_coin(mercury_client).await?;
    let stale_statechain_id = stale_coin
        .statechain_id
        .as_deref()
        .context("stale upload ID")?;
    let stale_owner = coin_auth_secret(&stale_coin)?;
    let stale_signature = stale_coin
        .signed_statechain_id
        .as_deref()
        .context("stale upload owner signature")?;
    let stale_recipient = SecretKey::from_secret_bytes([0x36; 32])?.public_key(&secp);
    let stale_sender =
        sender_request_value(stale_statechain_id, stale_signature, &stale_recipient, None);
    let stale_sender_response =
        post_mercury_json(mercury_client, "transfer/sender", &stale_sender).await?;
    let stale_x1 = sender_x1(&stale_sender_response)?;
    let stale_generation = SecretKey::from_secret_bytes(stale_x1)?.public_key(&secp);
    let stale_upload = update_message_request_value(
        stale_statechain_id,
        &stale_owner,
        &stale_recipient,
        &stale_generation,
        &[0x91, 0x92],
    )?;
    let successor_batch = format!("same-recipient-successor-{}", uuid::Uuid::new_v4());
    let successor_sender = sender_request_value(
        stale_statechain_id,
        stale_signature,
        &stale_recipient,
        Some(&successor_batch),
    );
    let successor_response =
        post_mercury_json(mercury_client, "transfer/sender", &successor_sender).await?;
    let successor_x1 = sender_x1(&successor_response)?;
    ensure!(
        successor_x1 != stale_x1,
        "same-recipient successor replayed stale x1"
    );
    let successor_row = load_transfer_generation(mercury_pool, stale_statechain_id).await?;
    let stale_upload_response =
        post_mercury_json(mercury_client, "transfer/update_msg", &stale_upload).await?;
    assert_json_response(
        &stale_upload_response,
        StatusCode::INTERNAL_SERVER_ERROR,
        generation_error.clone(),
    )?;
    ensure!(
        load_transfer_generation(mercury_pool, stale_statechain_id).await? == successor_row,
        "stale same-recipient upload changed successor B"
    );

    let (_wallet, ordered_coin) = mercury::create_deposited_coin(mercury_client).await?;
    let ordered_statechain_id = ordered_coin
        .statechain_id
        .as_deref()
        .context("ordered upload statechain ID")?
        .to_owned();
    let ordered_signature = ordered_coin
        .signed_statechain_id
        .as_deref()
        .context("ordered upload owner signature")?
        .to_owned();
    let ordered_owner = coin_auth_secret(&ordered_coin)?;
    let ordered_recipient_a = SecretKey::from_secret_bytes([0x37; 32])?.public_key(&secp);
    let ordered_recipient_b = SecretKey::from_secret_bytes([0x38; 32])?.public_key(&secp);
    let ordered_sender_a = sender_request_value(
        &ordered_statechain_id,
        &ordered_signature,
        &ordered_recipient_a,
        None,
    );
    let ordered_a_response =
        post_mercury_json(mercury_client, "transfer/sender", &ordered_sender_a).await?;
    let ordered_x1 = sender_x1(&ordered_a_response)?;
    let ordered_generation = SecretKey::from_secret_bytes(ordered_x1)?.public_key(&secp);
    let ordered_update = update_message_request_value(
        &ordered_statechain_id,
        &ordered_owner,
        &ordered_recipient_a,
        &ordered_generation,
        &[0x61, 0x62],
    )?;
    let row_lock = lock_transfer_row(mercury_pool, &ordered_statechain_id).await?;
    let update_client = mercury_client.clone();
    let update_payload = ordered_update.clone();
    let mut update_task = tokio::spawn(async move {
        post_mercury_json(&update_client, "transfer/update_msg", &update_payload).await
    });
    wait_for_blocked_mercury_query(
        mercury_pool,
        "SELECT new_user_auth_public_key, x1, key_updated",
    )
    .await?;
    ensure!(
        timeout(Duration::from_millis(100), &mut update_task)
            .await
            .is_err(),
        "A-first upload did not remain blocked at its transfer-row fence"
    );
    let sender_client = mercury_client.clone();
    let sender_b_payload = sender_request_value(
        &ordered_statechain_id,
        &ordered_signature,
        &ordered_recipient_b,
        None,
    );
    let mut sender_task = tokio::spawn(async move {
        post_mercury_json(&sender_client, "transfer/sender", &sender_b_payload).await
    });
    ensure!(
        timeout(Duration::from_millis(100), &mut sender_task)
            .await
            .is_err(),
        "successor sender bypassed A's statechain-data lock"
    );
    row_lock.commit().await?;
    let ordered_update_response = update_task.await??;
    assert_json_response(
        &ordered_update_response,
        StatusCode::OK,
        json!({"updated":true}),
    )?;
    let ordered_sender_response = sender_task.await??;
    sender_x1(&ordered_sender_response)?;
    let ordered_b_row = load_transfer_generation(mercury_pool, &ordered_statechain_id).await?;
    ensure!(
        ordered_b_row.recipient_auth_key == Some(ordered_recipient_b.serialize().to_vec())
            && ordered_b_row.encrypted_transfer_msg.is_none(),
        "A-first upload straddled successor replacement"
    );

    Ok(())
}

async fn assert_unlock_a_first_barrier(
    mercury_client: &reqwest::Client,
    mercury_pool: &PgPool,
    role: Bip448TransferUnlockRole,
    recipient_byte: u8,
    successor_byte: u8,
) -> Result<()> {
    let secp = Secp256k1::new();
    let (_wallet, coin) = mercury::create_deposited_coin(mercury_client).await?;
    let statechain_id = coin
        .statechain_id
        .as_deref()
        .context("A-first unlock Coin has no statechain ID")?
        .to_owned();
    let signed_statechain_id = coin
        .signed_statechain_id
        .as_deref()
        .context("A-first unlock Coin has no owner signature")?
        .to_owned();
    let current_owner = coin_auth_secret(&coin)?;
    let recipient_secret = SecretKey::from_secret_bytes([recipient_byte; 32])?;
    let recipient = recipient_secret.public_key(&secp);
    let successor = SecretKey::from_secret_bytes([successor_byte; 32])?.public_key(&secp);
    let sender_a = sender_request_value(&statechain_id, &signed_statechain_id, &recipient, None);
    let sender_a_response = post_mercury_json(mercury_client, "transfer/sender", &sender_a).await?;
    let x1 = sender_x1(&sender_a_response)?;
    let generation = SecretKey::from_secret_bytes(x1)?.public_key(&secp);
    sqlx::query("UPDATE statechain_transfer SET locked=true,locked2=true WHERE statechain_id=$1")
        .bind(&statechain_id)
        .execute(mercury_pool)
        .await?;
    let signer = match role {
        Bip448TransferUnlockRole::CurrentOwner => &current_owner,
        Bip448TransferUnlockRole::Recipient => &recipient_secret,
    };
    let unlock_payload = unlock_request_value(role, &statechain_id, signer, &generation)?;
    let row_lock = lock_transfer_row(mercury_pool, &statechain_id).await?;
    let unlock_client = mercury_client.clone();
    let mut unlock_task = tokio::spawn(async move {
        post_mercury_json(&unlock_client, "transfer/unlock", &unlock_payload).await
    });
    wait_for_blocked_mercury_query(
        mercury_pool,
        "SELECT new_user_auth_public_key, x1, batch_id, batch_time",
    )
    .await?;
    ensure!(
        timeout(Duration::from_millis(100), &mut unlock_task)
            .await
            .is_err(),
        "A-first {role:?} unlock did not remain blocked on row A"
    );
    let sender_client = mercury_client.clone();
    let sender_b = sender_request_value(&statechain_id, &signed_statechain_id, &successor, None);
    let mut sender_task = tokio::spawn(async move {
        post_mercury_json(&sender_client, "transfer/sender", &sender_b).await
    });
    ensure!(
        timeout(Duration::from_millis(100), &mut sender_task)
            .await
            .is_err(),
        "successor bypassed A-first {role:?} statechain-data lock"
    );
    row_lock.commit().await?;
    let unlock_response = unlock_task.await??;
    assert_json_response(
        &unlock_response,
        StatusCode::OK,
        json!({"message":"Success"}),
    )?;
    let sender_response = sender_task.await??;
    sender_x1(&sender_response)?;
    let successor_row = load_transfer_generation(mercury_pool, &statechain_id).await?;
    ensure!(
        successor_row.recipient_auth_key == Some(successor.serialize().to_vec())
            && !successor_row.locked
            && !successor_row.locked2
            && successor_row.encrypted_transfer_msg.is_none()
            && successor_row.key_updated == Some(false),
        "A-first {role:?} unlock changed successor B's intended flags or fields: {successor_row:?}"
    );
    Ok(())
}

async fn assert_unlock_generation_fences(
    mercury_client: &reqwest::Client,
    mercury_pool: &PgPool,
    lockbox_pool: &PgPool,
) -> Result<()> {
    let secp = Secp256k1::new();
    let (_wallet, coin) = mercury::create_deposited_coin(mercury_client).await?;
    let statechain_id = coin
        .statechain_id
        .as_deref()
        .context("unlock matrix Coin has no statechain ID")?
        .to_owned();
    let signed_statechain_id = coin
        .signed_statechain_id
        .as_deref()
        .context("unlock matrix Coin has no owner signature")?
        .to_owned();
    let current_owner = coin_auth_secret(&coin)?;
    let current_owner_key = current_owner.public_key(&secp);
    let recipient_secret = SecretKey::from_secret_bytes([0x41; 32])?;
    let recipient = recipient_secret.public_key(&secp);
    let batch_id = format!("unlock-latch-{}", uuid::Uuid::new_v4());
    sqlx::query(
        "INSERT INTO lightning_latch \
         (statechain_id,sender_auth_xonly_public_key,batch_id,pre_image,expires_at) \
         VALUES ($1,$2,$3,$4,NOW()+INTERVAL '1 day')",
    )
    .bind(&statechain_id)
    .bind(current_owner_key.x_only_public_key().0.serialize().to_vec())
    .bind(&batch_id)
    .bind("generation-fence-preimage")
    .execute(mercury_pool)
    .await?;
    let unrelated_latch_statechain = format!("unrelated-latch-{}", uuid::Uuid::new_v4());
    sqlx::query(
        "INSERT INTO lightning_latch \
         (statechain_id,sender_auth_xonly_public_key,batch_id,pre_image,expires_at) \
         VALUES ($1,$2,$3,$4,NOW()+INTERVAL '1 day')",
    )
    .bind(&unrelated_latch_statechain)
    .bind(current_owner_key.x_only_public_key().0.serialize().to_vec())
    .bind(&batch_id)
    .bind("unrelated-generation-fence-preimage")
    .execute(mercury_pool)
    .await?;
    let unrelated_latch_before = load_latch(mercury_pool, &unrelated_latch_statechain, &batch_id)
        .await?
        .context("unrelated unlock latch is missing")?;
    let sender = sender_request_value(
        &statechain_id,
        &signed_statechain_id,
        &recipient,
        Some(&batch_id),
    );
    let sender_response = post_mercury_json(mercury_client, "transfer/sender", &sender).await?;
    let x1 = sender_x1(&sender_response)?;
    let generation = SecretKey::from_secret_bytes(x1)?.public_key(&secp);
    let initial_row = load_transfer_generation(mercury_pool, &statechain_id).await?;
    let initial_latch = load_latch(mercury_pool, &statechain_id, &batch_id)
        .await?
        .context("unlock matrix latch is missing")?;
    ensure!(
        initial_row.locked && initial_row.locked2 && initial_latch.locked,
        "sender did not initialize both transfer locks and its latch"
    );
    let generation_error = json!({"message":"Transfer generation does not match current row."});
    let authentication_error = json!({"message":"Signature does not match authentication key."});

    let valid_recipient = unlock_request_value(
        Bip448TransferUnlockRole::Recipient,
        &statechain_id,
        &recipient_secret,
        &generation,
    )?;
    let mut missing_generation = valid_recipient.clone();
    missing_generation
        .as_object_mut()
        .context("unlock payload is not an object")?
        .remove("auth_pub_key");
    let mut malformed_generation = valid_recipient.clone();
    malformed_generation["auth_pub_key"] = json!("not-a-public-key");
    let mut noncanonical_generation = valid_recipient.clone();
    noncanonical_generation["auth_pub_key"] = json!(generation.to_string().to_uppercase());
    let mut wrong_generation = valid_recipient.clone();
    wrong_generation["auth_pub_key"] = json!(SecretKey::from_secret_bytes([0x42; 32])?
        .public_key(&secp)
        .to_string());
    for payload in [
        missing_generation,
        malformed_generation,
        noncanonical_generation,
        wrong_generation,
    ] {
        let response = post_mercury_json(mercury_client, "transfer/unlock", &payload).await?;
        assert_json_response(
            &response,
            StatusCode::INTERNAL_SERVER_ERROR,
            generation_error.clone(),
        )?;
        ensure!(
            load_transfer_generation(mercury_pool, &statechain_id).await? == initial_row
                && load_latch(mercury_pool, &statechain_id, &batch_id).await?
                    == Some(initial_latch.clone()),
            "invalid unlock generation changed row or latch"
        );
    }

    let wrong_role = unlock_request_value(
        Bip448TransferUnlockRole::CurrentOwner,
        &statechain_id,
        &recipient_secret,
        &generation,
    )?;
    let wrong_signer = unlock_request_value(
        Bip448TransferUnlockRole::Recipient,
        &statechain_id,
        &SecretKey::from_secret_bytes([0x43; 32])?,
        &generation,
    )?;
    for payload in [wrong_role, wrong_signer] {
        let response = post_mercury_json(mercury_client, "transfer/unlock", &payload).await?;
        assert_json_response(
            &response,
            StatusCode::FORBIDDEN,
            authentication_error.clone(),
        )?;
        ensure!(
            load_transfer_generation(mercury_pool, &statechain_id).await? == initial_row
                && load_latch(mercury_pool, &statechain_id, &batch_id).await?
                    == Some(initial_latch.clone()),
            "unauthorized unlock changed row or latch"
        );
    }

    let recipient_unlock =
        post_mercury_json(mercury_client, "transfer/unlock", &valid_recipient).await?;
    assert_json_response(
        &recipient_unlock,
        StatusCode::OK,
        json!({"message":"Success"}),
    )?;
    let after_recipient = load_transfer_generation(mercury_pool, &statechain_id).await?;
    ensure!(
        !after_recipient.locked && after_recipient.locked2,
        "recipient unlock changed the wrong flag"
    );
    ensure!(
        load_latch(mercury_pool, &statechain_id, &batch_id)
            .await?
            .context("latch disappeared after recipient unlock")?
            .locked,
        "recipient-only unlock cleared the latch early"
    );
    let recipient_replay =
        post_mercury_json(mercury_client, "transfer/unlock", &valid_recipient).await?;
    assert_json_response(
        &recipient_replay,
        StatusCode::OK,
        json!({"message":"Success"}),
    )?;
    ensure!(
        load_transfer_generation(mercury_pool, &statechain_id).await? == after_recipient,
        "recipient response-loss replay changed row timestamp or fields"
    );

    let valid_current = unlock_request_value(
        Bip448TransferUnlockRole::CurrentOwner,
        &statechain_id,
        &current_owner,
        &generation,
    )?;
    let current_unlock =
        post_mercury_json(mercury_client, "transfer/unlock", &valid_current).await?;
    assert_json_response(
        &current_unlock,
        StatusCode::OK,
        json!({"message":"Success"}),
    )?;
    let fully_unlocked = load_transfer_generation(mercury_pool, &statechain_id).await?;
    let unlocked_latch = load_latch(mercury_pool, &statechain_id, &batch_id)
        .await?
        .context("latch disappeared after full unlock")?;
    ensure!(
        !fully_unlocked.locked && !fully_unlocked.locked2 && !unlocked_latch.locked,
        "current-owner unlock did not atomically clear locked2 and exact latch"
    );
    ensure!(
        load_latch(mercury_pool, &unrelated_latch_statechain, &batch_id,).await?
            == Some(unrelated_latch_before.clone()),
        "full unlock changed an unrelated same-batch latch"
    );
    let current_replay =
        post_mercury_json(mercury_client, "transfer/unlock", &valid_current).await?;
    assert_json_response(
        &current_replay,
        StatusCode::OK,
        json!({"message":"Success"}),
    )?;
    ensure!(
        load_transfer_generation(mercury_pool, &statechain_id).await? == fully_unlocked
            && load_latch(mercury_pool, &statechain_id, &batch_id).await?
                == Some(unlocked_latch.clone()),
        "current-owner response-loss replay changed row or latch timestamp"
    );

    let receiver_request =
        generation_bound_receiver_request(&statechain_id, &recipient_secret, x1, [0x44; 32])?;
    let receiver_response = post_mercury_json(
        mercury_client,
        "transfer/receiver",
        &serde_json::to_value(&receiver_request)?,
    )
    .await?;
    ensure!(
        receiver_response.0 == StatusCode::OK,
        "receiver did not consume unlocked generation: {receiver_response:?}"
    );
    let consumed_row = load_transfer_generation(mercury_pool, &statechain_id).await?;
    let consumed_state = load_statechain_generation(mercury_pool, &statechain_id).await?;
    let consumed_lockbox = load_lockbox_generation(lockbox_pool, &statechain_id).await?;
    ensure!(
        consumed_row.key_updated == Some(true),
        "receiver did not consume generation"
    );
    let consumed_unlock =
        post_mercury_json(mercury_client, "transfer/unlock", &valid_recipient).await?;
    assert_json_response(
        &consumed_unlock,
        StatusCode::INTERNAL_SERVER_ERROR,
        generation_error.clone(),
    )?;
    ensure!(
        load_transfer_generation(mercury_pool, &statechain_id).await? == consumed_row
            && load_statechain_generation(mercury_pool, &statechain_id).await? == consumed_state
            && load_lockbox_generation(lockbox_pool, &statechain_id).await? == consumed_lockbox,
        "consumed-generation unlock changed Mercury or lockbox state"
    );

    let successor_signature = sign_statechain_id(&recipient_secret, &statechain_id);
    let next_sender = sender_request_value(
        &statechain_id,
        &successor_signature,
        &recipient,
        Some(&batch_id),
    );
    let next_sender_response =
        post_mercury_json(mercury_client, "transfer/sender", &next_sender).await?;
    let next_x1 = sender_x1(&next_sender_response)?;
    ensure!(next_x1 != x1, "new owner generation replayed consumed x1");
    let next_row = load_transfer_generation(mercury_pool, &statechain_id).await?;
    ensure!(
        next_row.key_updated == Some(false)
            && next_row.recipient_auth_key == Some(recipient.serialize().to_vec())
            && next_row.x1.as_deref() == Some(next_x1.as_slice()),
        "new owner generation did not receive one fresh active x1"
    );
    let next_owner = load_statechain_generation(mercury_pool, &statechain_id).await?;
    let next_latch = load_latch(mercury_pool, &statechain_id, &batch_id)
        .await?
        .context("predecessor-owned latch disappeared from fresh successor")?;
    let next_generation = SecretKey::from_secret_bytes(next_x1)?.public_key(&secp);
    let next_unlock = unlock_request_value(
        Bip448TransferUnlockRole::Recipient,
        &statechain_id,
        &recipient_secret,
        &next_generation,
    )?;
    let next_unlock_response =
        post_mercury_json(mercury_client, "transfer/unlock", &next_unlock).await?;
    assert_json_response(
        &next_unlock_response,
        StatusCode::INTERNAL_SERVER_ERROR,
        json!({"message":"Failed to unlock transfer generation."}),
    )?;
    ensure!(
        load_transfer_generation(mercury_pool, &statechain_id).await? == next_row
            && load_statechain_generation(mercury_pool, &statechain_id).await? == next_owner
            && load_latch(mercury_pool, &statechain_id, &batch_id).await?
                == Some(next_latch.clone()),
        "successor unlock with a predecessor-owned latch did not roll back exactly"
    );
    let old_receiver_after_successor = post_mercury_json(
        mercury_client,
        "transfer/receiver",
        &serde_json::to_value(&receiver_request)?,
    )
    .await?;
    assert_json_response(
        &old_receiver_after_successor,
        StatusCode::BAD_REQUEST,
        json!({"code":"StatecoinBatchLockedError","message":"Statecoin batch is locked"}),
    )?;
    ensure!(
        load_transfer_generation(mercury_pool, &statechain_id).await? == next_row
            && load_statechain_generation(mercury_pool, &statechain_id).await? == next_owner
            && load_latch(mercury_pool, &statechain_id, &batch_id).await? == Some(next_latch),
        "old consumed receiver request changed its fresh successor"
    );

    let (_wallet, mismatch_coin) = mercury::create_deposited_coin(mercury_client).await?;
    let mismatch_id = mismatch_coin
        .statechain_id
        .as_deref()
        .context("mismatched-latch Coin has no ID")?;
    let mismatch_signature = mismatch_coin
        .signed_statechain_id
        .as_deref()
        .context("mismatched-latch Coin has no owner signature")?;
    let mismatch_recipient_secret = SecretKey::from_secret_bytes([0x4d; 32])?;
    let mismatch_recipient = mismatch_recipient_secret.public_key(&secp);
    let mismatch_batch = format!("mismatched-latch-{}", uuid::Uuid::new_v4());
    let wrong_latch_owner = SecretKey::from_secret_bytes([0x4e; 32])?
        .public_key(&secp)
        .x_only_public_key()
        .0;
    sqlx::query(
        "INSERT INTO lightning_latch \
         (statechain_id,sender_auth_xonly_public_key,batch_id,pre_image,expires_at) \
         VALUES ($1,$2,$3,$4,NOW()+INTERVAL '1 day')",
    )
    .bind(mismatch_id)
    .bind(wrong_latch_owner.serialize().to_vec())
    .bind(&mismatch_batch)
    .bind("mismatched-owner-preimage")
    .execute(mercury_pool)
    .await?;
    let mismatch_sender = sender_request_value(
        mismatch_id,
        mismatch_signature,
        &mismatch_recipient,
        Some(&mismatch_batch),
    );
    let mismatch_sender_response =
        post_mercury_json(mercury_client, "transfer/sender", &mismatch_sender).await?;
    let mismatch_x1 = sender_x1(&mismatch_sender_response)?;
    let mismatch_generation = SecretKey::from_secret_bytes(mismatch_x1)?.public_key(&secp);
    let mismatch_row = load_transfer_generation(mercury_pool, mismatch_id).await?;
    let mismatch_latch = load_latch(mercury_pool, mismatch_id, &mismatch_batch)
        .await?
        .context("mismatched-owner latch disappeared")?;
    ensure!(
        mismatch_row.locked && !mismatch_row.locked2,
        "mismatched-owner latch was incorrectly treated as the sender's latch"
    );
    let mismatch_unlock = unlock_request_value(
        Bip448TransferUnlockRole::Recipient,
        mismatch_id,
        &mismatch_recipient_secret,
        &mismatch_generation,
    )?;
    let mismatch_unlock_response =
        post_mercury_json(mercury_client, "transfer/unlock", &mismatch_unlock).await?;
    assert_json_response(
        &mismatch_unlock_response,
        StatusCode::INTERNAL_SERVER_ERROR,
        json!({"message":"Failed to unlock transfer generation."}),
    )?;
    ensure!(
        load_transfer_generation(mercury_pool, mismatch_id).await? == mismatch_row
            && load_latch(mercury_pool, mismatch_id, &mismatch_batch).await?
                == Some(mismatch_latch),
        "mismatched latch-owner failure did not roll back transfer and latch"
    );

    for (same_recipient, recipient_byte, successor_byte) in
        [(true, 0x45, 0x46), (false, 0x47, 0x48)]
    {
        let (_wallet, stale_coin) = mercury::create_deposited_coin(mercury_client).await?;
        let stale_id = stale_coin
            .statechain_id
            .as_deref()
            .context("stale unlock ID")?;
        let stale_signature = stale_coin
            .signed_statechain_id
            .as_deref()
            .context("stale unlock owner signature")?;
        let stale_owner = coin_auth_secret(&stale_coin)?;
        let stale_recipient_secret = SecretKey::from_secret_bytes([recipient_byte; 32])?;
        let stale_recipient = stale_recipient_secret.public_key(&secp);
        let sender_a = sender_request_value(stale_id, stale_signature, &stale_recipient, None);
        let sender_a_response =
            post_mercury_json(mercury_client, "transfer/sender", &sender_a).await?;
        let stale_x1 = sender_x1(&sender_a_response)?;
        let stale_generation = SecretKey::from_secret_bytes(stale_x1)?.public_key(&secp);
        sqlx::query(
            "UPDATE statechain_transfer SET locked=true,locked2=true WHERE statechain_id=$1",
        )
        .bind(stale_id)
        .execute(mercury_pool)
        .await?;
        let stale_recipient_unlock = unlock_request_value(
            Bip448TransferUnlockRole::Recipient,
            stale_id,
            &stale_recipient_secret,
            &stale_generation,
        )?;
        let stale_current_unlock = unlock_request_value(
            Bip448TransferUnlockRole::CurrentOwner,
            stale_id,
            &stale_owner,
            &stale_generation,
        )?;
        let successor_recipient = if same_recipient {
            stale_recipient
        } else {
            SecretKey::from_secret_bytes([successor_byte; 32])?.public_key(&secp)
        };
        let successor_batch =
            same_recipient.then(|| format!("unlock-successor-{}", uuid::Uuid::new_v4()));
        let sender_b = sender_request_value(
            stale_id,
            stale_signature,
            &successor_recipient,
            successor_batch.as_deref(),
        );
        let sender_b_response =
            post_mercury_json(mercury_client, "transfer/sender", &sender_b).await?;
        let successor_x1 = sender_x1(&sender_b_response)?;
        ensure!(
            successor_x1 != stale_x1,
            "successor B reused stale unlock x1"
        );
        let successor_row = load_transfer_generation(mercury_pool, stale_id).await?;
        let successor_owner = load_statechain_generation(mercury_pool, stale_id).await?;
        for payload in [stale_recipient_unlock, stale_current_unlock] {
            let response = post_mercury_json(mercury_client, "transfer/unlock", &payload).await?;
            assert_json_response(
                &response,
                StatusCode::INTERNAL_SERVER_ERROR,
                generation_error.clone(),
            )?;
            ensure!(
                load_transfer_generation(mercury_pool, stale_id).await? == successor_row
                    && load_statechain_generation(mercury_pool, stale_id).await? == successor_owner,
                "stale unlock changed same/different-recipient successor B"
            );
        }
    }

    assert_unlock_a_first_barrier(
        mercury_client,
        mercury_pool,
        Bip448TransferUnlockRole::Recipient,
        0x49,
        0x4a,
    )
    .await?;
    assert_unlock_a_first_barrier(
        mercury_client,
        mercury_pool,
        Bip448TransferUnlockRole::CurrentOwner,
        0x4b,
        0x4c,
    )
    .await?;

    Ok(())
}

async fn assert_receiver_generation_fences(
    mercury_client: &reqwest::Client,
    mercury_pool: &PgPool,
    lockbox_pool: &PgPool,
) -> Result<()> {
    let secp = Secp256k1::new();
    let (_wallet, coin) = mercury::create_deposited_coin(mercury_client).await?;
    let statechain_id = coin
        .statechain_id
        .as_deref()
        .context("receiver matrix Coin has no statechain ID")?
        .to_owned();
    let signed_statechain_id = coin
        .signed_statechain_id
        .as_deref()
        .context("receiver matrix Coin has no owner signature")?
        .to_owned();
    let recipient_secret = SecretKey::from_secret_bytes([0x51; 32])?;
    let recipient = recipient_secret.public_key(&secp);
    let sender = sender_request_value(&statechain_id, &signed_statechain_id, &recipient, None);
    let sender_response = post_mercury_json(mercury_client, "transfer/sender", &sender).await?;
    let x1 = sender_x1(&sender_response)?;
    let generation = SecretKey::from_secret_bytes(x1)?.public_key(&secp);
    let receiver =
        generation_bound_receiver_request(&statechain_id, &recipient_secret, x1, [0xab; 32])?;
    let receiver_value = serde_json::to_value(&receiver)?;
    let initial_transfer = load_transfer_generation(mercury_pool, &statechain_id).await?;
    let initial_statechain = load_statechain_generation(mercury_pool, &statechain_id).await?;
    let initial_lockbox = load_lockbox_generation(lockbox_pool, &statechain_id).await?;
    let generation_error = json!({"message":"Transfer generation does not match current row."});

    let mut missing_generation = receiver_value.clone();
    missing_generation
        .as_object_mut()
        .context("receiver payload is not an object")?
        .remove("batch_data");
    let mut malformed_generation = receiver_value.clone();
    malformed_generation["batch_data"] = json!("not-a-public-key");
    let mut noncanonical_generation = receiver_value.clone();
    noncanonical_generation["batch_data"] = json!(generation.to_string().to_uppercase());
    let mut wrong_generation = receiver_value.clone();
    wrong_generation["batch_data"] = json!(SecretKey::from_secret_bytes([0x52; 32])?
        .public_key(&secp)
        .to_string());
    let mut noncanonical_t2 = receiver_value.clone();
    noncanonical_t2["t2"] = json!(receiver.t2.to_uppercase());
    let mut zero_t2 = receiver_value.clone();
    zero_t2["t2"] = json!("00".repeat(32));
    let mut substituted_t2 = receiver_value.clone();
    substituted_t2["t2"] = json!("ac".repeat(32));
    let mut wrong_signer = receiver_value.clone();
    let wrong_signer_secret = SecretKey::from_secret_bytes([0x53; 32])?;
    let wrong_signer_digest =
        bip448_transfer_receiver_auth_digest(&statechain_id, &[0xab; 32], &generation)?;
    wrong_signer["auth_sig"] = json!(sign_digest(&wrong_signer_secret, &wrong_signer_digest));
    for payload in [
        missing_generation,
        malformed_generation,
        noncanonical_generation,
        wrong_generation,
        noncanonical_t2,
        zero_t2,
        substituted_t2,
        wrong_signer,
    ] {
        let response = post_mercury_json(mercury_client, "transfer/receiver", &payload).await?;
        assert_json_response(
            &response,
            StatusCode::INTERNAL_SERVER_ERROR,
            generation_error.clone(),
        )?;
        ensure!(
            load_transfer_generation(mercury_pool, &statechain_id).await? == initial_transfer
                && load_statechain_generation(mercury_pool, &statechain_id).await?
                    == initial_statechain
                && load_lockbox_generation(lockbox_pool, &statechain_id).await? == initial_lockbox,
            "invalid receiver generation/auth input reached mutation"
        );
    }

    let missing_statechain = format!("missing-{}", uuid::Uuid::new_v4());
    let mut missing_statechain_request = receiver_value.clone();
    missing_statechain_request["statechain_id"] = json!(missing_statechain);
    let missing_statechain_response = post_mercury_json(
        mercury_client,
        "transfer/receiver",
        &missing_statechain_request,
    )
    .await?;
    assert_json_response(
        &missing_statechain_response,
        StatusCode::NOT_FOUND,
        json!({"message":"Statechain Id key not found."}),
    )?;
    let (_wallet, no_transfer_coin) = mercury::create_deposited_coin(mercury_client).await?;
    let no_transfer_id = no_transfer_coin
        .statechain_id
        .as_deref()
        .context("no-transfer receiver fixture has no ID")?;
    let no_transfer_request = json!({
        "statechain_id":no_transfer_id,
        "batch_data":generation.to_string(),
        "t2":receiver.t2,
        "auth_sig":receiver.auth_sig,
    });
    let no_transfer_response =
        post_mercury_json(mercury_client, "transfer/receiver", &no_transfer_request).await?;
    assert_json_response(
        &no_transfer_response,
        StatusCode::NOT_FOUND,
        json!({"message":"No transfer messages found for this statechain_id"}),
    )?;

    let (_wallet, other_coin) = mercury::create_deposited_coin(mercury_client).await?;
    let other_id = other_coin
        .statechain_id
        .as_deref()
        .context("other receiver fixture has no ID")?;
    let other_signature = other_coin
        .signed_statechain_id
        .as_deref()
        .context("other receiver fixture has no signature")?;
    let other_recipient = SecretKey::from_secret_bytes([0x54; 32])?.public_key(&secp);
    let other_sender = sender_request_value(other_id, other_signature, &other_recipient, None);
    let other_sender_response =
        post_mercury_json(mercury_client, "transfer/sender", &other_sender).await?;
    sender_x1(&other_sender_response)?;
    let other_before = load_transfer_generation(mercury_pool, other_id).await?;
    let other_state_before = load_statechain_generation(mercury_pool, other_id).await?;
    let other_lockbox_before = load_lockbox_generation(lockbox_pool, other_id).await?;
    let mut substituted_statechain = receiver_value.clone();
    substituted_statechain["statechain_id"] = json!(other_id);
    let substituted_statechain_response =
        post_mercury_json(mercury_client, "transfer/receiver", &substituted_statechain).await?;
    assert_json_response(
        &substituted_statechain_response,
        StatusCode::INTERNAL_SERVER_ERROR,
        generation_error.clone(),
    )?;
    ensure!(
        load_transfer_generation(mercury_pool, other_id).await? == other_before
            && load_statechain_generation(mercury_pool, other_id).await? == other_state_before
            && load_lockbox_generation(lockbox_pool, other_id).await? == other_lockbox_before,
        "receiver statechain substitution changed the other generation"
    );

    let valid_response =
        post_mercury_json(mercury_client, "transfer/receiver", &receiver_value).await?;
    ensure!(
        valid_response.0 == StatusCode::OK,
        "valid receiver failed: {valid_response:?}"
    );
    let valid_body: Value = serde_json::from_str(&valid_response.1)?;
    let after_valid_transfer = load_transfer_generation(mercury_pool, &statechain_id).await?;
    let after_valid_state = load_statechain_generation(mercury_pool, &statechain_id).await?;
    let after_valid_lockbox = load_lockbox_generation(lockbox_pool, &statechain_id).await?;
    ensure!(
        after_valid_transfer.key_updated == Some(true)
            && after_valid_state.auth_key
                == Some(recipient.x_only_public_key().0.serialize().to_vec())
            && valid_body["server_pubkey"].as_str().is_some(),
        "valid receiver did not consume its exact generation"
    );
    let valid_replay =
        post_mercury_json(mercury_client, "transfer/receiver", &receiver_value).await?;
    ensure!(
        valid_replay.0 == StatusCode::OK,
        "receiver replay failed: {valid_replay:?}"
    );
    ensure!(
        serde_json::from_str::<Value>(&valid_replay.1)? == valid_body
            && load_transfer_generation(mercury_pool, &statechain_id).await?
                == after_valid_transfer
            && load_statechain_generation(mercury_pool, &statechain_id).await? == after_valid_state
            && load_lockbox_generation(lockbox_pool, &statechain_id).await? == after_valid_lockbox,
        "exact receiver response-loss replay mutated its consumed generation"
    );

    let (_wallet, batch_coin) = mercury::create_deposited_coin(mercury_client).await?;
    let batch_statechain_id = batch_coin
        .statechain_id
        .as_deref()
        .context("batch receiver Coin has no ID")?;
    let batch_signature = batch_coin
        .signed_statechain_id
        .as_deref()
        .context("batch receiver Coin has no signature")?;
    let batch_recipient_secret = SecretKey::from_secret_bytes([0x55; 32])?;
    let batch_recipient = batch_recipient_secret.public_key(&secp);
    let batch_id = format!("receiver-batch-{}", uuid::Uuid::new_v4());
    let batch_sender = sender_request_value(
        batch_statechain_id,
        batch_signature,
        &batch_recipient,
        Some(&batch_id),
    );
    let batch_sender_response =
        post_mercury_json(mercury_client, "transfer/sender", &batch_sender).await?;
    let batch_x1 = sender_x1(&batch_sender_response)?;
    let batch_receiver = serde_json::to_value(generation_bound_receiver_request(
        batch_statechain_id,
        &batch_recipient_secret,
        batch_x1,
        [0x56; 32],
    )?)?;
    let locked_transfer = load_transfer_generation(mercury_pool, batch_statechain_id).await?;
    let locked_state = load_statechain_generation(mercury_pool, batch_statechain_id).await?;
    let locked_lockbox = load_lockbox_generation(lockbox_pool, batch_statechain_id).await?;
    let locked_response =
        post_mercury_json(mercury_client, "transfer/receiver", &batch_receiver).await?;
    assert_json_response(
        &locked_response,
        StatusCode::BAD_REQUEST,
        json!({"code":"StatecoinBatchLockedError","message":"Statecoin batch is locked"}),
    )?;
    ensure!(
        load_transfer_generation(mercury_pool, batch_statechain_id).await? == locked_transfer
            && load_statechain_generation(mercury_pool, batch_statechain_id).await? == locked_state
            && load_lockbox_generation(lockbox_pool, batch_statechain_id).await? == locked_lockbox,
        "locked batch receiver reached lockbox or Mercury mutation"
    );
    sqlx::query(
        "UPDATE statechain_transfer SET locked=false,locked2=false,\
         batch_time=NOW()-INTERVAL '30 days' WHERE statechain_id=$1",
    )
    .bind(batch_statechain_id)
    .execute(mercury_pool)
    .await?;
    let expired_transfer = load_transfer_generation(mercury_pool, batch_statechain_id).await?;
    let expired_response =
        post_mercury_json(mercury_client, "transfer/receiver", &batch_receiver).await?;
    assert_json_response(
        &expired_response,
        StatusCode::BAD_REQUEST,
        json!({"code":"ExpiredBatchTimeError","message":"Batch time has expired"}),
    )?;
    ensure!(
        load_transfer_generation(mercury_pool, batch_statechain_id).await? == expired_transfer
            && load_statechain_generation(mercury_pool, batch_statechain_id).await? == locked_state
            && load_lockbox_generation(lockbox_pool, batch_statechain_id).await? == locked_lockbox,
        "expired locked-row batch validation reached lockbox or Mercury mutation"
    );

    let (_wallet, ordered_coin) = mercury::create_deposited_coin(mercury_client).await?;
    let ordered_id = ordered_coin
        .statechain_id
        .as_deref()
        .context("ordered receiver Coin has no ID")?
        .to_owned();
    let ordered_signature = ordered_coin
        .signed_statechain_id
        .as_deref()
        .context("ordered receiver Coin has no signature")?
        .to_owned();
    let ordered_recipient_secret = SecretKey::from_secret_bytes([0x57; 32])?;
    let ordered_recipient = ordered_recipient_secret.public_key(&secp);
    let ordered_sender =
        sender_request_value(&ordered_id, &ordered_signature, &ordered_recipient, None);
    let ordered_sender_response =
        post_mercury_json(mercury_client, "transfer/sender", &ordered_sender).await?;
    let ordered_x1 = sender_x1(&ordered_sender_response)?;
    let ordered_receiver = serde_json::to_value(generation_bound_receiver_request(
        &ordered_id,
        &ordered_recipient_secret,
        ordered_x1,
        [0x58; 32],
    )?)?;
    let signatures_before: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM bip448_signature_data WHERE statechain_id=$1")
            .bind(&ordered_id)
            .fetch_one(mercury_pool)
            .await?;
    let row_lock = lock_transfer_row(mercury_pool, &ordered_id).await?;
    let receiver_client = mercury_client.clone();
    let mut receiver_task = tokio::spawn(async move {
        post_mercury_json(&receiver_client, "transfer/receiver", &ordered_receiver).await
    });
    wait_for_blocked_mercury_query(
        mercury_pool,
        "SELECT new_user_auth_public_key, x1, batch_id, batch_time",
    )
    .await?;
    ensure!(
        timeout(Duration::from_millis(100), &mut receiver_task)
            .await
            .is_err(),
        "A-first receiver did not remain blocked at its row-A fence"
    );
    let successor_recipient = SecretKey::from_secret_bytes([0x59; 32])?.public_key(&secp);
    let successor_sender =
        sender_request_value(&ordered_id, &ordered_signature, &successor_recipient, None);
    let sender_client = mercury_client.clone();
    let mut successor_task = tokio::spawn(async move {
        post_mercury_json(&sender_client, "transfer/sender", &successor_sender).await
    });
    ensure!(
        timeout(Duration::from_millis(100), &mut successor_task)
            .await
            .is_err(),
        "successor sender bypassed A-first receiver statechain-data lock"
    );
    row_lock.commit().await?;
    let ordered_receiver_response = receiver_task.await??;
    ensure!(
        ordered_receiver_response.0 == StatusCode::OK,
        "A-first receiver did not complete: {ordered_receiver_response:?}"
    );
    let stale_sender_response = successor_task.await??;
    assert_json_response(
        &stale_sender_response,
        StatusCode::INTERNAL_SERVER_ERROR,
        json!({"message":"Signature does not match authentication key."}),
    )?;
    let ordered_row = load_transfer_generation(mercury_pool, &ordered_id).await?;
    ensure!(
        ordered_row.recipient_auth_key == Some(ordered_recipient.serialize().to_vec())
            && ordered_row.key_updated == Some(true)
            && sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM statechain_transfer WHERE statechain_id=$1",
            )
            .bind(&ordered_id)
            .fetch_one(mercury_pool)
            .await?
                == 1
            && sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM bip448_signature_data WHERE statechain_id=$1",
            )
            .bind(&ordered_id)
            .fetch_one(mercury_pool)
            .await?
                == signatures_before,
        "receiver-first ordering inserted successor state or signature artifacts"
    );

    let (_wallet, b_first_coin) = mercury::create_deposited_coin(mercury_client).await?;
    let b_first_id = b_first_coin
        .statechain_id
        .as_deref()
        .context("B-first receiver Coin has no ID")?;
    let b_first_signature = b_first_coin
        .signed_statechain_id
        .as_deref()
        .context("B-first receiver Coin has no signature")?;
    let b_recipient_secret = SecretKey::from_secret_bytes([0x5a; 32])?;
    let b_recipient = b_recipient_secret.public_key(&secp);
    let sender_a = sender_request_value(b_first_id, b_first_signature, &b_recipient, None);
    let sender_a_response = post_mercury_json(mercury_client, "transfer/sender", &sender_a).await?;
    let a_x1 = sender_x1(&sender_a_response)?;
    let stale_receiver = serde_json::to_value(generation_bound_receiver_request(
        b_first_id,
        &b_recipient_secret,
        a_x1,
        [0x5b; 32],
    )?)?;
    let b_batch = format!("receiver-b-first-{}", uuid::Uuid::new_v4());
    let sender_b =
        sender_request_value(b_first_id, b_first_signature, &b_recipient, Some(&b_batch));
    let sender_b_response = post_mercury_json(mercury_client, "transfer/sender", &sender_b).await?;
    let b_x1 = sender_x1(&sender_b_response)?;
    ensure!(a_x1 != b_x1, "B-first receiver successor reused A x1");
    sqlx::query("UPDATE statechain_transfer SET locked=false WHERE statechain_id=$1")
        .bind(b_first_id)
        .execute(mercury_pool)
        .await?;
    let b_transfer = load_transfer_generation(mercury_pool, b_first_id).await?;
    let b_state = load_statechain_generation(mercury_pool, b_first_id).await?;
    let b_lockbox = load_lockbox_generation(lockbox_pool, b_first_id).await?;
    let stale_receiver_response =
        post_mercury_json(mercury_client, "transfer/receiver", &stale_receiver).await?;
    assert_json_response(
        &stale_receiver_response,
        StatusCode::INTERNAL_SERVER_ERROR,
        generation_error,
    )?;
    ensure!(
        load_transfer_generation(mercury_pool, b_first_id).await? == b_transfer
            && load_statechain_generation(mercury_pool, b_first_id).await? == b_state
            && load_lockbox_generation(lockbox_pool, b_first_id).await? == b_lockbox,
        "B-first stale receiver changed successor generation"
    );

    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct DeterministicVector {
    server_pubkey: String,
    server_pubnonce: String,
    partial_sig: String,
    updated_server_pubkey: String,
}

#[derive(Debug)]
struct Bip448SignatureDataRow {
    server_pubnonce: Option<String>,
    challenge: Option<String>,
    negate_seckey: Option<bool>,
    server_partial_sig: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MercuryDeletionRows {
    statechain_data: i64,
    bip448_signature_data: i64,
    completed_bip448_signature_data: i64,
    signing_nonce_leases: i64,
    statechain_transfer: i64,
}

impl MercuryDeletionRows {
    fn populated() -> Self {
        Self {
            statechain_data: 1,
            bip448_signature_data: 2,
            completed_bip448_signature_data: 1,
            signing_nonce_leases: 1,
            statechain_transfer: 1,
        }
    }

    fn absent() -> Self {
        Self {
            statechain_data: 0,
            bip448_signature_data: 0,
            completed_bip448_signature_data: 0,
            signing_nonce_leases: 0,
            statechain_transfer: 0,
        }
    }
}

struct ProductionRngRestoreGuard {
    active: bool,
}

impl ProductionRngRestoreGuard {
    fn armed() -> Self {
        Self { active: true }
    }

    async fn restore_now(&mut self, client: &reqwest::Client) -> Result<()> {
        lockbox::recreate_lockbox_service_with_rng_seed(client, None).await?;
        self.active = false;
        Ok(())
    }
}

impl Drop for ProductionRngRestoreGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }

        if let Err(err) = lockbox::recreate_lockbox_service_with_production_rng() {
            eprintln!("failed to restore lockbox production RNG after deterministic test: {err:#}");
        }
    }
}

fn mutate_bip448_session_challenge(session_hex: &str) -> Result<String> {
    const CHALLENGE_OFFSET: usize = 4 + 1 + 32 + 32;
    let mut session = hex::decode(session_hex)?;
    session[CHALLENGE_OFFSET] ^= 0x01;
    Ok(hex::encode(session))
}

fn deterministic_partial_signature_payload() -> Bip448LockboxPartialSignatureRequestPayload {
    Bip448LockboxPartialSignatureRequestPayload {
        statechain_id: DETERMINISTIC_STATECHAIN_ID.to_string(),
        signing_id: DETERMINISTIC_SIGNING_ID.to_string(),
        negate_seckey: 0,
        session: "9dede917000000000000000000000000000000000000000000000000000000000000000000b59faf7e0a44057b41d273e70cc0a59194347b286c8108fef3519bb52fe64b0729641b33afc4d71464ccde0ca4b0471ed2fda81a39056745ed7b1f4f90790dfd3ee2e8c6c5937a7f4dd30e9e78ec2096433ff32ea89ffca29a40b02b03b4e7eb".to_string(),
        server_pub_nonce: "032f7d30ca4641d314418be9e8e11ef28e079ce684f7271bceab6e9f835adea05303b1b76528c43918e991aa847abb7b6df753dc116de95a9d811bc9b35a7f020dfb".to_string(),
    }
}

fn bip448_partial_signature_payload(
    coin: &mercurylib::wallet::Coin,
    signing_id: &str,
    server_pubnonce: &str,
) -> Result<(Bip448PartialSignatureRequestPayload, String)> {
    let secp = Secp256k1::new();
    let client_seckey = PrivateKey::from_wif(&coin.user_privkey)?.inner;
    let client_pubkey = PublicKey::from_str(&coin.user_pubkey)?;
    let server_pubkey = PublicKey::from_str(
        coin.server_pubkey
            .as_ref()
            .context("deposited coin missing server_pubkey")?,
    )?;
    let aggregate_pubkey = client_pubkey.combine(&server_pubkey)?;

    let mut rng = rand::rng();
    let (_client_sec_nonce, client_pub_nonce) = new_musig_nonce_pair(
        &secp,
        MusigSessionId::new(&mut rng),
        None,
        Some(client_seckey),
        client_pubkey,
        None,
        None,
    )?;
    let server_pub_nonce = PublicNonce::from_slice(&hex::decode(server_pubnonce)?)?;
    let blinding_secret = SecretKey::new(&mut rng);
    let blinding_factor = BlindingFactor::from_slice(&blinding_secret.to_secret_bytes())?;
    let template_hash = TemplateHash::from_slice(&[0x51u8; 32])?;
    let session = CsfsSigningSession::new(
        &secp,
        CsfsSigningRole::FundingUpdate,
        aggregate_pubkey,
        &client_pub_nonce,
        &server_pub_nonce,
        template_hash,
        &blinding_factor,
    )?;
    let challenge = hex::encode(session.blinded_challenge());

    Ok((
        Bip448PartialSignatureRequestPayload {
            statechain_id: coin
                .statechain_id
                .as_ref()
                .context("deposited coin missing statechain_id")?
                .clone(),
            signed_statechain_id: coin
                .signed_statechain_id
                .as_ref()
                .context("deposited coin missing signed_statechain_id")?
                .clone(),
            signing_id: signing_id.to_string(),
            negate_seckey: u8::from(session.negate_seckey()),
            session: hex::encode(session.blinded_server_session().serialize()),
            server_pub_nonce: server_pubnonce.to_string(),
        },
        challenge,
    ))
}

async fn complete_bip448_signing_round(
    mercury_client: &reqwest::Client,
    coin: &mercurylib::wallet::Coin,
    signing_id: String,
) -> Result<(String, String)> {
    let first = mercury::bip448_sign_first(
        mercury_client,
        &Bip448SignFirstRequestPayload {
            statechain_id: coin
                .statechain_id
                .as_ref()
                .context("deposited coin missing statechain_id")?
                .clone(),
            signed_statechain_id: coin
                .signed_statechain_id
                .as_ref()
                .context("deposited coin missing signed_statechain_id")?
                .clone(),
            signing_id: signing_id.clone(),
        },
    )
    .await?;
    let (second_payload, challenge) =
        bip448_partial_signature_payload(coin, &signing_id, &first.server_pubnonce)?;
    let second = mercury::bip448_sign_second(mercury_client, &second_payload).await?;
    assert_eq!(second.partial_sig.len(), 64);

    Ok((first.server_pubnonce, challenge))
}

async fn insert_completed_bip448_signature_row(
    statechain_id: &str,
    signing_id: &str,
) -> Result<()> {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(MERCURY_DATABASE_URL)
        .await
        .context("failed to connect to mercury postgres")?;
    sqlx::query(
        "INSERT INTO bip448_signature_data \
         (statechain_id, signing_id, server_pubnonce, challenge, negate_seckey, server_partial_sig) \
         VALUES ($1, $2, $3, $4, false, $5)",
    )
    .bind(statechain_id)
    .bind(signing_id)
    .bind("mixed-bip448-server-pubnonce")
    .bind("mixed-bip448-challenge")
    .bind("mixed-bip448-partial-signature")
    .execute(&pool)
    .await?;

    Ok(())
}

async fn load_bip448_signature_data_row(
    pool: &sqlx::PgPool,
    statechain_id: &str,
    signing_id: &str,
) -> Result<Option<Bip448SignatureDataRow>> {
    let row: Option<(Option<String>, Option<String>, Option<bool>, Option<String>)> =
        sqlx::query_as(
            "SELECT server_pubnonce, challenge, negate_seckey, server_partial_sig \
         FROM bip448_signature_data \
         WHERE statechain_id = $1 AND signing_id = $2",
        )
        .bind(statechain_id)
        .bind(signing_id)
        .fetch_optional(pool)
        .await?;

    Ok(row.map(
        |(server_pubnonce, challenge, negate_seckey, server_partial_sig)| Bip448SignatureDataRow {
            server_pubnonce,
            challenge,
            negate_seckey,
            server_partial_sig,
        },
    ))
}

async fn load_mercury_deletion_rows(
    pool: &sqlx::PgPool,
    statechain_id: &str,
) -> Result<MercuryDeletionRows> {
    let row: (i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT \
            (SELECT COUNT(*) FROM statechain_data WHERE statechain_id = $1), \
            (SELECT COUNT(*) FROM bip448_signature_data WHERE statechain_id = $1), \
            (SELECT COUNT(*) FROM bip448_signature_data \
             WHERE statechain_id = $1 AND server_partial_sig IS NOT NULL), \
            (SELECT COUNT(*) FROM signing_nonce_leases WHERE statechain_id = $1), \
            (SELECT COUNT(*) FROM statechain_transfer WHERE statechain_id = $1)",
    )
    .bind(statechain_id)
    .fetch_one(pool)
    .await?;

    Ok(MercuryDeletionRows {
        statechain_data: row.0,
        bip448_signature_data: row.1,
        completed_bip448_signature_data: row.2,
        signing_nonce_leases: row.3,
        statechain_transfer: row.4,
    })
}

async fn prepare_mercury_deletion_fixture(
    mercury_client: &reqwest::Client,
    pool: &sqlx::PgPool,
    completed_signing_byte: u8,
    pending_signing_byte: u8,
    recipient_secret_byte: u8,
    x1_byte: u8,
) -> Result<mercurylib::wallet::Coin> {
    let (_wallet, coin) = mercury::create_deposited_coin(mercury_client).await?;
    let statechain_id = coin
        .statechain_id
        .as_deref()
        .context("deposited coin missing statechain_id")?;
    let completed_signing_id = hex::encode([completed_signing_byte; 32]);
    complete_bip448_signing_round(mercury_client, &coin, completed_signing_id).await?;

    let pending_signing_id = hex::encode([pending_signing_byte; 32]);
    let pending_nonce = mercury::bip448_sign_first(
        mercury_client,
        &Bip448SignFirstRequestPayload {
            statechain_id: statechain_id.to_string(),
            signed_statechain_id: coin
                .signed_statechain_id
                .as_ref()
                .context("deposited coin missing signed_statechain_id")?
                .clone(),
            signing_id: pending_signing_id,
        },
    )
    .await?;
    ensure!(
        pending_nonce.server_pubnonce.len() == 132,
        "pending signing nonce was not persisted"
    );

    let secp = Secp256k1::new();
    let recipient_secret = SecretKey::from_secret_bytes([recipient_secret_byte; 32])?;
    mercury::insert_statechain_transfer_row(
        statechain_id,
        &recipient_secret.public_key(&secp),
        [x1_byte; 32],
    )
    .await?;

    let rows = load_mercury_deletion_rows(pool, statechain_id).await?;
    ensure!(
        rows == MercuryDeletionRows::populated(),
        "deletion fixture did not populate every Mercury row class: {rows:?}"
    );

    Ok(coin)
}

async fn mercury_withdraw_complete_response(
    client: &reqwest::Client,
    coin: &mercurylib::wallet::Coin,
) -> Result<reqwest::Response> {
    let statechain_id = coin
        .statechain_id
        .as_ref()
        .context("deposited coin missing statechain_id")?;
    let signed_statechain_id = coin
        .signed_statechain_id
        .as_ref()
        .context("deposited coin missing signed_statechain_id")?;

    client
        .post(format!("{}/withdraw/complete", mercury::MERCURY_URL))
        .json(&WithdrawCompletePayload {
            statechain_id: statechain_id.clone(),
            signed_statechain_id: signed_statechain_id.clone(),
        })
        .send()
        .await
        .context("failed to call mercury withdraw/complete")
}

async fn response_status_and_body(
    response: reqwest::Response,
    context: &str,
) -> Result<(StatusCode, String)> {
    let status = response.status();
    let body = response
        .text()
        .await
        .with_context(|| format!("failed to read {context} body"))?;

    Ok((status, body))
}

async fn wait_until_lockbox_database_ready() -> Result<()> {
    let mut first_error = None;

    for _ in 0..60 {
        let readiness = async {
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(Duration::from_secs(1))
                .connect(LOCKBOX_DATABASE_URL)
                .await?;
            sqlx::query("SELECT 1").execute(&pool).await?;
            Ok::<(), sqlx::Error>(())
        }
        .await;

        match readiness {
            Ok(()) => {
                if let Some(first_error) = first_error {
                    eprintln!(
                        "lockbox database readiness was initially pending after restart: {first_error}"
                    );
                }
                return Ok(());
            }
            Err(err) => {
                if first_error.is_none() {
                    first_error = Some(err);
                }
                sleep(Duration::from_secs(1)).await;
            }
        }
    }

    Err(anyhow::anyhow!(
        "lockbox database did not become ready within 60 seconds; first error: {}",
        first_error
            .map(|err| err.to_string())
            .unwrap_or_else(|| "no connection attempt was recorded".to_string())
    ))
}

async fn assert_missing_statechain_error(response: reqwest::Response, context: &str) -> Result<()> {
    let status = response.status();
    let body = response
        .text()
        .await
        .with_context(|| format!("failed to read {} body", context))?;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(body.contains("Failed to load aggregated key data"));

    Ok(())
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn get_public_key_requires_statechain_id() -> Result<()> {
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    lockbox::wait_until_ready(&client).await?;

    let response = lockbox::post_json(&client, "get_public_key", json!({})).await?;
    let status = response.status();
    let body = response
        .text()
        .await
        .context("failed to read get_public_key body")?;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, "Invalid parameter. It must be 'statechain_id'.");

    Ok(())
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn bip448_get_public_nonce_requires_existing_statechain() -> Result<()> {
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    lockbox::wait_until_ready(&client).await?;

    let response = lockbox::post_json(
        &client,
        "bip448/get_public_nonce",
        serde_json::to_value(Bip448LockboxSignFirstRequestPayload {
            statechain_id: lockbox::new_statechain_id("missing-nonce"),
            signing_id: hex::encode([0x11u8; 32]),
        })?,
    )
    .await?;
    let status = response.status();
    let body = response
        .text()
        .await
        .context("failed to read bip448/get_public_nonce body")?;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(body.contains("Failed to load aggregated key data"));

    Ok(())
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn bip448_get_partial_signature_validates_session_length() -> Result<()> {
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    lockbox::wait_until_ready(&client).await?;

    let response = lockbox::post_json(
        &client,
        "bip448/get_partial_signature",
        serde_json::to_value(Bip448LockboxPartialSignatureRequestPayload {
            statechain_id: lockbox::new_statechain_id("bad-session"),
            signing_id: hex::encode([0x12u8; 32]),
            negate_seckey: 0,
            session: "00".to_string(),
            server_pub_nonce: "00".repeat(66),
        })?,
    )
    .await?;
    let status = response.status();
    let body = response
        .text()
        .await
        .context("failed to read bip448/get_partial_signature body")?;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, "Invalid session length. Must be 133 bytes!");

    Ok(())
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn bip448_get_partial_signature_requires_existing_nonce_state() -> Result<()> {
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    lockbox::wait_until_ready(&client).await?;

    let statechain_id = lockbox::new_statechain_id("missing-sign");
    let existing_signing_id = hex::encode([0x13u8; 32]);
    let missing_signing_id = hex::encode([0x14u8; 32]);
    let created = lockbox::create_statechain(&client, &statechain_id).await?;
    let server_pubnonce = lockbox::bip448_get_public_nonce(
        &client,
        &Bip448LockboxSignFirstRequestPayload {
            statechain_id: statechain_id.clone(),
            signing_id: existing_signing_id,
        },
    )
    .await?;
    let fixture = lockbox::build_bip448_partial_signature_fixture(
        &statechain_id,
        &missing_signing_id,
        &created.server_pubkey,
        &server_pubnonce.server_pubnonce,
    )?;
    let response = lockbox::post_json(
        &client,
        "bip448/get_partial_signature",
        serde_json::to_value(&fixture.payload)?,
    )
    .await?;
    let status = response.status();
    let body = response
        .text()
        .await
        .context("failed to read missing BIP448 nonce-state body")?;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, "BIP448 nonce state not found for signing_id");

    lockbox::delete_statechain(&client, &statechain_id).await?;

    Ok(())
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn keyupdate_validates_t2_and_x1_lengths() -> Result<()> {
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    lockbox::wait_until_ready(&client).await?;

    let bad_t2 = lockbox::post_json(
        &client,
        "keyupdate",
        json!({
            "statechain_id": lockbox::new_statechain_id("bad-keyupdate-t2"),
            "t2": "00",
            "x1": hex::encode([2u8; 32]),
        }),
    )
    .await?;
    let bad_t2_status = bad_t2.status();
    let bad_t2_body = bad_t2.text().await.context("failed to read bad t2 body")?;

    assert_eq!(bad_t2_status, StatusCode::BAD_REQUEST);
    assert_eq!(bad_t2_body, "Invalid t2 length. Must be 32 bytes!");

    let bad_x1 = lockbox::post_json(
        &client,
        "keyupdate",
        json!({
            "statechain_id": lockbox::new_statechain_id("bad-keyupdate-x1"),
            "t2": hex::encode([1u8; 32]),
            "x1": "00",
        }),
    )
    .await?;
    let bad_x1_status = bad_x1.status();
    let bad_x1_body = bad_x1.text().await.context("failed to read bad x1 body")?;

    assert_eq!(bad_x1_status, StatusCode::BAD_REQUEST);
    assert_eq!(bad_x1_body, "Invalid x1 length. Must be 32 bytes!");

    Ok(())
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn keyupdate_requires_existing_statechain() -> Result<()> {
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    lockbox::wait_until_ready(&client).await?;

    let response = lockbox::post_json(
        &client,
        "keyupdate",
        json!({
            "statechain_id": lockbox::new_statechain_id("missing-key"),
            "t2": hex::encode([5u8; 32]),
            "x1": hex::encode([6u8; 32]),
        }),
    )
    .await?;

    assert_missing_statechain_error(response, "missing keyupdate").await
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn signature_count_for_missing_statechain_returns_not_found() -> Result<()> {
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    lockbox::wait_until_ready(&client).await?;

    let response = lockbox::get(
        &client,
        &format!(
            "signature_count/{}",
            lockbox::new_statechain_id("missing-count")
        ),
    )
    .await?;
    let status = response.status();
    let body = response
        .text()
        .await
        .context("failed to read missing signature_count body")?;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.contains("Signature count not found."));

    Ok(())
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn bip448_signing_lifecycle_returns_a_valid_partial_signature_and_increments_signature_count(
) -> Result<()> {
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    lockbox::wait_until_ready(&client).await?;

    let statechain_id = lockbox::new_statechain_id("signing-lifecycle");
    let signing_id = hex::encode([0x21u8; 32]);
    let created = lockbox::create_statechain(&client, &statechain_id).await?;
    let server_pubnonce = lockbox::bip448_get_public_nonce(
        &client,
        &Bip448LockboxSignFirstRequestPayload {
            statechain_id: statechain_id.clone(),
            signing_id: signing_id.clone(),
        },
    )
    .await?;
    let partial_sig = lockbox::complete_bip448_signing_roundtrip(
        &client,
        &statechain_id,
        &signing_id,
        &created.server_pubkey,
        &server_pubnonce.server_pubnonce,
    )
    .await?;

    assert_eq!(hex::decode(&partial_sig)?.len(), 32);

    let sig_count = lockbox::get_signature_count(&client, &statechain_id).await?;
    assert_eq!(sig_count, 1);

    lockbox::delete_statechain(&client, &statechain_id).await?;

    Ok(())
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn keyupdate_returns_the_expected_server_pubkey_and_statechain_remains_usable() -> Result<()>
{
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    lockbox::wait_until_ready(&client).await?;

    let statechain_id = lockbox::new_statechain_id("keyupdate");
    let created = lockbox::create_statechain(&client, &statechain_id).await?;
    let old_signing_id = hex::encode([0x22u8; 32]);
    let old_server_pubnonce = lockbox::bip448_get_public_nonce(
        &client,
        &Bip448LockboxSignFirstRequestPayload {
            statechain_id: statechain_id.clone(),
            signing_id: old_signing_id.clone(),
        },
    )
    .await?;
    let old_partial_signature_fixture = lockbox::build_bip448_partial_signature_fixture(
        &statechain_id,
        &old_signing_id,
        &created.server_pubkey,
        &old_server_pubnonce.server_pubnonce,
    )?;
    assert_eq!(old_server_pubnonce.server_pubnonce.len(), 132);
    assert_eq!(
        lockbox::get_signature_count(&client, &statechain_id).await?,
        0
    );

    let t2 = [1u8; 32];
    let x1 = [2u8; 32];
    let expected_server_pubkey =
        lockbox::expected_keyupdate_server_pubkey(&created.server_pubkey, t2, x1)?;

    let new_key = lockbox::keyupdate(&client, &statechain_id, t2, x1).await?;

    assert_ne!(new_key.server_pubkey, created.server_pubkey);
    assert_eq!(new_key.server_pubkey, expected_server_pubkey);

    let old_partial_signature_response = lockbox::post_json(
        &client,
        "bip448/get_partial_signature",
        serde_json::to_value(&old_partial_signature_fixture.payload)?,
    )
    .await?;
    let old_partial_signature_status = old_partial_signature_response.status();
    let old_partial_signature_body = old_partial_signature_response
        .text()
        .await
        .context("failed to read post-keyupdate old BIP448 nonce-state body")?;
    assert_eq!(old_partial_signature_status, StatusCode::NOT_FOUND);
    assert_eq!(
        old_partial_signature_body,
        "BIP448 nonce state not found for signing_id"
    );
    assert_eq!(
        lockbox::get_signature_count(&client, &statechain_id).await?,
        0
    );

    let updated_signing_id = hex::encode([0x23u8; 32]);
    assert_ne!(updated_signing_id, old_signing_id);
    let new_server_pubnonce = lockbox::bip448_get_public_nonce(
        &client,
        &Bip448LockboxSignFirstRequestPayload {
            statechain_id: statechain_id.clone(),
            signing_id: updated_signing_id.clone(),
        },
    )
    .await?;
    assert_eq!(new_server_pubnonce.server_pubnonce.len(), 132);
    let updated_partial_signature_fixture = lockbox::build_bip448_partial_signature_fixture(
        &statechain_id,
        &updated_signing_id,
        &expected_server_pubkey,
        &new_server_pubnonce.server_pubnonce,
    )?;
    let partial_sig = lockbox::bip448_request_partial_signature(
        &client,
        &updated_partial_signature_fixture.payload,
    )
    .await?;
    updated_partial_signature_fixture.verify_server_partial_signature(&partial_sig)?;
    assert_eq!(hex::decode(&partial_sig)?.len(), 32);
    assert_eq!(
        lockbox::get_signature_count(&client, &statechain_id).await?,
        1
    );

    lockbox::delete_statechain(&client, &statechain_id).await?;

    Ok(())
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn bip448_nonce_state_replays_after_restart_and_rejects_conflicting_challenge() -> Result<()>
{
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    lockbox::wait_until_ready(&client).await?;

    let statechain_id = lockbox::new_statechain_id("bip448-lockbox");
    let signing_id = hex::encode([0x55u8; 32]);
    let created = lockbox::create_statechain(&client, &statechain_id).await?;
    let nonce_payload = Bip448LockboxSignFirstRequestPayload {
        statechain_id: statechain_id.clone(),
        signing_id: signing_id.clone(),
    };
    let server_pubnonce = lockbox::bip448_get_public_nonce(&client, &nonce_payload).await?;
    let repeated_server_pubnonce =
        lockbox::bip448_get_public_nonce(&client, &nonce_payload).await?;
    assert_eq!(
        repeated_server_pubnonce.server_pubnonce,
        server_pubnonce.server_pubnonce
    );

    let fixture = lockbox::build_bip448_partial_signature_fixture(
        &statechain_id,
        &signing_id,
        &created.server_pubkey,
        &server_pubnonce.server_pubnonce,
    )?;
    let payload = fixture.payload;

    let partial = lockbox::bip448_request_partial_signature(&client, &payload).await?;
    assert_eq!(partial.len(), 64);
    assert_eq!(
        lockbox::get_signature_count(&client, &statechain_id).await?,
        1
    );

    lockbox::restart_lockbox_service(&client).await?;

    let replay = lockbox::bip448_request_partial_signature(&client, &payload).await?;
    assert_eq!(replay, partial);
    assert_eq!(
        lockbox::get_signature_count(&client, &statechain_id).await?,
        1
    );

    let mut conflicting_payload = payload.clone();
    conflicting_payload.session = mutate_bip448_session_challenge(&payload.session)?;
    let conflict = lockbox::post_json(
        &client,
        "bip448/get_partial_signature",
        json!({
            "statechain_id": conflicting_payload.statechain_id,
            "signing_id": signing_id,
            "negate_seckey": conflicting_payload.negate_seckey,
            "session": conflicting_payload.session,
            "server_pub_nonce": conflicting_payload.server_pub_nonce,
        }),
    )
    .await?;
    let conflict_status = conflict.status();
    let conflict_body = conflict
        .text()
        .await
        .context("failed to read BIP448 conflict body")?;
    assert_eq!(conflict_status, StatusCode::CONFLICT);
    assert!(conflict_body.contains("challenge does not match"));
    assert_eq!(
        lockbox::get_signature_count(&client, &statechain_id).await?,
        1
    );

    lockbox::delete_statechain(&client, &statechain_id).await?;

    Ok(())
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn keyupdate_state_survives_lockbox_restart() -> Result<()> {
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    lockbox::wait_until_ready(&client).await?;

    let statechain_id = lockbox::new_statechain_id("restart-key");
    let created = lockbox::create_statechain(&client, &statechain_id).await?;
    let t2 = [3u8; 32];
    let x1 = [4u8; 32];
    let expected_server_pubkey =
        lockbox::expected_keyupdate_server_pubkey(&created.server_pubkey, t2, x1)?;

    let updated_key = lockbox::keyupdate(&client, &statechain_id, t2, x1).await?;
    assert_eq!(updated_key.server_pubkey, expected_server_pubkey);

    lockbox::restart_lockbox_service(&client).await?;

    let signing_id = hex::encode([0x23u8; 32]);
    let server_pubnonce = lockbox::bip448_get_public_nonce(
        &client,
        &Bip448LockboxSignFirstRequestPayload {
            statechain_id: statechain_id.clone(),
            signing_id: signing_id.clone(),
        },
    )
    .await?;
    let partial_sig = lockbox::complete_bip448_signing_roundtrip(
        &client,
        &statechain_id,
        &signing_id,
        &updated_key.server_pubkey,
        &server_pubnonce.server_pubnonce,
    )
    .await?;

    assert_eq!(hex::decode(&partial_sig)?.len(), 32);
    assert_eq!(
        lockbox::get_signature_count(&client, &statechain_id).await?,
        1
    );

    lockbox::delete_statechain(&client, &statechain_id).await?;

    Ok(())
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn delete_statechain_is_idempotent_and_deleted_statechain_cannot_be_used() -> Result<()> {
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    lockbox::wait_until_ready(&client).await?;

    let statechain_id = lockbox::new_statechain_id("delete-state");
    let signing_id = hex::encode([0x24u8; 32]);
    let created = lockbox::create_statechain(&client, &statechain_id).await?;
    let nonce_payload = Bip448LockboxSignFirstRequestPayload {
        statechain_id: statechain_id.clone(),
        signing_id: signing_id.clone(),
    };
    let server_pubnonce = lockbox::bip448_get_public_nonce(&client, &nonce_payload).await?;
    let partial_signature_fixture = lockbox::build_bip448_partial_signature_fixture(
        &statechain_id,
        &signing_id,
        &created.server_pubkey,
        &server_pubnonce.server_pubnonce,
    )?;

    let delete_response =
        lockbox::delete(&client, &format!("delete_statechain/{}", statechain_id)).await?;
    let delete_status = delete_response.status();
    let delete_body = delete_response
        .text()
        .await
        .context("failed to read first delete_statechain body")?;

    assert_eq!(delete_status, StatusCode::OK);
    assert_eq!(delete_body, "Statechain deleted.");

    let second_delete_response =
        lockbox::delete(&client, &format!("delete_statechain/{}", statechain_id)).await?;
    let second_delete_status = second_delete_response.status();
    let second_delete_body = second_delete_response
        .text()
        .await
        .context("failed to read second delete_statechain body")?;

    assert_eq!(second_delete_status, StatusCode::OK);
    assert_eq!(second_delete_body, "Statechain deleted.");

    let nonce_response = lockbox::post_json(
        &client,
        "bip448/get_public_nonce",
        serde_json::to_value(&nonce_payload)?,
    )
    .await?;
    assert_missing_statechain_error(nonce_response, "post-delete bip448/get_public_nonce").await?;

    let partial_signature_response = lockbox::post_json(
        &client,
        "bip448/get_partial_signature",
        serde_json::to_value(&partial_signature_fixture.payload)?,
    )
    .await?;
    let partial_signature_status = partial_signature_response.status();
    let partial_signature_body = partial_signature_response
        .text()
        .await
        .context("failed to read post-delete bip448/get_partial_signature body")?;
    assert_eq!(partial_signature_status, StatusCode::NOT_FOUND);
    assert_eq!(
        partial_signature_body,
        "BIP448 nonce state not found for signing_id"
    );

    let keyupdate_response = lockbox::post_json(
        &client,
        "keyupdate",
        json!({
            "statechain_id": statechain_id,
            "t2": hex::encode([7u8; 32]),
            "x1": hex::encode([8u8; 32]),
        }),
    )
    .await?;
    assert_missing_statechain_error(keyupdate_response, "post-delete keyupdate").await?;

    let sig_count_response =
        lockbox::get(&client, &format!("signature_count/{}", statechain_id)).await?;
    let sig_count_status = sig_count_response.status();
    let sig_count_body = sig_count_response
        .text()
        .await
        .context("failed to read post-delete signature_count body")?;

    assert_eq!(sig_count_status, StatusCode::NOT_FOUND);
    assert!(sig_count_body.contains("Signature count not found."));

    Ok(())
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn mercury_withdraw_complete_preserves_rows_when_lockbox_delete_fails() -> Result<()> {
    let _guard = common::test_guard();
    let mercury_client = mercury::http_client();
    let lockbox_client = lockbox::http_client();
    mercury::wait_until_ready(&mercury_client).await?;
    lockbox::wait_until_ready(&lockbox_client).await?;

    let mercury_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(MERCURY_DATABASE_URL)
        .await
        .context("failed to connect to mercury postgres")?;
    let outage_coin =
        prepare_mercury_deletion_fixture(&mercury_client, &mercury_pool, 0x71, 0x72, 0x73, 0x74)
            .await?;
    let outage_statechain_id = outage_coin
        .statechain_id
        .as_deref()
        .context("outage fixture missing statechain_id")?
        .to_string();

    lockbox::stop_token_stack_lockbox_database().await?;
    let outage_assertions = async {
        let direct_delete = lockbox::delete(
            &lockbox_client,
            &format!("delete_statechain/{outage_statechain_id}"),
        )
        .await?;
        let (direct_status, direct_body) =
            response_status_and_body(direct_delete, "lockbox outage delete").await?;
        ensure!(
            direct_status == StatusCode::INTERNAL_SERVER_ERROR,
            "direct lockbox delete during database outage returned {direct_status}: {direct_body}"
        );
        ensure!(
            direct_body == "500 Internal Server Error\r\n",
            "unexpected direct lockbox outage body: {direct_body}"
        );

        let mercury_delete =
            mercury_withdraw_complete_response(&mercury_client, &outage_coin).await?;
        let (mercury_status, mercury_body) =
            response_status_and_body(mercury_delete, "mercury outage completion").await?;
        ensure!(
            mercury_status == StatusCode::INTERNAL_SERVER_ERROR,
            "Mercury completion during lockbox outage returned {mercury_status}: {mercury_body}"
        );
        ensure!(
            mercury_body.contains("lockbox delete_statechain returned 500"),
            "Mercury did not classify the lockbox 500 before deletion: {mercury_body}"
        );

        let preserved_rows =
            load_mercury_deletion_rows(&mercury_pool, &outage_statechain_id).await?;
        ensure!(
            preserved_rows == MercuryDeletionRows::populated(),
            "Mercury rows changed after failed lockbox deletion: {preserved_rows:?}"
        );

        Ok::<(), anyhow::Error>(())
    }
    .await;

    let restart_result = lockbox::start_token_stack_lockbox_database(&lockbox_client).await;
    restart_result?;
    outage_assertions?;

    wait_until_lockbox_database_ready().await?;

    let completed_after_restart =
        mercury_withdraw_complete_response(&mercury_client, &outage_coin).await?;
    let (completed_status, completed_body) = response_status_and_body(
        completed_after_restart,
        "mercury completion after lockbox database restart",
    )
    .await?;
    ensure!(
        completed_status == StatusCode::OK,
        "completion after lockbox database restart returned {completed_status}: {completed_body}"
    );
    ensure!(
        completed_body == r#"{"message":"Statechain deleted."}"#,
        "unexpected successful Mercury completion body: {completed_body}"
    );
    ensure!(
        load_mercury_deletion_rows(&mercury_pool, &outage_statechain_id).await?
            == MercuryDeletionRows::absent(),
        "Mercury completion did not delete all four row classes"
    );

    let repeated_completion =
        mercury_withdraw_complete_response(&mercury_client, &outage_coin).await?;
    let (repeated_status, repeated_body) =
        response_status_and_body(repeated_completion, "repeated Mercury completion").await?;
    ensure!(
        repeated_status == StatusCode::INTERNAL_SERVER_ERROR,
        "repeated completion returned {repeated_status}: {repeated_body}"
    );
    ensure!(
        repeated_body == r#"{"message":"Signature does not match authentication key."}"#,
        "repeated completion did not follow current authentication/absence behavior: {repeated_body}"
    );
    ensure!(
        load_mercury_deletion_rows(&mercury_pool, &outage_statechain_id).await?
            == MercuryDeletionRows::absent(),
        "repeated completion recreated Mercury rows"
    );

    let partial_failure_coin =
        prepare_mercury_deletion_fixture(&mercury_client, &mercury_pool, 0x75, 0x76, 0x77, 0x78)
            .await?;
    let partial_failure_statechain_id = partial_failure_coin
        .statechain_id
        .as_deref()
        .context("partial-failure fixture missing statechain_id")?
        .to_string();

    let initial_info = mercury_client
        .get(format!(
            "{}/info/statechain/{partial_failure_statechain_id}",
            mercury::MERCURY_URL
        ))
        .send()
        .await
        .context("failed to call initial Mercury statechain info")?;
    let (initial_info_status, initial_info_body) =
        response_status_and_body(initial_info, "initial Mercury statechain info").await?;
    ensure!(
        initial_info_status == StatusCode::OK,
        "initial Mercury statechain info returned {initial_info_status}: {initial_info_body}"
    );

    let direct_delete = lockbox::delete(
        &lockbox_client,
        &format!("delete_statechain/{partial_failure_statechain_id}"),
    )
    .await?;
    let (direct_delete_status, direct_delete_body) =
        response_status_and_body(direct_delete, "partial-failure lockbox delete").await?;
    ensure!(
        direct_delete_status == StatusCode::OK,
        "direct lockbox delete returned {direct_delete_status}: {direct_delete_body}"
    );
    ensure!(
        direct_delete_body == "Statechain deleted.",
        "unexpected direct lockbox delete body: {direct_delete_body}"
    );
    ensure!(
        load_mercury_deletion_rows(&mercury_pool, &partial_failure_statechain_id).await?
            == MercuryDeletionRows::populated(),
        "direct lockbox deletion changed Mercury rows"
    );

    let lockbox_missing_info = mercury_client
        .get(format!(
            "{}/info/statechain/{partial_failure_statechain_id}",
            mercury::MERCURY_URL
        ))
        .send()
        .await
        .context("failed to call Mercury statechain info after lockbox-only deletion")?;
    let (lockbox_missing_status, lockbox_missing_body) = response_status_and_body(
        lockbox_missing_info,
        "Mercury statechain info after lockbox-only deletion",
    )
    .await?;
    ensure!(
        lockbox_missing_status == StatusCode::INTERNAL_SERVER_ERROR,
        "lockbox-only absence masqueraded as Mercury absence: {lockbox_missing_status}: {lockbox_missing_body}"
    );
    ensure!(
        lockbox_missing_body.contains("lockbox signature_count returned 404"),
        "Mercury did not report the lockbox signature-count failure: {lockbox_missing_body}"
    );

    let partial_failure_completion =
        mercury_withdraw_complete_response(&mercury_client, &partial_failure_coin).await?;
    let (partial_completion_status, partial_completion_body) = response_status_and_body(
        partial_failure_completion,
        "Mercury completion after lockbox-only deletion",
    )
    .await?;
    ensure!(
        partial_completion_status == StatusCode::OK,
        "Mercury completion after lockbox-only deletion returned {partial_completion_status}: {partial_completion_body}"
    );
    ensure!(
        partial_completion_body == r#"{"message":"Statechain deleted."}"#,
        "unexpected partial-failure completion body: {partial_completion_body}"
    );
    ensure!(
        load_mercury_deletion_rows(&mercury_pool, &partial_failure_statechain_id).await?
            == MercuryDeletionRows::absent(),
        "partial-failure completion did not delete all four Mercury row classes"
    );

    let final_info = mercury_client
        .get(format!(
            "{}/info/statechain/{partial_failure_statechain_id}",
            mercury::MERCURY_URL
        ))
        .send()
        .await
        .context("failed to call final Mercury statechain info")?;
    let (final_info_status, final_info_body) =
        response_status_and_body(final_info, "final Mercury statechain info").await?;
    ensure!(
        final_info_status == StatusCode::NOT_FOUND,
        "final Mercury statechain absence returned {final_info_status}: {final_info_body}"
    );
    ensure!(
        final_info_body == r#"{"message":"Statechain Id key not found."}"#,
        "unexpected final Mercury statechain absence body: {final_info_body}"
    );

    Ok(())
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn deterministic_lockbox_vectors_match_golden_outputs() -> Result<()> {
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    let statechain_id = DETERMINISTIC_STATECHAIN_ID;
    let partial_signature_payload = deterministic_partial_signature_payload();
    let mut production_rng_restore = ProductionRngRestoreGuard::armed();

    lockbox::recreate_lockbox_service_with_rng_seed(&client, Some(DETERMINISTIC_RNG_SEED)).await?;

    let first_created = lockbox::create_statechain(&client, statechain_id).await?;
    let nonce_payload = Bip448LockboxSignFirstRequestPayload {
        statechain_id: statechain_id.to_string(),
        signing_id: DETERMINISTIC_SIGNING_ID.to_string(),
    };
    let first_server_pubnonce = lockbox::bip448_get_public_nonce(&client, &nonce_payload).await?;
    assert_eq!(
        first_server_pubnonce.server_pubnonce,
        partial_signature_payload.server_pub_nonce
    );
    let first_partial_sig =
        lockbox::bip448_request_partial_signature(&client, &partial_signature_payload).await?;
    let first_updated_server_pubkey =
        lockbox::keyupdate(&client, statechain_id, [9u8; 32], [10u8; 32])
            .await?
            .server_pubkey;
    lockbox::delete_statechain(&client, statechain_id).await?;

    let first = DeterministicVector {
        server_pubkey: first_created.server_pubkey,
        server_pubnonce: first_server_pubnonce.server_pubnonce,
        partial_sig: first_partial_sig,
        updated_server_pubkey: first_updated_server_pubkey,
    };

    lockbox::recreate_lockbox_service_with_rng_seed(&client, Some(DETERMINISTIC_RNG_SEED)).await?;

    let second_created = lockbox::create_statechain(&client, statechain_id).await?;
    let second_server_pubnonce = lockbox::bip448_get_public_nonce(&client, &nonce_payload).await?;
    assert_eq!(
        second_server_pubnonce.server_pubnonce,
        partial_signature_payload.server_pub_nonce
    );
    let second_partial_sig =
        lockbox::bip448_request_partial_signature(&client, &partial_signature_payload).await?;
    let second_updated_server_pubkey =
        lockbox::keyupdate(&client, statechain_id, [9u8; 32], [10u8; 32])
            .await?
            .server_pubkey;
    lockbox::delete_statechain(&client, statechain_id).await?;

    let second = DeterministicVector {
        server_pubkey: second_created.server_pubkey,
        server_pubnonce: second_server_pubnonce.server_pubnonce,
        partial_sig: second_partial_sig,
        updated_server_pubkey: second_updated_server_pubkey,
    };

    assert_eq!(first, second);
    assert_eq!(
        first.server_pubkey,
        "03aefcb771d0ab2d82e1cf7b745c9e70cd8464d052b548b53fcca97dfcc9dcfcb0"
    );
    assert_eq!(
        first.server_pubnonce,
        "032f7d30ca4641d314418be9e8e11ef28e079ce684f7271bceab6e9f835adea05303b1b76528c43918e991aa847abb7b6df753dc116de95a9d811bc9b35a7f020dfb"
    );
    assert_eq!(
        first.partial_sig,
        "3ce98d8436bc256e5be176626d3de965a933ab302851ce575a98390a7ec25c21"
    );
    assert_eq!(
        first.updated_server_pubkey,
        "03b0e0d6db0474284547015b23f8e08a2fd9fe9e353688439624880af2b8444cea"
    );

    production_rng_restore.restore_now(&client).await?;

    Ok(())
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn parallel_statechains_can_sign_independently() -> Result<()> {
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    lockbox::wait_until_ready(&client).await?;

    let statechain_ids = (0..4)
        .map(|index| lockbox::new_statechain_id(&format!("parallel-{index}")))
        .collect::<Vec<_>>();

    let mut join_set = JoinSet::new();

    for statechain_id in statechain_ids {
        join_set.spawn(async move {
            let client = lockbox::http_client();
            let signing_id = hex::encode([0x61u8; 32]);
            let created = lockbox::create_statechain(&client, &statechain_id).await?;
            let server_pubnonce = lockbox::bip448_get_public_nonce(
                &client,
                &Bip448LockboxSignFirstRequestPayload {
                    statechain_id: statechain_id.clone(),
                    signing_id: signing_id.clone(),
                },
            )
            .await?;
            let partial_sig = lockbox::complete_bip448_signing_roundtrip(
                &client,
                &statechain_id,
                &signing_id,
                &created.server_pubkey,
                &server_pubnonce.server_pubnonce,
            )
            .await?;
            let sig_count = lockbox::get_signature_count(&client, &statechain_id).await?;
            lockbox::delete_statechain(&client, &statechain_id).await?;

            Ok::<_, anyhow::Error>((partial_sig, sig_count))
        });
    }

    while let Some(result) = join_set.join_next().await {
        let (partial_sig, sig_count) = result??;
        assert_eq!(hex::decode(&partial_sig)?.len(), 32);
        assert_eq!(sig_count, 1);
    }

    Ok(())
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn concurrent_exact_bip448_partial_replays_increment_signature_count_once() -> Result<()> {
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    lockbox::wait_until_ready(&client).await?;

    let statechain_id = lockbox::new_statechain_id("concurrent-sign");
    let signing_id = hex::encode([0x62u8; 32]);
    let created = lockbox::create_statechain(&client, &statechain_id).await?;
    let server_pubnonce = lockbox::bip448_get_public_nonce(
        &client,
        &Bip448LockboxSignFirstRequestPayload {
            statechain_id: statechain_id.clone(),
            signing_id: signing_id.clone(),
        },
    )
    .await?;
    let payload = Arc::new(
        lockbox::build_bip448_partial_signature_fixture(
            &statechain_id,
            &signing_id,
            &created.server_pubkey,
            &server_pubnonce.server_pubnonce,
        )?
        .payload,
    );
    let barrier = Arc::new(Barrier::new(3));
    let mut join_set = JoinSet::new();

    for _ in 0..2 {
        let client = lockbox::http_client();
        let barrier = barrier.clone();
        let payload = payload.clone();

        join_set.spawn(async move {
            barrier.wait().await;
            lockbox::bip448_request_partial_signature(&client, &payload).await
        });
    }

    barrier.wait().await;

    let mut partial_sigs = Vec::new();
    while let Some(result) = join_set.join_next().await {
        partial_sigs.push(result??);
    }

    assert_eq!(partial_sigs.len(), 2);
    assert_eq!(partial_sigs[0], partial_sigs[1]);
    assert_eq!(
        lockbox::get_signature_count(&client, &statechain_id).await?,
        1
    );

    lockbox::delete_statechain(&client, &statechain_id).await?;

    Ok(())
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn concurrent_keyupdate_replays_return_the_same_server_pubkey() -> Result<()> {
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    lockbox::wait_until_ready(&client).await?;

    let statechain_id = lockbox::new_statechain_id("concurrent-key");
    let created = lockbox::create_statechain(&client, &statechain_id).await?;
    let expected_server_pubkey =
        lockbox::expected_keyupdate_server_pubkey(&created.server_pubkey, [11u8; 32], [12u8; 32])?;
    let barrier = Arc::new(Barrier::new(3));
    let mut join_set = JoinSet::new();

    for _ in 0..2 {
        let client = lockbox::http_client();
        let barrier = barrier.clone();
        let statechain_id = statechain_id.clone();

        join_set.spawn(async move {
            barrier.wait().await;
            lockbox::keyupdate(&client, &statechain_id, [11u8; 32], [12u8; 32])
                .await
                .map(|response| response.server_pubkey)
        });
    }

    barrier.wait().await;

    let mut returned_pubkeys = Vec::new();
    while let Some(result) = join_set.join_next().await {
        returned_pubkeys.push(result??);
    }

    assert_eq!(returned_pubkeys.len(), 2);
    assert_eq!(returned_pubkeys[0], expected_server_pubkey);
    assert_eq!(returned_pubkeys[1], expected_server_pubkey);

    let signing_id = hex::encode([0x63u8; 32]);
    let server_pubnonce = lockbox::bip448_get_public_nonce(
        &client,
        &Bip448LockboxSignFirstRequestPayload {
            statechain_id: statechain_id.clone(),
            signing_id: signing_id.clone(),
        },
    )
    .await?;
    let partial_sig = lockbox::complete_bip448_signing_roundtrip(
        &client,
        &statechain_id,
        &signing_id,
        &expected_server_pubkey,
        &server_pubnonce.server_pubnonce,
    )
    .await?;

    assert_eq!(hex::decode(&partial_sig)?.len(), 32);
    assert_eq!(
        lockbox::get_signature_count(&client, &statechain_id).await?,
        1
    );

    lockbox::delete_statechain(&client, &statechain_id).await?;

    Ok(())
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn mercury_deposit_init_creates_a_lockbox_backed_statechain() -> Result<()> {
    let _guard = common::test_guard();
    let mercury_client = mercury::http_client();
    let lockbox_client = lockbox::http_client();
    mercury::wait_until_ready(&mercury_client).await?;
    lockbox::wait_until_ready(&lockbox_client).await?;

    let (_wallet, coin) = mercury::create_deposited_coin(&mercury_client).await?;
    let statechain_id = coin.statechain_id.clone().unwrap();
    assert_eq!(
        lockbox::get_signature_count(&lockbox_client, &statechain_id).await?,
        0
    );
    let server_pubnonce = lockbox::bip448_get_public_nonce(
        &lockbox_client,
        &Bip448LockboxSignFirstRequestPayload {
            statechain_id: statechain_id.clone(),
            signing_id: hex::encode([0x64u8; 32]),
        },
    )
    .await?;

    assert_eq!(server_pubnonce.server_pubnonce.len(), 132);
    assert_eq!(
        lockbox::get_signature_count(&lockbox_client, &statechain_id).await?,
        0
    );

    lockbox::delete_statechain(&lockbox_client, &statechain_id).await?;

    Ok(())
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn fresh_lockbox_schema_has_only_bip448_nonce_state_columns() -> Result<()> {
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    lockbox::wait_until_ready(&client).await?;

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(LOCKBOX_DATABASE_URL)
        .await
        .context("failed to connect to lockbox postgres")?;
    let tables: Vec<(String,)> = sqlx::query_as(
        "SELECT table_name FROM information_schema.tables \
         WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY table_name",
    )
    .fetch_all(&pool)
    .await?;
    assert_eq!(
        tables,
        vec![
            ("bip448_nonce_state".to_string(),),
            ("generated_public_key".to_string(),),
        ]
    );

    let columns: Vec<(String, String)> = sqlx::query_as(
        "SELECT table_name, column_name FROM information_schema.columns \
         WHERE table_schema = 'public' \
         AND table_name IN ('generated_public_key', 'bip448_nonce_state') \
         ORDER BY table_name, ordinal_position",
    )
    .fetch_all(&pool)
    .await?;
    let bip448_nonce_state_columns = columns
        .iter()
        .filter(|(table, _)| table == "bip448_nonce_state")
        .map(|(_, column)| column.as_str())
        .collect::<Vec<_>>();
    let generated_public_key_columns = columns
        .iter()
        .filter(|(table, _)| table == "generated_public_key")
        .map(|(_, column)| column.as_str())
        .collect::<Vec<_>>();

    assert_eq!(
        bip448_nonce_state_columns,
        vec![
            "id",
            "statechain_id",
            "signing_id",
            "public_nonce",
            "sealed_secnonce",
            "challenge",
            "negate_seckey",
            "partial_sig",
            "created_at",
            "updated_at",
        ]
    );
    assert_eq!(
        generated_public_key_columns,
        vec![
            "id",
            "statechain_id",
            "sealed_keypair",
            "public_key",
            "sig_count",
        ]
    );
    assert!(!generated_public_key_columns.contains(&"sealed_secnonce"));
    assert!(!generated_public_key_columns.contains(&"public_nonce"));

    Ok(())
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn fresh_mercury_schema_has_exact_bip448_tables_and_lease_columns() -> Result<()> {
    let _guard = common::test_guard();
    let client = mercury::http_client();
    mercury::wait_until_ready(&client).await?;

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(MERCURY_DATABASE_URL)
        .await
        .context("failed to connect to mercury postgres")?;
    let tables = sqlx::query_scalar::<_, String>(
        "SELECT table_name FROM information_schema.tables \
         WHERE table_schema = 'public' AND table_type = 'BASE TABLE' \
           AND table_name <> '_sqlx_migrations' \
         ORDER BY table_name",
    )
    .fetch_all(&pool)
    .await?;
    assert_eq!(
        tables,
        vec![
            "bip448_signature_data",
            "lightning_latch",
            "signing_nonce_leases",
            "statechain_data",
            "statechain_transfer",
            "tokens",
        ]
    );

    let lease_columns = sqlx::query_scalar::<_, String>(
        "SELECT column_name FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = 'signing_nonce_leases' \
         ORDER BY ordinal_position",
    )
    .fetch_all(&pool)
    .await?;
    assert_eq!(
        lease_columns,
        vec![
            "statechain_id",
            "signing_id",
            "lease_token",
            "created_at",
            "updated_at",
        ]
    );
    assert!(!lease_columns.iter().any(|column| column == "protocol"));

    let old_signing_tables = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM information_schema.tables \
         WHERE table_schema = 'public' \
           AND table_name IN ('statechain_signature_data', 'statechain_signing_protocol')",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(old_signing_tables, 0);

    let lease_protocol_columns = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = 'signing_nonce_leases' \
           AND column_name = 'protocol'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(lease_protocol_columns, 0);

    Ok(())
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn mercury_signing_routes_nonce_and_partial_signature_through_lockbox() -> Result<()> {
    let _guard = common::test_guard();
    let mercury_client = mercury::http_client();
    let lockbox_client = lockbox::http_client();
    mercury::wait_until_ready(&mercury_client).await?;
    lockbox::wait_until_ready(&lockbox_client).await?;

    let (_wallet, coin) = mercury::create_deposited_coin(&mercury_client).await?;
    let statechain_id = coin.statechain_id.clone().unwrap();
    let signing_id = hex::encode([0x44u8; 32]);
    let sign_first_payload = Bip448SignFirstRequestPayload {
        statechain_id: statechain_id.clone(),
        signed_statechain_id: coin.signed_statechain_id.clone().unwrap(),
        signing_id: signing_id.clone(),
    };
    let first_response = mercury::bip448_sign_first(&mercury_client, &sign_first_payload).await?;
    let repeated_first_response =
        mercury::bip448_sign_first(&mercury_client, &sign_first_payload).await?;

    assert_eq!(
        first_response.server_pubnonce,
        repeated_first_response.server_pubnonce
    );

    let (partial_signature_request, expected_challenge) =
        bip448_partial_signature_payload(&coin, &signing_id, &first_response.server_pubnonce)?;
    let partial_signature_response =
        mercury::bip448_sign_second(&mercury_client, &partial_signature_request).await?;

    assert_eq!(partial_signature_response.partial_sig.len(), 64);
    assert_eq!(
        hex::decode(&partial_signature_response.partial_sig)?.len(),
        32
    );
    assert_eq!(
        lockbox::get_signature_count(&lockbox_client, &statechain_id).await?,
        1
    );

    let statechain_info = mercury::statechain_info(&mercury_client, &statechain_id).await?;
    assert_eq!(statechain_info.num_sigs, 1);
    assert_eq!(statechain_info.statechain_info.len(), 1);
    assert_eq!(
        lockbox::normalize_hex(&statechain_info.statechain_info[0].server_pubnonce),
        first_response.server_pubnonce
    );
    assert_eq!(
        statechain_info.statechain_info[0].challenge,
        expected_challenge
    );

    lockbox::delete_statechain(&lockbox_client, &statechain_id).await?;

    Ok(())
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn mercury_statechain_info_returns_ordered_bip448_rows_and_transfer_clears_them() -> Result<()>
{
    let _guard = common::test_guard();
    let mercury_client = mercury::http_client();
    let lockbox_client = lockbox::http_client();
    mercury::wait_until_ready(&mercury_client).await?;
    lockbox::wait_until_ready(&lockbox_client).await?;
    common::bitcoin_core::ensure_wallet_ready()?;

    let (_wallet, coin) = mercury::create_deposited_coin(&mercury_client).await?;
    let statechain_id = coin
        .statechain_id
        .as_ref()
        .context("deposited coin missing statechain_id")?
        .clone();
    let first_signing_id = hex::encode([0xa5u8; 32]);
    let first_row =
        complete_bip448_signing_round(&mercury_client, &coin, first_signing_id.clone()).await?;
    let second_signing_id = hex::encode([0x5au8; 32]);
    let second_row =
        complete_bip448_signing_round(&mercury_client, &coin, second_signing_id.clone()).await?;
    let second_nonce = second_row.0.clone();
    let second_challenge = second_row.1.clone();
    let foreign_statechain_id = format!("foreign-{statechain_id}");
    let foreign_signing_id = hex::encode([0xb2u8; 32]);
    insert_completed_bip448_signature_row(&foreign_statechain_id, &foreign_signing_id).await?;

    let secp = Secp256k1::new();
    let new_user_auth_secret = SecretKey::from_secret_bytes([13u8; 32])?;
    let new_user_auth_public_key = new_user_auth_secret.public_key(&secp);
    let x1_secret_key = [14u8; 32];
    mercury::insert_statechain_transfer_row(
        &statechain_id,
        &new_user_auth_public_key,
        x1_secret_key,
    )
    .await?;

    let statechain_info = mercury::statechain_info(&mercury_client, &statechain_id).await?;
    assert_eq!(statechain_info.num_sigs, 2);
    assert_eq!(statechain_info.statechain_info.len(), 2);
    for (row, (expected_nonce, expected_challenge, expected_tx_n)) in
        statechain_info.statechain_info.iter().zip([
            (first_row.0, first_row.1, 1u32),
            (second_row.0, second_row.1, 2u32),
        ])
    {
        assert_eq!(row.statechain_id, statechain_id);
        assert_eq!(lockbox::normalize_hex(&row.server_pubnonce), expected_nonce);
        assert_eq!(row.challenge, expected_challenge);
        assert_eq!(row.tx_n, expected_tx_n);
    }

    mercury::clear_bip448_server_partial_signature(&statechain_id, &first_signing_id).await?;
    let incomplete_info = mercury::statechain_info(&mercury_client, &statechain_id).await?;
    assert_eq!(incomplete_info.num_sigs, 2);
    assert_eq!(incomplete_info.statechain_info.len(), 1);
    assert_eq!(incomplete_info.statechain_info[0].tx_n, 1);
    assert_eq!(
        lockbox::normalize_hex(&incomplete_info.statechain_info[0].server_pubnonce),
        second_nonce
    );
    assert_eq!(
        incomplete_info.statechain_info[0].challenge,
        second_challenge
    );

    let t2 = [15u8; 32];
    unlock_recipient_transfer_generation(
        &mercury_client,
        &statechain_id,
        &new_user_auth_secret,
        x1_secret_key,
    )
    .await?;
    mercury::transfer_receiver(
        &mercury_client,
        &generation_bound_receiver_request(
            &statechain_id,
            &new_user_auth_secret,
            x1_secret_key,
            t2,
        )?,
    )
    .await?;

    let post_transfer_info = mercury::statechain_info(&mercury_client, &statechain_id).await?;
    assert_eq!(post_transfer_info.num_sigs, 2);
    assert_eq!(post_transfer_info.statechain_info.len(), 1);
    assert_eq!(post_transfer_info.statechain_info[0].tx_n, 1);
    assert_eq!(
        lockbox::normalize_hex(&post_transfer_info.statechain_info[0].server_pubnonce),
        second_nonce
    );
    assert_eq!(
        post_transfer_info.statechain_info[0].challenge,
        second_challenge
    );

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(MERCURY_DATABASE_URL)
        .await
        .context("failed to connect to mercury postgres")?;
    assert!(
        load_bip448_signature_data_row(&pool, &statechain_id, &first_signing_id)
            .await?
            .is_none(),
        "the transferred statechain's exact incomplete signing row must be deleted"
    );

    let persisted_second_row =
        load_bip448_signature_data_row(&pool, &statechain_id, &second_signing_id)
            .await?
            .context("the transferred statechain's completed signing row was deleted")?;
    assert_eq!(
        lockbox::normalize_hex(
            persisted_second_row
                .server_pubnonce
                .as_deref()
                .context("completed signing row lost server_pubnonce")?
        ),
        second_nonce
    );
    assert_eq!(
        persisted_second_row.challenge.as_deref(),
        Some(second_challenge.as_str())
    );
    assert!(persisted_second_row.negate_seckey.is_some());
    assert_eq!(
        hex::decode(lockbox::normalize_hex(
            persisted_second_row
                .server_partial_sig
                .as_deref()
                .context("completed signing row lost server_partial_sig")?,
        ))?
        .len(),
        32
    );

    let persisted_foreign_row =
        load_bip448_signature_data_row(&pool, &foreign_statechain_id, &foreign_signing_id)
            .await?
            .context("foreign statechain's completed signing row was deleted")?;
    assert_eq!(
        persisted_foreign_row.server_pubnonce.as_deref(),
        Some("mixed-bip448-server-pubnonce")
    );
    assert_eq!(
        persisted_foreign_row.challenge.as_deref(),
        Some("mixed-bip448-challenge")
    );
    assert_eq!(persisted_foreign_row.negate_seckey, Some(false));
    assert_eq!(
        persisted_foreign_row.server_partial_sig.as_deref(),
        Some("mixed-bip448-partial-signature")
    );

    lockbox::delete_statechain(&lockbox_client, &statechain_id).await?;

    Ok(())
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn mercury_transfer_receiver_routes_keyupdate_to_lockbox() -> Result<()> {
    let _guard = common::test_guard();
    let mercury_client = mercury::http_client();
    let lockbox_client = lockbox::http_client();
    mercury::wait_until_ready(&mercury_client).await?;
    lockbox::wait_until_ready(&lockbox_client).await?;
    let mercury_pool = PgPoolOptions::new()
        .max_connections(16)
        .connect(MERCURY_DATABASE_URL)
        .await
        .context("failed to connect generation-fence tests to Mercury postgres")?;
    let lockbox_pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(LOCKBOX_DATABASE_URL)
        .await
        .context("failed to connect generation-fence tests to lockbox postgres")?;

    assert_sender_and_update_generation_fences(&mercury_client, &mercury_pool).await?;
    assert_unlock_generation_fences(&mercury_client, &mercury_pool, &lockbox_pool).await?;
    assert_receiver_generation_fences(&mercury_client, &mercury_pool, &lockbox_pool).await?;

    let (_wallet, coin) = mercury::create_deposited_coin(&mercury_client).await?;
    let statechain_id = coin.statechain_id.clone().unwrap();
    let original_server_pubkey = coin.server_pubkey.clone().unwrap();

    let secp = Secp256k1::new();
    let new_user_auth_secret = SecretKey::from_secret_bytes([13u8; 32])?;
    let new_user_auth_public_key = new_user_auth_secret.public_key(&secp);
    let x1_secret_key = [14u8; 32];
    let t2 = [15u8; 32];
    mercury::insert_statechain_transfer_row(
        &statechain_id,
        &new_user_auth_public_key,
        x1_secret_key,
    )
    .await?;

    unlock_recipient_transfer_generation(
        &mercury_client,
        &statechain_id,
        &new_user_auth_secret,
        x1_secret_key,
    )
    .await?;
    let request_payload = generation_bound_receiver_request(
        &statechain_id,
        &new_user_auth_secret,
        x1_secret_key,
        t2,
    )?;
    let expected_server_pubkey =
        lockbox::expected_keyupdate_server_pubkey(&original_server_pubkey, t2, x1_secret_key)?;

    let first_response = mercury::transfer_receiver(&mercury_client, &request_payload).await?;
    let repeated_response = mercury::transfer_receiver(&mercury_client, &request_payload).await?;

    assert_eq!(first_response.server_pubkey, expected_server_pubkey);
    assert_eq!(repeated_response.server_pubkey, expected_server_pubkey);

    let statechain_info = mercury::statechain_info(&mercury_client, &statechain_id).await?;
    assert_eq!(
        statechain_info.x1_pub,
        Some(
            SecretKey::from_secret_bytes(x1_secret_key)?
                .public_key(&secp)
                .to_string()
        )
    );

    let updated_signing_id = hex::encode([0x65u8; 32]);
    let server_pubnonce = lockbox::bip448_get_public_nonce(
        &lockbox_client,
        &Bip448LockboxSignFirstRequestPayload {
            statechain_id: statechain_id.clone(),
            signing_id: updated_signing_id.clone(),
        },
    )
    .await?;
    assert_eq!(server_pubnonce.server_pubnonce.len(), 132);
    let updated_partial_signature_fixture = lockbox::build_bip448_partial_signature_fixture(
        &statechain_id,
        &updated_signing_id,
        &expected_server_pubkey,
        &server_pubnonce.server_pubnonce,
    )?;
    let partial_sig = lockbox::bip448_request_partial_signature(
        &lockbox_client,
        &updated_partial_signature_fixture.payload,
    )
    .await?;
    updated_partial_signature_fixture.verify_server_partial_signature(&partial_sig)?;
    assert_eq!(hex::decode(&partial_sig)?.len(), 32);
    assert_eq!(
        lockbox::get_signature_count(&lockbox_client, &statechain_id).await?,
        1
    );

    lockbox::delete_statechain(&lockbox_client, &statechain_id).await?;

    Ok(())
}
