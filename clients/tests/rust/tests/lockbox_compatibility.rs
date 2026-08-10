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
    transfer::receiver::TransferReceiverRequestPayload,
    withdraw::WithdrawCompletePayload,
};
use reqwest::StatusCode;
use secp256k1::{
    musig::{new_musig_nonce_pair, BlindingFactor, MusigSessionId, PublicNonce},
    rand, PublicKey, Secp256k1, SecretKey,
};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use tokio::{sync::Barrier, task::JoinSet, time::sleep};

use crate::common::{lockbox, mercury};

const DETERMINISTIC_RNG_SEED: &str =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const DETERMINISTIC_STATECHAIN_ID: &str = "deterministic-vector";
const DETERMINISTIC_SIGNING_ID: &str =
    "d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1";
const MERCURY_DATABASE_URL: &str = "postgres://postgres:postgres@127.0.0.1:5432/mercury";
const LOCKBOX_DATABASE_URL: &str = "postgres://postgres:postgres@127.0.0.1:5433/enclave";

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

    let t2_hex = hex::encode([15u8; 32]);
    mercury::transfer_receiver(
        &mercury_client,
        &TransferReceiverRequestPayload {
            statechain_id: statechain_id.clone(),
            batch_data: None,
            t2: t2_hex.clone(),
            auth_sig: mercury::sign_t2_hex(&new_user_auth_secret, &t2_hex)?,
        },
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

    let (_wallet, coin) = mercury::create_deposited_coin(&mercury_client).await?;
    let statechain_id = coin.statechain_id.clone().unwrap();
    let original_server_pubkey = coin.server_pubkey.clone().unwrap();

    let secp = Secp256k1::new();
    let new_user_auth_secret = SecretKey::from_secret_bytes([13u8; 32])?;
    let new_user_auth_public_key = new_user_auth_secret.public_key(&secp);
    let x1_secret_key = [14u8; 32];
    let t2 = [15u8; 32];
    let t2_hex = hex::encode(t2);

    mercury::insert_statechain_transfer_row(
        &statechain_id,
        &new_user_auth_public_key,
        x1_secret_key,
    )
    .await?;

    let request_payload = TransferReceiverRequestPayload {
        statechain_id: statechain_id.clone(),
        batch_data: None,
        t2: t2_hex.clone(),
        auth_sig: mercury::sign_t2_hex(&new_user_auth_secret, &t2_hex)?,
    };
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
