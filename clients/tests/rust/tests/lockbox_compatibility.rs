mod common;

use std::sync::Arc;

use anyhow::{Context, Result};
use mercurylib::{deposit, transaction, transfer::receiver::TransferReceiverRequestPayload};
use reqwest::StatusCode;
use secp256k1::{Secp256k1, SecretKey};
use serde_json::json;
use tokio::{sync::Barrier, task::JoinSet};

use crate::common::{lockbox, mercury};

const DETERMINISTIC_RNG_SEED: &str =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const DETERMINISTIC_STATECHAIN_ID: &str = "deterministic-vector";

#[derive(Debug, PartialEq, Eq)]
struct DeterministicVector {
    server_pubkey: String,
    server_pubnonce: String,
    partial_sig: String,
    updated_server_pubkey: String,
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

fn dummy_session_hex() -> String {
    "00".repeat(133)
}

fn mutate_bip448_session_challenge(session_hex: &str) -> Result<String> {
    const CHALLENGE_OFFSET: usize = 4 + 1 + 32 + 32;
    let mut session = hex::decode(session_hex)?;
    session[CHALLENGE_OFFSET] ^= 0x01;
    Ok(hex::encode(session))
}

fn deterministic_partial_signature_payload() -> transaction::PartialSignatureRequestPayload {
    transaction::PartialSignatureRequestPayload {
        statechain_id: DETERMINISTIC_STATECHAIN_ID.to_string(),
        negate_seckey: 0,
        session: "9dede917000000000000000000000000000000000000000000000000000000000000000000b59faf7e0a44057b41d273e70cc0a59194347b286c8108fef3519bb52fe64b0729641b33afc4d71464ccde0ca4b0471ed2fda81a39056745ed7b1f4f90790dfd3ee2e8c6c5937a7f4dd30e9e78ec2096433ff32ea89ffca29a40b02b03b4e7eb".to_string(),
        signed_statechain_id: "469b4d8151ba9fbc78d178a7bbe30b80539b52df385647539ab3bfb0d1fade376ccb6e6909d298b31615cd38a8435bf3c92692389ffbadf4b33688976d2bb4ea".to_string(),
        server_pub_nonce: "032f7d30ca4641d314418be9e8e11ef28e079ce684f7271bceab6e9f835adea05303b1b76528c43918e991aa847abb7b6df753dc116de95a9d811bc9b35a7f020dfb".to_string(),
    }
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
async fn get_public_nonce_requires_existing_statechain() -> Result<()> {
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    lockbox::wait_until_ready(&client).await?;

    let response = lockbox::post_json(
        &client,
        "get_public_nonce",
        json!({ "statechain_id": lockbox::new_statechain_id("missing-nonce") }),
    )
    .await?;
    let status = response.status();
    let body = response
        .text()
        .await
        .context("failed to read get_public_nonce body")?;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(body.contains("Failed to load aggregated key data"));

    Ok(())
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn get_partial_signature_validates_session_length() -> Result<()> {
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    lockbox::wait_until_ready(&client).await?;

    let response = lockbox::post_json(
        &client,
        "get_partial_signature",
        json!({
            "statechain_id": lockbox::new_statechain_id("bad-session"),
            "negate_seckey": 0,
            "session": "00",
        }),
    )
    .await?;
    let status = response.status();
    let body = response
        .text()
        .await
        .context("failed to read get_partial_signature body")?;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, "Invalid session length. Must be 133 bytes!");

    Ok(())
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn get_partial_signature_requires_existing_statechain() -> Result<()> {
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    lockbox::wait_until_ready(&client).await?;

    let response = lockbox::post_json(
        &client,
        "get_partial_signature",
        json!({
            "statechain_id": lockbox::new_statechain_id("missing-sign"),
            "negate_seckey": 0,
            "session": dummy_session_hex(),
        }),
    )
    .await?;

    assert_missing_statechain_error(response, "missing partial signature").await
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
async fn signing_lifecycle_returns_a_valid_partial_signature_and_increments_signature_count(
) -> Result<()> {
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    lockbox::wait_until_ready(&client).await?;

    let statechain_id = lockbox::new_statechain_id("signing-lifecycle");
    let created = lockbox::create_statechain(&client, &statechain_id).await?;
    let server_pubnonce = lockbox::get_public_nonce(&client, &statechain_id).await?;
    let signed_tx = lockbox::complete_signing_roundtrip(
        &client,
        &statechain_id,
        &created.server_pubkey,
        &server_pubnonce.server_pubnonce,
    )
    .await?;

    assert_eq!(signed_tx.input.len(), 1);
    assert_eq!(signed_tx.output.len(), 1);
    assert_eq!(signed_tx.input[0].witness.len(), 1);

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
    let t2 = [1u8; 32];
    let x1 = [2u8; 32];
    let expected_server_pubkey =
        lockbox::expected_keyupdate_server_pubkey(&created.server_pubkey, t2, x1)?;

    let new_key = lockbox::keyupdate(&client, &statechain_id, t2, x1).await?;

    assert_ne!(new_key.server_pubkey, created.server_pubkey);
    assert_eq!(new_key.server_pubkey, expected_server_pubkey);

    let new_server_pubnonce = lockbox::get_public_nonce(&client, &statechain_id).await?;
    assert_eq!(new_server_pubnonce.server_pubnonce.len(), 132);

    lockbox::delete_statechain(&client, &statechain_id).await?;

    Ok(())
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn nonce_generated_signing_state_survives_lockbox_restart() -> Result<()> {
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    lockbox::wait_until_ready(&client).await?;

    let statechain_id = lockbox::new_statechain_id("restart-sign");
    let created = lockbox::create_statechain(&client, &statechain_id).await?;
    let server_pubnonce = lockbox::get_public_nonce(&client, &statechain_id).await?;

    lockbox::restart_lockbox_service(&client).await?;

    let signed_tx = lockbox::complete_signing_roundtrip(
        &client,
        &statechain_id,
        &created.server_pubkey,
        &server_pubnonce.server_pubnonce,
    )
    .await?;

    assert_eq!(signed_tx.input.len(), 1);
    assert_eq!(signed_tx.output.len(), 1);
    assert_eq!(signed_tx.input[0].witness.len(), 1);
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
    let server_pubnonce =
        lockbox::bip448_get_public_nonce(&client, &statechain_id, &signing_id).await?;
    let repeated_server_pubnonce =
        lockbox::bip448_get_public_nonce(&client, &statechain_id, &signing_id).await?;
    assert_eq!(
        repeated_server_pubnonce.server_pubnonce,
        server_pubnonce.server_pubnonce
    );

    let payload = lockbox::build_partial_signature_fixture(
        &statechain_id,
        &created.server_pubkey,
        &server_pubnonce.server_pubnonce,
    )?
    .partial_signature_request_payload;

    let partial = lockbox::bip448_request_partial_signature(&client, &signing_id, &payload).await?;
    assert_eq!(partial.len(), 64);
    assert_eq!(
        lockbox::get_signature_count(&client, &statechain_id).await?,
        1
    );

    lockbox::restart_lockbox_service(&client).await?;

    let replay = lockbox::bip448_request_partial_signature(&client, &signing_id, &payload).await?;
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

    let server_pubnonce = lockbox::get_public_nonce(&client, &statechain_id).await?;
    let signed_tx = lockbox::complete_signing_roundtrip(
        &client,
        &statechain_id,
        &updated_key.server_pubkey,
        &server_pubnonce.server_pubnonce,
    )
    .await?;

    assert_eq!(signed_tx.input.len(), 1);
    assert_eq!(signed_tx.output.len(), 1);
    assert_eq!(signed_tx.input[0].witness.len(), 1);
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
    let _created = lockbox::create_statechain(&client, &statechain_id).await?;

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
        "get_public_nonce",
        json!({ "statechain_id": statechain_id }),
    )
    .await?;
    assert_missing_statechain_error(nonce_response, "post-delete get_public_nonce").await?;

    let partial_signature_response = lockbox::post_json(
        &client,
        "get_partial_signature",
        json!({
            "statechain_id": statechain_id,
            "negate_seckey": 0,
            "session": dummy_session_hex(),
        }),
    )
    .await?;
    assert_missing_statechain_error(
        partial_signature_response,
        "post-delete get_partial_signature",
    )
    .await?;

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
async fn deterministic_lockbox_vectors_match_golden_outputs() -> Result<()> {
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    let statechain_id = DETERMINISTIC_STATECHAIN_ID;
    let partial_signature_payload = deterministic_partial_signature_payload();
    let mut production_rng_restore = ProductionRngRestoreGuard::armed();

    lockbox::recreate_lockbox_service_with_rng_seed(&client, Some(DETERMINISTIC_RNG_SEED)).await?;

    let first_created = lockbox::create_statechain(&client, statechain_id).await?;
    let first_server_pubnonce = lockbox::get_public_nonce(&client, statechain_id).await?;
    assert_eq!(
        first_server_pubnonce.server_pubnonce,
        partial_signature_payload.server_pub_nonce
    );
    let first_partial_sig =
        lockbox::request_partial_signature(&client, &partial_signature_payload).await?;
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
    let second_server_pubnonce = lockbox::get_public_nonce(&client, statechain_id).await?;
    assert_eq!(
        second_server_pubnonce.server_pubnonce,
        partial_signature_payload.server_pub_nonce
    );
    let second_partial_sig =
        lockbox::request_partial_signature(&client, &partial_signature_payload).await?;
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
            let created = lockbox::create_statechain(&client, &statechain_id).await?;
            let server_pubnonce = lockbox::get_public_nonce(&client, &statechain_id).await?;
            let signed_tx = lockbox::complete_signing_roundtrip(
                &client,
                &statechain_id,
                &created.server_pubkey,
                &server_pubnonce.server_pubnonce,
            )
            .await?;
            let sig_count = lockbox::get_signature_count(&client, &statechain_id).await?;
            lockbox::delete_statechain(&client, &statechain_id).await?;

            Ok::<_, anyhow::Error>((signed_tx, sig_count))
        });
    }

    while let Some(result) = join_set.join_next().await {
        let (signed_tx, sig_count) = result??;
        assert_eq!(signed_tx.input.len(), 1);
        assert_eq!(signed_tx.output.len(), 1);
        assert_eq!(signed_tx.input[0].witness.len(), 1);
        assert_eq!(sig_count, 1);
    }

    Ok(())
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn concurrent_partial_signature_replays_increment_signature_count() -> Result<()> {
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    lockbox::wait_until_ready(&client).await?;

    let statechain_id = lockbox::new_statechain_id("concurrent-sign");
    let created = lockbox::create_statechain(&client, &statechain_id).await?;
    let server_pubnonce = lockbox::get_public_nonce(&client, &statechain_id).await?;
    let payload = Arc::new(
        lockbox::build_partial_signature_fixture(
            &statechain_id,
            &created.server_pubkey,
            &server_pubnonce.server_pubnonce,
        )?
        .partial_signature_request_payload,
    );
    let barrier = Arc::new(Barrier::new(3));
    let mut join_set = JoinSet::new();

    for _ in 0..2 {
        let client = lockbox::http_client();
        let barrier = barrier.clone();
        let payload = payload.clone();

        join_set.spawn(async move {
            barrier.wait().await;
            lockbox::request_partial_signature(&client, &payload).await
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
        2
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

    let server_pubnonce = lockbox::get_public_nonce(&client, &statechain_id).await?;
    let signed_tx = lockbox::complete_signing_roundtrip(
        &client,
        &statechain_id,
        &expected_server_pubkey,
        &server_pubnonce.server_pubnonce,
    )
    .await?;

    assert_eq!(signed_tx.input.len(), 1);
    assert_eq!(signed_tx.output.len(), 1);
    assert_eq!(signed_tx.input[0].witness.len(), 1);

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
    let server_pubnonce = lockbox::get_public_nonce(&lockbox_client, &statechain_id).await?;

    assert_eq!(server_pubnonce.server_pubnonce.len(), 132);

    lockbox::delete_statechain(&lockbox_client, &statechain_id).await?;

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

    let (wallet, mut coin) = mercury::create_deposited_coin(&mercury_client).await?;
    let statechain_id = coin.statechain_id.clone().unwrap();
    let aggregated = deposit::create_aggregated_address(&coin, wallet.network.clone())?;
    coin.aggregated_pubkey = Some(aggregated.aggregate_pubkey);
    coin.aggregated_address = Some(aggregated.aggregate_address);
    coin.utxo_txid = Some(hex::encode([0x22u8; 32]));
    coin.utxo_vout = Some(0);
    coin.amount = Some(100_000);

    let coin_nonce = transaction::create_and_commit_nonces(&coin)?;
    let first_response =
        mercury::sign_first(&mercury_client, &coin_nonce.sign_first_request_payload).await?;
    let repeated_first_response =
        mercury::sign_first(&mercury_client, &coin_nonce.sign_first_request_payload).await?;

    assert_eq!(
        first_response.server_pubnonce,
        repeated_first_response.server_pubnonce
    );

    coin.secret_nonce = Some(coin_nonce.secret_nonce);
    coin.public_nonce = Some(coin_nonce.public_nonce);
    coin.blinding_factor = Some(coin_nonce.blinding_factor);
    coin.server_public_nonce = Some(first_response.server_pubnonce.clone());

    let partial_signature_request = transaction::get_partial_sig_request(
        &coin,
        1_500,
        wallet.initlock,
        wallet.interval,
        1.5,
        0,
        coin.backup_address.clone(),
        wallet.network.clone(),
        false,
    )?;
    let partial_signature_response = mercury::sign_second(
        &mercury_client,
        &partial_signature_request.partial_signature_request_payload,
    )
    .await?;

    assert_eq!(partial_signature_response.partial_sig.len(), 64);
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
    assert!(!statechain_info.statechain_info[0].challenge.is_empty());

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

    let server_pubnonce = lockbox::get_public_nonce(&lockbox_client, &statechain_id).await?;
    assert_eq!(server_pubnonce.server_pubnonce.len(), 132);

    lockbox::delete_statechain(&lockbox_client, &statechain_id).await?;

    Ok(())
}
