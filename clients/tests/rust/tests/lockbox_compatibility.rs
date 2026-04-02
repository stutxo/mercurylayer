mod common;

use anyhow::{Context, Result};
use bitcoin::Transaction;
use reqwest::StatusCode;
use serde_json::json;

use crate::common::lockbox;

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
async fn signing_lifecycle_returns_a_valid_partial_signature_and_increments_signature_count(
) -> Result<()> {
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    lockbox::wait_until_ready(&client).await?;

    let statechain_id = lockbox::new_statechain_id("signing-lifecycle");
    let created = lockbox::create_statechain(&client, &statechain_id).await?;
    let server_pubnonce = lockbox::get_public_nonce(&client, &statechain_id).await?;
    let msg1 = lockbox::build_partial_signature_fixture(
        &statechain_id,
        &created.server_pubkey,
        &server_pubnonce.server_pubnonce,
    )?;

    let response = lockbox::post_json(
        &client,
        "get_partial_signature",
        serde_json::to_value(&msg1.partial_signature_request_payload)?,
    )
    .await?;
    let response_status = response.status();
    let response_body = response
        .text()
        .await
        .context("failed to read partial_sig body")?;

    assert_eq!(response_status, StatusCode::OK);

    let mut partial_signature: lockbox::PartialSignatureResponse =
        serde_json::from_str(&response_body)?;
    partial_signature.partial_sig = lockbox::normalize_hex(&partial_signature.partial_sig);

    let aggregated_signature = mercurylib::transaction::create_signature(
        msg1.msg,
        msg1.client_partial_sig,
        partial_signature.partial_sig,
        msg1.encoded_session,
        msg1.output_pubkey,
    )?;
    let signed_tx_hex = mercurylib::transaction::new_backup_transaction(
        msg1.encoded_unsigned_tx,
        aggregated_signature,
    )?;
    let signed_tx: Transaction = bitcoin::consensus::deserialize(&hex::decode(&signed_tx_hex)?)
        .context("failed to decode signed tx")?;

    assert_eq!(signed_tx.input.len(), 1);
    assert_eq!(signed_tx.output.len(), 1);
    assert_eq!(signed_tx.input[0].witness.len(), 1);

    let sig_count_response =
        lockbox::get(&client, &format!("signature_count/{}", statechain_id)).await?;
    let sig_count_status = sig_count_response.status();
    let sig_count_body = sig_count_response
        .text()
        .await
        .context("failed to read sig_count body")?;

    assert_eq!(sig_count_status, StatusCode::OK);

    let sig_count: lockbox::SignatureCountResponse = serde_json::from_str(&sig_count_body)?;

    assert_eq!(sig_count.sig_count, 1);

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

    let keyupdate_response = lockbox::post_json(
        &client,
        "keyupdate",
        json!({
            "statechain_id": statechain_id.clone(),
            "t2": hex::encode(t2),
            "x1": hex::encode(x1),
        }),
    )
    .await?;
    let keyupdate_status = keyupdate_response.status();
    let keyupdate_body = keyupdate_response
        .text()
        .await
        .context("failed to read keyupdate body")?;

    assert_eq!(keyupdate_status, StatusCode::OK);

    let mut new_key: lockbox::ServerPubkeyResponse = serde_json::from_str(&keyupdate_body)?;
    new_key.server_pubkey = lockbox::normalize_hex(&new_key.server_pubkey);

    assert_ne!(new_key.server_pubkey, created.server_pubkey);
    assert_eq!(new_key.server_pubkey, expected_server_pubkey);

    let new_server_pubnonce = lockbox::get_public_nonce(&client, &statechain_id).await?;
    assert_eq!(new_server_pubnonce.server_pubnonce.len(), 132);

    lockbox::delete_statechain(&client, &statechain_id).await?;

    Ok(())
}
