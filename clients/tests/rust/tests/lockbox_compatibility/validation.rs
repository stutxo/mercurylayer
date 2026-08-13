use super::support::*;
use super::*;

pub(super) async fn get_public_key_requires_statechain_id() -> Result<()> {
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

pub(super) async fn bip448_get_public_nonce_requires_existing_statechain() -> Result<()> {
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

pub(super) async fn bip448_get_partial_signature_validates_session_length() -> Result<()> {
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

pub(super) async fn bip448_get_partial_signature_requires_existing_nonce_state() -> Result<()> {
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

pub(super) async fn keyupdate_validates_t2_and_x1_lengths() -> Result<()> {
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

pub(super) async fn keyupdate_requires_existing_statechain() -> Result<()> {
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

pub(super) async fn signature_count_for_missing_statechain_returns_not_found() -> Result<()> {
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
