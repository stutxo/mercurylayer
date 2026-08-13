use super::keyupdate_fences::*;
use super::support::*;
use super::*;

pub(super) async fn keyupdate_returns_the_expected_server_pubkey_and_statechain_remains_usable(
) -> Result<()> {
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

pub(super) async fn keyupdate_state_survives_lockbox_restart() -> Result<()> {
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

pub(super) async fn mercury_transfer_receiver_routes_keyupdate_to_lockbox() -> Result<()> {
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
