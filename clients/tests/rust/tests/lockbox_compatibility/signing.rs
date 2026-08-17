use super::support::*;
use super::*;

fn mutate_bip448_session_challenge(session_hex: &str) -> Result<String> {
    const CHALLENGE_OFFSET: usize = 4 + 1 + 32 + 32;
    let mut session = hex::decode(session_hex)?;
    session[CHALLENGE_OFFSET] ^= 0x01;
    Ok(hex::encode(session))
}

pub(super) async fn bip448_signing_lifecycle_returns_a_valid_partial_signature_and_increments_signature_count(
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
    let state = lockbox::get_bip448_state(&client, &statechain_id).await?;
    assert_eq!(state.sig_count.get(), 1);
    assert_eq!(state.key_generation.get(), 0);
    assert_eq!(
        hex::encode(state.server_pubkey.as_bytes()),
        created.server_pubkey
    );

    lockbox::delete_statechain(&client, &statechain_id).await?;

    Ok(())
}

pub(super) async fn bip448_nonce_state_replays_after_restart_and_rejects_conflicting_challenge(
) -> Result<()> {
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
        lockbox::bip448_partial_request_value(&client, &conflicting_payload).await?,
    )
    .await?;
    let conflict_status = conflict.status();
    let conflict_body = conflict
        .text()
        .await
        .context("failed to read BIP448 conflict body")?;
    assert_eq!(conflict_status, StatusCode::CONFLICT);
    assert_eq!(
        serde_json::from_str::<Value>(&conflict_body)?["code"],
        "bip448_operation_conflict"
    );
    assert_eq!(
        lockbox::get_signature_count(&client, &statechain_id).await?,
        1
    );

    lockbox::delete_statechain(&client, &statechain_id).await?;

    Ok(())
}

pub(super) async fn mercury_signing_routes_nonce_and_partial_signature_through_lockbox(
) -> Result<()> {
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
