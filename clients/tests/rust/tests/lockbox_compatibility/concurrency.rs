use super::*;

async fn assert_conflict_code(response: reqwest::Response, expected: &str) -> Result<()> {
    let status = response.status();
    let body: Value = serde_json::from_str(&response.text().await?)?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], expected);
    Ok(())
}

async fn assert_sign_before_keyupdate(client: &reqwest::Client) -> Result<()> {
    let statechain_id = lockbox::new_statechain_id("sign-first-win");
    let signing_id = hex::encode([0x65_u8; 32]);
    let created = lockbox::create_statechain(client, &statechain_id).await?;
    let nonce = lockbox::bip448_get_public_nonce(
        client,
        &Bip448LockboxSignFirstRequestPayload {
            statechain_id: statechain_id.clone(),
            signing_id: signing_id.clone(),
        },
    )
    .await?;
    let fixture = lockbox::build_bip448_partial_signature_fixture(
        &statechain_id,
        &signing_id,
        &created.server_pubkey,
        &nonce.server_pubnonce,
    )?;
    let sign_body = lockbox::bip448_partial_request_value(client, &fixture.payload).await?;
    let key_request =
        lockbox::build_keyupdate_request(client, &statechain_id, [15_u8; 32], [16_u8; 32]).await?;
    let key_body = serde_json::to_value(&key_request)?;

    let response =
        lockbox::post_json(client, "bip448/get_partial_signature", sign_body.clone()).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_str(&response.text().await?)?;
    let partial = body["partial_sig"]
        .as_str()
        .context("sign-first ordering omitted partial_sig")?;
    fixture.verify_server_partial_signature(partial)?;
    let state = lockbox::get_bip448_state(client, &statechain_id).await?;
    assert_eq!(state.sig_count.get(), 1);
    assert_eq!(state.key_generation.get(), 0);
    assert_eq!(
        hex::encode(state.server_pubkey.as_bytes()),
        created.server_pubkey
    );

    let replay = lockbox::post_json(client, "bip448/get_partial_signature", sign_body).await?;
    assert_eq!(replay.status(), StatusCode::OK);
    let replay_body: Value = serde_json::from_str(&replay.text().await?)?;
    assert_eq!(replay_body["partial_sig"], partial);
    assert_conflict_code(
        lockbox::post_json(client, "keyupdate", key_body.clone()).await?,
        "bip448_signature_count_mismatch",
    )
    .await?;
    assert_conflict_code(
        lockbox::post_json(client, "keyupdate", key_body).await?,
        "bip448_signature_count_mismatch",
    )
    .await?;
    assert_eq!(
        lockbox::get_bip448_state(client, &statechain_id).await?,
        state
    );
    lockbox::delete_statechain(client, &statechain_id).await?;
    Ok(())
}

async fn assert_keyupdate_before_sign(client: &reqwest::Client) -> Result<()> {
    let statechain_id = lockbox::new_statechain_id("key-first-win");
    let signing_id = hex::encode([0x66_u8; 32]);
    let created = lockbox::create_statechain(client, &statechain_id).await?;
    let nonce = lockbox::bip448_get_public_nonce(
        client,
        &Bip448LockboxSignFirstRequestPayload {
            statechain_id: statechain_id.clone(),
            signing_id: signing_id.clone(),
        },
    )
    .await?;
    let fixture = lockbox::build_bip448_partial_signature_fixture(
        &statechain_id,
        &signing_id,
        &created.server_pubkey,
        &nonce.server_pubnonce,
    )?;
    let old_sign_body = lockbox::bip448_partial_request_value(client, &fixture.payload).await?;
    let t2 = [17_u8; 32];
    let x1 = [18_u8; 32];
    let key_request = lockbox::build_keyupdate_request(client, &statechain_id, t2, x1).await?;
    let expected_key = lockbox::expected_keyupdate_server_pubkey(&created.server_pubkey, t2, x1)?;

    let receipt = lockbox::keyupdate_request(client, &key_request).await?;
    assert_eq!(receipt.operation_id, key_request.operation_id);
    assert_eq!(receipt.accepted_sig_count.get(), 0);
    assert_eq!(receipt.previous_key_generation.get(), 0);
    assert_eq!(receipt.resulting_key_generation.get(), 1);
    assert_eq!(
        hex::encode(receipt.previous_server_pubkey.as_bytes()),
        created.server_pubkey
    );
    assert_eq!(
        hex::encode(receipt.resulting_server_pubkey.as_bytes()),
        expected_key
    );
    let state = lockbox::get_bip448_state(client, &statechain_id).await?;
    assert_eq!(state.sig_count.get(), 0);
    assert_eq!(state.key_generation.get(), 1);
    assert_eq!(hex::encode(state.server_pubkey.as_bytes()), expected_key);

    assert_conflict_code(
        lockbox::post_json(client, "bip448/get_partial_signature", old_sign_body).await?,
        "bip448_key_generation_mismatch",
    )
    .await?;
    let deleted_nonce = lockbox::post_json(
        client,
        "bip448/get_partial_signature",
        lockbox::bip448_partial_request_value(client, &fixture.payload).await?,
    )
    .await?;
    assert_eq!(deleted_nonce.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        lockbox::keyupdate_request(client, &key_request).await?,
        receipt
    );
    assert_eq!(
        lockbox::get_bip448_state(client, &statechain_id).await?,
        state
    );
    lockbox::delete_statechain(client, &statechain_id).await?;
    Ok(())
}

pub(super) async fn parallel_statechains_can_sign_independently() -> Result<()> {
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

pub(super) async fn concurrent_exact_bip448_partial_replays_increment_signature_count_once(
) -> Result<()> {
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

    assert_sign_before_keyupdate(&client).await?;
    assert_keyupdate_before_sign(&client).await?;

    let race_statechain_id = lockbox::new_statechain_id("sign-key-race");
    let race_signing_id = hex::encode([0x64_u8; 32]);
    let race_created = lockbox::create_statechain(&client, &race_statechain_id).await?;
    let race_nonce = lockbox::bip448_get_public_nonce(
        &client,
        &Bip448LockboxSignFirstRequestPayload {
            statechain_id: race_statechain_id.clone(),
            signing_id: race_signing_id.clone(),
        },
    )
    .await?;
    let race_fixture = lockbox::build_bip448_partial_signature_fixture(
        &race_statechain_id,
        &race_signing_id,
        &race_created.server_pubkey,
        &race_nonce.server_pubnonce,
    )?;
    let sign_body = lockbox::bip448_partial_request_value(&client, &race_fixture.payload).await?;
    let key_request =
        lockbox::build_keyupdate_request(&client, &race_statechain_id, [13_u8; 32], [14_u8; 32])
            .await?;
    let key_body = serde_json::to_value(&key_request)?;
    let race_resulting_key = lockbox::expected_keyupdate_server_pubkey(
        &race_created.server_pubkey,
        [13_u8; 32],
        [14_u8; 32],
    )?;
    let start = Arc::new(Barrier::new(3));

    let sign_handle = tokio::spawn({
        let start = start.clone();
        async move {
            let client = lockbox::http_client();
            start.wait().await;
            lockbox::post_json(&client, "bip448/get_partial_signature", sign_body).await
        }
    });
    let key_handle = tokio::spawn({
        let start = start.clone();
        async move {
            let client = lockbox::http_client();
            start.wait().await;
            lockbox::post_json(&client, "keyupdate", key_body).await
        }
    });
    start.wait().await;

    let sign_response = sign_handle.await??;
    let key_response = key_handle.await??;
    let sign_status = sign_response.status();
    let key_status = key_response.status();
    let sign_response_body = sign_response.text().await?;
    let key_response_body = key_response.text().await?;
    assert_ne!(sign_status.is_success(), key_status.is_success());

    let race_state = lockbox::get_bip448_state(&client, &race_statechain_id).await?;
    if sign_status.is_success() {
        assert_eq!(key_status, StatusCode::CONFLICT);
        let partial = serde_json::from_str::<Value>(&sign_response_body)?["partial_sig"]
            .as_str()
            .context("race partial response omitted partial_sig")?
            .to_owned();
        race_fixture.verify_server_partial_signature(&partial)?;
        assert_eq!(race_state.sig_count.get(), 1);
        assert_eq!(race_state.key_generation.get(), 0);
        assert_eq!(
            hex::encode(race_state.server_pubkey.as_bytes()),
            race_created.server_pubkey
        );
        assert_eq!(
            serde_json::from_str::<Value>(&key_response_body)?["code"],
            "bip448_signature_count_mismatch"
        );
        assert_eq!(
            lockbox::bip448_request_partial_signature(&client, &race_fixture.payload).await?,
            partial
        );
    } else {
        assert_eq!(sign_status, StatusCode::CONFLICT);
        assert_eq!(key_status, StatusCode::OK);
        let applied_receipt = serde_json::from_str::<
            mercurylib::bip448_statechain::signing_api::Bip448KeyUpdateAppliedReceiptPayloadV2,
        >(&key_response_body)?;
        assert_eq!(race_state.sig_count.get(), 0);
        assert_eq!(race_state.key_generation.get(), 1);
        assert_eq!(
            hex::encode(race_state.server_pubkey.as_bytes()),
            race_resulting_key
        );
        assert_eq!(
            serde_json::from_str::<Value>(&sign_response_body)?["code"],
            "bip448_key_generation_mismatch"
        );
        let receipt = lockbox::keyupdate_request(&client, &key_request).await?;
        assert_eq!(receipt, applied_receipt);
        assert_eq!(receipt.operation_id, key_request.operation_id);
        assert_eq!(
            hex::encode(receipt.resulting_server_pubkey.as_bytes()),
            race_resulting_key
        );
        let stale_nonce = lockbox::post_json(
            &client,
            "bip448/get_partial_signature",
            lockbox::bip448_partial_request_value(&client, &race_fixture.payload).await?,
        )
        .await?;
        assert_eq!(stale_nonce.status(), StatusCode::NOT_FOUND);
    }
    lockbox::delete_statechain(&client, &race_statechain_id).await?;

    Ok(())
}

pub(super) async fn concurrent_keyupdate_replays_return_the_same_server_pubkey() -> Result<()> {
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    lockbox::wait_until_ready(&client).await?;

    let statechain_id = lockbox::new_statechain_id("concurrent-key");
    let created = lockbox::create_statechain(&client, &statechain_id).await?;
    let expected_server_pubkey =
        lockbox::expected_keyupdate_server_pubkey(&created.server_pubkey, [11u8; 32], [12u8; 32])?;
    let request = Arc::new(
        lockbox::build_keyupdate_request(&client, &statechain_id, [11_u8; 32], [12_u8; 32]).await?,
    );
    let barrier = Arc::new(Barrier::new(3));
    let mut join_set = JoinSet::new();

    for _ in 0..2 {
        let client = lockbox::http_client();
        let barrier = barrier.clone();
        let request = request.clone();

        join_set.spawn(async move {
            barrier.wait().await;
            lockbox::keyupdate_request(&client, &request)
                .await
                .map(|receipt| hex::encode(receipt.resulting_server_pubkey.as_bytes()))
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
    let state = lockbox::get_bip448_state(&client, &statechain_id).await?;
    assert_eq!(state.sig_count.get(), 0);
    assert_eq!(state.key_generation.get(), 1);
    assert_eq!(
        hex::encode(state.server_pubkey.as_bytes()),
        expected_server_pubkey
    );

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
