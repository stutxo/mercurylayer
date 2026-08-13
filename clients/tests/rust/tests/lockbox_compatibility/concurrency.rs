use super::*;

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
