use super::support::*;
use super::*;

pub(super) async fn bip448_duplicate_same_wallet_cancel_reassigns_current_owner() -> Result<()> {
    if run_commit10_child_if_requested().await? {
        return Ok(());
    }

    let _guard = common::test_guard();
    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;
    let lockbox_client = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox_client).await?;

    // Cancellation Coin creation and its intent insertion are one guarded
    // write. Let an attempt win after cancellation preflight and prove that the
    // losing cancellation appended neither a Coin nor any remote/local row.
    let race = duplicate_sweep_fixture(&[SMALL_DUPLICATE_AMOUNT_SATS]).await?;
    let race_wallet_before =
        mercuryrustlib::sqlite_manager::get_wallet(&race.config.pool, &race.wallet_name).await?;
    let (mut cancellation_child, reached, release) = spawn_commit10_barrier_child(
        "bip448_duplicate_same_wallet_cancel_reassigns_current_owner",
        "cancel",
        &race.wallet_name,
        &race.statechain_id,
        None,
        "cancellation_preflight_before_coin_intent",
    )?;
    wait_for_commit10_barrier(
        &mut cancellation_child,
        &reached,
        "cancellation_preflight_before_coin_intent",
    )?;
    let race_destination = common::bitcoin_core::getnewaddress()?;
    let attempt_winner = run_duplicate_sweep_child(
        &race.wallet_name,
        &race.statechain_id,
        race.bindings[1].binding_index,
        &race_destination,
        Some("attempt_prepared"),
        false,
    )?;
    require_child_exit(&attempt_winner, 86, "cancellation-versus-attempt winner")?;
    let cancellation_loser = release_commit10_barrier(cancellation_child, &reached, &release)?;
    assert!(
        !cancellation_loser.status.success(),
        "cancellation won after the competing attempt was durable"
    );
    assert!(String::from_utf8_lossy(&cancellation_loser.stderr)
        .to_ascii_lowercase()
        .contains("attempt"));
    assert_eq!(
        mercuryrustlib::sqlite_manager::get_wallet(&race.config.pool, &race.wallet_name)
            .await?
            .coins
            .len(),
        race_wallet_before.coins.len(),
        "losing cancellation appended its generated Coin"
    );
    assert_eq!(
        bip448_transfer_artifact_counts(&race.config, &race.wallet_name, &race.statechain_id)
            .await?,
        (0, 0, 0)
    );
    assert_eq!(
        mercury_transfer_side_effect_counts(&race.statechain_id).await?,
        (0, 0)
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &race.statechain_id).await?,
        1
    );

    // Force bypasses only the duplicate warning. Durable exit-only attempts
    // still block both user transfer and cancellation before any side effect.
    for (checkpoint, expected_phase) in [
        ("sign_second_armed", Bip448WithdrawalPhase::SecondArmed),
        ("signed_tx_persisted", Bip448WithdrawalPhase::Signed),
    ] {
        let blocked = duplicate_sweep_fixture(&[SMALL_DUPLICATE_AMOUNT_SATS]).await?;
        let destination = common::bitcoin_core::getnewaddress()?;
        let attempt_child = run_duplicate_sweep_child(
            &blocked.wallet_name,
            &blocked.statechain_id,
            blocked.bindings[1].binding_index,
            &destination,
            Some(checkpoint),
            false,
        )?;
        require_child_exit(&attempt_child, 86, checkpoint)?;
        let attempt = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
            &blocked.config.pool,
            &blocked.wallet_name,
            &blocked.statechain_id,
            blocked.bindings[1].binding_index,
        )
        .await?
        .context("exit-only blocker attempt is missing")?;
        assert_eq!(attempt.phase, expected_phase);

        let recipient_wallet_name = format!("bip448-exit-only-r-{}", uuid::Uuid::new_v4());
        let recipient_wallet =
            mercuryrustlib::wallet::create_wallet(&recipient_wallet_name, &blocked.config).await?;
        mercuryrustlib::sqlite_manager::insert_wallet(&blocked.config.pool, &recipient_wallet)
            .await?;
        let recipient = mercuryrustlib::transfer_receiver::new_transfer_address(
            &blocked.config,
            &recipient_wallet_name,
        )
        .await?;
        let wallet_before =
            mercuryrustlib::sqlite_manager::get_wallet(&blocked.config.pool, &blocked.wallet_name)
                .await?;
        let wallet_before = serde_json::to_string(&wallet_before)?;
        let accepted_before = accepted_state_bytes(
            &blocked.config.pool,
            &blocked.wallet_name,
            &blocked.statechain_id,
        )
        .await?;
        let mercury_before = mercury_state_bytes(&blocked.statechain_id).await?;
        let count_before =
            common::lockbox::get_signature_count(&lockbox_client, &blocked.statechain_id).await?;

        let transfer_error =
            mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender_with_options(
                &blocked.config,
                &recipient,
                &blocked.wallet_name,
                &blocked.statechain_id,
                None,
                mercuryrustlib::bip448_transfer_sender::Bip448TransferOptions {
                    acknowledge_cooperative_duplicates: true,
                    intent: Bip448TransferIntentKind::UserTransfer,
                },
            )
            .await
            .expect_err("force bypassed an exit-only withdrawal attempt");
        assert!(
            transfer_error.to_string().contains("exit-only"),
            "{checkpoint} transfer gate returned: {transfer_error}"
        );
        let cancellation_error = mercuryrustlib::bip448_transfer_sender::cancel_bip448_transfer(
            &blocked.config,
            &blocked.wallet_name,
            &blocked.statechain_id,
        )
        .await
        .expect_err("cancellation bypassed an exit-only withdrawal attempt");
        assert!(
            cancellation_error.to_string().contains("exit-only"),
            "{checkpoint} cancellation gate returned: {cancellation_error}"
        );
        assert_eq!(
            serde_json::to_string(
                &mercuryrustlib::sqlite_manager::get_wallet(
                    &blocked.config.pool,
                    &blocked.wallet_name,
                )
                .await?
            )?,
            wallet_before,
            "exit-only rejection changed or appended a wallet Coin at {checkpoint}"
        );
        assert_eq!(
            accepted_state_bytes(
                &blocked.config.pool,
                &blocked.wallet_name,
                &blocked.statechain_id,
            )
            .await?,
            accepted_before
        );
        assert_eq!(
            bip448_transfer_artifact_counts(
                &blocked.config,
                &blocked.wallet_name,
                &blocked.statechain_id,
            )
            .await?,
            (0, 0, 0)
        );
        assert_eq!(
            mercury_state_bytes(&blocked.statechain_id).await?,
            mercury_before
        );
        assert_eq!(
            common::lockbox::get_signature_count(&lockbox_client, &blocked.statechain_id).await?,
            count_before
        );
    }

    let fixture =
        duplicate_sweep_fixture(&[DUPLICATE_AMOUNT_SATS, SMALL_DUPLICATE_AMOUNT_SATS]).await?;
    let initial_bindings = fixture.bindings.clone();
    let initial_wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&fixture.config.pool, &fixture.wallet_name)
            .await?;
    let initial_coin = initial_wallet
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some(fixture.statechain_id.as_str()))
        .context("same-wallet initial owner Coin is missing")?;
    let old_user = initial_coin.user_pubkey.clone();
    let old_server = initial_coin
        .server_pubkey
        .clone()
        .context("same-wallet initial owner server key is missing")?;
    let old_owner_xonly = PublicKey::from_str(&old_user)?
        .x_only_public_key()
        .0
        .to_string();

    let first_recipient = mercuryrustlib::transfer_receiver::new_transfer_address(
        &fixture.config,
        &fixture.wallet_name,
    )
    .await?;
    mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender_with_options(
        &fixture.config,
        &first_recipient,
        &fixture.wallet_name,
        &fixture.statechain_id,
        None,
        mercuryrustlib::bip448_transfer_sender::Bip448TransferOptions {
            acknowledge_cooperative_duplicates: true,
            intent: Bip448TransferIntentKind::UserTransfer,
        },
    )
    .await?;
    assert!(
        mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?
        .iter()
        .all(
            |binding| binding.ownership_status == Bip448OwnershipStatus::Current
                && binding.owner_user_pubkey == old_owner_xonly
        )
    );
    let wallet_after_forced_send =
        mercuryrustlib::sqlite_manager::get_wallet(&fixture.config.pool, &fixture.wallet_name)
            .await?;
    assert_eq!(
        wallet_after_forced_send
            .coins
            .iter()
            .find(|coin| coin.user_pubkey == old_user)
            .context("forced same-wallet send lost old Coin")?
            .status,
        CoinStatus::IN_TRANSFER
    );

    let coin_count_before_cancellation = wallet_after_forced_send.coins.len();
    mercuryrustlib::transfer_receiver::inject_bip448_post_acceptance_sync_failures_for_test(1);
    let first_cancellation_error = mercuryrustlib::bip448_transfer_sender::cancel_bip448_transfer(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await
    .expect_err("injected post-acceptance cancellation rescan unexpectedly succeeded");
    let typed = first_cancellation_error
        .downcast_ref::<mercuryrustlib::transfer_receiver::Bip448PostAcceptanceSyncError>()
        .context("cancellation did not preserve the typed accepted/rescan-pending error")?;
    assert_eq!(
        typed.accepted_statechain_ids(),
        &[fixture.statechain_id.clone()]
    );
    assert!(first_cancellation_error
        .to_string()
        .contains("cancellation accepted; duplicate rescan pending"));

    let receiver_accepted = mercuryrustlib::sqlite_manager::get_active_bip448_transfer_intent(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?
    .context("accepted cancellation intent is missing")?;
    assert_eq!(
        receiver_accepted.intent_kind,
        Bip448TransferIntentKind::Cancellation
    );
    assert!(receiver_accepted.acknowledge_cooperative_duplicates);
    assert_eq!(receiver_accepted.phase.as_str(), "ReceiverAccepted");
    let generated_user = receiver_accepted
        .generated_coin_user_pubkey
        .clone()
        .context("cancellation generated user key is missing")?;
    let generated_auth = receiver_accepted
        .generated_coin_auth_pubkey
        .clone()
        .context("cancellation generated auth key is missing")?;
    let generated_address = receiver_accepted
        .generated_coin_address
        .clone()
        .context("cancellation generated address is missing")?;
    let accepted_wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&fixture.config.pool, &fixture.wallet_name)
            .await?;
    assert_eq!(
        accepted_wallet.coins.len(),
        coin_count_before_cancellation + 1
    );
    assert_eq!(
        accepted_wallet
            .coins
            .iter()
            .filter(|coin| {
                coin.user_pubkey == generated_user
                    && coin.auth_pubkey == generated_auth
                    && coin.address == generated_address
                    && coin.statechain_id.as_deref() == Some(fixture.statechain_id.as_str())
            })
            .count(),
        1,
        "accepted cancellation did not retain exactly one generated Coin"
    );
    let accepted_bytes = accepted_state_bytes(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?;
    assert_eq!(accepted_bytes.1.len(), 3);
    let accepted_record = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?;
    assert_eq!(accepted_record.latest_state_number, 3);
    let (retained_recipient, retained_message) =
        mercuryrustlib::sqlite_manager::get_bip448_transfer_msg_raw_optional(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
            Some(&generated_auth),
        )
        .await?
        .context("ReceiverAccepted cancellation lost its exact outgoing message")?;
    assert_eq!(retained_recipient, generated_auth);
    require_v2_message_without_duplicate_field(&retained_message)?;
    assert_eq!(
        bip448_transfer_artifact_counts(
            &fixture.config,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?,
        (1, 1, 1)
    );
    let mercury_after_acceptance = mercury_state_bytes(&fixture.statechain_id).await?;
    let count_after_acceptance =
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?;

    let blocked_destination = common::bitcoin_core::getnewaddress()?;
    assert!(
        mercuryrustlib::bip448_withdraw::execute(
            &fixture.config,
            &fixture.wallet_name,
            &fixture.statechain_id,
            &blocked_destination,
            Some(1.0),
        )
        .await
        .is_err(),
        "retained cancellation message/intent did not block canonical preflight"
    );
    assert!(
        mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
            0,
        )
        .await?
        .is_none()
    );
    assert_eq!(
        mercuryrustlib::sqlite_manager::get_bip448_transfer_msg_raw_optional(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
            Some(&generated_auth),
        )
        .await?,
        Some((generated_auth.clone(), retained_message.clone())),
        "blocked preflight changed retained cancellation message bytes"
    );

    let retry_state = mercuryrustlib::bip448_transfer_sender::cancel_bip448_transfer(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?;
    assert_eq!(retry_state, 3);
    assert_eq!(
        bip448_transfer_artifact_counts(
            &fixture.config,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?,
        (0, 0, 0),
        "passive cancellation retry retained message/intent/pending artifacts"
    );
    assert_eq!(
        accepted_state_bytes(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?,
        accepted_bytes,
        "passive cancellation retry inserted a second history state"
    );
    assert_eq!(
        mercury_state_bytes(&fixture.statechain_id).await?,
        mercury_after_acceptance
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
        count_after_acceptance,
        "passive cancellation retry consumed another signature"
    );
    let final_wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&fixture.config.pool, &fixture.wallet_name)
            .await?;
    assert_eq!(final_wallet.coins.len(), coin_count_before_cancellation + 1);
    let generated_coin_index = final_wallet
        .coins
        .iter()
        .position(|coin| {
            coin.user_pubkey == generated_user
                && coin.auth_pubkey == generated_auth
                && coin.address == generated_address
                && coin.statechain_id.as_deref() == Some(fixture.statechain_id.as_str())
        })
        .context("passive retry lost the accepted generated Coin")?;
    assert_eq!(
        final_wallet
            .coins
            .iter()
            .filter(|coin| {
                coin.user_pubkey == generated_user
                    && coin.auth_pubkey == generated_auth
                    && coin.address == generated_address
            })
            .count(),
        1,
        "passive retry appended a second generated Coin"
    );
    let current_owner = mercuryrustlib::bip448_owner::get_current_bip448_owner(
        &fixture.config,
        &final_wallet,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?;
    assert_eq!(current_owner.coin_index, generated_coin_index);
    assert_eq!(
        final_wallet.coins[generated_coin_index].user_pubkey,
        generated_user
    );
    assert_ne!(
        final_wallet.coins[generated_coin_index]
            .server_pubkey
            .as_deref(),
        Some(old_server.as_str())
    );

    let reassigned = mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?;
    assert_eq!(reassigned.len(), initial_bindings.len());
    let immutable_binding_set = |bindings: &[Bip448FundingBinding]| {
        bindings
            .iter()
            .map(|binding| {
                (
                    binding.binding_index,
                    binding.txid.clone(),
                    binding.vout,
                    binding.value_sats,
                )
            })
            .collect::<BTreeSet<_>>()
    };
    assert_eq!(
        immutable_binding_set(&reassigned),
        immutable_binding_set(&initial_bindings),
        "cancellation changed stable binding indices/outpoints/amounts"
    );
    let generated_owner_xonly = PublicKey::from_str(&generated_user)?
        .x_only_public_key()
        .0
        .to_string();
    assert!(reassigned.iter().all(|binding| {
        binding.owner_user_pubkey == generated_owner_xonly
            && binding.owner_state_number == 3
            && binding.ownership_status == Bip448OwnershipStatus::Current
    }));
    assert!(!reassigned.iter().any(|binding| {
        binding.owner_user_pubkey == old_owner_xonly
            && binding.ownership_status == Bip448OwnershipStatus::Current
    }));

    // Separately prove ordinary same-wallet UserTransfer cleanup: an exact
    // accepted outgoing row survives a failed post-acceptance sync, blocks
    // canonical preflight byte-for-byte, and is deleted only by successful
    // passive sync. With no duplicates, canonical preflight then succeeds.
    let ordinary = duplicate_sweep_fixture(&[]).await?;
    let ordinary_recipient = mercuryrustlib::transfer_receiver::new_transfer_address(
        &ordinary.config,
        &ordinary.wallet_name,
    )
    .await?;
    let (_, _, ordinary_auth) = mercurylib::decode_transfer_address(&ordinary_recipient)?;
    mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender(
        &ordinary.config,
        &ordinary_recipient,
        &ordinary.wallet_name,
        &ordinary.statechain_id,
        None,
    )
    .await?;
    let (_, ordinary_message) =
        mercuryrustlib::sqlite_manager::get_bip448_transfer_msg_raw_optional(
            &ordinary.config.pool,
            &ordinary.wallet_name,
            &ordinary.statechain_id,
            Some(&ordinary_auth.to_string()),
        )
        .await?
        .context("ordinary same-wallet message is missing")?;
    mercuryrustlib::transfer_receiver::inject_bip448_post_acceptance_sync_failures_for_test(1);
    let ordinary_error =
        match mercuryrustlib::transfer_receiver::execute(&ordinary.config, &ordinary.wallet_name)
            .await
        {
            Ok(_) => anyhow::bail!("ordinary injected post-acceptance sync unexpectedly succeeded"),
            Err(error) => error,
        };
    assert!(ordinary_error
        .downcast_ref::<mercuryrustlib::transfer_receiver::Bip448PostAcceptanceSyncError>()
        .is_some());
    assert_eq!(
        mercuryrustlib::sqlite_manager::get_bip448_transfer_msg_raw_optional(
            &ordinary.config.pool,
            &ordinary.wallet_name,
            &ordinary.statechain_id,
            Some(&ordinary_auth.to_string()),
        )
        .await?,
        Some((ordinary_auth.to_string(), ordinary_message.clone()))
    );
    let ordinary_destination = common::bitcoin_core::getnewaddress()?;
    assert!(mercuryrustlib::bip448_withdraw::execute(
        &ordinary.config,
        &ordinary.wallet_name,
        &ordinary.statechain_id,
        &ordinary_destination,
        Some(1.0),
    )
    .await
    .is_err());
    assert!(
        mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
            &ordinary.config.pool,
            &ordinary.wallet_name,
            &ordinary.statechain_id,
            0,
        )
        .await?
        .is_none()
    );
    assert_eq!(
        mercuryrustlib::sqlite_manager::get_bip448_transfer_msg_raw_optional(
            &ordinary.config.pool,
            &ordinary.wallet_name,
            &ordinary.statechain_id,
            Some(&ordinary_auth.to_string()),
        )
        .await?,
        Some((ordinary_auth.to_string(), ordinary_message))
    );
    mercuryrustlib::coin_status::update_coins(&ordinary.config, &ordinary.wallet_name).await?;
    assert_eq!(
        bip448_transfer_artifact_counts(
            &ordinary.config,
            &ordinary.wallet_name,
            &ordinary.statechain_id,
        )
        .await?,
        (0, 0, 0)
    );
    mercuryrustlib::bip448_withdraw::execute(
        &ordinary.config,
        &ordinary.wallet_name,
        &ordinary.statechain_id,
        &ordinary_destination,
        Some(1.0),
    )
    .await
    .context("ordinary accepted message still blocked no-duplicate canonical preflight")?;

    println!(
        "BIP448 forced same-wallet cancellation: statechain={} old_owner={} new_owner={} stable_bindings={}",
        fixture.statechain_id,
        old_owner_xonly,
        generated_owner_xonly,
        reassigned.len()
    );
    Ok(())
}
