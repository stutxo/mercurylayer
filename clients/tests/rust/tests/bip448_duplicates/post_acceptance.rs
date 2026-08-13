use super::support::*;
use super::*;

fn run_receiver_rescan_cancel_child(wallet_name: &str, statechain_id: &str) -> Result<Output> {
    Ok(Command::new(std::env::current_exe()?)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "--ignored",
            "--exact",
            "bip448_receiver_post_acceptance_duplicate_rescan_is_retryable",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ML_BIP448_RECEIVER_RESCAN_CHILD", "1")
        .env("ML_BIP448_RESTART_CHILD", "1")
        .env("ML_BIP448_RESTART_WALLET", wallet_name)
        .env("ML_BIP448_RESTART_STATECHAIN_ID", statechain_id)
        .env("ML_BIP448_TEST_CHECKPOINT", "transfer_sender_finished")
        .env("ML_NETWORK", "regtest")
        .env_remove("ML_BIP448_DUPLICATE_SWEEP_CHILD")
        .env_remove("ML_BIP448_CANONICAL_CLOSE_CHILD_MODE")
        .env_remove("ML_BIP448_TEST_BARRIER")
        .env_remove("ML_BIP448_TEST_BARRIER_REACHED")
        .env_remove("ML_BIP448_TEST_BARRIER_RELEASE")
        .output()?)
}

pub(super) async fn bip448_receiver_post_acceptance_duplicate_rescan_is_retryable() -> Result<()> {
    if std::env::var("ML_BIP448_RECEIVER_RESCAN_CHILD").as_deref() == Ok("1") {
        std::env::set_var("ML_NETWORK", "regtest");
        let config = mercuryrustlib::client_config::load().await;
        let result = mercuryrustlib::bip448_transfer_sender::cancel_bip448_transfer(
            &config,
            &std::env::var("ML_BIP448_RESTART_WALLET")?,
            &std::env::var("ML_BIP448_RESTART_STATECHAIN_ID")?,
        )
        .await
        .map(|_| ());
        config.pool.close().await;
        return result;
    }

    let _guard = common::test_guard();
    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;
    let lockbox_client = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox_client).await?;

    // Cancellation first: stop after sender preflight/finish, introduce a new
    // output, then fail only after the real outer receiver has persisted the
    // accepted record, complete history, and final wallet.
    let cancellation_fixture = duplicate_sweep_fixture(&[]).await?;
    let cancellation_wallet = mercuryrustlib::sqlite_manager::get_wallet(
        &cancellation_fixture.config.pool,
        &cancellation_fixture.wallet_name,
    )
    .await?;
    let cancellation_sender_coin = cancellation_wallet
        .coins
        .iter()
        .find(|coin| {
            coin.statechain_id.as_deref() == Some(cancellation_fixture.statechain_id.as_str())
        })
        .context("cancellation fixture sender Coin is missing")?;
    let cancellation_aggregate = Address::from_str(
        cancellation_sender_coin
            .aggregated_address
            .as_deref()
            .context("cancellation fixture aggregate address is missing")?,
    )?
    .require_network(cancellation_fixture.config.network)?;
    cancellation_fixture.config.pool.close().await;

    let sender_finished = run_receiver_rescan_cancel_child(
        &cancellation_fixture.wallet_name,
        &cancellation_fixture.statechain_id,
    )?;
    require_child_exit(
        &sender_finished,
        86,
        "cancellation after transfer_sender_finished",
    )?;
    let cancellation_config = mercuryrustlib::client_config::load().await;
    let sender_finished_intent = mercuryrustlib::sqlite_manager::get_active_bip448_transfer_intent(
        &cancellation_config.pool,
        &cancellation_fixture.wallet_name,
        &cancellation_fixture.statechain_id,
    )
    .await?
    .context("cancellation SenderFinished intent is missing")?;
    assert_eq!(sender_finished_intent.intent_kind.as_str(), "Cancellation");
    assert_eq!(sender_finished_intent.phase.as_str(), "SenderFinished");
    let generated_user = sender_finished_intent
        .generated_coin_user_pubkey
        .clone()
        .context("cancellation intent has no generated user key")?;
    let generated_auth = sender_finished_intent
        .generated_coin_auth_pubkey
        .clone()
        .context("cancellation intent has no generated auth key")?;
    let (cancellation_recipient, cancellation_message_raw) =
        mercuryrustlib::sqlite_manager::get_bip448_transfer_msg_raw_optional(
            &cancellation_config.pool,
            &cancellation_fixture.wallet_name,
            &cancellation_fixture.statechain_id,
            None,
        )
        .await?
        .context("cancellation outgoing message is missing")?;
    assert_eq!(cancellation_recipient, generated_auth);
    let cancellation_message =
        require_v2_message_without_duplicate_field(&cancellation_message_raw)?;
    assert_eq!(
        cancellation_message.receiver_user_public_key,
        generated_user
    );
    let sender_finished_bindings = mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
        &cancellation_config.pool,
        &cancellation_fixture.wallet_name,
        &cancellation_fixture.statechain_id,
    )
    .await?;
    assert_eq!(sender_finished_bindings.len(), 1);
    let sender_finished_canonical = sender_finished_bindings[0].clone();
    let sender_finished_wallet = mercuryrustlib::sqlite_manager::get_wallet(
        &cancellation_config.pool,
        &cancellation_fixture.wallet_name,
    )
    .await?;
    let generated_before_acceptance = sender_finished_wallet
        .coins
        .iter()
        .filter(|coin| coin.user_pubkey == generated_user && coin.auth_pubkey == generated_auth)
        .collect::<Vec<_>>();
    assert_eq!(generated_before_acceptance.len(), 1);
    assert_eq!(
        generated_before_acceptance[0].status,
        CoinStatus::INITIALISED
    );
    assert!(generated_before_acceptance[0].statechain_id.is_none());

    let late_duplicate = fund_address_output(&cancellation_aggregate, DUPLICATE_AMOUNT_SATS)?;
    common::bitcoin_core::mine_blocks(cancellation_config.confirmation_target)?;
    let duplicate_tx_out = cancellation_config
        .chain_client
        .get_tx_out(
            &late_duplicate.outpoint.txid,
            late_duplicate.outpoint.vout,
            true,
        )?
        .context("late cancellation duplicate is not unspent")?;
    let duplicate_funding_height = cancellation_config
        .chain_client
        .tip_height()?
        .checked_sub(duplicate_tx_out.confirmations.saturating_sub(1))
        .context("late cancellation duplicate confirmations exceed the tip")?;
    let mut simulated_receiver_wallet = mercuryrustlib::sqlite_manager::get_wallet(
        &cancellation_config.pool,
        &cancellation_fixture.wallet_name,
    )
    .await?;
    let simulated_receiver_birth = cancellation_config
        .chain_client
        .tip_height()?
        .checked_add(1)
        .context("simulated cancellation receiver birth height overflow")?;
    assert!(duplicate_funding_height < simulated_receiver_birth);
    simulated_receiver_wallet.blockheight = simulated_receiver_birth;
    mercuryrustlib::sqlite_manager::update_wallet(
        &cancellation_config.pool,
        &simulated_receiver_wallet,
    )
    .await?;
    assert_eq!(
        bip448_transfer_artifact_counts(
            &cancellation_config,
            &cancellation_fixture.wallet_name,
            &cancellation_fixture.statechain_id,
        )
        .await?,
        (1, 1, 1)
    );

    mercuryrustlib::transfer_receiver::inject_bip448_post_acceptance_sync_failures_for_test(1);
    let cancellation_error = match mercuryrustlib::transfer_receiver::execute(
        &cancellation_config,
        &cancellation_fixture.wallet_name,
    )
    .await
    {
        Ok(_) => anyhow::bail!("injected cancellation post-acceptance rescan did not fail"),
        Err(error) => error,
    };
    let typed_cancellation = cancellation_error
        .downcast_ref::<mercuryrustlib::transfer_receiver::Bip448PostAcceptanceSyncError>()
        .context("cancellation rescan error is not the typed post-acceptance error")?;
    assert_eq!(
        typed_cancellation.accepted_statechain_ids(),
        &[cancellation_fixture.statechain_id.clone()]
    );
    assert!(cancellation_error.to_string().contains("already accepted"));
    assert!(cancellation_error
        .to_string()
        .contains("next update/list will retry"));

    let receiver_accepted_intent =
        mercuryrustlib::sqlite_manager::get_active_bip448_transfer_intent(
            &cancellation_config.pool,
            &cancellation_fixture.wallet_name,
            &cancellation_fixture.statechain_id,
        )
        .await?
        .context("accepted cancellation intent was rolled back")?;
    assert_eq!(
        receiver_accepted_intent.intent_id,
        sender_finished_intent.intent_id
    );
    assert_eq!(receiver_accepted_intent.phase.as_str(), "ReceiverAccepted");
    assert_eq!(
        receiver_accepted_intent.intent_kind.as_str(),
        "Cancellation"
    );
    let accepted_cancellation_wallet = mercuryrustlib::sqlite_manager::get_wallet(
        &cancellation_config.pool,
        &cancellation_fixture.wallet_name,
    )
    .await?;
    let accepted_generated = accepted_cancellation_wallet
        .coins
        .iter()
        .filter(|coin| {
            coin.user_pubkey == generated_user
                && coin.auth_pubkey == generated_auth
                && coin.statechain_id.as_deref()
                    == Some(cancellation_fixture.statechain_id.as_str())
        })
        .collect::<Vec<_>>();
    assert_eq!(accepted_generated.len(), 1);
    assert!(matches!(
        accepted_generated[0].status,
        CoinStatus::UNCONFIRMED | CoinStatus::CONFIRMED
    ));
    let accepted_cancellation_record = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &cancellation_config.pool,
        &cancellation_fixture.wallet_name,
        &cancellation_fixture.statechain_id,
    )
    .await?;
    assert_eq!(accepted_cancellation_record.latest_state_number, 2);
    let accepted_cancellation_bytes = accepted_state_bytes(
        &cancellation_config.pool,
        &cancellation_fixture.wallet_name,
        &cancellation_fixture.statechain_id,
    )
    .await?;
    assert_eq!(accepted_cancellation_bytes.1.len(), 2);
    assert_eq!(
        mercuryrustlib::sqlite_manager::get_bip448_transfer_msg_raw_optional(
            &cancellation_config.pool,
            &cancellation_fixture.wallet_name,
            &cancellation_fixture.statechain_id,
            Some(&cancellation_recipient),
        )
        .await?,
        Some((
            cancellation_recipient.clone(),
            cancellation_message_raw.clone()
        ))
    );
    assert_eq!(
        mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
            &cancellation_config.pool,
            &cancellation_fixture.wallet_name,
            &cancellation_fixture.statechain_id,
        )
        .await?,
        sender_finished_bindings,
        "post-acceptance failure must precede binding reassignment/discovery"
    );
    assert!(
        mercuryrustlib::sqlite_manager::list_bip448_withdrawal_attempts(
            &cancellation_config.pool,
            &cancellation_fixture.wallet_name,
            &cancellation_fixture.statechain_id,
        )
        .await?
        .is_empty()
    );
    assert_eq!(
        bip448_transfer_artifact_counts(
            &cancellation_config,
            &cancellation_fixture.wallet_name,
            &cancellation_fixture.statechain_id,
        )
        .await?,
        (1, 1, 1),
        "post-acceptance failure lost cancellation message, intent, or pending lineage"
    );
    let cancellation_mercury_after_acceptance =
        mercury_state_bytes(&cancellation_fixture.statechain_id).await?;
    let cancellation_count_after_acceptance =
        common::lockbox::get_signature_count(&lockbox_client, &cancellation_fixture.statechain_id)
            .await?;
    cancellation_config.pool.close().await;

    let cancellation_retry = mercuryrustlib::client_config::load().await;
    assert_eq!(
        accepted_state_bytes(
            &cancellation_retry.pool,
            &cancellation_fixture.wallet_name,
            &cancellation_fixture.statechain_id,
        )
        .await?,
        accepted_cancellation_bytes,
        "accepted cancellation record/history did not survive restart"
    );
    assert_eq!(
        mercuryrustlib::sqlite_manager::get_bip448_transfer_msg_raw_optional(
            &cancellation_retry.pool,
            &cancellation_fixture.wallet_name,
            &cancellation_fixture.statechain_id,
            Some(&cancellation_recipient),
        )
        .await?,
        Some((
            cancellation_recipient.clone(),
            cancellation_message_raw.clone()
        ))
    );
    mercuryrustlib::coin_status::update_coins(
        &cancellation_retry,
        &cancellation_fixture.wallet_name,
    )
    .await?;
    assert_eq!(
        accepted_state_bytes(
            &cancellation_retry.pool,
            &cancellation_fixture.wallet_name,
            &cancellation_fixture.statechain_id,
        )
        .await?,
        accepted_cancellation_bytes
    );
    assert_eq!(
        bip448_transfer_artifact_counts(
            &cancellation_retry,
            &cancellation_fixture.wallet_name,
            &cancellation_fixture.statechain_id,
        )
        .await?,
        (0, 0, 0),
        "successful cancellation retry must atomically remove its exact terminal artifacts"
    );
    let cancellation_bindings = mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
        &cancellation_retry.pool,
        &cancellation_fixture.wallet_name,
        &cancellation_fixture.statechain_id,
    )
    .await?;
    assert_eq!(cancellation_bindings.len(), 2);
    let cancellation_canonical = cancellation_bindings
        .iter()
        .find(|binding| binding.role == Bip448BindingRole::Canonical)
        .context("reassigned cancellation canonical binding is missing")?;
    assert_eq!(
        cancellation_canonical.binding_index,
        sender_finished_canonical.binding_index
    );
    assert_eq!(cancellation_canonical.txid, sender_finished_canonical.txid);
    assert_eq!(cancellation_canonical.vout, sender_finished_canonical.vout);
    assert_eq!(
        cancellation_canonical.first_seen_at,
        sender_finished_canonical.first_seen_at
    );
    let cancellation_duplicate = cancellation_bindings
        .iter()
        .find(|binding| {
            binding.txid == late_duplicate.outpoint.txid.to_string()
                && binding.vout == late_duplicate.outpoint.vout
        })
        .context("height-0 retry did not discover the late cancellation duplicate")?;
    assert_eq!(cancellation_duplicate.role, Bip448BindingRole::Duplicate);
    assert!(
        cancellation_duplicate
            .funding_height
            .context("late cancellation duplicate has no funding height")?
            < simulated_receiver_birth
    );
    let cancellation_owner = accepted_cancellation_bytes
        .1
        .last()
        .map(|(_, entry)| serde_json::from_str::<serde_json::Value>(entry))
        .transpose()?
        .and_then(|entry| {
            entry
                .get("owner_public_key")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .context("accepted cancellation history has no owner")?;
    assert!(cancellation_bindings.iter().all(|binding| {
        binding.owner_user_pubkey == cancellation_owner
            && binding.owner_state_number == 2
            && binding.ownership_status == Bip448OwnershipStatus::Current
    }));
    assert!(
        mercuryrustlib::sqlite_manager::list_bip448_withdrawal_attempts(
            &cancellation_retry.pool,
            &cancellation_fixture.wallet_name,
            &cancellation_fixture.statechain_id,
        )
        .await?
        .is_empty()
    );
    assert_eq!(
        mercury_state_bytes(&cancellation_fixture.statechain_id).await?,
        cancellation_mercury_after_acceptance,
        "passive cancellation retry performed a second server key update"
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &cancellation_fixture.statechain_id,)
            .await?,
        cancellation_count_after_acceptance,
        "passive cancellation retry changed the signature count"
    );
    let rejection_recipient = mercuryrustlib::transfer_receiver::new_transfer_address(
        &cancellation_retry,
        &cancellation_fixture.wallet_name,
    )
    .await?;
    let duplicate_rejection = mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender(
        &cancellation_retry,
        &rejection_recipient,
        &cancellation_fixture.wallet_name,
        &cancellation_fixture.statechain_id,
        None,
    )
    .await
    .expect_err("normal sender accepted a known cooperative duplicate");
    assert!(duplicate_rejection
        .to_string()
        .to_ascii_lowercase()
        .contains("duplicate"));
    assert_eq!(
        bip448_transfer_artifact_counts(
            &cancellation_retry,
            &cancellation_fixture.wallet_name,
            &cancellation_fixture.statechain_id,
        )
        .await?,
        (0, 0, 0)
    );
    assert_eq!(
        mercury_state_bytes(&cancellation_fixture.statechain_id).await?,
        cancellation_mercury_after_acceptance
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &cancellation_fixture.statechain_id,)
            .await?,
        cancellation_count_after_acceptance
    );
    cancellation_retry.pool.close().await;

    // Ordinary same-wallet UserTransfer has no durable intent after sender
    // finish. Its exact local outgoing row must therefore be the restart
    // trigger for accepted-prefix cleanup in the normal update/list path.
    let ordinary_fixture = duplicate_sweep_fixture(&[]).await?;
    let ordinary_initial_binding = ordinary_fixture.bindings[0].clone();
    let ordinary_recipient = mercuryrustlib::transfer_receiver::new_transfer_address(
        &ordinary_fixture.config,
        &ordinary_fixture.wallet_name,
    )
    .await?;
    let (_, ordinary_receiver_user, ordinary_receiver_auth) =
        mercurylib::decode_transfer_address(&ordinary_recipient)?;
    mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender(
        &ordinary_fixture.config,
        &ordinary_recipient,
        &ordinary_fixture.wallet_name,
        &ordinary_fixture.statechain_id,
        None,
    )
    .await?;
    assert!(
        mercuryrustlib::sqlite_manager::get_active_bip448_transfer_intent(
            &ordinary_fixture.config.pool,
            &ordinary_fixture.wallet_name,
            &ordinary_fixture.statechain_id,
        )
        .await?
        .is_none(),
        "finished ordinary UserTransfer retained an active intent"
    );
    let (ordinary_recipient_auth, ordinary_message_raw) =
        mercuryrustlib::sqlite_manager::get_bip448_transfer_msg_raw_optional(
            &ordinary_fixture.config.pool,
            &ordinary_fixture.wallet_name,
            &ordinary_fixture.statechain_id,
            None,
        )
        .await?
        .context("ordinary same-wallet outgoing message is missing")?;
    assert_eq!(ordinary_recipient_auth, ordinary_receiver_auth.to_string());
    let ordinary_message = require_v2_message_without_duplicate_field(&ordinary_message_raw)?;
    assert_eq!(
        ordinary_message.receiver_user_public_key,
        ordinary_receiver_user.to_string()
    );
    let ordinary_sender_finished_bindings =
        mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
            &ordinary_fixture.config.pool,
            &ordinary_fixture.wallet_name,
            &ordinary_fixture.statechain_id,
        )
        .await?;
    assert_eq!(ordinary_sender_finished_bindings.len(), 1);

    mercuryrustlib::transfer_receiver::inject_bip448_post_acceptance_sync_failures_for_test(1);
    let ordinary_error = match mercuryrustlib::transfer_receiver::execute(
        &ordinary_fixture.config,
        &ordinary_fixture.wallet_name,
    )
    .await
    {
        Ok(_) => anyhow::bail!("injected ordinary post-acceptance rescan did not fail"),
        Err(error) => error,
    };
    let typed_ordinary = ordinary_error
        .downcast_ref::<mercuryrustlib::transfer_receiver::Bip448PostAcceptanceSyncError>()
        .context("ordinary rescan error is not the typed post-acceptance error")?;
    assert_eq!(
        typed_ordinary.accepted_statechain_ids(),
        &[ordinary_fixture.statechain_id.clone()]
    );
    assert!(ordinary_error.to_string().contains("already accepted"));
    let ordinary_accepted_bytes = accepted_state_bytes(
        &ordinary_fixture.config.pool,
        &ordinary_fixture.wallet_name,
        &ordinary_fixture.statechain_id,
    )
    .await?;
    assert_eq!(ordinary_accepted_bytes.1.len(), 2);
    assert_eq!(
        mercuryrustlib::sqlite_manager::get_bip448_transfer_msg_raw_optional(
            &ordinary_fixture.config.pool,
            &ordinary_fixture.wallet_name,
            &ordinary_fixture.statechain_id,
            Some(&ordinary_recipient_auth),
        )
        .await?,
        Some((
            ordinary_recipient_auth.clone(),
            ordinary_message_raw.clone()
        )),
        "ordinary accepted-prefix row was deleted before passive sync succeeded"
    );
    assert!(
        mercuryrustlib::sqlite_manager::get_active_bip448_transfer_intent(
            &ordinary_fixture.config.pool,
            &ordinary_fixture.wallet_name,
            &ordinary_fixture.statechain_id,
        )
        .await?
        .is_none()
    );
    assert_eq!(
        mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
            &ordinary_fixture.config.pool,
            &ordinary_fixture.wallet_name,
            &ordinary_fixture.statechain_id,
        )
        .await?,
        ordinary_sender_finished_bindings
    );
    let ordinary_wallet_after_acceptance = mercuryrustlib::sqlite_manager::get_wallet(
        &ordinary_fixture.config.pool,
        &ordinary_fixture.wallet_name,
    )
    .await?;
    assert_eq!(
        ordinary_wallet_after_acceptance
            .coins
            .iter()
            .filter(|coin| {
                coin.statechain_id.as_deref() == Some(ordinary_fixture.statechain_id.as_str())
                    && coin.user_pubkey == ordinary_receiver_user.to_string()
                    && coin.auth_pubkey == ordinary_receiver_auth.to_string()
            })
            .count(),
        1
    );
    assert_eq!(
        bip448_transfer_artifact_counts(
            &ordinary_fixture.config,
            &ordinary_fixture.wallet_name,
            &ordinary_fixture.statechain_id,
        )
        .await?,
        (1, 0, 1)
    );
    let ordinary_mercury_after_acceptance =
        mercury_state_bytes(&ordinary_fixture.statechain_id).await?;
    let ordinary_count_after_acceptance =
        common::lockbox::get_signature_count(&lockbox_client, &ordinary_fixture.statechain_id)
            .await?;
    ordinary_fixture.config.pool.close().await;

    let ordinary_retry = mercuryrustlib::client_config::load().await;
    assert_eq!(
        accepted_state_bytes(
            &ordinary_retry.pool,
            &ordinary_fixture.wallet_name,
            &ordinary_fixture.statechain_id,
        )
        .await?,
        ordinary_accepted_bytes
    );
    assert_eq!(
        mercuryrustlib::sqlite_manager::get_bip448_transfer_msg_raw_optional(
            &ordinary_retry.pool,
            &ordinary_fixture.wallet_name,
            &ordinary_fixture.statechain_id,
            Some(&ordinary_recipient_auth),
        )
        .await?,
        Some((
            ordinary_recipient_auth.clone(),
            ordinary_message_raw.clone()
        ))
    );
    mercuryrustlib::coin_status::update_coins(&ordinary_retry, &ordinary_fixture.wallet_name)
        .await?;
    assert_eq!(
        accepted_state_bytes(
            &ordinary_retry.pool,
            &ordinary_fixture.wallet_name,
            &ordinary_fixture.statechain_id,
        )
        .await?,
        ordinary_accepted_bytes
    );
    assert_eq!(
        bip448_transfer_artifact_counts(
            &ordinary_retry,
            &ordinary_fixture.wallet_name,
            &ordinary_fixture.statechain_id,
        )
        .await?,
        (0, 0, 0),
        "plain update did not reconcile the exact ordinary accepted-prefix row"
    );
    let ordinary_bindings = mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
        &ordinary_retry.pool,
        &ordinary_fixture.wallet_name,
        &ordinary_fixture.statechain_id,
    )
    .await?;
    assert_eq!(ordinary_bindings.len(), 1);
    assert_eq!(
        ordinary_bindings[0].binding_index,
        ordinary_initial_binding.binding_index
    );
    assert_eq!(ordinary_bindings[0].txid, ordinary_initial_binding.txid);
    assert_eq!(ordinary_bindings[0].vout, ordinary_initial_binding.vout);
    assert_eq!(
        ordinary_bindings[0].first_seen_at,
        ordinary_initial_binding.first_seen_at
    );
    assert_eq!(
        ordinary_bindings[0].owner_user_pubkey,
        ordinary_receiver_user.x_only_public_key().0.to_string()
    );
    assert_eq!(ordinary_bindings[0].owner_state_number, 2);
    assert_eq!(
        ordinary_bindings[0].ownership_status,
        Bip448OwnershipStatus::Current
    );
    assert_eq!(
        mercury_state_bytes(&ordinary_fixture.statechain_id).await?,
        ordinary_mercury_after_acceptance,
        "ordinary passive retry performed a second server key update"
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &ordinary_fixture.statechain_id)
            .await?,
        ordinary_count_after_acceptance,
        "ordinary passive retry changed the signature count"
    );

    let close_destination = common::bitcoin_core::getnewaddress()?;
    mercuryrustlib::bip448_withdraw::execute(
        &ordinary_retry,
        &ordinary_fixture.wallet_name,
        &ordinary_fixture.statechain_id,
        &close_destination,
        Some(1.0),
    )
    .await
    .context("no-duplicate canonical preflight remained blocked by an accepted local message")?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bip448_withdrawal_attempts \
             WHERE wallet_name=$1 AND statechain_id=$2 AND binding_index=0",
        )
        .bind(&ordinary_fixture.wallet_name)
        .bind(&ordinary_fixture.statechain_id)
        .fetch_one(&ordinary_retry.pool)
        .await?,
        1
    );
    assert!(
        !mercuryrustlib::sqlite_manager::has_bip448_transfer_msg_for_statechain(
            &ordinary_retry.pool,
            &ordinary_fixture.wallet_name,
            &ordinary_fixture.statechain_id,
        )
        .await?
    );

    println!(
        "BIP448 receiver rescan retry: cancellation_statechain={} late_duplicate={} birth_height={} duplicate_height={} ordinary_statechain={} cancellation_bindings={} ordinary_bindings={}",
        cancellation_fixture.statechain_id,
        late_duplicate.outpoint,
        simulated_receiver_birth,
        duplicate_funding_height,
        ordinary_fixture.statechain_id,
        cancellation_bindings.len(),
        ordinary_bindings.len(),
    );
    ordinary_retry.pool.close().await;
    Ok(())
}
