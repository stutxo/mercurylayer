use super::support::*;
use super::*;

pub(super) async fn bip448_duplicate_transfer_requires_ack_and_receiver_rediscovers() -> Result<()>
{
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

    // Retained-path race: the transfer completes its passive/current-owner
    // preflight, then a real duplicate attempt wins the storage guard. The
    // losing forced transfer must not reach /transfer/sender.
    let race = duplicate_sweep_fixture(&[SMALL_DUPLICATE_AMOUNT_SATS]).await?;
    let race_receiver_name = format!("bip448-transfer-race-r-{}", uuid::Uuid::new_v4());
    let race_receiver =
        mercuryrustlib::wallet::create_wallet(&race_receiver_name, &race.config).await?;
    mercuryrustlib::sqlite_manager::insert_wallet(&race.config.pool, &race_receiver).await?;
    let race_recipient =
        mercuryrustlib::transfer_receiver::new_transfer_address(&race.config, &race_receiver_name)
            .await?;
    let (mut transfer_child, reached, release) = spawn_commit10_barrier_child(
        "bip448_duplicate_transfer_requires_ack_and_receiver_rediscovers",
        "force-transfer",
        &race.wallet_name,
        &race.statechain_id,
        Some(&race_recipient),
        "transfer_preflight_before_intent",
    )?;
    wait_for_commit10_barrier(
        &mut transfer_child,
        &reached,
        "transfer_preflight_before_intent",
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
    require_child_exit(&attempt_winner, 86, "transfer-versus-attempt winner")?;
    let transfer_loser = release_commit10_barrier(transfer_child, &reached, &release)?;
    assert!(
        !transfer_loser.status.success(),
        "forced transfer won after the competing attempt was durable"
    );
    assert!(String::from_utf8_lossy(&transfer_loser.stderr)
        .to_ascii_lowercase()
        .contains("attempt"));
    assert_eq!(
        mercury_transfer_side_effect_counts(&race.statechain_id).await?,
        (0, 0),
        "losing transfer created a Mercury row or mailbox message"
    );
    assert_eq!(
        bip448_transfer_artifact_counts(&race.config, &race.wallet_name, &race.statechain_id)
            .await?,
        (0, 0, 0),
        "losing transfer created a local message, intent, or pending journal"
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &race.statechain_id).await?,
        1,
        "losing transfer consumed a lockbox signature"
    );

    let fixture =
        duplicate_sweep_fixture(&[DUPLICATE_AMOUNT_SATS, SMALL_DUPLICATE_AMOUNT_SATS]).await?;
    assert_ne!(
        fixture.bindings[1].value_sats,
        fixture.bindings[2].value_sats
    );
    common::bitcoin_core::mine_block()?;
    let sender_record = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?;
    let sender_wallet_before =
        mercuryrustlib::sqlite_manager::get_wallet(&fixture.config.pool, &fixture.wallet_name)
            .await?;
    let sender_coin_before = sender_wallet_before
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some(fixture.statechain_id.as_str()))
        .context("cross-wallet sender Coin is missing")?;
    let sender_user_xonly = PublicKey::from_str(&sender_coin_before.user_pubkey)?
        .x_only_public_key()
        .0
        .to_string();

    // Create the receiver only after all three funding outputs are confirmed;
    // its ordinary birth height therefore cannot account for their discovery.
    let receiver_name = format!("bip448-duplicate-receiver-{}", uuid::Uuid::new_v4());
    let receiver_wallet =
        mercuryrustlib::wallet::create_wallet(&receiver_name, &fixture.config).await?;
    let receiver_birth_height = receiver_wallet.blockheight;
    assert!(fixture.bindings.iter().all(|binding| {
        binding
            .funding_height
            .is_some_and(|height| height < receiver_birth_height)
    }));
    mercuryrustlib::sqlite_manager::insert_wallet(&fixture.config.pool, &receiver_wallet).await?;
    let recipient =
        mercuryrustlib::transfer_receiver::new_transfer_address(&fixture.config, &receiver_name)
            .await?;
    let (_, receiver_user, receiver_auth) = mercurylib::decode_transfer_address(&recipient)?;

    let accepted_before = accepted_state_bytes(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?;
    let sender_status_before = sender_coin_before.status.clone();
    let lockbox_before =
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?;
    assert_eq!(lockbox_before, 1);
    assert_eq!(
        mercury_transfer_side_effect_counts(&fixture.statechain_id).await?,
        (0, 0)
    );

    let warning = mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender(
        &fixture.config,
        &recipient,
        &fixture.wallet_name,
        &fixture.statechain_id,
        None,
    )
    .await
    .expect_err("unacknowledged duplicate transfer unexpectedly succeeded");
    let warning_text = warning.to_string();
    assert!(warning_text.contains("--force-send-with-duplicates"));
    assert!(warning_text.contains("not part of the verified canonical statechain amount"));
    assert!(warning_text.contains("server-dependent"));
    assert_eq!(
        accepted_state_bytes(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?,
        accepted_before,
        "warning path changed accepted record/history"
    );
    assert_eq!(
        bip448_transfer_artifact_counts(
            &fixture.config,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?,
        (0, 0, 0),
        "warning path created client transfer artifacts"
    );
    assert_eq!(
        mercury_transfer_side_effect_counts(&fixture.statechain_id).await?,
        (0, 0)
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
        lockbox_before
    );
    assert_eq!(
        mercuryrustlib::sqlite_manager::get_wallet(&fixture.config.pool, &fixture.wallet_name)
            .await?
            .coins
            .iter()
            .find(|coin| coin.statechain_id.as_deref() == Some(fixture.statechain_id.as_str()))
            .context("warning path lost sender Coin")?
            .status,
        sender_status_before,
        "warning path changed sender wallet status"
    );

    mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender_with_options(
        &fixture.config,
        &recipient,
        &fixture.wallet_name,
        &fixture.statechain_id,
        None,
        mercuryrustlib::bip448_transfer_sender::Bip448TransferOptions {
            acknowledge_cooperative_duplicates: true,
            intent: Bip448TransferIntentKind::UserTransfer,
        },
    )
    .await?;
    assert_eq!(
        mercury_transfer_side_effect_counts(&fixture.statechain_id).await?,
        (1, 1)
    );
    assert_eq!(
        bip448_transfer_artifact_counts(
            &fixture.config,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?,
        (1, 0, 1)
    );
    let (_, message_raw) = mercuryrustlib::sqlite_manager::get_bip448_transfer_msg_raw_optional(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        Some(&receiver_auth.to_string()),
    )
    .await?
    .context("forced transfer did not retain its exact outgoing message")?;
    let message = require_v2_message_without_duplicate_field(&message_raw)?;
    assert_eq!(message.amount_sats, sender_record.amount_sats);
    assert_eq!(message.funding_outpoint, sender_record.funding_outpoint);
    assert_eq!(
        message.funding_outpoint.txid, fixture.bindings[0].txid,
        "transfer message selected a duplicate outpoint"
    );
    assert_eq!(message.funding_outpoint.vout, fixture.bindings[0].vout);
    assert_eq!(message.receiver_user_public_key, receiver_user.to_string());

    let sender_after_send =
        mercuryrustlib::sqlite_manager::get_wallet(&fixture.config.pool, &fixture.wallet_name)
            .await?;
    assert_eq!(
        sender_after_send
            .coins
            .iter()
            .find(|coin| coin.statechain_id.as_deref() == Some(fixture.statechain_id.as_str()))
            .context("forced transfer lost sender Coin")?
            .status,
        CoinStatus::IN_TRANSFER
    );
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
                && binding.owner_user_pubkey == sender_user_xonly
        ),
        "sender bindings rotated before positive server rotation"
    );

    let received =
        mercuryrustlib::transfer_receiver::execute(&fixture.config, &receiver_name).await?;
    assert_eq!(
        received.received_statechain_ids,
        vec![fixture.statechain_id.clone()]
    );

    // There is deliberately no sender notification or sweep guarantee. Until
    // the sender performs its own positive-rotation sync, its local Coin and
    // bindings remain IN_TRANSFER/Current even though the receiver accepted.
    assert_eq!(
        mercuryrustlib::sqlite_manager::get_wallet(&fixture.config.pool, &fixture.wallet_name)
            .await?
            .coins
            .iter()
            .find(|coin| coin.statechain_id.as_deref() == Some(fixture.statechain_id.as_str()))
            .context("post-acceptance sender Coin is missing")?
            .status,
        CoinStatus::IN_TRANSFER
    );
    assert!(
        mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?
        .iter()
        .all(|binding| binding.ownership_status == Bip448OwnershipStatus::Current)
    );

    let receiver_bindings = mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
        &fixture.config.pool,
        &receiver_name,
        &fixture.statechain_id,
    )
    .await?;
    assert_eq!(receiver_bindings.len(), 3);
    let expected_outpoints = fixture
        .bindings
        .iter()
        .map(|binding| (binding.txid.clone(), binding.vout, binding.value_sats))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        receiver_bindings
            .iter()
            .map(|binding| (binding.txid.clone(), binding.vout, binding.value_sats))
            .collect::<BTreeSet<_>>(),
        expected_outpoints,
        "height-0 receiver rescan did not rediscover the exact funding set"
    );
    let receiver_owner_xonly = receiver_user.x_only_public_key().0.to_string();
    assert!(receiver_bindings.iter().all(|binding| {
        binding.ownership_status == Bip448OwnershipStatus::Current
            && binding.owner_user_pubkey == receiver_owner_xonly
            && binding.owner_state_number == 2
    }));
    let receiver_wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&fixture.config.pool, &receiver_name).await?;
    let receiver_coin = receiver_wallet
        .coins
        .iter()
        .find(|coin| {
            coin.statechain_id.as_deref() == Some(fixture.statechain_id.as_str())
                && coin.user_pubkey == receiver_user.to_string()
        })
        .context("receiver current owner Coin is missing")?;
    let listed = mercuryrustlib::coin_status::statecoin_list_entry_json(
        &receiver_name,
        receiver_coin,
        &receiver_bindings,
        &[],
    )?;
    let listed_duplicates = listed["coin.duplicates"]
        .as_array()
        .context("receiver duplicate list is not an array")?;
    assert_eq!(listed_duplicates.len(), 2);
    assert!(listed_duplicates.iter().all(|duplicate| {
        duplicate["cooperative_only"].as_bool() == Some(true)
            && duplicate["server_dependent"].as_bool() == Some(true)
    }));

    mercuryrustlib::coin_status::update_coins(&fixture.config, &fixture.wallet_name).await?;
    assert!(
        mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?
        .iter()
        .all(|binding| binding.ownership_status == Bip448OwnershipStatus::Previous),
        "positive rotation did not retire every sender binding"
    );

    // The receiver independently chooses its locally assigned indices and
    // timing. Sweep in reverse local-index order to avoid implying that sender
    // indices or notifications coordinate the action.
    let mut receiver_duplicate_indices = receiver_bindings
        .iter()
        .filter(|binding| binding.role == Bip448BindingRole::Duplicate)
        .map(|binding| binding.binding_index)
        .collect::<Vec<_>>();
    receiver_duplicate_indices.sort_unstable_by(|left, right| right.cmp(left));
    let destination = common::bitcoin_core::getnewaddress()?;
    for duplicate_index in &receiver_duplicate_indices {
        mercuryrustlib::bip448_withdraw::execute_duplicate_sweep(
            &fixture.config,
            &receiver_name,
            &fixture.statechain_id,
            *duplicate_index,
            &destination,
            Some(1.0),
        )
        .await?;
        assert!(
            mercuryrustlib::utils::get_statechain_info(&fixture.statechain_id, &fixture.config)
                .await?
                .is_some(),
            "duplicate sweep deleted the canonical statechain"
        );
    }
    mercuryrustlib::bip448_withdraw::execute(
        &fixture.config,
        &receiver_name,
        &fixture.statechain_id,
        &destination,
        Some(1.0),
    )
    .await?;
    assert!(
        mercuryrustlib::utils::get_statechain_info(&fixture.statechain_id, &fixture.config)
            .await?
            .is_none(),
        "receiver did not close canonical after independently sweeping duplicates"
    );
    println!(
        "BIP448 forced cross-wallet transfer: statechain={} receiver_birth={} receiver_indices={:?}; sender received no notification or sweep guarantee",
        fixture.statechain_id, receiver_birth_height, receiver_duplicate_indices
    );
    Ok(())
}
