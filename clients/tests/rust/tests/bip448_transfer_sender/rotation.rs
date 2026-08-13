use super::support::*;
use super::*;

pub(super) async fn bip448_sender_finishes_after_receiver_rotates_auth_key() -> Result<()> {
    let _guard = common::test_guard();
    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury).await?;
    let lockbox = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox).await?;

    let config = common::prepare_test_env().await?;
    let sender_name = format!("bip448-s3-sender-{}", uuid::Uuid::new_v4());
    let receiver_name = format!("bip448-s3-receiver-{}", uuid::Uuid::new_v4());
    let sender = create_wallet(&config, &sender_name).await?;
    let receiver = create_wallet(&config, &receiver_name).await?;
    let statechain_id = create_confirmed_deposit(&config, &sender).await?;
    let recipient =
        mercuryrustlib::transfer_receiver::new_transfer_address(&config, &receiver.name).await?;
    let receiver = mercuryrustlib::sqlite_manager::get_wallet(&config.pool, &receiver.name).await?;
    let recipient_coin = receiver
        .coins
        .iter()
        .find(|coin| coin.address == recipient)
        .context("recipient transfer coin is missing")?;
    let auth_pubkey = recipient_coin.auth_pubkey.clone();
    config.pool.close().await;

    assert_exit(
        &run_child(
            &sender_name,
            &statechain_id,
            &recipient,
            Some("transfer_msg_uploaded"),
        )?,
        RESTART_EXIT,
        "uploaded transfer before local completion",
    )?;
    let interrupted = mercuryrustlib::client_config::load().await;
    assert!(
        mercuryrustlib::sqlite_manager::get_bip448_pending_transfer_signing(
            &interrupted.pool,
            &sender_name,
            &statechain_id,
        )
        .await?
        .is_some()
    );
    let sender =
        mercuryrustlib::sqlite_manager::get_wallet(&interrupted.pool, &sender_name).await?;
    assert_eq!(
        sender
            .coins
            .iter()
            .find(|coin| coin.statechain_id.as_deref() == Some(&statechain_id))
            .context("sender transfer coin is missing")?
            .status,
        CoinStatus::CONFIRMED
    );
    let mailbox_before = get_encrypted_msgs(&mercury, &auth_pubkey).await?;
    assert_eq!(mailbox_before.len(), 1);

    let received = mercuryrustlib::transfer_receiver::execute(&interrupted, &receiver_name).await?;
    assert_eq!(
        received.received_statechain_ids,
        vec![statechain_id.clone()]
    );
    let accepted = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &interrupted.pool,
        &receiver_name,
        &statechain_id,
    )
    .await?;
    assert_eq!(accepted.latest_state_number, 2);
    let receiver =
        mercuryrustlib::sqlite_manager::get_wallet(&interrupted.pool, &receiver_name).await?;
    assert_eq!(
        receiver
            .coins
            .iter()
            .find(|coin| {
                coin.statechain_id.as_deref() == Some(&statechain_id)
                    && coin.status == CoinStatus::CONFIRMED
            })
            .context("receiver did not persist the accepted state-2 coin")?
            .status,
        CoinStatus::CONFIRMED
    );
    let (_, original_raw) = mercuryrustlib::sqlite_manager::get_bip448_transfer_msg_raw_optional(
        &interrupted.pool,
        &sender_name,
        &statechain_id,
        Some(&auth_pubkey),
    )
    .await?
    .context("rotated sender message is missing before tamper checks")?;
    let original_message: mercurylib::transfer::bip448::Bip448TransferMsg =
        serde_json::from_str(&original_raw)?;
    for tamper in ["transfer-signature", "t1"] {
        let mut changed = original_message.clone();
        match tamper {
            "transfer-signature" => changed.transfer_signature = "00".repeat(64),
            "t1" => changed.t1 = [10u8; 32],
            _ => unreachable!(),
        }
        let changed_raw = serde_json::to_string(&changed)?;
        set_outgoing_message_raw(
            &interrupted,
            &sender_name,
            &statechain_id,
            &auth_pubkey,
            &changed_raw,
        )
        .await?;
        assert_rotated_resume_fails_without_local_mutation(
            &interrupted,
            &sender_name,
            &statechain_id,
            &recipient,
            2,
            tamper,
        )
        .await?;
        set_outgoing_message_raw(
            &interrupted,
            &sender_name,
            &statechain_id,
            &auth_pubkey,
            &original_raw,
        )
        .await?;
    }
    interrupted.pool.close().await;

    assert_exit(
        &run_child(&sender_name, &statechain_id, &recipient, None)?,
        0,
        "sender resume after receiver key rotation",
    )?;
    let recovered = mercuryrustlib::client_config::load().await;
    assert!(
        mercuryrustlib::sqlite_manager::get_bip448_pending_transfer_signing(
            &recovered.pool,
            &sender_name,
            &statechain_id,
        )
        .await?
        .is_none()
    );
    let sender = mercuryrustlib::sqlite_manager::get_wallet(&recovered.pool, &sender_name).await?;
    assert_eq!(
        sender
            .coins
            .iter()
            .find(|coin| coin.statechain_id.as_deref() == Some(&statechain_id))
            .context("sender transfer coin is missing after recovery")?
            .status,
        CoinStatus::TRANSFERRED
    );
    let bindings = mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
        &recovered.pool,
        &sender_name,
        &statechain_id,
    )
    .await?;
    assert!(!bindings.is_empty());
    assert!(bindings.iter().all(|binding| {
        binding.ownership_status == mercuryrustlib::bip448_funding::Bip448OwnershipStatus::Previous
    }));
    assert!(
        !mercuryrustlib::sqlite_manager::has_bip448_transfer_msg_for_statechain(
            &recovered.pool,
            &sender_name,
            &statechain_id,
        )
        .await?
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox, &statechain_id).await?,
        2
    );
    assert_eq!(
        get_encrypted_msgs(&mercury, &auth_pubkey).await?,
        mailbox_before
    );
    recovered.pool.close().await;
    Ok(())
}
