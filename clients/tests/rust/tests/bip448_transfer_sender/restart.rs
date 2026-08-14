use super::support::*;
use super::*;

pub(super) async fn bip448_transfer_restart_child() -> Result<()> {
    if std::env::var("ML_BIP448_RESTART_CHILD").as_deref() != Ok("1") {
        return Ok(());
    }
    std::env::set_var("ML_NETWORK", "regtest");
    let config = mercuryrustlib::client_config::load().await;
    let wallet_name = std::env::var("ML_BIP448_RESTART_WALLET")?;
    let statechain_id = std::env::var("ML_BIP448_RESTART_STATECHAIN_ID")?;
    let result = if std::env::var("ML_BIP448_RESTART_OPERATION").as_deref() == Ok("cancel") {
        mercuryrustlib::bip448_transfer_sender::cancel_bip448_transfer(
            &config,
            &wallet_name,
            &statechain_id,
        )
        .await
        .map(|_| ())
    } else {
        mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender(
            &config,
            &std::env::var("ML_BIP448_RESTART_RECIPIENT")?,
            &wallet_name,
            &statechain_id,
            std::env::var("ML_BIP448_RESTART_BATCH_ID").ok(),
        )
        .await
    };
    config.pool.close().await;
    result
}
pub(super) async fn bip448_transfer_survives_signing_and_upload_restarts() -> Result<()> {
    let _guard = common::test_guard();
    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury).await?;
    let lockbox = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox).await?;
    common::prepare_test_env().await?.pool.close().await;
    let server_pool = sqlx::PgPool::connect(common::mercury::database_url()).await?;
    let checkpoints = [
        ("transfer_intent_prepared", 1u32, 1i64, false, None),
        ("transfer_sender_armed", 1, 1, false, None),
        (
            "transfer_sender_response_returned",
            1,
            1,
            false,
            Some(("SenderArmed", "NotStarted")),
        ),
        (
            "transfer_x1_persisted",
            1,
            1,
            false,
            Some(("X1Stored", "NotStarted")),
        ),
        (
            "transfer_state_sign_first_armed",
            1,
            1,
            true,
            Some(("X1Stored", "FirstArmed")),
        ),
        (
            "transfer_state_sign_first_response_returned",
            1,
            1,
            true,
            Some(("X1Stored", "FirstArmed")),
        ),
        (
            "transfer_state_nonce_persisted",
            1,
            1,
            true,
            Some(("X1Stored", "NonceStored")),
        ),
        (
            "transfer_state_sign_second_armed",
            1,
            1,
            true,
            Some(("X1Stored", "SecondArmed")),
        ),
        (
            "transfer_state_sign_second_response_returned",
            2,
            1,
            true,
            Some(("X1Stored", "SecondArmed")),
        ),
        (
            "transfer_state_signed_persisted",
            2,
            1,
            true,
            Some(("X1Stored", "Signed")),
        ),
        ("transfer_sender_finished", 2, 2, true, None),
    ];
    for (index, (checkpoint, expected_count, expected_history, pending_exists, phase)) in
        checkpoints.into_iter().enumerate()
    {
        let config = mercuryrustlib::client_config::load().await;
        let sender_name = format!("bip448-transfer-phase-{index}-{}", uuid::Uuid::new_v4());
        let receiver_name = format!("bip448-transfer-phase-r-{index}-{}", uuid::Uuid::new_v4());
        let sender = create_wallet(&config, &sender_name).await?;
        let receiver = create_wallet(&config, &receiver_name).await?;
        let statechain_id = create_confirmed_deposit(&config, &sender).await?;
        let recipient =
            mercuryrustlib::transfer_receiver::new_transfer_address(&config, &receiver.name)
                .await?;
        let batch_id = format!("bip448-restart-batch-{index}-{}", uuid::Uuid::new_v4());
        config.pool.close().await;

        assert_exit(
            &run_child_with_batch(
                &sender_name,
                &statechain_id,
                &recipient,
                Some(checkpoint),
                Some(&batch_id),
            )?,
            RESTART_EXIT,
            checkpoint,
        )?;
        let interrupted = mercuryrustlib::client_config::load().await;
        let history_len = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bip448_state_history WHERE wallet_name=$1 AND statechain_id=$2",
        )
        .bind(&sender_name)
        .bind(&statechain_id)
        .fetch_one(&interrupted.pool)
        .await?;
        assert_eq!(history_len, expected_history, "history at {checkpoint}");
        assert_eq!(
            mercuryrustlib::sqlite_manager::get_bip448_pending_transfer_signing(
                &interrupted.pool,
                &sender_name,
                &statechain_id,
            )
            .await?
            .is_some(),
            pending_exists,
            "pending journal at {checkpoint}"
        );
        let active = mercuryrustlib::sqlite_manager::get_active_bip448_transfer_intent(
            &interrupted.pool,
            &sender_name,
            &statechain_id,
        )
        .await?;
        if checkpoint == "transfer_sender_finished" {
            assert!(
                active.is_none(),
                "finished UserTransfer intent must be deleted"
            );
        } else {
            let active = active.context("checkpoint lost its one Active transfer intent")?;
            if let Some((expected_phase, expected_signing_phase)) = phase {
                assert_eq!(active.phase.as_str(), expected_phase);
                assert_eq!(active.state_signing_phase.as_str(), expected_signing_phase);
            }
        }
        assert_eq!(
            common::lockbox::get_signature_count(&lockbox, &statechain_id).await?,
            expected_count,
            "remote count at {checkpoint}"
        );
        let row = sqlx::query_as::<_, (Vec<u8>, Option<String>, bool)>(
            "SELECT x1,batch_id,key_updated FROM statechain_transfer WHERE statechain_id=$1",
        )
        .bind(&statechain_id)
        .fetch_optional(&server_pool)
        .await?;
        let expects_server_row = !matches!(
            checkpoint,
            "transfer_intent_prepared" | "transfer_sender_armed"
        );
        assert_eq!(
            row.is_some(),
            expects_server_row,
            "server row at {checkpoint}"
        );
        if let Some((x1, stored_batch, key_updated)) = &row {
            assert_eq!(x1.len(), 32);
            assert_eq!(stored_batch.as_deref(), Some(batch_id.as_str()));
            assert!(!key_updated);
        }
        interrupted.pool.close().await;

        if matches!(
            checkpoint,
            "transfer_sender_response_returned"
                | "transfer_state_sign_first_response_returned"
                | "transfer_state_sign_second_response_returned"
        ) {
            assert_exit(
                &run_child_with_batch(
                    &sender_name,
                    &statechain_id,
                    &recipient,
                    Some(checkpoint),
                    Some(&batch_id),
                )?,
                RESTART_EXIT,
                &format!("exact replay of {checkpoint}"),
            )?;
            let replayed_row = sqlx::query_as::<_, (Vec<u8>, Option<String>, bool)>(
                "SELECT x1,batch_id,key_updated FROM statechain_transfer WHERE statechain_id=$1",
            )
            .bind(&statechain_id)
            .fetch_one(&server_pool)
            .await?;
            assert_eq!(
                Some(replayed_row),
                row,
                "server generation changed on replay"
            );
            assert_eq!(
                common::lockbox::get_signature_count(&lockbox, &statechain_id).await?,
                expected_count,
                "response-loss replay changed count at {checkpoint}"
            );
        }
        assert_exit(
            &run_child_with_batch(
                &sender_name,
                &statechain_id,
                &recipient,
                None,
                Some(&batch_id),
            )?,
            0,
            &format!("final resume after {checkpoint}"),
        )?;
        let recovered = mercuryrustlib::client_config::load().await;
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM bip448_state_history WHERE wallet_name=$1 AND statechain_id=$2",
            )
            .bind(&sender_name)
            .bind(&statechain_id)
            .fetch_one(&recovered.pool)
            .await?,
            2
        );
        assert!(
            mercuryrustlib::sqlite_manager::get_active_bip448_transfer_intent(
                &recovered.pool,
                &sender_name,
                &statechain_id,
            )
            .await?
            .is_none()
        );
        assert!(
            mercuryrustlib::sqlite_manager::get_bip448_pending_transfer_signing(
                &recovered.pool,
                &sender_name,
                &statechain_id,
            )
            .await?
            .is_some(),
            "completed sender checkpoint must retain the signed journal until rotation"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM statechain_transfer WHERE statechain_id=$1"
            )
            .bind(&statechain_id)
            .fetch_one(&server_pool)
            .await?,
            1
        );
        assert_eq!(
            common::lockbox::get_signature_count(&lockbox, &statechain_id).await?,
            2
        );
        recovered.pool.close().await;
    }
    for (index, checkpoint) in ["server_nonce_persisted", "transfer_msg_persisted"]
        .into_iter()
        .enumerate()
    {
        let config = mercuryrustlib::client_config::load().await;
        let sender_name = format!("bip448-transfer-sender-{index}-{}", uuid::Uuid::new_v4());
        let receiver_name = format!("bip448-transfer-receiver-{index}-{}", uuid::Uuid::new_v4());
        let sender = create_wallet(&config, &sender_name).await?;
        let receiver = create_wallet(&config, &receiver_name).await?;
        let statechain_id = create_confirmed_deposit(&config, &sender).await?;
        let recipient =
            mercuryrustlib::transfer_receiver::new_transfer_address(&config, &receiver.name)
                .await?;
        let wrong_recipient =
            mercuryrustlib::transfer_receiver::new_transfer_address(&config, &receiver.name)
                .await?;
        let receiver =
            mercuryrustlib::sqlite_manager::get_wallet(&config.pool, &receiver.name).await?;
        let recipient_coin = receiver
            .coins
            .iter()
            .find(|coin| coin.address == recipient)
            .context("recipient transfer coin is missing")?;
        let (auth_pubkey, auth_privkey) = (
            recipient_coin.auth_pubkey.clone(),
            recipient_coin.auth_privkey.clone(),
        );
        let same_auth_wrong_user = mercurylib::encode_sc_address(
            &mercurylib::decode_transfer_address(&wrong_recipient)?.1,
            &mercurylib::decode_transfer_address(&recipient)?.2,
            config.network,
        )?;
        config.pool.close().await;
        assert_exit(
            &run_child(&sender_name, &statechain_id, &recipient, Some(checkpoint))?,
            RESTART_EXIT,
            checkpoint,
        )?;
        let interrupted = mercuryrustlib::client_config::load().await;
        let pending = mercuryrustlib::sqlite_manager::get_bip448_pending_transfer_signing(
            &interrupted.pool,
            &sender_name,
            &statechain_id,
        )
        .await?
        .context("transfer restart did not preserve its signing journal")?;
        let persisted = if checkpoint == "transfer_msg_persisted" {
            Some(
                mercuryrustlib::sqlite_manager::get_bip448_transfer_msg(
                    &interrupted.pool,
                    &sender_name,
                    &statechain_id,
                    &auth_pubkey,
                )
                .await?,
            )
        } else {
            None
        };
        let mut first_ciphertext = None;
        let expected_count = if checkpoint == "server_nonce_persisted" {
            1
        } else {
            2
        };
        assert_eq!(
            common::lockbox::get_signature_count(&lockbox, &statechain_id).await?,
            expected_count
        );
        interrupted.pool.close().await;
        if checkpoint == "transfer_msg_persisted" {
            assert!(
                get_encrypted_msg(&mercury, &auth_pubkey).await.is_err(),
                "plaintext checkpoint must fire before upload"
            );
            let mutation = mercuryrustlib::client_config::load().await;
            let active = mercuryrustlib::sqlite_manager::get_active_bip448_transfer_intent(
                &mutation.pool,
                &sender_name,
                &statechain_id,
            )
            .await?
            .context("Signed transfer intent is missing before mutation checks")?;
            let (_, exact_raw) =
                mercuryrustlib::sqlite_manager::get_bip448_transfer_msg_raw_optional(
                    &mutation.pool,
                    &sender_name,
                    &statechain_id,
                    None,
                )
                .await?
                .context("Signed transfer raw message is missing before mutation checks")?;
            let original_x1 = active
                .server_x1
                .clone()
                .context("Signed transfer intent x1 is missing before mutation checks")?;
            let alternate_x1 = if original_x1 == "02".repeat(32) {
                "03".repeat(32)
            } else {
                "02".repeat(32)
            };
            assert_eq!(
                sqlx::query(
                    "UPDATE bip448_transfer_intents SET server_x1=$1 \
                     WHERE wallet_name=$2 AND statechain_id=$3 AND intent_id=$4"
                )
                .bind(&alternate_x1)
                .bind(&sender_name)
                .bind(&statechain_id)
                .bind(&active.intent_id)
                .execute(&mutation.pool)
                .await?
                .rows_affected(),
                1
            );
            mutation.pool.close().await;
            let rejected_x1 = run_child(&sender_name, &statechain_id, &recipient, None)?;
            assert!(
                !rejected_x1.status.success()
                    && String::from_utf8_lossy(&rejected_x1.stderr)
                        .contains("persisted transfer t1 does not match its active intent x1")
            );
            let mutation = mercuryrustlib::client_config::load().await;
            assert_eq!(
                common::lockbox::get_signature_count(&lockbox, &statechain_id).await?,
                2,
                "x1 mutation rejection changed the remote signature count"
            );
            assert_eq!(
                mercuryrustlib::sqlite_manager::get_bip448_pending_transfer_signing(
                    &mutation.pool,
                    &sender_name,
                    &statechain_id,
                )
                .await?,
                Some(pending.clone())
            );
            assert_eq!(
                sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM bip448_state_history \
                     WHERE wallet_name=$1 AND statechain_id=$2"
                )
                .bind(&sender_name)
                .bind(&statechain_id)
                .fetch_one(&mutation.pool)
                .await?,
                2
            );
            assert_eq!(
                mercuryrustlib::sqlite_manager::get_bip448_transfer_msg_raw_optional(
                    &mutation.pool,
                    &sender_name,
                    &statechain_id,
                    None,
                )
                .await?
                .context("x1 mutation rejection deleted the exact raw message")?
                .1,
                exact_raw
            );
            assert_eq!(
                sqlx::query(
                    "UPDATE bip448_transfer_intents SET server_x1=$1 \
                     WHERE wallet_name=$2 AND statechain_id=$3 AND intent_id=$4 AND server_x1=$5"
                )
                .bind(&original_x1)
                .bind(&sender_name)
                .bind(&statechain_id)
                .bind(&active.intent_id)
                .bind(&alternate_x1)
                .execute(&mutation.pool)
                .await?
                .rows_affected(),
                1
            );
            let mut tampered_message: mercurylib::transfer::bip448::Bip448TransferMsg =
                serde_json::from_str(&exact_raw)?;
            tampered_message.transfer_signature = "01".repeat(64);
            let tampered_raw = serde_json::to_string(&tampered_message)?;
            assert_ne!(tampered_raw, exact_raw);
            assert_eq!(
                sqlx::query(
                    "UPDATE bip448_transfer_messages SET transfer_msg_json=$1 \
                     WHERE wallet_name=$2 AND statechain_id=$3 AND recipient_auth_pubkey=$4 \
                     AND transfer_msg_json=$5"
                )
                .bind(&tampered_raw)
                .bind(&sender_name)
                .bind(&statechain_id)
                .bind(&auth_pubkey)
                .bind(&exact_raw)
                .execute(&mutation.pool)
                .await?
                .rows_affected(),
                1
            );
            mutation.pool.close().await;
            let rejected_signature = run_child(&sender_name, &statechain_id, &recipient, None)?;
            assert!(
                !rejected_signature.status.success()
                    && String::from_utf8_lossy(&rejected_signature.stderr)
                        .contains("persisted transfer signature is invalid")
            );
            let mutation = mercuryrustlib::client_config::load().await;
            assert_eq!(
                common::lockbox::get_signature_count(&lockbox, &statechain_id).await?,
                2,
                "signature mutation rejection changed the remote signature count"
            );
            assert_eq!(
                mercuryrustlib::sqlite_manager::get_bip448_pending_transfer_signing(
                    &mutation.pool,
                    &sender_name,
                    &statechain_id,
                )
                .await?,
                Some(pending.clone())
            );
            assert_eq!(
                mercuryrustlib::sqlite_manager::get_bip448_transfer_msg_raw_optional(
                    &mutation.pool,
                    &sender_name,
                    &statechain_id,
                    None,
                )
                .await?
                .context("signature mutation rejection deleted the tampered raw message")?
                .1,
                tampered_raw
            );
            assert_eq!(
                sqlx::query(
                    "UPDATE bip448_transfer_messages SET transfer_msg_json=$1 \
                     WHERE wallet_name=$2 AND statechain_id=$3 AND recipient_auth_pubkey=$4 \
                     AND transfer_msg_json=$5"
                )
                .bind(&exact_raw)
                .bind(&sender_name)
                .bind(&statechain_id)
                .bind(&auth_pubkey)
                .bind(&tampered_raw)
                .execute(&mutation.pool)
                .await?
                .rows_affected(),
                1
            );
            let exact_active = mercuryrustlib::sqlite_manager::get_active_bip448_transfer_intent(
                &mutation.pool,
                &sender_name,
                &statechain_id,
            )
            .await?
            .context("Signed transfer intent is missing before generation substitution")?;
            let exact_history = mercuryrustlib::sqlite_manager::get_bip448_state_history(
                &mutation.pool,
                &sender_name,
                &statechain_id,
            )
            .await?;
            mutation.pool.close().await;
            assert_exit(
                &run_child(
                    &sender_name,
                    &statechain_id,
                    &recipient,
                    Some("transfer_msg_uploaded"),
                )?,
                RESTART_EXIT,
                "replayed upload checkpoint",
            )?;
            first_ciphertext = Some(get_encrypted_msg(&mercury, &auth_pubkey).await?);
            let rejected = run_child(&sender_name, &statechain_id, &same_auth_wrong_user, None)?;
            assert!(
                !rejected.status.success()
                    && String::from_utf8_lossy(&rejected.stderr).contains(
                        "persisted transfer message does not match the recipient address"
                    )
            );
            assert_eq!(
                get_encrypted_msg(&mercury, &auth_pubkey).await?,
                first_ciphertext.as_ref().unwrap().clone()
            );
            sqlx::query("UPDATE statechain_transfer SET new_user_auth_public_key = $1 WHERE statechain_id = $2").bind(mercurylib::decode_transfer_address(&wrong_recipient)?.2.serialize().to_vec()).bind(&statechain_id).execute(&server_pool).await?;
            let substituted_server_row = sqlx::query_scalar::<_, String>(
                "SELECT row_to_json(transfer_row)::text \
                 FROM statechain_transfer AS transfer_row WHERE statechain_id=$1",
            )
            .bind(&statechain_id)
            .fetch_one(&server_pool)
            .await?;
            let undelivered = run_child(&sender_name, &statechain_id, &recipient, None)?;
            assert!(
                !undelivered.status.success()
                    && String::from_utf8_lossy(&undelivered.stderr)
                        .contains("Failed to update transfer message")
            );
            let retryable = mercuryrustlib::client_config::load().await;
            assert_eq!(
                mercuryrustlib::sqlite_manager::get_active_bip448_transfer_intent(
                    &retryable.pool,
                    &sender_name,
                    &statechain_id,
                )
                .await?
                .context("generation-fenced rejection deleted the Signed transfer intent")?,
                exact_active
            );
            assert_eq!(
                mercuryrustlib::sqlite_manager::get_bip448_pending_transfer_signing(
                    &retryable.pool,
                    &sender_name,
                    &statechain_id
                )
                .await?,
                Some(pending.clone())
            );
            assert_eq!(
                mercuryrustlib::sqlite_manager::get_bip448_state_history(
                    &retryable.pool,
                    &sender_name,
                    &statechain_id,
                )
                .await?,
                exact_history
            );
            assert_eq!(
                mercuryrustlib::sqlite_manager::get_bip448_transfer_msg_raw_optional(
                    &retryable.pool,
                    &sender_name,
                    &statechain_id,
                    None,
                )
                .await?
                .context("generation-fenced rejection deleted the exact raw message")?
                .1,
                exact_raw
            );
            assert_eq!(
                common::lockbox::get_signature_count(&lockbox, &statechain_id).await?,
                2,
                "generation-fenced rejection changed the remote signature count"
            );
            let server_row_after_rejection = sqlx::query_scalar::<_, String>(
                "SELECT row_to_json(transfer_row)::text \
                 FROM statechain_transfer AS transfer_row WHERE statechain_id=$1",
            )
            .bind(&statechain_id)
            .fetch_one(&server_pool)
            .await?;
            assert!(
                server_row_after_rejection == substituted_server_row,
                "generation-fenced rejection mutated the substituted Mercury row"
            );
            let sender =
                mercuryrustlib::sqlite_manager::get_wallet(&retryable.pool, &sender_name).await?;
            assert_eq!(
                sender
                    .coins
                    .iter()
                    .find(|coin| coin.statechain_id.as_deref() == Some(&statechain_id))
                    .unwrap()
                    .status,
                CoinStatus::CONFIRMED
            );
            retryable.pool.close().await;
            sqlx::query("UPDATE statechain_transfer SET new_user_auth_public_key = $1 WHERE statechain_id = $2").bind(mercurylib::decode_transfer_address(&recipient)?.2.serialize().to_vec()).bind(&statechain_id).execute(&server_pool).await?;
        }
        assert_exit(
            &run_child(&sender_name, &statechain_id, &recipient, None)?,
            0,
            &format!("resume after {checkpoint}"),
        )?;
        let recovered = mercuryrustlib::client_config::load().await;
        assert_eq!(
            mercuryrustlib::sqlite_manager::get_bip448_pending_transfer_signing(
                &recovered.pool,
                &sender_name,
                &statechain_id
            )
            .await?,
            Some(pending.clone()),
            "delivered transfer must retain its signing journal until rotation"
        );
        let transfer_msg = mercuryrustlib::sqlite_manager::get_bip448_transfer_msg(
            &recovered.pool,
            &sender_name,
            &statechain_id,
            &auth_pubkey,
        )
        .await?;
        assert_eq!(
            transfer_msg.latest_state.signing_metadata.signing_id,
            pending.signing_id
        );
        assert_eq!(
            transfer_msg
                .latest_state
                .signing_metadata
                .client_public_nonce,
            pending.client_public_nonce
        );
        assert_eq!(
            common::lockbox::get_signature_count(&lockbox, &statechain_id).await?,
            2,
            "resume must produce exactly one state-2 signature"
        );
        let sender =
            mercuryrustlib::sqlite_manager::get_wallet(&recovered.pool, &sender_name).await?;
        assert_eq!(
            sender
                .coins
                .iter()
                .find(|coin| coin.statechain_id.as_deref() == Some(&statechain_id))
                .context("transferred coin is missing")?
                .status,
            CoinStatus::IN_TRANSFER
        );
        if let (Some(persisted), Some(first)) = (persisted, first_ciphertext) {
            assert_eq!(transfer_msg, persisted);
            let second = get_encrypted_msg(&mercury, &auth_pubkey).await?;
            assert_ne!(first, second);
            assert_eq!(
                decrypt_bip448_transfer_msg(&first, &auth_privkey)?,
                persisted
            );
            assert_eq!(
                decrypt_bip448_transfer_msg(&second, &auth_privkey)?,
                persisted
            );
        }
        recovered.pool.close().await;
    }
    assert_signed_transfer_pending_nonce_races(&lockbox).await?;
    server_pool.close().await;
    Ok(())
}

async fn assert_signed_transfer_pending_nonce_races(lockbox: &reqwest::Client) -> Result<()> {
    let mercury = common::mercury::http_client();
    for (case, prepare_checkpoint, barrier, expected_error, message_exists) in [
        (
            "new-message",
            "transfer_state_signed_persisted",
            "transfer_pending_validated_before_materialization",
            "pending signing changed after complete validation",
            false,
        ),
        (
            "stored-message",
            "transfer_msg_persisted",
            "transfer_materialized_before_sender_finish",
            "pending signing changed after complete validation",
            true,
        ),
    ] {
        let config = mercuryrustlib::client_config::load().await;
        let suffix = uuid::Uuid::new_v4();
        let sender_name = format!("bip448-pending-race-{case}-s-{suffix}");
        let receiver_name = format!("bip448-pending-race-{case}-r-{suffix}");
        let sender = create_wallet(&config, &sender_name).await?;
        let receiver = create_wallet(&config, &receiver_name).await?;
        let statechain_id = create_confirmed_deposit(&config, &sender).await?;
        let recipient =
            mercuryrustlib::transfer_receiver::new_transfer_address(&config, &receiver.name)
                .await?;
        let recipient_auth = mercurylib::decode_transfer_address(&recipient)?
            .2
            .to_string();
        config.pool.close().await;

        assert_exit(
            &run_child(
                &sender_name,
                &statechain_id,
                &recipient,
                Some(prepare_checkpoint),
            )?,
            RESTART_EXIT,
            &format!("{case} pending-row race preparation"),
        )?;

        let (mut child, reached, release) =
            spawn_child_at_barrier(&sender_name, &statechain_id, &recipient, barrier)?;
        wait_for_child_barrier(&mut child, &reached, barrier)?;

        let mutation = mercuryrustlib::client_config::load().await;
        let original_pending = mercuryrustlib::sqlite_manager::get_bip448_pending_transfer_signing(
            &mutation.pool,
            &sender_name,
            &statechain_id,
        )
        .await?
        .context("pending-row race lost its validated signing row")?;
        let replacement_secret_nonce =
            different_valid_client_secret_nonce(&original_pending.client_secret_nonce)?;
        let before =
            capture_pending_nonce_race_base(&mutation, &sender_name, &statechain_id).await?;
        assert_eq!(
            !before.outgoing_transfer_message_rows.is_empty(),
            message_exists,
            "{case} race reached the wrong materialization boundary"
        );
        let mailbox_before = get_encrypted_msgs(&mercury, &recipient_auth).await?;
        let count_before = common::lockbox::get_signature_count(lockbox, &statechain_id).await?;
        assert_eq!(count_before, 2, "{case} race changed count before mutation");

        let mut second_connection = mutation.pool.acquire().await?;
        let changed = sqlx::query(
            "UPDATE bip448_pending_transfer_signings SET client_secret_nonce=$1 \
             WHERE wallet_name=$2 AND statechain_id=$3 AND signing_id=$4 \
             AND client_secret_nonce=$5",
        )
        .bind(&replacement_secret_nonce)
        .bind(&sender_name)
        .bind(&statechain_id)
        .bind(&original_pending.signing_id)
        .bind(&original_pending.client_secret_nonce)
        .execute(&mut *second_connection)
        .await?;
        drop(second_connection);
        assert_eq!(
            changed.rows_affected(),
            1,
            "{case} race did not change exactly one pending row"
        );

        let rejected = release_child_barrier(child, &reached, &release)?;
        assert!(
            !rejected.status.success()
                && String::from_utf8_lossy(&rejected.stderr).contains(expected_error),
            "{case} race was not rejected at its guarded boundary\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&rejected.stdout),
            String::from_utf8_lossy(&rejected.stderr),
        );

        let mut expected_changed_pending = original_pending.clone();
        expected_changed_pending.client_secret_nonce = replacement_secret_nonce.clone();
        assert_eq!(
            mercuryrustlib::sqlite_manager::get_bip448_pending_transfer_signing(
                &mutation.pool,
                &sender_name,
                &statechain_id,
            )
            .await?,
            Some(expected_changed_pending),
            "{case} rejection changed another pending-row field"
        );
        let after =
            capture_pending_nonce_race_base(&mutation, &sender_name, &statechain_id).await?;
        let mut after_without_deliberate_edit = after;
        after_without_deliberate_edit.pending_transfer_rows = before.pending_transfer_rows.clone();
        assert_eq!(
            after_without_deliberate_edit, before,
            "{case} rejection changed Coin, binding, message, history, intent, or other local state"
        );
        assert_eq!(
            get_encrypted_msgs(&mercury, &recipient_auth).await?,
            mailbox_before,
            "{case} rejection made another message upload"
        );
        assert_eq!(
            common::lockbox::get_signature_count(lockbox, &statechain_id).await?,
            count_before,
            "{case} rejection changed the server signature count"
        );

        let restored = sqlx::query(
            "UPDATE bip448_pending_transfer_signings SET client_secret_nonce=$1 \
             WHERE wallet_name=$2 AND statechain_id=$3 AND signing_id=$4 \
             AND client_secret_nonce=$5",
        )
        .bind(&original_pending.client_secret_nonce)
        .bind(&sender_name)
        .bind(&statechain_id)
        .bind(&original_pending.signing_id)
        .bind(&replacement_secret_nonce)
        .execute(&mutation.pool)
        .await?;
        assert_eq!(
            restored.rows_affected(),
            1,
            "{case} race could not restore its exact validated pending row"
        );
        mutation.pool.close().await;

        assert_exit(
            &run_child(&sender_name, &statechain_id, &recipient, None)?,
            0,
            &format!("normal replay after {case} pending-row race"),
        )?;
        let recovered = mercuryrustlib::client_config::load().await;
        assert_eq!(
            mercuryrustlib::sqlite_manager::get_bip448_pending_transfer_signing(
                &recovered.pool,
                &sender_name,
                &statechain_id,
            )
            .await?,
            Some(original_pending),
            "{case} normal replay did not retain the restored pending row"
        );
        assert!(
            mercuryrustlib::sqlite_manager::get_active_bip448_transfer_intent(
                &recovered.pool,
                &sender_name,
                &statechain_id,
            )
            .await?
            .is_none(),
            "{case} normal replay did not finish the UserTransfer intent"
        );
        let sender =
            mercuryrustlib::sqlite_manager::get_wallet(&recovered.pool, &sender_name).await?;
        assert_eq!(
            sender
                .coins
                .iter()
                .find(|coin| coin.statechain_id.as_deref() == Some(&statechain_id))
                .context("normal replay sender Coin is missing")?
                .status,
            CoinStatus::IN_TRANSFER,
            "{case} normal replay did not finish the sender Coin"
        );
        assert_eq!(
            common::lockbox::get_signature_count(lockbox, &statechain_id).await?,
            2,
            "{case} normal replay consumed another signature"
        );
        recovered.pool.close().await;
    }
    Ok(())
}

async fn capture_pending_nonce_race_base(
    config: &ClientConfig,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<mercuryrustlib::bip448_funding::Bip448SyncBase> {
    let bindings = mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
        &config.pool,
        wallet_name,
        statechain_id,
    )
    .await?;
    let script = bindings
        .first()
        .context("pending-row race has no persisted funding binding")?
        .script_pubkey
        .clone();
    mercuryrustlib::sqlite_manager::capture_bip448_sync_base(&config.pool, wallet_name, &script)
        .await
}

fn different_valid_client_secret_nonce(original: &str) -> Result<String> {
    use secp256k1::{
        musig::{new_musig_nonce_pair, MusigSessionId},
        Secp256k1, SecretKey,
    };

    let secp = Secp256k1::new();
    let mut rng = secp256k1::rand::rng();
    for _ in 0..8 {
        let secret_key = SecretKey::new(&mut rng);
        let public_key = secret_key.public_key(&secp);
        let (secret_nonce, _) = new_musig_nonce_pair(
            &secp,
            MusigSessionId::new(&mut rng),
            None,
            Some(secret_key),
            public_key,
            None,
            None,
        )?;
        let candidate = hex::encode(secret_nonce.serialize());
        if candidate != original {
            return Ok(candidate);
        }
    }
    Err(anyhow!(
        "failed to generate a different valid MuSig secret nonce"
    ))
}

fn spawn_child_at_barrier(
    wallet: &str,
    statechain_id: &str,
    recipient: &str,
    barrier: &str,
) -> Result<(Child, PathBuf, PathBuf)> {
    let id = uuid::Uuid::new_v4();
    let reached = std::env::temp_dir().join(format!("bip448-{id}-barrier-reached"));
    let release = std::env::temp_dir().join(format!("bip448-{id}-barrier-release"));
    if reached.try_exists()? || release.try_exists()? {
        return Err(anyhow!("unique BIP448 test barrier path already exists"));
    }
    let child = Command::new(std::env::current_exe()?)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "--ignored",
            "--exact",
            "bip448_transfer_restart_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ML_BIP448_RESTART_CHILD", "1")
        .env("ML_BIP448_RESTART_WALLET", wallet)
        .env("ML_BIP448_RESTART_STATECHAIN_ID", statechain_id)
        .env("ML_BIP448_RESTART_RECIPIENT", recipient)
        .env("ML_BIP448_TEST_BARRIER", barrier)
        .env("ML_BIP448_TEST_BARRIER_REACHED", &reached)
        .env("ML_BIP448_TEST_BARRIER_RELEASE", &release)
        .env("ML_NETWORK", "regtest")
        .env_remove("ML_BIP448_TEST_CHECKPOINT")
        .env_remove("ML_BIP448_RESTART_BATCH_ID")
        .env_remove("ML_BIP448_RESTART_OPERATION")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    Ok((child, reached, release))
}

fn wait_for_child_barrier(child: &mut Child, reached: &Path, barrier: &str) -> Result<()> {
    for _ in 0..6_000 {
        if reached.try_exists()? {
            let observed = std::fs::read_to_string(reached)?;
            if observed != barrier {
                return Err(anyhow!(
                    "BIP448 child reached {observed}, expected {barrier}"
                ));
            }
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            return Err(anyhow!(
                "BIP448 barrier child exited with {status} before reaching {barrier}"
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    let _ = child.wait();
    Err(anyhow!(
        "timed out waiting for BIP448 child barrier {barrier}"
    ))
}

fn release_child_barrier(child: Child, reached: &Path, release: &Path) -> Result<Output> {
    std::fs::write(release, b"release")?;
    let output = child.wait_with_output();
    for path in [reached, release] {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(output?)
}
async fn get_encrypted_msg(client: &reqwest::Client, auth_pubkey: &str) -> Result<String> {
    get_encrypted_msgs(client, auth_pubkey)
        .await?
        .into_iter()
        .next()
        .context("server transfer message is missing")
}
