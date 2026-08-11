mod common;
use anyhow::{anyhow, Context, Result};
use common::bip448_regtest::FUNDING_AMOUNT_SATS;
use mercurylib::transfer::{
    bip448::decrypt_bip448_transfer_msg, receiver::GetMsgAddrResponsePayload,
};
use mercuryrustlib::{client_config::ClientConfig, CoinStatus, Wallet};
use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::Duration,
};
const RESTART_EXIT: i32 = 86;
#[tokio::test]
#[ignore = "internal child entry point for the BIP448 transfer restart test"]
async fn bip448_transfer_restart_child() -> Result<()> {
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
#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_transfer_survives_signing_and_upload_restarts() -> Result<()> {
    let _guard = common::test_guard();
    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury).await?;
    let lockbox = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox).await?;
    common::prepare_test_env().await?.pool.close().await;
    let server_pool =
        sqlx::PgPool::connect("postgres://postgres:postgres@127.0.0.1:5432/mercury").await?;
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

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_sender_finishes_after_receiver_rotates_auth_key() -> Result<()> {
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

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_retarget_before_signing_reuses_next_state() -> Result<()> {
    let _guard = common::test_guard();
    assert_true_pre_sign_retarget().await?;
    for (checkpoint, expected_signing_phase) in [
        ("transfer_state_sign_first_armed", "FirstArmed"),
        ("transfer_state_nonce_persisted", "NonceStored"),
    ] {
        assert_mid_sign_retarget_finishes_predecessor(checkpoint, expected_signing_phase).await?;
    }
    assert_predecessor_wins_prepared_barrier().await?;
    Ok(())
}

async fn assert_predecessor_wins_prepared_barrier() -> Result<()> {
    use secp256k1::{Secp256k1, SecretKey};

    let config = phase8_9_config().await?;
    let suffix = uuid::Uuid::new_v4();
    let sender = create_wallet(&config, &format!("bip448-predecessor-race-a-{suffix}")).await?;
    let predecessor_receiver =
        create_wallet(&config, &format!("bip448-predecessor-race-b-{suffix}")).await?;
    let successor_receiver =
        create_wallet(&config, &format!("bip448-predecessor-race-c-{suffix}")).await?;
    let statechain_id = create_confirmed_deposit(&config, &sender).await?;
    let predecessor_address = mercuryrustlib::transfer_receiver::new_transfer_address(
        &config,
        &predecessor_receiver.name,
    )
    .await?;
    let predecessor_auth = mercurylib::decode_transfer_address(&predecessor_address)?
        .2
        .serialize()
        .to_vec();
    let successor_address =
        mercuryrustlib::transfer_receiver::new_transfer_address(&config, &successor_receiver.name)
            .await?;
    config.pool.close().await;

    assert_exit(
        &run_child(
            &sender.name,
            &statechain_id,
            &predecessor_address,
            Some("transfer_msg_uploaded"),
        )?,
        RESTART_EXIT,
        "predecessor message upload",
    )?;
    assert_exit(
        &run_child(
            &sender.name,
            &statechain_id,
            &successor_address,
            Some("transfer_intent_prepared"),
        )?,
        RESTART_EXIT,
        "successor Prepared barrier",
    )?;

    let resumed = mercuryrustlib::client_config::load().await;
    let active = mercuryrustlib::sqlite_manager::get_active_bip448_transfer_intent(
        &resumed.pool,
        &sender.name,
        &statechain_id,
    )
    .await?
    .context("Prepared successor intent is missing")?;
    assert_eq!(active.phase.as_str(), "Prepared");
    assert_eq!(active.state_signing_phase.as_str(), "NotStarted");
    let bindings = mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
        &resumed.pool,
        &sender.name,
        &statechain_id,
    )
    .await?;
    let script = bindings
        .first()
        .context("predecessor barrier has no passive binding")?
        .script_pubkey
        .clone();
    let barrier_base = mercuryrustlib::sqlite_manager::capture_bip448_sync_base(
        &resumed.pool,
        &sender.name,
        &script,
    )
    .await?;
    let history_before = mercuryrustlib::sqlite_manager::get_bip448_state_history(
        &resumed.pool,
        &sender.name,
        &statechain_id,
    )
    .await?;
    let server_pool =
        sqlx::PgPool::connect("postgres://postgres:postgres@127.0.0.1:5432/mercury").await?;
    let remote_before = sqlx::query_as::<_, (Vec<u8>, Vec<u8>, Option<Vec<u8>>, bool)>(
        "SELECT x1,new_user_auth_public_key,encrypted_transfer_msg,key_updated \
         FROM statechain_transfer WHERE statechain_id=$1",
    )
    .bind(&statechain_id)
    .fetch_one(&server_pool)
    .await?;
    assert_eq!(remote_before.1, predecessor_auth);
    assert!(!remote_before.3);
    let lockbox = common::lockbox::http_client();
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox, &statechain_id).await?,
        2
    );

    let hidden_statechain_id = format!("hidden-{statechain_id}");
    let hidden = sqlx::query("UPDATE statechain_data SET statechain_id=$1 WHERE statechain_id=$2")
        .bind(&hidden_statechain_id)
        .bind(&statechain_id)
        .execute(&server_pool)
        .await?;
    assert_eq!(hidden.rows_affected(), 1);
    let missing_result = mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender(
        &resumed,
        &successor_address,
        &sender.name,
        &statechain_id,
        None,
    )
    .await;
    let restored =
        sqlx::query("UPDATE statechain_data SET statechain_id=$1 WHERE statechain_id=$2")
            .bind(&statechain_id)
            .bind(&hidden_statechain_id)
            .execute(&server_pool)
            .await?;
    assert_eq!(restored.rows_affected(), 1);
    assert!(
        missing_result.is_err(),
        "Missing predecessor presence must fail"
    );
    assert_eq!(
        mercuryrustlib::sqlite_manager::capture_bip448_sync_base(
            &resumed.pool,
            &sender.name,
            &script,
        )
        .await?,
        barrier_base,
        "Missing predecessor response changed successor state"
    );
    assert_eq!(
        sqlx::query_as::<_, (Vec<u8>, Vec<u8>, Option<Vec<u8>>, bool)>(
            "SELECT x1,new_user_auth_public_key,encrypted_transfer_msg,key_updated \
             FROM statechain_transfer WHERE statechain_id=$1",
        )
        .bind(&statechain_id)
        .fetch_one(&server_pool)
        .await?,
        remote_before,
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox, &statechain_id).await?,
        2,
        "Missing predecessor presence made a successor remote signing call"
    );

    let original_server_key = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT server_public_key FROM statechain_data WHERE statechain_id=$1",
    )
    .bind(&statechain_id)
    .fetch_one(&server_pool)
    .await?;
    let unrelated_server = SecretKey::new(&mut secp256k1::rand::rng())
        .public_key(&Secp256k1::new())
        .serialize()
        .to_vec();
    let changed =
        sqlx::query("UPDATE statechain_data SET server_public_key=$1 WHERE statechain_id=$2")
            .bind(&unrelated_server)
            .bind(&statechain_id)
            .execute(&server_pool)
            .await?;
    assert_eq!(changed.rows_affected(), 1);
    let unrelated_result = mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender(
        &resumed,
        &successor_address,
        &sender.name,
        &statechain_id,
        None,
    )
    .await;
    let restored =
        sqlx::query("UPDATE statechain_data SET server_public_key=$1 WHERE statechain_id=$2")
            .bind(&original_server_key)
            .bind(&statechain_id)
            .execute(&server_pool)
            .await?;
    assert_eq!(restored.rows_affected(), 1);
    assert!(
        unrelated_result.is_err(),
        "unrelated predecessor generation must fail"
    );
    assert_eq!(
        mercuryrustlib::sqlite_manager::capture_bip448_sync_base(
            &resumed.pool,
            &sender.name,
            &script,
        )
        .await?,
        barrier_base,
        "unrelated predecessor response changed successor state"
    );
    assert_eq!(
        sqlx::query_as::<_, (Vec<u8>, Vec<u8>, Option<Vec<u8>>, bool)>(
            "SELECT x1,new_user_auth_public_key,encrypted_transfer_msg,key_updated \
             FROM statechain_transfer WHERE statechain_id=$1",
        )
        .bind(&statechain_id)
        .fetch_one(&server_pool)
        .await?,
        remote_before,
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox, &statechain_id).await?,
        2,
        "unrelated predecessor generation made a successor remote signing call"
    );

    common::lockbox::stop_token_stack_lockbox_database().await?;
    let server_error_result = mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender(
        &resumed,
        &successor_address,
        &sender.name,
        &statechain_id,
        None,
    )
    .await;
    common::lockbox::start_token_stack_lockbox_database(&lockbox).await?;
    wait_for_lockbox_signature_count(&lockbox, &statechain_id, 2).await?;
    assert!(
        server_error_result.is_err(),
        "5xx predecessor lookup must fail"
    );
    assert_eq!(
        mercuryrustlib::sqlite_manager::capture_bip448_sync_base(
            &resumed.pool,
            &sender.name,
            &script,
        )
        .await?,
        barrier_base,
        "5xx predecessor response changed successor state"
    );
    assert_eq!(
        sqlx::query_as::<_, (Vec<u8>, Vec<u8>, Option<Vec<u8>>, bool)>(
            "SELECT x1,new_user_auth_public_key,encrypted_transfer_msg,key_updated \
             FROM statechain_transfer WHERE statechain_id=$1",
        )
        .bind(&statechain_id)
        .fetch_one(&server_pool)
        .await?,
        remote_before,
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox, &statechain_id).await?,
        2
    );

    let received =
        mercuryrustlib::transfer_receiver::execute(&resumed, &predecessor_receiver.name).await?;
    assert_eq!(
        received.received_statechain_ids,
        vec![statechain_id.clone()]
    );
    mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender(
        &resumed,
        &successor_address,
        &sender.name,
        &statechain_id,
        None,
    )
    .await?;
    assert!(
        mercuryrustlib::sqlite_manager::get_active_bip448_transfer_intent(
            &resumed.pool,
            &sender.name,
            &statechain_id,
        )
        .await?
        .is_none()
    );
    assert_eq!(
        mercuryrustlib::sqlite_manager::get_bip448_state_history(
            &resumed.pool,
            &sender.name,
            &statechain_id,
        )
        .await?,
        history_before,
        "predecessor win must not sign an N+2 successor state"
    );
    let remote_after = sqlx::query_as::<_, (Vec<u8>, Vec<u8>, Option<Vec<u8>>, bool)>(
        "SELECT x1,new_user_auth_public_key,encrypted_transfer_msg,key_updated \
         FROM statechain_transfer WHERE statechain_id=$1",
    )
    .bind(&statechain_id)
    .fetch_one(&server_pool)
    .await?;
    assert_eq!(
        (remote_after.0, remote_after.1, remote_after.2),
        (remote_before.0, remote_before.1, remote_before.2)
    );
    assert!(remote_after.3);
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox, &statechain_id).await?,
        2,
        "predecessor win made a successor remote signing call"
    );
    let sender_wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&resumed.pool, &sender.name).await?;
    assert_eq!(
        sender_wallet
            .coins
            .iter()
            .find(|coin| coin.statechain_id.as_deref() == Some(&statechain_id))
            .context("predecessor-win sender Coin is missing")?
            .status,
        CoinStatus::TRANSFERRED
    );
    server_pool.close().await;
    resumed.pool.close().await;
    Ok(())
}

async fn assert_true_pre_sign_retarget() -> Result<()> {
    let config = phase8_9_config().await?;
    let suffix = uuid::Uuid::new_v4();
    let sender = create_wallet(&config, &format!("bip448-retarget-before-a-{suffix}")).await?;
    let first_receiver =
        create_wallet(&config, &format!("bip448-retarget-before-b-{suffix}")).await?;
    let replacement = create_wallet(&config, &format!("bip448-retarget-before-c-{suffix}")).await?;
    let statechain_id = create_confirmed_deposit(&config, &sender).await?;
    let first_address =
        mercuryrustlib::transfer_receiver::new_transfer_address(&config, &first_receiver.name)
            .await?;
    let replacement_address =
        mercuryrustlib::transfer_receiver::new_transfer_address(&config, &replacement.name).await?;
    config.pool.close().await;

    assert_exit(
        &run_child(
            &sender.name,
            &statechain_id,
            &first_address,
            Some("transfer_x1_persisted"),
        )?,
        RESTART_EXIT,
        "retarget before signing starts",
    )?;
    let resumed = mercuryrustlib::client_config::load().await;
    let pre_sign = mercuryrustlib::sqlite_manager::get_active_bip448_transfer_intent(
        &resumed.pool,
        &sender.name,
        &statechain_id,
    )
    .await?
    .context("pre-sign transfer intent is missing")?;
    assert_eq!(pre_sign.phase.as_str(), "X1Stored");
    assert_eq!(pre_sign.state_signing_phase.as_str(), "NotStarted");
    assert!(pre_sign.server_x1.is_some());
    assert!(
        mercuryrustlib::sqlite_manager::get_bip448_pending_transfer_signing(
            &resumed.pool,
            &sender.name,
            &statechain_id,
        )
        .await?
        .is_none(),
        "X1Stored/NotStarted must not have created a pending signing row"
    );
    assert_eq!(
        mercuryrustlib::sqlite_manager::get_bip448_state_history(
            &resumed.pool,
            &sender.name,
            &statechain_id,
        )
        .await?
        .iter()
        .map(|entry| entry.state_number)
        .collect::<Vec<_>>(),
        vec![1]
    );
    let lockbox = common::lockbox::http_client();
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox, &statechain_id).await?,
        1
    );
    mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender(
        &resumed,
        &replacement_address,
        &sender.name,
        &statechain_id,
        None,
    )
    .await?;
    assert!(
        mercuryrustlib::sqlite_manager::get_active_bip448_transfer_intent(
            &resumed.pool,
            &sender.name,
            &statechain_id,
        )
        .await?
        .is_none()
    );
    let replacement_pending = mercuryrustlib::sqlite_manager::get_bip448_pending_transfer_signing(
        &resumed.pool,
        &sender.name,
        &statechain_id,
    )
    .await?
    .context("delivered replacement transfer lost its signing journal")?;
    let replacement_auth = mercurylib::decode_transfer_address(&replacement_address)?
        .2
        .to_string();
    let replacement_msg = mercuryrustlib::sqlite_manager::get_bip448_transfer_msg(
        &resumed.pool,
        &sender.name,
        &statechain_id,
        &replacement_auth,
    )
    .await?;
    assert_eq!(replacement_msg.latest_state_number, 2);
    assert_eq!(
        replacement_pending.signing_id,
        replacement_msg.latest_state.signing_metadata.signing_id
    );
    assert!(
        mercuryrustlib::transfer_receiver::execute(&resumed, &first_receiver.name)
            .await?
            .received_statechain_ids
            .is_empty()
    );
    let received = mercuryrustlib::transfer_receiver::execute(&resumed, &replacement.name).await?;
    assert_eq!(
        received.received_statechain_ids,
        vec![statechain_id.clone()]
    );
    let accepted = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &resumed.pool,
        &replacement.name,
        &statechain_id,
    )
    .await?;
    assert_eq!(accepted.latest_state_number, 2);
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox, &statechain_id).await?,
        2
    );
    mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender(
        &resumed,
        &replacement_address,
        &sender.name,
        &statechain_id,
        None,
    )
    .await?;
    assert!(
        mercuryrustlib::sqlite_manager::get_bip448_pending_transfer_signing(
            &resumed.pool,
            &sender.name,
            &statechain_id,
        )
        .await?
        .is_none()
    );
    resumed.pool.close().await;
    Ok(())
}

async fn assert_mid_sign_retarget_finishes_predecessor(
    checkpoint: &str,
    expected_signing_phase: &str,
) -> Result<()> {
    let config = phase8_9_config().await?;
    let suffix = uuid::Uuid::new_v4();
    let sender = create_wallet(&config, &format!("bip448-retarget-mid-a-{suffix}")).await?;
    let first_receiver = create_wallet(&config, &format!("bip448-retarget-mid-b-{suffix}")).await?;
    let replacement = create_wallet(&config, &format!("bip448-retarget-mid-c-{suffix}")).await?;
    let statechain_id = create_confirmed_deposit(&config, &sender).await?;
    let first_address =
        mercuryrustlib::transfer_receiver::new_transfer_address(&config, &first_receiver.name)
            .await?;
    let first_user_key = mercurylib::decode_transfer_address(&first_address)?
        .1
        .x_only_public_key()
        .0
        .to_string();
    let first_auth_key = mercurylib::decode_transfer_address(&first_address)?
        .2
        .to_string();
    let replacement_address =
        mercuryrustlib::transfer_receiver::new_transfer_address(&config, &replacement.name).await?;
    let replacement_user_key = mercurylib::decode_transfer_address(&replacement_address)?
        .1
        .x_only_public_key()
        .0
        .to_string();
    let replacement_auth_key = mercurylib::decode_transfer_address(&replacement_address)?
        .2
        .to_string();
    config.pool.close().await;

    assert_exit(
        &run_child(
            &sender.name,
            &statechain_id,
            &first_address,
            Some(checkpoint),
        )?,
        RESTART_EXIT,
        &format!("retarget from {expected_signing_phase}"),
    )?;
    let resumed = mercuryrustlib::client_config::load().await;
    let predecessor = mercuryrustlib::sqlite_manager::get_active_bip448_transfer_intent(
        &resumed.pool,
        &sender.name,
        &statechain_id,
    )
    .await?
    .context("interrupted predecessor intent is missing")?;
    assert_eq!(predecessor.phase.as_str(), "X1Stored");
    assert_eq!(
        predecessor.state_signing_phase.as_str(),
        expected_signing_phase
    );
    let predecessor_pending = mercuryrustlib::sqlite_manager::get_bip448_pending_transfer_signing(
        &resumed.pool,
        &sender.name,
        &statechain_id,
    )
    .await?
    .context("interrupted predecessor pending row is missing")?;
    assert_eq!(
        predecessor.current_pending_signing_id.as_deref(),
        Some(predecessor_pending.signing_id.as_str())
    );
    assert_eq!(
        predecessor_pending.server_public_nonce.is_some(),
        expected_signing_phase == "NonceStored"
    );
    assert_eq!(
        mercuryrustlib::sqlite_manager::get_bip448_state_history(
            &resumed.pool,
            &sender.name,
            &statechain_id,
        )
        .await?
        .iter()
        .map(|entry| entry.state_number)
        .collect::<Vec<_>>(),
        vec![1]
    );
    let lockbox = common::lockbox::http_client();
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox, &statechain_id).await?,
        1
    );
    assert!(
        !mercuryrustlib::sqlite_manager::has_bip448_transfer_msg_for_statechain(
            &resumed.pool,
            &sender.name,
            &statechain_id,
        )
        .await?
    );

    mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender(
        &resumed,
        &replacement_address,
        &sender.name,
        &statechain_id,
        None,
    )
    .await?;
    assert!(
        mercuryrustlib::sqlite_manager::get_active_bip448_transfer_intent(
            &resumed.pool,
            &sender.name,
            &statechain_id,
        )
        .await?
        .is_none()
    );
    let replacement_pending = mercuryrustlib::sqlite_manager::get_bip448_pending_transfer_signing(
        &resumed.pool,
        &sender.name,
        &statechain_id,
    )
    .await?
    .context("delivered N+2 transfer lost its signing journal")?;
    let (stored_recipient, replacement_raw) =
        mercuryrustlib::sqlite_manager::get_bip448_transfer_msg_raw_optional(
            &resumed.pool,
            &sender.name,
            &statechain_id,
            None,
        )
        .await?
        .context("retargeted transfer message is missing")?;
    assert_eq!(stored_recipient, replacement_auth_key);
    let replacement_message: mercurylib::transfer::bip448::Bip448TransferMsg =
        serde_json::from_str(&replacement_raw)?;
    assert_eq!(replacement_message.latest_state_number, 3);
    assert_eq!(
        replacement_pending.signing_id,
        replacement_message.latest_state.signing_metadata.signing_id
    );
    assert_eq!(
        replacement_message
            .state_history
            .iter()
            .map(|entry| entry.state_number)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert_eq!(
        replacement_message.state_history[1].owner_public_key,
        first_user_key
    );
    assert_eq!(
        replacement_message.state_history[2].owner_public_key,
        replacement_user_key
    );
    let mercury = common::mercury::http_client();
    assert!(get_encrypted_msgs(&mercury, &first_auth_key)
        .await?
        .is_empty());
    assert!(
        mercuryrustlib::transfer_receiver::execute(&resumed, &first_receiver.name)
            .await?
            .received_statechain_ids
            .is_empty()
    );
    let received = mercuryrustlib::transfer_receiver::execute(&resumed, &replacement.name).await?;
    assert_eq!(
        received.received_statechain_ids,
        vec![statechain_id.clone()]
    );
    let accepted = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &resumed.pool,
        &replacement.name,
        &statechain_id,
    )
    .await?;
    assert_eq!(accepted.latest_state_number, 3);
    assert_eq!(
        mercuryrustlib::sqlite_manager::get_bip448_state_history(
            &resumed.pool,
            &replacement.name,
            &statechain_id,
        )
        .await?
        .iter()
        .map(|entry| entry.state_number)
        .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox, &statechain_id).await?,
        3
    );
    mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender(
        &resumed,
        &replacement_address,
        &sender.name,
        &statechain_id,
        None,
    )
    .await?;
    assert!(
        mercuryrustlib::sqlite_manager::get_bip448_pending_transfer_signing(
            &resumed.pool,
            &sender.name,
            &statechain_id,
        )
        .await?
        .is_none()
    );
    resumed.pool.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_retarget_after_signing_preserves_superseded_history() -> Result<()> {
    let _guard = common::test_guard();
    let config = phase8_9_config().await?;
    let suffix = uuid::Uuid::new_v4();
    let sender = create_wallet(&config, &format!("bip448-retarget-after-a-{suffix}")).await?;
    let first_receiver =
        create_wallet(&config, &format!("bip448-retarget-after-b-{suffix}")).await?;
    let replacement = create_wallet(&config, &format!("bip448-retarget-after-c-{suffix}")).await?;
    let statechain_id = create_confirmed_deposit(&config, &sender).await?;
    let first_address =
        mercuryrustlib::transfer_receiver::new_transfer_address(&config, &first_receiver.name)
            .await?;
    let first_user_key = mercurylib::decode_transfer_address(&first_address)?
        .1
        .x_only_public_key()
        .0
        .to_string();
    let first_auth_key = mercurylib::decode_transfer_address(&first_address)?
        .2
        .to_string();
    let replacement_address =
        mercuryrustlib::transfer_receiver::new_transfer_address(&config, &replacement.name).await?;
    let replacement_auth_key = mercurylib::decode_transfer_address(&replacement_address)?
        .2
        .to_string();
    config.pool.close().await;

    assert_exit(
        &run_child(
            &sender.name,
            &statechain_id,
            &first_address,
            Some("transfer_msg_uploaded"),
        )?,
        RESTART_EXIT,
        "retarget after signing",
    )?;
    let mercury = common::mercury::http_client();
    assert_eq!(
        get_encrypted_msgs(&mercury, &first_auth_key).await?.len(),
        1
    );
    let resumed = mercuryrustlib::client_config::load().await;
    mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender(
        &resumed,
        &replacement_address,
        &sender.name,
        &statechain_id,
        None,
    )
    .await?;
    assert!(get_encrypted_msgs(&mercury, &first_auth_key)
        .await?
        .is_empty());
    let first_result =
        mercuryrustlib::transfer_receiver::execute(&resumed, &first_receiver.name).await?;
    assert!(first_result.received_statechain_ids.is_empty());
    let replacement_result =
        mercuryrustlib::transfer_receiver::execute(&resumed, &replacement.name).await?;
    assert_eq!(
        replacement_result.received_statechain_ids,
        vec![statechain_id.clone()]
    );
    let accepted = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &resumed.pool,
        &replacement.name,
        &statechain_id,
    )
    .await?;
    assert_eq!(accepted.latest_state_number, 3);
    let history = mercuryrustlib::sqlite_manager::get_bip448_state_history(
        &resumed.pool,
        &replacement.name,
        &statechain_id,
    )
    .await?;
    assert_eq!(
        history
            .iter()
            .map(|entry| entry.state_number)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert_eq!(history[1].owner_public_key, first_user_key);
    assert!(history[1].state_locktime < history[2].state_locktime);
    let lockbox = common::lockbox::http_client();
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox, &statechain_id).await?,
        3
    );
    let (_, original_raw) = mercuryrustlib::sqlite_manager::get_bip448_transfer_msg_raw_optional(
        &resumed.pool,
        &sender.name,
        &statechain_id,
        Some(&replacement_auth_key),
    )
    .await?
    .context("N+2 outgoing message is missing before suffix tamper checks")?;
    let original_message: mercurylib::transfer::bip448::Bip448TransferMsg =
        serde_json::from_str(&original_raw)?;
    assert_eq!(original_message.state_history.len(), 3);
    for (history_index, label) in [(1usize, "N+1-suffix"), (2usize, "N+2-suffix")] {
        let mut changed = original_message.clone();
        changed.state_history[history_index].update_signature = "00".repeat(64);
        if history_index + 1 == changed.state_history.len() {
            changed.latest_state.signing_metadata.update_signature = "00".repeat(64);
        }
        let changed_entry = serde_json::to_string(&changed.state_history[history_index])?;
        let updated = sqlx::query(
            "UPDATE bip448_state_history SET entry_json=$1 WHERE wallet_name=$2 \
             AND statechain_id=$3 AND state_number=$4",
        )
        .bind(&changed_entry)
        .bind(&sender.name)
        .bind(&statechain_id)
        .bind(i64::try_from(history_index + 1)?)
        .execute(&resumed.pool)
        .await?;
        assert_eq!(updated.rows_affected(), 1);
        let changed_raw = serde_json::to_string(&changed)?;
        set_outgoing_message_raw(
            &resumed,
            &sender.name,
            &statechain_id,
            &replacement_auth_key,
            &changed_raw,
        )
        .await?;
        assert_rotated_resume_fails_without_local_mutation(
            &resumed,
            &sender.name,
            &statechain_id,
            &replacement_address,
            3,
            label,
        )
        .await?;
        let original_entry = serde_json::to_string(&original_message.state_history[history_index])?;
        let restored = sqlx::query(
            "UPDATE bip448_state_history SET entry_json=$1 WHERE wallet_name=$2 \
             AND statechain_id=$3 AND state_number=$4",
        )
        .bind(&original_entry)
        .bind(&sender.name)
        .bind(&statechain_id)
        .bind(i64::try_from(history_index + 1)?)
        .execute(&resumed.pool)
        .await?;
        assert_eq!(restored.rows_affected(), 1);
        set_outgoing_message_raw(
            &resumed,
            &sender.name,
            &statechain_id,
            &replacement_auth_key,
            &original_raw,
        )
        .await?;
    }
    mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender(
        &resumed,
        &replacement_address,
        &sender.name,
        &statechain_id,
        None,
    )
    .await?;
    assert!(
        !mercuryrustlib::sqlite_manager::has_bip448_transfer_msg_for_statechain(
            &resumed.pool,
            &sender.name,
            &statechain_id,
        )
        .await?
    );
    assert!(
        mercuryrustlib::sqlite_manager::get_bip448_pending_transfer_signing(
            &resumed.pool,
            &sender.name,
            &statechain_id,
        )
        .await?
        .is_none()
    );
    resumed.pool.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_cancel_returns_coin_and_allows_real_transfer() -> Result<()> {
    let _guard = common::test_guard();
    let config = phase8_9_config().await?;
    let suffix = uuid::Uuid::new_v4();
    let sender = create_wallet(&config, &format!("bip448-cancel-a-{suffix}")).await?;
    let receiver = create_wallet(&config, &format!("bip448-cancel-b-{suffix}")).await?;
    let statechain_id = create_confirmed_deposit(&config, &sender).await?;
    let receiver_address =
        mercuryrustlib::transfer_receiver::new_transfer_address(&config, &receiver.name).await?;
    config.pool.close().await;

    assert_exit(
        &run_child(
            &sender.name,
            &statechain_id,
            &receiver_address,
            Some("transfer_msg_uploaded"),
        )?,
        RESTART_EXIT,
        "cancel after signing",
    )?;
    assert_exit(
        &run_cancel_child(
            &sender.name,
            &statechain_id,
            Some("transfer_receiver_accepted"),
        )?,
        RESTART_EXIT,
        "cancellation after ReceiverAccepted persistence",
    )?;
    let resumed = mercuryrustlib::client_config::load().await;
    let receiver_accepted = mercuryrustlib::sqlite_manager::get_active_bip448_transfer_intent(
        &resumed.pool,
        &sender.name,
        &statechain_id,
    )
    .await?
    .context("ReceiverAccepted cancellation journal is missing")?;
    assert_eq!(receiver_accepted.phase.as_str(), "ReceiverAccepted");
    let bindings = mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
        &resumed.pool,
        &sender.name,
        &statechain_id,
    )
    .await?;
    let script = bindings
        .first()
        .context("ReceiverAccepted cancellation has no passive binding")?
        .script_pubkey
        .clone();
    let receiver_accepted_bytes = mercuryrustlib::sqlite_manager::capture_bip448_sync_base(
        &resumed.pool,
        &sender.name,
        &script,
    )
    .await?;
    assert!(!receiver_accepted_bytes.transfer_intent_rows.is_empty());
    assert!(!receiver_accepted_bytes.pending_transfer_rows.is_empty());
    assert!(!receiver_accepted_bytes
        .outgoing_transfer_message_rows
        .is_empty());
    assert!(
        mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender(
            &resumed,
            &receiver_address,
            &sender.name,
            &statechain_id,
            None,
        )
        .await
        .is_err(),
        "ReceiverAccepted cancellation must block a successor transfer"
    );
    let after_blocked_successor = mercuryrustlib::sqlite_manager::capture_bip448_sync_base(
        &resumed.pool,
        &sender.name,
        &script,
    )
    .await?;
    assert_eq!(
        after_blocked_successor.transfer_intent_rows, receiver_accepted_bytes.transfer_intent_rows,
        "the ReceiverAccepted blocker changed its intent lineage bytes"
    );
    assert_eq!(
        after_blocked_successor.pending_transfer_rows,
        receiver_accepted_bytes.pending_transfer_rows,
        "the ReceiverAccepted blocker changed its pending journal bytes"
    );
    assert_eq!(
        after_blocked_successor.outgoing_transfer_message_rows,
        receiver_accepted_bytes.outgoing_transfer_message_rows,
        "the ReceiverAccepted blocker changed its outgoing message bytes"
    );

    let bitcoin_container = common::bitcoin_core::get_container_id()?;
    docker_container_action("stop", &bitcoin_container)?;
    let post_accept_sync_result = mercuryrustlib::bip448_transfer_sender::cancel_bip448_transfer(
        &resumed,
        &sender.name,
        &statechain_id,
    )
    .await;
    docker_container_action("start", &bitcoin_container)?;
    wait_for_bitcoin_core()?;
    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bitcoin_core::execute_bitcoin_command(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury loadwallet mercury_tokens >/dev/null 2>&1 || true",
    )?;
    common::bitcoin_core::execute_bitcoin_command(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury -rpcwallet=mercury_tokens getwalletinfo",
    )?;
    assert!(
        post_accept_sync_result.is_err(),
        "stopped Bitcoin Core must inject a post-accept passive-sync failure"
    );
    assert_eq!(
        mercuryrustlib::sqlite_manager::capture_bip448_sync_base(
            &resumed.pool,
            &sender.name,
            &script,
        )
        .await?,
        after_blocked_successor,
        "post-accept sync failure changed ReceiverAccepted artifacts"
    );
    assert_eq!(
        mercuryrustlib::sqlite_manager::get_active_bip448_transfer_intent(
            &resumed.pool,
            &sender.name,
            &statechain_id,
        )
        .await?,
        Some(receiver_accepted),
    );
    assert_eq!(
        mercuryrustlib::bip448_transfer_sender::cancel_bip448_transfer(
            &resumed,
            &sender.name,
            &statechain_id,
        )
        .await?,
        3,
    );
    let cleaned = mercuryrustlib::sqlite_manager::capture_bip448_sync_base(
        &resumed.pool,
        &sender.name,
        &script,
    )
    .await?;
    assert!(cleaned.transfer_intent_rows.is_empty());
    assert!(cleaned.pending_transfer_rows.is_empty());
    assert!(cleaned.outgoing_transfer_message_rows.is_empty());
    let cancelled = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &resumed.pool,
        &sender.name,
        &statechain_id,
    )
    .await?;
    assert_eq!(cancelled.latest_state_number, 3);
    mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender(
        &resumed,
        &receiver_address,
        &sender.name,
        &statechain_id,
        None,
    )
    .await?;
    let received = mercuryrustlib::transfer_receiver::execute(&resumed, &receiver.name).await?;
    assert_eq!(
        received.received_statechain_ids,
        vec![statechain_id.clone()]
    );
    let accepted = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &resumed.pool,
        &receiver.name,
        &statechain_id,
    )
    .await?;
    assert_eq!(accepted.latest_state_number, 4);
    let lockbox = common::lockbox::http_client();
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox, &statechain_id).await?,
        4
    );
    resumed.pool.close().await;
    Ok(())
}

async fn phase8_9_config() -> Result<ClientConfig> {
    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury).await?;
    let lockbox = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox).await?;
    common::prepare_test_env().await
}
async fn create_wallet(config: &ClientConfig, name: &str) -> Result<Wallet> {
    let wallet = mercuryrustlib::wallet::create_wallet(name, config).await?;
    mercuryrustlib::sqlite_manager::insert_wallet(&config.pool, &wallet).await?;
    Ok(wallet)
}
async fn create_confirmed_deposit(config: &ClientConfig, wallet: &Wallet) -> Result<String> {
    let token = mercuryrustlib::deposit::get_token(config).await?;
    let token_id = common::utils::handle_token_response(config, &token).await?;
    let deposit = mercuryrustlib::deposit::get_bip448_deposit_bitcoin_address(
        config,
        &wallet.name,
        &token_id,
        FUNDING_AMOUNT_SATS,
    )
    .await?;
    common::bitcoin_core::sendtoaddress(FUNDING_AMOUNT_SATS, &deposit.address)?;
    common::chain::wait_for_address_utxo(config, &deposit.address, FUNDING_AMOUNT_SATS).await?;
    common::bitcoin_core::mine_blocks(config.confirmation_target)?;
    mercuryrustlib::coin_status::update_coins(config, &wallet.name).await?;
    Ok(deposit.statechain_id)
}
fn run_child(
    wallet: &str,
    statechain_id: &str,
    recipient: &str,
    checkpoint: Option<&str>,
) -> Result<Output> {
    run_child_with_batch(wallet, statechain_id, recipient, checkpoint, None)
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

fn run_child_with_batch(
    wallet: &str,
    statechain_id: &str,
    recipient: &str,
    checkpoint: Option<&str>,
    batch_id: Option<&str>,
) -> Result<Output> {
    let mut command = Command::new(std::env::current_exe()?);
    command
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
        .env("ML_NETWORK", "regtest")
        .env_remove("ML_BIP448_TEST_CHECKPOINT")
        .env_remove("ML_BIP448_TEST_BARRIER")
        .env_remove("ML_BIP448_TEST_BARRIER_REACHED")
        .env_remove("ML_BIP448_TEST_BARRIER_RELEASE")
        .env_remove("ML_BIP448_RESTART_BATCH_ID")
        .env_remove("ML_BIP448_RESTART_OPERATION");
    if let Some(checkpoint) = checkpoint {
        command.env("ML_BIP448_TEST_CHECKPOINT", checkpoint);
    }
    if let Some(batch_id) = batch_id {
        command.env("ML_BIP448_RESTART_BATCH_ID", batch_id);
    }
    Ok(command.output()?)
}

fn run_cancel_child(wallet: &str, statechain_id: &str, checkpoint: Option<&str>) -> Result<Output> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "--ignored",
            "--exact",
            "bip448_transfer_restart_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ML_BIP448_RESTART_CHILD", "1")
        .env("ML_BIP448_RESTART_OPERATION", "cancel")
        .env("ML_BIP448_RESTART_WALLET", wallet)
        .env("ML_BIP448_RESTART_STATECHAIN_ID", statechain_id)
        .env("ML_NETWORK", "regtest")
        .env_remove("ML_BIP448_RESTART_RECIPIENT")
        .env_remove("ML_BIP448_RESTART_BATCH_ID")
        .env_remove("ML_BIP448_TEST_CHECKPOINT")
        .env_remove("ML_BIP448_TEST_BARRIER")
        .env_remove("ML_BIP448_TEST_BARRIER_REACHED")
        .env_remove("ML_BIP448_TEST_BARRIER_RELEASE");
    if let Some(checkpoint) = checkpoint {
        command.env("ML_BIP448_TEST_CHECKPOINT", checkpoint);
    }
    Ok(command.output()?)
}
fn assert_exit(output: &Output, expected: i32, context: &str) -> Result<()> {
    if output.status.code() == Some(expected) {
        return Ok(());
    }
    Err(anyhow!("transfer child at {context} exited with {:?}, expected {expected}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(), String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr)))
}

fn docker_container_action(action: &str, container_id: &str) -> Result<()> {
    if !matches!(action, "start" | "stop") || container_id.is_empty() {
        return Err(anyhow!("invalid Docker container action target"));
    }
    let output = Command::new("docker")
        .args([action, container_id])
        .output()?;
    if !output.status.success() {
        return Err(anyhow!(
            "docker {action} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

fn wait_for_bitcoin_core() -> Result<()> {
    for _ in 0..120 {
        if common::bitcoin_core::execute_bitcoin_command(
            "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury getblockchaininfo",
        )
        .is_ok()
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(250));
    }
    Err(anyhow!("Bitcoin Core did not become ready after restart"))
}

async fn wait_for_lockbox_signature_count(
    client: &reqwest::Client,
    statechain_id: &str,
    expected: u32,
) -> Result<()> {
    let mut last_result = String::from("no signature-count response");
    for _ in 0..120 {
        match common::lockbox::get_signature_count(client, statechain_id).await {
            Ok(actual) if actual == expected => return Ok(()),
            Ok(actual) => last_result = format!("signature count {actual}, expected {expected}"),
            Err(error) => last_result = error.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Err(anyhow!(
        "Lockbox database did not recover after the 5xx barrier: {last_result}"
    ))
}

async fn set_outgoing_message_raw(
    config: &ClientConfig,
    wallet_name: &str,
    statechain_id: &str,
    recipient_auth_pubkey: &str,
    raw: &str,
) -> Result<()> {
    let updated = sqlx::query(
        "UPDATE bip448_transfer_messages SET transfer_msg_json=$1 WHERE wallet_name=$2 \
         AND statechain_id=$3 AND recipient_auth_pubkey=$4",
    )
    .bind(raw)
    .bind(wallet_name)
    .bind(statechain_id)
    .bind(recipient_auth_pubkey)
    .execute(&config.pool)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(anyhow!(
            "outgoing-message tamper fixture affected {} rows",
            updated.rows_affected()
        ));
    }
    Ok(())
}

async fn assert_rotated_resume_fails_without_local_mutation(
    config: &ClientConfig,
    wallet_name: &str,
    statechain_id: &str,
    recipient_address: &str,
    expected_count: u32,
    label: &str,
) -> Result<()> {
    let bindings = mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
        &config.pool,
        wallet_name,
        statechain_id,
    )
    .await?;
    let script = bindings
        .first()
        .context("tamper fixture has no passive binding")?
        .script_pubkey
        .clone();
    let before = mercuryrustlib::sqlite_manager::capture_bip448_sync_base(
        &config.pool,
        wallet_name,
        &script,
    )
    .await?;
    assert!(!before.outgoing_transfer_message_rows.is_empty());
    assert!(!before.pending_transfer_rows.is_empty());
    let lockbox = common::lockbox::http_client();
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox, statechain_id).await?,
        expected_count,
        "remote count before {label}"
    );
    let error = mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender(
        config,
        recipient_address,
        wallet_name,
        statechain_id,
        None,
    )
    .await
    .err()
    .ok_or_else(|| anyhow!("{label} unexpectedly passed rotated cleanup"))?;
    assert!(!error.to_string().is_empty());
    let after = mercuryrustlib::sqlite_manager::capture_bip448_sync_base(
        &config.pool,
        wallet_name,
        &script,
    )
    .await?;
    assert_eq!(after, before, "{label} mutated local storage or cleaned up");
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox, statechain_id).await?,
        expected_count,
        "remote count changed after {label}"
    );
    Ok(())
}
async fn get_encrypted_msg(client: &reqwest::Client, auth_pubkey: &str) -> Result<String> {
    get_encrypted_msgs(client, auth_pubkey)
        .await?
        .into_iter()
        .next()
        .context("server transfer message is missing")
}
async fn get_encrypted_msgs(client: &reqwest::Client, auth_pubkey: &str) -> Result<Vec<String>> {
    Ok(client
        .get(format!(
            "{}/transfer/get_msg_addr/{auth_pubkey}",
            common::mercury::MERCURY_URL
        ))
        .send()
        .await?
        .json::<GetMsgAddrResponsePayload>()
        .await?
        .list_enc_transfer_msg)
}
