mod common;
use anyhow::{anyhow, Context, Result};
use common::bip448_regtest::FUNDING_AMOUNT_SATS;
use mercurylib::transfer::{
    bip448::decrypt_bip448_transfer_msg, receiver::GetMsgAddrResponsePayload,
};
use mercuryrustlib::{client_config::ClientConfig, CoinStatus, Wallet};
use std::process::{Command, Output};
const RESTART_EXIT: i32 = 86;
#[tokio::test]
#[ignore = "internal child entry point for the BIP448 transfer restart test"]
async fn bip448_transfer_restart_child() -> Result<()> {
    if std::env::var("ML_BIP448_RESTART_CHILD").as_deref() != Ok("1") {
        return Ok(());
    }
    std::env::set_var("ML_NETWORK", "regtest");
    let config = mercuryrustlib::client_config::load().await;
    let result = mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender(
        &config,
        &std::env::var("ML_BIP448_RESTART_RECIPIENT")?,
        &std::env::var("ML_BIP448_RESTART_WALLET")?,
        &std::env::var("ML_BIP448_RESTART_STATECHAIN_ID")?,
        None,
    )
    .await;
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
        if checkpoint == "server_nonce_persisted" {
            assert_exit(
                &run_child(&sender_name, &statechain_id, &recipient, Some(checkpoint))?,
                RESTART_EXIT,
                "replayed signing checkpoint",
            )?;
            let replayed = mercuryrustlib::client_config::load().await;
            assert_eq!(
                mercuryrustlib::sqlite_manager::get_bip448_pending_transfer_signing(
                    &replayed.pool,
                    &sender_name,
                    &statechain_id
                )
                .await?
                .context("replayed signing journal is missing")?,
                pending
            );
            replayed.pool.close().await;
        }
        if checkpoint == "transfer_msg_persisted" {
            assert!(
                get_encrypted_msg(&mercury, &auth_pubkey).await.is_err(),
                "plaintext checkpoint must fire before upload"
            );
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
            let undelivered = run_child(&sender_name, &statechain_id, &recipient, None)?;
            assert!(
                !undelivered.status.success()
                    && String::from_utf8_lossy(&undelivered.stderr)
                        .contains("transfer message was not stored")
            );
            let retryable = mercuryrustlib::client_config::load().await;
            assert_eq!(
                mercuryrustlib::sqlite_manager::get_bip448_pending_transfer_signing(
                    &retryable.pool,
                    &sender_name,
                    &statechain_id
                )
                .await?,
                Some(pending.clone())
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
        assert!(
            mercuryrustlib::sqlite_manager::get_bip448_pending_transfer_signing(
                &recovered.pool,
                &sender_name,
                &statechain_id
            )
            .await?
            .is_none()
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
    server_pool.close().await;
    Ok(())
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
        CoinStatus::IN_TRANSFER
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
            Some("pending_persisted"),
        )?,
        RESTART_EXIT,
        "retarget before sign/second",
    )?;
    let resumed = mercuryrustlib::client_config::load().await;
    let aborted = mercuryrustlib::sqlite_manager::get_bip448_pending_transfer_signing(
        &resumed.pool,
        &sender.name,
        &statechain_id,
    )
    .await?
    .context("aborted transfer signing is missing")?;
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
    assert_ne!(
        replacement_msg.latest_state.signing_metadata.signing_id,
        aborted.signing_id
    );
    assert_ne!(
        replacement_msg
            .latest_state
            .signing_metadata
            .client_public_nonce,
        aborted.client_public_nonce
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
    let resumed = mercuryrustlib::client_config::load().await;
    assert_eq!(
        mercuryrustlib::bip448_transfer_sender::cancel_bip448_transfer(
            &resumed,
            &sender.name,
            &statechain_id,
        )
        .await?,
        3,
    );
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
        .env_remove("ML_BIP448_TEST_CHECKPOINT");
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
