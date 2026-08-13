use super::support::*;
use super::*;

pub(super) async fn bip448_cancel_returns_coin_and_allows_real_transfer() -> Result<()> {
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
