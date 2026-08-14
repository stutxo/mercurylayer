use super::support::*;
use super::*;

pub(super) async fn bip448_retarget_before_signing_reuses_next_state() -> Result<()> {
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
    let server_pool = sqlx::PgPool::connect(common::mercury::database_url()).await?;
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

pub(super) async fn bip448_retarget_after_signing_preserves_superseded_history() -> Result<()> {
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
