use super::support::*;
use super::*;

async fn assert_lockbox_state_absent(client: &Client, statechain_id: &str) -> Result<()> {
    let response =
        common::lockbox::get(client, &format!("signature_count/{statechain_id}")).await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(response.text().await?, "Signature count not found.");
    Ok(())
}

fn run_canonical_close_child(
    wallet_name: &str,
    statechain_id: &str,
    destination: &str,
    mode: &str,
    checkpoint: Option<&str>,
) -> Result<Output> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "--ignored",
            "--exact",
            "bip448_duplicate_sweeps_are_one_input_and_canonical_closes_last",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ML_BIP448_RESTART_CHILD", "1")
        .env("ML_BIP448_CANONICAL_CLOSE_CHILD_MODE", mode)
        .env("ML_BIP448_RESTART_WALLET", wallet_name)
        .env("ML_BIP448_RESTART_STATECHAIN_ID", statechain_id)
        .env("ML_BIP448_RESTART_DESTINATION", destination)
        .env("ML_NETWORK", "regtest")
        .env_remove("ML_BIP448_TEST_CHECKPOINT");
    if let Some(checkpoint) = checkpoint {
        command.env("ML_BIP448_TEST_CHECKPOINT", checkpoint);
    }
    Ok(command.output()?)
}

#[derive(Debug, PartialEq, Eq)]
struct CanonicalSideEffectInvariant {
    wallet_json: String,
    accepted: (String, Vec<(i64, String)>),
    attempt_count: i64,
    signature_count: u32,
    mercury: (String, String, String),
}

async fn canonical_side_effect_invariant(
    fixture: &DuplicateSweepFixture,
    lockbox_client: &Client,
) -> Result<CanonicalSideEffectInvariant> {
    Ok(CanonicalSideEffectInvariant {
        wallet_json: sqlx::query_scalar("SELECT wallet_json FROM wallet WHERE wallet_name=$1")
            .bind(&fixture.wallet_name)
            .fetch_one(&fixture.config.pool)
            .await?,
        accepted: accepted_state_bytes(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?,
        attempt_count: sqlx::query_scalar(
            "SELECT COUNT(*) FROM bip448_withdrawal_attempts WHERE wallet_name=$1 AND statechain_id=$2",
        )
        .bind(&fixture.wallet_name)
        .bind(&fixture.statechain_id)
        .fetch_one(&fixture.config.pool)
        .await?,
        signature_count: common::lockbox::get_signature_count(
            lockbox_client,
            &fixture.statechain_id,
        )
        .await?,
        mercury: mercury_state_bytes(&fixture.statechain_id).await?,
    })
}

async fn accepted_prefix_message(
    fixture: &DuplicateSweepFixture,
) -> Result<(String, Bip448TransferMsg)> {
    let wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&fixture.config.pool, &fixture.wallet_name)
            .await?;
    let coin = wallet
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some(fixture.statechain_id.as_str()))
        .context("accepted-prefix fixture Coin is missing")?;
    let record = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?;
    let history = mercuryrustlib::sqlite_manager::get_bip448_state_history(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?;
    Ok((
        coin.auth_pubkey.clone(),
        Bip448TransferMsg {
            msg_version: 2,
            statechain_id: fixture.statechain_id.clone(),
            transfer_signature: "11".repeat(64),
            sender_user_public_key: coin.user_pubkey.clone(),
            receiver_user_public_key: coin.user_pubkey.clone(),
            server_public_key: coin
                .server_pubkey
                .clone()
                .context("accepted-prefix Coin has no server key")?,
            aggregate_pubkey: record.aggregate_pubkey.clone(),
            funding_outpoint: record.funding_outpoint.clone(),
            latest_state_number: record.latest_state_number,
            challenge_delay: record.challenge_delay,
            amount_sats: record.amount_sats,
            network: record.network.clone(),
            value_schedule: record.latest_state.value_schedule.clone(),
            latest_state: record.latest_state,
            server_signature_count: u64::from(record.latest_state_number),
            t1: [7; 32],
            state_history: history,
        },
    ))
}

async fn delete_exact_outgoing_message(
    fixture: &DuplicateSweepFixture,
    recipient_auth_pubkey: &str,
) -> Result<()> {
    let deleted = sqlx::query(
        "DELETE FROM bip448_transfer_messages WHERE wallet_name=$1 AND statechain_id=$2 AND recipient_auth_pubkey=$3",
    )
    .bind(&fixture.wallet_name)
    .bind(&fixture.statechain_id)
    .bind(recipient_auth_pubkey)
    .execute(&fixture.config.pool)
    .await?;
    assert_eq!(
        deleted.rows_affected(),
        1,
        "exact outgoing cleanup missed its row"
    );
    Ok(())
}

async fn exercise_late_binding_after_canonical_wallet_persisted(
    lockbox_client: &Client,
) -> Result<()> {
    let fixture = duplicate_sweep_fixture(&[]).await?;
    let destination = common::bitcoin_core::getnewaddress()?;
    let checkpoint = run_canonical_close_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        "execute",
        Some("canonical_wallet_persisted"),
    )?;
    require_child_exit(
        &checkpoint,
        86,
        "late binding after canonical_wallet_persisted",
    )?;
    let frozen = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        0,
    )
    .await?
    .context("late-binding canonical journal is missing")?;
    assert_eq!(frozen.phase, Bip448WithdrawalPhase::Signed);
    assert_eq!(frozen.broadcast_status, Bip448BroadcastStatus::Accepted);
    assert_eq!(frozen.closing_bindings_json.as_deref(), Some("[]"));
    let frozen_signing_id = frozen.signing_id.clone();
    let frozen_signed_tx = frozen
        .signed_tx_hex
        .clone()
        .context("late-binding canonical bytes are missing")?;
    assert_eq!(
        common::lockbox::get_signature_count(lockbox_client, &fixture.statechain_id).await?,
        2
    );

    let wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&fixture.config.pool, &fixture.wallet_name)
            .await?;
    let aggregate_address = wallet
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some(fixture.statechain_id.as_str()))
        .and_then(|coin| coin.aggregated_address.as_deref())
        .context("late-binding canonical Coin has no aggregate address")?;
    let aggregate_address =
        Address::from_str(aggregate_address)?.require_network(fixture.config.network)?;
    let late_funding = fund_address_output(&aggregate_address, DUPLICATE_AMOUNT_SATS)?;
    common::chain::wait_for_address_outpoint(
        &fixture.config,
        &aggregate_address.to_string(),
        late_funding.outpoint,
        late_funding.value_sats,
    )
    .await?;
    common::bitcoin_core::mine_blocks(fixture.config.confirmation_target)?;
    let report = mercuryrustlib::coin_status::sync_bip448_funding_bindings(
        &fixture.config,
        &fixture.wallet_name,
    )
    .await?;
    let late = report
        .bindings
        .iter()
        .find(|binding| {
            binding.statechain_id == fixture.statechain_id
                && binding.txid == late_funding.outpoint.txid.to_string()
                && binding.vout == late_funding.outpoint.vout
        })
        .context("late canonical-freeze duplicate was not discovered")?;
    assert_eq!(late.role, Bip448BindingRole::Duplicate);
    assert_eq!(late.ownership_status, Bip448OwnershipStatus::Current);
    assert_eq!(late.observation_status, Bip448ObservationStatus::Confirmed);
    assert!(
        mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
            late.binding_index,
        )
        .await?
        .is_none()
    );

    let before_rejections = canonical_side_effect_invariant(&fixture, lockbox_client).await?;
    assert!(mercuryrustlib::bip448_withdraw::execute_duplicate_sweep(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        late.binding_index,
        &destination,
        Some(1.0),
    )
    .await
    .is_err());
    assert!(
        mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
            late.binding_index,
        )
        .await?
        .is_none(),
        "late duplicate acquired an attempt after canonical freeze"
    );
    assert!(mercuryrustlib::bip448_withdraw::execute(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        Some(1.0),
    )
    .await
    .is_err());
    assert_eq!(
        canonical_side_effect_invariant(&fixture, lockbox_client).await?,
        before_rejections,
        "late binding changed wallet, signing count, or Mercury state"
    );
    let retained = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        0,
    )
    .await?
    .context("late binding removed the canonical journal")?;
    assert_eq!(retained.signing_id, frozen_signing_id);
    assert_eq!(
        retained.signed_tx_hex.as_deref(),
        Some(frozen_signed_tx.as_str())
    );
    assert_eq!(retained.closing_bindings_json.as_deref(), Some("[]"));
    assert!(
        mercuryrustlib::utils::get_statechain_info(&fixture.statechain_id, &fixture.config)
            .await?
            .is_some()
    );
    Ok(())
}

async fn exercise_frozen_signed_duplicate_mutations(lockbox_client: &Client) -> Result<()> {
    let fixture = duplicate_sweep_fixture(&[FUNDING_AMOUNT_SATS]).await?;
    let duplicate = fixture.bindings[1].clone();
    let destination = common::bitcoin_core::getnewaddress()?;
    let conflict = retained_update_conflict_package(&fixture, &duplicate).await?;
    save_empty_mempool_baseline()?;

    mercuryrustlib::bip448_withdraw::execute_duplicate_sweep(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        duplicate.binding_index,
        &destination,
        Some(1.0),
    )
    .await?;
    let frozen_sweep = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        duplicate.binding_index,
    )
    .await?
    .context("frozen duplicate sweep is missing")?;
    let frozen_sweep_signing_id = frozen_sweep.signing_id.clone();
    let frozen_sweep_bytes = frozen_sweep
        .signed_tx_hex
        .clone()
        .context("frozen duplicate sweep bytes are missing")?;
    assert_eq!(
        common::lockbox::get_signature_count(lockbox_client, &fixture.statechain_id).await?,
        2
    );

    let prepared_output = run_canonical_close_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        "execute",
        Some("attempt_prepared"),
    )?;
    require_child_exit(&prepared_output, 86, "frozen duplicate canonical Prepared")?;
    let prepared = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        0,
    )
    .await?
    .context("frozen duplicate canonical Prepared row is missing")?;
    assert_eq!(prepared.phase, Bip448WithdrawalPhase::Prepared);
    let canonical_signing_id = prepared.signing_id.clone();
    let frozen_snapshot = prepared
        .closing_bindings_json
        .clone()
        .context("frozen duplicate canonical snapshot is missing")?;

    let tip = fixture.config.chain_client.tip_height()?;
    restart_core_dropping_unpersisted_mempool(&fixture.config, tip, true)?;
    mercuryrustlib::coin_status::sync_bip448_funding_bindings(
        &fixture.config,
        &fixture.wallet_name,
    )
    .await?;
    submit_conflict_package(&conflict)?;
    mercuryrustlib::coin_status::sync_bip448_funding_bindings(
        &fixture.config,
        &fixture.wallet_name,
    )
    .await?;
    let conflicting_sweep = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        duplicate.binding_index,
    )
    .await?
    .context("conflicting frozen duplicate sweep is missing")?;
    assert_eq!(
        conflicting_sweep.broadcast_status,
        Bip448BroadcastStatus::Conflicting
    );

    let blocked_second_arm = run_canonical_close_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        "execute",
        None,
    )?;
    require_child_exit(
        &blocked_second_arm,
        101,
        "frozen duplicate mutation before SecondArmed",
    )?;
    let before_second_arm = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        0,
    )
    .await?
    .context("blocked canonical journal is missing")?;
    assert_eq!(before_second_arm.phase, Bip448WithdrawalPhase::NonceStored);
    assert_eq!(before_second_arm.signing_id, canonical_signing_id);
    assert_eq!(
        before_second_arm.closing_bindings_json.as_deref(),
        Some(frozen_snapshot.as_str())
    );
    assert_eq!(
        common::lockbox::get_signature_count(lockbox_client, &fixture.statechain_id).await?,
        2,
        "frozen mutation reached canonical sign/second"
    );
    assert!(
        mercuryrustlib::utils::get_statechain_info(&fixture.statechain_id, &fixture.config)
            .await?
            .is_some()
    );

    common::bitcoin_core::mine_block_with_transactions(&[
        conflict.parent_tx.txid(),
        conflict.cpfp_child_tx.txid(),
    ])?;
    let conflict_block_height = fixture.config.chain_client.tip_height()?;
    let conflict_block_hash = fixture
        .config
        .chain_client
        .get_block_hash(conflict_block_height)?
        .to_string();
    invalidate_conflict_and_evict(
        &fixture.config,
        &conflict_block_hash,
        conflict.parent_tx.txid(),
        false,
    )?;
    mercuryrustlib::coin_status::sync_bip448_funding_bindings(
        &fixture.config,
        &fixture.wallet_name,
    )
    .await?;
    let close_armed_output = run_canonical_close_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        "execute",
        Some("canonical_close_armed"),
    )?;
    require_child_exit(
        &close_armed_output,
        86,
        "exact frozen sweep reconciliation before CloseArmed",
    )?;
    let close_armed = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        0,
    )
    .await?
    .context("canonical CloseArmed journal is missing")?;
    assert_eq!(close_armed.phase, Bip448WithdrawalPhase::Signed);
    assert_eq!(
        close_armed.completion_status,
        Bip448CompletionStatus::CloseArmed
    );
    let canonical_signed_bytes = close_armed
        .signed_tx_hex
        .clone()
        .context("canonical CloseArmed bytes are missing")?;
    assert_eq!(
        common::lockbox::get_signature_count(lockbox_client, &fixture.statechain_id).await?,
        3
    );
    let mercury_before_blocked_completion = mercury_state_bytes(&fixture.statechain_id).await?;

    restart_core_dropping_unpersisted_mempool(&fixture.config, tip, false)?;
    mercuryrustlib::coin_status::sync_bip448_funding_bindings(
        &fixture.config,
        &fixture.wallet_name,
    )
    .await?;
    submit_conflict_package(&conflict)?;
    mercuryrustlib::coin_status::sync_bip448_funding_bindings(
        &fixture.config,
        &fixture.wallet_name,
    )
    .await?;
    let reorged_canonical = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        0,
    )
    .await?
    .context("reorged canonical CloseArmed journal is missing")?;
    assert_eq!(
        reorged_canonical.broadcast_status,
        Bip448BroadcastStatus::NeedsRebroadcast
    );
    assert_eq!(
        reorged_canonical.completion_status,
        Bip448CompletionStatus::CloseArmed
    );
    let blocked_completion = mercuryrustlib::bip448_withdraw::execute(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        Some(1.0),
    )
    .await;
    assert!(blocked_completion.is_err());
    let still_armed = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        0,
    )
    .await?
    .context("blocked completion lost canonical journal")?;
    assert_eq!(
        still_armed.completion_status,
        Bip448CompletionStatus::CloseArmed
    );
    assert_eq!(still_armed.signing_id, canonical_signing_id);
    assert_eq!(
        still_armed.signed_tx_hex.as_deref(),
        Some(canonical_signed_bytes.as_str())
    );
    assert_eq!(
        common::lockbox::get_signature_count(lockbox_client, &fixture.statechain_id).await?,
        3
    );
    assert_eq!(
        mercury_state_bytes(&fixture.statechain_id).await?,
        mercury_before_blocked_completion,
        "frozen conflict reached completion or mutated Mercury signing state"
    );

    restart_core_dropping_unpersisted_mempool(&fixture.config, tip, true)?;
    mercuryrustlib::coin_status::sync_bip448_funding_bindings(
        &fixture.config,
        &fixture.wallet_name,
    )
    .await?;
    mercuryrustlib::bip448_withdraw::execute(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        Some(1.0),
    )
    .await?;
    let closed = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        0,
    )
    .await?
    .context("reconciled canonical journal is missing")?;
    assert_eq!(closed.completion_status, Bip448CompletionStatus::Closed);
    assert_eq!(closed.signing_id, canonical_signing_id);
    assert_eq!(
        closed.signed_tx_hex.as_deref(),
        Some(canonical_signed_bytes.as_str())
    );
    let restored_sweep = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        duplicate.binding_index,
    )
    .await?
    .context("reconciled frozen sweep is missing")?;
    assert_eq!(restored_sweep.signing_id, frozen_sweep_signing_id);
    assert_eq!(
        restored_sweep.signed_tx_hex.as_deref(),
        Some(frozen_sweep_bytes.as_str())
    );
    assert_lockbox_state_absent(lockbox_client, &fixture.statechain_id).await?;
    assert!(
        mercuryrustlib::utils::get_statechain_info(&fixture.statechain_id, &fixture.config)
            .await?
            .is_none()
    );
    Ok(())
}

async fn exercise_frozen_independent_spend_reorg(lockbox_client: &Client) -> Result<()> {
    let fixture = duplicate_sweep_fixture(&[FUNDING_AMOUNT_SATS]).await?;
    let duplicate = fixture.bindings[1].clone();
    let destination = common::bitcoin_core::getnewaddress()?;
    let conflict = retained_update_conflict_package(&fixture, &duplicate).await?;
    let conflict_block_hash = confirm_conflict_package(&fixture.config, &conflict)?;
    let report = mercuryrustlib::coin_status::sync_bip448_funding_bindings(
        &fixture.config,
        &fixture.wallet_name,
    )
    .await?;
    let spent = report
        .bindings
        .iter()
        .find(|binding| {
            binding.statechain_id == fixture.statechain_id
                && binding.binding_index == duplicate.binding_index
        })
        .context("independently spent frozen duplicate is missing")?;
    assert_eq!(
        spent.observation_status,
        Bip448ObservationStatus::SpentConfirmed
    );
    assert_eq!(
        spent.spend_txid.as_deref(),
        Some(conflict.parent_tx.txid().to_string().as_str())
    );
    assert!(
        mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
            duplicate.binding_index,
        )
        .await?
        .is_none()
    );

    let prepared_output = run_canonical_close_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        "execute",
        Some("attempt_prepared"),
    )?;
    require_child_exit(&prepared_output, 86, "independent-spend canonical Prepared")?;
    let prepared = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        0,
    )
    .await?
    .context("independent-spend canonical journal is missing")?;
    let frozen_snapshot = prepared
        .closing_bindings_json
        .clone()
        .context("independent-spend snapshot is missing")?;
    assert!(frozen_snapshot.contains("\"kind\":\"IndependentSpend\""));
    let canonical_signing_id = prepared.signing_id.clone();
    assert_eq!(
        common::lockbox::get_signature_count(lockbox_client, &fixture.statechain_id).await?,
        1
    );

    invalidate_conflict_and_evict(
        &fixture.config,
        &conflict_block_hash,
        conflict.parent_tx.txid(),
        true,
    )?;
    mercuryrustlib::coin_status::sync_bip448_funding_bindings(
        &fixture.config,
        &fixture.wallet_name,
    )
    .await?;
    let blocked = run_canonical_close_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        "execute",
        None,
    )?;
    require_child_exit(&blocked, 101, "reorged independent frozen spend")?;
    let blocked_attempt = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        0,
    )
    .await?
    .context("independent-spend reorg lost canonical journal")?;
    assert_eq!(blocked_attempt.phase, Bip448WithdrawalPhase::NonceStored);
    assert_eq!(blocked_attempt.signing_id, canonical_signing_id);
    assert_eq!(
        blocked_attempt.closing_bindings_json.as_deref(),
        Some(frozen_snapshot.as_str())
    );
    assert_eq!(
        common::lockbox::get_signature_count(lockbox_client, &fixture.statechain_id).await?,
        1,
        "reorged independent spend consumed a new signature"
    );
    assert!(
        mercuryrustlib::utils::get_statechain_info(&fixture.statechain_id, &fixture.config)
            .await?
            .is_some()
    );

    common::bitcoin_core::execute_bitcoin_command(&format!(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury reconsiderblock {conflict_block_hash}"
    ))?;
    let restored = mercuryrustlib::coin_status::sync_bip448_funding_bindings(
        &fixture.config,
        &fixture.wallet_name,
    )
    .await?;
    let restored_binding = restored
        .bindings
        .iter()
        .find(|binding| {
            binding.statechain_id == fixture.statechain_id
                && binding.binding_index == duplicate.binding_index
        })
        .context("reconsidered independent frozen duplicate is missing")?;
    assert_eq!(
        restored_binding.observation_status,
        Bip448ObservationStatus::SpentConfirmed
    );
    assert_eq!(
        restored_binding.spend_txid.as_deref(),
        Some(conflict.parent_tx.txid().to_string().as_str())
    );
    mercuryrustlib::bip448_withdraw::execute(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        Some(1.0),
    )
    .await?;
    let closed = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        0,
    )
    .await?
    .context("reconciled independent-spend canonical journal is missing")?;
    assert_eq!(closed.completion_status, Bip448CompletionStatus::Closed);
    assert_eq!(closed.signing_id, canonical_signing_id);
    assert_lockbox_state_absent(lockbox_client, &fixture.statechain_id).await?;
    Ok(())
}

async fn exercise_canonical_prepared_confirmed_conflict(lockbox_client: &Client) -> Result<()> {
    let fixture = duplicate_sweep_fixture(&[]).await?;
    let canonical_binding = fixture.bindings[0].clone();
    let destination = common::bitcoin_core::getnewaddress()?;
    let conflict = retained_update_conflict_package(&fixture, &canonical_binding).await?;
    let prepared_output = run_canonical_close_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        "execute",
        Some("attempt_prepared"),
    )?;
    require_child_exit(&prepared_output, 86, "canonical Prepared conflict fixture")?;
    let prepared = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        0,
    )
    .await?
    .context("canonical conflict Prepared row is missing")?;
    assert_eq!(prepared.phase, Bip448WithdrawalPhase::Prepared);
    let exact_prepared_journal = raw_withdrawal_attempt_journal_snapshot(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        0,
    )
    .await?;
    let frozen_snapshot = prepared
        .closing_bindings_json
        .clone()
        .context("canonical conflict snapshot is missing")?;
    assert_eq!(frozen_snapshot, "[]");
    let canonical_signing_id = prepared.signing_id.clone();

    let conflict_block_hash = confirm_conflict_package(&fixture.config, &conflict)?;
    let report = mercuryrustlib::coin_status::sync_bip448_funding_bindings(
        &fixture.config,
        &fixture.wallet_name,
    )
    .await?;
    let spent = report
        .bindings
        .iter()
        .find(|binding| {
            binding.statechain_id == fixture.statechain_id && binding.binding_index == 0
        })
        .context("confirmed canonical conflict binding is missing")?;
    assert_eq!(
        spent.observation_status,
        Bip448ObservationStatus::SpentConfirmed
    );
    assert_eq!(
        spent.spend_txid.as_deref(),
        Some(conflict.parent_tx.txid().to_string().as_str())
    );
    assert!(mercuryrustlib::bip448_withdraw::execute(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        Some(1.0),
    )
    .await
    .is_err());
    let retained = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        0,
    )
    .await?
    .context("confirmed conflict compare-deleted canonical Prepared")?;
    assert_eq!(retained.phase, Bip448WithdrawalPhase::Prepared);
    assert_eq!(retained.signing_id, canonical_signing_id);
    assert_eq!(
        retained.closing_bindings_json.as_deref(),
        Some(frozen_snapshot.as_str())
    );
    assert_eq!(
        raw_withdrawal_attempt_journal_snapshot(
            &fixture.config,
            &fixture.wallet_name,
            &fixture.statechain_id,
            0,
        )
        .await?,
        exact_prepared_journal,
        "confirmed canonical conflict mutated the Prepared journal"
    );
    let conflict_tip = fixture.config.chain_client.tip_height()?;
    let conflict_tip_hash = fixture
        .config
        .chain_client
        .get_block_hash(conflict_tip)?
        .to_string();
    assert!(
        mercuryrustlib::sqlite_manager::delete_prepared_bip448_withdrawal_attempt_for_confirmed_spend(
            &fixture.config.pool,
            &retained,
            &conflict.parent_tx.txid().to_string(),
            conflict_tip,
            &conflict_tip_hash,
        )
        .await
        .is_err(),
        "canonical Prepared unexpectedly entered duplicate compare-delete"
    );
    assert!(
        mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
            0,
        )
        .await?
        .is_some()
    );
    assert_eq!(
        common::lockbox::get_signature_count(lockbox_client, &fixture.statechain_id).await?,
        1
    );
    assert!(
        mercuryrustlib::utils::get_statechain_info(&fixture.statechain_id, &fixture.config)
            .await?
            .is_some()
    );

    invalidate_conflict_and_evict(
        &fixture.config,
        &conflict_block_hash,
        conflict.parent_tx.txid(),
        true,
    )?;
    mercuryrustlib::coin_status::sync_bip448_funding_bindings(
        &fixture.config,
        &fixture.wallet_name,
    )
    .await?;
    mercuryrustlib::bip448_withdraw::execute(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        Some(1.0),
    )
    .await?;
    let closed = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        0,
    )
    .await?
    .context("restored canonical conflict journal is missing")?;
    assert_eq!(closed.completion_status, Bip448CompletionStatus::Closed);
    assert_eq!(closed.signing_id, canonical_signing_id);
    assert_lockbox_state_absent(lockbox_client, &fixture.statechain_id).await?;
    Ok(())
}

pub(super) async fn bip448_duplicate_sweeps_are_one_input_and_canonical_closes_last() -> Result<()>
{
    if let Ok(mode) = std::env::var("ML_BIP448_CANONICAL_CLOSE_CHILD_MODE") {
        std::env::set_var("ML_NETWORK", "regtest");
        let config = mercuryrustlib::client_config::load().await;
        let wallet_name = std::env::var("ML_BIP448_RESTART_WALLET")?;
        let statechain_id = std::env::var("ML_BIP448_RESTART_STATECHAIN_ID")?;
        let result = match mode.as_str() {
            "execute" => {
                mercuryrustlib::bip448_withdraw::execute(
                    &config,
                    &wallet_name,
                    &statechain_id,
                    &std::env::var("ML_BIP448_RESTART_DESTINATION")?,
                    Some(1.0),
                )
                .await
            }
            "assert-outgoing" => {
                let count: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM bip448_transfer_messages WHERE wallet_name=$1 AND statechain_id=$2",
                )
                .bind(&wallet_name)
                .bind(&statechain_id)
                .fetch_one(&config.pool)
                .await?;
                if count != 1 {
                    anyhow::bail!("accepted-prefix outgoing row did not survive restart");
                }
                Ok(())
            }
            _ => anyhow::bail!("unknown canonical-close child mode {mode}"),
        };
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

    exercise_canonical_prepared_confirmed_conflict(&lockbox_client).await?;
    exercise_frozen_independent_spend_reorg(&lockbox_client).await?;
    exercise_frozen_signed_duplicate_mutations(&lockbox_client).await?;
    exercise_late_binding_after_canonical_wallet_persisted(&lockbox_client).await?;

    let fixture =
        duplicate_sweep_fixture(&[DUPLICATE_AMOUNT_SATS, SMALL_DUPLICATE_AMOUNT_SATS]).await?;
    assert_ne!(
        fixture.bindings[1].value_sats,
        fixture.bindings[2].value_sats
    );
    let destination = common::bitcoin_core::getnewaddress()?;
    let initial = canonical_side_effect_invariant(&fixture, &lockbox_client).await?;
    assert_eq!(initial.signature_count, 1);
    assert!(mercuryrustlib::bip448_withdraw::execute(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        Some(1.0),
    )
    .await
    .is_err());
    assert_eq!(
        canonical_side_effect_invariant(&fixture, &lockbox_client).await?,
        initial,
        "pre-sweep canonical rejection caused a signing/wallet/completion side effect"
    );
    assert!(
        mercuryrustlib::utils::get_statechain_info(&fixture.statechain_id, &fixture.config)
            .await?
            .is_some()
    );

    let original_wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&fixture.config.pool, &fixture.wallet_name)
            .await?;
    let mut in_transfer_wallet = original_wallet.clone();
    let owner_coin = in_transfer_wallet
        .coins
        .iter_mut()
        .find(|coin| coin.statechain_id.as_deref() == Some(fixture.statechain_id.as_str()))
        .context("canonical guard Coin is missing")?;
    owner_coin.status = CoinStatus::IN_TRANSFER;
    mercuryrustlib::sqlite_manager::update_wallet(&fixture.config.pool, &in_transfer_wallet)
        .await?;
    let in_transfer_before = canonical_side_effect_invariant(&fixture, &lockbox_client).await?;
    assert!(mercuryrustlib::bip448_withdraw::execute(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        Some(1.0),
    )
    .await
    .is_err());
    assert_eq!(
        canonical_side_effect_invariant(&fixture, &lockbox_client).await?,
        in_transfer_before,
        "IN_TRANSFER rejection changed durable state"
    );
    mercuryrustlib::sqlite_manager::update_wallet(&fixture.config.pool, &original_wallet).await?;

    let record = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?;
    let guard_coin = original_wallet
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some(fixture.statechain_id.as_str()))
        .context("active-intent guard Coin is missing")?;
    let intent_id = "a1".repeat(32);
    sqlx::query(
        "INSERT INTO bip448_transfer_intents (wallet_name,statechain_id,intent_id, \
         predecessor_intent_id,activity_status,intent_kind,acknowledge_cooperative_duplicates, \
         recipient_address,receiver_user_pubkey,recipient_auth_pubkey,batch_id, \
         sender_signed_statechain_id,planned_state_number,expected_signature_count, \
         previous_locktime,prior_pending_signing_id,prior_transfer_recipient_auth_pubkey, \
         prior_transfer_msg_hash,reuse_pending,reuse_signed_state,clear_local_attempt, \
         generated_coin_user_pubkey,generated_coin_auth_pubkey,generated_coin_address,phase, \
         server_x1,current_pending_signing_id,state_signing_phase,server_partial_sig, \
         update_signature) VALUES ($1,$2,$3,NULL,'Active','UserTransfer',1,$4,$5,$6,NULL, \
         $7,$8,$9,$10,NULL,NULL,NULL,0,0,0,NULL,NULL,NULL,'Prepared',NULL,NULL,'NotStarted',NULL,NULL)",
    )
    .bind(&fixture.wallet_name)
    .bind(&fixture.statechain_id)
    .bind(&intent_id)
    .bind(&guard_coin.address)
    .bind(&guard_coin.user_pubkey)
    .bind(&guard_coin.auth_pubkey)
    .bind(
        guard_coin
            .signed_statechain_id
            .as_deref()
            .context("active-intent guard Coin has no signature")?,
    )
    .bind(i64::from(record.latest_state_number + 1))
    .bind(i64::from(record.latest_state_number))
    .bind(i64::from(record.latest_state.state_locktime))
    .execute(&fixture.config.pool)
    .await?;
    let intent_before = canonical_side_effect_invariant(&fixture, &lockbox_client).await?;
    assert!(mercuryrustlib::bip448_withdraw::execute(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        Some(1.0),
    )
    .await
    .is_err());
    assert_eq!(
        canonical_side_effect_invariant(&fixture, &lockbox_client).await?,
        intent_before,
        "active transfer intent did not reject before canonical side effects"
    );
    let deleted = sqlx::query(
        "DELETE FROM bip448_transfer_intents WHERE wallet_name=$1 AND statechain_id=$2 AND intent_id=$3",
    )
    .bind(&fixture.wallet_name)
    .bind(&fixture.statechain_id)
    .bind(&intent_id)
    .execute(&fixture.config.pool)
    .await?;
    assert_eq!(deleted.rows_affected(), 1);

    let (accepted_recipient, accepted_message) = accepted_prefix_message(&fixture).await?;
    mercuryrustlib::sqlite_manager::insert_or_update_bip448_transfer_msg(
        &fixture.config.pool,
        &fixture.wallet_name,
        &accepted_recipient,
        &accepted_message,
    )
    .await?;
    let restart = run_canonical_close_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        "assert-outgoing",
        None,
    )?;
    require_child_exit(&restart, 0, "accepted-prefix restart persistence")?;
    let accepted_prefix_before = canonical_side_effect_invariant(&fixture, &lockbox_client).await?;
    assert!(mercuryrustlib::bip448_withdraw::execute(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        Some(1.0),
    )
    .await
    .is_err());
    assert_eq!(
        canonical_side_effect_invariant(&fixture, &lockbox_client).await?,
        accepted_prefix_before,
        "accepted-prefix cleanup changed anything except its exact outgoing row"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bip448_transfer_messages WHERE wallet_name=$1 AND statechain_id=$2",
        )
        .bind(&fixture.wallet_name)
        .bind(&fixture.statechain_id)
        .fetch_one(&fixture.config.pool)
        .await?,
        0
    );

    let mut beyond_accepted = accepted_message.clone();
    beyond_accepted.latest_state_number = beyond_accepted
        .latest_state_number
        .checked_add(1)
        .context("beyond-accepted state number overflow")?;
    for (case, recipient, message) in [
        (
            "beyond accepted",
            accepted_recipient.clone(),
            beyond_accepted,
        ),
        (
            "one field",
            accepted_recipient.clone(),
            Bip448TransferMsg {
                amount_sats: accepted_message.amount_sats + 1,
                ..accepted_message.clone()
            },
        ),
        ("history", accepted_recipient.clone(), {
            let mut message = accepted_message.clone();
            message.state_history[0].update_template_hash = "a2".repeat(32);
            message
        }),
        (
            "recipient",
            PublicKey::from_secret_key(
                &Secp256k1::new(),
                &secp256k1::SecretKey::from_secret_bytes([99; 32])?,
            )
            .to_string(),
            accepted_message.clone(),
        ),
    ] {
        mercuryrustlib::sqlite_manager::insert_or_update_bip448_transfer_msg(
            &fixture.config.pool,
            &fixture.wallet_name,
            &recipient,
            &message,
        )
        .await?;
        let mismatch_before = canonical_side_effect_invariant(&fixture, &lockbox_client).await?;
        assert!(
            mercuryrustlib::bip448_withdraw::execute(
                &fixture.config,
                &fixture.wallet_name,
                &fixture.statechain_id,
                &destination,
                Some(1.0),
            )
            .await
            .is_err(),
            "{case} outgoing mismatch did not block canonical close"
        );
        assert_eq!(
            canonical_side_effect_invariant(&fixture, &lockbox_client).await?,
            mismatch_before,
            "{case} outgoing mismatch changed signing/wallet/completion state"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM bip448_transfer_messages WHERE wallet_name=$1 AND statechain_id=$2 AND recipient_auth_pubkey=$3",
            )
            .bind(&fixture.wallet_name)
            .bind(&fixture.statechain_id)
            .bind(&recipient)
            .fetch_one(&fixture.config.pool)
            .await?,
            1,
            "{case} outgoing mismatch was incorrectly deleted"
        );
        delete_exact_outgoing_message(&fixture, &recipient).await?;
    }

    common::bitcoin_core::mine_block()?;
    save_empty_mempool_baseline()?;
    let accepted_before = accepted_state_bytes(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?;
    let sweep_one = mercuryrustlib::bip448_withdraw::execute_duplicate_sweep(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        fixture.bindings[1].binding_index,
        &destination,
        Some(1.0),
    )
    .await?;
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
        2
    );
    assert!(
        mercuryrustlib::utils::get_statechain_info(&fixture.statechain_id, &fixture.config)
            .await?
            .is_some()
    );
    assert!(mercuryrustlib::bip448_withdraw::execute(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        Some(1.0),
    )
    .await
    .is_err());
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
        2
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

    let sweep_two = mercuryrustlib::bip448_withdraw::execute_duplicate_sweep(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        fixture.bindings[2].binding_index,
        &destination,
        Some(1.0),
    )
    .await?;
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
        3
    );
    assert!(
        mercuryrustlib::utils::get_statechain_info(&fixture.statechain_id, &fixture.config)
            .await?
            .is_some()
    );
    assert_eq!(
        accepted_state_bytes(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?,
        accepted_before
    );

    let canonical_checkpoints = [
        (
            "attempt_prepared",
            Bip448WithdrawalPhase::Prepared,
            Bip448BroadcastStatus::NotBroadcast,
            Bip448CompletionStatus::Open,
            3,
        ),
        (
            "sign_first_armed",
            Bip448WithdrawalPhase::FirstArmed,
            Bip448BroadcastStatus::NotBroadcast,
            Bip448CompletionStatus::Open,
            3,
        ),
        (
            "server_nonce_returned",
            Bip448WithdrawalPhase::FirstArmed,
            Bip448BroadcastStatus::NotBroadcast,
            Bip448CompletionStatus::Open,
            3,
        ),
        (
            "server_nonce_persisted",
            Bip448WithdrawalPhase::NonceStored,
            Bip448BroadcastStatus::NotBroadcast,
            Bip448CompletionStatus::Open,
            3,
        ),
        (
            "sign_second_armed",
            Bip448WithdrawalPhase::SecondArmed,
            Bip448BroadcastStatus::NotBroadcast,
            Bip448CompletionStatus::Open,
            3,
        ),
        (
            "server_partial_returned",
            Bip448WithdrawalPhase::SecondArmed,
            Bip448BroadcastStatus::NotBroadcast,
            Bip448CompletionStatus::Open,
            4,
        ),
        (
            "signed_tx_persisted",
            Bip448WithdrawalPhase::Signed,
            Bip448BroadcastStatus::NotBroadcast,
            Bip448CompletionStatus::Open,
            4,
        ),
        (
            "broadcast_returned",
            Bip448WithdrawalPhase::Signed,
            Bip448BroadcastStatus::NeedsRebroadcast,
            Bip448CompletionStatus::Open,
            4,
        ),
        (
            "canonical_wallet_persisted",
            Bip448WithdrawalPhase::Signed,
            Bip448BroadcastStatus::Accepted,
            Bip448CompletionStatus::Open,
            4,
        ),
        (
            "canonical_close_armed",
            Bip448WithdrawalPhase::Signed,
            Bip448BroadcastStatus::Accepted,
            Bip448CompletionStatus::CloseArmed,
            4,
        ),
        (
            "canonical_completion_returned",
            Bip448WithdrawalPhase::Signed,
            Bip448BroadcastStatus::Accepted,
            Bip448CompletionStatus::CloseArmed,
            4,
        ),
    ];
    let raw_wallet_before_canonical: String =
        sqlx::query_scalar("SELECT wallet_json FROM wallet WHERE wallet_name=$1")
            .bind(&fixture.wallet_name)
            .fetch_one(&fixture.config.pool)
            .await?;
    let mut canonical_immutable = None;
    for (checkpoint, phase, broadcast, completion, count) in canonical_checkpoints {
        let output = run_canonical_close_child(
            &fixture.wallet_name,
            &fixture.statechain_id,
            &destination,
            "execute",
            Some(checkpoint),
        )?;
        require_child_exit(&output, 86, checkpoint)?;
        let attempts = mercuryrustlib::sqlite_manager::list_bip448_withdrawal_attempts(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?;
        assert_eq!(
            attempts.len(),
            3,
            "{checkpoint} changed attempt cardinality"
        );
        let canonical = attempts
            .iter()
            .find(|attempt| attempt.binding_index == 0)
            .context("canonical journal is missing")?;
        assert_eq!(
            canonical.attempt_kind,
            Bip448WithdrawalAttemptKind::Canonical
        );
        assert_eq!(
            canonical.phase, phase,
            "wrong canonical phase at {checkpoint}"
        );
        assert_eq!(
            canonical.broadcast_status, broadcast,
            "wrong canonical broadcast status at {checkpoint}"
        );
        assert_eq!(
            canonical.completion_status, completion,
            "wrong canonical completion status at {checkpoint}"
        );
        let immutable = duplicate_attempt_immutable_json(canonical);
        if let Some(expected) = &canonical_immutable {
            assert_eq!(
                &immutable, expected,
                "canonical immutable drift at {checkpoint}"
            );
        } else {
            canonical_immutable = Some(immutable);
        }
        if checkpoint == "canonical_completion_returned" {
            assert_lockbox_state_absent(&lockbox_client, &fixture.statechain_id).await?;
        } else {
            assert_eq!(
                common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id)
                    .await?,
                count,
                "wrong canonical lockbox count at {checkpoint}"
            );
        }
        assert_eq!(
            accepted_state_bytes(
                &fixture.config.pool,
                &fixture.wallet_name,
                &fixture.statechain_id,
            )
            .await?,
            accepted_before,
            "canonical checkpoint {checkpoint} changed accepted history"
        );
        if checkpoint == "attempt_prepared" {
            let wallet = mercuryrustlib::sqlite_manager::get_wallet(
                &fixture.config.pool,
                &fixture.wallet_name,
            )
            .await?;
            let listed = mercuryrustlib::coin_status::statecoin_list_entry_json(
                &fixture.wallet_name,
                wallet
                    .coins
                    .iter()
                    .find(|coin| {
                        coin.statechain_id.as_deref() == Some(fixture.statechain_id.as_str())
                    })
                    .context("canonical listed Coin is missing")?,
                &mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
                    &fixture.config.pool,
                    &fixture.wallet_name,
                    &fixture.statechain_id,
                )
                .await?,
                &attempts,
            )?;
            assert_eq!(listed["coin.address_retired"].as_bool(), Some(true));
            assert_eq!(
                listed["coin.close_tip_height"].as_u64(),
                canonical.closing_tip_height.map(u64::from)
            );
            assert_eq!(
                listed["coin.close_tip_hash"].as_str(),
                canonical.closing_tip_hash.as_deref()
            );
            let close_height = canonical.closing_tip_height.context("close height")?;
            assert_eq!(
                canonical.closing_tip_hash.as_deref(),
                Some(
                    fixture
                        .config
                        .chain_client
                        .get_block_hash(close_height)?
                        .to_string()
                        .as_str()
                )
            );
        }
        if matches!(
            checkpoint,
            "attempt_prepared"
                | "sign_first_armed"
                | "server_nonce_returned"
                | "server_nonce_persisted"
                | "sign_second_armed"
                | "server_partial_returned"
                | "signed_tx_persisted"
                | "broadcast_returned"
        ) {
            assert_eq!(
                sqlx::query_scalar::<_, String>(
                    "SELECT wallet_json FROM wallet WHERE wallet_name=$1",
                )
                .bind(&fixture.wallet_name)
                .fetch_one(&fixture.config.pool)
                .await?,
                raw_wallet_before_canonical,
                "wallet changed before canonical acceptance at {checkpoint}"
            );
        }
        let server_present =
            mercuryrustlib::utils::get_statechain_info(&fixture.statechain_id, &fixture.config)
                .await?
                .is_some();
        assert_eq!(
            server_present,
            checkpoint != "canonical_completion_returned",
            "server deletion occurred at the wrong canonical checkpoint"
        );
    }

    let final_resume = run_canonical_close_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        "execute",
        None,
    )?;
    require_child_exit(&final_resume, 0, "canonical lost-response reconciliation")?;
    let attempts = mercuryrustlib::sqlite_manager::list_bip448_withdrawal_attempts(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?;
    assert_eq!(attempts.len(), 3);
    let canonical = attempts
        .iter()
        .find(|attempt| attempt.binding_index == 0)
        .context("closed canonical journal is missing")?;
    assert_eq!(canonical.completion_status, Bip448CompletionStatus::Closed);
    let canonical_txid = Txid::from_str(canonical.txid.as_deref().context("canonical txid")?)?;
    let signed_bytes = canonical
        .signed_tx_hex
        .clone()
        .context("canonical signed bytes are missing")?;
    let all_txids = [
        Txid::from_str(&sweep_one.sweep_txid)?,
        Txid::from_str(&sweep_two.sweep_txid)?,
        canonical_txid,
    ];
    let mut sources = BTreeSet::new();
    for txid in all_txids {
        let transaction: bitcoin::Transaction =
            bitcoin::consensus::deserialize(&fixture.config.chain_client.get_raw_tx(&txid)?)?;
        assert_eq!(transaction.input.len(), 1);
        assert_eq!(transaction.output.len(), 1);
        sources.insert(transaction.input[0].previous_output);
    }
    assert_eq!(sources.len(), 3);
    let wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&fixture.config.pool, &fixture.wallet_name)
            .await?;
    assert_eq!(
        wallet
            .activities
            .iter()
            .filter(|activity| activity.utxo == canonical_txid.to_string())
            .count(),
        1
    );
    assert_lockbox_state_absent(&lockbox_client, &fixture.statechain_id).await?;
    assert_eq!(
        accepted_state_bytes(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?,
        accepted_before
    );

    let tip = fixture.config.chain_client.tip_height()?;
    restart_core_dropping_unpersisted_mempool(&fixture.config, tip, false)?;
    mercuryrustlib::coin_status::sync_bip448_funding_bindings(
        &fixture.config,
        &fixture.wallet_name,
    )
    .await?;
    let disappeared = mercuryrustlib::sqlite_manager::list_bip448_withdrawal_attempts(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?;
    assert!(disappeared
        .iter()
        .all(|attempt| attempt.broadcast_status == Bip448BroadcastStatus::NeedsRebroadcast));
    assert_eq!(
        disappeared
            .iter()
            .find(|attempt| attempt.binding_index == 0)
            .context("disappeared canonical journal is missing")?
            .completion_status,
        Bip448CompletionStatus::Closed
    );
    for (index, expected_txid) in [
        (
            fixture.bindings[1].binding_index,
            sweep_one.sweep_txid.as_str(),
        ),
        (
            fixture.bindings[2].binding_index,
            sweep_two.sweep_txid.as_str(),
        ),
    ] {
        let replayed = mercuryrustlib::bip448_withdraw::execute_duplicate_sweep(
            &fixture.config,
            &fixture.wallet_name,
            &fixture.statechain_id,
            index,
            &destination,
            Some(1.0),
        )
        .await?;
        assert_eq!(replayed.sweep_txid, expected_txid);
    }
    mercuryrustlib::bip448_withdraw::execute(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        &destination,
        Some(1.0),
    )
    .await?;
    let rebroadcast = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        0,
    )
    .await?
    .context("rebroadcast canonical journal is missing")?;
    assert_eq!(
        rebroadcast.completion_status,
        Bip448CompletionStatus::Closed
    );
    assert_eq!(
        rebroadcast.signed_tx_hex.as_deref(),
        Some(signed_bytes.as_str())
    );
    assert_lockbox_state_absent(&lockbox_client, &fixture.statechain_id).await?;
    assert!(
        mercuryrustlib::utils::get_statechain_info(&fixture.statechain_id, &fixture.config)
            .await?
            .is_none()
    );
    let wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&fixture.config.pool, &fixture.wallet_name)
            .await?;
    assert_eq!(
        wallet
            .activities
            .iter()
            .filter(|activity| activity.utxo == canonical_txid.to_string())
            .count(),
        1
    );
    common::bitcoin_core::execute_bitcoin_command(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury loadwallet mercury_test",
    )?;
    common::bitcoin_core::execute_bitcoin_command(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury loadwallet mercury_tokens",
    )?;
    common::bitcoin_core::mine_block_with_transactions(&all_txids)?;
    Ok(())
}
