use super::support::*;
use super::*;

fn child_server_nonce(output: &Output) -> Result<String> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| {
            line.split_once("BIP448_TEST_SERVER_NONCE=")
                .map(|(_, nonce)| nonce)
        })
        .map(str::to_owned)
        .context("duplicate sweep child did not report its decoded server nonce")
}

async fn exercise_target_confirmed_duplicate_conflict(
    checkpoint: &str,
    phase: Bip448WithdrawalPhase,
) -> Result<()> {
    let fixture = duplicate_sweep_fixture(&[FUNDING_AMOUNT_SATS]).await?;
    let selected = fixture.bindings[1].clone();
    assert_eq!(selected.value_sats, fixture.bindings[0].value_sats);
    assert_eq!(selected.script_pubkey, fixture.bindings[0].script_pubkey);
    let destination = common::bitcoin_core::getnewaddress()?;
    let accepted_before = accepted_state_bytes(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?;
    let raw_wallet_before =
        sqlx::query_scalar::<_, String>("SELECT wallet_json FROM wallet WHERE wallet_name=$1")
            .bind(&fixture.wallet_name)
            .fetch_one(&fixture.config.pool)
            .await?;
    let mercury_before = mercury_state_bytes(&fixture.statechain_id).await?;
    let lockbox_client = common::lockbox::http_client();
    let initial_count =
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?;
    assert_eq!(initial_count, 1);

    let checkpoint_output = run_duplicate_sweep_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
        &destination,
        Some(checkpoint),
        false,
    )?;
    require_child_exit(&checkpoint_output, 86, checkpoint)?;
    let before_conflict = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
    )
    .await?
    .context("conflict checkpoint did not persist its attempt")?;
    assert_eq!(before_conflict.phase, phase);
    assert_eq!(
        before_conflict.broadcast_status,
        Bip448BroadcastStatus::NotBroadcast
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
        initial_count
    );
    let immutable_before = duplicate_attempt_immutable_json(&before_conflict);
    let package = retained_update_conflict_package(&fixture, &selected).await?;
    assert_eq!(
        package.parent_tx.input[0].previous_output,
        OutPoint {
            txid: Txid::from_str(&selected.txid)?,
            vout: selected.vout,
        }
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
        initial_count,
        "constructing the retained-U conflict consumed a lockbox signature"
    );
    let conflict_block_hash = confirm_conflict_package(&fixture.config, &package)?;
    let resolve_output = run_duplicate_sweep_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
        &destination,
        None,
        false,
    )?;

    if phase == Bip448WithdrawalPhase::Prepared {
        require_child_exit(&resolve_output, 101, "Prepared target-confirmed conflict")?;
        assert!(
            mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
                &fixture.config.pool,
                &fixture.wallet_name,
                &fixture.statechain_id,
                selected.binding_index,
            )
            .await?
            .is_none(),
            "duplicate Prepared conflict was not compare-deleted"
        );
        assert_eq!(
            common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
            initial_count,
            "duplicate Prepared conflict consumed a signature count"
        );
    } else {
        require_child_exit(&resolve_output, 0, "armed target-confirmed conflict")?;
        let conflicted = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
            selected.binding_index,
        )
        .await?
        .context("armed target-confirmed conflict lost its attempt")?;
        assert_eq!(conflicted.phase, Bip448WithdrawalPhase::Signed);
        assert_eq!(
            conflicted.broadcast_status,
            Bip448BroadcastStatus::Conflicted
        );
        assert_eq!(
            duplicate_attempt_immutable_json(&conflicted),
            immutable_before
        );
        assert!(conflicted.signed_tx_hex.is_some());
        assert_eq!(
            common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
            initial_count + 1,
            "armed target-confirmed conflict did not resolve with exactly one count"
        );
    }
    assert_eq!(
        accepted_state_bytes(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?,
        accepted_before
    );

    invalidate_conflict_and_evict(
        &fixture.config,
        &conflict_block_hash,
        package.parent_tx.txid(),
        true,
    )?;
    let reopened = mercuryrustlib::coin_status::sync_bip448_funding_bindings(
        &fixture.config,
        &fixture.wallet_name,
    )
    .await?;
    let reopened_binding = reopened
        .bindings
        .iter()
        .find(|binding| {
            binding.statechain_id == fixture.statechain_id
                && binding.binding_index == selected.binding_index
        })
        .context("reorged conflict lost the duplicate binding")?;
    assert_eq!(
        reopened_binding.observation_status,
        Bip448ObservationStatus::Confirmed
    );

    if phase == Bip448WithdrawalPhase::Prepared {
        assert!(
            mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
                &fixture.config.pool,
                &fixture.wallet_name,
                &fixture.statechain_id,
                selected.binding_index,
            )
            .await?
            .is_none(),
            "reorg recreated a compare-deleted Prepared row"
        );
        let reopened_output = run_duplicate_sweep_child(
            &fixture.wallet_name,
            &fixture.statechain_id,
            selected.binding_index,
            &destination,
            Some("attempt_prepared"),
            false,
        )?;
        require_child_exit(&reopened_output, 86, "reopened Prepared duplicate")?;
        assert_eq!(
            common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
            initial_count
        );
    } else {
        let needs_rebroadcast = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
            selected.binding_index,
        )
        .await?
        .context("reorg deleted the retained Signed conflict")?;
        assert_eq!(needs_rebroadcast.phase, Bip448WithdrawalPhase::Signed);
        assert_eq!(
            needs_rebroadcast.broadcast_status,
            Bip448BroadcastStatus::NeedsRebroadcast
        );
        assert_eq!(
            duplicate_attempt_immutable_json(&needs_rebroadcast),
            immutable_before
        );
    }

    let rebroadcast = run_duplicate_sweep_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
        &destination,
        None,
        false,
    )?;
    require_child_exit(&rebroadcast, 0, "reopened exact duplicate sweep")?;
    let accepted = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
    )
    .await?
    .context("reopened exact sweep did not persist")?;
    assert_eq!(accepted.phase, Bip448WithdrawalPhase::Signed);
    assert_eq!(accepted.broadcast_status, Bip448BroadcastStatus::Accepted);
    assert_eq!(
        accepted.completion_status,
        Bip448CompletionStatus::NotApplicable
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
        initial_count + 1
    );
    common::bitcoin_core::mine_block()?;
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT wallet_json FROM wallet WHERE wallet_name=$1")
            .bind(&fixture.wallet_name)
            .fetch_one(&fixture.config.pool)
            .await?,
        raw_wallet_before
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
    let mercury_after = mercury_state_bytes(&fixture.statechain_id).await?;
    assert_eq!(mercury_after.0, mercury_before.0);
    assert_eq!(mercury_after.2, mercury_before.2);
    Ok(())
}

async fn exercise_prepared_mempool_conflict_and_eviction() -> Result<()> {
    let fixture = duplicate_sweep_fixture(&[FUNDING_AMOUNT_SATS]).await?;
    let selected = fixture.bindings[1].clone();
    let destination = common::bitcoin_core::getnewaddress()?;
    let lockbox_client = common::lockbox::http_client();
    let server_before = mercury_state_bytes(&fixture.statechain_id).await?;
    let checkpoint = run_duplicate_sweep_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
        &destination,
        Some("attempt_prepared"),
        false,
    )?;
    require_child_exit(&checkpoint, 86, "Prepared mempool-conflict fixture")?;
    let prepared = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
    )
    .await?
    .context("Prepared mempool-conflict row is missing")?;
    let immutable = duplicate_attempt_immutable_json(&prepared);
    let package = retained_update_conflict_package(&fixture, &selected).await?;
    save_empty_mempool_baseline()?;
    submit_conflict_package(&package)?;
    let transient = run_duplicate_sweep_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
        &destination,
        None,
        false,
    )?;
    require_child_exit(&transient, 101, "Prepared mempool conflict")?;
    let waiting = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
    )
    .await?
    .context("mempool conflict deleted the Prepared row")?;
    assert_eq!(waiting.phase, Bip448WithdrawalPhase::Prepared);
    assert_eq!(
        waiting.broadcast_status,
        Bip448BroadcastStatus::NotBroadcast
    );
    assert_eq!(duplicate_attempt_immutable_json(&waiting), immutable);
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
        1
    );
    assert_eq!(
        mercury_state_bytes(&fixture.statechain_id).await?.1,
        server_before.1,
        "Prepared mempool conflict reached sign/first"
    );

    let unchanged_tip = fixture.config.chain_client.tip_height()?;
    restart_core_dropping_unpersisted_mempool(&fixture.config, unchanged_tip, true)?;
    common::bitcoin_core::assert_not_in_mempool(&package.parent_tx.txid())?;
    let resumed = run_duplicate_sweep_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
        &destination,
        Some("sign_first_armed"),
        false,
    )?;
    require_child_exit(&resumed, 86, "Prepared conflict eviction resume")?;
    let armed = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
    )
    .await?
    .context("evicted Prepared conflict did not resume")?;
    assert_eq!(armed.phase, Bip448WithdrawalPhase::FirstArmed);
    assert_eq!(duplicate_attempt_immutable_json(&armed), immutable);
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
        1
    );
    let finish = run_duplicate_sweep_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
        &destination,
        None,
        false,
    )?;
    require_child_exit(&finish, 0, "post-eviction exact sweep")?;
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
        2
    );
    common::bitcoin_core::mine_block()?;
    Ok(())
}

async fn exercise_signed_sweep_with_missing_funding_parent() -> Result<()> {
    let fixture = duplicate_sweep_fixture(&[DUPLICATE_AMOUNT_SATS]).await?;
    let selected = fixture.bindings[1].clone();
    let destination = common::bitcoin_core::getnewaddress()?;
    let recovery_mining_address = common::bitcoin_core::getnewaddress()?;
    let funding_transaction =
        common::bitcoin_core::wallet_transaction(&Txid::from_str(&selected.txid)?)?;
    let funding_block_height = selected
        .funding_height
        .context("signed-parent fixture funding height is missing")?;
    let funding_block_hash = fixture
        .config
        .chain_client
        .get_block_hash(funding_block_height)?
        .to_string();
    let signed_checkpoint = run_duplicate_sweep_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
        &destination,
        Some("signed_tx_persisted"),
        false,
    )?;
    require_child_exit(&signed_checkpoint, 86, "signed missing-parent fixture")?;
    let signed = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
    )
    .await?
    .context("signed missing-parent attempt is missing")?;
    let signed_bytes = signed
        .signed_tx_hex
        .clone()
        .context("signed missing-parent bytes are missing")?;
    let sweep_txid = Txid::from_str(signed.txid.as_deref().context("signed sweep txid")?)?;
    save_empty_mempool_baseline()?;
    common::bitcoin_core::execute_bitcoin_command(&format!(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury invalidateblock {funding_block_hash}"
    ))?;
    common::bitcoin_core::assert_in_mempool(&funding_transaction.txid())?;
    let reorg_tip = fixture.config.chain_client.tip_height()?;
    restart_core_dropping_unpersisted_mempool(&fixture.config, reorg_tip, false)?;
    common::bitcoin_core::assert_not_in_mempool(&funding_transaction.txid())?;

    let unavailable = run_duplicate_sweep_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
        &destination,
        None,
        false,
    )?;
    require_child_exit(&unavailable, 101, "signed sweep with unavailable parent")?;
    let needs = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
    )
    .await?
    .context("missing-parent broadcast deleted signed bytes")?;
    assert_eq!(
        needs.broadcast_status,
        Bip448BroadcastStatus::NeedsRebroadcast
    );
    assert_eq!(needs.signed_tx_hex.as_deref(), Some(signed_bytes.as_str()));
    common::bitcoin_core::assert_not_in_mempool(&sweep_txid)?;

    assert_eq!(
        common::bitcoin_core::broadcast_raw_transaction(&funding_transaction)?,
        funding_transaction.txid()
    );
    common::bitcoin_core::assert_in_mempool(&funding_transaction.txid())?;
    let current_tip = fixture.config.chain_client.tip_height()?;
    let blocks_until_sweep_final = signed.lock_time.saturating_sub(current_tip).max(1);
    common::bitcoin_core::generatetoaddress(blocks_until_sweep_final, &recovery_mining_address)?;
    common::bitcoin_core::assert_confirmed(&funding_transaction.txid())?;
    common::bitcoin_core::execute_bitcoin_command(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury loadwallet mercury_test",
    )?;
    common::bitcoin_core::execute_bitcoin_command(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury loadwallet mercury_tokens",
    )?;
    let recovered = run_duplicate_sweep_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
        &destination,
        None,
        false,
    )?;
    require_child_exit(&recovered, 0, "signed sweep after parent resubmission")?;
    common::bitcoin_core::assert_in_mempool(&sweep_txid)?;
    let accepted = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
    )
    .await?
    .context("resubmitted-parent sweep attempt is missing")?;
    assert_eq!(accepted.broadcast_status, Bip448BroadcastStatus::Accepted);
    assert_eq!(
        accepted.signed_tx_hex.as_deref(),
        Some(signed_bytes.as_str())
    );
    assert_eq!(
        common::lockbox::get_signature_count(
            &common::lockbox::http_client(),
            &fixture.statechain_id,
        )
        .await?,
        2
    );
    common::bitcoin_core::mine_block_with_transactions(&[sweep_txid])?;
    Ok(())
}

pub(super) async fn bip448_duplicate_sweep_replays_every_signing_and_broadcast_boundary(
) -> Result<()> {
    if std::env::var("ML_BIP448_DUPLICATE_SWEEP_CHILD").as_deref() == Ok("1") {
        std::env::set_var("ML_NETWORK", "regtest");
        let config = mercuryrustlib::client_config::load().await;
        let result = mercuryrustlib::bip448_withdraw::execute_duplicate_sweep(
            &config,
            &std::env::var("ML_BIP448_RESTART_WALLET")?,
            &std::env::var("ML_BIP448_RESTART_STATECHAIN_ID")?,
            std::env::var("ML_BIP448_RESTART_DUPLICATE_INDEX")?.parse()?,
            &std::env::var("ML_BIP448_RESTART_DESTINATION")?,
            Some(1.0),
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

    exercise_prepared_mempool_conflict_and_eviction().await?;
    for (checkpoint, phase) in [
        ("attempt_prepared", Bip448WithdrawalPhase::Prepared),
        ("sign_first_armed", Bip448WithdrawalPhase::FirstArmed),
        ("server_nonce_persisted", Bip448WithdrawalPhase::NonceStored),
    ] {
        exercise_target_confirmed_duplicate_conflict(checkpoint, phase).await?;
    }
    exercise_signed_sweep_with_missing_funding_parent().await?;

    let fixture =
        duplicate_sweep_fixture(&[DUPLICATE_AMOUNT_SATS, SMALL_DUPLICATE_AMOUNT_SATS]).await?;
    let selected = fixture.bindings[1].clone();
    let other = fixture.bindings[2].clone();
    let destination = common::bitcoin_core::getnewaddress()?;
    let raw_wallet_before =
        sqlx::query_scalar::<_, String>("SELECT wallet_json FROM wallet WHERE wallet_name=$1")
            .bind(&fixture.wallet_name)
            .fetch_one(&fixture.config.pool)
            .await?;
    let accepted_before = accepted_state_bytes(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?;
    let mercury_before = mercury_state_bytes(&fixture.statechain_id).await?;
    let initial_count =
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?;
    assert_eq!(initial_count, 1);

    let checkpoints = [
        ("attempt_prepared", Bip448WithdrawalPhase::Prepared, 1),
        ("sign_first_armed", Bip448WithdrawalPhase::FirstArmed, 1),
        (
            "server_nonce_returned",
            Bip448WithdrawalPhase::FirstArmed,
            1,
        ),
        (
            "server_nonce_persisted",
            Bip448WithdrawalPhase::NonceStored,
            1,
        ),
        ("sign_second_armed", Bip448WithdrawalPhase::SecondArmed, 1),
        (
            "server_partial_returned",
            Bip448WithdrawalPhase::SecondArmed,
            2,
        ),
        ("signed_tx_persisted", Bip448WithdrawalPhase::Signed, 2),
        ("broadcast_returned", Bip448WithdrawalPhase::Signed, 2),
    ];
    let mut immutable = None;
    let mut nonce_artifacts = None;
    let mut signed_artifacts = None;
    let mut returned_server_nonce = None;
    for (checkpoint, phase, count) in checkpoints {
        let output = run_duplicate_sweep_child(
            &fixture.wallet_name,
            &fixture.statechain_id,
            selected.binding_index,
            &destination,
            Some(checkpoint),
            false,
        )?;
        require_child_exit(&output, 86, checkpoint)?;
        let attempts = mercuryrustlib::sqlite_manager::list_bip448_withdrawal_attempts(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?;
        assert_eq!(attempts.len(), 1, "{checkpoint} created a second row");
        let attempt = &attempts[0];
        assert_eq!(attempt.binding_index, selected.binding_index);
        assert_eq!(attempt.phase, phase, "wrong phase at {checkpoint}");
        assert_eq!(
            attempt.completion_status,
            mercuryrustlib::bip448_funding::Bip448CompletionStatus::NotApplicable,
            "duplicate attempt entered canonical completion at {checkpoint}"
        );
        let current_immutable = duplicate_attempt_immutable_json(attempt);
        if let Some(expected) = &immutable {
            assert_eq!(
                &current_immutable, expected,
                "immutable drift at {checkpoint}"
            );
        } else {
            immutable = Some(current_immutable);
        }
        if attempt.server_public_nonce.is_some() {
            let current = serde_json::json!({
                "server_public_nonce": attempt.server_public_nonce,
                "message_hex": attempt.message_hex,
                "output_pubkey": attempt.output_pubkey,
                "client_partial_sig": attempt.client_partial_sig,
                "encoded_session": attempt.encoded_session,
                "sign_second_payload_json": attempt.sign_second_payload_json,
            });
            if let Some(expected) = &nonce_artifacts {
                assert_eq!(&current, expected, "nonce/session drift at {checkpoint}");
            } else {
                nonce_artifacts = Some(current);
            }
        }
        if attempt.signed_tx_hex.is_some() {
            let current = serde_json::json!({
                "server_partial_sig": attempt.server_partial_sig,
                "aggregate_signature": attempt.aggregate_signature,
                "signed_tx_hex": attempt.signed_tx_hex,
                "txid": attempt.txid,
            });
            if let Some(expected) = &signed_artifacts {
                assert_eq!(&current, expected, "signed-artifact drift at {checkpoint}");
            } else {
                signed_artifacts = Some(current);
            }
        }
        assert_eq!(
            common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
            count,
            "wrong lockbox count at {checkpoint}"
        );

        if checkpoint == "server_nonce_returned" {
            assert!(
                attempt.server_public_nonce.is_none(),
                "returned nonce was persisted before its checkpoint"
            );
            returned_server_nonce = Some(child_server_nonce(&output)?);
        }
        if checkpoint == "server_nonce_persisted" {
            let replayed = child_server_nonce(&output)?;
            assert_eq!(
                Some(replayed.as_str()),
                returned_server_nonce.as_deref(),
                "exact sign/first replay returned a different server nonce"
            );
            assert_eq!(
                attempt.server_public_nonce.as_deref(),
                Some(replayed.as_str()),
                "persisted nonce differs from the replayed response"
            );

            let exact_payload_json = attempt
                .sign_second_payload_json
                .clone()
                .context("NonceStored attempt has no exact sign/second payload")?;
            let mut corrupted_payload: Bip448PartialSignatureRequestPayload =
                serde_json::from_str(&exact_payload_json)?;
            let full_session = attempt
                .encoded_session
                .as_deref()
                .context("NonceStored attempt has no full MuSig session")?;
            assert_ne!(
                full_session, corrupted_payload.session,
                "full and blinded MuSig sessions were falsely persisted as equal"
            );
            let mut different_blinded_session = hex::decode(&corrupted_payload.session)?;
            *different_blinded_session
                .get_mut(70)
                .context("blinded MuSig session is shorter than its typed encoding")? ^= 1;
            corrupted_payload.session = hex::encode(different_blinded_session);
            let corrupted_payload_json = serde_json::to_string(&corrupted_payload)?;
            sqlx::query(
                "UPDATE bip448_withdrawal_attempts SET sign_second_payload_json=$1 \
                 WHERE wallet_name=$2 AND statechain_id=$3 AND binding_index=$4",
            )
            .bind(&corrupted_payload_json)
            .bind(&fixture.wallet_name)
            .bind(&fixture.statechain_id)
            .bind(i64::from(selected.binding_index))
            .execute(&fixture.config.pool)
            .await?;
            let corrupted_journal = raw_withdrawal_attempt_journal_snapshot(
                &fixture.config,
                &fixture.wallet_name,
                &fixture.statechain_id,
                selected.binding_index,
            )
            .await?;
            let mercury_before_rejected_resume =
                mercury_state_bytes(&fixture.statechain_id).await?;
            let count_before_rejected_resume =
                common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id)
                    .await?;
            let rejected_resume = run_duplicate_sweep_child(
                &fixture.wallet_name,
                &fixture.statechain_id,
                selected.binding_index,
                &destination,
                None,
                false,
            )?;
            require_child_exit(&rejected_resume, 101, "mutated blinded session resume")?;
            let rejected_output = format!(
                "{}{}",
                String::from_utf8_lossy(&rejected_resume.stdout),
                String::from_utf8_lossy(&rejected_resume.stderr)
            );
            assert!(
                rejected_output.contains(
                    "BIP448 blinded MuSig session does not derive from the persisted full session"
                ),
                "mutated blinded session returned an unrelated error: {rejected_output}"
            );
            assert_eq!(
                raw_withdrawal_attempt_journal_snapshot(
                    &fixture.config,
                    &fixture.wallet_name,
                    &fixture.statechain_id,
                    selected.binding_index,
                )
                .await?,
                corrupted_journal,
                "rejected mutated-session resume changed the exact journal"
            );
            assert_eq!(
                sqlx::query_scalar::<_, String>(
                    "SELECT phase FROM bip448_withdrawal_attempts WHERE wallet_name=$1 \
                     AND statechain_id=$2 AND binding_index=$3",
                )
                .bind(&fixture.wallet_name)
                .bind(&fixture.statechain_id)
                .bind(i64::from(selected.binding_index))
                .fetch_one(&fixture.config.pool)
                .await?,
                "NonceStored",
                "mutated blinded session reached SecondArmed"
            );
            assert_eq!(
                mercury_state_bytes(&fixture.statechain_id).await?,
                mercury_before_rejected_resume,
                "mutated-session resume reached a Mercury signing side effect"
            );
            assert_eq!(
                common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id)
                    .await?,
                count_before_rejected_resume,
                "mutated-session resume consumed a lockbox count"
            );

            sqlx::query(
                "UPDATE bip448_withdrawal_attempts SET sign_second_payload_json=$1 \
                 WHERE wallet_name=$2 AND statechain_id=$3 AND binding_index=$4",
            )
            .bind(&exact_payload_json)
            .bind(&fixture.wallet_name)
            .bind(&fixture.statechain_id)
            .bind(i64::from(selected.binding_index))
            .execute(&fixture.config.pool)
            .await?;
            let restored = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
                &fixture.config.pool,
                &fixture.wallet_name,
                &fixture.statechain_id,
                selected.binding_index,
            )
            .await?
            .context("restored exact session journal disappeared")?;
            assert_eq!(restored.phase, Bip448WithdrawalPhase::NonceStored);
            assert_eq!(
                restored.sign_second_payload_json.as_deref(),
                Some(exact_payload_json.as_str())
            );
        }
        if checkpoint == "server_partial_returned" {
            let failed_count_read = run_duplicate_sweep_child(
                &fixture.wallet_name,
                &fixture.statechain_id,
                selected.binding_index,
                &destination,
                None,
                true,
            )?;
            require_child_exit(&failed_count_read, 101, "post-sign count-read failure")?;
            assert!(String::from_utf8_lossy(&failed_count_read.stderr)
                .contains("injected BIP448 post-sign lockbox count read failure"));
            let after_failure = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
                &fixture.config.pool,
                &fixture.wallet_name,
                &fixture.statechain_id,
                selected.binding_index,
            )
            .await?
            .context("count-read failure deleted the attempt")?;
            assert_eq!(after_failure.phase, Bip448WithdrawalPhase::SecondArmed);
            assert_eq!(
                duplicate_attempt_immutable_json(&after_failure),
                immutable.clone().unwrap(),
                "count-read failure changed immutable attempt artifacts"
            );
            assert!(after_failure.signed_tx_hex.is_none());
            assert_eq!(
                common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id)
                    .await?,
                2,
                "exact sign/second replay incremented the count twice"
            );
        }

        if checkpoint == "signed_tx_persisted" {
            let different = mercuryrustlib::bip448_withdraw::execute_duplicate_sweep(
                &fixture.config,
                &fixture.wallet_name,
                &fixture.statechain_id,
                other.binding_index,
                &destination,
                Some(1.0),
            )
            .await;
            assert!(different.is_err());
            assert!(
                mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
                    &fixture.config.pool,
                    &fixture.wallet_name,
                    &fixture.statechain_id,
                    other.binding_index,
                )
                .await?
                .is_none()
            );
            assert_eq!(
                common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id)
                    .await?,
                2
            );
        }
    }

    let final_output = run_duplicate_sweep_child(
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
        &destination,
        None,
        false,
    )?;
    require_child_exit(&final_output, 0, "final reconciliation")?;
    let attempt = mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
        selected.binding_index,
    )
    .await?
    .context("final duplicate attempt is missing")?;
    assert_eq!(attempt.phase, Bip448WithdrawalPhase::Signed);
    assert_eq!(attempt.broadcast_status, Bip448BroadcastStatus::Accepted);
    assert_eq!(
        duplicate_attempt_immutable_json(&attempt),
        immutable.unwrap()
    );
    let txid = Txid::from_str(attempt.txid.as_deref().context("signed txid")?)?;
    let transaction: bitcoin::Transaction =
        bitcoin::consensus::deserialize(&fixture.config.chain_client.get_raw_tx(&txid)?)?;
    assert_eq!(transaction.input.len(), 1);
    assert_eq!(transaction.output.len(), 1);
    assert_eq!(transaction.input[0].witness.len(), 1);
    let keypath_signature = transaction.input[0]
        .witness
        .iter()
        .next()
        .context("duplicate sweep keypath witness is missing")?;
    assert_eq!(keypath_signature.len(), 65);
    assert_eq!(
        keypath_signature[64], 0x01,
        "duplicate sweep lost SIGHASH_ALL"
    );
    assert_eq!(
        transaction.input[0].previous_output,
        OutPoint {
            txid: Txid::from_str(&selected.txid)?,
            vout: selected.vout,
        }
    );
    assert_ne!(
        transaction.input[0].previous_output,
        OutPoint {
            txid: Txid::from_str(&fixture.bindings[0].txid)?,
            vout: fixture.bindings[0].vout,
        }
    );
    assert_eq!(
        transaction.output[0].value,
        selected.value_sats.checked_sub(attempt.fee_sats).unwrap()
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT wallet_json FROM wallet WHERE wallet_name=$1")
            .bind(&fixture.wallet_name)
            .fetch_one(&fixture.config.pool)
            .await?,
        raw_wallet_before
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
    let mercury_after = mercury_state_bytes(&fixture.statechain_id).await?;
    assert_eq!(
        mercury_after.0, mercury_before.0,
        "duplicate sweep deleted/changed Mercury state"
    );
    assert_eq!(
        mercury_after.2, mercury_before.2,
        "duplicate sweep changed transfer state"
    );
    let wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&fixture.config.pool, &fixture.wallet_name)
            .await?;
    let coin = wallet
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some(&fixture.statechain_id))
        .context("canonical Coin disappeared")?;
    let record = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?;
    let user = PublicKey::from_str(&coin.user_pubkey)?;
    let server = PublicKey::from_str(coin.server_pubkey.as_deref().context("server key")?)?;
    assert_eq!(
        record
            .latest_state
            .verify_recovery_against_keys(&Secp256k1::new(), &user, &server)?,
        PublicKey::from_str(&record.aggregate_pubkey)?
    );
    let funded_fee_inputs = [fund_p2a_fee_input()?, fund_p2a_fee_input()?];
    common::bitcoin_core::mine_block()?;
    let fee_inputs = funded_fee_inputs
        .into_iter()
        .map(|funding| Bip448CpfpFeeInput::keyless(funding.outpoint, funding.value_sats))
        .collect::<Vec<_>>();
    let change_script =
        common::bitcoin_core::regtest_address(&common::bitcoin_core::getnewaddress()?)?
            .script_pubkey();
    let update_package = build_latest_state_recovery_package(
        &record,
        Bip448RecoveryTemplateRole::FundingUpdate,
        &fee_inputs[..1],
        change_script.clone(),
        2.0,
    )?;
    let settlement_package = build_latest_state_recovery_package(
        &record,
        Bip448RecoveryTemplateRole::Settlement,
        &fee_inputs[1..],
        change_script,
        2.0,
    )?;
    assert_eq!(
        hex::encode(bitcoin::consensus::serialize(&update_package.parent_tx)),
        record.latest_state.update_tx,
        "duplicate sweep changed canonical U recovery bytes"
    );
    assert_eq!(
        hex::encode(bitcoin::consensus::serialize(&settlement_package.parent_tx)),
        record.latest_state.settlement_tx,
        "duplicate sweep changed canonical S recovery bytes"
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
        2
    );
    Ok(())
}
