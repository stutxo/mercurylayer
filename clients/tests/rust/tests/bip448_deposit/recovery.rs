use super::support::*;
use super::*;

const FEE_INPUT_COUNT: usize = 8;

pub(super) async fn bip448_deposit_recovers_through_update_and_settlement_packages() -> Result<()> {
    let _guard = common::test_guard();

    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;
    let lockbox_client = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox_client).await?;

    let client_config = common::prepare_test_env().await?;
    let wallet = mercuryrustlib::wallet::create_wallet("bip448-wallet", &client_config).await?;
    mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, &wallet).await?;

    let deposit = create_confirmed_bip448_deposit(&client_config, &wallet).await?;
    let record = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &client_config.pool,
        &wallet.name,
        &deposit.statechain_id,
    )
    .await?;
    assert_server_persistence_excludes_locktime(&record).await?;
    let wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet.name).await?;
    let coin = wallet
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some(&deposit.statechain_id))
        .context("BIP448 deposit coin not found after status update")?;
    assert_eq!(coin.statechain_protocol.as_deref(), Some("bip448"));
    assert!(matches!(
        coin.status,
        CoinStatus::UNCONFIRMED | CoinStatus::CONFIRMED
    ));

    let fee_inputs = confirmed_p2a_fee_inputs(FEE_INPUT_COUNT)?;
    let change_script = wallet_change_script()?;
    let update_tx = tx_from_hex(&record.latest_state.update_tx)?;
    let settlement_tx = tx_from_hex(&record.latest_state.settlement_tx)?;

    assert_eq!(update_tx.lock_time, settlement_tx.lock_time);
    assert_eq!(
        update_tx.lock_time.to_consensus_u32(),
        record.latest_state.state_locktime
    );
    assert!((500_000_000..=1_000_000_000).contains(&record.latest_state.state_locktime));
    let state_update_leaf = hex::decode(&record.latest_state.state_update_script)?;
    let expected_gate_prefix = Builder::new()
        .push_int(i64::from(record.latest_state.state_locktime) + 1)
        .push_opcode(OP_CLTV)
        .into_script();
    assert!(state_update_leaf.starts_with(expected_gate_prefix.as_bytes()));

    assert_eq!(update_tx.output[1].script_pubkey, pay_to_anchor_script());
    assert_eq!(
        settlement_tx.output[1].script_pubkey,
        pay_to_anchor_script()
    );
    assert_eq!(settlement_tx.input[0].witness.len(), 2);
    assert_ne!(settlement_tx.input[0].witness.nth(0).unwrap().len(), 64);

    assert_parent_only_rejected(&update_tx, "zero-fee BIP448 update parent")?;
    assert_committed_update_mutation_rejected(&record, &fee_inputs[0], change_script.clone())?;
    assert_anchor_mutation_rejected(
        &update_tx,
        record.funding_outpoint.value_sats,
        &fee_inputs[1],
        change_script.clone(),
    )?;

    let update_package = build_latest_state_recovery_package(
        &record,
        Bip448RecoveryTemplateRole::FundingUpdate,
        &[fee_inputs[2].clone()],
        change_script.clone(),
        PACKAGE_FEERATE_SAT_PER_VBYTE,
    )?;
    submit_package_success(&update_package)?;
    common::bitcoin_core::assert_in_mempool(&update_package.parent_tx.txid())?;
    common::bitcoin_core::assert_in_mempool(&update_package.cpfp_child_tx.txid())?;
    common::bitcoin_core::mine_block()?;
    common::bitcoin_core::assert_confirmed(&update_package.parent_tx.txid())?;

    let early_settlement_package = build_latest_state_recovery_package(
        &record,
        Bip448RecoveryTemplateRole::Settlement,
        &[fee_inputs[3].clone()],
        change_script.clone(),
        PACKAGE_FEERATE_SAT_PER_VBYTE,
    )?;
    assert_package_rejected(&early_settlement_package, "early BIP68 settlement package")?;

    common::bitcoin_core::mine_blocks(record.challenge_delay as u32)?;

    assert_committed_settlement_mutation_rejected(&record, &fee_inputs[4], change_script.clone())?;
    assert_anchor_mutation_rejected(
        &settlement_tx,
        record
            .latest_state
            .value_schedule
            .settlement_input_value_sats,
        &fee_inputs[5],
        change_script.clone(),
    )?;

    let settlement_package = build_latest_state_recovery_package(
        &record,
        Bip448RecoveryTemplateRole::Settlement,
        &[fee_inputs[6].clone()],
        change_script,
        PACKAGE_FEERATE_SAT_PER_VBYTE,
    )?;
    submit_package_success(&settlement_package)?;
    common::bitcoin_core::assert_in_mempool(&settlement_package.parent_tx.txid())?;
    common::bitcoin_core::assert_in_mempool(&settlement_package.cpfp_child_tx.txid())?;
    common::bitcoin_core::mine_block()?;
    common::bitcoin_core::assert_confirmed(&settlement_package.parent_tx.txid())?;

    common::chain::wait_for_address_outpoint(
        &client_config,
        &coin.backup_address,
        OutPoint {
            txid: settlement_package.parent_tx.txid(),
            vout: 0,
        },
        u64::from(FUNDING_AMOUNT_SATS),
    )
    .await?;

    Ok(())
}

pub(super) async fn bip448_client_submitter_broadcasts_recovery_package() -> Result<()> {
    let _guard = common::test_guard();

    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;
    let lockbox_client = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox_client).await?;

    let client_config = common::prepare_test_env().await?;
    let wallet =
        mercuryrustlib::wallet::create_wallet("bip448-submitter-wallet", &client_config).await?;
    mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, &wallet).await?;

    let deposit = create_confirmed_bip448_deposit(&client_config, &wallet).await?;
    let fee_inputs = confirmed_p2a_fee_inputs(1)?;
    let change_address = common::bitcoin_core::getnewaddress()?;

    // Exercise the client submitter end-to-end, including both mempool deduplication
    // and Bitcoin Core's response when the parent is already confirmed.
    let submit_funding_update = || {
        mercuryrustlib::bip448_recovery::submit_latest_state_recovery_package(
            &client_config,
            &wallet.name,
            &deposit.statechain_id,
            Bip448RecoveryTemplateRole::FundingUpdate,
            &fee_inputs,
            &change_address,
            Some(PACKAGE_FEERATE_SAT_PER_VBYTE),
        )
    };
    let submission = submit_funding_update().await?;
    let mempool_replay = submit_funding_update().await?;

    assert_eq!(submission.role, "funding_update");
    assert_eq!(mempool_replay.parent_txid, submission.parent_txid);
    assert_eq!(mempool_replay.cpfp_child_txid, submission.cpfp_child_txid);
    let parent_txid = Txid::from_str(&submission.parent_txid)?;
    let child_txid = Txid::from_str(&submission.cpfp_child_txid)?;
    common::bitcoin_core::assert_in_mempool(&parent_txid)?;
    common::bitcoin_core::assert_in_mempool(&child_txid)?;

    // Mine only the parent so Core can evaluate every transaction in the
    // replayed package.
    common::bitcoin_core::mine_block_with_transactions(&[parent_txid])?;
    common::bitcoin_core::assert_confirmed(&parent_txid)?;
    common::bitcoin_core::assert_not_in_mempool(&parent_txid)?;
    common::bitcoin_core::assert_in_mempool(&child_txid)?;

    let confirmed_parent_replay = submit_funding_update().await?;
    assert_eq!(confirmed_parent_replay.parent_txid, submission.parent_txid);
    assert_eq!(
        confirmed_parent_replay.cpfp_child_txid,
        submission.cpfp_child_txid
    );
    assert_ne!(
        confirmed_parent_replay
            .submitpackage_response
            .get("package_msg")
            .and_then(Value::as_str),
        Some("success")
    );
    let tx_results = confirmed_parent_replay
        .submitpackage_response
        .get("tx-results")
        .and_then(Value::as_object)
        .context("confirmed-parent replay did not include transaction results")?;
    assert_eq!(tx_results.len(), 2);
    let parent_result = tx_results
        .values()
        .find(|result| result.get("txid").and_then(Value::as_str) == Some(&submission.parent_txid))
        .context("confirmed-parent replay did not include the parent result")?;
    assert_eq!(
        parent_result.get("error").and_then(Value::as_str),
        Some("txn-already-known")
    );
    let child_result = tx_results
        .values()
        .find(|result| {
            result.get("txid").and_then(Value::as_str) == Some(&submission.cpfp_child_txid)
        })
        .context("confirmed-parent replay did not include the CPFP child result")?;
    assert!(child_result.get("error").is_none());

    let stored_attempt = mercuryrustlib::sqlite_manager::get_bip448_package_attempt(
        &client_config.pool,
        &wallet.name,
        &deposit.statechain_id,
        Bip448RecoveryTemplateRole::FundingUpdate.as_str(),
    )
    .await?
    .context("submitted recovery attempt disappeared")?;
    let mempool_before_corruption = common::bitcoin_core::raw_mempool()?
        .into_iter()
        .collect::<HashSet<_>>();
    sqlx::query(
        "UPDATE bip448_package_attempts \
         SET target_feerate_sat_per_vbyte = $1 \
         WHERE wallet_name = $2 AND statechain_id = $3 AND role = 'funding_update'",
    )
    .bind(stored_attempt.target_feerate_sat_per_vbyte + 100.0)
    .bind(&wallet.name)
    .bind(&deposit.statechain_id)
    .execute(&client_config.pool)
    .await?;
    let target_error = submit_funding_update()
        .await
        .expect_err("corrupt persisted target feerate did not fail closed");
    assert!(target_error.to_string().contains("inconsistent"));
    assert_eq!(
        common::bitcoin_core::raw_mempool()?
            .into_iter()
            .collect::<HashSet<_>>(),
        mempool_before_corruption
    );
    sqlx::query(
        "UPDATE bip448_package_attempts \
         SET target_feerate_sat_per_vbyte = $1 \
         WHERE wallet_name = $2 AND statechain_id = $3 AND role = 'funding_update'",
    )
    .bind(stored_attempt.target_feerate_sat_per_vbyte)
    .bind(&wallet.name)
    .bind(&deposit.statechain_id)
    .execute(&client_config.pool)
    .await?;

    common::bitcoin_core::mine_block()?;
    common::bitcoin_core::assert_confirmed(&child_txid)?;
    sqlx::query(
        "UPDATE bip448_package_attempts SET child_tx_hex = '00' \
         WHERE wallet_name = $1 AND statechain_id = $2 AND role = 'funding_update'",
    )
    .bind(&wallet.name)
    .bind(&deposit.statechain_id)
    .execute(&client_config.pool)
    .await?;
    let corrupt_child_error =
        mercuryrustlib::bip448_recovery::confirm_latest_state_recovery_package(
            &client_config,
            &wallet.name,
            &deposit.statechain_id,
            Bip448RecoveryTemplateRole::FundingUpdate,
        )
        .await
        .expect_err("unparseable persisted child was marked confirmed");
    assert!(corrupt_child_error
        .to_string()
        .contains("invalid stored BIP448 recovery child"));
    assert_eq!(
        mercuryrustlib::sqlite_manager::get_bip448_package_attempt(
            &client_config.pool,
            &wallet.name,
            &deposit.statechain_id,
            Bip448RecoveryTemplateRole::FundingUpdate.as_str(),
        )
        .await?
        .context("corrupt recovery attempt disappeared")?
        .status,
        mercuryrustlib::sqlite_manager::Bip448PackageAttemptStatus::Submitted
    );
    assert!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bip448_scanned_outpoints \
             WHERE wallet_name = $1 AND reserved_by IS NOT NULL",
        )
        .bind(&wallet.name)
        .fetch_one(&client_config.pool)
        .await?
            > 0
    );
    sqlx::query(
        "UPDATE bip448_package_attempts SET child_tx_hex = $1 \
         WHERE wallet_name = $2 AND statechain_id = $3 AND role = 'funding_update'",
    )
    .bind(&stored_attempt.child_tx_hex)
    .bind(&wallet.name)
    .bind(&deposit.statechain_id)
    .execute(&client_config.pool)
    .await?;

    let child: Transaction = encode::deserialize(&hex::decode(&stored_attempt.child_tx_hex)?)?;
    let descendant_txid = common::bitcoin_core::spend_wallet_outpoint(
        OutPoint {
            txid: child_txid,
            vout: 0,
        },
        child.output[0].value,
    )?;
    common::bitcoin_core::assert_in_mempool(&descendant_txid)?;
    assert!(client_config
        .chain_client
        .get_tx_out(&child_txid, 0, true)?
        .is_none());
    let confirmed_replay = submit_funding_update().await?;
    assert_eq!(
        confirmed_replay
            .submitpackage_response
            .get("package_msg")
            .and_then(Value::as_str),
        Some("already-in-chain")
    );
    assert_eq!(
        mercuryrustlib::sqlite_manager::get_bip448_package_attempt(
            &client_config.pool,
            &wallet.name,
            &deposit.statechain_id,
            Bip448RecoveryTemplateRole::FundingUpdate.as_str(),
        )
        .await?
        .context("confirmed recovery attempt disappeared")?
        .status,
        mercuryrustlib::sqlite_manager::Bip448PackageAttemptStatus::Confirmed
    );

    Ok(())
}

pub(super) async fn bip448_owner_recovery_survives_restart_mid_broadcast() -> Result<()> {
    let _guard = common::test_guard();

    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;
    let lockbox_client = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox_client).await?;

    let initial_config = common::prepare_test_env().await?;
    initial_config.pool.close().await;
    for (index, checkpoint) in ["recovery_pending", "recovery_submitted"]
        .into_iter()
        .enumerate()
    {
        let client_config = mercuryrustlib::client_config::load().await;
        let wallet_name = format!("bip448-recovery-restart-{index}-{}", uuid::Uuid::new_v4());
        let wallet = mercuryrustlib::wallet::create_wallet(&wallet_name, &client_config).await?;
        mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, &wallet).await?;
        let deposit = create_confirmed_bip448_deposit(&client_config, &wallet).await?;
        let fee_input = confirmed_p2a_fee_inputs(1)?
            .into_iter()
            .next()
            .context("fee input funding returned no input")?;
        let fee_input_descriptor = format!(
            "{}:{}:{}",
            fee_input.previous_output.txid, fee_input.previous_output.vout, fee_input.value_sats
        );
        let change_address = common::bitcoin_core::getnewaddress()?;
        let missing = mercuryrustlib::bip448_recovery::resume_latest_state_recovery_package(
            &client_config,
            &wallet_name,
            &deposit.statechain_id,
            Bip448RecoveryTemplateRole::FundingUpdate,
        )
        .await
        .expect_err("recovery without a persisted attempt did not fail closed");
        assert!(missing.to_string().contains("attempt is missing"));
        client_config.pool.close().await;

        let interrupted = run_recovery_restart_child(
            &wallet_name,
            &deposit.statechain_id,
            &fee_input_descriptor,
            &change_address,
            Some(checkpoint),
        )?;
        assert_child_status(&interrupted, Some(RESTART_CHECKPOINT_EXIT_CODE), checkpoint)?;

        let interrupted_config = mercuryrustlib::client_config::load().await;
        let attempt = mercuryrustlib::sqlite_manager::get_bip448_package_attempt(
            &interrupted_config.pool,
            &wallet_name,
            &deposit.statechain_id,
            Bip448RecoveryTemplateRole::FundingUpdate.as_str(),
        )
        .await?
        .context("recovery checkpoint did not persist an attempt")?;
        assert_eq!(
            attempt.status,
            mercuryrustlib::sqlite_manager::Bip448PackageAttemptStatus::Pending
        );
        let parent_txid = Txid::from_str(&attempt.parent_txid)?;
        let child_txid = Txid::from_str(&attempt.child_txid)?;
        let stored_child_hex = attempt.child_tx_hex.clone();
        let mempool_before_resume = common::bitcoin_core::raw_mempool()?
            .into_iter()
            .collect::<HashSet<_>>();
        if checkpoint == "recovery_pending" {
            assert!(!mempool_before_resume.contains(&parent_txid));
            assert!(!mempool_before_resume.contains(&child_txid));
        } else {
            assert!(mempool_before_resume.contains(&parent_txid));
            assert!(mempool_before_resume.contains(&child_txid));
        }
        interrupted_config.pool.close().await;

        let resumed = run_recovery_restart_child(
            &wallet_name,
            &deposit.statechain_id,
            &fee_input_descriptor,
            &change_address,
            None,
        )?;
        assert_child_status(&resumed, Some(0), &format!("resume after {checkpoint}"))?;

        let resumed_config = mercuryrustlib::client_config::load().await;
        let resumed_attempt = mercuryrustlib::sqlite_manager::get_bip448_package_attempt(
            &resumed_config.pool,
            &wallet_name,
            &deposit.statechain_id,
            Bip448RecoveryTemplateRole::FundingUpdate.as_str(),
        )
        .await?
        .context("resumed recovery attempt disappeared")?;
        assert_eq!(resumed_attempt.child_tx_hex, stored_child_hex);
        assert_eq!(resumed_attempt.child_txid, child_txid.to_string());
        assert_eq!(
            resumed_attempt.status,
            mercuryrustlib::sqlite_manager::Bip448PackageAttemptStatus::Submitted
        );
        common::bitcoin_core::assert_in_mempool(&parent_txid)?;
        common::bitcoin_core::assert_in_mempool(&child_txid)?;
        if checkpoint == "recovery_submitted" {
            assert_eq!(
                common::bitcoin_core::raw_mempool()?
                    .into_iter()
                    .collect::<HashSet<_>>(),
                mempool_before_resume
            );
        }
        resumed_config.pool.close().await;

        common::bitcoin_core::mine_block()?;
        common::bitcoin_core::assert_confirmed(&parent_txid)?;
        common::bitcoin_core::assert_confirmed(&child_txid)?;
        let confirmed = run_recovery_restart_child(
            &wallet_name,
            &deposit.statechain_id,
            &fee_input_descriptor,
            &change_address,
            None,
        )?;
        assert_child_status(
            &confirmed,
            Some(0),
            &format!("confirmed replay after {checkpoint}"),
        )?;
        let confirmed_config = mercuryrustlib::client_config::load().await;
        let confirmed_attempt = mercuryrustlib::sqlite_manager::get_bip448_package_attempt(
            &confirmed_config.pool,
            &wallet_name,
            &deposit.statechain_id,
            Bip448RecoveryTemplateRole::FundingUpdate.as_str(),
        )
        .await?
        .context("confirmed recovery attempt disappeared")?;
        assert_eq!(confirmed_attempt.child_tx_hex, stored_child_hex);
        assert_eq!(
            confirmed_attempt.status,
            mercuryrustlib::sqlite_manager::Bip448PackageAttemptStatus::Confirmed
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM bip448_scanned_outpoints \
                 WHERE wallet_name = $1 AND reserved_by IS NOT NULL",
            )
            .bind(&wallet_name)
            .fetch_one(&confirmed_config.pool)
            .await?,
            0
        );
        confirmed_config.pool.close().await;
    }

    Ok(())
}

pub(super) async fn bip448_cli_wallet_funded_and_keyless_recovery_packages() -> Result<()> {
    let _guard = common::test_guard();
    let client_cli = build_client_cli()?;

    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;
    let lockbox_client = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox_client).await?;

    let client_config = common::prepare_test_env().await?;
    let wallet =
        mercuryrustlib::wallet::create_wallet("bip448-wallet-funded-cli", &client_config).await?;
    mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, &wallet).await?;
    let deposit = create_confirmed_bip448_deposit(&client_config, &wallet).await?;

    let fee_address = run_client_cli(
        &client_cli,
        &[
            "bip448-recovery-fee-address".to_string(),
            wallet.name.clone(),
        ],
    )?;
    let fee_address = fee_address
        .get("address")
        .and_then(Value::as_str)
        .context("fee-address command omitted address")?;
    let fee_address = common::bitcoin_core::regtest_address(fee_address)?;
    fund_address_output(&fee_address, FEE_INPUT_AMOUNT_SATS)?;
    common::bitcoin_core::mine_block()?;

    let wallet_funded = run_client_cli(
        &client_cli,
        &[
            "broadcast-bip448-recovery-package".to_string(),
            wallet.name.clone(),
            deposit.statechain_id,
            "funding_update".to_string(),
            "--fund-from-wallet".to_string(),
            "--fee-rate".to_string(),
            PACKAGE_FEERATE_SAT_PER_VBYTE.to_string(),
        ],
    )?;
    confirm_cli_recovery_package(&wallet_funded)?;

    let keyless_wallet =
        mercuryrustlib::wallet::create_wallet("bip448-keyless-cli", &client_config).await?;
    mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, &keyless_wallet).await?;
    let keyless_deposit = create_confirmed_bip448_deposit(&client_config, &keyless_wallet).await?;
    let fee_input = fund_p2a_fee_input()?;
    common::bitcoin_core::mine_block()?;
    let fee_input = format!(
        "{}:{}:{}",
        fee_input.outpoint.txid, fee_input.outpoint.vout, fee_input.value_sats
    );

    let keyless = run_client_cli(
        &client_cli,
        &[
            "broadcast-bip448-recovery-package".to_string(),
            keyless_wallet.name,
            keyless_deposit.statechain_id,
            "funding_update".to_string(),
            common::bitcoin_core::getnewaddress()?,
            "--fee-input".to_string(),
            fee_input,
            "--fee-rate".to_string(),
            PACKAGE_FEERATE_SAT_PER_VBYTE.to_string(),
        ],
    )?;
    confirm_cli_recovery_package(&keyless)?;

    Ok(())
}

fn build_client_cli() -> Result<PathBuf> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "build",
            "--locked",
            "--package",
            "client-rust",
            "--bin",
            "client-rust",
            "--message-format=json-render-diagnostics",
        ])
        .output()
        .context("failed to build client-rust for the CLI recovery test")?;
    if !output.status.success() {
        return Err(anyhow!(
            "client-rust build failed with {:?}\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ));
    }

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find_map(|message| {
            (message.get("reason").and_then(Value::as_str) == Some("compiler-artifact")
                && message
                    .get("target")
                    .and_then(|target| target.get("name"))
                    .and_then(Value::as_str)
                    == Some("client-rust"))
            .then(|| {
                message
                    .get("executable")
                    .and_then(Value::as_str)
                    .map(PathBuf::from)
            })
            .flatten()
        })
        .context("client-rust build did not report its executable")
}

fn run_client_cli(binary: &Path, args: &[String]) -> Result<Value> {
    let output = Command::new(binary)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("ML_NETWORK", "regtest")
        .args(args)
        .output()
        .with_context(|| format!("failed to execute {}", binary.display()))?;
    if !output.status.success() {
        return Err(anyhow!(
            "client command failed with {:?}\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ));
    }

    Ok(serde_json::from_slice(&output.stdout)?)
}

fn confirm_cli_recovery_package(submission: &Value) -> Result<()> {
    let parent_txid = submission
        .get("parent_txid")
        .and_then(Value::as_str)
        .context("CLI recovery omitted parent_txid")?
        .parse::<Txid>()?;
    let child_txid = submission
        .get("cpfp_child_txid")
        .and_then(Value::as_str)
        .context("CLI recovery omitted cpfp_child_txid")?
        .parse::<Txid>()?;
    common::bitcoin_core::assert_in_mempool(&parent_txid)?;
    common::bitcoin_core::assert_in_mempool(&child_txid)?;
    common::bitcoin_core::mine_block()?;
    common::bitcoin_core::assert_confirmed(&parent_txid)?;
    common::bitcoin_core::assert_confirmed(&child_txid)?;

    Ok(())
}

fn run_recovery_restart_child(
    wallet_name: &str,
    statechain_id: &str,
    fee_input: &str,
    change_address: &str,
    checkpoint: Option<&str>,
) -> Result<Output> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "--ignored",
            "--exact",
            "bip448_client_restart_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ML_BIP448_RESTART_CHILD", "1")
        .env("ML_BIP448_RESTART_WALLET", wallet_name)
        .env("ML_BIP448_RECOVERY_STATECHAIN", statechain_id)
        .env("ML_BIP448_RECOVERY_FEE_INPUT", fee_input)
        .env("ML_BIP448_RECOVERY_CHANGE_ADDRESS", change_address)
        .env("ML_NETWORK", "regtest")
        .env_remove("ML_BIP448_TEST_CHECKPOINT");
    if let Some(checkpoint) = checkpoint {
        command.env("ML_BIP448_TEST_CHECKPOINT", checkpoint);
    }
    Ok(command.output()?)
}

async fn assert_server_persistence_excludes_locktime(
    record: &Bip448StatechainRecord,
) -> Result<()> {
    let databases = [
        (
            common::mercury::database_url(),
            &["bip448_signature_data", "signing_nonce_leases"][..],
        ),
        (
            common::lockbox::database_url(),
            &["bip448_nonce_state", "generated_public_key"][..],
        ),
    ];
    let forbidden = [
        "state_locktime",
        "locktime",
        "state_number",
        "template_hash",
        "random_offset",
        "stride",
    ];
    let forbidden_values = [
        record.latest_state.state_locktime.to_string(),
        record
            .latest_state
            .update_template_hash
            .to_ascii_lowercase(),
        record
            .latest_state
            .settlement_template_hash
            .to_ascii_lowercase(),
        record.latest_state.update_tx.to_ascii_lowercase(),
        record.latest_state.settlement_tx.to_ascii_lowercase(),
        record
            .latest_state
            .state_output_script_pubkey
            .to_ascii_lowercase(),
        record
            .latest_state
            .funding_update_script
            .to_ascii_lowercase(),
        record
            .latest_state
            .funding_update_control_block
            .to_ascii_lowercase(),
        record.latest_state.state_update_script.to_ascii_lowercase(),
        record
            .latest_state
            .state_update_control_block
            .to_ascii_lowercase(),
        record
            .latest_state
            .state_settlement_script
            .to_ascii_lowercase(),
        record
            .latest_state
            .state_settlement_control_block
            .to_ascii_lowercase(),
    ];

    for (database_url, tables) in databases {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(database_url)
            .await?;
        let columns = sqlx::query(
            "SELECT table_name, column_name FROM information_schema.columns \
             WHERE table_schema = 'public'",
        )
        .fetch_all(&pool)
        .await?;
        let mut audited_tables = HashSet::new();
        for row in columns {
            let table_name: String = row.get("table_name");
            if !tables.contains(&table_name.as_str()) {
                continue;
            }
            audited_tables.insert(table_name.clone());
            let column_name: String = row.get("column_name");
            assert!(
                !forbidden.iter().any(|name| column_name.contains(name)),
                "server-side table {table_name} exposes forbidden column {column_name}"
            );
        }
        assert_eq!(
            audited_tables.len(),
            tables.len(),
            "server-side audit did not find every expected table: {tables:?}"
        );

        let mut populated_rows = 0;
        for table_name in tables {
            let query = format!(
                "SELECT row_to_json(row_data)::text FROM {table_name} AS row_data \
                 WHERE statechain_id = $1"
            );
            let rows = sqlx::query_scalar::<_, String>(&query)
                .bind(&record.statechain_id)
                .fetch_all(&pool)
                .await?;
            populated_rows += rows.len();
            for row_json in rows {
                let row_json = row_json.to_ascii_lowercase();
                assert!(
                    !forbidden.iter().any(|name| row_json.contains(name)),
                    "server-side row in {table_name} exposed consensus metadata: {row_json}"
                );
                for forbidden_value in &forbidden_values {
                    assert!(
                        !row_json.contains(forbidden_value),
                        "server-side row in {table_name} exposed template value {forbidden_value}"
                    );
                }
            }
        }
        assert!(
            populated_rows > 0,
            "server-side audit queried no populated rows"
        );
        pool.close().await;
    }

    Ok(())
}

fn assert_package_rejected(package: &Bip448RecoveryPackage, context: &str) -> Result<()> {
    let response = common::bitcoin_core::submit_package(&[
        package.parent_tx.clone(),
        package.cpfp_child_tx.clone(),
    ])
    .with_context(|| format!("{context}: submitpackage invocation failed"))?;
    let package_msg = response
        .get("package_msg")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{context}: submitpackage omitted package_msg: {response}"))?;
    if package_msg == "success" {
        return Err(anyhow!(
            "{context} unexpectedly accepted by submitpackage: {response}"
        ));
    }

    common::bitcoin_core::assert_not_in_mempool(&package.parent_tx.txid())?;
    common::bitcoin_core::assert_not_in_mempool(&package.cpfp_child_tx.txid())?;

    Ok(())
}

fn assert_parent_only_rejected(parent_tx: &Transaction, context: &str) -> Result<()> {
    match common::bitcoin_core::broadcast_raw_transaction(parent_tx) {
        Ok(txid) => Err(anyhow!("{context} unexpectedly broadcast alone: {txid}")),
        Err(error) => {
            let error = error.to_string();
            if !error.contains("error code: -26") || !error.contains("min relay fee not met") {
                return Err(anyhow!(
                    "{context} broadcast failed for an unexpected reason: {error}"
                ));
            }
            common::bitcoin_core::assert_not_in_mempool(&parent_tx.txid())?;
            Ok(())
        }
    }
}

fn assert_committed_update_mutation_rejected(
    record: &Bip448StatechainRecord,
    fee_input: &Bip448CpfpFeeInput,
    change_script: ScriptBuf,
) -> Result<()> {
    let mut mutated = tx_from_hex(&record.latest_state.update_tx)?;
    mutated.output[0].value -= 1;
    let package = build_anchor_cpfp_package(
        &mutated,
        record.funding_outpoint.value_sats,
        1,
        &[fee_input.clone()],
        change_script,
        PACKAGE_FEERATE_SAT_PER_VBYTE,
    )?;

    assert_package_rejected(&package, "mutated BIP448 update package")
}

fn assert_committed_settlement_mutation_rejected(
    record: &Bip448StatechainRecord,
    fee_input: &Bip448CpfpFeeInput,
    change_script: ScriptBuf,
) -> Result<()> {
    let mut mutated = tx_from_hex(&record.latest_state.settlement_tx)?;
    mutated.output[0].value -= 1;
    let package = build_anchor_cpfp_package(
        &mutated,
        record
            .latest_state
            .value_schedule
            .settlement_input_value_sats,
        1,
        &[fee_input.clone()],
        change_script,
        PACKAGE_FEERATE_SAT_PER_VBYTE,
    )?;

    assert_package_rejected(&package, "mutated BIP448 settlement package")
}

fn assert_anchor_mutation_rejected(
    parent_tx: &Transaction,
    parent_input_value_sats: u64,
    fee_input: &Bip448CpfpFeeInput,
    change_script: ScriptBuf,
) -> Result<()> {
    let mut missing_anchor = parent_tx.clone();
    missing_anchor.output.pop();
    assert!(build_anchor_cpfp_package(
        &missing_anchor,
        parent_input_value_sats,
        1,
        &[fee_input.clone()],
        change_script.clone(),
        PACKAGE_FEERATE_SAT_PER_VBYTE,
    )
    .is_err());

    let mut mutated_anchor = parent_tx.clone();
    mutated_anchor.output[1].script_pubkey = change_script.clone();
    assert!(build_anchor_cpfp_package(
        &mutated_anchor,
        parent_input_value_sats,
        1,
        &[fee_input.clone()],
        change_script.clone(),
        PACKAGE_FEERATE_SAT_PER_VBYTE,
    )
    .is_err());

    let mut moved_anchor = parent_tx.clone();
    let replacement_anchor = moved_anchor.output[1].clone();
    moved_anchor.output[1] = TxOut {
        value: 0,
        script_pubkey: ScriptBuf::from_bytes(vec![0x6a]),
    };
    moved_anchor.output.push(replacement_anchor);
    let replacement_anchor_package = build_anchor_cpfp_package(
        &moved_anchor,
        parent_input_value_sats,
        2,
        &[fee_input.clone()],
        change_script,
        PACKAGE_FEERATE_SAT_PER_VBYTE,
    )?;
    assert_package_rejected(
        &replacement_anchor_package,
        "BIP448 parent with its committed anchor replaced and moved",
    )?;

    Ok(())
}
