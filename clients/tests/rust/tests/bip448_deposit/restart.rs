use super::support::*;
use super::*;

pub(super) async fn bip448_client_restart_child() -> Result<()> {
    if std::env::var("ML_BIP448_RESTART_CHILD").as_deref() != Ok("1") {
        return Ok(());
    }

    let wallet_name = std::env::var("ML_BIP448_RESTART_WALLET")?;
    std::env::set_var("ML_NETWORK", "regtest");
    let client_config = mercuryrustlib::client_config::load().await;
    if let Ok(statechain_id) = std::env::var("ML_BIP448_RECOVERY_STATECHAIN") {
        let fee_input = mercuryrustlib::bip448_recovery::parse_keyless_p2a_fee_input(
            &std::env::var("ML_BIP448_RECOVERY_FEE_INPUT")?,
        )?;
        let change_address = std::env::var("ML_BIP448_RECOVERY_CHANGE_ADDRESS")?;
        let result = mercuryrustlib::bip448_recovery::submit_latest_state_recovery_package(
            &client_config,
            &wallet_name,
            &statechain_id,
            Bip448RecoveryTemplateRole::FundingUpdate,
            &[fee_input],
            &change_address,
            Some(PACKAGE_FEERATE_SAT_PER_VBYTE),
        )
        .await
        .map(|_| ());
        client_config.pool.close().await;
        return result;
    }
    let result = mercuryrustlib::coin_status::update_coins(&client_config, &wallet_name).await;
    client_config.pool.close().await;
    result
}

pub(super) async fn bip448_deposit_survives_client_process_restarts() -> Result<()> {
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
    let boundaries = [
        ("pending_persisted", false, false, 0),
        ("server_nonce_persisted", true, false, 0),
        ("final_signature_completed", true, false, 1),
        ("accepted_persisted", true, true, 1),
    ];

    for (index, (checkpoint, expect_server_nonce, expect_accepted, expected_count)) in
        boundaries.into_iter().enumerate()
    {
        let client_config = mercuryrustlib::client_config::load().await;
        let wallet_name = format!("bip448-restart-{index}-{}", uuid::Uuid::new_v4());
        let wallet = mercuryrustlib::wallet::create_wallet(&wallet_name, &client_config).await?;
        mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, &wallet).await?;
        let deposit = fund_confirmed_bip448_deposit(&client_config, &wallet).await?;
        client_config.pool.close().await;

        let interrupted = run_restart_child(&wallet_name, Some(checkpoint))?;
        assert_child_status(&interrupted, Some(RESTART_CHECKPOINT_EXIT_CODE), checkpoint)?;

        let interrupted_config = mercuryrustlib::client_config::load().await;
        let pending = mercuryrustlib::sqlite_manager::get_bip448_pending_deposit_signing(
            &interrupted_config.pool,
            &wallet_name,
            &deposit.statechain_id,
        )
        .await?
        .context("restart checkpoint did not leave a pending signing journal")?;
        assert_eq!(pending.server_public_nonce.is_some(), expect_server_nonce);
        let interrupted_accepted = mercuryrustlib::sqlite_manager::get_bip448_statechain_optional(
            &interrupted_config.pool,
            &wallet_name,
            &deposit.statechain_id,
        )
        .await?;
        assert_eq!(interrupted_accepted.is_some(), expect_accepted);
        if let Some(record) = &interrupted_accepted {
            assert_pending_matches_record(&pending, record);
        }
        assert_eq!(
            common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
            expected_count
        );
        interrupted_config.pool.close().await;

        let resumed = run_restart_child(&wallet_name, None)?;
        assert_child_status(&resumed, Some(0), &format!("resume after {checkpoint}"))?;

        let recovered_config = mercuryrustlib::client_config::load().await;
        assert!(
            mercuryrustlib::sqlite_manager::get_bip448_pending_deposit_signing(
                &recovered_config.pool,
                &wallet_name,
                &deposit.statechain_id,
            )
            .await?
            .is_none(),
            "resume after {checkpoint} did not clean up the pending journal"
        );
        let record = mercuryrustlib::sqlite_manager::get_bip448_statechain(
            &recovered_config.pool,
            &wallet_name,
            &deposit.statechain_id,
        )
        .await?;
        assert_pending_matches_record(&pending, &record);
        if let Some(interrupted_record) = interrupted_accepted {
            assert_eq!(record, interrupted_record);
        }

        let recovered_wallet =
            mercuryrustlib::sqlite_manager::get_wallet(&recovered_config.pool, &wallet_name)
                .await?;
        let recovered_coin = recovered_wallet
            .coins
            .iter()
            .find(|coin| coin.statechain_id.as_deref() == Some(&deposit.statechain_id))
            .context("resumed wallet does not contain the BIP448 deposit coin")?;
        assert_eq!(
            recovered_coin.public_nonce.as_deref(),
            Some(
                record
                    .latest_state
                    .signing_metadata
                    .client_public_nonce
                    .as_str()
            )
        );
        assert_eq!(
            recovered_coin.server_public_nonce.as_deref(),
            Some(
                record
                    .latest_state
                    .signing_metadata
                    .server_public_nonce
                    .as_str()
            )
        );
        assert_eq!(
            recovered_coin.blinding_factor.as_deref(),
            Some(
                record
                    .latest_state
                    .signing_metadata
                    .blinding_factor
                    .as_str()
            )
        );
        let update_tx = tx_from_hex(&record.latest_state.update_tx)?;
        let settlement_tx = tx_from_hex(&record.latest_state.settlement_tx)?;
        assert_eq!(update_tx.lock_time, settlement_tx.lock_time);
        assert_eq!(
            update_tx.lock_time.to_consensus_u32(),
            pending.state_locktime
        );
        assert_eq!(
            common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
            1,
            "resume after {checkpoint} consumed another blind signature"
        );
        recovered_config.pool.close().await;
    }

    Ok(())
}

fn run_restart_child(wallet_name: &str, checkpoint: Option<&str>) -> Result<Output> {
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
        .env("ML_NETWORK", "regtest")
        .env_remove("ML_BIP448_TEST_CHECKPOINT");
    if let Some(checkpoint) = checkpoint {
        command.env("ML_BIP448_TEST_CHECKPOINT", checkpoint);
    }

    Ok(command.output()?)
}

fn assert_pending_matches_record(
    pending: &mercuryrustlib::sqlite_manager::Bip448PendingDepositSigning,
    record: &Bip448StatechainRecord,
) {
    assert_eq!(record.latest_state_number, 1);
    assert_eq!(record.latest_state.state_number, 1);
    assert_eq!(
        record.latest_state.signing_metadata.server_signature_count,
        1
    );
    assert_eq!(pending.wallet_name, record.wallet_name);
    assert_eq!(pending.statechain_id, record.statechain_id);
    assert_eq!(pending.funding_txid, record.funding_outpoint.txid);
    assert_eq!(pending.funding_vout, record.funding_outpoint.vout);
    assert_eq!(
        pending.funding_value_sats,
        record.funding_outpoint.value_sats
    );
    assert_eq!(pending.state_locktime, record.latest_state.state_locktime);
    assert_eq!(
        pending.update_template_hash,
        record.latest_state.update_template_hash
    );
    assert_eq!(
        pending.settlement_template_hash,
        record.latest_state.settlement_template_hash
    );
    assert_eq!(
        pending.signing_id,
        record.latest_state.signing_metadata.signing_id
    );
    assert_eq!(
        pending.client_public_nonce,
        record.latest_state.signing_metadata.client_public_nonce
    );
    assert_eq!(
        pending.blinding_factor,
        record.latest_state.signing_metadata.blinding_factor
    );
    if let Some(server_public_nonce) = &pending.server_public_nonce {
        assert_eq!(
            server_public_nonce,
            &record.latest_state.signing_metadata.server_public_nonce
        );
    }
}
