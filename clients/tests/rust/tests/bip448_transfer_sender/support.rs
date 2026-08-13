use super::*;

pub(super) const RESTART_EXIT: i32 = 86;

pub(super) async fn phase8_9_config() -> Result<ClientConfig> {
    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury).await?;
    let lockbox = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox).await?;
    common::prepare_test_env().await
}
pub(super) async fn create_wallet(config: &ClientConfig, name: &str) -> Result<Wallet> {
    let wallet = mercuryrustlib::wallet::create_wallet(name, config).await?;
    mercuryrustlib::sqlite_manager::insert_wallet(&config.pool, &wallet).await?;
    Ok(wallet)
}
pub(super) async fn create_confirmed_deposit(
    config: &ClientConfig,
    wallet: &Wallet,
) -> Result<String> {
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
pub(super) fn run_child(
    wallet: &str,
    statechain_id: &str,
    recipient: &str,
    checkpoint: Option<&str>,
) -> Result<Output> {
    run_child_with_batch(wallet, statechain_id, recipient, checkpoint, None)
}

pub(super) fn run_child_with_batch(
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
pub(super) fn assert_exit(output: &Output, expected: i32, context: &str) -> Result<()> {
    if output.status.code() == Some(expected) {
        return Ok(());
    }
    Err(anyhow!("transfer child at {context} exited with {:?}, expected {expected}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(), String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr)))
}

pub(super) async fn set_outgoing_message_raw(
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

pub(super) async fn assert_rotated_resume_fails_without_local_mutation(
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
pub(super) async fn get_encrypted_msgs(
    client: &reqwest::Client,
    auth_pubkey: &str,
) -> Result<Vec<String>> {
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
