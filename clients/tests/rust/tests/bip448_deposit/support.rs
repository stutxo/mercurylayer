use super::*;

pub(super) const PACKAGE_FEERATE_SAT_PER_VBYTE: f64 = 2.0;
pub(super) const RESTART_CHECKPOINT_EXIT_CODE: i32 = 86;

pub(super) async fn transfer_and_accept_bip448(
    client_config: &ClientConfig,
    sender_wallet: &str,
    receiver_wallet: &str,
    statechain_id: &str,
) -> Result<Bip448StatechainRecord> {
    let recipient_address =
        mercuryrustlib::transfer_receiver::new_transfer_address(client_config, receiver_wallet)
            .await?;
    mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender(
        client_config,
        &recipient_address,
        sender_wallet,
        statechain_id,
        None,
    )
    .await?;
    let receive_result =
        mercuryrustlib::transfer_receiver::execute(client_config, receiver_wallet).await?;
    assert!(!receive_result.is_there_batch_locked);
    assert_eq!(
        receive_result.received_statechain_ids,
        vec![statechain_id.to_string()]
    );
    mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &client_config.pool,
        receiver_wallet,
        statechain_id,
    )
    .await
}

pub(super) struct Bip448DepositFixture {
    pub(super) statechain_id: String,
}

pub(super) fn assert_child_status(
    output: &Output,
    expected: Option<i32>,
    context: &str,
) -> Result<()> {
    if output.status.code() == expected {
        return Ok(());
    }

    Err(anyhow!(
        "client process at {context} exited with {:?}, expected {expected:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    ))
}

pub(super) async fn create_confirmed_bip448_deposit(
    client_config: &ClientConfig,
    wallet: &Wallet,
) -> Result<Bip448DepositFixture> {
    let deposit = fund_confirmed_bip448_deposit(client_config, wallet).await?;
    mercuryrustlib::coin_status::update_coins(client_config, &wallet.name).await?;

    Ok(deposit)
}

pub(super) async fn fund_confirmed_bip448_deposit(
    client_config: &ClientConfig,
    wallet: &Wallet,
) -> Result<Bip448DepositFixture> {
    let token_response = mercuryrustlib::deposit::get_token(client_config).await?;
    let token_id = common::utils::handle_token_response(client_config, &token_response).await?;
    let deposit_address = mercuryrustlib::deposit::get_bip448_deposit_bitcoin_address(
        client_config,
        &wallet.name,
        &token_id,
        FUNDING_AMOUNT_SATS,
    )
    .await?;

    let _ = common::bitcoin_core::sendtoaddress(FUNDING_AMOUNT_SATS, &deposit_address.address)?;
    common::chain::wait_for_address_utxo(
        client_config,
        &deposit_address.address,
        FUNDING_AMOUNT_SATS,
    )
    .await?;
    common::bitcoin_core::mine_block()?;

    Ok(Bip448DepositFixture {
        statechain_id: deposit_address.statechain_id,
    })
}

pub(super) fn confirmed_p2a_fee_inputs(count: usize) -> Result<Vec<Bip448CpfpFeeInput>> {
    let funded = (0..count)
        .map(|_| fund_p2a_fee_input())
        .collect::<Result<Vec<_>>>()?;
    common::bitcoin_core::mine_block()?;

    Ok(funded
        .into_iter()
        .map(|funding| Bip448CpfpFeeInput::keyless(funding.outpoint, funding.value_sats))
        .collect())
}

pub(super) fn wallet_change_script() -> Result<ScriptBuf> {
    Ok(
        common::bitcoin_core::regtest_address(&common::bitcoin_core::getnewaddress()?)?
            .script_pubkey(),
    )
}

pub(super) fn tx_from_hex(tx_hex: &str) -> Result<Transaction> {
    Ok(encode::deserialize(&hex::decode(tx_hex)?)?)
}

pub(super) fn submit_package_success(package: &Bip448RecoveryPackage) -> Result<Value> {
    let response = common::bitcoin_core::submit_package(&[
        package.parent_tx.clone(),
        package.cpfp_child_tx.clone(),
    ])?;

    if !package_response_is_success(&response) {
        return Err(anyhow!("submitpackage did not accept package: {response}"));
    }

    Ok(response)
}

pub(super) fn package_response_is_success(response: &Value) -> bool {
    response.get("package_msg").and_then(Value::as_str) == Some("success")
}
