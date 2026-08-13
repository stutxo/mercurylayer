use super::support::*;
use super::*;

pub(super) async fn bip448_duplicate_dust_remains_visible_and_blocks_close() -> Result<()> {
    let _guard = common::test_guard();
    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;
    let lockbox_client = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox_client).await?;

    let fixture = duplicate_sweep_fixture(&[DUST_DUPLICATE_AMOUNT_SATS]).await?;
    let dust = fixture.bindings[1].clone();
    let destination = common::bitcoin_core::getnewaddress()?;
    let destination_script = Address::from_str(&destination)?
        .require_network(fixture.config.network)?
        .script_pubkey();
    let output_value = dust.value_sats.checked_sub(112).context("dust fee")?;
    assert!(output_value < destination_script.dust_value().to_sat());
    let before_count =
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?;
    let wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&fixture.config.pool, &fixture.wallet_name)
            .await?;
    let entry = mercuryrustlib::coin_status::statecoin_list_entry_json(
        &fixture.wallet_name,
        wallet
            .coins
            .iter()
            .find(|coin| coin.statechain_id.as_deref() == Some(&fixture.statechain_id))
            .context("dust fixture Coin missing")?,
        &fixture.bindings,
        &[],
    )?;
    assert!(entry["coin.duplicates"]
        .as_array()
        .context("duplicate list is not an array")?
        .iter()
        .any(|duplicate| {
            duplicate["duplicate_index"].as_u64() == Some(u64::from(dust.binding_index))
                && duplicate["amount_sats"].as_u64() == Some(dust.value_sats)
        }));

    let error = mercuryrustlib::bip448_withdraw::execute_duplicate_sweep(
        &fixture.config,
        &fixture.wallet_name,
        &fixture.statechain_id,
        dust.binding_index,
        &destination,
        Some(1.0),
    )
    .await
    .unwrap_err();
    assert!(
        error.to_string().contains("TransactionReconstructionError")
            || error.to_string().contains("dust")
    );
    assert!(
        mercuryrustlib::sqlite_manager::get_bip448_withdrawal_attempt(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
            dust.binding_index,
        )
        .await?
        .is_none()
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
        before_count
    );
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
        "canonical close ignored the visible dust duplicate"
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &fixture.statechain_id).await?,
        before_count
    );
    assert_eq!(
        mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
            &fixture.config.pool,
            &fixture.wallet_name,
            &fixture.statechain_id,
        )
        .await?
        .into_iter()
        .find(|binding| binding.binding_index == dust.binding_index)
        .context("dust duplicate disappeared")?
        .value_sats,
        dust.value_sats
    );
    Ok(())
}
