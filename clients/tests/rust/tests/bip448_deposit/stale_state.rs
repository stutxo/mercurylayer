use super::support::*;
use super::*;

pub(super) async fn bip448_latest_state_fast_forwards_over_confirmed_old_state() -> Result<()> {
    let _guard = common::test_guard();

    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;
    let lockbox_client = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox_client).await?;

    let client_config = common::prepare_test_env().await?;
    let original_owner =
        mercuryrustlib::wallet::create_wallet("bip448-stale-original", &client_config).await?;
    let intermediate_owner =
        mercuryrustlib::wallet::create_wallet("bip448-stale-intermediate", &client_config).await?;
    let current_owner =
        mercuryrustlib::wallet::create_wallet("bip448-stale-current", &client_config).await?;
    for wallet in [&original_owner, &intermediate_owner, &current_owner] {
        mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, wallet).await?;
    }

    let deposit = create_confirmed_bip448_deposit(&client_config, &original_owner).await?;
    common::bitcoin_core::mine_blocks(client_config.confirmation_target)?;
    mercuryrustlib::coin_status::update_coins(&client_config, &original_owner.name).await?;
    let state_one = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &client_config.pool,
        &original_owner.name,
        &deposit.statechain_id,
    )
    .await?;

    let state_two = transfer_and_accept_bip448(
        &client_config,
        &original_owner.name,
        &intermediate_owner.name,
        &deposit.statechain_id,
    )
    .await?;
    assert_eq!(state_two.latest_state_number, 2);
    let state_three = transfer_and_accept_bip448(
        &client_config,
        &intermediate_owner.name,
        &current_owner.name,
        &deposit.statechain_id,
    )
    .await?;

    let current_wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &current_owner.name)
            .await?;
    let current_coin = current_wallet
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some(&deposit.statechain_id))
        .context("current owner does not contain the accepted state-3 BIP448 coin")?;
    let current_recovery_address = current_coin.backup_address.clone();

    assert_eq!(state_one.latest_state_number, 1);
    assert_eq!(state_one.latest_state.state_number, 1);
    assert_eq!(state_three.latest_state_number, 3);
    assert_eq!(state_three.latest_state.state_number, 3);
    let lockbox_client = common::lockbox::http_client();
    let accepted_signature_count =
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?;
    assert_eq!(accepted_signature_count, 3);

    let fee_inputs = confirmed_p2a_fee_inputs(3)?;
    let change_script = wallet_change_script()?;
    let old_update_package = build_latest_state_recovery_package(
        &state_one,
        Bip448RecoveryTemplateRole::FundingUpdate,
        &[fee_inputs[0].clone()],
        change_script.clone(),
        PACKAGE_FEERATE_SAT_PER_VBYTE,
    )?;
    submit_package_success(&old_update_package)?;
    let old_update_txid = old_update_package.parent_tx.txid();
    let old_update_child_txid = old_update_package.cpfp_child_tx.txid();
    common::bitcoin_core::assert_in_mempool(&old_update_txid)?;
    common::bitcoin_core::assert_in_mempool(&old_update_child_txid)?;
    common::bitcoin_core::mine_block()?;
    common::bitcoin_core::assert_confirmed(&old_update_txid)?;
    common::bitcoin_core::assert_confirmed(&old_update_child_txid)?;

    let old_update_outpoint = OutPoint {
        txid: old_update_txid,
        vout: 0,
    };
    let old_update_output = &old_update_package.parent_tx.output[0];
    let state_one_output_script = ScriptBuf::from_bytes(hex::decode(
        &state_one.latest_state.state_output_script_pubkey,
    )?);
    assert_eq!(old_update_output.script_pubkey, state_one_output_script);

    let original_latest_update = tx_from_hex(&state_three.latest_state.update_tx)?;
    let original_latest_update_hash = transaction::update_template_hash(&original_latest_update)?;
    let mut rebound_latest_update = transaction::rebind_update_tx(
        &original_latest_update,
        old_update_outpoint,
        old_update_output.value,
        FeePolicy::ZeroFeeEphemeralAnchor,
    )?;
    let latest_update_signature =
        schnorr::Signature::from_str(&state_three.latest_state.signing_metadata.update_signature)?;
    let state_one_update_script =
        ScriptBuf::from_bytes(hex::decode(&state_one.latest_state.state_update_script)?);
    let state_one_update_control_block = ControlBlock::decode(&hex::decode(
        &state_one.latest_state.state_update_control_block,
    )?)?;
    rebound_latest_update.input[0].witness = csfs_script_witness(
        &latest_update_signature,
        &state_one_update_script,
        &state_one_update_control_block,
    );

    assert_eq!(
        rebound_latest_update.input[0].previous_output,
        old_update_outpoint
    );
    assert_eq!(
        transaction::update_template_hash(&rebound_latest_update)?,
        original_latest_update_hash
    );
    assert!(
        rebound_latest_update.lock_time.to_consensus_u32() > state_one.latest_state.state_locktime
    );
    assert!(transaction::update_can_satisfy_state_gate(
        &rebound_latest_update,
        absolute::LockTime::from_consensus(state_one.latest_state.state_locktime),
    )?);

    let latest_update_anchor = state_three
        .latest_state
        .anchors
        .iter()
        .find(|anchor| anchor.tx_role == Bip448RecoveryTemplateRole::FundingUpdate)
        .context("state-3 update is missing its FundingUpdate anchor metadata")?;
    let rebound_update_package = build_anchor_cpfp_package(
        &rebound_latest_update,
        old_update_output.value,
        latest_update_anchor.output_index,
        &[fee_inputs[1].clone()],
        change_script.clone(),
        PACKAGE_FEERATE_SAT_PER_VBYTE,
    )?;
    submit_package_success(&rebound_update_package)?;
    let rebound_update_txid = rebound_update_package.parent_tx.txid();
    let rebound_update_child_txid = rebound_update_package.cpfp_child_tx.txid();
    common::bitcoin_core::assert_in_mempool(&rebound_update_txid)?;
    common::bitcoin_core::assert_in_mempool(&rebound_update_child_txid)?;
    common::bitcoin_core::mine_block()?;
    common::bitcoin_core::assert_confirmed(&rebound_update_txid)?;
    common::bitcoin_core::assert_confirmed(&rebound_update_child_txid)?;

    let rebound_update_outpoint = OutPoint {
        txid: rebound_update_txid,
        vout: 0,
    };
    let rebound_update_output = &rebound_update_package.parent_tx.output[0];
    let original_latest_settlement = tx_from_hex(&state_three.latest_state.settlement_tx)?;
    let original_settlement_witness = original_latest_settlement.input[0].witness.clone();
    let rebound_latest_settlement = transaction::rebind_settlement_tx(
        &original_latest_settlement,
        rebound_update_outpoint,
        rebound_update_output.value,
        FeePolicy::ZeroFeeEphemeralAnchor,
    )?;
    assert_eq!(
        rebound_latest_settlement.input[0].previous_output,
        rebound_update_outpoint
    );
    assert_eq!(
        rebound_latest_settlement.input[0].witness,
        original_settlement_witness
    );

    common::bitcoin_core::mine_blocks(state_three.challenge_delay as u32)?;
    let settlement_anchor = state_three
        .latest_state
        .anchors
        .iter()
        .find(|anchor| anchor.tx_role == Bip448RecoveryTemplateRole::Settlement)
        .context("state-3 settlement is missing its anchor metadata")?;
    let rebound_settlement_package = build_anchor_cpfp_package(
        &rebound_latest_settlement,
        rebound_update_output.value,
        settlement_anchor.output_index,
        &[fee_inputs[2].clone()],
        change_script,
        PACKAGE_FEERATE_SAT_PER_VBYTE,
    )?;
    submit_package_success(&rebound_settlement_package)?;
    let rebound_settlement_txid = rebound_settlement_package.parent_tx.txid();
    let rebound_settlement_child_txid = rebound_settlement_package.cpfp_child_tx.txid();
    common::bitcoin_core::assert_in_mempool(&rebound_settlement_txid)?;
    common::bitcoin_core::assert_in_mempool(&rebound_settlement_child_txid)?;
    common::bitcoin_core::mine_block()?;
    common::bitcoin_core::assert_confirmed(&rebound_settlement_txid)?;
    common::bitcoin_core::assert_confirmed(&rebound_settlement_child_txid)?;

    let settlement_output = &rebound_settlement_package.parent_tx.output[0];
    assert_eq!(
        settlement_output.script_pubkey,
        common::bitcoin_core::regtest_address(&current_recovery_address)?.script_pubkey()
    );
    common::chain::wait_for_address_outpoint(
        &client_config,
        &current_recovery_address,
        OutPoint {
            txid: rebound_settlement_txid,
            vout: 0,
        },
        settlement_output.value,
    )
    .await?;

    let lockbox_client = common::lockbox::http_client();
    let final_signature_count =
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?;
    assert_eq!(final_signature_count, accepted_signature_count);
    assert_eq!(final_signature_count, 3);
    eprintln!(
        "confirmed stale-state path: Tx0={} -> U(1)={} (CPFP {}) -> U(3)={} (CPFP {}) -> S(3)={} (CPFP {}); lockbox signatures={}",
        state_one.funding_outpoint.txid,
        old_update_txid,
        old_update_child_txid,
        rebound_update_txid,
        rebound_update_child_txid,
        rebound_settlement_txid,
        rebound_settlement_child_txid,
        final_signature_count,
    );

    Ok(())
}
