use super::support::*;
use super::*;

pub(super) async fn bip448_transfer_address_reuse_accepts_two_distinct_statechains() -> Result<()> {
    let _guard = common::test_guard();

    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;
    let lockbox_client = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox_client).await?;

    let client_config = common::prepare_test_env().await?;
    let sender =
        mercuryrustlib::wallet::create_wallet("bip448-reused-address-sender", &client_config)
            .await?;
    let receiver =
        mercuryrustlib::wallet::create_wallet("bip448-reused-address-receiver", &client_config)
            .await?;
    for wallet in [&sender, &receiver] {
        mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, wallet).await?;
    }

    let first_deposit = fund_confirmed_bip448_deposit(&client_config, &sender).await?;
    let second_deposit = fund_confirmed_bip448_deposit(&client_config, &sender).await?;
    assert_ne!(first_deposit.statechain_id, second_deposit.statechain_id);

    common::bitcoin_core::mine_blocks(client_config.confirmation_target)?;
    mercuryrustlib::coin_status::update_coins(&client_config, &sender.name).await?;
    let sender_wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &sender.name).await?;
    let first_sender_coin = sender_wallet
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some(&first_deposit.statechain_id))
        .context("sender wallet does not contain the first BIP448 deposit")?;
    let second_sender_coin = sender_wallet
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some(&second_deposit.statechain_id))
        .context("sender wallet does not contain the second BIP448 deposit")?;
    assert_eq!(first_sender_coin.status, CoinStatus::CONFIRMED);
    assert_eq!(second_sender_coin.status, CoinStatus::CONFIRMED);
    let first_sender_protocol = first_sender_coin
        .statechain_protocol
        .as_deref()
        .context("first confirmed sender coin is missing its protocol marker")?;
    let second_sender_protocol = second_sender_coin
        .statechain_protocol
        .as_deref()
        .context("second confirmed sender coin is missing its protocol marker")?;
    assert_eq!(first_sender_protocol, "bip448");
    assert_eq!(second_sender_protocol, "bip448");
    let first_sender_txid = first_sender_coin
        .utxo_txid
        .as_deref()
        .context("first confirmed sender coin is missing its funding txid")?;
    let first_sender_vout = first_sender_coin
        .utxo_vout
        .context("first confirmed sender coin is missing its funding vout")?;
    let second_sender_txid = second_sender_coin
        .utxo_txid
        .as_deref()
        .context("second confirmed sender coin is missing its funding txid")?;
    let second_sender_vout = second_sender_coin
        .utxo_vout
        .context("second confirmed sender coin is missing its funding vout")?;
    assert_ne!(
        (first_sender_txid, first_sender_vout),
        (second_sender_txid, second_sender_vout)
    );

    let recipient_address =
        mercuryrustlib::transfer_receiver::new_transfer_address(&client_config, &receiver.name)
            .await?;
    let (_, _, recipient_auth_pubkey) = mercurylib::decode_transfer_address(&recipient_address)?;
    let recipient_auth_pubkey = recipient_auth_pubkey.to_string();

    mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender(
        &client_config,
        &recipient_address,
        &sender.name,
        &first_deposit.statechain_id,
        None,
    )
    .await?;
    let first_receive =
        mercuryrustlib::transfer_receiver::execute(&client_config, &receiver.name).await?;
    assert!(!first_receive.is_there_batch_locked);
    assert_eq!(
        first_receive.received_statechain_ids,
        vec![first_deposit.statechain_id.clone()]
    );

    let receiver_after_first =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &receiver.name).await?;
    let first_persisted_receiver_coin = receiver_after_first
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some(&first_deposit.statechain_id))
        .context("first accepted statechain was not persisted before address reuse")?;
    assert_eq!(first_persisted_receiver_coin.status, CoinStatus::CONFIRMED);
    assert_eq!(
        first_persisted_receiver_coin.auth_pubkey,
        recipient_auth_pubkey
    );
    assert_eq!(
        receiver_after_first
            .coins
            .iter()
            .filter(|coin| coin.auth_pubkey == recipient_auth_pubkey)
            .count(),
        1
    );
    assert!(!receiver_after_first.coins.iter().any(|coin| {
        coin.auth_pubkey == recipient_auth_pubkey && coin.status == CoinStatus::INITIALISED
    }));

    mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender(
        &client_config,
        &recipient_address,
        &sender.name,
        &second_deposit.statechain_id,
        None,
    )
    .await?;
    let second_receive =
        mercuryrustlib::transfer_receiver::execute(&client_config, &receiver.name).await?;
    assert!(!second_receive.is_there_batch_locked);
    assert_eq!(
        second_receive.received_statechain_ids,
        vec![second_deposit.statechain_id.clone()]
    );

    let receiver_wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &receiver.name).await?;
    let received_coin_count = receiver_wallet
        .coins
        .iter()
        .filter(|coin| {
            coin.statechain_id.as_deref() == Some(&first_deposit.statechain_id)
                || coin.statechain_id.as_deref() == Some(&second_deposit.statechain_id)
        })
        .count();
    assert_eq!(received_coin_count, 2);
    let first_receiver_coin = receiver_wallet
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some(&first_deposit.statechain_id))
        .context("receiver wallet does not contain the first accepted statechain")?;
    let second_receiver_coin = receiver_wallet
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some(&second_deposit.statechain_id))
        .context("receiver wallet does not contain the second accepted statechain")?;
    assert_ne!(first_receiver_coin.status, CoinStatus::INITIALISED);
    assert_ne!(second_receiver_coin.status, CoinStatus::INITIALISED);
    assert_eq!(first_receiver_coin.status, CoinStatus::CONFIRMED);
    assert_eq!(second_receiver_coin.status, CoinStatus::CONFIRMED);
    let first_receiver_protocol = first_receiver_coin
        .statechain_protocol
        .as_deref()
        .context("first accepted receiver coin is missing its protocol marker")?;
    let second_receiver_protocol = second_receiver_coin
        .statechain_protocol
        .as_deref()
        .context("second accepted receiver coin is missing its protocol marker")?;
    assert_eq!(first_receiver_protocol, "bip448");
    assert_eq!(second_receiver_protocol, "bip448");

    let first_record = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &client_config.pool,
        &receiver.name,
        &first_deposit.statechain_id,
    )
    .await?;
    let second_record = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &client_config.pool,
        &receiver.name,
        &second_deposit.statechain_id,
    )
    .await?;
    for record in [&first_record, &second_record] {
        assert_eq!(record.latest_state_number, 2);
        assert_eq!(record.latest_state.state_number, 2);
    }

    assert_eq!(first_receiver_coin.index, second_receiver_coin.index);
    assert_eq!(
        first_receiver_coin.user_privkey,
        second_receiver_coin.user_privkey
    );
    assert_eq!(
        first_receiver_coin.user_pubkey,
        second_receiver_coin.user_pubkey
    );
    assert_eq!(
        first_receiver_coin.auth_privkey,
        second_receiver_coin.auth_privkey
    );
    assert_eq!(
        first_receiver_coin.auth_pubkey,
        second_receiver_coin.auth_pubkey
    );
    assert_eq!(
        first_receiver_coin.derivation_path,
        second_receiver_coin.derivation_path
    );
    assert_eq!(
        first_receiver_coin.fingerprint,
        second_receiver_coin.fingerprint
    );
    assert_eq!(first_receiver_coin.address, second_receiver_coin.address);
    assert_eq!(
        first_receiver_coin.backup_address,
        second_receiver_coin.backup_address
    );

    let first_receiver_statechain_id = first_receiver_coin
        .statechain_id
        .as_deref()
        .context("first accepted receiver coin is missing its statechain ID")?;
    let second_receiver_statechain_id = second_receiver_coin
        .statechain_id
        .as_deref()
        .context("second accepted receiver coin is missing its statechain ID")?;
    assert_eq!(first_receiver_statechain_id, first_deposit.statechain_id);
    assert_eq!(second_receiver_statechain_id, second_deposit.statechain_id);
    assert_ne!(first_receiver_statechain_id, second_receiver_statechain_id);

    let first_receiver_server_pubkey = first_receiver_coin
        .server_pubkey
        .as_deref()
        .context("first accepted receiver coin is missing its server public key")?;
    let second_receiver_server_pubkey = second_receiver_coin
        .server_pubkey
        .as_deref()
        .context("second accepted receiver coin is missing its server public key")?;
    assert_ne!(first_receiver_server_pubkey, second_receiver_server_pubkey);

    let first_receiver_aggregated_pubkey = first_receiver_coin
        .aggregated_pubkey
        .as_deref()
        .context("first accepted receiver coin is missing its aggregate public key")?;
    let second_receiver_aggregated_pubkey = second_receiver_coin
        .aggregated_pubkey
        .as_deref()
        .context("second accepted receiver coin is missing its aggregate public key")?;
    assert_ne!(
        first_receiver_aggregated_pubkey,
        second_receiver_aggregated_pubkey
    );

    let first_receiver_aggregated_address = first_receiver_coin
        .aggregated_address
        .as_deref()
        .context("first accepted receiver coin is missing its aggregate address")?;
    let second_receiver_aggregated_address = second_receiver_coin
        .aggregated_address
        .as_deref()
        .context("second accepted receiver coin is missing its aggregate address")?;
    assert_ne!(
        first_receiver_aggregated_address,
        second_receiver_aggregated_address
    );

    assert_ne!(
        (
            &first_record.funding_outpoint.txid,
            first_record.funding_outpoint.vout,
        ),
        (
            &second_record.funding_outpoint.txid,
            second_record.funding_outpoint.vout,
        )
    );
    let expected_funding_value_sats = u64::from(FUNDING_AMOUNT_SATS);
    assert_eq!(
        first_record.funding_outpoint.value_sats,
        expected_funding_value_sats
    );
    assert_eq!(
        second_record.funding_outpoint.value_sats,
        expected_funding_value_sats
    );

    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &first_deposit.statechain_id).await?,
        2
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &second_deposit.statechain_id)
            .await?,
        2
    );

    assert_eq!(receiver_wallet.coins.len(), 2);
    assert_eq!(
        receiver_wallet
            .coins
            .iter()
            .filter(|coin| coin.auth_pubkey == recipient_auth_pubkey)
            .count(),
        2
    );

    Ok(())
}

pub(super) async fn bip448_one_hop_transfer_accepts_and_recovers_state_two() -> Result<()> {
    let _guard = common::test_guard();

    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;
    let lockbox_client = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox_client).await?;

    let client_config = common::prepare_test_env().await?;
    let sender =
        mercuryrustlib::wallet::create_wallet("bip448-one-hop-sender", &client_config).await?;
    let receiver =
        mercuryrustlib::wallet::create_wallet("bip448-one-hop-receiver", &client_config).await?;
    for wallet in [&sender, &receiver] {
        mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, wallet).await?;
    }

    let deposit = create_confirmed_bip448_deposit(&client_config, &sender).await?;
    common::bitcoin_core::mine_blocks(client_config.confirmation_target)?;
    mercuryrustlib::coin_status::update_coins(&client_config, &sender.name).await?;
    let state_one = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &client_config.pool,
        &sender.name,
        &deposit.statechain_id,
    )
    .await?;
    assert_eq!(state_one.latest_state_number, 1);
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
        1
    );

    let recipient_address =
        mercuryrustlib::transfer_receiver::new_transfer_address(&client_config, &receiver.name)
            .await?;
    mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender(
        &client_config,
        &recipient_address,
        &sender.name,
        &deposit.statechain_id,
        None,
    )
    .await?;
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
        2
    );

    let receive_result =
        mercuryrustlib::transfer_receiver::execute(&client_config, &receiver.name).await?;
    assert!(!receive_result.is_there_batch_locked);
    assert_eq!(
        receive_result.received_statechain_ids,
        vec![deposit.statechain_id.clone()]
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
        2
    );

    let state_two = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &client_config.pool,
        &receiver.name,
        &deposit.statechain_id,
    )
    .await?;
    assert_eq!(state_two.latest_state_number, 2);
    assert_eq!(state_two.latest_state.state_number, 2);
    assert_eq!(
        state_two
            .latest_state
            .signing_metadata
            .server_signature_count,
        2
    );
    let receiver_wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &receiver.name).await?;
    let received_coin = receiver_wallet
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some(&deposit.statechain_id))
        .context("receiver wallet does not contain the accepted BIP448 coin")?;
    assert_eq!(received_coin.status, CoinStatus::CONFIRMED);
    assert_eq!(received_coin.statechain_protocol.as_deref(), Some("bip448"));
    let receiver_backup_address = received_coin.backup_address.clone();

    let fee_inputs = confirmed_p2a_fee_inputs(2)?;
    let change_address = common::bitcoin_core::getnewaddress()?;
    let update = mercuryrustlib::bip448_recovery::submit_latest_state_recovery_package(
        &client_config,
        &receiver.name,
        &deposit.statechain_id,
        Bip448RecoveryTemplateRole::FundingUpdate,
        &fee_inputs[..1],
        &change_address,
        Some(PACKAGE_FEERATE_SAT_PER_VBYTE),
    )
    .await?;
    assert_eq!(update.role, "funding_update");
    let update_txid = Txid::from_str(&update.parent_txid)?;
    let update_child_txid = Txid::from_str(&update.cpfp_child_txid)?;
    common::bitcoin_core::assert_in_mempool(&update_txid)?;
    common::bitcoin_core::assert_in_mempool(&update_child_txid)?;
    common::bitcoin_core::mine_block()?;
    common::bitcoin_core::assert_confirmed(&update_txid)?;
    common::bitcoin_core::assert_confirmed(&update_child_txid)?;

    common::bitcoin_core::mine_blocks(state_two.challenge_delay as u32)?;

    let settlement = mercuryrustlib::bip448_recovery::submit_latest_state_recovery_package(
        &client_config,
        &receiver.name,
        &deposit.statechain_id,
        Bip448RecoveryTemplateRole::Settlement,
        &fee_inputs[1..],
        &change_address,
        Some(PACKAGE_FEERATE_SAT_PER_VBYTE),
    )
    .await?;
    assert_eq!(settlement.role, "settlement");
    let settlement_txid = Txid::from_str(&settlement.parent_txid)?;
    let settlement_child_txid = Txid::from_str(&settlement.cpfp_child_txid)?;
    common::bitcoin_core::assert_in_mempool(&settlement_txid)?;
    common::bitcoin_core::assert_in_mempool(&settlement_child_txid)?;
    common::bitcoin_core::mine_block()?;
    common::bitcoin_core::assert_confirmed(&settlement_txid)?;
    common::bitcoin_core::assert_confirmed(&settlement_child_txid)?;

    common::chain::wait_for_address_outpoint(
        &client_config,
        &receiver_backup_address,
        OutPoint {
            txid: settlement_txid,
            vout: 0,
        },
        u64::from(FUNDING_AMOUNT_SATS),
    )
    .await?;

    Ok(())
}

pub(super) async fn bip448_two_hop_transfer_accepts_and_recovers_state_three() -> Result<()> {
    let _guard = common::test_guard();

    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;
    let lockbox_client = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox_client).await?;

    let client_config = common::prepare_test_env().await?;
    let sender =
        mercuryrustlib::wallet::create_wallet("bip448-two-hop-sender", &client_config).await?;
    let middle =
        mercuryrustlib::wallet::create_wallet("bip448-two-hop-middle", &client_config).await?;
    let receiver =
        mercuryrustlib::wallet::create_wallet("bip448-two-hop-receiver", &client_config).await?;
    for wallet in [&sender, &middle, &receiver] {
        mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, wallet).await?;
    }

    let deposit = create_confirmed_bip448_deposit(&client_config, &sender).await?;
    common::bitcoin_core::mine_blocks(client_config.confirmation_target)?;
    mercuryrustlib::coin_status::update_coins(&client_config, &sender.name).await?;
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
        1
    );

    let state_two = transfer_and_accept_bip448(
        &client_config,
        &sender.name,
        &middle.name,
        &deposit.statechain_id,
    )
    .await?;
    assert_eq!(state_two.latest_state_number, 2);
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
        2
    );

    let state_three = transfer_and_accept_bip448(
        &client_config,
        &middle.name,
        &receiver.name,
        &deposit.statechain_id,
    )
    .await?;
    assert_eq!(state_three.latest_state_number, 3);
    assert_eq!(state_three.latest_state.state_number, 3);
    assert_eq!(
        state_three
            .latest_state
            .signing_metadata
            .server_signature_count,
        3
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
        3
    );

    let receiver_wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &receiver.name).await?;
    let received_coin = receiver_wallet
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some(&deposit.statechain_id))
        .context("final receiver does not contain the accepted state-3 BIP448 coin")?;
    assert_eq!(received_coin.status, CoinStatus::CONFIRMED);
    let receiver_backup_address = received_coin.backup_address.clone();

    let fee_inputs = confirmed_p2a_fee_inputs(2)?;
    let change_address = common::bitcoin_core::getnewaddress()?;
    let update = mercuryrustlib::bip448_recovery::submit_latest_state_recovery_package(
        &client_config,
        &receiver.name,
        &deposit.statechain_id,
        Bip448RecoveryTemplateRole::FundingUpdate,
        &fee_inputs[..1],
        &change_address,
        Some(PACKAGE_FEERATE_SAT_PER_VBYTE),
    )
    .await?;
    let update_txid = Txid::from_str(&update.parent_txid)?;
    let update_child_txid = Txid::from_str(&update.cpfp_child_txid)?;
    common::bitcoin_core::assert_in_mempool(&update_txid)?;
    common::bitcoin_core::assert_in_mempool(&update_child_txid)?;
    common::bitcoin_core::mine_block()?;
    common::bitcoin_core::assert_confirmed(&update_txid)?;
    common::bitcoin_core::assert_confirmed(&update_child_txid)?;

    common::bitcoin_core::mine_blocks(state_three.challenge_delay as u32)?;

    let settlement = mercuryrustlib::bip448_recovery::submit_latest_state_recovery_package(
        &client_config,
        &receiver.name,
        &deposit.statechain_id,
        Bip448RecoveryTemplateRole::Settlement,
        &fee_inputs[1..],
        &change_address,
        Some(PACKAGE_FEERATE_SAT_PER_VBYTE),
    )
    .await?;
    let settlement_txid = Txid::from_str(&settlement.parent_txid)?;
    let settlement_child_txid = Txid::from_str(&settlement.cpfp_child_txid)?;
    common::bitcoin_core::assert_in_mempool(&settlement_txid)?;
    common::bitcoin_core::assert_in_mempool(&settlement_child_txid)?;
    common::bitcoin_core::mine_block()?;
    common::bitcoin_core::assert_confirmed(&settlement_txid)?;
    common::bitcoin_core::assert_confirmed(&settlement_child_txid)?;

    common::chain::wait_for_address_outpoint(
        &client_config,
        &receiver_backup_address,
        OutPoint {
            txid: settlement_txid,
            vout: 0,
        },
        u64::from(FUNDING_AMOUNT_SATS),
    )
    .await?;

    Ok(())
}

pub(super) async fn bip448_ten_hop_transfer_advances_to_state_eleven() -> Result<()> {
    const TRANSFER_COUNT: usize = 10;

    let _guard = common::test_guard();

    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;
    let lockbox_client = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox_client).await?;

    let client_config = common::prepare_test_env().await?;
    let mut wallets = Vec::with_capacity(TRANSFER_COUNT + 1);
    for index in 0..=TRANSFER_COUNT {
        let wallet = mercuryrustlib::wallet::create_wallet(
            &format!("bip448-ten-hop-{index:02}"),
            &client_config,
        )
        .await?;
        mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, &wallet).await?;
        wallets.push(wallet);
    }

    let deposit = create_confirmed_bip448_deposit(&client_config, &wallets[0]).await?;
    common::bitcoin_core::mine_blocks(client_config.confirmation_target)?;
    mercuryrustlib::coin_status::update_coins(&client_config, &wallets[0].name).await?;

    for hop in 0..TRANSFER_COUNT {
        let expected_state_number = u32::try_from(hop + 2)?;
        let state = transfer_and_accept_bip448(
            &client_config,
            &wallets[hop].name,
            &wallets[hop + 1].name,
            &deposit.statechain_id,
        )
        .await?;

        for _ in 0..2 {
            mercuryrustlib::coin_status::update_coins(&client_config, &wallets[hop].name).await?;
            let previous_sender =
                mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallets[hop].name)
                    .await?;
            let previous_sender_coin = previous_sender
                .coins
                .iter()
                .find(|coin| coin.statechain_id.as_deref() == Some(&deposit.statechain_id))
                .context("previous sender does not contain the transferred BIP448 coin")?;
            assert_eq!(previous_sender_coin.status, CoinStatus::TRANSFERRED);
        }

        assert_eq!(state.latest_state_number, expected_state_number);
        assert_eq!(state.latest_state.state_number, expected_state_number);
        assert_eq!(
            state.latest_state.signing_metadata.server_signature_count,
            u64::from(expected_state_number)
        );
        assert_eq!(
            common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
            expected_state_number
        );
    }

    for previous_wallet in &wallets[..TRANSFER_COUNT] {
        let previous_wallet =
            mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &previous_wallet.name)
                .await?;
        let previous_coin = previous_wallet
            .coins
            .iter()
            .find(|coin| coin.statechain_id.as_deref() == Some(&deposit.statechain_id))
            .context("previous wallet does not contain the transferred BIP448 coin")?;
        assert_eq!(previous_coin.status, CoinStatus::TRANSFERRED);
    }

    let final_wallet = mercuryrustlib::sqlite_manager::get_wallet(
        &client_config.pool,
        &wallets[TRANSFER_COUNT].name,
    )
    .await?;
    let final_coin = final_wallet
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some(&deposit.statechain_id))
        .context("final receiver does not contain the accepted state-11 BIP448 coin")?;
    assert_eq!(final_coin.status, CoinStatus::CONFIRMED);
    let final_state = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &client_config.pool,
        &wallets[TRANSFER_COUNT].name,
        &deposit.statechain_id,
    )
    .await?;
    assert_eq!(final_state.latest_state_number, 11);
    assert_eq!(final_state.latest_state.state_number, 11);
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
        11
    );

    Ok(())
}

pub(super) async fn bip448_same_wallet_second_hop_advances_to_state_three() -> Result<()> {
    let _guard = common::test_guard();

    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;
    let lockbox_client = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox_client).await?;

    let client_config = common::prepare_test_env().await?;
    let sender =
        mercuryrustlib::wallet::create_wallet("bip448-state-three-sender", &client_config).await?;
    let holder =
        mercuryrustlib::wallet::create_wallet("bip448-state-three-same-wallet", &client_config)
            .await?;
    for wallet in [&sender, &holder] {
        mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, wallet).await?;
    }

    let deposit = create_confirmed_bip448_deposit(&client_config, &sender).await?;
    common::bitcoin_core::mine_blocks(client_config.confirmation_target)?;
    mercuryrustlib::coin_status::update_coins(&client_config, &sender.name).await?;
    let state_two = transfer_and_accept_bip448(
        &client_config,
        &sender.name,
        &holder.name,
        &deposit.statechain_id,
    )
    .await?;
    assert_eq!(state_two.latest_state_number, 2);

    let state_three = transfer_and_accept_bip448(
        &client_config,
        &holder.name,
        &holder.name,
        &deposit.statechain_id,
    )
    .await?;
    assert_eq!(state_three.latest_state_number, 3);
    assert_eq!(state_three.latest_state.state_number, 3);
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
        3
    );

    let wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &holder.name).await?;
    assert!(wallet.coins.iter().any(|coin| {
        coin.statechain_id.as_deref() == Some(deposit.statechain_id.as_str())
            && coin.status == CoinStatus::CONFIRMED
    }));
    assert!(wallet.coins.iter().any(|coin| {
        coin.statechain_id.as_deref() == Some(deposit.statechain_id.as_str())
            && coin.status == CoinStatus::IN_TRANSFER
    }));

    Ok(())
}

pub(super) async fn bip448_same_wallet_transfer_advances_the_accepted_record_to_state_two(
) -> Result<()> {
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
        mercuryrustlib::wallet::create_wallet("bip448-same-wallet", &client_config).await?;
    mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, &wallet).await?;

    let deposit = create_confirmed_bip448_deposit(&client_config, &wallet).await?;
    common::bitcoin_core::mine_blocks(client_config.confirmation_target)?;
    mercuryrustlib::coin_status::update_coins(&client_config, &wallet.name).await?;
    let recipient_address =
        mercuryrustlib::transfer_receiver::new_transfer_address(&client_config, &wallet.name)
            .await?;
    let (_, recipient_user_pubkey, recipient_auth_pubkey) =
        mercurylib::decode_transfer_address(&recipient_address)?;

    mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender(
        &client_config,
        &recipient_address,
        &wallet.name,
        &deposit.statechain_id,
        None,
    )
    .await?;
    let receive_result =
        mercuryrustlib::transfer_receiver::execute(&client_config, &wallet.name).await?;

    assert_eq!(
        receive_result.received_statechain_ids,
        vec![deposit.statechain_id.clone()]
    );
    let state_two = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &client_config.pool,
        &wallet.name,
        &deposit.statechain_id,
    )
    .await?;
    assert_eq!(state_two.latest_state_number, 2);
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
        2
    );

    let wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet.name).await?;
    let received = wallet
        .coins
        .iter()
        .find(|coin| {
            coin.statechain_id.as_deref() == Some(deposit.statechain_id.as_str())
                && coin.user_pubkey == recipient_user_pubkey.to_string()
                && coin.auth_pubkey == recipient_auth_pubkey.to_string()
        })
        .context("same-wallet recipient coin was not accepted")?;
    assert_eq!(received.status, CoinStatus::CONFIRMED);
    assert_eq!(received.statechain_protocol.as_deref(), Some("bip448"));
    assert!(wallet.coins.iter().any(|coin| {
        coin.statechain_id.as_deref() == Some(deposit.statechain_id.as_str())
            && coin.status == CoinStatus::IN_TRANSFER
    }));

    Ok(())
}
