use super::super::{
    accepted::upsert_bip448_statechain_record,
    transfer_intents::{insert_transfer_intent_on, intent_is_directly_supersedable},
};
use super::support::*;

fn exact_transfer_message(
    record: &Bip448StatechainRecord,
    latest_state: Bip448LatestState,
    receiver_user_public_key: &str,
    history: Vec<Bip448StateHistoryEntry>,
) -> Bip448TransferMsg {
    let mut message = sample_bip448_transfer_msg();
    message.statechain_id = record.statechain_id.clone();
    message.receiver_user_public_key = receiver_user_public_key.to_owned();
    message.aggregate_pubkey = record.aggregate_pubkey.clone();
    message.funding_outpoint = record.funding_outpoint.clone();
    message.latest_state_number = latest_state.state_number;
    message.challenge_delay = record.challenge_delay;
    message.amount_sats = record.amount_sats;
    message.network = record.network.clone();
    message.value_schedule = latest_state.value_schedule.clone();
    message.server_signature_count = u64::from(latest_state.state_number);
    message.latest_state = latest_state;
    message.state_history = history;
    message
}

fn transfer_intent_for_phase_pair(
    intent_id_byte: &str,
    phase: Bip448TransferIntentPhase,
    signing_phase: Bip448TransferStateSigningPhase,
    reuse_signed_state: bool,
) -> Result<Bip448TransferIntent> {
    let mut intent = sample_transfer_intent(intent_id_byte);
    intent.activity_status = Bip448TransferIntentActivityStatus::Superseded;
    intent.phase = phase;
    intent.server_x1 = (!matches!(
        phase,
        Bip448TransferIntentPhase::Prepared | Bip448TransferIntentPhase::SenderArmed
    ))
    .then(|| "01".repeat(32));
    intent.state_signing_phase = signing_phase;
    if reuse_signed_state {
        intent.reuse_pending = true;
        intent.reuse_signed_state = true;
        intent.prior_pending_signing_id = Some("31".repeat(32));
        intent.planned_state_number = intent.expected_signature_count;
    }
    match signing_phase {
        Bip448TransferStateSigningPhase::NotStarted => {}
        Bip448TransferStateSigningPhase::FirstArmed
        | Bip448TransferStateSigningPhase::NonceStored
        | Bip448TransferStateSigningPhase::SecondArmed => {
            intent.current_pending_signing_id = Some("32".repeat(32));
        }
        Bip448TransferStateSigningPhase::Signed => {
            intent.current_pending_signing_id = Some("32".repeat(32));
            intent.server_partial_sig = (!reuse_signed_state).then(|| "33".repeat(32));
            intent.update_signature = Some("34".repeat(64));
        }
    }
    if matches!(
        phase,
        Bip448TransferIntentPhase::SenderFinished | Bip448TransferIntentPhase::ReceiverAccepted
    ) {
        let generated = sample_wallet().get_new_coin()?;
        intent.intent_kind = Bip448TransferIntentKind::Cancellation;
        intent.recipient_address = generated.address.clone();
        intent.receiver_user_pubkey = generated.user_pubkey.clone();
        intent.recipient_auth_pubkey = generated.auth_pubkey.clone();
        intent.generated_coin_user_pubkey = Some(generated.user_pubkey);
        intent.generated_coin_auth_pubkey = Some(generated.auth_pubkey);
        intent.generated_coin_address = Some(generated.address);
    }
    Ok(intent)
}

fn sender_test_config(pool: Pool<Sqlite>) -> Result<ClientConfig> {
    let url = "http://127.0.0.1:1";
    Ok(ClientConfig {
        statechain_entity: url.into(),
        chain_backend: "core".into(),
        chain_client: ChainClient::new(CoreRpcConfig {
            url: url.into(),
            auth: CoreRpcAuth::None,
        })?,
        chain_endpoint: Some(url.into()),
        core_rpc_auth: Some("none".into()),
        core_rpc_user: None,
        core_rpc_password: None,
        core_rpc_cookie_file: None,
        network: Network::Regtest,
        fee_rate_tolerance: 0.0,
        confirmation_target: 1,
        pool,
        tor_proxy: None,
        max_fee_rate: 10.0,
    })
}

async fn accepted_local_outgoing_fixture() -> Result<(
    Pool<Sqlite>,
    Bip448StatechainRecord,
    String,
    Bip448TransferMsg,
)> {
    let pool = migrated_pool().await?;
    let (mut record, _, _) = accepted_binding_fixture(&pool).await?;
    let mut wallet = get_wallet(&pool, "wallet").await?;
    let mut local_coin = wallet.get_new_coin()?;
    local_coin.statechain_protocol = Some("bip448".into());
    local_coin.statechain_id = Some("statechain".into());
    local_coin.status = CoinStatus::CONFIRMED;
    let recipient_auth = local_coin.auth_pubkey.clone();
    let receiver_user = local_coin.user_pubkey.clone();
    let receiver = secp256k1::PublicKey::from_str(&receiver_user)?;
    let state_two = real_fixture_state_for_owner(
        &wallet,
        &record,
        receiver.x_only_public_key().0,
        2,
        record.latest_state.state_locktime + 1,
    )?;
    wallet.coins.push(local_coin);
    update_wallet(&pool, &wallet).await?;

    record.latest_state_number = 2;
    record.latest_state = state_two.clone();
    upsert_bip448_statechain_record(&pool, &record).await?;
    let entry_two = history_entry(&state_two, receiver.x_only_public_key().0);
    insert_bip448_state_history_entry(&pool, "wallet", "statechain", &entry_two).await?;
    let history = get_bip448_state_history(&pool, "wallet", "statechain").await?;
    let message = exact_transfer_message(&record, state_two, &receiver_user, history);
    insert_or_update_bip448_transfer_msg(&pool, "wallet", &recipient_auth, &message).await?;
    Ok((pool, record, recipient_auth, message))
}

async fn assert_corrupt_transfer_lineage_blocks(
    intents: &[Bip448TransferIntent],
    remove_active_index: bool,
) -> Result<()> {
    let pool = migrated_pool().await?;
    let (_, owner, script) = accepted_binding_fixture(&pool).await?;
    let duplicate = reconcile_bip448_funding_bindings(
        &pool,
        "wallet",
        "statechain",
        &owner.to_string(),
        1,
        &[
            sample_binding_observation("34", 0, 100_000, &script),
            sample_binding_observation("11", 1, 70_000, &script),
        ],
    )
    .await?
    .into_iter()
    .find(|row| row.binding_index == 1)
    .ok_or_else(|| anyhow!("duplicate fixture binding is missing"))?;
    if remove_active_index {
        sqlx::query("DROP INDEX bip448_one_active_transfer_intent")
            .execute(&pool)
            .await?;
    }
    let mut connection = pool.acquire().await?;
    for intent in intents {
        insert_transfer_intent_on(&mut connection, intent).await?;
    }
    drop(connection);

    assert!(
        get_active_bip448_transfer_intent(&pool, "wallet", "statechain")
            .await
            .is_err(),
        "corrupt intent lineage must fail the active-intent query"
    );
    assert!(matches!(
        classify_bip448_close_gate(&pool, "wallet", "statechain").await?,
        Bip448CloseGate::Blocked { reasons }
            if matches!(reasons.as_slice(), [Bip448CloseBlockReason::InvalidTransferIntentLineage { .. }])
    ));
    assert!(
        insert_bip448_withdrawal_attempt_if_absent(&pool, &sample_duplicate_attempt(&duplicate))
            .await
            .is_err(),
        "corrupt intent lineage must block attempt insertion"
    );
    assert!(
        list_bip448_withdrawal_attempts(&pool, "wallet", "statechain")
            .await?
            .is_empty()
    );
    Ok(())
}

async fn assert_sender_ineligible(config: &ClientConfig) {
    let error = transfer_bip448_sender(config, "unused", "wallet", "statechain", None)
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "only transfer of a CONFIRMED BIP448 coin at its accepted latest state is supported"
    );
}

#[tokio::test]
async fn bip448_sender_exercises_record_coin_state_and_status_guards() -> Result<()> {
    let config = sender_test_config(migrated_pool().await?)?;
    let mut wallet = sample_wallet();
    insert_wallet(&config.pool, &wallet).await?;
    assert_sender_ineligible(&config).await;
    upsert_bip448_statechain_record(&config.pool, &sample_bip448_record(1)).await?;
    assert_sender_ineligible(&config).await;
    let mut coin = wallet.get_new_coin()?;
    coin.statechain_protocol =
        Some(mercurylib::bip448_statechain::deposit::BIP448_COIN_PROTOCOL.into());
    coin.statechain_id = Some("statechain".into());
    coin.status = CoinStatus::TRANSFERRED;
    wallet.coins.push(coin);
    update_wallet(&config.pool, &wallet).await?;
    assert_sender_ineligible(&config).await;
    wallet.coins[0].status = CoinStatus::CONFIRMED;
    let config = sender_test_config(migrated_pool().await?)?;
    insert_wallet(&config.pool, &wallet).await?;
    upsert_bip448_statechain_record(&config.pool, &sample_bip448_record(0)).await?;
    assert_sender_ineligible(&config).await;
    Ok(())
}

#[tokio::test]
async fn bip448_transfer_outer_and_signing_phase_cross_product_is_exact() -> Result<()> {
    let pool = migrated_pool().await?;
    let outer_phases = [
        Bip448TransferIntentPhase::Prepared,
        Bip448TransferIntentPhase::SenderArmed,
        Bip448TransferIntentPhase::X1Stored,
        Bip448TransferIntentPhase::SenderFinished,
        Bip448TransferIntentPhase::ReceiverAccepted,
    ];
    let signing_phases = [
        Bip448TransferStateSigningPhase::NotStarted,
        Bip448TransferStateSigningPhase::FirstArmed,
        Bip448TransferStateSigningPhase::NonceStored,
        Bip448TransferStateSigningPhase::SecondArmed,
        Bip448TransferStateSigningPhase::Signed,
    ];
    let mut case_number = 1u8;
    for outer in outer_phases {
        for signing in signing_phases {
            let legal = matches!(
                (outer, signing),
                (
                    Bip448TransferIntentPhase::Prepared | Bip448TransferIntentPhase::SenderArmed,
                    Bip448TransferStateSigningPhase::NotStarted,
                ) | (
                    Bip448TransferIntentPhase::X1Stored,
                    Bip448TransferStateSigningPhase::NotStarted
                        | Bip448TransferStateSigningPhase::FirstArmed
                        | Bip448TransferStateSigningPhase::NonceStored
                        | Bip448TransferStateSigningPhase::SecondArmed
                        | Bip448TransferStateSigningPhase::Signed,
                ) | (
                    Bip448TransferIntentPhase::SenderFinished
                        | Bip448TransferIntentPhase::ReceiverAccepted,
                    Bip448TransferStateSigningPhase::Signed,
                )
            );
            let id = format!("{case_number:02x}");
            case_number = case_number
                .checked_add(1)
                .ok_or_else(|| anyhow!("BIP448 transfer matrix case number overflow"))?;
            let intent = transfer_intent_for_phase_pair(&id, outer, signing, false)?;
            assert_eq!(
                bip448_funding::validate_transfer_intent(&intent).is_ok(),
                legal,
                "domain matrix mismatch for {outer:?} × {signing:?}"
            );
            let mut connection = pool.acquire().await?;
            let inserted = insert_transfer_intent_on(&mut connection, &intent).await;
            assert_eq!(
                inserted.is_ok(),
                legal,
                "SQL matrix mismatch for {outer:?} × {signing:?}"
            );
        }
    }

    let mut invalid_reuse = transfer_intent_for_phase_pair(
        "e1",
        Bip448TransferIntentPhase::X1Stored,
        Bip448TransferStateSigningPhase::FirstArmed,
        true,
    )?;
    let mut signed_without_partial = transfer_intent_for_phase_pair(
        "e2",
        Bip448TransferIntentPhase::X1Stored,
        Bip448TransferStateSigningPhase::Signed,
        false,
    )?;
    signed_without_partial.server_partial_sig = None;
    let mut reused_with_partial = transfer_intent_for_phase_pair(
        "e3",
        Bip448TransferIntentPhase::X1Stored,
        Bip448TransferStateSigningPhase::Signed,
        true,
    )?;
    reused_with_partial.server_partial_sig = Some("35".repeat(32));
    let mut unstarted_with_artifact = transfer_intent_for_phase_pair(
        "e4",
        Bip448TransferIntentPhase::Prepared,
        Bip448TransferStateSigningPhase::NotStarted,
        false,
    )?;
    unstarted_with_artifact.current_pending_signing_id = Some("36".repeat(32));
    let mut active_with_result = transfer_intent_for_phase_pair(
        "e5",
        Bip448TransferIntentPhase::X1Stored,
        Bip448TransferStateSigningPhase::NonceStored,
        false,
    )?;
    active_with_result.update_signature = Some("37".repeat(64));
    for invalid in [
        &mut invalid_reuse,
        &mut signed_without_partial,
        &mut reused_with_partial,
        &mut unstarted_with_artifact,
        &mut active_with_result,
    ] {
        assert!(bip448_funding::validate_transfer_intent(invalid).is_err());
        let mut connection = pool.acquire().await?;
        assert!(insert_transfer_intent_on(&mut connection, invalid)
            .await
            .is_err());
    }

    let corrupt_pool = migrated_pool().await?;
    let corrupt = transfer_intent_for_phase_pair(
        "f1",
        Bip448TransferIntentPhase::Prepared,
        Bip448TransferStateSigningPhase::FirstArmed,
        false,
    )?;
    let mut connection = corrupt_pool.acquire().await?;
    sqlx::query("PRAGMA ignore_check_constraints = ON")
        .execute(&mut *connection)
        .await?;
    insert_transfer_intent_on(&mut connection, &corrupt).await?;
    sqlx::query("PRAGMA ignore_check_constraints = OFF")
        .execute(&mut *connection)
        .await?;
    drop(connection);
    assert!(
        list_bip448_transfer_intents(&corrupt_pool, "wallet", "statechain")
            .await
            .is_err()
    );
    assert!(
        reject_bip448_transfer_intent_and_reactivate_predecessor(&corrupt_pool, &corrupt,)
            .await
            .is_err()
    );
    assert!(
        reactivate_bip448_transfer_intent_predecessor_after_definitive_rejection(
            &corrupt_pool,
            &corrupt,
        )
        .await
        .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn bip448_sender_fails_before_signing_when_history_is_incomplete() -> Result<()> {
    let config = sender_test_config(migrated_pool().await?)?;
    let mut wallet = sample_wallet();
    let mut coin = wallet.get_new_coin()?;
    coin.statechain_protocol =
        Some(mercurylib::bip448_statechain::deposit::BIP448_COIN_PROTOCOL.into());
    coin.statechain_id = Some("statechain".into());
    coin.status = CoinStatus::CONFIRMED;
    wallet.coins.push(coin);
    let recipient_address = wallet.get_new_coin()?.address;
    insert_wallet(&config.pool, &wallet).await?;
    let record = sample_bip448_record(2);
    upsert_bip448_statechain_record(&config.pool, &record).await?;

    let error = transfer_bip448_sender(&config, &recipient_address, "wallet", "statechain", None)
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "BIP448 state history is incomplete for this coin"
    );
    assert!(
        get_bip448_pending_transfer_signing(&config.pool, "wallet", "statechain")
            .await?
            .is_none()
    );
    assert_eq!(
        get_bip448_statechain(&config.pool, "wallet", "statechain")
            .await?
            .latest_state
            .signing_metadata
            .server_signature_count,
        2
    );
    Ok(())
}

#[tokio::test]
async fn bip448_transfer_intent_successors_reactivation_and_stale_workers_are_guarded() -> Result<()>
{
    let pool = migrated_pool().await?;
    let (record, _, _) = accepted_binding_fixture(&pool).await?;
    let root = sample_transfer_intent("a1");
    let mut boundary = root.clone();
    boundary.phase = Bip448TransferIntentPhase::X1Stored;
    boundary.state_signing_phase = Bip448TransferStateSigningPhase::NotStarted;
    assert!(intent_is_directly_supersedable(&boundary));
    boundary.state_signing_phase = Bip448TransferStateSigningPhase::FirstArmed;
    assert!(!intent_is_directly_supersedable(&boundary));
    boundary.state_signing_phase = Bip448TransferStateSigningPhase::NonceStored;
    assert!(!intent_is_directly_supersedable(&boundary));
    boundary.state_signing_phase = Bip448TransferStateSigningPhase::SecondArmed;
    assert!(!intent_is_directly_supersedable(&boundary));
    boundary.state_signing_phase = Bip448TransferStateSigningPhase::Signed;
    assert!(intent_is_directly_supersedable(&boundary));
    let persisted = insert_bip448_transfer_intent_if_absent(&pool, &root).await?;
    assert_eq!(
        insert_bip448_transfer_intent_if_absent(&pool, &root).await?,
        persisted
    );
    let mut immutable_conflict = root.clone();
    immutable_conflict.recipient_address = "different".into();
    assert!(
        insert_bip448_transfer_intent_if_absent(&pool, &immutable_conflict)
            .await
            .is_err()
    );
    arm_bip448_transfer_sender(&pool, "wallet", "statechain", &root.intent_id).await?;
    let mut premature = sample_transfer_intent("a2");
    premature.predecessor_intent_id = Some(root.intent_id.clone());
    assert!(
        supersede_bip448_transfer_intent(&pool, &root.intent_id, &premature)
            .await
            .is_err()
    );
    let x1 = "01".repeat(32);
    store_bip448_transfer_server_x1(&pool, "wallet", "statechain", &root.intent_id, &x1).await?;
    let successor = supersede_bip448_transfer_intent(&pool, &root.intent_id, &premature).await?;
    assert_eq!(
        successor.predecessor_intent_id.as_deref(),
        Some(root.intent_id.as_str())
    );
    assert!(
        arm_bip448_transfer_sender(&pool, "wallet", "statechain", &root.intent_id)
            .await
            .is_err(),
        "a superseded predecessor worker must lose its activity CAS"
    );
    let reactivated = reject_bip448_transfer_intent_and_reactivate_predecessor(&pool, &successor)
        .await?
        .expect("direct predecessor reactivated");
    assert_eq!(reactivated.intent_id, root.intent_id);
    assert_eq!(reactivated.phase, Bip448TransferIntentPhase::X1Stored);
    assert_eq!(reactivated.server_x1.as_deref(), Some(x1.as_str()));

    let wallet = get_wallet(&pool, "wallet").await?;
    let receiver = secp256k1::PublicKey::from_str(&root.receiver_user_pubkey)?;
    let state_two = real_fixture_state_for_owner(
        &wallet,
        &record,
        receiver.x_only_public_key().0,
        2,
        record.latest_state.state_locktime + 1,
    )?;
    let pending = Bip448PendingDepositSigning {
        wallet_name: "wallet".into(),
        statechain_id: "statechain".into(),
        funding_txid: record.funding_outpoint.txid.clone(),
        funding_vout: record.funding_outpoint.vout,
        funding_value_sats: record.funding_outpoint.value_sats,
        update_template_hash: state_two.update_template_hash.clone(),
        settlement_template_hash: state_two.settlement_template_hash.clone(),
        state_locktime: state_two.state_locktime,
        signing_id: state_two.signing_metadata.signing_id.clone(),
        client_secret_nonce: "44".repeat(132),
        client_public_nonce: state_two.signing_metadata.client_public_nonce.clone(),
        blinding_factor: state_two.signing_metadata.blinding_factor.clone(),
        server_public_nonce: None,
    };
    install_bip448_transfer_target_pending_signing(&pool, &root.intent_id, &pending).await?;
    store_bip448_transfer_state_nonce(
        &pool,
        "wallet",
        "statechain",
        &root.intent_id,
        &pending.signing_id,
        &state_two.signing_metadata.server_public_nonce,
    )
    .await?;
    arm_bip448_transfer_state_sign_second(
        &pool,
        "wallet",
        "statechain",
        &root.intent_id,
        &pending.signing_id,
    )
    .await?;
    store_signed_bip448_transfer_state(
        &pool,
        "wallet",
        "statechain",
        &root.intent_id,
        &pending.signing_id,
        &"48".repeat(32),
        &state_two.signing_metadata.update_signature,
    )
    .await?;
    let active = get_active_bip448_transfer_intent(&pool, "wallet", "statechain")
        .await?
        .unwrap();
    assert_eq!(
        active.state_signing_phase,
        Bip448TransferStateSigningPhase::Signed
    );
    let mut post_sign_plan = sample_transfer_intent("a3");
    post_sign_plan.predecessor_intent_id = Some(root.intent_id.clone());
    post_sign_plan.expected_signature_count = 2;
    post_sign_plan.planned_state_number = 3;
    post_sign_plan.previous_locktime = pending.state_locktime;
    post_sign_plan.prior_pending_signing_id = Some(pending.signing_id.clone());
    post_sign_plan.clear_local_attempt = true;
    assert!(
        supersede_bip448_transfer_intent(&pool, &root.intent_id, &post_sign_plan)
            .await
            .is_err(),
        "Signed retarget must first materialize exact history and outgoing message"
    );
    let state_two_entry = history_entry(&state_two, receiver.x_only_public_key().0);
    insert_bip448_state_history_entry(&pool, "wallet", "statechain", &state_two_entry).await?;
    let complete_history = get_bip448_state_history(&pool, "wallet", "statechain").await?;
    let mut message = sample_bip448_transfer_msg();
    message.statechain_id = "statechain".into();
    message.receiver_user_public_key = root.receiver_user_pubkey.clone();
    message.aggregate_pubkey = record.aggregate_pubkey.clone();
    message.funding_outpoint = record.funding_outpoint.clone();
    message.latest_state = state_two;
    message.latest_state_number = 2;
    message.challenge_delay = record.challenge_delay;
    message.amount_sats = record.amount_sats;
    message.network = record.network.clone();
    message.value_schedule = message.latest_state.value_schedule.clone();
    message.server_signature_count = 2;
    message.state_history = complete_history;
    insert_or_update_bip448_transfer_msg(&pool, "wallet", &root.recipient_auth_pubkey, &message)
        .await?;
    post_sign_plan.prior_transfer_recipient_auth_pubkey = Some(root.recipient_auth_pubkey.clone());
    post_sign_plan.prior_transfer_msg_hash =
        Some(sha256::Hash::hash(serde_json::to_string(&message)?.as_bytes()).to_string());
    let post_sign =
        supersede_bip448_transfer_intent(&pool, &root.intent_id, &post_sign_plan).await?;
    assert_eq!(
        list_bip448_transfer_intents(&pool, "wallet", "statechain")
            .await?
            .len(),
        2,
        "the predecessor chain remains durable through successor state signing"
    );
    arm_bip448_transfer_sender(&pool, "wallet", "statechain", &post_sign.intent_id).await?;
    store_bip448_transfer_server_x1(
        &pool,
        "wallet",
        "statechain",
        &post_sign.intent_id,
        &"02".repeat(32),
    )
    .await?;
    let successor_receiver = secp256k1::PublicKey::from_str(&post_sign.receiver_user_pubkey)?;
    let state_three = real_fixture_state_for_owner(
        &wallet,
        &record,
        successor_receiver.x_only_public_key().0,
        3,
        pending.state_locktime + 1,
    )?;
    let successor_pending = Bip448PendingDepositSigning {
        wallet_name: "wallet".into(),
        statechain_id: "statechain".into(),
        funding_txid: record.funding_outpoint.txid.clone(),
        funding_vout: record.funding_outpoint.vout,
        funding_value_sats: record.funding_outpoint.value_sats,
        update_template_hash: state_three.update_template_hash.clone(),
        settlement_template_hash: state_three.settlement_template_hash.clone(),
        state_locktime: state_three.state_locktime,
        signing_id: state_three.signing_metadata.signing_id.clone(),
        client_secret_nonce: "45".repeat(132),
        client_public_nonce: state_three.signing_metadata.client_public_nonce.clone(),
        blinding_factor: state_three.signing_metadata.blinding_factor.clone(),
        server_public_nonce: None,
    };
    install_bip448_transfer_target_pending_signing(&pool, &post_sign.intent_id, &successor_pending)
        .await?;
    assert!(
        !has_bip448_transfer_msg_for_statechain(&pool, "wallet", "statechain").await?,
        "target-pending installation compare-deletes the fingerprinted predecessor message"
    );
    let mut accepted_connection = pool.acquire().await?;
    let (_, replacement_window_history) =
        accepted_record_and_history_on(&mut accepted_connection, "wallet", "statechain").await?;
    assert_eq!(
        replacement_window_history.len(),
        2,
        "the N+1 suffix remains journal-proven while the N+2 target is FirstArmed"
    );
    drop(accepted_connection);
    store_bip448_transfer_state_nonce(
        &pool,
        "wallet",
        "statechain",
        &post_sign.intent_id,
        &successor_pending.signing_id,
        &state_three.signing_metadata.server_public_nonce,
    )
    .await?;
    arm_bip448_transfer_state_sign_second(
        &pool,
        "wallet",
        "statechain",
        &post_sign.intent_id,
        &successor_pending.signing_id,
    )
    .await?;
    store_signed_bip448_transfer_state(
        &pool,
        "wallet",
        "statechain",
        &post_sign.intent_id,
        &successor_pending.signing_id,
        &"49".repeat(32),
        &state_three.signing_metadata.update_signature,
    )
    .await?;
    let signed_successor = get_active_bip448_transfer_intent(&pool, "wallet", "statechain")
        .await?
        .ok_or_else(|| anyhow!("signed successor disappeared"))?;
    let mut state_three_history = replacement_window_history;
    state_three_history.push(history_entry(
        &state_three,
        successor_receiver.x_only_public_key().0,
    ));
    let mut state_three_message = sample_bip448_transfer_msg();
    state_three_message.statechain_id = "statechain".into();
    state_three_message.receiver_user_public_key = post_sign.receiver_user_pubkey.clone();
    state_three_message.aggregate_pubkey = record.aggregate_pubkey.clone();
    state_three_message.funding_outpoint = record.funding_outpoint.clone();
    state_three_message.latest_state = state_three;
    state_three_message.latest_state_number = 3;
    state_three_message.challenge_delay = record.challenge_delay;
    state_three_message.amount_sats = record.amount_sats;
    state_three_message.network = record.network.clone();
    state_three_message.value_schedule = state_three_message.latest_state.value_schedule.clone();
    state_three_message.server_signature_count = 3;
    state_three_message.state_history = state_three_history;
    let signed_successor_pending =
        get_bip448_pending_transfer_signing(&pool, "wallet", "statechain")
            .await?
            .ok_or_else(|| anyhow!("signed successor pending row disappeared"))?;
    let alternate_secret_nonce = "46".repeat(132);
    assert_ne!(
        alternate_secret_nonce,
        signed_successor_pending.client_secret_nonce
    );
    assert_eq!(
        sqlx::query(
            "UPDATE bip448_pending_transfer_signings SET client_secret_nonce=$1 \
             WHERE wallet_name='wallet' AND statechain_id='statechain' \
             AND client_secret_nonce=$2"
        )
        .bind(&alternate_secret_nonce)
        .bind(&signed_successor_pending.client_secret_nonce)
        .execute(&pool)
        .await?
        .rows_affected(),
        1
    );
    let materialization_error = materialize_bip448_signed_transfer_intent(
        &pool,
        &signed_successor,
        &signed_successor_pending,
        &state_three_message,
    )
    .await
    .unwrap_err();
    assert!(materialization_error
        .to_string()
        .contains("pending signing changed after complete validation"));
    assert_eq!(
        get_bip448_state_history(&pool, "wallet", "statechain")
            .await?
            .len(),
        2,
        "new-message materialization mismatch must not append history"
    );
    assert!(
        !has_bip448_transfer_msg_for_statechain(&pool, "wallet", "statechain").await?,
        "new-message materialization mismatch must not insert a message"
    );
    assert_eq!(
        get_active_bip448_transfer_intent(&pool, "wallet", "statechain").await?,
        Some(signed_successor.clone()),
        "new-message materialization mismatch must not change the intent"
    );
    assert_eq!(
        sqlx::query(
            "UPDATE bip448_pending_transfer_signings SET client_secret_nonce=$1 \
             WHERE wallet_name='wallet' AND statechain_id='statechain' \
             AND client_secret_nonce=$2"
        )
        .bind(&signed_successor_pending.client_secret_nonce)
        .bind(&alternate_secret_nonce)
        .execute(&pool)
        .await?
        .rows_affected(),
        1
    );
    let materialized_json = materialize_bip448_signed_transfer_intent(
        &pool,
        &signed_successor,
        &signed_successor_pending,
        &state_three_message,
    )
    .await?;
    let materialized_history = get_bip448_state_history(&pool, "wallet", "statechain").await?;
    assert_eq!(
        sqlx::query(
            "UPDATE bip448_pending_transfer_signings SET client_secret_nonce=$1 \
             WHERE wallet_name='wallet' AND statechain_id='statechain' \
             AND client_secret_nonce=$2"
        )
        .bind(&alternate_secret_nonce)
        .bind(&signed_successor_pending.client_secret_nonce)
        .execute(&pool)
        .await?
        .rows_affected(),
        1
    );
    let replay_error = materialize_bip448_signed_transfer_intent(
        &pool,
        &signed_successor,
        &signed_successor_pending,
        &state_three_message,
    )
    .await
    .unwrap_err();
    assert!(replay_error
        .to_string()
        .contains("pending signing changed after complete validation"));
    assert_eq!(
        get_bip448_state_history(&pool, "wallet", "statechain").await?,
        materialized_history,
        "stored-message replay mismatch must not change history"
    );
    assert_eq!(
        get_bip448_transfer_msg_raw_optional(&pool, "wallet", "statechain", None)
            .await?
            .map(|(_, raw)| raw),
        Some(materialized_json.clone()),
        "stored-message replay mismatch must not replace the message"
    );
    assert_eq!(
        sqlx::query(
            "UPDATE bip448_pending_transfer_signings SET client_secret_nonce=$1 \
             WHERE wallet_name='wallet' AND statechain_id='statechain' \
             AND client_secret_nonce=$2"
        )
        .bind(&signed_successor_pending.client_secret_nonce)
        .bind(&alternate_secret_nonce)
        .execute(&pool)
        .await?
        .rows_affected(),
        1
    );
    assert_eq!(
        materialize_bip448_signed_transfer_intent(
            &pool,
            &signed_successor,
            &signed_successor_pending,
            &state_three_message,
        )
        .await?,
        materialized_json,
        "restored complete pending row must permit exact stored-message replay"
    );
    assert_eq!(
        get_bip448_state_history(&pool, "wallet", "statechain")
            .await?
            .len(),
        3,
        "successor materialization consumes the already-recorded predecessor fingerprint once"
    );

    let mut orphan = sample_transfer_intent("a4");
    orphan.activity_status = Bip448TransferIntentActivityStatus::Superseded;
    let mut connection = pool.acquire().await?;
    insert_transfer_intent_on(&mut connection, &orphan).await?;
    drop(connection);
    assert!(
        get_active_bip448_transfer_intent(&pool, "wallet", "statechain")
            .await
            .is_err()
    );
    assert!(
        reject_bip448_transfer_intent_and_reactivate_predecessor(&pool, &post_sign)
            .await
            .is_err(),
        "corrupt lineage blocks even otherwise legal cleanup"
    );
    Ok(())
}

#[tokio::test]
async fn bip448_every_corrupt_transfer_lineage_blocks_attempt_and_close() -> Result<()> {
    let active = sample_transfer_intent("b1");
    let mut orphan = sample_transfer_intent("b2");
    orphan.activity_status = Bip448TransferIntentActivityStatus::Superseded;
    assert_corrupt_transfer_lineage_blocks(&[active, orphan], false).await?;

    let mut missing = sample_transfer_intent("b3");
    missing.predecessor_intent_id = Some("b4".repeat(32));
    assert_corrupt_transfer_lineage_blocks(&[missing], false).await?;

    let mut cycle_active = sample_transfer_intent("b5");
    cycle_active.predecessor_intent_id = Some("b6".repeat(32));
    let mut cycle_predecessor = sample_transfer_intent("b6");
    cycle_predecessor.predecessor_intent_id = Some(cycle_active.intent_id.clone());
    cycle_predecessor.activity_status = Bip448TransferIntentActivityStatus::Superseded;
    assert_corrupt_transfer_lineage_blocks(&[cycle_active, cycle_predecessor], false).await?;

    assert_corrupt_transfer_lineage_blocks(
        &[sample_transfer_intent("b7"), sample_transfer_intent("b8")],
        true,
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn bip448_accepted_local_outgoing_reconciliation_is_exact_and_conservative() -> Result<()> {
    let (pool, _, _recipient_auth, _message) = accepted_local_outgoing_fixture().await?;
    assert_eq!(
        reconcile_bip448_accepted_local_outgoing_messages(&pool, "wallet", "statechain").await?,
        1
    );
    assert!(!has_bip448_transfer_msg_for_statechain(&pool, "wallet", "statechain").await?);

    let (pending_pool, pending_record, _, pending_message) =
        accepted_local_outgoing_fixture().await?;
    let pending_entry = pending_message
        .state_history
        .last()
        .ok_or_else(|| anyhow!("accepted-prefix fixture history is empty"))?;
    let pending = Bip448PendingDepositSigning {
        wallet_name: "wallet".into(),
        statechain_id: "statechain".into(),
        funding_txid: pending_record.funding_outpoint.txid.clone(),
        funding_vout: pending_record.funding_outpoint.vout,
        funding_value_sats: pending_record.funding_outpoint.value_sats,
        update_template_hash: pending_entry.update_template_hash.clone(),
        settlement_template_hash: pending_entry.settlement_template_hash.clone(),
        state_locktime: pending_entry.state_locktime,
        signing_id: pending_message
            .latest_state
            .signing_metadata
            .signing_id
            .clone(),
        client_secret_nonce: "ab".repeat(132),
        client_public_nonce: pending_entry.client_public_nonce.clone(),
        blinding_factor: pending_entry.blinding_factor.clone(),
        server_public_nonce: Some(pending_entry.server_public_nonce.clone()),
    };
    insert_bip448_pending_transfer_signing_if_absent(&pending_pool, &pending).await?;
    assert_eq!(
        reconcile_bip448_accepted_local_outgoing_messages(&pending_pool, "wallet", "statechain")
            .await?,
        1
    );
    assert!(
        get_bip448_pending_transfer_signing(&pending_pool, "wallet", "statechain")
            .await?
            .is_none(),
        "the exact accepted-prefix pending signing must be deleted atomically"
    );

    let (conflicting_pending_pool, conflicting_record, _, conflicting_message) =
        accepted_local_outgoing_fixture().await?;
    let conflicting_entry = conflicting_message
        .state_history
        .last()
        .ok_or_else(|| anyhow!("accepted-prefix fixture history is empty"))?;
    let conflicting_pending = Bip448PendingDepositSigning {
        wallet_name: "wallet".into(),
        statechain_id: "statechain".into(),
        funding_txid: conflicting_record.funding_outpoint.txid.clone(),
        funding_vout: conflicting_record.funding_outpoint.vout,
        funding_value_sats: conflicting_record.funding_outpoint.value_sats,
        update_template_hash: conflicting_entry.update_template_hash.clone(),
        settlement_template_hash: conflicting_entry.settlement_template_hash.clone(),
        state_locktime: conflicting_entry.state_locktime,
        signing_id: conflicting_message
            .latest_state
            .signing_metadata
            .signing_id
            .clone(),
        client_secret_nonce: "ab".repeat(132),
        client_public_nonce: "55".repeat(66),
        blinding_factor: conflicting_entry.blinding_factor.clone(),
        server_public_nonce: Some(conflicting_entry.server_public_nonce.clone()),
    };
    insert_bip448_pending_transfer_signing_if_absent(
        &conflicting_pending_pool,
        &conflicting_pending,
    )
    .await?;
    assert!(reconcile_bip448_accepted_local_outgoing_messages(
        &conflicting_pending_pool,
        "wallet",
        "statechain"
    )
    .await
    .is_err());
    assert!(
        has_bip448_transfer_msg_for_statechain(&conflicting_pending_pool, "wallet", "statechain")
            .await?
    );
    assert!(
        get_bip448_pending_transfer_signing(&conflicting_pending_pool, "wallet", "statechain")
            .await?
            .is_some(),
        "a conflicting pending signing must roll back accepted-prefix cleanup"
    );

    let (pool, record, recipient_auth, message) = accepted_local_outgoing_fixture().await?;
    let stored_json = serde_json::to_string(&message)?;
    let mut active = sample_transfer_intent("c1");
    active.expected_signature_count = 2;
    active.planned_state_number = 3;
    active.previous_locktime = record.latest_state.state_locktime;
    active.prior_transfer_recipient_auth_pubkey = Some(recipient_auth.clone());
    active.prior_transfer_msg_hash = Some(sha256::Hash::hash(stored_json.as_bytes()).to_string());
    active.clear_local_attempt = true;
    insert_bip448_transfer_intent_if_absent(&pool, &active).await?;
    assert_eq!(
        reconcile_bip448_accepted_local_outgoing_messages(&pool, "wallet", "statechain").await?,
        0,
        "an intent-referenced message must be retained"
    );
    assert!(has_bip448_transfer_msg_for_statechain(&pool, "wallet", "statechain").await?);

    let suffix_pool = migrated_pool().await?;
    let (suffix_record, _, _) = accepted_binding_fixture(&suffix_pool).await?;
    let (receiver, _) = sample_owner_key(2);
    let (auth, _) = sample_owner_key(3);
    let suffix_wallet = get_wallet(&suffix_pool, "wallet").await?;
    let state_two = real_fixture_state_for_owner(
        &suffix_wallet,
        &suffix_record,
        receiver.x_only_public_key().0,
        2,
        suffix_record.latest_state.state_locktime + 1,
    )?;
    let entry_two = history_entry(&state_two, receiver.x_only_public_key().0);
    insert_bip448_state_history_entry(&suffix_pool, "wallet", "statechain", &entry_two).await?;
    let suffix_history = get_bip448_state_history(&suffix_pool, "wallet", "statechain").await?;
    let suffix_message = exact_transfer_message(
        &suffix_record,
        state_two,
        &receiver.to_string(),
        suffix_history,
    );
    insert_or_update_bip448_transfer_msg(
        &suffix_pool,
        "wallet",
        &auth.to_string(),
        &suffix_message,
    )
    .await?;
    assert_eq!(
        reconcile_bip448_accepted_local_outgoing_messages(&suffix_pool, "wallet", "statechain")
            .await?,
        0,
        "the journal-proven current sender suffix is not an accepted local prefix"
    );
    assert!(has_bip448_transfer_msg_for_statechain(&suffix_pool, "wallet", "statechain").await?);

    let (malformed_pool, _, malformed_recipient, malformed_message) =
        accepted_local_outgoing_fixture().await?;
    sqlx::query(
        "UPDATE bip448_transfer_messages SET transfer_msg_json='{' \
         WHERE wallet_name='wallet' AND statechain_id='statechain'",
    )
    .execute(&malformed_pool)
    .await?;
    assert!(reconcile_bip448_accepted_local_outgoing_messages(
        &malformed_pool,
        "wallet",
        "statechain"
    )
    .await
    .is_err());
    assert!(has_bip448_transfer_msg_for_statechain(&malformed_pool, "wallet", "statechain").await?);
    let mut wrong_statechain = malformed_message;
    wrong_statechain.statechain_id = "other-statechain".into();
    let wrong_json = serde_json::to_string(&wrong_statechain)?;
    sqlx::query(
        "UPDATE bip448_transfer_messages SET transfer_msg_json=$1 \
         WHERE wallet_name='wallet' AND statechain_id='statechain' \
         AND recipient_auth_pubkey=$2",
    )
    .bind(wrong_json)
    .bind(&malformed_recipient)
    .execute(&malformed_pool)
    .await?;
    assert!(reconcile_bip448_accepted_local_outgoing_messages(
        &malformed_pool,
        "wallet",
        "statechain"
    )
    .await
    .is_err());

    let (conflict_pool, _, first_recipient, conflict_message) =
        accepted_local_outgoing_fixture().await?;
    let mut wallet = get_wallet(&conflict_pool, "wallet").await?;
    let mut second_coin = wallet.get_new_coin()?;
    second_coin.user_pubkey = conflict_message.receiver_user_public_key.clone();
    second_coin.statechain_protocol = Some("bip448".into());
    second_coin.statechain_id = Some("statechain".into());
    second_coin.status = CoinStatus::CONFIRMED;
    let second_recipient = second_coin.auth_pubkey.clone();
    assert_ne!(second_recipient, first_recipient);
    wallet.coins.push(second_coin);
    update_wallet(&conflict_pool, &wallet).await?;
    insert_or_update_bip448_transfer_msg(
        &conflict_pool,
        "wallet",
        &second_recipient,
        &conflict_message,
    )
    .await?;
    assert!(reconcile_bip448_accepted_local_outgoing_messages(
        &conflict_pool,
        "wallet",
        "statechain"
    )
    .await
    .is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bip448_transfer_messages \
             WHERE wallet_name='wallet' AND statechain_id='statechain'",
        )
        .fetch_one(&conflict_pool)
        .await?,
        2,
        "conflicting rows must roll back without partial deletion"
    );
    Ok(())
}

#[tokio::test]
async fn bip448_cross_wallet_receiver_without_local_outgoing_row_deletes_nothing() -> Result<()> {
    let (pool, _, recipient_auth, _) = accepted_local_outgoing_fixture().await?;
    let deleted = sqlx::query(
        "DELETE FROM bip448_transfer_messages WHERE wallet_name='wallet' \
         AND statechain_id='statechain' AND recipient_auth_pubkey=$1",
    )
    .bind(recipient_auth)
    .execute(&pool)
    .await?;
    assert_eq!(deleted.rows_affected(), 1);
    let wallet_before = get_bip448_raw_wallet_json(&pool, "wallet").await?;

    assert_eq!(
        reconcile_bip448_accepted_local_outgoing_messages(&pool, "wallet", "statechain").await?,
        0
    );
    assert_eq!(
        get_bip448_raw_wallet_json(&pool, "wallet").await?,
        wallet_before
    );
    assert!(!has_bip448_transfer_msg_for_statechain(&pool, "wallet", "statechain").await?);
    Ok(())
}

#[tokio::test]
async fn bip448_cancellation_wallet_signing_acceptance_and_cleanup_are_atomic() -> Result<()> {
    let pool = migrated_pool().await?;
    let (wallet, mut record, initial_entry, _) = real_accepted_fixture(CoinStatus::CONFIRMED)?;
    let generated_coin = wallet.get_new_coin()?;
    insert_wallet(&pool, &wallet).await?;
    let generated_user = secp256k1::PublicKey::from_str(&generated_coin.user_pubkey)?;
    persist_bip448_initial_acceptance(&pool, &record, &initial_entry).await?;

    let old_raw = sqlx::query_scalar::<_, String>(
        "SELECT wallet_json FROM wallet WHERE wallet_name='wallet'",
    )
    .fetch_one(&pool)
    .await?;
    let mut replacement_wallet = wallet.clone();
    replacement_wallet.coins.push(generated_coin.clone());
    let mut cancellation = sample_transfer_intent("d1");
    cancellation.intent_kind = Bip448TransferIntentKind::Cancellation;
    cancellation.sender_signed_statechain_id = wallet.coins[0]
        .signed_statechain_id
        .clone()
        .ok_or_else(|| anyhow!("real source Coin has no statechain authorization"))?;
    cancellation.recipient_address = generated_coin.address.clone();
    cancellation.receiver_user_pubkey = generated_coin.user_pubkey.clone();
    cancellation.recipient_auth_pubkey = generated_coin.auth_pubkey.clone();
    cancellation.generated_coin_user_pubkey = Some(generated_coin.user_pubkey.clone());
    cancellation.generated_coin_auth_pubkey = Some(generated_coin.auth_pubkey.clone());
    cancellation.generated_coin_address = Some(generated_coin.address.clone());

    let mut invalid_replacement = replacement_wallet.clone();
    invalid_replacement.blockheight += 1;
    assert!(insert_bip448_cancellation_intent_with_wallet(
        &pool,
        &cancellation,
        &old_raw,
        &invalid_replacement,
    )
    .await
    .is_err());
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT wallet_json FROM wallet WHERE wallet_name='wallet'"
        )
        .fetch_one(&pool)
        .await?,
        old_raw
    );

    let rejected = insert_bip448_cancellation_intent_with_wallet(
        &pool,
        &cancellation,
        &old_raw,
        &replacement_wallet,
    )
    .await?;
    assert_eq!(
        insert_bip448_cancellation_intent_with_wallet(
            &pool,
            &cancellation,
            &old_raw,
            &replacement_wallet,
        )
        .await?,
        rejected,
        "exact replay must not append a second generated Coin"
    );
    assert!(
        reactivate_bip448_transfer_intent_predecessor_after_definitive_rejection(&pool, &rejected)
            .await?
            .is_none()
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT wallet_json FROM wallet WHERE wallet_name='wallet'"
        )
        .fetch_one(&pool)
        .await?,
        old_raw,
        "definitive rejection removes only the generated Coin"
    );
    assert!(list_bip448_transfer_intents(&pool, "wallet", "statechain")
        .await?
        .is_empty());

    cancellation.intent_id = "d2".repeat(32);
    let stored = insert_bip448_cancellation_intent_with_wallet(
        &pool,
        &cancellation,
        &old_raw,
        &replacement_wallet,
    )
    .await?;
    transition_bip448_transfer_intent_phase(
        &pool,
        "wallet",
        "statechain",
        &stored.intent_id,
        Bip448TransferIntentPhase::Prepared,
        Bip448TransferIntentPhase::SenderArmed,
    )
    .await?;
    let x1_stored = store_bip448_transfer_intent_x1(
        &pool,
        "wallet",
        "statechain",
        &stored.intent_id,
        &"01".repeat(32),
    )
    .await?;
    assert_eq!(x1_stored.phase, Bip448TransferIntentPhase::X1Stored);
    assert!(transition_bip448_transfer_intent_phase(
        &pool,
        "wallet",
        "statechain",
        &stored.intent_id,
        Bip448TransferIntentPhase::SenderArmed,
        Bip448TransferIntentPhase::Prepared,
    )
    .await
    .is_err());

    let state_two = real_fixture_state_for_owner(
        &wallet,
        &record,
        generated_user.x_only_public_key().0,
        2,
        record.latest_state.state_locktime + 1,
    )?;
    let pending = Bip448PendingDepositSigning {
        wallet_name: "wallet".into(),
        statechain_id: "statechain".into(),
        funding_txid: record.funding_outpoint.txid.clone(),
        funding_vout: record.funding_outpoint.vout,
        funding_value_sats: record.funding_outpoint.value_sats,
        update_template_hash: state_two.update_template_hash.clone(),
        settlement_template_hash: state_two.settlement_template_hash.clone(),
        state_locktime: state_two.state_locktime,
        signing_id: state_two.signing_metadata.signing_id.clone(),
        client_secret_nonce: "44".repeat(132),
        client_public_nonce: state_two.signing_metadata.client_public_nonce.clone(),
        blinding_factor: state_two.signing_metadata.blinding_factor.clone(),
        server_public_nonce: None,
    };
    let first_armed =
        install_bip448_transfer_target_pending(&pool, &stored.intent_id, &pending).await?;
    assert_eq!(
        first_armed.state_signing_phase,
        Bip448TransferStateSigningPhase::FirstArmed
    );
    let nonce_stored = store_bip448_transfer_state_nonce(
        &pool,
        "wallet",
        "statechain",
        &stored.intent_id,
        &pending.signing_id,
        &state_two.signing_metadata.server_public_nonce,
    )
    .await?;
    assert_eq!(
        nonce_stored.state_signing_phase,
        Bip448TransferStateSigningPhase::NonceStored
    );
    assert!(store_bip448_transfer_state_nonce(
        &pool,
        "wallet",
        "statechain",
        &stored.intent_id,
        &pending.signing_id,
        &state_two.signing_metadata.server_public_nonce,
    )
    .await
    .is_err());
    transition_bip448_transfer_state_signing_phase(
        &pool,
        "wallet",
        "statechain",
        &stored.intent_id,
        &pending.signing_id,
        Bip448TransferStateSigningPhase::NonceStored,
        Bip448TransferStateSigningPhase::SecondArmed,
    )
    .await?;
    assert!(transition_bip448_transfer_state_signing_phase(
        &pool,
        "wallet",
        "statechain",
        &stored.intent_id,
        &pending.signing_id,
        Bip448TransferStateSigningPhase::NonceStored,
        Bip448TransferStateSigningPhase::SecondArmed,
    )
    .await
    .is_err());
    let signed = store_bip448_transfer_state_signed_artifacts(
        &pool,
        "wallet",
        "statechain",
        &stored.intent_id,
        &pending.signing_id,
        &"48".repeat(32),
        &state_two.signing_metadata.update_signature,
    )
    .await?;
    assert_eq!(
        signed.state_signing_phase,
        Bip448TransferStateSigningPhase::Signed
    );
    assert!(store_bip448_transfer_state_signed_artifacts(
        &pool,
        "wallet",
        "statechain",
        &stored.intent_id,
        &pending.signing_id,
        &"48".repeat(32),
        &state_two.signing_metadata.update_signature,
    )
    .await
    .is_err());

    let state_two_entry = history_entry(&state_two, generated_user.x_only_public_key().0);
    insert_bip448_state_history_entry(&pool, "wallet", "statechain", &state_two_entry).await?;
    let complete_history = get_bip448_state_history(&pool, "wallet", "statechain").await?;
    let message = exact_transfer_message(
        &record,
        state_two.clone(),
        &generated_coin.user_pubkey,
        complete_history,
    );
    let message_json = serde_json::to_string(&message)?;
    insert_or_update_bip448_transfer_msg(&pool, "wallet", &generated_coin.auth_pubkey, &message)
        .await?;
    let signed = get_active_bip448_transfer_intent(&pool, "wallet", "statechain")
        .await?
        .unwrap();
    let signed_pending = get_bip448_pending_transfer_signing(&pool, "wallet", "statechain")
        .await?
        .context("signed cancellation pending row is missing")?;
    let sender_raw = sqlx::query_scalar::<_, String>(
        "SELECT wallet_json FROM wallet WHERE wallet_name='wallet'",
    )
    .fetch_one(&pool)
    .await?;
    let mut sender_finished_wallet: Wallet = serde_json::from_str(&sender_raw)?;
    sender_finished_wallet.coins[0].status = CoinStatus::IN_TRANSFER;
    let history_before_finish = get_bip448_state_history(&pool, "wallet", "statechain").await?;
    let alternate_secret_nonce = "47".repeat(132);
    assert_ne!(alternate_secret_nonce, signed_pending.client_secret_nonce);
    assert_eq!(
        sqlx::query(
            "UPDATE bip448_pending_transfer_signings SET client_secret_nonce=$1 \
             WHERE wallet_name='wallet' AND statechain_id='statechain' \
             AND client_secret_nonce=$2"
        )
        .bind(&alternate_secret_nonce)
        .bind(&signed_pending.client_secret_nonce)
        .execute(&pool)
        .await?
        .rows_affected(),
        1
    );
    let finish_error = finish_bip448_cancellation_sender(
        &pool,
        &signed,
        &sender_raw,
        &sender_finished_wallet,
        &message_json,
        &signed_pending,
    )
    .await
    .unwrap_err();
    assert!(finish_error
        .to_string()
        .contains("pending signing changed after complete validation"));
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT wallet_json FROM wallet WHERE wallet_name='wallet'"
        )
        .fetch_one(&pool)
        .await?,
        sender_raw,
        "pending-row mismatch must not change sender Coin status"
    );
    assert_eq!(
        get_active_bip448_transfer_intent(&pool, "wallet", "statechain").await?,
        Some(signed.clone()),
        "pending-row mismatch must not advance the cancellation intent"
    );
    assert_eq!(
        get_bip448_state_history(&pool, "wallet", "statechain").await?,
        history_before_finish,
        "pending-row mismatch must not change history"
    );
    assert_eq!(
        get_bip448_transfer_msg_raw_optional(&pool, "wallet", "statechain", None)
            .await?
            .map(|(_, raw)| raw),
        Some(message_json.clone()),
        "pending-row mismatch must not change the materialized message"
    );
    assert_eq!(
        sqlx::query(
            "UPDATE bip448_pending_transfer_signings SET client_secret_nonce=$1 \
             WHERE wallet_name='wallet' AND statechain_id='statechain' \
             AND client_secret_nonce=$2"
        )
        .bind(&signed_pending.client_secret_nonce)
        .bind(&alternate_secret_nonce)
        .execute(&pool)
        .await?
        .rows_affected(),
        1
    );
    let sender_finished = finish_bip448_cancellation_sender(
        &pool,
        &signed,
        &sender_raw,
        &sender_finished_wallet,
        &message_json,
        &signed_pending,
    )
    .await?;
    assert_eq!(
        sender_finished.phase,
        Bip448TransferIntentPhase::SenderFinished
    );
    assert_eq!(
        get_bip448_pending_transfer_signing(&pool, "wallet", "statechain").await?,
        Some(signed_pending),
        "sender finish must retain the signed journal until terminal cleanup"
    );
    assert_eq!(
        list_bip448_transfer_intents(&pool, "wallet", "statechain")
            .await?
            .len(),
        1
    );

    record.latest_state_number = 2;
    record.latest_state = state_two;
    upsert_bip448_statechain_record(&pool, &record).await?;
    let mut accepted_wallet = get_wallet(&pool, "wallet").await?;
    let accepted_coin = accepted_wallet
        .coins
        .iter_mut()
        .find(|coin| coin.auth_pubkey == generated_coin.auth_pubkey)
        .unwrap();
    accepted_coin.statechain_protocol = Some("bip448".into());
    accepted_coin.statechain_id = Some("statechain".into());
    accepted_coin.signed_statechain_id = Some(mercurylib::transfer::receiver::sign_message(
        "statechain",
        accepted_coin,
    )?);
    accepted_coin.status = CoinStatus::CONFIRMED;
    let aggregate_pubkey = PublicKey::from_str(&record.aggregate_pubkey)?;
    let receiver_server_key = aggregate_pubkey.combine(&generated_user.negate())?;
    accepted_coin.server_pubkey = Some(receiver_server_key.to_string());
    accepted_coin.aggregated_pubkey = Some(record.aggregate_pubkey.clone());
    accepted_coin.utxo_txid = Some(record.funding_outpoint.txid.clone());
    accepted_coin.utxo_vout = Some(record.funding_outpoint.vout);
    accepted_coin.amount = Some(u32::try_from(record.funding_outpoint.value_sats)?);
    accepted_coin.locktime = Some(record.latest_state.state_locktime);
    accepted_coin.public_nonce = Some(
        record
            .latest_state
            .signing_metadata
            .client_public_nonce
            .clone(),
    );
    accepted_coin.server_public_nonce = Some(
        record
            .latest_state
            .signing_metadata
            .server_public_nonce
            .clone(),
    );
    accepted_coin.blinding_factor =
        Some(record.latest_state.signing_metadata.blinding_factor.clone());
    accepted_coin.aggregated_address =
        Some(bip448_deposit::create_deposit_address(accepted_coin, "regtest")?.address);
    update_wallet(&pool, &accepted_wallet).await?;
    let receiver_accepted = mark_bip448_cancellation_receiver_accepted(
        &pool,
        "wallet",
        "statechain",
        &stored.intent_id,
    )
    .await?;
    assert_eq!(
        receiver_accepted.phase,
        Bip448TransferIntentPhase::ReceiverAccepted
    );
    assert_eq!(
        mark_bip448_cancellation_receiver_accepted(
            &pool,
            "wallet",
            "statechain",
            &stored.intent_id,
        )
        .await?,
        receiver_accepted,
        "ReceiverAccepted is exact-idempotent"
    );
    let (conflicting_recipient, _) = sample_owner_key(29);
    assert_ne!(
        conflicting_recipient.to_string(),
        receiver_accepted.recipient_auth_pubkey
    );
    insert_or_update_bip448_transfer_msg(
        &pool,
        "wallet",
        &conflicting_recipient.to_string(),
        &message,
    )
    .await?;
    assert!(delete_bip448_cancellation_artifacts_after_sync(
        &pool,
        &receiver_accepted,
        &message_json,
    )
    .await
    .is_err());
    assert_eq!(
        get_active_bip448_transfer_intent(&pool, "wallet", "statechain").await?,
        Some(receiver_accepted.clone()),
        "a conflicting outgoing row must preserve ReceiverAccepted lineage"
    );
    assert!(
        get_bip448_pending_transfer_signing(&pool, "wallet", "statechain")
            .await?
            .is_some()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bip448_transfer_messages \
             WHERE wallet_name='wallet' AND statechain_id='statechain'",
        )
        .fetch_one(&pool)
        .await?,
        2,
        "conflicting cancellation cleanup must not delete either message"
    );
    let removed_conflict = sqlx::query(
        "DELETE FROM bip448_transfer_messages WHERE wallet_name='wallet' \
         AND statechain_id='statechain' AND recipient_auth_pubkey=$1",
    )
    .bind(conflicting_recipient.to_string())
    .execute(&pool)
    .await?;
    assert_eq!(removed_conflict.rows_affected(), 1);
    delete_bip448_cancellation_artifacts_after_sync(&pool, &receiver_accepted, &message_json)
        .await?;
    assert!(list_bip448_transfer_intents(&pool, "wallet", "statechain")
        .await?
        .is_empty());
    assert!(!has_bip448_transfer_msg_for_statechain(&pool, "wallet", "statechain").await?);
    assert!(
        get_bip448_pending_transfer_signing(&pool, "wallet", "statechain")
            .await?
            .is_none()
    );
    assert_eq!(
        get_wallet(&pool, "wallet")
            .await?
            .coins
            .iter()
            .filter(|coin| coin.auth_pubkey == generated_coin.auth_pubkey)
            .count(),
        1,
        "terminal cleanup preserves the accepted generated Coin"
    );
    Ok(())
}
