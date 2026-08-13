use super::super::withdrawals::legal_broadcast_transition;
use super::support::*;

fn mutate_session_byte(session: &str, byte_index: usize) -> Result<String> {
    let mut bytes = hex::decode(session)?;
    let byte = bytes
        .get_mut(byte_index)
        .ok_or_else(|| anyhow!("session mutation index is out of bounds"))?;
    *byte ^= 1;
    Ok(hex::encode(bytes))
}

fn sign_second_payload_for_attempt(
    attempt: &Bip448WithdrawalAttempt,
    server_public_nonce: &str,
    blinded_session: &str,
) -> Result<String> {
    Ok(serde_json::to_string(
        &mercurylib::bip448_statechain::signing_api::Bip448PartialSignatureRequestPayload {
            statechain_id: attempt.statechain_id.clone(),
            signed_statechain_id: attempt.signed_statechain_id.clone(),
            signing_id: attempt.signing_id.clone(),
            negate_seckey: 0,
            session: blinded_session.to_owned(),
            server_pub_nonce: server_public_nonce.to_owned(),
        },
    )?)
}

async fn raw_withdrawal_attempt_snapshot(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    binding_index: u32,
) -> Result<String> {
    Ok(sqlx::query_scalar(
        "SELECT json_array(wallet_name,statechain_id,binding_index,attempt_kind,\
            owner_user_pubkey,owner_state_number,source_txid,source_vout,source_value_sats,\
            source_script_pubkey,destination_address,destination_script_pubkey,\
            fee_rate_sat_per_vbyte,fee_sats,lock_time,unsigned_tx_hex,signing_id,\
            signed_statechain_id,sign_first_payload_json,client_secret_nonce,\
            client_public_nonce,blinding_factor,server_public_nonce,message_hex,\
            output_pubkey,client_partial_sig,encoded_session,sign_second_payload_json,\
            server_partial_sig,aggregate_signature,signed_tx_hex,txid,phase,broadcast_status,\
            completion_status,closing_tip_height,closing_tip_hash,closing_bindings_json,\
            created_at,updated_at) FROM bip448_withdrawal_attempts \
         WHERE wallet_name=$1 AND statechain_id=$2 AND binding_index=$3",
    )
    .bind(wallet_name)
    .bind(statechain_id)
    .bind(i64::from(binding_index))
    .fetch_one(pool)
    .await?)
}

async fn ready_canonical_attempt_fixture(pool: &Pool<Sqlite>) -> Result<Bip448WithdrawalAttempt> {
    let (_, owner, script) = accepted_binding_fixture(pool).await?;
    let canonical = reconcile_bip448_funding_bindings(
        pool,
        "wallet",
        "statechain",
        &owner.to_string(),
        1,
        &[sample_binding_observation("34", 0, 100_000, &script)],
    )
    .await?
    .into_iter()
    .find(|binding| binding.binding_index == 0)
    .ok_or_else(|| anyhow!("canonical test binding is missing"))?;
    let close_tip_hash = "61".repeat(32);
    persist_bip448_scan_state(
        pool,
        "wallet",
        &script,
        &Bip448ScanCursor {
            coverage_start_height: 0,
            scan_revision: 0,
            last_scanned_height: 20,
            last_scanned_block_hash: close_tip_hash.clone(),
        },
        &[],
    )
    .await?;
    let closing_bindings_json =
        match classify_bip448_close_gate(pool, "wallet", "statechain").await? {
            Bip448CloseGate::Ready {
                closing_bindings_json,
                ..
            } => closing_bindings_json,
            blocked => return Err(anyhow!("unexpected canonical close blocker: {blocked:?}")),
        };
    let mut attempt = sample_duplicate_attempt(&canonical);
    attempt.attempt_kind = Bip448WithdrawalAttemptKind::Canonical;
    attempt.completion_status = Bip448CompletionStatus::Open;
    attempt.destination_address = get_wallet(pool, "wallet")
        .await?
        .coins
        .first()
        .ok_or_else(|| anyhow!("canonical destination fixture Coin is missing"))?
        .backup_address
        .clone();
    attempt.closing_tip_height = Some(20);
    attempt.closing_tip_hash = Some(close_tip_hash);
    attempt.closing_bindings_json = Some(closing_bindings_json);
    Ok(attempt)
}

#[tokio::test]
async fn bip448_signed_attempt_requires_exact_keypath_witness_and_rolls_back() -> Result<()> {
    let pool = migrated_pool().await?;
    let (_, owner, script) = accepted_binding_fixture(&pool).await?;
    let binding = reconcile_bip448_funding_bindings(
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
    .find(|binding| binding.binding_index == 1)
    .ok_or_else(|| anyhow!("duplicate test binding is missing"))?;
    let armed = second_arm_duplicate_attempt(&pool, &binding).await?;
    let aggregate_signature = hex::decode("92".repeat(64))?;
    let mut with_sighash_byte = aggregate_signature.clone();
    with_sighash_byte.push(1);
    let invalid_witnesses = vec![
        Vec::<Vec<u8>>::new(),
        vec![Vec::new()],
        vec![hex::decode("93".repeat(64))?],
        vec![aggregate_signature.clone(), vec![1]],
        vec![aggregate_signature.clone()],
    ];
    for witness_items in invalid_witnesses {
        let mut transaction: bitcoin::Transaction =
            bitcoin::consensus::deserialize(&hex::decode(&armed.unsigned_tx_hex)?)?;
        for item in witness_items {
            transaction.input[0].witness.push(item);
        }
        let result = store_bip448_withdrawal_signed_artifacts(
            &pool,
            "wallet",
            "statechain",
            1,
            &armed.signing_id,
            &"91".repeat(32),
            &hex::encode(&aggregate_signature),
            &hex::encode(bitcoin::consensus::serialize(&transaction)),
            &transaction.txid().to_string(),
            Bip448BroadcastStatus::NotBroadcast,
        )
        .await;
        assert!(result.is_err());
        let unchanged = get_bip448_withdrawal_attempt(&pool, "wallet", "statechain", 1)
            .await?
            .ok_or_else(|| anyhow!("armed attempt disappeared"))?;
        assert_eq!(unchanged.phase, Bip448WithdrawalPhase::SecondArmed);
        assert!(unchanged.server_partial_sig.is_none());
        assert!(unchanged.aggregate_signature.is_none());
        assert!(unchanged.signed_tx_hex.is_none());
        assert!(unchanged.txid.is_none());
    }

    let mut transaction: bitcoin::Transaction =
        bitcoin::consensus::deserialize(&hex::decode(&armed.unsigned_tx_hex)?)?;
    transaction.input[0].witness.push(with_sighash_byte);
    let stored = store_bip448_withdrawal_signed_artifacts(
        &pool,
        "wallet",
        "statechain",
        1,
        &armed.signing_id,
        &"91".repeat(32),
        &hex::encode(&aggregate_signature),
        &hex::encode(bitcoin::consensus::serialize(&transaction)),
        &transaction.txid().to_string(),
        Bip448BroadcastStatus::NotBroadcast,
    )
    .await?;
    assert_eq!(stored.phase, Bip448WithdrawalPhase::Signed);
    Ok(())
}

#[tokio::test]
async fn bip448_withdrawal_session_relationship_is_typed_and_mutation_resistant() -> Result<()> {
    let pool = migrated_pool().await?;
    let (_, owner, script) = accepted_binding_fixture(&pool).await?;
    let binding = reconcile_bip448_funding_bindings(
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
    .find(|binding| binding.binding_index == 1)
    .ok_or_else(|| anyhow!("duplicate session test binding is missing"))?;
    let attempt = sample_duplicate_attempt(&binding);
    insert_bip448_withdrawal_attempt_if_absent(&pool, &attempt).await?;
    let first_armed =
        arm_bip448_withdrawal_sign_first(&pool, "wallet", "statechain", 1, &attempt.signing_id)
            .await?;

    let server_public_nonce = "81".repeat(66);
    let output_pubkey = sample_owner_key(4).0.to_string();
    let (full_session, blinded_session) = real_keypath_session_pair(94)?;
    let (_, other_blinded_session) = real_keypath_session_pair(95)?;
    assert_ne!(full_session, blinded_session);
    assert_ne!(blinded_session, other_blinded_session);
    assert_eq!(
        bip448_funding::derive_bip448_blinded_session(&full_session)?,
        blinded_session
    );

    let mutated_full_session = mutate_session_byte(&full_session, 70)?;
    let mutated_blinded_session = mutate_session_byte(&blinded_session, 70)?;
    let truncated_full_session = full_session[..full_session.len() - 2].to_owned();
    let extended_full_session = format!("{full_session}00");
    let malformed_full_session = format!("g0{}", &full_session[2..]);
    let noncanonical_full_session = full_session.to_uppercase();
    let invalid_storage_cases = [
        (
            "mutated full",
            mutated_full_session.clone(),
            blinded_session.clone(),
        ),
        (
            "mutated blinded",
            full_session.clone(),
            mutated_blinded_session.clone(),
        ),
        (
            "truncated full",
            truncated_full_session.clone(),
            blinded_session.clone(),
        ),
        (
            "extended full",
            extended_full_session.clone(),
            blinded_session.clone(),
        ),
        (
            "malformed full",
            malformed_full_session.clone(),
            blinded_session.clone(),
        ),
        (
            "noncanonical full",
            noncanonical_full_session.clone(),
            blinded_session.clone(),
        ),
        (
            "different valid blinded",
            full_session.clone(),
            other_blinded_session.clone(),
        ),
    ];
    let first_armed_snapshot =
        raw_withdrawal_attempt_snapshot(&pool, "wallet", "statechain", 1).await?;
    for (case, candidate_full, candidate_blinded) in invalid_storage_cases {
        let payload = sign_second_payload_for_attempt(
            &first_armed,
            &server_public_nonce,
            &candidate_blinded,
        )?;
        assert!(
            store_bip448_withdrawal_nonce_session(
                &pool,
                "wallet",
                "statechain",
                1,
                &attempt.signing_id,
                &server_public_nonce,
                &"82".repeat(32),
                &output_pubkey,
                &"84".repeat(32),
                &candidate_full,
                &payload,
            )
            .await
            .is_err(),
            "invalid storage case {case} was accepted"
        );
        assert_eq!(
            raw_withdrawal_attempt_snapshot(&pool, "wallet", "statechain", 1).await?,
            first_armed_snapshot,
            "invalid storage case {case} changed the exact journal row"
        );
        let expectation = bip448_expected_signature_count(&pool, "wallet", "statechain").await?;
        assert_eq!(expectation.settled_count, 1);
        assert_eq!(expectation.second_armed_landed_count, None);
    }

    let valid_payload =
        sign_second_payload_for_attempt(&first_armed, &server_public_nonce, &blinded_session)?;
    let nonce_stored = store_bip448_withdrawal_nonce_session(
        &pool,
        "wallet",
        "statechain",
        1,
        &attempt.signing_id,
        &server_public_nonce,
        &"82".repeat(32),
        &output_pubkey,
        &"84".repeat(32),
        &full_session,
        &valid_payload,
    )
    .await?;
    assert_eq!(nonce_stored.phase, Bip448WithdrawalPhase::NonceStored);

    let invalid_load_cases = [
        (
            "mutated full",
            mutated_full_session,
            blinded_session.clone(),
        ),
        (
            "mutated blinded",
            full_session.clone(),
            mutated_blinded_session,
        ),
        (
            "truncated full",
            truncated_full_session,
            blinded_session.clone(),
        ),
        (
            "extended full",
            extended_full_session,
            blinded_session.clone(),
        ),
        (
            "malformed full",
            malformed_full_session,
            blinded_session.clone(),
        ),
        (
            "noncanonical full",
            noncanonical_full_session,
            blinded_session.clone(),
        ),
        (
            "different valid blinded",
            full_session.clone(),
            other_blinded_session,
        ),
    ];
    for (case, candidate_full, candidate_blinded) in invalid_load_cases {
        let payload = sign_second_payload_for_attempt(
            &nonce_stored,
            &server_public_nonce,
            &candidate_blinded,
        )?;
        sqlx::query(
            "UPDATE bip448_withdrawal_attempts SET encoded_session=$1,\
                sign_second_payload_json=$2 WHERE wallet_name='wallet' \
                AND statechain_id='statechain' AND binding_index=1",
        )
        .bind(candidate_full)
        .bind(payload)
        .execute(&pool)
        .await?;
        let corrupted_snapshot =
            raw_withdrawal_attempt_snapshot(&pool, "wallet", "statechain", 1).await?;
        assert!(
            get_bip448_withdrawal_attempt(&pool, "wallet", "statechain", 1)
                .await
                .is_err(),
            "invalid load case {case} passed typed validation"
        );
        assert!(
            arm_bip448_withdrawal_sign_second(
                &pool,
                "wallet",
                "statechain",
                1,
                &attempt.signing_id,
            )
            .await
            .is_err(),
            "invalid load case {case} reached SecondArmed"
        );
        assert_eq!(
            raw_withdrawal_attempt_snapshot(&pool, "wallet", "statechain", 1).await?,
            corrupted_snapshot,
            "invalid load case {case} changed the exact journal row"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM bip448_withdrawal_attempts \
                 WHERE wallet_name='wallet' AND statechain_id='statechain' \
                   AND phase='SecondArmed'",
            )
            .fetch_one(&pool)
            .await?,
            0,
            "invalid load case {case} armed sign/second"
        );
        sqlx::query(
            "UPDATE bip448_withdrawal_attempts SET encoded_session=$1,\
                sign_second_payload_json=$2 WHERE wallet_name='wallet' \
                AND statechain_id='statechain' AND binding_index=1",
        )
        .bind(&full_session)
        .bind(&valid_payload)
        .execute(&pool)
        .await?;
        assert_eq!(
            get_bip448_withdrawal_attempt(&pool, "wallet", "statechain", 1)
                .await?
                .ok_or_else(|| anyhow!("restored nonce row is missing"))?
                .phase,
            Bip448WithdrawalPhase::NonceStored
        );
    }

    let second_armed =
        arm_bip448_withdrawal_sign_second(&pool, "wallet", "statechain", 1, &attempt.signing_id)
            .await?;
    assert_eq!(second_armed.phase, Bip448WithdrawalPhase::SecondArmed);
    Ok(())
}

#[tokio::test]
async fn bip448_attempt_transitions_serialize_and_never_regress() -> Result<()> {
    let pool = migrated_pool().await?;
    let (record, owner, script) = accepted_binding_fixture(&pool).await?;
    let canonical = sample_binding_observation("34", 0, 100_000, &script);
    let duplicate = sample_binding_observation("11", 1, 70_000, &script);
    let bindings = reconcile_bip448_funding_bindings(
        &pool,
        "wallet",
        "statechain",
        &owner.to_string(),
        1,
        &[canonical, duplicate],
    )
    .await?;
    let binding = bindings
        .into_iter()
        .find(|row| row.binding_index == 1)
        .unwrap();
    let attempt = sample_duplicate_attempt(&binding);
    let inserted = insert_bip448_withdrawal_attempt_if_absent(&pool, &attempt).await?;
    assert_eq!(
        insert_bip448_withdrawal_attempt_if_absent(&pool, &attempt).await?,
        inserted
    );
    assert!(transition_bip448_withdrawal_phase(
        &pool,
        "wallet",
        "statechain",
        1,
        &attempt.signing_id,
        Bip448WithdrawalPhase::Prepared,
        Bip448WithdrawalPhase::SecondArmed,
    )
    .await
    .is_err());
    arm_bip448_withdrawal_sign_first(&pool, "wallet", "statechain", 1, &attempt.signing_id).await?;
    assert!(arm_bip448_withdrawal_sign_first(
        &pool,
        "wallet",
        "statechain",
        1,
        &attempt.signing_id
    )
    .await
    .is_err());
    let output_pubkey = sample_owner_key(4).0.to_string();
    let server_public_nonce = "81".repeat(66);
    let (encoded_session, blinded_session) = real_keypath_session_pair(91)?;
    let sign_second_payload_json = serde_json::to_string(
        &mercurylib::bip448_statechain::signing_api::Bip448PartialSignatureRequestPayload {
            statechain_id: "statechain".into(),
            signed_statechain_id: attempt.signed_statechain_id.clone(),
            signing_id: attempt.signing_id.clone(),
            negate_seckey: 0,
            session: blinded_session,
            server_pub_nonce: server_public_nonce.clone(),
        },
    )?;
    store_bip448_withdrawal_nonce_session(
        &pool,
        "wallet",
        "statechain",
        1,
        &attempt.signing_id,
        &server_public_nonce,
        &"82".repeat(32),
        &output_pubkey,
        &"84".repeat(32),
        &encoded_session,
        &sign_second_payload_json,
    )
    .await?;
    assert!(store_bip448_withdrawal_nonce_session(
        &pool,
        "wallet",
        "statechain",
        1,
        &attempt.signing_id,
        &server_public_nonce,
        &"82".repeat(32),
        &output_pubkey,
        &"84".repeat(32),
        &encoded_session,
        &sign_second_payload_json,
    )
    .await
    .is_err());
    arm_bip448_withdrawal_sign_second(&pool, "wallet", "statechain", 1, &attempt.signing_id)
        .await?;
    assert!(arm_bip448_withdrawal_sign_second(
        &pool,
        "wallet",
        "statechain",
        1,
        &attempt.signing_id
    )
    .await
    .is_err());
    assert!(bip448_statechain_is_exit_only(&pool, "wallet", "statechain").await?);
    let expectation = bip448_expected_signature_count(&pool, "wallet", "statechain").await?;
    assert_eq!(expectation.settled_count, 1);
    assert_eq!(expectation.second_armed_landed_count, Some(2));
    let server_partial_sig = "91".repeat(32);
    let aggregate_signature = "92".repeat(64);
    let mut signed_transaction: bitcoin::Transaction =
        bitcoin::consensus::deserialize(&hex::decode(&attempt.unsigned_tx_hex)?)?;
    let mut keypath_witness = hex::decode(&aggregate_signature)?;
    keypath_witness.push(0x01);
    signed_transaction.input[0].witness.push(keypath_witness);
    let signed_tx_hex = hex::encode(bitcoin::consensus::serialize(&signed_transaction));
    let signed_txid = signed_transaction.txid().to_string();
    store_signed_bip448_withdrawal(
        &pool,
        "wallet",
        "statechain",
        1,
        &attempt.signing_id,
        &server_partial_sig,
        &aggregate_signature,
        &signed_tx_hex,
        &signed_txid,
        Bip448BroadcastStatus::NotBroadcast,
    )
    .await?;
    assert!(store_signed_bip448_withdrawal(
        &pool,
        "wallet",
        "statechain",
        1,
        &attempt.signing_id,
        &server_partial_sig,
        &aggregate_signature,
        &signed_tx_hex,
        &signed_txid,
        Bip448BroadcastStatus::NotBroadcast,
    )
    .await
    .is_err());
    for (from, to) in [
        (
            Bip448BroadcastStatus::NotBroadcast,
            Bip448BroadcastStatus::Accepted,
        ),
        (
            Bip448BroadcastStatus::Accepted,
            Bip448BroadcastStatus::NeedsRebroadcast,
        ),
        (
            Bip448BroadcastStatus::NeedsRebroadcast,
            Bip448BroadcastStatus::Conflicting,
        ),
        (
            Bip448BroadcastStatus::Conflicting,
            Bip448BroadcastStatus::Conflicted,
        ),
        (
            Bip448BroadcastStatus::Conflicted,
            Bip448BroadcastStatus::NeedsRebroadcast,
        ),
    ] {
        transition_bip448_withdrawal_broadcast_status(
            &pool,
            "wallet",
            "statechain",
            1,
            &attempt.signing_id,
            from,
            to,
        )
        .await?;
    }
    assert!(transition_bip448_withdrawal_broadcast_status(
        &pool,
        "wallet",
        "statechain",
        1,
        &attempt.signing_id,
        Bip448BroadcastStatus::NeedsRebroadcast,
        Bip448BroadcastStatus::NotBroadcast
    )
    .await
    .is_err());
    assert_eq!(
        bip448_expected_signature_count(&pool, "wallet", "statechain")
            .await?
            .settled_count,
        2
    );
    assert_eq!(
        get_bip448_statechain(&pool, "wallet", "statechain").await?,
        record
    );
    Ok(())
}

#[test]
fn bip448_broadcast_transition_matrix_is_exact() {
    let statuses = [
        Bip448BroadcastStatus::NotBroadcast,
        Bip448BroadcastStatus::Accepted,
        Bip448BroadcastStatus::Confirmed,
        Bip448BroadcastStatus::NeedsRebroadcast,
        Bip448BroadcastStatus::Conflicting,
        Bip448BroadcastStatus::Conflicted,
    ];
    for from in statuses {
        for to in statuses {
            let expected = from == to
                || from == Bip448BroadcastStatus::NotBroadcast
                || to != Bip448BroadcastStatus::NotBroadcast;
            assert_eq!(
                legal_broadcast_transition(from, to),
                expected,
                "unexpected broadcast edge {from:?} -> {to:?}"
            );
        }
    }
}

#[tokio::test]
async fn bip448_prepared_compare_delete_is_duplicate_only_and_tip_bound() -> Result<()> {
    let pool = migrated_pool().await?;
    let (_, owner, script) = accepted_binding_fixture(&pool).await?;
    let binding = reconcile_bip448_funding_bindings(
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
    .unwrap();
    let candidate = Bip448ScanCursor {
        coverage_start_height: 0,
        scan_revision: 0,
        last_scanned_height: 20,
        last_scanned_block_hash: "61".repeat(32),
    };
    persist_bip448_scan_state(&pool, "wallet", &script, &candidate, &[]).await?;
    let attempt = sample_duplicate_attempt(&binding);
    let attempt = insert_bip448_withdrawal_attempt_if_absent(&pool, &attempt).await?;
    let prospective_txid = bip448_funding::expected_withdrawal_txid(&attempt)?;
    let exact_sweep_spend = Bip448BindingObservation {
        observation_status: Bip448ObservationStatus::SpentConfirmed,
        spend_txid: Some(prospective_txid.clone()),
        spend_height: Some(19),
        ..sample_binding_observation("11", 1, 70_000, &script)
    };
    let exact_spent_binding =
        update_bip448_funding_binding_observation(&pool, &binding, &exact_sweep_spend).await?;
    assert!(
        delete_prepared_bip448_withdrawal_attempt_for_confirmed_spend(
            &pool,
            &attempt,
            &prospective_txid,
            20,
            &"61".repeat(32),
        )
        .await
        .is_err(),
        "the attempt's own prospective txid is not a competing spend"
    );
    let spent = Bip448BindingObservation {
        observation_status: Bip448ObservationStatus::SpentConfirmed,
        spend_txid: Some("62".repeat(32)),
        spend_height: Some(19),
        ..sample_binding_observation("11", 1, 70_000, &script)
    };
    update_bip448_funding_binding_observation(&pool, &exact_spent_binding, &spent).await?;
    assert!(
        delete_prepared_bip448_withdrawal_attempt_for_confirmed_spend(
            &pool,
            &attempt,
            &"62".repeat(32),
            20,
            &"63".repeat(32)
        )
        .await
        .is_err(),
        "wrong stable hash must retain row"
    );
    assert!(
        get_bip448_withdrawal_attempt(&pool, "wallet", "statechain", 1)
            .await?
            .is_some()
    );
    delete_prepared_bip448_withdrawal_attempt_for_confirmed_spend(
        &pool,
        &attempt,
        &"62".repeat(32),
        20,
        &"61".repeat(32),
    )
    .await?;
    assert!(
        get_bip448_withdrawal_attempt(&pool, "wallet", "statechain", 1)
            .await?
            .is_none()
    );

    let spent_binding = get_bip448_funding_binding(&pool, "wallet", "statechain", 1)
        .await?
        .unwrap();
    let confirmed = sample_binding_observation("11", 1, 70_000, &script);
    let confirmed_binding =
        update_bip448_funding_binding_observation(&pool, &spent_binding, &confirmed).await?;
    let mut armed = sample_duplicate_attempt(&confirmed_binding);
    armed.signing_id = "76".repeat(32);
    refresh_attempt_sign_first_payload(&mut armed);
    let armed = insert_bip448_withdrawal_attempt_if_absent(&pool, &armed).await?;
    arm_bip448_withdrawal_sign_first(&pool, "wallet", "statechain", 1, &armed.signing_id).await?;
    let live = get_bip448_funding_binding(&pool, "wallet", "statechain", 1)
        .await?
        .unwrap();
    update_bip448_funding_binding_observation(&pool, &live, &spent).await?;
    let armed_live = get_bip448_withdrawal_attempt(&pool, "wallet", "statechain", 1)
        .await?
        .unwrap();
    assert!(
        delete_prepared_bip448_withdrawal_attempt_for_confirmed_spend(
            &pool,
            &armed_live,
            &"62".repeat(32),
            20,
            &"61".repeat(32)
        )
        .await
        .is_err()
    );
    assert_eq!(
        get_bip448_withdrawal_attempt(&pool, "wallet", "statechain", 1)
            .await?
            .unwrap()
            .phase,
        Bip448WithdrawalPhase::FirstArmed
    );
    let output_pubkey = sample_owner_key(4).0.to_string();
    let server_public_nonce = "81".repeat(66);
    let (encoded_session, blinded_session) = real_keypath_session_pair(92)?;
    let sign_second_payload_json = serde_json::to_string(
        &mercurylib::bip448_statechain::signing_api::Bip448PartialSignatureRequestPayload {
            statechain_id: "statechain".into(),
            signed_statechain_id: armed.signed_statechain_id.clone(),
            signing_id: armed.signing_id.clone(),
            negate_seckey: 0,
            session: blinded_session,
            server_pub_nonce: server_public_nonce.clone(),
        },
    )?;
    let nonce_stored = store_bip448_withdrawal_nonce_artifacts(
        &pool,
        "wallet",
        "statechain",
        1,
        &armed.signing_id,
        &server_public_nonce,
        &"82".repeat(32),
        &output_pubkey,
        &"84".repeat(32),
        &encoded_session,
        &sign_second_payload_json,
    )
    .await?;
    assert!(
        delete_prepared_bip448_withdrawal_attempt_for_confirmed_spend(
            &pool,
            &nonce_stored,
            &"62".repeat(32),
            20,
            &"61".repeat(32),
        )
        .await
        .is_err()
    );
    let second_armed =
        arm_bip448_withdrawal_sign_second(&pool, "wallet", "statechain", 1, &armed.signing_id)
            .await?;
    assert!(
        delete_prepared_bip448_withdrawal_attempt_for_confirmed_spend(
            &pool,
            &second_armed,
            &"62".repeat(32),
            20,
            &"61".repeat(32),
        )
        .await
        .is_err()
    );
    let aggregate_signature = "92".repeat(64);
    let mut signed_transaction: bitcoin::Transaction =
        bitcoin::consensus::deserialize(&hex::decode(&armed.unsigned_tx_hex)?)?;
    let mut keypath_witness = hex::decode(&aggregate_signature)?;
    keypath_witness.push(0x01);
    signed_transaction.input[0].witness.push(keypath_witness);
    let signed_tx_hex = hex::encode(bitcoin::consensus::serialize(&signed_transaction));
    let signed = store_bip448_withdrawal_signed_artifacts(
        &pool,
        "wallet",
        "statechain",
        1,
        &armed.signing_id,
        &"91".repeat(32),
        &aggregate_signature,
        &signed_tx_hex,
        &signed_transaction.txid().to_string(),
        Bip448BroadcastStatus::Conflicted,
    )
    .await?;
    assert!(
        delete_prepared_bip448_withdrawal_attempt_for_confirmed_spend(
            &pool,
            &signed,
            &"62".repeat(32),
            20,
            &"61".repeat(32),
        )
        .await
        .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn bip448_canonical_attempt_requires_one_exact_confirmed_coin() -> Result<()> {
    for status in [
        CoinStatus::INITIALISED,
        CoinStatus::IN_MEMPOOL,
        CoinStatus::UNCONFIRMED,
        CoinStatus::IN_TRANSFER,
        CoinStatus::TRANSFERRED,
        CoinStatus::WITHDRAWING,
        CoinStatus::WITHDRAWN,
    ] {
        let pool = migrated_pool().await?;
        let attempt = ready_canonical_attempt_fixture(&pool).await?;
        let mut wallet = get_wallet(&pool, "wallet").await?;
        wallet.coins[0].status = status;
        update_wallet(&pool, &wallet).await?;
        assert!(insert_bip448_withdrawal_attempt_if_absent(&pool, &attempt)
            .await
            .is_err());
        assert!(
            list_bip448_withdrawal_attempts(&pool, "wallet", "statechain")
                .await?
                .is_empty()
        );
    }

    let absent_pool = migrated_pool().await?;
    let absent_attempt = ready_canonical_attempt_fixture(&absent_pool).await?;
    sqlx::query("DELETE FROM wallet WHERE wallet_name = 'wallet'")
        .execute(&absent_pool)
        .await?;
    assert!(
        insert_bip448_withdrawal_attempt_if_absent(&absent_pool, &absent_attempt)
            .await
            .is_err()
    );

    let empty_pool = migrated_pool().await?;
    let empty_attempt = ready_canonical_attempt_fixture(&empty_pool).await?;
    update_wallet(&empty_pool, &sample_wallet()).await?;
    assert!(
        insert_bip448_withdrawal_attempt_if_absent(&empty_pool, &empty_attempt)
            .await
            .is_err()
    );

    let unrelated_pool = migrated_pool().await?;
    let unrelated_attempt = ready_canonical_attempt_fixture(&unrelated_pool).await?;
    let mut unrelated_wallet = get_wallet(&unrelated_pool, "wallet").await?;
    unrelated_wallet.coins[0].statechain_id = Some("unrelated".into());
    update_wallet(&unrelated_pool, &unrelated_wallet).await?;
    assert!(
        insert_bip448_withdrawal_attempt_if_absent(&unrelated_pool, &unrelated_attempt,)
            .await
            .is_err()
    );

    let multiple_pool = migrated_pool().await?;
    let multiple_attempt = ready_canonical_attempt_fixture(&multiple_pool).await?;
    let mut multiple_wallet = get_wallet(&multiple_pool, "wallet").await?;
    multiple_wallet.coins.push(multiple_wallet.coins[0].clone());
    update_wallet(&multiple_pool, &multiple_wallet).await?;
    assert!(
        insert_bip448_withdrawal_attempt_if_absent(&multiple_pool, &multiple_attempt,)
            .await
            .is_err()
    );

    let confirmed_pool = migrated_pool().await?;
    let confirmed_attempt = ready_canonical_attempt_fixture(&confirmed_pool).await?;
    assert!(
        insert_bip448_withdrawal_attempt_if_absent(&confirmed_pool, &confirmed_attempt,)
            .await
            .is_ok()
    );
    Ok(())
}

#[tokio::test]
async fn bip448_canonical_attempt_requires_and_freezes_exact_close_snapshot() -> Result<()> {
    let pools = independent_migrated_pools().await?;
    let pool = pools.first.clone();
    let (_, owner, script) = accepted_binding_fixture(&pool).await?;
    let bindings = reconcile_bip448_funding_bindings(
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
    .await?;
    let canonical_binding = bindings
        .iter()
        .find(|binding| binding.binding_index == 0)
        .unwrap()
        .clone();
    let duplicate_binding = bindings
        .iter()
        .find(|binding| binding.binding_index == 1)
        .unwrap()
        .clone();
    let spent_duplicate = Bip448BindingObservation {
        observation_status: Bip448ObservationStatus::SpentConfirmed,
        spend_txid: Some("62".repeat(32)),
        spend_height: Some(19),
        ..sample_binding_observation("11", 1, 70_000, &script)
    };
    update_bip448_funding_binding_observation(&pool, &duplicate_binding, &spent_duplicate).await?;
    let close_tip_hash = "61".repeat(32);
    persist_bip448_scan_state(
        &pool,
        "wallet",
        &script,
        &Bip448ScanCursor {
            coverage_start_height: 0,
            scan_revision: 0,
            last_scanned_height: 20,
            last_scanned_block_hash: close_tip_hash.clone(),
        },
        &[],
    )
    .await?;
    let snapshot = match classify_bip448_close_gate(&pool, "wallet", "statechain").await? {
        Bip448CloseGate::Ready {
            closing_bindings_json,
            ..
        } => closing_bindings_json,
        blocked => return Err(anyhow!("unexpected canonical close blocker: {blocked:?}")),
    };
    assert!(snapshot.contains("\"kind\":\"IndependentSpend\""));

    let mut canonical_attempt = sample_duplicate_attempt(&canonical_binding);
    canonical_attempt.attempt_kind = Bip448WithdrawalAttemptKind::Canonical;
    canonical_attempt.completion_status = Bip448CompletionStatus::Open;
    let wallet = get_wallet(&pool, "wallet").await?;
    let coin = wallet
        .coins
        .first()
        .ok_or_else(|| anyhow!("canonical destination fixture Coin is missing"))?;
    canonical_attempt.destination_address = coin.backup_address.clone();
    let nonce = create_bip448_keypath_nonces(coin)?;
    canonical_attempt.client_secret_nonce = nonce.secret_nonce;
    canonical_attempt.client_public_nonce = nonce.public_nonce;
    canonical_attempt.blinding_factor = nonce.blinding_factor;
    canonical_attempt.closing_tip_height = Some(20);
    canonical_attempt.closing_tip_hash = Some(close_tip_hash.clone());
    canonical_attempt.closing_bindings_json = Some(snapshot.clone());
    let mut malformed = canonical_attempt.clone();
    malformed.closing_bindings_json = Some(format!(" {snapshot}"));
    assert!(
        insert_bip448_withdrawal_attempt_if_absent(&pool, &malformed)
            .await
            .is_err()
    );

    let mut illegal_duplicate_snapshot = sample_duplicate_attempt(&duplicate_binding);
    illegal_duplicate_snapshot.closing_tip_height = Some(20);
    illegal_duplicate_snapshot.closing_tip_hash = Some(close_tip_hash.clone());
    illegal_duplicate_snapshot.closing_bindings_json = Some(snapshot.clone());
    assert!(bip448_funding::validate_withdrawal_attempt(&illegal_duplicate_snapshot).is_err());

    let stored = insert_bip448_withdrawal_attempt_if_absent(&pool, &canonical_attempt).await?;
    assert!(
        delete_prepared_bip448_withdrawal_attempt_for_confirmed_spend(
            &pool,
            &stored,
            &"62".repeat(32),
            20,
            &close_tip_hash,
        )
        .await
        .is_err(),
        "canonical index 0 is never compare-deletable"
    );
    assert_eq!(
        insert_bip448_withdrawal_attempt_if_absent(&pool, &canonical_attempt).await?,
        stored
    );
    let mut conflict = canonical_attempt.clone();
    conflict.destination_address = "different-destination".into();
    assert!(insert_bip448_withdrawal_attempt_if_absent(&pool, &conflict)
        .await
        .is_err());

    arm_bip448_withdrawal_sign_first(
        &pool,
        "wallet",
        "statechain",
        0,
        &canonical_attempt.signing_id,
    )
    .await?;
    let secp = Secp256k1::new();
    let server_nonce_key = SecretKey::from_secret_bytes([93u8; 32])?;
    let (_, server_public_nonce) = new_musig_nonce_pair(
        &secp,
        MusigSessionId::assume_unique_per_nonce_gen([94u8; 32]),
        None,
        Some(server_nonce_key),
        server_nonce_key.public_key(&secp),
        None,
        None,
    )?;
    let server_public_nonce = hex::encode(server_public_nonce.serialize());
    let (encoded_session, blinded_session) = real_keypath_session_pair(93)?;
    let sign_second_payload_json = serde_json::to_string(
        &mercurylib::bip448_statechain::signing_api::Bip448PartialSignatureRequestPayload {
            statechain_id: "statechain".into(),
            signed_statechain_id: canonical_attempt.signed_statechain_id.clone(),
            signing_id: canonical_attempt.signing_id.clone(),
            negate_seckey: 0,
            session: blinded_session,
            server_pub_nonce: server_public_nonce.clone(),
        },
    )?;
    store_bip448_withdrawal_nonce_artifacts(
        &pool,
        "wallet",
        "statechain",
        0,
        &canonical_attempt.signing_id,
        &server_public_nonce,
        &"82".repeat(32),
        &sample_owner_key(4).0.to_string(),
        &"84".repeat(32),
        &encoded_session,
        &sign_second_payload_json,
    )
    .await?;
    arm_bip448_withdrawal_sign_second(
        &pool,
        "wallet",
        "statechain",
        0,
        &canonical_attempt.signing_id,
    )
    .await?;
    let aggregate_signature = "92".repeat(64);
    let mut signed_transaction: bitcoin::Transaction =
        bitcoin::consensus::deserialize(&hex::decode(&canonical_attempt.unsigned_tx_hex)?)?;
    let mut keypath_witness = hex::decode(&aggregate_signature)?;
    keypath_witness.push(0x01);
    signed_transaction
        .input
        .get_mut(0)
        .ok_or_else(|| anyhow!("sample canonical withdrawal has no input"))?
        .witness
        .push(keypath_witness);
    store_bip448_withdrawal_signed_artifacts(
        &pool,
        "wallet",
        "statechain",
        0,
        &canonical_attempt.signing_id,
        &"91".repeat(32),
        &aggregate_signature,
        &hex::encode(bitcoin::consensus::serialize(&signed_transaction)),
        &signed_transaction.txid().to_string(),
        Bip448BroadcastStatus::NotBroadcast,
    )
    .await?;
    update_bip448_withdrawal_broadcast_status(
        &pool,
        "wallet",
        "statechain",
        0,
        &canonical_attempt.signing_id,
        Bip448BroadcastStatus::NotBroadcast,
        Bip448BroadcastStatus::Accepted,
    )
    .await?;
    let persisted_wallet = persist_bip448_canonical_withdrawal_wallet(
        &pool,
        "wallet",
        "statechain",
        &canonical_attempt.signing_id,
    )
    .await?;
    let persisted_coin = persisted_wallet
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some("statechain"))
        .ok_or_else(|| anyhow!("persisted canonical Coin is missing"))?;
    assert_eq!(persisted_coin.status, CoinStatus::WITHDRAWING);
    assert_eq!(
        persisted_coin.tx_withdraw.as_deref(),
        Some(signed_transaction.txid().to_string().as_str())
    );
    assert_eq!(
        persisted_wallet
            .activities
            .iter()
            .filter(|activity| activity.utxo == signed_transaction.txid().to_string())
            .count(),
        1
    );
    update_bip448_withdrawal_completion_status(
        &pool,
        "wallet",
        "statechain",
        &canonical_attempt.signing_id,
        Bip448CompletionStatus::Open,
        Bip448CompletionStatus::CloseArmed,
    )
    .await?;
    let mut current = Bip448BroadcastStatus::Accepted;
    for next in [
        Bip448BroadcastStatus::Confirmed,
        Bip448BroadcastStatus::NeedsRebroadcast,
        Bip448BroadcastStatus::Conflicting,
        Bip448BroadcastStatus::Conflicted,
        Bip448BroadcastStatus::Accepted,
    ] {
        let row = update_bip448_withdrawal_broadcast_status(
            &pool,
            "wallet",
            "statechain",
            0,
            &canonical_attempt.signing_id,
            current,
            next,
        )
        .await?;
        assert_eq!(row.completion_status, Bip448CompletionStatus::CloseArmed);
        if matches!(
            next,
            Bip448BroadcastStatus::NeedsRebroadcast
                | Bip448BroadcastStatus::Conflicting
                | Bip448BroadcastStatus::Conflicted
        ) {
            assert!(update_bip448_withdrawal_completion_status(
                &pool,
                "wallet",
                "statechain",
                &canonical_attempt.signing_id,
                Bip448CompletionStatus::CloseArmed,
                Bip448CompletionStatus::Closed,
            )
            .await
            .is_err());
            assert_eq!(
                get_bip448_withdrawal_attempt(&pool, "wallet", "statechain", 0)
                    .await?
                    .unwrap()
                    .completion_status,
                Bip448CompletionStatus::CloseArmed
            );
        }
        current = next;
    }

    let live_duplicate = get_bip448_funding_binding(&pool, "wallet", "statechain", 1)
        .await?
        .ok_or_else(|| anyhow!("frozen independent-spend binding is missing"))?;
    let conflict_observation = Bip448BindingObservation {
        txid: live_duplicate.txid.clone(),
        vout: live_duplicate.vout,
        value_sats: live_duplicate.value_sats,
        script_pubkey: live_duplicate.script_pubkey.clone(),
        observation_status: Bip448ObservationStatus::SpentUnconfirmed,
        funding_height: live_duplicate.funding_height,
        spend_txid: live_duplicate.spend_txid.clone(),
        spend_height: live_duplicate.spend_height,
        last_scanned_height: live_duplicate.last_scanned_height,
    };
    let confirmed_observation = Bip448BindingObservation {
        observation_status: Bip448ObservationStatus::SpentConfirmed,
        ..conflict_observation.clone()
    };
    let completion_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    // A passive conflict that linearizes before the final gate prevents
    // the irreversible callback entirely.
    let conflicted =
        update_bip448_funding_binding_observation(&pool, &live_duplicate, &conflict_observation)
            .await?;
    let blocked_completion_calls = completion_calls.clone();
    let blocked = with_bip448_canonical_completion_fence(
        &pool,
        "wallet",
        "statechain",
        &canonical_attempt.signing_id,
        Duration::from_secs(5),
        move |_| async move {
            blocked_completion_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok::<_, anyhow::Error>(())
        },
    )
    .await;
    assert!(
        blocked.is_err(),
        "a committed frozen-binding conflict passed the final gate"
    );
    assert_eq!(
        completion_calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a committed frozen-binding conflict permitted completion"
    );
    let restored =
        update_bip448_funding_binding_observation(&pool, &conflicted, &confirmed_observation)
            .await?;

    // At the exact post-validation/pre-completion interval, a second real
    // pool connection tries to commit the same passive conflict. It must
    // remain behind the retained mutation fence until the completion
    // boundary has linearized.
    let hook = Arc::new(Bip448BeginImmediateTestHook::default());
    let task_hook = hook.clone();
    let second_pool = pools.second.clone();
    let writer_commits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let task_writer_commits = writer_commits.clone();
    let fenced_hook = hook.clone();
    let fenced_writer_commits = writer_commits.clone();
    let fenced_completion_calls = completion_calls.clone();
    let (completion_attempt, writer) = with_bip448_canonical_completion_fence(
        &pool,
        "wallet",
        "statechain",
        &canonical_attempt.signing_id,
        Duration::from_secs(5),
        move |_| async move {
            let writer = tokio::spawn(BIP448_BEGIN_IMMEDIATE_TEST_HOOK.scope(
                task_hook,
                async move {
                    let updated = update_bip448_funding_binding_observation(
                        &second_pool,
                        &restored,
                        &conflict_observation,
                    )
                    .await?;
                    task_writer_commits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok::<_, anyhow::Error>(updated)
                },
            ));
            assert_begin_is_contested(&fenced_hook).await?;
            if fenced_writer_commits.load(std::sync::atomic::Ordering::SeqCst) != 0 {
                return Err(anyhow!(
                    "passive conflict committed before the completion boundary"
                ));
            }
            fenced_completion_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if fenced_hook
                .after_emitted
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                return Err(anyhow!(
                    "passive writer acquired during the completion request"
                ));
            }
            Ok::<_, anyhow::Error>(writer)
        },
    )
    .await?;
    let writer = writer?;
    assert_eq!(
        completion_attempt.completion_status,
        Bip448CompletionStatus::CloseArmed
    );
    hook.after_acquire.notified().await;
    let conflicted_after_boundary = writer.await??;
    assert_eq!(
        writer_commits.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "passive writer did not commit after the completion boundary"
    );

    // Once that later conflict is durable, a retry cannot cross the same
    // gate or issue another completion request.
    let retry_completion_calls = completion_calls.clone();
    let retry = with_bip448_canonical_completion_fence(
        &pool,
        "wallet",
        "statechain",
        &canonical_attempt.signing_id,
        Duration::from_secs(5),
        move |_| async move {
            retry_completion_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok::<_, anyhow::Error>(())
        },
    )
    .await;
    assert!(
        retry.is_err(),
        "late frozen-binding conflict passed the retry gate"
    );
    assert_eq!(
        completion_calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "late frozen-binding conflict permitted another completion"
    );
    let restored_after_boundary = update_bip448_funding_binding_observation(
        &pool,
        &conflicted_after_boundary,
        &confirmed_observation,
    )
    .await?;

    // A callback that never resolves is bounded while holding the same
    // real BEGIN IMMEDIATE fence. The waiting writer cannot acquire until
    // timeout rolls the guard back, and its durable mutation must then
    // prevent a retry from invoking completion again.
    let timeout_hook = Arc::new(Bip448BeginImmediateTestHook::default());
    let timeout_task_hook = timeout_hook.clone();
    let timeout_callback_started = Arc::new(tokio::sync::Notify::new());
    let timeout_writer_started = timeout_callback_started.clone();
    let timeout_second_pool = pools.second.clone();
    let timeout_conflict_observation = Bip448BindingObservation {
        observation_status: Bip448ObservationStatus::SpentUnconfirmed,
        ..confirmed_observation.clone()
    };
    let timeout_restore_observation = confirmed_observation.clone();
    let timeout_writer = tokio::spawn(BIP448_BEGIN_IMMEDIATE_TEST_HOOK.scope(
        timeout_task_hook,
        async move {
            timeout_writer_started.notified().await;
            update_bip448_funding_binding_observation(
                &timeout_second_pool,
                &restored_after_boundary,
                &timeout_conflict_observation,
            )
            .await
        },
    ));
    let timeout_callback_hook = timeout_hook.clone();
    let timeout_callback_signal = timeout_callback_started.clone();
    let timeout_writer_contested = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let timed_writer_contested = timeout_writer_contested.clone();
    let timeout_completion_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let timed_completion_calls = timeout_completion_calls.clone();
    let (timed_attempt, timed_result) = with_bip448_canonical_completion_fence(
        &pool,
        "wallet",
        "statechain",
        &canonical_attempt.signing_id,
        Duration::from_secs(1),
        move |_| async move {
            timed_completion_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            timeout_callback_signal.notify_one();
            assert_begin_is_contested(&timeout_callback_hook).await?;
            timed_writer_contested.store(true, std::sync::atomic::Ordering::SeqCst);
            std::future::pending::<Result<()>>().await
        },
    )
    .await?;
    assert_eq!(
        timed_attempt.completion_status,
        Bip448CompletionStatus::CloseArmed
    );
    let timeout_error = timed_result.expect_err("never-resolving completion did not time out");
    assert!(
        timeout_error
            .to_string()
            .contains("canonical completion timed out"),
        "unexpected completion-timeout error: {timeout_error:#}"
    );
    assert!(
        timeout_writer_contested.load(std::sync::atomic::Ordering::SeqCst),
        "writer did not contend while the never-resolving callback held the fence"
    );
    timeout_hook.after_acquire.notified().await;
    let conflicted_after_timeout = timeout_writer.await??;
    assert_eq!(
        conflicted_after_timeout.observation_status,
        Bip448ObservationStatus::SpentUnconfirmed,
        "waiting writer did not commit its durable mutation after timeout"
    );
    let armed_after_timeout = get_bip448_withdrawal_attempt(&pool, "wallet", "statechain", 0)
        .await?
        .ok_or_else(|| anyhow!("canonical attempt disappeared after completion timeout"))?;
    assert_eq!(
        armed_after_timeout.completion_status,
        Bip448CompletionStatus::CloseArmed,
        "completion timeout changed the indeterminate journal to Closed"
    );

    let retry_after_timeout_calls = timeout_completion_calls.clone();
    let retry_after_timeout = with_bip448_canonical_completion_fence(
        &pool,
        "wallet",
        "statechain",
        &canonical_attempt.signing_id,
        Duration::from_secs(5),
        move |_| async move {
            retry_after_timeout_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok::<_, anyhow::Error>(())
        },
    )
    .await;
    assert!(
        retry_after_timeout.is_err(),
        "durable mutation after timeout passed the retry snapshot gate"
    );
    assert_eq!(
        timeout_completion_calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "retry invoked completion after the timeout writer changed frozen facts"
    );
    let restored_after_timeout = update_bip448_funding_binding_observation(
        &pool,
        &conflicted_after_timeout,
        &timeout_restore_observation,
    )
    .await?;

    // Callback errors explicitly roll back, while cancellation and panic
    // exercise Transaction's rollback-on-drop path. Each case must release
    // the writer lock without changing the CloseArmed journal.
    let (error_attempt, callback_error) = with_bip448_canonical_completion_fence(
        &pool,
        "wallet",
        "statechain",
        &canonical_attempt.signing_id,
        Duration::from_secs(5),
        move |_| async move { Err::<(), _>(anyhow!("injected completion failure")) },
    )
    .await?;
    assert_eq!(
        error_attempt.completion_status,
        Bip448CompletionStatus::CloseArmed
    );
    assert!(callback_error
        .expect_err("completion callback error was discarded")
        .to_string()
        .contains("injected completion failure"));
    let error_release_guard = tokio::time::timeout(
        Duration::from_secs(2),
        begin_bip448_mutation_guard(&pools.second),
    )
    .await
    .context("callback error retained the BIP448 mutation fence")??;
    error_release_guard.commit().await?;

    let cancellation_started = Arc::new(tokio::sync::Notify::new());
    let cancellation_signal = cancellation_started.clone();
    let cancellation_pool = pool.clone();
    let cancellation_signing_id = canonical_attempt.signing_id.clone();
    let cancellation_task = tokio::spawn(async move {
        with_bip448_canonical_completion_fence(
            &cancellation_pool,
            "wallet",
            "statechain",
            &cancellation_signing_id,
            Duration::from_secs(5),
            move |_| async move {
                cancellation_signal.notify_one();
                std::future::pending::<Result<()>>().await
            },
        )
        .await
    });
    cancellation_started.notified().await;
    cancellation_task.abort();
    assert!(
        cancellation_task.await.unwrap_err().is_cancelled(),
        "completion-fence cancellation did not cancel its task"
    );
    let cancellation_release_guard = tokio::time::timeout(
        Duration::from_secs(2),
        begin_bip448_mutation_guard(&pools.second),
    )
    .await
    .context("cancelled completion retained the BIP448 mutation fence")??;
    cancellation_release_guard.commit().await?;

    let panic_pool = pool.clone();
    let panic_signing_id = canonical_attempt.signing_id.clone();
    let panic_task = tokio::spawn(async move {
        with_bip448_canonical_completion_fence(
            &panic_pool,
            "wallet",
            "statechain",
            &panic_signing_id,
            Duration::from_secs(5),
            move |_| async move {
                panic!("injected completion panic");
                #[allow(unreachable_code)]
                Ok::<(), anyhow::Error>(())
            },
        )
        .await
    });
    assert!(
        panic_task.await.unwrap_err().is_panic(),
        "completion callback panic did not unwind its task"
    );
    let panic_release_guard = tokio::time::timeout(
        Duration::from_secs(2),
        begin_bip448_mutation_guard(&pools.second),
    )
    .await
    .context("panicked completion retained the BIP448 mutation fence")??;
    panic_release_guard.commit().await?;

    assert_eq!(
        get_bip448_funding_binding(&pool, "wallet", "statechain", 1)
            .await?
            .ok_or_else(|| anyhow!("frozen binding disappeared after fence lifecycle checks"))?,
        restored_after_timeout
    );
    assert_eq!(
        get_bip448_withdrawal_attempt(&pool, "wallet", "statechain", 0)
            .await?
            .ok_or_else(|| anyhow!("canonical attempt disappeared after fence lifecycle checks"))?
            .completion_status,
        Bip448CompletionStatus::CloseArmed
    );

    update_bip448_withdrawal_completion_status(
        &pool,
        "wallet",
        "statechain",
        &canonical_attempt.signing_id,
        Bip448CompletionStatus::CloseArmed,
        Bip448CompletionStatus::Closed,
    )
    .await?;
    assert!(update_bip448_withdrawal_completion_status(
        &pool,
        "wallet",
        "statechain",
        &canonical_attempt.signing_id,
        Bip448CompletionStatus::Closed,
        Bip448CompletionStatus::Open,
    )
    .await
    .is_err());

    let live_bindings = list_bip448_funding_bindings(&pool, "wallet", "statechain").await?;
    let mut guard = begin_bip448_mutation_guard(&pool).await?;
    let observed = guard
        .reconcile_withdrawal_attempt_observations("wallet", "statechain", &live_bindings)
        .await?;
    guard.commit().await?;
    let closed = observed
        .iter()
        .find(|attempt| attempt.binding_index == 0)
        .ok_or_else(|| anyhow!("closed canonical attempt is missing"))?;
    assert_eq!(
        closed.broadcast_status,
        Bip448BroadcastStatus::NeedsRebroadcast
    );
    assert_eq!(closed.completion_status, Bip448CompletionStatus::Closed);

    let late = sample_binding_observation("12", 2, 60_000, &script);
    let rows = reconcile_bip448_funding_bindings(
        &pool,
        "wallet",
        "statechain",
        &owner.to_string(),
        1,
        &[
            sample_binding_observation("34", 0, 100_000, &script),
            spent_duplicate,
            late,
        ],
    )
    .await?;
    let late_binding = rows
        .into_iter()
        .find(|binding| binding.txid == "12".repeat(32))
        .unwrap();
    assert!(insert_bip448_withdrawal_attempt_if_absent(
        &pool,
        &sample_duplicate_attempt(&late_binding)
    )
    .await
    .is_err());
    assert!(validate_bip448_canonical_close_snapshot(
        &pool,
        "wallet",
        "statechain",
        &canonical_attempt.signing_id
    )
    .await
    .is_err());
    assert_eq!(
        get_bip448_withdrawal_attempt(&pool, "wallet", "statechain", 0)
            .await?
            .unwrap()
            .closing_bindings_json,
        Some(snapshot),
        "late discovery never rewrites the frozen canonical snapshot"
    );
    Ok(())
}

#[tokio::test]
async fn bip448_close_gate_classifies_every_observation_phase_and_broadcast_blocker() -> Result<()>
{
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
    .unwrap();
    for status in [
        Bip448ObservationStatus::Mempool,
        Bip448ObservationStatus::Unconfirmed,
        Bip448ObservationStatus::Confirmed,
        Bip448ObservationStatus::SpentMempool,
        Bip448ObservationStatus::SpentUnconfirmed,
        Bip448ObservationStatus::Absent,
    ] {
        let mut binding = duplicate.clone();
        binding.observation_status = status;
        binding.funding_height = match status {
            Bip448ObservationStatus::Mempool
            | Bip448ObservationStatus::SpentMempool
            | Bip448ObservationStatus::Absent => None,
            _ => Some(10),
        };
        binding.spend_txid = matches!(
            status,
            Bip448ObservationStatus::SpentMempool | Bip448ObservationStatus::SpentUnconfirmed
        )
        .then(|| "81".repeat(32));
        binding.spend_height = (status == Bip448ObservationStatus::SpentUnconfirmed).then_some(11);
        assert!(
            matches!(
                bip448_funding::evaluate_bip448_close_gate(&[binding], &[])?,
                Bip448CloseGate::Blocked { .. }
            ),
            "{status:?} did not block"
        );
    }
    let mut independently_spent = duplicate.clone();
    independently_spent.observation_status = Bip448ObservationStatus::SpentConfirmed;
    independently_spent.spend_txid = Some("82".repeat(32));
    independently_spent.spend_height = Some(11);
    assert!(matches!(
        bip448_funding::evaluate_bip448_close_gate(&[independently_spent.clone()], &[])?,
        Bip448CloseGate::Ready { .. }
    ));

    let mut attempt = sample_duplicate_attempt(&duplicate);
    for phase in [
        Bip448WithdrawalPhase::Prepared,
        Bip448WithdrawalPhase::FirstArmed,
        Bip448WithdrawalPhase::NonceStored,
        Bip448WithdrawalPhase::SecondArmed,
    ] {
        attempt.phase = phase;
        assert!(matches!(
            bip448_funding::evaluate_bip448_close_gate(&[duplicate.clone()], &[attempt.clone()])?,
            Bip448CloseGate::Blocked { .. }
        ));
    }
    attempt.phase = Bip448WithdrawalPhase::Signed;
    attempt.txid = Some("83".repeat(32));
    for status in [
        Bip448BroadcastStatus::NotBroadcast,
        Bip448BroadcastStatus::NeedsRebroadcast,
        Bip448BroadcastStatus::Conflicting,
    ] {
        attempt.broadcast_status = status;
        assert!(matches!(
            bip448_funding::evaluate_bip448_close_gate(&[duplicate.clone()], &[attempt.clone()])?,
            Bip448CloseGate::Blocked { .. }
        ));
    }
    for status in [
        Bip448BroadcastStatus::Accepted,
        Bip448BroadcastStatus::Confirmed,
    ] {
        attempt.broadcast_status = status;
        assert!(matches!(
            bip448_funding::evaluate_bip448_close_gate(&[duplicate.clone()], &[attempt.clone()])?,
            Bip448CloseGate::Ready { .. }
        ));
    }
    attempt.broadcast_status = Bip448BroadcastStatus::Conflicted;
    assert!(matches!(
        bip448_funding::evaluate_bip448_close_gate(&[independently_spent], &[attempt])?,
        Bip448CloseGate::Ready { .. }
    ));
    Ok(())
}

#[tokio::test]
async fn bip448_storage_close_gate_checks_transfer_pending_message_and_coin_blockers() -> Result<()>
{
    let pool = migrated_pool().await?;
    let (record, owner, script) = accepted_binding_fixture(&pool).await?;
    reconcile_bip448_funding_bindings(
        &pool,
        "wallet",
        "statechain",
        &owner.to_string(),
        1,
        &[sample_binding_observation("34", 0, 100_000, &script)],
    )
    .await?;
    assert!(matches!(
        classify_bip448_close_gate(&pool, "wallet", "statechain").await?,
        Bip448CloseGate::Ready { .. }
    ));

    let pending = Bip448PendingDepositSigning {
        wallet_name: "wallet".into(),
        statechain_id: "statechain".into(),
        funding_txid: record.funding_outpoint.txid.clone(),
        funding_vout: record.funding_outpoint.vout,
        funding_value_sats: record.funding_outpoint.value_sats,
        update_template_hash: "41".repeat(32),
        settlement_template_hash: "42".repeat(32),
        state_locktime: 700_000_043,
        signing_id: "43".repeat(32),
        client_secret_nonce: "44".repeat(132),
        client_public_nonce: "45".repeat(66),
        blinding_factor: "46".repeat(32),
        server_public_nonce: None,
    };
    insert_bip448_pending_transfer_signing_if_absent(&pool, &pending).await?;
    assert!(matches!(
        classify_bip448_close_gate(&pool, "wallet", "statechain").await?,
        Bip448CloseGate::Blocked { reasons }
            if reasons == vec![Bip448CloseBlockReason::PendingTransferSigning]
    ));
    delete_bip448_pending_transfer_signing(&pool, "wallet", "statechain", &pending.signing_id)
        .await?;

    let recipient = sample_owner_key(3).0.to_string();
    insert_or_update_bip448_transfer_msg(
        &pool,
        "wallet",
        &recipient,
        &sample_bip448_transfer_msg(),
    )
    .await?;
    assert!(matches!(
        classify_bip448_close_gate(&pool, "wallet", "statechain").await?,
        Bip448CloseGate::Blocked { reasons }
            if reasons == vec![Bip448CloseBlockReason::OutgoingTransferMessage {
                recipient_auth_pubkey: recipient.clone()
            }]
    ));
    delete_bip448_transfer_msgs(&pool, "wallet", "statechain").await?;

    let mut wallet = get_wallet(&pool, "wallet").await?;
    let mut in_transfer = wallet.get_new_coin()?;
    in_transfer.statechain_protocol = Some("bip448".into());
    in_transfer.statechain_id = Some("statechain".into());
    in_transfer.status = CoinStatus::IN_TRANSFER;
    wallet.coins.push(in_transfer);
    update_wallet(&pool, &wallet).await?;
    assert!(matches!(
        classify_bip448_close_gate(&pool, "wallet", "statechain").await?,
        Bip448CloseGate::Blocked { reasons }
            if reasons == vec![Bip448CloseBlockReason::CoinInTransfer]
    ));
    wallet.coins.clear();
    update_wallet(&pool, &wallet).await?;

    let intent = sample_transfer_intent("e1");
    insert_bip448_transfer_intent_if_absent(&pool, &intent).await?;
    assert!(matches!(
        classify_bip448_close_gate(&pool, "wallet", "statechain").await?,
        Bip448CloseGate::Blocked { reasons }
            if reasons == vec![Bip448CloseBlockReason::ActiveTransferIntent {
                intent_id: intent.intent_id.clone()
            }]
    ));
    Ok(())
}
