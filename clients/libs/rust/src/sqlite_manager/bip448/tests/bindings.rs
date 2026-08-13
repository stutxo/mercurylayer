use super::super::accepted::upsert_bip448_statechain_record;
use super::support::*;

fn set_valid_withdrawal_lifecycle(coin: &mut Coin, status: CoinStatus) -> Result<()> {
    let nonce = create_bip448_keypath_nonces(coin)?;
    coin.secret_nonce = Some(nonce.secret_nonce);
    coin.public_nonce = Some(nonce.public_nonce);
    coin.blinding_factor = Some(nonce.blinding_factor);
    let secp = Secp256k1::new();
    let server_nonce_key = SecretKey::from_secret_bytes([99u8; 32])?;
    let (_, server_public_nonce) = new_musig_nonce_pair(
        &secp,
        MusigSessionId::assume_unique_per_nonce_gen([98u8; 32]),
        None,
        Some(server_nonce_key),
        server_nonce_key.public_key(&secp),
        None,
        None,
    )?;
    coin.server_public_nonce = Some(hex::encode(server_public_nonce.serialize()));
    coin.tx_withdraw = Some("62".repeat(32));
    coin.withdrawal_address = Some(coin.backup_address.clone());
    coin.status = status;
    Ok(())
}

#[tokio::test]
async fn bip448_binding_indices_are_canonical_deterministic_stable_and_checked() -> Result<()> {
    let pool = migrated_pool().await?;
    let (record, owner, script) = accepted_binding_fixture(&pool).await?;
    let canonical = sample_binding_observation("34", 0, 100_000, &script);
    let one = sample_binding_observation("11", 1, 70_000, &script);
    let two = sample_binding_observation("22", 2, 80_000, &script);
    let bindings = reconcile_bip448_funding_bindings(
        &pool,
        "wallet",
        "statechain",
        &owner.to_string(),
        1,
        &[two.clone(), canonical.clone(), one.clone()],
    )
    .await?;
    assert_eq!(
        bindings
            .iter()
            .map(|row| (row.binding_index, row.txid.clone()))
            .collect::<Vec<_>>(),
        vec![
            (0, record.funding_outpoint.txid.clone()),
            (1, one.txid.clone()),
            (2, two.txid.clone())
        ]
    );
    let replay = reconcile_bip448_funding_bindings(
        &pool,
        "wallet",
        "statechain",
        &owner.to_string(),
        1,
        &[one.clone(), canonical.clone()],
    )
    .await?;
    assert_eq!(
        replay.len(),
        3,
        "an absent observation never deletes or renumbers a binding"
    );
    let three = sample_binding_observation("01", 3, 90_000, &script);
    let rows = reconcile_bip448_funding_bindings(
        &pool,
        "wallet",
        "statechain",
        &owner.to_string(),
        1,
        &[canonical.clone(), three.clone()],
    )
    .await?;
    assert_eq!(
        rows.iter()
            .find(|row| row.txid == three.txid)
            .unwrap()
            .binding_index,
        3
    );

    let before = rows.clone();
    let mut conflict = canonical.clone();
    conflict.value_sats += 1;
    assert!(reconcile_bip448_funding_bindings(
        &pool,
        "wallet",
        "statechain",
        &owner.to_string(),
        1,
        &[conflict]
    )
    .await
    .is_err());
    assert_eq!(
        list_bip448_funding_bindings(&pool, "wallet", "statechain").await?,
        before
    );
    for (status, spend_txid, spend_height) in [
        ("Unconfirmed", None, None),
        ("Confirmed", None, None),
        ("SpentUnconfirmed", Some("aa".repeat(32)), Some(11_i64)),
        ("SpentConfirmed", Some("aa".repeat(32)), Some(11_i64)),
    ] {
        let result = sqlx::query(
            "UPDATE bip448_funding_bindings SET observation_status=$1,\
            funding_height=NULL,spend_txid=$2,spend_height=$3 WHERE wallet_name='wallet' \
            AND statechain_id='statechain' AND binding_index=1",
        )
        .bind(status)
        .bind(spend_txid)
        .bind(spend_height)
        .execute(&pool)
        .await;
        assert!(result.is_err(), "{status} accepted a null funding height");
    }
    assert!(sqlx::query(
        "UPDATE bip448_funding_bindings SET role='DebugCanonical' WHERE wallet_name='wallet'"
    )
    .execute(&pool)
    .await
    .is_err());
    assert!(sqlx::query("UPDATE bip448_funding_bindings SET binding_index=4294967296 WHERE wallet_name='wallet' AND binding_index=3")
        .execute(&pool).await.is_err());
    let moved = sqlx::query(
        "UPDATE bip448_funding_bindings SET binding_index=4294967295 \
         WHERE wallet_name='wallet' AND statechain_id='statechain' AND binding_index=3",
    )
    .execute(&pool)
    .await?;
    assert_eq!(moved.rows_affected(), 1);
    let max_replay = reconcile_bip448_funding_bindings(
        &pool,
        "wallet",
        "statechain",
        &owner.to_string(),
        1,
        &[canonical.clone(), three.clone()],
    )
    .await?;
    assert_eq!(
        max_replay
            .iter()
            .find(|row| row.txid == three.txid)
            .unwrap()
            .binding_index,
        u32::MAX,
        "u32::MAX remains replayable when no allocation is required"
    );
    let four = sample_binding_observation("02", 4, 95_000, &script);
    let before_overflow = max_replay;
    assert!(reconcile_bip448_funding_bindings(
        &pool,
        "wallet",
        "statechain",
        &owner.to_string(),
        1,
        &[canonical, four]
    )
    .await
    .is_err());
    assert_eq!(
        list_bip448_funding_bindings(&pool, "wallet", "statechain").await?,
        before_overflow,
        "allocation overflow rolls back every earlier observation update"
    );
    Ok(())
}

#[tokio::test]
async fn passive_binding_sync_requires_one_exact_current_generation_coin_before_writes(
) -> Result<()> {
    for status in [CoinStatus::WITHDRAWING, CoinStatus::WITHDRAWN] {
        let pool = migrated_pool().await?;
        let (record, owner, script) = accepted_binding_fixture(&pool).await?;
        let mut wallet = get_wallet(&pool, "wallet").await?;
        set_valid_withdrawal_lifecycle(&mut wallet.coins[0], status.clone())?;
        update_wallet(&pool, &wallet).await?;
        let raw_wallet = get_bip448_raw_wallet_json(&pool, "wallet").await?;
        assert_eq!(
            recover_bip448_initial_acceptance_wallet(&pool, "wallet", &raw_wallet).await?,
            Bip448InitialAcceptanceRecovery::Unchanged
        );
        assert_eq!(
            get_bip448_raw_wallet_json(&pool, "wallet").await?,
            raw_wallet
        );
        let bindings = reconcile_bip448_funding_bindings(
            &pool,
            "wallet",
            "statechain",
            &owner.to_string(),
            1,
            &[sample_binding_observation(
                "34",
                record.funding_outpoint.vout,
                record.funding_outpoint.value_sats,
                &script,
            )],
        )
        .await?;
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].owner_user_pubkey, owner.to_string());
        assert_eq!(bindings[0].owner_state_number, 1);
    }

    for case in ["zero", "multiple", "malformed", "mismatched-owner"] {
        let pool = migrated_pool().await?;
        let (record, owner, script) = accepted_binding_fixture(&pool).await?;
        let cursor = Bip448ScanCursor {
            coverage_start_height: 0,
            scan_revision: 0,
            last_scanned_height: 20,
            last_scanned_block_hash: "61".repeat(32),
        };
        persist_bip448_scan_state(&pool, "wallet", &script, &cursor, &[]).await?;
        match case {
            "zero" => {
                let mut wallet = get_wallet(&pool, "wallet").await?;
                wallet.coins.clear();
                update_wallet(&pool, &wallet).await?;
            }
            "multiple" => {
                let mut wallet = get_wallet(&pool, "wallet").await?;
                wallet.coins.push(wallet.coins[0].clone());
                update_wallet(&pool, &wallet).await?;
            }
            "malformed" => {
                let updated = sqlx::query(
                    "UPDATE wallet SET wallet_json='{not-json' WHERE wallet_name='wallet'",
                )
                .execute(&pool)
                .await?;
                assert_eq!(updated.rows_affected(), 1);
            }
            "mismatched-owner" => {
                let mut wallet = get_wallet(&pool, "wallet").await?;
                let mut unrelated = wallet.get_new_coin()?;
                unrelated.statechain_protocol = Some(BIP448_COIN_PROTOCOL.to_string());
                unrelated.statechain_id = Some("statechain".to_string());
                wallet.coins = vec![unrelated];
                update_wallet(&pool, &wallet).await?;
            }
            _ => unreachable!(),
        }
        let before = capture_bip448_sync_base(&pool, "wallet", &script).await?;
        let error = reconcile_bip448_funding_bindings(
            &pool,
            "wallet",
            "statechain",
            &owner.to_string(),
            1,
            &[sample_binding_observation(
                "34",
                record.funding_outpoint.vout,
                record.funding_outpoint.value_sats,
                &script,
            )],
        )
        .await
        .err()
        .ok_or_else(|| anyhow!("{case} passive wallet unexpectedly reconciled"))?;
        assert!(
            !error.to_string().is_empty(),
            "{case} returned an empty error"
        );
        let after = capture_bip448_sync_base(&pool, "wallet", &script).await?;
        assert_eq!(
            after, before,
            "{case} changed storage or advanced its cursor"
        );
    }

    for case in [
        "withdraw-missing-secret",
        "withdraw-malformed-client-nonce",
        "withdraw-unpaired-identifiers",
    ] {
        let pool = migrated_pool().await?;
        let (record, owner, script) = accepted_binding_fixture(&pool).await?;
        let cursor = Bip448ScanCursor {
            coverage_start_height: 0,
            scan_revision: 0,
            last_scanned_height: 20,
            last_scanned_block_hash: "61".repeat(32),
        };
        persist_bip448_scan_state(&pool, "wallet", &script, &cursor, &[]).await?;
        let mut wallet = get_wallet(&pool, "wallet").await?;
        set_valid_withdrawal_lifecycle(&mut wallet.coins[0], CoinStatus::WITHDRAWING)?;
        match case {
            "withdraw-missing-secret" => wallet.coins[0].secret_nonce = None,
            "withdraw-malformed-client-nonce" => {
                wallet.coins[0].public_nonce = Some("00".repeat(66));
            }
            "withdraw-unpaired-identifiers" => {
                wallet.coins[0].withdrawal_address = None;
            }
            _ => unreachable!(),
        }
        update_wallet(&pool, &wallet).await?;
        let before = capture_bip448_sync_base(&pool, "wallet", &script).await?;
        assert!(reconcile_bip448_funding_bindings(
            &pool,
            "wallet",
            "statechain",
            &owner.to_string(),
            1,
            &[sample_binding_observation(
                "34",
                record.funding_outpoint.vout,
                record.funding_outpoint.value_sats,
                &script,
            )],
        )
        .await
        .is_err());
        assert_eq!(
            capture_bip448_sync_base(&pool, "wallet", &script).await?,
            before,
            "{case} changed storage or advanced its cursor"
        );
    }
    Ok(())
}

#[tokio::test]
async fn bip448_binding_sql_domains_nullable_states_and_wallet_uniqueness() -> Result<()> {
    let pool = migrated_pool().await?;
    let (_record, owner, script) = accepted_binding_fixture(&pool).await?;
    reconcile_bip448_funding_bindings(
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

    for (status, funding_height, spend_txid, spend_height, accepted) in [
        ("Mempool", None, None, None, true),
        ("Mempool", Some(10_i64), None, None, false),
        ("Unconfirmed", None, None, None, false),
        ("Unconfirmed", Some(10), None, None, true),
        ("Confirmed", None, None, None, false),
        ("Confirmed", Some(10), None, None, true),
        ("SpentMempool", None, Some("aa".repeat(32)), None, true),
        ("SpentMempool", Some(10), Some("aa".repeat(32)), None, true),
        (
            "SpentUnconfirmed",
            None,
            Some("aa".repeat(32)),
            Some(11),
            false,
        ),
        (
            "SpentUnconfirmed",
            Some(10),
            Some("aa".repeat(32)),
            Some(11),
            true,
        ),
        (
            "SpentConfirmed",
            None,
            Some("aa".repeat(32)),
            Some(11),
            false,
        ),
        (
            "SpentConfirmed",
            Some(10),
            Some("aa".repeat(32)),
            Some(11),
            true,
        ),
        ("Absent", None, None, None, true),
        ("Absent", Some(10), None, None, true),
    ] {
        let result = sqlx::query(
            "UPDATE bip448_funding_bindings SET observation_status=$1, \
             funding_height=$2,spend_txid=$3,spend_height=$4 \
             WHERE wallet_name='wallet' AND statechain_id='statechain' AND binding_index=1",
        )
        .bind(status)
        .bind(funding_height)
        .bind(spend_txid)
        .bind(spend_height)
        .execute(&pool)
        .await;
        assert_eq!(result.is_ok(), accepted, "direct SQL status case {status}");
    }
    sqlx::query(
        "UPDATE bip448_funding_bindings SET observation_status='Confirmed',funding_height=10, \
         spend_txid=NULL,spend_height=NULL WHERE wallet_name='wallet' \
         AND statechain_id='statechain' AND binding_index=1",
    )
    .execute(&pool)
    .await?;
    for statement in [
        "UPDATE bip448_funding_bindings SET role='canonical' WHERE wallet_name='wallet' AND binding_index=1",
        "UPDATE bip448_funding_bindings SET observation_status='Unknown' WHERE wallet_name='wallet' AND binding_index=1",
        "UPDATE bip448_funding_bindings SET ownership_status='current' WHERE wallet_name='wallet' AND binding_index=1",
    ] {
        assert!(sqlx::query(statement).execute(&pool).await.is_err());
    }
    let max_value = i64::try_from(bip448_funding::BIP448_MAX_MONEY_SATS)?;
    assert_eq!(
        sqlx::query("UPDATE bip448_funding_bindings SET value_sats=$1 WHERE wallet_name='wallet' AND binding_index=1")
            .bind(max_value)
            .execute(&pool)
            .await?
            .rows_affected(),
        1
    );
    assert_eq!(
        get_bip448_funding_binding(&pool, "wallet", "statechain", 1)
            .await?
            .unwrap()
            .value_sats,
        bip448_funding::BIP448_MAX_MONEY_SATS
    );
    assert!(sqlx::query("UPDATE bip448_funding_bindings SET value_sats=$1 WHERE wallet_name='wallet' AND binding_index=1")
        .bind(max_value.checked_add(1).unwrap())
        .execute(&pool).await.is_err());
    assert!(sqlx::query("UPDATE bip448_funding_bindings SET value_sats=-1 WHERE wallet_name='wallet' AND binding_index=1")
        .execute(&pool).await.is_err());
    sqlx::query("UPDATE bip448_funding_bindings SET value_sats=70000 WHERE wallet_name='wallet' AND binding_index=1")
        .execute(&pool).await?;
    assert_eq!(
        sqlx::query("UPDATE bip448_funding_bindings SET vout=4294967295 WHERE wallet_name='wallet' AND binding_index=1")
            .execute(&pool).await?.rows_affected(),
        1
    );
    assert_eq!(
        get_bip448_funding_binding(&pool, "wallet", "statechain", 1)
            .await?
            .unwrap()
            .vout,
        u32::MAX
    );
    assert!(sqlx::query("UPDATE bip448_funding_bindings SET vout=4294967296 WHERE wallet_name='wallet' AND binding_index=1")
        .execute(&pool).await.is_err());
    sqlx::query(
        "UPDATE bip448_funding_bindings SET vout=1 WHERE wallet_name='wallet' AND binding_index=1",
    )
    .execute(&pool)
    .await?;

    let (second_wallet, second_record, second_entry, second_owner) =
        real_accepted_fixture_for(CoinStatus::CONFIRMED, "statechain-two", &"35".repeat(32))?;
    let mut combined_wallet = get_wallet(&pool, "wallet").await?;
    combined_wallet.coins.extend(second_wallet.coins);
    update_wallet(&pool, &combined_wallet).await?;
    persist_bip448_initial_acceptance(&pool, &second_record, &second_entry).await?;
    let second_script = accepted_funding_script(&second_record)?;
    assert!(reconcile_bip448_funding_bindings(
        &pool,
        "wallet",
        "statechain-two",
        &second_owner.to_string(),
        1,
        &[
            sample_binding_observation("35", 0, 100_000, &second_script),
            sample_binding_observation("11", 1, 70_000, &second_script),
        ],
    )
    .await
    .is_err());
    assert!(
        list_bip448_funding_bindings(&pool, "wallet", "statechain-two")
            .await?
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn bip448_owner_reassignment_preserves_every_binding_index_and_identity() -> Result<()> {
    let pool = migrated_pool().await?;
    let (record, owner_one, script) = accepted_binding_fixture(&pool).await?;
    let observations = [
        sample_binding_observation("34", 0, 100_000, &script),
        sample_binding_observation("11", 1, 70_000, &script),
    ];
    let rows = reconcile_bip448_funding_bindings(
        &pool,
        "wallet",
        "statechain",
        &owner_one.to_string(),
        1,
        &observations,
    )
    .await?;
    let attempt = sample_duplicate_attempt(&rows[1]);
    insert_bip448_withdrawal_attempt_if_absent(&pool, &attempt).await?;
    let mut wallet = get_wallet(&pool, "wallet").await?;
    let mut receiver_coin = wallet.get_new_coin()?;
    let receiver_user = PublicKey::from_str(&receiver_coin.user_pubkey)?;
    let owner_two = receiver_user.x_only_public_key().0;
    let mut state_two = record.clone();
    state_two.latest_state_number = 2;
    state_two.latest_state = real_fixture_state_for_owner(
        &wallet,
        &record,
        owner_two,
        2,
        record.latest_state.state_locktime + 1,
    )?;
    let receiver_server =
        PublicKey::from_str(&record.aggregate_pubkey)?.combine(&receiver_user.negate())?;
    receiver_coin.server_pubkey = Some(receiver_server.to_string());
    receiver_coin.aggregated_pubkey = Some(record.aggregate_pubkey.clone());
    receiver_coin.statechain_protocol = Some(BIP448_COIN_PROTOCOL.to_string());
    receiver_coin.statechain_id = Some("statechain".to_string());
    receiver_coin.signed_statechain_id = Some(mercurylib::transfer::receiver::sign_message(
        "statechain",
        &receiver_coin,
    )?);
    receiver_coin.utxo_txid = Some(record.funding_outpoint.txid.clone());
    receiver_coin.utxo_vout = Some(record.funding_outpoint.vout);
    receiver_coin.amount = Some(u32::try_from(record.amount_sats)?);
    receiver_coin.status = CoinStatus::CONFIRMED;
    receiver_coin.locktime = Some(state_two.latest_state.state_locktime);
    receiver_coin.public_nonce = Some(
        state_two
            .latest_state
            .signing_metadata
            .client_public_nonce
            .clone(),
    );
    receiver_coin.server_public_nonce = Some(
        state_two
            .latest_state
            .signing_metadata
            .server_public_nonce
            .clone(),
    );
    receiver_coin.blinding_factor = Some(
        state_two
            .latest_state
            .signing_metadata
            .blinding_factor
            .clone(),
    );
    receiver_coin.aggregated_address =
        Some(bip448_deposit::create_deposit_address(&receiver_coin, "regtest")?.address);
    wallet.coins.push(receiver_coin);
    update_wallet(&pool, &wallet).await?;
    upsert_bip448_statechain_record(&pool, &state_two).await?;
    insert_bip448_state_history_entry(
        &pool,
        "wallet",
        "statechain",
        &history_entry(&state_two.latest_state, owner_two),
    )
    .await?;
    let reassignment_error = reconcile_bip448_funding_bindings(
        &pool,
        "wallet",
        "statechain",
        &owner_two.to_string(),
        2,
        &observations,
    )
    .await
    .expect_err("a sender-generation spend attempt must stop owner reassignment");
    assert!(reassignment_error
        .to_string()
        .contains("attempt-free generation"));
    assert_eq!(
        list_bip448_funding_bindings(&pool, "wallet", "statechain").await?,
        rows
    );
    let deleted_attempt = sqlx::query(
        "DELETE FROM bip448_withdrawal_attempts WHERE wallet_name='wallet' \
         AND statechain_id='statechain' AND binding_index=$1 AND signing_id=$2",
    )
    .bind(i64::from(attempt.binding_index))
    .bind(&attempt.signing_id)
    .execute(&pool)
    .await?;
    assert_eq!(deleted_attempt.rows_affected(), 1);
    let reassigned = reconcile_bip448_funding_bindings(
        &pool,
        "wallet",
        "statechain",
        &owner_two.to_string(),
        2,
        &observations,
    )
    .await?;
    assert_eq!(
        rows.iter()
            .map(|row| (row.binding_index, row.txid.clone(), row.vout))
            .collect::<Vec<_>>(),
        reassigned
            .iter()
            .map(|row| (row.binding_index, row.txid.clone(), row.vout))
            .collect::<Vec<_>>()
    );
    for (before, after) in rows.iter().zip(&reassigned) {
        assert_eq!(after.binding_index, before.binding_index);
        assert_eq!(after.txid, before.txid);
        assert_eq!(after.vout, before.vout);
        assert_eq!(after.value_sats, before.value_sats);
        assert_eq!(after.script_pubkey, before.script_pubkey);
        assert_eq!(after.role, before.role);
        assert_eq!(after.observation_status, before.observation_status);
        assert_eq!(after.funding_height, before.funding_height);
        assert_eq!(after.spend_txid, before.spend_txid);
        assert_eq!(after.spend_height, before.spend_height);
        assert_eq!(after.last_scanned_height, before.last_scanned_height);
        assert_eq!(after.first_seen_at, before.first_seen_at);
    }
    assert!(
        list_bip448_withdrawal_attempts(&pool, "wallet", "statechain")
            .await?
            .is_empty()
    );
    assert!(reassigned
        .iter()
        .all(|row| row.owner_user_pubkey == owner_two.to_string()
            && row.owner_state_number == 2
            && row.ownership_status == Bip448OwnershipStatus::Current));
    let mut accepted_wallet = get_wallet(&pool, "wallet").await?;
    accepted_wallet.coins[0].status = CoinStatus::IN_TRANSFER;
    update_wallet(&pool, &accepted_wallet).await?;
    let accepted_raw = get_bip448_raw_wallet_json(&pool, "wallet").await?;
    let mut status_reconciled = accepted_wallet;
    status_reconciled.coins[0].status = CoinStatus::TRANSFERRED;
    let mut status_guard = begin_bip448_mutation_guard(&pool).await?;
    assert!(
        status_guard
            .update_wallet_if_unchanged_and_scan_current(
                "wallet",
                &accepted_raw,
                &status_reconciled,
                &[],
            )
            .await?
    );
    status_guard.commit().await?;
    assert!(list_bip448_funding_bindings(&pool, "wallet", "statechain")
        .await?
        .iter()
        .all(|row| row.owner_user_pubkey == owner_two.to_string()
            && row.ownership_status == Bip448OwnershipStatus::Current));
    let previous = mark_bip448_funding_bindings_previous(
        &pool,
        "wallet",
        "statechain",
        &owner_two.to_string(),
        2,
    )
    .await?;
    assert!(previous
        .iter()
        .all(|row| row.ownership_status == Bip448OwnershipStatus::Previous));
    Ok(())
}

#[tokio::test]
async fn bip448_positive_coin_status_rotation_invalidates_bindings_with_wallet_cas() -> Result<()> {
    let pool = migrated_pool().await?;
    let (_, owner, script) = accepted_binding_fixture(&pool).await?;
    reconcile_bip448_funding_bindings(
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
    let mut wallet = get_wallet(&pool, "wallet").await?;
    wallet.coins[0].status = CoinStatus::IN_TRANSFER;
    update_wallet(&pool, &wallet).await?;
    let raw = get_bip448_raw_wallet_json(&pool, "wallet").await?;
    let mut transferred = wallet.clone();
    transferred.coins[0].status = CoinStatus::TRANSFERRED;

    let mut guard = begin_bip448_mutation_guard(&pool).await?;
    assert!(
        guard
            .update_wallet_if_unchanged_and_scan_current("wallet", &raw, &transferred, &[],)
            .await?
    );
    guard.commit().await?;
    assert_eq!(
        serde_json::to_value(get_wallet(&pool, "wallet").await?)?,
        serde_json::to_value(&transferred)?
    );
    assert!(list_bip448_funding_bindings(&pool, "wallet", "statechain")
        .await?
        .iter()
        .all(|binding| { binding.ownership_status == Bip448OwnershipStatus::Previous }));

    let stale_raw = raw;
    let mut stale_guard = begin_bip448_mutation_guard(&pool).await?;
    assert!(
        !stale_guard
            .update_wallet_if_unchanged_and_scan_current("wallet", &stale_raw, &transferred, &[],)
            .await?
    );
    stale_guard.commit().await?;
    Ok(())
}
