use super::support::*;

fn spawn_sync_base_loser(
    pool: Pool<Sqlite>,
    base: Bip448SyncBase,
) -> (
    Arc<Bip448BeginImmediateTestHook>,
    tokio::task::JoinHandle<Result<Bip448MutationGuard>>,
) {
    let hook = Arc::new(Bip448BeginImmediateTestHook::default());
    let task_hook = hook.clone();
    let task = tokio::spawn(
        BIP448_BEGIN_IMMEDIATE_TEST_HOOK.scope(task_hook, async move {
            begin_bip448_sync_base_guard(&pool, &base).await
        }),
    );
    (hook, task)
}

async fn commit_winner_and_assert_sync_loser_loses(
    hook: Arc<Bip448BeginImmediateTestHook>,
    winner: Bip448MutationGuard,
    loser: tokio::task::JoinHandle<Result<Bip448MutationGuard>>,
) -> Result<()> {
    assert_begin_is_contested(&hook).await?;
    winner.commit().await?;
    hook.after_acquire.notified().await;
    if loser.await?.is_ok() {
        return Err(anyhow!(
            "stale BIP448 synchronization base passed after deterministic serialization"
        ));
    }
    Ok(())
}

#[tokio::test]
async fn bip448_sync_base_revision_pending_and_wallet_tokens_are_full_cas() -> Result<()> {
    let pool = migrated_pool().await?;
    let wallet = sample_wallet();
    insert_wallet(&pool, &wallet).await?;
    let base = capture_bip448_sync_base(&pool, "wallet", "51").await?;
    let pending = Bip448PendingDepositSigning {
        wallet_name: "wallet".into(),
        statechain_id: "statechain".into(),
        funding_txid: "11".repeat(32),
        funding_vout: 0,
        funding_value_sats: 1,
        update_template_hash: "21".repeat(32),
        settlement_template_hash: "22".repeat(32),
        state_locktime: 700_000_000,
        signing_id: "23".repeat(32),
        client_secret_nonce: "24".repeat(32),
        client_public_nonce: "25".repeat(33),
        blinding_factor: "26".repeat(32),
        server_public_nonce: None,
    };
    insert_bip448_pending_deposit_signing_if_absent(&pool, &pending).await?;
    assert!(begin_bip448_sync_base_guard(&pool, &base).await.is_err());
    let inserted_base = capture_bip448_sync_base(&pool, "wallet", "51").await?;
    update_bip448_pending_deposit_server_public_nonce(
        &pool,
        "wallet",
        "statechain",
        &pending.signing_id,
        &"27".repeat(33),
    )
    .await?;
    assert!(begin_bip448_sync_base_guard(&pool, &inserted_base)
        .await
        .is_err());
    let nonce_base = capture_bip448_sync_base(&pool, "wallet", "51").await?;
    delete_bip448_pending_deposit_signing(&pool, "wallet", "statechain", &pending.signing_id)
        .await?;
    assert!(begin_bip448_sync_base_guard(&pool, &nonce_base)
        .await
        .is_err());

    let base = capture_bip448_sync_base(&pool, "wallet", "51").await?;
    let candidate = Bip448ScanCursor {
        coverage_start_height: 10,
        scan_revision: 0,
        last_scanned_height: 20,
        last_scanned_block_hash: "31".repeat(32),
    };
    let mut guard = begin_bip448_sync_base_guard(&pool, &base).await?;
    let token1 = guard
        .apply_scan_cache_and_cursor("wallet", "51", &candidate, &[])
        .await?;
    guard.commit().await?;
    assert_eq!(token1.scan_revision, 1);
    assert!(begin_bip448_sync_base_guard(&pool, &base).await.is_err());
    let base2 = capture_bip448_sync_base(&pool, "wallet", "51").await?;
    let candidate2 = Bip448ScanCursor {
        scan_revision: 1,
        ..candidate.clone()
    };
    let mut guard = begin_bip448_sync_base_guard(&pool, &base2).await?;
    let token2 = guard
        .apply_scan_cache_and_cursor("wallet", "51", &candidate2, &[])
        .await?;
    guard.commit().await?;
    assert_eq!(
        token2.scan_revision, 2,
        "same-tip semantic no-op increments revision"
    );
    let mut replacement = wallet.clone();
    replacement.blockheight += 1;
    assert!(
        !compare_and_set_wallet_after_bip448_scan(
            &pool,
            "wallet",
            &base.raw_wallet_json,
            &replacement,
            &[token1]
        )
        .await?
    );
    let live_raw = sqlx::query_scalar::<_, String>(
        "SELECT wallet_json FROM wallet WHERE wallet_name='wallet'",
    )
    .fetch_one(&pool)
    .await?;
    assert!(
        compare_and_set_wallet_after_bip448_scan(
            &pool,
            "wallet",
            &live_raw,
            &replacement,
            &[token2]
        )
        .await?
    );
    let base3 = capture_bip448_sync_base(&pool, "wallet", "51").await?;
    let lower = Bip448ScanCursor {
        coverage_start_height: 0,
        scan_revision: 2,
        ..candidate
    };
    let mut guard = begin_bip448_sync_base_guard(&pool, &base3).await?;
    let token3 = guard
        .apply_scan_cache_and_cursor("wallet", "51", &lower, &[])
        .await?;
    guard.commit().await?;
    assert_eq!(token3.scan_revision, 3);
    assert_eq!(
        load_bip448_scan_state(&pool, "wallet", "51")
            .await?
            .0
            .unwrap()
            .coverage_start_height,
        0
    );
    let expected_after_lower = sqlx::query_scalar::<_, String>(
        "SELECT wallet_json FROM wallet WHERE wallet_name='wallet'",
    )
    .fetch_one(&pool)
    .await?;
    let mut winning_wallet: Wallet = serde_json::from_str(&expected_after_lower)?;
    winning_wallet.blockheight = winning_wallet
        .blockheight
        .checked_add(1)
        .ok_or_else(|| anyhow!("wallet height overflow"))?;
    update_wallet(&pool, &winning_wallet).await?;
    let winning_raw = sqlx::query_scalar::<_, String>(
        "SELECT wallet_json FROM wallet WHERE wallet_name='wallet'",
    )
    .fetch_one(&pool)
    .await?;
    let mut losing_wallet = winning_wallet.clone();
    losing_wallet.blockheight = losing_wallet
        .blockheight
        .checked_add(1)
        .ok_or_else(|| anyhow!("wallet height overflow"))?;
    assert!(
        !compare_and_set_wallet_after_bip448_scan(
            &pool,
            "wallet",
            &expected_after_lower,
            &losing_wallet,
            std::slice::from_ref(&token3),
        )
        .await?,
        "wallet-only CAS loss must report false"
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT wallet_json FROM wallet WHERE wallet_name='wallet'"
        )
        .fetch_one(&pool)
        .await?,
        winning_raw,
        "a losing wallet CAS must not overwrite the winner"
    );
    assert!(compare_and_set_wallet_after_bip448_scan(
        &pool,
        "wallet",
        &winning_raw,
        &losing_wallet,
        &[token3.clone(), token3.clone()],
    )
    .await
    .is_err());
    sqlx::query("UPDATE bip448_scan_cursors SET scan_revision=$1 WHERE wallet_name='wallet' AND script_pubkey='51'")
        .bind(i64::MAX).execute(&pool).await?;
    let overflow_base = capture_bip448_sync_base(&pool, "wallet", "51").await?;
    let overflow = Bip448ScanCursor {
        coverage_start_height: 0,
        scan_revision: u64::try_from(i64::MAX)?,
        last_scanned_height: 21,
        last_scanned_block_hash: "32".repeat(32),
    };
    let mut guard = begin_bip448_sync_base_guard(&pool, &overflow_base).await?;
    assert!(guard
        .apply_scan_cache_and_cursor(
            "wallet",
            "51",
            &overflow,
            &[ChainUtxo {
                txid: "33".repeat(32),
                vout: 0,
                value: 1,
                height: 21
            }]
        )
        .await
        .is_err());
    drop(guard);
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT scan_revision FROM bip448_scan_cursors WHERE wallet_name='wallet' AND script_pubkey='51'").fetch_one(&pool).await?,i64::MAX);
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT COUNT(*) FROM bip448_scanned_outpoints WHERE wallet_name='wallet' AND script_pubkey='51'").fetch_one(&pool).await?,0);
    Ok(())
}

#[tokio::test]
async fn bip448_pending_aba_and_wallet_cas_have_deterministic_ordering() -> Result<()> {
    let pools = independent_migrated_pools().await?;
    let wallet = sample_wallet();
    insert_wallet(&pools.first, &wallet).await?;
    let pending = Bip448PendingDepositSigning {
        wallet_name: "wallet".into(),
        statechain_id: "statechain".into(),
        funding_txid: "11".repeat(32),
        funding_vout: 0,
        funding_value_sats: 1,
        update_template_hash: "21".repeat(32),
        settlement_template_hash: "22".repeat(32),
        state_locktime: 700_000_000,
        signing_id: "23".repeat(32),
        client_secret_nonce: "24".repeat(132),
        client_public_nonce: "25".repeat(66),
        blinding_factor: "26".repeat(32),
        server_public_nonce: None,
    };

    let insert_base = capture_bip448_sync_base(&pools.second, "wallet", "51").await?;
    let mut insert_winner = begin_bip448_mutation_guard(&pools.first).await?;
    sqlx::query(
        "INSERT INTO bip448_pending_deposit_signings (wallet_name,statechain_id,\
         funding_txid,funding_vout,funding_value_sats,update_template_hash,\
         settlement_template_hash,state_locktime,signing_id,client_secret_nonce,\
         client_public_nonce,blinding_factor,server_public_nonce) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NULL)",
    )
    .bind(&pending.wallet_name)
    .bind(&pending.statechain_id)
    .bind(&pending.funding_txid)
    .bind(i64::from(pending.funding_vout))
    .bind(i64::try_from(pending.funding_value_sats)?)
    .bind(&pending.update_template_hash)
    .bind(&pending.settlement_template_hash)
    .bind(i64::from(pending.state_locktime))
    .bind(&pending.signing_id)
    .bind(&pending.client_secret_nonce)
    .bind(&pending.client_public_nonce)
    .bind(&pending.blinding_factor)
    .execute(insert_winner.connection())
    .await?;
    let (hook, loser) = spawn_sync_base_loser(pools.second.clone(), insert_base);
    commit_winner_and_assert_sync_loser_loses(hook, insert_winner, loser).await?;

    let nonce_base = capture_bip448_sync_base(&pools.second, "wallet", "51").await?;
    let mut nonce_winner = begin_bip448_mutation_guard(&pools.first).await?;
    sqlx::query(
        "UPDATE bip448_pending_deposit_signings SET server_public_nonce=$1 \
         WHERE wallet_name='wallet' AND statechain_id='statechain' AND signing_id=$2",
    )
    .bind("27".repeat(66))
    .bind(&pending.signing_id)
    .execute(nonce_winner.connection())
    .await?;
    let (hook, loser) = spawn_sync_base_loser(pools.second.clone(), nonce_base);
    commit_winner_and_assert_sync_loser_loses(hook, nonce_winner, loser).await?;

    let delete_base = capture_bip448_sync_base(&pools.second, "wallet", "51").await?;
    let mut delete_winner = begin_bip448_mutation_guard(&pools.first).await?;
    sqlx::query(
        "DELETE FROM bip448_pending_deposit_signings \
         WHERE wallet_name='wallet' AND statechain_id='statechain' AND signing_id=$1",
    )
    .bind(&pending.signing_id)
    .execute(delete_winner.connection())
    .await?;
    let (hook, loser) = spawn_sync_base_loser(pools.second.clone(), delete_base);
    commit_winner_and_assert_sync_loser_loses(hook, delete_winner, loser).await?;

    persist_bip448_scan_state(
        &pools.first,
        "wallet",
        "51",
        &Bip448ScanCursor {
            coverage_start_height: 0,
            scan_revision: 0,
            last_scanned_height: 20,
            last_scanned_block_hash: "31".repeat(32),
        },
        &[],
    )
    .await?;
    let aba_base = capture_bip448_sync_base(&pools.second, "wallet", "51").await?;
    let mut aba_winner = begin_bip448_sync_base_guard(&pools.first, &aba_base).await?;
    let token_two = aba_winner
        .apply_scan_cache_and_cursor(
            "wallet",
            "51",
            &Bip448ScanCursor {
                coverage_start_height: 0,
                scan_revision: 1,
                last_scanned_height: 20,
                last_scanned_block_hash: "31".repeat(32),
            },
            &[],
        )
        .await?;
    let (hook, loser) = spawn_sync_base_loser(pools.second.clone(), aba_base);
    commit_winner_and_assert_sync_loser_loses(hook, aba_winner, loser).await?;
    assert_eq!(token_two.scan_revision, 2);

    let expected_raw = sqlx::query_scalar::<_, String>(
        "SELECT wallet_json FROM wallet WHERE wallet_name='wallet'",
    )
    .fetch_one(&pools.first)
    .await?;
    let mut replacement = wallet.clone();
    replacement.blockheight = replacement
        .blockheight
        .checked_add(1)
        .ok_or_else(|| anyhow!("wallet height overflow"))?;
    let token_winner_base = capture_bip448_sync_base(&pools.first, "wallet", "51").await?;
    let mut token_winner = begin_bip448_sync_base_guard(&pools.first, &token_winner_base).await?;
    let token_three = token_winner
        .apply_scan_cache_and_cursor(
            "wallet",
            "51",
            &Bip448ScanCursor {
                coverage_start_height: 0,
                scan_revision: 2,
                last_scanned_height: 20,
                last_scanned_block_hash: "31".repeat(32),
            },
            &[],
        )
        .await?;
    let hook = Arc::new(Bip448BeginImmediateTestHook::default());
    let task_hook = hook.clone();
    let second_pool = pools.second.clone();
    let stale_expected_raw = expected_raw.clone();
    let stale_replacement = replacement.clone();
    let stale_token = token_two.clone();
    let wallet_token_loser = tokio::spawn(BIP448_BEGIN_IMMEDIATE_TEST_HOOK.scope(
        task_hook,
        async move {
            compare_and_set_wallet_after_bip448_scan(
                &second_pool,
                "wallet",
                &stale_expected_raw,
                &stale_replacement,
                &[stale_token],
            )
            .await
        },
    ));
    assert_begin_is_contested(&hook).await?;
    token_winner.commit().await?;
    hook.after_acquire.notified().await;
    assert!(!wallet_token_loser.await??);
    assert_eq!(token_three.scan_revision, 3);

    let raw_before_wallet_winner = sqlx::query_scalar::<_, String>(
        "SELECT wallet_json FROM wallet WHERE wallet_name='wallet'",
    )
    .fetch_one(&pools.first)
    .await?;
    let mut winning_wallet = wallet.clone();
    winning_wallet.blockheight = winning_wallet
        .blockheight
        .checked_add(2)
        .ok_or_else(|| anyhow!("wallet height overflow"))?;
    let winning_json = canonical_wallet_json(&winning_wallet)?;
    let mut wallet_winner = begin_bip448_mutation_guard(&pools.first).await?;
    sqlx::query("UPDATE wallet SET wallet_json=$1 WHERE wallet_name='wallet' AND wallet_json=$2")
        .bind(&winning_json)
        .bind(&raw_before_wallet_winner)
        .execute(wallet_winner.connection())
        .await?;
    let hook = Arc::new(Bip448BeginImmediateTestHook::default());
    let task_hook = hook.clone();
    let second_pool = pools.second.clone();
    let losing_expected = raw_before_wallet_winner.clone();
    let losing_replacement = replacement;
    let current_token = token_three;
    let wallet_bytes_loser = tokio::spawn(BIP448_BEGIN_IMMEDIATE_TEST_HOOK.scope(
        task_hook,
        async move {
            compare_and_set_wallet_after_bip448_scan(
                &second_pool,
                "wallet",
                &losing_expected,
                &losing_replacement,
                &[current_token],
            )
            .await
        },
    ));
    assert_begin_is_contested(&hook).await?;
    wallet_winner.commit().await?;
    hook.after_acquire.notified().await;
    assert!(!wallet_bytes_loser.await??);
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT wallet_json FROM wallet WHERE wallet_name='wallet'",
        )
        .fetch_one(&pools.first)
        .await?,
        winning_json
    );
    Ok(())
}

#[tokio::test]
async fn bip448_reverse_order_sync_base_cas_preserves_every_newer_fact_and_reruns() -> Result<()> {
    let pools = independent_migrated_pools().await?;
    let (_, owner, script) = accepted_binding_fixture(&pools.first).await?;
    let initial_observations = [
        sample_binding_observation("34", 0, 100_000, &script),
        sample_binding_observation("11", 1, 70_000, &script),
    ];
    let bindings = reconcile_bip448_funding_bindings(
        &pools.first,
        "wallet",
        "statechain",
        &owner.to_string(),
        1,
        &initial_observations,
    )
    .await?;
    let duplicate = bindings
        .iter()
        .find(|row| row.binding_index == 1)
        .ok_or_else(|| anyhow!("duplicate fixture binding is missing"))?;
    let signed = sign_duplicate_attempt(&pools.first, duplicate).await?;
    transition_bip448_withdrawal_broadcast_status(
        &pools.first,
        "wallet",
        "statechain",
        1,
        &signed.signing_id,
        Bip448BroadcastStatus::NotBroadcast,
        Bip448BroadcastStatus::Accepted,
    )
    .await?;
    persist_bip448_scan_state(
        &pools.first,
        "wallet",
        &script,
        &Bip448ScanCursor {
            coverage_start_height: 10,
            scan_revision: 0,
            last_scanned_height: 20,
            last_scanned_block_hash: "51".repeat(32),
        },
        &[],
    )
    .await?;
    let (older_base, newer_base) = tokio::try_join!(
        capture_bip448_sync_base(&pools.first, "wallet", &script),
        capture_bip448_sync_base(&pools.second, "wallet", &script),
    )?;
    assert_eq!(older_base, newer_base);

    let mut absent_duplicate = sample_binding_observation("11", 1, 70_000, &script);
    absent_duplicate.observation_status = Bip448ObservationStatus::Absent;
    absent_duplicate.funding_height = None;
    absent_duplicate.last_scanned_height = 21;
    let mut newer_canonical = sample_binding_observation("34", 0, 100_000, &script);
    newer_canonical.last_scanned_height = 21;
    let mut newer_guard = begin_bip448_sync_base_guard(&pools.first, &newer_base).await?;
    newer_guard
        .reconcile_funding_bindings(
            "wallet",
            "statechain",
            &owner.to_string(),
            1,
            &[newer_canonical, absent_duplicate],
        )
        .await?;
    newer_guard
        .update_withdrawal_broadcast_status(
            "wallet",
            "statechain",
            1,
            &signed.signing_id,
            Bip448BroadcastStatus::Accepted,
            Bip448BroadcastStatus::NeedsRebroadcast,
        )
        .await?;
    newer_guard
        .apply_scan_cache_and_cursor(
            "wallet",
            &script,
            &Bip448ScanCursor {
                coverage_start_height: 10,
                scan_revision: 1,
                last_scanned_height: 21,
                last_scanned_block_hash: "52".repeat(32),
            },
            &[],
        )
        .await?;
    let hook = Arc::new(Bip448BeginImmediateTestHook::default());
    let task_hook = hook.clone();
    let second_pool = pools.second.clone();
    let older_task = tokio::spawn(
        BIP448_BEGIN_IMMEDIATE_TEST_HOOK.scope(task_hook, async move {
            begin_bip448_sync_base_guard(&second_pool, &older_base).await
        }),
    );
    assert_begin_is_contested(&hook).await?;
    newer_guard.commit().await?;
    hook.after_acquire.notified().await;
    assert!(
        older_task.await?.is_err(),
        "the older observation candidate must lose its full SyncBase CAS"
    );
    let durable_binding = get_bip448_funding_binding(&pools.first, "wallet", "statechain", 1)
        .await?
        .ok_or_else(|| anyhow!("duplicate binding disappeared"))?;
    assert_eq!(
        durable_binding.observation_status,
        Bip448ObservationStatus::Absent
    );
    assert_eq!(
        get_bip448_withdrawal_attempt(&pools.first, "wallet", "statechain", 1)
            .await?
            .ok_or_else(|| anyhow!("signed attempt disappeared"))?
            .broadcast_status,
        Bip448BroadcastStatus::NeedsRebroadcast
    );
    assert_eq!(
        load_bip448_scan_state(&pools.first, "wallet", &script)
            .await?
            .0
            .ok_or_else(|| anyhow!("scan cursor disappeared"))?
            .scan_revision,
        2
    );

    let rerun_base = capture_bip448_sync_base(&pools.second, "wallet", &script).await?;
    let mut rerun_guard = begin_bip448_sync_base_guard(&pools.second, &rerun_base).await?;
    let mut rerun_canonical = sample_binding_observation("34", 0, 100_000, &script);
    rerun_canonical.last_scanned_height = 22;
    let mut rerun_duplicate = sample_binding_observation("11", 1, 70_000, &script);
    rerun_duplicate.last_scanned_height = 22;
    rerun_guard
        .reconcile_funding_bindings(
            "wallet",
            "statechain",
            &owner.to_string(),
            1,
            &[rerun_canonical, rerun_duplicate],
        )
        .await?;
    rerun_guard
        .update_withdrawal_broadcast_status(
            "wallet",
            "statechain",
            1,
            &signed.signing_id,
            Bip448BroadcastStatus::NeedsRebroadcast,
            Bip448BroadcastStatus::Accepted,
        )
        .await?;
    rerun_guard
        .apply_scan_cache_and_cursor(
            "wallet",
            &script,
            &Bip448ScanCursor {
                coverage_start_height: 10,
                scan_revision: 2,
                last_scanned_height: 22,
                last_scanned_block_hash: "53".repeat(32),
            },
            &[],
        )
        .await?;
    rerun_guard.commit().await?;
    assert_eq!(
        get_bip448_funding_binding(&pools.first, "wallet", "statechain", 1)
            .await?
            .ok_or_else(|| anyhow!("rerun binding disappeared"))?
            .observation_status,
        Bip448ObservationStatus::Confirmed
    );
    assert_eq!(
        get_bip448_withdrawal_attempt(&pools.first, "wallet", "statechain", 1)
            .await?
            .ok_or_else(|| anyhow!("rerun attempt disappeared"))?
            .broadcast_status,
        Bip448BroadcastStatus::Accepted
    );
    assert_eq!(
        load_bip448_scan_state(&pools.first, "wallet", &script)
            .await?
            .0
            .ok_or_else(|| anyhow!("rerun cursor disappeared"))?
            .scan_revision,
        3
    );
    Ok(())
}

#[tokio::test]
async fn bip448_lower_coverage_floor_preserves_durable_bindings_and_attempts() -> Result<()> {
    let pool = migrated_pool().await?;
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
    let duplicate = bindings
        .iter()
        .find(|row| row.binding_index == 1)
        .ok_or_else(|| anyhow!("duplicate fixture binding is missing"))?;
    insert_bip448_withdrawal_attempt_if_absent(&pool, &sample_duplicate_attempt(duplicate)).await?;
    persist_bip448_scan_state(
        &pool,
        "wallet",
        &script,
        &Bip448ScanCursor {
            coverage_start_height: 10,
            scan_revision: 0,
            last_scanned_height: 20,
            last_scanned_block_hash: "54".repeat(32),
        },
        &[ChainUtxo {
            txid: "55".repeat(32),
            vout: 0,
            value: 42,
            height: 20,
        }],
    )
    .await?;
    let bindings_before = list_bip448_funding_bindings(&pool, "wallet", "statechain").await?;
    let attempts_before = list_bip448_withdrawal_attempts(&pool, "wallet", "statechain").await?;
    let base = capture_bip448_sync_base(&pool, "wallet", &script).await?;
    let mut guard = begin_bip448_sync_base_guard(&pool, &base).await?;
    let token = guard
        .apply_scan_cache_and_cursor(
            "wallet",
            &script,
            &Bip448ScanCursor {
                coverage_start_height: 0,
                scan_revision: 1,
                last_scanned_height: 21,
                last_scanned_block_hash: "56".repeat(32),
            },
            &[],
        )
        .await?;
    guard.commit().await?;
    assert_eq!(token.scan_revision, 2);
    let (cursor, cache) = load_bip448_scan_state(&pool, "wallet", &script).await?;
    let cursor = cursor.ok_or_else(|| anyhow!("lower-floor cursor disappeared"))?;
    assert_eq!(cursor.coverage_start_height, 0);
    assert_eq!(cursor.scan_revision, 2);
    assert!(cache.is_empty(), "lower-floor apply replaces current cache");
    assert_eq!(
        list_bip448_funding_bindings(&pool, "wallet", "statechain").await?,
        bindings_before
    );
    assert_eq!(
        list_bip448_withdrawal_attempts(&pool, "wallet", "statechain").await?,
        attempts_before
    );
    Ok(())
}
