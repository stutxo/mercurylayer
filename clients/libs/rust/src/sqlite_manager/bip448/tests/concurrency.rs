use super::support::*;

async fn current_duplicate_attempt_fixture(
    pool: &Pool<Sqlite>,
    duplicate_txid_byte: &str,
) -> Result<(Bip448WithdrawalAttempt, String, String)> {
    let (_, owner, script) = accepted_binding_fixture(pool).await?;
    let binding = reconcile_bip448_funding_bindings(
        pool,
        "wallet",
        "statechain",
        &owner.to_string(),
        1,
        &[
            sample_binding_observation("34", 0, 100_000, &script),
            sample_binding_observation(duplicate_txid_byte, 1, 70_000, &script),
        ],
    )
    .await?
    .into_iter()
    .find(|row| row.binding_index == 1)
    .ok_or_else(|| anyhow!("duplicate fixture binding is missing"))?;
    let wallet = get_wallet(pool, "wallet").await?;
    let signed_statechain_id = wallet
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some("statechain"))
        .and_then(|coin| coin.signed_statechain_id.clone())
        .ok_or_else(|| anyhow!("duplicate fixture signed statechain ID is missing"))?;
    Ok((
        sample_duplicate_attempt(&binding),
        owner.to_string(),
        signed_statechain_id,
    ))
}

#[tokio::test]
async fn bip448_begin_immediate_excludes_two_real_pool_connections() -> Result<()> {
    let pools = independent_migrated_pools().await?;
    let (_, owner, script) = accepted_binding_fixture(&pools.first).await?;
    let canonical = sample_binding_observation("34", 0, 100_000, &script);
    let duplicate = sample_binding_observation("11", 1, 70_000, &script);
    let binding = reconcile_bip448_funding_bindings(
        &pools.first,
        "wallet",
        "statechain",
        &owner.to_string(),
        1,
        &[canonical, duplicate],
    )
    .await?
    .into_iter()
    .find(|row| row.binding_index == 1)
    .unwrap();
    let first = sample_duplicate_attempt(&binding);
    let mut second = first.clone();
    second.signing_id = "75".repeat(32);
    second.client_secret_nonce = "76".repeat(132);
    refresh_attempt_sign_first_payload(&mut second);

    let mut first_guard = begin_bip448_mutation_guard(&pools.first).await?;
    first_guard
        .insert_withdrawal_attempt_if_absent(&first)
        .await?;
    let hook = Arc::new(Bip448BeginImmediateTestHook::default());
    let task_hook = hook.clone();
    let second_pool = pools.second.clone();
    let task = tokio::spawn(
        BIP448_BEGIN_IMMEDIATE_TEST_HOOK.scope(task_hook, async move {
            insert_bip448_withdrawal_attempt_if_absent(&second_pool, &second).await
        }),
    );
    assert_begin_is_contested(&hook).await?;
    first_guard.commit().await?;
    hook.after_acquire.notified().await;
    assert!(
        task.await?.is_err(),
        "second competing immutable plan must lose after serialization"
    );
    assert_eq!(
        list_bip448_withdrawal_attempts(&pools.first, "wallet", "statechain")
            .await?
            .len(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn bip448_transfer_intent_and_duplicate_attempt_have_one_durable_winner() -> Result<()> {
    {
        let pools = independent_migrated_pools().await?;
        let (attempt, _, _) = current_duplicate_attempt_fixture(&pools.first, "11").await?;
        let mut intent = sample_transfer_intent("a9");
        intent.acknowledge_cooperative_duplicates = true;

        let mut attempt_guard = begin_bip448_mutation_guard(&pools.first).await?;
        attempt_guard
            .insert_withdrawal_attempt_if_absent(&attempt)
            .await?;
        let remote_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let task_remote_calls = remote_calls.clone();
        let hook = Arc::new(Bip448BeginImmediateTestHook::default());
        let task_hook = hook.clone();
        let second_pool = pools.second.clone();
        let task = tokio::spawn(
            BIP448_BEGIN_IMMEDIATE_TEST_HOOK.scope(task_hook, async move {
                let mut guard = begin_bip448_mutation_guard(&second_pool).await?;
                let stored = guard
                    .prepare_or_supersede_transfer_intent(None, &intent)
                    .await?;
                guard.commit().await?;
                task_remote_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok::<_, anyhow::Error>(stored)
            }),
        );
        assert_begin_is_contested(&hook).await?;
        attempt_guard.commit().await?;
        hook.after_acquire.notified().await;
        assert!(
            task.await?.is_err(),
            "attempt-first serialization must reject transfer intent creation"
        );
        assert_eq!(
            remote_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "losing transfer must make no remote call"
        );
        assert_eq!(
            list_bip448_withdrawal_attempts(&pools.first, "wallet", "statechain")
                .await?
                .len(),
            1
        );
        assert!(
            list_bip448_transfer_intents(&pools.first, "wallet", "statechain")
                .await?
                .is_empty()
        );
    }

    {
        let pools = independent_migrated_pools().await?;
        let (attempt, _, _) = current_duplicate_attempt_fixture(&pools.first, "12").await?;
        let mut intent = sample_transfer_intent("aa");
        intent.acknowledge_cooperative_duplicates = true;

        let mut transfer_guard = begin_bip448_mutation_guard(&pools.first).await?;
        transfer_guard
            .prepare_or_supersede_transfer_intent(None, &intent)
            .await?;
        let hook = Arc::new(Bip448BeginImmediateTestHook::default());
        let task_hook = hook.clone();
        let second_pool = pools.second.clone();
        let task = tokio::spawn(
            BIP448_BEGIN_IMMEDIATE_TEST_HOOK.scope(task_hook, async move {
                insert_bip448_withdrawal_attempt_if_absent(&second_pool, &attempt).await
            }),
        );
        assert_begin_is_contested(&hook).await?;
        transfer_guard.commit().await?;
        hook.after_acquire.notified().await;
        assert!(
            task.await?.is_err(),
            "transfer-first serialization must reject attempt creation"
        );
        assert_eq!(
            list_bip448_transfer_intents(&pools.first, "wallet", "statechain")
                .await?
                .len(),
            1
        );
        assert!(
            list_bip448_withdrawal_attempts(&pools.first, "wallet", "statechain")
                .await?
                .is_empty()
        );
    }
    Ok(())
}

#[tokio::test]
async fn bip448_latch_creation_and_duplicate_attempt_are_asymmetrically_linearized() -> Result<()> {
    {
        let pools = independent_migrated_pools().await?;
        let (attempt, owner, signed_statechain_id) =
            current_duplicate_attempt_fixture(&pools.first, "13").await?;
        let mut attempt_guard = begin_bip448_mutation_guard(&pools.first).await?;
        attempt_guard
            .insert_withdrawal_attempt_if_absent(&attempt)
            .await?;
        let remote_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let task_remote_calls = remote_calls.clone();
        let hook = Arc::new(Bip448BeginImmediateTestHook::default());
        let task_hook = hook.clone();
        let second_pool = pools.second.clone();
        let task = tokio::spawn(
            BIP448_BEGIN_IMMEDIATE_TEST_HOOK.scope(task_hook, async move {
                let mut guard = begin_bip448_mutation_guard(&second_pool).await?;
                let coin = guard
                    .latch_creation_coin("wallet", "statechain", &owner, &signed_statechain_id)
                    .await?;
                task_remote_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                guard.commit().await?;
                Ok::<_, anyhow::Error>(coin)
            }),
        );
        assert_begin_is_contested(&hook).await?;
        attempt_guard.commit().await?;
        hook.after_acquire.notified().await;
        assert!(
            task.await?.is_err(),
            "attempt-first serialization must reject latch creation"
        );
        assert_eq!(
            remote_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "attempt-first latch rejection must precede the remote call"
        );
    }

    {
        let pools = independent_migrated_pools().await?;
        let (attempt, owner, signed_statechain_id) =
            current_duplicate_attempt_fixture(&pools.first, "14").await?;
        let mut latch_guard = begin_bip448_mutation_guard(&pools.first).await?;
        let selected = latch_guard
            .latch_creation_coin("wallet", "statechain", &owner, &signed_statechain_id)
            .await?;
        let remote_calls = std::sync::atomic::AtomicUsize::new(0);
        remote_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        let hook = Arc::new(Bip448BeginImmediateTestHook::default());
        let task_hook = hook.clone();
        let second_pool = pools.second.clone();
        let task = tokio::spawn(
            BIP448_BEGIN_IMMEDIATE_TEST_HOOK.scope(task_hook, async move {
                insert_bip448_withdrawal_attempt_if_absent(&second_pool, &attempt).await
            }),
        );
        assert_begin_is_contested(&hook).await?;
        latch_guard.commit().await?;
        hook.after_acquire.notified().await;
        let stored_attempt = task.await??;
        assert_eq!(selected.statechain_id.as_deref(), Some("statechain"));
        assert_eq!(stored_attempt.binding_index, 1);
        assert_eq!(
            remote_calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "latch-first may finish its one remote call while retaining the guard"
        );
        assert_eq!(
            list_bip448_withdrawal_attempts(&pools.first, "wallet", "statechain")
                .await?
                .len(),
            1,
            "completed latch creation reserves no future transfer right"
        );
    }
    Ok(())
}

#[tokio::test]
async fn bip448_accepted_to_needs_rebroadcast_serializes_before_later_attempt() -> Result<()> {
    let pools = independent_migrated_pools().await?;
    let (_, owner, script) = accepted_binding_fixture(&pools.first).await?;
    let bindings = reconcile_bip448_funding_bindings(
        &pools.first,
        "wallet",
        "statechain",
        &owner.to_string(),
        1,
        &[
            sample_binding_observation("34", 0, 100_000, &script),
            sample_binding_observation("11", 1, 70_000, &script),
            sample_binding_observation("12", 2, 60_000, &script),
        ],
    )
    .await?;
    let first_binding = bindings
        .iter()
        .find(|row| row.binding_index == 1)
        .ok_or_else(|| anyhow!("first duplicate binding is missing"))?;
    let second_binding = bindings
        .iter()
        .find(|row| row.binding_index == 2)
        .ok_or_else(|| anyhow!("second duplicate binding is missing"))?;
    let first = sign_duplicate_attempt(&pools.first, first_binding).await?;
    transition_bip448_withdrawal_broadcast_status(
        &pools.first,
        "wallet",
        "statechain",
        1,
        &first.signing_id,
        Bip448BroadcastStatus::NotBroadcast,
        Bip448BroadcastStatus::Accepted,
    )
    .await?;
    let second = sample_duplicate_attempt(second_binding);

    let mut reconciliation = begin_bip448_mutation_guard(&pools.first).await?;
    reconciliation
        .update_withdrawal_broadcast_status(
            "wallet",
            "statechain",
            1,
            &first.signing_id,
            Bip448BroadcastStatus::Accepted,
            Bip448BroadcastStatus::NeedsRebroadcast,
        )
        .await?;
    let hook = Arc::new(Bip448BeginImmediateTestHook::default());
    let task_hook = hook.clone();
    let second_pool = pools.second.clone();
    let task = tokio::spawn(
        BIP448_BEGIN_IMMEDIATE_TEST_HOOK.scope(task_hook, async move {
            insert_bip448_withdrawal_attempt_if_absent(&second_pool, &second).await
        }),
    );
    assert_begin_is_contested(&hook).await?;
    reconciliation.commit().await?;
    hook.after_acquire.notified().await;
    assert!(
        task.await?.is_err(),
        "later attempt must observe NeedsRebroadcast and roll back"
    );
    let attempts = list_bip448_withdrawal_attempts(&pools.first, "wallet", "statechain").await?;
    assert_eq!(attempts.len(), 1);
    assert_eq!(
        attempts[0].broadcast_status,
        Bip448BroadcastStatus::NeedsRebroadcast
    );
    Ok(())
}
