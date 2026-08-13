use super::super::scan::clear_bip448_scan_state;
use super::support::*;

#[tokio::test]
async fn bip448_scan_state_round_trips_canonical_txids_and_clears_only_cache() -> Result<()> {
    let pool = migrated_pool().await?;
    let cursor = Bip448ScanCursor {
        coverage_start_height: 7,
        scan_revision: 0,
        last_scanned_height: 42,
        last_scanned_block_hash: "22".repeat(32),
    };
    persist_bip448_scan_state(
        &pool,
        "wallet",
        "51",
        &cursor,
        &[ChainUtxo {
            txid: "AA".repeat(32),
            vout: 1,
            value: 50_000,
            height: 40,
        }],
    )
    .await?;

    let (stored_cursor, outpoints) = load_bip448_scan_state(&pool, "wallet", "51").await?;
    assert_eq!(
        stored_cursor,
        Some(Bip448ScanCursor {
            scan_revision: 1,
            ..cursor.clone()
        })
    );
    assert_eq!(outpoints[0].txid, "aa".repeat(32));

    clear_bip448_scan_state(&pool, "wallet", "51").await?;
    assert_eq!(
        load_bip448_scan_state(&pool, "wallet", "51").await?,
        (
            Some(Bip448ScanCursor {
                scan_revision: 1,
                ..cursor
            }),
            Vec::new()
        )
    );
    Ok(())
}

#[tokio::test]
async fn package_attempt_reserves_expires_releases_and_fails_closed() -> Result<()> {
    let pool = migrated_pool().await?;
    let fee = ChainUtxo {
        txid: "aa".repeat(32),
        vout: 1,
        value: 50_000,
        height: 2,
    };
    upsert_bip448_scanned_outpoint(&pool, "wallet", "51", &fee).await?;
    let attempt = Bip448PackageAttempt {
        wallet_name: "wallet".into(),
        statechain_id: "statechain".into(),
        role: "funding_update".into(),
        parent_txid: "bb".repeat(32),
        child_txid: "cc".repeat(32),
        child_tx_hex: "deadbeef".into(),
        fee_inputs: vec![Bip448FeeInputRecord {
            txid: fee.txid.clone(),
            vout: fee.vout,
            value_sats: fee.value,
        }],
        target_feerate_sat_per_vbyte: 2.0,
        status: Bip448PackageAttemptStatus::Pending,
    };
    insert_bip448_package_attempt(&pool, &attempt).await?;
    assert_eq!(
        get_bip448_package_attempt(&pool, "wallet", "statechain", "funding_update")
            .await?
            .unwrap(),
        attempt
    );
    assert!(
        available_bip448_scanned_outpoints(&pool, "wallet", "51", "other")
            .await?
            .is_empty()
    );
    sqlx::query("UPDATE bip448_scanned_outpoints SET reserved_at = unixepoch() - $1")
        .bind(BIP448_FEE_RESERVATION_TTL_SECONDS + 1)
        .execute(&pool)
        .await?;
    assert_eq!(
        available_bip448_scanned_outpoints(&pool, "wallet", "51", "other")
            .await?
            .len(),
        1
    );
    set_bip448_package_attempt_status(
        &pool,
        "wallet",
        "statechain",
        "funding_update",
        Bip448PackageAttemptStatus::Abandoned,
    )
    .await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bip448_scanned_outpoints WHERE reserved_by IS NOT NULL"
        )
        .fetch_one(&pool)
        .await?,
        0
    );
    sqlx::query("UPDATE bip448_package_attempts SET fee_inputs_json = '{'")
        .execute(&pool)
        .await?;
    assert!(
        get_bip448_package_attempt(&pool, "wallet", "statechain", "funding_update")
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn scan_reset_clears_all_and_rediscovery_restores_only_active_valid_reservations(
) -> Result<()> {
    let pool = migrated_pool().await?;
    let fee = ChainUtxo {
        txid: "aa".repeat(32),
        vout: 1,
        value: 50_000,
        height: 2,
    };
    let mut cursor = Bip448ScanCursor {
        coverage_start_height: 0,
        scan_revision: 0,
        last_scanned_height: 3,
        last_scanned_block_hash: "11".repeat(32),
    };
    persist_bip448_scan_state(&pool, "wallet", "51", &cursor, &[fee.clone()]).await?;
    cursor.scan_revision = 1;
    let attempt = Bip448PackageAttempt {
        wallet_name: "wallet".into(),
        statechain_id: "statechain".into(),
        role: "funding_update".into(),
        parent_txid: "bb".repeat(32),
        child_txid: "cc".repeat(32),
        child_tx_hex: "deadbeef".into(),
        fee_inputs: vec![Bip448FeeInputRecord {
            txid: fee.txid.clone(),
            vout: fee.vout,
            value_sats: fee.value,
        }],
        target_feerate_sat_per_vbyte: 2.0,
        status: Bip448PackageAttemptStatus::Pending,
    };
    insert_bip448_package_attempt(&pool, &attempt).await?;

    clear_bip448_scan_state(&pool, "wallet", "51").await?;
    assert_eq!(
        load_bip448_scan_state(&pool, "wallet", "51").await?,
        (Some(cursor.clone()), Vec::new())
    );
    persist_bip448_scan_state(&pool, "wallet", "51", &cursor, &[fee.clone()]).await?;
    cursor.scan_revision = 2;
    assert_eq!(
        load_bip448_scan_state(&pool, "wallet", "51").await?.1,
        vec![fee.clone()]
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT reserved_by FROM bip448_scanned_outpoints \
             WHERE wallet_name = 'wallet' AND txid = $1 AND vout = 1",
        )
        .bind(&fee.txid)
        .fetch_one(&pool)
        .await?,
        bip448_reservation_id("statechain", "funding_update")
    );
    persist_bip448_scan_state(&pool, "wallet", "51", &cursor, &[]).await?;
    cursor.scan_revision = 3;
    assert!(load_bip448_scan_state(&pool, "wallet", "51")
        .await?
        .1
        .is_empty());

    set_bip448_package_attempt_status(
        &pool,
        "wallet",
        "statechain",
        "funding_update",
        Bip448PackageAttemptStatus::Abandoned,
    )
    .await?;
    clear_bip448_scan_state(&pool, "wallet", "51").await?;
    assert!(load_bip448_scan_state(&pool, "wallet", "51")
        .await?
        .1
        .is_empty());
    Ok(())
}

#[tokio::test]
async fn orphaned_same_operation_reservation_rejects_a_rebuilt_attempt() -> Result<()> {
    let pool = migrated_pool().await?;
    let fee = ChainUtxo {
        txid: "aa".repeat(32),
        vout: 1,
        value: 50_000,
        height: 2,
    };
    upsert_bip448_scanned_outpoint(&pool, "wallet", "51", &fee).await?;
    let attempt = Bip448PackageAttempt {
        wallet_name: "wallet".into(),
        statechain_id: "statechain".into(),
        role: "funding_update".into(),
        parent_txid: "bb".repeat(32),
        child_txid: "cc".repeat(32),
        child_tx_hex: "deadbeef".into(),
        fee_inputs: vec![Bip448FeeInputRecord {
            txid: fee.txid,
            vout: fee.vout,
            value_sats: fee.value,
        }],
        target_feerate_sat_per_vbyte: 2.0,
        status: Bip448PackageAttemptStatus::Pending,
    };
    insert_bip448_package_attempt(&pool, &attempt).await?;
    sqlx::query(
        "DELETE FROM bip448_package_attempts \
         WHERE wallet_name = 'wallet' AND statechain_id = 'statechain'",
    )
    .execute(&pool)
    .await?;
    sqlx::query("UPDATE bip448_scanned_outpoints SET reserved_at = unixepoch() - $1")
        .bind(BIP448_FEE_RESERVATION_TTL_SECONDS + 1)
        .execute(&pool)
        .await?;

    assert!(
        ensure_no_orphaned_bip448_reservation(&pool, "wallet", "statechain", "funding_update",)
            .await
            .is_err()
    );
    assert!(available_bip448_scanned_outpoints(
        &pool,
        "wallet",
        "51",
        &bip448_reservation_id("statechain", "funding_update"),
    )
    .await?
    .is_empty());
    assert!(insert_bip448_package_attempt(&pool, &attempt)
        .await
        .is_err());
    assert!(
        get_bip448_package_attempt(&pool, "wallet", "statechain", "funding_update",)
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn replay_reacquires_expired_reservations_or_fails_after_reclaim() -> Result<()> {
    let pool = migrated_pool().await?;
    let fee = ChainUtxo {
        txid: "aa".repeat(32),
        vout: 1,
        value: 50_000,
        height: 2,
    };
    upsert_bip448_scanned_outpoint(&pool, "wallet", "51", &fee).await?;
    let attempt = Bip448PackageAttempt {
        wallet_name: "wallet".into(),
        statechain_id: "statechain-a".into(),
        role: "funding_update".into(),
        parent_txid: "bb".repeat(32),
        child_txid: "cc".repeat(32),
        child_tx_hex: "deadbeef".into(),
        fee_inputs: vec![Bip448FeeInputRecord {
            txid: fee.txid.clone(),
            vout: fee.vout,
            value_sats: fee.value,
        }],
        target_feerate_sat_per_vbyte: 2.0,
        status: Bip448PackageAttemptStatus::Pending,
    };
    insert_bip448_package_attempt(&pool, &attempt).await?;
    sqlx::query("UPDATE bip448_scanned_outpoints SET reserved_at = unixepoch() - $1")
        .bind(BIP448_FEE_RESERVATION_TTL_SECONDS + 1)
        .execute(&pool)
        .await?;
    reacquire_bip448_package_attempt_reservations(&pool, &attempt).await?;
    assert!(
        available_bip448_scanned_outpoints(&pool, "wallet", "51", "other")
            .await?
            .is_empty()
    );

    sqlx::query("UPDATE bip448_scanned_outpoints SET reserved_at = unixepoch() - $1")
        .bind(BIP448_FEE_RESERVATION_TTL_SECONDS + 1)
        .execute(&pool)
        .await?;
    let mut reclaimed = attempt.clone();
    reclaimed.statechain_id = "statechain-b".into();
    reclaimed.parent_txid = "dd".repeat(32);
    reclaimed.child_txid = "ee".repeat(32);
    insert_bip448_package_attempt(&pool, &reclaimed).await?;
    assert!(
        reacquire_bip448_package_attempt_reservations(&pool, &attempt)
            .await
            .is_err()
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT reserved_by FROM bip448_scanned_outpoints \
             WHERE wallet_name = 'wallet' AND txid = $1 AND vout = 1",
        )
        .bind(&fee.txid)
        .fetch_one(&pool)
        .await?,
        bip448_reservation_id(&reclaimed.statechain_id, &reclaimed.role)
    );
    Ok(())
}
