use super::*;

pub(super) async fn bip448_discovery_cursor_reorg_and_restart_state() -> Result<()> {
    let _guard = common::test_guard();

    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;

    let client_config = common::prepare_test_env().await?;
    let scan_address =
        common::bitcoin_core::regtest_address(&common::bitcoin_core::getnewaddress()?)?;
    let first = fund_address_output(&scan_address, FUNDING_AMOUNT_SATS)?;
    common::bitcoin_core::mine_block()?;
    common::bitcoin_core::set_wallet_outpoint_locked(first.outpoint, true)?;

    let wallet_name = format!("bip448-scan-state-{}", uuid::Uuid::new_v4());
    let mut wallet = mercuryrustlib::wallet::create_wallet(&wallet_name, &client_config).await?;
    let wallet_birth_height = wallet.blockheight;
    let mut coin = wallet.get_new_coin()?;
    coin.aggregated_address = Some(scan_address.to_string());
    // Keep this scan-state fixture out of the signing path, which its synthetic
    // statechain does not configure, while retaining descriptor discovery.
    coin.amount = Some(u32::try_from(first.value_sats)?.saturating_add(1));
    coin.statechain_id = Some(format!("bip448-scan-{}", uuid::Uuid::new_v4()));
    coin.statechain_protocol = Some(BIP448_COIN_PROTOCOL.to_string());
    wallet.coins.push(coin);
    mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, &wallet).await?;

    let script_hex = hex::encode(scan_address.script_pubkey().as_bytes());
    mercuryrustlib::chain::take_scan_blocks_calls();
    mercuryrustlib::coin_status::update_coins(&client_config, &wallet_name).await?;
    let first_calls = mercuryrustlib::chain::take_scan_blocks_calls();
    assert_eq!(first_calls.len(), 1);
    assert_eq!(first_calls[0].0, wallet_birth_height);
    let (first_cursor_height, _): (i64, String) = sqlx::query_as(
        "SELECT last_scanned_height, last_scanned_block_hash \
         FROM bip448_scan_cursors WHERE wallet_name = $1 AND script_pubkey = $2",
    )
    .bind(&wallet_name)
    .bind(&script_hex)
    .fetch_one(&client_config.pool)
    .await?;

    common::bitcoin_core::mine_block()?;
    let next_tip = client_config.chain_client.tip_height()?;
    mercuryrustlib::chain::take_scan_blocks_calls();
    mercuryrustlib::coin_status::update_coins(&client_config, &wallet_name).await?;
    assert_eq!(
        mercuryrustlib::chain::take_scan_blocks_calls(),
        vec![(u32::try_from(first_cursor_height)? + 1, next_tip)]
    );

    let second = fund_address_output(&scan_address, FUNDING_AMOUNT_SATS)?;
    common::bitcoin_core::mine_block()?;
    mercuryrustlib::coin_status::update_coins(&client_config, &wallet_name).await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bip448_scanned_outpoints \
             WHERE wallet_name = $1 AND txid = $2 AND vout = $3",
        )
        .bind(&wallet_name)
        .bind(second.outpoint.txid.to_string())
        .bind(i64::from(second.outpoint.vout))
        .fetch_one(&client_config.pool)
        .await?,
        1
    );

    client_config.pool.close().await;
    common::bitcoin_core::spend_wallet_outpoint(second.outpoint, second.value_sats)?;
    let restarted_config = mercuryrustlib::client_config::load().await;
    mercuryrustlib::coin_status::update_coins(&restarted_config, &wallet_name).await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bip448_scanned_outpoints \
             WHERE wallet_name = $1 AND txid = $2 AND vout = $3",
        )
        .bind(&wallet_name)
        .bind(second.outpoint.txid.to_string())
        .bind(i64::from(second.outpoint.vout))
        .fetch_one(&restarted_config.pool)
        .await?,
        0
    );

    let reservation_statechain = format!("scan-reservation-{}", uuid::Uuid::new_v4());
    let reservation_id = format!("{reservation_statechain}:funding_update");
    let fake_txid = "f0".repeat(32);
    let fee_inputs = serde_json::json!([
        {
            "txid": first.outpoint.txid.to_string(),
            "vout": first.outpoint.vout,
            "value_sats": first.value_sats,
        },
        {
            "txid": fake_txid,
            "vout": 7,
            "value_sats": 12345,
        }
    ]);
    sqlx::query(
        "INSERT INTO bip448_package_attempts \
            (wallet_name, statechain_id, role, parent_txid, child_txid, child_tx_hex, \
             fee_inputs_json, target_feerate_sat_per_vbyte, status) \
         VALUES ($1, $2, 'funding_update', $3, $4, '00', $5, 2.0, 'Pending')",
    )
    .bind(&wallet_name)
    .bind(&reservation_statechain)
    .bind("a1".repeat(32))
    .bind("b2".repeat(32))
    .bind(fee_inputs.to_string())
    .execute(&restarted_config.pool)
    .await?;
    sqlx::query(
        "UPDATE bip448_scanned_outpoints SET reserved_by = $1, reserved_at = unixepoch() \
         WHERE wallet_name = $2 AND txid = $3 AND vout = $4",
    )
    .bind(&reservation_id)
    .bind(&wallet_name)
    .bind(first.outpoint.txid.to_string())
    .bind(i64::from(first.outpoint.vout))
    .execute(&restarted_config.pool)
    .await?;
    sqlx::query(
        "INSERT INTO bip448_scanned_outpoints \
            (wallet_name, txid, vout, script_pubkey, value_sats, height, \
             reserved_by, reserved_at) \
         VALUES ($1, $2, 7, $3, 12345, 1, $4, unixepoch())",
    )
    .bind(&wallet_name)
    .bind(&fake_txid)
    .bind(&script_hex)
    .bind(&reservation_id)
    .execute(&restarted_config.pool)
    .await?;
    let genesis_hash = restarted_config.chain_client.get_block_hash(0)?.to_string();
    sqlx::query(
        "UPDATE bip448_scan_cursors SET last_scanned_block_hash = $1 \
         WHERE wallet_name = $2 AND script_pubkey = $3",
    )
    .bind(genesis_hash)
    .bind(&wallet_name)
    .bind(&script_hex)
    .execute(&restarted_config.pool)
    .await?;

    let rescan_tip = restarted_config.chain_client.tip_height()?;
    mercuryrustlib::chain::take_scan_blocks_calls();
    mercuryrustlib::coin_status::update_coins(&restarted_config, &wallet_name).await?;
    assert_eq!(
        mercuryrustlib::chain::take_scan_blocks_calls(),
        vec![(wallet_birth_height, rescan_tip)]
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bip448_scanned_outpoints \
             WHERE wallet_name = $1 AND txid = $2",
        )
        .bind(&wallet_name)
        .bind(&fake_txid)
        .fetch_one(&restarted_config.pool)
        .await?,
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT reserved_by FROM bip448_scanned_outpoints \
             WHERE wallet_name = $1 AND txid = $2 AND vout = $3",
        )
        .bind(&wallet_name)
        .bind(first.outpoint.txid.to_string())
        .bind(i64::from(first.outpoint.vout))
        .fetch_one(&restarted_config.pool)
        .await?,
        reservation_id
    );
    let (cursor_height, cursor_hash): (i64, String) = sqlx::query_as(
        "SELECT last_scanned_height, last_scanned_block_hash \
         FROM bip448_scan_cursors WHERE wallet_name = $1 AND script_pubkey = $2",
    )
    .bind(&wallet_name)
    .bind(&script_hex)
    .fetch_one(&restarted_config.pool)
    .await?;
    assert_eq!(u32::try_from(cursor_height)?, rescan_tip);
    assert_eq!(
        cursor_hash,
        restarted_config
            .chain_client
            .get_block_hash(rescan_tip)?
            .to_string()
    );

    common::bitcoin_core::set_wallet_outpoint_locked(first.outpoint, false)?;
    Ok(())
}
