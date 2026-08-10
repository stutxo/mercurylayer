#[path = "common/mod.rs"]
mod common;

use std::str::FromStr;

use anyhow::{Context, Result};
use bitcoin::{Address, OutPoint, Txid};
use common::bip448_regtest::{fund_address_output, FUNDING_AMOUNT_SATS};
use mercuryrustlib::CoinStatus;

const DUPLICATE_AMOUNT_SATS: u32 = 73_421;

async fn accepted_state_bytes(
    pool: &sqlx::SqlitePool,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<(String, Vec<(i64, String)>)> {
    let record_json = sqlx::query_scalar(
        "SELECT record_json FROM bip448_statechains \
         WHERE wallet_name = $1 AND statechain_id = $2",
    )
    .bind(wallet_name)
    .bind(statechain_id)
    .fetch_one(pool)
    .await?;
    let history_rows = sqlx::query_as(
        "SELECT state_number, entry_json FROM bip448_state_history \
         WHERE wallet_name = $1 AND statechain_id = $2 ORDER BY state_number",
    )
    .bind(wallet_name)
    .bind(statechain_id)
    .fetch_all(pool)
    .await?;

    Ok((record_json, history_rows))
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_repeated_funding_preserves_canonical_state_and_signature_count() -> Result<()> {
    let _guard = common::test_guard();

    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;
    let lockbox_client = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox_client).await?;

    let client_config = common::prepare_test_env().await?;
    let wallet_name = format!("bip448-duplicates-{}", uuid::Uuid::new_v4());
    let wallet = mercuryrustlib::wallet::create_wallet(&wallet_name, &client_config).await?;
    mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, &wallet).await?;

    let token = mercuryrustlib::deposit::get_token(&client_config).await?;
    let token_id = common::utils::handle_token_response(&client_config, &token).await?;
    let deposit = mercuryrustlib::deposit::get_bip448_deposit_bitcoin_address(
        &client_config,
        &wallet_name,
        &token_id,
        FUNDING_AMOUNT_SATS,
    )
    .await?;
    let aggregate_address =
        Address::from_str(&deposit.address)?.require_network(client_config.network)?;
    let expected_script = aggregate_address.script_pubkey();
    let canonical_funding = fund_address_output(&aggregate_address, FUNDING_AMOUNT_SATS)?;
    common::chain::wait_for_address_outpoint(
        &client_config,
        &deposit.address,
        canonical_funding.outpoint,
        canonical_funding.value_sats,
    )
    .await?;
    common::bitcoin_core::mine_blocks(client_config.confirmation_target)?;
    mercuryrustlib::coin_status::update_coins(&client_config, &wallet_name).await?;

    let wallet_before =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet_name).await?;
    let wallet_coin_count_before = wallet_before.coins.len();
    let statechain_coins_before = wallet_before
        .coins
        .iter()
        .filter(|coin| coin.statechain_id.as_deref() == Some(&deposit.statechain_id))
        .collect::<Vec<_>>();
    assert_eq!(statechain_coins_before.len(), 1);
    let canonical_coin = statechain_coins_before[0];
    assert_eq!(canonical_coin.status, CoinStatus::CONFIRMED);
    assert_eq!(canonical_coin.amount, Some(FUNDING_AMOUNT_SATS));
    let canonical_txid_string = canonical_coin
        .utxo_txid
        .as_deref()
        .context("confirmed BIP448 coin is missing its funding txid")?;
    let canonical_txid = Txid::from_str(canonical_txid_string)?;
    let canonical_vout = canonical_coin
        .utxo_vout
        .context("confirmed BIP448 coin is missing its funding vout")?;
    let canonical_outpoint = OutPoint {
        txid: canonical_txid,
        vout: canonical_vout,
    };
    assert_eq!(canonical_outpoint, canonical_funding.outpoint);

    let accepted_record_before = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &client_config.pool,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    assert_eq!(accepted_record_before.latest_state_number, 1);
    assert_eq!(accepted_record_before.latest_state.state_number, 1);
    assert_eq!(
        accepted_record_before.amount_sats,
        u64::from(FUNDING_AMOUNT_SATS)
    );
    assert_eq!(
        accepted_record_before.funding_outpoint.txid,
        canonical_outpoint.txid.to_string()
    );
    assert_eq!(
        accepted_record_before.funding_outpoint.vout,
        canonical_outpoint.vout
    );
    assert_eq!(
        accepted_record_before.funding_outpoint.value_sats,
        canonical_funding.value_sats
    );
    let (record_json_before, history_rows_before) =
        accepted_state_bytes(&client_config.pool, &wallet_name, &deposit.statechain_id).await?;
    assert_eq!(
        history_rows_before
            .iter()
            .map(|(state_number, _)| *state_number)
            .collect::<Vec<_>>(),
        vec![1]
    );
    let signature_count_before =
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?;
    assert_eq!(signature_count_before, 1);

    assert_ne!(DUPLICATE_AMOUNT_SATS, FUNDING_AMOUNT_SATS);
    let duplicate_funding = fund_address_output(&aggregate_address, DUPLICATE_AMOUNT_SATS)?;
    assert_ne!(duplicate_funding.outpoint, canonical_outpoint);
    common::bitcoin_core::mine_blocks(client_config.confirmation_target)?;

    let canonical_utxo = client_config
        .chain_client
        .get_tx_out(&canonical_outpoint.txid, canonical_outpoint.vout, true)?
        .context("canonical BIP448 funding output is no longer unspent")?;
    let duplicate_utxo = client_config
        .chain_client
        .get_tx_out(
            &duplicate_funding.outpoint.txid,
            duplicate_funding.outpoint.vout,
            true,
        )?
        .context("repeated BIP448 funding output is not unspent")?;
    assert!(canonical_utxo.confirmations >= client_config.confirmation_target);
    assert!(duplicate_utxo.confirmations >= client_config.confirmation_target);
    assert_eq!(canonical_utxo.script_pubkey, expected_script);
    assert_eq!(duplicate_utxo.script_pubkey, expected_script);
    assert_eq!(canonical_utxo.value, canonical_funding.value_sats);
    assert_eq!(duplicate_utxo.value, u64::from(DUPLICATE_AMOUNT_SATS));

    // This is the same update/load preparation used by the list-statecoins path.
    mercuryrustlib::coin_status::update_coins(&client_config, &wallet_name).await?;
    let wallet_after =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet_name).await?;
    assert_eq!(wallet_after.coins.len(), wallet_coin_count_before);
    let statechain_coins_after = wallet_after
        .coins
        .iter()
        .filter(|coin| coin.statechain_id.as_deref() == Some(&deposit.statechain_id))
        .collect::<Vec<_>>();
    assert_eq!(statechain_coins_after.len(), 1);
    let canonical_coin_after = statechain_coins_after[0];
    assert_eq!(
        canonical_coin_after.utxo_txid.as_deref(),
        Some(canonical_txid_string)
    );
    assert_eq!(
        canonical_coin_after.utxo_vout,
        Some(canonical_outpoint.vout)
    );
    assert_eq!(canonical_coin_after.amount, Some(FUNDING_AMOUNT_SATS));
    assert_eq!(canonical_coin_after.status, CoinStatus::CONFIRMED);

    let accepted_record_after = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &client_config.pool,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    assert_eq!(accepted_record_after.latest_state_number, 1);
    assert_eq!(
        accepted_record_after.funding_outpoint,
        accepted_record_before.funding_outpoint
    );
    assert_eq!(
        accepted_record_after.amount_sats,
        accepted_record_before.amount_sats
    );
    let (record_json_after, history_rows_after) =
        accepted_state_bytes(&client_config.pool, &wallet_name, &deposit.statechain_id).await?;
    assert_eq!(record_json_after, record_json_before);
    assert_eq!(history_rows_after, history_rows_before);
    let signature_count_after =
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?;
    assert_eq!(signature_count_after, signature_count_before);

    println!(
        "BIP448 repeated funding: canonical_outpoint={} duplicate_outpoint={} canonical_value_sats={} duplicate_value_sats={} signature_count_before={} signature_count_after={}",
        canonical_outpoint,
        duplicate_funding.outpoint,
        canonical_utxo.value,
        duplicate_utxo.value,
        signature_count_before,
        signature_count_after
    );

    Ok(())
}
