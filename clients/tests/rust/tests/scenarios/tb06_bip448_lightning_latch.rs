use anyhow::Result;
use common::bip448_regtest::FUNDING_AMOUNT_SATS;
use mercuryrustlib::{client_config::ClientConfig, Wallet};
use sha2::{Digest, Sha256};

use crate::common;

async fn phase8_10_config() -> Result<ClientConfig> {
    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury).await?;
    let lockbox = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox).await?;
    common::prepare_test_env().await
}

async fn create_wallet(config: &ClientConfig, role: &str) -> Result<Wallet> {
    let name = format!("bip448-latch-{role}-{}", uuid::Uuid::new_v4());
    let wallet = mercuryrustlib::wallet::create_wallet(&name, config).await?;
    mercuryrustlib::sqlite_manager::insert_wallet(&config.pool, &wallet).await?;
    Ok(wallet)
}

async fn create_confirmed_deposit(config: &ClientConfig, wallet: &Wallet) -> Result<String> {
    let token = mercuryrustlib::deposit::get_token(config).await?;
    let token_id = common::utils::handle_token_response(config, &token).await?;
    let deposit = mercuryrustlib::deposit::get_bip448_deposit_bitcoin_address(
        config,
        &wallet.name,
        &token_id,
        FUNDING_AMOUNT_SATS,
    )
    .await?;
    common::bitcoin_core::sendtoaddress(FUNDING_AMOUNT_SATS, &deposit.address)?;
    common::chain::wait_for_address_utxo(config, &deposit.address, FUNDING_AMOUNT_SATS).await?;
    common::bitcoin_core::mine_blocks(config.confirmation_target)?;
    mercuryrustlib::coin_status::update_coins(config, &wallet.name).await?;
    Ok(deposit.statechain_id)
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn tb06_bip448_lightning_latch() -> Result<()> {
    let _guard = common::test_guard();
    let config = phase8_10_config().await?;
    let sender = create_wallet(&config, "sender").await?;
    let receiver = create_wallet(&config, "receiver").await?;
    let statechain_id = create_confirmed_deposit(&config, &sender).await?;
    let lockbox = common::lockbox::http_client();
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox, &statechain_id).await?,
        1
    );

    let latch =
        mercuryrustlib::lightning_latch::create_pre_image(&config, &sender.name, &statechain_id)
            .await?;
    let recipient =
        mercuryrustlib::transfer_receiver::new_transfer_address(&config, &receiver.name).await?;
    mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender(
        &config,
        &recipient,
        &sender.name,
        &statechain_id,
        Some(latch.batch_id.clone()),
    )
    .await?;
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox, &statechain_id).await?,
        2
    );
    assert_eq!(
        mercuryrustlib::lightning_latch::get_payment_hash(&config, &latch.batch_id).await?,
        Some(latch.hash.clone()),
    );
    let sender_state_before_lock = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &config.pool,
        &sender.name,
        &statechain_id,
    )
    .await?;

    let receiver_wallet_json_before =
        sqlx::query_scalar::<_, String>("SELECT wallet_json FROM wallet WHERE wallet_name = $1")
            .bind(&receiver.name)
            .fetch_one(&config.pool)
            .await?;
    let locked = mercuryrustlib::transfer_receiver::execute(&config, &receiver.name).await?;
    assert!(locked.is_there_batch_locked);
    assert!(locked.received_statechain_ids.is_empty());
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox, &statechain_id).await?,
        2
    );
    let receiver_wallet_json_after =
        sqlx::query_scalar::<_, String>("SELECT wallet_json FROM wallet WHERE wallet_name = $1")
            .bind(&receiver.name)
            .fetch_one(&config.pool)
            .await?;
    assert_eq!(
        receiver_wallet_json_after.as_bytes(),
        receiver_wallet_json_before.as_bytes(),
    );
    assert!(
        mercuryrustlib::sqlite_manager::get_bip448_statechain_optional(
            &config.pool,
            &receiver.name,
            &statechain_id,
        )
        .await?
        .is_none()
    );
    assert!(mercuryrustlib::sqlite_manager::get_bip448_state_history(
        &config.pool,
        &receiver.name,
        &statechain_id,
    )
    .await?
    .is_empty());
    assert_eq!(
        mercuryrustlib::sqlite_manager::get_bip448_statechain(
            &config.pool,
            &sender.name,
            &statechain_id,
        )
        .await?,
        sender_state_before_lock,
    );

    mercuryrustlib::lightning_latch::confirm_pending_invoice(&config, &sender.name, &statechain_id)
        .await?;
    let received = mercuryrustlib::transfer_receiver::execute(&config, &receiver.name).await?;
    assert!(!received.is_there_batch_locked);
    assert_eq!(
        received.received_statechain_ids,
        vec![statechain_id.clone()]
    );
    let accepted = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &config.pool,
        &receiver.name,
        &statechain_id,
    )
    .await?;
    assert_eq!(accepted.latest_state_number, 2);

    let preimage = mercuryrustlib::lightning_latch::retrieve_pre_image(
        &config,
        &sender.name,
        &statechain_id,
        &latch.batch_id,
    )
    .await?;
    assert_eq!(
        hex::encode(Sha256::digest(hex::decode(preimage)?)),
        latch.hash
    );
    Ok(())
}
