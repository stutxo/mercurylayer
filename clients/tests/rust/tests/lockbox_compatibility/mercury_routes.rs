use super::support::*;
use super::*;

#[derive(Debug)]
struct Bip448SignatureDataRow {
    server_pubnonce: Option<String>,
    challenge: Option<String>,
    negate_seckey: Option<bool>,
    server_partial_sig: Option<String>,
}

async fn insert_completed_bip448_signature_row(
    statechain_id: &str,
    signing_id: &str,
) -> Result<()> {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(mercury::database_url())
        .await
        .context("failed to connect to mercury postgres")?;
    sqlx::query(
        "INSERT INTO bip448_signature_data \
         (statechain_id, signing_id, server_pubnonce, challenge, negate_seckey, server_partial_sig) \
         VALUES ($1, $2, $3, $4, false, $5)",
    )
    .bind(statechain_id)
    .bind(signing_id)
    .bind("mixed-bip448-server-pubnonce")
    .bind("mixed-bip448-challenge")
    .bind("mixed-bip448-partial-signature")
    .execute(&pool)
    .await?;

    Ok(())
}

async fn load_bip448_signature_data_row(
    pool: &sqlx::PgPool,
    statechain_id: &str,
    signing_id: &str,
) -> Result<Option<Bip448SignatureDataRow>> {
    let row: Option<(Option<String>, Option<String>, Option<bool>, Option<String>)> =
        sqlx::query_as(
            "SELECT server_pubnonce, challenge, negate_seckey, server_partial_sig \
         FROM bip448_signature_data \
         WHERE statechain_id = $1 AND signing_id = $2",
        )
        .bind(statechain_id)
        .bind(signing_id)
        .fetch_optional(pool)
        .await?;

    Ok(row.map(
        |(server_pubnonce, challenge, negate_seckey, server_partial_sig)| Bip448SignatureDataRow {
            server_pubnonce,
            challenge,
            negate_seckey,
            server_partial_sig,
        },
    ))
}

pub(super) async fn mercury_deposit_init_creates_a_lockbox_backed_statechain() -> Result<()> {
    let _guard = common::test_guard();
    let mercury_client = mercury::http_client();
    let lockbox_client = lockbox::http_client();
    mercury::wait_until_ready(&mercury_client).await?;
    lockbox::wait_until_ready(&lockbox_client).await?;

    let (_wallet, coin) = mercury::create_deposited_coin(&mercury_client).await?;
    let statechain_id = coin.statechain_id.clone().unwrap();
    assert_eq!(
        lockbox::get_signature_count(&lockbox_client, &statechain_id).await?,
        0
    );
    let server_pubnonce = lockbox::bip448_get_public_nonce(
        &lockbox_client,
        &Bip448LockboxSignFirstRequestPayload {
            statechain_id: statechain_id.clone(),
            signing_id: hex::encode([0x64u8; 32]),
        },
    )
    .await?;

    assert_eq!(server_pubnonce.server_pubnonce.len(), 132);
    assert_eq!(
        lockbox::get_signature_count(&lockbox_client, &statechain_id).await?,
        0
    );

    lockbox::delete_statechain(&lockbox_client, &statechain_id).await?;

    Ok(())
}

pub(super) async fn mercury_statechain_info_returns_ordered_bip448_rows_and_transfer_clears_them(
) -> Result<()> {
    let _guard = common::test_guard();
    let mercury_client = mercury::http_client();
    let lockbox_client = lockbox::http_client();
    mercury::wait_until_ready(&mercury_client).await?;
    lockbox::wait_until_ready(&lockbox_client).await?;
    common::bitcoin_core::ensure_wallet_ready()?;

    let (_wallet, coin) = mercury::create_deposited_coin(&mercury_client).await?;
    let statechain_id = coin
        .statechain_id
        .as_ref()
        .context("deposited coin missing statechain_id")?
        .clone();
    let first_signing_id = hex::encode([0xa5u8; 32]);
    let first_row =
        complete_bip448_signing_round(&mercury_client, &coin, first_signing_id.clone()).await?;
    let second_signing_id = hex::encode([0x5au8; 32]);
    let second_row =
        complete_bip448_signing_round(&mercury_client, &coin, second_signing_id.clone()).await?;
    let second_nonce = second_row.0.clone();
    let second_challenge = second_row.1.clone();
    let foreign_statechain_id = format!("foreign-{statechain_id}");
    let foreign_signing_id = hex::encode([0xb2u8; 32]);
    insert_completed_bip448_signature_row(&foreign_statechain_id, &foreign_signing_id).await?;

    let secp = Secp256k1::new();
    let new_user_auth_secret = SecretKey::from_secret_bytes([13u8; 32])?;
    let new_user_auth_public_key = new_user_auth_secret.public_key(&secp);
    let x1_secret_key = [14u8; 32];
    mercury::insert_statechain_transfer_row(
        &statechain_id,
        &new_user_auth_public_key,
        x1_secret_key,
    )
    .await?;

    let statechain_info = mercury::statechain_info(&mercury_client, &statechain_id).await?;
    assert_eq!(statechain_info.num_sigs, 2);
    assert_eq!(statechain_info.statechain_info.len(), 2);
    for (row, (expected_nonce, expected_challenge, expected_tx_n)) in
        statechain_info.statechain_info.iter().zip([
            (first_row.0, first_row.1, 1u32),
            (second_row.0, second_row.1, 2u32),
        ])
    {
        assert_eq!(row.statechain_id, statechain_id);
        assert_eq!(lockbox::normalize_hex(&row.server_pubnonce), expected_nonce);
        assert_eq!(row.challenge, expected_challenge);
        assert_eq!(row.tx_n, expected_tx_n);
    }

    mercury::clear_bip448_server_partial_signature(&statechain_id, &first_signing_id).await?;
    let incomplete_info = mercury::statechain_info(&mercury_client, &statechain_id).await?;
    assert_eq!(incomplete_info.num_sigs, 2);
    assert_eq!(incomplete_info.statechain_info.len(), 1);
    assert_eq!(incomplete_info.statechain_info[0].tx_n, 1);
    assert_eq!(
        lockbox::normalize_hex(&incomplete_info.statechain_info[0].server_pubnonce),
        second_nonce
    );
    assert_eq!(
        incomplete_info.statechain_info[0].challenge,
        second_challenge
    );

    let t2 = [15u8; 32];
    unlock_recipient_transfer_generation(
        &mercury_client,
        &statechain_id,
        &new_user_auth_secret,
        x1_secret_key,
    )
    .await?;
    mercury::transfer_receiver(
        &mercury_client,
        &generation_bound_receiver_request(
            &statechain_id,
            &new_user_auth_secret,
            x1_secret_key,
            t2,
        )?,
    )
    .await?;

    let post_transfer_info = mercury::statechain_info(&mercury_client, &statechain_id).await?;
    assert_eq!(post_transfer_info.num_sigs, 2);
    assert_eq!(post_transfer_info.statechain_info.len(), 1);
    assert_eq!(post_transfer_info.statechain_info[0].tx_n, 1);
    assert_eq!(
        lockbox::normalize_hex(&post_transfer_info.statechain_info[0].server_pubnonce),
        second_nonce
    );
    assert_eq!(
        post_transfer_info.statechain_info[0].challenge,
        second_challenge
    );

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(mercury::database_url())
        .await
        .context("failed to connect to mercury postgres")?;
    assert!(
        load_bip448_signature_data_row(&pool, &statechain_id, &first_signing_id)
            .await?
            .is_none(),
        "the transferred statechain's exact incomplete signing row must be deleted"
    );

    let persisted_second_row =
        load_bip448_signature_data_row(&pool, &statechain_id, &second_signing_id)
            .await?
            .context("the transferred statechain's completed signing row was deleted")?;
    assert_eq!(
        lockbox::normalize_hex(
            persisted_second_row
                .server_pubnonce
                .as_deref()
                .context("completed signing row lost server_pubnonce")?
        ),
        second_nonce
    );
    assert_eq!(
        persisted_second_row.challenge.as_deref(),
        Some(second_challenge.as_str())
    );
    assert!(persisted_second_row.negate_seckey.is_some());
    assert_eq!(
        hex::decode(lockbox::normalize_hex(
            persisted_second_row
                .server_partial_sig
                .as_deref()
                .context("completed signing row lost server_partial_sig")?,
        ))?
        .len(),
        32
    );

    let persisted_foreign_row =
        load_bip448_signature_data_row(&pool, &foreign_statechain_id, &foreign_signing_id)
            .await?
            .context("foreign statechain's completed signing row was deleted")?;
    assert_eq!(
        persisted_foreign_row.server_pubnonce.as_deref(),
        Some("mixed-bip448-server-pubnonce")
    );
    assert_eq!(
        persisted_foreign_row.challenge.as_deref(),
        Some("mixed-bip448-challenge")
    );
    assert_eq!(persisted_foreign_row.negate_seckey, Some(false));
    assert_eq!(
        persisted_foreign_row.server_partial_sig.as_deref(),
        Some("mixed-bip448-partial-signature")
    );

    lockbox::delete_statechain(&lockbox_client, &statechain_id).await?;

    Ok(())
}
