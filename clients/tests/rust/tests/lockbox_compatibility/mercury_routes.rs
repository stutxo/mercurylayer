use super::support::*;
use super::*;
use secp256k1::XOnlyPublicKey;

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

async fn assert_browser_lockbox_access_boundary(
    statechain_id: &str,
    expected_server_key: &PublicKey,
) -> Result<()> {
    let client = reqwest::Client::new();
    let challenge = "ab".repeat(32);
    let response = client
        .post(format!("{}/verify_statechain", lockbox::url()))
        .json(&serde_json::json!({
            "statechain_id": statechain_id,
            "challenge": challenge,
        }))
        .send()
        .await?;
    let status = response.status();
    let body: serde_json::Value = response.json().await?;
    ensure!(
        status == StatusCode::OK,
        "public Lockbox proof returned {status}"
    );
    ensure!(
        body["statechain_id"].as_str() == Some(statechain_id)
            && body["challenge"].as_str() == Some(challenge.as_str())
            && body["server_pubkey"].as_str() == Some(expected_server_key.to_string().as_str()),
        "public Lockbox proof did not bind the requested state and challenge"
    );

    let protected_routes = [
        (reqwest::Method::GET, "/"),
        (reqwest::Method::GET, "/health/live"),
        (reqwest::Method::GET, "/health/ready"),
        (
            reqwest::Method::GET,
            "/signature_count/browser-access-check",
        ),
        (reqwest::Method::GET, "/bip448/state/browser-access-check"),
        (reqwest::Method::POST, "/get_public_key"),
        (reqwest::Method::POST, "/bip448/get_public_nonce"),
        (reqwest::Method::POST, "/bip448/get_partial_signature"),
        (reqwest::Method::POST, "/keyupdate"),
        (
            reqwest::Method::DELETE,
            "/delete_statechain/browser-access-check",
        ),
    ];
    for (method, path) in protected_routes {
        let mut request = client.request(method.clone(), format!("{}{path}", lockbox::url()));
        if method == reqwest::Method::POST {
            request = request.json(&serde_json::json!({}));
        }
        let response = request.send().await?;
        ensure!(
            response.status() == StatusCode::UNAUTHORIZED,
            "unauthenticated {method} {path} returned {} instead of 401",
            response.status()
        );
    }
    Ok(())
}

async fn assert_post_lockbox_deposit_recovery(
    mercury_client: &reqwest::Client,
    lockbox_client: &reqwest::Client,
    mercury_pool: &sqlx::PgPool,
    coin: &mercurylib::wallet::Coin,
) -> Result<()> {
    let token = mercury::get_token(mercury_client).await?;
    ensure!(
        token.payment_method != "onchain",
        "post-Lockbox recovery fixture requires a confirmed local token"
    );
    let request = mercurylib::deposit::create_deposit_msg1(coin, &token.token_id)?;
    let auth_key = XOnlyPublicKey::from_str(&request.auth_key)?;
    let statechain_id = token.token_id.replace('-', "");
    sqlx::query(
        "INSERT INTO deposit_initialization \
         (token_id, auth_xonly_public_key, statechain_id, enclave_index) \
         VALUES ($1, $2, $3, 0)",
    )
    .bind(&token.token_id)
    .bind(auth_key.serialize())
    .bind(&statechain_id)
    .execute(mercury_pool)
    .await?;

    let lockbox_key = lockbox::create_statechain(lockbox_client, &statechain_id).await?;
    let active_before: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM statechain_data WHERE token_id=$1")
            .bind(&token.token_id)
            .fetch_one(mercury_pool)
            .await?;
    ensure!(
        active_before == 0,
        "pending reservation leaked into active statechains"
    );

    let recovered = mercury::deposit_init(mercury_client, &request).await?;
    ensure!(
        recovered.statechain_id == statechain_id
            && recovered.server_pubkey == lockbox_key.server_pubkey,
        "Mercury did not recover the exact key already committed by Lockbox"
    );
    let replayed = mercury::deposit_init(mercury_client, &request).await?;
    ensure!(
        replayed.statechain_id == recovered.statechain_id
            && replayed.server_pubkey == recovered.server_pubkey,
        "completed deposit receipt did not replay exactly"
    );

    let (status, receipt_key, active_rows, token_spent): (String, Option<Vec<u8>>, i64, bool) =
        sqlx::query_as(
            "SELECT \
             (SELECT status FROM deposit_initialization WHERE token_id=$1), \
             (SELECT server_public_key FROM deposit_initialization WHERE token_id=$1), \
             (SELECT COUNT(*) FROM statechain_data WHERE token_id=$1), \
             (SELECT spent FROM tokens WHERE token_id=$1)",
        )
        .bind(&token.token_id)
        .fetch_one(mercury_pool)
        .await?;
    ensure!(
        status == "completed"
            && receipt_key.as_deref()
                == Some(
                    PublicKey::from_str(&recovered.server_pubkey)?
                        .serialize()
                        .as_slice()
                )
            && active_rows == 1
            && token_spent,
        "deposit recovery did not atomically publish one active statechain"
    );

    let shared_auth_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM statechain_data WHERE auth_xonly_public_key=$1")
            .bind(auth_key.serialize())
            .fetch_one(mercury_pool)
            .await?;
    ensure!(
        shared_auth_rows >= 2,
        "mutable owner authentication keys remain globally unique"
    );
    Ok(())
}

pub(super) async fn mercury_deposit_init_creates_a_lockbox_backed_statechain() -> Result<()> {
    let _guard = common::test_guard();
    let mercury_client = mercury::http_client();
    let lockbox_client = lockbox::http_client();
    mercury::wait_until_ready(&mercury_client).await?;
    lockbox::wait_until_ready(&lockbox_client).await?;

    let (_wallet, coin) = mercury::create_deposited_coin(&mercury_client).await?;
    let statechain_id = coin.statechain_id.clone().unwrap();
    let expected_server_key = PublicKey::from_str(
        coin.server_pubkey
            .as_deref()
            .context("deposited coin missing server public key")?,
    )?;
    assert_browser_lockbox_access_boundary(&statechain_id, &expected_server_key).await?;

    let replayed_lockbox = lockbox::create_statechain(&lockbox_client, &statechain_id).await?;
    assert_eq!(
        PublicKey::from_str(&replayed_lockbox.server_pubkey)?,
        expected_server_key
    );
    let replay_diagnostics = lockbox::post_json(
        &lockbox_client,
        "get_public_key",
        serde_json::json!({ "statechain_id": statechain_id }),
    )
    .await?;
    ensure!(
        replay_diagnostics.status() == StatusCode::OK,
        "diagnostic Lockbox replay failed"
    );
    let replay_diagnostics: serde_json::Value = replay_diagnostics.json().await?;
    ensure!(
        replay_diagnostics["storage_outcome"] == "existing"
            && replay_diagnostics["key_generation_us"] == 0
            && replay_diagnostics["server_pubkey"].as_str()
                == Some(expected_server_key.to_string().as_str()),
        "exact Lockbox replay generated or returned a different key"
    );
    let lockbox_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(lockbox::database_url())
        .await?;
    let lockbox_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM generated_public_key WHERE statechain_id=$1")
            .bind(&statechain_id)
            .fetch_one(&lockbox_pool)
            .await?;
    assert_eq!(lockbox_rows, 1);

    let mercury_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(mercury::database_url())
        .await?;
    assert_post_lockbox_deposit_recovery(&mercury_client, &lockbox_client, &mercury_pool, &coin)
        .await?;
    let token_id: String =
        sqlx::query_scalar("SELECT token_id FROM statechain_data WHERE statechain_id=$1")
            .bind(&statechain_id)
            .fetch_one(&mercury_pool)
            .await?;
    let replay_request = mercurylib::deposit::create_deposit_msg1(&coin, &token_id)?;
    let replayed_deposit = mercury::deposit_init(&mercury_client, &replay_request).await?;
    assert_eq!(replayed_deposit.statechain_id, statechain_id);
    assert_eq!(
        PublicKey::from_str(&replayed_deposit.server_pubkey)?,
        expected_server_key
    );
    let (deposit_rows, token_spent): (i64, bool) = sqlx::query_as(
        "SELECT \
         (SELECT COUNT(*) FROM statechain_data WHERE statechain_id=$1), \
         (SELECT spent FROM tokens WHERE token_id=$2)",
    )
    .bind(&statechain_id)
    .bind(&token_id)
    .fetch_one(&mercury_pool)
    .await?;
    assert_eq!(deposit_rows, 1);
    assert!(token_spent);
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
            &lockbox_client,
            &statechain_id,
            &new_user_auth_secret,
            x1_secret_key,
            t2,
        )
        .await?,
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
    let original_token_id: String =
        sqlx::query_scalar("SELECT token_id FROM deposit_initialization WHERE statechain_id=$1")
            .bind(&statechain_id)
            .fetch_one(&pool)
            .await?;
    let stale_replay = mercury_client
        .post(format!("{}/deposit/init/pod", mercury::url()))
        .json(&mercurylib::deposit::create_deposit_msg1(
            &coin,
            &original_token_id,
        )?)
        .send()
        .await?;
    assert_eq!(
        stale_replay.status(),
        StatusCode::CONFLICT,
        "a completed deposit receipt must not restore the previous owner after transfer"
    );
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
