use super::support::*;
use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
struct MercuryDeletionRows {
    statechain_data: i64,
    bip448_signature_data: i64,
    completed_bip448_signature_data: i64,
    signing_nonce_leases: i64,
    statechain_transfer: i64,
}

impl MercuryDeletionRows {
    fn populated() -> Self {
        Self {
            statechain_data: 1,
            bip448_signature_data: 2,
            completed_bip448_signature_data: 1,
            signing_nonce_leases: 1,
            statechain_transfer: 1,
        }
    }

    fn absent() -> Self {
        Self {
            statechain_data: 0,
            bip448_signature_data: 0,
            completed_bip448_signature_data: 0,
            signing_nonce_leases: 0,
            statechain_transfer: 0,
        }
    }
}

async fn load_mercury_deletion_rows(
    pool: &sqlx::PgPool,
    statechain_id: &str,
) -> Result<MercuryDeletionRows> {
    let row: (i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT \
            (SELECT COUNT(*) FROM statechain_data WHERE statechain_id = $1), \
            (SELECT COUNT(*) FROM bip448_signature_data WHERE statechain_id = $1), \
            (SELECT COUNT(*) FROM bip448_signature_data \
             WHERE statechain_id = $1 AND server_partial_sig IS NOT NULL), \
            (SELECT COUNT(*) FROM signing_nonce_leases WHERE statechain_id = $1), \
            (SELECT COUNT(*) FROM statechain_transfer WHERE statechain_id = $1)",
    )
    .bind(statechain_id)
    .fetch_one(pool)
    .await?;

    Ok(MercuryDeletionRows {
        statechain_data: row.0,
        bip448_signature_data: row.1,
        completed_bip448_signature_data: row.2,
        signing_nonce_leases: row.3,
        statechain_transfer: row.4,
    })
}

async fn prepare_mercury_deletion_fixture(
    mercury_client: &reqwest::Client,
    pool: &sqlx::PgPool,
    completed_signing_byte: u8,
    pending_signing_byte: u8,
    recipient_secret_byte: u8,
    x1_byte: u8,
) -> Result<mercurylib::wallet::Coin> {
    let (_wallet, coin) = mercury::create_deposited_coin(mercury_client).await?;
    let statechain_id = coin
        .statechain_id
        .as_deref()
        .context("deposited coin missing statechain_id")?;
    let completed_signing_id = hex::encode([completed_signing_byte; 32]);
    complete_bip448_signing_round(mercury_client, &coin, completed_signing_id).await?;

    let pending_signing_id = hex::encode([pending_signing_byte; 32]);
    let pending_nonce = mercury::bip448_sign_first(
        mercury_client,
        &Bip448SignFirstRequestPayload {
            statechain_id: statechain_id.to_string(),
            signed_statechain_id: coin
                .signed_statechain_id
                .as_ref()
                .context("deposited coin missing signed_statechain_id")?
                .clone(),
            signing_id: pending_signing_id,
        },
    )
    .await?;
    ensure!(
        pending_nonce.server_pubnonce.len() == 132,
        "pending signing nonce was not persisted"
    );

    let secp = Secp256k1::new();
    let recipient_secret = SecretKey::from_secret_bytes([recipient_secret_byte; 32])?;
    mercury::insert_statechain_transfer_row(
        statechain_id,
        &recipient_secret.public_key(&secp),
        [x1_byte; 32],
    )
    .await?;

    let rows = load_mercury_deletion_rows(pool, statechain_id).await?;
    ensure!(
        rows == MercuryDeletionRows::populated(),
        "deletion fixture did not populate every Mercury row class: {rows:?}"
    );

    Ok(coin)
}

async fn mercury_withdraw_complete_response(
    client: &reqwest::Client,
    coin: &mercurylib::wallet::Coin,
) -> Result<reqwest::Response> {
    let statechain_id = coin
        .statechain_id
        .as_ref()
        .context("deposited coin missing statechain_id")?;
    let signed_statechain_id = coin
        .signed_statechain_id
        .as_ref()
        .context("deposited coin missing signed_statechain_id")?;

    client
        .post(format!("{}/withdraw/complete", mercury::url()))
        .json(&WithdrawCompletePayload {
            statechain_id: statechain_id.clone(),
            signed_statechain_id: signed_statechain_id.clone(),
        })
        .send()
        .await
        .context("failed to call mercury withdraw/complete")
}

async fn response_status_and_body(
    response: reqwest::Response,
    context: &str,
) -> Result<(StatusCode, String)> {
    let status = response.status();
    let body = response
        .text()
        .await
        .with_context(|| format!("failed to read {context} body"))?;

    Ok((status, body))
}

async fn wait_until_lockbox_database_ready() -> Result<()> {
    let mut first_error = None;

    for _ in 0..60 {
        let readiness = async {
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(Duration::from_secs(1))
                .connect(lockbox::database_url())
                .await?;
            sqlx::query("SELECT 1").execute(&pool).await?;
            Ok::<(), sqlx::Error>(())
        }
        .await;

        match readiness {
            Ok(()) => {
                if let Some(first_error) = first_error {
                    eprintln!(
                        "lockbox database readiness was initially pending after restart: {first_error}"
                    );
                }
                return Ok(());
            }
            Err(err) => {
                if first_error.is_none() {
                    first_error = Some(err);
                }
                sleep(Duration::from_secs(1)).await;
            }
        }
    }

    Err(anyhow::anyhow!(
        "lockbox database did not become ready within 60 seconds; first error: {}",
        first_error
            .map(|err| err.to_string())
            .unwrap_or_else(|| "no connection attempt was recorded".to_string())
    ))
}

pub(super) async fn delete_statechain_is_idempotent_and_deleted_statechain_cannot_be_used(
) -> Result<()> {
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    lockbox::wait_until_ready(&client).await?;

    let statechain_id = lockbox::new_statechain_id("delete-state");
    let signing_id = hex::encode([0x24u8; 32]);
    let created = lockbox::create_statechain(&client, &statechain_id).await?;
    let nonce_payload = Bip448LockboxSignFirstRequestPayload {
        statechain_id: statechain_id.clone(),
        signing_id: signing_id.clone(),
    };
    let nonce_request = lockbox::bip448_sign_first_request_value(&client, &nonce_payload).await?;
    let server_pubnonce = lockbox::bip448_get_public_nonce(&client, &nonce_payload).await?;
    let partial_signature_fixture = lockbox::build_bip448_partial_signature_fixture(
        &statechain_id,
        &signing_id,
        &created.server_pubkey,
        &server_pubnonce.server_pubnonce,
    )?;
    let partial_signature_request =
        lockbox::bip448_partial_request_value(&client, &partial_signature_fixture.payload).await?;
    let keyupdate_request =
        lockbox::build_keyupdate_request(&client, &statechain_id, [7u8; 32], [8u8; 32]).await?;

    let delete_response =
        lockbox::delete(&client, &format!("delete_statechain/{}", statechain_id)).await?;
    let delete_status = delete_response.status();
    let delete_body = delete_response
        .text()
        .await
        .context("failed to read first delete_statechain body")?;

    assert_eq!(delete_status, StatusCode::OK);
    assert_eq!(delete_body, "Statechain deleted.");

    let second_delete_response =
        lockbox::delete(&client, &format!("delete_statechain/{}", statechain_id)).await?;
    let second_delete_status = second_delete_response.status();
    let second_delete_body = second_delete_response
        .text()
        .await
        .context("failed to read second delete_statechain body")?;

    assert_eq!(second_delete_status, StatusCode::OK);
    assert_eq!(second_delete_body, "Statechain deleted.");

    let nonce_response =
        lockbox::post_json(&client, "bip448/get_public_nonce", nonce_request).await?;
    assert_missing_statechain_error(nonce_response, "post-delete bip448/get_public_nonce").await?;

    let partial_signature_response = lockbox::post_json(
        &client,
        "bip448/get_partial_signature",
        partial_signature_request,
    )
    .await?;
    let partial_signature_status = partial_signature_response.status();
    let partial_signature_body = partial_signature_response
        .text()
        .await
        .context("failed to read post-delete bip448/get_partial_signature body")?;
    assert_eq!(partial_signature_status, StatusCode::NOT_FOUND);
    assert_eq!(partial_signature_body, "BIP448 state not found");

    let keyupdate_response = lockbox::post_json(
        &client,
        "keyupdate",
        serde_json::to_value(&keyupdate_request)?,
    )
    .await?;
    assert_missing_statechain_error(keyupdate_response, "post-delete keyupdate").await?;

    let sig_count_response =
        lockbox::get(&client, &format!("signature_count/{}", statechain_id)).await?;
    let sig_count_status = sig_count_response.status();
    let sig_count_body = sig_count_response
        .text()
        .await
        .context("failed to read post-delete signature_count body")?;

    assert_eq!(sig_count_status, StatusCode::NOT_FOUND);
    assert!(sig_count_body.contains("Signature count not found."));

    Ok(())
}

pub(super) async fn mercury_withdraw_complete_preserves_rows_when_lockbox_delete_fails(
) -> Result<()> {
    let _guard = common::test_guard();
    let mercury_client = mercury::http_client();
    let lockbox_client = lockbox::http_client();
    mercury::wait_until_ready(&mercury_client).await?;
    lockbox::wait_until_ready(&lockbox_client).await?;

    let mercury_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(mercury::database_url())
        .await
        .context("failed to connect to mercury postgres")?;
    let outage_coin =
        prepare_mercury_deletion_fixture(&mercury_client, &mercury_pool, 0x71, 0x72, 0x73, 0x74)
            .await?;
    let outage_statechain_id = outage_coin
        .statechain_id
        .as_deref()
        .context("outage fixture missing statechain_id")?
        .to_string();

    lockbox::stop_token_stack_lockbox_database().await?;
    let outage_assertions = async {
        let direct_delete = lockbox::delete(
            &lockbox_client,
            &format!("delete_statechain/{outage_statechain_id}"),
        )
        .await?;
        let (direct_status, direct_body) =
            response_status_and_body(direct_delete, "lockbox outage delete").await?;
        ensure!(
            direct_status == StatusCode::INTERNAL_SERVER_ERROR,
            "direct lockbox delete during database outage returned {direct_status}: {direct_body}"
        );
        ensure!(
            direct_body == "BIP448 storage operation failed",
            "unexpected direct lockbox outage body: {direct_body}"
        );

        let mercury_delete =
            mercury_withdraw_complete_response(&mercury_client, &outage_coin).await?;
        let (mercury_status, mercury_body) =
            response_status_and_body(mercury_delete, "mercury outage completion").await?;
        ensure!(
            mercury_status == StatusCode::INTERNAL_SERVER_ERROR,
            "Mercury completion during lockbox outage returned {mercury_status}: {mercury_body}"
        );
        ensure!(
            mercury_body.contains("lockbox delete_statechain returned 500"),
            "Mercury did not classify the lockbox 500 before deletion: {mercury_body}"
        );

        let preserved_rows =
            load_mercury_deletion_rows(&mercury_pool, &outage_statechain_id).await?;
        ensure!(
            preserved_rows == MercuryDeletionRows::populated(),
            "Mercury rows changed after failed lockbox deletion: {preserved_rows:?}"
        );

        Ok::<(), anyhow::Error>(())
    }
    .await;

    let restart_result = lockbox::start_token_stack_lockbox_database(&lockbox_client).await;
    restart_result?;
    outage_assertions?;

    wait_until_lockbox_database_ready().await?;

    let completed_after_restart =
        mercury_withdraw_complete_response(&mercury_client, &outage_coin).await?;
    let (completed_status, completed_body) = response_status_and_body(
        completed_after_restart,
        "mercury completion after lockbox database restart",
    )
    .await?;
    ensure!(
        completed_status == StatusCode::OK,
        "completion after lockbox database restart returned {completed_status}: {completed_body}"
    );
    ensure!(
        completed_body == r#"{"message":"Statechain deleted."}"#,
        "unexpected successful Mercury completion body: {completed_body}"
    );
    ensure!(
        load_mercury_deletion_rows(&mercury_pool, &outage_statechain_id).await?
            == MercuryDeletionRows::absent(),
        "Mercury completion did not delete all four row classes"
    );

    let repeated_completion =
        mercury_withdraw_complete_response(&mercury_client, &outage_coin).await?;
    let (repeated_status, repeated_body) =
        response_status_and_body(repeated_completion, "repeated Mercury completion").await?;
    ensure!(
        repeated_status == StatusCode::INTERNAL_SERVER_ERROR,
        "repeated completion returned {repeated_status}: {repeated_body}"
    );
    ensure!(
        repeated_body == r#"{"message":"Signature does not match authentication key."}"#,
        "repeated completion did not follow current authentication/absence behavior: {repeated_body}"
    );
    ensure!(
        load_mercury_deletion_rows(&mercury_pool, &outage_statechain_id).await?
            == MercuryDeletionRows::absent(),
        "repeated completion recreated Mercury rows"
    );

    let partial_failure_coin =
        prepare_mercury_deletion_fixture(&mercury_client, &mercury_pool, 0x75, 0x76, 0x77, 0x78)
            .await?;
    let partial_failure_statechain_id = partial_failure_coin
        .statechain_id
        .as_deref()
        .context("partial-failure fixture missing statechain_id")?
        .to_string();

    let initial_info = mercury_client
        .get(format!(
            "{}/info/statechain/{partial_failure_statechain_id}",
            mercury::url()
        ))
        .send()
        .await
        .context("failed to call initial Mercury statechain info")?;
    let (initial_info_status, initial_info_body) =
        response_status_and_body(initial_info, "initial Mercury statechain info").await?;
    ensure!(
        initial_info_status == StatusCode::OK,
        "initial Mercury statechain info returned {initial_info_status}: {initial_info_body}"
    );

    let direct_delete = lockbox::delete(
        &lockbox_client,
        &format!("delete_statechain/{partial_failure_statechain_id}"),
    )
    .await?;
    let (direct_delete_status, direct_delete_body) =
        response_status_and_body(direct_delete, "partial-failure lockbox delete").await?;
    ensure!(
        direct_delete_status == StatusCode::OK,
        "direct lockbox delete returned {direct_delete_status}: {direct_delete_body}"
    );
    ensure!(
        direct_delete_body == "Statechain deleted.",
        "unexpected direct lockbox delete body: {direct_delete_body}"
    );
    ensure!(
        load_mercury_deletion_rows(&mercury_pool, &partial_failure_statechain_id).await?
            == MercuryDeletionRows::populated(),
        "direct lockbox deletion changed Mercury rows"
    );

    let lockbox_missing_info = mercury_client
        .get(format!(
            "{}/info/statechain/{partial_failure_statechain_id}",
            mercury::url()
        ))
        .send()
        .await
        .context("failed to call Mercury statechain info after lockbox-only deletion")?;
    let (lockbox_missing_status, lockbox_missing_body) = response_status_and_body(
        lockbox_missing_info,
        "Mercury statechain info after lockbox-only deletion",
    )
    .await?;
    ensure!(
        lockbox_missing_status == StatusCode::INTERNAL_SERVER_ERROR,
        "lockbox-only absence masqueraded as Mercury absence: {lockbox_missing_status}: {lockbox_missing_body}"
    );
    ensure!(
        lockbox_missing_body
            .contains("lockbox BIP448 state is unavailable for an existing Mercury statechain"),
        "Mercury did not report the lockbox state divergence: {lockbox_missing_body}"
    );

    let partial_failure_completion =
        mercury_withdraw_complete_response(&mercury_client, &partial_failure_coin).await?;
    let (partial_completion_status, partial_completion_body) = response_status_and_body(
        partial_failure_completion,
        "Mercury completion after lockbox-only deletion",
    )
    .await?;
    ensure!(
        partial_completion_status == StatusCode::OK,
        "Mercury completion after lockbox-only deletion returned {partial_completion_status}: {partial_completion_body}"
    );
    ensure!(
        partial_completion_body == r#"{"message":"Statechain deleted."}"#,
        "unexpected partial-failure completion body: {partial_completion_body}"
    );
    ensure!(
        load_mercury_deletion_rows(&mercury_pool, &partial_failure_statechain_id).await?
            == MercuryDeletionRows::absent(),
        "partial-failure completion did not delete all four Mercury row classes"
    );

    let final_info = mercury_client
        .get(format!(
            "{}/info/statechain/{partial_failure_statechain_id}",
            mercury::url()
        ))
        .send()
        .await
        .context("failed to call final Mercury statechain info")?;
    let (final_info_status, final_info_body) =
        response_status_and_body(final_info, "final Mercury statechain info").await?;
    ensure!(
        final_info_status == StatusCode::NOT_FOUND,
        "final Mercury statechain absence returned {final_info_status}: {final_info_body}"
    );
    ensure!(
        final_info_body == r#"{"message":"Statechain Id key not found."}"#,
        "unexpected final Mercury statechain absence body: {final_info_body}"
    );

    Ok(())
}
