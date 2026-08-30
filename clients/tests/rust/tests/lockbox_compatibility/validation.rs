use super::*;

const COUNTER_OVERFLOW: u64 = i64::MAX as u64 + 1;

async fn assert_bad_request(client: &reqwest::Client, path: &str, body: Value) -> Result<()> {
    let response = lockbox::post_json(client, path, body).await?;
    ensure!(
        response.status() == StatusCode::BAD_REQUEST,
        "{path} accepted an invalid request with status {}",
        response.status()
    );
    Ok(())
}

async fn assert_each_missing_field(
    client: &reqwest::Client,
    path: &str,
    exact: &Value,
    fields: &[&str],
) -> Result<()> {
    for field in fields {
        let mut missing = exact.clone();
        ensure!(
            missing
                .as_object_mut()
                .and_then(|body| body.remove(*field))
                .is_some(),
            "missing-field fixture did not contain {field}"
        );
        assert_bad_request(client, path, missing).await?;
    }
    Ok(())
}

fn duplicate_field_json(exact: &Value, field: &str) -> Result<String> {
    let object = exact
        .as_object()
        .context("duplicate-field fixture is not an object")?;
    let value = object
        .get(field)
        .with_context(|| format!("duplicate-field fixture omitted {field}"))?;
    let exact_json = serde_json::to_string(exact)?;
    ensure!(exact_json.starts_with('{'));
    Ok(format!(
        "{{{}:{},{}",
        serde_json::to_string(field)?,
        serde_json::to_string(value)?,
        &exact_json[1..]
    ))
}

async fn assert_duplicate_field_rejected(
    client: &reqwest::Client,
    path: &str,
    exact: &Value,
    field: &str,
) -> Result<()> {
    let response =
        lockbox::post_raw_json(client, path, duplicate_field_json(exact, field)?).await?;
    ensure!(
        response.status() == StatusCode::BAD_REQUEST,
        "{path} accepted duplicate field {field} with status {}",
        response.status()
    );
    Ok(())
}

pub(super) async fn get_public_key_requires_statechain_id() -> Result<()> {
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    lockbox::wait_until_ready(&client).await?;

    let response = lockbox::post_json(&client, "get_public_key", json!({})).await?;
    let status = response.status();
    let body = response
        .text()
        .await
        .context("failed to read get_public_key body")?;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, "Invalid parameter. It must be 'statechain_id'.");

    Ok(())
}

pub(super) async fn bip448_get_public_nonce_requires_existing_statechain() -> Result<()> {
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    lockbox::wait_until_ready(&client).await?;

    let statechain_id = lockbox::new_statechain_id("missing-nonce");
    lockbox::create_statechain(&client, &statechain_id).await?;
    let signing_id = hex::encode([0x11_u8; 32]);
    let payload = Bip448LockboxSignFirstRequestPayload {
        statechain_id: statechain_id.clone(),
        signing_id: signing_id.clone(),
    };
    let exact = lockbox::bip448_sign_first_request_value(&client, &payload).await?;
    let initial_state = lockbox::get_bip448_state(&client, &statechain_id).await?;

    assert_each_missing_field(
        &client,
        "bip448/get_public_nonce",
        &exact,
        &[
            "statechain_id",
            "signing_id",
            "expected_key_generation",
            "expected_server_pubkey",
        ],
    )
    .await?;
    assert_duplicate_field_rejected(&client, "bip448/get_public_nonce", &exact, "signing_id")
        .await?;

    let mut unknown = exact.clone();
    unknown["transaction_hash"] = json!("00".repeat(32));
    assert_bad_request(&client, "bip448/get_public_nonce", unknown).await?;
    let mut overflow = exact.clone();
    overflow["expected_key_generation"] = json!(COUNTER_OVERFLOW);
    assert_bad_request(&client, "bip448/get_public_nonce", overflow).await?;

    assert_eq!(
        lockbox::get_bip448_state(&client, &statechain_id).await?,
        initial_state
    );
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(lockbox::database_url())
        .await?;
    let nonce_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM public.bip448_nonce_state WHERE statechain_id=$1 AND signing_id=$2",
    )
    .bind(&statechain_id)
    .bind(&signing_id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(nonce_count, 0);

    let mut missing_parent = exact;
    missing_parent["statechain_id"] = json!(lockbox::new_statechain_id("missing-parent"));
    let response = lockbox::post_json(&client, "bip448/get_public_nonce", missing_parent).await?;
    let status = response.status();
    let body = response
        .text()
        .await
        .context("failed to read bip448/get_public_nonce body")?;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, "BIP448 state not found");

    lockbox::delete_statechain(&client, &statechain_id).await?;

    Ok(())
}

pub(super) async fn bip448_get_partial_signature_validates_session_length() -> Result<()> {
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    lockbox::wait_until_ready(&client).await?;

    let statechain_id = lockbox::new_statechain_id("bad-session");
    let signing_id = hex::encode([0x12_u8; 32]);
    let created = lockbox::create_statechain(&client, &statechain_id).await?;
    let nonce_payload = Bip448LockboxSignFirstRequestPayload {
        statechain_id: statechain_id.clone(),
        signing_id: signing_id.clone(),
    };
    let nonce = lockbox::bip448_get_public_nonce(&client, &nonce_payload).await?;
    let fixture = lockbox::build_bip448_partial_signature_fixture(
        &statechain_id,
        &signing_id,
        &created.server_pubkey,
        &nonce.server_pubnonce,
    )?;
    let exact = lockbox::bip448_partial_request_value(&client, &fixture.payload).await?;
    let initial_state = lockbox::get_bip448_state(&client, &statechain_id).await?;
    assert_each_missing_field(
        &client,
        "bip448/get_partial_signature",
        &exact,
        &[
            "statechain_id",
            "signing_id",
            "negate_seckey",
            "session",
            "server_pub_nonce",
            "expected_key_generation",
            "expected_server_pubkey",
        ],
    )
    .await?;
    assert_duplicate_field_rejected(&client, "bip448/get_partial_signature", &exact, "session")
        .await?;

    let mut unknown = exact.clone();
    unknown["transaction"] = json!("forbidden");
    assert_bad_request(&client, "bip448/get_partial_signature", unknown).await?;
    let mut overflow = exact.clone();
    overflow["expected_key_generation"] = json!(COUNTER_OVERFLOW);
    assert_bad_request(&client, "bip448/get_partial_signature", overflow).await?;

    let mut invalid_session = exact;
    invalid_session["session"] = json!("00");
    let response =
        lockbox::post_json(&client, "bip448/get_partial_signature", invalid_session).await?;
    let status = response.status();
    let body = response
        .text()
        .await
        .context("failed to read bip448/get_partial_signature body")?;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, "Invalid BIP448 request");

    assert_eq!(
        lockbox::get_bip448_state(&client, &statechain_id).await?,
        initial_state
    );
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(lockbox::database_url())
        .await?;
    let claimed_nonce_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM public.bip448_nonce_state WHERE statechain_id=$1 AND signing_id=$2 AND (challenge IS NOT NULL OR negate_seckey IS NOT NULL OR partial_sig IS NOT NULL)",
    )
    .bind(&statechain_id)
    .bind(&signing_id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(claimed_nonce_count, 0);

    lockbox::delete_statechain(&client, &statechain_id).await?;

    Ok(())
}

pub(super) async fn bip448_get_partial_signature_requires_existing_nonce_state() -> Result<()> {
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    lockbox::wait_until_ready(&client).await?;

    let statechain_id = lockbox::new_statechain_id("missing-sign");
    let existing_signing_id = hex::encode([0x13u8; 32]);
    let missing_signing_id = hex::encode([0x14u8; 32]);
    let created = lockbox::create_statechain(&client, &statechain_id).await?;
    let server_pubnonce = lockbox::bip448_get_public_nonce(
        &client,
        &Bip448LockboxSignFirstRequestPayload {
            statechain_id: statechain_id.clone(),
            signing_id: existing_signing_id,
        },
    )
    .await?;
    let fixture = lockbox::build_bip448_partial_signature_fixture(
        &statechain_id,
        &missing_signing_id,
        &created.server_pubkey,
        &server_pubnonce.server_pubnonce,
    )?;
    let response = lockbox::post_json(
        &client,
        "bip448/get_partial_signature",
        lockbox::bip448_partial_request_value(&client, &fixture.payload).await?,
    )
    .await?;
    let status = response.status();
    let body = response
        .text()
        .await
        .context("failed to read missing BIP448 nonce-state body")?;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, "BIP448 state not found");

    lockbox::delete_statechain(&client, &statechain_id).await?;

    Ok(())
}

pub(super) async fn keyupdate_validates_t2_and_x1_lengths() -> Result<()> {
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    lockbox::wait_until_ready(&client).await?;

    let statechain_id = lockbox::new_statechain_id("bad-keyupdate");
    lockbox::create_statechain(&client, &statechain_id).await?;
    let request =
        lockbox::build_keyupdate_request(&client, &statechain_id, [1; 32], [2; 32]).await?;
    let exact = serde_json::to_value(&request)?;
    let initial_state = lockbox::get_bip448_state(&client, &statechain_id).await?;
    assert_each_missing_field(
        &client,
        "keyupdate",
        &exact,
        &[
            "protocol_version",
            "operation_id",
            "statechain_id",
            "t2",
            "x1",
            "expected_sig_count",
            "expected_key_generation",
            "expected_server_pubkey",
        ],
    )
    .await?;
    assert_duplicate_field_rejected(&client, "keyupdate", &exact, "operation_id").await?;

    let mut unknown = exact.clone();
    unknown["outpoint"] = json!("forbidden");
    assert_bad_request(&client, "keyupdate", unknown).await?;
    let mut wrong_version = exact.clone();
    wrong_version["protocol_version"] = json!(2);
    assert_bad_request(&client, "keyupdate", wrong_version).await?;
    let mut count_overflow = exact.clone();
    count_overflow["expected_sig_count"] = json!(COUNTER_OVERFLOW);
    assert_bad_request(&client, "keyupdate", count_overflow).await?;
    let mut generation_overflow = exact.clone();
    generation_overflow["expected_key_generation"] = json!(COUNTER_OVERFLOW);
    assert_bad_request(&client, "keyupdate", generation_overflow).await?;

    let mut bad_t2_request = exact.clone();
    bad_t2_request["t2"] = json!("00");
    let bad_t2 = lockbox::post_json(&client, "keyupdate", bad_t2_request).await?;
    let bad_t2_status = bad_t2.status();
    let bad_t2_body = bad_t2.text().await.context("failed to read bad t2 body")?;

    assert_eq!(bad_t2_status, StatusCode::BAD_REQUEST);
    assert_eq!(bad_t2_body, "Invalid BIP448 request");

    let mut bad_x1_request = exact;
    bad_x1_request["x1"] = json!("00");
    let bad_x1 = lockbox::post_json(&client, "keyupdate", bad_x1_request).await?;
    let bad_x1_status = bad_x1.status();
    let bad_x1_body = bad_x1.text().await.context("failed to read bad x1 body")?;

    assert_eq!(bad_x1_status, StatusCode::BAD_REQUEST);
    assert_eq!(bad_x1_body, "Invalid BIP448 request");

    assert_eq!(
        lockbox::get_bip448_state(&client, &statechain_id).await?,
        initial_state
    );
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(lockbox::database_url())
        .await?;
    let receipt_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM public.bip448_keyupdate_receipt WHERE statechain_id=$1",
    )
    .bind(&statechain_id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(receipt_count, 0);

    lockbox::delete_statechain(&client, &statechain_id).await?;

    Ok(())
}

pub(super) async fn keyupdate_requires_existing_statechain() -> Result<()> {
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    lockbox::wait_until_ready(&client).await?;

    let statechain_id = lockbox::new_statechain_id("missing-key");
    let server_pubkey = SecretKey::from_secret_bytes([7_u8; 32])?
        .public_key(&Secp256k1::new())
        .to_string();
    let response = lockbox::post_json(
        &client,
        "keyupdate",
        json!({
            "protocol_version": 1,
            "operation_id": hex::encode([8_u8; 32]),
            "statechain_id": statechain_id,
            "t2": hex::encode([5_u8; 32]),
            "x1": hex::encode([6_u8; 32]),
            "expected_sig_count": 0,
            "expected_key_generation": 0,
            "expected_server_pubkey": server_pubkey,
        }),
    )
    .await?;
    let status = response.status();
    let body = response.text().await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, "BIP448 state not found");
    Ok(())
}

pub(super) async fn signature_count_for_missing_statechain_returns_not_found() -> Result<()> {
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    lockbox::wait_until_ready(&client).await?;

    let response = lockbox::get(
        &client,
        &format!(
            "signature_count/{}",
            lockbox::new_statechain_id("missing-count")
        ),
    )
    .await?;
    let status = response.status();
    let body = response
        .text()
        .await
        .context("failed to read missing signature_count body")?;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, "Signature count not found.");

    Ok(())
}
