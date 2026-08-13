use super::support::*;
use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
struct TransferGenerationSnapshot {
    recipient_auth_key: Option<Vec<u8>>,
    x1: Option<Vec<u8>>,
    encrypted_transfer_msg: Option<Vec<u8>>,
    key_updated: Option<bool>,
    batch_id: Option<String>,
    batch_time: Option<String>,
    locked: bool,
    locked2: bool,
    updated_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StatechainGenerationSnapshot {
    auth_key: Option<Vec<u8>>,
    server_key: Option<Vec<u8>>,
    enclave_index: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LatchSnapshot {
    sender_auth_key: Option<Vec<u8>>,
    locked: bool,
    updated_at: String,
}

async fn post_mercury_json(
    client: &reqwest::Client,
    path: &str,
    payload: &Value,
) -> Result<(StatusCode, String)> {
    let response = client
        .post(format!("{}/{path}", mercury::MERCURY_URL))
        .json(payload)
        .send()
        .await
        .with_context(|| format!("failed to post Mercury {path}"))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .with_context(|| format!("failed to read Mercury {path} response"))?;
    Ok((status, body))
}

fn assert_json_response(
    response: &(StatusCode, String),
    expected_status: StatusCode,
    expected_body: Value,
) -> Result<()> {
    ensure!(
        response.0 == expected_status,
        "unexpected status: expected {expected_status}, got {} with {}",
        response.0,
        response.1
    );
    let actual: Value = serde_json::from_str(&response.1)
        .with_context(|| format!("response body was not JSON: {}", response.1))?;
    ensure!(
        actual == expected_body,
        "unexpected response body: expected {expected_body}, got {actual}"
    );
    Ok(())
}

fn coin_auth_secret(coin: &mercurylib::wallet::Coin) -> Result<SecretKey> {
    Ok(PrivateKey::from_wif(&coin.auth_privkey)?.inner)
}

fn sign_statechain_id(auth_secret: &SecretKey, statechain_id: &str) -> String {
    let digest = bitcoin::hashes::sha256::Hash::hash(statechain_id.as_bytes()).to_byte_array();
    let keypair = KeyPair::from_secret_key(&Secp256k1::new(), auth_secret);
    schnorr::sign(&digest, &keypair).to_string()
}

fn sign_digest(auth_secret: &SecretKey, digest: &[u8; 32]) -> String {
    let keypair = KeyPair::from_secret_key(&Secp256k1::new(), auth_secret);
    schnorr::sign(digest, &keypair).to_string()
}

fn sender_request_value(
    statechain_id: &str,
    auth_sig: &str,
    recipient: &PublicKey,
    batch_id: Option<&str>,
) -> Value {
    json!({
        "statechain_id": statechain_id,
        "auth_sig": auth_sig,
        "new_user_auth_key": recipient.to_string(),
        "batch_id": batch_id,
    })
}

fn sender_x1(response: &(StatusCode, String)) -> Result<[u8; 32]> {
    ensure!(
        response.0 == StatusCode::OK,
        "transfer sender returned {}: {}",
        response.0,
        response.1
    );
    let payload: TransferSenderResponsePayload = serde_json::from_str(&response.1)?;
    let bytes: [u8; 32] = hex::decode(payload.x1)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("sender x1 was not 32 bytes"))?;
    SecretKey::from_secret_bytes(bytes)?;
    Ok(bytes)
}

fn update_message_request_value(
    statechain_id: &str,
    owner_auth_secret: &SecretKey,
    recipient: &PublicKey,
    generation: &PublicKey,
    ciphertext: &[u8],
) -> Result<Value> {
    let digest =
        bip448_transfer_update_msg_auth_digest(statechain_id, recipient, generation, ciphertext)?;
    Ok(serde_json::to_value(TransferUpdateMsgRequestPayload {
        statechain_id: statechain_id.to_owned(),
        auth_sig: sign_digest(owner_auth_secret, &digest),
        new_user_auth_key: recipient.to_string(),
        x1_pub: generation.to_string(),
        enc_transfer_msg: hex::encode(ciphertext),
    })?)
}

fn unlock_request_value(
    role: Bip448TransferUnlockRole,
    statechain_id: &str,
    signer: &SecretKey,
    generation: &PublicKey,
) -> Result<Value> {
    let digest = bip448_transfer_unlock_auth_digest(role, statechain_id, generation)?;
    Ok(serde_json::to_value(TransferUnlockRequestPayload {
        statechain_id: statechain_id.to_owned(),
        auth_sig: sign_digest(signer, &digest),
        auth_pub_key: Some(generation.to_string()),
    })?)
}

async fn load_transfer_generation(
    pool: &PgPool,
    statechain_id: &str,
) -> Result<TransferGenerationSnapshot> {
    let row: (
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<bool>,
        Option<String>,
        Option<String>,
        bool,
        bool,
        String,
    ) = sqlx::query_as(
        "SELECT new_user_auth_public_key,x1,encrypted_transfer_msg,key_updated,batch_id,\
         batch_time::text,locked,locked2,updated_at::text FROM statechain_transfer \
         WHERE statechain_id=$1",
    )
    .bind(statechain_id)
    .fetch_one(pool)
    .await?;
    Ok(TransferGenerationSnapshot {
        recipient_auth_key: row.0,
        x1: row.1,
        encrypted_transfer_msg: row.2,
        key_updated: row.3,
        batch_id: row.4,
        batch_time: row.5,
        locked: row.6,
        locked2: row.7,
        updated_at: row.8,
    })
}

async fn load_statechain_generation(
    pool: &PgPool,
    statechain_id: &str,
) -> Result<StatechainGenerationSnapshot> {
    let row: (Option<Vec<u8>>, Option<Vec<u8>>, i32) = sqlx::query_as(
        "SELECT auth_xonly_public_key,server_public_key,enclave_index FROM statechain_data \
         WHERE statechain_id=$1",
    )
    .bind(statechain_id)
    .fetch_one(pool)
    .await?;
    Ok(StatechainGenerationSnapshot {
        auth_key: row.0,
        server_key: row.1,
        enclave_index: row.2,
    })
}

async fn load_latch(
    pool: &PgPool,
    statechain_id: &str,
    batch_id: &str,
) -> Result<Option<LatchSnapshot>> {
    let row: Option<(Option<Vec<u8>>, bool, String)> = sqlx::query_as(
        "SELECT sender_auth_xonly_public_key,locked,updated_at::text FROM lightning_latch \
         WHERE statechain_id=$1 AND batch_id=$2",
    )
    .bind(statechain_id)
    .bind(batch_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| LatchSnapshot {
        sender_auth_key: row.0,
        locked: row.1,
        updated_at: row.2,
    }))
}

async fn load_lockbox_generation(
    pool: &PgPool,
    statechain_id: &str,
) -> Result<(Option<Vec<u8>>, Option<i32>)> {
    Ok(sqlx::query_as(
        "SELECT public_key,sig_count FROM generated_public_key WHERE statechain_id=$1",
    )
    .bind(statechain_id)
    .fetch_one(pool)
    .await?)
}

async fn lock_transfer_row<'a>(
    pool: &'a PgPool,
    statechain_id: &str,
) -> Result<Transaction<'a, Postgres>> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT statechain_id FROM statechain_transfer WHERE statechain_id=$1 FOR UPDATE")
        .bind(statechain_id)
        .fetch_one(&mut *transaction)
        .await?;
    Ok(transaction)
}

async fn wait_for_blocked_mercury_query(pool: &PgPool, needle: &str) -> Result<()> {
    for _ in 0..200 {
        let blocked: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pg_stat_activity WHERE datname=current_database() \
             AND pid <> pg_backend_pid() AND wait_event_type='Lock' AND query LIKE $1",
        )
        .bind(format!("%{needle}%"))
        .fetch_one(pool)
        .await?;
        if blocked > 0 {
            return Ok(());
        }
        sleep(Duration::from_millis(10)).await;
    }
    Err(anyhow::anyhow!(
        "Mercury endpoint did not reach the expected PostgreSQL lock barrier: {needle}"
    ))
}

async fn join_http_task(
    task: JoinHandle<Result<(StatusCode, String)>>,
) -> Result<(StatusCode, String)> {
    task.await.context("Mercury HTTP barrier task panicked")?
}

pub(super) async fn assert_sender_and_update_generation_fences(
    mercury_client: &reqwest::Client,
    mercury_pool: &PgPool,
) -> Result<()> {
    let secp = Secp256k1::new();
    let (_wallet, coin) = mercury::create_deposited_coin(mercury_client).await?;
    let statechain_id = coin
        .statechain_id
        .as_deref()
        .context("sender replay Coin has no statechain ID")?
        .to_owned();
    let signed_statechain_id = coin
        .signed_statechain_id
        .as_deref()
        .context("sender replay Coin has no owner signature")?
        .to_owned();
    let owner_secret = coin_auth_secret(&coin)?;
    let recipient_secret = SecretKey::from_secret_bytes([0x31; 32])?;
    let recipient = recipient_secret.public_key(&secp);
    let batch_id = format!("generation-replay-{}", uuid::Uuid::new_v4());
    let request = sender_request_value(
        &statechain_id,
        &signed_statechain_id,
        &recipient,
        Some(&batch_id),
    );
    let barrier = Arc::new(Barrier::new(3));
    let mut tasks = Vec::new();
    for _ in 0..2 {
        let client = mercury_client.clone();
        let payload = request.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            post_mercury_json(&client, "transfer/sender", &payload).await
        }));
    }
    barrier.wait().await;
    let first = join_http_task(tasks.remove(0)).await?;
    let second = join_http_task(tasks.remove(0)).await?;
    let first_x1 = sender_x1(&first)?;
    let second_x1 = sender_x1(&second)?;
    ensure!(
        first_x1 == second_x1,
        "concurrent exact sender replay changed x1"
    );
    let replay_row = load_transfer_generation(mercury_pool, &statechain_id).await?;
    ensure!(
        replay_row.recipient_auth_key == Some(recipient.serialize().to_vec())
            && replay_row.x1.as_deref() == Some(first_x1.as_slice())
            && replay_row.batch_id.as_deref() == Some(batch_id.as_str())
            && replay_row.key_updated == Some(false),
        "concurrent sender replay stored the wrong generation: {replay_row:?}"
    );
    let replay_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM statechain_transfer WHERE statechain_id=$1")
            .bind(&statechain_id)
            .fetch_one(mercury_pool)
            .await?;
    ensure!(
        replay_count == 1,
        "concurrent sender replay stored {replay_count} rows"
    );

    let mut malformed_sender = request.clone();
    malformed_sender["new_user_auth_key"] = json!("not-a-public-key");
    let malformed_response =
        post_mercury_json(mercury_client, "transfer/sender", &malformed_sender).await?;
    assert_json_response(
        &malformed_response,
        StatusCode::BAD_REQUEST,
        json!({"message":"Invalid new_user_auth_key."}),
    )?;
    ensure!(
        load_transfer_generation(mercury_pool, &statechain_id).await? == replay_row,
        "malformed sender request mutated the replay row"
    );
    let mut unauthenticated_sender = request.clone();
    unauthenticated_sender["auth_sig"] = json!("not-a-signature");
    let unauthenticated_response =
        post_mercury_json(mercury_client, "transfer/sender", &unauthenticated_sender).await?;
    assert_json_response(
        &unauthenticated_response,
        StatusCode::INTERNAL_SERVER_ERROR,
        json!({"message":"Signature does not match authentication key."}),
    )?;
    ensure!(
        load_transfer_generation(mercury_pool, &statechain_id).await? == replay_row,
        "unauthenticated sender request mutated the replay row"
    );

    let (_wallet, competing_coin) = mercury::create_deposited_coin(mercury_client).await?;
    let competing_statechain_id = competing_coin
        .statechain_id
        .as_deref()
        .context("competing sender Coin has no statechain ID")?
        .to_owned();
    let competing_signature = competing_coin
        .signed_statechain_id
        .as_deref()
        .context("competing sender Coin has no owner signature")?
        .to_owned();
    let competing_batch = format!("recipient-race-{}", uuid::Uuid::new_v4());
    let competing_recipients = [
        SecretKey::from_secret_bytes([0x32; 32])?.public_key(&secp),
        SecretKey::from_secret_bytes([0x33; 32])?.public_key(&secp),
    ];
    let barrier = Arc::new(Barrier::new(3));
    let mut competing_tasks = Vec::new();
    for recipient in competing_recipients {
        let client = mercury_client.clone();
        let barrier = barrier.clone();
        let payload = sender_request_value(
            &competing_statechain_id,
            &competing_signature,
            &recipient,
            Some(&competing_batch),
        );
        competing_tasks.push((
            recipient,
            tokio::spawn(async move {
                barrier.wait().await;
                post_mercury_json(&client, "transfer/sender", &payload).await
            }),
        ));
    }
    barrier.wait().await;
    let first_competing = (
        competing_tasks[0].0,
        join_http_task(competing_tasks.remove(0).1).await?,
    );
    let second_competing = (
        competing_tasks[0].0,
        join_http_task(competing_tasks.remove(0).1).await?,
    );
    let results = [first_competing, second_competing];
    ensure!(
        results
            .iter()
            .filter(|(_, response)| response.0 == StatusCode::OK)
            .count()
            == 1,
        "different-recipient batch race did not have one winner: {results:?}"
    );
    let loser = results
        .iter()
        .find(|(_, response)| response.0 != StatusCode::OK)
        .context("different-recipient batch race had no loser")?;
    assert_json_response(
        &loser.1,
        StatusCode::BAD_REQUEST,
        json!({"message":"Statecoin batch locked (the batch time has not expired)."}),
    )?;
    let winner = results
        .iter()
        .find(|(_, response)| response.0 == StatusCode::OK)
        .context("different-recipient batch race had no winner")?;
    sender_x1(&winner.1)?;
    let competing_row = load_transfer_generation(mercury_pool, &competing_statechain_id).await?;
    ensure!(
        competing_row.recipient_auth_key == Some(winner.0.serialize().to_vec())
            && competing_row.batch_id.as_deref() == Some(competing_batch.as_str()),
        "different-recipient batch loser replaced the winner"
    );

    let generation = SecretKey::from_secret_bytes(first_x1)?.public_key(&secp);
    let first_ciphertext = [0x00, 0x01, 0xfe, 0xff];
    let first_update = update_message_request_value(
        &statechain_id,
        &owner_secret,
        &recipient,
        &generation,
        &first_ciphertext,
    )?;
    let first_update_response =
        post_mercury_json(mercury_client, "transfer/update_msg", &first_update).await?;
    assert_json_response(
        &first_update_response,
        StatusCode::OK,
        json!({"updated":true}),
    )?;
    let first_update_replay =
        post_mercury_json(mercury_client, "transfer/update_msg", &first_update).await?;
    assert_json_response(
        &first_update_replay,
        StatusCode::OK,
        json!({"updated":true}),
    )?;
    let randomized_ciphertext = [0x05, 0x04, 0x03, 0x02, 0x01];
    let randomized_update = update_message_request_value(
        &statechain_id,
        &owner_secret,
        &recipient,
        &generation,
        &randomized_ciphertext,
    )?;
    let randomized_response =
        post_mercury_json(mercury_client, "transfer/update_msg", &randomized_update).await?;
    assert_json_response(
        &randomized_response,
        StatusCode::OK,
        json!({"updated":true}),
    )?;
    let updated_row = load_transfer_generation(mercury_pool, &statechain_id).await?;
    ensure!(
        updated_row.x1.as_deref() == Some(first_x1.as_slice())
            && updated_row.encrypted_transfer_msg.as_deref()
                == Some(randomized_ciphertext.as_slice()),
        "legal update replay changed generation or stored the wrong ciphertext"
    );

    let generation_error = json!({
        "error":"Internal Server Error",
        "message":"Transfer message generation does not match current state."
    });
    let authentication_error = json!({
        "error":"Internal Server Error",
        "message":"Signature does not match authentication key."
    });
    let mut missing_x1 = randomized_update.clone();
    missing_x1
        .as_object_mut()
        .context("update request is not an object")?
        .remove("x1_pub");
    let missing_x1_response =
        post_mercury_json(mercury_client, "transfer/update_msg", &missing_x1).await?;
    ensure!(
        missing_x1_response.0 == StatusCode::UNPROCESSABLE_ENTITY,
        "missing update x1_pub did not use Rocket's deserialization status: {missing_x1_response:?}"
    );
    ensure!(
        load_transfer_generation(mercury_pool, &statechain_id).await? == updated_row,
        "missing update x1_pub mutated its row"
    );

    let mut noncanonical_x1 = randomized_update.clone();
    noncanonical_x1["x1_pub"] = json!(generation.to_string().to_uppercase());
    let noncanonical_x1_response =
        post_mercury_json(mercury_client, "transfer/update_msg", &noncanonical_x1).await?;
    assert_json_response(
        &noncanonical_x1_response,
        StatusCode::INTERNAL_SERVER_ERROR,
        generation_error.clone(),
    )?;
    let wrong_generation = SecretKey::from_secret_bytes([0x34; 32])?.public_key(&secp);
    let wrong_generation_request = update_message_request_value(
        &statechain_id,
        &owner_secret,
        &recipient,
        &wrong_generation,
        &randomized_ciphertext,
    )?;
    let wrong_generation_response = post_mercury_json(
        mercury_client,
        "transfer/update_msg",
        &wrong_generation_request,
    )
    .await?;
    assert_json_response(
        &wrong_generation_response,
        StatusCode::INTERNAL_SERVER_ERROR,
        generation_error.clone(),
    )?;
    let substituted_recipient = SecretKey::from_secret_bytes([0x35; 32])?.public_key(&secp);
    let recipient_substitution = update_message_request_value(
        &statechain_id,
        &owner_secret,
        &substituted_recipient,
        &generation,
        &randomized_ciphertext,
    )?;
    let recipient_substitution_response = post_mercury_json(
        mercury_client,
        "transfer/update_msg",
        &recipient_substitution,
    )
    .await?;
    assert_json_response(
        &recipient_substitution_response,
        StatusCode::INTERNAL_SERVER_ERROR,
        generation_error.clone(),
    )?;
    let wrong_statechain = format!("wrong-{}", uuid::Uuid::new_v4());
    let statechain_substitution = update_message_request_value(
        &wrong_statechain,
        &owner_secret,
        &recipient,
        &generation,
        &randomized_ciphertext,
    )?;
    let statechain_substitution_response = post_mercury_json(
        mercury_client,
        "transfer/update_msg",
        &statechain_substitution,
    )
    .await?;
    assert_json_response(
        &statechain_substitution_response,
        StatusCode::INTERNAL_SERVER_ERROR,
        generation_error.clone(),
    )?;
    let mut ciphertext_substitution = randomized_update.clone();
    ciphertext_substitution["enc_transfer_msg"] = json!(hex::encode([0xaa, 0xbb]));
    let ciphertext_substitution_response = post_mercury_json(
        mercury_client,
        "transfer/update_msg",
        &ciphertext_substitution,
    )
    .await?;
    assert_json_response(
        &ciphertext_substitution_response,
        StatusCode::INTERNAL_SERVER_ERROR,
        authentication_error,
    )?;
    ensure!(
        load_transfer_generation(mercury_pool, &statechain_id).await? == updated_row,
        "update-message substitution changed the authenticated generation"
    );

    let (_wallet, stale_coin) = mercury::create_deposited_coin(mercury_client).await?;
    let stale_statechain_id = stale_coin
        .statechain_id
        .as_deref()
        .context("stale upload ID")?;
    let stale_owner = coin_auth_secret(&stale_coin)?;
    let stale_signature = stale_coin
        .signed_statechain_id
        .as_deref()
        .context("stale upload owner signature")?;
    let stale_recipient = SecretKey::from_secret_bytes([0x36; 32])?.public_key(&secp);
    let stale_sender =
        sender_request_value(stale_statechain_id, stale_signature, &stale_recipient, None);
    let stale_sender_response =
        post_mercury_json(mercury_client, "transfer/sender", &stale_sender).await?;
    let stale_x1 = sender_x1(&stale_sender_response)?;
    let stale_generation = SecretKey::from_secret_bytes(stale_x1)?.public_key(&secp);
    let stale_upload = update_message_request_value(
        stale_statechain_id,
        &stale_owner,
        &stale_recipient,
        &stale_generation,
        &[0x91, 0x92],
    )?;
    let successor_batch = format!("same-recipient-successor-{}", uuid::Uuid::new_v4());
    let successor_sender = sender_request_value(
        stale_statechain_id,
        stale_signature,
        &stale_recipient,
        Some(&successor_batch),
    );
    let successor_response =
        post_mercury_json(mercury_client, "transfer/sender", &successor_sender).await?;
    let successor_x1 = sender_x1(&successor_response)?;
    ensure!(
        successor_x1 != stale_x1,
        "same-recipient successor replayed stale x1"
    );
    let successor_row = load_transfer_generation(mercury_pool, stale_statechain_id).await?;
    let stale_upload_response =
        post_mercury_json(mercury_client, "transfer/update_msg", &stale_upload).await?;
    assert_json_response(
        &stale_upload_response,
        StatusCode::INTERNAL_SERVER_ERROR,
        generation_error.clone(),
    )?;
    ensure!(
        load_transfer_generation(mercury_pool, stale_statechain_id).await? == successor_row,
        "stale same-recipient upload changed successor B"
    );

    let (_wallet, ordered_coin) = mercury::create_deposited_coin(mercury_client).await?;
    let ordered_statechain_id = ordered_coin
        .statechain_id
        .as_deref()
        .context("ordered upload statechain ID")?
        .to_owned();
    let ordered_signature = ordered_coin
        .signed_statechain_id
        .as_deref()
        .context("ordered upload owner signature")?
        .to_owned();
    let ordered_owner = coin_auth_secret(&ordered_coin)?;
    let ordered_recipient_a = SecretKey::from_secret_bytes([0x37; 32])?.public_key(&secp);
    let ordered_recipient_b = SecretKey::from_secret_bytes([0x38; 32])?.public_key(&secp);
    let ordered_sender_a = sender_request_value(
        &ordered_statechain_id,
        &ordered_signature,
        &ordered_recipient_a,
        None,
    );
    let ordered_a_response =
        post_mercury_json(mercury_client, "transfer/sender", &ordered_sender_a).await?;
    let ordered_x1 = sender_x1(&ordered_a_response)?;
    let ordered_generation = SecretKey::from_secret_bytes(ordered_x1)?.public_key(&secp);
    let ordered_update = update_message_request_value(
        &ordered_statechain_id,
        &ordered_owner,
        &ordered_recipient_a,
        &ordered_generation,
        &[0x61, 0x62],
    )?;
    let row_lock = lock_transfer_row(mercury_pool, &ordered_statechain_id).await?;
    let update_client = mercury_client.clone();
    let update_payload = ordered_update.clone();
    let mut update_task = tokio::spawn(async move {
        post_mercury_json(&update_client, "transfer/update_msg", &update_payload).await
    });
    wait_for_blocked_mercury_query(
        mercury_pool,
        "SELECT new_user_auth_public_key, x1, key_updated",
    )
    .await?;
    ensure!(
        timeout(Duration::from_millis(100), &mut update_task)
            .await
            .is_err(),
        "A-first upload did not remain blocked at its transfer-row fence"
    );
    let sender_client = mercury_client.clone();
    let sender_b_payload = sender_request_value(
        &ordered_statechain_id,
        &ordered_signature,
        &ordered_recipient_b,
        None,
    );
    let mut sender_task = tokio::spawn(async move {
        post_mercury_json(&sender_client, "transfer/sender", &sender_b_payload).await
    });
    ensure!(
        timeout(Duration::from_millis(100), &mut sender_task)
            .await
            .is_err(),
        "successor sender bypassed A's statechain-data lock"
    );
    row_lock.commit().await?;
    let ordered_update_response = update_task.await??;
    assert_json_response(
        &ordered_update_response,
        StatusCode::OK,
        json!({"updated":true}),
    )?;
    let ordered_sender_response = sender_task.await??;
    sender_x1(&ordered_sender_response)?;
    let ordered_b_row = load_transfer_generation(mercury_pool, &ordered_statechain_id).await?;
    ensure!(
        ordered_b_row.recipient_auth_key == Some(ordered_recipient_b.serialize().to_vec())
            && ordered_b_row.encrypted_transfer_msg.is_none(),
        "A-first upload straddled successor replacement"
    );

    Ok(())
}

async fn assert_unlock_a_first_barrier(
    mercury_client: &reqwest::Client,
    mercury_pool: &PgPool,
    role: Bip448TransferUnlockRole,
    recipient_byte: u8,
    successor_byte: u8,
) -> Result<()> {
    let secp = Secp256k1::new();
    let (_wallet, coin) = mercury::create_deposited_coin(mercury_client).await?;
    let statechain_id = coin
        .statechain_id
        .as_deref()
        .context("A-first unlock Coin has no statechain ID")?
        .to_owned();
    let signed_statechain_id = coin
        .signed_statechain_id
        .as_deref()
        .context("A-first unlock Coin has no owner signature")?
        .to_owned();
    let current_owner = coin_auth_secret(&coin)?;
    let recipient_secret = SecretKey::from_secret_bytes([recipient_byte; 32])?;
    let recipient = recipient_secret.public_key(&secp);
    let successor = SecretKey::from_secret_bytes([successor_byte; 32])?.public_key(&secp);
    let sender_a = sender_request_value(&statechain_id, &signed_statechain_id, &recipient, None);
    let sender_a_response = post_mercury_json(mercury_client, "transfer/sender", &sender_a).await?;
    let x1 = sender_x1(&sender_a_response)?;
    let generation = SecretKey::from_secret_bytes(x1)?.public_key(&secp);
    sqlx::query("UPDATE statechain_transfer SET locked=true,locked2=true WHERE statechain_id=$1")
        .bind(&statechain_id)
        .execute(mercury_pool)
        .await?;
    let signer = match role {
        Bip448TransferUnlockRole::CurrentOwner => &current_owner,
        Bip448TransferUnlockRole::Recipient => &recipient_secret,
    };
    let unlock_payload = unlock_request_value(role, &statechain_id, signer, &generation)?;
    let row_lock = lock_transfer_row(mercury_pool, &statechain_id).await?;
    let unlock_client = mercury_client.clone();
    let mut unlock_task = tokio::spawn(async move {
        post_mercury_json(&unlock_client, "transfer/unlock", &unlock_payload).await
    });
    wait_for_blocked_mercury_query(
        mercury_pool,
        "SELECT new_user_auth_public_key, x1, batch_id, batch_time",
    )
    .await?;
    ensure!(
        timeout(Duration::from_millis(100), &mut unlock_task)
            .await
            .is_err(),
        "A-first {role:?} unlock did not remain blocked on row A"
    );
    let sender_client = mercury_client.clone();
    let sender_b = sender_request_value(&statechain_id, &signed_statechain_id, &successor, None);
    let mut sender_task = tokio::spawn(async move {
        post_mercury_json(&sender_client, "transfer/sender", &sender_b).await
    });
    ensure!(
        timeout(Duration::from_millis(100), &mut sender_task)
            .await
            .is_err(),
        "successor bypassed A-first {role:?} statechain-data lock"
    );
    row_lock.commit().await?;
    let unlock_response = unlock_task.await??;
    assert_json_response(
        &unlock_response,
        StatusCode::OK,
        json!({"message":"Success"}),
    )?;
    let sender_response = sender_task.await??;
    sender_x1(&sender_response)?;
    let successor_row = load_transfer_generation(mercury_pool, &statechain_id).await?;
    ensure!(
        successor_row.recipient_auth_key == Some(successor.serialize().to_vec())
            && !successor_row.locked
            && !successor_row.locked2
            && successor_row.encrypted_transfer_msg.is_none()
            && successor_row.key_updated == Some(false),
        "A-first {role:?} unlock changed successor B's intended flags or fields: {successor_row:?}"
    );
    Ok(())
}

pub(super) async fn assert_unlock_generation_fences(
    mercury_client: &reqwest::Client,
    mercury_pool: &PgPool,
    lockbox_pool: &PgPool,
) -> Result<()> {
    let secp = Secp256k1::new();
    let (_wallet, coin) = mercury::create_deposited_coin(mercury_client).await?;
    let statechain_id = coin
        .statechain_id
        .as_deref()
        .context("unlock matrix Coin has no statechain ID")?
        .to_owned();
    let signed_statechain_id = coin
        .signed_statechain_id
        .as_deref()
        .context("unlock matrix Coin has no owner signature")?
        .to_owned();
    let current_owner = coin_auth_secret(&coin)?;
    let current_owner_key = current_owner.public_key(&secp);
    let recipient_secret = SecretKey::from_secret_bytes([0x41; 32])?;
    let recipient = recipient_secret.public_key(&secp);
    let batch_id = format!("unlock-latch-{}", uuid::Uuid::new_v4());
    sqlx::query(
        "INSERT INTO lightning_latch \
         (statechain_id,sender_auth_xonly_public_key,batch_id,pre_image,expires_at) \
         VALUES ($1,$2,$3,$4,NOW()+INTERVAL '1 day')",
    )
    .bind(&statechain_id)
    .bind(current_owner_key.x_only_public_key().0.serialize().to_vec())
    .bind(&batch_id)
    .bind("generation-fence-preimage")
    .execute(mercury_pool)
    .await?;
    let unrelated_latch_statechain = format!("unrelated-latch-{}", uuid::Uuid::new_v4());
    sqlx::query(
        "INSERT INTO lightning_latch \
         (statechain_id,sender_auth_xonly_public_key,batch_id,pre_image,expires_at) \
         VALUES ($1,$2,$3,$4,NOW()+INTERVAL '1 day')",
    )
    .bind(&unrelated_latch_statechain)
    .bind(current_owner_key.x_only_public_key().0.serialize().to_vec())
    .bind(&batch_id)
    .bind("unrelated-generation-fence-preimage")
    .execute(mercury_pool)
    .await?;
    let unrelated_latch_before = load_latch(mercury_pool, &unrelated_latch_statechain, &batch_id)
        .await?
        .context("unrelated unlock latch is missing")?;
    let sender = sender_request_value(
        &statechain_id,
        &signed_statechain_id,
        &recipient,
        Some(&batch_id),
    );
    let sender_response = post_mercury_json(mercury_client, "transfer/sender", &sender).await?;
    let x1 = sender_x1(&sender_response)?;
    let generation = SecretKey::from_secret_bytes(x1)?.public_key(&secp);
    let initial_row = load_transfer_generation(mercury_pool, &statechain_id).await?;
    let initial_latch = load_latch(mercury_pool, &statechain_id, &batch_id)
        .await?
        .context("unlock matrix latch is missing")?;
    ensure!(
        initial_row.locked && initial_row.locked2 && initial_latch.locked,
        "sender did not initialize both transfer locks and its latch"
    );
    let generation_error = json!({"message":"Transfer generation does not match current row."});
    let authentication_error = json!({"message":"Signature does not match authentication key."});

    let valid_recipient = unlock_request_value(
        Bip448TransferUnlockRole::Recipient,
        &statechain_id,
        &recipient_secret,
        &generation,
    )?;
    let mut missing_generation = valid_recipient.clone();
    missing_generation
        .as_object_mut()
        .context("unlock payload is not an object")?
        .remove("auth_pub_key");
    let mut malformed_generation = valid_recipient.clone();
    malformed_generation["auth_pub_key"] = json!("not-a-public-key");
    let mut noncanonical_generation = valid_recipient.clone();
    noncanonical_generation["auth_pub_key"] = json!(generation.to_string().to_uppercase());
    let mut wrong_generation = valid_recipient.clone();
    wrong_generation["auth_pub_key"] = json!(SecretKey::from_secret_bytes([0x42; 32])?
        .public_key(&secp)
        .to_string());
    for payload in [
        missing_generation,
        malformed_generation,
        noncanonical_generation,
        wrong_generation,
    ] {
        let response = post_mercury_json(mercury_client, "transfer/unlock", &payload).await?;
        assert_json_response(
            &response,
            StatusCode::INTERNAL_SERVER_ERROR,
            generation_error.clone(),
        )?;
        ensure!(
            load_transfer_generation(mercury_pool, &statechain_id).await? == initial_row
                && load_latch(mercury_pool, &statechain_id, &batch_id).await?
                    == Some(initial_latch.clone()),
            "invalid unlock generation changed row or latch"
        );
    }

    let wrong_role = unlock_request_value(
        Bip448TransferUnlockRole::CurrentOwner,
        &statechain_id,
        &recipient_secret,
        &generation,
    )?;
    let wrong_signer = unlock_request_value(
        Bip448TransferUnlockRole::Recipient,
        &statechain_id,
        &SecretKey::from_secret_bytes([0x43; 32])?,
        &generation,
    )?;
    for payload in [wrong_role, wrong_signer] {
        let response = post_mercury_json(mercury_client, "transfer/unlock", &payload).await?;
        assert_json_response(
            &response,
            StatusCode::FORBIDDEN,
            authentication_error.clone(),
        )?;
        ensure!(
            load_transfer_generation(mercury_pool, &statechain_id).await? == initial_row
                && load_latch(mercury_pool, &statechain_id, &batch_id).await?
                    == Some(initial_latch.clone()),
            "unauthorized unlock changed row or latch"
        );
    }

    let recipient_unlock =
        post_mercury_json(mercury_client, "transfer/unlock", &valid_recipient).await?;
    assert_json_response(
        &recipient_unlock,
        StatusCode::OK,
        json!({"message":"Success"}),
    )?;
    let after_recipient = load_transfer_generation(mercury_pool, &statechain_id).await?;
    ensure!(
        !after_recipient.locked && after_recipient.locked2,
        "recipient unlock changed the wrong flag"
    );
    ensure!(
        load_latch(mercury_pool, &statechain_id, &batch_id)
            .await?
            .context("latch disappeared after recipient unlock")?
            .locked,
        "recipient-only unlock cleared the latch early"
    );
    let recipient_replay =
        post_mercury_json(mercury_client, "transfer/unlock", &valid_recipient).await?;
    assert_json_response(
        &recipient_replay,
        StatusCode::OK,
        json!({"message":"Success"}),
    )?;
    ensure!(
        load_transfer_generation(mercury_pool, &statechain_id).await? == after_recipient,
        "recipient response-loss replay changed row timestamp or fields"
    );

    let valid_current = unlock_request_value(
        Bip448TransferUnlockRole::CurrentOwner,
        &statechain_id,
        &current_owner,
        &generation,
    )?;
    let current_unlock =
        post_mercury_json(mercury_client, "transfer/unlock", &valid_current).await?;
    assert_json_response(
        &current_unlock,
        StatusCode::OK,
        json!({"message":"Success"}),
    )?;
    let fully_unlocked = load_transfer_generation(mercury_pool, &statechain_id).await?;
    let unlocked_latch = load_latch(mercury_pool, &statechain_id, &batch_id)
        .await?
        .context("latch disappeared after full unlock")?;
    ensure!(
        !fully_unlocked.locked && !fully_unlocked.locked2 && !unlocked_latch.locked,
        "current-owner unlock did not atomically clear locked2 and exact latch"
    );
    ensure!(
        load_latch(mercury_pool, &unrelated_latch_statechain, &batch_id,).await?
            == Some(unrelated_latch_before.clone()),
        "full unlock changed an unrelated same-batch latch"
    );
    let current_replay =
        post_mercury_json(mercury_client, "transfer/unlock", &valid_current).await?;
    assert_json_response(
        &current_replay,
        StatusCode::OK,
        json!({"message":"Success"}),
    )?;
    ensure!(
        load_transfer_generation(mercury_pool, &statechain_id).await? == fully_unlocked
            && load_latch(mercury_pool, &statechain_id, &batch_id).await?
                == Some(unlocked_latch.clone()),
        "current-owner response-loss replay changed row or latch timestamp"
    );

    let receiver_request =
        generation_bound_receiver_request(&statechain_id, &recipient_secret, x1, [0x44; 32])?;
    let receiver_response = post_mercury_json(
        mercury_client,
        "transfer/receiver",
        &serde_json::to_value(&receiver_request)?,
    )
    .await?;
    ensure!(
        receiver_response.0 == StatusCode::OK,
        "receiver did not consume unlocked generation: {receiver_response:?}"
    );
    let consumed_row = load_transfer_generation(mercury_pool, &statechain_id).await?;
    let consumed_state = load_statechain_generation(mercury_pool, &statechain_id).await?;
    let consumed_lockbox = load_lockbox_generation(lockbox_pool, &statechain_id).await?;
    ensure!(
        consumed_row.key_updated == Some(true),
        "receiver did not consume generation"
    );
    let consumed_unlock =
        post_mercury_json(mercury_client, "transfer/unlock", &valid_recipient).await?;
    assert_json_response(
        &consumed_unlock,
        StatusCode::INTERNAL_SERVER_ERROR,
        generation_error.clone(),
    )?;
    ensure!(
        load_transfer_generation(mercury_pool, &statechain_id).await? == consumed_row
            && load_statechain_generation(mercury_pool, &statechain_id).await? == consumed_state
            && load_lockbox_generation(lockbox_pool, &statechain_id).await? == consumed_lockbox,
        "consumed-generation unlock changed Mercury or lockbox state"
    );

    let successor_signature = sign_statechain_id(&recipient_secret, &statechain_id);
    let next_sender = sender_request_value(
        &statechain_id,
        &successor_signature,
        &recipient,
        Some(&batch_id),
    );
    let next_sender_response =
        post_mercury_json(mercury_client, "transfer/sender", &next_sender).await?;
    let next_x1 = sender_x1(&next_sender_response)?;
    ensure!(next_x1 != x1, "new owner generation replayed consumed x1");
    let next_row = load_transfer_generation(mercury_pool, &statechain_id).await?;
    ensure!(
        next_row.key_updated == Some(false)
            && next_row.recipient_auth_key == Some(recipient.serialize().to_vec())
            && next_row.x1.as_deref() == Some(next_x1.as_slice()),
        "new owner generation did not receive one fresh active x1"
    );
    let next_owner = load_statechain_generation(mercury_pool, &statechain_id).await?;
    let next_latch = load_latch(mercury_pool, &statechain_id, &batch_id)
        .await?
        .context("predecessor-owned latch disappeared from fresh successor")?;
    let next_generation = SecretKey::from_secret_bytes(next_x1)?.public_key(&secp);
    let next_unlock = unlock_request_value(
        Bip448TransferUnlockRole::Recipient,
        &statechain_id,
        &recipient_secret,
        &next_generation,
    )?;
    let next_unlock_response =
        post_mercury_json(mercury_client, "transfer/unlock", &next_unlock).await?;
    assert_json_response(
        &next_unlock_response,
        StatusCode::INTERNAL_SERVER_ERROR,
        json!({"message":"Failed to unlock transfer generation."}),
    )?;
    ensure!(
        load_transfer_generation(mercury_pool, &statechain_id).await? == next_row
            && load_statechain_generation(mercury_pool, &statechain_id).await? == next_owner
            && load_latch(mercury_pool, &statechain_id, &batch_id).await?
                == Some(next_latch.clone()),
        "successor unlock with a predecessor-owned latch did not roll back exactly"
    );
    let old_receiver_after_successor = post_mercury_json(
        mercury_client,
        "transfer/receiver",
        &serde_json::to_value(&receiver_request)?,
    )
    .await?;
    assert_json_response(
        &old_receiver_after_successor,
        StatusCode::BAD_REQUEST,
        json!({"code":"StatecoinBatchLockedError","message":"Statecoin batch is locked"}),
    )?;
    ensure!(
        load_transfer_generation(mercury_pool, &statechain_id).await? == next_row
            && load_statechain_generation(mercury_pool, &statechain_id).await? == next_owner
            && load_latch(mercury_pool, &statechain_id, &batch_id).await? == Some(next_latch),
        "old consumed receiver request changed its fresh successor"
    );

    let (_wallet, mismatch_coin) = mercury::create_deposited_coin(mercury_client).await?;
    let mismatch_id = mismatch_coin
        .statechain_id
        .as_deref()
        .context("mismatched-latch Coin has no ID")?;
    let mismatch_signature = mismatch_coin
        .signed_statechain_id
        .as_deref()
        .context("mismatched-latch Coin has no owner signature")?;
    let mismatch_recipient_secret = SecretKey::from_secret_bytes([0x4d; 32])?;
    let mismatch_recipient = mismatch_recipient_secret.public_key(&secp);
    let mismatch_batch = format!("mismatched-latch-{}", uuid::Uuid::new_v4());
    let wrong_latch_owner = SecretKey::from_secret_bytes([0x4e; 32])?
        .public_key(&secp)
        .x_only_public_key()
        .0;
    sqlx::query(
        "INSERT INTO lightning_latch \
         (statechain_id,sender_auth_xonly_public_key,batch_id,pre_image,expires_at) \
         VALUES ($1,$2,$3,$4,NOW()+INTERVAL '1 day')",
    )
    .bind(mismatch_id)
    .bind(wrong_latch_owner.serialize().to_vec())
    .bind(&mismatch_batch)
    .bind("mismatched-owner-preimage")
    .execute(mercury_pool)
    .await?;
    let mismatch_sender = sender_request_value(
        mismatch_id,
        mismatch_signature,
        &mismatch_recipient,
        Some(&mismatch_batch),
    );
    let mismatch_sender_response =
        post_mercury_json(mercury_client, "transfer/sender", &mismatch_sender).await?;
    let mismatch_x1 = sender_x1(&mismatch_sender_response)?;
    let mismatch_generation = SecretKey::from_secret_bytes(mismatch_x1)?.public_key(&secp);
    let mismatch_row = load_transfer_generation(mercury_pool, mismatch_id).await?;
    let mismatch_latch = load_latch(mercury_pool, mismatch_id, &mismatch_batch)
        .await?
        .context("mismatched-owner latch disappeared")?;
    ensure!(
        mismatch_row.locked && !mismatch_row.locked2,
        "mismatched-owner latch was incorrectly treated as the sender's latch"
    );
    let mismatch_unlock = unlock_request_value(
        Bip448TransferUnlockRole::Recipient,
        mismatch_id,
        &mismatch_recipient_secret,
        &mismatch_generation,
    )?;
    let mismatch_unlock_response =
        post_mercury_json(mercury_client, "transfer/unlock", &mismatch_unlock).await?;
    assert_json_response(
        &mismatch_unlock_response,
        StatusCode::INTERNAL_SERVER_ERROR,
        json!({"message":"Failed to unlock transfer generation."}),
    )?;
    ensure!(
        load_transfer_generation(mercury_pool, mismatch_id).await? == mismatch_row
            && load_latch(mercury_pool, mismatch_id, &mismatch_batch).await?
                == Some(mismatch_latch),
        "mismatched latch-owner failure did not roll back transfer and latch"
    );

    for (same_recipient, recipient_byte, successor_byte) in
        [(true, 0x45, 0x46), (false, 0x47, 0x48)]
    {
        let (_wallet, stale_coin) = mercury::create_deposited_coin(mercury_client).await?;
        let stale_id = stale_coin
            .statechain_id
            .as_deref()
            .context("stale unlock ID")?;
        let stale_signature = stale_coin
            .signed_statechain_id
            .as_deref()
            .context("stale unlock owner signature")?;
        let stale_owner = coin_auth_secret(&stale_coin)?;
        let stale_recipient_secret = SecretKey::from_secret_bytes([recipient_byte; 32])?;
        let stale_recipient = stale_recipient_secret.public_key(&secp);
        let sender_a = sender_request_value(stale_id, stale_signature, &stale_recipient, None);
        let sender_a_response =
            post_mercury_json(mercury_client, "transfer/sender", &sender_a).await?;
        let stale_x1 = sender_x1(&sender_a_response)?;
        let stale_generation = SecretKey::from_secret_bytes(stale_x1)?.public_key(&secp);
        sqlx::query(
            "UPDATE statechain_transfer SET locked=true,locked2=true WHERE statechain_id=$1",
        )
        .bind(stale_id)
        .execute(mercury_pool)
        .await?;
        let stale_recipient_unlock = unlock_request_value(
            Bip448TransferUnlockRole::Recipient,
            stale_id,
            &stale_recipient_secret,
            &stale_generation,
        )?;
        let stale_current_unlock = unlock_request_value(
            Bip448TransferUnlockRole::CurrentOwner,
            stale_id,
            &stale_owner,
            &stale_generation,
        )?;
        let successor_recipient = if same_recipient {
            stale_recipient
        } else {
            SecretKey::from_secret_bytes([successor_byte; 32])?.public_key(&secp)
        };
        let successor_batch =
            same_recipient.then(|| format!("unlock-successor-{}", uuid::Uuid::new_v4()));
        let sender_b = sender_request_value(
            stale_id,
            stale_signature,
            &successor_recipient,
            successor_batch.as_deref(),
        );
        let sender_b_response =
            post_mercury_json(mercury_client, "transfer/sender", &sender_b).await?;
        let successor_x1 = sender_x1(&sender_b_response)?;
        ensure!(
            successor_x1 != stale_x1,
            "successor B reused stale unlock x1"
        );
        let successor_row = load_transfer_generation(mercury_pool, stale_id).await?;
        let successor_owner = load_statechain_generation(mercury_pool, stale_id).await?;
        for payload in [stale_recipient_unlock, stale_current_unlock] {
            let response = post_mercury_json(mercury_client, "transfer/unlock", &payload).await?;
            assert_json_response(
                &response,
                StatusCode::INTERNAL_SERVER_ERROR,
                generation_error.clone(),
            )?;
            ensure!(
                load_transfer_generation(mercury_pool, stale_id).await? == successor_row
                    && load_statechain_generation(mercury_pool, stale_id).await? == successor_owner,
                "stale unlock changed same/different-recipient successor B"
            );
        }
    }

    assert_unlock_a_first_barrier(
        mercury_client,
        mercury_pool,
        Bip448TransferUnlockRole::Recipient,
        0x49,
        0x4a,
    )
    .await?;
    assert_unlock_a_first_barrier(
        mercury_client,
        mercury_pool,
        Bip448TransferUnlockRole::CurrentOwner,
        0x4b,
        0x4c,
    )
    .await?;

    Ok(())
}

pub(super) async fn assert_receiver_generation_fences(
    mercury_client: &reqwest::Client,
    mercury_pool: &PgPool,
    lockbox_pool: &PgPool,
) -> Result<()> {
    let secp = Secp256k1::new();
    let (_wallet, coin) = mercury::create_deposited_coin(mercury_client).await?;
    let statechain_id = coin
        .statechain_id
        .as_deref()
        .context("receiver matrix Coin has no statechain ID")?
        .to_owned();
    let signed_statechain_id = coin
        .signed_statechain_id
        .as_deref()
        .context("receiver matrix Coin has no owner signature")?
        .to_owned();
    let recipient_secret = SecretKey::from_secret_bytes([0x51; 32])?;
    let recipient = recipient_secret.public_key(&secp);
    let sender = sender_request_value(&statechain_id, &signed_statechain_id, &recipient, None);
    let sender_response = post_mercury_json(mercury_client, "transfer/sender", &sender).await?;
    let x1 = sender_x1(&sender_response)?;
    let generation = SecretKey::from_secret_bytes(x1)?.public_key(&secp);
    let receiver =
        generation_bound_receiver_request(&statechain_id, &recipient_secret, x1, [0xab; 32])?;
    let receiver_value = serde_json::to_value(&receiver)?;
    let initial_transfer = load_transfer_generation(mercury_pool, &statechain_id).await?;
    let initial_statechain = load_statechain_generation(mercury_pool, &statechain_id).await?;
    let initial_lockbox = load_lockbox_generation(lockbox_pool, &statechain_id).await?;
    let generation_error = json!({"message":"Transfer generation does not match current row."});

    let mut missing_generation = receiver_value.clone();
    missing_generation
        .as_object_mut()
        .context("receiver payload is not an object")?
        .remove("batch_data");
    let mut malformed_generation = receiver_value.clone();
    malformed_generation["batch_data"] = json!("not-a-public-key");
    let mut noncanonical_generation = receiver_value.clone();
    noncanonical_generation["batch_data"] = json!(generation.to_string().to_uppercase());
    let mut wrong_generation = receiver_value.clone();
    wrong_generation["batch_data"] = json!(SecretKey::from_secret_bytes([0x52; 32])?
        .public_key(&secp)
        .to_string());
    let mut noncanonical_t2 = receiver_value.clone();
    noncanonical_t2["t2"] = json!(receiver.t2.to_uppercase());
    let mut zero_t2 = receiver_value.clone();
    zero_t2["t2"] = json!("00".repeat(32));
    let mut substituted_t2 = receiver_value.clone();
    substituted_t2["t2"] = json!("ac".repeat(32));
    let mut wrong_signer = receiver_value.clone();
    let wrong_signer_secret = SecretKey::from_secret_bytes([0x53; 32])?;
    let wrong_signer_digest =
        bip448_transfer_receiver_auth_digest(&statechain_id, &[0xab; 32], &generation)?;
    wrong_signer["auth_sig"] = json!(sign_digest(&wrong_signer_secret, &wrong_signer_digest));
    for payload in [
        missing_generation,
        malformed_generation,
        noncanonical_generation,
        wrong_generation,
        noncanonical_t2,
        zero_t2,
        substituted_t2,
        wrong_signer,
    ] {
        let response = post_mercury_json(mercury_client, "transfer/receiver", &payload).await?;
        assert_json_response(
            &response,
            StatusCode::INTERNAL_SERVER_ERROR,
            generation_error.clone(),
        )?;
        ensure!(
            load_transfer_generation(mercury_pool, &statechain_id).await? == initial_transfer
                && load_statechain_generation(mercury_pool, &statechain_id).await?
                    == initial_statechain
                && load_lockbox_generation(lockbox_pool, &statechain_id).await? == initial_lockbox,
            "invalid receiver generation/auth input reached mutation"
        );
    }

    let missing_statechain = format!("missing-{}", uuid::Uuid::new_v4());
    let mut missing_statechain_request = receiver_value.clone();
    missing_statechain_request["statechain_id"] = json!(missing_statechain);
    let missing_statechain_response = post_mercury_json(
        mercury_client,
        "transfer/receiver",
        &missing_statechain_request,
    )
    .await?;
    assert_json_response(
        &missing_statechain_response,
        StatusCode::NOT_FOUND,
        json!({"message":"Statechain Id key not found."}),
    )?;
    let (_wallet, no_transfer_coin) = mercury::create_deposited_coin(mercury_client).await?;
    let no_transfer_id = no_transfer_coin
        .statechain_id
        .as_deref()
        .context("no-transfer receiver fixture has no ID")?;
    let no_transfer_request = json!({
        "statechain_id":no_transfer_id,
        "batch_data":generation.to_string(),
        "t2":receiver.t2,
        "auth_sig":receiver.auth_sig,
    });
    let no_transfer_response =
        post_mercury_json(mercury_client, "transfer/receiver", &no_transfer_request).await?;
    assert_json_response(
        &no_transfer_response,
        StatusCode::NOT_FOUND,
        json!({"message":"No transfer messages found for this statechain_id"}),
    )?;

    let (_wallet, other_coin) = mercury::create_deposited_coin(mercury_client).await?;
    let other_id = other_coin
        .statechain_id
        .as_deref()
        .context("other receiver fixture has no ID")?;
    let other_signature = other_coin
        .signed_statechain_id
        .as_deref()
        .context("other receiver fixture has no signature")?;
    let other_recipient = SecretKey::from_secret_bytes([0x54; 32])?.public_key(&secp);
    let other_sender = sender_request_value(other_id, other_signature, &other_recipient, None);
    let other_sender_response =
        post_mercury_json(mercury_client, "transfer/sender", &other_sender).await?;
    sender_x1(&other_sender_response)?;
    let other_before = load_transfer_generation(mercury_pool, other_id).await?;
    let other_state_before = load_statechain_generation(mercury_pool, other_id).await?;
    let other_lockbox_before = load_lockbox_generation(lockbox_pool, other_id).await?;
    let mut substituted_statechain = receiver_value.clone();
    substituted_statechain["statechain_id"] = json!(other_id);
    let substituted_statechain_response =
        post_mercury_json(mercury_client, "transfer/receiver", &substituted_statechain).await?;
    assert_json_response(
        &substituted_statechain_response,
        StatusCode::INTERNAL_SERVER_ERROR,
        generation_error.clone(),
    )?;
    ensure!(
        load_transfer_generation(mercury_pool, other_id).await? == other_before
            && load_statechain_generation(mercury_pool, other_id).await? == other_state_before
            && load_lockbox_generation(lockbox_pool, other_id).await? == other_lockbox_before,
        "receiver statechain substitution changed the other generation"
    );

    let valid_response =
        post_mercury_json(mercury_client, "transfer/receiver", &receiver_value).await?;
    ensure!(
        valid_response.0 == StatusCode::OK,
        "valid receiver failed: {valid_response:?}"
    );
    let valid_body: Value = serde_json::from_str(&valid_response.1)?;
    let after_valid_transfer = load_transfer_generation(mercury_pool, &statechain_id).await?;
    let after_valid_state = load_statechain_generation(mercury_pool, &statechain_id).await?;
    let after_valid_lockbox = load_lockbox_generation(lockbox_pool, &statechain_id).await?;
    ensure!(
        after_valid_transfer.key_updated == Some(true)
            && after_valid_state.auth_key
                == Some(recipient.x_only_public_key().0.serialize().to_vec())
            && valid_body["server_pubkey"].as_str().is_some(),
        "valid receiver did not consume its exact generation"
    );
    let valid_replay =
        post_mercury_json(mercury_client, "transfer/receiver", &receiver_value).await?;
    ensure!(
        valid_replay.0 == StatusCode::OK,
        "receiver replay failed: {valid_replay:?}"
    );
    ensure!(
        serde_json::from_str::<Value>(&valid_replay.1)? == valid_body
            && load_transfer_generation(mercury_pool, &statechain_id).await?
                == after_valid_transfer
            && load_statechain_generation(mercury_pool, &statechain_id).await? == after_valid_state
            && load_lockbox_generation(lockbox_pool, &statechain_id).await? == after_valid_lockbox,
        "exact receiver response-loss replay mutated its consumed generation"
    );

    let (_wallet, batch_coin) = mercury::create_deposited_coin(mercury_client).await?;
    let batch_statechain_id = batch_coin
        .statechain_id
        .as_deref()
        .context("batch receiver Coin has no ID")?;
    let batch_signature = batch_coin
        .signed_statechain_id
        .as_deref()
        .context("batch receiver Coin has no signature")?;
    let batch_recipient_secret = SecretKey::from_secret_bytes([0x55; 32])?;
    let batch_recipient = batch_recipient_secret.public_key(&secp);
    let batch_id = format!("receiver-batch-{}", uuid::Uuid::new_v4());
    let batch_sender = sender_request_value(
        batch_statechain_id,
        batch_signature,
        &batch_recipient,
        Some(&batch_id),
    );
    let batch_sender_response =
        post_mercury_json(mercury_client, "transfer/sender", &batch_sender).await?;
    let batch_x1 = sender_x1(&batch_sender_response)?;
    let batch_receiver = serde_json::to_value(generation_bound_receiver_request(
        batch_statechain_id,
        &batch_recipient_secret,
        batch_x1,
        [0x56; 32],
    )?)?;
    let locked_transfer = load_transfer_generation(mercury_pool, batch_statechain_id).await?;
    let locked_state = load_statechain_generation(mercury_pool, batch_statechain_id).await?;
    let locked_lockbox = load_lockbox_generation(lockbox_pool, batch_statechain_id).await?;
    let locked_response =
        post_mercury_json(mercury_client, "transfer/receiver", &batch_receiver).await?;
    assert_json_response(
        &locked_response,
        StatusCode::BAD_REQUEST,
        json!({"code":"StatecoinBatchLockedError","message":"Statecoin batch is locked"}),
    )?;
    ensure!(
        load_transfer_generation(mercury_pool, batch_statechain_id).await? == locked_transfer
            && load_statechain_generation(mercury_pool, batch_statechain_id).await? == locked_state
            && load_lockbox_generation(lockbox_pool, batch_statechain_id).await? == locked_lockbox,
        "locked batch receiver reached lockbox or Mercury mutation"
    );
    sqlx::query(
        "UPDATE statechain_transfer SET locked=false,locked2=false,\
         batch_time=NOW()-INTERVAL '30 days' WHERE statechain_id=$1",
    )
    .bind(batch_statechain_id)
    .execute(mercury_pool)
    .await?;
    let expired_transfer = load_transfer_generation(mercury_pool, batch_statechain_id).await?;
    let expired_response =
        post_mercury_json(mercury_client, "transfer/receiver", &batch_receiver).await?;
    assert_json_response(
        &expired_response,
        StatusCode::BAD_REQUEST,
        json!({"code":"ExpiredBatchTimeError","message":"Batch time has expired"}),
    )?;
    ensure!(
        load_transfer_generation(mercury_pool, batch_statechain_id).await? == expired_transfer
            && load_statechain_generation(mercury_pool, batch_statechain_id).await? == locked_state
            && load_lockbox_generation(lockbox_pool, batch_statechain_id).await? == locked_lockbox,
        "expired locked-row batch validation reached lockbox or Mercury mutation"
    );

    let (_wallet, ordered_coin) = mercury::create_deposited_coin(mercury_client).await?;
    let ordered_id = ordered_coin
        .statechain_id
        .as_deref()
        .context("ordered receiver Coin has no ID")?
        .to_owned();
    let ordered_signature = ordered_coin
        .signed_statechain_id
        .as_deref()
        .context("ordered receiver Coin has no signature")?
        .to_owned();
    let ordered_recipient_secret = SecretKey::from_secret_bytes([0x57; 32])?;
    let ordered_recipient = ordered_recipient_secret.public_key(&secp);
    let ordered_sender =
        sender_request_value(&ordered_id, &ordered_signature, &ordered_recipient, None);
    let ordered_sender_response =
        post_mercury_json(mercury_client, "transfer/sender", &ordered_sender).await?;
    let ordered_x1 = sender_x1(&ordered_sender_response)?;
    let ordered_receiver = serde_json::to_value(generation_bound_receiver_request(
        &ordered_id,
        &ordered_recipient_secret,
        ordered_x1,
        [0x58; 32],
    )?)?;
    let signatures_before: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM bip448_signature_data WHERE statechain_id=$1")
            .bind(&ordered_id)
            .fetch_one(mercury_pool)
            .await?;
    let row_lock = lock_transfer_row(mercury_pool, &ordered_id).await?;
    let receiver_client = mercury_client.clone();
    let mut receiver_task = tokio::spawn(async move {
        post_mercury_json(&receiver_client, "transfer/receiver", &ordered_receiver).await
    });
    wait_for_blocked_mercury_query(
        mercury_pool,
        "SELECT new_user_auth_public_key, x1, batch_id, batch_time",
    )
    .await?;
    ensure!(
        timeout(Duration::from_millis(100), &mut receiver_task)
            .await
            .is_err(),
        "A-first receiver did not remain blocked at its row-A fence"
    );
    let successor_recipient = SecretKey::from_secret_bytes([0x59; 32])?.public_key(&secp);
    let successor_sender =
        sender_request_value(&ordered_id, &ordered_signature, &successor_recipient, None);
    let sender_client = mercury_client.clone();
    let mut successor_task = tokio::spawn(async move {
        post_mercury_json(&sender_client, "transfer/sender", &successor_sender).await
    });
    ensure!(
        timeout(Duration::from_millis(100), &mut successor_task)
            .await
            .is_err(),
        "successor sender bypassed A-first receiver statechain-data lock"
    );
    row_lock.commit().await?;
    let ordered_receiver_response = receiver_task.await??;
    ensure!(
        ordered_receiver_response.0 == StatusCode::OK,
        "A-first receiver did not complete: {ordered_receiver_response:?}"
    );
    let stale_sender_response = successor_task.await??;
    assert_json_response(
        &stale_sender_response,
        StatusCode::INTERNAL_SERVER_ERROR,
        json!({"message":"Signature does not match authentication key."}),
    )?;
    let ordered_row = load_transfer_generation(mercury_pool, &ordered_id).await?;
    ensure!(
        ordered_row.recipient_auth_key == Some(ordered_recipient.serialize().to_vec())
            && ordered_row.key_updated == Some(true)
            && sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM statechain_transfer WHERE statechain_id=$1",
            )
            .bind(&ordered_id)
            .fetch_one(mercury_pool)
            .await?
                == 1
            && sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM bip448_signature_data WHERE statechain_id=$1",
            )
            .bind(&ordered_id)
            .fetch_one(mercury_pool)
            .await?
                == signatures_before,
        "receiver-first ordering inserted successor state or signature artifacts"
    );

    let (_wallet, b_first_coin) = mercury::create_deposited_coin(mercury_client).await?;
    let b_first_id = b_first_coin
        .statechain_id
        .as_deref()
        .context("B-first receiver Coin has no ID")?;
    let b_first_signature = b_first_coin
        .signed_statechain_id
        .as_deref()
        .context("B-first receiver Coin has no signature")?;
    let b_recipient_secret = SecretKey::from_secret_bytes([0x5a; 32])?;
    let b_recipient = b_recipient_secret.public_key(&secp);
    let sender_a = sender_request_value(b_first_id, b_first_signature, &b_recipient, None);
    let sender_a_response = post_mercury_json(mercury_client, "transfer/sender", &sender_a).await?;
    let a_x1 = sender_x1(&sender_a_response)?;
    let stale_receiver = serde_json::to_value(generation_bound_receiver_request(
        b_first_id,
        &b_recipient_secret,
        a_x1,
        [0x5b; 32],
    )?)?;
    let b_batch = format!("receiver-b-first-{}", uuid::Uuid::new_v4());
    let sender_b =
        sender_request_value(b_first_id, b_first_signature, &b_recipient, Some(&b_batch));
    let sender_b_response = post_mercury_json(mercury_client, "transfer/sender", &sender_b).await?;
    let b_x1 = sender_x1(&sender_b_response)?;
    ensure!(a_x1 != b_x1, "B-first receiver successor reused A x1");
    sqlx::query("UPDATE statechain_transfer SET locked=false WHERE statechain_id=$1")
        .bind(b_first_id)
        .execute(mercury_pool)
        .await?;
    let b_transfer = load_transfer_generation(mercury_pool, b_first_id).await?;
    let b_state = load_statechain_generation(mercury_pool, b_first_id).await?;
    let b_lockbox = load_lockbox_generation(lockbox_pool, b_first_id).await?;
    let stale_receiver_response =
        post_mercury_json(mercury_client, "transfer/receiver", &stale_receiver).await?;
    assert_json_response(
        &stale_receiver_response,
        StatusCode::INTERNAL_SERVER_ERROR,
        generation_error,
    )?;
    ensure!(
        load_transfer_generation(mercury_pool, b_first_id).await? == b_transfer
            && load_statechain_generation(mercury_pool, b_first_id).await? == b_state
            && load_lockbox_generation(lockbox_pool, b_first_id).await? == b_lockbox,
        "B-first stale receiver changed successor generation"
    );

    Ok(())
}
