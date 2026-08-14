use super::*;

pub(super) fn generation_bound_receiver_request(
    statechain_id: &str,
    recipient_secret: &SecretKey,
    x1: [u8; 32],
    t2: [u8; 32],
) -> Result<TransferReceiverRequestPayload> {
    let secp = Secp256k1::new();
    let generation = SecretKey::from_secret_bytes(x1)?.public_key(&secp);
    let digest = bip448_transfer_receiver_auth_digest(statechain_id, &t2, &generation)?;
    let keypair = KeyPair::from_secret_key(&secp, recipient_secret);
    Ok(TransferReceiverRequestPayload {
        statechain_id: statechain_id.to_owned(),
        batch_data: Some(generation.to_string()),
        t2: hex::encode(t2),
        auth_sig: schnorr::sign(&digest, &keypair).to_string(),
    })
}

pub(super) async fn unlock_recipient_transfer_generation(
    client: &reqwest::Client,
    statechain_id: &str,
    recipient_secret: &SecretKey,
    x1: [u8; 32],
) -> Result<()> {
    let secp = Secp256k1::new();
    let generation = SecretKey::from_secret_bytes(x1)?.public_key(&secp);
    let digest = bip448_transfer_unlock_auth_digest(
        Bip448TransferUnlockRole::Recipient,
        statechain_id,
        &generation,
    )?;
    let keypair = KeyPair::from_secret_key(&secp, recipient_secret);
    let response = client
        .post(format!("{}/transfer/unlock", mercury::url()))
        .json(&TransferUnlockRequestPayload {
            statechain_id: statechain_id.to_owned(),
            auth_sig: schnorr::sign(&digest, &keypair).to_string(),
            auth_pub_key: Some(generation.to_string()),
        })
        .send()
        .await?;
    let status = response.status();
    let body = response.text().await?;
    ensure!(
        status == StatusCode::OK && body == r#"{"message":"Success"}"#,
        "generation-bound recipient unlock returned {status}: {body}"
    );
    Ok(())
}

pub(super) fn bip448_partial_signature_payload(
    coin: &mercurylib::wallet::Coin,
    signing_id: &str,
    server_pubnonce: &str,
) -> Result<(Bip448PartialSignatureRequestPayload, String)> {
    let secp = Secp256k1::new();
    let client_seckey = PrivateKey::from_wif(&coin.user_privkey)?.inner;
    let client_pubkey = PublicKey::from_str(&coin.user_pubkey)?;
    let server_pubkey = PublicKey::from_str(
        coin.server_pubkey
            .as_ref()
            .context("deposited coin missing server_pubkey")?,
    )?;
    let aggregate_pubkey = client_pubkey.combine(&server_pubkey)?;

    let mut rng = rand::rng();
    let (_client_sec_nonce, client_pub_nonce) = new_musig_nonce_pair(
        &secp,
        MusigSessionId::new(&mut rng),
        None,
        Some(client_seckey),
        client_pubkey,
        None,
        None,
    )?;
    let server_pub_nonce = PublicNonce::from_slice(&hex::decode(server_pubnonce)?)?;
    let blinding_secret = SecretKey::new(&mut rng);
    let blinding_factor = BlindingFactor::from_slice(&blinding_secret.to_secret_bytes())?;
    let template_hash = TemplateHash::from_slice(&[0x51u8; 32])?;
    let session = CsfsSigningSession::new(
        &secp,
        CsfsSigningRole::FundingUpdate,
        aggregate_pubkey,
        &client_pub_nonce,
        &server_pub_nonce,
        template_hash,
        &blinding_factor,
    )?;
    let challenge = hex::encode(session.blinded_challenge());

    Ok((
        Bip448PartialSignatureRequestPayload {
            statechain_id: coin
                .statechain_id
                .as_ref()
                .context("deposited coin missing statechain_id")?
                .clone(),
            signed_statechain_id: coin
                .signed_statechain_id
                .as_ref()
                .context("deposited coin missing signed_statechain_id")?
                .clone(),
            signing_id: signing_id.to_string(),
            negate_seckey: u8::from(session.negate_seckey()),
            session: hex::encode(session.blinded_server_session().serialize()),
            server_pub_nonce: server_pubnonce.to_string(),
        },
        challenge,
    ))
}

pub(super) async fn complete_bip448_signing_round(
    mercury_client: &reqwest::Client,
    coin: &mercurylib::wallet::Coin,
    signing_id: String,
) -> Result<(String, String)> {
    let first = mercury::bip448_sign_first(
        mercury_client,
        &Bip448SignFirstRequestPayload {
            statechain_id: coin
                .statechain_id
                .as_ref()
                .context("deposited coin missing statechain_id")?
                .clone(),
            signed_statechain_id: coin
                .signed_statechain_id
                .as_ref()
                .context("deposited coin missing signed_statechain_id")?
                .clone(),
            signing_id: signing_id.clone(),
        },
    )
    .await?;
    let (second_payload, challenge) =
        bip448_partial_signature_payload(coin, &signing_id, &first.server_pubnonce)?;
    let second = mercury::bip448_sign_second(mercury_client, &second_payload).await?;
    assert_eq!(second.partial_sig.len(), 64);

    Ok((first.server_pubnonce, challenge))
}

pub(super) async fn assert_missing_statechain_error(
    response: reqwest::Response,
    context: &str,
) -> Result<()> {
    let status = response.status();
    let body = response
        .text()
        .await
        .with_context(|| format!("failed to read {} body", context))?;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(body.contains("Failed to load aggregated key data"));

    Ok(())
}
