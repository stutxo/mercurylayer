mod common;

use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use bitcoin::{
    hashes::Hash,
    secp256k1::{
        musig::{new_musig_nonce_pair, BlindingFactor, MusigSessionId, PublicNonce},
        rand, schnorr, KeyPair, PublicKey, Secp256k1, SecretKey,
    },
    sighash::TemplateHash,
    Address, Network, PrivateKey, ScriptBuf, Transaction,
};
use common::bip448_regtest::{fund_bip448_output, unsigned_spend, SPEND_AMOUNT_SATS};
use mercurylib::bip448::template_hash::template_hash;
use mercurylib::bip448_statechain::script::{
    funding_spend_info, funding_update_control_block, funding_update_leaf, output_script_pubkey,
};
use mercurylib::bip448_statechain::signing::{
    csfs_script_witness, csfs_witness_signature, CsfsSigningParticipant, CsfsSigningRole,
    CsfsSigningSession,
};
use mercurylib::bip448_statechain::signing_api::{
    Bip448PartialSignatureRequestPayload, Bip448SignFirstRequestPayload,
};
use reqwest::StatusCode;

/// Phase 4 end-to-end proof on Inquisition consensus: a blinded two-party
/// MuSig CSFS signature over a BIP446 template hash, produced against the
/// untweaked aggregate key `P`, spends the library-built funding output;
/// the same signature rebinds to a second funding; and a 65-byte witness
/// signature (sighash byte appended) is rejected.
#[test]
#[ignore = "requires docker regtest stack with active BIP448 Inquisition deployments"]
fn bip448_blinded_musig_csfs_signature_spends_on_inquisition() -> Result<()> {
    let _guard = common::test_guard();

    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;

    let secp = Secp256k1::new();

    // Two-party key set: simulated client and server shares aggregated into
    // the untweaked Mercury key P, used as the Taproot internal key.
    let client = KeyPair::from_secret_key(&secp, &SecretKey::from_secret_bytes([11u8; 32])?);
    let server = KeyPair::from_secret_key(&secp, &SecretKey::from_secret_bytes([12u8; 32])?);
    let aggregate_pubkey: PublicKey = client.public_key().combine(&server.public_key())?;
    let aggregate_xonly = aggregate_pubkey.x_only_public_key().0;

    // The funding output is built through the library helpers, so this test
    // exercises the shipped script construction on-chain.
    let spend_info = funding_spend_info(&secp, aggregate_xonly)?;
    let control_block = funding_update_control_block(&spend_info)?;
    let script = funding_update_leaf();
    let address = Address::from_script(&output_script_pubkey(&spend_info), Network::Regtest)?;

    let funding_a = fund_bip448_output(&address)?;
    let funding_b = fund_bip448_output(&address)?;
    let funding_c = fund_bip448_output(&address)?;
    common::bitcoin_core::mine_block()?;

    let destination_script =
        common::bitcoin_core::regtest_address(&common::bitcoin_core::getnewaddress()?)?
            .script_pubkey();
    let spend_template = unsigned_spend(funding_a.outpoint, destination_script, SPEND_AMOUNT_SATS);
    let hash = template_hash(&spend_template, 0, None)?;

    // Blinded two-party MuSig over the raw template hash, keyed to the
    // untweaked P. The server share signs from the fin-nonce-removed blinded
    // session, mirroring the real blind-server flow.
    let mut rng = rand::rng();
    let client_session_id = MusigSessionId::new(&mut rng);
    let server_session_id = MusigSessionId::new(&mut rng);
    let signing_message = hash.into();
    let (client_sec_nonce, client_pub_nonce) = new_musig_nonce_pair(
        &secp,
        client_session_id,
        None,
        Some(client.secret_key()),
        client.public_key(),
        Some(signing_message),
        None,
    )?;
    let (server_sec_nonce, server_pub_nonce) = new_musig_nonce_pair(
        &secp,
        server_session_id,
        None,
        Some(server.secret_key()),
        server.public_key(),
        Some(signing_message),
        None,
    )?;
    let blinding_secret = SecretKey::new(&mut rng);
    let blinding_factor = BlindingFactor::from_slice(&blinding_secret.to_secret_bytes())?;

    let session = CsfsSigningSession::new(
        &secp,
        CsfsSigningRole::FundingUpdate,
        aggregate_pubkey,
        &client_pub_nonce,
        &server_pub_nonce,
        hash,
        &blinding_factor,
    )?;

    let client_partial = session.partial_sign_verified(
        &secp,
        CsfsSigningParticipant::Client,
        client_sec_nonce,
        &client_pub_nonce,
        &client,
    )?;
    let server_partial = session
        .blinded_server_session()
        .blinded_partial_sign_without_keyaggcoeff(
            &secp,
            server_sec_nonce,
            &server,
            session.negate_seckey(),
        )?;
    session.verify_partial(
        &secp,
        CsfsSigningParticipant::Server,
        &server_partial,
        &server_pub_nonce,
        &server.public_key(),
    )?;
    let signature = session.aggregate_and_verify(&[&client_partial, &server_partial])?;
    assert!(schnorr::verify(&signature, hash.as_byte_array(), &aggregate_xonly).is_ok());

    // Spend A: direct broadcast of the MuSig-signed CSFS spend.
    let mut spend_a = spend_template.clone();
    push_csfs_witness(&mut spend_a, &signature, &script, &control_block, None);
    let spend_a_txid = common::bitcoin_core::broadcast_raw_transaction(&spend_a)?;

    // Spend B: rebind the identical signed template to a different funding
    // outpoint; the signature stays valid because the template hash does not
    // commit to the prevout.
    let mut spend_b = spend_template.clone();
    spend_b.input[0].previous_output = funding_b.outpoint;
    assert_eq!(hash, template_hash(&spend_b, 0, None)?);
    push_csfs_witness(&mut spend_b, &signature, &script, &control_block, None);
    let spend_b_txid = common::bitcoin_core::broadcast_raw_transaction(&spend_b)?;

    // Spend C: the same valid signature with a Taproot-style sighash byte
    // appended is a 65-byte witness item; BIP348 requires exactly 64 bytes
    // for a 32-byte key and consensus must reject it.
    let mut spend_c = spend_template.clone();
    spend_c.input[0].previous_output = funding_c.outpoint;
    push_csfs_witness(
        &mut spend_c,
        &signature,
        &script,
        &control_block,
        Some(0x01),
    );
    assert_rejected_for_signature_size(&spend_c)?;

    common::bitcoin_core::mine_block()?;
    common::bitcoin_core::assert_confirmed(&spend_a_txid)?;
    common::bitcoin_core::assert_confirmed(&spend_b_txid)?;

    Ok(())
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server and lockbox"]
async fn bip448_sign_second_recovers_after_post_claim_server_failure() -> Result<()> {
    let _guard = common::test_guard();
    let client = common::mercury::http_client();
    common::mercury::wait_until_ready(&client).await?;

    let (_wallet, coin) = common::mercury::create_deposited_coin(&client).await?;
    let statechain_id = coin
        .statechain_id
        .as_ref()
        .context("deposited coin missing statechain_id")?
        .clone();
    let signed_statechain_id = coin
        .signed_statechain_id
        .as_ref()
        .context("deposited coin missing signed_statechain_id")?
        .clone();
    let signing_id = hex::encode([0x44u8; 32]);

    let first = common::mercury::bip448_sign_first(
        &client,
        &Bip448SignFirstRequestPayload {
            statechain_id: statechain_id.clone(),
            signed_statechain_id: signed_statechain_id.clone(),
            signing_id: signing_id.clone(),
        },
    )
    .await?;
    let second_payload =
        bip448_partial_signature_payload(&coin, &signing_id, &first.server_pubnonce)?;

    let lockbox_client = common::lockbox::http_client();
    common::lockbox::stop_token_stack_lockbox_service().await?;
    let failure_result = client
        .post(format!(
            "{}/bip448-statechain/sign/second",
            common::mercury::MERCURY_URL
        ))
        .json(&second_payload)
        .send()
        .await;
    common::lockbox::start_token_stack_lockbox_service(&lockbox_client).await?;

    let failure = failure_result.context("failed to call mercury bip448 sign/second")?;
    let failure_status = failure.status();
    assert_eq!(failure_status, StatusCode::INTERNAL_SERVER_ERROR);

    let partial = common::mercury::bip448_sign_second(&client, &second_payload).await?;
    assert_eq!(partial.partial_sig.len(), 64);

    let replay = common::mercury::bip448_sign_second(&client, &second_payload).await?;
    assert_eq!(replay.partial_sig, partial.partial_sig);

    Ok(())
}

fn bip448_partial_signature_payload(
    coin: &mercurylib::wallet::Coin,
    signing_id: &str,
    server_pubnonce: &str,
) -> Result<Bip448PartialSignatureRequestPayload> {
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

    Ok(Bip448PartialSignatureRequestPayload {
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
    })
}

fn push_csfs_witness(
    tx: &mut Transaction,
    signature: &schnorr::Signature,
    script: &ScriptBuf,
    control_block: &bitcoin::taproot::ControlBlock,
    appended_sighash_byte: Option<u8>,
) {
    if appended_sighash_byte.is_none() {
        tx.input[0].witness = csfs_script_witness(signature, script, control_block);
        return;
    }

    let mut signature_bytes = csfs_witness_signature(signature).to_vec();
    if let Some(byte) = appended_sighash_byte {
        signature_bytes.push(byte);
    }

    tx.input[0].witness.push(signature_bytes);
    tx.input[0].witness.push(script.as_bytes());
    tx.input[0].witness.push(control_block.serialize());
}

fn assert_rejected_for_signature_size(tx: &Transaction) -> Result<()> {
    let err = match common::bitcoin_core::broadcast_raw_transaction(tx) {
        Ok(txid) => {
            return Err(anyhow!(
                "sighash-byte-appended CSFS signature unexpectedly broadcast successfully: {txid}"
            ));
        }
        Err(err) => err.to_string(),
    };

    let expected_rejection_reasons = [
        "mandatory-script-verify-flag-failed (Invalid Schnorr signature size)",
        "mempool-script-verify-flag-failed (Invalid Schnorr signature size)",
    ];

    if expected_rejection_reasons
        .iter()
        .any(|reason| err.contains(reason))
    {
        return Ok(());
    }

    Err(anyhow!(
        "sighash-byte-appended signature was rejected for an unexpected reason: {err}"
    ))
}
