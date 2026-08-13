use super::bip448_process_checkpoint;
use crate::{
    bip448_funding::Bip448TransferIntent,
    client_config::ClientConfig,
    deposit::{bip448_sign_first, bip448_sign_second, bip448_signature_count},
    sqlite_manager::{
        get_bip448_pending_transfer_signing, get_bip448_state_history, get_bip448_statechain,
        get_wallet, install_bip448_transfer_target_pending,
        install_reused_signed_bip448_transfer_state, store_bip448_transfer_state_nonce,
        store_bip448_transfer_state_signed_artifacts, Bip448PendingDepositSigning,
    },
};
use anyhow::{anyhow, Result};
use bitcoin::{absolute, hashes::Hash, Address, Network, OutPoint, PrivateKey, Txid};
use mercurylib::{
    bip448_statechain::{
        script::{checked_next_state_locktime, sample_future_state_stride},
        signing::*,
        signing_api::*,
        storage::{
            build_funding_recovery_artifacts, Bip448RecoveryArtifacts, Bip448RecoveryTemplateRole,
            Bip448SigningMetadata, Bip448StatechainRecord,
        },
    },
    transfer::bip448::Bip448StateHistoryEntry,
    wallet::{Coin, Wallet},
};
use secp256k1::{
    musig::{
        new_musig_nonce_pair, BlindingFactor, MusigSessionId, PublicNonce,
        SecretNonce as MusigSecNonce,
    },
    rand, KeyPair, Message, PublicKey, Secp256k1, SecretKey,
};
use std::str::FromStr;

pub(super) const INCOMPLETE_HISTORY_ERROR: &str =
    "BIP448 state history is incomplete for this coin";
pub(super) const SIGNATURE_COUNT_ERROR: &str =
    "BIP448 signature count does not match any supported transfer state";

pub(super) fn sender_coin_for_intent<'a>(
    wallet: &'a Wallet,
    intent: &Bip448TransferIntent,
) -> Result<(usize, &'a Coin)> {
    let matches = wallet
        .coins
        .iter()
        .enumerate()
        .filter(|(_, coin)| {
            coin.statechain_id.as_deref() == Some(intent.statechain_id.as_str())
                && coin.signed_statechain_id.as_deref()
                    == Some(intent.sender_signed_statechain_id.as_str())
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [(index, coin)] => Ok((*index, *coin)),
        [] => Err(anyhow!("BIP448 transfer sender Coin is missing")),
        _ => Err(anyhow!(
            "BIP448 transfer sender Coin identity is not unique"
        )),
    }
}

pub(super) async fn install_bip448_intent_pending(
    client_config: &ClientConfig,
    intent: &Bip448TransferIntent,
) -> Result<()> {
    let record = get_bip448_statechain(
        &client_config.pool,
        &intent.wallet_name,
        &intent.statechain_id,
    )
    .await?;
    let wallet = get_wallet(&client_config.pool, &intent.wallet_name).await?;
    let (_, coin) = sender_coin_for_intent(&wallet, intent)?;
    let receiver = PublicKey::from_str(&intent.receiver_user_pubkey)?;
    if intent.reuse_signed_state {
        let pending = get_bip448_pending_transfer_signing(
            &client_config.pool,
            &intent.wallet_name,
            &intent.statechain_id,
        )
        .await?
        .ok_or_else(|| anyhow!("BIP448 reused transfer pending row is missing"))?;
        let history = get_bip448_state_history(
            &client_config.pool,
            &intent.wallet_name,
            &intent.statechain_id,
        )
        .await?;
        let entry = history
            .get(
                usize::try_from(intent.planned_state_number)?
                    .checked_sub(1)
                    .ok_or_else(|| anyhow!(INCOMPLETE_HISTORY_ERROR))?,
            )
            .ok_or_else(|| anyhow!(INCOMPLETE_HISTORY_ERROR))?;
        install_reused_signed_bip448_transfer_state(
            &client_config.pool,
            &intent.wallet_name,
            &intent.statechain_id,
            &intent.intent_id,
            &pending.signing_id,
            &entry.update_signature,
        )
        .await?;
        bip448_process_checkpoint("transfer_state_signed_persisted");
        return Ok(());
    }
    let pending = if intent.reuse_pending {
        get_bip448_pending_transfer_signing(
            &client_config.pool,
            &intent.wallet_name,
            &intent.statechain_id,
        )
        .await?
        .ok_or_else(|| anyhow!("BIP448 reused transfer pending row is missing"))?
    } else {
        new_bip448_transfer_pending(&record, coin, &receiver, intent)?
    };
    let artifacts = transfer_artifacts(
        &record,
        &receiver,
        intent.planned_state_number,
        pending.state_locktime,
    )?;
    validate_pending(&pending, &record, &artifacts)?;
    install_bip448_transfer_target_pending(&client_config.pool, &intent.intent_id, &pending)
        .await?;
    bip448_process_checkpoint("pending_persisted");
    bip448_process_checkpoint("transfer_state_sign_first_armed");
    Ok(())
}

fn new_bip448_transfer_pending(
    record: &Bip448StatechainRecord,
    coin: &Coin,
    receiver_user_pubkey: &PublicKey,
    intent: &Bip448TransferIntent,
) -> Result<Bip448PendingDepositSigning> {
    let state_locktime = checked_next_state_locktime(
        absolute::LockTime::from_consensus(intent.previous_locktime),
        sample_future_state_stride(),
    )?
    .to_consensus_u32();
    let artifacts = transfer_artifacts(
        record,
        receiver_user_pubkey,
        intent.planned_state_number,
        state_locktime,
    )?;
    let secp = Secp256k1::new();
    let client_seckey = PrivateKey::from_wif(&coin.user_privkey)?.inner;
    let client_pubkey = PublicKey::from_str(&coin.user_pubkey)?;
    let mut rng = rand::rng();
    let (client_secret_nonce, client_public_nonce) = new_musig_nonce_pair(
        &secp,
        MusigSessionId::new(&mut rng),
        None,
        Some(client_seckey),
        client_pubkey,
        Some(Message::from(artifacts.update_template_hash)),
        None,
    )?;
    let blinding_factor = BlindingFactor::from_slice(&SecretKey::new(&mut rng).to_secret_bytes())?;
    Ok(Bip448PendingDepositSigning {
        wallet_name: intent.wallet_name.clone(),
        statechain_id: intent.statechain_id.clone(),
        funding_txid: record.funding_outpoint.txid.clone(),
        funding_vout: record.funding_outpoint.vout,
        funding_value_sats: record.funding_outpoint.value_sats,
        update_template_hash: hex::encode(artifacts.update_template_hash.to_byte_array()),
        settlement_template_hash: hex::encode(artifacts.settlement_template_hash.to_byte_array()),
        state_locktime,
        signing_id: hex::encode(SecretKey::new(&mut rng).to_secret_bytes()),
        client_secret_nonce: hex::encode(client_secret_nonce.serialize()),
        client_public_nonce: hex::encode(client_public_nonce.serialize()),
        blinding_factor: hex::encode(blinding_factor.as_bytes()),
        server_public_nonce: None,
    })
}

pub(super) async fn request_and_store_bip448_transfer_nonce(
    client_config: &ClientConfig,
    intent: &Bip448TransferIntent,
) -> Result<()> {
    if bip448_signature_count(client_config, &intent.statechain_id).await?
        != u64::from(intent.expected_signature_count)
    {
        return Err(anyhow!(SIGNATURE_COUNT_ERROR));
    }
    let signing_id = intent
        .current_pending_signing_id
        .as_deref()
        .ok_or_else(|| anyhow!("BIP448 transfer intent has no pending signing id"))?;
    let server_nonce = bip448_sign_first(
        client_config,
        &Bip448SignFirstRequestPayload {
            statechain_id: intent.statechain_id.clone(),
            signed_statechain_id: intent.sender_signed_statechain_id.clone(),
            signing_id: signing_id.to_owned(),
        },
    )
    .await?;
    bip448_process_checkpoint("transfer_state_sign_first_response_returned");
    store_bip448_transfer_state_nonce(
        &client_config.pool,
        &intent.wallet_name,
        &intent.statechain_id,
        &intent.intent_id,
        signing_id,
        &server_nonce,
    )
    .await?;
    bip448_process_checkpoint("server_nonce_persisted");
    bip448_process_checkpoint("transfer_state_nonce_persisted");
    Ok(())
}

pub(super) fn bip448_transfer_sign_second_artifacts(
    coin: &Coin,
    record: &Bip448StatechainRecord,
    pending: &Bip448PendingDepositSigning,
    artifacts: &Bip448RecoveryArtifacts,
) -> Result<(
    CsfsSigningSession,
    PublicNonce,
    secp256k1::musig::PartialSignature,
    Bip448PartialSignatureRequestPayload,
)> {
    let secp = Secp256k1::new();
    let client_seckey = PrivateKey::from_wif(&coin.user_privkey)?.inner;
    let client_keypair = KeyPair::from_secret_key(&secp, &client_seckey);
    let client_secret_nonce = musig_secret_nonce(&pending.client_secret_nonce)?;
    let client_public_nonce = PublicNonce::from_slice(&hex::decode(&pending.client_public_nonce)?)?;
    let server_public_nonce = pending
        .server_public_nonce
        .as_deref()
        .ok_or_else(|| anyhow!("BIP448 transfer server nonce is not persisted"))?;
    let server_nonce = PublicNonce::from_slice(&hex::decode(server_public_nonce)?)?;
    let blinding_factor = BlindingFactor::from_slice(&hex::decode(&pending.blinding_factor)?)?;
    let session = CsfsSigningSession::new(
        &secp,
        CsfsSigningRole::FundingUpdate,
        PublicKey::from_str(&record.aggregate_pubkey)?,
        &client_public_nonce,
        &server_nonce,
        artifacts.update_template_hash,
        &blinding_factor,
    )?;
    let client_partial = session.partial_sign_verified(
        &secp,
        CsfsSigningParticipant::Client,
        client_secret_nonce,
        &client_public_nonce,
        &client_keypair,
    )?;
    let payload = Bip448PartialSignatureRequestPayload {
        statechain_id: record.statechain_id.clone(),
        signed_statechain_id: coin
            .signed_statechain_id
            .clone()
            .ok_or_else(|| anyhow!("BIP448 transfer coin missing signed_statechain_id"))?,
        signing_id: pending.signing_id.clone(),
        negate_seckey: u8::from(session.negate_seckey()),
        session: hex::encode(session.blinded_server_session().serialize()),
        server_pub_nonce: server_public_nonce.to_owned(),
    };
    Ok((session, server_nonce, client_partial, payload))
}

pub(super) async fn complete_bip448_transfer_sign_second(
    client_config: &ClientConfig,
    intent: &Bip448TransferIntent,
) -> Result<()> {
    let before = bip448_signature_count(client_config, &intent.statechain_id).await?;
    let expected = u64::from(intent.expected_signature_count);
    if before != expected && before != expected.saturating_add(1) {
        return Err(anyhow!(SIGNATURE_COUNT_ERROR));
    }
    let wallet = get_wallet(&client_config.pool, &intent.wallet_name).await?;
    let (_, coin) = sender_coin_for_intent(&wallet, intent)?;
    let record = get_bip448_statechain(
        &client_config.pool,
        &intent.wallet_name,
        &intent.statechain_id,
    )
    .await?;
    let pending = get_bip448_pending_transfer_signing(
        &client_config.pool,
        &intent.wallet_name,
        &intent.statechain_id,
    )
    .await?
    .ok_or_else(|| anyhow!("BIP448 transfer pending row is missing"))?;
    if intent.current_pending_signing_id.as_deref() != Some(pending.signing_id.as_str()) {
        return Err(anyhow!("BIP448 transfer pending identity changed"));
    }
    let receiver = PublicKey::from_str(&intent.receiver_user_pubkey)?;
    let artifacts = transfer_artifacts(
        &record,
        &receiver,
        intent.planned_state_number,
        pending.state_locktime,
    )?;
    validate_pending(&pending, &record, &artifacts)?;
    let (session, server_nonce, client_partial, payload) =
        bip448_transfer_sign_second_artifacts(coin, &record, &pending, &artifacts)?;
    let server_partial = bip448_sign_second(client_config, &payload).await?;
    let server_pubkey = PublicKey::from_str(
        coin.server_pubkey
            .as_deref()
            .ok_or_else(|| anyhow!("BIP448 transfer coin missing server_pubkey"))?,
    )?;
    session.verify_partial(
        &Secp256k1::new(),
        CsfsSigningParticipant::Server,
        &server_partial,
        &server_nonce,
        &server_pubkey,
    )?;
    bip448_process_checkpoint("transfer_state_sign_second_response_returned");
    let signature = session.aggregate_and_verify(&[&client_partial, &server_partial])?;
    if bip448_signature_count(client_config, &intent.statechain_id).await?
        != expected
            .checked_add(1)
            .ok_or_else(|| anyhow!(SIGNATURE_COUNT_ERROR))?
    {
        return Err(anyhow!(SIGNATURE_COUNT_ERROR));
    }
    store_bip448_transfer_state_signed_artifacts(
        &client_config.pool,
        &intent.wallet_name,
        &intent.statechain_id,
        &intent.intent_id,
        &pending.signing_id,
        &hex::encode(server_partial.serialize()),
        &signature.to_string(),
    )
    .await?;
    bip448_process_checkpoint("final_signature_completed");
    bip448_process_checkpoint("transfer_state_signed_persisted");
    Ok(())
}

pub(super) fn transfer_artifacts(
    record: &Bip448StatechainRecord,
    receiver_user_pubkey: &PublicKey,
    state_number: u32,
    state_locktime: u32,
) -> Result<Bip448RecoveryArtifacts> {
    let secp = Secp256k1::new();
    let network = Network::from_str(&record.network)?;
    let recovery_script = Address::p2tr(
        &secp,
        receiver_user_pubkey.x_only_public_key().0,
        None,
        network,
    )
    .script_pubkey();
    Ok(build_funding_recovery_artifacts(
        &secp,
        &PublicKey::from_str(&record.aggregate_pubkey)?,
        OutPoint {
            txid: Txid::from_str(&record.funding_outpoint.txid)?,
            vout: record.funding_outpoint.vout,
        },
        record.funding_outpoint.value_sats,
        recovery_script,
        state_number,
        absolute::LockTime::from_consensus(state_locktime),
        record.challenge_delay,
        record.latest_state.fee_bump_policy,
    )?)
}
pub(super) fn validate_pending(
    pending: &Bip448PendingDepositSigning,
    record: &Bip448StatechainRecord,
    artifacts: &Bip448RecoveryArtifacts,
) -> Result<()> {
    if pending.funding_txid != record.funding_outpoint.txid
        || pending.funding_vout != record.funding_outpoint.vout
        || pending.funding_value_sats != record.funding_outpoint.value_sats
        || pending.update_template_hash
            != hex::encode(artifacts.update_template_hash.to_byte_array())
        || pending.settlement_template_hash
            != hex::encode(artifacts.settlement_template_hash.to_byte_array())
    {
        return Err(anyhow!(
            "BIP448 pending transfer signing does not match the next-state templates"
        ));
    }
    Ok(())
}

pub(super) fn signing_metadata_from_history(
    pending: &Bip448PendingDepositSigning,
    entry: &Bip448StateHistoryEntry,
    state_number: u32,
) -> Result<Bip448SigningMetadata> {
    if entry.state_number != state_number
        || entry.update_template_hash != pending.update_template_hash
        || entry.client_public_nonce != pending.client_public_nonce
        || entry.blinding_factor != pending.blinding_factor
        || pending
            .server_public_nonce
            .as_deref()
            .is_some_and(|nonce| normalize_hex(nonce) != normalize_hex(&entry.server_public_nonce))
    {
        return Err(anyhow!(INCOMPLETE_HISTORY_ERROR));
    }
    Ok(Bip448SigningMetadata {
        role: Bip448RecoveryTemplateRole::FundingUpdate,
        signing_id: pending.signing_id.clone(),
        client_public_nonce: entry.client_public_nonce.clone(),
        server_public_nonce: entry.server_public_nonce.clone(),
        blinding_factor: entry.blinding_factor.clone(),
        update_template_hash: entry.update_template_hash.clone(),
        update_signature: entry.update_signature.clone(),
        server_signature_count: u64::from(state_number),
    })
}
pub(super) fn musig_secret_nonce(value: &str) -> Result<MusigSecNonce> {
    let bytes: [u8; 132] = hex::decode(value)?
        .try_into()
        .map_err(|_| anyhow!("BIP448 pending client secret nonce must be 132 bytes"))?;
    Ok(MusigSecNonce::from_slice(bytes))
}
pub(super) fn normalize_hex(value: &str) -> &str {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value)
}
