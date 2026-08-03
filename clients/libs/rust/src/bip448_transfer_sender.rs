use std::{future::Future, str::FromStr};
use anyhow::{anyhow, Result};
use bitcoin::{absolute, hashes::Hash, Address, Network, OutPoint, PrivateKey, Txid};
use mercurylib::{
    bip448_statechain::{
        script::{checked_next_state_locktime, sample_future_state_stride},
        signing::*,
        signing_api::*,
        storage::*,
    },
    decode_transfer_address,
    transfer::{
        bip448::{Bip448StateHistoryEntry, Bip448TransferMsg},
        sender::*,
    },
    validate_address,
    wallet::{Coin, CoinStatus, Wallet},
};
use secp256k1::{
    musig::{
        new_musig_nonce_pair, BlindingFactor, MusigSessionId, PublicNonce,
        SecretNonce as MusigSecNonce,
    },
    rand, KeyPair, Message, PublicKey, Scalar, Secp256k1, SecretKey,
};
use crate::{
    client_config::ClientConfig,
    deposit::{bip448_sign_first, bip448_sign_second, bip448_signature_count},
    sqlite_manager::*,
    transfer_receiver::bip448_transfer_receiver::expected_server_pubkey,
    transfer_sender::get_new_x1,
    utils,
};
const ELIGIBILITY_ERROR: &str =
    "only transfer of a CONFIRMED BIP448 coin at its accepted latest state is supported";
const INCOMPLETE_HISTORY_ERROR: &str = "BIP448 state history is incomplete for this coin";
const SIGNATURE_COUNT_ERROR: &str =
    "BIP448 signature count does not match any supported transfer state";
const BATCHED_PENDING_ERROR: &str =
    "BIP448 batched pending transfers cannot be cancelled or retargeted";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TransferStatePlan {
    state_number: u32,
    reuse_pending: bool,
    reuse_signed_state: bool,
    clear_local_attempt: bool,
}
#[cfg(feature = "test-hooks")]
fn bip448_process_checkpoint(checkpoint: &str) {
    if std::env::var("ML_BIP448_RESTART_CHILD").as_deref() == Ok("1") && std::env::var("ML_BIP448_TEST_CHECKPOINT").as_deref() == Ok(checkpoint) {
        std::process::exit(86);
    }
}
#[cfg(not(feature = "test-hooks"))]
fn bip448_process_checkpoint(_checkpoint: &str) {}
pub async fn transfer_bip448_sender(
    client_config: &ClientConfig,
    recipient_address: &str,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<()> {
    let mut wallet = get_wallet(&client_config.pool, wallet_name).await?;
    let record = get_bip448_statechain_optional(&client_config.pool, wallet_name, statechain_id).await?.ok_or_else(eligibility_error)?;
    let coin_index = wallet
        .coins
        .iter()
        .position(|coin| coin.statechain_id.as_deref() == Some(statechain_id) && coin.status == CoinStatus::CONFIRMED && mercurylib::bip448_statechain::deposit::is_bip448_coin(coin))
        .ok_or_else(eligibility_error)?;
    ensure_local_eligibility(record.latest_state_number, &wallet.coins[coin_index].status)?;
    if !validate_address(recipient_address, &wallet.network)? {
        return Err(anyhow!("Invalid address"));
    }
    let (_, receiver_user_pubkey, recipient_auth_pubkey) = decode_transfer_address(recipient_address)?;
    let recipient_auth = recipient_auth_pubkey.to_string();
    if let Some(transfer_msg) = get_bip448_transfer_msg(&client_config.pool, wallet_name, statechain_id, &recipient_auth).await.map(Some).or_else(|error| if matches!(error.downcast_ref::<sqlx::Error>(), Some(sqlx::Error::RowNotFound)) { Ok(None) } else { Err(error) })? {
        if transfer_msg.statechain_id != statechain_id || transfer_msg.receiver_user_public_key != receiver_user_pubkey.to_string() { return Err(anyhow!("BIP448 persisted transfer message does not match the recipient address")); }
        let coin = wallet.coins[coin_index].clone();
        ensure_persisted_transfer_delivered(
            || verify_persisted_transfer_completed(client_config, &transfer_msg, &receiver_user_pubkey),
            || async {
                let encrypted_transfer_msg =
                    upload_transfer_msg(client_config, &coin, &recipient_auth_pubkey, &transfer_msg).await?;
                bip448_process_checkpoint("transfer_msg_uploaded");
                Ok(encrypted_transfer_msg)
            },
            |encrypted_transfer_msg| {
                let recipient_auth = recipient_auth.as_str();
                async move {
                    transfer_message_is_stored(
                        client_config,
                        recipient_auth,
                        &encrypted_transfer_msg,
                    ).await
                }
            },
        ).await?;
        finish_transfer(client_config, &mut wallet, coin_index).await?;
        return Ok(());
    }
    let has_other_transfer_msg = has_bip448_transfer_msg_for_statechain(&client_config.pool, wallet_name, statechain_id).await?;
    let mut state_history = outgoing_state_history(
        &client_config.pool, wallet_name, &record.statechain_id, record.latest_state_number,
    ).await?;
    let existing_pending = get_bip448_pending_transfer_signing(&client_config.pool, wallet_name, statechain_id).await?;
    let current_count = bip448_signature_count(client_config, statechain_id).await?;
    let pending_matches_recipient = !has_other_transfer_msg && existing_pending.as_ref().is_some_and(|pending|
        pending_matches_next_state(&record, &receiver_user_pubkey, pending));
    let plan = transfer_state_plan(current_count, record.latest_state_number,
        pending_matches_recipient, existing_pending.is_some() || has_other_transfer_msg, None)?;
    if current_count == u64::from(record.latest_state_number) + 1 {
        state_history = outgoing_state_history(
            &client_config.pool, wallet_name, &record.statechain_id, record.latest_state_number + 1,
        ).await?;
    }
    let previous_locktime = if plan.state_number == record.latest_state_number + 2 {
        state_history.last().ok_or_else(|| anyhow!(INCOMPLETE_HISTORY_ERROR))?.state_locktime
    } else {
        record.latest_state.state_locktime
    };
    let reused_history_entry = if plan.reuse_signed_state {
        state_history.pop()
    } else {
        None
    };
    let coin = wallet.coins[coin_index].clone();
    if PublicKey::from_str(&coin.user_pubkey)?.combine(&PublicKey::from_str(coin.server_pubkey.as_deref().ok_or_else(|| anyhow!("BIP448 transfer coin missing server_pubkey"))?)?)? != PublicKey::from_str(&record.aggregate_pubkey)? { return Err(anyhow!("BIP448 transfer coin keys do not match the accepted aggregate public key")); }
    let transfer_signature = create_transfer_signature(recipient_address, &record.funding_outpoint.txid, record.funding_outpoint.vout, &coin.user_privkey)?;
    let resumed = if plan.reuse_pending {
        Some(pending_or_new_transfer_signing(client_config, wallet_name, &record, &coin,
            &receiver_user_pubkey, plan.state_number, previous_locktime, existing_pending.clone()).await?)
    } else { None };
    let x1 = map_new_x1_result(get_new_x1(client_config, statechain_id,
        coin.signed_statechain_id.as_deref().ok_or_else(|| anyhow!("BIP448 transfer coin missing signed_statechain_id"))?,
        &recipient_auth, None).await)?;
    if plan.clear_local_attempt {
        if let Some(pending) = existing_pending.as_ref() {
            delete_bip448_pending_transfer_signing(&client_config.pool, wallet_name, statechain_id, &pending.signing_id).await?;
        }
        delete_bip448_transfer_msgs(&client_config.pool, wallet_name, statechain_id).await?;
    }
    let (artifacts, pending) = match resumed {
        Some(value) => value,
        None => pending_or_new_transfer_signing(client_config, wallet_name, &record, &coin,
            &receiver_user_pubkey, plan.state_number, previous_locktime, None).await?,
    };
    bip448_process_checkpoint("pending_persisted");
    let signing_metadata = match reused_history_entry.as_ref() {
        Some(entry) => signing_metadata_from_history(&pending, entry, plan.state_number)?,
        None => sign_next_state(client_config, &coin, &record, &artifacts, &pending, plan.state_number).await?,
    };
    let transfer_msg = build_transfer_msg(&record, &coin, receiver_user_pubkey, &x1, &transfer_signature, &artifacts, signing_metadata, state_history)?;
    insert_bip448_state_history_entry(
        &client_config.pool,
        wallet_name,
        statechain_id,
        transfer_msg
            .state_history
            .last()
            .ok_or_else(|| anyhow!(INCOMPLETE_HISTORY_ERROR))?,
    )
    .await?;
    insert_or_update_bip448_transfer_msg(&client_config.pool, wallet_name, &recipient_auth, &transfer_msg).await?;
    bip448_process_checkpoint("transfer_msg_persisted");
    let encrypted_transfer_msg =
        upload_transfer_msg(client_config, &coin, &recipient_auth_pubkey, &transfer_msg).await?;
    bip448_process_checkpoint("transfer_msg_uploaded");
    if !matches!(
        transfer_message_is_stored(client_config, &recipient_auth, &encrypted_transfer_msg).await,
        Ok(true)
    ) {
        return Err(anyhow!("transfer message was not stored"));
    }
    finish_transfer(client_config, &mut wallet, coin_index).await
}
async fn ensure_persisted_transfer_delivered<C, CF, U, UF, S, SF>(
    mut verify_completed: C,
    upload: U,
    verify_stored: S,
) -> Result<()>
where
    C: FnMut() -> CF,
    CF: Future<Output = Result<bool>>,
    U: FnOnce() -> UF,
    UF: Future<Output = Result<String>>,
    S: FnOnce(String) -> SF,
    SF: Future<Output = Result<bool>>,
{
    if matches!(verify_completed().await, Ok(true)) {
        return Ok(());
    }

    let upload_error = match upload().await {
        Ok(encrypted_transfer_msg) => {
            return if matches!(verify_stored(encrypted_transfer_msg).await, Ok(true)) {
                Ok(())
            } else {
                Err(anyhow!("transfer message was not stored"))
            }
        }
        Err(error) => error,
    };
    if matches!(verify_completed().await, Ok(true)) {
        Ok(())
    } else {
        Err(upload_error)
    }
}
async fn transfer_message_is_stored(
    client_config: &ClientConfig,
    recipient_auth_pubkey: &str,
    encrypted_transfer_msg: &str,
) -> Result<bool> {
    let path = format!(
        "transfer/get_msg_addr/{}",
        recipient_auth_pubkey.to_string()
    );
    let client = client_config.get_reqwest_client()?;
    let request = client.get(&format!("{}/{}", client_config.statechain_entity, path));
    let value = request.send().await?.text().await?;
    let response: mercurylib::transfer::receiver::GetMsgAddrResponsePayload =
        serde_json::from_str(value.as_str())?;
    Ok(mailbox_contains_transfer_message(
        &response.list_enc_transfer_msg,
        encrypted_transfer_msg,
    ))
}
fn mailbox_contains_transfer_message(messages: &[String], encrypted_transfer_msg: &str) -> bool {
    messages
        .iter()
        .any(|message| message == encrypted_transfer_msg)
}
async fn verify_persisted_transfer_completed(
    client_config: &ClientConfig,
    transfer_msg: &Bip448TransferMsg,
    receiver_user_pubkey: &PublicKey,
) -> Result<bool> {
    let Some(statechain_info) =
        utils::get_statechain_info(&transfer_msg.statechain_id, client_config).await?
    else {
        return Ok(false);
    };
    let current_server = PublicKey::from_str(&statechain_info.enclave_public_key)?;
    Ok(expected_server_pubkey(transfer_msg, receiver_user_pubkey)
        .is_ok_and(|expected| current_server == expected))
}
fn ensure_local_eligibility(latest_state_number: u32, status: &CoinStatus) -> Result<()> {
    if latest_state_number < 1 || status != &CoinStatus::CONFIRMED { return Err(eligibility_error()); }
    Ok(())
}
fn transfer_state_plan(
    count: u64,
    latest: u32,
    pending_matches_recipient: bool,
    has_local_attempt: bool,
    pending_batch_id: Option<&str>,
) -> Result<TransferStatePlan> {
    if pending_batch_id.is_some() { return Err(anyhow!(BATCHED_PENDING_ERROR)); }
    let next = latest.checked_add(1).ok_or_else(|| anyhow!(SIGNATURE_COUNT_ERROR))?;
    if count == u64::from(latest) {
        return Ok(TransferStatePlan { state_number: next,
            reuse_pending: pending_matches_recipient, reuse_signed_state: false,
            clear_local_attempt: has_local_attempt && !pending_matches_recipient });
    }
    if count == u64::from(next) {
        if !has_local_attempt { return Err(anyhow!(SIGNATURE_COUNT_ERROR)); }
        return if pending_matches_recipient {
            Ok(TransferStatePlan { state_number: next, reuse_pending: true,
                reuse_signed_state: true, clear_local_attempt: false })
        } else {
            Ok(TransferStatePlan { state_number: next.checked_add(1).ok_or_else(|| anyhow!(SIGNATURE_COUNT_ERROR))?,
                reuse_pending: false, reuse_signed_state: false, clear_local_attempt: has_local_attempt })
        };
    }
    Err(anyhow!(SIGNATURE_COUNT_ERROR))
}
fn eligibility_error() -> anyhow::Error {
    anyhow!(ELIGIBILITY_ERROR)
}
fn pending_matches_next_state(
    record: &Bip448StatechainRecord,
    receiver_user_pubkey: &PublicKey,
    pending: &Bip448PendingDepositSigning,
) -> bool {
    transfer_artifacts(record, receiver_user_pubkey, record.latest_state_number + 1, pending.state_locktime)
        .and_then(|artifacts| validate_pending(pending, record, &artifacts)).is_ok()
}
fn map_new_x1_result(result: Result<String>) -> Result<String> {
    result.map_err(|error| if error.to_string().contains("Statecoin batch locked") {
        anyhow!(BATCHED_PENDING_ERROR)
    } else { error })
}
async fn outgoing_state_history(
    pool: &sqlx::Pool<sqlx::Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    history_tip: u32,
) -> Result<Vec<Bip448StateHistoryEntry>> {
    let history = get_bip448_state_history(pool, wallet_name, statechain_id)
        .await?
        .into_iter()
        .filter(|entry| (1..=history_tip).contains(&entry.state_number))
        .collect::<Vec<_>>();
    if history.len() != history_tip as usize
        || history
            .iter()
            .enumerate()
            .any(|(index, entry)| entry.state_number != index as u32 + 1)
    {
        return Err(anyhow!(INCOMPLETE_HISTORY_ERROR));
    }
    Ok(history)
}
async fn pending_or_new_transfer_signing(
    client_config: &ClientConfig,
    wallet_name: &str,
    record: &Bip448StatechainRecord,
    coin: &Coin,
    receiver_user_pubkey: &PublicKey,
    state_number: u32,
    previous_locktime: u32,
    existing: Option<Bip448PendingDepositSigning>,
) -> Result<(Bip448RecoveryArtifacts, Bip448PendingDepositSigning)> {
    if let Some(pending) = existing {
        let _ = checked_next_state_locktime(absolute::LockTime::from_consensus(previous_locktime), pending.state_locktime.checked_sub(previous_locktime).ok_or_else(|| anyhow!("BIP448 pending transfer state locktime does not advance the latest state"))?)?;
        let artifacts = transfer_artifacts(record, receiver_user_pubkey, state_number, pending.state_locktime)?;
        validate_pending(&pending, record, &artifacts)?;
        return Ok((artifacts, pending));
    }
    let state_locktime = checked_next_state_locktime(
        absolute::LockTime::from_consensus(previous_locktime), sample_future_state_stride(),
    )?.to_consensus_u32();
    let artifacts = transfer_artifacts(record, receiver_user_pubkey, state_number, state_locktime)?;
    let secp = Secp256k1::new();
    let client_seckey = PrivateKey::from_wif(&coin.user_privkey)?.inner;
    let client_pubkey = PublicKey::from_str(&coin.user_pubkey)?;
    let mut rng = rand::rng();
    let (client_secret_nonce, client_public_nonce) = new_musig_nonce_pair(
        &secp, MusigSessionId::new(&mut rng), None, Some(client_seckey), client_pubkey,
        Some(Message::from(artifacts.update_template_hash)), None,
    )?;
    let blinding_factor = BlindingFactor::from_slice(&SecretKey::new(&mut rng).to_secret_bytes())?;
    let pending = Bip448PendingDepositSigning {
        wallet_name: wallet_name.to_string(),
        statechain_id: record.statechain_id.clone(),
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
    };
    let persisted = insert_bip448_pending_transfer_signing_if_absent(&client_config.pool, &pending).await?;
    let artifacts = transfer_artifacts(record, receiver_user_pubkey, state_number, persisted.state_locktime)?;
    validate_pending(&persisted, record, &artifacts)?;
    Ok((artifacts, persisted))
}
fn transfer_artifacts(
    record: &Bip448StatechainRecord,
    receiver_user_pubkey: &PublicKey,
    state_number: u32,
    state_locktime: u32,
) -> Result<Bip448RecoveryArtifacts> {
    let secp = Secp256k1::new();
    let network = Network::from_str(&record.network)?;
    let recovery_script = Address::p2tr(
        &secp, receiver_user_pubkey.x_only_public_key().0, None, network,
    ).script_pubkey();
    Ok(build_funding_recovery_artifacts(
        &secp, &PublicKey::from_str(&record.aggregate_pubkey)?,
        OutPoint { txid: Txid::from_str(&record.funding_outpoint.txid)?, vout: record.funding_outpoint.vout },
        record.funding_outpoint.value_sats, recovery_script, state_number,
        absolute::LockTime::from_consensus(state_locktime), record.challenge_delay,
        record.latest_state.fee_bump_policy,
    )?)
}
fn validate_pending(
    pending: &Bip448PendingDepositSigning,
    record: &Bip448StatechainRecord,
    artifacts: &Bip448RecoveryArtifacts,
) -> Result<()> {
    if pending.funding_txid != record.funding_outpoint.txid
        || pending.funding_vout != record.funding_outpoint.vout
        || pending.funding_value_sats != record.funding_outpoint.value_sats
        || pending.update_template_hash != hex::encode(artifacts.update_template_hash.to_byte_array())
        || pending.settlement_template_hash != hex::encode(artifacts.settlement_template_hash.to_byte_array())
    {
        return Err(anyhow!("BIP448 pending transfer signing does not match the next-state templates"));
    }
    Ok(())
}
async fn sign_next_state(
    client_config: &ClientConfig,
    coin: &Coin,
    record: &Bip448StatechainRecord,
    artifacts: &Bip448RecoveryArtifacts,
    pending: &Bip448PendingDepositSigning,
    state_number: u32,
) -> Result<Bip448SigningMetadata> {
    let secp = Secp256k1::new();
    let client_seckey = PrivateKey::from_wif(&coin.user_privkey)?.inner;
    let client_keypair = KeyPair::from_secret_key(&secp, &client_seckey);
    let server_pubkey = PublicKey::from_str(coin.server_pubkey.as_deref().ok_or_else(|| anyhow!("BIP448 transfer coin missing server_pubkey"))?)?;
    let aggregate_pubkey = PublicKey::from_str(&record.aggregate_pubkey)?;
    let client_secret_nonce = musig_secret_nonce(&pending.client_secret_nonce)?;
    let client_public_nonce = PublicNonce::from_slice(&hex::decode(&pending.client_public_nonce)?)?;
    let blinding_factor = BlindingFactor::from_slice(&hex::decode(&pending.blinding_factor)?)?;
    let server_public_nonce = replay_or_request_server_nonce(client_config, coin, pending).await?;
    bip448_process_checkpoint("server_nonce_persisted");
    let server_nonce = PublicNonce::from_slice(&hex::decode(&server_public_nonce)?)?;
    let session = CsfsSigningSession::new(
        &secp, CsfsSigningRole::FundingUpdate, aggregate_pubkey, &client_public_nonce,
        &server_nonce, artifacts.update_template_hash, &blinding_factor,
    )?;
    let client_partial = session.partial_sign_verified(
        &secp, CsfsSigningParticipant::Client, client_secret_nonce,
        &client_public_nonce, &client_keypair,
    )?;
    let server_partial = bip448_sign_second(
        client_config,
        &Bip448PartialSignatureRequestPayload {
            statechain_id: record.statechain_id.clone(),
            signed_statechain_id: coin.signed_statechain_id.clone().ok_or_else(|| anyhow!("BIP448 transfer coin missing signed_statechain_id"))?,
            signing_id: pending.signing_id.clone(),
            negate_seckey: u8::from(session.negate_seckey()),
            session: hex::encode(session.blinded_server_session().serialize()),
            server_pub_nonce: server_public_nonce.clone(),
        },
    )
    .await?;
    session.verify_partial(&secp, CsfsSigningParticipant::Server, &server_partial, &server_nonce, &server_pubkey)?;
    let signature = session.aggregate_and_verify(&[&client_partial, &server_partial])?;
    bip448_process_checkpoint("final_signature_completed");
    let server_signature_count = bip448_signature_count(client_config, &record.statechain_id).await?;
    let expected_signature_count = u64::from(state_number);
    if server_signature_count != expected_signature_count {
        return Err(anyhow!("BIP448 next-state signing completed with server signature count {server_signature_count}; expected {expected_signature_count}"));
    }
    Ok(Bip448SigningMetadata {
        role: Bip448RecoveryTemplateRole::FundingUpdate,
        signing_id: pending.signing_id.clone(),
        client_public_nonce: pending.client_public_nonce.clone(),
        server_public_nonce,
        blinding_factor: pending.blinding_factor.clone(),
        update_template_hash: pending.update_template_hash.clone(),
        update_signature: signature.to_string(),
        server_signature_count,
    })
}
fn signing_metadata_from_history(
    pending: &Bip448PendingDepositSigning,
    entry: &Bip448StateHistoryEntry,
    state_number: u32,
) -> Result<Bip448SigningMetadata> {
    if entry.state_number != state_number || entry.update_template_hash != pending.update_template_hash
        || entry.client_public_nonce != pending.client_public_nonce || entry.blinding_factor != pending.blinding_factor
        || pending.server_public_nonce.as_deref().is_some_and(|nonce| normalize_hex(nonce) != normalize_hex(&entry.server_public_nonce))
    { return Err(anyhow!(INCOMPLETE_HISTORY_ERROR)); }
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
async fn replay_or_request_server_nonce(
    client_config: &ClientConfig,
    coin: &Coin,
    pending: &Bip448PendingDepositSigning,
) -> Result<String> {
    if let Some(server_nonce) = &pending.server_public_nonce {
        return Ok(normalize_hex(server_nonce).to_string());
    }
    let server_nonce = bip448_sign_first(
        client_config,
        &Bip448SignFirstRequestPayload {
            statechain_id: pending.statechain_id.clone(),
            signed_statechain_id: coin.signed_statechain_id.clone().ok_or_else(|| anyhow!("BIP448 transfer coin missing signed_statechain_id"))?,
            signing_id: pending.signing_id.clone(),
        },
    )
    .await?;
    update_bip448_pending_transfer_server_public_nonce(
        &client_config.pool, &pending.wallet_name, &pending.statechain_id,
        &pending.signing_id, &server_nonce,
    ).await?;
    Ok(normalize_hex(&server_nonce).to_string())
}
fn build_transfer_msg(
    record: &Bip448StatechainRecord,
    coin: &Coin,
    receiver_user_pubkey: PublicKey,
    x1: &str,
    transfer_signature: &str,
    artifacts: &Bip448RecoveryArtifacts,
    signing_metadata: Bip448SigningMetadata,
    mut state_history: Vec<Bip448StateHistoryEntry>,
) -> Result<Bip448TransferMsg> {
    let secp = Secp256k1::new();
    let aggregate_pubkey = PublicKey::from_str(&record.aggregate_pubkey)?;
    let latest_state = build_funding_latest_state(
        &secp, &aggregate_pubkey, artifacts, signing_metadata, Vec::new(),
    )?;
    let x1_bytes: [u8; 32] = hex::decode(normalize_hex(x1))?
        .try_into()
        .map_err(|_| anyhow!("transfer x1 must be 32 bytes"))?;
    let t1 = PrivateKey::from_wif(&coin.user_privkey)?
        .inner
        .add_tweak(&Scalar::from_be_bytes(x1_bytes)?)?
        .to_secret_bytes();
    let server_public_key = coin.server_pubkey.clone().ok_or_else(|| anyhow!("BIP448 transfer coin missing server_pubkey"))?;
    state_history.push(history_entry(
        &latest_state,
        receiver_user_pubkey.x_only_public_key().0,
    ));
    let receiver_user_public_key = receiver_user_pubkey.to_string();
    Ok(Bip448TransferMsg {
        msg_version: 2,
        statechain_id: record.statechain_id.clone(),
        transfer_signature: transfer_signature.to_string(),
        sender_user_public_key: coin.user_pubkey.clone(),
        receiver_user_public_key,
        server_public_key,
        aggregate_pubkey: aggregate_pubkey.to_string(),
        funding_outpoint: record.funding_outpoint.clone(),
        latest_state_number: latest_state.state_number,
        challenge_delay: record.challenge_delay,
        amount_sats: record.amount_sats,
        network: record.network.clone(),
        value_schedule: latest_state.value_schedule.clone(),
        server_signature_count: latest_state.signing_metadata.server_signature_count,
        t1,
        state_history,
        latest_state,
    })
}
async fn upload_transfer_msg(
    client_config: &ClientConfig,
    coin: &Coin,
    recipient_auth_pubkey: &PublicKey,
    transfer_msg: &Bip448TransferMsg,
) -> Result<String> {
    let payload = TransferUpdateMsgRequestPayload {
        statechain_id: transfer_msg.statechain_id.clone(),
        auth_sig: coin.signed_statechain_id.clone().ok_or_else(|| anyhow!("BIP448 transfer coin missing signed_statechain_id"))?,
        new_user_auth_key: recipient_auth_pubkey.to_string(),
        enc_transfer_msg: transfer_msg.encrypt(recipient_auth_pubkey)?,
    };
    let response = client_config
        .get_reqwest_client()?
        .post(format!("{}/transfer/update_msg", client_config.statechain_entity))
        .json(&payload)
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(anyhow!("Failed to update transfer message"));
    }
    Ok(payload.enc_transfer_msg)
}
pub async fn cancel_bip448_transfer(
    client_config: &ClientConfig,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<u32> {
    let recipient_address = crate::transfer_receiver::new_transfer_address(client_config, wallet_name).await?;
    transfer_bip448_sender(client_config, &recipient_address, wallet_name, statechain_id).await?;
    let received = crate::transfer_receiver::execute(client_config, wallet_name).await?;
    if received.is_there_batch_locked { return Err(anyhow!(BATCHED_PENDING_ERROR)); }
    if !received.received_statechain_ids.iter().any(|id| id == statechain_id) {
        return Err(anyhow!("BIP448 transfer cancellation did not receive the replacement state"));
    }
    Ok(get_bip448_statechain(&client_config.pool, wallet_name, statechain_id).await?.latest_state_number)
}
async fn finish_transfer(
    client_config: &ClientConfig,
    wallet: &mut Wallet,
    coin_index: usize,
) -> Result<()> {
    let wallet_name = wallet.name.clone();
    let statechain_id = wallet.coins[coin_index].statechain_id.clone().ok_or_else(|| anyhow!("BIP448 transfer coin missing statechain_id"))?;
    if let Some(pending) = get_bip448_pending_transfer_signing(&client_config.pool, &wallet_name, &statechain_id).await? {
        delete_bip448_pending_transfer_signing(&client_config.pool, &wallet_name, &statechain_id, &pending.signing_id).await?;
    }
    wallet.coins[coin_index].status = CoinStatus::IN_TRANSFER;
    update_wallet(&client_config.pool, wallet).await
}
fn musig_secret_nonce(value: &str) -> Result<MusigSecNonce> {
    let bytes: [u8; 132] = hex::decode(value)?.try_into()
        .map_err(|_| anyhow!("BIP448 pending client secret nonce must be 132 bytes"))?;
    Ok(MusigSecNonce::from_slice(bytes))
}
fn normalize_hex(value: &str) -> &str {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value)
}
#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    #[test]
    fn unknown_signature_count_fails_closed_before_mutation() {
        let mutated = Cell::new(false);
        let error = transfer_state_plan(5, 3, false, false, None)
            .map(|plan| { mutated.set(plan.clear_local_attempt); plan })
            .unwrap_err();
        assert_eq!(error.to_string(), SIGNATURE_COUNT_ERROR);
        assert!(!mutated.get());
        assert_eq!(transfer_state_plan(4, 3, false, false, None)
            .unwrap_err().to_string(), SIGNATURE_COUNT_ERROR);
        assert_eq!(transfer_state_plan(3, 3, true, true, None).unwrap(),
            TransferStatePlan { state_number: 4, reuse_pending: true,
                reuse_signed_state: false, clear_local_attempt: false });
        assert_eq!(transfer_state_plan(4, 3, false, true, None).unwrap().state_number, 5);
        assert!(ensure_local_eligibility(2, &CoinStatus::CONFIRMED).is_ok());
    }

    #[test]
    fn batched_pending_attempt_stops_retargeting() {
        assert_eq!(transfer_state_plan(3, 3, false, true, Some("batch"))
            .unwrap_err().to_string(), BATCHED_PENDING_ERROR);
        assert_eq!(map_new_x1_result(Err(anyhow!("status: 400, error: Statecoin batch locked (the batch time has not expired).")))
            .unwrap_err().to_string(), BATCHED_PENDING_ERROR);
    }

    #[tokio::test]
    async fn verified_completion_skips_reupload() {
        let checks = Cell::new(0);
        let uploads = Cell::new(0);

        ensure_persisted_transfer_delivered(
            || {
                checks.set(checks.get() + 1);
                std::future::ready(Ok(true))
            },
            || {
                uploads.set(uploads.get() + 1);
                std::future::ready(Err(anyhow!("upload must be skipped")))
            },
            |_| std::future::ready(Err(anyhow!("storage check must be skipped"))),
        )
        .await
        .unwrap();

        assert_eq!(checks.get(), 1);
        assert_eq!(uploads.get(), 0);
    }

    #[tokio::test]
    async fn successful_upload_requires_retrievable_message() {
        ensure_persisted_transfer_delivered(
            || std::future::ready(Ok(false)),
            || std::future::ready(Ok("current ciphertext".to_string())),
            |encrypted_transfer_msg| {
                std::future::ready(Ok(encrypted_transfer_msg == "current ciphertext"))
            },
        )
        .await
        .unwrap();

        for stored in [Ok(false), Err(anyhow!("mailbox unavailable"))] {
            let error = ensure_persisted_transfer_delivered(
                || std::future::ready(Ok(false)),
                || std::future::ready(Ok("current ciphertext".to_string())),
                move |encrypted_transfer_msg| {
                    assert_eq!(encrypted_transfer_msg, "current ciphertext");
                    std::future::ready(stored)
                },
            )
            .await
            .unwrap_err();
            assert_eq!(error.to_string(), "transfer message was not stored");
        }
    }

    #[test]
    fn mailbox_must_contain_the_current_ciphertext() {
        let old_message = "old ciphertext".to_string();
        let current_message = "current ciphertext".to_string();

        assert!(!mailbox_contains_transfer_message(
            &[old_message.clone()],
            &current_message,
        ));
        assert!(mailbox_contains_transfer_message(
            &[old_message, current_message.clone()],
            &current_message,
        ));
    }

    #[tokio::test]
    async fn upload_failure_finishes_only_after_verified_completion() {
        let checks = Cell::new(0);
        ensure_persisted_transfer_delivered(
            || {
                let completed = checks.get() == 1;
                checks.set(checks.get() + 1);
                std::future::ready(Ok(completed))
            },
            || std::future::ready(Err(anyhow!("rotated authentication key"))),
            |_| std::future::ready(Err(anyhow!("storage check must be skipped"))),
        )
        .await
        .unwrap();
        assert_eq!(checks.get(), 2);

        let error = ensure_persisted_transfer_delivered(
            || std::future::ready(Ok(false)),
            || std::future::ready(Err(anyhow!("original upload error"))),
            |_| std::future::ready(Err(anyhow!("storage check must be skipped"))),
        )
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "original upload error");

        let error = ensure_persisted_transfer_delivered(
            || std::future::ready(Err(anyhow!("completion evidence unavailable"))),
            || std::future::ready(Err(anyhow!("original upload error"))),
            |_| std::future::ready(Err(anyhow!("storage check must be skipped"))),
        )
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "original upload error");
    }

}
