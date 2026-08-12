use crate::{
    bip448_funding::{
        Bip448ObservationStatus, Bip448OwnershipStatus, Bip448TransferIntent,
        Bip448TransferIntentActivityStatus, Bip448TransferIntentKind, Bip448TransferIntentPhase,
        Bip448TransferStateSigningPhase,
    },
    bip448_owner::{
        classify_bip448_owner_relation, current_server_public_key, get_bip448_statechain_presence,
        get_current_bip448_owner, select_current_bip448_owner, validate_bip448_coin_local_auth,
        Bip448OwnerRelation, Bip448StatechainPresence,
    },
    client_config::ClientConfig,
    coin_status::sync_bip448_funding_bindings,
    deposit::{bip448_sign_first, bip448_sign_second, bip448_signature_count},
    sqlite_manager::*,
    transfer_receiver::bip448_transfer_receiver::expected_server_pubkey,
};
use anyhow::{anyhow, Context, Result};
use bitcoin::{
    absolute,
    hashes::{sha256, Hash},
    Address, Network, OutPoint, PrivateKey, Txid,
};
use mercurylib::{
    bip448_statechain::{
        script::{checked_next_state_locktime, sample_future_state_stride},
        signing::*,
        signing_api::*,
        storage::*,
    },
    decode_transfer_address,
    transfer::{
        bip448::{
            verify_bip448_transfer_msg, Bip448StateHistoryEntry, Bip448TransferChainFacts,
            Bip448TransferMsg,
        },
        receiver::{StatechainInfo, StatechainInfoResponsePayload},
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
    rand, schnorr, KeyPair, Message, PublicKey, Scalar, Secp256k1, SecretKey,
};
use std::{fmt, future::Future, str::FromStr};
#[cfg(feature = "test-hooks")]
use std::{path::Path, thread, time::Duration};
const ELIGIBILITY_ERROR: &str =
    "only transfer of a CONFIRMED BIP448 coin at its accepted latest state is supported";
const INCOMPLETE_HISTORY_ERROR: &str = "BIP448 state history is incomplete for this coin";
const SIGNATURE_COUNT_ERROR: &str =
    "BIP448 signature count does not match any supported transfer state";
const BATCHED_PENDING_ERROR: &str =
    "BIP448 batched pending transfers cannot be cancelled or retargeted";

#[derive(Debug)]
enum GetNewX1Error {
    DefinitiveBatch(String),
    Indeterminate(anyhow::Error),
}

impl fmt::Display for GetNewX1Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DefinitiveBatch(message) => formatter.write_str(message),
            Self::Indeterminate(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for GetNewX1Error {}

async fn get_new_x1(
    client_config: &ClientConfig,
    statechain_id: &str,
    signed_statechain_id: &str,
    recipient_auth_pubkey: &str,
    batch_id: Option<String>,
) -> std::result::Result<String, GetNewX1Error> {
    let endpoint = client_config.statechain_entity.clone();
    let path = "transfer/sender";

    let client = client_config
        .get_reqwest_client()
        .map_err(GetNewX1Error::Indeterminate)?;
    let request = client.post(&format!("{}/{}", endpoint, path));

    let transfer_sender_request_payload = TransferSenderRequestPayload {
        statechain_id: statechain_id.to_string(),
        auth_sig: signed_statechain_id.to_string(),
        new_user_auth_key: recipient_auth_pubkey.to_string(),
        batch_id,
    };

    let response = request
        .json(&transfer_sender_request_payload)
        .send()
        .await
        .map_err(|error| {
            GetNewX1Error::Indeterminate(anyhow!(
                "transfer sender request failed before a response: {error}"
            ))
        })?;
    let status = response.status();
    let value = response.text().await.map_err(|error| {
        GetNewX1Error::Indeterminate(anyhow!("failed to read transfer sender response: {error}"))
    })?;
    if !status.is_success() {
        let message = serde_json::from_str::<serde_json::Value>(&value)
            .ok()
            .and_then(|value| value.get("message")?.as_str().map(str::to_owned));
        if status == reqwest::StatusCode::BAD_REQUEST
            && message.as_deref().is_some_and(|message| {
                matches!(
                    message,
                    "Statecoin batch locked (the batch time has not expired)."
                        | "Batch time has expired. Try a new batch id."
                )
            })
        {
            return Err(GetNewX1Error::DefinitiveBatch(message.ok_or_else(
                || {
                    GetNewX1Error::Indeterminate(anyhow!(
                        "missing definitive transfer sender error body"
                    ))
                },
            )?));
        }
        return Err(GetNewX1Error::Indeterminate(anyhow!(
            "status: {status}, error: {value}"
        )));
    }

    let response: TransferSenderResponsePayload =
        serde_json::from_str(&value).map_err(|error| {
            GetNewX1Error::Indeterminate(anyhow!(
                "failed to parse transfer sender response: {error}"
            ))
        })?;
    let x1_bytes: [u8; 32] = hex::decode(normalize_hex(&response.x1))
        .map_err(|error| GetNewX1Error::Indeterminate(error.into()))?
        .try_into()
        .map_err(|_| {
            GetNewX1Error::Indeterminate(anyhow!(
                "transfer sender response x1 must be exactly 32 bytes"
            ))
        })?;
    SecretKey::from_secret_bytes(x1_bytes).map_err(|_| {
        GetNewX1Error::Indeterminate(anyhow!("transfer sender response x1 is not a valid scalar"))
    })?;
    Ok(hex::encode(x1_bytes))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TransferStatePlan {
    state_number: u32,
    reuse_pending: bool,
    reuse_signed_state: bool,
    clear_local_attempt: bool,
}

struct ValidatedPersistedTransfer {
    wallet: Wallet,
    record: Bip448StatechainRecord,
    message: Bip448TransferMsg,
    pending: Bip448PendingDepositSigning,
    coin_index: usize,
    x1_pub: String,
}
#[cfg(feature = "test-hooks")]
fn bip448_process_checkpoint(checkpoint: &str) {
    if std::env::var("ML_BIP448_RESTART_CHILD").as_deref() == Ok("1")
        && std::env::var("ML_BIP448_TEST_CHECKPOINT").as_deref() == Ok(checkpoint)
    {
        std::process::exit(86);
    }
}
#[cfg(not(feature = "test-hooks"))]
fn bip448_process_checkpoint(_checkpoint: &str) {}

#[cfg(feature = "test-hooks")]
fn bip448_test_barrier(checkpoint: &str) -> Result<()> {
    if std::env::var("ML_BIP448_TEST_BARRIER").as_deref() != Ok(checkpoint) {
        return Ok(());
    }
    let reached = std::env::var("ML_BIP448_TEST_BARRIER_REACHED")
        .context("BIP448 test barrier reached path is missing")?;
    let release = std::env::var("ML_BIP448_TEST_BARRIER_RELEASE")
        .context("BIP448 test barrier release path is missing")?;
    std::fs::write(&reached, checkpoint.as_bytes())
        .context("failed to publish BIP448 test barrier")?;
    for _ in 0..6_000 {
        if Path::new(&release).try_exists()? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(10));
    }
    Err(anyhow!("timed out waiting for BIP448 test barrier release"))
}

#[cfg(not(feature = "test-hooks"))]
fn bip448_test_barrier(_checkpoint: &str) -> Result<()> {
    Ok(())
}
pub async fn transfer_bip448_sender(
    client_config: &ClientConfig,
    recipient_address: &str,
    wallet_name: &str,
    statechain_id: &str,
    batch_id: Option<String>,
) -> Result<()> {
    let wallet = get_wallet(&client_config.pool, wallet_name).await?;
    let record = get_bip448_statechain_optional(&client_config.pool, wallet_name, statechain_id)
        .await?
        .ok_or_else(eligibility_error)?;
    ensure_any_locally_eligible_coin(&wallet, statechain_id, record.latest_state_number)?;
    if !validate_address(recipient_address, &wallet.network)? {
        return Err(anyhow!("Invalid address"));
    }
    let (_, receiver_user_pubkey, recipient_auth_pubkey) =
        decode_transfer_address(recipient_address)?;
    let recipient_auth = recipient_auth_pubkey.to_string();

    let mut active =
        get_active_bip448_transfer_intent(&client_config.pool, wallet_name, statechain_id).await?;
    if let Some((stored_recipient, stored_json)) = get_bip448_transfer_msg_raw_optional(
        &client_config.pool,
        wallet_name,
        statechain_id,
        Some(&recipient_auth),
    )
    .await?
    {
        if stored_recipient != recipient_auth {
            return Err(anyhow!("BIP448 outgoing-message recipient changed"));
        }
        let transfer_msg: Bip448TransferMsg = serde_json::from_str(&stored_json)?;
        if serde_json::to_string(&transfer_msg)? != stored_json {
            return Err(anyhow!("BIP448 outgoing transfer message is noncanonical"));
        }
        if active.is_none() {
            return resume_unintended_persisted_transfer(
                client_config,
                wallet,
                record,
                receiver_user_pubkey,
                recipient_auth_pubkey,
                stored_json,
                transfer_msg,
            )
            .await;
        }
        if transfer_msg.receiver_user_public_key != receiver_user_pubkey.to_string() {
            return Err(anyhow!(
                "BIP448 persisted transfer message does not match the recipient address"
            ));
        }
    }

    if let Some(live) = active.as_ref() {
        if finish_if_bip448_active_message_rotated(client_config, live).await? {
            return Ok(());
        }
        if matches!(
            live.phase,
            Bip448TransferIntentPhase::Prepared | Bip448TransferIntentPhase::SenderArmed
        ) && finish_if_bip448_predecessor_rotated(client_config, live).await?
        {
            return Ok(());
        }
    }
    require_local_accepted_history_prefix(client_config, &record).await?;
    require_fresh_transfer_duplicate_safety(client_config, wallet_name, statechain_id).await?;
    let wallet = get_wallet(&client_config.pool, wallet_name).await?;
    let record = get_bip448_statechain(&client_config.pool, wallet_name, statechain_id).await?;
    ensure_any_locally_eligible_coin(&wallet, statechain_id, record.latest_state_number)?;

    if let Some(existing) = active.clone() {
        let same_invocation = existing.intent_kind == Bip448TransferIntentKind::UserTransfer
            && existing.recipient_address == recipient_address
            && existing.receiver_user_pubkey == receiver_user_pubkey.to_string()
            && existing.recipient_auth_pubkey == recipient_auth
            && existing.batch_id == batch_id
            && !existing.acknowledge_cooperative_duplicates;
        if same_invocation {
            drive_bip448_transfer_intent(client_config, existing).await?;
            return Ok(());
        }
        recover_bip448_intent_for_successor(client_config, &existing).await?;
        active = get_active_bip448_transfer_intent(&client_config.pool, wallet_name, statechain_id)
            .await?;
    }

    let intent = build_bip448_user_transfer_intent(
        client_config,
        &wallet,
        &record,
        recipient_address,
        &receiver_user_pubkey,
        &recipient_auth_pubkey,
        batch_id,
        active.as_ref(),
    )
    .await?;
    let intent = match active {
        Some(predecessor) => {
            supersede_bip448_transfer_intent(&client_config.pool, &predecessor.intent_id, &intent)
                .await?
        }
        None => insert_bip448_transfer_intent_if_absent(&client_config.pool, &intent).await?,
    };
    bip448_process_checkpoint("transfer_intent_prepared");
    drive_bip448_transfer_intent(client_config, intent).await?;
    Ok(())
}

async fn require_local_accepted_history_prefix(
    client_config: &ClientConfig,
    record: &Bip448StatechainRecord,
) -> Result<()> {
    let history = get_bip448_state_history(
        &client_config.pool,
        &record.wallet_name,
        &record.statechain_id,
    )
    .await?;
    let accepted_len = usize::try_from(record.latest_state_number)
        .map_err(|_| anyhow!(INCOMPLETE_HISTORY_ERROR))?;
    let maximum_len = accepted_len
        .checked_add(2)
        .ok_or_else(|| anyhow!(INCOMPLETE_HISTORY_ERROR))?;
    if history.len() < accepted_len
        || history.len() > maximum_len
        || history.iter().enumerate().any(|(index, entry)| {
            u32::try_from(index)
                .ok()
                .and_then(|index| index.checked_add(1))
                != Some(entry.state_number)
        })
        || accepted_len == 0
        || !history_entry_matches_latest_state(&history[accepted_len - 1], &record.latest_state)
    {
        return Err(anyhow!(INCOMPLETE_HISTORY_ERROR));
    }
    Ok(())
}

async fn require_fresh_transfer_duplicate_safety(
    client_config: &ClientConfig,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<()> {
    let report = sync_bip448_funding_bindings(client_config, wallet_name).await?;
    if report.bindings.iter().any(|binding| {
        binding.statechain_id == statechain_id
            && binding.role == crate::bip448_funding::Bip448BindingRole::Duplicate
            && binding.ownership_status == Bip448OwnershipStatus::Current
            && binding.observation_status != Bip448ObservationStatus::SpentConfirmed
    }) {
        return Err(anyhow!(
            "BIP448 current-owner duplicate funding must be spent-confirmed before transfer"
        ));
    }
    Ok(())
}

async fn resume_unintended_persisted_transfer(
    client_config: &ClientConfig,
    wallet: Wallet,
    record: Bip448StatechainRecord,
    receiver_user_pubkey: PublicKey,
    recipient_auth_pubkey: PublicKey,
    transfer_msg_json: String,
    transfer_msg: Bip448TransferMsg,
) -> Result<()> {
    let statechain_id = transfer_msg.statechain_id.clone();
    let presence = get_bip448_statechain_presence(client_config, &statechain_id).await?;
    let Bip448StatechainPresence::Present(statechain_info) = &presence else {
        return Err(anyhow!(
            "BIP448 statechain is missing; persisted transfer ownership is closed or unknown"
        ));
    };
    let validated = validate_persisted_transfer_raw(
        client_config,
        &wallet.name,
        &statechain_id,
        &recipient_auth_pubkey.to_string(),
        &transfer_msg_json,
        &receiver_user_pubkey,
        None,
        statechain_info,
    )
    .await?;
    if serde_json::to_string(&validated.wallet)? != serde_json::to_string(&wallet)?
        || validated.record != record
        || validated.message != transfer_msg
    {
        return Err(anyhow!(
            "BIP448 persisted transfer storage changed during raw-first validation"
        ));
    }
    let mut wallet = validated.wallet;
    let record = validated.record;
    let transfer_msg = validated.message;
    let sender_coin_index = validated.coin_index;
    let relation = classify_bip448_owner_relation(
        &presence,
        &transfer_msg.sender_user_public_key,
        &transfer_msg.server_public_key,
        &record.aggregate_pubkey,
    )?;
    let coin_index = match relation {
        Bip448OwnerRelation::Current => {
            require_fresh_transfer_duplicate_safety(client_config, &wallet.name, &statechain_id)
                .await?;
            wallet = get_wallet(&client_config.pool, &wallet.name).await?;
            let owner = select_current_bip448_owner(
                &wallet,
                &statechain_id,
                &record.aggregate_pubkey,
                presence,
            )?;
            if owner.coin_index != sender_coin_index {
                return Err(anyhow!(
                    "persisted BIP448 transfer sender does not match the current owner generation"
                ));
            }
            ensure_local_eligibility(
                record.latest_state_number,
                &wallet
                    .coins
                    .get(owner.coin_index)
                    .ok_or_else(|| {
                        anyhow!("selected BIP448 transfer owner index is absent from its wallet snapshot")
                    })?
                    .status,
            )?;
            owner.coin_index
        }
        Bip448OwnerRelation::Rotated => {
            let Bip448StatechainPresence::Present(statechain_info) = &presence else {
                unreachable!("Rotated requires a present statechain response")
            };
            let current_server = current_server_public_key(statechain_info)?;
            if current_server != expected_server_pubkey(&transfer_msg, &receiver_user_pubkey)? {
                return Err(anyhow!(
                    "BIP448 statechain rotated to an unrelated owner generation"
                ));
            }
            finish_bip448_rotated_outgoing_transfer(
                &client_config.pool,
                &wallet.name,
                &statechain_id,
                &recipient_auth_pubkey.to_string(),
                &transfer_msg_json,
                &validated.x1_pub,
                &validated.pending,
            )
            .await?;
            return Ok(());
        }
        Bip448OwnerRelation::Missing => {
            return Err(anyhow!(
                "BIP448 statechain is missing; persisted transfer ownership is closed or unknown"
            ));
        }
    };
    let coin = wallet
        .coins
        .get(coin_index)
        .ok_or_else(|| {
            anyhow!("selected BIP448 transfer owner index is absent from its wallet snapshot")
        })?
        .clone();
    let recipient_auth = recipient_auth_pubkey.to_string();
    resume_persisted_transfer(
        relation,
        || async {
            ensure_persisted_transfer_delivered(
                || {
                    verify_persisted_transfer_completed(
                        client_config,
                        &transfer_msg,
                        &receiver_user_pubkey,
                    )
                },
                || async {
                    let x1 = transfer_x1_from_message(&coin, &transfer_msg)?;
                    let encrypted = upload_transfer_msg(
                        client_config,
                        &coin,
                        &recipient_auth_pubkey,
                        &transfer_msg,
                        &x1,
                    )
                    .await?;
                    bip448_process_checkpoint("transfer_msg_uploaded");
                    Ok(encrypted)
                },
                |encrypted| async move {
                    transfer_message_is_stored(client_config, &recipient_auth, &encrypted).await
                },
            )
            .await
        },
        || finish_transfer(client_config, &mut wallet, coin_index),
    )
    .await
}

async fn build_bip448_user_transfer_intent(
    client_config: &ClientConfig,
    wallet: &Wallet,
    record: &Bip448StatechainRecord,
    recipient_address: &str,
    receiver_user_pubkey: &PublicKey,
    recipient_auth_pubkey: &PublicKey,
    batch_id: Option<String>,
    predecessor: Option<&Bip448TransferIntent>,
) -> Result<Bip448TransferIntent> {
    if predecessor.is_some_and(|intent| intent.batch_id.is_some()) {
        return Err(anyhow!(BATCHED_PENDING_ERROR));
    }
    let owner =
        get_current_bip448_owner(client_config, wallet, &wallet.name, &record.statechain_id)
            .await?;
    let coin = wallet
        .coins
        .get(owner.coin_index)
        .ok_or_else(|| anyhow!("selected BIP448 transfer owner Coin is missing"))?;
    ensure_local_eligibility(record.latest_state_number, &coin.status)?;
    let server = PublicKey::from_str(
        coin.server_pubkey
            .as_deref()
            .ok_or_else(|| anyhow!("BIP448 transfer coin missing server_pubkey"))?,
    )?;
    if PublicKey::from_str(&coin.user_pubkey)?.combine(&server)?
        != PublicKey::from_str(&record.aggregate_pubkey)?
    {
        return Err(anyhow!(
            "BIP448 transfer coin keys do not match the accepted aggregate public key"
        ));
    }
    let pending = get_bip448_pending_transfer_signing(
        &client_config.pool,
        &wallet.name,
        &record.statechain_id,
    )
    .await?;
    let prior_message = get_bip448_transfer_msg_raw_optional(
        &client_config.pool,
        &wallet.name,
        &record.statechain_id,
        None,
    )
    .await?;
    let current_count = bip448_signature_count(client_config, &record.statechain_id).await?;
    let pending_matches_recipient = prior_message.is_none()
        && pending.as_ref().is_some_and(|pending| {
            pending_matches_next_state(record, receiver_user_pubkey, pending)
        });
    let plan = transfer_state_plan(
        current_count,
        record.latest_state_number,
        pending_matches_recipient,
        pending.is_some() || prior_message.is_some(),
        predecessor.and_then(|intent| intent.batch_id.as_deref()),
    )?;
    let expected_signature_count =
        u32::try_from(current_count).map_err(|_| anyhow!(SIGNATURE_COUNT_ERROR))?;
    let state_history = outgoing_state_history(
        &client_config.pool,
        &wallet.name,
        &record.statechain_id,
        expected_signature_count,
    )
    .await?;
    let previous_locktime = if plan.state_number
        == record
            .latest_state_number
            .checked_add(2)
            .ok_or_else(|| anyhow!(SIGNATURE_COUNT_ERROR))?
    {
        state_history
            .last()
            .ok_or_else(|| anyhow!(INCOMPLETE_HISTORY_ERROR))?
            .state_locktime
    } else {
        record.latest_state.state_locktime
    };
    let (prior_transfer_recipient_auth_pubkey, prior_transfer_msg_hash) = match prior_message {
        Some((recipient, raw)) => (
            Some(recipient),
            Some(sha256::Hash::hash(raw.as_bytes()).to_string()),
        ),
        None => (None, None),
    };
    Ok(Bip448TransferIntent {
        wallet_name: wallet.name.clone(),
        statechain_id: record.statechain_id.clone(),
        intent_id: hex::encode(SecretKey::new(&mut rand::rng()).to_secret_bytes()),
        predecessor_intent_id: predecessor.map(|intent| intent.intent_id.clone()),
        activity_status: Bip448TransferIntentActivityStatus::Active,
        intent_kind: Bip448TransferIntentKind::UserTransfer,
        acknowledge_cooperative_duplicates: false,
        recipient_address: recipient_address.to_owned(),
        receiver_user_pubkey: receiver_user_pubkey.to_string(),
        recipient_auth_pubkey: recipient_auth_pubkey.to_string(),
        batch_id,
        sender_signed_statechain_id: coin
            .signed_statechain_id
            .clone()
            .ok_or_else(|| anyhow!("BIP448 transfer coin missing signed_statechain_id"))?,
        planned_state_number: plan.state_number,
        expected_signature_count,
        previous_locktime,
        prior_pending_signing_id: pending.map(|pending| pending.signing_id),
        prior_transfer_recipient_auth_pubkey,
        prior_transfer_msg_hash,
        reuse_pending: plan.reuse_pending,
        reuse_signed_state: plan.reuse_signed_state,
        clear_local_attempt: plan.clear_local_attempt,
        generated_coin_user_pubkey: None,
        generated_coin_auth_pubkey: None,
        generated_coin_address: None,
        phase: Bip448TransferIntentPhase::Prepared,
        server_x1: None,
        current_pending_signing_id: None,
        state_signing_phase: Bip448TransferStateSigningPhase::NotStarted,
        server_partial_sig: None,
        update_signature: None,
        created_at: String::new(),
        updated_at: String::new(),
    })
}

async fn exact_active_bip448_intent(
    client_config: &ClientConfig,
    expected: &Bip448TransferIntent,
) -> Result<Bip448TransferIntent> {
    let live = get_active_bip448_transfer_intent(
        &client_config.pool,
        &expected.wallet_name,
        &expected.statechain_id,
    )
    .await?
    .ok_or_else(|| anyhow!("stale BIP448 transfer worker has no Active intent"))?;
    if live.intent_id != expected.intent_id {
        return Err(anyhow!(
            "stale BIP448 transfer worker lost its activity CAS"
        ));
    }
    Ok(live)
}

fn sender_coin_for_intent<'a>(
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

async fn drive_bip448_transfer_intent(
    client_config: &ClientConfig,
    intent: Bip448TransferIntent,
) -> Result<Option<Bip448TransferIntent>> {
    for _ in 0..12 {
        let live = exact_active_bip448_intent(client_config, &intent).await?;
        match (live.phase, live.state_signing_phase) {
            (Bip448TransferIntentPhase::Prepared, Bip448TransferStateSigningPhase::NotStarted) => {
                if finish_if_bip448_predecessor_rotated(client_config, &live).await? {
                    return Ok(None);
                }
                transition_bip448_transfer_intent_phase(
                    &client_config.pool,
                    &live.wallet_name,
                    &live.statechain_id,
                    &live.intent_id,
                    Bip448TransferIntentPhase::Prepared,
                    Bip448TransferIntentPhase::SenderArmed,
                )
                .await?;
                bip448_process_checkpoint("transfer_sender_armed");
            }
            (
                Bip448TransferIntentPhase::SenderArmed,
                Bip448TransferStateSigningPhase::NotStarted,
            ) => {
                if finish_if_bip448_predecessor_rotated(client_config, &live).await? {
                    return Ok(None);
                }
                let x1 = match get_new_x1(
                    client_config,
                    &live.statechain_id,
                    &live.sender_signed_statechain_id,
                    &live.recipient_auth_pubkey,
                    live.batch_id.clone(),
                )
                .await
                {
                    Ok(x1) => x1,
                    Err(GetNewX1Error::DefinitiveBatch(message)) => {
                        reactivate_bip448_transfer_intent_predecessor_after_definitive_rejection(
                            &client_config.pool,
                            &live,
                        )
                        .await?;
                        return Err(if message.starts_with("Statecoin batch locked") {
                            anyhow!(BATCHED_PENDING_ERROR)
                        } else {
                            anyhow!(message)
                        });
                    }
                    Err(GetNewX1Error::Indeterminate(error)) => return Err(error),
                };
                bip448_process_checkpoint("transfer_sender_response_returned");
                store_bip448_transfer_intent_x1(
                    &client_config.pool,
                    &live.wallet_name,
                    &live.statechain_id,
                    &live.intent_id,
                    &x1,
                )
                .await?;
                bip448_process_checkpoint("transfer_x1_persisted");
            }
            (Bip448TransferIntentPhase::X1Stored, Bip448TransferStateSigningPhase::NotStarted) => {
                install_bip448_intent_pending(client_config, &live).await?;
            }
            (Bip448TransferIntentPhase::X1Stored, Bip448TransferStateSigningPhase::FirstArmed) => {
                request_and_store_bip448_transfer_nonce(client_config, &live).await?;
            }
            (Bip448TransferIntentPhase::X1Stored, Bip448TransferStateSigningPhase::NonceStored) => {
                let count = bip448_signature_count(client_config, &live.statechain_id).await?;
                if count != u64::from(live.expected_signature_count) {
                    return Err(anyhow!(SIGNATURE_COUNT_ERROR));
                }
                let signing_id = live
                    .current_pending_signing_id
                    .as_deref()
                    .ok_or_else(|| anyhow!("BIP448 transfer intent has no pending signing id"))?;
                transition_bip448_transfer_state_signing_phase(
                    &client_config.pool,
                    &live.wallet_name,
                    &live.statechain_id,
                    &live.intent_id,
                    signing_id,
                    Bip448TransferStateSigningPhase::NonceStored,
                    Bip448TransferStateSigningPhase::SecondArmed,
                )
                .await?;
                bip448_process_checkpoint("transfer_state_sign_second_armed");
            }
            (Bip448TransferIntentPhase::X1Stored, Bip448TransferStateSigningPhase::SecondArmed) => {
                complete_bip448_transfer_sign_second(client_config, &live).await?;
            }
            (Bip448TransferIntentPhase::X1Stored, Bip448TransferStateSigningPhase::Signed) => {
                return materialize_deliver_and_finish_bip448_intent(client_config, &live).await;
            }
            (
                Bip448TransferIntentPhase::SenderFinished
                | Bip448TransferIntentPhase::ReceiverAccepted,
                Bip448TransferStateSigningPhase::Signed,
            ) if live.intent_kind == Bip448TransferIntentKind::Cancellation => {
                return Ok(Some(live));
            }
            _ => return Err(anyhow!("invalid BIP448 transfer intent phase combination")),
        }
    }
    Err(anyhow!(
        "BIP448 transfer intent exceeded its bounded phase driver"
    ))
}

async fn finish_if_bip448_predecessor_rotated(
    client_config: &ClientConfig,
    intent: &Bip448TransferIntent,
) -> Result<bool> {
    let (Some(recipient_auth), Some(expected_hash)) = (
        intent.prior_transfer_recipient_auth_pubkey.as_deref(),
        intent.prior_transfer_msg_hash.as_deref(),
    ) else {
        return Ok(false);
    };
    let (_, raw) = get_bip448_transfer_msg_raw_optional(
        &client_config.pool,
        &intent.wallet_name,
        &intent.statechain_id,
        Some(recipient_auth),
    )
    .await?
    .ok_or_else(|| anyhow!("BIP448 predecessor outgoing message is missing"))?;
    if sha256::Hash::hash(raw.as_bytes()).to_string() != expected_hash {
        return Err(anyhow!("BIP448 predecessor outgoing message bytes changed"));
    }
    let message: Bip448TransferMsg = serde_json::from_str(&raw)?;
    if serde_json::to_string(&message)? != raw {
        return Err(anyhow!(
            "BIP448 predecessor outgoing message is noncanonical"
        ));
    }
    let presence = get_bip448_statechain_presence(client_config, &intent.statechain_id).await?;
    match classify_bip448_owner_relation(
        &presence,
        &message.sender_user_public_key,
        &message.server_public_key,
        &message.aggregate_pubkey,
    )? {
        Bip448OwnerRelation::Current => Ok(false),
        Bip448OwnerRelation::Missing => Err(anyhow!(
            "BIP448 statechain is missing while checking predecessor rotation"
        )),
        Bip448OwnerRelation::Rotated => {
            let Bip448StatechainPresence::Present(statechain_info) = &presence else {
                unreachable!("Rotated requires a present statechain response")
            };
            let receiver = PublicKey::from_str(&message.receiver_user_public_key)?;
            if current_server_public_key(statechain_info)?
                != expected_server_pubkey(&message, &receiver)?
            {
                return Err(anyhow!(
                    "BIP448 predecessor rotated to an unrelated owner generation"
                ));
            }
            let validated = validate_persisted_transfer_raw(
                client_config,
                &intent.wallet_name,
                &intent.statechain_id,
                recipient_auth,
                &raw,
                &receiver,
                Some(intent),
                statechain_info,
            )
            .await?;
            finish_bip448_rotated_outgoing_transfer(
                &client_config.pool,
                &intent.wallet_name,
                &intent.statechain_id,
                recipient_auth,
                &raw,
                &validated.x1_pub,
                &validated.pending,
            )
            .await?;
            Ok(true)
        }
    }
}

async fn finish_if_bip448_active_message_rotated(
    client_config: &ClientConfig,
    intent: &Bip448TransferIntent,
) -> Result<bool> {
    if intent.intent_kind != Bip448TransferIntentKind::UserTransfer
        || intent.phase != Bip448TransferIntentPhase::X1Stored
        || intent.state_signing_phase != Bip448TransferStateSigningPhase::Signed
    {
        return Ok(false);
    }
    let Some((stored_recipient, raw)) = get_bip448_transfer_msg_raw_optional(
        &client_config.pool,
        &intent.wallet_name,
        &intent.statechain_id,
        Some(&intent.recipient_auth_pubkey),
    )
    .await?
    else {
        return Ok(false);
    };
    let message: Bip448TransferMsg = serde_json::from_str(&raw)?;
    if stored_recipient != intent.recipient_auth_pubkey
        || serde_json::to_string(&message)? != raw
        || message.statechain_id != intent.statechain_id
        || message.receiver_user_public_key != intent.receiver_user_pubkey
    {
        return Err(anyhow!(
            "BIP448 Active transfer message is noncanonical or changed identity"
        ));
    }
    let presence = get_bip448_statechain_presence(client_config, &intent.statechain_id).await?;
    match classify_bip448_owner_relation(
        &presence,
        &message.sender_user_public_key,
        &message.server_public_key,
        &message.aggregate_pubkey,
    )? {
        Bip448OwnerRelation::Current => Ok(false),
        Bip448OwnerRelation::Missing => Err(anyhow!(
            "BIP448 statechain is missing while finishing an Active transfer"
        )),
        Bip448OwnerRelation::Rotated => {
            let Bip448StatechainPresence::Present(statechain_info) = &presence else {
                unreachable!("Rotated requires a present statechain response")
            };
            let receiver = PublicKey::from_str(&message.receiver_user_public_key)?;
            if current_server_public_key(statechain_info)?
                != expected_server_pubkey(&message, &receiver)?
            {
                return Err(anyhow!(
                    "BIP448 Active transfer rotated to an unrelated owner generation"
                ));
            }
            let validated = validate_persisted_transfer_raw(
                client_config,
                &intent.wallet_name,
                &intent.statechain_id,
                &intent.recipient_auth_pubkey,
                &raw,
                &receiver,
                Some(intent),
                statechain_info,
            )
            .await?;
            finish_bip448_rotated_outgoing_transfer(
                &client_config.pool,
                &intent.wallet_name,
                &intent.statechain_id,
                &intent.recipient_auth_pubkey,
                &raw,
                &validated.x1_pub,
                &validated.pending,
            )
            .await?;
            Ok(true)
        }
    }
}

async fn install_bip448_intent_pending(
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

async fn request_and_store_bip448_transfer_nonce(
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

fn bip448_transfer_sign_second_artifacts(
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

async fn complete_bip448_transfer_sign_second(
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

async fn build_materialized_bip448_transfer_message(
    client_config: &ClientConfig,
    intent: &Bip448TransferIntent,
) -> Result<(
    Wallet,
    usize,
    Coin,
    Bip448TransferMsg,
    Bip448PendingDepositSigning,
)> {
    let wallet = get_wallet(&client_config.pool, &intent.wallet_name).await?;
    let (coin_index, coin) = sender_coin_for_intent(&wallet, intent)?;
    let coin = coin.clone();
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
    .ok_or_else(|| anyhow!("BIP448 Signed transfer pending row is missing"))?;
    let receiver = PublicKey::from_str(&intent.receiver_user_pubkey)?;
    let artifacts = transfer_artifacts(
        &record,
        &receiver,
        intent.planned_state_number,
        pending.state_locktime,
    )?;
    let history = get_bip448_state_history(
        &client_config.pool,
        &intent.wallet_name,
        &intent.statechain_id,
    )
    .await?;
    let prefix_len = usize::try_from(intent.planned_state_number)?
        .checked_sub(1)
        .ok_or_else(|| anyhow!(INCOMPLETE_HISTORY_ERROR))?;
    let state_history = history
        .get(..prefix_len)
        .ok_or_else(|| anyhow!(INCOMPLETE_HISTORY_ERROR))?
        .to_vec();
    let signing_metadata = if intent.reuse_signed_state {
        let entry = history
            .get(prefix_len)
            .ok_or_else(|| anyhow!(INCOMPLETE_HISTORY_ERROR))?;
        signing_metadata_from_history(&pending, entry, intent.planned_state_number)?
    } else {
        Bip448SigningMetadata {
            role: Bip448RecoveryTemplateRole::FundingUpdate,
            signing_id: pending.signing_id.clone(),
            client_public_nonce: pending.client_public_nonce.clone(),
            server_public_nonce: pending
                .server_public_nonce
                .clone()
                .ok_or_else(|| anyhow!("BIP448 Signed transfer server nonce is missing"))?,
            blinding_factor: pending.blinding_factor.clone(),
            update_template_hash: pending.update_template_hash.clone(),
            update_signature: intent
                .update_signature
                .clone()
                .ok_or_else(|| anyhow!("BIP448 Signed transfer signature is missing"))?,
            server_signature_count: u64::from(intent.planned_state_number),
        }
    };
    let transfer_signature = create_transfer_signature(
        &intent.recipient_address,
        &record.funding_outpoint.txid,
        record.funding_outpoint.vout,
        &coin.user_privkey,
    )?;
    let x1 = intent
        .server_x1
        .as_deref()
        .ok_or_else(|| anyhow!("BIP448 transfer intent x1 is missing"))?;
    let message = build_transfer_msg(
        &record,
        &coin,
        receiver,
        x1,
        &transfer_signature,
        &artifacts,
        signing_metadata,
        state_history,
    )?;
    if intent.current_pending_signing_id.as_deref() != Some(pending.signing_id.as_str())
        || intent.update_signature.as_deref()
            != message
                .state_history
                .last()
                .map(|entry| entry.update_signature.as_str())
    {
        return Err(anyhow!(
            "BIP448 newly built Signed transfer intent/pending fingerprint changed"
        ));
    }
    validate_complete_signed_transfer_pending(&coin, &record, &receiver, &message, &pending)
        .context("BIP448 newly built Signed transfer pending row is invalid")?;
    Ok((wallet, coin_index, coin, message, pending))
}

async fn load_or_materialize_signed_bip448_transfer_message(
    client_config: &ClientConfig,
    intent: &Bip448TransferIntent,
) -> Result<(
    Wallet,
    usize,
    Coin,
    Bip448TransferMsg,
    String,
    Bip448PendingDepositSigning,
)> {
    let stored = get_bip448_transfer_msg_raw_optional(
        &client_config.pool,
        &intent.wallet_name,
        &intent.statechain_id,
        None,
    )
    .await?;
    let signed_count = u64::from(intent.expected_signature_count)
        .checked_add(1)
        .ok_or_else(|| anyhow!(SIGNATURE_COUNT_ERROR))?;

    if let Some((stored_recipient, raw)) = stored {
        if stored_recipient != intent.recipient_auth_pubkey {
            return Err(anyhow!("BIP448 Signed transfer message recipient changed"));
        }
        let message: Bip448TransferMsg = serde_json::from_str(&raw)
            .context("failed to parse persisted BIP448 Signed transfer message")?;
        if serde_json::to_string(&message)? != raw {
            return Err(anyhow!(
                "BIP448 persisted Signed transfer message is noncanonical"
            ));
        }
        if message.statechain_id != intent.statechain_id
            || message.receiver_user_public_key != intent.receiver_user_pubkey
            || message.latest_state_number != intent.planned_state_number
        {
            return Err(anyhow!(
                "BIP448 persisted Signed transfer message changed intent identity"
            ));
        }

        let receiver = PublicKey::from_str(&intent.receiver_user_pubkey)?;
        let presence = get_bip448_statechain_presence(client_config, &intent.statechain_id).await?;
        let Bip448StatechainPresence::Present(statechain_info) = &presence else {
            return Err(anyhow!(
                "BIP448 statechain is missing while recovering a persisted Signed transfer"
            ));
        };
        let validated = validate_persisted_transfer_raw(
            client_config,
            &intent.wallet_name,
            &intent.statechain_id,
            &intent.recipient_auth_pubkey,
            &raw,
            &receiver,
            Some(intent),
            statechain_info,
        )
        .await?;
        if validated.message != message {
            return Err(anyhow!(
                "BIP448 persisted Signed transfer changed during raw-first validation"
            ));
        }
        let wallet = validated.wallet;
        let record = validated.record;
        let pending = validated.pending;
        let validated_coin_index = validated.coin_index;
        let (coin_index, coin) = sender_coin_for_intent(&wallet, intent)?;
        if coin_index != validated_coin_index {
            return Err(anyhow!(
                "BIP448 persisted Signed transfer sender Coin changed identity"
            ));
        }
        let coin = coin.clone();
        if intent.current_pending_signing_id.as_deref() != Some(pending.signing_id.as_str()) {
            return Err(anyhow!("BIP448 Signed transfer pending identity changed"));
        }
        let artifacts = transfer_artifacts(
            &record,
            &receiver,
            intent.planned_state_number,
            pending.state_locktime,
        )?;
        validate_pending(&pending, &record, &artifacts)?;
        let latest_entry = message
            .state_history
            .last()
            .ok_or_else(|| anyhow!("BIP448 persisted Signed transfer history is empty"))?;
        if latest_entry.state_locktime != pending.state_locktime
            || latest_entry.settlement_template_hash != pending.settlement_template_hash
            || intent.update_signature.as_deref() != Some(latest_entry.update_signature.as_str())
            || signing_metadata_from_history(&pending, latest_entry, intent.planned_state_number)?
                != message.latest_state.signing_metadata
        {
            return Err(anyhow!(
                "BIP448 persisted Signed transfer does not match its current signing journal"
            ));
        }
        let expected_x1 = intent
            .server_x1
            .as_deref()
            .ok_or_else(|| anyhow!("BIP448 transfer intent x1 is missing"))?;
        if transfer_x1_from_message(&coin, &message)? != expected_x1 {
            return Err(anyhow!(
                "BIP448 persisted Signed transfer x1 does not match its intent generation"
            ));
        }
        if bip448_signature_count(client_config, &intent.statechain_id).await? != signed_count {
            return Err(anyhow!(SIGNATURE_COUNT_ERROR));
        }
        bip448_test_barrier("transfer_pending_validated_before_materialization")?;
        let materialized = materialize_bip448_signed_transfer_intent(
            &client_config.pool,
            intent,
            &pending,
            &message,
        )
        .await?;
        if materialized != raw {
            return Err(anyhow!(
                "BIP448 persisted Signed transfer bytes changed during exact replay"
            ));
        }
        return Ok((wallet, coin_index, coin, message, raw, pending));
    }

    if bip448_signature_count(client_config, &intent.statechain_id).await? != signed_count {
        return Err(anyhow!(SIGNATURE_COUNT_ERROR));
    }
    let (wallet, coin_index, coin, message, pending) =
        build_materialized_bip448_transfer_message(client_config, intent).await?;
    bip448_test_barrier("transfer_pending_validated_before_materialization")?;
    let message_json =
        materialize_bip448_signed_transfer_intent(&client_config.pool, intent, &pending, &message)
            .await?;
    Ok((wallet, coin_index, coin, message, message_json, pending))
}

async fn materialize_deliver_and_finish_bip448_intent(
    client_config: &ClientConfig,
    intent: &Bip448TransferIntent,
) -> Result<Option<Bip448TransferIntent>> {
    let (_, coin_index, coin, message, message_json, validated_pending) =
        load_or_materialize_signed_bip448_transfer_message(client_config, intent).await?;
    bip448_process_checkpoint("transfer_msg_persisted");
    let recipient_auth = PublicKey::from_str(&intent.recipient_auth_pubkey)?;
    let receiver_user = PublicKey::from_str(&intent.receiver_user_pubkey)?;
    let x1 = intent
        .server_x1
        .as_deref()
        .ok_or_else(|| anyhow!("BIP448 transfer intent x1 is missing"))?;
    ensure_persisted_transfer_delivered(
        || verify_persisted_transfer_completed(client_config, &message, &receiver_user),
        || async {
            let encrypted =
                upload_transfer_msg(client_config, &coin, &recipient_auth, &message, x1).await?;
            bip448_process_checkpoint("transfer_msg_uploaded");
            Ok(encrypted)
        },
        |encrypted| async move {
            transfer_message_is_stored(client_config, &intent.recipient_auth_pubkey, &encrypted)
                .await
        },
    )
    .await?;

    if finish_if_bip448_active_message_rotated(client_config, intent).await? {
        return Ok(None);
    }

    bip448_test_barrier("transfer_materialized_before_sender_finish")?;

    let raw_wallet = get_bip448_raw_wallet_json(&client_config.pool, &intent.wallet_name).await?;
    let mut wallet: Wallet = serde_json::from_str(&raw_wallet)?;
    let (live_coin_index, _) = sender_coin_for_intent(&wallet, intent)?;
    if live_coin_index != coin_index {
        return Err(anyhow!("BIP448 sender Coin index changed before finish"));
    }
    wallet
        .coins
        .get_mut(live_coin_index)
        .ok_or_else(|| anyhow!("BIP448 sender Coin disappeared before finish"))?
        .status = CoinStatus::IN_TRANSFER;
    let result = match intent.intent_kind {
        Bip448TransferIntentKind::UserTransfer => {
            finish_bip448_user_transfer_and_delete_intent(
                &client_config.pool,
                intent,
                &raw_wallet,
                &wallet,
                &message_json,
                &validated_pending,
            )
            .await?;
            None
        }
        Bip448TransferIntentKind::Cancellation => Some(
            finish_bip448_cancellation_sender(
                &client_config.pool,
                intent,
                &raw_wallet,
                &wallet,
                &message_json,
                &validated_pending,
            )
            .await?,
        ),
    };
    bip448_process_checkpoint("transfer_sender_finished");
    Ok(result)
}

async fn recover_bip448_intent_for_successor(
    client_config: &ClientConfig,
    expected: &Bip448TransferIntent,
) -> Result<()> {
    for _ in 0..8 {
        let live = exact_active_bip448_intent(client_config, expected).await?;
        match (live.phase, live.state_signing_phase) {
            (Bip448TransferIntentPhase::Prepared, Bip448TransferStateSigningPhase::NotStarted)
            | (Bip448TransferIntentPhase::X1Stored, Bip448TransferStateSigningPhase::NotStarted) => {
                return Ok(())
            }
            (
                Bip448TransferIntentPhase::SenderArmed,
                Bip448TransferStateSigningPhase::NotStarted,
            ) => {
                if finish_if_bip448_predecessor_rotated(client_config, &live).await? {
                    return Ok(());
                }
                let x1 = match get_new_x1(
                    client_config,
                    &live.statechain_id,
                    &live.sender_signed_statechain_id,
                    &live.recipient_auth_pubkey,
                    live.batch_id.clone(),
                )
                .await
                {
                    Ok(x1) => x1,
                    Err(GetNewX1Error::DefinitiveBatch(message)) => {
                        reactivate_bip448_transfer_intent_predecessor_after_definitive_rejection(
                            &client_config.pool,
                            &live,
                        )
                        .await?;
                        return Err(if message.starts_with("Statecoin batch locked") {
                            anyhow!(BATCHED_PENDING_ERROR)
                        } else {
                            anyhow!(message)
                        });
                    }
                    Err(GetNewX1Error::Indeterminate(error)) => return Err(error),
                };
                bip448_process_checkpoint("transfer_sender_response_returned");
                store_bip448_transfer_intent_x1(
                    &client_config.pool,
                    &live.wallet_name,
                    &live.statechain_id,
                    &live.intent_id,
                    &x1,
                )
                .await?;
                bip448_process_checkpoint("transfer_x1_persisted");
                return Ok(());
            }
            (Bip448TransferIntentPhase::X1Stored, Bip448TransferStateSigningPhase::FirstArmed) => {
                request_and_store_bip448_transfer_nonce(client_config, &live).await?;
            }
            (Bip448TransferIntentPhase::X1Stored, Bip448TransferStateSigningPhase::NonceStored) => {
                let count = bip448_signature_count(client_config, &live.statechain_id).await?;
                if count != u64::from(live.expected_signature_count) {
                    return Err(anyhow!(SIGNATURE_COUNT_ERROR));
                }
                let signing_id = live
                    .current_pending_signing_id
                    .as_deref()
                    .ok_or_else(|| anyhow!("BIP448 transfer intent has no pending signing id"))?;
                transition_bip448_transfer_state_signing_phase(
                    &client_config.pool,
                    &live.wallet_name,
                    &live.statechain_id,
                    &live.intent_id,
                    signing_id,
                    Bip448TransferStateSigningPhase::NonceStored,
                    Bip448TransferStateSigningPhase::SecondArmed,
                )
                .await?;
                bip448_process_checkpoint("transfer_state_sign_second_armed");
            }
            (Bip448TransferIntentPhase::X1Stored, Bip448TransferStateSigningPhase::SecondArmed) => {
                complete_bip448_transfer_sign_second(client_config, &live).await?;
            }
            (Bip448TransferIntentPhase::X1Stored, Bip448TransferStateSigningPhase::Signed) => {
                load_or_materialize_signed_bip448_transfer_message(client_config, &live).await?;
                return Ok(());
            }
            _ => {
                return Err(anyhow!(
                    "BIP448 active transfer intent is not at a recoverable retarget boundary"
                ))
            }
        }
    }
    Err(anyhow!(
        "BIP448 predecessor recovery exceeded its bounded phase driver"
    ))
}

#[allow(clippy::too_many_arguments)]
async fn validate_persisted_transfer_raw(
    client_config: &ClientConfig,
    wallet_name: &str,
    statechain_id: &str,
    recipient_auth_pubkey: &str,
    expected_raw: &str,
    receiver_user_pubkey: &PublicKey,
    expected_intent: Option<&Bip448TransferIntent>,
    authoritative: &StatechainInfoResponsePayload,
) -> Result<ValidatedPersistedTransfer> {
    let (stored_recipient, stored_raw) = get_bip448_transfer_msg_raw_optional(
        &client_config.pool,
        wallet_name,
        statechain_id,
        Some(recipient_auth_pubkey),
    )
    .await?
    .ok_or_else(|| anyhow!("BIP448 persisted outgoing transfer message is missing"))?;
    if stored_recipient != recipient_auth_pubkey || stored_raw != expected_raw {
        return Err(anyhow!(
            "BIP448 persisted outgoing transfer message bytes or recipient changed"
        ));
    }
    let message: Bip448TransferMsg = serde_json::from_str(&stored_raw)
        .context("failed to parse persisted BIP448 transfer message")?;
    if serde_json::to_string(&message)? != stored_raw
        || message.statechain_id != statechain_id
        || message.receiver_user_public_key != receiver_user_pubkey.to_string()
    {
        return Err(anyhow!(
            "BIP448 persisted outgoing transfer message is noncanonical or changed identity"
        ));
    }

    let raw_wallet = get_bip448_raw_wallet_json(&client_config.pool, wallet_name).await?;
    let wallet: Wallet = serde_json::from_str(&raw_wallet)
        .context("failed to parse wallet while validating persisted BIP448 transfer")?;
    if wallet.name != wallet_name || serde_json::to_string(&wallet)? != raw_wallet {
        return Err(anyhow!(
            "BIP448 persisted-transfer wallet bytes are noncanonical or changed identity"
        ));
    }
    let record = get_bip448_statechain(&client_config.pool, wallet_name, statechain_id).await?;
    let coin_index = validate_persisted_transfer_message_local(
        &client_config.pool,
        &wallet,
        &record,
        statechain_id,
        receiver_user_pubkey,
        &message,
    )
    .await?;

    let active =
        get_active_bip448_transfer_intent(&client_config.pool, wallet_name, statechain_id).await?;
    match (expected_intent, active.as_ref()) {
        (Some(expected), Some(stored)) if expected == stored => {}
        (None, None) => {}
        (Some(_), Some(_)) => {
            return Err(anyhow!(
                "BIP448 persisted transfer intent bytes changed during validation"
            ))
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err(anyhow!(
                "BIP448 persisted transfer intent presence changed during validation"
            ))
        }
    }
    if let Some(intent) = active.as_ref() {
        let message_hash = sha256::Hash::hash(stored_raw.as_bytes()).to_string();
        let direct = intent.intent_kind == Bip448TransferIntentKind::UserTransfer
            && intent.phase == Bip448TransferIntentPhase::X1Stored
            && intent.state_signing_phase == Bip448TransferStateSigningPhase::Signed
            && intent.recipient_auth_pubkey == recipient_auth_pubkey
            && intent.receiver_user_pubkey == message.receiver_user_public_key
            && intent.planned_state_number == message.latest_state_number;
        let predecessor = matches!(
            intent.phase,
            Bip448TransferIntentPhase::Prepared | Bip448TransferIntentPhase::SenderArmed
        ) && intent.state_signing_phase
            == Bip448TransferStateSigningPhase::NotStarted
            && intent.server_x1.is_none()
            && intent.prior_transfer_recipient_auth_pubkey.as_deref()
                == Some(recipient_auth_pubkey)
            && intent.prior_transfer_msg_hash.as_deref() == Some(message_hash.as_str());
        if !direct && !predecessor {
            return Err(anyhow!(
                "BIP448 persisted transfer message does not match its active journal fingerprint"
            ));
        }
    }

    let pending =
        get_bip448_pending_transfer_signing(&client_config.pool, wallet_name, statechain_id)
            .await?
            .ok_or_else(|| anyhow!("BIP448 persisted transfer pending signing is missing"))?;
    let coin = wallet
        .coins
        .get(coin_index)
        .ok_or_else(|| anyhow!("BIP448 persisted transfer sender Coin disappeared"))?;
    validate_complete_signed_transfer_pending(
        coin,
        &record,
        receiver_user_pubkey,
        &message,
        &pending,
    )
    .context("BIP448 persisted transfer pending row is invalid")?;
    if let Some(intent) = active.as_ref() {
        let message_is_direct = intent.phase == Bip448TransferIntentPhase::X1Stored
            && intent.state_signing_phase == Bip448TransferStateSigningPhase::Signed
            && intent.recipient_auth_pubkey == recipient_auth_pubkey;
        let expected_pending = if message_is_direct {
            intent.current_pending_signing_id.as_deref()
        } else {
            intent.prior_pending_signing_id.as_deref()
        };
        if expected_pending != Some(pending.signing_id.as_str()) {
            return Err(anyhow!(
                "BIP448 persisted transfer intent/pending fingerprint changed"
            ));
        }
    }
    let derived_x1 = transfer_x1_from_message(coin, &message)?;
    let derived_secret_bytes: [u8; 32] = hex::decode(&derived_x1)?
        .try_into()
        .map_err(|_| anyhow!("BIP448 persisted transfer x1 is not exactly 32 bytes"))?;
    let derived_x1_pub =
        SecretKey::from_secret_bytes(derived_secret_bytes)?.public_key(&Secp256k1::new());
    if let Some(intent) = active.as_ref().filter(|intent| {
        intent.recipient_auth_pubkey == recipient_auth_pubkey
            && intent.state_signing_phase == Bip448TransferStateSigningPhase::Signed
    }) {
        if intent.server_x1.as_deref() != Some(derived_x1.as_str()) {
            return Err(anyhow!(
                "BIP448 persisted transfer t1 does not match its active intent x1"
            ));
        }
    }
    let authoritative_x1_text = authoritative
        .x1_pub
        .as_deref()
        .ok_or_else(|| anyhow!("BIP448 persisted transfer has no authoritative x1 generation"))?;
    let authoritative_x1 = PublicKey::from_str(authoritative_x1_text)
        .context("invalid authoritative BIP448 x1 generation")?;
    if authoritative_x1.to_string() != authoritative_x1_text || authoritative_x1 != derived_x1_pub {
        return Err(anyhow!(
            "BIP448 persisted transfer t1 does not match the authoritative x1 generation"
        ));
    }

    let current_server = current_server_public_key(authoritative)?;
    let sender_server = PublicKey::from_str(&message.server_public_key)?;
    let receiver_server = expected_server_pubkey(&message, receiver_user_pubkey)?;
    if current_server != sender_server && current_server != receiver_server {
        return Err(anyhow!(
            "BIP448 persisted transfer has an unrelated authoritative owner generation"
        ));
    }
    if authoritative.num_sigs != message.latest_state_number {
        return Err(anyhow!(SIGNATURE_COUNT_ERROR));
    }
    let sender_generation_info = StatechainInfoResponsePayload {
        enclave_public_key: message.server_public_key.clone(),
        num_sigs: authoritative.num_sigs,
        statechain_info: authoritative
            .statechain_info
            .iter()
            .map(|row| StatechainInfo {
                statechain_id: row.statechain_id.clone(),
                server_pubnonce: row.server_pubnonce.clone(),
                challenge: row.challenge.clone(),
                tx_n: row.tx_n,
            })
            .collect(),
        x1_pub: Some(authoritative_x1_text.to_owned()),
    };
    let chain_facts: Bip448TransferChainFacts =
        crate::transfer_receiver::bip448_transfer_receiver::transfer_chain_facts(
            client_config,
            &message,
            *receiver_user_pubkey,
            &record.network,
        )
        .await?;
    verify_bip448_transfer_msg(&message, &sender_generation_info, &chain_facts)
        .context("persisted BIP448 transfer failed full cryptographic validation")?;

    Ok(ValidatedPersistedTransfer {
        wallet,
        record,
        message,
        pending,
        coin_index,
        x1_pub: authoritative_x1_text.to_owned(),
    })
}

async fn validate_persisted_transfer_message_local(
    pool: &sqlx::Pool<sqlx::Sqlite>,
    wallet: &Wallet,
    record: &Bip448StatechainRecord,
    statechain_id: &str,
    receiver_user_pubkey: &PublicKey,
    transfer_msg: &Bip448TransferMsg,
) -> Result<usize> {
    if transfer_msg.statechain_id != statechain_id
        || transfer_msg.receiver_user_public_key != receiver_user_pubkey.to_string()
    {
        return Err(anyhow!(
            "BIP448 persisted transfer message does not match the recipient address"
        ));
    }
    let sender_user_pubkey = PublicKey::from_str(&transfer_msg.sender_user_public_key)
        .map_err(|_| anyhow!("BIP448 persisted transfer message has an invalid sender key"))?;
    let server_pubkey = PublicKey::from_str(&transfer_msg.server_public_key)
        .map_err(|_| anyhow!("BIP448 persisted transfer message has an invalid server key"))?;
    let aggregate_pubkey = PublicKey::from_str(&transfer_msg.aggregate_pubkey)
        .map_err(|_| anyhow!("BIP448 persisted transfer message has an invalid aggregate key"))?;
    if sender_user_pubkey.to_string() != transfer_msg.sender_user_public_key
        || server_pubkey.to_string() != transfer_msg.server_public_key
        || aggregate_pubkey.to_string() != transfer_msg.aggregate_pubkey
    {
        return Err(anyhow!(
            "BIP448 persisted transfer message contains a non-canonical public key"
        ));
    }
    let max_message_state = record
        .latest_state_number
        .checked_add(2)
        .ok_or_else(|| anyhow!("BIP448 persisted transfer state number overflow"))?;
    if transfer_msg.msg_version != 2
        || transfer_msg.aggregate_pubkey != record.aggregate_pubkey
        || transfer_msg.funding_outpoint != record.funding_outpoint
        || transfer_msg.challenge_delay != record.challenge_delay
        || transfer_msg.amount_sats != record.amount_sats
        || transfer_msg.network != record.network
        || transfer_msg.latest_state_number < record.latest_state_number
        || transfer_msg.latest_state_number > max_message_state
        || transfer_msg.latest_state_number < 2
        || transfer_msg.latest_state_number != transfer_msg.latest_state.state_number
        || transfer_msg.challenge_delay != transfer_msg.latest_state.challenge_delay
        || transfer_msg.value_schedule != transfer_msg.latest_state.value_schedule
        || transfer_msg.server_signature_count != u64::from(transfer_msg.latest_state_number)
        || transfer_msg
            .latest_state
            .signing_metadata
            .server_signature_count
            != u64::from(transfer_msg.latest_state_number)
        || !transfer_msg.latest_state.cpfp_child_templates.is_empty()
        || sender_user_pubkey.combine(&server_pubkey)? != aggregate_pubkey
    {
        return Err(anyhow!(
            "BIP448 persisted transfer message does not exactly match the accepted state and recipient"
        ));
    }
    if transfer_msg.latest_state.verify_recovery_against_keys(
        &Secp256k1::new(),
        &sender_user_pubkey,
        &server_pubkey,
    )? != aggregate_pubkey
    {
        return Err(anyhow!(
            "BIP448 persisted transfer message recovery key does not match its aggregate key"
        ));
    }

    let history = get_bip448_state_history(pool, &wallet.name, statechain_id).await?;
    if history != transfer_msg.state_history
        || history.len() != transfer_msg.latest_state_number as usize
        || history
            .iter()
            .enumerate()
            .any(|(index, entry)| entry.state_number != index as u32 + 1)
    {
        return Err(anyhow!(
            "BIP448 persisted transfer message does not exactly match local state history"
        ));
    }
    let accepted_history_index = record
        .latest_state_number
        .checked_sub(1)
        .ok_or_else(|| anyhow!("BIP448 accepted state number must be positive"))?
        as usize;
    let accepted_history = history
        .get(accepted_history_index)
        .ok_or_else(|| anyhow!("BIP448 persisted transfer history is incomplete"))?;
    let accepted_owner = if transfer_msg.latest_state_number == record.latest_state_number {
        receiver_user_pubkey.x_only_public_key().0.to_string()
    } else {
        sender_user_pubkey.x_only_public_key().0.to_string()
    };
    if accepted_history.owner_public_key != accepted_owner
        || !history_entry_matches_latest_state(accepted_history, &record.latest_state)
    {
        return Err(anyhow!(
            "BIP448 persisted transfer history does not contain the exact accepted state"
        ));
    }
    let latest_history = history
        .last()
        .ok_or_else(|| anyhow!("BIP448 persisted transfer history is empty"))?;
    if latest_history.owner_public_key != receiver_user_pubkey.x_only_public_key().0.to_string()
        || !history_entry_matches_latest_state(latest_history, &transfer_msg.latest_state)
    {
        return Err(anyhow!(
            "BIP448 persisted transfer latest state does not match its receiver history entry"
        ));
    }

    let transfer_signature = schnorr::Signature::from_str(&transfer_msg.transfer_signature)
        .map_err(|_| anyhow!("BIP448 persisted transfer signature is invalid"))?;
    let funding_txid = Txid::from_str(&transfer_msg.funding_outpoint.txid)?;
    let mut authorization = Vec::new();
    authorization.extend_from_slice(&funding_txid[..]);
    authorization.extend_from_slice(&transfer_msg.funding_outpoint.vout.to_le_bytes());
    authorization.extend_from_slice(&receiver_user_pubkey.serialize());
    let digest = sha256::Hash::hash(&authorization).to_byte_array();
    schnorr::verify(
        &transfer_signature,
        &digest,
        &sender_user_pubkey.x_only_public_key().0,
    )
    .map_err(|_| anyhow!("BIP448 persisted transfer signature is invalid"))?;

    let mut matching_coin = None;
    for (coin_index, coin) in wallet.coins.iter().enumerate().filter(|(_, coin)| {
        coin.statechain_id.as_deref() == Some(statechain_id)
            && mercurylib::bip448_statechain::deposit::is_bip448_coin(coin)
            && coin.user_pubkey == transfer_msg.sender_user_public_key
            && coin.server_pubkey.as_deref() == Some(transfer_msg.server_public_key.as_str())
    }) {
        if matching_coin.is_some() {
            return Err(anyhow!(
                "multiple wallet coins match the persisted BIP448 transfer sender generation"
            ));
        }
        if coin.aggregated_pubkey.as_deref() != Some(record.aggregate_pubkey.as_str())
            || coin.utxo_txid.as_deref() != Some(record.funding_outpoint.txid.as_str())
            || coin.utxo_vout != Some(record.funding_outpoint.vout)
            || coin.amount.map(u64::from) != Some(record.amount_sats)
        {
            return Err(anyhow!(
                "persisted BIP448 transfer sender coin does not match the accepted funding record"
            ));
        }
        let user_private = PrivateKey::from_wif(&coin.user_privkey)?;
        if user_private.inner.public_key(&Secp256k1::new()) != sender_user_pubkey {
            return Err(anyhow!(
                "persisted BIP448 transfer sender private key does not match its public key"
            ));
        }
        validate_bip448_coin_local_auth(coin, statechain_id)?;
        matching_coin = Some(coin_index);
    }
    matching_coin.ok_or_else(|| {
        anyhow!("no wallet coin exactly matches the persisted BIP448 transfer sender generation")
    })
}

fn history_entry_matches_latest_state(
    entry: &Bip448StateHistoryEntry,
    latest_state: &Bip448LatestState,
) -> bool {
    entry.state_number == latest_state.state_number
        && entry.state_locktime == latest_state.state_locktime
        && entry.update_template_hash == latest_state.update_template_hash
        && entry.settlement_template_hash == latest_state.settlement_template_hash
        && entry.update_signature == latest_state.signing_metadata.update_signature
        && entry.client_public_nonce == latest_state.signing_metadata.client_public_nonce
        && entry.server_public_nonce == latest_state.signing_metadata.server_public_nonce
        && entry.blinding_factor == latest_state.signing_metadata.blinding_factor
}

async fn resume_persisted_transfer<D, DF, F, FF>(
    relation: Bip448OwnerRelation,
    deliver: D,
    finish_local: F,
) -> Result<()>
where
    D: FnOnce() -> DF,
    DF: Future<Output = Result<()>>,
    F: FnOnce() -> FF,
    FF: Future<Output = Result<()>>,
{
    match relation {
        Bip448OwnerRelation::Current => deliver().await?,
        Bip448OwnerRelation::Rotated => {}
        Bip448OwnerRelation::Missing => {
            return Err(anyhow!(
                "BIP448 statechain is missing; persisted transfer ownership is closed or unknown"
            ));
        }
    }
    finish_local().await
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
    if verify_completed().await? {
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
    if verify_completed().await? {
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
    let presence =
        get_bip448_statechain_presence(client_config, &transfer_msg.statechain_id).await?;
    let Bip448StatechainPresence::Present(statechain_info) = presence else {
        return Err(anyhow!(
            "BIP448 statechain is missing; persisted transfer ownership is closed or unknown"
        ));
    };
    let current_server = current_server_public_key(&statechain_info)?;
    let expected_receiver_server = expected_server_pubkey(transfer_msg, receiver_user_pubkey)?;
    if current_server == expected_receiver_server {
        return Ok(true);
    }
    let sender_server = PublicKey::from_str(&transfer_msg.server_public_key)?;
    if current_server == sender_server {
        Ok(false)
    } else {
        Err(anyhow!(
            "BIP448 statechain rotated to an unrelated owner generation"
        ))
    }
}
fn ensure_local_eligibility(latest_state_number: u32, status: &CoinStatus) -> Result<()> {
    if latest_state_number < 1 || !matches!(status, CoinStatus::CONFIRMED | CoinStatus::IN_TRANSFER)
    {
        return Err(eligibility_error());
    }
    Ok(())
}

fn ensure_any_locally_eligible_coin(
    wallet: &Wallet,
    statechain_id: &str,
    latest_state_number: u32,
) -> Result<()> {
    if latest_state_number < 1
        || !wallet.coins.iter().any(|coin| {
            coin.statechain_id.as_deref() == Some(statechain_id)
                && mercurylib::bip448_statechain::deposit::is_bip448_coin(coin)
                && matches!(coin.status, CoinStatus::CONFIRMED | CoinStatus::IN_TRANSFER)
        })
    {
        return Err(eligibility_error());
    }
    Ok(())
}
fn transfer_state_plan(
    count: u64,
    latest: u32,
    pending_matches_recipient: bool,
    has_local_attempt: bool,
    pending_batch_id: Option<&str>,
) -> Result<TransferStatePlan> {
    if pending_batch_id.is_some() {
        return Err(anyhow!(BATCHED_PENDING_ERROR));
    }
    let next = latest
        .checked_add(1)
        .ok_or_else(|| anyhow!(SIGNATURE_COUNT_ERROR))?;
    if count == u64::from(latest) {
        return Ok(TransferStatePlan {
            state_number: next,
            reuse_pending: pending_matches_recipient,
            reuse_signed_state: false,
            clear_local_attempt: has_local_attempt && !pending_matches_recipient,
        });
    }
    if count == u64::from(next) {
        if !has_local_attempt {
            return Err(anyhow!(SIGNATURE_COUNT_ERROR));
        }
        return if pending_matches_recipient {
            Ok(TransferStatePlan {
                state_number: next,
                reuse_pending: true,
                reuse_signed_state: true,
                clear_local_attempt: false,
            })
        } else {
            Ok(TransferStatePlan {
                state_number: next
                    .checked_add(1)
                    .ok_or_else(|| anyhow!(SIGNATURE_COUNT_ERROR))?,
                reuse_pending: false,
                reuse_signed_state: false,
                clear_local_attempt: has_local_attempt,
            })
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
    transfer_artifacts(
        record,
        receiver_user_pubkey,
        record.latest_state_number + 1,
        pending.state_locktime,
    )
    .and_then(|artifacts| validate_pending(pending, record, &artifacts))
    .is_ok()
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
fn transfer_artifacts(
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
fn validate_pending(
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

fn validate_complete_signed_transfer_pending(
    coin: &Coin,
    record: &Bip448StatechainRecord,
    receiver_user_pubkey: &PublicKey,
    message: &Bip448TransferMsg,
    pending: &Bip448PendingDepositSigning,
) -> Result<()> {
    crate::bip448_funding::require_canonical_txid(&pending.funding_txid)?;
    crate::bip448_funding::require_canonical_hex(&pending.update_template_hash, Some(32))?;
    crate::bip448_funding::require_canonical_hex(&pending.settlement_template_hash, Some(32))?;
    crate::bip448_funding::require_canonical_hex(&pending.signing_id, Some(32))?;
    crate::bip448_funding::require_canonical_hex(&pending.client_secret_nonce, Some(132))?;
    crate::bip448_funding::require_canonical_hex(&pending.client_public_nonce, Some(66))?;
    crate::bip448_funding::require_canonical_hex(&pending.blinding_factor, Some(32))?;
    let server_public_nonce = pending
        .server_public_nonce
        .as_deref()
        .ok_or_else(|| anyhow!("BIP448 Signed transfer server nonce is missing"))?;
    crate::bip448_funding::require_canonical_hex(server_public_nonce, Some(66))?;

    let latest = message
        .state_history
        .last()
        .ok_or_else(|| anyhow!("BIP448 Signed transfer history is empty"))?;
    let metadata = &message.latest_state.signing_metadata;
    if pending.wallet_name != record.wallet_name
        || pending.statechain_id != record.statechain_id
        || pending.funding_txid != record.funding_outpoint.txid
        || pending.funding_vout != record.funding_outpoint.vout
        || pending.funding_value_sats != record.funding_outpoint.value_sats
        || pending.state_locktime != latest.state_locktime
        || pending.update_template_hash != latest.update_template_hash
        || pending.settlement_template_hash != latest.settlement_template_hash
        || pending.signing_id != metadata.signing_id
        || pending.client_public_nonce != latest.client_public_nonce
        || server_public_nonce != latest.server_public_nonce
        || pending.blinding_factor != latest.blinding_factor
    {
        return Err(anyhow!(
            "BIP448 Signed transfer pending/message fingerprint changed"
        ));
    }
    let artifacts = transfer_artifacts(
        record,
        receiver_user_pubkey,
        message.latest_state_number,
        pending.state_locktime,
    )?;
    validate_pending(pending, record, &artifacts)?;
    bip448_transfer_sign_second_artifacts(coin, record, pending, &artifacts)
        .context("BIP448 Signed transfer pending nonce pair is invalid")?;
    if signing_metadata_from_history(pending, latest, message.latest_state_number)? != *metadata {
        return Err(anyhow!(
            "BIP448 Signed transfer metadata does not match its complete pending row"
        ));
    }
    Ok(())
}
fn signing_metadata_from_history(
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
        &secp,
        &aggregate_pubkey,
        artifacts,
        signing_metadata,
        Vec::new(),
    )?;
    let x1_bytes: [u8; 32] = hex::decode(normalize_hex(x1))?
        .try_into()
        .map_err(|_| anyhow!("transfer x1 must be 32 bytes"))?;
    let t1 = PrivateKey::from_wif(&coin.user_privkey)?
        .inner
        .add_tweak(&Scalar::from_be_bytes(x1_bytes)?)?
        .to_secret_bytes();
    let server_public_key = coin
        .server_pubkey
        .clone()
        .ok_or_else(|| anyhow!("BIP448 transfer coin missing server_pubkey"))?;
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
    x1: &str,
) -> Result<String> {
    let x1_bytes: [u8; 32] = hex::decode(normalize_hex(x1))?
        .try_into()
        .map_err(|_| anyhow!("transfer x1 must be 32 bytes"))?;
    let x1_generation = SecretKey::from_secret_bytes(x1_bytes)?.public_key(&Secp256k1::new());
    let enc_transfer_msg = transfer_msg.encrypt(recipient_auth_pubkey)?;
    let decoded_ciphertext = hex::decode(&enc_transfer_msg)?;
    let digest = bip448_transfer_update_msg_auth_digest(
        &transfer_msg.statechain_id,
        recipient_auth_pubkey,
        &x1_generation,
        &decoded_ciphertext,
    )?;
    let auth_secret = PrivateKey::from_wif(&coin.auth_privkey)?.inner;
    let auth_keypair = KeyPair::from_secret_key(&Secp256k1::new(), &auth_secret);
    let payload = TransferUpdateMsgRequestPayload {
        statechain_id: transfer_msg.statechain_id.clone(),
        auth_sig: schnorr::sign(&digest, &auth_keypair).to_string(),
        new_user_auth_key: recipient_auth_pubkey.to_string(),
        x1_pub: x1_generation.to_string(),
        enc_transfer_msg,
    };
    let response = client_config
        .get_reqwest_client()?
        .post(format!(
            "{}/transfer/update_msg",
            client_config.statechain_entity
        ))
        .json(&payload)
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(anyhow!("Failed to update transfer message"));
    }
    Ok(payload.enc_transfer_msg)
}

fn transfer_x1_from_message(coin: &Coin, transfer_msg: &Bip448TransferMsg) -> Result<String> {
    let t1 = SecretKey::from_secret_bytes(transfer_msg.t1)?;
    let sender_secret = PrivateKey::from_wif(&coin.user_privkey)?.inner;
    let x1 = t1.add_tweak(&Scalar::from(sender_secret.negate()))?;
    Ok(hex::encode(x1.to_secret_bytes()))
}
pub async fn cancel_bip448_transfer(
    client_config: &ClientConfig,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<u32> {
    let mut active =
        get_active_bip448_transfer_intent(&client_config.pool, wallet_name, statechain_id).await?;
    if let Some(live) = active.as_ref() {
        let rotated = finish_if_bip448_active_message_rotated(client_config, live).await?
            || matches!(
                live.phase,
                Bip448TransferIntentPhase::Prepared | Bip448TransferIntentPhase::SenderArmed
            ) && finish_if_bip448_predecessor_rotated(client_config, live).await?;
        if rotated {
            return Ok(
                get_bip448_statechain(&client_config.pool, wallet_name, statechain_id)
                    .await?
                    .latest_state_number,
            );
        }
    }
    if active
        .as_ref()
        .is_some_and(|intent| intent.intent_kind != Bip448TransferIntentKind::Cancellation)
    {
        recover_bip448_intent_for_successor(
            client_config,
            active
                .as_ref()
                .ok_or_else(|| anyhow!("BIP448 cancellation predecessor disappeared"))?,
        )
        .await?;
        active = get_active_bip448_transfer_intent(&client_config.pool, wallet_name, statechain_id)
            .await?;
    }

    let mut cancellation = match active {
        Some(intent) if intent.intent_kind == Bip448TransferIntentKind::Cancellation => intent,
        predecessor => {
            require_fresh_transfer_duplicate_safety(client_config, wallet_name, statechain_id)
                .await?;
            let raw_wallet = get_bip448_raw_wallet_json(&client_config.pool, wallet_name).await?;
            let wallet: Wallet = serde_json::from_str(&raw_wallet)?;
            let record =
                get_bip448_statechain(&client_config.pool, wallet_name, statechain_id).await?;
            ensure_any_locally_eligible_coin(&wallet, statechain_id, record.latest_state_number)?;
            let generated_coin = wallet.get_new_coin()?;
            let recipient_address = generated_coin.address.clone();
            let (_, receiver_user_pubkey, recipient_auth_pubkey) =
                decode_transfer_address(&recipient_address)?;
            if receiver_user_pubkey.to_string() != generated_coin.user_pubkey
                || recipient_auth_pubkey.to_string() != generated_coin.auth_pubkey
            {
                return Err(anyhow!(
                    "BIP448 cancellation generated Coin address does not match its keys"
                ));
            }
            let mut intent = build_bip448_user_transfer_intent(
                client_config,
                &wallet,
                &record,
                &recipient_address,
                &receiver_user_pubkey,
                &recipient_auth_pubkey,
                None,
                predecessor.as_ref(),
            )
            .await?;
            intent.intent_kind = Bip448TransferIntentKind::Cancellation;
            intent.generated_coin_user_pubkey = Some(generated_coin.user_pubkey.clone());
            intent.generated_coin_auth_pubkey = Some(generated_coin.auth_pubkey.clone());
            intent.generated_coin_address = Some(generated_coin.address.clone());
            let mut replacement_wallet = wallet;
            replacement_wallet.coins.push(generated_coin);
            let stored = match predecessor {
                Some(predecessor) => {
                    supersede_bip448_transfer_intent_with_cancellation_wallet(
                        &client_config.pool,
                        &predecessor.intent_id,
                        &intent,
                        &raw_wallet,
                        &replacement_wallet,
                    )
                    .await?
                }
                None => {
                    insert_bip448_cancellation_intent_with_wallet(
                        &client_config.pool,
                        &intent,
                        &raw_wallet,
                        &replacement_wallet,
                    )
                    .await?
                }
            };
            bip448_process_checkpoint("transfer_intent_prepared");
            stored
        }
    };

    if !matches!(
        cancellation.phase,
        Bip448TransferIntentPhase::SenderFinished | Bip448TransferIntentPhase::ReceiverAccepted
    ) {
        require_fresh_transfer_duplicate_safety(client_config, wallet_name, statechain_id).await?;
        cancellation = drive_bip448_transfer_intent(client_config, cancellation)
            .await?
            .ok_or_else(|| anyhow!("BIP448 cancellation sender deleted its intent"))?;
    }
    if cancellation.phase == Bip448TransferIntentPhase::SenderFinished {
        let received = match crate::transfer_receiver::execute(client_config, wallet_name).await {
            Ok(received) => received,
            Err(error)
                if error
                    .downcast_ref::<crate::transfer_receiver::Bip448PostAcceptanceSyncError>()
                    .is_some_and(|accepted| {
                        accepted
                            .accepted_statechain_ids()
                            .iter()
                            .any(|accepted_id| accepted_id == statechain_id)
                    }) =>
            {
                mark_bip448_cancellation_receiver_accepted(
                    &client_config.pool,
                    wallet_name,
                    statechain_id,
                    &cancellation.intent_id,
                )
                .await
                .context(
                    "BIP448 cancellation key update was accepted but its durable receiver proof failed",
                )?;
                if let Err(retry_error) =
                    crate::coin_status::update_coins(client_config, wallet_name).await
                {
                    return Err(retry_error
                        .context("BIP448 cancellation accepted; duplicate rescan pending"));
                }
                return Ok(
                    get_bip448_statechain(&client_config.pool, wallet_name, statechain_id)
                        .await?
                        .latest_state_number,
                );
            }
            Err(error) => return Err(error),
        };
        if received.is_there_batch_locked {
            return Err(anyhow!(BATCHED_PENDING_ERROR));
        }
        match get_active_bip448_transfer_intent(&client_config.pool, wallet_name, statechain_id)
            .await?
        {
            None => {
                return Ok(
                    get_bip448_statechain(&client_config.pool, wallet_name, statechain_id)
                        .await?
                        .latest_state_number,
                );
            }
            Some(live) => {
                if live.intent_id != cancellation.intent_id {
                    return Err(anyhow!(
                        "BIP448 cancellation receiver changed its active intent"
                    ));
                }
                cancellation = mark_bip448_cancellation_receiver_accepted(
                    &client_config.pool,
                    wallet_name,
                    statechain_id,
                    &cancellation.intent_id,
                )
                .await
                .map_err(|error| {
                    if received
                        .received_statechain_ids
                        .iter()
                        .any(|id| id == statechain_id)
                    {
                        error
                            .context("BIP448 cancellation receiver accepted but local proof failed")
                    } else {
                        error.context(
                            "BIP448 transfer cancellation did not receive the replacement state",
                        )
                    }
                })?;
                bip448_process_checkpoint("transfer_receiver_accepted");
            }
        }
    }
    if cancellation.phase != Bip448TransferIntentPhase::ReceiverAccepted {
        return Err(anyhow!(
            "BIP448 cancellation did not reach ReceiverAccepted"
        ));
    }
    crate::coin_status::update_coins(client_config, wallet_name)
        .await
        .context("BIP448 cancellation accepted; duplicate rescan pending")?;
    Ok(
        get_bip448_statechain(&client_config.pool, wallet_name, statechain_id)
            .await?
            .latest_state_number,
    )
}
async fn finish_transfer(
    client_config: &ClientConfig,
    wallet: &mut Wallet,
    coin_index: usize,
) -> Result<()> {
    wallet
        .coins
        .get_mut(coin_index)
        .ok_or_else(|| {
            anyhow!("selected BIP448 transfer owner index is absent from its wallet snapshot")
        })?
        .status = CoinStatus::IN_TRANSFER;
    update_wallet(&client_config.pool, wallet).await
}
fn musig_secret_nonce(value: &str) -> Result<MusigSecNonce> {
    let bytes: [u8; 132] = hex::decode(value)?
        .try_into()
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
            .map(|plan| {
                mutated.set(plan.clear_local_attempt);
                plan
            })
            .unwrap_err();
        assert_eq!(error.to_string(), SIGNATURE_COUNT_ERROR);
        assert!(!mutated.get());
        assert_eq!(
            transfer_state_plan(4, 3, false, false, None)
                .unwrap_err()
                .to_string(),
            SIGNATURE_COUNT_ERROR
        );
        assert_eq!(
            transfer_state_plan(3, 3, true, true, None).unwrap(),
            TransferStatePlan {
                state_number: 4,
                reuse_pending: true,
                reuse_signed_state: false,
                clear_local_attempt: false
            }
        );
        assert_eq!(
            transfer_state_plan(4, 3, false, true, None)
                .unwrap()
                .state_number,
            5
        );
        assert!(ensure_local_eligibility(2, &CoinStatus::CONFIRMED).is_ok());
        assert!(ensure_local_eligibility(2, &CoinStatus::IN_TRANSFER).is_ok());
    }

    #[test]
    fn selected_owner_status_gate_accepts_confirmed_and_in_transfer() {
        assert!(ensure_local_eligibility(2, &CoinStatus::CONFIRMED).is_ok());
        assert!(ensure_local_eligibility(2, &CoinStatus::IN_TRANSFER).is_ok());
        assert!(ensure_local_eligibility(2, &CoinStatus::INITIALISED).is_err());
    }

    #[test]
    fn batched_pending_attempt_stops_retargeting() {
        assert_eq!(
            transfer_state_plan(3, 3, false, true, Some("batch"))
                .unwrap_err()
                .to_string(),
            BATCHED_PENDING_ERROR
        );
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
        assert_eq!(error.to_string(), "completion evidence unavailable");
    }

    #[tokio::test]
    async fn rotated_persisted_transfer_runs_only_local_cleanup() {
        let deliveries = Cell::new(0);
        let cleanups = Cell::new(0);
        resume_persisted_transfer(
            Bip448OwnerRelation::Rotated,
            || {
                deliveries.set(deliveries.get() + 1);
                std::future::ready(Err(anyhow!("delivery must not run")))
            },
            || {
                cleanups.set(cleanups.get() + 1);
                std::future::ready(Ok(()))
            },
        )
        .await
        .unwrap();
        assert_eq!(deliveries.get(), 0);
        assert_eq!(cleanups.get(), 1);
    }
}
