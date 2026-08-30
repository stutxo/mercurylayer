use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use bitcoin::{
    absolute,
    hashes::{sha256, Hash},
    Address, OutPoint, PrivateKey, Txid,
};
use mercurylib::{
    bip448_statechain::{
        deposit::{
            self as bip448_deposit, BIP448_COIN_PROTOCOL, DEFAULT_BIP448_CHALLENGE_DELAY,
            INITIAL_BIP448_STATE_NUMBER,
        },
        script,
        signing::{CsfsSigningRole, CsfsSigningSession},
        storage::{
            build_funding_latest_state, build_funding_recovery_artifacts, Bip448FeeBumpPolicy,
            Bip448LatestState, Bip448RecoveryTemplateRole, Bip448StatechainRecord,
        },
    },
    transfer::bip448::{
        Bip448StateHistoryEntry, Bip448TransferMsg, BIP448_TRANSFER_MESSAGE_VERSION,
    },
    wallet::{Activity, Coin, CoinStatus, Wallet},
};
use secp256k1::{
    musig::{BlindingFactor, PublicNonce, SecretNonce as MusigSecNonce},
    schnorr, PublicKey, Secp256k1, XOnlyPublicKey,
};
use sqlx::{Pool, Row, Sqlite, SqliteConnection};

use crate::bip448_funding::{
    self, Bip448TransferIntent, Bip448TransferIntentActivityStatus, Bip448TransferIntentPhase,
    Bip448TransferStateSigningPhase,
};

use super::super::{
    canonical_txid, canonical_wallet_json, pending_transfer_on,
    transfer_message_matches_history_prefix, validate_bip448_transfer_intent_lineage,
};
use super::{
    accepted::{validated_bip448_record_json, Bip448PendingDepositSigning},
    guard::begin_bip448_mutation_guard,
    rows::list_bip448_transfer_intents_on,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Bip448InitialAcceptanceRecovery {
    Unchanged,
    Recovered,
    WalletChanged,
}
pub(in crate::sqlite_manager) fn history_entry_matches_latest_state(
    entry: &Bip448StateHistoryEntry,
    state: &Bip448LatestState,
) -> bool {
    entry.state_number == state.state_number
        && entry.state_locktime == state.state_locktime
        && entry.update_template_hash == state.update_template_hash
        && entry.settlement_template_hash == state.settlement_template_hash
        && entry.update_signature == state.signing_metadata.update_signature
        && entry.client_public_nonce == state.signing_metadata.client_public_nonce
        && entry.server_public_nonce == state.signing_metadata.server_public_nonce
        && entry.blinding_factor == state.signing_metadata.blinding_factor
}

fn validate_bip448_history_entry(entry: &Bip448StateHistoryEntry) -> Result<()> {
    if entry.state_number == 0 {
        return Err(anyhow!("BIP448 history state number must be positive"));
    }
    let state_locktime = absolute::LockTime::from_consensus(entry.state_locktime);
    if entry.state_number == INITIAL_BIP448_STATE_NUMBER {
        script::validate_initial_state_locktime(state_locktime)?;
    } else {
        script::validate_state_locktime(state_locktime)?;
    }
    bip448_funding::require_canonical_xonly_public_key(&entry.owner_public_key)?;
    bip448_funding::require_canonical_hex(&entry.update_template_hash, Some(32))?;
    bip448_funding::require_canonical_hex(&entry.settlement_template_hash, Some(32))?;
    bip448_funding::require_canonical_hex(&entry.update_signature, Some(64))?;
    bip448_funding::require_canonical_hex(&entry.client_public_nonce, Some(66))?;
    bip448_funding::require_canonical_hex(&entry.server_public_nonce, Some(66))?;
    bip448_funding::require_canonical_hex(&entry.blinding_factor, Some(32))?;
    Ok(())
}

fn validate_bip448_accepted_artifacts(
    record: &Bip448StatechainRecord,
    history: &[Bip448StateHistoryEntry],
) -> Result<()> {
    if record.wallet_name.is_empty()
        || record.statechain_id.is_empty()
        || record.latest_state_number == 0
        || record.latest_state_number != record.latest_state.state_number
        || record.challenge_delay != DEFAULT_BIP448_CHALLENGE_DELAY
        || record.latest_state.challenge_delay != record.challenge_delay
        || record.amount_sats != record.funding_outpoint.value_sats
        || record.latest_state.signing_metadata.server_signature_count
            != u64::from(record.latest_state_number)
        || record.latest_state.signing_metadata.role != Bip448RecoveryTemplateRole::FundingUpdate
        || record.latest_state.fee_bump_policy != Bip448FeeBumpPolicy::ZeroFeeEphemeralAnchor
        || !record.latest_state.cpfp_child_templates.is_empty()
    {
        return Err(anyhow!(
            "BIP448 accepted record has incoherent state, count, or recovery policy"
        ));
    }
    if canonical_txid(&record.funding_outpoint.txid)? != record.funding_outpoint.txid {
        return Err(anyhow!("BIP448 accepted funding txid is not canonical"));
    }
    let network = mercurylib::utils::get_network(&record.network)
        .context("invalid BIP448 accepted network")?;
    let aggregate_pubkey = PublicKey::from_str(&record.aggregate_pubkey)
        .context("invalid BIP448 accepted aggregate public key")?;
    if aggregate_pubkey.to_string() != record.aggregate_pubkey {
        return Err(anyhow!(
            "BIP448 accepted aggregate public key is not canonical"
        ));
    }
    bip448_funding::require_canonical_hex(
        &record.latest_state.signing_metadata.signing_id,
        Some(32),
    )?;
    let accepted_len = usize::try_from(record.latest_state_number)?;
    if history.len() < accepted_len {
        return Err(anyhow!("BIP448 accepted history prefix is incomplete"));
    }

    let secp = Secp256k1::new();
    let funding_outpoint = OutPoint {
        txid: Txid::from_str(&record.funding_outpoint.txid)?,
        vout: record.funding_outpoint.vout,
    };
    for (index, entry) in history.iter().enumerate() {
        validate_bip448_history_entry(entry)?;
        let expected_state_number = u32::try_from(index)?
            .checked_add(1)
            .ok_or_else(|| anyhow!("BIP448 history state number overflows"))?;
        if entry.state_number != expected_state_number {
            return Err(anyhow!("BIP448 accepted history is not contiguous"));
        }
        let owner = XOnlyPublicKey::from_str(&entry.owner_public_key)?;
        let recovery_script = Address::p2tr(&secp, owner, None, network).script_pubkey();
        let artifacts = build_funding_recovery_artifacts(
            &secp,
            &aggregate_pubkey,
            funding_outpoint,
            record.funding_outpoint.value_sats,
            recovery_script,
            entry.state_number,
            absolute::LockTime::from_consensus(entry.state_locktime),
            record.challenge_delay,
            Bip448FeeBumpPolicy::ZeroFeeEphemeralAnchor,
        )
        .context("invalid BIP448 accepted recovery templates")?;
        if entry.update_template_hash != hex::encode(artifacts.update_template_hash.to_byte_array())
            || entry.settlement_template_hash
                != hex::encode(artifacts.settlement_template_hash.to_byte_array())
        {
            return Err(anyhow!(
                "BIP448 accepted history hashes do not match reconstructed templates"
            ));
        }
        let update_signature = schnorr::Signature::from_str(&entry.update_signature)
            .context("invalid BIP448 accepted update signature")?;
        schnorr::verify(
            &update_signature,
            artifacts.update_template_hash.as_byte_array(),
            &aggregate_pubkey.x_only_public_key().0,
        )
        .context("BIP448 accepted update signature does not verify")?;
        let client_nonce = PublicNonce::from_slice(&hex::decode(&entry.client_public_nonce)?)
            .context("invalid BIP448 accepted client public nonce")?;
        let server_nonce = PublicNonce::from_slice(&hex::decode(&entry.server_public_nonce)?)
            .context("invalid BIP448 accepted server public nonce")?;
        let blinding_factor = BlindingFactor::from_slice(&hex::decode(&entry.blinding_factor)?)
            .context("invalid BIP448 accepted blinding factor")?;
        CsfsSigningSession::new(
            &secp,
            CsfsSigningRole::FundingUpdate,
            aggregate_pubkey,
            &client_nonce,
            &server_nonce,
            artifacts.update_template_hash,
            &blinding_factor,
        )
        .context("invalid BIP448 accepted blinded signing session")?;
    }
    for pair in history.windows(2) {
        let stride = pair[1]
            .state_locktime
            .checked_sub(pair[0].state_locktime)
            .ok_or_else(|| anyhow!("BIP448 accepted state locktime regressed"))?;
        let next = script::checked_next_state_locktime(
            absolute::LockTime::from_consensus(pair[0].state_locktime),
            stride,
        )?;
        if next.to_consensus_u32() != pair[1].state_locktime {
            return Err(anyhow!("BIP448 accepted state locktime stride is invalid"));
        }
    }

    let accepted_entry = history
        .get(
            accepted_len
                .checked_sub(1)
                .ok_or_else(|| anyhow!("BIP448 accepted state number must be positive"))?,
        )
        .ok_or_else(|| anyhow!("BIP448 accepted history prefix is missing"))?;
    if !history_entry_matches_latest_state(accepted_entry, &record.latest_state) {
        return Err(anyhow!(
            "BIP448 accepted history prefix does not match the accepted record"
        ));
    }
    let accepted_owner = XOnlyPublicKey::from_str(&accepted_entry.owner_public_key)?;
    let accepted_recovery_script =
        Address::p2tr(&secp, accepted_owner, None, network).script_pubkey();
    let accepted_artifacts = build_funding_recovery_artifacts(
        &secp,
        &aggregate_pubkey,
        funding_outpoint,
        record.funding_outpoint.value_sats,
        accepted_recovery_script,
        record.latest_state_number,
        absolute::LockTime::from_consensus(record.latest_state.state_locktime),
        record.challenge_delay,
        Bip448FeeBumpPolicy::ZeroFeeEphemeralAnchor,
    )?;
    let canonical_latest = build_funding_latest_state(
        &secp,
        &aggregate_pubkey,
        &accepted_artifacts,
        record.latest_state.signing_metadata.clone(),
        Vec::new(),
    )?;
    if canonical_latest != record.latest_state {
        return Err(anyhow!(
            "BIP448 accepted latest state is not the canonical reconstructed state"
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(in crate::sqlite_manager) enum Bip448WalletCoinRequirement {
    InitialAcceptance,
    MaterializedInitialAcceptance,
    ConfirmedCanonicalAttempt,
    PersistedTransferSender,
    PassiveBindingSync,
}

fn validate_passive_bip448_withdrawal_lifecycle_coin(
    coin: &Coin,
    record: &Bip448StatechainRecord,
) -> Result<()> {
    if !matches!(coin.status, CoinStatus::WITHDRAWING | CoinStatus::WITHDRAWN)
        || coin.locktime != Some(record.latest_state.state_locktime)
    {
        return Err(anyhow!(
            "passive BIP448 binding sync withdrawal lifecycle does not match the accepted state"
        ));
    }

    let withdrawal_txid = coin
        .tx_withdraw
        .as_deref()
        .ok_or_else(|| anyhow!("passive BIP448 withdrawal Coin is missing its transaction"))?;
    if canonical_txid(withdrawal_txid)? != withdrawal_txid {
        return Err(anyhow!(
            "passive BIP448 withdrawal transaction is not canonical"
        ));
    }
    let withdrawal_address = coin
        .withdrawal_address
        .as_deref()
        .ok_or_else(|| anyhow!("passive BIP448 withdrawal Coin is missing its address"))?;
    if !mercurylib::validate_address(withdrawal_address, &record.network)? {
        return Err(anyhow!("passive BIP448 withdrawal address is invalid"));
    }
    if withdrawal_address.starts_with("ml") || withdrawal_address.starts_with("tml") {
        let (version, user, auth) =
            std::panic::catch_unwind(|| mercurylib::decode_transfer_address(withdrawal_address))
                .map_err(|_| anyhow!("invalid passive BIP448 withdrawal transfer address"))??;
        let canonical = mercurylib::encode_sc_address(
            &user,
            &auth,
            mercurylib::utils::get_network(&record.network)?,
        )?;
        if version != 0 || canonical != withdrawal_address {
            return Err(anyhow!(
                "passive BIP448 withdrawal transfer address is not canonical"
            ));
        }
    } else {
        let canonical_address = Address::from_str(withdrawal_address)?
            .require_network(mercurylib::utils::get_network(&record.network)?)?;
        if canonical_address.to_string() != withdrawal_address {
            return Err(anyhow!(
                "passive BIP448 withdrawal address is not canonical"
            ));
        }
    }

    let secret_nonce = coin
        .secret_nonce
        .as_deref()
        .ok_or_else(|| anyhow!("passive BIP448 withdrawal Coin is missing its secret nonce"))?;
    bip448_funding::require_canonical_hex(secret_nonce, Some(132))?;
    let secret_nonce_bytes: [u8; 132] = hex::decode(secret_nonce)?
        .try_into()
        .map_err(|_| anyhow!("passive BIP448 withdrawal secret nonce has invalid length"))?;
    let _secret_nonce = MusigSecNonce::from_slice(secret_nonce_bytes);

    for (field, value) in [
        ("client", coin.public_nonce.as_deref()),
        ("server", coin.server_public_nonce.as_deref()),
    ] {
        let value = value.ok_or_else(|| {
            anyhow!("passive BIP448 withdrawal Coin is missing its {field} public nonce")
        })?;
        bip448_funding::require_canonical_hex(value, Some(66))?;
        let public_nonce = PublicNonce::from_str(value)
            .with_context(|| format!("invalid passive BIP448 withdrawal {field} public nonce"))?;
        if hex::encode(public_nonce.serialize()) != value {
            return Err(anyhow!(
                "passive BIP448 withdrawal {field} public nonce is not canonical"
            ));
        }
    }

    let blinding_factor = coin
        .blinding_factor
        .as_deref()
        .ok_or_else(|| anyhow!("passive BIP448 withdrawal Coin is missing its blinding factor"))?;
    bip448_funding::require_canonical_hex(blinding_factor, Some(32))?;
    BlindingFactor::from_slice(&hex::decode(blinding_factor)?)
        .context("invalid passive BIP448 withdrawal blinding factor")?;
    Ok(())
}

pub(in crate::sqlite_manager) fn validate_selected_bip448_coin(
    coin: &Coin,
    record: &Bip448StatechainRecord,
    accepted_owner: XOnlyPublicKey,
    requirement: Bip448WalletCoinRequirement,
) -> Result<()> {
    if coin.statechain_id.as_deref() != Some(record.statechain_id.as_str())
        || coin.statechain_protocol.as_deref() != Some(BIP448_COIN_PROTOCOL)
    {
        return Err(anyhow!(
            "selected BIP448 Coin does not match the accepted protocol identity"
        ));
    }
    let user_pubkey = PublicKey::from_str(&coin.user_pubkey)
        .context("invalid selected BIP448 Coin user public key")?;
    if user_pubkey.to_string() != coin.user_pubkey
        || user_pubkey.x_only_public_key().0 != accepted_owner
    {
        return Err(anyhow!(
            "selected BIP448 Coin does not match the accepted owner"
        ));
    }
    let server_text = coin
        .server_pubkey
        .as_deref()
        .ok_or_else(|| anyhow!("selected BIP448 Coin is missing its server public key"))?;
    let server_pubkey = PublicKey::from_str(server_text)
        .context("invalid selected BIP448 Coin server public key")?;
    if server_pubkey.to_string() != server_text
        || user_pubkey.combine(&server_pubkey)? != PublicKey::from_str(&record.aggregate_pubkey)?
        || coin.aggregated_pubkey.as_deref() != Some(record.aggregate_pubkey.as_str())
    {
        return Err(anyhow!(
            "selected BIP448 Coin does not match the accepted aggregate key"
        ));
    }

    let user_private = PrivateKey::from_wif(&coin.user_privkey)
        .context("invalid selected BIP448 Coin user private key")?;
    if user_private.inner.public_key(&Secp256k1::new()) != user_pubkey {
        return Err(anyhow!(
            "selected BIP448 Coin user private key does not match its public key"
        ));
    }
    crate::bip448_owner::validate_bip448_coin_local_auth(coin, &record.statechain_id)?;
    let (address_version, address_user, address_auth) =
        std::panic::catch_unwind(|| mercurylib::decode_transfer_address(&coin.address))
            .map_err(|_| anyhow!("invalid selected BIP448 Coin transfer address"))??;
    if address_version != 0
        || address_user != user_pubkey
        || address_auth.to_string() != coin.auth_pubkey
    {
        return Err(anyhow!(
            "selected BIP448 Coin transfer address does not match its local keys"
        ));
    }
    let deposit_address = bip448_deposit::create_deposit_address(coin, &record.network)
        .context("invalid selected BIP448 Coin funding or recovery address")?;
    if deposit_address.aggregate_pubkey != record.aggregate_pubkey
        || coin.aggregated_address.as_deref() != Some(deposit_address.address.as_str())
        || coin.amount.map(u64::from) != Some(record.amount_sats)
    {
        return Err(anyhow!(
            "selected BIP448 Coin does not match the accepted funding/state facts"
        ));
    }
    let exact_outpoint = coin.utxo_txid.as_deref() == Some(record.funding_outpoint.txid.as_str())
        && coin.utxo_vout == Some(record.funding_outpoint.vout);
    let absent_outpoint = coin.utxo_txid.is_none() && coin.utxo_vout.is_none();
    let signing = &record.latest_state.signing_metadata;
    let exact_signing_facts = coin.locktime == Some(record.latest_state.state_locktime)
        && coin.public_nonce.as_deref() == Some(signing.client_public_nonce.as_str())
        && coin.server_public_nonce.as_deref() == Some(signing.server_public_nonce.as_str())
        && coin.blinding_factor.as_deref() == Some(signing.blinding_factor.as_str());
    let absent_signing_facts = coin.locktime.is_none()
        && coin.public_nonce.is_none()
        && coin.server_public_nonce.is_none()
        && coin.blinding_factor.is_none();
    match requirement {
        Bip448WalletCoinRequirement::InitialAcceptance => {
            if record.latest_state_number != INITIAL_BIP448_STATE_NUMBER
                || !(exact_outpoint || absent_outpoint)
                || !(exact_signing_facts || absent_signing_facts)
                || (absent_outpoint && coin.status != CoinStatus::INITIALISED)
                || (exact_outpoint
                    && !matches!(
                        coin.status,
                        CoinStatus::IN_MEMPOOL | CoinStatus::UNCONFIRMED | CoinStatus::CONFIRMED
                    ))
            {
                return Err(anyhow!(
                    "initial BIP448 acceptance requires an exact pre- or post-acceptance state-1 Coin"
                ));
            }
        }
        Bip448WalletCoinRequirement::MaterializedInitialAcceptance => {
            if record.latest_state_number != INITIAL_BIP448_STATE_NUMBER
                || !exact_outpoint
                || !exact_signing_facts
                || !matches!(
                    coin.status,
                    CoinStatus::IN_MEMPOOL | CoinStatus::UNCONFIRMED | CoinStatus::CONFIRMED
                )
            {
                return Err(anyhow!(
                    "materialized BIP448 initial acceptance requires an exact funded state-1 Coin"
                ));
            }
        }
        Bip448WalletCoinRequirement::ConfirmedCanonicalAttempt => {
            if !exact_outpoint
                || !exact_signing_facts
                || coin.status != CoinStatus::CONFIRMED
                || coin.tx_withdraw.is_some()
                || coin.withdrawal_address.is_some()
            {
                return Err(anyhow!(
                    "canonical BIP448 attempt requires exactly one CONFIRMED Coin"
                ));
            }
        }
        Bip448WalletCoinRequirement::PersistedTransferSender => {
            if !exact_outpoint
                || !exact_signing_facts
                || !matches!(coin.status, CoinStatus::CONFIRMED | CoinStatus::IN_TRANSFER)
                || coin.tx_withdraw.is_some()
                || coin.withdrawal_address.is_some()
            {
                return Err(anyhow!(
                    "persisted BIP448 transfer requires one exact sender-generation Coin"
                ));
            }
        }
        Bip448WalletCoinRequirement::PassiveBindingSync => {
            if !exact_outpoint {
                return Err(anyhow!(
                    "passive BIP448 binding sync requires one exact current-generation Coin"
                ));
            }
            match &coin.status {
                CoinStatus::IN_MEMPOOL
                | CoinStatus::UNCONFIRMED
                | CoinStatus::CONFIRMED
                | CoinStatus::IN_TRANSFER
                | CoinStatus::TRANSFERRED
                    if exact_signing_facts
                        && coin.tx_withdraw.is_none()
                        && coin.withdrawal_address.is_none() => {}
                CoinStatus::WITHDRAWING | CoinStatus::WITHDRAWN => {
                    validate_passive_bip448_withdrawal_lifecycle_coin(coin, record)?;
                }
                _ => {
                    return Err(anyhow!(
                        "passive BIP448 binding sync requires one exact current-generation Coin"
                    ));
                }
            }
        }
    }
    Ok(())
}

async fn validate_initial_acceptance_pending_signing_on(
    connection: &mut SqliteConnection,
    record: &Bip448StatechainRecord,
    entry: &Bip448StateHistoryEntry,
) -> Result<Option<String>> {
    let row = sqlx::query(
        "SELECT funding_txid, funding_vout, funding_value_sats, update_template_hash, \
         settlement_template_hash, state_locktime, signing_id, client_secret_nonce, \
         client_public_nonce, blinding_factor, server_public_nonce \
         FROM bip448_pending_deposit_signings \
         WHERE wallet_name = $1 AND statechain_id = $2",
    )
    .bind(&record.wallet_name)
    .bind(&record.statechain_id)
    .fetch_optional(&mut *connection)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };

    let funding_txid = row
        .try_get::<Option<String>, _>(0)?
        .ok_or_else(|| anyhow!("BIP448 pending signing funding outpoint is missing"))?;
    let funding_vout = u32::try_from(
        row.try_get::<Option<i64>, _>(1)?
            .ok_or_else(|| anyhow!("BIP448 pending signing funding outpoint is missing"))?,
    )?;
    let funding_value_sats = u64::try_from(
        row.try_get::<Option<i64>, _>(2)?
            .ok_or_else(|| anyhow!("BIP448 pending signing funding value is missing"))?,
    )?;
    let update_template_hash: String = row.try_get(3)?;
    let settlement_template_hash = row
        .try_get::<Option<String>, _>(4)?
        .ok_or_else(|| anyhow!("BIP448 pending signing settlement hash is missing"))?;
    let state_locktime = u32::try_from(
        row.try_get::<Option<i64>, _>(5)?
            .ok_or_else(|| anyhow!("BIP448 pending signing locktime is missing"))?,
    )?;
    let signing_id: String = row.try_get(6)?;
    let client_secret_nonce: String = row.try_get(7)?;
    let client_public_nonce: String = row.try_get(8)?;
    let blinding_factor: String = row.try_get(9)?;
    let server_public_nonce = row
        .try_get::<Option<String>, _>(10)?
        .ok_or_else(|| anyhow!("BIP448 pending signing server nonce is missing"))?;

    bip448_funding::require_canonical_hex(&update_template_hash, Some(32))?;
    bip448_funding::require_canonical_hex(&settlement_template_hash, Some(32))?;
    bip448_funding::require_canonical_hex(&signing_id, Some(32))?;
    bip448_funding::require_canonical_hex(&client_secret_nonce, Some(132))?;
    bip448_funding::require_canonical_hex(&client_public_nonce, Some(66))?;
    bip448_funding::require_canonical_hex(&blinding_factor, Some(32))?;
    bip448_funding::require_canonical_hex(&server_public_nonce, Some(66))?;

    let signing = &record.latest_state.signing_metadata;
    if canonical_txid(&funding_txid)? != record.funding_outpoint.txid
        || funding_vout != record.funding_outpoint.vout
        || funding_value_sats != record.funding_outpoint.value_sats
        || update_template_hash != entry.update_template_hash
        || settlement_template_hash != entry.settlement_template_hash
        || state_locktime != entry.state_locktime
        || signing_id != signing.signing_id
        || client_public_nonce != entry.client_public_nonce
        || server_public_nonce != entry.server_public_nonce
        || blinding_factor != entry.blinding_factor
    {
        return Err(anyhow!(
            "fresh BIP448 initial acceptance does not match its pending signing row"
        ));
    }
    Ok(Some(signing_id))
}

async fn require_initial_acceptance_pending_signing_on(
    connection: &mut SqliteConnection,
    record: &Bip448StatechainRecord,
    entry: &Bip448StateHistoryEntry,
) -> Result<()> {
    if validate_initial_acceptance_pending_signing_on(connection, record, entry)
        .await?
        .is_none()
    {
        require_selected_bip448_wallet_coin_on(
            &mut *connection,
            record,
            XOnlyPublicKey::from_str(&entry.owner_public_key)?,
            Bip448WalletCoinRequirement::MaterializedInitialAcceptance,
        )
        .await?;
    }
    Ok(())
}

fn require_canonical_bip448_wallet(
    raw_wallet: &str,
    wallet_name: &str,
    network: &str,
) -> Result<Wallet> {
    let wallet: Wallet = serde_json::from_str(&raw_wallet)?;
    if wallet.name != wallet_name
        || wallet.network != network
        || wallet.settings.network != network
        || canonical_wallet_json(&wallet)? != raw_wallet
    {
        return Err(anyhow!(
            "BIP448 accepted wallet identity or canonical bytes are invalid"
        ));
    }
    Ok(wallet)
}

fn selected_bip448_wallet_coin_index(
    wallet: &Wallet,
    record: &Bip448StatechainRecord,
    accepted_owner: XOnlyPublicKey,
) -> Result<usize> {
    let mut matching_owner_coins = Vec::new();
    for (index, coin) in wallet.coins.iter().enumerate() {
        if coin.statechain_id.as_deref() != Some(record.statechain_id.as_str())
            || coin.statechain_protocol.as_deref() != Some(BIP448_COIN_PROTOCOL)
        {
            continue;
        }
        let user_pubkey = PublicKey::from_str(&coin.user_pubkey)
            .context("invalid current-statechain BIP448 Coin user public key")?;
        if user_pubkey.to_string() != coin.user_pubkey {
            return Err(anyhow!(
                "current-statechain BIP448 Coin user public key is not canonical"
            ));
        }
        if user_pubkey.x_only_public_key().0 == accepted_owner {
            matching_owner_coins.push((index, coin));
        }
    }
    match matching_owner_coins.as_slice() {
        [(index, _)] => Ok(*index),
        [] => Err(anyhow!(
            "no wallet Coin exactly matches the accepted BIP448 owner and binding"
        )),
        _ => Err(anyhow!(
            "multiple wallet Coins match the accepted BIP448 owner and binding"
        )),
    }
}

fn require_selected_bip448_wallet_coin(
    wallet: &Wallet,
    record: &Bip448StatechainRecord,
    accepted_owner: XOnlyPublicKey,
    requirement: Bip448WalletCoinRequirement,
) -> Result<usize> {
    let index = selected_bip448_wallet_coin_index(wallet, record, accepted_owner)?;
    validate_selected_bip448_coin(&wallet.coins[index], record, accepted_owner, requirement)?;
    Ok(index)
}

pub(in crate::sqlite_manager) async fn require_selected_bip448_wallet_coin_on(
    connection: &mut SqliteConnection,
    record: &Bip448StatechainRecord,
    accepted_owner: XOnlyPublicKey,
    requirement: Bip448WalletCoinRequirement,
) -> Result<()> {
    let raw_wallet =
        sqlx::query_scalar::<_, String>("SELECT wallet_json FROM wallet WHERE wallet_name = $1")
            .bind(&record.wallet_name)
            .fetch_optional(&mut *connection)
            .await?
            .ok_or_else(|| anyhow!("BIP448 accepted wallet is missing"))?;
    let wallet =
        require_canonical_bip448_wallet(&raw_wallet, &record.wallet_name, &record.network)?;
    require_selected_bip448_wallet_coin(&wallet, record, accepted_owner, requirement).map(|_| ())
}

pub(in crate::sqlite_manager) fn history_entry_matches_pending_intent(
    entry: &Bip448StateHistoryEntry,
    pending: &Bip448PendingDepositSigning,
    intent: &Bip448TransferIntent,
) -> Result<bool> {
    let receiver_owner = secp256k1::PublicKey::from_str(&intent.receiver_user_pubkey)
        .context("invalid BIP448 intent receiver user key")?
        .x_only_public_key()
        .0
        .to_string();
    Ok(entry.state_number == intent.planned_state_number
        && entry.owner_public_key == receiver_owner
        && entry.update_template_hash == pending.update_template_hash
        && entry.settlement_template_hash == pending.settlement_template_hash
        && entry.state_locktime == pending.state_locktime
        && entry.client_public_nonce == pending.client_public_nonce
        && pending.server_public_nonce.as_deref() == Some(entry.server_public_nonce.as_str())
        && entry.blinding_factor == pending.blinding_factor
        && intent.update_signature.as_deref() == Some(entry.update_signature.as_str()))
}

pub(in crate::sqlite_manager) fn transfer_message_matches_record_and_history(
    message: &Bip448TransferMsg,
    record: &Bip448StatechainRecord,
    history: &[Bip448StateHistoryEntry],
) -> Result<bool> {
    let receiver_owner = secp256k1::PublicKey::from_str(&message.receiver_user_public_key)
        .context("invalid BIP448 transfer-message receiver user key")?
        .x_only_public_key()
        .0
        .to_string();
    Ok(message.msg_version == BIP448_TRANSFER_MESSAGE_VERSION
        && message.statechain_id == record.statechain_id
        && message.aggregate_pubkey == record.aggregate_pubkey
        && message.funding_outpoint == record.funding_outpoint
        && message.challenge_delay == record.challenge_delay
        && message.amount_sats == record.amount_sats
        && message.network == record.network
        && message
            .state_history
            .last()
            .is_some_and(|entry| entry.owner_public_key == receiver_owner)
        && transfer_message_matches_history_prefix(message, history)?)
}

pub async fn persist_bip448_initial_acceptance(
    pool: &Pool<Sqlite>,
    record: &Bip448StatechainRecord,
    entry: &Bip448StateHistoryEntry,
) -> Result<()> {
    let mut record = record.clone();
    record.funding_outpoint.txid = canonical_txid(&record.funding_outpoint.txid)?;
    let record_json = validated_bip448_record_json(&record)?;
    let entry_json = serde_json::to_string(entry)?;
    let mut transaction = pool.begin_with("BEGIN IMMEDIATE").await?;
    validate_bip448_accepted_artifacts(&record, std::slice::from_ref(entry))?;
    let owner = XOnlyPublicKey::from_str(&entry.owner_public_key)?;
    require_selected_bip448_wallet_coin_on(
        &mut *transaction,
        &record,
        owner,
        Bip448WalletCoinRequirement::InitialAcceptance,
    )
    .await?;

    let stored_record = sqlx::query_scalar::<_, String>(
        "SELECT record_json FROM bip448_statechains \
         WHERE wallet_name = $1 AND statechain_id = $2",
    )
    .bind(&record.wallet_name)
    .bind(&record.statechain_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let stored_entry = sqlx::query_scalar::<_, String>(
        "SELECT entry_json FROM bip448_state_history \
         WHERE wallet_name = $1 AND statechain_id = $2 AND state_number = 1",
    )
    .bind(&record.wallet_name)
    .bind(&record.statechain_id)
    .fetch_optional(&mut *transaction)
    .await?;

    match (&stored_record, &stored_entry) {
        (Some(stored), Some(stored_entry))
            if stored == &record_json && stored_entry == &entry_json =>
        {
            transaction.commit().await?;
            return Ok(());
        }
        (Some(stored), _) if stored != &record_json => {
            return Err(anyhow!(
                "BIP448 initial accepted record conflicts with storage"
            ));
        }
        (_, Some(stored)) if stored != &entry_json => {
            return Err(anyhow!(
                "BIP448 initial state history conflicts with storage"
            ));
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err(anyhow!(
                "BIP448 initial acceptance has a partial record/history pair"
            ));
        }
        (None, None) => {
            require_initial_acceptance_pending_signing_on(&mut *transaction, &record, entry)
                .await?;
            let result = sqlx::query(
                "INSERT INTO bip448_statechains (\
                    wallet_name, statechain_id, aggregate_pubkey, funding_txid, funding_vout, \
                    funding_value_sats, latest_state_number, challenge_delay, amount_sats, network, \
                    record_json\
                 ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
            )
            .bind(&record.wallet_name)
            .bind(&record.statechain_id)
            .bind(&record.aggregate_pubkey)
            .bind(&record.funding_outpoint.txid)
            .bind(i64::from(record.funding_outpoint.vout))
            .bind(i64::try_from(record.funding_outpoint.value_sats)?)
            .bind(i64::from(record.latest_state_number))
            .bind(i64::from(record.challenge_delay))
            .bind(i64::try_from(record.amount_sats)?)
            .bind(&record.network)
            .bind(&record_json)
            .execute(&mut *transaction)
            .await?;
            if result.rows_affected() != 1 {
                return Err(anyhow!(
                    "BIP448 initial accepted record insert affected an unexpected row count"
                ));
            }
            let result = sqlx::query(
                "INSERT INTO bip448_state_history \
                    (wallet_name, statechain_id, state_number, entry_json) \
                 VALUES ($1,$2,1,$3)",
            )
            .bind(&record.wallet_name)
            .bind(&record.statechain_id)
            .bind(&entry_json)
            .execute(&mut *transaction)
            .await?;
            if result.rows_affected() != 1 {
                return Err(anyhow!(
                    "BIP448 initial history insert affected an unexpected row count"
                ));
            }
        }
        (Some(_), Some(_)) => {
            return Err(anyhow!(
                "BIP448 initial acceptance pair failed exact replay validation"
            ));
        }
    }
    transaction.commit().await?;
    Ok(())
}

pub(in crate::sqlite_manager) async fn accepted_record_and_history_on(
    connection: &mut SqliteConnection,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<(Bip448StatechainRecord, Vec<Bip448StateHistoryEntry>)> {
    let record_row = sqlx::query(
        "SELECT aggregate_pubkey, funding_txid, funding_vout, funding_value_sats, \
         latest_state_number, challenge_delay, amount_sats, network, record_json \
         FROM bip448_statechains \
         WHERE wallet_name = $1 AND statechain_id = $2",
    )
    .bind(wallet_name)
    .bind(statechain_id)
    .fetch_optional(&mut *connection)
    .await?
    .ok_or_else(|| anyhow!("BIP448 accepted record is missing"))?;
    let record_json: String = record_row.try_get(8)?;
    let record: Bip448StatechainRecord = serde_json::from_str(&record_json)?;
    if serde_json::to_string(&record)? != record_json
        || record.wallet_name != wallet_name
        || record.statechain_id != statechain_id
        || record.aggregate_pubkey != record_row.try_get::<String, _>(0)?
        || record.funding_outpoint.txid != record_row.try_get::<String, _>(1)?
        || record.funding_outpoint.vout != u32::try_from(record_row.try_get::<i64, _>(2)?)?
        || record.funding_outpoint.value_sats != u64::try_from(record_row.try_get::<i64, _>(3)?)?
        || record.latest_state_number != u32::try_from(record_row.try_get::<i64, _>(4)?)?
        || record.challenge_delay != u16::try_from(record_row.try_get::<i64, _>(5)?)?
        || record.amount_sats != u64::try_from(record_row.try_get::<i64, _>(6)?)?
        || record.network != record_row.try_get::<String, _>(7)?
    {
        return Err(anyhow!(
            "BIP448 accepted record JSON and indexed columns disagree"
        ));
    }
    let history_rows = sqlx::query(
        "SELECT state_number, entry_json FROM bip448_state_history \
         WHERE wallet_name = $1 AND statechain_id = $2 ORDER BY state_number",
    )
    .bind(wallet_name)
    .bind(statechain_id)
    .fetch_all(&mut *connection)
    .await?;
    let history = history_rows
        .into_iter()
        .map(|row| -> Result<Bip448StateHistoryEntry> {
            let state_number = u32::try_from(row.try_get::<i64, _>(0)?)?;
            let value: String = row.try_get(1)?;
            let entry: Bip448StateHistoryEntry = serde_json::from_str(&value)?;
            if entry.state_number != state_number || serde_json::to_string(&entry)? != value {
                return Err(anyhow!(
                    "BIP448 history JSON and indexed state number disagree"
                ));
            }
            Ok(entry)
        })
        .collect::<Result<Vec<Bip448StateHistoryEntry>>>()?;
    validate_bip448_accepted_artifacts(&record, &history)?;
    let accepted_len = usize::try_from(record.latest_state_number)?;
    let maximum_len = accepted_len
        .checked_add(2)
        .ok_or_else(|| anyhow!("BIP448 state-history length overflow"))?;
    if history.len() < accepted_len
        || history.len() > maximum_len
        || history.iter().enumerate().try_fold(
            false,
            |mismatch, (index, entry)| -> Result<bool> {
                let expected = u32::try_from(index)?
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("BIP448 history state-number overflow"))?;
                Ok(mismatch || entry.state_number != expected)
            },
        )?
    {
        return Err(anyhow!(
            "BIP448 state history is incomplete or has an unsupported suffix"
        ));
    }
    let accepted_entry = history
        .get(
            accepted_len
                .checked_sub(1)
                .ok_or_else(|| anyhow!("BIP448 accepted state number must be positive"))?,
        )
        .ok_or_else(|| anyhow!("BIP448 accepted history prefix is missing"))?;
    if !history_entry_matches_latest_state(accepted_entry, &record.latest_state) {
        return Err(anyhow!(
            "BIP448 accepted history prefix does not match the accepted record"
        ));
    }
    if history.len() > accepted_len {
        let outgoing_json = sqlx::query_scalar::<_, String>(
            "SELECT transfer_msg_json FROM bip448_transfer_messages \
             WHERE wallet_name = $1 AND statechain_id = $2 ORDER BY recipient_auth_pubkey",
        )
        .bind(wallet_name)
        .bind(statechain_id)
        .fetch_all(&mut *connection)
        .await?;
        let exact_message =
            outgoing_json
                .into_iter()
                .try_fold(false, |found, json| -> Result<bool> {
                    let message: Bip448TransferMsg = serde_json::from_str(&json)?;
                    if serde_json::to_string(&message)? != json {
                        return Err(anyhow!(
                            "BIP448 transfer-message suffix proof is not canonical JSON"
                        ));
                    }
                    Ok(found
                        || (message.state_history == history
                            && transfer_message_matches_record_and_history(
                                &message, &record, &history,
                            )?))
                })?;
        if !exact_message {
            let intents =
                list_bip448_transfer_intents_on(connection, wallet_name, statechain_id).await?;
            if intents.is_empty() {
                return Err(anyhow!(
                    "BIP448 state history suffix has no exact transfer journal"
                ));
            }
            validate_bip448_transfer_intent_lineage(&intents)?;
            let active = intents
                .iter()
                .find(|intent| intent.activity_status == Bip448TransferIntentActivityStatus::Active)
                .ok_or_else(|| anyhow!("BIP448 transfer intent lineage has no Active row"))?;
            let pending = pending_transfer_on(connection, wallet_name, statechain_id)
                .await?
                .ok_or_else(|| anyhow!("BIP448 active suffix pending signing is missing"))?;
            let planned_len = usize::try_from(active.planned_state_number)?;
            let expected_count = usize::try_from(active.expected_signature_count)?;
            let successor_replacement_window = active.phase == Bip448TransferIntentPhase::X1Stored
                && matches!(
                    active.state_signing_phase,
                    Bip448TransferStateSigningPhase::FirstArmed
                        | Bip448TransferStateSigningPhase::NonceStored
                        | Bip448TransferStateSigningPhase::SecondArmed
                        | Bip448TransferStateSigningPhase::Signed
                )
                && active.clear_local_attempt
                && !active.reuse_pending
                && !active.reuse_signed_state
                && active.prior_transfer_recipient_auth_pubkey.is_some()
                && active.prior_transfer_msg_hash.is_some()
                && history.len()
                    == accepted_len
                        .checked_add(1)
                        .ok_or_else(|| anyhow!("BIP448 state-history length overflow"))?
                && expected_count == history.len()
                && planned_len
                    == history
                        .len()
                        .checked_add(1)
                        .ok_or_else(|| anyhow!("BIP448 transfer plan length overflow"))?;
            if active.current_pending_signing_id.as_deref() != Some(pending.signing_id.as_str())
                || pending.funding_txid != record.funding_outpoint.txid
                || pending.funding_vout != record.funding_outpoint.vout
                || pending.funding_value_sats != record.funding_outpoint.value_sats
            {
                return Err(anyhow!(
                    "BIP448 state history suffix artifacts do not match the active journal"
                ));
            }
            if successor_replacement_window {
                if history
                    .last()
                    .is_none_or(|entry| entry.state_locktime != active.previous_locktime)
                    || pending.state_locktime <= active.previous_locktime
                {
                    return Err(anyhow!(
                        "BIP448 successor replacement window has incoherent locktimes"
                    ));
                }
            } else if active.state_signing_phase != Bip448TransferStateSigningPhase::Signed
                || planned_len != history.len()
                || !history_entry_matches_pending_intent(
                    history
                        .last()
                        .ok_or_else(|| anyhow!("BIP448 state history suffix is empty"))?,
                    &pending,
                    active,
                )?
            {
                return Err(anyhow!(
                    "BIP448 state history suffix does not match its active transfer intent"
                ));
            }
            if history.len()
                == accepted_len
                    .checked_add(2)
                    .ok_or_else(|| anyhow!("BIP448 state-history length overflow"))?
            {
                let recipient = active
                    .prior_transfer_recipient_auth_pubkey
                    .as_deref()
                    .ok_or_else(|| anyhow!("BIP448 N+2 suffix has no predecessor recipient"))?;
                let expected_hash = active
                    .prior_transfer_msg_hash
                    .as_deref()
                    .ok_or_else(|| anyhow!("BIP448 N+2 suffix has no predecessor hash"))?;
                let prior_json = sqlx::query_scalar::<_, String>(
                    "SELECT transfer_msg_json FROM bip448_transfer_messages \
                     WHERE wallet_name=$1 AND statechain_id=$2 AND recipient_auth_pubkey=$3",
                )
                .bind(wallet_name)
                .bind(statechain_id)
                .bind(recipient)
                .fetch_optional(&mut *connection)
                .await?
                .ok_or_else(|| anyhow!("BIP448 N+2 predecessor message is missing"))?;
                if sha256::Hash::hash(prior_json.as_bytes()).to_string() != expected_hash {
                    return Err(anyhow!("BIP448 N+2 predecessor message hash changed"));
                }
                let prior: Bip448TransferMsg = serde_json::from_str(&prior_json)?;
                let predecessor_len = accepted_len
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("BIP448 predecessor state length overflow"))?;
                if serde_json::to_string(&prior)? != prior_json
                    || prior.state_history.as_slice() != &history[..predecessor_len]
                    || !transfer_message_matches_record_and_history(
                        &prior,
                        &record,
                        &history[..predecessor_len],
                    )?
                {
                    return Err(anyhow!(
                        "BIP448 N+2 predecessor message does not prove the first suffix"
                    ));
                }
            }
        }
    }
    Ok((record, history))
}

pub(crate) async fn recover_bip448_initial_acceptance_wallet(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    expected_raw_wallet_json: &str,
) -> Result<Bip448InitialAcceptanceRecovery> {
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    let live_raw_wallet_json =
        sqlx::query_scalar::<_, String>("SELECT wallet_json FROM wallet WHERE wallet_name = $1")
            .bind(wallet_name)
            .fetch_optional(guard.connection())
            .await?
            .ok_or_else(|| anyhow!("BIP448 initial-acceptance recovery wallet is missing"))?;
    if live_raw_wallet_json != expected_raw_wallet_json {
        return Ok(Bip448InitialAcceptanceRecovery::WalletChanged);
    }
    let wallet: Wallet = serde_json::from_str(&live_raw_wallet_json)?;
    if wallet.name != wallet_name
        || wallet.network != wallet.settings.network
        || canonical_wallet_json(&wallet)? != live_raw_wallet_json
    {
        return Err(anyhow!(
            "BIP448 initial-acceptance recovery wallet identity or canonical bytes are invalid"
        ));
    }

    let accepted_statechain_ids = sqlx::query_scalar::<_, String>(
        "SELECT statechain_id FROM bip448_statechains \
         WHERE wallet_name = $1 ORDER BY statechain_id",
    )
    .bind(wallet_name)
    .fetch_all(guard.connection())
    .await?;
    let mut replacement_wallet = wallet.clone();
    let mut accepted_generations = Vec::new();
    let mut pending_deletions = Vec::new();
    let mut recovered = false;

    for statechain_id in accepted_statechain_ids {
        let (record, history) =
            accepted_record_and_history_on(guard.connection(), wallet_name, &statechain_id).await?;
        let accepted_index = usize::try_from(record.latest_state_number)?
            .checked_sub(1)
            .ok_or_else(|| anyhow!("BIP448 accepted state number must be positive"))?;
        let accepted_entry = history
            .get(accepted_index)
            .ok_or_else(|| anyhow!("BIP448 accepted owner history is missing"))?;
        let accepted_owner = XOnlyPublicKey::from_str(&accepted_entry.owner_public_key)?;
        require_canonical_bip448_wallet(&live_raw_wallet_json, wallet_name, &record.network)?;
        let coin_index = selected_bip448_wallet_coin_index(&wallet, &record, accepted_owner)?;
        let coin = &wallet.coins[coin_index];
        if validate_selected_bip448_coin(
            coin,
            &record,
            accepted_owner,
            Bip448WalletCoinRequirement::PassiveBindingSync,
        )
        .is_ok()
        {
            accepted_generations.push((record, accepted_owner));
            continue;
        }

        validate_selected_bip448_coin(
            coin,
            &record,
            accepted_owner,
            Bip448WalletCoinRequirement::InitialAcceptance,
        )?;
        let absent_outpoint = coin.utxo_txid.is_none() && coin.utxo_vout.is_none();
        let exact_outpoint = coin.utxo_txid.as_deref()
            == Some(record.funding_outpoint.txid.as_str())
            && coin.utxo_vout == Some(record.funding_outpoint.vout);
        let absent_signing_facts = coin.locktime.is_none()
            && coin.public_nonce.is_none()
            && coin.server_public_nonce.is_none()
            && coin.blinding_factor.is_none();
        if record.latest_state_number != INITIAL_BIP448_STATE_NUMBER
            || history.len() != usize::try_from(INITIAL_BIP448_STATE_NUMBER)?
            || !absent_signing_facts
            || !((absent_outpoint && coin.status == CoinStatus::INITIALISED)
                || (exact_outpoint
                    && matches!(
                        coin.status,
                        CoinStatus::IN_MEMPOOL | CoinStatus::UNCONFIRMED
                    )))
            || coin.secret_nonce.is_some()
            || coin.tx_withdraw.is_some()
            || coin.withdrawal_address.is_some()
        {
            return Err(anyhow!(
                "BIP448 initial-acceptance recovery requires an exact pre-materialized state-1 Coin"
            ));
        }
        let pending_signing_id = validate_initial_acceptance_pending_signing_on(
            guard.connection(),
            &record,
            accepted_entry,
        )
        .await?;
        let activity_utxo = format!(
            "{}:{}",
            record.funding_outpoint.txid, record.funding_outpoint.vout
        );
        if wallet
            .activities
            .iter()
            .any(|activity| activity.action == "bip448_deposit" && activity.utxo == activity_utxo)
        {
            return Err(anyhow!(
                "BIP448 pre-materialized initial acceptance already has a deposit activity"
            ));
        }

        let replacement_coin = &mut replacement_wallet.coins[coin_index];
        replacement_coin.utxo_txid = Some(record.funding_outpoint.txid.clone());
        replacement_coin.utxo_vout = Some(record.funding_outpoint.vout);
        replacement_coin.locktime = Some(record.latest_state.state_locktime);
        replacement_coin.public_nonce = Some(accepted_entry.client_public_nonce.clone());
        replacement_coin.server_public_nonce = Some(accepted_entry.server_public_nonce.clone());
        replacement_coin.blinding_factor = Some(accepted_entry.blinding_factor.clone());
        replacement_coin.status = CoinStatus::UNCONFIRMED;
        validate_selected_bip448_coin(
            replacement_coin,
            &record,
            accepted_owner,
            Bip448WalletCoinRequirement::MaterializedInitialAcceptance,
        )?;
        replacement_wallet.activities.push(Activity {
            utxo: activity_utxo,
            amount: u32::try_from(record.funding_outpoint.value_sats)?,
            action: "bip448_deposit".to_owned(),
            date: chrono::Utc::now().to_rfc3339(),
        });
        pending_deletions.push((record.statechain_id.clone(), pending_signing_id));
        accepted_generations.push((record, accepted_owner));
        recovered = true;
    }

    if !recovered {
        return Ok(Bip448InitialAcceptanceRecovery::Unchanged);
    }
    for (record, accepted_owner) in &accepted_generations {
        require_selected_bip448_wallet_coin(
            &replacement_wallet,
            record,
            *accepted_owner,
            Bip448WalletCoinRequirement::PassiveBindingSync,
        )?;
    }
    let replacement_raw_wallet_json = canonical_wallet_json(&replacement_wallet)?;
    let updated = sqlx::query(
        "UPDATE wallet SET wallet_json = $1 WHERE wallet_name = $2 AND wallet_json = $3",
    )
    .bind(&replacement_raw_wallet_json)
    .bind(wallet_name)
    .bind(expected_raw_wallet_json)
    .execute(guard.connection())
    .await?;
    if updated.rows_affected() != 1 {
        return Err(anyhow!(
            "BIP448 initial-acceptance recovery wallet CAS lost"
        ));
    }
    for (statechain_id, signing_id) in pending_deletions {
        if let Some(signing_id) = signing_id {
            let deleted = sqlx::query(
                "DELETE FROM bip448_pending_deposit_signings \
                 WHERE wallet_name = $1 AND statechain_id = $2 AND signing_id = $3",
            )
            .bind(wallet_name)
            .bind(&statechain_id)
            .bind(&signing_id)
            .execute(guard.connection())
            .await?;
            if deleted.rows_affected() != 1 {
                return Err(anyhow!(
                    "BIP448 initial-acceptance recovery pending cleanup CAS lost"
                ));
            }
        }
    }
    guard.commit().await?;
    Ok(Bip448InitialAcceptanceRecovery::Recovered)
}
