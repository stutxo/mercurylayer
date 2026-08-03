use std::str::FromStr;

use bitcoin::{
    absolute, hashes::Hash, sighash::TemplateHash, Address, Network, OutPoint, PrivateKey,
    ScriptBuf, TxOut, Txid,
};
use secp256k1::{
    musig::{BlindingFactor, PublicNonce},
    schnorr, PublicKey, Secp256k1, Signing, Verification, XOnlyPublicKey,
};
use serde::{Deserialize, Serialize};

use crate::bip448_statechain::deposit::DEFAULT_BIP448_CHALLENGE_DELAY;
use crate::bip448_statechain::script as bip448_script;
use crate::bip448_statechain::signing::{CsfsSigningRole, CsfsSigningSession};
use crate::bip448_statechain::storage::{
    Bip448FeeBumpPolicy, Bip448FundingOutpoint, Bip448LatestState, Bip448RecoveryVerifyError,
    Bip448ValueSchedule, Bip448VerifiedRecoveryBinding,
};
use crate::bip448_statechain::transaction as bip448_transaction;
use crate::error::MercuryError;

use super::receiver::{
    validate_t1pub, verify_transfer_signature_with_keys, StatechainInfoResponsePayload,
};

/// Receiver-controlled chain and wallet facts used for transfer verification.
#[derive(Debug, Clone)]
pub struct Bip448TransferChainFacts {
    pub expected_network: Network,
    pub median_time_past: u32,
    pub funding_outpoint: OutPoint,
    pub funding_output: TxOut,
    pub tx0_confirmed: bool,
    pub tx0_unspent: bool,
    pub receiver_user_pubkey: PublicKey,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Bip448TransferVerifyError {
    #[error("unsupported BIP448 transfer message version")]
    UnsupportedMessageVersion,
    #[error("BIP448 transfer network or challenge delay is invalid")]
    InvalidNetworkOrChallengeDelay,
    #[error("BIP448 transfer signature count or state history is invalid")]
    InvalidSignatureCount,
    #[error("BIP448 transfer authorization signature is invalid")]
    InvalidTransferSignature,
    #[error("BIP448 transfer t1 does not match the sender key and x1")]
    InvalidT1,
    #[error("BIP448 transfer aggregate-key continuity is invalid")]
    InvalidKeyContinuity,
    #[error("BIP448 funding output is spent, unconfirmed, or has the wrong value")]
    InvalidFundingOutput,
    #[error("BIP448 state history is invalid")]
    InvalidStateHistory,
    #[error("BIP448 state update signature is invalid")]
    InvalidUpdateSignature,
    #[error("BIP448 state signing evidence does not match the server challenge")]
    InvalidBlindedChallenge,
    #[error("BIP448 state locktime progression is invalid")]
    InvalidStateLocktime,
    #[error("BIP448 latest recovery state is invalid: {0}")]
    Recovery(#[from] Bip448RecoveryVerifyError),
}

/// Receiver-controlled facts required to validate a BIP448 recovery state.
///
/// The outpoint/output and BIP113 median-time-past must come from the receiver's
/// trusted chain backend, the signature count from a direct lockbox query, and
/// the remaining values from the local wallet or independently queried
/// statechain state. Sender fields and local wall-clock time must never be used
/// to construct this context.
#[derive(Debug, Clone)]
pub struct Bip448TrustedRecoveryContext {
    expected_statechain_id: String,
    expected_network: Network,
    median_time_past: u32,
    funding_outpoint: OutPoint,
    funding_output: TxOut,
    lockbox_signature_count: u64,
    expected_challenge_delay: u16,
    expected_fee_bump_policy: Bip448FeeBumpPolicy,
    receiver_user_pubkey: PublicKey,
    server_pubkey: PublicKey,
    recovery_script: ScriptBuf,
    allow_transferred_funding_state: bool,
}

impl Bip448TrustedRecoveryContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        expected_statechain_id: impl Into<String>,
        expected_network: Network,
        median_time_past: u32,
        funding_outpoint: OutPoint,
        funding_output: TxOut,
        lockbox_signature_count: u64,
        expected_challenge_delay: u16,
        expected_fee_bump_policy: Bip448FeeBumpPolicy,
        receiver_user_pubkey: PublicKey,
        server_pubkey: PublicKey,
        recovery_script: ScriptBuf,
    ) -> Self {
        Self {
            expected_statechain_id: expected_statechain_id.into(),
            expected_network,
            median_time_past,
            funding_outpoint,
            funding_output,
            lockbox_signature_count,
            expected_challenge_delay,
            expected_fee_bump_policy,
            receiver_user_pubkey,
            server_pubkey,
            recovery_script,
            allow_transferred_funding_state: false,
        }
    }
}

/// Canonical recovery data produced only after the Phase 6 trust checks pass.
///
/// This is not complete transfer acceptance: sender authorization, `t1`, and
/// key-share update still belong to Phase 8. Its security-relevant recovery
/// fields use the receiver-reconstructed lowercase representation. Sender
/// signing-retry metadata remains operational data that Phase 8 must strip or
/// independently validate before accepted persistence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip448VerifiedRecoveryState {
    statechain_id: String,
    network: Network,
    funding_outpoint: OutPoint,
    funding_output: TxOut,
    receiver_user_pubkey: PublicKey,
    server_pubkey: PublicKey,
    aggregate_pubkey: PublicKey,
    canonical_latest_state: Bip448LatestState,
}

impl Bip448VerifiedRecoveryState {
    pub fn statechain_id(&self) -> &str {
        &self.statechain_id
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn funding_outpoint(&self) -> OutPoint {
        self.funding_outpoint
    }

    pub fn funding_output(&self) -> &TxOut {
        &self.funding_output
    }

    pub fn receiver_user_pubkey(&self) -> &PublicKey {
        &self.receiver_user_pubkey
    }

    pub fn server_pubkey(&self) -> &PublicKey {
        &self.server_pubkey
    }

    pub fn aggregate_pubkey(&self) -> &PublicKey {
        &self.aggregate_pubkey
    }

    pub fn canonical_latest_state(&self) -> &Bip448LatestState {
        &self.canonical_latest_state
    }

    pub fn into_canonical_latest_state(self) -> Bip448LatestState {
        self.canonical_latest_state
    }
}

/// BIP448 transfer message. This deliberately does not reuse the legacy
/// `TransferMsg`/`BackupTx` shape, because BIP448 receivers validate signed
/// update/settlement templates rather than legacy backup transactions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bip448TransferMsg {
    pub msg_version: u32,
    pub statechain_id: String,
    pub transfer_signature: String,
    pub sender_user_public_key: String,
    pub receiver_user_public_key: String,
    pub server_public_key: String,
    pub aggregate_pubkey: String,
    pub funding_outpoint: Bip448FundingOutpoint,
    pub latest_state_number: u32,
    pub challenge_delay: u16,
    pub amount_sats: u64,
    pub network: String,
    pub value_schedule: Bip448ValueSchedule,
    pub latest_state: Bip448LatestState,
    /// Lockbox-authoritative count observed by the sender. The receiver can
    /// compare it with `/bip448-statechain/signature-count/<statechain_id>`.
    pub server_signature_count: u64,
    /// Sender's tweaked client key share material needed by the receiver's key
    /// update flow. It is protocol key-share state, not a legacy backup tx.
    pub t1: [u8; 32],
    pub state_history: Vec<Bip448StateHistoryEntry>,
}

/// One signed BIP448 state carried in transfer order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bip448StateHistoryEntry {
    pub state_number: u32,
    pub state_locktime: u32,
    pub owner_public_key: String,
    pub update_template_hash: String,
    pub settlement_template_hash: String,
    pub update_signature: String,
    pub client_public_nonce: String,
    pub server_public_nonce: String,
    pub blinding_factor: String,
}

impl Bip448TransferMsg {
    pub fn encrypt(&self, recipient_auth_pubkey: &PublicKey) -> Result<String, MercuryError> {
        let transfer_msg_json = serde_json::json!(self);
        let transfer_msg_json = serde_json::to_string_pretty(&transfer_msg_json)?;
        let encrypted = ecies::encrypt(
            &recipient_auth_pubkey.serialize(),
            transfer_msg_json.as_bytes(),
        )
        .map_err(|_| MercuryError::SecpError)?;

        Ok(hex::encode(encrypted))
    }

    /// Verifies the transfer message binds recovery authority to keys the
    /// receiver trusts. It reconciles the top-level convenience fields against
    /// the nested `latest_state`, recomputes `P = receiver_user_pubkey +
    /// server_pubkey`, requires the duplicated message key strings to use the
    /// canonical encodings of those trusted keys, checks the message
    /// `aggregate_pubkey` equals canonical `P`, and verifies the CSFS key
    /// metadata + update signature against `P.x`.
    ///
    /// `receiver_user_pubkey` and `server_pubkey` MUST be the receiver's own
    /// key and the server key it confirms out of band (e.g. from
    /// `statechain_info`), NOT values read from this sender-controlled message —
    /// otherwise a malicious sender could substitute a self-consistent but wrong
    /// aggregate key. Returns the recomputed `P` on success.
    pub fn verify_recovery_against_keys<C: Verification + Signing>(
        &self,
        secp: &Secp256k1<C>,
        receiver_user_pubkey: &PublicKey,
        server_pubkey: &PublicKey,
    ) -> Result<PublicKey, Bip448RecoveryVerifyError> {
        Ok(self
            .verify_recovery_binding_against_keys(secp, receiver_user_pubkey, server_pubkey)?
            .into_aggregate_pubkey())
    }

    fn verify_recovery_binding_against_keys<C: Verification + Signing>(
        &self,
        secp: &Secp256k1<C>,
        receiver_user_pubkey: &PublicKey,
        server_pubkey: &PublicKey,
    ) -> Result<Bip448VerifiedRecoveryBinding, Bip448RecoveryVerifyError> {
        if self.receiver_user_public_key != receiver_user_pubkey.to_string() {
            return Err(Bip448RecoveryVerifyError::TrustedFieldMismatch(
                "receiver_user_public_key",
            ));
        }
        if self.server_public_key != server_pubkey.to_string() {
            return Err(Bip448RecoveryVerifyError::TrustedFieldMismatch(
                "server_public_key",
            ));
        }

        self.verify_recovery_binding_against_aggregate_keys(
            secp,
            receiver_user_pubkey,
            server_pubkey,
        )
    }

    fn verify_recovery_binding_against_sender_keys<C: Verification + Signing>(
        &self,
        secp: &Secp256k1<C>,
        sender_user_pubkey: &PublicKey,
        server_pubkey: &PublicKey,
    ) -> Result<Bip448VerifiedRecoveryBinding, Bip448RecoveryVerifyError> {
        if self.sender_user_public_key != sender_user_pubkey.to_string() {
            return Err(Bip448RecoveryVerifyError::TrustedFieldMismatch(
                "sender_user_public_key",
            ));
        }
        if self.server_public_key != server_pubkey.to_string() {
            return Err(Bip448RecoveryVerifyError::TrustedFieldMismatch(
                "server_public_key",
            ));
        }

        self.verify_recovery_binding_against_aggregate_keys(secp, sender_user_pubkey, server_pubkey)
    }

    fn verify_recovery_binding_against_aggregate_keys<C: Verification + Signing>(
        &self,
        secp: &Secp256k1<C>,
        owner_user_pubkey: &PublicKey,
        server_pubkey: &PublicKey,
    ) -> Result<Bip448VerifiedRecoveryBinding, Bip448RecoveryVerifyError> {
        if self.latest_state_number != self.latest_state.state_number {
            return Err(Bip448RecoveryVerifyError::InconsistentField(
                "latest_state_number",
            ));
        }
        if self.challenge_delay != self.latest_state.challenge_delay {
            return Err(Bip448RecoveryVerifyError::InconsistentField(
                "challenge_delay",
            ));
        }
        if self.value_schedule != self.latest_state.value_schedule {
            return Err(Bip448RecoveryVerifyError::InconsistentField(
                "value_schedule",
            ));
        }
        if self.server_signature_count != self.latest_state.signing_metadata.server_signature_count
        {
            return Err(Bip448RecoveryVerifyError::InconsistentField(
                "server_signature_count",
            ));
        }

        let binding = self.latest_state.verify_recovery_binding_against_keys(
            secp,
            owner_user_pubkey,
            server_pubkey,
        )?;

        if self.aggregate_pubkey != binding.aggregate_pubkey().to_string() {
            return Err(Bip448RecoveryVerifyError::AggregateKeyMismatch);
        }

        Ok(binding)
    }

    /// Validates the BIP448 recovery state against receiver-controlled chain,
    /// wallet, network, lockbox, and chain-MTP facts. Template reconstruction is
    /// seeded by the chain-reported value, never by a sender-provided value
    /// schedule, and both reconstructed transactions must already be final under
    /// the chain's BIP113 median-time-past.
    ///
    /// This is deliberately NOT complete transfer acceptance: it does not verify
    /// `transfer_signature`, validate `t1` against key-update state, or perform
    /// the server key-share update. Phase 8 must complete those checks before a
    /// receiver persists the message as an accepted transfer. Returns typed
    /// trusted facts plus the receiver-reconstructed canonical latest state;
    /// callers must not promote the original sender strings into persistence.
    pub fn verify_recovery_state<C: Verification + Signing>(
        &self,
        secp: &Secp256k1<C>,
        trusted: &Bip448TrustedRecoveryContext,
    ) -> Result<Bip448VerifiedRecoveryState, Bip448RecoveryVerifyError> {
        if self.statechain_id != trusted.expected_statechain_id {
            return Err(Bip448RecoveryVerifyError::TrustedFieldMismatch(
                "statechain_id",
            ));
        }
        let network = Network::from_str(&self.network)
            .map_err(|_| Bip448RecoveryVerifyError::TrustedFieldMismatch("network"))?;
        if network != trusted.expected_network {
            return Err(Bip448RecoveryVerifyError::TrustedFieldMismatch("network"));
        }
        let funding_txid = Txid::from_str(&self.funding_outpoint.txid)
            .map_err(|_| Bip448RecoveryVerifyError::InvalidFundingTxid)?;
        let claimed_funding_outpoint = OutPoint {
            txid: funding_txid,
            vout: self.funding_outpoint.vout,
        };
        if claimed_funding_outpoint != trusted.funding_outpoint {
            return Err(Bip448RecoveryVerifyError::TrustedFieldMismatch(
                "funding_outpoint",
            ));
        }
        if self.funding_outpoint.value_sats != trusted.funding_output.value {
            return Err(Bip448RecoveryVerifyError::TrustedFieldMismatch(
                "funding_outpoint.value_sats",
            ));
        }
        if self.amount_sats != trusted.funding_output.value {
            return Err(Bip448RecoveryVerifyError::TrustedFieldMismatch(
                "amount_sats",
            ));
        }
        if self.server_signature_count != trusted.lockbox_signature_count
            || self.latest_state.signing_metadata.server_signature_count
                != trusted.lockbox_signature_count
        {
            return Err(Bip448RecoveryVerifyError::TrustedFieldMismatch(
                "server_signature_count",
            ));
        }
        // The provisional count tracks logical state bookkeeping independently
        // from consensus locktime. Initial funding recovery is restricted to
        // state 1 below; complete future-state history binding belongs to Phase 8.
        if u64::from(self.latest_state_number) != trusted.lockbox_signature_count
            || u64::from(self.latest_state.state_number) != trusted.lockbox_signature_count
        {
            return Err(Bip448RecoveryVerifyError::TrustedFieldMismatch(
                "latest_state_number",
            ));
        }
        if self.challenge_delay != trusted.expected_challenge_delay
            || self.latest_state.challenge_delay != trusted.expected_challenge_delay
        {
            return Err(Bip448RecoveryVerifyError::TrustedFieldMismatch(
                "challenge_delay",
            ));
        }
        if self.latest_state.fee_bump_policy != trusted.expected_fee_bump_policy {
            return Err(Bip448RecoveryVerifyError::TrustedFieldMismatch(
                "fee_bump_policy",
            ));
        }
        let binding = self.verify_recovery_binding_against_keys(
            secp,
            &trusted.receiver_user_pubkey,
            &trusted.server_pubkey,
        )?;

        let canonical_latest_state = self
            .latest_state
            .verify_reconstructed_templates_with_binding(
                secp,
                &binding,
                trusted.funding_outpoint,
                &trusted.funding_output,
                &trusted.recovery_script,
                trusted.allow_transferred_funding_state,
            )?;
        // Canonical reconstruction proves both U(n) and S(n) use the same
        // explicit state locktime, so this one chain-time check covers both.
        bip448_transaction::validate_immediately_final(
            absolute::LockTime::from_consensus(canonical_latest_state.state_locktime),
            trusted.median_time_past,
        )
        .map_err(recovery_finality_error)?;

        Ok(Bip448VerifiedRecoveryState {
            statechain_id: trusted.expected_statechain_id.clone(),
            network: trusted.expected_network,
            funding_outpoint: trusted.funding_outpoint,
            funding_output: trusted.funding_output.clone(),
            receiver_user_pubkey: trusted.receiver_user_pubkey,
            server_pubkey: trusted.server_pubkey,
            aggregate_pubkey: binding.into_aggregate_pubkey(),
            canonical_latest_state,
        })
    }
}

pub fn decrypt_bip448_transfer_msg(
    encrypted_message: &str,
    private_key_wif: &str,
) -> Result<Bip448TransferMsg, MercuryError> {
    let client_auth_key = PrivateKey::from_wif(private_key_wif)?.inner;
    let encrypted = hex::decode(encrypted_message)?;
    let decrypted = ecies::decrypt(&client_auth_key.to_secret_bytes(), &encrypted)
        .map_err(|_| MercuryError::SecpError)?;
    let transfer_msg = serde_json::from_slice(&decrypted)?;

    Ok(transfer_msg)
}

/// Verifies BIP448 receiver checks 1-9 without performing network or storage I/O.
pub fn verify_bip448_transfer_msg(
    msg: &Bip448TransferMsg,
    statechain_info: &StatechainInfoResponsePayload,
    chain_facts: &Bip448TransferChainFacts,
) -> Result<(), Bip448TransferVerifyError> {
    let secp = Secp256k1::new();
    let expected_fee_bump_policy = Bip448FeeBumpPolicy::ZeroFeeEphemeralAnchor;
    if msg.msg_version != 2 {
        return Err(Bip448TransferVerifyError::UnsupportedMessageVersion);
    }
    let network = Network::from_str(&msg.network)
        .map_err(|_| Bip448TransferVerifyError::InvalidNetworkOrChallengeDelay)?;
    if network != chain_facts.expected_network
        || msg.challenge_delay != DEFAULT_BIP448_CHALLENGE_DELAY
        || msg.latest_state.challenge_delay != DEFAULT_BIP448_CHALLENGE_DELAY
    {
        return Err(Bip448TransferVerifyError::InvalidNetworkOrChallengeDelay);
    }

    let n = msg.latest_state_number;
    if n < 2
        || statechain_info.num_sigs != n
        || msg.state_history.len() != n as usize
        || msg.server_signature_count != u64::from(n)
        || msg.latest_state.state_number != n
        || msg.latest_state.signing_metadata.server_signature_count != u64::from(n)
    {
        return Err(Bip448TransferVerifyError::InvalidSignatureCount);
    }

    let funding_txid = Txid::from_str(&msg.funding_outpoint.txid)
        .map_err(|_| Bip448TransferVerifyError::InvalidFundingOutput)?;
    let funding_outpoint = OutPoint {
        txid: funding_txid,
        vout: msg.funding_outpoint.vout,
    };
    if !chain_facts.tx0_confirmed
        || !chain_facts.tx0_unspent
        || funding_outpoint != chain_facts.funding_outpoint
        || msg.funding_outpoint.value_sats != chain_facts.funding_output.value
        || msg.amount_sats != chain_facts.funding_output.value
    {
        return Err(Bip448TransferVerifyError::InvalidFundingOutput);
    }

    let receiver_user_pubkey = PublicKey::from_str(&msg.receiver_user_public_key)
        .map_err(|_| Bip448TransferVerifyError::InvalidKeyContinuity)?;
    if receiver_user_pubkey != chain_facts.receiver_user_pubkey
        || msg.receiver_user_public_key != chain_facts.receiver_user_pubkey.to_string()
    {
        return Err(Bip448TransferVerifyError::InvalidKeyContinuity);
    }
    let sender_user_pubkey = PublicKey::from_str(&msg.sender_user_public_key)
        .map_err(|_| Bip448TransferVerifyError::InvalidKeyContinuity)?;
    let server_pubkey = PublicKey::from_str(&statechain_info.enclave_public_key)
        .map_err(|_| Bip448TransferVerifyError::InvalidKeyContinuity)?;
    if msg.server_public_key != server_pubkey.to_string() {
        return Err(Bip448TransferVerifyError::InvalidKeyContinuity);
    }

    verify_transfer_authorization(
        &secp,
        msg,
        &funding_outpoint,
        &sender_user_pubkey,
        &receiver_user_pubkey,
    )?;
    let x1_pub = statechain_info
        .x1_pub
        .as_ref()
        .ok_or(Bip448TransferVerifyError::InvalidT1)
        .and_then(|x1| PublicKey::from_str(x1).map_err(|_| Bip448TransferVerifyError::InvalidT1))?;
    if !validate_t1pub(&msg.t1, &x1_pub, &sender_user_pubkey)
        .map_err(|_| Bip448TransferVerifyError::InvalidT1)?
    {
        return Err(Bip448TransferVerifyError::InvalidT1);
    }

    let binding = msg
        .verify_recovery_binding_against_sender_keys(&secp, &sender_user_pubkey, &server_pubkey)
        .map_err(transfer_binding_error)?;
    let aggregate_pubkey = binding.aggregate_pubkey().clone();

    for (index, entry) in msg.state_history.iter().enumerate() {
        let expected_state_number = index as u32 + 1;
        let signing_row = statechain_info
            .statechain_info
            .iter()
            .find(|row| row.tx_n == expected_state_number)
            .ok_or(Bip448TransferVerifyError::InvalidStateHistory)?;
        if signing_row.statechain_id != msg.statechain_id {
            return Err(Bip448TransferVerifyError::InvalidStateHistory);
        }
        let owner_public_key = XOnlyPublicKey::from_str(&entry.owner_public_key)
            .map_err(|_| Bip448TransferVerifyError::InvalidStateHistory)?;
        let recovery_script = Address::p2tr(
            &secp,
            owner_public_key,
            None,
            chain_facts.expected_network,
        )
        .script_pubkey();
        verify_history_entry(
            &secp,
            entry,
            expected_state_number,
            signing_row.challenge.as_str(),
            &aggregate_pubkey,
            chain_facts.funding_outpoint,
            chain_facts.funding_output.value,
            &recovery_script,
            msg.challenge_delay,
            expected_fee_bump_policy,
        )?;
    }
    if msg.state_history[n as usize - 1].owner_public_key
        != receiver_user_pubkey.x_only_public_key().0.to_string()
    {
        return Err(Bip448TransferVerifyError::InvalidStateHistory);
    }

    for entries in msg.state_history.windows(2) {
        let stride = entries[1]
            .state_locktime
            .checked_sub(entries[0].state_locktime)
            .ok_or(Bip448TransferVerifyError::InvalidStateLocktime)?;
        let next_locktime = bip448_script::checked_next_state_locktime(
            absolute::LockTime::from_consensus(entries[0].state_locktime),
            stride,
        )
        .map_err(|_| Bip448TransferVerifyError::InvalidStateLocktime)?;
        if next_locktime.to_consensus_u32() != entries[1].state_locktime {
            return Err(Bip448TransferVerifyError::InvalidStateLocktime);
        }
    }
    let last_entry = msg
        .state_history
        .last()
        .ok_or(Bip448TransferVerifyError::InvalidStateHistory)?;
    bip448_transaction::validate_immediately_final(
        absolute::LockTime::from_consensus(last_entry.state_locktime),
        chain_facts.median_time_past,
    )
    .map_err(|_| Bip448TransferVerifyError::InvalidStateLocktime)?;
    if !latest_history_matches_state(last_entry, &msg.latest_state) {
        return Err(Bip448TransferVerifyError::InvalidStateHistory);
    }

    // Project the post-transfer server share so recovery verification uses
    // P = O2 + S2 while validating the state-2 templates against Tx0.
    let post_transfer_server_pubkey = aggregate_pubkey
        .combine(&receiver_user_pubkey.negate())
        .map_err(|_| Bip448TransferVerifyError::InvalidKeyContinuity)?;
    let recovery_script = Address::p2tr(
        &secp,
        receiver_user_pubkey.x_only_public_key().0,
        None,
        chain_facts.expected_network,
    )
    .script_pubkey();
    let mut recovery_msg = msg.clone();
    recovery_msg.server_public_key = post_transfer_server_pubkey.to_string();
    let mut recovery_context = Bip448TrustedRecoveryContext::new(
        msg.statechain_id.clone(),
        chain_facts.expected_network,
        chain_facts.median_time_past,
        chain_facts.funding_outpoint,
        chain_facts.funding_output.clone(),
        u64::from(msg.latest_state_number),
        DEFAULT_BIP448_CHALLENGE_DELAY,
        expected_fee_bump_policy,
        receiver_user_pubkey,
        post_transfer_server_pubkey,
        recovery_script,
    );
    recovery_context.allow_transferred_funding_state = true;
    recovery_msg.verify_recovery_state(&secp, &recovery_context)?;

    Ok(())
}

fn transfer_binding_error(error: Bip448RecoveryVerifyError) -> Bip448TransferVerifyError {
    match error {
        Bip448RecoveryVerifyError::InvalidUpdateSignature
        | Bip448RecoveryVerifyError::UpdateSignatureVerification => {
            Bip448TransferVerifyError::InvalidUpdateSignature
        }
        Bip448RecoveryVerifyError::AggregateKeyMismatch
        | Bip448RecoveryVerifyError::KeyMetadataMismatch
        | Bip448RecoveryVerifyError::TrustedFieldMismatch(_)
        | Bip448RecoveryVerifyError::Secp256k1(_) => {
            Bip448TransferVerifyError::InvalidKeyContinuity
        }
        error => Bip448TransferVerifyError::Recovery(error),
    }
}

fn verify_transfer_authorization<C: Verification>(
    secp: &Secp256k1<C>,
    msg: &Bip448TransferMsg,
    funding_outpoint: &OutPoint,
    sender_user_pubkey: &PublicKey,
    receiver_user_pubkey: &PublicKey,
) -> Result<(), Bip448TransferVerifyError> {
    let signature = schnorr::Signature::from_str(&msg.transfer_signature)
        .map_err(|_| Bip448TransferVerifyError::InvalidTransferSignature)?;
    if !verify_transfer_signature_with_keys(
        secp,
        receiver_user_pubkey,
        &funding_outpoint.txid,
        funding_outpoint.vout,
        sender_user_pubkey,
        &signature,
    ) {
        return Err(Bip448TransferVerifyError::InvalidTransferSignature);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_history_entry<C: Verification + Signing>(
    secp: &Secp256k1<C>,
    entry: &Bip448StateHistoryEntry,
    expected_state_number: u32,
    expected_challenge: &str,
    aggregate_pubkey: &PublicKey,
    funding_outpoint: OutPoint,
    funding_value: u64,
    recovery_script: &ScriptBuf,
    challenge_delay: u16,
    fee_bump_policy: Bip448FeeBumpPolicy,
) -> Result<(), Bip448TransferVerifyError> {
    if entry.state_number != expected_state_number {
        return Err(Bip448TransferVerifyError::InvalidStateHistory);
    }
    let state_locktime = absolute::LockTime::from_consensus(entry.state_locktime);
    bip448_script::validate_state_locktime(state_locktime)
        .map_err(|_| Bip448TransferVerifyError::InvalidStateLocktime)?;
    let templates = bip448_transaction::build_state_templates(
        secp,
        aggregate_pubkey.x_only_public_key().0,
        funding_outpoint,
        funding_value,
        recovery_script.clone(),
        entry.state_number,
        state_locktime,
        challenge_delay,
        transfer_fee_policy(fee_bump_policy),
    )
    .map_err(|_| Bip448TransferVerifyError::InvalidStateHistory)?;
    let update_hash = bip448_transaction::update_template_hash(&templates.update_tx)
        .map_err(|_| Bip448TransferVerifyError::InvalidStateHistory)?;
    let carried_update_hash = parse_template_hash(&entry.update_template_hash)?;
    let carried_settlement_hash = parse_template_hash(&entry.settlement_template_hash)?;
    if carried_update_hash != update_hash
        || carried_settlement_hash != templates.settlement_template_hash
    {
        return Err(Bip448TransferVerifyError::InvalidStateHistory);
    }

    let signature = schnorr::Signature::from_str(&entry.update_signature)
        .map_err(|_| Bip448TransferVerifyError::InvalidUpdateSignature)?;
    schnorr::verify(
        &signature,
        update_hash.as_byte_array(),
        &aggregate_pubkey.x_only_public_key().0,
    )
    .map_err(|_| Bip448TransferVerifyError::InvalidUpdateSignature)?;

    let client_nonce = parse_public_nonce(&entry.client_public_nonce)?;
    let server_nonce = parse_public_nonce(&entry.server_public_nonce)?;
    let blinding_factor = BlindingFactor::from_slice(
        &hex::decode(&entry.blinding_factor)
            .map_err(|_| Bip448TransferVerifyError::InvalidBlindedChallenge)?,
    )
    .map_err(|_| Bip448TransferVerifyError::InvalidBlindedChallenge)?;
    let signing_session = CsfsSigningSession::new(
        secp,
        CsfsSigningRole::FundingUpdate,
        aggregate_pubkey.clone(),
        &client_nonce,
        &server_nonce,
        update_hash,
        &blinding_factor,
    )
    .map_err(|_| Bip448TransferVerifyError::InvalidBlindedChallenge)?;
    if hex::encode(signing_session.blinded_challenge()) != expected_challenge {
        return Err(Bip448TransferVerifyError::InvalidBlindedChallenge);
    }

    Ok(())
}

fn parse_template_hash(value: &str) -> Result<TemplateHash, Bip448TransferVerifyError> {
    let bytes = hex::decode(value).map_err(|_| Bip448TransferVerifyError::InvalidStateHistory)?;
    TemplateHash::from_slice(&bytes).map_err(|_| Bip448TransferVerifyError::InvalidStateHistory)
}

fn parse_public_nonce(value: &str) -> Result<PublicNonce, Bip448TransferVerifyError> {
    let bytes =
        hex::decode(value).map_err(|_| Bip448TransferVerifyError::InvalidBlindedChallenge)?;
    PublicNonce::from_slice(&bytes).map_err(|_| Bip448TransferVerifyError::InvalidBlindedChallenge)
}

fn transfer_fee_policy(policy: Bip448FeeBumpPolicy) -> bip448_transaction::FeePolicy {
    match policy {
        Bip448FeeBumpPolicy::ZeroFeeEphemeralAnchor => {
            bip448_transaction::FeePolicy::ZeroFeeEphemeralAnchor
        }
    }
}

fn latest_history_matches_state(
    entry: &Bip448StateHistoryEntry,
    latest_state: &Bip448LatestState,
) -> bool {
    entry.state_number == latest_state.state_number
        && entry.state_locktime == latest_state.state_locktime
        && encoded_hex_eq(
            &entry.update_template_hash,
            &latest_state.update_template_hash,
        )
        && encoded_hex_eq(
            &entry.settlement_template_hash,
            &latest_state.settlement_template_hash,
        )
        && encoded_hex_eq(
            &entry.update_signature,
            &latest_state.signing_metadata.update_signature,
        )
        && encoded_hex_eq(
            &entry.client_public_nonce,
            &latest_state.signing_metadata.client_public_nonce,
        )
        && encoded_hex_eq(
            &entry.server_public_nonce,
            &latest_state.signing_metadata.server_public_nonce,
        )
        && encoded_hex_eq(
            &entry.blinding_factor,
            &latest_state.signing_metadata.blinding_factor,
        )
}

fn encoded_hex_eq(left: &str, right: &str) -> bool {
    match (hex::decode(left), hex::decode(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn recovery_finality_error(
    error: bip448_transaction::TransactionTemplateError,
) -> Bip448RecoveryVerifyError {
    match error {
        bip448_transaction::TransactionTemplateError::StateLocktimeNotFinal {
            locktime,
            median_time_past,
        } => Bip448RecoveryVerifyError::StateLocktimeNotFinal {
            locktime,
            median_time_past,
        },
        error => Bip448RecoveryVerifyError::Reconstruction(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip448_statechain::storage::{
        build_funding_latest_state, build_funding_recovery_artifacts, script_hex,
        Bip448AnchorOutput, Bip448CpfpChildTemplate, Bip448CsfsKeyMetadata, Bip448FeeBumpPolicy,
        Bip448RecoveryTemplateRole, Bip448SigningMetadata,
    };
    use crate::bip448_statechain::{script, transaction};
    use crate::transfer::receiver::StatechainInfo;
    use bitcoin::{
        consensus::encode,
        hashes::{sha256, Hash},
        script::Builder,
        OutPoint, ScriptBuf, Transaction, Txid,
    };
    use secp256k1::{
        musig::{new_musig_nonce_pair, MusigSessionId},
        schnorr, KeyPair, Message, PublicKey, Secp256k1, SecretKey,
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    use Bip448TransferVerifyError::*;

    static ECIES_TEST_LOCK: AtomicBool = AtomicBool::new(false);

    #[no_mangle]
    unsafe fn _critical_section_1_0_acquire() {
        while ECIES_TEST_LOCK
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            std::thread::yield_now();
        }
    }

    #[no_mangle]
    unsafe fn _critical_section_1_0_release(_: ()) {
        ECIES_TEST_LOCK.store(false, Ordering::Release);
    }

    const TEST_MEDIAN_TIME_PAST: u32 = 1_900_000_000;
    const TEST_STATE_LOCKTIME: u32 = 999_999_995;

    fn latest_state() -> Bip448LatestState {
        Bip448LatestState {
            state_number: 2,
            state_locktime: TEST_STATE_LOCKTIME,
            challenge_delay: 144,
            update_tx: "02000000".to_string(),
            settlement_tx: "03000000".to_string(),
            update_template_hash: "11".repeat(32),
            settlement_template_hash: "22".repeat(32),
            state_output_script_pubkey: "5120".to_string() + &"33".repeat(32),
            funding_update_script: "51cecbcc".to_string(),
            funding_update_control_block: "c0".to_string() + &"44".repeat(32),
            state_update_script: "b175cecbcc".to_string(),
            state_update_control_block: "c0".to_string() + &"55".repeat(32),
            state_settlement_script: "20".to_string() + &"22".repeat(32) + "ce87",
            state_settlement_control_block: "c0".to_string() + &"66".repeat(32),
            csfs_key_metadata: Bip448CsfsKeyMetadata {
                aggregate_pubkey_parity_odd: false,
                negate_seckey: false,
            },
            signing_metadata: Bip448SigningMetadata {
                role: Bip448RecoveryTemplateRole::StateUpdate,
                signing_id: "77".repeat(32),
                client_public_nonce: "88".repeat(66),
                server_public_nonce: "99".repeat(66),
                blinding_factor: "aa".repeat(32),
                update_template_hash: "11".repeat(32),
                update_signature: "bb".repeat(64),
                server_signature_count: 2,
            },
            fee_bump_policy: Bip448FeeBumpPolicy::ZeroFeeEphemeralAnchor,
            value_schedule: Bip448ValueSchedule {
                funding_value_sats: 100_000,
                update_input_value_sats: 100_000,
                update_state_output_value_sats: 100_000,
                settlement_input_value_sats: 100_000,
                settlement_recovery_output_value_sats: 100_000,
            },
            anchors: vec![Bip448AnchorOutput {
                tx_role: Bip448RecoveryTemplateRole::StateUpdate,
                output_index: 1,
                value_sats: 0,
                script_pubkey: "51024e73".to_string(),
            }],
            cpfp_child_templates: vec![Bip448CpfpChildTemplate {
                parent_role: Bip448RecoveryTemplateRole::StateUpdate,
                anchor_output_index: 1,
                tx_hex: "03000000".to_string(),
                fee_sats: 1_000,
                target_feerate_sat_per_vbyte: Some(10),
            }],
        }
    }

    fn tx_from_hex(tx_hex: &str) -> Transaction {
        encode::deserialize(&hex::decode(tx_hex).unwrap()).unwrap()
    }

    fn aggregate_key() -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_secret_bytes([7u8; 32]).unwrap();
        let aggregate_pubkey = secret_key.public_key(&secp);

        (secret_key, aggregate_pubkey)
    }

    fn recovery_script() -> ScriptBuf {
        Builder::new().push_slice([7u8; 32]).into_script()
    }

    fn outpoint(seed: u8, vout: u32) -> OutPoint {
        OutPoint {
            txid: Txid::from_slice(&[seed; 32]).unwrap(),
            vout,
        }
    }

    fn trusted_outpoint(funding_outpoint: &Bip448FundingOutpoint) -> OutPoint {
        OutPoint {
            txid: Txid::from_str(&funding_outpoint.txid).unwrap(),
            vout: funding_outpoint.vout,
        }
    }

    fn trusted_funding_output(
        secp: &Secp256k1<secp256k1::All>,
        aggregate_pubkey: &PublicKey,
        value: u64,
    ) -> TxOut {
        let spend_info =
            script::funding_spend_info(secp, aggregate_pubkey.x_only_public_key().0).unwrap();
        TxOut {
            value,
            script_pubkey: script::output_script_pubkey(&spend_info),
        }
    }

    fn trusted_recovery_context(
        secp: &Secp256k1<secp256k1::All>,
        funding_outpoint: &Bip448FundingOutpoint,
        receiver_user_pubkey: &PublicKey,
        server_pubkey: &PublicKey,
        recovery_script: &ScriptBuf,
        lockbox_signature_count: u64,
    ) -> Bip448TrustedRecoveryContext {
        let aggregate_pubkey = receiver_user_pubkey.combine(server_pubkey).unwrap();
        Bip448TrustedRecoveryContext::new(
            "statechain",
            Network::Regtest,
            TEST_MEDIAN_TIME_PAST,
            trusted_outpoint(funding_outpoint),
            trusted_funding_output(secp, &aggregate_pubkey, funding_outpoint.value_sats),
            lockbox_signature_count,
            144,
            Bip448FeeBumpPolicy::ZeroFeeEphemeralAnchor,
            receiver_user_pubkey.clone(),
            server_pubkey.clone(),
            recovery_script.clone(),
        )
    }

    struct TransferFixture {
        msg: Bip448TransferMsg,
        info: StatechainInfoResponsePayload,
        facts: Bip448TransferChainFacts,
    }

    #[allow(clippy::too_many_arguments)]
    fn signed_history_state(
        secp: &Secp256k1<secp256k1::All>,
        aggregate_secret: &SecretKey,
        aggregate_pubkey: &PublicKey,
        funding_outpoint: OutPoint,
        funding_value: u64,
        owner_public_key: &PublicKey,
        state_number: u32,
        state_locktime: u32,
    ) -> (Bip448StateHistoryEntry, Bip448LatestState, StatechainInfo) {
        let recovery_script = Address::p2tr(
            secp,
            owner_public_key.x_only_public_key().0,
            None,
            Network::Regtest,
        )
        .script_pubkey();
        let artifacts = build_funding_recovery_artifacts(
            secp,
            aggregate_pubkey,
            funding_outpoint,
            funding_value,
            recovery_script,
            state_number,
            absolute::LockTime::from_consensus(state_locktime),
            DEFAULT_BIP448_CHALLENGE_DELAY,
            Bip448FeeBumpPolicy::ZeroFeeEphemeralAnchor,
        )
        .unwrap();
        let aggregate_keypair = KeyPair::from_secret_key(secp, aggregate_secret);
        let signature = schnorr::sign(
            artifacts.update_template_hash.as_byte_array(),
            &aggregate_keypair,
        );
        let message: Message = artifacts.update_template_hash.into();
        let client_keypair =
            KeyPair::from_secret_key(secp, &SecretKey::from_secret_bytes([3u8; 32]).unwrap());
        let server_keypair =
            KeyPair::from_secret_key(secp, &SecretKey::from_secret_bytes([4u8; 32]).unwrap());
        let (_, client_nonce) = new_musig_nonce_pair(
            secp,
            MusigSessionId::assume_unique_per_nonce_gen([state_number as u8; 32]),
            None,
            Some(client_keypair.secret_key()),
            client_keypair.public_key(),
            Some(message),
            None,
        )
        .unwrap();
        let (_, server_nonce) = new_musig_nonce_pair(
            secp,
            MusigSessionId::assume_unique_per_nonce_gen([state_number as u8 + 10; 32]),
            None,
            Some(server_keypair.secret_key()),
            server_keypair.public_key(),
            Some(message),
            None,
        )
        .unwrap();
        let blinding_factor = BlindingFactor::from_slice(&[state_number as u8 + 20; 32]).unwrap();
        let session = CsfsSigningSession::new(
            secp,
            CsfsSigningRole::FundingUpdate,
            aggregate_pubkey.clone(),
            &client_nonce,
            &server_nonce,
            artifacts.update_template_hash,
            &blinding_factor,
        )
        .unwrap();
        let metadata = Bip448SigningMetadata {
            role: Bip448RecoveryTemplateRole::FundingUpdate,
            signing_id: hex::encode([state_number as u8; 32]),
            client_public_nonce: hex::encode(client_nonce.serialize()),
            server_public_nonce: hex::encode(server_nonce.serialize()),
            blinding_factor: hex::encode(blinding_factor.as_bytes()),
            update_template_hash: hex::encode(artifacts.update_template_hash.to_byte_array()),
            update_signature: signature.to_string(),
            server_signature_count: u64::from(state_number),
        };
        let latest = build_funding_latest_state(
            secp,
            aggregate_pubkey,
            &artifacts,
            metadata.clone(),
            Vec::new(),
        )
        .unwrap();
        let entry = Bip448StateHistoryEntry {
            state_number,
            state_locktime,
            owner_public_key: owner_public_key.x_only_public_key().0.to_string(),
            update_template_hash: latest.update_template_hash.clone(),
            settlement_template_hash: latest.settlement_template_hash.clone(),
            update_signature: metadata.update_signature,
            client_public_nonce: metadata.client_public_nonce,
            server_public_nonce: metadata.server_public_nonce.clone(),
            blinding_factor: metadata.blinding_factor,
        };
        let info = StatechainInfo {
            statechain_id: "statechain".to_string(),
            server_pubnonce: metadata.server_public_nonce,
            challenge: hex::encode(session.blinded_challenge()),
            tx_n: state_number,
        };
        (entry, latest, info)
    }

    fn transfer_fixture() -> TransferFixture {
        transfer_fixture_with_locktimes(TEST_STATE_LOCKTIME, TEST_STATE_LOCKTIME + 10)
    }

    fn transfer_fixture_with_locktimes(
        state1_locktime: u32,
        state2_locktime: u32,
    ) -> TransferFixture {
        transfer_fixture_with_history(&[state1_locktime, state2_locktime], 3, 4, 5, 6, &[3, 5])
    }

    fn three_state_transfer_fixture() -> TransferFixture {
        transfer_fixture_with_history(
            &[
                TEST_STATE_LOCKTIME,
                TEST_STATE_LOCKTIME + 10,
                TEST_STATE_LOCKTIME + 20,
            ],
            5,
            2,
            6,
            4,
            &[3, 5, 6],
        )
    }

    fn four_state_transfer_fixture() -> TransferFixture {
        transfer_fixture_with_history(
            &[
                TEST_STATE_LOCKTIME,
                TEST_STATE_LOCKTIME + 10,
                TEST_STATE_LOCKTIME + 20,
                TEST_STATE_LOCKTIME + 30,
            ],
            5,
            2,
            6,
            4,
            &[3, 8, 5, 6],
        )
    }

    fn three_state_transfer_fixture_with_last_stride(last_stride: u32) -> TransferFixture {
        transfer_fixture_with_history(
            &[
                TEST_STATE_LOCKTIME,
                TEST_STATE_LOCKTIME + 10,
                TEST_STATE_LOCKTIME + 10 + last_stride,
            ],
            5,
            2,
            6,
            4,
            &[3, 5, 6],
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn transfer_fixture_with_history(
        state_locktimes: &[u32],
        sender_seed: u8,
        server_seed: u8,
        receiver_seed: u8,
        x1_seed: u8,
        owner_seeds: &[u8],
    ) -> TransferFixture {
        assert_eq!(state_locktimes.len(), owner_seeds.len());
        let secp = Secp256k1::new();
        let sender_secret = SecretKey::from_secret_bytes([sender_seed; 32]).unwrap();
        let server_secret = SecretKey::from_secret_bytes([server_seed; 32]).unwrap();
        let receiver_secret = SecretKey::from_secret_bytes([receiver_seed; 32]).unwrap();
        let x1_secret = SecretKey::from_secret_bytes([x1_seed; 32]).unwrap();
        let aggregate_secret = SecretKey::from_secret_bytes([7u8; 32]).unwrap();
        let sender_pubkey = sender_secret.public_key(&secp);
        let server_pubkey = server_secret.public_key(&secp);
        let receiver_pubkey = receiver_secret.public_key(&secp);
        let aggregate_pubkey = aggregate_secret.public_key(&secp);
        assert_eq!(
            sender_pubkey.combine(&server_pubkey).unwrap(),
            aggregate_pubkey
        );
        let funding_outpoint = outpoint(0x42, 0);
        let funding_value = 100_000;
        let mut state_history = Vec::new();
        let mut signing_rows = Vec::new();
        let mut latest_state = None;
        for (index, (&state_locktime, &owner_seed)) in
            state_locktimes.iter().zip(owner_seeds).enumerate()
        {
            let owner_public_key = SecretKey::from_secret_bytes([owner_seed; 32])
                .unwrap()
                .public_key(&secp);
            let state_number = index as u32 + 1;
            let (entry, state, signing_row) = signed_history_state(
                &secp,
                &aggregate_secret,
                &aggregate_pubkey,
                funding_outpoint,
                funding_value,
                &owner_public_key,
                state_number,
                state_locktime,
            );
            state_history.push(entry);
            signing_rows.push(signing_row);
            latest_state = Some(state);
        }
        let latest_state = latest_state.unwrap();
        let latest_state_number = state_locktimes.len() as u32;
        let mut authorization_data = Vec::new();
        authorization_data.extend_from_slice(&funding_outpoint.txid[..]);
        authorization_data.extend_from_slice(&funding_outpoint.vout.to_le_bytes());
        authorization_data.extend_from_slice(&receiver_pubkey.serialize());
        let authorization_message = sha256::Hash::hash(&authorization_data).to_byte_array();
        let transfer_signature = schnorr::sign(
            &authorization_message,
            &KeyPair::from_secret_key(&secp, &sender_secret),
        );
        let funding_output = TxOut {
            value: funding_value,
            script_pubkey: script::output_script_pubkey(
                &script::funding_spend_info(&secp, aggregate_pubkey.x_only_public_key().0).unwrap(),
            ),
        };
        let msg = Bip448TransferMsg {
            msg_version: 2,
            statechain_id: "statechain".to_string(),
            transfer_signature: transfer_signature.to_string(),
            sender_user_public_key: sender_pubkey.to_string(),
            receiver_user_public_key: receiver_pubkey.to_string(),
            server_public_key: server_pubkey.to_string(),
            aggregate_pubkey: aggregate_pubkey.to_string(),
            funding_outpoint: Bip448FundingOutpoint {
                txid: funding_outpoint.txid.to_string(),
                vout: funding_outpoint.vout,
                value_sats: funding_value,
            },
            latest_state_number,
            challenge_delay: DEFAULT_BIP448_CHALLENGE_DELAY,
            amount_sats: funding_value,
            network: Network::Regtest.to_string(),
            value_schedule: latest_state.value_schedule.clone(),
            server_signature_count: u64::from(latest_state_number),
            latest_state,
            t1: SecretKey::from_secret_bytes([9u8; 32])
                .unwrap()
                .to_secret_bytes(),
            state_history,
        };
        TransferFixture {
            msg,
            info: StatechainInfoResponsePayload {
                enclave_public_key: server_pubkey.to_string(),
                num_sigs: latest_state_number,
                statechain_info: signing_rows,
                x1_pub: Some(x1_secret.public_key(&secp).to_string()),
            },
            facts: Bip448TransferChainFacts {
                expected_network: Network::Regtest,
                median_time_past: TEST_MEDIAN_TIME_PAST,
                funding_outpoint,
                funding_output,
                tx0_confirmed: true,
                tx0_unspent: true,
                receiver_user_pubkey: receiver_pubkey,
            },
        }
    }

    fn transfer_error(fixture: &TransferFixture) -> Bip448TransferVerifyError {
        verify_bip448_transfer_msg(&fixture.msg, &fixture.info, &fixture.facts).unwrap_err()
    }

    #[test]
    fn transfer_message_serialization_round_trips_without_legacy_backups() {
        let latest_state = latest_state();
        let msg = Bip448TransferMsg {
            msg_version: 2,
            statechain_id: "statechain".to_string(),
            transfer_signature: "ab".repeat(64),
            sender_user_public_key: "02".to_string() + &"12".repeat(32),
            receiver_user_public_key: "03".to_string() + &"13".repeat(32),
            server_public_key: "02".to_string() + &"14".repeat(32),
            aggregate_pubkey: "02".to_string() + &"15".repeat(32),
            funding_outpoint: Bip448FundingOutpoint {
                txid: "44".repeat(32),
                vout: 1,
                value_sats: 100_000,
            },
            latest_state_number: latest_state.state_number,
            challenge_delay: latest_state.challenge_delay,
            amount_sats: 100_000,
            network: "regtest".to_string(),
            value_schedule: latest_state.value_schedule.clone(),
            latest_state,
            server_signature_count: 2,
            t1: [9u8; 32],
            state_history: Vec::new(),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let roundtrip: Bip448TransferMsg = serde_json::from_str(&json).unwrap();

        assert_eq!(roundtrip, msg);
        assert!(json.contains("msg_version"));
        assert!(json.contains("state_history"));
        assert!(json.contains("latest_state"));
        assert!(!json.contains("backup_transactions"));
    }

    #[test]
    fn transfer_message_ecies_round_trips() {
        let secp = Secp256k1::new();
        let auth_secret = SecretKey::from_secret_bytes([42u8; 32]).unwrap();
        let auth_public = auth_secret.public_key(&secp);
        let auth_wif = PrivateKey::new(auth_secret, Network::Regtest).to_wif();
        let msg = transfer_fixture().msg;

        let encrypted = msg.encrypt(&auth_public).unwrap();
        let decrypted = decrypt_bip448_transfer_msg(&encrypted, &auth_wif).unwrap();

        assert_eq!(decrypted, msg);
    }

    #[test]
    fn transfer_message_contains_reconstructible_templates_and_committed_anchors() {
        const INPUT_AMOUNT: u64 = 100_000;
        const STATE_NUMBER: u32 = 1;
        const CHALLENGE_DELAY: u16 = 144;

        let secp = Secp256k1::new();
        let (aggregate_secret, aggregate_pubkey) = aggregate_key();
        let aggregate_xonly = aggregate_pubkey.x_only_public_key().0;
        let (latest_state, funding_outpoint, recovery_script) =
            reconstructible_latest_state(&secp, &aggregate_secret, &aggregate_pubkey);
        let msg = Bip448TransferMsg {
            msg_version: 2,
            statechain_id: "statechain".to_string(),
            transfer_signature: "ab".repeat(64),
            sender_user_public_key: "02".to_string() + &"12".repeat(32),
            receiver_user_public_key: "03".to_string() + &"13".repeat(32),
            server_public_key: "02".to_string() + &"14".repeat(32),
            aggregate_pubkey: aggregate_pubkey.to_string(),
            funding_outpoint,
            latest_state_number: STATE_NUMBER,
            challenge_delay: CHALLENGE_DELAY,
            amount_sats: INPUT_AMOUNT,
            network: "regtest".to_string(),
            value_schedule: latest_state.value_schedule.clone(),
            latest_state,
            server_signature_count: 1,
            t1: [9u8; 32],
            state_history: Vec::new(),
        };

        let encoded = serde_json::to_string(&msg).unwrap();
        let decoded: Bip448TransferMsg = serde_json::from_str(&encoded).unwrap();
        let stored_update_tx = tx_from_hex(&decoded.latest_state.update_tx);
        let stored_settlement_tx = tx_from_hex(&decoded.latest_state.settlement_tx);
        let settlement_hash = transaction::validate_state_template_set(
            &secp,
            aggregate_xonly,
            decoded.latest_state_number,
            absolute::LockTime::from_consensus(decoded.latest_state.state_locktime),
            decoded.value_schedule.update_input_value_sats,
            &recovery_script,
            decoded.challenge_delay,
            transaction::FeePolicy::ZeroFeeEphemeralAnchor,
            &stored_update_tx,
            &stored_settlement_tx,
        )
        .unwrap();
        assert_eq!(
            decoded.latest_state.settlement_template_hash,
            hex::encode(settlement_hash.to_byte_array())
        );

        let update_anchor = decoded
            .latest_state
            .anchors
            .iter()
            .find(|anchor| anchor.tx_role == Bip448RecoveryTemplateRole::FundingUpdate)
            .unwrap();
        assert_eq!(update_anchor.output_index, 1);
        assert_eq!(
            update_anchor.script_pubkey,
            script_hex(&stored_update_tx.output[1].script_pubkey)
        );
        assert_eq!(update_anchor.value_sats, stored_update_tx.output[1].value);

        let settlement_anchor = decoded
            .latest_state
            .anchors
            .iter()
            .find(|anchor| anchor.tx_role == Bip448RecoveryTemplateRole::Settlement)
            .unwrap();
        assert_eq!(settlement_anchor.output_index, 1);
        assert_eq!(
            settlement_anchor.script_pubkey,
            script_hex(&stored_settlement_tx.output[1].script_pubkey)
        );
        assert_eq!(
            settlement_anchor.value_sats,
            stored_settlement_tx.output[1].value
        );
    }

    /// Two keys that sum to a known aggregate secret, so the test can produce a
    /// real BIP340 signature under `P.x` while exercising the receiver's
    /// recompute-`P`-from-parties check. Returns
    /// `(aggregate_secret, aggregate_pub, user_pub, server_pub)` with
    /// `user_pub + server_pub == aggregate_pub`.
    fn recovery_keys(
        secp: &Secp256k1<secp256k1::All>,
    ) -> (SecretKey, PublicKey, PublicKey, PublicKey) {
        let aggregate_secret = SecretKey::from_secret_bytes([7u8; 32]).unwrap();
        let aggregate_pub = aggregate_secret.public_key(secp);
        let server_secret = SecretKey::from_secret_bytes([4u8; 32]).unwrap();
        let server_pub = server_secret.public_key(secp);
        let user_pub = aggregate_pub.combine(&server_pub.negate()).unwrap();

        (aggregate_secret, aggregate_pub, user_pub, server_pub)
    }

    #[test]
    fn verify_recovery_binds_aggregate_key_and_update_signature() {
        let secp = Secp256k1::new();
        let (aggregate_secret, aggregate_pub, user_pub, server_pub) = recovery_keys(&secp);

        // Sign the real update template hash with the aggregate key, so the
        // stored update_signature actually verifies under P.x.
        let mut latest = latest_state();
        let template_hash: [u8; 32] = hex::decode(&latest.update_template_hash)
            .unwrap()
            .try_into()
            .unwrap();
        let keypair = KeyPair::from_secret_key(&secp, &aggregate_secret);
        latest.signing_metadata.update_signature =
            schnorr::sign(&template_hash, &keypair).to_string();
        latest.csfs_key_metadata =
            Bip448CsfsKeyMetadata::from_aggregate_pubkey(&secp, &aggregate_pub);

        let msg = Bip448TransferMsg {
            msg_version: 2,
            statechain_id: "statechain".to_string(),
            transfer_signature: "ab".repeat(64),
            sender_user_public_key: "02".to_string() + &"12".repeat(32),
            receiver_user_public_key: user_pub.to_string(),
            server_public_key: server_pub.to_string(),
            aggregate_pubkey: aggregate_pub.to_string(),
            funding_outpoint: Bip448FundingOutpoint {
                txid: "44".repeat(32),
                vout: 1,
                value_sats: 100_000,
            },
            latest_state_number: latest.state_number,
            challenge_delay: latest.challenge_delay,
            amount_sats: 100_000,
            network: "regtest".to_string(),
            value_schedule: latest.value_schedule.clone(),
            server_signature_count: latest.signing_metadata.server_signature_count,
            latest_state: latest,
            t1: [9u8; 32],
            state_history: Vec::new(),
        };

        // Binds to the recomputed aggregate P = user_pub + server_pub and
        // verifies the real update signature against P.x.
        assert_eq!(
            msg.verify_recovery_against_keys(&secp, &user_pub, &server_pub)
                .unwrap(),
            aggregate_pub
        );

        let mut wrong_receiver_field = msg.clone();
        wrong_receiver_field.receiver_user_public_key = server_pub.to_string();
        assert_eq!(
            wrong_receiver_field.verify_recovery_against_keys(&secp, &user_pub, &server_pub),
            Err(Bip448RecoveryVerifyError::TrustedFieldMismatch(
                "receiver_user_public_key"
            ))
        );

        let mut wrong_server_field = msg.clone();
        wrong_server_field.server_public_key = user_pub.to_string();
        assert_eq!(
            wrong_server_field.verify_recovery_against_keys(&secp, &user_pub, &server_pub),
            Err(Bip448RecoveryVerifyError::TrustedFieldMismatch(
                "server_public_key"
            ))
        );

        // Even an alternate encoding of the same curve point is rejected so
        // downstream code cannot observe non-canonical sender-controlled text.
        let alternate_receiver_encoding = hex::encode(user_pub.serialize_uncompressed());
        assert_eq!(
            PublicKey::from_str(&alternate_receiver_encoding).unwrap(),
            user_pub
        );
        let mut noncanonical_receiver = msg.clone();
        noncanonical_receiver.receiver_user_public_key = alternate_receiver_encoding;
        assert_eq!(
            noncanonical_receiver.verify_recovery_against_keys(&secp, &user_pub, &server_pub),
            Err(Bip448RecoveryVerifyError::TrustedFieldMismatch(
                "receiver_user_public_key"
            ))
        );

        // A substituted aggregate_pubkey in the (sender-controlled) message is
        // rejected against the receiver's recomputed P.
        let mut wrong_aggregate = msg.clone();
        wrong_aggregate.aggregate_pubkey = server_pub.to_string();
        assert_eq!(
            wrong_aggregate.verify_recovery_against_keys(&secp, &user_pub, &server_pub),
            Err(Bip448RecoveryVerifyError::AggregateKeyMismatch)
        );

        let mut noncanonical_aggregate = msg.clone();
        noncanonical_aggregate.aggregate_pubkey =
            hex::encode(aggregate_pub.serialize_uncompressed());
        assert_eq!(
            noncanonical_aggregate.verify_recovery_against_keys(&secp, &user_pub, &server_pub),
            Err(Bip448RecoveryVerifyError::AggregateKeyMismatch)
        );

        // A trusted server parameter that disagrees with the message is rejected
        // before any downstream consumer can read the duplicated field.
        assert_eq!(
            msg.verify_recovery_against_keys(&secp, &user_pub, &user_pub),
            Err(Bip448RecoveryVerifyError::TrustedFieldMismatch(
                "server_public_key"
            ))
        );

        // A corrupted update signature does not verify against P.x.
        let mut bad_signature = msg.clone();
        bad_signature.latest_state.signing_metadata.update_signature = "cc".repeat(64);
        assert_eq!(
            bad_signature.verify_recovery_against_keys(&secp, &user_pub, &server_pub),
            Err(Bip448RecoveryVerifyError::UpdateSignatureVerification)
        );

        // An inconsistent top-level convenience field is rejected before the
        // crypto checks run.
        let mut inconsistent = msg.clone();
        inconsistent.server_signature_count += 1;
        assert_eq!(
            inconsistent.verify_recovery_against_keys(&secp, &user_pub, &server_pub),
            Err(Bip448RecoveryVerifyError::InconsistentField(
                "server_signature_count"
            ))
        );
    }

    /// Builds a fully reconstructible latest state for `aggregate_pubkey`, plus
    /// the funding outpoint and receiver recovery script it was built from — the
    /// exact trusted inputs a receiver would supply to the reconstruction check.
    fn reconstructible_latest_state(
        secp: &Secp256k1<secp256k1::All>,
        aggregate_secret: &SecretKey,
        aggregate_pubkey: &PublicKey,
    ) -> (Bip448LatestState, Bip448FundingOutpoint, ScriptBuf) {
        reconstructible_latest_state_at(
            secp,
            aggregate_secret,
            aggregate_pubkey,
            1,
            TEST_STATE_LOCKTIME,
        )
    }

    fn reconstructible_latest_state_at(
        secp: &Secp256k1<secp256k1::All>,
        aggregate_secret: &SecretKey,
        aggregate_pubkey: &PublicKey,
        state_number: u32,
        state_locktime: u32,
    ) -> (Bip448LatestState, Bip448FundingOutpoint, ScriptBuf) {
        const INPUT_AMOUNT: u64 = 100_000;
        const CHALLENGE_DELAY: u16 = 144;

        let funding_outpoint = outpoint(0x11, 0);
        let recovery_script = recovery_script();
        let artifacts = build_funding_recovery_artifacts(
            secp,
            aggregate_pubkey,
            funding_outpoint,
            INPUT_AMOUNT,
            recovery_script.clone(),
            state_number,
            absolute::LockTime::from_consensus(state_locktime),
            CHALLENGE_DELAY,
            Bip448FeeBumpPolicy::ZeroFeeEphemeralAnchor,
        )
        .unwrap();
        let keypair = KeyPair::from_secret_key(secp, aggregate_secret);
        let signature = schnorr::sign(&artifacts.update_template_hash.to_byte_array(), &keypair);
        let update_template_hash = hex::encode(artifacts.update_template_hash.to_byte_array());
        let update_signature = signature.to_string();
        let latest_state = build_funding_latest_state(
            secp,
            aggregate_pubkey,
            &artifacts,
            Bip448SigningMetadata {
                role: Bip448RecoveryTemplateRole::FundingUpdate,
                signing_id: "77".repeat(32),
                client_public_nonce: "88".repeat(66),
                server_public_nonce: "99".repeat(66),
                blinding_factor: "aa".repeat(32),
                update_template_hash: update_template_hash.to_uppercase(),
                update_signature: update_signature.to_uppercase(),
                server_signature_count: u64::from(state_number),
            },
            Vec::new(),
        )
        .unwrap();
        assert_eq!(
            latest_state.signing_metadata.update_template_hash,
            update_template_hash
        );
        assert_eq!(
            latest_state.signing_metadata.update_signature,
            update_signature
        );

        let funding_outpoint = Bip448FundingOutpoint {
            txid: funding_outpoint.txid.to_string(),
            vout: funding_outpoint.vout,
            value_sats: INPUT_AMOUNT,
        };

        (latest_state, funding_outpoint, recovery_script)
    }

    fn uppercase_recovery_hex(state: &mut Bip448LatestState) {
        state.update_tx.make_ascii_uppercase();
        state.settlement_tx.make_ascii_uppercase();
        state.update_template_hash.make_ascii_uppercase();
        state.settlement_template_hash.make_ascii_uppercase();
        state.state_output_script_pubkey.make_ascii_uppercase();
        state.funding_update_script.make_ascii_uppercase();
        state.funding_update_control_block.make_ascii_uppercase();
        state.state_update_script.make_ascii_uppercase();
        state.state_update_control_block.make_ascii_uppercase();
        state.state_settlement_script.make_ascii_uppercase();
        state.state_settlement_control_block.make_ascii_uppercase();
        state
            .signing_metadata
            .update_template_hash
            .make_ascii_uppercase();
        state
            .signing_metadata
            .update_signature
            .make_ascii_uppercase();
        for anchor in &mut state.anchors {
            anchor.script_pubkey.make_ascii_uppercase();
        }
    }

    #[test]
    fn verify_reconstructed_templates_rejects_every_tampered_field() {
        let secp = Secp256k1::new();
        let (aggregate_secret, aggregate_pub, _, _) = recovery_keys(&secp);
        let (state, funding_outpoint, recovery_script) =
            reconstructible_latest_state(&secp, &aggregate_secret, &aggregate_pub);
        let chain_outpoint = trusted_outpoint(&funding_outpoint);
        let chain_output =
            trusted_funding_output(&secp, &aggregate_pub, funding_outpoint.value_sats);

        // A faithful record recomputes to itself and is accepted.
        state
            .verify_reconstructed_templates(
                &secp,
                &aggregate_pub,
                chain_outpoint,
                &chain_output,
                &recovery_script,
            )
            .unwrap();

        // Locktime seeds reconstruction, so changing it invalidates the
        // signature over the reconstructed update template before comparison.
        let mut tampered_locktime = state.clone();
        tampered_locktime.state_locktime += 1;
        assert_eq!(
            tampered_locktime.verify_reconstructed_templates(
                &secp,
                &aggregate_pub,
                chain_outpoint,
                &chain_output,
                &recovery_script,
            ),
            Err(Bip448RecoveryVerifyError::UpdateSignatureVerification)
        );

        // Every sender-copy field is projected into one canonical derived-state
        // value, so tampering with any copy makes the struct comparison fail.
        let cases: [(&'static str, fn(&mut Bip448LatestState)); 13] = [
            ("update_tx", |s| s.update_tx = "00".to_string()),
            ("settlement_tx", |s| s.settlement_tx = "00".to_string()),
            ("update_template_hash", |s| {
                s.update_template_hash = "00".repeat(32)
            }),
            ("settlement_template_hash", |s| {
                s.settlement_template_hash = "00".repeat(32)
            }),
            ("state_output_script_pubkey", |s| {
                s.state_output_script_pubkey = "00".to_string()
            }),
            ("funding_update_script", |s| {
                s.funding_update_script = "00".to_string()
            }),
            ("funding_update_control_block", |s| {
                s.funding_update_control_block = "00".to_string()
            }),
            ("state_update_script", |s| {
                s.state_update_script = "00".to_string()
            }),
            ("state_update_control_block", |s| {
                s.state_update_control_block = "00".to_string()
            }),
            ("state_settlement_script", |s| {
                s.state_settlement_script = "00".to_string()
            }),
            ("state_settlement_control_block", |s| {
                s.state_settlement_control_block = "00".to_string()
            }),
            // Compared but not used as a reconstruction input, so the templates
            // still recompute cleanly and the value-schedule check is what fires.
            ("value_schedule", |s| {
                s.value_schedule.funding_value_sats += 1
            }),
            ("anchors", |s| s.anchors[0].value_sats += 1),
        ];

        for (field, tamper) in cases {
            let mut tampered = state.clone();
            tamper(&mut tampered);
            assert_eq!(
                tampered.verify_reconstructed_templates(
                    &secp,
                    &aggregate_pub,
                    chain_outpoint,
                    &chain_output,
                    &recovery_script,
                ),
                Err(Bip448RecoveryVerifyError::TemplateFieldMismatch(
                    "derived_latest_state"
                )),
                "tampering `{field}` must be rejected"
            );
        }

        let mut out_of_range_locktime = state.clone();
        out_of_range_locktime.state_locktime = script::INITIAL_STATE_LOCKTIME_MAX + 1;
        assert!(matches!(
            out_of_range_locktime.verify_reconstructed_templates(
                &secp,
                &aggregate_pub,
                chain_outpoint,
                &chain_output,
                &recovery_script,
            ),
            Err(Bip448RecoveryVerifyError::Reconstruction(_))
        ));

        let mut later_state_without_history = state.clone();
        later_state_without_history.state_number = 2;
        later_state_without_history
            .signing_metadata
            .server_signature_count = 2;
        assert_eq!(
            later_state_without_history.verify_reconstructed_templates(
                &secp,
                &aggregate_pub,
                chain_outpoint,
                &chain_output,
                &recovery_script,
            ),
            Err(Bip448RecoveryVerifyError::UnsupportedInitialStateNumber { state_number: 2 })
        );

        let mut unverified_cpfp = state.clone();
        unverified_cpfp
            .cpfp_child_templates
            .push(Bip448CpfpChildTemplate {
                parent_role: Bip448RecoveryTemplateRole::FundingUpdate,
                anchor_output_index: 1,
                tx_hex: "03000000".to_string(),
                fee_sats: 1_000,
                target_feerate_sat_per_vbyte: Some(10),
            });
        assert_eq!(
            unverified_cpfp.verify_reconstructed_templates(
                &secp,
                &aggregate_pub,
                chain_outpoint,
                &chain_output,
                &recovery_script,
            ),
            Err(Bip448RecoveryVerifyError::UnverifiedSenderMetadata(
                "cpfp_child_templates"
            ))
        );

        let mut unsupported_state_update = state.clone();
        unsupported_state_update.signing_metadata.role = Bip448RecoveryTemplateRole::StateUpdate;
        assert_eq!(
            unsupported_state_update.verify_reconstructed_templates(
                &secp,
                &aggregate_pub,
                chain_outpoint,
                &chain_output,
                &recovery_script,
            ),
            Err(Bip448RecoveryVerifyError::UnsupportedRecoveryRole(
                Bip448RecoveryTemplateRole::StateUpdate
            ))
        );

        let mut inconsistent_settlement = state.clone();
        inconsistent_settlement.signing_metadata.role = Bip448RecoveryTemplateRole::Settlement;
        assert_eq!(
            inconsistent_settlement.verify_reconstructed_templates(
                &secp,
                &aggregate_pub,
                chain_outpoint,
                &chain_output,
                &recovery_script,
            ),
            Err(Bip448RecoveryVerifyError::InconsistentField(
                "signing_metadata.role"
            ))
        );

        // The receiver's own recovery script is a trust anchor: reconstructing
        // against a different script yields different templates, so the record is
        // rejected rather than silently accepted.
        let wrong_recovery_script = Builder::new().push_slice([9u8; 32]).into_script();
        assert_eq!(
            state.verify_reconstructed_templates(
                &secp,
                &aggregate_pub,
                chain_outpoint,
                &chain_output,
                &wrong_recovery_script,
            ),
            Err(Bip448RecoveryVerifyError::UpdateSignatureVerification)
        );

        let mut wrong_funding_output = chain_output.clone();
        wrong_funding_output.value += 1;
        assert_eq!(
            state.verify_reconstructed_templates(
                &secp,
                &aggregate_pub,
                chain_outpoint,
                &wrong_funding_output,
                &recovery_script,
            ),
            Err(Bip448RecoveryVerifyError::UpdateSignatureVerification)
        );

        let mut wrong_funding_script = chain_output;
        wrong_funding_script.script_pubkey = Builder::new().push_int(1).into_script();
        assert_eq!(
            state.verify_reconstructed_templates(
                &secp,
                &aggregate_pub,
                chain_outpoint,
                &wrong_funding_script,
                &recovery_script,
            ),
            Err(Bip448RecoveryVerifyError::TrustedFieldMismatch(
                "funding_output.script_pubkey"
            ))
        );
    }

    #[test]
    fn verify_recovery_state_uses_trusted_context_and_rejects_tampering() {
        let secp = Secp256k1::new();
        let (aggregate_secret, aggregate_pub, user_pub, server_pub) = recovery_keys(&secp);
        let (latest, funding_outpoint, recovery_script) =
            reconstructible_latest_state(&secp, &aggregate_secret, &aggregate_pub);

        let msg = Bip448TransferMsg {
            msg_version: 2,
            statechain_id: "statechain".to_string(),
            transfer_signature: "ab".repeat(64),
            sender_user_public_key: "02".to_string() + &"12".repeat(32),
            receiver_user_public_key: user_pub.to_string(),
            server_public_key: server_pub.to_string(),
            aggregate_pubkey: aggregate_pub.to_string(),
            funding_outpoint: funding_outpoint.clone(),
            latest_state_number: latest.state_number,
            challenge_delay: latest.challenge_delay,
            amount_sats: funding_outpoint.value_sats,
            network: "regtest".to_string(),
            value_schedule: latest.value_schedule.clone(),
            server_signature_count: latest.signing_metadata.server_signature_count,
            latest_state: latest,
            t1: [9u8; 32],
            state_history: Vec::new(),
        };
        let trusted = trusted_recovery_context(
            &secp,
            &funding_outpoint,
            &user_pub,
            &server_pub,
            &recovery_script,
            msg.server_signature_count,
        );

        // The recovery-state check binds keys + signature and every reconstructed
        // field to independently supplied chain/network/lockbox facts.
        let verified = msg.verify_recovery_state(&secp, &trusted).unwrap();
        assert_eq!(verified.aggregate_pubkey(), &aggregate_pub);
        assert_eq!(verified.canonical_latest_state(), &msg.latest_state);
        assert_eq!(
            verified.canonical_latest_state().state_locktime,
            TEST_STATE_LOCKTIME
        );

        // A tampered template field is rejected by the combined check even though
        // the aggregate-key binding and update signature are still valid.
        let mut tampered = msg.clone();
        tampered.latest_state.state_output_script_pubkey = "00".to_string();
        assert_eq!(
            tampered.verify_recovery_state(&secp, &trusted),
            Err(Bip448RecoveryVerifyError::TemplateFieldMismatch(
                "derived_latest_state"
            ))
        );

        // Passing the wrong receiver recovery script is rejected.
        let mut wrong_recovery_context = trusted.clone();
        wrong_recovery_context.recovery_script = Builder::new().push_slice([9u8; 32]).into_script();
        assert_eq!(
            msg.verify_recovery_state(&secp, &wrong_recovery_context),
            Err(Bip448RecoveryVerifyError::UpdateSignatureVerification)
        );

        let mut wrong_amount = msg.clone();
        wrong_amount.amount_sats += 1;
        assert_eq!(
            wrong_amount.verify_recovery_state(&secp, &trusted),
            Err(Bip448RecoveryVerifyError::TrustedFieldMismatch(
                "amount_sats"
            ))
        );

        let mut wrong_funding_value = msg.clone();
        wrong_funding_value.funding_outpoint.value_sats += 1;
        wrong_funding_value.amount_sats = wrong_funding_value.funding_outpoint.value_sats;
        assert_eq!(
            wrong_funding_value.verify_recovery_state(&secp, &trusted),
            Err(Bip448RecoveryVerifyError::TrustedFieldMismatch(
                "funding_outpoint.value_sats"
            ))
        );

        // Even a sender-self-consistent fabricated amount is rejected against
        // the independently queried chain value before reconstruction.
        let mut fabricated_amount = msg.clone();
        let fabricated_value = funding_outpoint.value_sats * 100;
        fabricated_amount.amount_sats = fabricated_value;
        fabricated_amount.funding_outpoint.value_sats = fabricated_value;
        fabricated_amount.value_schedule.funding_value_sats = fabricated_value;
        fabricated_amount.value_schedule.update_input_value_sats = fabricated_value;
        fabricated_amount.latest_state.value_schedule = fabricated_amount.value_schedule.clone();
        assert_eq!(
            fabricated_amount.verify_recovery_state(&secp, &trusted),
            Err(Bip448RecoveryVerifyError::TrustedFieldMismatch(
                "funding_outpoint.value_sats"
            ))
        );

        let mut stale_context = trusted.clone();
        stale_context.lockbox_signature_count += 1;
        assert_eq!(
            msg.verify_recovery_state(&secp, &stale_context),
            Err(Bip448RecoveryVerifyError::TrustedFieldMismatch(
                "server_signature_count"
            ))
        );

        // Sender-reported counters are not receipts. Relabeling an older signed
        // state with the current count is rejected because the signed state
        // number must itself equal the lockbox count.
        let mut relabeled_old_state = msg.clone();
        relabeled_old_state.server_signature_count += 1;
        relabeled_old_state
            .latest_state
            .signing_metadata
            .server_signature_count += 1;
        let mut current_count = trusted.clone();
        current_count.lockbox_signature_count += 1;
        assert_eq!(
            relabeled_old_state.verify_recovery_state(&secp, &current_count),
            Err(Bip448RecoveryVerifyError::TrustedFieldMismatch(
                "latest_state_number"
            ))
        );

        // Once locktime is independent, changing every sender/count copy could
        // otherwise relabel the same signed candidate as a later logical state.
        // Phase 6 verifies only the initial funding state until Phase 8 supplies
        // complete verified history.
        let mut coordinated_relabel = msg.clone();
        coordinated_relabel.latest_state_number = 2;
        coordinated_relabel.latest_state.state_number = 2;
        coordinated_relabel.server_signature_count = 2;
        coordinated_relabel
            .latest_state
            .signing_metadata
            .server_signature_count = 2;
        let mut count_two = trusted.clone();
        count_two.lockbox_signature_count = 2;
        assert_eq!(
            coordinated_relabel.verify_recovery_state(&secp, &count_two),
            Err(Bip448RecoveryVerifyError::UnsupportedInitialStateNumber { state_number: 2 })
        );

        let mut wrong_delay = msg.clone();
        wrong_delay.challenge_delay += 1;
        wrong_delay.latest_state.challenge_delay = wrong_delay.challenge_delay;
        assert_eq!(
            wrong_delay.verify_recovery_state(&secp, &trusted),
            Err(Bip448RecoveryVerifyError::TrustedFieldMismatch(
                "challenge_delay"
            ))
        );

        let mut wrong_network = msg.clone();
        wrong_network.network = "testnet".to_string();
        assert_eq!(
            wrong_network.verify_recovery_state(&secp, &trusted),
            Err(Bip448RecoveryVerifyError::TrustedFieldMismatch("network"))
        );

        let mut wrong_statechain = msg.clone();
        wrong_statechain.statechain_id = "other-statechain".to_string();
        assert_eq!(
            wrong_statechain.verify_recovery_state(&secp, &trusted),
            Err(Bip448RecoveryVerifyError::TrustedFieldMismatch(
                "statechain_id"
            ))
        );

        let mut wrong_outpoint = msg.clone();
        wrong_outpoint.funding_outpoint.vout += 1;
        assert_eq!(
            wrong_outpoint.verify_recovery_state(&secp, &trusted),
            Err(Bip448RecoveryVerifyError::TrustedFieldMismatch(
                "funding_outpoint"
            ))
        );

        let mut malformed_txid = msg.clone();
        malformed_txid.funding_outpoint.txid = "not-a-txid".to_string();
        assert_eq!(
            malformed_txid.verify_recovery_state(&secp, &trusted),
            Err(Bip448RecoveryVerifyError::InvalidFundingTxid)
        );

        let mut wrong_chain_script = trusted.clone();
        wrong_chain_script.funding_output.script_pubkey = Builder::new().push_int(1).into_script();
        assert_eq!(
            msg.verify_recovery_state(&secp, &wrong_chain_script),
            Err(Bip448RecoveryVerifyError::TrustedFieldMismatch(
                "funding_output.script_pubkey"
            ))
        );

        let mut wrong_receiver_key = msg.clone();
        wrong_receiver_key.receiver_user_public_key = server_pub.to_string();
        assert_eq!(
            wrong_receiver_key.verify_recovery_state(&secp, &trusted),
            Err(Bip448RecoveryVerifyError::TrustedFieldMismatch(
                "receiver_user_public_key"
            ))
        );

        let mut wrong_server_key = msg.clone();
        wrong_server_key.server_public_key = user_pub.to_string();
        assert_eq!(
            wrong_server_key.verify_recovery_state(&secp, &trusted),
            Err(Bip448RecoveryVerifyError::TrustedFieldMismatch(
                "server_public_key"
            ))
        );

        let mut wrong_signing_hash = msg;
        wrong_signing_hash
            .latest_state
            .signing_metadata
            .update_template_hash = "00".repeat(32);
        assert_eq!(
            wrong_signing_hash.verify_recovery_state(&secp, &trusted),
            Err(Bip448RecoveryVerifyError::InconsistentField(
                "signing_metadata.update_template_hash"
            ))
        );
    }

    #[test]
    fn verify_recovery_state_rejects_self_consistent_future_locktime() {
        const FUTURE_LOCKTIME: u32 = 900_000_000;

        let secp = Secp256k1::new();
        let (aggregate_secret, aggregate_pub, user_pub, server_pub) = recovery_keys(&secp);
        let (latest, funding_outpoint, recovery_script) = reconstructible_latest_state_at(
            &secp,
            &aggregate_secret,
            &aggregate_pub,
            1,
            FUTURE_LOCKTIME,
        );
        let msg = Bip448TransferMsg {
            msg_version: 2,
            statechain_id: "statechain".to_string(),
            transfer_signature: "ab".repeat(64),
            sender_user_public_key: "02".to_string() + &"12".repeat(32),
            receiver_user_public_key: user_pub.to_string(),
            server_public_key: server_pub.to_string(),
            aggregate_pubkey: aggregate_pub.to_string(),
            funding_outpoint: funding_outpoint.clone(),
            latest_state_number: latest.state_number,
            challenge_delay: latest.challenge_delay,
            amount_sats: funding_outpoint.value_sats,
            network: "regtest".to_string(),
            value_schedule: latest.value_schedule.clone(),
            server_signature_count: latest.signing_metadata.server_signature_count,
            latest_state: latest,
            t1: [9u8; 32],
            state_history: Vec::new(),
        };
        let mut trusted = trusted_recovery_context(
            &secp,
            &funding_outpoint,
            &user_pub,
            &server_pub,
            &recovery_script,
            msg.server_signature_count,
        );
        trusted.median_time_past = FUTURE_LOCKTIME - 1;

        assert_eq!(
            msg.verify_recovery_state(&secp, &trusted),
            Err(Bip448RecoveryVerifyError::StateLocktimeNotFinal {
                locktime: FUTURE_LOCKTIME,
                median_time_past: FUTURE_LOCKTIME - 1,
            })
        );

        // Bitcoin finality is strict: equality with MTP is still non-final.
        trusted.median_time_past = FUTURE_LOCKTIME;
        assert_eq!(
            msg.verify_recovery_state(&secp, &trusted),
            Err(Bip448RecoveryVerifyError::StateLocktimeNotFinal {
                locktime: FUTURE_LOCKTIME,
                median_time_past: FUTURE_LOCKTIME,
            })
        );

        trusted.median_time_past = FUTURE_LOCKTIME + 1;
        assert_eq!(
            msg.verify_recovery_state(&secp, &trusted)
                .unwrap()
                .aggregate_pubkey(),
            &aggregate_pub
        );
    }

    #[test]
    fn verify_recovery_state_accepts_uppercase_hex_and_returns_canonical_state() {
        let secp = Secp256k1::new();
        let (aggregate_secret, aggregate_pub, user_pub, server_pub) = recovery_keys(&secp);
        let (canonical_latest, canonical_funding_outpoint, recovery_script) =
            reconstructible_latest_state(&secp, &aggregate_secret, &aggregate_pub);
        let mut uppercase_latest = canonical_latest.clone();
        uppercase_recovery_hex(&mut uppercase_latest);
        let mut uppercase_funding_outpoint = canonical_funding_outpoint.clone();
        uppercase_funding_outpoint.txid.make_ascii_uppercase();

        let msg = Bip448TransferMsg {
            msg_version: 2,
            statechain_id: "statechain".to_string(),
            transfer_signature: "ab".repeat(64),
            sender_user_public_key: "02".to_string() + &"12".repeat(32),
            receiver_user_public_key: user_pub.to_string(),
            server_public_key: server_pub.to_string(),
            aggregate_pubkey: aggregate_pub.to_string(),
            funding_outpoint: uppercase_funding_outpoint,
            latest_state_number: uppercase_latest.state_number,
            challenge_delay: uppercase_latest.challenge_delay,
            amount_sats: canonical_funding_outpoint.value_sats,
            network: "regtest".to_string(),
            value_schedule: uppercase_latest.value_schedule.clone(),
            server_signature_count: uppercase_latest.signing_metadata.server_signature_count,
            latest_state: uppercase_latest,
            t1: [9u8; 32],
            state_history: Vec::new(),
        };
        let trusted = trusted_recovery_context(
            &secp,
            &canonical_funding_outpoint,
            &user_pub,
            &server_pub,
            &recovery_script,
            msg.server_signature_count,
        );

        let verified = msg.verify_recovery_state(&secp, &trusted).unwrap();
        assert_eq!(verified.aggregate_pubkey(), &aggregate_pub);
        assert_eq!(verified.canonical_latest_state(), &canonical_latest);
        assert_eq!(
            verified.funding_outpoint(),
            trusted_outpoint(&canonical_funding_outpoint)
        );

        let mut odd_length = msg.clone();
        odd_length.latest_state.update_tx.push('0');
        assert_eq!(
            odd_length.verify_recovery_state(&secp, &trusted),
            Err(Bip448RecoveryVerifyError::TemplateFieldMismatch(
                "derived_latest_state"
            ))
        );

        let mut malformed = msg.clone();
        malformed
            .latest_state
            .state_update_script
            .replace_range(0..1, "z");
        assert_eq!(
            malformed.verify_recovery_state(&secp, &trusted),
            Err(Bip448RecoveryVerifyError::TemplateFieldMismatch(
                "derived_latest_state"
            ))
        );

        let mut prefixed = msg.clone();
        prefixed.latest_state.settlement_tx = format!("0x{}", prefixed.latest_state.settlement_tx);
        assert!(prefixed.verify_recovery_state(&secp, &trusted).is_err());

        let mut whitespace = msg;
        whitespace
            .latest_state
            .state_settlement_control_block
            .push(' ');
        assert!(whitespace.verify_recovery_state(&secp, &trusted).is_err());
    }

    #[test]
    fn bip448_transfer_valid_fixture_passes() {
        let fixture = transfer_fixture();
        assert!(fixture.msg.latest_state.state_locktime > script::INITIAL_STATE_LOCKTIME_MAX);
        verify_bip448_transfer_msg(&fixture.msg, &fixture.info, &fixture.facts).unwrap();

        let fixture = three_state_transfer_fixture();
        verify_bip448_transfer_msg(&fixture.msg, &fixture.info, &fixture.facts).unwrap();
    }

    #[test]
    fn bip448_transfer_rejects_tampered_t1() {
        let mut fixture = transfer_fixture();
        fixture.msg.t1 = [10u8; 32];
        assert_eq!(transfer_error(&fixture), InvalidT1);
    }

    #[test]
    fn bip448_transfer_rejects_missing_transfer_signature() {
        let mut fixture = transfer_fixture();
        fixture.msg.transfer_signature.clear();
        assert_eq!(transfer_error(&fixture), InvalidTransferSignature);
    }

    #[test]
    fn bip448_transfer_rejects_signature_count_history_mismatch() {
        let mut fixture = three_state_transfer_fixture();
        fixture.info.num_sigs = 2;
        assert_eq!(transfer_error(&fixture), InvalidSignatureCount);

        let mut fixture = three_state_transfer_fixture();
        fixture.msg.state_history.pop();
        assert_eq!(transfer_error(&fixture), InvalidSignatureCount);
    }

    #[test]
    fn bip448_transfer_rejects_tampered_update_signature() {
        let mut fixture = transfer_fixture();
        fixture.msg.latest_state.signing_metadata.update_signature = "00".repeat(64);
        assert_eq!(transfer_error(&fixture), InvalidUpdateSignature);
    }

    #[test]
    fn bip448_transfer_rejects_tampered_middle_history() {
        let mut fixture = four_state_transfer_fixture();
        fixture.msg.state_history[1].update_signature = "00".repeat(64);
        assert_eq!(transfer_error(&fixture), InvalidUpdateSignature);

        let mut fixture = four_state_transfer_fixture();
        fixture.msg.state_history[1].blinding_factor = "18".repeat(32);
        assert_eq!(transfer_error(&fixture), InvalidBlindedChallenge);

        let secp = Secp256k1::new();
        let mut fixture = four_state_transfer_fixture();
        fixture.msg.state_history[1].owner_public_key = SecretKey::from_secret_bytes([9u8; 32])
            .unwrap()
            .public_key(&secp)
            .x_only_public_key()
            .0
            .to_string();
        assert_eq!(transfer_error(&fixture), InvalidStateHistory);

        let mut fixture = four_state_transfer_fixture();
        fixture.msg.state_history[1].owner_public_key = SecretKey::from_secret_bytes([8u8; 32])
            .unwrap()
            .public_key(&secp)
            .negate()
            .to_string();
        assert_eq!(transfer_error(&fixture), InvalidStateHistory);
    }

    #[test]
    fn bip448_transfer_rejects_invalid_locktime_progression() {
        for state2_locktime in [
            TEST_STATE_LOCKTIME - 1,
            TEST_STATE_LOCKTIME,
            TEST_STATE_LOCKTIME + script::FUTURE_STATE_STRIDE_MAX + 1,
        ] {
            let fixture = transfer_fixture_with_locktimes(TEST_STATE_LOCKTIME, state2_locktime);
            assert_eq!(transfer_error(&fixture), InvalidStateLocktime);
        }

        let mut fixture = transfer_fixture();
        fixture.msg.state_history[1].state_locktime = 1;
        assert_eq!(transfer_error(&fixture), InvalidStateLocktime);

        for stride in [0, script::FUTURE_STATE_STRIDE_MAX + 1] {
            let fixture = three_state_transfer_fixture_with_last_stride(stride);
            assert_eq!(transfer_error(&fixture), InvalidStateLocktime);
        }
    }

    #[test]
    fn bip448_transfer_rejects_wrong_network() {
        let mut fixture = transfer_fixture();
        fixture.msg.network = Network::Testnet.to_string();
        assert_eq!(transfer_error(&fixture), InvalidNetworkOrChallengeDelay);
    }

    #[test]
    fn bip448_transfer_rejects_spent_funding_output() {
        let mut fixture = transfer_fixture();
        fixture.facts.tx0_unspent = false;
        assert_eq!(transfer_error(&fixture), InvalidFundingOutput);
    }

    #[test]
    fn bip448_transfer_rejects_latest_settlement_paying_wrong_key() {
        let mut fixture = transfer_fixture();
        let mut settlement = tx_from_hex(&fixture.msg.latest_state.settlement_tx);
        let secp = Secp256k1::new();
        let wrong_key = SecretKey::from_secret_bytes([8u8; 32])
            .unwrap()
            .public_key(&secp);
        settlement.output[0].script_pubkey = Address::p2tr(
            &secp,
            wrong_key.x_only_public_key().0,
            None,
            Network::Regtest,
        )
        .script_pubkey();
        fixture.msg.latest_state.settlement_tx = hex::encode(encode::serialize(&settlement));
        assert_eq!(
            transfer_error(&fixture),
            Recovery(Bip448RecoveryVerifyError::TemplateFieldMismatch(
                "derived_latest_state"
            ))
        );
    }
}
