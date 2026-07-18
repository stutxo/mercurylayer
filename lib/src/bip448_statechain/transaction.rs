//! Deterministic BIP448 statechain transaction templates.
//!
//! This module builds the unsigned `U(n)` update and `S(n)` settlement
//! templates that match the Phase 2 script constraints, and the validators a
//! receiver or watcher needs to reconstruct and verify them byte-for-byte.
//!
//! # Fee-bump output policy (Phase 3 decision)
//!
//! `OP_TEMPLATEHASH` commits to every output, so the fee-bump strategy is part
//! of the committed template shape and is fixed here, before signing exists.
//!
//! The default policy is [`FeePolicy::ZeroFeeEphemeralAnchor`]:
//!
//! - `U(n)` and `S(n)` pay zero fee and carry a zero-value pay-to-anchor
//!   (P2A, `OP_1 <0x4e73>`) output at index 1.
//! - All fees come from a CPFP child spending the anchor. P2A is keyless, so
//!   the owner or any watcher can fee-bump without signing material.
//! - Zero-value outputs are relay-valid under Bitcoin Core's ephemeral dust
//!   policy only when the transaction pays zero fee and is submitted as a
//!   TRUC (v3) 1-parent-1-child package whose child spends the dust output.
//!   Recovery broadcast paths must therefore use package submission with an
//!   anchor-spending child.
//! - Zero-fee templates keep the value schedule constant: every state output
//!   and the recovery output carry the full funding amount. This satisfies
//!   the rule that an update output value must not exceed the value of any
//!   input it may be rebound to (funding output or any older state output),
//!   with equality for every rebind target.
//! - Rebind helpers require the target prevout value and reject targets that
//!   would change this schedule, because input amounts are not committed by
//!   `OP_TEMPLATEHASH`.
//!
//! Unit tests also exercise a prototype-only fixed-fee/no-anchor policy. It is
//! compiled behind `cfg(test)` so production callers cannot select templates
//! whose committed fee cannot be CPFP-bumped during a challenge-window race.
//!
//! # Sequence values
//!
//! - The update protocol input uses [`UPDATE_INPUT_SEQUENCE`]
//!   (`Sequence::ZERO`): non-final so CLTV and transaction locktime are
//!   enforced, BIP68 disable flag clear with a relative lock of zero blocks,
//!   and deterministic.
//! - The settlement protocol input uses `Sequence::from_height(challenge_delay)`
//!   so BIP68 consensus-enforces the challenge window relative to `U(n)`
//!   confirmation. No script CSV is needed.

use std::{error::Error, fmt};

use bitcoin::{
    absolute,
    blockdata::opcodes::all::OP_PUSHNUM_1,
    script::Builder,
    secp256k1::{Secp256k1, Verification, XOnlyPublicKey},
    sighash::{Annex, Error as SighashError, TemplateHash},
    OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};

use crate::bip448::template_hash;
use crate::bip448_statechain::script::{
    self, output_script_pubkey, state_spend_info, state_update_gate_locktime, ScriptTemplateError,
};

use bitcoin::hashes::Hash;

/// BIP448 recovery transactions default to TRUC/v3 relay policy.
pub const TX_VERSION: i32 = 3;

/// Deterministic non-final sequence for the update protocol input.
///
/// Zero is non-final (so CLTV and `nLockTime` apply), signals replaceability,
/// and keeps the BIP68 disable flag clear with a relative lock of zero blocks,
/// which never delays an update broadcast.
pub const UPDATE_INPUT_SEQUENCE: Sequence = Sequence::ZERO;

/// Fee-bump output policy committed into the transaction templates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeePolicy {
    /// Default: zero-fee template with a zero-value P2A anchor output at
    /// index 1. Fees are provided by a CPFP child spending the anchor,
    /// submitted as a TRUC 1-parent-1-child package.
    ///
    /// Broadcast paths must construct the child to satisfy TRUC and
    /// ephemeral-dust policy: the child is also v3, spends the parent's
    /// anchor output plus the fee-providing wallet inputs, stays within the
    /// TRUC child size limit (1,000 vB), and must be the parent's only
    /// unconfirmed child. A zero-fee parent is not relayable alone; always
    /// submit parent and child together (`submitpackage`). The child itself
    /// is not committed by any template hash and needs no protocol signing
    /// material: P2A is anyone-can-spend, so watchers fee-bump with their
    /// own wallet UTXOs.
    ZeroFeeEphemeralAnchor,
    /// Reviewed prototype-only policy: fixed direct fee, no anchor output.
    /// The committed fee cannot be bumped, and rebinding onto same-value
    /// older state outputs leaves zero fee. Do not use outside controlled
    /// tests with explicit receiver validation.
    #[cfg(test)]
    PrototypeFixedFeeNoAnchor { fee: u64 },
}

#[derive(Debug)]
pub enum TransactionTemplateError {
    Script(ScriptTemplateError),
    Sighash(SighashError),
    InvalidStateNumber {
        state_number: u32,
    },
    InvalidChallengeDelay {
        challenge_delay: u16,
    },
    FeeExceedsInput {
        input_amount: u64,
        fee: u64,
    },
    DustOutput {
        value: u64,
        minimum: u64,
    },
    StateLocktimeNotFinal {
        locktime: u32,
        median_time_past: u32,
    },
    FinalProtocolInputSequence {
        sequence: Sequence,
    },
    ProtocolInputSequenceDisablesBip68 {
        sequence: Sequence,
    },
    UnexpectedUpdateInputSequence {
        sequence: Sequence,
    },
    UnexpectedSettlementInputSequence {
        sequence: Sequence,
    },
    UnexpectedTransactionVersion {
        version: i32,
    },
    UnexpectedUpdateLocktime {
        expected: u32,
        actual: u32,
    },
    UnexpectedSettlementLocktime {
        expected: u32,
        actual: u32,
    },
    UnexpectedInputValue {
        fee_policy: FeePolicy,
        expected: u64,
        actual: u64,
    },
    UnexpectedProtocolInputCount {
        inputs: usize,
    },
    UnexpectedProtocolInputScriptSig {
        bytes: usize,
    },
    UnexpectedOutputSet {
        fee_policy: FeePolicy,
    },
}

impl fmt::Display for TransactionTemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransactionTemplateError::Script(err) => {
                write!(f, "BIP448 script template error: {err}")
            }
            TransactionTemplateError::Sighash(err) => {
                write!(f, "BIP448 template hash error: {err:?}")
            }
            TransactionTemplateError::InvalidStateNumber { state_number } => {
                write!(f, "invalid BIP448 logical state number {state_number}")
            }
            TransactionTemplateError::InvalidChallengeDelay { challenge_delay } => {
                write!(f, "invalid BIP448 challenge delay {challenge_delay}")
            }
            TransactionTemplateError::FeeExceedsInput { input_amount, fee } => write!(
                f,
                "BIP448 template fee {fee} does not leave a spendable output from input {input_amount}"
            ),
            TransactionTemplateError::DustOutput { value, minimum } => write!(
                f,
                "BIP448 template output value {value} is below the dust minimum {minimum}"
            ),
            TransactionTemplateError::StateLocktimeNotFinal {
                locktime,
                median_time_past,
            } => write!(
                f,
                "BIP448 state locktime {locktime} is not final for median time past {median_time_past}"
            ),
            TransactionTemplateError::FinalProtocolInputSequence { sequence } => write!(
                f,
                "BIP448 protocol input sequence {sequence} is final and disables locktime/CLTV"
            ),
            TransactionTemplateError::ProtocolInputSequenceDisablesBip68 { sequence } => write!(
                f,
                "BIP448 protocol input sequence {sequence} has the BIP68 disable flag set"
            ),
            TransactionTemplateError::UnexpectedUpdateInputSequence { sequence } => write!(
                f,
                "BIP448 update input sequence {sequence} does not match the deterministic update sequence"
            ),
            TransactionTemplateError::UnexpectedSettlementInputSequence { sequence } => write!(
                f,
                "BIP448 settlement input sequence {sequence} does not match the challenge delay"
            ),
            TransactionTemplateError::UnexpectedTransactionVersion { version } => write!(
                f,
                "BIP448 recovery template version {version} does not match protocol version {TX_VERSION}"
            ),
            TransactionTemplateError::UnexpectedUpdateLocktime {
                expected,
                actual,
            } => write!(
                f,
                "BIP448 update template uses locktime {actual}, expected {expected}"
            ),
            TransactionTemplateError::UnexpectedSettlementLocktime {
                expected,
                actual,
            } => write!(
                f,
                "BIP448 settlement template uses locktime {actual}, expected {expected}"
            ),
            TransactionTemplateError::UnexpectedInputValue {
                fee_policy,
                expected,
                actual,
            } => write!(
                f,
                "BIP448 template input value {actual} does not match expected value {expected} for fee policy {fee_policy:?}"
            ),
            TransactionTemplateError::UnexpectedProtocolInputCount { inputs } => write!(
                f,
                "BIP448 recovery template must have exactly one protocol input, found {inputs}"
            ),
            TransactionTemplateError::UnexpectedProtocolInputScriptSig { bytes } => write!(
                f,
                "BIP448 protocol input scriptSig must be empty, found {bytes} bytes"
            ),
            TransactionTemplateError::UnexpectedOutputSet { fee_policy } => write!(
                f,
                "BIP448 template output set does not match fee policy {fee_policy:?}"
            ),
        }
    }
}

impl Error for TransactionTemplateError {}

impl From<ScriptTemplateError> for TransactionTemplateError {
    fn from(err: ScriptTemplateError) -> Self {
        TransactionTemplateError::Script(err)
    }
}

impl From<SighashError> for TransactionTemplateError {
    fn from(err: SighashError) -> Self {
        TransactionTemplateError::Sighash(err)
    }
}

/// The pay-to-anchor scriptPubKey (`OP_1 <0x4e73>`) recognized by Bitcoin
/// Core / Inquisition as an anyone-can-spend fee anchor.
pub fn pay_to_anchor_script() -> ScriptBuf {
    Builder::new()
        .push_opcode(OP_PUSHNUM_1)
        .push_slice([0x4e, 0x73])
        .into_script()
}

/// Deterministic placeholder prevout for unbound templates.
///
/// The txid is all zeroes but the vout is 0, so an unbound template is never
/// mistaken for a coinbase (which requires vout `0xffffffff`) and can never
/// spend a real output. Templates must be rebound before broadcast.
pub fn placeholder_outpoint() -> OutPoint {
    OutPoint {
        txid: Txid::all_zeros(),
        vout: 0,
    }
}

/// Builds the unsigned rebindable update transaction `U(n)`.
///
/// `input_amount` is the value of the smallest output this update may be
/// rebound to spend. Under the default zero-fee policy this is also the
/// state output value.
pub fn build_update_tx(
    previous_output: OutPoint,
    input_amount: u64,
    state_output_script: ScriptBuf,
    state_locktime: absolute::LockTime,
    fee_policy: FeePolicy,
) -> Result<Transaction, TransactionTemplateError> {
    script::validate_state_locktime(state_locktime)?;
    let main_output_value = main_output_value(input_amount, fee_policy)?;
    validate_non_dust(main_output_value, &state_output_script)?;

    Ok(Transaction {
        version: TX_VERSION,
        lock_time: state_locktime,
        input: vec![TxIn {
            previous_output,
            script_sig: ScriptBuf::new(),
            sequence: UPDATE_INPUT_SEQUENCE,
            witness: Witness::new(),
        }],
        output: outputs_for_policy(main_output_value, state_output_script, fee_policy),
    })
}

/// Rebinds an update template to a different previous output.
///
/// The CSFS signature stays valid because `OP_TEMPLATEHASH` does not commit
/// to the prevout. The target value is still checked because input amounts are
/// also uncommitted: a lower-value target would be consensus-invalid, and a
/// higher-value target would change the committed fee policy.
pub fn rebind_update_tx(
    template: &Transaction,
    previous_output: OutPoint,
    previous_output_value: u64,
    fee_policy: FeePolicy,
) -> Result<Transaction, TransactionTemplateError> {
    rebind_protocol_input(template, previous_output, previous_output_value, fee_policy)
}

/// Builds the unsigned settlement transaction `S(n)`.
///
/// `input_amount` is the state output value `S(n)` will spend. The BIP68
/// relative challenge delay is committed in the input sequence.
pub fn build_settlement_tx(
    previous_output: OutPoint,
    input_amount: u64,
    recovery_script: ScriptBuf,
    state_locktime: absolute::LockTime,
    challenge_delay: u16,
    fee_policy: FeePolicy,
) -> Result<Transaction, TransactionTemplateError> {
    if challenge_delay == 0 {
        return Err(TransactionTemplateError::InvalidChallengeDelay { challenge_delay });
    }
    script::validate_state_locktime(state_locktime)?;
    let main_output_value = main_output_value(input_amount, fee_policy)?;
    validate_non_dust(main_output_value, &recovery_script)?;

    Ok(Transaction {
        version: TX_VERSION,
        lock_time: state_locktime,
        input: vec![TxIn {
            previous_output,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_height(challenge_delay),
            witness: Witness::new(),
        }],
        output: outputs_for_policy(main_output_value, recovery_script, fee_policy),
    })
}

/// Rebinds a settlement template to a different previous output.
///
/// The committed `settlement_template_hash(n)` stays valid because
/// `OP_TEMPLATEHASH` does not commit to the prevout. The target value is still
/// checked so rebinding cannot create an invalid transaction or an unintended
/// parent fee under the selected fee policy.
pub fn rebind_settlement_tx(
    template: &Transaction,
    previous_output: OutPoint,
    previous_output_value: u64,
    fee_policy: FeePolicy,
) -> Result<Transaction, TransactionTemplateError> {
    rebind_protocol_input(template, previous_output, previous_output_value, fee_policy)
}

/// Computes the update template hash signed by the CSFS update role.
pub fn update_template_hash(
    update_tx: &Transaction,
) -> Result<TemplateHash, TransactionTemplateError> {
    Ok(template_hash::template_hash(update_tx, 0, None)?)
}

/// Computes the settlement template hash committed by
/// `state_settlement_leaf(settlement_template_hash)`.
pub fn settlement_template_hash(
    settlement_tx: &Transaction,
    input_index: usize,
    annex: Option<Annex<'_>>,
) -> Result<TemplateHash, TransactionTemplateError> {
    Ok(template_hash::template_hash(
        settlement_tx,
        input_index,
        annex,
    )?)
}

/// The deterministic template set for one state.
#[derive(Debug, Clone)]
pub struct StateTemplates {
    pub state_number: u32,
    pub state_locktime: absolute::LockTime,
    pub challenge_delay: u16,
    pub fee_policy: FeePolicy,
    /// Value of the funding or older-state output that `U(n)` spends.
    pub update_input_amount: u64,
    /// Value of the state output that `S(n)` spends. This equals `U(n)`'s main
    /// output value and is the amount that must be passed to
    /// [`validate_fee_bump_outputs`] when validating `settlement_tx`.
    pub settlement_input_amount: u64,
    pub settlement_tx: Transaction,
    pub settlement_template_hash: TemplateHash,
    pub state_output_script_pubkey: ScriptBuf,
    pub update_tx: Transaction,
}

/// Deterministic construction helper implementing the required build order:
///
/// ```text
/// build S(n) → hash it → build the two-leaf state output containing the
/// hash → build U(n) paying to that output
/// ```
///
/// `S(n)` is created with a placeholder prevout; it is rebound to the actual
/// `U(n)` outpoint after `U(n)` is itself rebound and broadcast.
pub fn build_state_templates<C: Verification>(
    secp: &Secp256k1<C>,
    aggregate_key: XOnlyPublicKey,
    update_previous_output: OutPoint,
    input_amount: u64,
    recovery_script: ScriptBuf,
    state_number: u32,
    state_locktime: absolute::LockTime,
    challenge_delay: u16,
    fee_policy: FeePolicy,
) -> Result<StateTemplates, TransactionTemplateError> {
    validate_state_number(state_number)?;
    script::validate_state_locktime(state_locktime)?;
    let state_output_value = main_output_value(input_amount, fee_policy)?;
    let settlement_tx = build_settlement_tx(
        placeholder_outpoint(),
        state_output_value,
        recovery_script,
        state_locktime,
        challenge_delay,
        fee_policy,
    )?;
    let settlement_hash = settlement_template_hash(&settlement_tx, 0, None)?;

    let spend_info = state_spend_info(secp, aggregate_key, state_locktime, settlement_hash)?;
    let state_output_script_pubkey = output_script_pubkey(&spend_info);

    let update_tx = build_update_tx(
        update_previous_output,
        input_amount,
        state_output_script_pubkey.clone(),
        state_locktime,
        fee_policy,
    )?;

    Ok(StateTemplates {
        state_number,
        state_locktime,
        challenge_delay,
        fee_policy,
        update_input_amount: input_amount,
        settlement_input_amount: state_output_value,
        settlement_tx,
        settlement_template_hash: settlement_hash,
        state_output_script_pubkey,
        update_tx,
    })
}

/// Validates that an explicit state locktime is already final for the
/// receiver's chain view, so a recovery package is immediately usable.
///
/// Bitcoin finality (BIP113) requires `nLockTime < median_time_past`. Normal
/// Protocol locktimes are timestamps and must be strictly below chain MTP.
pub fn validate_immediately_final(
    state_locktime: absolute::LockTime,
    median_time_past: u32,
) -> Result<(), TransactionTemplateError> {
    script::validate_state_locktime(state_locktime)?;
    let locktime = state_locktime.to_consensus_u32();
    if locktime >= median_time_past {
        return Err(TransactionTemplateError::StateLocktimeNotFinal {
            locktime,
            median_time_past,
        });
    }

    Ok(())
}

/// Validates the complete deterministic template pair for one state.
///
/// Receiver and watcher acceptance should use this entry point, not only the
/// lower-level field validators. It derives `settlement_template_hash` from
/// `settlement_tx`, reconstructs the expected state output script for
/// `(aggregate_key, state_locktime, settlement_hash)`, and then verifies `U(n)`
/// pays to that exact output. This binds the update's explicit locktime to the
/// CLTV gate encoded in the output script, preserving the ratchet without
/// deriving locktime from logical state number.
///
/// This validates template structure only. The caller must still confirm the
/// state locktime is final for its own chain view with
/// [`validate_immediately_final`] before treating the package as immediately
/// recoverable, because that check needs a chain median-time-past this
/// function does not have.
pub fn validate_state_template_set<C: Verification>(
    secp: &Secp256k1<C>,
    aggregate_key: XOnlyPublicKey,
    state_number: u32,
    state_locktime: absolute::LockTime,
    update_input_amount: u64,
    recovery_script: &ScriptBuf,
    challenge_delay: u16,
    fee_policy: FeePolicy,
    update_tx: &Transaction,
    settlement_tx: &Transaction,
) -> Result<TemplateHash, TransactionTemplateError> {
    validate_state_number(state_number)?;
    validate_update_protocol_input(update_tx, state_locktime)?;
    validate_settlement_protocol_input(settlement_tx, state_locktime, challenge_delay)?;

    let settlement_hash = settlement_template_hash(settlement_tx, 0, None)?;
    let expected_state_output =
        expected_state_output_script_pubkey(secp, aggregate_key, state_locktime, settlement_hash)?;
    validate_fee_bump_outputs(
        update_tx,
        &expected_state_output,
        update_input_amount,
        fee_policy,
    )?;

    let state_output_value = main_output_value(update_input_amount, fee_policy)?;
    validate_fee_bump_outputs(
        settlement_tx,
        recovery_script,
        state_output_value,
        fee_policy,
    )?;

    Ok(settlement_hash)
}

/// Validates the update protocol fields: the exact explicit state locktime and
/// exactly one input whose sequence is the
/// deterministic non-final update sequence, so transaction locktime and the
/// CLTV state gate apply and BIP68 remains enabled.
///
/// The locktime equality matters for stale-state defense and deterministic
/// reconstruction; ordering against prior states is validated separately.
///
/// Also requires the deterministic v3 template version for TRUC consistency;
/// the template hash commits the version, so any other value is not a
/// protocol template.
///
/// This is a low-level field validator. It does not verify the update output
/// script; use [`validate_state_template_set`] for receiver or watcher
/// acceptance.
pub fn validate_update_protocol_input(
    update_tx: &Transaction,
    expected_state_locktime: absolute::LockTime,
) -> Result<(), TransactionTemplateError> {
    validate_protocol_transaction(
        update_tx,
        expected_state_locktime,
        UPDATE_INPUT_SEQUENCE,
        ProtocolTransactionRole::Update,
    )
}

/// Validates the settlement protocol fields: the exact state locktime, and
/// exactly one input whose sequence is non-final, matches the expected
/// challenge delay, and keeps the BIP68 disable flag clear so the relative
/// delay is consensus-enforced.
///
/// Also requires the deterministic v3 template version. This is security
/// relevant here: BIP68 relative locktimes are unenforced below version 2,
/// so a lower-version settlement template would have no challenge window at
/// all.
pub fn validate_settlement_protocol_input(
    settlement_tx: &Transaction,
    expected_state_locktime: absolute::LockTime,
    challenge_delay: u16,
) -> Result<(), TransactionTemplateError> {
    if challenge_delay == 0 {
        return Err(TransactionTemplateError::InvalidChallengeDelay { challenge_delay });
    }
    validate_protocol_transaction(
        settlement_tx,
        expected_state_locktime,
        Sequence::from_height(challenge_delay),
        ProtocolTransactionRole::Settlement,
    )
}

/// Whether a well-formed protocol update can satisfy the update CLTV gate of
/// the given state's output. Strictly newer updates satisfy older gates;
/// same-state and older updates cannot satisfy them.
///
/// This is a protocol-template predicate, not a consensus predicate: it also
/// requires the deterministic update protocol input, so a transaction with
/// any other non-final sequence returns `false` even though consensus CLTV
/// would accept it. Do not use it to assess whether an adversarial
/// transaction could spend through a gate; consensus only requires a
/// non-final sequence and a sufficient same-type locktime.
pub fn update_can_satisfy_state_gate(
    update_tx: &Transaction,
    spent_state_locktime: absolute::LockTime,
) -> Result<bool, TransactionTemplateError> {
    let gate = state_update_gate_locktime(spent_state_locktime)?;
    let update_locktime = update_tx.lock_time;
    // CLTV requires matching locktime types. Both sides use timestamp-range
    // encoding; anything else is not a protocol locktime.
    if update_locktime.is_block_height() {
        return Ok(false);
    }
    if validate_update_protocol_input(update_tx, update_locktime).is_err() {
        return Ok(false);
    }

    Ok(update_locktime.to_consensus_u32() >= gate.to_consensus_u32())
}

/// Exact-byte check for the funding update leaf. Receiver validation must
/// not pattern-match CSFS-like scripts: BIP348 treats non-32-byte public
/// keys as auto-succeeding upgrade hooks, so only the exact expected bytes
/// are acceptable.
pub fn is_expected_funding_update_leaf(leaf: &ScriptBuf) -> bool {
    *leaf == script::funding_update_leaf()
}

/// Exact-byte check for `state_update_leaf(L)`.
pub fn is_expected_state_update_leaf(
    leaf: &ScriptBuf,
    state_locktime: absolute::LockTime,
) -> Result<bool, TransactionTemplateError> {
    Ok(*leaf == script::state_update_leaf(state_locktime)?)
}

/// Exact-byte check for `state_settlement_leaf(settlement_template_hash)`.
pub fn is_expected_state_settlement_leaf(
    leaf: &ScriptBuf,
    settlement_template_hash: TemplateHash,
) -> bool {
    *leaf == script::state_settlement_leaf(settlement_template_hash)
}

/// Reconstructs the expected two-leaf state output scriptPubKey for
/// `(P, L, hash)`.
///
/// This is the single source of truth for the state output, shared by
/// [`verify_state_output_script_pubkey`] and [`validate_state_template_set`]
/// so the two acceptance paths cannot reconstruct it differently.
pub fn expected_state_output_script_pubkey<C: Verification>(
    secp: &Secp256k1<C>,
    aggregate_key: XOnlyPublicKey,
    state_locktime: absolute::LockTime,
    settlement_template_hash: TemplateHash,
) -> Result<ScriptBuf, TransactionTemplateError> {
    let spend_info = state_spend_info(
        secp,
        aggregate_key,
        state_locktime,
        settlement_template_hash,
    )?;

    Ok(output_script_pubkey(&spend_info))
}

/// Reconstructs the expected two-leaf state output for `(P, L, hash)` and
/// compares the claimed scriptPubKey byte-for-byte.
pub fn verify_state_output_script_pubkey<C: Verification>(
    secp: &Secp256k1<C>,
    aggregate_key: XOnlyPublicKey,
    state_locktime: absolute::LockTime,
    settlement_template_hash: TemplateHash,
    claimed_script_pubkey: &ScriptBuf,
) -> Result<bool, TransactionTemplateError> {
    let expected = expected_state_output_script_pubkey(
        secp,
        aggregate_key,
        state_locktime,
        settlement_template_hash,
    )?;

    Ok(expected == *claimed_script_pubkey)
}

/// Validates that a template's output set matches its fee policy: the main
/// output at index 0 with the expected script and value, and under the
/// default policy a zero-value P2A anchor at index 1 and nothing else. The
/// main output must be non-dust; only the committed P2A anchor may be dust
/// under the zero-fee ephemeral-anchor policy.
///
/// For transfer acceptance, the expected main script must be reconstructed
/// from protocol data. Do not pass a sender-provided update output script back
/// into this function; use [`validate_state_template_set`] instead.
pub fn validate_fee_bump_outputs(
    tx: &Transaction,
    expected_main_script: &ScriptBuf,
    expected_input_amount: u64,
    fee_policy: FeePolicy,
) -> Result<(), TransactionTemplateError> {
    validate_fee_policy_input_value(tx, expected_input_amount, fee_policy)?;
    if tx.output[0].script_pubkey != *expected_main_script {
        return Err(TransactionTemplateError::UnexpectedOutputSet { fee_policy });
    }

    Ok(())
}

/// Validates that the committed outputs imply exactly the provided input value
/// under the selected fee policy, and that the main output is non-dust.
///
/// This is required because `OP_TEMPLATEHASH` commits to outputs but not input
/// amounts. Rebinding to any other value would either be consensus-invalid or
/// alter the parent fee that the fee-bump policy relies on.
pub fn validate_fee_policy_input_value(
    tx: &Transaction,
    input_value: u64,
    fee_policy: FeePolicy,
) -> Result<(), TransactionTemplateError> {
    let expected_input_value = expected_input_value_for_outputs(tx, fee_policy)?;
    if input_value != expected_input_value {
        return Err(TransactionTemplateError::UnexpectedInputValue {
            fee_policy,
            expected: expected_input_value,
            actual: input_value,
        });
    }

    Ok(())
}

fn main_output_value(
    input_amount: u64,
    fee_policy: FeePolicy,
) -> Result<u64, TransactionTemplateError> {
    match fee_policy {
        FeePolicy::ZeroFeeEphemeralAnchor => Ok(input_amount),
        #[cfg(test)]
        FeePolicy::PrototypeFixedFeeNoAnchor { fee } => input_amount
            .checked_sub(fee)
            .filter(|remaining| *remaining > 0)
            .ok_or(TransactionTemplateError::FeeExceedsInput { input_amount, fee }),
    }
}

fn outputs_for_policy(
    main_output_value: u64,
    main_script: ScriptBuf,
    fee_policy: FeePolicy,
) -> Vec<TxOut> {
    let main_output = TxOut {
        value: main_output_value,
        script_pubkey: main_script,
    };

    match fee_policy {
        FeePolicy::ZeroFeeEphemeralAnchor => vec![
            main_output,
            TxOut {
                value: 0,
                script_pubkey: pay_to_anchor_script(),
            },
        ],
        #[cfg(test)]
        FeePolicy::PrototypeFixedFeeNoAnchor { .. } => vec![main_output],
    }
}

fn validate_non_dust(
    value: u64,
    script_pubkey: &ScriptBuf,
) -> Result<(), TransactionTemplateError> {
    let minimum = script_pubkey.dust_value().to_sat();
    if value < minimum {
        return Err(TransactionTemplateError::DustOutput { value, minimum });
    }

    Ok(())
}

fn rebind_protocol_input(
    template: &Transaction,
    previous_output: OutPoint,
    previous_output_value: u64,
    fee_policy: FeePolicy,
) -> Result<Transaction, TransactionTemplateError> {
    single_protocol_input(template)?;
    validate_fee_policy_input_value(template, previous_output_value, fee_policy)?;

    let mut rebound = template.clone();
    rebound.input[0].previous_output = previous_output;

    Ok(rebound)
}

fn expected_input_value_for_outputs(
    tx: &Transaction,
    fee_policy: FeePolicy,
) -> Result<u64, TransactionTemplateError> {
    match fee_policy {
        FeePolicy::ZeroFeeEphemeralAnchor => match tx.output.as_slice() {
            [main, anchor]
                if anchor.value == 0 && anchor.script_pubkey == pay_to_anchor_script() =>
            {
                validate_non_dust(main.value, &main.script_pubkey)?;
                Ok(main.value)
            }
            _ => Err(TransactionTemplateError::UnexpectedOutputSet { fee_policy }),
        },
        #[cfg(test)]
        FeePolicy::PrototypeFixedFeeNoAnchor { fee } => match tx.output.as_slice() {
            [main] => {
                validate_non_dust(main.value, &main.script_pubkey)?;
                main.value
                    .checked_add(fee)
                    .ok_or(TransactionTemplateError::UnexpectedOutputSet { fee_policy })
            }
            _ => Err(TransactionTemplateError::UnexpectedOutputSet { fee_policy }),
        },
    }
}

#[derive(Clone, Copy)]
enum ProtocolTransactionRole {
    Update,
    Settlement,
}

fn validate_protocol_transaction(
    tx: &Transaction,
    expected_lock_time: absolute::LockTime,
    expected_sequence: Sequence,
    role: ProtocolTransactionRole,
) -> Result<(), TransactionTemplateError> {
    validate_transaction_version(tx.version)?;
    script::validate_state_locktime(expected_lock_time)?;
    if tx.lock_time != expected_lock_time {
        return Err(unexpected_locktime_error(
            role,
            expected_lock_time.to_consensus_u32(),
            tx.lock_time.to_consensus_u32(),
        ));
    }

    let input = single_protocol_input(tx)?;
    validate_locktime_enabled(input.sequence)?;
    if !input.sequence.is_relative_lock_time() {
        return Err(
            TransactionTemplateError::ProtocolInputSequenceDisablesBip68 {
                sequence: input.sequence,
            },
        );
    }
    if input.sequence != expected_sequence {
        return Err(unexpected_sequence_error(role, input.sequence));
    }

    Ok(())
}

fn unexpected_locktime_error(
    role: ProtocolTransactionRole,
    expected: u32,
    actual: u32,
) -> TransactionTemplateError {
    match role {
        ProtocolTransactionRole::Update => {
            TransactionTemplateError::UnexpectedUpdateLocktime { expected, actual }
        }
        ProtocolTransactionRole::Settlement => {
            TransactionTemplateError::UnexpectedSettlementLocktime { expected, actual }
        }
    }
}

fn unexpected_sequence_error(
    role: ProtocolTransactionRole,
    sequence: Sequence,
) -> TransactionTemplateError {
    match role {
        ProtocolTransactionRole::Update => {
            TransactionTemplateError::UnexpectedUpdateInputSequence { sequence }
        }
        ProtocolTransactionRole::Settlement => {
            TransactionTemplateError::UnexpectedSettlementInputSequence { sequence }
        }
    }
}

fn single_protocol_input(tx: &Transaction) -> Result<&TxIn, TransactionTemplateError> {
    if tx.input.len() != 1 {
        return Err(TransactionTemplateError::UnexpectedProtocolInputCount {
            inputs: tx.input.len(),
        });
    }

    let input = &tx.input[0];
    if !input.script_sig.as_bytes().is_empty() {
        return Err(TransactionTemplateError::UnexpectedProtocolInputScriptSig {
            bytes: input.script_sig.as_bytes().len(),
        });
    }

    Ok(input)
}

fn validate_locktime_enabled(sequence: Sequence) -> Result<(), TransactionTemplateError> {
    if !sequence.enables_absolute_lock_time() {
        return Err(TransactionTemplateError::FinalProtocolInputSequence { sequence });
    }

    Ok(())
}

fn validate_transaction_version(version: i32) -> Result<(), TransactionTemplateError> {
    if version != TX_VERSION {
        return Err(TransactionTemplateError::UnexpectedTransactionVersion { version });
    }

    Ok(())
}

fn validate_state_number(state_number: u32) -> Result<(), TransactionTemplateError> {
    if state_number == 0 {
        return Err(TransactionTemplateError::InvalidStateNumber { state_number });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip448_statechain::test_helpers::aggregate_key;

    use bitcoin::blockdata::opcodes::{
        all::{OP_CLTV, OP_DROP, OP_EQUAL},
        OP_CHECKSIGFROMSTACK, OP_TEMPLATEHASH,
    };

    const INPUT_AMOUNT: u64 = 50_000;
    const STATE_NUMBER: u32 = 9;
    const STATE_LOCKTIME: u32 = 700_000_042;
    const CHALLENGE_DELAY: u16 = 12;
    // 2025-06-15T15:06:40Z; far above any protocol state locktime in tests.
    const CURRENT_MTP: u32 = 1_750_000_000;

    fn state_locktime() -> absolute::LockTime {
        absolute::LockTime::from_consensus(STATE_LOCKTIME)
    }

    #[test]
    fn anchor_script_matches_core_pay_to_anchor_bytes() {
        assert_eq!(pay_to_anchor_script().as_bytes(), [0x51, 0x02, 0x4e, 0x73]);
    }

    #[test]
    fn placeholder_outpoint_is_not_a_coinbase_marker() {
        let placeholder = placeholder_outpoint();

        assert_eq!(placeholder.txid, Txid::all_zeros());
        assert_eq!(placeholder.vout, 0);
        assert_ne!(placeholder, OutPoint::null());
    }

    #[test]
    fn update_tx_has_protocol_input_and_committed_anchor_output() {
        let templates = sample_templates();
        let update = &templates.update_tx;

        assert_eq!(update.version, 3);
        assert_eq!(update.input.len(), 1);
        assert_eq!(update.input[0].sequence, UPDATE_INPUT_SEQUENCE);
        assert_eq!(update.output.len(), 2);
        assert_eq!(update.output[0].value, INPUT_AMOUNT);
        assert_eq!(
            update.output[0].script_pubkey,
            templates.state_output_script_pubkey
        );
        assert_eq!(update.output[1].value, 0);
        assert_eq!(update.output[1].script_pubkey, pay_to_anchor_script());
    }

    #[test]
    fn settlement_tx_has_expected_shape() {
        let templates = sample_templates();
        let settlement = &templates.settlement_tx;

        assert_eq!(settlement.version, 3);
        assert_eq!(settlement.input.len(), 1);
        assert_eq!(
            settlement.input[0].sequence,
            Sequence::from_height(CHALLENGE_DELAY)
        );
        assert_eq!(settlement.lock_time.to_consensus_u32(), STATE_LOCKTIME);
        assert_eq!(settlement.output.len(), 2);
        assert_eq!(settlement.output[0].value, INPUT_AMOUNT);
        assert_eq!(settlement.output[0].script_pubkey, recovery_script());
        assert_eq!(settlement.output[1].script_pubkey, pay_to_anchor_script());
    }

    #[test]
    fn update_and_settlement_use_timestamp_state_locktime() {
        let templates = sample_templates();

        assert_eq!(templates.state_number, STATE_NUMBER);
        assert_eq!(templates.state_locktime, state_locktime());
        assert_eq!(
            templates.update_tx.lock_time.to_consensus_u32(),
            STATE_LOCKTIME
        );
        assert_eq!(
            templates.settlement_tx.lock_time,
            templates.update_tx.lock_time
        );
        assert!(!templates.update_tx.lock_time.is_block_height());
    }

    #[test]
    fn logical_state_number_does_not_select_consensus_locktime() {
        let state_one = sample_templates_for_state_and_locktime(1, STATE_LOCKTIME);
        let state_forty_two = sample_templates_for_state_and_locktime(42, STATE_LOCKTIME);

        assert_eq!(
            state_one.update_tx.lock_time,
            state_forty_two.update_tx.lock_time
        );
        assert_eq!(
            state_one.settlement_tx.lock_time,
            state_forty_two.settlement_tx.lock_time
        );
        assert!(matches!(
            script::checked_next_state_locktime(state_one.state_locktime, 0),
            Err(script::ScriptTemplateError::InvalidStateLocktimeStride { stride: 0 })
        ));
    }

    #[test]
    fn changing_only_explicit_locktime_changes_both_template_hashes() {
        let first = sample_templates_for_state_and_locktime(STATE_NUMBER, STATE_LOCKTIME);
        let second = sample_templates_for_state_and_locktime(STATE_NUMBER, STATE_LOCKTIME + 123);

        assert_ne!(
            update_template_hash(&first.update_tx).unwrap(),
            update_template_hash(&second.update_tx).unwrap()
        );
        assert_ne!(
            first.settlement_template_hash,
            second.settlement_template_hash
        );
        assert_ne!(
            first.state_output_script_pubkey,
            second.state_output_script_pubkey
        );
    }

    #[test]
    fn update_template_hash_is_unchanged_by_rebinding() {
        let templates = sample_templates();
        let base_hash = update_template_hash(&templates.update_tx).unwrap();

        let rebound = rebind_update_tx(
            &templates.update_tx,
            funding_outpoint(7, 3),
            INPUT_AMOUNT,
            FeePolicy::ZeroFeeEphemeralAnchor,
        )
        .unwrap();

        assert_eq!(base_hash, update_template_hash(&rebound).unwrap());
    }

    #[test]
    fn settlement_template_hash_is_unchanged_by_rebinding() {
        let templates = sample_templates();

        let rebound = rebind_settlement_tx(
            &templates.settlement_tx,
            funding_outpoint(8, 1),
            INPUT_AMOUNT,
            FeePolicy::ZeroFeeEphemeralAnchor,
        )
        .unwrap();

        assert_eq!(
            templates.settlement_template_hash,
            settlement_template_hash(&rebound, 0, None).unwrap()
        );
    }

    #[test]
    fn rebind_rejects_malformed_input_count() {
        let templates = sample_templates();

        let mut zero_input = templates.update_tx.clone();
        zero_input.input.clear();
        assert!(matches!(
            rebind_update_tx(
                &zero_input,
                funding_outpoint(9, 0),
                INPUT_AMOUNT,
                FeePolicy::ZeroFeeEphemeralAnchor,
            ),
            Err(TransactionTemplateError::UnexpectedProtocolInputCount { inputs: 0 })
        ));

        let mut multi_input = templates.settlement_tx.clone();
        multi_input.input.push(multi_input.input[0].clone());
        assert!(matches!(
            rebind_settlement_tx(
                &multi_input,
                funding_outpoint(9, 1),
                INPUT_AMOUNT,
                FeePolicy::ZeroFeeEphemeralAnchor,
            ),
            Err(TransactionTemplateError::UnexpectedProtocolInputCount { inputs: 2 })
        ));
    }

    #[test]
    fn protocol_input_validation_rejects_non_empty_script_sig() {
        let templates = sample_templates();
        let script_sig = Builder::new().push_slice([1u8; 1]).into_script();
        let script_sig_len = script_sig.as_bytes().len();

        let mut update = templates.update_tx.clone();
        update.input[0].script_sig = script_sig.clone();
        assert!(matches!(
            validate_update_protocol_input(&update, state_locktime()),
            Err(TransactionTemplateError::UnexpectedProtocolInputScriptSig { bytes })
                if bytes == script_sig_len
        ));
        assert!(matches!(
            rebind_update_tx(
                &update,
                funding_outpoint(9, 2),
                INPUT_AMOUNT,
                FeePolicy::ZeroFeeEphemeralAnchor,
            ),
            Err(TransactionTemplateError::UnexpectedProtocolInputScriptSig { bytes })
                if bytes == script_sig_len
        ));

        let mut settlement = templates.settlement_tx.clone();
        settlement.input[0].script_sig = script_sig;
        assert!(matches!(
            validate_settlement_protocol_input(&settlement, state_locktime(), CHALLENGE_DELAY),
            Err(TransactionTemplateError::UnexpectedProtocolInputScriptSig { bytes })
                if bytes == script_sig_len
        ));
        assert!(matches!(
            rebind_settlement_tx(
                &settlement,
                funding_outpoint(9, 3),
                INPUT_AMOUNT,
                FeePolicy::ZeroFeeEphemeralAnchor,
            ),
            Err(TransactionTemplateError::UnexpectedProtocolInputScriptSig { bytes })
                if bytes == script_sig_len
        ));
    }

    #[test]
    fn rebind_rejects_mismatched_target_values() {
        let templates = sample_templates();

        assert!(matches!(
            rebind_update_tx(
                &templates.update_tx,
                funding_outpoint(10, 0),
                INPUT_AMOUNT - 1,
                FeePolicy::ZeroFeeEphemeralAnchor,
            ),
            Err(TransactionTemplateError::UnexpectedInputValue {
                expected: INPUT_AMOUNT,
                actual,
                ..
            }) if actual == INPUT_AMOUNT - 1
        ));

        assert!(matches!(
            rebind_update_tx(
                &templates.update_tx,
                funding_outpoint(10, 1),
                INPUT_AMOUNT + 1,
                FeePolicy::ZeroFeeEphemeralAnchor,
            ),
            Err(TransactionTemplateError::UnexpectedInputValue {
                expected: INPUT_AMOUNT,
                actual,
                ..
            }) if actual == INPUT_AMOUNT + 1
        ));

        assert!(matches!(
            rebind_settlement_tx(
                &templates.settlement_tx,
                funding_outpoint(10, 2),
                INPUT_AMOUNT - 1,
                FeePolicy::ZeroFeeEphemeralAnchor,
            ),
            Err(TransactionTemplateError::UnexpectedInputValue {
                expected: INPUT_AMOUNT,
                actual,
                ..
            }) if actual == INPUT_AMOUNT - 1
        ));

        assert!(matches!(
            rebind_settlement_tx(
                &templates.settlement_tx,
                funding_outpoint(10, 3),
                INPUT_AMOUNT + 1,
                FeePolicy::ZeroFeeEphemeralAnchor,
            ),
            Err(TransactionTemplateError::UnexpectedInputValue {
                expected: INPUT_AMOUNT,
                actual,
                ..
            }) if actual == INPUT_AMOUNT + 1
        ));
    }

    #[test]
    fn update_template_hash_changes_on_committed_field_mutations() {
        let templates = sample_templates();
        let base = &templates.update_tx;
        let base_hash = update_template_hash(base).unwrap();

        let mutations: Vec<Box<dyn Fn(&mut Transaction)>> = vec![
            Box::new(|tx| tx.input[0].sequence = Sequence::from_consensus(1)),
            Box::new(|tx| {
                tx.lock_time = bitcoin::absolute::LockTime::from_consensus(STATE_LOCKTIME + 1)
            }),
            Box::new(|tx| tx.output[0].value -= 1),
            Box::new(|tx| tx.output[0].script_pubkey = recovery_script()),
            Box::new(|tx| tx.output[1].value += 1),
            Box::new(|tx| tx.output[1].script_pubkey = recovery_script()),
            Box::new(|tx| tx.output.swap(0, 1)),
            Box::new(|tx| tx.version = 2),
        ];

        for (index, mutate) in mutations.iter().enumerate() {
            let mut mutated = base.clone();
            mutate(&mut mutated);
            assert_ne!(
                base_hash,
                update_template_hash(&mutated).unwrap(),
                "mutation {index} should change the update template hash"
            );
        }
    }

    #[test]
    fn settlement_mutations_fail_template_hash_equality() {
        let templates = sample_templates();
        let base = &templates.settlement_tx;
        let committed = templates.settlement_template_hash;

        let mutations: Vec<Box<dyn Fn(&mut Transaction)>> = vec![
            Box::new(|tx| tx.input[0].sequence = Sequence::from_height(CHALLENGE_DELAY + 1)),
            Box::new(|tx| {
                tx.lock_time = bitcoin::absolute::LockTime::from_consensus(STATE_LOCKTIME - 1)
            }),
            Box::new(|tx| tx.output[0].value -= 1),
            Box::new(|tx| tx.output[0].script_pubkey = pay_to_anchor_script()),
            Box::new(|tx| tx.version = 2),
        ];

        for (index, mutate) in mutations.iter().enumerate() {
            let mut mutated = base.clone();
            mutate(&mut mutated);
            assert_ne!(
                committed,
                settlement_template_hash(&mutated, 0, None).unwrap(),
                "mutation {index} should break settlement hash equality"
            );
        }

        let annex_bytes = [0x50, 0x01];
        let annex = Annex::new(&annex_bytes).unwrap();
        assert_ne!(
            committed,
            settlement_template_hash(base, 0, Some(annex)).unwrap()
        );
    }

    #[test]
    fn strictly_greater_locktime_satisfies_older_gate_but_same_locktime_does_not() {
        let older = sample_templates();
        let minimum_newer =
            sample_templates_for_state_and_locktime(STATE_NUMBER + 1, STATE_LOCKTIME + 1);
        let later = sample_templates_for_state_and_locktime(42, STATE_LOCKTIME + 65_536);

        assert!(!update_can_satisfy_state_gate(&older.update_tx, state_locktime()).unwrap());
        assert!(update_can_satisfy_state_gate(&minimum_newer.update_tx, state_locktime()).unwrap());
        assert!(update_can_satisfy_state_gate(&later.update_tx, state_locktime()).unwrap());
        assert!(!update_can_satisfy_state_gate(
            &minimum_newer.update_tx,
            minimum_newer.state_locktime,
        )
        .unwrap());
    }

    #[test]
    fn older_settlement_cannot_satisfy_newer_gate() {
        let older = sample_templates();
        let newer_gate = state_update_gate_locktime(state_locktime()).unwrap();

        assert!(older.settlement_tx.lock_time.to_consensus_u32() < newer_gate.to_consensus_u32());
    }

    #[test]
    fn update_sequence_validation_rejects_bad_sequences() {
        let templates = sample_templates();

        let mut wrong_version = templates.update_tx.clone();
        wrong_version.version = 2;
        assert!(matches!(
            validate_update_protocol_input(&wrong_version, state_locktime()),
            Err(TransactionTemplateError::UnexpectedTransactionVersion { version: 2 })
        ));

        let mut wrong_locktime = templates.update_tx.clone();
        wrong_locktime.lock_time = bitcoin::absolute::LockTime::from_consensus(STATE_LOCKTIME - 1);
        assert!(matches!(
            validate_update_protocol_input(&wrong_locktime, state_locktime()),
            Err(TransactionTemplateError::UnexpectedUpdateLocktime { .. })
        ));

        let mut mutated = templates.update_tx.clone();
        mutated.input[0].sequence = Sequence::MAX;
        assert!(matches!(
            validate_update_protocol_input(&mutated, state_locktime()),
            Err(TransactionTemplateError::FinalProtocolInputSequence { .. })
        ));
        assert!(!update_can_satisfy_state_gate(&mutated, state_locktime()).unwrap());

        let mut disabled_bip68 = templates.update_tx.clone();
        disabled_bip68.input[0].sequence = Sequence::from_consensus(0x8000_0000);
        assert!(matches!(
            validate_update_protocol_input(&disabled_bip68, state_locktime()),
            Err(TransactionTemplateError::ProtocolInputSequenceDisablesBip68 { .. })
        ));
        assert!(!update_can_satisfy_state_gate(&disabled_bip68, state_locktime()).unwrap());

        let mut nonzero_relative_delay = templates.update_tx.clone();
        nonzero_relative_delay.input[0].sequence = Sequence::from_height(1);
        assert!(matches!(
            validate_update_protocol_input(&nonzero_relative_delay, state_locktime()),
            Err(TransactionTemplateError::UnexpectedUpdateInputSequence { .. })
        ));

        let mut height_locktime = templates.update_tx.clone();
        height_locktime.lock_time =
            bitcoin::absolute::LockTime::from_consensus(script::LOCKTIME_TIMESTAMP_THRESHOLD - 1);
        assert!(!update_can_satisfy_state_gate(&height_locktime, state_locktime()).unwrap());
    }

    #[test]
    fn settlement_sequence_validation_rejects_bad_sequences() {
        let templates = sample_templates();

        let mut version_1 = templates.settlement_tx.clone();
        version_1.version = 1;
        assert!(matches!(
            validate_settlement_protocol_input(&version_1, state_locktime(), CHALLENGE_DELAY),
            Err(TransactionTemplateError::UnexpectedTransactionVersion { version: 1 })
        ));

        let mut wrong_locktime = templates.settlement_tx.clone();
        wrong_locktime.lock_time = bitcoin::absolute::LockTime::from_consensus(STATE_LOCKTIME - 1);
        assert!(matches!(
            validate_settlement_protocol_input(&wrong_locktime, state_locktime(), CHALLENGE_DELAY),
            Err(TransactionTemplateError::UnexpectedSettlementLocktime { .. })
        ));

        let mut final_sequence = templates.settlement_tx.clone();
        final_sequence.input[0].sequence = Sequence::MAX;
        assert!(matches!(
            validate_settlement_protocol_input(&final_sequence, state_locktime(), CHALLENGE_DELAY),
            Err(TransactionTemplateError::FinalProtocolInputSequence { .. })
        ));

        let mut disabled_bip68 = templates.settlement_tx.clone();
        disabled_bip68.input[0].sequence = Sequence::from_consensus(0x8000_0000 | 12);
        assert!(matches!(
            validate_settlement_protocol_input(&disabled_bip68, state_locktime(), CHALLENGE_DELAY),
            Err(TransactionTemplateError::ProtocolInputSequenceDisablesBip68 { .. })
        ));

        let mut wrong_delay = templates.settlement_tx.clone();
        wrong_delay.input[0].sequence = Sequence::from_height(CHALLENGE_DELAY + 1);
        assert!(matches!(
            validate_settlement_protocol_input(&wrong_delay, state_locktime(), CHALLENGE_DELAY),
            Err(TransactionTemplateError::UnexpectedSettlementInputSequence { sequence })
                if sequence == Sequence::from_height(CHALLENGE_DELAY + 1)
        ));

        assert!(validate_settlement_protocol_input(
            &templates.settlement_tx,
            state_locktime(),
            CHALLENGE_DELAY
        )
        .is_ok());
    }

    #[test]
    fn zero_challenge_delay_is_rejected() {
        let result = build_settlement_tx(
            placeholder_outpoint(),
            INPUT_AMOUNT,
            recovery_script(),
            state_locktime(),
            0,
            FeePolicy::ZeroFeeEphemeralAnchor,
        );

        assert!(matches!(
            result,
            Err(TransactionTemplateError::InvalidChallengeDelay { challenge_delay: 0 })
        ));
    }

    #[test]
    fn state_locktime_finality_validation() {
        assert!(validate_immediately_final(state_locktime(), CURRENT_MTP).is_ok());

        let future_locktime = absolute::LockTime::from_consensus(CURRENT_MTP);
        assert!(matches!(
            validate_immediately_final(future_locktime, CURRENT_MTP),
            Err(TransactionTemplateError::StateLocktimeNotFinal { .. })
        ));
    }

    #[test]
    fn builder_rejects_state_zero_and_invalid_locktimes() {
        let zero = build_state_templates(
            &Secp256k1::new(),
            aggregate_key(),
            placeholder_outpoint(),
            INPUT_AMOUNT,
            recovery_script(),
            0,
            state_locktime(),
            CHALLENGE_DELAY,
            FeePolicy::ZeroFeeEphemeralAnchor,
        );
        assert!(matches!(
            zero,
            Err(TransactionTemplateError::InvalidStateNumber { state_number: 0 })
        ));

        let height_type = build_update_tx(
            placeholder_outpoint(),
            INPUT_AMOUNT,
            recovery_script(),
            absolute::LockTime::from_consensus(script::LOCKTIME_TIMESTAMP_THRESHOLD - 1),
            FeePolicy::ZeroFeeEphemeralAnchor,
        );
        assert!(matches!(
            height_type,
            Err(TransactionTemplateError::Script(_))
        ));

        let no_gate = build_update_tx(
            placeholder_outpoint(),
            INPUT_AMOUNT,
            recovery_script(),
            absolute::LockTime::from_consensus(u32::MAX),
            FeePolicy::ZeroFeeEphemeralAnchor,
        );
        assert!(matches!(no_gate, Err(TransactionTemplateError::Script(_))));
    }

    #[test]
    fn builder_rejects_dust_and_fee_over_input() {
        let dust = build_update_tx(
            placeholder_outpoint(),
            100,
            recovery_script(),
            state_locktime(),
            FeePolicy::ZeroFeeEphemeralAnchor,
        );
        assert!(matches!(
            dust,
            Err(TransactionTemplateError::DustOutput { .. })
        ));

        let fee_over_input = build_update_tx(
            placeholder_outpoint(),
            INPUT_AMOUNT,
            recovery_script(),
            state_locktime(),
            FeePolicy::PrototypeFixedFeeNoAnchor { fee: INPUT_AMOUNT },
        );
        assert!(matches!(
            fee_over_input,
            Err(TransactionTemplateError::FeeExceedsInput { .. })
        ));
    }

    #[test]
    fn prototype_fixed_fee_policy_omits_anchor_and_decrements_value() {
        let fee = 1_000;
        let update = build_update_tx(
            placeholder_outpoint(),
            INPUT_AMOUNT,
            recovery_script(),
            state_locktime(),
            FeePolicy::PrototypeFixedFeeNoAnchor { fee },
        )
        .unwrap();

        assert_eq!(update.output.len(), 1);
        assert_eq!(update.output[0].value, INPUT_AMOUNT - fee);
    }

    #[test]
    fn prototype_fixed_fee_state_templates_track_settlement_input_amount() {
        let secp = Secp256k1::new();
        let fee = 1_000;
        let fee_policy = FeePolicy::PrototypeFixedFeeNoAnchor { fee };
        let recovery = recovery_script();
        let templates = build_state_templates(
            &secp,
            aggregate_key(),
            placeholder_outpoint(),
            INPUT_AMOUNT,
            recovery.clone(),
            STATE_NUMBER,
            state_locktime(),
            CHALLENGE_DELAY,
            fee_policy,
        )
        .unwrap();

        assert_eq!(templates.update_input_amount, INPUT_AMOUNT);
        assert_eq!(templates.settlement_input_amount, INPUT_AMOUNT - fee);
        assert_eq!(templates.update_tx.output[0].value, INPUT_AMOUNT - fee);
        assert_eq!(
            templates.settlement_tx.output[0].value,
            INPUT_AMOUNT - 2 * fee
        );

        assert!(validate_fee_bump_outputs(
            &templates.update_tx,
            &templates.state_output_script_pubkey,
            templates.update_input_amount,
            fee_policy,
        )
        .is_ok());
        assert!(validate_fee_bump_outputs(
            &templates.settlement_tx,
            &recovery,
            templates.settlement_input_amount,
            fee_policy,
        )
        .is_ok());
        assert!(validate_fee_bump_outputs(
            &templates.settlement_tx,
            &recovery,
            templates.update_input_amount,
            fee_policy,
        )
        .is_err());

        assert!(validate_state_template_set(
            &secp,
            aggregate_key(),
            STATE_NUMBER,
            state_locktime(),
            templates.update_input_amount,
            &recovery,
            CHALLENGE_DELAY,
            fee_policy,
            &templates.update_tx,
            &templates.settlement_tx,
        )
        .is_ok());
    }

    #[test]
    fn update_output_commits_to_settlement_template_hash() {
        let secp = Secp256k1::new();
        let base = sample_templates();

        let other_recovery = Builder::new().push_slice([9u8; 32]).into_script();
        let other = build_state_templates(
            &secp,
            aggregate_key(),
            placeholder_outpoint(),
            INPUT_AMOUNT,
            other_recovery,
            STATE_NUMBER,
            state_locktime(),
            CHALLENGE_DELAY,
            FeePolicy::ZeroFeeEphemeralAnchor,
        )
        .unwrap();

        assert_ne!(
            base.settlement_template_hash,
            other.settlement_template_hash
        );
        assert_ne!(
            base.update_tx.output[0].script_pubkey,
            other.update_tx.output[0].script_pubkey
        );

        assert!(verify_state_output_script_pubkey(
            &secp,
            aggregate_key(),
            state_locktime(),
            base.settlement_template_hash,
            &base.update_tx.output[0].script_pubkey,
        )
        .unwrap());
        assert!(!verify_state_output_script_pubkey(
            &secp,
            aggregate_key(),
            state_locktime(),
            other.settlement_template_hash,
            &base.update_tx.output[0].script_pubkey,
        )
        .unwrap());

        // Both acceptance paths must reconstruct the identical scriptPubKey.
        assert_eq!(
            expected_state_output_script_pubkey(
                &secp,
                aggregate_key(),
                state_locktime(),
                base.settlement_template_hash,
            )
            .unwrap(),
            base.update_tx.output[0].script_pubkey
        );
    }

    #[test]
    fn state_template_set_validation_reconstructs_update_output_script() {
        let secp = Secp256k1::new();
        let templates = sample_templates();
        let recovery = recovery_script();

        assert_eq!(
            validate_state_template_set(
                &secp,
                aggregate_key(),
                STATE_NUMBER,
                state_locktime(),
                INPUT_AMOUNT,
                &recovery,
                CHALLENGE_DELAY,
                FeePolicy::ZeroFeeEphemeralAnchor,
                &templates.update_tx,
                &templates.settlement_tx,
            )
            .unwrap(),
            templates.settlement_template_hash
        );

        let stale_state_locktime = absolute::LockTime::from_consensus(STATE_LOCKTIME - 1);
        let stale_spend_info = state_spend_info(
            &secp,
            aggregate_key(),
            stale_state_locktime,
            templates.settlement_template_hash,
        )
        .unwrap();
        let mut wrong_state_output = templates.update_tx.clone();
        wrong_state_output.output[0].script_pubkey = output_script_pubkey(&stale_spend_info);

        // The low-level pieces can be composed unsafely if the expected script
        // is taken from the transaction itself.
        assert!(validate_update_protocol_input(&wrong_state_output, state_locktime()).is_ok());
        assert!(validate_fee_bump_outputs(
            &wrong_state_output,
            &wrong_state_output.output[0].script_pubkey,
            INPUT_AMOUNT,
            FeePolicy::ZeroFeeEphemeralAnchor,
        )
        .is_ok());
        assert!(
            update_can_satisfy_state_gate(&sample_templates().update_tx, stale_state_locktime,)
                .unwrap()
        );

        assert!(matches!(
            validate_state_template_set(
                &secp,
                aggregate_key(),
                STATE_NUMBER,
                state_locktime(),
                INPUT_AMOUNT,
                &recovery,
                CHALLENGE_DELAY,
                FeePolicy::ZeroFeeEphemeralAnchor,
                &wrong_state_output,
                &templates.settlement_tx,
            ),
            Err(TransactionTemplateError::UnexpectedOutputSet {
                fee_policy: FeePolicy::ZeroFeeEphemeralAnchor
            })
        ));
    }

    #[test]
    fn lookalike_leaves_are_rejected_by_exact_byte_checks() {
        let templates = sample_templates();
        let update_leaf = script::state_update_leaf(state_locktime()).unwrap();
        let settlement_leaf = script::state_settlement_leaf(templates.settlement_template_hash);

        assert!(is_expected_funding_update_leaf(
            &script::funding_update_leaf()
        ));
        assert!(is_expected_state_update_leaf(&update_leaf, state_locktime()).unwrap());
        assert!(is_expected_state_settlement_leaf(
            &settlement_leaf,
            templates.settlement_template_hash
        ));

        // Explicit 33-byte pubkey instead of OP_INTERNALKEY: BIP348 would
        // treat it as an auto-succeeding unknown key type.
        let explicit_key_leaf = Builder::new()
            .push_lock_time(state_update_gate_locktime(state_locktime()).unwrap())
            .push_opcode(OP_CLTV)
            .push_opcode(OP_DROP)
            .push_opcode(OP_TEMPLATEHASH)
            .push_slice([2u8; 33])
            .push_opcode(OP_CHECKSIGFROMSTACK)
            .into_script();
        assert!(!is_expected_state_update_leaf(&explicit_key_leaf, state_locktime()).unwrap());

        // Reordered opcodes.
        let reordered_leaf = Builder::new()
            .push_lock_time(state_update_gate_locktime(state_locktime()).unwrap())
            .push_opcode(OP_CLTV)
            .push_opcode(OP_DROP)
            .push_opcode(OP_TEMPLATEHASH)
            .push_opcode(OP_EQUAL)
            .into_script();
        assert!(!is_expected_state_update_leaf(&reordered_leaf, state_locktime()).unwrap());

        // Wrong explicit locktime gate.
        assert!(!is_expected_state_update_leaf(
            &update_leaf,
            absolute::LockTime::from_consensus(STATE_LOCKTIME + 1),
        )
        .unwrap());

        // The settlement leaf is exact hash equality only; a redundant CLTV prefix
        // is a different script and must not be accepted as the protocol leaf.
        let cltv_prefixed_settlement_leaf = Builder::new()
            .push_lock_time(state_locktime())
            .push_opcode(OP_CLTV)
            .push_opcode(OP_DROP)
            .push_slice(templates.settlement_template_hash.to_byte_array())
            .push_opcode(OP_TEMPLATEHASH)
            .push_opcode(OP_EQUAL)
            .into_script();
        assert!(!is_expected_state_settlement_leaf(
            &cltv_prefixed_settlement_leaf,
            templates.settlement_template_hash
        ));
    }

    #[test]
    fn fee_bump_output_validation_matches_policy() {
        let templates = sample_templates();

        assert!(validate_fee_bump_outputs(
            &templates.update_tx,
            &templates.state_output_script_pubkey,
            INPUT_AMOUNT,
            FeePolicy::ZeroFeeEphemeralAnchor,
        )
        .is_ok());

        let mut missing_anchor = templates.update_tx.clone();
        missing_anchor.output.pop();
        assert!(validate_fee_bump_outputs(
            &missing_anchor,
            &templates.state_output_script_pubkey,
            INPUT_AMOUNT,
            FeePolicy::ZeroFeeEphemeralAnchor,
        )
        .is_err());

        let mut mutated_anchor = templates.update_tx.clone();
        mutated_anchor.output[1].value = 1;
        assert!(validate_fee_bump_outputs(
            &mutated_anchor,
            &templates.state_output_script_pubkey,
            INPUT_AMOUNT,
            FeePolicy::ZeroFeeEphemeralAnchor,
        )
        .is_err());
    }

    #[test]
    fn fee_bump_validation_rejects_dust_main_outputs() {
        let templates = sample_templates();

        let mut dust_update = templates.update_tx.clone();
        dust_update.output[0].value = 1;
        assert!(matches!(
            validate_fee_bump_outputs(
                &dust_update,
                &templates.state_output_script_pubkey,
                1,
                FeePolicy::ZeroFeeEphemeralAnchor,
            ),
            Err(TransactionTemplateError::DustOutput { value: 1, .. })
        ));
        assert!(matches!(
            rebind_update_tx(
                &dust_update,
                funding_outpoint(11, 0),
                1,
                FeePolicy::ZeroFeeEphemeralAnchor,
            ),
            Err(TransactionTemplateError::DustOutput { value: 1, .. })
        ));
        assert!(matches!(
            validate_state_template_set(
                &Secp256k1::new(),
                aggregate_key(),
                STATE_NUMBER,
                state_locktime(),
                1,
                &recovery_script(),
                CHALLENGE_DELAY,
                FeePolicy::ZeroFeeEphemeralAnchor,
                &dust_update,
                &templates.settlement_tx,
            ),
            Err(TransactionTemplateError::DustOutput { value: 1, .. })
        ));

        // Settlement main output must also be non-dust. Note we cannot exercise
        // this through validate_state_template_set with a matching update, because
        // mutating the settlement output changes its template hash and the update
        // would fail output-script reconstruction first; the direct output and
        // rebind paths isolate the settlement dust check.
        let mut dust_settlement = templates.settlement_tx.clone();
        dust_settlement.output[0].value = 1;
        assert!(matches!(
            validate_fee_bump_outputs(
                &dust_settlement,
                &recovery_script(),
                1,
                FeePolicy::ZeroFeeEphemeralAnchor,
            ),
            Err(TransactionTemplateError::DustOutput { value: 1, .. })
        ));
        assert!(matches!(
            rebind_settlement_tx(
                &dust_settlement,
                funding_outpoint(11, 1),
                1,
                FeePolicy::ZeroFeeEphemeralAnchor,
            ),
            Err(TransactionTemplateError::DustOutput { value: 1, .. })
        ));

        let fee_policy = FeePolicy::PrototypeFixedFeeNoAnchor { fee: 1_000 };
        let recovery = recovery_script();
        let mut fixed_fee_update = build_update_tx(
            placeholder_outpoint(),
            INPUT_AMOUNT,
            recovery.clone(),
            state_locktime(),
            fee_policy,
        )
        .unwrap();
        fixed_fee_update.output[0].value = 1;
        assert!(matches!(
            validate_fee_bump_outputs(&fixed_fee_update, &recovery, 1_001, fee_policy),
            Err(TransactionTemplateError::DustOutput { value: 1, .. })
        ));
    }

    fn sample_templates() -> StateTemplates {
        sample_templates_for_state(STATE_NUMBER)
    }

    fn sample_templates_for_state(state_number: u32) -> StateTemplates {
        sample_templates_for_state_and_locktime(state_number, STATE_LOCKTIME)
    }

    fn sample_templates_for_state_and_locktime(
        state_number: u32,
        state_locktime: u32,
    ) -> StateTemplates {
        let secp = Secp256k1::new();
        build_state_templates(
            &secp,
            aggregate_key(),
            placeholder_outpoint(),
            INPUT_AMOUNT,
            recovery_script(),
            state_number,
            absolute::LockTime::from_consensus(state_locktime),
            CHALLENGE_DELAY,
            FeePolicy::ZeroFeeEphemeralAnchor,
        )
        .unwrap()
    }

    fn recovery_script() -> ScriptBuf {
        Builder::new().push_slice([7u8; 32]).into_script()
    }

    fn funding_outpoint(txid_seed: u8, vout: u32) -> OutPoint {
        OutPoint {
            txid: Txid::from_slice(&[txid_seed; 32]).unwrap(),
            vout,
        }
    }
}
