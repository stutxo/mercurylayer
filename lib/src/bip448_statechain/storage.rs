use std::str::FromStr;

use bitcoin::{
    absolute, consensus::encode, hashes::Hash, taproot::ControlBlock, OutPoint, ScriptBuf,
    Transaction, TxOut, Witness,
};
use secp256k1::{schnorr, Message, PublicKey, Secp256k1, Signing, Verification};
use serde::{Deserialize, Serialize};

use crate::bip448_statechain::signing::{csfs_negate_seckey, csfs_script_witness};
use crate::bip448_statechain::{script, transaction};

/// Failure to bind a BIP448 recovery record to keys the receiver trusts.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Bip448RecoveryVerifyError {
    #[error("recomputed aggregate key does not match the record's aggregate_pubkey")]
    AggregateKeyMismatch,
    #[error("CSFS key metadata does not match the recomputed aggregate key")]
    KeyMetadataMismatch,
    #[error("update template hash is not 32 bytes of hex")]
    InvalidTemplateHash,
    #[error("update signature is not a valid BIP340 signature")]
    InvalidUpdateSignature,
    #[error("update signature does not verify against the recomputed aggregate key")]
    UpdateSignatureVerification,
    #[error("funding outpoint txid is not a valid transaction id")]
    InvalidFundingTxid,
    #[error("recovery record field `{0}` is internally inconsistent")]
    InconsistentField(&'static str),
    #[error("reconstructed template field `{0}` does not match the record's value")]
    TemplateFieldMismatch(&'static str),
    #[error("record field `{0}` does not match the trusted receiver context")]
    TrustedFieldMismatch(&'static str),
    #[error(
        "BIP448 state locktime {locktime} is not immediately final at chain median time past {median_time_past}"
    )]
    StateLocktimeNotFinal {
        locktime: u32,
        median_time_past: u32,
    },
    #[error("initial funding recovery verification requires logical state 1, got {state_number}")]
    UnsupportedInitialStateNumber { state_number: u32 },
    #[error("recovery record contains unverified sender metadata in `{0}`")]
    UnverifiedSenderMetadata(&'static str),
    #[error("failed to reconstruct BIP448 recovery templates: {0}")]
    Reconstruction(String),
    #[error("recovery verification does not yet support role {0:?}")]
    UnsupportedRecoveryRole(Bip448RecoveryTemplateRole),
    #[error("secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),
}

/// Parsed update authority proven against receiver-trusted recovery keys.
///
/// The private fields ensure template reconstruction cannot manufacture this
/// proof from sender strings without first completing the key-binding check.
pub(crate) struct Bip448VerifiedRecoveryBinding {
    aggregate_pubkey: PublicKey,
    update_signature: schnorr::Signature,
}

impl Bip448VerifiedRecoveryBinding {
    pub(crate) fn aggregate_pubkey(&self) -> &PublicKey {
        &self.aggregate_pubkey
    }

    pub(crate) fn into_aggregate_pubkey(self) -> PublicKey {
        self.aggregate_pubkey
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Bip448RecoveryArtifactError {
    #[error("BIP448 recovery transaction template error: {0}")]
    TransactionTemplate(#[from] transaction::TransactionTemplateError),
    #[error("BIP448 recovery script template error: {0}")]
    ScriptTemplate(#[from] script::ScriptTemplateError),
    #[error("BIP448 recovery update signature is invalid")]
    InvalidUpdateSignature,
    #[error("BIP448 recovery update signature does not verify against the aggregate key")]
    UpdateSignatureVerification,
    #[error("BIP448 recovery aggregate key does not match the artifact builder key")]
    AggregateKeyMismatch,
    #[error("BIP448 recovery latest-state builder does not support role {0:?}")]
    UnsupportedRecoveryRole(Bip448RecoveryTemplateRole),
    #[error("BIP448 recovery signing metadata has the wrong update template hash")]
    UpdateTemplateHashMismatch,
    #[error("BIP448 accepted latest state cannot contain unverified CPFP child templates")]
    UnverifiedCpfpChildTemplates,
    #[error("BIP448 recovery transaction {role:?} is missing anchor output {output_index}")]
    MissingAnchor {
        role: Bip448RecoveryTemplateRole,
        output_index: usize,
    },
    #[error("BIP448 recovery artifacts are not a canonical self-consistent template set")]
    InconsistentArtifacts,
}

/// The durable outpoint and value of a BIP448 statechain funding output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bip448FundingOutpoint {
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
}

/// Serializable fee-bump policy chosen for committed recovery templates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Bip448FeeBumpPolicy {
    ZeroFeeEphemeralAnchor,
}

impl Bip448FeeBumpPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ZeroFeeEphemeralAnchor => "zero_fee_ephemeral_anchor",
        }
    }
}

/// The value schedule committed by the latest update/settlement pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bip448ValueSchedule {
    pub funding_value_sats: u64,
    pub update_input_value_sats: u64,
    pub update_state_output_value_sats: u64,
    pub settlement_input_value_sats: u64,
    pub settlement_recovery_output_value_sats: u64,
}

/// A committed anchor output in a recovery template.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bip448AnchorOutput {
    pub tx_role: Bip448RecoveryTemplateRole,
    pub output_index: u32,
    pub value_sats: u64,
    pub script_pubkey: String,
}

/// A CPFP child template or placeholder associated with a committed anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bip448CpfpChildTemplate {
    pub parent_role: Bip448RecoveryTemplateRole,
    pub anchor_output_index: u32,
    pub tx_hex: String,
    pub fee_sats: u64,
    pub target_feerate_sat_per_vbyte: Option<u64>,
}

/// The role of a recoverable BIP448 transaction template.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Bip448RecoveryTemplateRole {
    FundingUpdate,
    StateUpdate,
    Settlement,
}

impl Bip448RecoveryTemplateRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FundingUpdate => "funding_update",
            Self::StateUpdate => "state_update",
            Self::Settlement => "settlement",
        }
    }
}

/// CSFS aggregate-key metadata needed to rederive BIP340 share negation.
///
/// `aggregate_pubkey_parity_odd` records the Y-parity of `P_full`, while
/// `negate_seckey` records whether the CSFS shares must be negated. Under the
/// current untweaked flow (`UNTWEAKED_PARITY_ACC = 0`) these are always equal —
/// the negation flag reduces to the parity of `P_full`. Both are kept as
/// distinct explicit protocol state so that, if the parity accumulator ever
/// changes, the persisted metadata continues to record each independently; the
/// receiver's binding check recomputes both from the aggregate key regardless.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bip448CsfsKeyMetadata {
    pub aggregate_pubkey_parity_odd: bool,
    pub negate_seckey: bool,
}

pub fn aggregate_pubkey_parity_odd(aggregate_pubkey: &PublicKey) -> bool {
    aggregate_pubkey.serialize()[0] == 0x03
}

impl Bip448CsfsKeyMetadata {
    pub fn from_aggregate_pubkey<C: Signing>(
        secp: &Secp256k1<C>,
        aggregate_pubkey: &PublicKey,
    ) -> Self {
        Self {
            aggregate_pubkey_parity_odd: aggregate_pubkey_parity_odd(aggregate_pubkey),
            negate_seckey: csfs_negate_seckey(secp, aggregate_pubkey),
        }
    }

    pub fn verifies_aggregate_pubkey<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        aggregate_pubkey: &PublicKey,
    ) -> bool {
        self == &Self::from_aggregate_pubkey(secp, aggregate_pubkey)
    }
}

/// Blind-signing metadata for the latest signed update template.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bip448SigningMetadata {
    pub role: Bip448RecoveryTemplateRole,
    pub signing_id: String,
    pub client_public_nonce: String,
    pub server_public_nonce: String,
    pub blinding_factor: String,
    pub update_template_hash: String,
    pub update_signature: String,
    pub server_signature_count: u64,
}

/// Typed deterministic recovery data derived from trusted protocol inputs.
///
/// This is the canonical construction result shared by deposit creation and
/// receiver verification. It deliberately excludes signing retry metadata,
/// server counters, transfer signatures, and chain truth: those values are not
/// deterministic template fields and must be verified separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip448RecoveryArtifacts {
    pub aggregate_pubkey: PublicKey,
    pub state_number: u32,
    pub state_locktime: u32,
    pub challenge_delay: u16,
    pub update_tx: Transaction,
    pub settlement_tx: Transaction,
    pub update_template_hash: bitcoin::sighash::TemplateHash,
    pub settlement_template_hash: bitcoin::sighash::TemplateHash,
    pub state_output_script_pubkey: ScriptBuf,
    pub funding_output_script_pubkey: ScriptBuf,
    pub funding_update_script: ScriptBuf,
    pub funding_update_control_block: ControlBlock,
    pub state_update_script: ScriptBuf,
    pub state_update_control_block: ControlBlock,
    pub state_settlement_script: ScriptBuf,
    pub state_settlement_control_block: ControlBlock,
    pub fee_bump_policy: Bip448FeeBumpPolicy,
    pub value_schedule: Bip448ValueSchedule,
    pub anchors: Vec<Bip448AnchorOutput>,
}

/// Canonical serialized subset of [`Bip448LatestState`] that a receiver can
/// derive independently. Acceptance compares its encoded byte fields by decoded
/// bytes, while this type supplies the canonical lowercase representation;
/// sender-originated operational metadata is intentionally absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip448ExpectedLatestStateFields {
    pub state_locktime: u32,
    pub update_tx: String,
    pub settlement_tx: String,
    pub update_template_hash: String,
    pub settlement_template_hash: String,
    pub state_output_script_pubkey: String,
    pub funding_update_script: String,
    pub funding_update_control_block: String,
    pub state_update_script: String,
    pub state_update_control_block: String,
    pub state_settlement_script: String,
    pub state_settlement_control_block: String,
    pub value_schedule: Bip448ValueSchedule,
    pub anchors: Vec<Bip448AnchorOutput>,
}

impl Bip448ExpectedLatestStateFields {
    fn matches_expected(&self, expected: &Self) -> bool {
        self.state_locktime == expected.state_locktime
            && encoded_hex_eq(&self.update_tx, &expected.update_tx)
            && encoded_hex_eq(&self.settlement_tx, &expected.settlement_tx)
            && template_hash_hex_eq(&self.update_template_hash, &expected.update_template_hash)
            && template_hash_hex_eq(
                &self.settlement_template_hash,
                &expected.settlement_template_hash,
            )
            && encoded_hex_eq(
                &self.state_output_script_pubkey,
                &expected.state_output_script_pubkey,
            )
            && encoded_hex_eq(&self.funding_update_script, &expected.funding_update_script)
            && encoded_hex_eq(
                &self.funding_update_control_block,
                &expected.funding_update_control_block,
            )
            && encoded_hex_eq(&self.state_update_script, &expected.state_update_script)
            && encoded_hex_eq(
                &self.state_update_control_block,
                &expected.state_update_control_block,
            )
            && encoded_hex_eq(
                &self.state_settlement_script,
                &expected.state_settlement_script,
            )
            && encoded_hex_eq(
                &self.state_settlement_control_block,
                &expected.state_settlement_control_block,
            )
            && self.value_schedule == expected.value_schedule
            && anchor_outputs_match(&self.anchors, &expected.anchors)
    }
}

pub fn build_funding_recovery_artifacts<C: Verification>(
    secp: &Secp256k1<C>,
    aggregate_pubkey: &PublicKey,
    funding_outpoint: OutPoint,
    funding_value_sats: u64,
    recovery_script: ScriptBuf,
    state_number: u32,
    state_locktime: absolute::LockTime,
    challenge_delay: u16,
    fee_bump_policy: Bip448FeeBumpPolicy,
) -> Result<Bip448RecoveryArtifacts, Bip448RecoveryArtifactError> {
    if state_number == crate::bip448_statechain::deposit::INITIAL_BIP448_STATE_NUMBER {
        script::validate_initial_state_locktime(state_locktime)?;
    } else {
        script::validate_state_locktime(state_locktime)?;
    }
    let aggregate_xonly = aggregate_pubkey.x_only_public_key().0;
    let fee_policy = transaction_fee_policy(fee_bump_policy);
    let templates = transaction::build_state_templates(
        secp,
        aggregate_xonly,
        transaction::placeholder_outpoint(),
        funding_value_sats,
        recovery_script.clone(),
        state_number,
        state_locktime,
        challenge_delay,
        fee_policy,
    )?;
    let update_tx = transaction::rebind_update_tx(
        &templates.update_tx,
        funding_outpoint,
        funding_value_sats,
        fee_policy,
    )?;
    let settlement_tx = transaction::rebind_settlement_tx(
        &templates.settlement_tx,
        OutPoint {
            txid: update_tx.txid(),
            vout: 0,
        },
        templates.settlement_input_amount,
        fee_policy,
    )?;
    let settlement_template_hash = transaction::validate_state_template_set(
        secp,
        aggregate_xonly,
        state_number,
        state_locktime,
        funding_value_sats,
        &recovery_script,
        challenge_delay,
        fee_policy,
        &update_tx,
        &settlement_tx,
    )?;
    let update_template_hash = transaction::update_template_hash(&update_tx)?;
    let funding_spend_info = script::funding_spend_info(secp, aggregate_xonly)?;
    let state_spend_info = script::state_spend_info(
        secp,
        aggregate_xonly,
        state_locktime,
        settlement_template_hash,
    )?;
    let funding_update_script = script::funding_update_leaf();
    let funding_update_control_block = script::funding_update_control_block(&funding_spend_info)?;
    let state_update_script = script::state_update_leaf(state_locktime)?;
    let state_update_control_block =
        script::state_update_control_block(&state_spend_info, state_locktime)?;
    let state_settlement_script = script::state_settlement_leaf(settlement_template_hash);
    let state_settlement_control_block =
        script::state_settlement_control_block(&state_spend_info, settlement_template_hash)?;

    Ok(Bip448RecoveryArtifacts {
        aggregate_pubkey: aggregate_pubkey.clone(),
        state_number,
        state_locktime: state_locktime.to_consensus_u32(),
        challenge_delay,
        update_template_hash,
        settlement_template_hash,
        state_output_script_pubkey: templates.state_output_script_pubkey,
        funding_output_script_pubkey: script::output_script_pubkey(&funding_spend_info),
        funding_update_script,
        funding_update_control_block,
        state_update_script,
        state_update_control_block,
        state_settlement_script,
        state_settlement_control_block,
        fee_bump_policy,
        value_schedule: Bip448ValueSchedule {
            funding_value_sats: templates.update_input_amount,
            update_input_value_sats: templates.update_input_amount,
            update_state_output_value_sats: templates.settlement_input_amount,
            settlement_input_value_sats: templates.settlement_input_amount,
            settlement_recovery_output_value_sats: settlement_tx.output[0].value,
        },
        anchors: vec![
            anchor_output(Bip448RecoveryTemplateRole::FundingUpdate, &update_tx, 1)?,
            anchor_output(Bip448RecoveryTemplateRole::Settlement, &settlement_tx, 1)?,
        ],
        update_tx,
        settlement_tx,
    })
}

impl Bip448RecoveryArtifacts {
    pub fn expected_funding_latest_state_fields(
        &self,
        signature: &schnorr::Signature,
    ) -> Bip448ExpectedLatestStateFields {
        let mut update_tx = self.update_tx.clone();
        update_tx.input[0].witness = csfs_script_witness(
            signature,
            &self.funding_update_script,
            &self.funding_update_control_block,
        );
        let mut settlement_tx = self.settlement_tx.clone();
        settlement_tx.input[0].witness = settlement_template_witness(
            &self.state_settlement_script,
            &self.state_settlement_control_block,
        );

        Bip448ExpectedLatestStateFields {
            state_locktime: self.state_locktime,
            update_tx: tx_hex(&update_tx),
            settlement_tx: tx_hex(&settlement_tx),
            update_template_hash: hex::encode(self.update_template_hash.to_byte_array()),
            settlement_template_hash: hex::encode(self.settlement_template_hash.to_byte_array()),
            state_output_script_pubkey: script_hex(&self.state_output_script_pubkey),
            funding_update_script: script_hex(&self.funding_update_script),
            funding_update_control_block: control_block_hex(&self.funding_update_control_block),
            state_update_script: script_hex(&self.state_update_script),
            state_update_control_block: control_block_hex(&self.state_update_control_block),
            state_settlement_script: script_hex(&self.state_settlement_script),
            state_settlement_control_block: control_block_hex(&self.state_settlement_control_block),
            value_schedule: self.value_schedule.clone(),
            anchors: self.anchors.clone(),
        }
    }
}

pub fn build_funding_latest_state<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    aggregate_pubkey: &PublicKey,
    artifacts: &Bip448RecoveryArtifacts,
    mut signing_metadata: Bip448SigningMetadata,
    cpfp_child_templates: Vec<Bip448CpfpChildTemplate>,
) -> Result<Bip448LatestState, Bip448RecoveryArtifactError> {
    validate_funding_recovery_artifacts(secp, artifacts)?;
    if !cpfp_child_templates.is_empty() {
        return Err(Bip448RecoveryArtifactError::UnverifiedCpfpChildTemplates);
    }
    if &artifacts.aggregate_pubkey != aggregate_pubkey {
        return Err(Bip448RecoveryArtifactError::AggregateKeyMismatch);
    }
    if signing_metadata.role != Bip448RecoveryTemplateRole::FundingUpdate {
        return Err(Bip448RecoveryArtifactError::UnsupportedRecoveryRole(
            signing_metadata.role,
        ));
    }
    let expected_update_template_hash = hex::encode(artifacts.update_template_hash.to_byte_array());
    if !template_hash_hex_eq(
        &signing_metadata.update_template_hash,
        &expected_update_template_hash,
    ) {
        return Err(Bip448RecoveryArtifactError::UpdateTemplateHashMismatch);
    }
    let signature = schnorr::Signature::from_str(&signing_metadata.update_signature)
        .map_err(|_| Bip448RecoveryArtifactError::InvalidUpdateSignature)?;
    let aggregate_xonly = aggregate_pubkey.x_only_public_key().0;
    schnorr::verify(
        &signature,
        artifacts.update_template_hash.as_byte_array(),
        &aggregate_xonly,
    )
    .map_err(|_| Bip448RecoveryArtifactError::UpdateSignatureVerification)?;
    signing_metadata.update_template_hash = expected_update_template_hash;
    signing_metadata.update_signature = signature.to_string();
    let expected = artifacts.expected_funding_latest_state_fields(&signature);

    Ok(Bip448LatestState::from_expected_fields(
        artifacts.state_number,
        artifacts.challenge_delay,
        expected,
        Bip448CsfsKeyMetadata::from_aggregate_pubkey(secp, aggregate_pubkey),
        signing_metadata,
        artifacts.fee_bump_policy,
    ))
}

/// Durable latest-state data for receiver validation and local recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bip448LatestState {
    pub state_number: u32,
    pub state_locktime: u32,
    pub challenge_delay: u16,
    pub update_tx: String,
    pub settlement_tx: String,
    pub update_template_hash: String,
    pub settlement_template_hash: String,
    pub state_output_script_pubkey: String,
    pub funding_update_script: String,
    pub funding_update_control_block: String,
    pub state_update_script: String,
    pub state_update_control_block: String,
    pub state_settlement_script: String,
    pub state_settlement_control_block: String,
    pub csfs_key_metadata: Bip448CsfsKeyMetadata,
    pub signing_metadata: Bip448SigningMetadata,
    pub fee_bump_policy: Bip448FeeBumpPolicy,
    pub value_schedule: Bip448ValueSchedule,
    pub anchors: Vec<Bip448AnchorOutput>,
    pub cpfp_child_templates: Vec<Bip448CpfpChildTemplate>,
}

impl Bip448LatestState {
    fn from_expected_fields(
        state_number: u32,
        challenge_delay: u16,
        expected: Bip448ExpectedLatestStateFields,
        csfs_key_metadata: Bip448CsfsKeyMetadata,
        signing_metadata: Bip448SigningMetadata,
        fee_bump_policy: Bip448FeeBumpPolicy,
    ) -> Self {
        Self {
            state_number,
            state_locktime: expected.state_locktime,
            challenge_delay,
            update_tx: expected.update_tx,
            settlement_tx: expected.settlement_tx,
            update_template_hash: expected.update_template_hash,
            settlement_template_hash: expected.settlement_template_hash,
            state_output_script_pubkey: expected.state_output_script_pubkey,
            funding_update_script: expected.funding_update_script,
            funding_update_control_block: expected.funding_update_control_block,
            state_update_script: expected.state_update_script,
            state_update_control_block: expected.state_update_control_block,
            state_settlement_script: expected.state_settlement_script,
            state_settlement_control_block: expected.state_settlement_control_block,
            csfs_key_metadata,
            signing_metadata,
            fee_bump_policy,
            value_schedule: expected.value_schedule,
            anchors: expected.anchors,
            cpfp_child_templates: Vec::new(),
        }
    }

    /// Verifies the CSFS key metadata and the stored update signature against an
    /// aggregate key `P` recomputed from keys the receiver trusts — its own user
    /// public key plus the server public key it confirms out of band — instead
    /// of trusting a sender-provided `aggregate_pubkey`. Recovery authority is
    /// `P = receiver_user_pubkey + server_pubkey`; a substituted aggregate key,
    /// mismatched parity/negation metadata, or an update signature that does not
    /// verify against `P.x` is rejected. Returns the recomputed `P` on success.
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

    pub(crate) fn verify_recovery_binding_against_keys<C: Verification + Signing>(
        &self,
        secp: &Secp256k1<C>,
        receiver_user_pubkey: &PublicKey,
        server_pubkey: &PublicKey,
    ) -> Result<Bip448VerifiedRecoveryBinding, Bip448RecoveryVerifyError> {
        let recomputed = receiver_user_pubkey.combine(server_pubkey)?;

        if !template_hash_hex_eq(
            &self.signing_metadata.update_template_hash,
            &self.update_template_hash,
        ) {
            return Err(Bip448RecoveryVerifyError::InconsistentField(
                "signing_metadata.update_template_hash",
            ));
        }

        if !self
            .csfs_key_metadata
            .verifies_aggregate_pubkey(secp, &recomputed)
        {
            return Err(Bip448RecoveryVerifyError::KeyMetadataMismatch);
        }

        if self.update_template_hash.len() != 64 {
            return Err(Bip448RecoveryVerifyError::InvalidTemplateHash);
        }
        let hash_bytes = hex::decode(&self.update_template_hash)
            .map_err(|_| Bip448RecoveryVerifyError::InvalidTemplateHash)?;
        let message = Message::from_slice(&hash_bytes)
            .map_err(|_| Bip448RecoveryVerifyError::InvalidTemplateHash)?;
        let signature = schnorr::Signature::from_str(&self.signing_metadata.update_signature)
            .map_err(|_| Bip448RecoveryVerifyError::InvalidUpdateSignature)?;
        let xonly = recomputed.x_only_public_key().0;

        secp.verify_schnorr(&signature, message.as_ref(), &xonly)
            .map_err(|_| Bip448RecoveryVerifyError::UpdateSignatureVerification)?;

        Ok(Bip448VerifiedRecoveryBinding {
            aggregate_pubkey: recomputed,
            update_signature: signature,
        })
    }

    /// Reconstructs the committed update/settlement templates from keys and
    /// values the receiver trusts, then rejects the record if ANY sender-provided
    /// template field — transaction hex, template hashes, leaf scripts, control
    /// blocks, the state output script, the value schedule, or the committed
    /// anchors — disagrees with the receiver-recomputed value. This is the
    /// field-level counterpart to `verify_recovery_against_keys` (which binds the
    /// aggregate key and update signature): together they ensure a receiver never
    /// persists a template it did not independently recompute, so a malicious
    /// sender cannot smuggle in a script, hash, anchor, or value the receiver did
    /// not derive itself.
    ///
    /// `aggregate_pubkey` MUST be the value returned by
    /// `verify_recovery_against_keys` (i.e. `receiver_user_pubkey +
    /// server_pubkey`), never a sender-provided key. `recovery_script` is the
    /// receiver's own unilateral-exit output script committed in `S(n)`. The
    /// `funding_outpoint` and `funding_output` MUST come from an independent
    /// chain lookup. The trusted output value seeds reconstruction, and its
    /// scriptPubKey is checked against the aggregate-key funding output.
    /// This standalone entry point parses the signature once because it does not
    /// receive the typed key-binding result; `verify_recovery_state` carries that
    /// result into reconstruction and does not parse the signature again.
    ///
    /// Only `FundingUpdate` is supported here. A `StateUpdate` witness must use
    /// the older state output being spent, including that state's number,
    /// settlement hash, and control block; the latest state alone cannot derive
    /// a valid fast-forward witness, so unsupported roles fail closed.
    pub fn verify_reconstructed_templates<C: Verification + Signing>(
        &self,
        secp: &Secp256k1<C>,
        aggregate_pubkey: &PublicKey,
        funding_outpoint: OutPoint,
        funding_output: &TxOut,
        recovery_script: &ScriptBuf,
    ) -> Result<Bip448LatestState, Bip448RecoveryVerifyError> {
        self.verify_reconstruction_metadata(false)?;
        let signature = schnorr::Signature::from_str(&self.signing_metadata.update_signature)
            .map_err(|_| Bip448RecoveryVerifyError::InvalidUpdateSignature)?;

        self.verify_reconstructed_templates_with_signature(
            secp,
            aggregate_pubkey,
            funding_outpoint,
            funding_output,
            recovery_script,
            &signature,
        )
    }

    pub(crate) fn verify_reconstructed_templates_with_binding<C: Verification + Signing>(
        &self,
        secp: &Secp256k1<C>,
        binding: &Bip448VerifiedRecoveryBinding,
        funding_outpoint: OutPoint,
        funding_output: &TxOut,
        recovery_script: &ScriptBuf,
        allow_transferred_funding_state: bool,
    ) -> Result<Bip448LatestState, Bip448RecoveryVerifyError> {
        self.verify_reconstruction_metadata(allow_transferred_funding_state)?;
        self.verify_reconstructed_templates_with_signature(
            secp,
            &binding.aggregate_pubkey,
            funding_outpoint,
            funding_output,
            recovery_script,
            &binding.update_signature,
        )
    }

    fn verify_reconstruction_metadata(
        &self,
        allow_transferred_funding_state: bool,
    ) -> Result<(), Bip448RecoveryVerifyError> {
        if !self.cpfp_child_templates.is_empty() {
            return Err(Bip448RecoveryVerifyError::UnverifiedSenderMetadata(
                "cpfp_child_templates",
            ));
        }
        match self.signing_metadata.role {
            Bip448RecoveryTemplateRole::FundingUpdate => {
                let initial_state = crate::bip448_statechain::deposit::INITIAL_BIP448_STATE_NUMBER;
                if self.state_number != initial_state
                    && !(allow_transferred_funding_state && self.state_number > initial_state)
                {
                    return Err(Bip448RecoveryVerifyError::UnsupportedInitialStateNumber {
                        state_number: self.state_number,
                    });
                }
            }
            Bip448RecoveryTemplateRole::StateUpdate => {
                return Err(Bip448RecoveryVerifyError::UnsupportedRecoveryRole(
                    Bip448RecoveryTemplateRole::StateUpdate,
                ));
            }
            Bip448RecoveryTemplateRole::Settlement => {
                return Err(Bip448RecoveryVerifyError::InconsistentField(
                    "signing_metadata.role",
                ));
            }
        }

        Ok(())
    }

    fn verify_reconstructed_templates_with_signature<C: Verification + Signing>(
        &self,
        secp: &Secp256k1<C>,
        aggregate_pubkey: &PublicKey,
        funding_outpoint: OutPoint,
        funding_output: &TxOut,
        recovery_script: &ScriptBuf,
        signature: &schnorr::Signature,
    ) -> Result<Bip448LatestState, Bip448RecoveryVerifyError> {
        let artifacts = build_funding_recovery_artifacts(
            secp,
            aggregate_pubkey,
            funding_outpoint,
            funding_output.value,
            recovery_script.clone(),
            self.state_number,
            absolute::LockTime::from_consensus(self.state_locktime),
            self.challenge_delay,
            self.fee_bump_policy,
        )
        .map_err(reconstruction_error)?;
        let aggregate_xonly = aggregate_pubkey.x_only_public_key().0;
        schnorr::verify(
            signature,
            artifacts.update_template_hash.as_byte_array(),
            &aggregate_xonly,
        )
        .map_err(|_| Bip448RecoveryVerifyError::UpdateSignatureVerification)?;
        if artifacts.funding_output_script_pubkey != funding_output.script_pubkey {
            return Err(Bip448RecoveryVerifyError::TrustedFieldMismatch(
                "funding_output.script_pubkey",
            ));
        }
        let expected = artifacts.expected_funding_latest_state_fields(signature);
        if !self.deterministic_fields().matches_expected(&expected) {
            return Err(Bip448RecoveryVerifyError::TemplateFieldMismatch(
                "derived_latest_state",
            ));
        }

        Ok(self.canonicalized_recovery_state(secp, aggregate_pubkey, expected, signature))
    }

    fn deterministic_fields(&self) -> Bip448ExpectedLatestStateFields {
        Bip448ExpectedLatestStateFields {
            state_locktime: self.state_locktime,
            update_tx: self.update_tx.clone(),
            settlement_tx: self.settlement_tx.clone(),
            update_template_hash: self.update_template_hash.clone(),
            settlement_template_hash: self.settlement_template_hash.clone(),
            state_output_script_pubkey: self.state_output_script_pubkey.clone(),
            funding_update_script: self.funding_update_script.clone(),
            funding_update_control_block: self.funding_update_control_block.clone(),
            state_update_script: self.state_update_script.clone(),
            state_update_control_block: self.state_update_control_block.clone(),
            state_settlement_script: self.state_settlement_script.clone(),
            state_settlement_control_block: self.state_settlement_control_block.clone(),
            value_schedule: self.value_schedule.clone(),
            anchors: self.anchors.clone(),
        }
    }

    fn canonicalized_recovery_state<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        aggregate_pubkey: &PublicKey,
        expected: Bip448ExpectedLatestStateFields,
        signature: &schnorr::Signature,
    ) -> Bip448LatestState {
        let mut signing_metadata = self.signing_metadata.clone();
        signing_metadata.update_template_hash = expected.update_template_hash.clone();
        signing_metadata.update_signature = signature.to_string();

        Self::from_expected_fields(
            self.state_number,
            self.challenge_delay,
            expected,
            Bip448CsfsKeyMetadata::from_aggregate_pubkey(secp, aggregate_pubkey),
            signing_metadata,
            self.fee_bump_policy,
        )
    }
}

fn validate_funding_recovery_artifacts<C: Verification>(
    secp: &Secp256k1<C>,
    artifacts: &Bip448RecoveryArtifacts,
) -> Result<(), Bip448RecoveryArtifactError> {
    let funding_outpoint = artifacts
        .update_tx
        .input
        .first()
        .ok_or(Bip448RecoveryArtifactError::InconsistentArtifacts)?
        .previous_output;
    let recovery_script = artifacts
        .settlement_tx
        .output
        .first()
        .ok_or(Bip448RecoveryArtifactError::InconsistentArtifacts)?
        .script_pubkey
        .clone();
    let rebuilt = build_funding_recovery_artifacts(
        secp,
        &artifacts.aggregate_pubkey,
        funding_outpoint,
        artifacts.value_schedule.funding_value_sats,
        recovery_script,
        artifacts.state_number,
        absolute::LockTime::from_consensus(artifacts.state_locktime),
        artifacts.challenge_delay,
        artifacts.fee_bump_policy,
    )?;
    if &rebuilt != artifacts {
        return Err(Bip448RecoveryArtifactError::InconsistentArtifacts);
    }

    Ok(())
}

fn template_hash_hex_eq(actual: &str, expected: &str) -> bool {
    actual.len() == 64 && expected.len() == 64 && encoded_hex_eq(actual, expected)
}

fn encoded_hex_eq(actual: &str, expected: &str) -> bool {
    if actual.len() != expected.len() {
        return false;
    }

    match (hex::decode(actual), hex::decode(expected)) {
        (Ok(actual), Ok(expected)) => actual == expected,
        _ => false,
    }
}

fn anchor_outputs_match(actual: &[Bip448AnchorOutput], expected: &[Bip448AnchorOutput]) -> bool {
    actual.len() == expected.len()
        && actual.iter().zip(expected).all(|(actual, expected)| {
            actual.tx_role == expected.tx_role
                && actual.output_index == expected.output_index
                && actual.value_sats == expected.value_sats
                && encoded_hex_eq(&actual.script_pubkey, &expected.script_pubkey)
        })
}

fn reconstruction_error<E: std::fmt::Display>(error: E) -> Bip448RecoveryVerifyError {
    Bip448RecoveryVerifyError::Reconstruction(error.to_string())
}

fn transaction_fee_policy(policy: Bip448FeeBumpPolicy) -> transaction::FeePolicy {
    match policy {
        Bip448FeeBumpPolicy::ZeroFeeEphemeralAnchor => {
            transaction::FeePolicy::ZeroFeeEphemeralAnchor
        }
    }
}

fn anchor_output(
    tx_role: Bip448RecoveryTemplateRole,
    tx: &Transaction,
    output_index: usize,
) -> Result<Bip448AnchorOutput, Bip448RecoveryArtifactError> {
    let output = tx
        .output
        .get(output_index)
        .ok_or(Bip448RecoveryArtifactError::MissingAnchor {
            role: tx_role,
            output_index,
        })?;
    Ok(Bip448AnchorOutput {
        tx_role,
        output_index: output_index as u32,
        value_sats: output.value,
        script_pubkey: script_hex(&output.script_pubkey),
    })
}

fn tx_hex(tx: &Transaction) -> String {
    hex::encode(encode::serialize(tx))
}

pub(crate) fn script_hex(script: &ScriptBuf) -> String {
    hex::encode(script.as_bytes())
}

pub(crate) fn control_block_hex(control_block: &ControlBlock) -> String {
    hex::encode(control_block.serialize())
}

fn settlement_template_witness(script: &ScriptBuf, control_block: &ControlBlock) -> Witness {
    let mut witness = Witness::new();
    witness.push(script.as_bytes());
    witness.push(control_block.serialize());
    witness
}

/// BIP448 statechain storage record. This is intentionally independent from
/// legacy `BackupTx` and the `backup_txs` SQLite table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bip448StatechainRecord {
    pub wallet_name: String,
    pub statechain_id: String,
    /// Full untweaked aggregate public key `P_full`; receivers recompute `P.x`
    /// and parity from transfer public keys instead of trusting Taproot `Q`.
    pub aggregate_pubkey: String,
    pub funding_outpoint: Bip448FundingOutpoint,
    pub latest_state_number: u32,
    pub challenge_delay: u16,
    pub amount_sats: u64,
    pub network: String,
    pub latest_state: Bip448LatestState,
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Secp256k1, SecretKey};

    fn sample_latest_state() -> Bip448LatestState {
        Bip448LatestState {
            state_number: 7,
            state_locktime: 700_000_042,
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
                aggregate_pubkey_parity_odd: true,
                negate_seckey: true,
            },
            signing_metadata: Bip448SigningMetadata {
                role: Bip448RecoveryTemplateRole::FundingUpdate,
                signing_id: "77".repeat(32),
                client_public_nonce: "88".repeat(66),
                server_public_nonce: "99".repeat(66),
                blinding_factor: "aa".repeat(32),
                update_template_hash: "11".repeat(32),
                update_signature: "bb".repeat(64),
                server_signature_count: 1,
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

    #[test]
    fn latest_state_serialization_round_trips() {
        let latest = sample_latest_state();
        let json = serde_json::to_string(&latest).unwrap();
        let roundtrip: Bip448LatestState = serde_json::from_str(&json).unwrap();

        assert_eq!(roundtrip, latest);
        assert!(json.contains("zero_fee_ephemeral_anchor"));
        assert!(!json.contains("backup_transactions"));
    }

    #[test]
    fn statechain_record_is_independent_from_legacy_backup_txs() {
        let latest_state = sample_latest_state();
        let record = Bip448StatechainRecord {
            wallet_name: "wallet".to_string(),
            statechain_id: "statechain".to_string(),
            aggregate_pubkey: "02".to_string() + &"12".repeat(32),
            funding_outpoint: Bip448FundingOutpoint {
                txid: "34".repeat(32),
                vout: 0,
                value_sats: 100_000,
            },
            latest_state_number: latest_state.state_number,
            challenge_delay: latest_state.challenge_delay,
            amount_sats: 100_000,
            network: "regtest".to_string(),
            latest_state,
        };

        let json = serde_json::to_string(&record).unwrap();
        let roundtrip: Bip448StatechainRecord = serde_json::from_str(&json).unwrap();

        assert_eq!(roundtrip, record);
        assert!(!json.contains("backup_txs"));
        assert!(!json.contains("backup_transactions"));
    }

    #[test]
    fn transferred_funding_reconstruction_accepts_state_three_only_when_allowed() {
        let mut state = sample_latest_state();
        state.state_number = 3;
        state.cpfp_child_templates.clear();

        assert_eq!(state.verify_reconstruction_metadata(true), Ok(()));
        assert_eq!(
            state.verify_reconstruction_metadata(false),
            Err(Bip448RecoveryVerifyError::UnsupportedInitialStateNumber { state_number: 3 })
        );
    }

    #[test]
    fn csfs_key_metadata_rejects_wrong_parity_or_negation() {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_secret_bytes([7u8; 32]).unwrap();
        let aggregate_pubkey = secret_key.public_key(&secp);
        let metadata = Bip448CsfsKeyMetadata::from_aggregate_pubkey(&secp, &aggregate_pubkey);

        assert!(metadata.verifies_aggregate_pubkey(&secp, &aggregate_pubkey));

        let mut wrong_parity = metadata.clone();
        wrong_parity.aggregate_pubkey_parity_odd = !wrong_parity.aggregate_pubkey_parity_odd;
        assert!(!wrong_parity.verifies_aggregate_pubkey(&secp, &aggregate_pubkey));

        let mut wrong_negation = metadata;
        wrong_negation.negate_seckey = !wrong_negation.negate_seckey;
        assert!(!wrong_negation.verifies_aggregate_pubkey(&secp, &aggregate_pubkey));
    }
}
