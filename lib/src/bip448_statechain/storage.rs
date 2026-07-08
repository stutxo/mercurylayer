use std::str::FromStr;

use secp256k1::{schnorr, Message, PublicKey, Secp256k1, Signing, Verification};
use serde::{Deserialize, Serialize};

use crate::bip448_statechain::signing::csfs_negate_seckey;

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
    #[error("transfer message field `{0}` disagrees with the nested latest_state")]
    InconsistentField(&'static str),
    #[error("secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),
}

/// The durable outpoint and value of a BIP448 statechain funding output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bip448FundingOutpoint {
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
}

/// Serializable fee-bump policy chosen for committed recovery templates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// Durable latest-state data for receiver validation and local recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bip448LatestState {
    pub state_number: u32,
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
        let recomputed = receiver_user_pubkey.combine(server_pubkey)?;

        if !self.csfs_key_metadata.verifies_aggregate_pubkey(secp, &recomputed) {
            return Err(Bip448RecoveryVerifyError::KeyMetadataMismatch);
        }

        let hash_bytes = hex::decode(&self.update_template_hash)
            .ok()
            .filter(|bytes| bytes.len() == 32)
            .ok_or(Bip448RecoveryVerifyError::InvalidTemplateHash)?;
        let message = Message::from_slice(&hash_bytes)
            .map_err(|_| Bip448RecoveryVerifyError::InvalidTemplateHash)?;
        let signature = schnorr::Signature::from_str(&self.signing_metadata.update_signature)
            .map_err(|_| Bip448RecoveryVerifyError::InvalidUpdateSignature)?;
        let xonly = recomputed.x_only_public_key().0;

        secp.verify_schnorr(&signature, message.as_ref(), &xonly)
            .map_err(|_| Bip448RecoveryVerifyError::UpdateSignatureVerification)?;

        Ok(recomputed)
    }
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
