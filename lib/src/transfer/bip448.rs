use std::str::FromStr;

use bitcoin::{absolute, Network, OutPoint, ScriptBuf, TxOut, Txid};
use secp256k1::{PublicKey, Secp256k1, Signing, Verification};
use serde::{Deserialize, Serialize};

use crate::bip448_statechain::storage::{
    Bip448FeeBumpPolicy, Bip448FundingOutpoint, Bip448LatestState, Bip448RecoveryVerifyError,
    Bip448ValueSchedule, Bip448VerifiedRecoveryBinding,
};
use crate::bip448_statechain::transaction as bip448_transaction;

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
}

impl Bip448TransferMsg {
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

        let binding = self.latest_state.verify_recovery_binding_against_keys(
            secp,
            receiver_user_pubkey,
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
    use bitcoin::{
        consensus::encode, hashes::Hash, script::Builder, OutPoint, ScriptBuf, Transaction, Txid,
    };
    use secp256k1::{schnorr, KeyPair, PublicKey, Secp256k1, SecretKey};

    const TEST_MEDIAN_TIME_PAST: u32 = 1_900_000_000;
    const TEST_STATE_LOCKTIME: u32 = 700_000_042;

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

    #[test]
    fn transfer_message_serialization_round_trips_without_legacy_backups() {
        let latest_state = latest_state();
        let msg = Bip448TransferMsg {
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
        };

        let json = serde_json::to_string(&msg).unwrap();
        let roundtrip: Bip448TransferMsg = serde_json::from_str(&json).unwrap();

        assert_eq!(roundtrip, msg);
        assert!(json.contains("latest_state"));
        assert!(!json.contains("backup_transactions"));
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
}
