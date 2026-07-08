use std::str::FromStr;

use secp256k1::{PublicKey, Secp256k1, Signing, Verification};
use serde::{Deserialize, Serialize};

use crate::bip448_statechain::storage::{
    Bip448FundingOutpoint, Bip448LatestState, Bip448RecoveryVerifyError, Bip448ValueSchedule,
};

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
    /// server_pubkey`, checks the message `aggregate_pubkey` equals it, and
    /// verifies the CSFS key metadata + update signature against `P.x`.
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
        if self.latest_state_number != self.latest_state.state_number {
            return Err(Bip448RecoveryVerifyError::InconsistentField(
                "latest_state_number",
            ));
        }
        if self.challenge_delay != self.latest_state.challenge_delay {
            return Err(Bip448RecoveryVerifyError::InconsistentField("challenge_delay"));
        }
        if self.value_schedule != self.latest_state.value_schedule {
            return Err(Bip448RecoveryVerifyError::InconsistentField("value_schedule"));
        }
        if self.server_signature_count
            != self.latest_state.signing_metadata.server_signature_count
        {
            return Err(Bip448RecoveryVerifyError::InconsistentField(
                "server_signature_count",
            ));
        }

        let recomputed = self.latest_state.verify_recovery_against_keys(
            secp,
            receiver_user_pubkey,
            server_pubkey,
        )?;

        let claimed = PublicKey::from_str(&self.aggregate_pubkey)?;
        if claimed != recomputed {
            return Err(Bip448RecoveryVerifyError::AggregateKeyMismatch);
        }

        Ok(recomputed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip448_statechain::storage::{
        Bip448AnchorOutput, Bip448CpfpChildTemplate, Bip448CsfsKeyMetadata, Bip448FeeBumpPolicy,
        Bip448RecoveryTemplateRole, Bip448SigningMetadata,
    };
    use crate::bip448_statechain::{script, transaction};
    use bitcoin::{
        consensus::encode, hashes::Hash, script::Builder, taproot::ControlBlock, OutPoint,
        ScriptBuf, Transaction, Txid,
    };
    use secp256k1::{schnorr, KeyPair, PublicKey, Secp256k1, SecretKey};

    fn latest_state() -> Bip448LatestState {
        Bip448LatestState {
            state_number: 2,
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

    fn tx_hex(tx: &Transaction) -> String {
        hex::encode(encode::serialize(tx))
    }

    fn tx_from_hex(tx_hex: &str) -> Transaction {
        encode::deserialize(&hex::decode(tx_hex).unwrap()).unwrap()
    }

    fn script_hex(script: &ScriptBuf) -> String {
        hex::encode(script.as_bytes())
    }

    fn control_block_hex(control_block: ControlBlock) -> String {
        hex::encode(control_block.serialize())
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

    fn latest_state_from_templates(
        aggregate_pubkey: &PublicKey,
        update_tx: &Transaction,
        settlement_tx: &Transaction,
        templates: &transaction::StateTemplates,
    ) -> Bip448LatestState {
        let secp = Secp256k1::new();
        let aggregate_xonly = aggregate_pubkey.x_only_public_key().0;
        let funding_spend_info = script::funding_spend_info(&secp, aggregate_xonly).unwrap();
        let state_spend_info = script::state_spend_info(
            &secp,
            aggregate_xonly,
            templates.state_number,
            templates.settlement_template_hash,
        )
        .unwrap();
        let update_template_hash = transaction::update_template_hash(update_tx).unwrap();

        Bip448LatestState {
            state_number: templates.state_number,
            challenge_delay: templates.challenge_delay,
            update_tx: tx_hex(update_tx),
            settlement_tx: tx_hex(settlement_tx),
            update_template_hash: hex::encode(update_template_hash.to_byte_array()),
            settlement_template_hash: hex::encode(
                templates.settlement_template_hash.to_byte_array(),
            ),
            state_output_script_pubkey: script_hex(&templates.state_output_script_pubkey),
            funding_update_script: script_hex(&script::funding_update_leaf()),
            funding_update_control_block: control_block_hex(
                script::funding_update_control_block(&funding_spend_info).unwrap(),
            ),
            state_update_script: script_hex(
                &script::state_update_leaf(templates.state_number).unwrap(),
            ),
            state_update_control_block: control_block_hex(
                script::state_update_control_block(&state_spend_info, templates.state_number)
                    .unwrap(),
            ),
            state_settlement_script: script_hex(&script::state_settlement_leaf(
                templates.settlement_template_hash,
            )),
            state_settlement_control_block: control_block_hex(
                script::state_settlement_control_block(
                    &state_spend_info,
                    templates.settlement_template_hash,
                )
                .unwrap(),
            ),
            csfs_key_metadata: Bip448CsfsKeyMetadata::from_aggregate_pubkey(
                &secp,
                aggregate_pubkey,
            ),
            signing_metadata: Bip448SigningMetadata {
                role: Bip448RecoveryTemplateRole::FundingUpdate,
                signing_id: "77".repeat(32),
                client_public_nonce: "88".repeat(66),
                server_public_nonce: "99".repeat(66),
                blinding_factor: "aa".repeat(32),
                update_template_hash: hex::encode(update_template_hash.to_byte_array()),
                update_signature: "bb".repeat(64),
                server_signature_count: 1,
            },
            fee_bump_policy: Bip448FeeBumpPolicy::ZeroFeeEphemeralAnchor,
            value_schedule: Bip448ValueSchedule {
                funding_value_sats: templates.update_input_amount,
                update_input_value_sats: templates.update_input_amount,
                update_state_output_value_sats: templates.settlement_input_amount,
                settlement_input_value_sats: templates.settlement_input_amount,
                settlement_recovery_output_value_sats: settlement_tx.output[0].value,
            },
            anchors: vec![
                Bip448AnchorOutput {
                    tx_role: Bip448RecoveryTemplateRole::FundingUpdate,
                    output_index: 1,
                    value_sats: update_tx.output[1].value,
                    script_pubkey: script_hex(&update_tx.output[1].script_pubkey),
                },
                Bip448AnchorOutput {
                    tx_role: Bip448RecoveryTemplateRole::Settlement,
                    output_index: 1,
                    value_sats: settlement_tx.output[1].value,
                    script_pubkey: script_hex(&settlement_tx.output[1].script_pubkey),
                },
            ],
            cpfp_child_templates: vec![Bip448CpfpChildTemplate {
                parent_role: Bip448RecoveryTemplateRole::FundingUpdate,
                anchor_output_index: 1,
                tx_hex: "03000000".to_string(),
                fee_sats: 1_000,
                target_feerate_sat_per_vbyte: Some(10),
            }],
        }
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
        let (_, aggregate_pubkey) = aggregate_key();
        let aggregate_xonly = aggregate_pubkey.x_only_public_key().0;
        let funding_outpoint = outpoint(0x11, 0);
        let recovery_script = recovery_script();
        let templates = transaction::build_state_templates(
            &secp,
            aggregate_xonly,
            transaction::placeholder_outpoint(),
            INPUT_AMOUNT,
            recovery_script.clone(),
            STATE_NUMBER,
            CHALLENGE_DELAY,
            transaction::FeePolicy::ZeroFeeEphemeralAnchor,
        )
        .unwrap();
        let update_tx = transaction::rebind_update_tx(
            &templates.update_tx,
            funding_outpoint,
            INPUT_AMOUNT,
            transaction::FeePolicy::ZeroFeeEphemeralAnchor,
        )
        .unwrap();
        let settlement_tx = transaction::rebind_settlement_tx(
            &templates.settlement_tx,
            OutPoint {
                txid: update_tx.txid(),
                vout: 0,
            },
            templates.settlement_input_amount,
            transaction::FeePolicy::ZeroFeeEphemeralAnchor,
        )
        .unwrap();
        let latest_state =
            latest_state_from_templates(&aggregate_pubkey, &update_tx, &settlement_tx, &templates);
        let msg = Bip448TransferMsg {
            statechain_id: "statechain".to_string(),
            transfer_signature: "ab".repeat(64),
            sender_user_public_key: "02".to_string() + &"12".repeat(32),
            receiver_user_public_key: "03".to_string() + &"13".repeat(32),
            server_public_key: "02".to_string() + &"14".repeat(32),
            aggregate_pubkey: aggregate_pubkey.to_string(),
            funding_outpoint: Bip448FundingOutpoint {
                txid: funding_outpoint.txid.to_string(),
                vout: funding_outpoint.vout,
                value_sats: INPUT_AMOUNT,
            },
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
        let reconstructed_templates = transaction::build_state_templates(
            &secp,
            aggregate_xonly,
            transaction::placeholder_outpoint(),
            decoded.value_schedule.update_input_value_sats,
            recovery_script.clone(),
            decoded.latest_state_number,
            decoded.challenge_delay,
            transaction::FeePolicy::ZeroFeeEphemeralAnchor,
        )
        .unwrap();
        let reconstructed_update_tx = transaction::rebind_update_tx(
            &reconstructed_templates.update_tx,
            funding_outpoint,
            decoded.value_schedule.update_input_value_sats,
            transaction::FeePolicy::ZeroFeeEphemeralAnchor,
        )
        .unwrap();
        let reconstructed_settlement_tx = transaction::rebind_settlement_tx(
            &reconstructed_templates.settlement_tx,
            OutPoint {
                txid: stored_update_tx.txid(),
                vout: 0,
            },
            decoded.value_schedule.settlement_input_value_sats,
            transaction::FeePolicy::ZeroFeeEphemeralAnchor,
        )
        .unwrap();

        assert_eq!(tx_hex(&stored_update_tx), tx_hex(&reconstructed_update_tx));
        assert_eq!(
            tx_hex(&stored_settlement_tx),
            tx_hex(&reconstructed_settlement_tx)
        );
        let settlement_hash = transaction::validate_state_template_set(
            &secp,
            aggregate_xonly,
            decoded.latest_state_number,
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
    fn recovery_keys(secp: &Secp256k1<secp256k1::All>) -> (SecretKey, PublicKey, PublicKey, PublicKey) {
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

        // A substituted aggregate_pubkey in the (sender-controlled) message is
        // rejected against the receiver's recomputed P.
        let mut wrong_aggregate = msg.clone();
        wrong_aggregate.aggregate_pubkey = server_pub.to_string();
        assert_eq!(
            wrong_aggregate.verify_recovery_against_keys(&secp, &user_pub, &server_pub),
            Err(Bip448RecoveryVerifyError::AggregateKeyMismatch)
        );

        // A wrong server key changes the recomputed P; the metadata no longer
        // matches, so recovery is rejected.
        assert!(msg
            .verify_recovery_against_keys(&secp, &user_pub, &user_pub)
            .is_err());

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
}
