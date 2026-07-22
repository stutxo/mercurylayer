use std::{error::Error, fmt};

pub mod fee_signing;

use bitcoin::{
    absolute, consensus::encode, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};

use crate::bip448_statechain::{
    storage::{Bip448RecoveryTemplateRole, Bip448StatechainRecord},
    transaction::{self, TX_VERSION},
};

/// Bitcoin Core TRUC/v3 policy limits a child with an unconfirmed v3 parent to
/// 1,000 virtual bytes. Recovery packages must satisfy this before submission.
pub const TRUC_CHILD_MAX_VBYTES: usize = 1_000;
const TAPROOT_KEY_PATH_SIGNATURE_SIZE: usize = 64;

#[derive(Debug, Clone)]
pub struct Bip448CpfpFeeInput {
    pub previous_output: OutPoint,
    pub value_sats: u64,
    pub script_sig: ScriptBuf,
    pub sequence: Sequence,
    pub witness: Witness,
}

impl Bip448CpfpFeeInput {
    pub fn keyless(previous_output: OutPoint, value_sats: u64) -> Self {
        Self {
            previous_output,
            value_sats,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }
    }

    pub fn signed(previous_output: OutPoint, value_sats: u64) -> Self {
        let mut witness = Witness::new();
        witness.push([0u8; TAPROOT_KEY_PATH_SIGNATURE_SIZE]);

        Self {
            previous_output,
            value_sats,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Bip448RecoveryPackage {
    pub parent_tx: Transaction,
    pub cpfp_child_tx: Transaction,
    pub package_fee_sats: u64,
    pub package_vbytes: usize,
    pub package_feerate_sat_per_vbyte: f64,
}

impl Bip448RecoveryPackage {
    pub fn transactions(&self) -> [&Transaction; 2] {
        [&self.parent_tx, &self.cpfp_child_tx]
    }

    fn replace_fee_input_witnesses(
        &mut self,
        witnesses: Vec<Witness>,
    ) -> Result<(), Bip448PackageError> {
        let expected = self.cpfp_child_tx.input.len().saturating_sub(1);
        if witnesses.len() != expected {
            return Err(Bip448PackageError::FeeInputWitnessCountMismatch {
                expected,
                actual: witnesses.len(),
            });
        }

        let estimated_vbytes = self.cpfp_child_tx.vsize();
        let mut signed_child = self.cpfp_child_tx.clone();
        for (input, witness) in signed_child.input.iter_mut().skip(1).zip(witnesses) {
            input.witness = witness;
        }
        let final_vbytes = signed_child.vsize();
        if final_vbytes != estimated_vbytes {
            return Err(Bip448PackageError::SignedChildVsizeMismatch {
                estimated_vbytes,
                final_vbytes,
            });
        }

        self.cpfp_child_tx = signed_child;
        Ok(())
    }
}

#[derive(Debug)]
pub enum Bip448PackageError {
    InvalidAnchorOutput {
        output_index: u32,
    },
    MissingFeeInputs,
    InvalidTargetFeerate {
        target_feerate_sat_per_vbyte: f64,
    },
    FeeExceedsFeeInputs {
        fee_sats: u64,
        input_value_sats: u64,
    },
    ChangeWouldBeDust {
        value_sats: u64,
        dust_sats: u64,
    },
    PackageOutputsExceedInputs {
        input_sats: u64,
        output_sats: u64,
    },
    PackageFeerateTooLow {
        required_sat_per_vbyte: f64,
        actual_sat_per_vbyte: f64,
    },
    ChildExceedsTrucLimit {
        child_vbytes: usize,
        max_vbytes: usize,
    },
    FeeInputWitnessCountMismatch {
        expected: usize,
        actual: usize,
    },
    SignedChildVsizeMismatch {
        estimated_vbytes: usize,
        final_vbytes: usize,
    },
    UnsupportedRecoveryRole {
        role: Bip448RecoveryTemplateRole,
    },
    MissingAnchorMetadata {
        role: Bip448RecoveryTemplateRole,
    },
    Hex(hex::FromHexError),
    Consensus(encode::Error),
}

impl fmt::Display for Bip448PackageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAnchorOutput { output_index } => write!(
                f,
                "BIP448 recovery parent output {output_index} is not the committed zero-value P2A anchor"
            ),
            Self::MissingFeeInputs => f.write_str("BIP448 CPFP child requires at least one fee input"),
            Self::InvalidTargetFeerate {
                target_feerate_sat_per_vbyte,
            } => write!(
                f,
                "BIP448 package target feerate must be positive and finite, got {target_feerate_sat_per_vbyte}"
            ),
            Self::FeeExceedsFeeInputs {
                fee_sats,
                input_value_sats,
            } => write!(
                f,
                "BIP448 CPFP fee {fee_sats} exceeds fee input value {input_value_sats}"
            ),
            Self::ChangeWouldBeDust {
                value_sats,
                dust_sats,
            } => write!(
                f,
                "BIP448 CPFP child change {value_sats} sats is below dust threshold {dust_sats}"
            ),
            Self::PackageOutputsExceedInputs {
                input_sats,
                output_sats,
            } => write!(
                f,
                "BIP448 package outputs {output_sats} sats exceed inputs {input_sats} sats"
            ),
            Self::PackageFeerateTooLow {
                required_sat_per_vbyte,
                actual_sat_per_vbyte,
            } => write!(
                f,
                "BIP448 package feerate {actual_sat_per_vbyte:.3} sat/vB is below required {required_sat_per_vbyte:.3} sat/vB"
            ),
            Self::ChildExceedsTrucLimit {
                child_vbytes,
                max_vbytes,
            } => write!(
                f,
                "BIP448 CPFP child is {child_vbytes} vB, exceeding TRUC/v3 child limit {max_vbytes} vB"
            ),
            Self::FeeInputWitnessCountMismatch { expected, actual } => write!(
                f,
                "BIP448 CPFP child requires {expected} fee-input witnesses, got {actual}"
            ),
            Self::SignedChildVsizeMismatch {
                estimated_vbytes,
                final_vbytes,
            } => write!(
                f,
                "signed BIP448 CPFP child is {final_vbytes} vB, expected {estimated_vbytes} vB"
            ),
            Self::UnsupportedRecoveryRole { role } => {
                write!(f, "BIP448 recovery package role {} is not supported here", role.as_str())
            }
            Self::MissingAnchorMetadata { role } => {
                write!(f, "BIP448 latest state is missing committed anchor metadata for {}", role.as_str())
            }
            Self::Hex(err) => write!(f, "BIP448 recovery package hex decode error: {err}"),
            Self::Consensus(err) => write!(f, "BIP448 recovery package transaction decode error: {err}"),
        }
    }
}

impl Error for Bip448PackageError {}

impl From<hex::FromHexError> for Bip448PackageError {
    fn from(err: hex::FromHexError) -> Self {
        Self::Hex(err)
    }
}

impl From<encode::Error> for Bip448PackageError {
    fn from(err: encode::Error) -> Self {
        Self::Consensus(err)
    }
}

pub fn build_latest_state_recovery_package(
    record: &Bip448StatechainRecord,
    role: Bip448RecoveryTemplateRole,
    fee_inputs: &[Bip448CpfpFeeInput],
    change_script_pubkey: ScriptBuf,
    target_feerate_sat_per_vbyte: f64,
) -> Result<Bip448RecoveryPackage, Bip448PackageError> {
    let (parent_tx_hex, parent_input_value_sats) = match role {
        Bip448RecoveryTemplateRole::FundingUpdate => (
            &record.latest_state.update_tx,
            record.funding_outpoint.value_sats,
        ),
        Bip448RecoveryTemplateRole::Settlement => (
            &record.latest_state.settlement_tx,
            record
                .latest_state
                .value_schedule
                .settlement_input_value_sats,
        ),
        Bip448RecoveryTemplateRole::StateUpdate => {
            return Err(Bip448PackageError::UnsupportedRecoveryRole { role })
        }
    };
    let parent_tx: Transaction = encode::deserialize(&hex::decode(parent_tx_hex)?)?;
    let anchor_output_index = record
        .latest_state
        .anchors
        .iter()
        .find(|anchor| anchor.tx_role == role)
        .map(|anchor| anchor.output_index)
        .ok_or(Bip448PackageError::MissingAnchorMetadata { role })?;

    build_anchor_cpfp_package(
        &parent_tx,
        parent_input_value_sats,
        anchor_output_index,
        fee_inputs,
        change_script_pubkey,
        target_feerate_sat_per_vbyte,
    )
}

pub fn build_anchor_cpfp_package(
    parent_tx: &Transaction,
    parent_input_value_sats: u64,
    anchor_output_index: u32,
    fee_inputs: &[Bip448CpfpFeeInput],
    change_script_pubkey: ScriptBuf,
    target_feerate_sat_per_vbyte: f64,
) -> Result<Bip448RecoveryPackage, Bip448PackageError> {
    validate_target_feerate(target_feerate_sat_per_vbyte)?;
    validate_anchor_output(parent_tx, anchor_output_index)?;
    if fee_inputs.is_empty() {
        return Err(Bip448PackageError::MissingFeeInputs);
    }

    let provisional_child = build_anchor_cpfp_child(
        parent_tx,
        anchor_output_index,
        fee_inputs,
        change_script_pubkey.clone(),
        0,
    )?;
    let package_vbytes = parent_tx.vsize() + provisional_child.vsize();
    let required_fee_sats = (target_feerate_sat_per_vbyte * package_vbytes as f64).ceil() as u64;
    let cpfp_child_tx = build_anchor_cpfp_child(
        parent_tx,
        anchor_output_index,
        fee_inputs,
        change_script_pubkey,
        required_fee_sats,
    )?;
    let package_fee_sats = package_fee(
        parent_input_value_sats,
        fee_inputs,
        parent_tx,
        &cpfp_child_tx,
    )?;
    let package_vbytes = parent_tx.vsize() + cpfp_child_tx.vsize();
    let package_feerate_sat_per_vbyte = package_fee_sats as f64 / package_vbytes as f64;

    if package_feerate_sat_per_vbyte < target_feerate_sat_per_vbyte {
        return Err(Bip448PackageError::PackageFeerateTooLow {
            required_sat_per_vbyte: target_feerate_sat_per_vbyte,
            actual_sat_per_vbyte: package_feerate_sat_per_vbyte,
        });
    }

    Ok(Bip448RecoveryPackage {
        parent_tx: parent_tx.clone(),
        cpfp_child_tx,
        package_fee_sats,
        package_vbytes,
        package_feerate_sat_per_vbyte,
    })
}

pub fn build_anchor_cpfp_child(
    parent_tx: &Transaction,
    anchor_output_index: u32,
    fee_inputs: &[Bip448CpfpFeeInput],
    change_script_pubkey: ScriptBuf,
    fee_sats: u64,
) -> Result<Transaction, Bip448PackageError> {
    validate_anchor_output(parent_tx, anchor_output_index)?;
    if fee_inputs.is_empty() {
        return Err(Bip448PackageError::MissingFeeInputs);
    }

    let fee_input_value = fee_inputs_value(fee_inputs);
    if fee_sats > fee_input_value {
        return Err(Bip448PackageError::FeeExceedsFeeInputs {
            fee_sats,
            input_value_sats: fee_input_value,
        });
    }

    let change_value = fee_input_value - fee_sats;
    let dust_sats = change_script_pubkey.dust_value().to_sat();
    if change_value < dust_sats {
        return Err(Bip448PackageError::ChangeWouldBeDust {
            value_sats: change_value,
            dust_sats,
        });
    }

    let mut input = vec![TxIn {
        previous_output: OutPoint {
            txid: parent_tx.txid(),
            vout: anchor_output_index,
        },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    }];
    input.extend(fee_inputs.iter().map(|fee_input| TxIn {
        previous_output: fee_input.previous_output,
        script_sig: fee_input.script_sig.clone(),
        sequence: fee_input.sequence,
        witness: fee_input.witness.clone(),
    }));

    let child = Transaction {
        version: TX_VERSION,
        lock_time: absolute::LockTime::ZERO,
        input,
        output: vec![TxOut {
            value: change_value,
            script_pubkey: change_script_pubkey,
        }],
    };

    validate_truc_child_size(&child)?;

    Ok(child)
}

fn validate_target_feerate(target_feerate_sat_per_vbyte: f64) -> Result<(), Bip448PackageError> {
    if !target_feerate_sat_per_vbyte.is_finite() || target_feerate_sat_per_vbyte <= 0.0 {
        return Err(Bip448PackageError::InvalidTargetFeerate {
            target_feerate_sat_per_vbyte,
        });
    }

    Ok(())
}

fn validate_anchor_output(
    parent_tx: &Transaction,
    anchor_output_index: u32,
) -> Result<(), Bip448PackageError> {
    match parent_tx.output.get(anchor_output_index as usize) {
        Some(output)
            if output.value == 0 && output.script_pubkey == transaction::pay_to_anchor_script() =>
        {
            Ok(())
        }
        _ => Err(Bip448PackageError::InvalidAnchorOutput {
            output_index: anchor_output_index,
        }),
    }
}

fn validate_truc_child_size(child_tx: &Transaction) -> Result<(), Bip448PackageError> {
    let child_vbytes = child_tx.vsize();
    if child_vbytes > TRUC_CHILD_MAX_VBYTES {
        return Err(Bip448PackageError::ChildExceedsTrucLimit {
            child_vbytes,
            max_vbytes: TRUC_CHILD_MAX_VBYTES,
        });
    }

    Ok(())
}

fn package_fee(
    parent_input_value_sats: u64,
    fee_inputs: &[Bip448CpfpFeeInput],
    parent_tx: &Transaction,
    cpfp_child_tx: &Transaction,
) -> Result<u64, Bip448PackageError> {
    let input_sats = parent_input_value_sats + fee_inputs_value(fee_inputs);
    let output_sats = parent_tx
        .output
        .iter()
        .chain(cpfp_child_tx.output.iter())
        .map(|output| output.value)
        .sum::<u64>();

    input_sats
        .checked_sub(output_sats)
        .ok_or(Bip448PackageError::PackageOutputsExceedInputs {
            input_sats,
            output_sats,
        })
}

fn fee_inputs_value(fee_inputs: &[Bip448CpfpFeeInput]) -> u64 {
    fee_inputs.iter().map(|input| input.value_sats).sum()
}

#[cfg(test)]
mod tests {
    use super::fee_signing::sign_cpfp_fee_inputs;
    use super::*;
    use crate::bip448_statechain::transaction::pay_to_anchor_script;
    use bitcoin::{
        hashes::Hash,
        key::TapTweak,
        sighash::{self, SighashCache, TapSighashType},
        Address, Network, Txid, Witness,
    };
    use secp256k1::{schnorr, KeyPair, Message, Secp256k1, SecretKey};

    const PARENT_VALUE: u64 = 50_000;
    const FEE_INPUT_VALUE: u64 = 20_000;

    fn parent_tx() -> Transaction {
        Transaction {
            version: TX_VERSION,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_slice(&[1u8; 32]).unwrap(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ZERO,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: PARENT_VALUE,
                    script_pubkey: change_script(),
                },
                TxOut {
                    value: 0,
                    script_pubkey: pay_to_anchor_script(),
                },
            ],
        }
    }

    fn fee_input() -> Bip448CpfpFeeInput {
        Bip448CpfpFeeInput::keyless(
            OutPoint {
                txid: Txid::from_slice(&[2u8; 32]).unwrap(),
                vout: 1,
            },
            FEE_INPUT_VALUE,
        )
    }

    fn fee_inputs(count: usize) -> Vec<Bip448CpfpFeeInput> {
        (0..count)
            .map(|i| {
                let mut txid_bytes = [2u8; 32];
                txid_bytes[0] = i as u8;
                Bip448CpfpFeeInput::keyless(
                    OutPoint {
                        txid: Txid::from_slice(&txid_bytes).unwrap(),
                        vout: i as u32,
                    },
                    FEE_INPUT_VALUE,
                )
            })
            .collect()
    }

    fn signed_fee_inputs(count: usize) -> Vec<Bip448CpfpFeeInput> {
        (0..count)
            .map(|i| {
                let mut txid_bytes = [3u8; 32];
                txid_bytes[0] = i as u8;
                Bip448CpfpFeeInput::signed(
                    OutPoint {
                        txid: Txid::from_slice(&txid_bytes).unwrap(),
                        vout: i as u32,
                    },
                    FEE_INPUT_VALUE,
                )
            })
            .collect()
    }

    fn fee_key_and_script() -> (SecretKey, ScriptBuf) {
        let secp = Secp256k1::new();
        let key = SecretKey::from_secret_bytes([8u8; 32]).unwrap();
        let address = Address::p2tr(
            &secp,
            key.public_key(&secp).x_only_public_key().0,
            None,
            Network::Regtest,
        );
        (key, address.script_pubkey())
    }

    fn change_script() -> ScriptBuf {
        let secp = Secp256k1::new();
        let key = SecretKey::from_secret_bytes([9u8; 32]).unwrap();
        bitcoin::Address::p2tr(
            &secp,
            key.public_key(&secp).x_only_public_key().0,
            None,
            bitcoin::Network::Regtest,
        )
        .script_pubkey()
    }

    #[test]
    fn cpfp_child_spends_parent_anchor_and_fee_input() {
        let parent = parent_tx();
        let package = build_anchor_cpfp_package(
            &parent,
            PARENT_VALUE,
            1,
            &[fee_input()],
            change_script(),
            2.0,
        )
        .unwrap();

        assert_eq!(package.parent_tx, parent);
        assert_eq!(package.cpfp_child_tx.version, TX_VERSION);
        assert_eq!(package.cpfp_child_tx.input.len(), 2);
        assert_eq!(
            package.cpfp_child_tx.input[0].previous_output.txid,
            parent.txid()
        );
        assert_eq!(package.cpfp_child_tx.input[0].previous_output.vout, 1);
        assert_eq!(package.cpfp_child_tx.input[0].witness.len(), 0);
        assert_eq!(
            package.package_fee_sats,
            package.cpfp_child_tx.vsize() as u64 * 2 + parent.vsize() as u64 * 2
        );
        assert!(package.package_feerate_sat_per_vbyte >= 2.0);
    }

    #[test]
    fn package_builder_rejects_missing_or_mutated_anchor() {
        let mut parent = parent_tx();

        assert!(matches!(
            build_anchor_cpfp_package(
                &parent,
                PARENT_VALUE,
                2,
                &[fee_input()],
                change_script(),
                1.0,
            ),
            Err(Bip448PackageError::InvalidAnchorOutput { output_index: 2 })
        ));

        parent.output[1].script_pubkey = change_script();
        assert!(matches!(
            build_anchor_cpfp_package(
                &parent,
                PARENT_VALUE,
                1,
                &[fee_input()],
                change_script(),
                1.0,
            ),
            Err(Bip448PackageError::InvalidAnchorOutput { output_index: 1 })
        ));
    }

    #[test]
    fn package_builder_rejects_underfunded_child() {
        let parent = parent_tx();

        assert!(matches!(
            build_anchor_cpfp_package(
                &parent,
                PARENT_VALUE,
                1,
                &[Bip448CpfpFeeInput::keyless(
                    fee_input().previous_output,
                    1_000,
                )],
                change_script(),
                100.0,
            ),
            Err(Bip448PackageError::ChangeWouldBeDust { .. })
                | Err(Bip448PackageError::FeeExceedsFeeInputs { .. })
        ));
    }

    #[test]
    fn package_builder_rejects_child_exceeding_truc_size_limit() {
        let parent = parent_tx();
        let inputs = fee_inputs(30);

        assert!(matches!(
            build_anchor_cpfp_package(&parent, PARENT_VALUE, 1, &inputs, change_script(), 1.0),
            Err(Bip448PackageError::ChildExceedsTrucLimit {
                max_vbytes: TRUC_CHILD_MAX_VBYTES,
                ..
            })
        ));
    }

    #[test]
    fn signed_fee_inputs_keep_estimated_vsize_and_verify() {
        let parent = parent_tx();
        let fee_inputs = signed_fee_inputs(2);
        let (fee_secret_key, fee_script_pubkey) = fee_key_and_script();
        assert!(fee_inputs.iter().all(|input| {
            input.witness.len() == 1
                && input.witness.iter().next().unwrap().len() == TAPROOT_KEY_PATH_SIGNATURE_SIZE
        }));

        let mut package = build_anchor_cpfp_package(
            &parent,
            PARENT_VALUE,
            1,
            &fee_inputs,
            fee_script_pubkey.clone(),
            2.0,
        )
        .unwrap();
        let estimated_child_vbytes = package.cpfp_child_tx.vsize();

        sign_cpfp_fee_inputs(
            &mut package,
            &fee_inputs,
            &fee_script_pubkey,
            &fee_secret_key,
        )
        .unwrap();

        assert_eq!(package.cpfp_child_tx.vsize(), estimated_child_vbytes);
        assert_eq!(
            package.package_vbytes,
            package.parent_tx.vsize() + package.cpfp_child_tx.vsize()
        );
        assert!(package.cpfp_child_tx.input[0].witness.is_empty());

        let mut prevouts = vec![parent.output[1].clone()];
        prevouts.extend(fee_inputs.iter().map(|input| TxOut {
            value: input.value_sats,
            script_pubkey: fee_script_pubkey.clone(),
        }));
        let secp = Secp256k1::new();
        let output_key = KeyPair::from_secret_key(&secp, &fee_secret_key)
            .tap_tweak(&secp, None)
            .to_inner()
            .x_only_public_key()
            .0;
        for input_index in 1..package.cpfp_child_tx.input.len() {
            let witness = &package.cpfp_child_tx.input[input_index].witness;
            let signature_bytes = witness.iter().next().unwrap();
            assert_eq!(signature_bytes.len(), TAPROOT_KEY_PATH_SIGNATURE_SIZE);
            let signature = schnorr::Signature::from_slice(signature_bytes).unwrap();
            let sighash = SighashCache::new(&package.cpfp_child_tx)
                .taproot_key_spend_signature_hash(
                    input_index,
                    &sighash::Prevouts::All(&prevouts),
                    TapSighashType::Default,
                )
                .unwrap();
            let message: Message = sighash.into();
            secp.verify_schnorr(&signature, message.as_ref(), &output_key)
                .unwrap();
        }
    }

    #[test]
    fn signed_child_rejects_changed_witness_size() {
        let parent = parent_tx();
        let mut package = build_anchor_cpfp_package(
            &parent,
            PARENT_VALUE,
            1,
            &signed_fee_inputs(1),
            change_script(),
            1.0,
        )
        .unwrap();
        let estimated_vbytes = package.cpfp_child_tx.vsize();
        let mut wrong_size_witness = Witness::new();
        wrong_size_witness.push([0u8; TAPROOT_KEY_PATH_SIGNATURE_SIZE + 8]);

        assert!(matches!(
            package.replace_fee_input_witnesses(vec![wrong_size_witness]),
            Err(Bip448PackageError::SignedChildVsizeMismatch {
                estimated_vbytes: expected,
                final_vbytes,
            }) if expected == estimated_vbytes && final_vbytes != expected
        ));
        assert_eq!(package.cpfp_child_tx.vsize(), estimated_vbytes);
    }

    #[test]
    fn signed_inputs_preserve_package_rejections() {
        let parent = parent_tx();
        let dust_sats = change_script().dust_value().to_sat();

        assert!(matches!(
            build_anchor_cpfp_child(
                &parent,
                1,
                &signed_fee_inputs(1),
                change_script(),
                FEE_INPUT_VALUE + 1,
            ),
            Err(Bip448PackageError::FeeExceedsFeeInputs { .. })
        ));
        assert!(matches!(
            build_anchor_cpfp_child(
                &parent,
                1,
                &signed_fee_inputs(1),
                change_script(),
                FEE_INPUT_VALUE - dust_sats + 1,
            ),
            Err(Bip448PackageError::ChangeWouldBeDust { .. })
        ));
        assert!(matches!(
            build_anchor_cpfp_package(
                &parent,
                PARENT_VALUE,
                1,
                &signed_fee_inputs(30),
                change_script(),
                1.0,
            ),
            Err(Bip448PackageError::ChildExceedsTrucLimit {
                max_vbytes: TRUC_CHILD_MAX_VBYTES,
                ..
            })
        ));
    }
}
