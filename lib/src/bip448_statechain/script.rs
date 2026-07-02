use std::{error::Error, fmt};

use bitcoin::{
    absolute,
    blockdata::opcodes::{
        all::{OP_CLTV, OP_DROP, OP_EQUAL},
        OP_CHECKSIGFROMSTACK, OP_INTERNALKEY, OP_TEMPLATEHASH,
    },
    hashes::Hash,
    script::Builder,
    secp256k1::{Secp256k1, Verification, XOnlyPublicKey},
    sighash::TemplateHash,
    taproot::{ControlBlock, LeafVersion, TaprootBuilder, TaprootBuilderError, TaprootSpendInfo},
    ScriptBuf,
};

use crate::bip448;

pub const STATE_LOCKTIME_BASE: u32 = 500_000_000;

#[derive(Debug)]
pub enum ScriptTemplateError {
    TaprootBuilder(TaprootBuilderError),
    UnfinalizedTaprootBuilder,
    MissingControlBlock,
    InvalidStateNumber { state_number: u32 },
    InvalidStateLocktime { locktime: u32 },
    StateLocktimeOverflow { state_number: u32 },
}

impl fmt::Display for ScriptTemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScriptTemplateError::TaprootBuilder(err) => {
                write!(f, "failed to build BIP448 taproot script tree: {err:?}")
            }
            ScriptTemplateError::UnfinalizedTaprootBuilder => {
                f.write_str("failed to finalize BIP448 taproot script tree")
            }
            ScriptTemplateError::MissingControlBlock => {
                f.write_str("missing BIP448 taproot control block")
            }
            ScriptTemplateError::InvalidStateNumber { state_number } => {
                write!(f, "invalid BIP448 state number {state_number}")
            }
            ScriptTemplateError::InvalidStateLocktime { locktime } => {
                write!(f, "invalid BIP448 state locktime {locktime}")
            }
            ScriptTemplateError::StateLocktimeOverflow { state_number } => write!(
                f,
                "BIP448 state number {state_number} overflows consensus locktime"
            ),
        }
    }
}

impl Error for ScriptTemplateError {}

impl From<TaprootBuilderError> for ScriptTemplateError {
    fn from(err: TaprootBuilderError) -> Self {
        ScriptTemplateError::TaprootBuilder(err)
    }
}

pub fn funding_update_leaf() -> ScriptBuf {
    bip448::primitive_script()
}

pub fn state_locktime(state_number: u32) -> Result<absolute::LockTime, ScriptTemplateError> {
    validate_state_number(state_number)?;

    let locktime = STATE_LOCKTIME_BASE
        .checked_add(state_number)
        .ok_or(ScriptTemplateError::StateLocktimeOverflow { state_number })?;

    Ok(absolute::LockTime::from_consensus(locktime))
}

pub fn state_number_from_locktime(
    locktime: absolute::LockTime,
) -> Result<u32, ScriptTemplateError> {
    let locktime = locktime.to_consensus_u32();
    let state_number = locktime
        .checked_sub(STATE_LOCKTIME_BASE)
        .ok_or(ScriptTemplateError::InvalidStateLocktime { locktime })?;
    validate_state_number(state_number)?;

    Ok(state_number)
}

/// The CLTV gate for the update leaf of state `n`.
///
/// This uses `state_locktime(n + 1)` so `U(n)` cannot replay onto its own
/// state output and reset the settlement challenge delay.
pub fn state_update_gate_locktime(
    state_number: u32,
) -> Result<absolute::LockTime, ScriptTemplateError> {
    validate_state_number(state_number)?;

    let gate_state_number = state_number
        .checked_add(1)
        .ok_or(ScriptTemplateError::StateLocktimeOverflow { state_number })?;
    state_locktime(gate_state_number).map_err(|err| match err {
        ScriptTemplateError::StateLocktimeOverflow { .. } => {
            ScriptTemplateError::StateLocktimeOverflow { state_number }
        }
        err => err,
    })
}

pub fn state_update_leaf(state_number: u32) -> Result<ScriptBuf, ScriptTemplateError> {
    Ok(Builder::new()
        .push_lock_time(state_update_gate_locktime(state_number)?)
        .push_opcode(OP_CLTV)
        .push_opcode(OP_DROP)
        .push_opcode(OP_TEMPLATEHASH)
        .push_opcode(OP_INTERNALKEY)
        .push_opcode(OP_CHECKSIGFROMSTACK)
        .into_script())
}

pub fn state_settlement_leaf(settlement_template_hash: TemplateHash) -> ScriptBuf {
    Builder::new()
        .push_slice(settlement_template_hash.to_byte_array())
        .push_opcode(OP_TEMPLATEHASH)
        .push_opcode(OP_EQUAL)
        .into_script()
}

pub fn funding_spend_info<C: Verification>(
    secp: &Secp256k1<C>,
    aggregate_key: XOnlyPublicKey,
) -> Result<TaprootSpendInfo, ScriptTemplateError> {
    single_leaf_spend_info(secp, aggregate_key, funding_update_leaf())
}

pub fn state_spend_info<C: Verification>(
    secp: &Secp256k1<C>,
    aggregate_key: XOnlyPublicKey,
    state_number: u32,
    settlement_template_hash: TemplateHash,
) -> Result<TaprootSpendInfo, ScriptTemplateError> {
    // Mercury uses the aggregate key P as the Taproot internal key. OP_INTERNALKEY
    // in the update leaf pushes this same P, so CSFS signatures verify against P.
    TaprootBuilder::new()
        .add_leaf(1, state_update_leaf(state_number)?)?
        .add_leaf(1, state_settlement_leaf(settlement_template_hash))?
        .finalize(secp, aggregate_key)
        .map_err(|_| ScriptTemplateError::UnfinalizedTaprootBuilder)
}

pub fn funding_update_control_block(
    spend_info: &TaprootSpendInfo,
) -> Result<ControlBlock, ScriptTemplateError> {
    control_block(spend_info, funding_update_leaf())
}

pub fn state_update_control_block(
    spend_info: &TaprootSpendInfo,
    state_number: u32,
) -> Result<ControlBlock, ScriptTemplateError> {
    control_block(spend_info, state_update_leaf(state_number)?)
}

pub fn state_settlement_control_block(
    spend_info: &TaprootSpendInfo,
    settlement_template_hash: TemplateHash,
) -> Result<ControlBlock, ScriptTemplateError> {
    control_block(spend_info, state_settlement_leaf(settlement_template_hash))
}

pub fn output_script_pubkey(spend_info: &TaprootSpendInfo) -> ScriptBuf {
    ScriptBuf::new_v1_p2tr_tweaked(spend_info.output_key())
}

fn single_leaf_spend_info<C: Verification>(
    secp: &Secp256k1<C>,
    aggregate_key: XOnlyPublicKey,
    leaf: ScriptBuf,
) -> Result<TaprootSpendInfo, ScriptTemplateError> {
    // Mercury uses the aggregate key P as the Taproot internal key. OP_INTERNALKEY
    // pushes this same P in Tapscript, so CSFS signatures verify against P, not NUMS.
    TaprootBuilder::new()
        .add_leaf(0, leaf)?
        .finalize(secp, aggregate_key)
        .map_err(|_| ScriptTemplateError::UnfinalizedTaprootBuilder)
}

fn validate_state_number(state_number: u32) -> Result<(), ScriptTemplateError> {
    if state_number == 0 {
        return Err(ScriptTemplateError::InvalidStateNumber { state_number });
    }

    Ok(())
}

fn control_block(
    spend_info: &TaprootSpendInfo,
    leaf: ScriptBuf,
) -> Result<ControlBlock, ScriptTemplateError> {
    spend_info
        .control_block(&(leaf, LeafVersion::TapScript))
        .ok_or(ScriptTemplateError::MissingControlBlock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip448_statechain::test_helpers::aggregate_key;

    use bitcoin::blockdata::opcodes::all::OP_CSV;

    const OP_CHECKLOCKTIMEVERIFY_BYTE: u8 = 0xb1;
    const OP_CHECKSEQUENCEVERIFY_BYTE: u8 = 0xb2;
    const OP_DROP_BYTE: u8 = 0x75;
    const OP_EQUAL_BYTE: u8 = 0x87;
    const OP_INTERNALKEY_BYTE: u8 = 0xcb;
    const OP_CHECKSIGFROMSTACK_BYTE: u8 = 0xcc;
    const OP_TEMPLATEHASH_BYTE: u8 = 0xce;

    #[test]
    fn state_locktime_uses_ln_symmetry_timestamp_range() {
        assert_eq!(STATE_LOCKTIME_BASE, 500_000_000);
        assert_eq!(state_locktime(42).unwrap().to_consensus_u32(), 500_000_042);
        assert_eq!(
            state_number_from_locktime(state_locktime(42).unwrap()).unwrap(),
            42
        );
        assert_eq!(
            state_update_gate_locktime(42).unwrap().to_consensus_u32(),
            500_000_043
        );
    }

    #[test]
    fn state_zero_is_rejected() {
        let secp = Secp256k1::new();
        let aggregate_key = aggregate_key();

        assert!(matches!(
            state_locktime(0),
            Err(ScriptTemplateError::InvalidStateNumber { state_number: 0 })
        ));
        assert!(matches!(
            state_number_from_locktime(absolute::LockTime::from_consensus(STATE_LOCKTIME_BASE)),
            Err(ScriptTemplateError::InvalidStateNumber { state_number: 0 })
        ));
        assert!(matches!(
            state_update_leaf(0),
            Err(ScriptTemplateError::InvalidStateNumber { state_number: 0 })
        ));
        assert!(matches!(
            state_spend_info(&secp, aggregate_key, 0, template_hash(0)),
            Err(ScriptTemplateError::InvalidStateNumber { state_number: 0 })
        ));
    }

    #[test]
    fn state_locktime_overflow_is_rejected() {
        let overflowing_state_number = u32::MAX - STATE_LOCKTIME_BASE + 1;

        assert!(matches!(
            state_locktime(overflowing_state_number),
            Err(ScriptTemplateError::StateLocktimeOverflow { state_number })
                if state_number == overflowing_state_number
        ));
        assert!(matches!(
            state_update_leaf(overflowing_state_number),
            Err(ScriptTemplateError::StateLocktimeOverflow { state_number })
                if state_number == overflowing_state_number
        ));

        let final_settlement_state = u32::MAX - STATE_LOCKTIME_BASE;
        assert!(state_locktime(final_settlement_state).is_ok());
        assert!(matches!(
            state_update_gate_locktime(final_settlement_state),
            Err(ScriptTemplateError::StateLocktimeOverflow { state_number })
                if state_number == final_settlement_state
        ));
        assert!(matches!(
            state_number_from_locktime(absolute::LockTime::from_consensus(STATE_LOCKTIME_BASE - 1)),
            Err(ScriptTemplateError::InvalidStateLocktime { locktime })
                if locktime == STATE_LOCKTIME_BASE - 1
        ));
    }

    #[test]
    fn funding_output_script_uses_bip448_update_leaf() {
        assert_eq!(
            funding_update_leaf().as_bytes(),
            [
                OP_TEMPLATEHASH_BYTE,
                OP_INTERNALKEY_BYTE,
                OP_CHECKSIGFROMSTACK_BYTE,
            ]
        );
    }

    #[test]
    fn state_update_leaf_uses_next_state_cltv_drop_templatehash_internalkey_csfs() {
        assert_eq!(
            state_update_leaf(42).unwrap().as_bytes(),
            [
                0x04,
                0x2b,
                0x65,
                0xcd,
                0x1d,
                OP_CHECKLOCKTIMEVERIFY_BYTE,
                OP_DROP_BYTE,
                OP_TEMPLATEHASH_BYTE,
                OP_INTERNALKEY_BYTE,
                OP_CHECKSIGFROMSTACK_BYTE,
            ]
        );
    }

    #[test]
    fn state_settlement_leaf_uses_templatehash_equality() {
        let settlement_hash = template_hash(3);
        let mut expected = vec![0x20];
        expected.extend_from_slice(&settlement_hash.to_byte_array());
        expected.extend_from_slice(&[OP_TEMPLATEHASH_BYTE, OP_EQUAL_BYTE]);

        assert_eq!(state_settlement_leaf(settlement_hash).as_bytes(), expected);
    }

    #[test]
    fn state_leaves_do_not_include_csv() {
        assert_eq!(OP_CSV.to_u8(), OP_CHECKSEQUENCEVERIFY_BYTE);
        assert!(!state_update_leaf(42)
            .unwrap()
            .as_bytes()
            .contains(&OP_CSV.to_u8()));
        assert!(!state_settlement_leaf(template_hash(4))
            .as_bytes()
            .contains(&OP_CSV.to_u8()));
    }

    #[test]
    fn taproot_spend_info_uses_mercury_aggregate_key_as_internal_key() {
        let secp = Secp256k1::new();
        let aggregate_key = aggregate_key();

        let spend_info = state_spend_info(&secp, aggregate_key, 1, template_hash(5)).unwrap();

        assert_eq!(spend_info.internal_key(), aggregate_key);
    }

    #[test]
    fn control_blocks_are_available_for_expected_leaves() {
        let secp = Secp256k1::new();
        let aggregate_key = aggregate_key();
        let funding_info = funding_spend_info(&secp, aggregate_key).unwrap();
        let settlement_hash = template_hash(6);
        let state_info = state_spend_info(&secp, aggregate_key, 7, settlement_hash).unwrap();

        assert!(funding_update_control_block(&funding_info).is_ok());
        assert!(state_update_control_block(&state_info, 7).is_ok());
        assert!(state_settlement_control_block(&state_info, settlement_hash).is_ok());
    }

    #[test]
    fn state_number_changes_state_leaf_and_output_script_pubkey() {
        let secp = Secp256k1::new();
        let aggregate_key = aggregate_key();
        let settlement_hash = template_hash(7);
        let state_1_info = state_spend_info(&secp, aggregate_key, 1, settlement_hash).unwrap();
        let state_2_info = state_spend_info(&secp, aggregate_key, 2, settlement_hash).unwrap();

        assert_ne!(state_update_leaf(1).unwrap(), state_update_leaf(2).unwrap());
        assert_ne!(
            output_script_pubkey(&state_1_info),
            output_script_pubkey(&state_2_info)
        );
    }

    #[test]
    fn settlement_template_hash_changes_state_leaf_and_output_script_pubkey() {
        let secp = Secp256k1::new();
        let aggregate_key = aggregate_key();
        let state_with_hash_1 =
            state_spend_info(&secp, aggregate_key, 8, template_hash(8)).unwrap();
        let state_with_hash_2 =
            state_spend_info(&secp, aggregate_key, 8, template_hash(9)).unwrap();

        assert_ne!(
            state_settlement_leaf(template_hash(8)),
            state_settlement_leaf(template_hash(9))
        );
        assert_ne!(
            output_script_pubkey(&state_with_hash_1),
            output_script_pubkey(&state_with_hash_2)
        );
    }

    fn template_hash(seed: u8) -> TemplateHash {
        TemplateHash::from_byte_array([seed; 32])
    }
}
