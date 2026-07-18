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
use secp256k1::rand::RngCore;

use crate::bip448;

pub const LOCKTIME_TIMESTAMP_THRESHOLD: u32 = 500_000_000;
pub const INITIAL_STATE_LOCKTIME_MIN: u32 = LOCKTIME_TIMESTAMP_THRESHOLD;
pub const INITIAL_STATE_LOCKTIME_MAX: u32 = 1_000_000_000;
pub const FUTURE_STATE_STRIDE_MIN: u32 = 1;
pub const FUTURE_STATE_STRIDE_MAX: u32 = 65_536;

#[derive(Debug)]
pub enum ScriptTemplateError {
    TaprootBuilder(TaprootBuilderError),
    UnfinalizedTaprootBuilder,
    MissingControlBlock,
    InvalidStateLocktime { locktime: u32 },
    InitialStateLocktimeOutOfRange { locktime: u32 },
    InvalidStateLocktimeStride { stride: u32 },
    InsufficientStateLocktimeHeadroom { locktime: u32 },
    StateLocktimeOverflow { locktime: u32 },
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
            ScriptTemplateError::InvalidStateLocktime { locktime } => {
                write!(
                    f,
                    "BIP448 state locktime {locktime} is not a timestamp locktime"
                )
            }
            ScriptTemplateError::InitialStateLocktimeOutOfRange { locktime } => write!(
                f,
                "BIP448 initial state locktime {locktime} is outside the allowed range"
            ),
            ScriptTemplateError::InvalidStateLocktimeStride { stride } => write!(
                f,
                "BIP448 state locktime stride {stride} is outside the allowed range"
            ),
            ScriptTemplateError::InsufficientStateLocktimeHeadroom { locktime } => write!(
                f,
                "BIP448 state locktime {locktime} leaves no valid superseding cancellation state"
            ),
            ScriptTemplateError::StateLocktimeOverflow { locktime } => {
                write!(
                    f,
                    "BIP448 state locktime {locktime} has no representable update gate"
                )
            }
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

pub fn validate_state_locktime(locktime: absolute::LockTime) -> Result<(), ScriptTemplateError> {
    let consensus_locktime = locktime.to_consensus_u32();
    if locktime.is_block_height() || consensus_locktime < LOCKTIME_TIMESTAMP_THRESHOLD {
        return Err(ScriptTemplateError::InvalidStateLocktime {
            locktime: consensus_locktime,
        });
    }
    if consensus_locktime == u32::MAX {
        return Err(ScriptTemplateError::StateLocktimeOverflow {
            locktime: consensus_locktime,
        });
    }

    Ok(())
}

pub fn validate_initial_state_locktime(
    locktime: absolute::LockTime,
) -> Result<(), ScriptTemplateError> {
    validate_state_locktime(locktime)?;
    let consensus_locktime = locktime.to_consensus_u32();
    if !(INITIAL_STATE_LOCKTIME_MIN..=INITIAL_STATE_LOCKTIME_MAX).contains(&consensus_locktime) {
        return Err(ScriptTemplateError::InitialStateLocktimeOutOfRange {
            locktime: consensus_locktime,
        });
    }

    Ok(())
}

/// The CLTV gate for the update leaf at explicit locktime `L`.
///
/// The gate is `L + 1`, so an update cannot replay onto its own state output
/// and reset the settlement challenge delay.
pub fn state_update_gate_locktime(
    state_locktime: absolute::LockTime,
) -> Result<absolute::LockTime, ScriptTemplateError> {
    validate_state_locktime(state_locktime)?;
    let current = state_locktime.to_consensus_u32();
    let gate = current
        .checked_add(1)
        .ok_or(ScriptTemplateError::StateLocktimeOverflow { locktime: current })?;

    Ok(absolute::LockTime::from_consensus(gate))
}

pub fn checked_next_state_locktime(
    current_locktime: absolute::LockTime,
    stride: u32,
) -> Result<absolute::LockTime, ScriptTemplateError> {
    validate_state_locktime(current_locktime)?;
    if !(FUTURE_STATE_STRIDE_MIN..=FUTURE_STATE_STRIDE_MAX).contains(&stride) {
        return Err(ScriptTemplateError::InvalidStateLocktimeStride { stride });
    }

    let current = current_locktime.to_consensus_u32();
    let next = current
        .checked_add(stride)
        .ok_or(ScriptTemplateError::StateLocktimeOverflow { locktime: current })?;
    let next_locktime = absolute::LockTime::from_consensus(next);
    validate_state_locktime(next_locktime)?;
    let cancellation_locktime = next
        .checked_add(FUTURE_STATE_STRIDE_MIN)
        .ok_or(ScriptTemplateError::InsufficientStateLocktimeHeadroom { locktime: next })?;
    validate_state_locktime(absolute::LockTime::from_consensus(cancellation_locktime))
        .map_err(|_| ScriptTemplateError::InsufficientStateLocktimeHeadroom { locktime: next })?;

    Ok(next_locktime)
}

pub fn sample_future_state_stride() -> u32 {
    let mut rng = secp256k1::rand::rng();
    sample_future_state_stride_with_rng(&mut rng)
}

fn sample_future_state_stride_with_rng<R: RngCore + ?Sized>(rng: &mut R) -> u32 {
    loop {
        if let Some(stride) = map_future_state_stride_sample(rng.next_u32()) {
            return stride;
        }
    }
}

fn map_future_state_stride_sample(sample: u32) -> Option<u32> {
    let range_size = u64::from(FUTURE_STATE_STRIDE_MAX) - u64::from(FUTURE_STATE_STRIDE_MIN) + 1;
    let source_size = u64::from(u32::MAX) + 1;
    let unbiased_zone = source_size - (source_size % range_size);
    let sample = u64::from(sample);
    if sample >= unbiased_zone {
        return None;
    }

    Some(FUTURE_STATE_STRIDE_MIN + (sample % range_size) as u32)
}

pub fn state_update_leaf(
    state_locktime: absolute::LockTime,
) -> Result<ScriptBuf, ScriptTemplateError> {
    Ok(Builder::new()
        .push_lock_time(state_update_gate_locktime(state_locktime)?)
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
    state_locktime: absolute::LockTime,
    settlement_template_hash: TemplateHash,
) -> Result<TaprootSpendInfo, ScriptTemplateError> {
    // Mercury uses the aggregate key P as the Taproot internal key. OP_INTERNALKEY
    // in the update leaf pushes this same P, so CSFS signatures verify against P.
    TaprootBuilder::new()
        .add_leaf(1, state_update_leaf(state_locktime)?)?
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
    state_locktime: absolute::LockTime,
) -> Result<ControlBlock, ScriptTemplateError> {
    control_block(spend_info, state_update_leaf(state_locktime)?)
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
    const STATE_LOCKTIME: u32 = 700_000_042;

    fn locktime(value: u32) -> absolute::LockTime {
        absolute::LockTime::from_consensus(value)
    }

    #[test]
    fn initial_state_locktime_range_and_gate_are_explicit() {
        assert_eq!(LOCKTIME_TIMESTAMP_THRESHOLD, 500_000_000);
        assert!(validate_initial_state_locktime(locktime(INITIAL_STATE_LOCKTIME_MIN)).is_ok());
        assert!(validate_initial_state_locktime(locktime(INITIAL_STATE_LOCKTIME_MAX)).is_ok());
        assert_eq!(
            state_update_gate_locktime(locktime(STATE_LOCKTIME))
                .unwrap()
                .to_consensus_u32(),
            STATE_LOCKTIME + 1
        );
    }

    #[test]
    fn invalid_and_out_of_range_locktimes_are_rejected() {
        assert!(matches!(
            validate_initial_state_locktime(locktime(LOCKTIME_TIMESTAMP_THRESHOLD - 1)),
            Err(ScriptTemplateError::InvalidStateLocktime { .. })
        ));
        assert!(matches!(
            validate_initial_state_locktime(locktime(INITIAL_STATE_LOCKTIME_MAX + 1)),
            Err(ScriptTemplateError::InitialStateLocktimeOutOfRange { .. })
        ));
        assert!(matches!(
            validate_state_locktime(locktime(u32::MAX)),
            Err(ScriptTemplateError::StateLocktimeOverflow { locktime: u32::MAX })
        ));
        assert!(matches!(
            state_update_gate_locktime(locktime(u32::MAX)),
            Err(ScriptTemplateError::StateLocktimeOverflow { locktime: u32::MAX })
        ));
    }

    #[test]
    fn future_stride_is_bounded_and_checked() {
        let current = locktime(STATE_LOCKTIME);
        assert_eq!(
            checked_next_state_locktime(current, FUTURE_STATE_STRIDE_MIN)
                .unwrap()
                .to_consensus_u32(),
            STATE_LOCKTIME + FUTURE_STATE_STRIDE_MIN
        );
        assert_eq!(
            checked_next_state_locktime(current, FUTURE_STATE_STRIDE_MAX)
                .unwrap()
                .to_consensus_u32(),
            STATE_LOCKTIME + FUTURE_STATE_STRIDE_MAX
        );
        assert!(matches!(
            checked_next_state_locktime(current, 0),
            Err(ScriptTemplateError::InvalidStateLocktimeStride { stride: 0 })
        ));
        assert!(matches!(
            checked_next_state_locktime(current, FUTURE_STATE_STRIDE_MAX + 1),
            Err(ScriptTemplateError::InvalidStateLocktimeStride { .. })
        ));
        assert!(matches!(
            checked_next_state_locktime(locktime(u32::MAX - 1), 1),
            Err(ScriptTemplateError::StateLocktimeOverflow { locktime: u32::MAX })
        ));
        assert!(matches!(
            checked_next_state_locktime(locktime(u32::MAX - 2), 1),
            Err(ScriptTemplateError::InsufficientStateLocktimeHeadroom {
                locktime
            }) if locktime == u32::MAX - 1
        ));
    }

    #[test]
    fn future_stride_sampler_is_uniform_and_includes_both_boundaries() {
        let range_size = FUTURE_STATE_STRIDE_MAX - FUTURE_STATE_STRIDE_MIN + 1;

        assert_eq!(
            map_future_state_stride_sample(0),
            Some(FUTURE_STATE_STRIDE_MIN)
        );
        assert_eq!(
            map_future_state_stride_sample(range_size - 1),
            Some(FUTURE_STATE_STRIDE_MAX)
        );
        assert_eq!(
            map_future_state_stride_sample(range_size),
            Some(FUTURE_STATE_STRIDE_MIN)
        );
        assert_eq!(
            map_future_state_stride_sample(u32::MAX),
            Some(FUTURE_STATE_STRIDE_MAX)
        );
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
            state_update_leaf(locktime(500_000_042)).unwrap().as_bytes(),
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
        assert!(!state_update_leaf(locktime(STATE_LOCKTIME))
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

        let spend_info = state_spend_info(
            &secp,
            aggregate_key,
            locktime(STATE_LOCKTIME),
            template_hash(5),
        )
        .unwrap();

        assert_eq!(spend_info.internal_key(), aggregate_key);
    }

    #[test]
    fn control_blocks_are_available_for_expected_leaves() {
        let secp = Secp256k1::new();
        let aggregate_key = aggregate_key();
        let funding_info = funding_spend_info(&secp, aggregate_key).unwrap();
        let settlement_hash = template_hash(6);
        let state_info = state_spend_info(
            &secp,
            aggregate_key,
            locktime(STATE_LOCKTIME),
            settlement_hash,
        )
        .unwrap();

        assert!(funding_update_control_block(&funding_info).is_ok());
        assert!(state_update_control_block(&state_info, locktime(STATE_LOCKTIME)).is_ok());
        assert!(state_settlement_control_block(&state_info, settlement_hash).is_ok());
    }

    #[test]
    fn explicit_locktime_changes_state_leaf_and_output_script_pubkey() {
        let secp = Secp256k1::new();
        let aggregate_key = aggregate_key();
        let settlement_hash = template_hash(7);
        let first_locktime = locktime(STATE_LOCKTIME);
        let second_locktime = locktime(STATE_LOCKTIME + 42);
        let state_1_info =
            state_spend_info(&secp, aggregate_key, first_locktime, settlement_hash).unwrap();
        let state_2_info =
            state_spend_info(&secp, aggregate_key, second_locktime, settlement_hash).unwrap();

        assert_ne!(
            state_update_leaf(first_locktime).unwrap(),
            state_update_leaf(second_locktime).unwrap()
        );
        assert_ne!(
            output_script_pubkey(&state_1_info),
            output_script_pubkey(&state_2_info)
        );
    }

    #[test]
    fn settlement_template_hash_changes_state_leaf_and_output_script_pubkey() {
        let secp = Secp256k1::new();
        let aggregate_key = aggregate_key();
        let state_with_hash_1 = state_spend_info(
            &secp,
            aggregate_key,
            locktime(STATE_LOCKTIME),
            template_hash(8),
        )
        .unwrap();
        let state_with_hash_2 = state_spend_info(
            &secp,
            aggregate_key,
            locktime(STATE_LOCKTIME),
            template_hash(9),
        )
        .unwrap();

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
