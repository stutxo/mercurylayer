mod bindings;
mod canonical;
mod close;
mod enums;
mod transfer;
mod withdrawal;

pub(crate) use bindings::{validate_binding, validate_binding_observation, validate_observation};
pub use bindings::{
    Bip448AppliedScanRevision, Bip448BindingObservation, Bip448FundingBinding, Bip448SyncBase,
    Bip448SyncReport,
};
pub(crate) use canonical::{
    canonical_block_hash, canonical_public_key, canonical_txid, canonical_xonly_public_key,
    parse_canonical_sign_first_payload, parse_canonical_sign_second_payload,
    require_canonical_block_hash, require_canonical_hex, require_canonical_public_key,
    require_canonical_script, require_canonical_txid, require_canonical_xonly_public_key,
};
pub(crate) use close::decode_bip448_closing_bindings;
pub use close::{
    evaluate_bip448_close_gate, Bip448CloseBlockReason, Bip448CloseGate, Bip448ClosingBinding,
    Bip448ClosingResolution,
};
pub use enums::{
    Bip448BindingRole, Bip448BroadcastStatus, Bip448CompletionStatus, Bip448ObservationStatus,
    Bip448OwnershipStatus, Bip448TransferIntentActivityStatus, Bip448TransferIntentKind,
    Bip448TransferIntentPhase, Bip448TransferStateSigningPhase, Bip448WithdrawalAttemptKind,
    Bip448WithdrawalPhase,
};
pub use transfer::Bip448TransferIntent;
pub(crate) use transfer::{transfer_intent_immutable_eq, validate_transfer_intent};
pub use withdrawal::{
    bip448_attempts_are_exit_only, bip448_one_output_fee_and_value,
    bip448_signature_count_expectation, Bip448SignatureCountExpectation, Bip448WithdrawalAttempt,
    BIP448_MAX_MONEY_SATS, BIP448_ONE_INPUT_ONE_OUTPUT_VBYTES,
};
pub(crate) use withdrawal::{
    derive_bip448_blinded_session, expected_withdrawal_txid, require_bip448_session_relationship,
    validate_withdrawal_attempt, withdrawal_attempt_immutable_eq,
};
