mod accepted;
mod guard;
mod initial_acceptance;
mod rows;
mod scan;

pub use accepted::{
    delete_bip448_pending_deposit_signing, delete_bip448_pending_transfer_signing,
    delete_bip448_transfer_msgs, get_bip448_pending_deposit_signing,
    get_bip448_pending_transfer_signing, get_bip448_state_history, get_bip448_statechain,
    get_bip448_statechain_optional, get_bip448_transfer_msg, get_bip448_transfer_msg_raw_optional,
    has_bip448_transfer_msg_for_statechain, insert_bip448_pending_deposit_signing_if_absent,
    insert_bip448_pending_transfer_signing_if_absent, insert_bip448_state_history_entry,
    insert_or_update_bip448_transfer_msg, update_bip448_pending_deposit_server_public_nonce,
    update_bip448_pending_transfer_server_public_nonce, Bip448PendingDepositSigning,
};
pub(crate) use accepted::{
    history_entry, insert_or_update_bip448_statechain,
    insert_or_update_bip448_statechain_from_transfer, list_bip448_transfer_msg_raw_rows,
};

pub use guard::{begin_bip448_mutation_guard, Bip448MutationGuard};

pub use initial_acceptance::persist_bip448_initial_acceptance;
pub(super) use initial_acceptance::{
    accepted_record_and_history_on, history_entry_matches_latest_state,
    history_entry_matches_pending_intent, require_selected_bip448_wallet_coin_on,
    transfer_message_matches_record_and_history, validate_selected_bip448_coin,
    Bip448WalletCoinRequirement,
};
pub(crate) use initial_acceptance::{
    recover_bip448_initial_acceptance_wallet, Bip448InitialAcceptanceRecovery,
};

pub(super) use rows::{
    checked_u32, checked_u64, list_bip448_funding_bindings_on, list_bip448_transfer_intents_on,
    list_bip448_withdrawal_attempts_on, row_to_bip448_attempt, row_to_bip448_binding,
    row_to_bip448_intent, BIP448_ATTEMPT_COLUMNS, BIP448_BINDING_COLUMNS, BIP448_INTENT_COLUMNS,
};
pub use rows::{
    get_bip448_funding_binding, get_bip448_withdrawal_attempt, list_bip448_funding_bindings,
    list_bip448_transfer_intents, list_bip448_withdrawal_attempts,
};

pub(super) use scan::replace_bip448_scan_cache_on;
pub(crate) use scan::{
    available_bip448_scanned_outpoints, bip448_reservation_id,
    ensure_no_orphaned_bip448_reservation, insert_bip448_package_attempt, load_bip448_scan_state,
    persist_bip448_scan_state, reacquire_bip448_package_attempt_reservations,
    upsert_bip448_scanned_outpoint,
};
pub use scan::{
    get_bip448_package_attempt, set_bip448_package_attempt_status, Bip448FeeInputRecord,
    Bip448PackageAttempt, Bip448PackageAttemptStatus, Bip448ScanCursor,
    BIP448_FEE_RESERVATION_TTL_SECONDS,
};

#[cfg(test)]
pub(super) use accepted::upsert_bip448_statechain_record;
#[cfg(test)]
pub(super) use guard::{Bip448BeginImmediateTestHook, BIP448_BEGIN_IMMEDIATE_TEST_HOOK};
#[cfg(test)]
pub(super) use scan::clear_bip448_scan_state;
