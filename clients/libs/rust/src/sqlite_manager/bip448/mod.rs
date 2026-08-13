mod accepted;
mod bindings;
mod guard;
mod initial_acceptance;
mod rows;
mod scan;
mod sync;
mod transfer_completion;
mod transfer_intents;
mod transfer_signing;
mod withdrawals;

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) use accepted::insert_or_update_bip448_statechain;
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
    history_entry, insert_or_update_bip448_statechain_from_transfer,
    list_bip448_transfer_msg_raw_rows,
};

pub(super) use bindings::accepted_funding_script;
pub use bindings::{
    finish_bip448_rotated_outgoing_transfer, mark_bip448_funding_bindings_previous,
    reassign_bip448_funding_bindings_owner, reconcile_bip448_funding_bindings,
    update_bip448_funding_binding_observation,
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

pub use sync::{
    begin_bip448_sync_base_guard, capture_bip448_sync_base,
    compare_and_set_wallet_after_bip448_scan,
};

pub(super) use transfer_completion::transfer_message_matches_history_prefix;
pub use transfer_completion::{
    cleanup_bip448_cancellation_after_acceptance, delete_bip448_cancellation_artifacts_after_sync,
    finish_bip448_cancellation_sender, finish_bip448_transfer_sender,
    finish_bip448_user_transfer_and_delete_intent, mark_bip448_cancellation_receiver_accepted,
    reconcile_bip448_accepted_local_outgoing_messages,
};

pub use transfer_intents::{
    arm_bip448_transfer_sender, get_active_bip448_transfer_intent,
    insert_bip448_cancellation_intent_with_wallet, insert_bip448_transfer_intent_if_absent,
    reactivate_bip448_transfer_intent_predecessor_after_definitive_rejection,
    reject_bip448_transfer_intent_and_reactivate_predecessor, store_bip448_transfer_intent_x1,
    store_bip448_transfer_server_x1, supersede_bip448_transfer_intent,
    supersede_bip448_transfer_intent_with_cancellation_wallet,
    transition_bip448_transfer_intent_phase,
};
pub(super) use transfer_intents::{
    require_materialized_signed_transfer_intent_on, validate_bip448_successor_plan_on,
    validate_bip448_transfer_intent_lineage,
};

pub(super) use transfer_signing::pending_transfer_on;
pub use transfer_signing::{
    arm_bip448_transfer_state_sign_second, install_bip448_transfer_target_pending,
    install_bip448_transfer_target_pending_signing, install_reused_signed_bip448_transfer_state,
    materialize_bip448_signed_transfer_intent, store_bip448_transfer_state_nonce,
    store_bip448_transfer_state_signed_artifacts, store_signed_bip448_transfer_state,
    transition_bip448_transfer_state_signing_phase,
};

pub(crate) use withdrawals::with_bip448_canonical_completion_fence;
pub use withdrawals::{
    arm_bip448_withdrawal_sign_first, arm_bip448_withdrawal_sign_second,
    bip448_active_withdrawal_attempt, bip448_expected_signature_count,
    bip448_statechain_is_exit_only, classify_bip448_close_gate,
    delete_prepared_bip448_withdrawal_attempt_for_confirmed_spend,
    insert_bip448_withdrawal_attempt_if_absent, persist_bip448_canonical_withdrawal_wallet,
    store_bip448_withdrawal_nonce_artifacts, store_bip448_withdrawal_nonce_session,
    store_bip448_withdrawal_signed_artifacts, store_signed_bip448_withdrawal,
    transition_bip448_withdrawal_broadcast_status, transition_bip448_withdrawal_completion_status,
    transition_bip448_withdrawal_phase, update_bip448_withdrawal_broadcast_status,
    update_bip448_withdrawal_completion_status, validate_bip448_canonical_close_snapshot,
};
