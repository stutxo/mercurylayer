#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MatrixTarget {
    pub target: &'static str,
    pub tests: &'static [&'static str],
}

pub const MATRIX: &[MatrixTarget] = &[
    MatrixTarget {
        target: "functional",
        tests: &[
            "tb06_bip448_lightning_latch::tb06_bip448_lightning_latch",
            "tb06_bip448_lightning_latch::tb06_bip448_batch_expiry_recovery",
        ],
    },
    MatrixTarget {
        target: "bip448_primitive_spike",
        tests: &["bip448_template_signature_rebinds_prevout_on_inquisition"],
    },
    MatrixTarget {
        target: "bip448_csfs_signing",
        tests: &[
            "bip448_blinded_musig_csfs_signature_spends_on_inquisition",
            "bip448_sign_second_recovers_missing_mercury_partial_from_lockbox_replay",
            "bip448_sign_second_accepts_uppercase_0x_server_pubnonce",
            "bip448_sign_second_fails_closed_while_lockbox_status_is_unavailable",
        ],
    },
    MatrixTarget {
        target: "bip448_deposit",
        tests: &[
            "bip448_client_restart_child",
            "bip448_deposit_survives_client_process_restarts",
            "bip448_deposit_recovers_through_update_and_settlement_packages",
            "bip448_client_submitter_broadcasts_recovery_package",
            "bip448_owner_recovery_survives_restart_mid_broadcast",
            "bip448_cli_wallet_funded_and_keyless_recovery_packages",
            "bip448_transfer_address_reuse_accepts_two_distinct_statechains",
            "bip448_one_hop_transfer_accepts_and_recovers_state_two",
            "bip448_two_hop_transfer_accepts_and_recovers_state_three",
            "bip448_ten_hop_transfer_advances_to_state_eleven",
            "bip448_same_wallet_second_hop_advances_to_state_three",
            "bip448_same_wallet_transfer_advances_the_accepted_record_to_state_two",
            "bip448_latest_state_fast_forwards_over_confirmed_old_state",
            "bip448_discovery_cursor_reorg_and_restart_state",
        ],
    },
    MatrixTarget {
        target: "bip448_duplicates",
        tests: &[
            "bip448_repeated_funding_preserves_canonical_state_and_signature_count",
            "bip448_duplicate_inventory_is_stable_across_restart_reorg_and_spend",
            "bip448_duplicate_sweep_replays_every_signing_and_broadcast_boundary",
            "bip448_duplicate_sweeps_are_one_input_and_canonical_closes_last",
            "bip448_receiver_post_acceptance_duplicate_rescan_is_retryable",
            "bip448_duplicate_transfer_requires_ack_and_receiver_rediscovers",
            "bip448_duplicate_same_wallet_cancel_reassigns_current_owner",
            "bip448_duplicate_dust_remains_visible_and_blocks_close",
        ],
    },
    MatrixTarget {
        target: "bip448_transfer_sender",
        tests: &[
            "bip448_transfer_restart_child",
            "bip448_transfer_survives_signing_and_upload_restarts",
            "bip448_sender_finishes_after_receiver_rotates_auth_key",
            "bip448_retarget_before_signing_reuses_next_state",
            "bip448_retarget_after_signing_preserves_superseded_history",
            "bip448_cancel_returns_coin_and_allows_real_transfer",
        ],
    },
    MatrixTarget {
        target: "bip448_withdraw",
        tests: &["bip448_cooperative_withdrawal_closed_list"],
    },
    MatrixTarget {
        target: "lockbox_compatibility",
        tests: &[
            "get_public_key_requires_statechain_id",
            "bip448_get_public_nonce_requires_existing_statechain",
            "bip448_get_partial_signature_validates_session_length",
            "bip448_get_partial_signature_requires_existing_nonce_state",
            "keyupdate_validates_t2_and_x1_lengths",
            "keyupdate_requires_existing_statechain",
            "signature_count_for_missing_statechain_returns_not_found",
            "bip448_signing_lifecycle_returns_a_valid_partial_signature_and_increments_signature_count",
            "bip448_nonce_state_replays_after_restart_and_rejects_conflicting_challenge",
            "mercury_signing_routes_nonce_and_partial_signature_through_lockbox",
            "keyupdate_returns_the_expected_server_pubkey_and_statechain_remains_usable",
            "keyupdate_state_survives_lockbox_restart",
            "mercury_transfer_receiver_routes_keyupdate_to_lockbox",
            "delete_statechain_is_idempotent_and_deleted_statechain_cannot_be_used",
            "mercury_withdraw_complete_preserves_rows_when_lockbox_delete_fails",
            "deterministic_lockbox_vectors_match_golden_outputs",
            "parallel_statechains_can_sign_independently",
            "concurrent_exact_bip448_partial_replays_increment_signature_count_once",
            "concurrent_keyupdate_replays_return_the_same_server_pubkey",
            "mercury_deposit_init_creates_a_lockbox_backed_statechain",
            "mercury_statechain_info_returns_ordered_bip448_rows_and_transfer_clears_them",
            "fresh_lockbox_schema_has_only_bip448_nonce_state_columns",
            "fresh_mercury_schema_has_exact_bip448_tables_and_lease_columns",
        ],
    },
];

pub fn test_count() -> usize {
    MATRIX.iter().map(|entry| entry.tests.len()).sum()
}

pub(super) fn select(target: &str, identity: &str) -> Result<&'static MatrixTarget, String> {
    let entry = MATRIX
        .iter()
        .find(|entry| entry.target == target)
        .ok_or_else(|| format!("test binary {target:?} is not in the frozen BIP448 matrix"))?;
    if !entry.tests.contains(&identity) {
        return Err(format!(
            "test identity {identity:?} is not frozen for BIP448 binary {target:?}"
        ));
    }
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn matrix_has_the_exact_target_order_and_counts() {
        assert_eq!(MATRIX.len(), 8);
        assert_eq!(test_count(), 59);
        assert_eq!(
            MATRIX
                .iter()
                .map(|entry| (entry.target, entry.tests.len()))
                .collect::<Vec<_>>(),
            [
                ("functional", 2),
                ("bip448_primitive_spike", 1),
                ("bip448_csfs_signing", 4),
                ("bip448_deposit", 14),
                ("bip448_duplicates", 8),
                ("bip448_transfer_sender", 6),
                ("bip448_withdraw", 1),
                ("lockbox_compatibility", 23),
            ]
        );
        assert_eq!(
            MATRIX[0].tests[0],
            "tb06_bip448_lightning_latch::tb06_bip448_lightning_latch"
        );
        assert_eq!(
            MATRIX[7].tests[1],
            "bip448_get_public_nonce_requires_existing_statechain"
        );
    }

    #[test]
    fn every_cargo_test_identity_is_unique() {
        let mut identities = BTreeSet::new();
        for entry in MATRIX {
            assert!(!entry.target.is_empty());
            assert!(!entry.tests.is_empty());
            for test in entry.tests {
                assert!(
                    identities.insert((entry.target, *test)),
                    "duplicate {}::{test}",
                    entry.target
                );
            }
        }
        assert_eq!(identities.len(), 59);
    }

    #[test]
    fn selection_requires_an_exact_matrix_pair() {
        let selected = select(
            "bip448_primitive_spike",
            "bip448_template_signature_rebinds_prevout_on_inquisition",
        )
        .unwrap();
        assert_eq!(selected, &MATRIX[1]);
        assert!(select("not_a_binary", selected.tests[0]).is_err());
        assert!(select(selected.target, "substring").is_err());
    }
}
