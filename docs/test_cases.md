# Retained integration test evidence

The commands and fresh-stack procedure are in [Test.md](../Test.md). The
following entries describe the narrow assertions in the current ignored test
binaries. They are not broader protocol or deployment guarantees.

## `functional`

- `tb06_bip448_lightning_latch` proves the exercised one-coin locked/unlocked
  flow, state 2 and count 2, no receiver mutation while locked, and preimage
  hash equality.
- `tb06_bip448_batch_expiry_recovery` proves the exercised one-coin expiry,
  cancel to state/count 3, and later unbatched acceptance at state/count 4.

There is no retained multi-coin BIP448 atomic-transfer end-to-end case.

## `bip448_primitive_spike`

- `bip448_template_signature_rebinds_prevout_on_inquisition` proves on the
  pinned Inquisition regtest that the same BIP448 template signature spends two
  equal-value prevouts after rebinding, while a committed output mutation is
  rejected.

## `bip448_csfs_signing`

- `bip448_blinded_musig_csfs_signature_spends_on_inquisition` proves the
  exercised two-party blinded signature satisfies the CSFS funding leaf after
  rebinding and that the tested 65-byte signature witness is rejected.
- `bip448_sign_second_recovers_missing_mercury_partial_from_lockbox_replay`
  proves exact lockbox replay repopulates a deliberately missing Mercury
  partial with the same value, replays the same first-round nonce, and rejects
  a different challenge.
- `bip448_sign_second_accepts_uppercase_0x_server_pubnonce` proves the second
  signing route normalizes that tested nonce representation and replays the
  same partial.
- `bip448_sign_second_fails_closed_while_lockbox_status_is_unavailable` proves
  the tested second-round request returns an error while lockbox status is
  unavailable, preserves the conflict guard, and succeeds after the service is
  restored.

## `bip448_deposit`

`bip448_client_restart_child` is an internal subprocess entry point; without
its private environment switch it exits without exercising a capability. The
parent cases are:

- `bip448_deposit_survives_client_process_restarts` uses four independently
  created signing IDs to interrupt deposit signing at the persisted-pending,
  persisted-server-nonce, completed-signature, and accepted-record boundaries,
  then asserts the recorded checkpoint state and one signature after resume.
- `bip448_deposit_recovers_through_update_and_settlement_packages` asserts the
  initial locktime range, `L + 1` gate, zero-fee P2A shape, rejection of a
  parent alone and tested committed mutations, rejection of early settlement,
  and confirmation of update and delayed settlement packages to the recovery
  output.
- `bip448_transfer_address_reuse_accepts_two_distinct_statechains` sends two
  independently created statechains to one transfer address and asserts
  distinct funding, key, record, and state-2 results. It does not fund one
  deposit address twice.
- `bip448_one_hop_transfer_accepts_and_recovers_state_two` accepts state 2 with
  count 2 and confirms the exercised update/settlement recovery packages.
- `bip448_two_hop_transfer_accepts_and_recovers_state_three` accepts state 3
  with ordered history/count 3 and confirms the exercised recovery packages.
- `bip448_latest_state_fast_forwards_over_confirmed_old_state` manually
  confirms `U(1)`, rebinds and confirms `U(3)` on its output, waits the relative
  delay, confirms rebound `S(3)`, and asserts recovery to the current owner
  without a fourth signature.
- `bip448_same_wallet_second_hop_advances_to_state_three` exercises a transfer
  into a holder wallet and then a same-wallet transfer to state/count 3.
- `bip448_same_wallet_transfer_advances_the_accepted_record_to_state_two`
  exercises a direct same-wallet transfer and asserts the accepted recipient
  coin, record, and count are state 2 while the sender coin remains in transfer.
- `bip448_discovery_cursor_reorg_and_restart_state` asserts descriptor scan
  cursor continuation, spent-outpoint removal after restart, rewind on a
  deliberately stale cursor hash, and preservation/removal of the tested
  reservations.
- `bip448_client_submitter_broadcasts_recovery_package` asserts identical
  parent/child reuse in mempool and confirmed-parent cases, fail-closed checks
  for deliberately inconsistent persisted attempts, and transition to
  `Confirmed` after the chain facts are visible.
- `bip448_owner_recovery_survives_restart_mid_broadcast` interrupts before and
  after package submission, then asserts the same persisted child resumes and
  eventually reaches `Confirmed` with released input reservations.
- `bip448_cli_wallet_funded_and_keyless_recovery_packages` executes the CLI
  with a wallet-discovered fee input and with an explicit keyless descriptor,
  asserting both resulting parent/child packages confirm.

## `bip448_transfer_sender`

`bip448_transfer_restart_child` is the environment-controlled subprocess used
by the restart cases. The parent cases are:

- `bip448_transfer_survives_signing_and_upload_restarts` interrupts at nonce,
  message-persist, and message-upload boundaries, asserts journal/ciphertext
  consistency and mismatch failures, then resumes one state-2 signature and
  clears the journal.
- `bip448_sender_finishes_after_receiver_rotates_auth_key` lets the receiver
  accept an uploaded message before the sender resumes, then asserts sender
  completion does not duplicate the mailbox message or signature.
- `bip448_retarget_before_signing_reuses_next_state` interrupts before the
  second signing round, retargets with new signing material, and has the
  replacement recipient accept state/count 2.
- `bip448_retarget_after_signing_preserves_superseded_history` retargets an
  already signed but unfinished transfer, removes the old mailbox message, and
  has the replacement accept ordered states 1, 2, and 3 with count 3.
- `bip448_cancel_returns_coin_and_allows_real_transfer` cancels the interrupted
  transfer into sender state 3, then has the intended receiver accept a later
  state/count 4.

## `bip448_withdraw`

- `bip448_cooperative_withdrawal_closed_list` broadcasts and confirms funding
  key-path withdrawals from state 1 and transferred state 2, checks destination
  output and wallet status transitions, and shows that a test interruption
  after a withdrawal signature advances the count so a later transfer is
  rejected by the supported-state/count check.

## `lockbox_compatibility`

Route validation and absence cases:

- `get_public_key_requires_statechain_id` checks the required JSON field.
- `bip448_get_public_nonce_requires_existing_statechain` checks failure without
  a stored key share.
- `bip448_get_partial_signature_validates_session_length` checks the 133-byte
  session requirement.
- `bip448_get_partial_signature_requires_existing_nonce_state` checks failure
  without the matching nonce row.
- `keyupdate_validates_t2_and_x1_lengths` checks both 32-byte requirements.
- `keyupdate_requires_existing_statechain` checks failure without a stored key
  share.
- `signature_count_for_missing_statechain_returns_not_found` checks the route's
  not-found response.

Signing, replay, update, and concurrency cases:

- `bip448_signing_lifecycle_returns_a_valid_partial_signature_and_increments_signature_count`
  verifies the returned partial for its fixture and a one-step count increase.
- `keyupdate_returns_the_expected_server_pubkey_and_statechain_remains_usable`
  verifies the fixture's rotated key and a later signing round.
- `bip448_nonce_state_replays_after_restart_and_rejects_conflicting_challenge`
  verifies nonce/partial persistence across restart, exact replay, stable count,
  and conflict on the mutated challenge.
- `keyupdate_state_survives_lockbox_restart` verifies the tested rotated share
  remains usable after restart.
- `delete_statechain_is_idempotent_and_deleted_statechain_cannot_be_used`
  verifies repeated route deletion and subsequent route failures for that ID;
  it does not attest to storage outside the tested database/service.
- `deterministic_lockbox_vectors_match_golden_outputs` compares deterministic
  seeded public key, nonce, partial, and key-update results with stored vectors.
- `parallel_statechains_can_sign_independently` signs concurrently across four
  distinct statechain IDs with the same opaque `signing_id`, verifies each
  partial is 32 bytes, and asserts a separate signature count of 1 for each
  statechain.
- `concurrent_exact_bip448_partial_replays_increment_signature_count_once`
  races exact partial requests and asserts identical responses with one count
  increment.
- `concurrent_keyupdate_replays_return_the_same_server_pubkey` races identical
  key updates and asserts one resulting public key.

Mercury/lockbox and schema cases:

- `mercury_deposit_init_creates_a_lockbox_backed_statechain` asserts lockbox
  count 0 after Mercury deposit initialization, obtains a 132-character nonce
  from a BIP448 nonce request, and asserts the count remains 0.
- `fresh_lockbox_schema_has_only_bip448_nonce_state_columns` checks the exact
  two public table names and the exact ordered column names of
  `generated_public_key` and `bip448_nonce_state`.
- `fresh_mercury_schema_has_exact_bip448_tables_and_lease_columns` checks the
  exact six application-table names, the exact five ordered
  `signing_nonce_leases` columns, absence of the two legacy signing tables, and
  absence of the lease `protocol` column.
- `mercury_signing_routes_nonce_and_partial_signature_through_lockbox` verifies
  the routed lifecycle, persisted Mercury row, valid partial, and count.
- `mercury_statechain_info_returns_ordered_bip448_rows_and_transfer_clears_them`
  makes one of two signing rows incomplete, asserts count 2 with the remaining
  completed row as history, then verifies transfer deletes that incomplete row
  while the completed row persists with count 2 and one history entry.
- `mercury_transfer_receiver_routes_keyupdate_to_lockbox` verifies the
  receiver route returns the expected rotated server key and persisted server
  state.

## Prototype boundaries

- Exact legacy duplicate-deposit behavior is not reproduced: paying one
  BIP448 deposit address more than once does not create another wallet coin.
- There is no chain watcher and no automatic selection of a stale state's
  funding source.
- The stale-state end-to-end proof manually selects, rebinds, submits, and
  mines transactions from test code; the running services do not orchestrate
  it.
- BIP448 consensus execution requires the Bitcoin Inquisition revision pinned
  by this repository.
- This is not software for Bitcoin mainnet or production use.
- Start with fresh Mercury and lockbox databases and a fresh client wallet
  database; old data is not migrated.
- Passing tests establish only the assertions and paths that those tests
  execute.
