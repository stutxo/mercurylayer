# Retained integration test evidence

The commands and fresh-stack procedure are in [Test.md](../Test.md). The
following entries describe the narrow assertions in the current ignored test
binaries. They are not broader protocol or deployment guarantees.

The intended discovery inventory is exactly 58 ignored entries in eight test
binaries:

| Binary | Ignored entries |
| --- | ---: |
| `functional` | 2 |
| `bip448_primitive_spike` | 1 |
| `bip448_csfs_signing` | 4 |
| `bip448_deposit` | 13 |
| `bip448_duplicates` | 8 |
| `bip448_transfer_sender` | 6 |
| `bip448_withdraw` | 1 |
| `lockbox_compatibility` | 23 |
| **Total** | **58** |

## `functional`

- `tb06_bip448_lightning_latch` asserts the exercised one-coin locked/unlocked
  flow, state 2 and count 2, no receiver mutation while locked, and preimage
  hash equality.
- `tb06_bip448_batch_expiry_recovery` asserts the exercised one-coin expiry,
  cancel to state/count 3, and later unbatched acceptance at state/count 4.

There is no retained multi-coin BIP448 atomic-transfer end-to-end case.

## `bip448_primitive_spike`

- `bip448_template_signature_rebinds_prevout_on_inquisition` asserts on the
  pinned Inquisition regtest that the same BIP448 template signature spends two
  equal-value prevouts after rebinding, while a committed output mutation is
  rejected.

## `bip448_csfs_signing`

- `bip448_blinded_musig_csfs_signature_spends_on_inquisition` asserts the
  exercised two-party blinded signature satisfies the CSFS funding leaf after
  rebinding and that the tested 65-byte signature witness is rejected.
- `bip448_sign_second_recovers_missing_mercury_partial_from_lockbox_replay`
  asserts exact lockbox replay repopulates a deliberately missing Mercury
  partial with the same value, replays the same first-round nonce, and rejects
  a different challenge.
- `bip448_sign_second_accepts_uppercase_0x_server_pubnonce` asserts the second
  signing route normalizes that tested nonce representation and replays the
  same partial.
- `bip448_sign_second_fails_closed_while_lockbox_status_is_unavailable` asserts
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

## `bip448_duplicates`

- `bip448_repeated_funding_preserves_canonical_state_and_signature_count`
  asserts that a different-value second payment to the accepted funding script
  leaves one logical Coin, its canonical amount/outpoint/status, the accepted
  record and history bytes, and lockbox signature count unchanged.
- `bip448_duplicate_inventory_is_stable_across_restart_reorg_and_spend`
  asserts height-0 discovery of canonical and different-value same-script
  outputs, stable database-local indices through restart, disappearance,
  reappearance, spend, and reorg, unchanged passive signature count, the exact
  top-level/nested list fields, and the tested current/previous/retired
  actionability flags.
- `bip448_duplicate_sweep_replays_every_signing_and_broadcast_boundary`
  interrupts each exercised journal checkpoint and asserts one immutable
  attempt row, the expected phase and lockbox count, exact replay of stored
  nonce/signing/transaction artifacts, a final one-input/one-output key-path
  transaction, unchanged canonical wallet/history, and no completion state on
  the duplicate row.
- `bip448_duplicate_sweeps_are_one_input_and_canonical_closes_last` asserts
  canonical rejection before duplicate resolution, sequential accepted sweeps,
  restart behavior at the exercised canonical checkpoints, three distinct
  one-input/one-output transactions for its two duplicates plus canonical
  output, and server deletion only at canonical completion.
- `bip448_receiver_post_acceptance_duplicate_rescan_is_retryable` injects the
  post-acceptance scan error and asserts the typed accepted/rescan-pending
  result, one accepted generated Coin and retained intent/message, then exact
  passive retry cleanup without another accepted state, history row, signature,
  generated Coin, sender call, or transfer message.
- `bip448_duplicate_transfer_requires_ack_and_receiver_rediscovers` asserts
  that omission of `--force-send-with-duplicates` produces the warning with no
  tested sender/server/signature side effect, then that forced transfer keeps
  the canonical v2 message amount/outpoint and the receiver's height-0 scan
  reconstructs and displays the exact two duplicates under receiver-local
  indices before its tested sweeps and canonical close.
- `bip448_duplicate_same_wallet_cancel_reassigns_current_owner` asserts the
  transfer/attempt and cancellation/attempt race losers have no tested side
  effects, forced transfer and cancellation cannot bypass `SecondArmed` or
  `Signed`, the accepted cancellation retry creates no second Coin/state,
  and all stable bindings move to exactly the generated current owner.
- `bip448_duplicate_dust_remains_visible_and_blocks_close` asserts the dust
  binding is listed, sweep construction rejects it before an attempt/signature,
  and canonical close remains blocked without a count or completion change.

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
- `mercury_withdraw_complete_preserves_rows_when_lockbox_delete_fails` asserts
  that a lockbox 500 leaves all four tested Mercury row classes populated,
  successful retry deletes them, lockbox-only deletion is reported by Mercury
  as an internal signature-count error rather than a missing statechain, and
  subsequent completion deletes the retained Mercury rows.
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

- One logical `Coin` and canonical amount are retained. Normalized bindings
  expose every same-script value separately through nested `coin.duplicates`,
  using stable wallet-database-local indices; passive discovery never signs.
- Exact command `bip448-sweep-duplicate <WALLET_NAME> <STATECHAIN_ID>
  <DUPLICATE_INDEX> <TO_ADDRESS> [FEE_RATE]` sweeps one target-confirmed
  duplicate in a one-input/one-output transaction. Its checked fee is
  `ceil(112 * fee_rate_sat_per_vbyte)` and a dust result is rejected before
  signing. Each output has its own transaction, fee, and signing count.
- Attempt artifacts and phases are durable and exact retry reuses them.
  `SecondArmed` precedes a possibly delivered `sign/second` and permanently
  makes the statechain exit-only. Duplicate sweeps never delete statechain
  server state; canonical withdrawal is last and requires every known
  current-owner duplicate to be handled.
- `--force-send-with-duplicates` acknowledges only the duplicate warning. A
  receiver independently rescans from height 0, assigns its own local indices,
  and decides whether and when to sweep; the sender receives no notification
  or sweep guarantee. The receiver key-update crash boundary remains
  unrepaired.
- The client durably persists a transfer intent before sender mutation. With
  no different authenticated request intervening, an exact same-request
  `/transfer/sender` response-loss retry returns the stored `x1` for the active
  unconsumed owner generation under locked authentication. Update-message
  `x1_pub`, unlock `auth_pub_key`, and receiver `batch_data` carry that
  canonical compressed generation key, with signatures bound respectively to
  recipient/ciphertext, role, and `t2`. Completed latch creation does not
  reserve future transfer rights against a later durable sweep attempt.
- Current-owner live or unresolved arbitrary-value duplicates remain
  cooperatively server-dependent until exact signed sweep bytes exist or an
  independent spend confirms. Previous-owner and retired-address late rows
  remain visible but are not actionable. Only canonical update/settlement
  (`U/S`) recovery is claimed unilateral, and emergency recovery can strand
  duplicates.
- There is no multi-input batching, equal-value recovery forest,
  arbitrary-value duplicate unilateral recovery, or exact legacy parity.
- A canonical close freezes its known binding set. A later discovery blocks
  completion while server state remains, while discovery after deletion may
  be unrecoverable. Start with fresh databases: the client has twelve
  application tables, Mercury six, and lockbox two. The CLI has sixteen
  commands and the exact force flag above.
- There is no automatic stale-state watcher. BIP448 uses the pinned Bitcoin
  Inquisition revision and remains a proof of concept, not for Bitcoin mainnet
  or production use. The 58 ignored entries above establish only their direct
  assertions.
