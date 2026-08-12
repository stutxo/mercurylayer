# BIP448 client architecture

## Purpose and review order

This is the short review map for the approved BIP448 client behavior. It
describes ownership and boundaries; the protocol itself is documented in
[BIP448 rebindable statechains](bip448_rebindable_statechains.md).
Use the [client guide](client_guide.md) for commands and lifecycle details, the
[database reference](server_db.md) for schemas, and [test cases](test_cases.md)
for the assertions behind each claim.

For any path, review in this order:

1. Start at the stable public facade and its entry point.
2. Follow policy and domain validation, including persisted-enum validation.
3. Inspect the owning SQLite transaction and its compare-and-set conditions.
4. Read the integration scenario that exercises the same remote boundary.

The four main entry paths are:

| Entry path | Stable facade | First behavior to locate |
| --- | --- | --- |
| Passive update/list | `coin_status` | binding sync, projection, then the separate wallet coordinator |
| Duplicate sweep | `bip448_withdraw` | duplicate policy and the typed durable attempt driver |
| Canonical close | `bip448_withdraw` | ready-close gate, canonical driver, then completion last |
| Transfer, receiver, cancellation | `bip448_transfer_sender` and `transfer_receiver` | durable intent, signing, delivery, acceptance, and cleanup |

The behavior described here is already approved. The refactor movement is behavior-preserving: public paths, persisted representations, remote/write ordering, error text, and test assertions remain fixed.

## Module and dependency map

The intended dependency direction is deliberately concrete:

```text
CLI / outer receiver -> stable public facades
facades -> orchestration -> domain + SQLite + concrete chain/HTTP helpers
facades -> passive sync  -> domain + SQLite + concrete chain reads
SQLite -> domain
```

Domain code does not depend on SQLx, client configuration, chain RPC, HTTP, or orchestration.
Storage does not perform chain RPC or construct HTTP requests. Passive sync can read Bitcoin and
write observations, but cannot sign, transfer, complete a withdrawal, or mutate a latch.
Orchestration may use domain, storage, passive sync, and existing concrete adapters.
One orchestration state machine does not become another state machine's implementation.

The concrete `chain` and `utils` modules remain adapters; this series adds no repository, unit-of-work, generic transaction, or adapter-trait layer.

### Target layout for this refactor series

The approved parent still has flat facade implementations; the new child paths in this
behavior-preserving target layout do not yet exist in this commit.

Domain ownership keeps `clients/libs/rust/src/bip448_funding.rs` as the stable facade:

| Target path | Exact owner |
| --- | --- |
| `clients/libs/rust/src/bip448_funding/enums.rs` | parsed-enum macro and every exact persisted enum literal |
| `clients/libs/rust/src/bip448_funding/canonical.rs` | canonical txid, block hash, hex, script, key, JSON, and transaction parsing |
| `clients/libs/rust/src/bip448_funding/bindings.rs` | binding and observation models, validation, sync base, report, and revisions |
| `clients/libs/rust/src/bip448_funding/withdrawal.rs` | fee policy, full/blinded MuSig relationship, attempt validation, count, and exit-only policy |
| `clients/libs/rust/src/bip448_funding/transfer.rs` | transfer intent model, validation, and immutable equality |
| `clients/libs/rust/src/bip448_funding/close.rs` | close snapshots, strict codec, blockers, and gate evaluation |

Storage keeps generic wallet CRUD in `clients/libs/rust/src/sqlite_manager.rs`
and gives each guarded concern one owner:

| Target path | Exact owner |
| --- | --- |
| `clients/libs/rust/src/sqlite_manager/bip448/mod.rs` | private storage subtree and facade-facing re-exports |
| `clients/libs/rust/src/sqlite_manager/bip448/rows.rs` | checked row conversion, exact lookup, and connection-scoped lists |
| `clients/libs/rust/src/sqlite_manager/bip448/guard.rs` | `Bip448MutationGuard`, begin, connection access, commit, rollback, and contention hook |
| `clients/libs/rust/src/sqlite_manager/bip448/scan.rs` | cursor/cache, fee reservations, packages, and scan-state persistence |
| `clients/libs/rust/src/sqlite_manager/bip448/accepted.rs` | accepted record/history, pending signing, messages, and raw rows |
| `clients/libs/rust/src/sqlite_manager/bip448/initial_acceptance.rs` | exact wallet-Coin validation, atomic accepted record/history insertion, and separate restart wallet recovery |
| `clients/libs/rust/src/sqlite_manager/bip448/bindings.rs` | guarded reconcile, observation, owner movement, and rotated cleanup |
| `clients/libs/rust/src/sqlite_manager/bip448/withdrawals.rs` | attempts, phases, artifacts, broadcast/completion, count, close gate, latch gate, and completion fence |
| `clients/libs/rust/src/sqlite_manager/bip448/transfer_intents.rs` | intent lineage, blockers, cancellation insertion, supersession, rejection, and reactivation |
| `clients/libs/rust/src/sqlite_manager/bip448/transfer_signing.rs` | target pending, nonce, second arm, signed/reused state, and message materialization |
| `clients/libs/rust/src/sqlite_manager/bip448/transfer_completion.rs` | sender finish, terminal cleanup, receiver acceptance, and post-sync cancellation cleanup |
| `clients/libs/rust/src/sqlite_manager/bip448/sync.rs` | sync-base capture and full wallet/revision compare-and-set |

Passive synchronization keeps `clients/libs/rust/src/coin_status.rs` as its stable facade:

| Target path | Exact owner |
| --- | --- |
| `clients/libs/rust/src/coin_status/discovery.rs` | generic UTXO discovery, scan state, batching, and complete-operation retry |
| `clients/libs/rust/src/coin_status/reducer.rs` | receive/spend facts, deterministic ordering, and authoritative replay predicates |
| `clients/libs/rust/src/coin_status/sync.rs` | scan plans, guarded apply, retry, public sync, and separately called reconciliation |
| `clients/libs/rust/src/coin_status/list.rs` | exact JSON list projection only |
| `clients/libs/rust/src/coin_status/wallet_update.rs` | deposit recovery, status effects, wallet CAS, and `update_coins` |

Withdrawal orchestration keeps `clients/libs/rust/src/bip448_withdraw.rs` as its stable facade:

| Target path | Exact owner |
| --- | --- |
| `clients/libs/rust/src/bip448_withdraw/policy.rs` | identity, confirmation, invocation, owner, count, close, and response policy |
| `clients/libs/rust/src/bip448_withdraw/driver.rs` | typed attempt refresh, phase progression, frozen revalidation, broadcast, and reconciliation |
| `clients/libs/rust/src/bip448_withdraw/duplicate.rs` | duplicate result and public duplicate-sweep entry; never completion |
| `clients/libs/rust/src/bip448_withdraw/canonical.rs` | canonical identity, ready-close gate, canonical refresh, completion, and public close entry |

Transfer sender orchestration keeps `clients/libs/rust/src/bip448_transfer_sender.rs` as its stable facade:

| Target path | Exact owner |
| --- | --- |
| `clients/libs/rust/src/bip448_transfer_sender/api.rs` | compatibility wrapper, options entry, and public exports |
| `clients/libs/rust/src/bip448_transfer_sender/preflight.rs` | fresh sync, current owner/count proof, gates, acknowledgement, and intent plan |
| `clients/libs/rust/src/bip448_transfer_sender/driver.rs` | active phase loop, rotation cleanup, recovery, server x1 boundary, and checkpoints |
| `clients/libs/rust/src/bip448_transfer_sender/signing.rs` | templates, pending plan, first/second signing, persistence, and reuse |
| `clients/libs/rust/src/bip448_transfer_sender/message.rs` | validation, construction, materialization, upload, mailbox proof, delivery, and finish |
| `clients/libs/rust/src/bip448_transfer_sender/cancellation.rs` | cancellation preparation, public cancellation, and cancellation finish |

Receiver behavior keeps the included-module facade `clients/libs/rust/src/bip448_transfer_receiver.rs`
and the outer facade `clients/libs/rust/src/transfer_receiver.rs`:

| Target path | Exact owner |
| --- | --- |
| `clients/libs/rust/src/bip448_transfer_receiver/verify.rs` | decrypt, version/auth/history checks, chain facts, server key, and receiver request |
| `clients/libs/rust/src/bip448_transfer_receiver/driver.rs` | key-update completion, idempotent attempt, already-updated resolution, and test seam |
| `clients/libs/rust/src/bip448_transfer_receiver/persist.rs` | accepted-record upsert, separately committed history inserts, and in-memory Coin/activity construction |
| `clients/libs/rust/src/transfer_receiver/bip448_post_acceptance.rs` | message disposition, checkpoint, height-zero rescan, acceptance retry, and cleanup |

Concrete boundaries stay at `clients/libs/rust/src/chain/`, `clients/libs/rust/src/utils.rs`,
`clients/libs/rust/src/deposit.rs`, and `clients/apps/rust/src/main.rs`; shared Mercury and
lockbox DTOs stay in their current crates.

Test ownership becomes explicit without changing root test identities:

| Target path group | Contents |
| --- | --- |
| `clients/libs/rust/src/sqlite_manager/bip448/tests/mod.rs` | storage test declarations only |
| `clients/libs/rust/src/sqlite_manager/bip448/tests/support.rs` | fixtures shared by at least two storage groups |
| `clients/libs/rust/src/sqlite_manager/bip448/tests/schema_and_accepted.rs` | schema and accepted-state tests |
| `clients/libs/rust/src/sqlite_manager/bip448/tests/scan_and_packages.rs` | scan and package tests |
| `clients/libs/rust/src/sqlite_manager/bip448/tests/bindings.rs` | binding tests |
| `clients/libs/rust/src/sqlite_manager/bip448/tests/withdrawals.rs` | withdrawal tests |
| `clients/libs/rust/src/sqlite_manager/bip448/tests/transfer_intents.rs` | transfer-intent tests |
| `clients/libs/rust/src/sqlite_manager/bip448/tests/synchronization.rs` | synchronization tests |
| `clients/libs/rust/src/sqlite_manager/bip448/tests/concurrency.rs` | concurrency tests |
| `clients/libs/rust/src/coin_status/test_support.rs` | exact shared coin-status test support |
| `clients/tests/rust/tests/bip448_duplicates/support.rs` | duplicate-scenario shared support |
| `clients/tests/rust/tests/bip448_duplicates/repeated_funding.rs` | repeated funding scenario |
| `clients/tests/rust/tests/bip448_duplicates/inventory.rs` | inventory scenario |
| `clients/tests/rust/tests/bip448_duplicates/restart.rs` | restart scenario |
| `clients/tests/rust/tests/bip448_duplicates/canonical_close.rs` | close scenario |
| `clients/tests/rust/tests/bip448_duplicates/post_acceptance.rs` | post-acceptance scenario |
| `clients/tests/rust/tests/bip448_duplicates/transfer.rs` | transfer scenario |
| `clients/tests/rust/tests/bip448_duplicates/same_wallet.rs` | same-wallet scenario |
| `clients/tests/rust/tests/bip448_duplicates/dust.rs` | dust scenario |
| `clients/tests/rust/tests/bip448_transfer_sender/support.rs` | sender shared support |
| `clients/tests/rust/tests/bip448_transfer_sender/restart.rs` | sender restart scenario |
| `clients/tests/rust/tests/bip448_transfer_sender/rotation.rs` | sender rotation scenario |
| `clients/tests/rust/tests/bip448_transfer_sender/retarget.rs` | sender retarget scenarios |
| `clients/tests/rust/tests/bip448_transfer_sender/cancellation.rs` | cancellation scenario |
| `clients/tests/rust/tests/bip448_deposit/support.rs` | deposit shared support |
| `clients/tests/rust/tests/bip448_deposit/restart.rs` | deposit restart scenario |
| `clients/tests/rust/tests/bip448_deposit/transfer.rs` | deposit transfer scenarios |
| `clients/tests/rust/tests/bip448_deposit/discovery.rs` | discovery scenario |
| `clients/tests/rust/tests/bip448_deposit/stale_state.rs` | stale-state scenario |
| `clients/tests/rust/tests/bip448_deposit/recovery.rs` | recovery scenarios |
| `clients/tests/rust/tests/lockbox_compatibility/support.rs` | lockbox shared support |
| `clients/tests/rust/tests/lockbox_compatibility/validation.rs` | validation scenarios |
| `clients/tests/rust/tests/lockbox_compatibility/signing.rs` | signing scenarios |
| `clients/tests/rust/tests/lockbox_compatibility/keyupdate.rs` | key-update scenarios |
| `clients/tests/rust/tests/lockbox_compatibility/deletion.rs` | deletion scenarios |
| `clients/tests/rust/tests/lockbox_compatibility/deterministic.rs` | deterministic-vector scenario |
| `clients/tests/rust/tests/lockbox_compatibility/concurrency.rs` | concurrency scenarios |
| `clients/tests/rust/tests/lockbox_compatibility/schema.rs` | schema scenarios |
| `clients/tests/rust/tests/lockbox_compatibility/mercury_routes.rs` | Mercury route scenarios |

## Durable state machines

Withdrawal signing uses a typed attempt kind, never a completion boolean.
The durable phase write always precedes the remote call named below.

| Withdrawal phase | Durable meaning and next boundary |
| --- | --- |
| `Prepared` | immutable source, destination, fee, unsigned bytes, signing identity, and exact first request exist |
| `FirstArmed` | written before the remote sign-first request may be delivered |
| `NonceStored` | server nonce plus full and blinded session artifacts and exact second request are stored |
| `SecondArmed` | written before the remote sign-second request may be delivered; the attempt is now irreversible and exit-only |
| `Signed` | server partial, aggregate signature, exact transaction bytes, and txid are durable before broadcast |

Broadcast observation is a separate axis:

| Broadcast status | Meaning |
| --- | --- |
| `NotBroadcast` | exact signed bytes have not been accepted by the chain client |
| `NeedsRebroadcast` | the same bytes are neither observed nor conclusively conflicting and must be retried |
| `Accepted` | exact txid/bytes were accepted or are visible without target confirmation |
| `Confirmed` | the exact attempt transaction is target-confirmed |
| `Conflicting` | a different spend is known but is not yet target-confirmed |
| `Conflicted` | a different spender is target-confirmed for the source |

Canonical completion is also independent:

| Attempt kind | Completion progression |
| --- | --- |
| Canonical | `Open`; durable `CloseArmed` is written before remote `complete_withdraw` may be delivered; `Closed` follows only a positive completion response or journal-first reconciliation evidence |
| Duplicate | `NotApplicable`; duplicate code never enters completion or calls completion |

The transfer outer journal is:

| Transfer phase | Durable meaning and remote boundary |
| --- | --- |
| `Prepared` | immutable intent exists before any sender mutation |
| `SenderArmed` | written before the remote sender x1 request may be delivered |
| `X1Stored` | returned x1 is durable; transfer-state signing and message materialization may proceed |
| `SenderFinished` | exact message was delivered or rotation proved; user-transfer cleanup or cancellation receive follows |
| `ReceiverAccepted` | cancellation receiver acceptance is durable; height-zero rescan and terminal cleanup may retry |

Supersession is a separate activity/lineage relation, not another outer phase.
True pre-sign retarget is limited to an approved pre-nonce boundary; after a
nonce might have been delivered, the predecessor must finish and a successor
uses the post-sign count.

Transfer-state signing has its own journal:

| Signing phase | Durable meaning and next boundary |
| --- | --- |
| `NotStarted` | no target nonce request may have been delivered |
| `FirstArmed` | target pending identity is durable before sign-first |
| `NonceStored` | returned server nonce is durable and the exact second request can be rebuilt |
| `SecondArmed` | written before sign-second may be delivered; replay uses the same request |
| `Signed` | server partial and aggregate/update signature artifacts are durable; history and message materialization follow |

A later guarded transaction appends the additional outgoing state-history entry and stores the exact transfer message, which is durable at `transfer_msg_persisted` before upload or sender finish.

These tables are review sequences, not a claim that every enum cross-product
is legal. Domain and storage validators define the exact legal combinations.

## Side-effect and persistence boundaries

| Path | Permitted reads/writes and remote effects |
| --- | --- |
| Passive binding sync | Bitcoin reads plus client SQLite scan, binding, observation, cursor, and revision writes only |
| `update_coins` | separate coordinator: passive sync plus approved initial-deposit acceptance/recovery and wallet/status effects |
| Duplicate sweep | may sign and broadcast one exact sweep; never completes or deletes server state |
| Canonical close | refreshes and closes last; it is the sole client caller of `complete_withdraw` |
| Sender | persists an intent before the first sender mutation, then journals each armed/reply boundary |
| Receiver | verifies, updates the key, separately commits the record upsert and each history entry, builds Coin/activity in memory, then the outer receiver writes the wallet and rescans |

`sync_bip448_funding_bindings` is passive. `update_coins` is not wholly passive, because it
coordinates initial acceptance, wallet Coin/status updates, and a full-wallet compare-and-set.
The local `reconcile_bip448_post_sync_transfer_artifacts` cleanup remains separately invoked
outside the body of passive binding sync.

Full and blinded MuSig sessions are different persisted artifacts. The client
stores both and validates their derivation relationship before accepting or
replaying a signing phase; one encoding is not treated as the other.

Initial acceptance validates the exact wallet Coin under `BEGIN IMMEDIATE`, but that transaction
inserts only the accepted record and state-1 history. `update_coins` persists the mutated wallet
later through a separate full-wallet compare-and-set; restart recovery repairs that existing crash
boundary. Receiver acceptance is not one atomic transaction: the accepted-record upsert commits
independently, every history entry commits separately, Coin/activity changes are built in memory,
and the outer receiver persists the full wallet later. Sender and cancellation terminal functions
retain their exact wallet, history, pending-signing, message, intent, and generated-Coin effects in their owning atomic operation.

## Mutation guards and concurrency

`Bip448MutationGuard` starts with `BEGIN IMMEDIATE`, so competing writers are
serialized before guarded local checks and writes. Transfer/attempt and cancellation/attempt races
have one durable winner. Latch/attempt is asymmetric: attempt-first holds the guard, persists the
attempt, and rejects latch creation before any remote latch call; latch-first may finish its one
remote call under the guard, then the waiting attempt may persist after that guard commits because
completed latch creation reserves no future transfer right. Cancellation preparation atomically appends its generated Coin with its intent.

Passive sync captures a full base, applies the scan under a guard, and uses a
full-wallet compare-and-set with scan revision tokens. Positive ownership
rotation invalidates the old binding generation inside that same wallet CAS;
it is not a later cleanup transaction.

Transaction boundaries stay exact even when responsibilities span modules:

- initial acceptance atomically inserts only record/history after validating the
  wallet Coin; the later wallet CAS and restart recovery remain separate;
- sync CAS owns positive-rotation binding invalidation with the wallet write;
- terminal transfer/cancellation owns exact wallet, history, message, pending,
  intent, and generated-Coin cleanup.

The single storage/remote exception is the canonical completion fence.
Storage validates the final snapshot while holding one mutation guard, then
awaits the caller-supplied whole HTTP response under the fixed 20-second
bound. Storage does not construct that request. The guard spans final snapshot
validation and the whole bounded response; a timeout or callback error rolls
back before canonical orchestration performs journal-first reconciliation.
Only the canonical withdrawal path can reach this exception.

## Crash, replay, and reconciliation

Persist-before-remote is the central rule. An armed phase means the following
remote request might already have been delivered, even when its response is
missing. Replay therefore reconstructs the exact persisted request instead of
choosing new nonces, signing identities, destinations, fees, or transaction
bytes.

`SecondArmed` is the irreversible exit-only boundary. A retry may reconcile a
previously completed sign-second or submit the exact request again, but it may
not return the statechain to a transferable pre-sign state.

Signed broadcast reconciliation reasons about the exact persisted transaction bytes and
txid. Disappearance or absence of that exact signed transaction becomes `NeedsRebroadcast`
only when no different spender is known; retry rebroadcasts only those same bytes. A different mempool
or below-target spender is `Conflicting`; an exact target-confirmed different spender is `Conflicted`.

Sender response loss is journaled at both the x1 and signing boundaries.
Exact same-request sender replay can recover the stored x1 for the active,
unconsumed owner generation. Message upload is checked against mailbox bytes,
and rotation evidence permits local terminal cleanup without reupload.

After accepted receipt, `ReceiverAccepted` makes the cancellation's passive
height-zero rescan and local cleanup retryable. A normal accepted receiver also
reports a typed post-acceptance sync error so a later update/list can retry.

This does not repair the receiver key-update crash boundary. A crash after
lockbox key update but before the separate record, history-entry, and outer
wallet writes finish can still require manual completion; this document makes no stronger claim.

## Ownership across transfer and cancellation

Funding bindings record an owner user key, owner state number, and ownership
status. Current bindings are actionable only for the proven current generation;
previous bindings remain visible history and are not silently reassigned to an
unrelated wallet Coin.

Same-wallet transfer selection uses the current server key together with the
user key to prove the aggregate key and select one exact current-generation
Coin. A positive remote rotation moves the outgoing Coin to transferred state
and changes current bindings to previous in the same compare-and-set. A
same-wallet accepted receiver generation can instead become the exact current
binding owner after accepted history proves it.

Receiver discovery is independent. It rescans from height zero and allocates
receiver-local duplicate indices, so sender and receiver indices need not
match. The receiver decides whether and when to sweep; the sender gets no
sweep notification or guarantee.

Cancellation is a transfer to one atomically generated local Coin. Acceptance proves it, advances the cancellation to `ReceiverAccepted`,
rescans, and atomically removes the exact outgoing message, pending signing, and intent lineage.
Only a definitive pre-insert batch rejection atomically removes that active intent and generated Coin, then reactivates a valid direct
predecessor; transport failures, any other HTTP status, body-read failures, malformed success, and equivalent response loss are
indeterminate and retain the active cancellation intent and generated Coin for exact replay.

Lightning-latch creation and confirmation use the current owner selector.
The intentional exception is `retrieve_pre_image`: it authenticates with the
historical lowest-locktime Coin that created the latch, even after ownership
rotates. That historical cleanup rule must not be generalized to create or
confirm selection.

## Tests to read with each path

The ignored root names below remain exact; scenario files may move later, but root binary, attributes,
Tokio flavor, environment-child behavior, return type, name, and assertion stay fixed.

Passive update/list and discovery:

- `bip448_repeated_funding_preserves_canonical_state_and_signature_count`
- `bip448_duplicate_inventory_is_stable_across_restart_reorg_and_spend`
- `bip448_client_restart_child`
- `bip448_deposit_survives_client_process_restarts`
- `bip448_deposit_recovers_through_update_and_settlement_packages`
- `bip448_latest_state_fast_forwards_over_confirmed_old_state`
- `bip448_discovery_cursor_reorg_and_restart_state`
- `bip448_client_submitter_broadcasts_recovery_package`
- `bip448_owner_recovery_survives_restart_mid_broadcast`
- `bip448_cli_wallet_funded_and_keyless_recovery_packages`

Duplicate sweep and its signing/broadcast boundary:

- `bip448_template_signature_rebinds_prevout_on_inquisition`
- `bip448_blinded_musig_csfs_signature_spends_on_inquisition`
- `bip448_sign_second_recovers_missing_mercury_partial_from_lockbox_replay`
- `bip448_sign_second_accepts_uppercase_0x_server_pubnonce`
- `bip448_sign_second_fails_closed_while_lockbox_status_is_unavailable`
- `bip448_duplicate_sweep_replays_every_signing_and_broadcast_boundary`
- `bip448_duplicate_dust_remains_visible_and_blocks_close`
- `bip448_signing_lifecycle_returns_a_valid_partial_signature_and_increments_signature_count`
- `bip448_nonce_state_replays_after_restart_and_rejects_conflicting_challenge`
- `deterministic_lockbox_vectors_match_golden_outputs`
- `parallel_statechains_can_sign_independently`
- `concurrent_exact_bip448_partial_replays_increment_signature_count_once`
- `mercury_signing_routes_nonce_and_partial_signature_through_lockbox`

Canonical close:

- `bip448_duplicate_sweeps_are_one_input_and_canonical_closes_last`
- `bip448_cooperative_withdrawal_closed_list`
- `delete_statechain_is_idempotent_and_deleted_statechain_cannot_be_used`
- `mercury_withdraw_complete_preserves_rows_when_lockbox_delete_fails`

Sender, receiver, same-wallet transfer, and cancellation:

- `tb06_bip448_lightning_latch`
- `tb06_bip448_batch_expiry_recovery`
- `bip448_transfer_address_reuse_accepts_two_distinct_statechains`
- `bip448_one_hop_transfer_accepts_and_recovers_state_two`
- `bip448_two_hop_transfer_accepts_and_recovers_state_three`
- `bip448_same_wallet_second_hop_advances_to_state_three`
- `bip448_same_wallet_transfer_advances_the_accepted_record_to_state_two`
- `bip448_receiver_post_acceptance_duplicate_rescan_is_retryable`
- `bip448_duplicate_transfer_requires_ack_and_receiver_rediscovers`
- `bip448_duplicate_same_wallet_cancel_reassigns_current_owner`
- `bip448_transfer_restart_child`
- `bip448_transfer_survives_signing_and_upload_restarts`
- `bip448_sender_finishes_after_receiver_rotates_auth_key`
- `bip448_retarget_before_signing_reuses_next_state`
- `bip448_retarget_after_signing_preserves_superseded_history`
- `bip448_cancel_returns_coin_and_allows_real_transfer`
- `keyupdate_validates_t2_and_x1_lengths`
- `keyupdate_requires_existing_statechain`
- `keyupdate_returns_the_expected_server_pubkey_and_statechain_remains_usable`
- `keyupdate_state_survives_lockbox_restart`
- `concurrent_keyupdate_replays_return_the_same_server_pubkey`
- `mercury_statechain_info_returns_ordered_bip448_rows_and_transfer_clears_them`
- `mercury_transfer_receiver_routes_keyupdate_to_lockbox`

Storage/schema and route prerequisites read across all four paths:

- `get_public_key_requires_statechain_id`
- `bip448_get_public_nonce_requires_existing_statechain`
- `bip448_get_partial_signature_validates_session_length`
- `bip448_get_partial_signature_requires_existing_nonce_state`
- `signature_count_for_missing_statechain_returns_not_found`
- `fresh_lockbox_schema_has_only_bip448_nonce_state_columns`
- `fresh_mercury_schema_has_exact_bip448_tables_and_lease_columns`
- `mercury_deposit_init_creates_a_lockbox_backed_statechain`

Read these storage concurrency unit tests with the path they protect:

- `bip448_begin_immediate_excludes_two_real_pool_connections`
- `bip448_transfer_intent_and_duplicate_attempt_have_one_durable_winner`
- `bip448_latch_creation_and_duplicate_attempt_are_asymmetrically_linearized`
- `bip448_accepted_to_needs_rebroadcast_serializes_before_later_attempt`

## Deliberate limitations

- `cooperative_only` means there is neither a durable `Signed` attempt nor a target-confirmed independent spend. `server_dependent` additionally requires `Current` ownership and a non-retired address: a live unresolved current-owner arbitrary-value duplicate on such an address has both flags until exact signed sweep bytes or a target-confirmed independent spend exists; previous-owner and retired-late rows stay visible but are not actionable.
- A sweep has exactly one input and one output. Each output therefore needs its own transaction, fee, and lockbox signing-count increment.
- A fee not smaller than the input, a dust result, or an unresolved duplicate
  is rejected or remains visible; dust and unresolved rows block canonical
  close.
- There is no multi-input batching or equal-value recovery forest.
- Arbitrary-value duplicates have no unilateral recovery path. Only canonical update/settlement recovery has the unilateral claim, and emergency recovery can strand duplicates.
- The prototype does not claim exact legacy parity.
- There is no chain watcher and no automatic stale-state source selection.
- The receiver key-update crash/manual-completion boundary remains unrepaired.
- Only fresh databases are supported; no legacy-schema migration is claimed.
- Consensus execution depends on the repository's pinned Bitcoin Inquisition revision.
- This is a proof of concept, with no Bitcoin mainnet support or production-use claim. Tests establish only their direct assertions.
