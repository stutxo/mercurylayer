# BIP448 batch and lightning latch

The retained code has a batch identifier and latch around the ordinary BIP448
transfer path. It does not contain a separate multi-coin statechain protocol.

## Implemented latch flow

1. The current owner calls `POST /transfer/paymenthash` with
   `statechain_id`, an owner `auth_sig`, and `batch_id`. Mercury creates a
   random 32-byte preimage, stores the latch as locked, and returns its SHA-256
   `hash`.
2. The sender passes that `batch_id` to `POST /transfer/sender` through
   `bip448-transfer-send`. The normal BIP448 sender creates and signs the next
   state and uploads the encrypted transfer message.
3. `POST /transfer/receiver` checks the transfer's batch. Before expiry, a
   receiver gets `StatecoinBatchLockedError` while any transfer in that batch
   remains locked. The client reports the locked result without accepting the
   statechain.
4. An authorized call to `POST /transfer/unlock` changes the stored lock. Once
   the batch is unlocked, the receiver performs the full BIP448 validation and
   key update.
5. `GET /transfer/paymenthash/<batch_id>` returns `hash` when the preimage is
   present. `POST /transfer/transfer_preimage` returns `preimage` only to the
   authorized previous owner after it is available.

The command-line wrappers are `payment-hash`, `bip448-transfer-send`,
`transfer-receive`, `confirm-pending-invoice`, `get-payment-hash`, and
`retrieve-pre-image`; their exact arguments and output are in the
[client guide](client_guide.md).

If the batch time recorded by the transfer path has expired, receiver
validation returns `ExpiredBatchTimeError`. The sender can call
`bip448-transfer-cancel`, which creates a later signed BIP448 state back to its
own wallet. A subsequent transfer can use no batch ID or a new one.

## What the two retained tests establish

The ignored `functional` binary contains exactly these two latch tests:

- `tb06_bip448_lightning_latch` exercises one statecoin. It asserts signature
  count 1 after deposit and 2 after send, retrieves the stored payment hash,
  verifies that a locked receive returns no IDs and leaves the receiver wallet,
  receiver BIP448 tables, sender state, and signature count unchanged, unlocks
  the transfer, accepts state 2, retrieves the preimage, and verifies its
  SHA-256 hash.
- `tb06_bip448_batch_expiry_recovery` exercises one statecoin. It sends state
  2 with a batch ID, waits for `batchtimeout + 1`, asserts the exact expiry
  error, cancels into confirmed sender state 3 with signature count 3, then
  sends without a batch and has a different receiver accept state 4 with
  signature count 4.

There is no retained multi-coin BIP448 atomic-transfer end-to-end test. The two
one-coin tests therefore do not demonstrate an exact replacement for the
deleted multi-coin scenario, cross-coin all-or-nothing settlement, Lightning
Network payment settlement, or behavior outside the assertions above.

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
