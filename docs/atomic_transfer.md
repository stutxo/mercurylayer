# BIP448 batch and lightning latch

The retained code has a batch identifier and latch around the ordinary BIP448
transfer path. It does not contain a separate multi-coin statechain protocol.

## Implemented latch flow

1. The current owner calls `POST /transfer/paymenthash` with
   `statechain_id`, an owner `auth_sig`, and `batch_id`. Mercury creates a
   random 32-byte preimage, stores the latch as locked, and returns its SHA-256
   `hash`.
2. The sender passes that `batch_id` to `POST /transfer/sender` through
   `bip448-transfer-send`. The client first persists an exact transfer intent.
   The normal BIP448 sender creates and signs the next state and uploads the
   encrypted transfer message.
3. `POST /transfer/receiver` checks the transfer's batch. Before expiry, a
   receiver gets `StatecoinBatchLockedError` while any transfer in that batch
   remains locked. The client reports the locked result without accepting the
   statechain.
4. An authorized, exact-generation call to `POST /transfer/unlock` changes only
   its role's stored lock. Once the batch is unlocked, the receiver performs
   the full BIP448 validation and generation-fenced key update.
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

## Exact transfer generation

An exact `/transfer/sender` retry for the active, unconsumed owner/recipient/
batch tuple returns the same stored `x1` after response loss. Authentication,
batch validation, exact replay, and fresh insertion run under the locked
current-owner row. A different authenticated request may replace the one-row
server generation, so the replay guarantee is not historical across such a
replacement.

The remaining BIP448 mutations bind to the compressed public key derived from
that exact `x1`:

- `/transfer/update_msg` adds required `x1_pub`; `auth_sig` covers
  `SHA256("BIP448/transfer-update-msg/v1\0" ||
  u32_be(statechain_id_utf8_len) || statechain_id_utf8 ||
  recipient_key_compressed || x1_pub_compressed ||
  SHA256(decoded_ciphertext_bytes))`.
- Existing `/transfer/unlock.auth_pub_key` is required for BIP448 and carries
  the canonical `x1` public key as a generation tag, not as the authentication
  key. Its signature covers
  `SHA256("BIP448/transfer-unlock/v1\0" || role_byte ||
  u32_be(statechain_id_utf8_len) || statechain_id_utf8 ||
  x1_pub_compressed)`, with role byte `0x00` for current owner and `0x01` for
  recipient.
- Existing `/transfer/receiver.batch_data` is required for BIP448 and carries
  the same generation key. The recipient signature covers
  `SHA256("BIP448/transfer-receiver/v1\0" ||
  u32_be(statechain_id_utf8_len) || statechain_id_utf8 || t2_bytes ||
  x1_pub_compressed)`.

The receiver reruns batch validation against the locked row before the lockbox
call. These fences prevent a stale unlock, upload, or receiver request from
mutating a replacement generation, including reuse of a recipient key. The
receiver's lockbox-success/Mercury-commit crash boundary is unchanged.

A completed latch-creation call does not reserve future transfer rights. A
later durable sweep attempt can make transfer unavailable; only a latch
creation that wins the local mutation guard first is allowed to finish before
that attempt.

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

## Cooperative duplicate-sweep boundaries

- Once canonical funding is pinned, the wallet keeps one logical `Coin` and
  canonical amount while normalized bindings record every observed
  same-script value. Duplicate indices are stable only inside that wallet
  database and are nested under `coin.duplicates`; passive binding
  synchronization does not sign.
- The exact command `bip448-sweep-duplicate <WALLET_NAME> <STATECHAIN_ID>
  <DUPLICATE_INDEX> <TO_ADDRESS> [FEE_RATE]` sweeps one confirmed duplicate in
  one one-input/one-output transaction. Its checked fee is
  `ceil(112 * fee_rate_sat_per_vbyte)`; a nonpositive/nonfinite rate, fee not
  smaller than the input, or dust output is rejected before signing. Each
  output has its own transaction, fee, and signing count.
- Attempt artifacts and phases are durable and retries reuse the exact request
  and transaction. `SecondArmed` is persisted before a possibly delivered
  `sign/second`, making the statechain permanently exit-only. A duplicate sweep
  never deletes server state; canonical withdrawal is last and requires every
  known current-owner duplicate to be handled. Dust and unresolved bindings
  remain visible and can block that close.
- The client durably records a transfer intent before sender mutation. With no
  intervening different authenticated request, exact same-request
  `/transfer/sender` response-loss replay returns one stored `x1` for the
  active unconsumed owner generation; authentication and generation changes
  are checked against locked rows. BIP448 update-message `x1_pub`, unlock
  `auth_pub_key`, and receiver `batch_data` carry the canonical compressed
  `x1` public generation key. Their signatures respectively bind
  statechain/recipient/generation/ciphertext hash,
  role/statechain/generation, and statechain/`t2`/generation.
- `--force-send-with-duplicates` acknowledges only the cooperative-value
  warning. The receiver rescans independently from height 0, assigns its own
  local indices, and decides whether and when to sweep; the sender receives no
  notification or sweep guarantee. A completed latch creation does not reserve
  future transfer rights against a later durable sweep attempt.
- Live unresolved arbitrary-value duplicates of the current owner remain
  cooperatively server-dependent until exact signed sweep bytes exist or an
  independent spend confirms. Previous-owner and retired late rows stay
  visible but are not actionable. Canonical `U`/`S` packages are the only
  claimed unilateral recovery; the emergency recovery commands can strand
  cooperative-only duplicates.
- There is no multi-input batching, equal-value recovery forest, arbitrary-value
  duplicate unilateral recovery, or exact legacy parity. A canonical attempt
  retires and freezes the address: a duplicate first found afterward blocks
  completion while server state remains, and one found only after deletion may
  be unrecoverable. The receiver key-update crash boundary remains unrepaired.
- Use fresh databases: the client schema has twelve application tables;
  Mercury has six and lockbox has two. The CLI has sixteen commands, including
  exact flag `--force-send-with-duplicates`; the intended ignored matrix has
  58 direct entries in eight binaries. This is an Inquisition-dependent proof
  of concept, with no automatic stale-state watcher, Bitcoin mainnet support,
  or production-use claim. Tests establish only their direct assertions.
