# BIP448 rebindable statechains

This document describes the protocol implemented by the current Rust client,
shared library, Mercury server, and lockbox. The consensus examples require the
Bitcoin Inquisition revision pinned by this repository.

## Keys and funding output

For each statechain, the owner key share and lockbox key share combine to an
aggregate public key `P`. The funding transaction `Tx0` pays the full statecoin
amount to a Taproot output whose internal key is `P` and whose single script
leaf is:

```text
OP_TEMPLATEHASH OP_INTERNALKEY OP_CHECKSIGFROMSTACK
```

`OP_TEMPLATEHASH` pushes a hash of the spending transaction's version,
locktime, sequences, outputs, and input position, while deliberately omitting
the previous outpoint. `OP_CHECKSIGFROMSTACK` verifies a Schnorr signature over
that hash, and `OP_INTERNALKEY` supplies the Taproot output's aggregate
internal key `P` without embedding it in the leaf. The client creates the
signature through a blinded two-party MuSig exchange with Mercury and the
lockbox. Because the previous outpoint is not committed, the signed update
template can be rebound to a compatible earlier state output and move the coin
to the latest state before an older settlement becomes valid.

## Funding bindings and repeated payments

After the accepted funding outpoint is pinned, the wallet retains one logical
statechain `Coin` and its canonical amount. The client normalizes every
observed same-script output into a separate local binding,
including consensus-valid values different from the canonical amount. Binding
index 0 is canonical; later duplicates receive stable indices assigned by that
wallet database. Those indices are local identifiers, not protocol or wire
identifiers, and another wallet can assign different numbers.

`list-statecoins` leaves the canonical fields on `coin` and nests duplicate
rows under `coin.duplicates`. Each row exposes its own outpoint, value,
observation state, owner generation, sweep broadcast state, and
`cooperative_only`/`server_dependent` flags. Passive synchronization updates
only the SQLite cursor, observation cache, bindings, and attempt observations.
It does not call either signing round, add a state/history row, increment a
lockbox count, or clone the logical Coin.

## One logical state

A logical state `n` consists of an update transaction `U(n)` and a settlement
transaction `S(n)`. The builder creates them in this order:

```text
build S(n) -> compute hash(S(n)) -> build the state output -> build U(n)
```

Both transactions are version 3, use the same explicit timestamp locktime
`L(n)`, have one protocol input, preserve the full statecoin value at output
index 0, and place the zero-value P2A script `OP_1 <0x4e73>` at output index 1.
The parent transactions intentionally pay zero fee.

`U(n)` uses input sequence zero. Its output 0 is a Taproot tree with internal
key `P` and these two leaves:

```text
<L(n) + 1> OP_CHECKLOCKTIMEVERIFY OP_DROP
OP_TEMPLATEHASH OP_INTERNALKEY OP_CHECKSIGFROMSTACK

<hash(S(n))> OP_TEMPLATEHASH OP_EQUAL
```

The update leaf allows a later state with a greater locktime to replace an
older confirmed state. The settlement leaf commits to exactly the associated
settlement template. `S(n)` uses input sequence `challenge_delay`; the retained
default is 144 blocks. It pays output 0 to that state's owner recovery address.

The initial `L(1)` is sampled in the inclusive timestamp range 500,000,000 to
1,000,000,000. A later state adds a freshly sampled stride in the inclusive
range 1 to 65,536. Receivers validate every adjacent stride and require the
latest locktime to be final under their median-time-past view.

## Why a signed update can be rebound

BIP448 `OP_TEMPLATEHASH` commits to the transaction template but omits the
input prevout. The implementation can replace the input of a signed `U(n)` or
`S(n)` while preserving its template hash. Rebinding helpers still require the
target output value to equal the committed value schedule; they reject a
target that would change the parent fee or output amount. Mutating a committed
field changes the template hash and invalidates the proof.

This is what permits a current update to spend the output of an older update:
the current `L(n)` satisfies the older output's `L(old) + 1` gate, while the
current signature and template remain unchanged.

## Blind signing and replay

The client calls:

1. `POST /bip448-statechain/sign/first` with `statechain_id`, an owner
   `signed_statechain_id`, and a random opaque 32-byte `signing_id`; then
2. `POST /bip448-statechain/sign/second` with those fields plus
   `negate_seckey`, the blinded `session`, and `server_pub_nonce`.

The serialized wire payload does not include the state number, signing role,
template hash, transaction, outputs, locktime, or settlement hash. Mercury
authenticates the owner, persists retry state, and forwards only
`statechain_id`, `signing_id`, and blinded signing material to the lockbox.

The lockbox stores one `bip448_nonce_state` row for each
`(statechain_id, signing_id)`. Exact first-round retries return the recorded
public nonce. Exact second-round retries return the recorded partial signature
and do not increment `sig_count` again. Reusing the identifier with a different
public nonce, session challenge, or negation flag conflicts. Mercury can fill a
missing local partial-signature record from an exact lockbox replay after a
failed persistence attempt.

Cooperative duplicate and canonical withdrawal signing also has a durable
client journal: `Prepared`, `FirstArmed`, `NonceStored`, `SecondArmed`, then
`Signed`. Immutable request, nonce, session, partial-signature, and transaction
artifacts are reused by an exact retry. Before the potentially delivered
second signing request, `SecondArmed` and the wallet's permanent exit-only
state are persisted. A response-loss retry therefore reconciles the exact
count and bytes; it does not create a new signing identity. The first such
possibly delivered duplicate signature permanently ends transfer eligibility.

These rules provide the retry behavior asserted by the implementation. They do
not establish what an operator does outside the observed requests and stored
rows.

## Transfer construction and receiver validation

The sender creates the next state with a new owner recovery output and a
greater sampled locktime, obtains its update signature, encrypts a version-2
transfer message to the recipient authentication key, and uploads the message.
Mercury records the transfer, then the recipient submits `t2` so the lockbox can
rotate its sealed share by `x1`.

Before the first sender request, the client persists a transfer intent that
binds the current owner generation, recipient, batch, cooperative-duplicate
acknowledgment, planned state/count, and prior state/history fingerprints.
Retries resume that exact intent. At Mercury, authentication, batch checks,
same-request replay, and fresh insertion occur against the locked current-owner
row. If no different authenticated request intervenes, an exact
`/transfer/sender` retry after response loss returns the same stored `x1` and
one active transfer row. A consumed (`key_updated = true`) generation is not
replayed.

Before accepting, the recipient client decrypts the message and checks all of
the following together:

- message version 1, the configured network, and challenge delay 144;
- the transfer signature binding the funding outpoint to the recipient key;
- the confirmed, unspent `Tx0` outpoint, its script, and its value from the
  recipient's Bitcoin Core view;
- recipient, sender, aggregate-key, server-key, `t1`, and `x1` continuity;
- the latest state number against both the message counts and Mercury's
  lockbox-derived signature count;
- one ordered history entry and one matching Mercury signing row for every
  state number from 1 through `n`;
- reconstructed update and settlement template hashes, each update signature,
  the server nonce/challenge rows, the zero-fee P2A value schedule, increasing
  locktimes, and latest-state consistency; and
- immediate finality of the latest timestamp locktime under chain median time
  past.

Only after verification does the client call `/transfer/receiver`, persist the
canonical history and accepted state, and update its wallet coin. A signature
count by itself is not accepted as state history and cannot reconstruct missing
history.

The generation-changing requests bind to the canonical compressed public key
derived from that exact `x1`:

- `POST /transfer/update_msg` requires `x1_pub`. Its current-owner `auth_sig`
  covers `SHA256("BIP448/transfer-update-msg/v1\0" ||
  u32_be(statechain_id_utf8_len) || statechain_id_utf8 ||
  recipient_key_compressed || x1_pub_compressed ||
  SHA256(decoded_ciphertext_bytes))`.
- For BIP448, existing `/transfer/unlock.auth_pub_key` is required and carries
  the `x1` generation public key, not an authentication identity. Its
  current-owner or recipient signature covers
  `SHA256("BIP448/transfer-unlock/v1\0" || role_byte ||
  u32_be(statechain_id_utf8_len) || statechain_id_utf8 ||
  x1_pub_compressed)`, where role is `0x00` or `0x01`, respectively.
- For BIP448, existing `/transfer/receiver.batch_data` is required and carries
  that generation public key. The recipient `auth_sig` covers
  `SHA256("BIP448/transfer-receiver/v1\0" ||
  u32_be(statechain_id_utf8_len) || statechain_id_utf8 || t2_bytes ||
  x1_pub_compressed)`.

Each server mutation revalidates the active owner generation and authenticated
request against its locked row, so a stale upload, unlock, or receiver call
cannot alter a replacement generation. After key update, accepted history, and
wallet persistence, the receiver performs its own passive scan from height 0.
A scan failure at that point is a typed accepted/rescan-pending outcome that a
later update/list retries without another key update. The sender receives no
notification and no guarantee that the receiver will sweep; the receiver
chooses and uses its own local indices as assigned by its wallet. The
lockbox-success/Mercury-commit receiver key-update crash boundary is unchanged.

A completed batch/latch-creation call does not reserve future transfer rights.
A later duplicate sweep attempt that wins the client mutation guard blocks new
transfer and latch creation; an already completed latch remains available for
its existing unlock/preimage cleanup flow.

## Recovery packages

Every stored update and settlement parent has a zero-value P2A output at index
1 and is submitted with a version-3 CPFP child through Bitcoin Core
`submitpackage`. The public recovery command's `funding_update` and
`settlement` roles select the already-stored latest-state update or settlement
parent, respectively. Independently, the caller supplies either keyless fee-
input descriptors or confirmed inputs discovered at the wallet-derived
recovery fee address for the CPFP child. The client persists package attempts
as `Pending`, `Submitted`, `Confirmed`, or `Abandoned` so exact retries can
resume the same child.

The public command does not accept or select a protocol-input prevout, and its
package builder does not invoke the low-level transaction rebinding helpers.
Selecting an older state output and rebinding the current update and settlement
to it is demonstrated only by the manually orchestrated test below. No running
component watches the chain, selects that stale-state source, or performs that
recovery sequence automatically.

Only those canonical update/settlement (`U/S`) transactions have the claimed
unilateral recovery behavior. Arbitrary-value duplicate outputs do not inherit
it. The public recovery commands are an emergency exemption to normal
duplicate/attempt gates and may strand unswept duplicates.

## Cooperative duplicate sweeps and canonical close

The current owner selects one target-confirmed duplicate by its local index:

```text
bip448-sweep-duplicate <WALLET_NAME> <STATECHAIN_ID> <DUPLICATE_INDEX> \
  <TO_ADDRESS> [FEE_RATE]
```

The client builds exactly one input and one output. It subtracts
`ceil(112 * fee_rate_sat_per_vbyte)` from that binding's exact value and
rejects a non-finite/non-positive fee rate, a fee not smaller than the input,
or a destination output below that script's dust threshold before signing.
There is one transaction, fee, and lockbox signing-count increment per swept
output; no multi-input batching is implemented. The result reports the exact
source outpoint, amount, sweep transaction ID, broadcast status, and permanent
exit-only state. This path never calls `/withdraw/complete` and never deletes
the logical statechain or its canonical `U/S` history.

Canonical cooperative withdrawal is last. A new close requires the canonical
binding to be current-owner, target-confirmed, and unspent, with no transfer
intent/signing/message, and requires every known current-owner duplicate to
have accepted/confirmed signed sweep bytes or a confirmed independent spend.
Unresolved `Mempool`, `Unconfirmed`, unswept `Confirmed`, `SpentMempool`,
`SpentUnconfirmed`, and `Absent` bindings block close; an uneconomic dust
binding therefore blocks while it lacks a permitted handled resolution. Every
pre-`Signed` attempt and signed `NotBroadcast`, `NeedsRebroadcast`, or
`Conflicting` attempt also blocks. A duplicate attempt that is `Signed` and
`Conflicted` is instead accepted into the frozen close snapshot only when its
exact different spender is target-confirmed.
Previous-owner and retired-address late bindings are visible but not
actionable.

The close freezes its known binding resolution set and chain tip before
signing the canonical one-input/one-output key-path transaction. After exact
broadcast acceptance, wallet persistence, and another frozen-snapshot check,
it durably enters `CloseArmed`; only this canonical path calls
`POST /withdraw/complete`. A binding first discovered after the freeze blocks
completion while Mercury state remains. A payment discovered only after
Mercury/lockbox deletion can be unrecoverable. Duplicate sweeps themselves do
not mark the statechain withdrawn or delete any server row.

## Manually orchestrated stale-state proof

The ignored test
`bip448_latest_state_fast_forwards_over_confirmed_old_state` creates states 1,
2, and 3, then explicitly performs this sequence from test code:

1. build and submit the state-1 update plus its CPFP child, and mine it;
2. rebind the already-signed state-3 update to the confirmed state-1 output,
   attach the state-1 update-leaf witness, submit its package, and mine it;
3. rebind the state-3 settlement to the new state-3 output, mine the 144-block
   delay, submit its package, and mine it; and
4. verify payment to the current owner's recovery address without increasing
   the signature count beyond 3.

This is consensus and client-library evidence for the explicitly exercised
sequence. It is test-side orchestration, not a runtime watcher or source
selection service.

## Prototype boundaries

- Current-owner live/unresolved duplicates remain cooperatively
  server-dependent until exact signed sweep bytes exist or an independent
  spend confirms. Consensus-valid arbitrary-value duplicates have no
  unilateral recovery. Previous-owner and retired late bindings are visible
  but not actionable.
- There is no multi-input batching, equal-value recovery forest, arbitrary
  duplicate unilateral protection, or exact legacy parity. One
  output means one transaction, fee, and signing count; known dust or
  unresolved outputs can block normal close.
- The first possibly delivered duplicate signature permanently makes the
  statechain exit-only. `--force-send-with-duplicates` acknowledges only the
  warning and cannot bypass attempts, count mismatch, or exit-only state. The
  sender is not notified after receipt and has no receiver sweep guarantee.
- Receiver duplicate discovery is independent and receiver-local. Receiver
  key-update crash recovery is unchanged. Emergency canonical recovery may
  strand duplicates, and late payment after address retirement/server deletion
  may be unrecoverable.
- Start from fresh databases only: the client has twelve application tables;
  Mercury's six and lockbox's two application tables are unchanged. The CLI
  has sixteen commands and the intended ignored matrix is 58 direct entries in
  eight binaries.
- There is no chain watcher and no automatic selection of a stale state's
  funding source. The stale-state proof remains test-side orchestration.
  BIP448 consensus execution requires the pinned Bitcoin Inquisition revision.
  This remains a proof of concept, not for Bitcoin mainnet or production use;
  tests establish only their direct assertions.
