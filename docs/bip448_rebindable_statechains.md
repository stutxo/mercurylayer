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

The leaf therefore requires both a BIP448 template-hash match and a Schnorr
signature checked against the Taproot internal key. The client creates that
signature through a blinded two-party MuSig exchange with Mercury and the
lockbox.

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

These rules provide the retry behavior asserted by the implementation. They do
not establish what an operator does outside the observed requests and stored
rows.

## Transfer construction and receiver validation

The sender creates the next state with a new owner recovery output and a
greater sampled locktime, obtains its update signature, encrypts a version-2
transfer message to the recipient authentication key, and uploads the message.
Mercury records the transfer, then the recipient submits `t2` so the lockbox can
rotate its sealed share by `x1`.

Before accepting, the recipient client decrypts the message and checks all of
the following together:

- message version 2, the configured network, and challenge delay 144;
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

## Cooperative withdrawal

The cooperative withdrawal path spends `Tx0` through the funding output's
Taproot key path. The client validates the accepted record and funding value,
applies the funding tree's Taproot merkle-root tweak, performs blinded MuSig
through the BIP448 signing endpoints, broadcasts the signed transaction, and
then calls `POST /withdraw/complete`. The server asks the lockbox to delete its
rows and deletes the Mercury statechain rows. This records the implemented
request flow; it does not prove deletion beyond those operations.

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
