# BIP448 client guide

The Rust client stores wallets and canonical BIP448 state records in SQLite,
uses Bitcoin Core/Inquisition as its only chain backend, and talks to the
Mercury Rocket service over HTTP.

Run examples from the workspace root with this prefix:

```text
RUSTUP_TOOLCHAIN=1.92.0 cargo run -p client-rust --
```

The complete argument grammar is in [Usage.md](../Usage.md).

## Client settings

The current settings keys are:

| Key | Requirement |
| --- | --- |
| `statechain_entity` | required Mercury base URL |
| `chain_backend` | optional; defaults to and only accepts `core` |
| `core_rpc_url` | required when the Core backend is selected |
| `core_rpc_auth` | optional: `none`, `userpass`, or `cookie` |
| `core_rpc_user`, `core_rpc_password` | required together for `userpass` |
| `core_rpc_cookie_file` | required for `cookie`; relative paths resolve beside the settings file |
| `network` | required: `signet`, `testnet`, `regtest`, or `bitcoin` |
| `fee_rate_tolerance` | required integer, loaded as a floating-point value |
| `database_file` | required SQLite filename or URL |
| `confirmation_target` | required unsigned confirmation count |
| `tor_proxy` | optional proxy URL |
| `max_fee_rate` | required integer sat/vbyte cap, loaded as a floating-point value |

`ML_SETTINGS_FILE` selects a settings file. A value containing a path or file
extension is used directly; otherwise `.toml` is appended. If it is unset,
`ML_NETWORK=regtest` selects `regtest.Settings.toml`; all other cases select
`Settings.toml`.

## Create a wallet and token

```text
cargo run -p client-rust -- create-wallet alice
cargo run -p client-rust -- new-token
```

Wallet creation prints a debug line beginning `Wallet created:`. `new-token`
prints this JSON shape:

```json
{
  "token_id": "...",
  "payment_method": "free or onchain",
  "deposit_address": null,
  "fee": 0,
  "confirmation_target": 0
}
```

For an on-chain token, `deposit_address` is a string and the fee and target are
the token-server values. For a local free token, it is `null` and both numbers
are zero. See [tokens.md](tokens.md) for the exact verification flow.

## Create and fund one statechain

```text
cargo run -p client-rust -- \
  new-bip448-deposit-address alice <TOKEN_ID> 50000
```

`AMOUNT` is parsed as an unsigned 32-bit satoshi amount. The command initializes
the Mercury/lockbox statechain, records the address and amount metadata, saves
the wallet, and prints the result below. It does not construct or sign state 1.
Later, after a normal coin-status refresh discovers the confirmed funding UTXO,
the BIP448 deposit-state path constructs state 1, persists its restart signing
journal, signs it, and stores the accepted state.

```json
{
  "address": "...",
  "statechain_id": "...",
  "aggregate_pubkey": "..."
}
```

Send exactly the requested amount to `address`. Wallet refresh happens when
commands such as `list-statecoins`, transfer, or withdrawal update coin status
through Bitcoin Core. Once a canonical funding candidate is pinned, passive
binding synchronization watches the exact aggregate script from height 0 and
records every other same-script output without signing or changing the
canonical amount/history.

`list-statecoins alice` still prints one object per logical wallet `Coin`. Each
object has exactly these fifteen keys:

```text
coin.user_pubkey
coin.aggregated_address
coin.address
coin.statechain_id
coin.amount
coin.status
coin.locktime
coin.statechain_protocol
coin.utxo_txid
coin.utxo_vout
coin.exit_only
coin.address_retired
coin.close_tip_height
coin.close_tip_hash
coin.duplicates
```

The status progresses through the exercised values such as `IN_MEMPOOL`,
`UNCONFIRMED`, and `CONFIRMED` as chain facts change. The three optional
canonical identity fields `coin.statechain_protocol`, `coin.utxo_txid`, and
`coin.utxo_vout` serialize as their JSON value or `null`; the two close-tip
fields likewise serialize as a value or `null`.
`coin.exit_only` is true after any owned attempt is `SecondArmed` or `Signed`;
`coin.address_retired` and the close-tip fields come from an index-0 canonical
attempt.

`coin.duplicates` is sorted by this wallet database's stable
`duplicate_index`; sender and receiver databases may assign different indices.
Each element has exactly these keys:

```text
duplicate_index
txid
vout
amount_sats
observation_status
sweep_phase
broadcast_status
ownership_status
spend_txid
cooperative_only
server_dependent
```

Every same-script value is an exact JSON integer here and is not added to
`coin.amount`. Observation is one of `Mempool`, `Unconfirmed`, `Confirmed`,
`SpentMempool`, `SpentUnconfirmed`, `SpentConfirmed`, or `Absent`.
`sweep_phase` and `broadcast_status` are `null` without an attempt. Current and
previous generations remain distinguishable. `cooperative_only` becomes false
only with durable signed sweep bytes or a target-confirmed spend;
`server_dependent` is true only while the current owner still needs Mercury and
the address is not retired.

## Transfer

The recipient creates an address:

```text
cargo run -p client-rust -- new-transfer-address bob
```

The JSON key printed for the address is literally `new_transfer_address:`:

```json
{
  "new_transfer_address:": "..."
}
```

With `-b` or `--generate-batch-id`, the object also contains `batch_id`.
A transfer address may receive distinct statechains; this is different from
funding one deposit address repeatedly.

The current owner sends a confirmed coin:

```text
cargo run -p client-rust -- \
  bip448-transfer-send [--force-send-with-duplicates] \
  alice <STATECHAIN_ID> <TRANSFER_ADDRESS> [BATCH_ID]
```

Without the exact `--force-send-with-duplicates` flag, unresolved current-owner
duplicates reject before sender-side mutation. The flag acknowledges that
their value is outside the verified canonical statechain amount, has no
arbitrary-value unilateral backup, and depends on Mercury until the recipient
chooses to sweep. It bypasses only this warning: any withdrawal attempt still
blocks transfer, and `SecondArmed`/`Signed` makes rejection permanent.

On success it prints:

```json
{
  "Transfer": "sent"
}
```

The recipient polls and validates messages with:

```text
cargo run -p client-rust -- transfer-receive bob
```

It prints a JSON array of accepted statechain IDs. While a batch is locked, it
prints a waiting message and retries every five seconds. Before mutating the
wallet, the BIP448 path validates the transfer authorization, chain funding
facts, server key and count, every history row, signatures, reconstructed
templates, value schedule, and locktimes described in the
[protocol document](bip448_rebindable_statechains.md).

The sender journal persists its immutable transfer intent before
`/transfer/sender`. If the exact same-request response is lost, the server
replays the same active-generation `x1` while no different authenticated
request intervenes. Owner authentication and every unlock, message upload, and
receiver mutation are fenced under the locked `x1` generation.

For BIP448, update-message `x1_pub`, unlock `auth_pub_key`, and receiver
`batch_data` each carry the canonical compressed public key derived from that
`x1`. The update signature binds statechain ID, recipient, generation, and
ciphertext hash; the unlock signature binds its current-owner/recipient role,
statechain ID, and generation, and `auth_pub_key` is not the authentication
key; the receiver signature binds statechain ID, exact `t2`, and generation.
The transfer message is version 1 and contains only canonical
funding/value facts; it does not carry duplicate inventory.

After key update and accepted wallet/state persistence, the receiver performs
its own height-0 passive rescan. A post-acceptance scan error is typed and
retryable through a later update/list without another key update. The sender
gets no notification and no guarantee that the receiver will sweep. The
receiver decides whether and when to sweep and must use the indices displayed
by its own wallet.

The sender can cancel an in-flight BIP448 transfer:

```text
cargo run -p client-rust -- bip448-transfer-cancel alice <STATECHAIN_ID>
```

Cancellation transfers to a new address in the same wallet and prints the new
`state_number`. It creates a later state; it does not roll the counter back.

## Batch/latch commands

`payment-hash <WALLET_NAME> <STATECHAIN_ID>` creates a random batch ID and
preimage on Mercury and prints:

```json
{
  "hash": "...",
  "batch_id": "..."
}
```

`confirm-pending-invoice <WALLET_NAME> <STATECHAIN_ID>` unlocks the pending
transfer and has no success output. `retrieve-pre-image <WALLET_NAME>
<STATECHAIN_ID> <BATCH_ID>` prints `pre_image`. `get-payment-hash <BATCH_ID>`
prints `payment_hash` when Mercury returns a hash. The precise one-coin behavior
and test limits are in [atomic_transfer.md](atomic_transfer.md).

A completed payment-hash/latch creation does not reserve future transfer
rights. If a later duplicate sweep attempt is durably inserted, new transfer
and latch creation are blocked even though existing latch cleanup calls remain
available.

## Recovery packages

Get the wallet-derived fee address with:

```text
cargo run -p client-rust -- bip448-recovery-fee-address alice
```

It prints `{ "address": "..." }`. After funding that address and confirming
its input, submit the latest update package with:

```text
cargo run -p client-rust -- \
  broadcast-bip448-recovery-package alice <STATECHAIN_ID> funding_update \
  --fund-from-wallet --fee-rate 2
```

The `funding_update` role selects the update parent already stored in the
accepted latest-state record. After that parent confirms and its relative delay
passes, the `settlement` role selects the settlement parent already stored in
the same record. Alternatively, provide one or more
`--fee-input txid:vout:value_sats` values instead of `--fund-from-wallet`.
Exactly one CPFP fee-input source is required.

The success JSON fields are:

```text
statechain_id
role
parent_txid
cpfp_child_txid
package_fee_sats
package_vbytes
package_feerate_sat_per_vbyte
submitpackage_response
```

The command submits the parent and P2A CPFP child through Core
`submitpackage`. Neither the role nor the fee-input option selects a stale
protocol prevout, and this public command does not call the low-level rebinding
helpers. Older-output rebinding is exercised only by the manually orchestrated
stale-state E2E test; the client does not watch the chain, choose that source,
or run that sequence on its own.

Only the canonical update/settlement (`U/S`) path has the claimed unilateral
recovery behavior. The recovery commands are an emergency exemption to the
normal duplicate gates and can strand unswept duplicates.

## Cooperative duplicate sweep

Sweep exactly one locally indexed duplicate with:

```text
cargo run -p client-rust -- \
  bip448-sweep-duplicate alice <STATECHAIN_ID> <DUPLICATE_INDEX> \
  <TO_ADDRESS> [FEE_RATE]
```

The selected binding must be a current-owner, target-confirmed, unspent
duplicate. The client builds one input and one output, subtracting
`ceil(112 * fee_rate_sat_per_vbyte)` satoshis from that duplicate's exact
value. An invalid fee rate, a fee greater than or equal to the source value,
or a resulting output below the destination script's dust threshold is
rejected before signing. Each duplicate therefore has its own transaction,
fee, and lockbox signing-count increment; there is no multi-input batching.

The result reports `statechain_id`, `duplicate_index`, `source_outpoint`,
`amount_sats`, `sweep_txid`, `broadcast_status`, and `exit_only`. Attempts are
durably journaled through `Prepared`, `FirstArmed`, `NonceStored`,
`SecondArmed`, and `Signed`, and an exact retry resumes the stored request and
bytes. The wallet is durably marked exit-only before the possibly delivered
`sign/second` request. A duplicate sweep never calls withdrawal completion and
never deletes the statechain. Canonical cooperative close is last.

## Canonical cooperative withdrawal

```text
cargo run -p client-rust -- \
  bip448-withdraw alice <STATECHAIN_ID> <TO_ADDRESS> [FEE_RATE]
```

The optional fee rate is sat/vbyte. A new canonical attempt requires an
accepted BIP448 coin in `CONFIRMED`, no active transfer intent, pending transfer
signing, or outgoing transfer message, and a target-confirmed unspent canonical
binding. Every known current-owner duplicate must already have exact signed
sweep bytes with an accepted/confirmed broadcast or a confirmed independent
spend; dust and otherwise unresolved duplicates remain visible and block the
close.

The client freezes that known binding resolution set, signs and broadcasts the
canonical one-input/one-output key-path spend with the same durable phase
journal, persists the wallet state, and arms `CloseArmed` before the only path
that calls `/withdraw/complete`. Exact accepted bytes and the frozen snapshot
are revalidated before completion. Discovery of another current-owner binding
after the freeze blocks completion while Mercury state remains. Discovery only
after server/lockbox deletion can be unrecoverable. The command has no success
output.

## Prototype boundaries

- One logical `Coin` and canonical amount are retained. Normalized bindings
  expose every same-script value separately through nested `coin.duplicates`,
  using stable wallet-database-local indices; passive discovery never signs.
- Current-owner live or unresolved duplicates remain cooperatively
  server-dependent until exact signed sweep bytes exist or an independent
  spend confirms. Previous-owner and retired-address late rows remain visible
  but are not actionable. Consensus-valid arbitrary-value duplicates do not
  inherit canonical unilateral recovery.
- The first possibly delivered duplicate `sign/second` permanently ends
  transfer eligibility. The force flag acknowledges only the duplicate
  warning; it does not bypass an attempt, count, or exit-only gate. The sender
  receives no notification or sweep guarantee. The receiver independently
  rescans from height 0, decides whether and when to sweep, and uses its own
  locally assigned indices.
- There is no multi-input batching, equal-value recovery forest, arbitrary
  duplicate unilateral recovery, or exact legacy parity. Receiver
  key-update crash recovery is unchanged.
- Only canonical update/settlement (`U/S`) recovery is claimed unilateral.
  Emergency recovery can strand duplicates, and known dust or unresolved
  outputs can block normal close. Late payments after address retirement may
  be unrecoverable.
- Start with fresh databases: the client has twelve application tables while
  Mercury's six and lockbox's two application tables are unchanged. The CLI
  has sixteen commands, including exact flag
  `--force-send-with-duplicates`; the intended ignored matrix is 58 direct
  tests in eight binaries.
- There is no chain watcher and no automatic stale-state source selection.
  The stale-state proof is manually orchestrated by test code. BIP448 requires
  the pinned Bitcoin Inquisition revision and remains a prototype, not for
  Bitcoin mainnet or production use. Tests establish only their direct
  assertions.
