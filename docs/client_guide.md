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
through Bitcoin Core. `list-statecoins alice` prints an array whose object keys
are exactly:

```text
coin.user_pubkey
coin.aggregated_address
coin.address
coin.statechain_id
coin.amount
coin.status
coin.locktime
```

The status progresses through the exercised values such as `IN_MEMPOOL`,
`UNCONFIRMED`, and `CONFIRMED` as chain facts change. A second payment to the
same BIP448 deposit address is not turned into a second wallet coin. To create
another statechain, request another token and another BIP448 deposit address.

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
  bip448-transfer-send alice <STATECHAIN_ID> <TRANSFER_ADDRESS> [BATCH_ID]
```

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

## Cooperative withdrawal

```text
cargo run -p client-rust -- \
  bip448-withdraw alice <STATECHAIN_ID> <TO_ADDRESS> [FEE_RATE]
```

The optional fee rate is sat/byte. The client requires an accepted BIP448 coin
in `CONFIRMED` or `IN_TRANSFER`, rejects an outstanding transfer signing, signs
the funding output's Taproot key path with Mercury/lockbox, broadcasts the
transaction, persists `WITHDRAWING`, and calls `/withdraw/complete`. The
command has no success output. Later status refresh can promote a confirmed
transaction to `WITHDRAWN`.

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
