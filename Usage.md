# BIP448 client usage

Run the command-line client from the workspace root with:

```text
RUSTUP_TOOLCHAIN=1.92.0 cargo run -p client-rust -- <COMMAND>
```

The client loads `Settings.toml` by default. `ML_SETTINGS_FILE` selects another
settings file; an explicit extension or path is used as written, otherwise
`.toml` is appended. `ML_NETWORK=regtest` selects
`regtest.Settings.toml` when `ML_SETTINGS_FILE` is unset. The only supported
`chain_backend` value is `core`.

## Complete command surface

Angle-bracketed arguments are required and square-bracketed arguments or
options are optional. These spellings are the Clap command names.

```text
create-wallet <NAME>
new-token
new-bip448-deposit-address <WALLET_NAME> <TOKEN_ID> <AMOUNT>
bip448-recovery-fee-address <WALLET_NAME>
broadcast-bip448-recovery-package [OPTIONS] <WALLET_NAME> <STATECHAIN_ID> <ROLE> [CHANGE_ADDRESS]
list-statecoins <WALLET_NAME>
bip448-withdraw <WALLET_NAME> <STATECHAIN_ID> <TO_ADDRESS> [FEE_RATE]
new-transfer-address [OPTIONS] <WALLET_NAME>
bip448-transfer-send <WALLET_NAME> <STATECHAIN_ID> <TO_ADDRESS> [BATCH_ID]
bip448-transfer-cancel <WALLET_NAME> <STATECHAIN_ID>
transfer-receive <WALLET_NAME>
payment-hash <WALLET_NAME> <STATECHAIN_ID>
confirm-pending-invoice <WALLET_NAME> <STATECHAIN_ID>
retrieve-pre-image <WALLET_NAME> <STATECHAIN_ID> <BATCH_ID>
get-payment-hash <BATCH_ID>
```

`new-transfer-address` accepts `-b` or `--generate-batch-id`.

For `broadcast-bip448-recovery-package`, use the canonical `ROLE` value
`funding_update` or `settlement` and choose exactly one fee source:

- repeat `--fee-input <FEE_INPUTS>` with values encoded as
  `txid:vout:value_sats`; or
- pass `--fund-from-wallet` to discover confirmed inputs at the wallet-derived
  recovery fee address.

The recovery command also accepts `--fee-rate <FEE_RATE>` in sat/vbyte. Its
optional `CHANGE_ADDRESS` receives fee-input change; when explicit keyless
inputs are used and it is omitted, the wallet-derived recovery fee address is
used. `bip448-withdraw` interprets its optional fee rate as sat/byte.

See the [client guide](docs/client_guide.md) for the lifecycle and exact JSON
fields printed by each workflow command.

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
